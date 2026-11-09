"""RAG vector store.

Uses ChromaDB (persistent, on disk) with three collections:
  policies : enterprise refund policy documents (chunked)
  cases    : customer case files (requests, decisions)
  profiles : customer profiles, including synthetic financial info

Embeddings are computed locally with a hashing embedder so the app works
offline with no model download. Set EMBEDDINGS=chroma to use Chroma's default
sentence-transformer model instead (downloads ~80MB on first use).

If chromadb is not installed, a small JSON-backed store with the same API is
used so the app still runs.
"""
import hashlib
import json
import math
import os
import re
import threading

from app import config

DIM = 384
_TOKEN = re.compile(r"[a-z0-9$]+")
_STOP = set("""a an the and or of to in on for is are was be by with at as it this that from any may
not no do does i my me you your we our can how what when which who will would should could have has
""".split())
COLLECTIONS = ("policies", "cases", "profiles")


def embed(text: str) -> list:
    """Hashing-trick embedding over unigrams and bigrams, L2-normalised."""
    vec = [0.0] * DIM
    toks = [t for t in _TOKEN.findall((text or "").lower()) if t not in _STOP]
    feats = toks + [a + "_" + b for a, b in zip(toks, toks[1:])]
    for f in feats:
        h = int(hashlib.md5(f.encode()).hexdigest(), 16)
        vec[h % DIM] += 1.0 if (h >> 8) & 1 else -1.0
    n = math.sqrt(sum(v * v for v in vec)) or 1.0
    return [v / n for v in vec]


def chunk(text: str, size: int = 450, overlap: int = 80) -> list:
    """Split on paragraphs, then pack into ~size-char chunks."""
    paras = [p.strip() for p in re.split(r"\n\s*\n", text or "") if p.strip()]
    chunks, cur = [], ""
    for p in paras:
        if len(cur) + len(p) + 2 <= size:
            cur = f"{cur}\n\n{p}" if cur else p
        else:
            if cur:
                chunks.append(cur)
            while len(p) > size:
                chunks.append(p[:size])
                p = p[size - overlap:]
            cur = p
    if cur:
        chunks.append(cur)
    return chunks or [text or ""]


class _ChromaStore:
    def __init__(self, path):
        import chromadb
        self.client = chromadb.PersistentClient(path=str(path))
        self.use_default_ef = os.environ.get("EMBEDDINGS", "hash").lower() == "chroma"
        self.cols = {}
        for name in COLLECTIONS:
            kwargs = {"metadata": {"hnsw:space": "cosine"}}
            if not self.use_default_ef:
                kwargs["embedding_function"] = None
            self.cols[name] = self.client.get_or_create_collection(name, **kwargs)

    def upsert(self, col, ids, docs, metas):
        kw = {"ids": ids, "documents": docs, "metadatas": metas}
        if not self.use_default_ef:
            kw["embeddings"] = [embed(d) for d in docs]
        self.cols[col].upsert(**kw)

    def delete(self, col, where):
        self.cols[col].delete(where=where)

    def query(self, col, text, k=4, where=None):
        c = self.cols[col]
        if c.count() == 0:
            return []
        kw = {"n_results": min(k, c.count())}
        if where:
            kw["where"] = where
        if self.use_default_ef:
            kw["query_texts"] = [text]
        else:
            kw["query_embeddings"] = [embed(text)]
        try:
            r = c.query(**kw)
        except Exception:
            return []
        out = []
        for i in range(len(r["ids"][0])):
            out.append({"id": r["ids"][0][i], "text": r["documents"][0][i],
                        "metadata": r["metadatas"][0][i],
                        "score": round(1 - r["distances"][0][i], 4)})
        return out

    def count(self, col):
        return self.cols[col].count()


class _JsonStore:
    """Fallback store when chromadb is unavailable."""

    def __init__(self, path):
        self.path = path / "vectors.json"
        path.mkdir(parents=True, exist_ok=True)
        self.data = json.loads(self.path.read_text()) if self.path.exists() else {c: {} for c in COLLECTIONS}

    def _save(self):
        self.path.write_text(json.dumps(self.data))

    def upsert(self, col, ids, docs, metas):
        for i, d, m in zip(ids, docs, metas):
            self.data[col][i] = {"text": d, "metadata": m, "emb": embed(d)}
        self._save()

    def delete(self, col, where):
        for i in [i for i, v in self.data[col].items() if _match(v["metadata"], where)]:
            del self.data[col][i]
        self._save()

    def query(self, col, text, k=4, where=None):
        q = embed(text)
        scored = []
        for i, v in self.data[col].items():
            if where and not _match(v["metadata"], where):
                continue
            scored.append((sum(a * b for a, b in zip(q, v["emb"])), i, v))
        scored.sort(reverse=True)
        return [{"id": i, "text": v["text"], "metadata": v["metadata"], "score": round(s, 4)}
                for s, i, v in scored[:k]]

    def count(self, col):
        return len(self.data[col])


def _match(meta, where):
    for k, v in (where or {}).items():
        if k == "$and":
            if not all(_match(meta, w) for w in v):
                return False
        elif meta.get(k) != v:
            return False
    return True


_store = None
_lock = threading.Lock()


def store():
    global _store
    with _lock:
        if _store is None:
            config.CHROMA_DIR.mkdir(parents=True, exist_ok=True)
            try:
                _store = _ChromaStore(config.CHROMA_DIR)
            except Exception as e:  # pragma: no cover - depends on install
                print(f"[vectorstore] chromadb unavailable ({e}); using JSON fallback store")
                _store = _JsonStore(config.CHROMA_DIR)
        return _store


def wipe():
    """Delete every vector in every collection (used by the sandbox reset)."""
    s = store()
    with _lock:
        if isinstance(s, _ChromaStore):
            for name in COLLECTIONS:
                s.client.delete_collection(name)
            kwargs = {"metadata": {"hnsw:space": "cosine"}}
            if not s.use_default_ef:
                kwargs["embedding_function"] = None
            for name in COLLECTIONS:
                s.cols[name] = s.client.get_or_create_collection(name, **kwargs)
        else:
            s.data = {c: {} for c in COLLECTIONS}
            s._save()


def backend_name() -> str:
    return type(store()).__name__.strip("_")
