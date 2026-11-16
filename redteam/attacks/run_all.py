#!/usr/bin/env python3
"""Runner for the live-LLM red-team attacks (sandbox only, guardrails ON).

  python redteam/attacks/run_all.py --section 5 --reset
  python redteam/attacks/run_all.py --only 5.3,5.7 --repeat 3
  python redteam/attacks/run_all.py --allow-mock --section 5     # dry run on the mock model

Attack modules are discovered as sN_*.py next to this file; a missing module is
skipped, so sections can be added one at a time.
"""
import argparse
import glob
import importlib
import json
import os
import sys
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import harness  # noqa: E402


def load_sections():
    for path in sorted(glob.glob(os.path.join(HERE, "s[0-9]_*.py"))):
        importlib.import_module(os.path.splitext(os.path.basename(path))[0])


def sort_key(a):
    return [int(p) if p.isdigit() else 0 for p in a["id"].split(".")]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base-url", default="http://localhost:8000")
    ap.add_argument("--section", default="", help="comma-separated section numbers, e.g. 1,5")
    ap.add_argument("--only", default="", help="comma-separated attack ids, e.g. 1.2,5.3")
    ap.add_argument("--repeat", type=int, default=1, help="repeat each attack N times (live models vary)")
    ap.add_argument("--reset", action="store_true", help="re-seed the sandbox first, and between sections")
    ap.add_argument("--include-disruptive", action="store_true",
                    help="also run attacks that lock accounts, spawn servers or generate volume")
    ap.add_argument("--allow-mock", action="store_true", help="permit the mock LLM (dry run)")
    ap.add_argument("--out", default=None)
    args = ap.parse_args()

    load_sections()
    h = harness.Harness(args.base_url)
    system = h.preflight(allow_mock=args.allow_mock)
    sections = {s.strip() for s in args.section.split(",") if s.strip()}
    only = {s.strip() for s in args.only.split(",") if s.strip()}
    chosen = [a for a in sorted(harness.REGISTRY, key=sort_key)
              if (not sections or a["section"] in sections) and (not only or a["id"] in only)]
    skipped_disruptive = [a["id"] for a in chosen if a["disruptive"] and not args.include_disruptive]
    chosen = [a for a in chosen if not a["disruptive"] or args.include_disruptive]
    if not chosen:
        raise SystemExit("no attacks selected (are the section modules written yet?)")

    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_dir = args.out or os.path.join(harness.ROOT, "redteam", "results", f"live-{ts}")
    os.makedirs(out_dir, exist_ok=True)
    print(f"LLM {system.get('llm_provider')}/{system.get('llm_model')}  guardrails={system.get('guardrails')}  "
          f"-> {out_dir}")

    if args.reset:
        h.reset()
    results, last_section = [], None
    for a in chosen:
        if args.reset and last_section not in (None, a["section"]):
            h.reset()
        last_section = a["section"]
        r = harness.run_attack(h, a, repeat=args.repeat)
        results.append(r)
        with open(os.path.join(out_dir, f"{a['id']}.json"), "w") as f:
            json.dump({"config": system, **r}, f, indent=2, default=str)
        print(f"{a['id']:<6} {r['outcome']:<24} {a['title']}  | {r['runs'][-1]['observed'][:110]}")

    if args.reset:
        h.reset()   # leave the sandbox seeded and with the original policy active
    with open(os.path.join(out_dir, "summary.json"), "w") as f:
        json.dump({"run_at": ts, "config": system, "skipped_disruptive": skipped_disruptive,
                   "results": [{k: v for k, v in r.items() if k != "runs"} for r in results]}, f, indent=2)
    harness.write_report(out_dir, system, results)
    if skipped_disruptive:
        print("skipped (need --include-disruptive):", ", ".join(skipped_disruptive))
    print(f"\nreport: {os.path.join(out_dir, 'report.md')}")


if __name__ == "__main__":
    main()
