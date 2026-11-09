// Refund Me Maybe - browser UI (vanilla JS).
// All server data is inserted with textContent (never innerHTML) so model or
// customer output cannot inject markup (LLM05 improper output handling).
"use strict";

let session = null;
try { session = JSON.parse(sessionStorage.getItem("rmm_session") || "null"); } catch (e) { session = null; }

// ---------- helpers ----------
function h(tag, attrs, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else if (k === "class") el.className = v;
    else el.setAttribute(k, v === true ? "" : v);
  }
  for (const c of children.flat()) {
    if (c === null || c === undefined || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}
const $view = () => document.getElementById("view");
const money = (n) => (n === null || n === undefined) ? "" : "$" + Number(n).toFixed(2);
const short = (s) => (s || "").replace("T", " ").slice(0, 16);

async function api(path, opts = {}) {
  const headers = opts.headers || {};
  if (session) headers["Authorization"] = "Bearer " + session.token;
  if (opts.json !== undefined) { headers["Content-Type"] = "application/json"; opts.body = JSON.stringify(opts.json); }
  const res = await fetch(path, { method: opts.method || (opts.body ? "POST" : "GET"), headers, body: opts.body });
  let data = null;
  try { data = await res.json(); } catch (e) { data = null; }
  if (res.status === 401 && session) { logout(); throw new Error("Signed out"); }
  if (!res.ok) throw new Error((data && data.detail) || res.statusText);
  return data;
}

function statusPill(status) {
  const cls = { active: "ok", refunded: "ok", approved: "ok", denied: "bad", escalated: "warn", on_hold: "warn",
                returned: "warn", allowed: "ok", blocked: "bad", would_block: "warn", error: "bad" }[status] || "";
  return h("span", { class: "pill " + cls }, status || "-");
}

function table(cols, rows, onClick) {
  return h("div", { class: "table-wrap" }, h("table", {},
    h("thead", {}, h("tr", {}, cols.map(c => h("th", {}, c[0])))),
    h("tbody", {}, rows.length ? rows.map(r => h("tr", onClick ? { class: "clickable", onclick: () => onClick(r) } : {},
      cols.map(c => h("td", {}, c[1](r))))) : h("tr", {}, h("td", { colspan: cols.length, class: "muted" }, "Nothing yet")))));
}

function errorBox(e) { return h("div", { class: "msg bad" }, String(e.message || e)); }

function traceTable(trace) {
  if (!trace || !trace.length) return h("div");
  return h("details", { open: true }, h("summary", {}, `Agent trace (${trace.length} tool calls through the gateway)`),
    table([["Agent", r => r.agent], ["Tool", r => r.tool], ["Outcome", r => statusPill(r.outcome)],
           ["Control", r => r.control || ""], ["Detail", r => r.reason || r.summary || ""],
           ["Decision ID", r => h("code", {}, r.decision_id || "")]], trace));
}

// ---------- top bar ----------
async function renderSysbar() {
  const bar = document.getElementById("sysbar");
  bar.replaceChildren();
  try {
    const s = await api("/api/system");
    bar.append(h("span", { class: "pill" }, "LLM: " + s.llm_provider + (s.llm_provider === "mock" ? (s.llm_mock_naive ? " (naive)" : "") : " / " + s.llm_model)));
    bar.append(h("span", { class: "pill " + (s.guardrails && !s.guardrail_disable.length ? "ok" : "bad") },
      s.guardrails ? (s.guardrail_disable.length ? "Guardrails partly off: " + s.guardrail_disable.join(", ") : "Guardrails on") : "Guardrails OFF (monitor only)"));
    bar.append(h("span", { class: "pill " + (s.agent_authority && s.agent_authority.revoked ? "bad" : "ok") },
      s.agent_authority && s.agent_authority.revoked ? "Agent authority REVOKED" : "Agent authority active"));
    bar.append(h("span", { class: "pill" }, "Vector DB: " + s.vector_store));
  } catch (e) { bar.append(h("span", { class: "pill bad" }, "server unreachable")); }
}

function renderUserbar() {
  const bar = document.getElementById("userbar");
  bar.replaceChildren();
  if (!session) return;
  bar.append(h("span", {}, session.username + " "), h("span", { class: "pill" }, session.role),
    h("button", { class: "btn secondary", style: "margin:0", onclick: logout }, "Sign out"));
}

function logout() {
  if (session) fetch("/api/logout", { method: "POST", headers: { Authorization: "Bearer " + session.token } }).catch(() => {});
  session = null;
  try { sessionStorage.removeItem("rmm_session"); } catch (e) {}
  boot();
}

// ---------- login ----------
function renderLogin() {
  document.getElementById("tabs").replaceChildren();
  const user = h("input", { id: "u", autocomplete: "username" });
  const pw = h("input", { id: "p", type: "password", autocomplete: "current-password" });
  const out = h("div");
  async function go(u, p) {
    try {
      session = await api("/api/login", { json: { username: u, password: p } });
      try { sessionStorage.setItem("rmm_session", JSON.stringify(session)); } catch (e) {}
      boot();
    } catch (e) { out.replaceChildren(errorBox(e)); }
  }
  const demo = [["alice", "alice123", "Customer"], ["bob", "bob123", "Customer"], ["carol", "carol123", "Customer"],
                ["admin", "admin123", "Admin"], ["supervisor", "super123", "Supervisor"]];
  $view().replaceChildren(h("div", { class: "panel login" },
    h("h2", {}, "Sign in"),
    h("form", { onsubmit: (e) => { e.preventDefault(); go(user.value, pw.value); } },
      h("label", { for: "u" }, "Username"), user, h("label", { for: "p" }, "Password"), pw,
      h("button", { class: "btn", type: "submit" }, "Sign in")),
    out,
    h("h3", {}, "Demo accounts (synthetic)"),
    h("div", { class: "demo-users" }, demo.map(([u, p, r]) =>
      h("button", { class: "btn secondary", onclick: () => go(u, p) }, `${r}: ${u}`)))));
}

// ---------- tabs ----------
const TABS = {
  customer: [["New refund", viewNewRefund], ["My cases", viewMyCases], ["Inbox", viewInbox], ["Assistant", viewChat]],
  admin: [["Policies", viewPolicies], ["Reports", viewReports], ["Audit log", viewAudit], ["Assistant", viewChat], ["Sandbox", viewSandbox]],
  supervisor: [["Review queue", viewQueue], ["All cases", viewAllCases], ["Kill switch", viewKill], ["Reports", viewReports],
               ["Audit log", viewAudit], ["Observability", viewObservability], ["Assistant", viewChat]],
};
let currentTab = 0;

function renderTabs() {
  const tabs = TABS[session.role];
  const nav = document.getElementById("tabs");
  nav.replaceChildren(...tabs.map(([name], i) =>
    h("button", { class: i === currentTab ? "active" : "", onclick: () => { currentTab = i; renderTabs(); } }, name)));
  $view().replaceChildren(h("div", { class: "muted" }, "Loading..."));
  tabs[currentTab][1]().catch(e => $view().replaceChildren(errorBox(e)));
}

// ---------- customer ----------
async function viewNewRefund() {
  const orders = await api("/api/customer/orders");
  const profile = await api("/api/customer/profile");
  const order = h("select", { id: "order" }, orders.map(o => h("option", { value: o.order_id },
    `${o.order_id} - ${o.item} - ${money(o.amount)} - ${o.order_date.slice(0, 10)}${o.refunded_case ? " (refunded)" : ""}`)));
  const amount = h("input", { id: "amount", type: "number", step: "0.01", min: "0.01" });
  const setAmt = () => { const o = orders.find(x => x.order_id === order.value); if (o) amount.value = o.amount; };
  order.addEventListener("change", setAmt); setAmt();
  const reason = h("select", { id: "reason" },
    [["damaged", "Damaged item"], ["not_delivered", "Item not delivered"], ["wrong_item", "Wrong item received"],
     ["duplicate_charge", "Duplicate charge"], ["other", "Other"]].map(([v, t]) => h("option", { value: v }, t)));
  const desc = h("textarea", { id: "desc", placeholder: "Tell us what happened" });
  const out = h("div");
  const balanceEl = h("div", {}, money(profile.balance));
  const btn = h("button", { class: "btn", type: "submit" }, "Submit refund request");
  const form = h("form", { onsubmit: async (e) => {
    e.preventDefault(); btn.disabled = true; out.replaceChildren(h("div", { class: "muted" }, "Agents are working on your case..."));
    try {
      const r = await api("/api/cases", { json: { order_id: order.value, amount: parseFloat(amount.value), reason: reason.value, description: desc.value } });
      const cls = { refunded: "ok", denied: "bad" }[r.status] || "warn";
      out.replaceChildren(h("div", { class: "msg " + cls }, h("strong", {}, `${r.case_id}: ${r.status}. `), r.reason || ""),
        h("details", {}, h("summary", {}, "Workflow plan and steps"),
          table([["Step", s => s.step], ["Agent", s => s.agent], ["Result", s => s.ok ? statusPill("allowed") : statusPill("blocked")],
                 ["Detail", s => s.summary || s.reason || s.error || ""]], r.steps)),
        traceTable(r.trace));
      renderSysbar();
      try { const p2 = await api("/api/customer/profile"); balanceEl.textContent = money(p2.balance); } catch (e2) {}
    } catch (e) { out.replaceChildren(errorBox(e)); }
    btn.disabled = false;
  } }, h("label", { for: "order" }, "Order"), order, h("label", { for: "amount" }, "Refund amount"), amount,
     h("label", { for: "reason" }, "Reason"), reason, h("label", { for: "desc" }, "Description"), desc, btn);
  $view().replaceChildren(h("div", { class: "grid2" },
    h("div", { class: "panel" }, h("h2", {}, "Request a refund"), form, out),
    h("div", { class: "panel" }, h("h2", {}, "Your account"),
      h("div", { class: "kv" }, h("div", {}, "Name"), h("div", {}, profile.name), h("div", {}, "Email"), h("div", {}, profile.email),
        h("div", {}, "Bank"), h("div", {}, `${profile.bank_name} ${profile.bank_account}`),
        h("div", {}, "Balance"), balanceEl),
      h("h3", {}, "Refund policy in short"),
      h("ul", {}, h("li", {}, "Up to $100 per refund is decided automatically; more goes to a supervisor."),
        h("li", {}, "Orders must be from the last 30 days and on your account."),
        h("li", {}, "One refund per order."),
        h("li", {}, "Damaged, not delivered, wrong item and duplicate charge are eligible; other reasons are reviewed by a supervisor.")))));
}

async function viewMyCases() {
  const cases = await api("/api/cases");
  const detail = h("div");
  $view().replaceChildren(h("div", { class: "panel" }, h("h2", {}, "My cases"),
    table([["Case", r => r.id], ["Order", r => r.order_id], ["Amount", r => money(r.amount)], ["Reason", r => r.reason],
           ["Status", r => statusPill(r.status)], ["Decision reason", r => r.decision_reason || ""], ["Updated", r => short(r.updated_at)]],
      cases, async (r) => { const d = await api("/api/cases/" + r.id); detail.replaceChildren(emailList(d.emails, `Emails for ${r.id}`)); })),
    detail);
}

function emailList(emails, title) {
  return h("div", { class: "panel" }, h("h2", {}, title),
    emails.length ? emails.map(m => h("div", { class: "panel" },
      h("div", { class: "row" }, statusPill(m.direction === "in" ? "received" : "sent"), h("strong", {}, m.subject),
        h("span", { class: "muted" }, ` ${m.from_addr} → ${m.to_addr} · ${short(m.created_at)} · ${m.folder}`)),
      h("pre", {}, m.body))) : h("div", { class: "muted" }, "No emails"));
}

async function viewInbox() {
  const mail = await api("/api/inbox");
  const subj = h("input", { id: "subj" });
  const body = h("textarea", { id: "body" });
  const out = h("div");
  $view().replaceChildren(h("div", { class: "grid2" },
    h("div", {}, emailList(mail, "Inbox")),
    h("div", { class: "panel" }, h("h2", {}, "Email support"),
      h("p", { class: "muted" }, "Mention your case ID (e.g. CASE-0002) so we can file it with your case."),
      h("form", { onsubmit: async (e) => { e.preventDefault();
        try { const r = await api("/api/inbox/send", { json: { subject: subj.value, body: body.value } });
              out.replaceChildren(h("div", { class: "msg ok" }, `Sent. Filed in '${r.folder}'${r.case_id ? " for " + r.case_id : ""}.`)); }
        catch (err) { out.replaceChildren(errorBox(err)); } } },
        h("label", { for: "subj" }, "Subject"), subj, h("label", { for: "body" }, "Message"), body,
        h("button", { class: "btn", type: "submit" }, "Send")), out)));
}

// ---------- assistant (orchestrator chat) ----------
const chatHistory = [];
async function viewChat() {
  const log = h("div", { class: "chatlog" });
  const trace = h("div");
  const input = h("input", { id: "chatmsg", placeholder: "Ask about a case, the refund policy, or reports" });
  const draw = () => log.replaceChildren(...chatHistory.map(m => h("div", { class: "bubble " + m.who }, m.text)));
  draw();
  const examples = {
    customer: ["What is the status of my cases?", "How many days do I have to request a refund?", "My order ORD-1001 arrived damaged, please refund $79.99"],
    admin: ["Show this week's refund report", "What is the weekly refund limit?"],
    supervisor: ["Show this week's refund report", "Process CASE-0002", "Search cases about damaged items"],
  }[session.role];
  $view().replaceChildren(h("div", { class: "panel" }, h("h2", {}, "Support assistant"),
    h("p", { class: "muted" }, "The orchestrator plans your request, routes each step to a specialized agent, and combines the results."),
    log,
    h("form", { onsubmit: async (e) => {
      e.preventDefault(); const text = input.value.trim(); if (!text) return;
      chatHistory.push({ who: "user", text }); input.value = ""; draw();
      try {
        const r = await api("/api/chat", { json: { message: text } });
        chatHistory.push({ who: "bot", text: r.answer }); draw();
        trace.replaceChildren(h("details", {}, h("summary", {}, `Plan (${r.plan.length} steps)`), h("pre", {}, JSON.stringify(r.plan, null, 2))),
          traceTable(r.trace));
      } catch (err) { chatHistory.push({ who: "bot", text: "Error: " + err.message }); draw(); }
      log.scrollTop = log.scrollHeight;
    } }, h("div", { class: "row" }, input, h("button", { class: "btn", type: "submit" }, "Send"))),
    h("div", { class: "row" }, examples.map(x => h("button", { class: "btn secondary", onclick: () => { input.value = x; input.focus(); } }, x))),
    trace));
}

// ---------- admin ----------
async function viewPolicies() {
  const list = await api("/api/policies");
  const title = h("input", { id: "ptitle", value: "Customer Refund Policy v2" });
  const file = h("input", { id: "pfile", type: "file", accept: ".md,.txt,.pdf,.docx" });
  const text = h("textarea", { id: "ptext", placeholder: "...or paste policy Markdown here" });
  const out = h("div");
  const q = h("input", { id: "q", placeholder: "e.g. how long is the purchase window?" });
  const results = h("div");
  const viewer = h("div");
  $view().replaceChildren(
    h("div", { class: "panel" }, h("h2", {}, "Refund policies"),
      table([["ID", r => r.id], ["Title", r => r.title], ["File", r => r.filename || ""], ["Active", r => r.active ? statusPill("active") : ""],
             ["Rules", r => `$${r.rules.single_refund_limit}/refund, $${r.rules.weekly_refund_limit}/week, ${r.rules.purchase_window_days} days`],
             ["Uploaded", r => `${r.uploaded_by} ${short(r.created_at)}`],
             ["", r => session.role === "admin" && !r.active ? h("button", { class: "btn secondary", style: "margin:0", onclick: async (e) => { e.stopPropagation(); await api(`/api/policies/${r.id}/activate`, { method: "POST" }); renderTabs(); } }, "Activate") : ""]],
        list, async (r) => { const p = await api("/api/policies/" + r.id); viewer.replaceChildren(h("div", { class: "panel" }, h("h2", {}, p.title), h("pre", {}, p.content))); })),
    viewer,
    h("div", { class: "grid2" },
      h("div", { class: "panel" }, h("h2", {}, "Upload a policy"),
        h("p", { class: "muted" }, "PDF, DOCX, Markdown or text. Include a ```policy-rules block to set limits. Limits above the org maximum ($100 / $500) are clamped."),
        h("form", { onsubmit: async (e) => { e.preventDefault();
          const fd = new FormData(); fd.append("title", title.value);
          if (file.files[0]) fd.append("file", file.files[0]); else fd.append("text", text.value);
          try { const r = await api("/api/policies", { body: fd });
                out.replaceChildren(h("div", { class: "msg ok" }, `Policy ${r.id} indexed (${r.chunks} chunks) and active.`),
                  r.warnings.length ? h("div", { class: "msg warn" }, r.warnings.join(" ")) : "", h("pre", {}, JSON.stringify(r.rules, null, 2))); }
          catch (err) { out.replaceChildren(errorBox(err)); } } },
          h("label", { for: "ptitle" }, "Title"), title, h("label", { for: "pfile" }, "File"), file, h("label", { for: "ptext" }, "Text"), text,
          h("button", { class: "btn", type: "submit" }, "Upload and activate")), out),
      h("div", { class: "panel" }, h("h2", {}, "Search policies (RAG retrieval check)"),
        h("form", { onsubmit: async (e) => { e.preventDefault();
          const r = await api("/api/policies/search", { json: { query: q.value } });
          results.replaceChildren(...r.results.map(x => h("div", { class: "panel" }, h("div", { class: "muted" }, `score ${x.score} · ${x.metadata.title} · chunk ${x.metadata.chunk}`), h("pre", {}, x.text)))); } },
          q, h("button", { class: "btn", type: "submit" }, "Search")), results)));
}

async function viewReports() {
  const r = await api("/api/reports");
  const t = r.totals;
  const cols = [["Case", x => x.case_id], ["Customer", x => x.customer_id], ["Order", x => x.order_id], ["Amount", x => money(x.amount)],
                ["Status", x => statusPill(x.status)], ["Reason", x => x.decision_reason || ""], ["Rule", x => x.policy_rule || ""],
                ["Decided by", x => x.decided_by || ""], ["Date", x => short(x.updated_at)]];
  $view().replaceChildren(
    h("div", { class: "panel" }, h("h2", {}, "This week"),
      h("div", { class: "kv" }, h("div", {}, "Week starting"), h("div", {}, short(t.week_start)),
        h("div", {}, "Autonomous refunds"), h("div", {}, `${money(t.autonomous_total)} of ${money(t.weekly_limit)} (remaining ${money(t.remaining_autonomous)})`),
        h("div", {}, "All refunds incl. supervisor"), h("div", {}, money(t.all_refunds_total)))),
    h("div", { class: "panel" }, h("h2", {}, `Approved (${r.approved.length})`), table(cols, r.approved)),
    h("div", { class: "panel" }, h("h2", {}, `Denied (${r.denied.length})`), table(cols, r.denied)),
    h("div", { class: "panel" }, h("h2", {}, `Escalated or returned (${r.escalated.length})`), table(cols, r.escalated)));
}

async function viewAudit() {
  const outcome = h("select", {}, ["", "allowed", "blocked", "would_block", "error", "info"].map(o => h("option", { value: o }, o || "all outcomes")));
  const box = h("div"); const verify = h("div");
  async function load() {
    const rows = await api("/api/audit?limit=300" + (outcome.value ? "&outcome=" + outcome.value : ""));
    box.replaceChildren(table([["#", r => r.seq], ["Time", r => short(r.ts)], ["Decision ID", r => h("code", {}, r.decision_id)], ["Actor", r => r.actor],
      ["Agent", r => r.agent || ""], ["Tool", r => r.tool || ""], ["Case", r => r.case_id || ""], ["Outcome", r => statusPill(r.outcome)],
      ["Control", r => r.control || ""], ["Reason", r => r.reason || ""]], rows));
  }
  outcome.addEventListener("change", load);
  $view().replaceChildren(h("div", { class: "panel" }, h("h2", {}, "Audit log (append-only, hash-chained)"),
    h("div", { class: "row" }, outcome, h("button", { class: "btn secondary", onclick: async () => {
      const v = await api("/api/audit/verify");
      verify.replaceChildren(h("div", { class: "msg " + (v.ok ? "ok" : "bad") }, v.ok ? `Chain intact: ${v.rows} rows.` : `Chain BROKEN at row ${v.broken_at_seq}.`)); } }, "Verify chain")),
    verify, box));
  await load();
}

async function viewSandbox() {
  const out = h("div");
  $view().replaceChildren(h("div", { class: "panel" }, h("h2", {}, "Sandbox"),
    h("p", {}, "Re-seed all synthetic data (customers, orders, cases, emails, policies, audit log). Use between red-team runs."),
    h("button", { class: "btn danger", onclick: async () => {
      if (!confirm("Wipe and re-seed the sandbox?")) return;
      try { const r = await api("/api/admin/reset-sandbox", { method: "POST" }); out.replaceChildren(h("div", { class: "msg ok" }, r.note)); setTimeout(logout, 1500); }
      catch (e) { out.replaceChildren(errorBox(e)); } } }, "Reset sandbox data"), out));
}

// ---------- supervisor ----------
async function caseDetailPanel(caseId, onDone) {
  const d = await api("/api/cases/" + caseId);
  const c = d.case;
  const note = h("textarea", { placeholder: "Note to customer / reason (optional)" });
  const out = h("div");
  const act = async (action) => {
    try { const r = await api(`/api/supervisor/cases/${caseId}/decision`, { json: { action, note: note.value } });
          out.replaceChildren(h("div", { class: "msg ok" }, `${caseId} is now ${r.case.status}.`), traceTable(r.trace)); onDone && onDone(); }
    catch (e) { out.replaceChildren(errorBox(e)); }
  };
  const rerun = async () => {
    try { const r = await api(`/api/supervisor/cases/${caseId}/rerun`, { method: "POST" });
          out.replaceChildren(h("div", { class: "msg ok" }, `${caseId} re-run: ${r.status}.`), traceTable(r.trace)); onDone && onDone(); }
    catch (e) { out.replaceChildren(errorBox(e)); }
  };
  const locked = !!c.supervisor_locked;
  return h("div", { class: "panel" }, h("h2", {}, `${c.id} `, statusPill(c.status)),
    h("div", { class: "grid2" },
      h("div", {}, h("div", { class: "kv" },
        h("div", {}, "Customer"), h("div", {}, c.customer_id), h("div", {}, "Order"), h("div", {}, `${c.order_id} (${d.order ? d.order.item + ", " + money(d.order.amount) + ", " + d.order.order_date.slice(0, 10) : "not found"})`),
        h("div", {}, "Requested"), h("div", {}, money(c.amount)), h("div", {}, "Reason"), h("div", {}, c.reason),
        h("div", {}, "Injection flag"), h("div", {}, c.injection_flag ? statusPill("blocked") : "no"),
        h("div", {}, "Decision"), h("div", {}, `${c.decision || "-"} by ${c.decided_by || "-"}: ${c.decision_reason || ""}`)),
        h("h3", {}, "Customer description (untrusted)"), h("pre", {}, c.description || "")),
      h("div", {},
        h("h3", {}, "Policy engine check"), h("div", {}, statusPill(d.policy_check.result), " ", d.policy_check.reason),
        table([["Rule", x => x.rule], ["Pass", x => x.passed ? "yes" : "no"], ["Detail", x => x.detail]], d.policy_check.checks),
        h("h3", {}, "LLM recommendation"), h("pre", {}, d.llm_recommendation ? JSON.stringify(d.llm_recommendation, null, 2) : "none"))),
    locked ? h("div", { class: "msg warn" }, "This case has a final supervisor decision.") :
      h("div", {}, note, h("div", { class: "row" },
        h("button", { class: "btn ok", onclick: () => act("approve") }, "Approve and issue refund"),
        h("button", { class: "btn danger", onclick: () => act("deny") }, "Deny"),
        h("button", { class: "btn secondary", onclick: () => act("return") }, "Return to customer"),
        c.status === "on_hold" ? h("button", { class: "btn secondary", onclick: rerun }, "Re-run agent workflow") : "")),
    out,
    h("details", {}, h("summary", {}, `Audit trail (${d.audit.length})`),
      table([["Time", r => short(r.ts)], ["Decision ID", r => h("code", {}, r.decision_id)], ["Actor", r => r.actor], ["Agent", r => r.agent || ""],
             ["Tool", r => r.tool || ""], ["Outcome", r => statusPill(r.outcome)], ["Control", r => r.control || ""], ["Reason", r => r.reason || ""]], d.audit)),
    h("details", {}, h("summary", {}, `Emails (${d.emails.length})`), d.emails.map(m => h("pre", {}, `${m.direction === "in" ? "FROM " + m.from_addr : "TO " + m.to_addr}: ${m.subject}\n\n${m.body}`))));
}

async function viewQueue() {
  const rows = await api("/api/supervisor/queue");
  const detail = h("div");
  const open = async (r) => detail.replaceChildren(await caseDetailPanel(r.id, () => viewQueue()));
  $view().replaceChildren(h("div", { class: "panel" }, h("h2", {}, "Review queue"),
    table([["Case", r => r.id], ["Customer", r => r.customer_id], ["Amount", r => money(r.amount)], ["Reason", r => r.reason],
           ["Status", r => statusPill(r.status)], ["Why", r => r.policy_rule || ""], ["Flag", r => r.injection_flag ? statusPill("blocked") : ""],
           ["Created", r => short(r.created_at)]], rows, open)), detail);
}

async function viewAllCases() {
  const rows = await api("/api/cases");
  const detail = h("div");
  $view().replaceChildren(h("div", { class: "panel" }, h("h2", {}, "All cases"),
    table([["Case", r => r.id], ["Customer", r => r.customer_id], ["Order", r => r.order_id], ["Amount", r => money(r.amount)],
           ["Status", r => statusPill(r.status)], ["Decided by", r => r.decided_by || ""], ["Updated", r => short(r.updated_at)]],
      rows, async (r) => detail.replaceChildren(await caseDetailPanel(r.id, () => viewAllCases())))), detail);
}

async function viewKill() {
  const st = await api("/api/supervisor/authority");
  const note = h("input", { placeholder: "Reason (recorded in the audit log)" });
  const out = h("div");
  const set = async (revoked) => {
    try { await api("/api/supervisor/authority", { json: { revoked, note: note.value } }); renderSysbar(); viewKill(); }
    catch (e) { out.replaceChildren(errorBox(e)); }
  };
  $view().replaceChildren(h("div", { class: "panel" }, h("h2", {}, "Agent authority (kill switch)"),
    h("div", { class: "msg " + (st.revoked ? "bad" : "ok") }, st.revoked ? `REVOKED by ${st.by} at ${short(st.at)}. Agents cannot take refund or email actions.` : "Active. Agents may act within policy."),
    note,
    st.revoked ? h("button", { class: "btn ok", onclick: () => set(false) }, "Restore agent authority")
               : h("button", { class: "btn danger", onclick: () => set(true) }, "Revoke agent authority"),
    h("p", { class: "muted" }, "Cases submitted while authority is revoked are put on hold. Open them from the review queue and re-run the workflow after restoring authority."),
    out));
}

async function viewObservability() {
  const [sys, bus, calls] = await Promise.all([api("/api/system"), api("/api/bus?limit=60"), api("/api/llm-calls")]);
  $view().replaceChildren(
    h("div", { class: "panel" }, h("h2", {}, "Configuration"), h("pre", {}, JSON.stringify(sys, null, 2))),
    h("div", { class: "panel" }, h("h2", {}, "Inter-agent bus (MCP-style JSON-RPC, HMAC-signed)"),
      table([["#", r => r.id], ["Time", r => short(r.ts)], ["From", r => r.sender], ["To", r => r.recipient],
             ["Tool", r => { try { return JSON.parse(r.message).params.name; } catch (e) { return ""; } }],
             ["Signature", r => r.signature_valid ? statusPill("allowed") : statusPill("blocked")],
             ["Response", r => (r.response || "").slice(0, 140)]], bus)),
    h("div", { class: "panel" }, h("h2", {}, "Recent LLM calls"),
      table([["Purpose", r => r.purpose], ["Provider", r => r.provider], ["OK", r => r.ok ? "yes" : "no"], ["ms", r => r.ms],
             ["Output", r => JSON.stringify(r.output).slice(0, 200)]], calls)));
}

// ---------- boot ----------
function boot() {
  renderSysbar();
  renderUserbar();
  if (!session) return renderLogin();
  currentTab = 0;
  renderTabs();
}
boot();
