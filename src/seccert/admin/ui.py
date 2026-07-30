"""The SecCert admin console — a single self-contained HTML page (no external assets)."""

CONSOLE_HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>SecCert — CA Console</title>
<style>
  :root {
    --bg:#0b0e0c; --panel:#111614; --panel2:#0e1210; --line:#243029;
    --ink:#d8e0da; --dim:#8a978f; --accent:#7fb069; --accent2:#e0b341;
    --bad:#e06c6c; --ok:#7fb069; --mono: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  }
  * { box-sizing:border-box; }
  body { margin:0; background:var(--bg); color:var(--ink); font-family:var(--mono);
         font-size:14px; line-height:1.5; }
  header { display:flex; align-items:center; gap:14px; padding:16px 22px;
           border-bottom:1px solid var(--line); background:var(--panel2); }
  header h1 { font-size:16px; margin:0; letter-spacing:.5px; font-weight:600; }
  header .tag { color:var(--dim); font-size:12px; }
  .pill { margin-left:auto; padding:3px 10px; border-radius:999px; font-size:12px;
          border:1px solid var(--line); color:var(--dim); }
  .pill.ok { color:var(--ok); border-color:#2c4030; }
  .pill.bad { color:var(--bad); border-color:#4a2a2a; }
  main { max-width:1040px; margin:0 auto; padding:22px; display:grid; gap:18px; }
  .card { background:var(--panel); border:1px solid var(--line); border-radius:8px; padding:16px 18px; }
  .card h2 { font-size:13px; text-transform:uppercase; letter-spacing:1px; color:var(--dim);
             margin:0 0 12px; }
  .kv { display:grid; grid-template-columns:150px 1fr; gap:6px 14px; font-size:13px; }
  .kv dt { color:var(--dim); }
  .kv dd { margin:0; word-break:break-all; }
  .row { display:flex; gap:10px; flex-wrap:wrap; align-items:center; }
  input[type=password], input[type=text] { background:var(--panel2); border:1px solid var(--line);
    color:var(--ink); padding:8px 10px; border-radius:6px; font-family:var(--mono); min-width:280px; }
  button { background:var(--accent); color:#0b0e0c; border:0; padding:8px 14px; border-radius:6px;
    font-family:var(--mono); font-weight:600; cursor:pointer; }
  button.ghost { background:transparent; color:var(--ink); border:1px solid var(--line); }
  button.danger { background:transparent; color:var(--bad); border:1px solid #4a2a2a; }
  a.btn { text-decoration:none; display:inline-block; }
  table { width:100%; border-collapse:collapse; font-size:12.5px; }
  th, td { text-align:left; padding:8px 10px; border-bottom:1px solid var(--line); vertical-align:top; }
  th { color:var(--dim); font-weight:600; text-transform:uppercase; font-size:11px; letter-spacing:.5px; }
  td.sans { max-width:320px; }
  .badge { padding:2px 8px; border-radius:4px; font-size:11px; border:1px solid var(--line); }
  .badge.valid { color:var(--ok); border-color:#2c4030; }
  .badge.revoked { color:var(--bad); border-color:#4a2a2a; }
  .muted { color:var(--dim); }
  .hint { color:var(--dim); font-size:12px; margin-top:8px; }
  code { color:var(--accent2); }
  .audit { max-height:240px; overflow:auto; font-size:12px; }
  .audit div { padding:3px 0; border-bottom:1px solid var(--panel2); }
</style>
</head>
<body>
<header>
  <h1>SecCert</h1><span class="tag">ACME CA console</span>
  <span id="pill" class="pill">connecting…</span>
</header>
<main>
  <section class="card">
    <h2>Certificate authority</h2>
    <dl class="kv" id="ca"><dd class="muted">loading…</dd></dl>
    <div class="row" style="margin-top:14px">
      <a class="btn" href="/ca.crt"><button class="ghost">Download Root (trust anchor)</button></a>
      <a class="btn" href="/intermediate.crt"><button class="ghost">Download Intermediate</button></a>
      <a class="btn" href="/crl"><button class="ghost">Download CRL</button></a>
    </div>
  </section>

  <section class="card">
    <h2>Admin access</h2>
    <div class="row">
      <input id="token" type="password" placeholder="admin token (SECCERT_ADMIN_TOKEN)" />
      <button id="connect">Connect</button>
      <button id="forget" class="ghost">Forget</button>
    </div>
    <div class="hint">The token gates the API below. Set <code>SECCERT_ADMIN_TOKEN</code>, or copy the one printed in the server log on first boot.</div>
  </section>

  <section class="card">
    <h2>Issued certificates <span id="counts" class="muted"></span></h2>
    <div id="certs"><div class="muted">connect with an admin token to list certificates</div></div>
  </section>

  <section class="card">
    <h2>Audit ledger</h2>
    <div id="audit" class="audit"><div class="muted">—</div></div>
  </section>
</main>
<script>
const $ = (id) => document.getElementById(id);
const tokenKey = "seccert_token";
let token = localStorage.getItem(tokenKey) || "";
$("token").value = token;

function pill(state, text) { const p=$("pill"); p.className="pill "+state; p.textContent=text; }
async function api(path, opts={}) {
  opts.headers = Object.assign({}, opts.headers, token ? {Authorization:"Bearer "+token} : {});
  const r = await fetch(path, opts);
  if (!r.ok) throw new Error(path+" → "+r.status);
  return r.json();
}
function esc(s){ return String(s).replace(/[&<>]/g, c=>({"&":"&amp;","<":"&lt;",">":"&gt;"}[c])); }
function shortSerial(s){ return s.length>18 ? s.slice(0,10)+"…"+s.slice(-6) : s; }

async function loadHealth() {
  try {
    const h = await fetch("/health").then(r=>r.json());
    pill("ok", "healthy");
    const c = h.ca;
    $("ca").innerHTML =
      row("Organization", "") +
      row("Root", esc(c.root.subject)) +
      row("Root SHA-256", esc(c.root.fingerprint_sha256)) +
      row("Root expires", esc(c.root.not_after)) +
      row("Intermediate", esc(c.intermediate.subject)) +
      row("Int. SHA-256", esc(c.intermediate.fingerprint_sha256)) +
      row("Int. expires", esc(c.intermediate.not_after));
  } catch(e) { pill("bad", "unreachable"); }
}
function row(k,v){ return "<dt>"+esc(k)+"</dt><dd>"+v+"</dd>"; }

async function loadCerts() {
  if (!token) return;
  try {
    const d = await api("/admin/api/certificates");
    $("counts").textContent = `· ${d.count} total, ${d.valid} valid, ${d.revoked} revoked`;
    if (!d.certificates.length) { $("certs").innerHTML='<div class="muted">no certificates issued yet</div>'; return; }
    let html = "<table><thead><tr><th>Serial</th><th>Names (SAN)</th><th>Status</th><th>Issued</th><th>Expires</th><th></th></tr></thead><tbody>";
    for (const c of d.certificates) {
      const revoke = c.status==="valid"
        ? `<button class="danger" onclick="revoke('${c.serial}')">Revoke</button>` : "";
      html += `<tr><td title="${esc(c.serial)}"><code>${esc(shortSerial(c.serial))}</code></td>`+
        `<td class="sans">${c.sans.map(esc).join("<br>")}</td>`+
        `<td><span class="badge ${c.status}">${c.status}</span></td>`+
        `<td class="muted">${esc((c.issued_at||"").slice(0,19))}</td>`+
        `<td class="muted">${esc((c.not_after||"").slice(0,10))}</td>`+
        `<td>${revoke}</td></tr>`;
    }
    $("certs").innerHTML = html+"</tbody></table>";
  } catch(e) {
    $("certs").innerHTML = '<div class="muted">'+esc(e.message)+' — check the admin token</div>';
  }
}
async function loadAudit() {
  if (!token) return;
  try {
    const d = await api("/admin/api/audit");
    $("audit").innerHTML = d.events.length
      ? d.events.map(e=>`<div><span class="muted">${esc((e.ts||'').slice(0,19))}</span> <code>${esc(e.event)}</code> ${esc(JSON.stringify(e.detail))}</div>`).join("")
      : '<div class="muted">no events</div>';
  } catch(e) { $("audit").innerHTML = '<div class="muted">'+esc(e.message)+'</div>'; }
}
async function revoke(serial) {
  if (!confirm("Revoke certificate "+serial+"?")) return;
  try { await api(`/admin/api/certificates/${serial}/revoke`, {method:"POST"}); loadCerts(); loadAudit(); }
  catch(e){ alert("Revoke failed: "+e.message); }
}
$("connect").onclick = () => { token=$("token").value.trim(); localStorage.setItem(tokenKey, token); loadCerts(); loadAudit(); };
$("forget").onclick = () => { token=""; localStorage.removeItem(tokenKey); $("token").value=""; $("certs").innerHTML='<div class="muted">disconnected</div>'; $("audit").innerHTML='<div class="muted">—</div>'; };
window.revoke = revoke;
loadHealth(); loadCerts(); loadAudit();
</script>
</body>
</html>
"""
