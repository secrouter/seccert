"""The SecCert admin console — a single self-contained HTML page (no external assets)."""

CONSOLE_HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>SecCert — CA Console</title>
<style>
  /* SecRouter suite "field console" theme — warm manila paper, olive drab, oxide red. System fonts only (air-gapped). */
  :root {
    --mono: ui-monospace, "SF Mono", SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace;
    --sans: ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
    /* light: warm manila "field console" */
    --bg:#e7e3d8; --panel:#f3f0e8; --panel2:#fbfaf4; --fg:#211f18; --muted:#6c6552;
    --accent:#4f6a2e; --accent-ink:#f6f3ea; --accent-soft:rgba(79,106,46,.18);
    --ok:#2f5a22; --warn:#8a5a12; --bad:#8a2b1d;
    --border:#cdc6b2; --rule:#dad4c2; --shadow:2px 2px 0 rgba(33,31,24,.06);
    --pill-bg:#e2ddcd; --pill-ok-bg:#e3ebd7; --pill-ok-bd:#b9c9a8;
    --pill-bad-bg:#f0ddd7; --pill-bad-bd:#d8b3aa; --pill-warn-bg:#efe6cf; --pill-warn-bd:#d8c69a;
    --code-bg:#e2ddcd;
  }
  /* dark: warm "night ops" — same identity, charcoal + brighter olive/terracotta */
  :root[data-theme="dark"] {
    --bg:#171511; --panel:#201e17; --panel2:#29271e; --fg:#e8e3d3; --muted:#9a9077;
    --accent:#94ad50; --accent-ink:#16140e; --accent-soft:rgba(148,173,80,.26);
    --ok:#86b257; --warn:#cb9c3e; --bad:#d4634c;
    --border:#3a3730; --rule:#272520; --shadow:2px 2px 0 rgba(0,0,0,.30);
    --pill-bg:#2b2920; --pill-ok-bg:#26331c; --pill-ok-bd:#3f5230;
    --pill-bad-bg:#37201a; --pill-bad-bd:#5c2f25; --pill-warn-bg:#332a17; --pill-warn-bd:#544321;
    --code-bg:#2b2920;
  }
  @media (prefers-color-scheme: dark) {
    :root:not([data-theme="light"]) {
      --bg:#171511; --panel:#201e17; --panel2:#29271e; --fg:#e8e3d3; --muted:#9a9077;
      --accent:#94ad50; --accent-ink:#16140e; --accent-soft:rgba(148,173,80,.26);
      --ok:#86b257; --warn:#cb9c3e; --bad:#d4634c;
      --border:#3a3730; --rule:#272520; --shadow:2px 2px 0 rgba(0,0,0,.30);
      --pill-bg:#2b2920; --pill-ok-bg:#26331c; --pill-ok-bd:#3f5230;
      --pill-bad-bg:#37201a; --pill-bad-bd:#5c2f25; --pill-warn-bg:#332a17; --pill-warn-bd:#544321;
      --code-bg:#2b2920;
    }
  }
  * { box-sizing:border-box; }
  body { margin:0; font:14px/1.55 var(--sans); background:var(--bg); color:var(--fg);
         background-image:linear-gradient(var(--rule) 1px, transparent 1px); background-size:100% 28px; background-attachment:fixed; }
  header { display:flex; align-items:center; gap:14px; padding:14px 22px; background:var(--panel);
           border-bottom:1px solid var(--border); border-top:3px solid var(--accent); }
  .logo-icon { display:block; }
  .logo-icon.logo-dark { display:none; }
  :root[data-theme="dark"] .logo-icon.logo-light { display:none; }
  :root[data-theme="dark"] .logo-icon.logo-dark { display:block; }
  @media (prefers-color-scheme: dark) {
    :root:not([data-theme="light"]) .logo-icon.logo-light { display:none; }
    :root:not([data-theme="light"]) .logo-icon.logo-dark { display:block; }
  }
  header h1 { font-size:15px; margin:0; font-weight:700; text-transform:uppercase; letter-spacing:.14em; }
  header h1 .sec { color:var(--accent); }
  header .tag { color:var(--muted); font:11px var(--mono); text-transform:uppercase; letter-spacing:.08em; }
  main { max-width:1080px; margin:0 auto; padding:24px 22px; display:grid; gap:18px; }
  .card { background:var(--panel); border:1px solid var(--border); border-radius:2px; padding:18px;
          box-shadow:var(--shadow); }
  .card h2 { font:11px var(--mono); font-weight:700; text-transform:uppercase; letter-spacing:.12em;
             color:var(--muted); margin:0 0 12px; display:flex; align-items:center; gap:8px;
             padding-bottom:8px; border-bottom:1px solid var(--rule); }
  .kv { display:grid; grid-template-columns:150px 1fr; gap:6px 14px; font-size:13px; }
  .kv dt { color:var(--muted); font:11px var(--mono); text-transform:uppercase; letter-spacing:.06em; }
  .kv dd { margin:0; word-break:break-all; font:13px var(--mono); }
  .row { display:flex; gap:10px; flex-wrap:wrap; align-items:center; }
  input[type=password], input[type=text] { background:var(--panel2); border:1px solid var(--border);
    color:var(--fg); padding:6px 9px; border-radius:2px; font:13px var(--mono); min-width:280px; }
  input[type=password]:focus, input[type=text]:focus { outline:none; border-color:var(--accent); box-shadow:0 0 0 2px var(--accent-soft); }
  button { background:var(--accent); color:var(--accent-ink); border:1px solid var(--accent); padding:7px 14px; border-radius:2px;
    font:11px var(--mono); font-weight:700; text-transform:uppercase; letter-spacing:.08em; cursor:pointer; }
  button:hover { filter:brightness(1.08); }
  button.ghost { background:var(--panel2); color:var(--fg); border-color:var(--border); }
  button.danger { background:transparent; color:var(--bad); border:1px solid var(--bad); }
  button.theme-toggle { padding:5px 11px; }
  a.btn { text-decoration:none; display:inline-block; }
  table { width:100%; border-collapse:collapse; font-size:13px; }
  th, td { text-align:left; padding:7px 10px; border-bottom:1px solid var(--rule); vertical-align:top; }
  td { font:12.5px var(--mono); }
  th { color:var(--muted); font:10px var(--mono); font-weight:700; text-transform:uppercase; letter-spacing:.1em; border-bottom:1px solid var(--border); }
  td.sans { max-width:320px; font:13px var(--sans); }
  .pill { margin-left:auto; display:inline-block; padding:2px 9px; border-radius:2px; font:10px var(--mono);
          text-transform:uppercase; letter-spacing:.06em; background:var(--pill-bg); color:var(--muted); border:1px solid var(--border); }
  .pill.ok { color:var(--ok); border-color:var(--pill-ok-bd); background:var(--pill-ok-bg); }
  .pill.bad { color:var(--bad); border-color:var(--pill-bad-bd); background:var(--pill-bad-bg); }
  .badge { display:inline-block; padding:2px 9px; border-radius:2px; font:10px var(--mono);
           text-transform:uppercase; letter-spacing:.06em; background:var(--pill-bg); color:var(--muted); border:1px solid var(--border); }
  .badge.valid { color:var(--ok); border-color:var(--pill-ok-bd); background:var(--pill-ok-bg); }
  .badge.revoked { color:var(--bad); border-color:var(--pill-bad-bd); background:var(--pill-bad-bg); }
  .muted { color:var(--muted); }
  .hint { color:var(--muted); font-size:12px; margin-top:8px; }
  code { background:var(--code-bg); color:var(--accent); padding:1px 5px; border-radius:2px; font:12px var(--mono); }
  .audit { max-height:240px; overflow:auto; font-size:12px; border:1px solid var(--border); border-radius:2px; background:var(--panel2); padding:4px 10px; }
  .audit div { padding:3px 0; border-bottom:1px solid var(--rule); font:12px var(--mono); }
  .audit div:last-child { border-bottom:none; }
</style>
<script>
  /* Apply the saved theme before first paint (no flash). Default = follow OS. */
  (function(){ try { var t = localStorage.getItem('secrouter-theme'); if (t === 'dark' || t === 'light') document.documentElement.setAttribute('data-theme', t); } catch (e) {} })();
</script>
</head>
<body>
<header>
  <svg class="logo-icon logo-light" viewBox="0 0 48 60" width="26" height="32" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
    <g transform="translate(4,5)">
      <polygon points="24,2 44,13 44,37 24,54 4,37 4,13" fill="none" stroke="#17140d" stroke-width="2" stroke-linejoin="round"/>
      <path d="M24 28 L24 14 M24 28 L14 38 M24 28 L34 38" stroke="#17140d" stroke-width="1.9"/>
      <path d="M24 14 L14 38 M24 14 L34 38 M14 38 L34 38" stroke="#17140d" stroke-width="1.4" stroke-opacity="0.4"/>
      <circle cx="24" cy="14" r="2.7" fill="#17140d"/><circle cx="14" cy="38" r="2.7" fill="#17140d"/><circle cx="34" cy="38" r="2.7" fill="#17140d"/>
      <circle cx="24" cy="28" r="4.4" fill="#54672f"/>
    </g>
  </svg>
  <svg class="logo-icon logo-dark" viewBox="0 0 48 60" width="26" height="32" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
    <g transform="translate(4,5)">
      <polygon points="24,2 44,13 44,37 24,54 4,37 4,13" fill="none" stroke="#f5f3ea" stroke-width="2" stroke-linejoin="round"/>
      <path d="M24 28 L24 14 M24 28 L14 38 M24 28 L34 38" stroke="#f5f3ea" stroke-width="1.9"/>
      <path d="M24 14 L14 38 M24 14 L34 38 M14 38 L34 38" stroke="#f5f3ea" stroke-width="1.4" stroke-opacity="0.4"/>
      <circle cx="24" cy="14" r="2.7" fill="#f5f3ea"/><circle cx="14" cy="38" r="2.7" fill="#f5f3ea"/><circle cx="34" cy="38" r="2.7" fill="#f5f3ea"/>
      <circle cx="24" cy="28" r="4.4" fill="#cdd6a6"/>
    </g>
  </svg>
  <h1><span class="sec">SEC</span>CERT</h1><span class="tag">ACME CA console</span>
  <span id="pill" class="pill">connecting…</span>
  <button id="themeToggle" class="ghost theme-toggle" title="Toggle light / dark">DARK</button>
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
      <span id="who" class="muted"></span>
      <button id="signin" class="ghost" style="display:none">Sign in with SecSSO</button>
      <button id="signout" class="ghost" style="display:none">Sign out</button>
      <input id="token" type="password" placeholder="admin token (SECCERT_ADMIN_TOKEN)" />
      <button id="connect">Connect</button>
      <button id="forget" class="ghost">Forget</button>
    </div>
    <div class="hint">The token gates the API below. Set <code>SECCERT_ADMIN_TOKEN</code>, or copy the one printed in the server log on first boot. When <code>SECCERT_OIDC_*</code> is configured, signing in with SecSSO (admin group membership required) works instead of the token.</div>
  </section>

  <section class="card">
    <h2>Issued certificates <span id="counts" class="muted"></span></h2>
    <div id="certs"><div class="muted">connect with an admin token to list certificates</div></div>
  </section>

  <section class="card">
    <h2>Audit ledger <span id="chainPill" class="pill"></span></h2>
    <div id="audit" class="audit"><div class="muted">—</div></div>
  </section>
</main>
<script>
const $ = (id) => document.getElementById(id);
const tokenKey = "seccert_token";
let token = localStorage.getItem(tokenKey) || "";
$("token").value = token;
let signedIn = false; // true once an SSO session cookie is active (no admin token needed then)

// ── Theme (light / dark, follows OS by default, choice persisted) ──
function effectiveTheme(){ var a=document.documentElement.getAttribute("data-theme"); if(a==="dark"||a==="light") return a; return (window.matchMedia && matchMedia("(prefers-color-scheme: dark)").matches) ? "dark" : "light"; }
function setTheme(t){ document.documentElement.setAttribute("data-theme", t); try { localStorage.setItem("secrouter-theme", t); } catch(e){} var b=$("themeToggle"); if(b) b.textContent = effectiveTheme()==="dark" ? "LIGHT" : "DARK"; }
function toggleTheme(){ setTheme(effectiveTheme()==="dark" ? "light" : "dark"); }
$("themeToggle").textContent = effectiveTheme()==="dark" ? "LIGHT" : "DARK";
$("themeToggle").onclick = toggleTheme;

function pill(state, text) { const p=$("pill"); p.className="pill "+state; p.textContent=text; }
// credentials:same-origin sends the SSO session cookie (when signed in); the admin token header is
// added only when a token is present (break-glass / bearer-only / SSO-off). Either satisfies require_admin.
async function api(path, opts={}) {
  opts.credentials = "same-origin";
  opts.headers = Object.assign({}, opts.headers, token ? {Authorization:"Bearer "+token} : {});
  const r = await fetch(path, opts);
  if (!r.ok) throw new Error(path+" → "+r.status);
  return r.json();
}
async function loadAuth(){ try { applyAuth(await fetch("/auth/status",{credentials:"same-origin"}).then(r=>r.json())); } catch(e){} }
function applyAuth(a){
  signedIn = !!(a && a.user);
  const admin = signedIn && a.user.admin;
  // Sign-in button only when the browser (BFF) login is available and we're not already signed in.
  $("signin").style.display = (a && a.sso && !signedIn) ? "" : "none";
  $("signout").style.display = signedIn ? "" : "none";
  // Hide the manual admin-token box once a session is active — the cookie authorizes the API.
  $("token").style.display = signedIn ? "none" : "";
  $("connect").style.display = signedIn ? "none" : "";
  $("who").textContent = signedIn
    ? ("signed in as "+(a.user.name||a.user.sub)+(admin?"":" — not a member of "+(a.admin_group||"the admin group")))
    : "";
  if (signedIn) { loadCerts(); loadAudit(); }
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
  if (!token && !signedIn) return;
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
  if (!token && !signedIn) return;
  try {
    const d = await api("/admin/api/audit");
    $("audit").innerHTML = d.events.length
      ? d.events.map(e=>`<div><span class="muted">${esc((e.ts||'').slice(0,19))}</span> <code>${esc(e.event)}</code>`+
          `${e.principal?` <span class="badge" title="acting principal">${esc(e.principal)}</span>`:""} ${esc(JSON.stringify(e.detail))}</div>`).join("")
      : '<div class="muted">no events</div>';
  } catch(e) { $("audit").innerHTML = '<div class="muted">'+esc(e.message)+'</div>'; }
  try {
    const v = await api("/admin/api/audit/verify");
    const p = $("chainPill");
    if (v.startedAtId == null) { p.className = "pill"; p.textContent = "no chained events yet"; }
    else if (v.ok) { p.className = "pill ok"; p.textContent = `chain intact (${v.checked} checked, from #${v.startedAtId})`; }
    else { p.className = "pill bad"; p.textContent = `chain BROKEN at #${v.brokenAtId}`; }
  } catch(e) { const p = $("chainPill"); p.className = "pill"; p.textContent = ""; }
}
async function revoke(serial) {
  if (!confirm("Revoke certificate "+serial+"?")) return;
  try { await api(`/admin/api/certificates/${serial}/revoke`, {method:"POST"}); loadCerts(); loadAudit(); }
  catch(e){ alert("Revoke failed: "+e.message); }
}
$("connect").onclick = () => { token=$("token").value.trim(); localStorage.setItem(tokenKey, token); loadCerts(); loadAudit(); };
$("forget").onclick = () => { token=""; localStorage.removeItem(tokenKey); $("token").value=""; $("certs").innerHTML='<div class="muted">disconnected</div>'; $("audit").innerHTML='<div class="muted">—</div>'; };
$("signin").onclick = () => { location.href = "/auth/login?next=/admin"; };
$("signout").onclick = () => { fetch("/auth/logout", {method:"POST", credentials:"same-origin"}).then(()=>location.reload()); };
window.revoke = revoke;
loadHealth(); loadAuth(); loadCerts(); loadAudit();
</script>
</body>
</html>
"""
