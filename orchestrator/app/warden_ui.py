"""Phone pages for passkey enrollment and Warden approval.

Static HTML + one JS file + one CSS file, so the CSP can forbid inline script.
Everything that came from telemetry or the LLM is written with textContent,
never innerHTML.
"""

_HEAD = """<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="dark light">
<title>{title}</title>
<link rel="stylesheet" href="/warden/static/warden.css">
<script src="/warden/static/warden.js" defer></script>
</head>"""

ENROLL_HTML = _HEAD.format(title="Enroll passkey · SOC Warden") + """
<body data-page="enroll">
<main>
  <header><span class="mark">◆</span> SOC Warden</header>
  <h1>Enroll a passkey</h1>
  <p class="muted">On the Hub, run
    <code>docker exec soc-orchestrator python -m app.passkeys enroll-code</code>
    and paste the code here. It works once and expires in 15 minutes.</p>
  <div id="insecure" class="banner bad" hidden></div>
  <label for="code">Enrollment code</label>
  <input id="code" autocomplete="one-time-code" autocapitalize="off" spellcheck="false">
  <label for="label">Name for this passkey</label>
  <input id="label" value="My phone" maxlength="64">
  <button id="enroll" class="primary">Create passkey</button>
  <div id="status" class="status" role="status" aria-live="polite"></div>
</main>
</body></html>
"""

APPROVE_HTML = _HEAD.format(title="Approve action · SOC Warden") + """
<body data-page="approve">
<main>
  <header><span class="mark">◆</span> SOC Warden</header>
  <h1>Approval required</h1>
  <div id="insecure" class="banner bad" hidden></div>
  <section id="details" class="card" hidden>
    <div class="row"><span>Endpoint</span><code id="d-endpoint"></code></div>
    <div class="row"><span>Action</span><code id="d-action"></code></div>
    <div class="row"><span>Target</span><code id="d-target"></code></div>
    <div class="row"><span>Threat score</span><strong id="d-score"></strong></div>
    <div class="row"><span>Expires in</span><strong id="d-ttl"></strong></div>
    <p class="sigs-title">Why</p>
    <ul id="d-sigs"></ul>
  </section>
  <p class="muted">Approving signs an execution order for exactly this action.
    Your passkey will ask for your fingerprint or PIN.</p>
  <div class="actions">
    <button id="approve" class="primary danger" disabled>Approve with passkey</button>
    <button id="deny" disabled>Deny</button>
  </div>
  <div id="status" class="status" role="status" aria-live="polite"></div>
</main>
</body></html>
"""

WARDEN_CSS = """
:root{--bg:#0b0d10;--card:#151a20;--fg:#e8edf2;--muted:#94a3b8;--line:#263040;
--accent:#3b82f6;--danger:#dc2626;--ok:#16a34a;--warn:#f59e0b}
@media (prefers-color-scheme: light){:root{--bg:#f6f7f9;--card:#fff;--fg:#0f172a;
--muted:#475569;--line:#dbe1e8}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);
font:16px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:30rem;margin:0 auto;padding:1.25rem 1rem 3rem}
header{font-weight:600;letter-spacing:.02em;color:var(--muted);margin-bottom:1rem}
.mark{color:var(--accent)}
h1{font-size:1.5rem;margin:.25rem 0 1rem}
.muted{color:var(--muted);font-size:.95rem}
code{font:.9em ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;word-break:break-all}
label{display:block;margin:1rem 0 .35rem;font-weight:600}
input{width:100%;padding:.8rem;border-radius:.6rem;border:1px solid var(--line);
background:var(--card);color:var(--fg);font:inherit}
button{width:100%;padding:.95rem;margin-top:1rem;border-radius:.7rem;
border:1px solid var(--line);background:var(--card);color:var(--fg);
font:600 1rem/1 inherit;cursor:pointer}
button.primary{background:var(--accent);border-color:var(--accent);color:#fff}
button.danger{background:var(--danger);border-color:var(--danger)}
button:disabled{opacity:.45;cursor:not-allowed}
.actions{display:grid;gap:.25rem}
.card{background:var(--card);border:1px solid var(--line);border-radius:.8rem;padding:1rem}
.row{display:flex;justify-content:space-between;gap:1rem;padding:.4rem 0;
border-bottom:1px solid var(--line)}
.row span{color:var(--muted)}
.sigs-title{margin:.75rem 0 .25rem;color:var(--muted)}
ul{margin:0;padding-left:1.2rem}
.banner{padding:.8rem 1rem;border-radius:.6rem;margin:1rem 0}
.bad{background:color-mix(in srgb,var(--danger) 18%,transparent);border:1px solid var(--danger)}
.status{margin-top:1rem;min-height:1.5rem;font-weight:600}
.status.ok{color:var(--ok)}.status.err{color:var(--danger)}.status.wait{color:var(--warn)}
"""

WARDEN_JS = r"""
"use strict";
const $ = (id) => document.getElementById(id);
const enc = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)))
  .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const dec = (s) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")
  + "===".slice((s.length + 3) % 4)), (c) => c.charCodeAt(0));

function say(text, kind) { const s = $("status"); s.textContent = text; s.className = "status " + (kind || ""); }

async function api(path, body) {
  const r = await fetch(path, {
    method: body === undefined ? "GET" : "POST",
    headers: body === undefined ? {} : { "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
    credentials: "omit", cache: "no-store",
  });
  let data = null;
  try { data = await r.json(); } catch (_) {}
  if (!r.ok) {
    const d = data && data.detail;
    throw new Error(typeof d === "string" ? d : ("HTTP " + r.status));
  }
  return data;
}

function secureOrWarn() {
  if (window.isSecureContext && window.PublicKeyCredential) return true;
  const b = $("insecure");
  b.hidden = false;
  b.textContent = "Passkeys only work over HTTPS. Open this page at the Hub's https://…ts.net address.";
  return false;
}

// ---------------- enrollment ----------------
async function enroll() {
  const btn = $("enroll");
  btn.disabled = true;
  try {
    say("Checking code…", "wait");
    const { session_id, options } = await api("/warden/webauthn/register/options",
      { code: $("code").value.trim() });
    options.challenge = dec(options.challenge);
    options.user.id = dec(options.user.id);
    (options.excludeCredentials || []).forEach((c) => (c.id = dec(c.id)));

    say("Follow the prompt on your phone…", "wait");
    const cred = await navigator.credentials.create({ publicKey: options });
    const r = cred.response;
    const credential = {
      id: cred.id, rawId: enc(cred.rawId), type: cred.type,
      response: {
        clientDataJSON: enc(r.clientDataJSON),
        attestationObject: enc(r.attestationObject),
        transports: r.getTransports ? r.getTransports() : [],
      },
      clientExtensionResults: cred.getClientExtensionResults(),
      authenticatorAttachment: cred.authenticatorAttachment || undefined,
    };
    const saved = await api("/warden/webauthn/register/verify",
      { session_id, label: $("label").value.trim(), credential });
    say("Enrolled “" + saved.label + "” (" + saved.device_type + "). You can close this page.", "ok");
  } catch (e) {
    say(e.name === "NotAllowedError" ? "Cancelled or timed out." : ("Failed: " + e.message), "err");
    btn.disabled = false;
  }
}

// ---------------- approval ----------------
const challengeId = decodeURIComponent(location.pathname.split("/").pop() || "");
let ttlTimer = null;

async function loadPending() {
  try {
    const p = await api("/warden/pending/" + encodeURIComponent(challengeId));
    $("d-endpoint").textContent = p.endpoint_id;
    $("d-action").textContent = p.action;
    $("d-target").textContent = p.action === "quarantine_file"
      ? p.target_path + " (sha256 " + String(p.target_sha256).slice(0, 12) + "…)"
      : p.action === "deploy_release" ? p.target_path + " (manifest " + String(p.target_sha256).slice(0, 12) + "…)"
      : (p.target_ip || "none identified");
    $("d-score").textContent = p.action === "deploy_release" ? "— (agent update)" : p.threat_score + " / 100";
    const ul = $("d-sigs");
    ul.replaceChildren(...(p.attack_signatures.length ? p.attack_signatures : ["—"]).map((s) => {
      const li = document.createElement("li"); li.textContent = s; return li;
    }));
    let left = p.seconds_left;
    const tick = () => {
      $("d-ttl").textContent = left + " s";
      if (left-- <= 0) { clearInterval(ttlTimer); lock("Expired. Nothing was executed.", "err"); }
    };
    tick(); ttlTimer = setInterval(tick, 1000);
    $("details").hidden = false;
    $("approve").disabled = !secureOrWarn();
    $("deny").disabled = false;
  } catch (e) {
    say("This request is no longer pending (" + e.message + ").", "err");
  }
}

function lock(text, kind) {
  $("approve").disabled = true; $("deny").disabled = true;
  if (ttlTimer) clearInterval(ttlTimer);
  say(text, kind);
}

async function approve() {
  $("approve").disabled = true; $("deny").disabled = true;
  try {
    say("Preparing…", "wait");
    const options = await api("/warden/webauthn/auth/options", { challenge_id: challengeId });
    options.challenge = dec(options.challenge);
    (options.allowCredentials || []).forEach((c) => (c.id = dec(c.id)));

    say("Confirm with your fingerprint or PIN…", "wait");
    const cred = await navigator.credentials.get({ publicKey: options });
    const r = cred.response;
    const res = await api("/warden/verify-fido2", {
      challenge_id: challengeId,
      webauthn_assertion: {
        credential_id: cred.id,
        client_data_json: enc(r.clientDataJSON),
        authenticator_data: enc(r.authenticatorData),
        signature: enc(r.signature),
        user_handle: r.userHandle && r.userHandle.byteLength ? enc(r.userHandle) : null,
      },
    });
    lock(res.order.action === "deploy_release"
      ? "Approved release #" + res.order.seq + ". Endpoints install it the next time they check in."
      : "Approved. Signed order " + res.order.order_id + " for " + res.order.action
        + " " + (res.order.target_ip || "") + ".", "ok");
  } catch (e) {
    if (e.name === "NotAllowedError") {
      // The browser prompt was cancelled before anything was sent: still pending.
      say("Cancelled. The request is still pending.", "wait");
      $("approve").disabled = false; $("deny").disabled = false;
    } else {
      lock("Not approved: " + e.message, "err");
    }
  }
}

async function deny() {
  $("approve").disabled = true; $("deny").disabled = true;
  try { await api("/warden/deny/" + encodeURIComponent(challengeId), {}); lock("Denied. Nothing was executed.", "ok"); }
  catch (e) { lock("Deny failed: " + e.message, "err"); }
}

document.addEventListener("DOMContentLoaded", () => {
  const page = document.body.dataset.page;
  if (page === "enroll") {
    const ok = secureOrWarn();
    $("enroll").disabled = !ok;
    $("enroll").addEventListener("click", enroll);
  } else if (page === "approve") {
    $("approve").addEventListener("click", approve);
    $("deny").addEventListener("click", deny);
    loadPending();
  }
});
"""
