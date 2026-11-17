"""SOC Hub dashboard: one HTML page, one JS file, one CSS file.

Dark gray + purple. The agents are the centerpiece: what each one is doing now,
what it did last, and every batch flowing through them. Then devices, the test
lab, trends and history.

Served under the same strict CSP as the Warden pages (no inline script or style,
no third-party origins). Charts are hand-drawn SVG. Everything that came from
telemetry or the LLM is written with textContent, never innerHTML.
"""

DASHBOARD_HTML = """<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="dark">
<meta name="referrer" content="no-referrer">
<title>SOC Hub</title>
<link rel="stylesheet" href="/dashboard/static/dashboard.css">
<script src="/dashboard/static/dashboard.js" defer></script>
</head>
<body>
<header class="top">
  <div class="brand">
    <span class="logo" aria-hidden="true">◆</span>
    <div><div class="brand-name">SOC Hub</div><div class="brand-sub">Zero-trust AI security operations</div></div>
  </div>
  <div id="headline" class="headline" role="status" aria-live="polite"></div>
  <div class="who"><span id="who" class="who-chip" hidden></span><button id="logout" class="ghost" hidden>Sign out</button></div>
</header>
<nav id="nav" class="nav" hidden aria-label="Sections">
  <a href="#agents">Agents</a><a href="#devices">Devices</a><a href="#testlab">Test lab</a>
  <a href="#trends">Trends</a><a href="#history">History</a>
</nav>

<main>
  <section id="login" class="login card" hidden>
    <div class="login-logo" aria-hidden="true">◆</div>
    <h1>Welcome back</h1>
    <p class="sub">Sign in with the passkey that approves Warden actions.
      On a PC, pick <em>Use a phone or tablet</em> and scan the code with your Pixel.</p>
    <div id="insecure" class="banner bad" hidden></div>
    <button id="signin" class="primary big">Sign in with passkey</button>
    <div id="login-status" class="status" role="status" aria-live="polite"></div>
  </section>

  <div id="app" hidden>
    <section id="pending-wrap" class="pending-wrap" hidden aria-live="polite">
      <div id="pending" class="pending-list"></div>
    </section>

    <section id="agents" class="section">
      <div class="section-head">
        <div><h2>Your AI agents</h2>
          <p class="sub">Every batch of telemetry flows left to right through these agents. Live, updated every few seconds.</p></div>
      </div>
      <div id="flow" class="flow"></div>
      <div class="card feed-card">
        <div class="card-head"><h3>Live pipeline</h3><span class="sub small">Latest batches and what each agent decided. Click one for details.</span></div>
        <ol id="feed" class="feed"></ol>
      </div>
    </section>

    <section id="devices" class="section">
      <div class="section-head"><div><h2>Devices &amp; services</h2>
        <p class="sub">Everything that takes part in your SOC, what role it plays and what it's doing now.</p></div></div>
      <div id="devgrid" class="devgrid"></div>
    </section>

    <section id="testlab" class="section">
      <div class="section-head">
        <div><h2>Test lab</h2>
          <p class="sub">Fire a fake attack through the real agents and check each one did its job.
            Tests use a virtual endpoint and documentation-only IPs, so nothing real is ever blocked.</p></div>
        <div class="lab-actions"><span id="lab-msg" class="lab-msg" role="status" aria-live="polite"></span>
          <button id="run-all" class="primary">Run all tests</button></div>
      </div>
      <div id="scenarios" class="scenarios"></div>
      <div id="results" class="results"></div>
    </section>

    <section id="trends" class="section">
      <div class="section-head"><div><h2>Trends</h2><p class="sub">Real traffic only (test attacks excluded)</p></div></div>
      <div id="kpis" class="kpis"></div>
      <div class="grid two">
        <article class="card">
          <h3>Telemetry per minute</h3>
          <p class="sub small">Connections received from all endpoints, last 60 minutes</p>
          <div class="chart" id="chart-volume"></div>
          <details><summary>View as table</summary><div id="table-volume" class="tablewrap"></div></details>
        </article>
        <article class="card">
          <h3>Highest threat score per minute</h3>
          <p class="sub small">At or above <strong id="thr"></strong> the Warden pauses and asks for your passkey</p>
          <div class="chart" id="chart-score"></div>
          <details><summary>View as table</summary><div id="table-score" class="tablewrap"></div></details>
        </article>
      </div>
    </section>

    <section id="history" class="section">
      <div class="section-head"><div><h2>History</h2></div></div>
      <div class="grid two wide-left">
        <article class="card"><h3>Activity</h3><ol id="timeline" class="timeline"></ol></article>
        <div class="stack">
          <article class="card">
            <h3>Blocked IPs</h3>
            <p class="sub small">To remove one, run <code>shipper.py --unblock IP</code> on that endpoint.</p>
            <div id="blocks" class="tablewrap"></div>
          </article>
          <article class="card">
            <h3>New connections</h3>
            <p class="sub small">First time a process was seen talking to this address</p>
            <ul id="newconns" class="conns"></ul>
          </article>
        </div>
      </div>
      <details class="card system">
        <summary>Settings, keys &amp; passkeys</summary>
        <div class="grid two"><dl id="system" class="kv"></dl><div><h3>Passkeys</h3><ul id="passkeys" class="plain"></ul></div></div>
      </details>
    </section>

    <footer id="foot" class="foot"></footer>
  </div>
</main>
<div id="tip" class="tip" role="tooltip" hidden></div>
<aside id="live" class="live" hidden aria-label="Live test view">
  <div class="live-head">
    <span class="live-dot" id="live-dot" aria-hidden="true"></span>
    <span id="live-title" class="live-title">Live test</span>
    <span id="live-progress" class="live-prog"></span>
    <button id="live-min" class="icon-btn" aria-label="Minimize live view" title="Minimize">–</button>
    <button id="live-close" class="icon-btn" aria-label="Close live view" title="Close">×</button>
  </div>
  <div id="live-path" class="live-path" aria-label="Path through the agents"></div>
  <div id="live-body" class="live-body">
    <div id="live-attack" class="live-attack"></div>
    <ol id="live-log" class="live-log" aria-live="polite"></ol>
  </div>
  <div id="live-foot" class="live-foot"></div>
</aside>
</body></html>
"""

DASHBOARD_CSS = """
:root{color-scheme:dark;
--bg:#0d0c11;--surface:#16141d;--surface2:#1c1925;--raised:#221e2d;--line:#2a2636;--line2:#3a3349;
--text:#eeeaf6;--text2:#b9b1ca;--muted:#8a829f;
--purple:#8b5cf6;--purple2:#a78bfa;--purple-ink:#c4b5fd;--purple-wash:rgba(139,92,246,.14);--purple-deep:#5b3fc4;
--series:#9085e9;--series-wash:rgba(144,133,233,.14);
--good:#0ca30c;--good-ink:#5fd35f;--warning:#fab219;--warn-ink:#fcc64f;--serious:#ec835a;
--critical:#d03b3b;--critical-ink:#f07878;
--radius:14px;--shadow:0 1px 0 rgba(255,255,255,.03) inset,0 8px 24px rgba(0,0,0,.25)}
*{box-sizing:border-box}
html{scroll-behavior:smooth;scroll-padding-top:110px}
html,body{margin:0;background:var(--bg);color:var(--text)}
body{font:14px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;
background:radial-gradient(1200px 500px at 15% -10%,rgba(139,92,246,.13),transparent 60%),
radial-gradient(900px 400px at 100% 0,rgba(91,63,196,.10),transparent 60%),var(--bg);background-attachment:fixed}
a{color:var(--purple-ink)}
code,.mono{font:12.5px/1.4 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
h1{font-size:1.6rem;margin:.25rem 0 .5rem}
h2{font-size:1.35rem;margin:0;font-weight:700;letter-spacing:-.01em}
h3{font-size:.98rem;margin:0 0 .2rem;font-weight:650}
.sub{margin:.2rem 0 0;color:var(--text2)}
.small{font-size:.83rem}
.muted{color:var(--muted)}
/* header */
.top{position:sticky;top:0;z-index:10;display:flex;gap:1rem;align-items:center;flex-wrap:wrap;
padding:.75rem 1.5rem;background:rgba(13,12,17,.82);backdrop-filter:blur(10px);border-bottom:1px solid var(--line)}
.brand{display:flex;gap:.7rem;align-items:center}
.logo{display:grid;place-items:center;width:2.1rem;height:2.1rem;border-radius:10px;color:#fff;font-size:1rem;
background:linear-gradient(135deg,var(--purple),var(--purple-deep));box-shadow:0 4px 14px rgba(139,92,246,.35)}
.brand-name{font-weight:750;letter-spacing:.01em}
.brand-sub{color:var(--muted);font-size:.75rem}
.headline{flex:1;display:flex;justify-content:center}
.hl{display:inline-flex;align-items:center;gap:.5rem;padding:.35rem .9rem;border-radius:999px;font-weight:600;font-size:.85rem;
background:var(--surface2);border:1px solid var(--line2)}
.hl.alert{border-color:var(--critical);background:rgba(208,59,59,.14)}
.hl.busy{border-color:var(--purple);background:var(--purple-wash)}
.who{display:flex;gap:.6rem;align-items:center}
.who-chip{color:var(--text2);font-size:.82rem;padding:.25rem .6rem;border-radius:999px;background:var(--surface2);border:1px solid var(--line)}
.nav{position:sticky;top:3.6rem;z-index:9;display:flex;gap:.25rem;justify-content:center;flex-wrap:wrap;padding:.4rem 1rem;
background:rgba(13,12,17,.75);backdrop-filter:blur(10px);border-bottom:1px solid var(--line)}
.nav a{color:var(--text2);text-decoration:none;padding:.3rem .8rem;border-radius:999px;font-size:.85rem;font-weight:600}
.nav a:hover{background:var(--surface2);color:var(--text)}
main{max-width:1440px;margin:0 auto;padding:1.25rem 1.5rem 3rem}
.section{margin-top:2rem}
.section:first-of-type{margin-top:.5rem}
.section-head{display:flex;justify-content:space-between;align-items:flex-end;gap:1rem;margin-bottom:1rem;flex-wrap:wrap}
.card{background:linear-gradient(180deg,var(--surface2),var(--surface));border:1px solid var(--line);border-radius:var(--radius);
padding:1.1rem 1.2rem;min-width:0;box-shadow:var(--shadow)}
.card-head{display:flex;align-items:baseline;gap:.75rem;flex-wrap:wrap;margin-bottom:.6rem}
.grid{display:grid;gap:1rem}
.grid.two{grid-template-columns:repeat(2,minmax(0,1fr))}
.grid.wide-left{grid-template-columns:minmax(0,1.5fr) minmax(0,1fr)}
.stack{display:grid;gap:1rem;align-content:start}
@media (max-width:980px){.grid.two,.grid.wide-left{grid-template-columns:1fr}}
/* buttons */
button,.btn{display:inline-flex;align-items:center;justify-content:center;gap:.4rem;padding:.55rem 1rem;border-radius:10px;
border:1px solid var(--line2);background:var(--raised);color:var(--text);font:600 .88rem/1 inherit;cursor:pointer;
text-decoration:none;transition:transform .08s,background .15s,border-color .15s}
button:hover,.btn:hover{border-color:var(--purple2)}
button:active,.btn:active{transform:translateY(1px)}
button.primary,.btn.primary{background:linear-gradient(135deg,var(--purple),var(--purple-deep));border-color:transparent;color:#fff;
box-shadow:0 4px 14px rgba(139,92,246,.3)}
.btn.danger{background:var(--critical);border-color:var(--critical);color:#fff;box-shadow:none}
button.ghost{background:transparent;padding:.4rem .75rem;font-size:.82rem}
button.big{width:100%;padding:.9rem;font-size:1rem;margin-top:.75rem}
button:disabled{opacity:.5;cursor:not-allowed;transform:none}
/* login */
.login{max-width:27rem;margin:11vh auto 0;text-align:center;padding:2rem}
.login-logo{display:grid;place-items:center;width:3.2rem;height:3.2rem;margin:0 auto .5rem;border-radius:14px;color:#fff;font-size:1.4rem;
background:linear-gradient(135deg,var(--purple),var(--purple-deep));box-shadow:0 8px 24px rgba(139,92,246,.4)}
.banner{padding:.7rem .9rem;border-radius:10px;margin:.75rem 0;text-align:left}
.bad{border:1px solid var(--critical);background:rgba(208,59,59,.12)}
.status{margin-top:.75rem;min-height:1.3rem;font-weight:600}
.status.ok{color:var(--good-ink)}.status.err{color:var(--critical-ink)}.status.wait{color:var(--text2)}
/* badges, dots */
.dot{display:inline-block;width:.55rem;height:.55rem;border-radius:50%;flex:none;background:var(--muted)}
.dot.good{background:var(--good)}.dot.warn{background:var(--warning)}.dot.bad{background:var(--critical)}
.dot.purple{background:var(--purple2)}
.dot.pulse{animation:pulse 1.4s ease-out infinite}
@keyframes pulse{0%{box-shadow:0 0 0 0 rgba(167,139,250,.6)}100%{box-shadow:0 0 0 8px rgba(167,139,250,0)}}
.tag{display:inline-flex;align-items:center;gap:.3rem;padding:.12rem .5rem;border-radius:999px;font-size:.74rem;font-weight:600;
background:var(--surface);border:1px solid var(--line2);color:var(--text2);white-space:nowrap}
.tag.test{background:var(--purple-wash);border-color:var(--purple);color:var(--purple-ink)}
.tag.crit{border-color:var(--critical);color:var(--critical-ink);background:rgba(208,59,59,.12)}
.tag.warn{border-color:var(--warning);color:var(--warn-ink)}
.tag.good{border-color:var(--good);color:var(--good-ink)}
.score{display:inline-grid;place-items:center;min-width:2.3rem;padding:.1rem .45rem;border-radius:8px;font-weight:700;
font-variant-numeric:tabular-nums;border:1px solid var(--line2);background:var(--surface)}
.score.crit{border-color:var(--critical);color:var(--critical-ink);background:rgba(208,59,59,.12)}
.score.serious{border-color:var(--serious);color:#f4a685}
/* pending approvals */
.pending-wrap{margin:.25rem 0 1rem}
.pending-list{display:grid;gap:.75rem}
.pcard{display:grid;grid-template-columns:auto 1fr auto;gap:1.25rem;align-items:center;padding:1rem 1.25rem;border-radius:var(--radius);
border:1.5px solid var(--critical);background:linear-gradient(90deg,rgba(208,59,59,.16),var(--surface) 55%)}
.pcard.test{border-color:var(--purple);background:linear-gradient(90deg,var(--purple-wash),var(--surface) 55%)}
.pcard .big-score{font-size:2.2rem;font-weight:800;line-height:1}
.pcard .big-score small{font-size:.8rem;color:var(--text2);font-weight:500;display:block;text-align:center}
.pcard .what{font-weight:650}
.pcard ul{margin:.3rem 0 0;padding-left:1.1rem;color:var(--text2);font-size:.85rem}
.pcard .side{display:grid;gap:.5rem;justify-items:end}
.pcard .ttl{font:700 1.05rem/1 ui-monospace,Consolas,monospace;color:var(--critical-ink)}
.pcard.test .ttl{color:var(--purple-ink)}
.pcard .actions{display:flex;gap:.5rem}
@media (max-width:760px){.pcard{grid-template-columns:1fr}.pcard .side{justify-items:start}}
/* agent flow */
.flow{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:1.4rem;position:relative;margin-bottom:1rem}
@media (max-width:1200px){.flow{grid-template-columns:repeat(3,minmax(0,1fr))}}
@media (max-width:760px){.flow{grid-template-columns:1fr}}
.agent{position:relative;display:flex;flex-direction:column;gap:.6rem;padding:1rem 1rem .9rem;border-radius:var(--radius);
background:linear-gradient(180deg,var(--surface2),var(--surface));border:1px solid var(--line);box-shadow:var(--shadow);
transition:border-color .3s,box-shadow .3s}
.agent:not(:last-child)::after{content:"›";position:absolute;right:-1.05rem;top:2.1rem;color:var(--purple2);font-size:1.5rem;
font-weight:700;opacity:.7}
@media (max-width:1200px){.agent::after{display:none}}
.agent.active{border-color:var(--purple);box-shadow:0 0 0 1px var(--purple),0 0 28px rgba(139,92,246,.35)}
.agent.alert{border-color:var(--critical);box-shadow:0 0 0 1px var(--critical),0 0 24px rgba(208,59,59,.25)}
.agent-top{display:flex;gap:.7rem;align-items:center}
.agent-ic{display:grid;place-items:center;width:2.6rem;height:2.6rem;border-radius:12px;font-size:1.3rem;flex:none;
background:linear-gradient(135deg,rgba(139,92,246,.35),rgba(91,63,196,.2));border:1px solid rgba(167,139,250,.35)}
.agent-name{font-weight:700;font-size:1rem}
.agent-role{color:var(--muted);font-size:.78rem;line-height:1.3}
.agent-state{display:flex;align-items:center;gap:.4rem;font-size:.8rem;font-weight:650;color:var(--text2)}
.agent-now{font-size:.85rem;color:var(--text);min-height:3.8em;overflow-wrap:anywhere;
display:-webkit-box;-webkit-line-clamp:4;-webkit-box-orient:vertical;overflow:hidden}
.agent-when{font-size:.75rem;color:var(--muted)}
.agent-stats{display:grid;grid-template-columns:repeat(3,1fr);gap:.4rem;padding-top:.6rem;border-top:1px solid var(--line);margin-top:auto}
.agent-stats div{min-width:0}
.agent-stats b{display:block;font-size:1.05rem;font-variant-numeric:tabular-nums}
.agent-stats span{display:block;font-size:.7rem;color:var(--muted);line-height:1.2}
/* live feed */
.feed{list-style:none;margin:0;padding:0;max-height:440px;overflow:auto}
.feed>li{border-bottom:1px solid var(--line)}
.feed>li:last-child{border-bottom:0}
.run{display:grid;grid-template-columns:5.2rem minmax(7rem,11rem) 1fr auto;gap:.8rem;align-items:center;width:100%;padding:.55rem .25rem;
background:none;border:0;border-radius:8px;color:inherit;font:inherit;text-align:left;cursor:pointer}
.run:hover{background:var(--surface2)}
.run .t{color:var(--muted);font-size:.8rem;font-variant-numeric:tabular-nums}
.run .ep{display:flex;gap:.35rem;align-items:center;min-width:0}
.run .ep code{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.stages{display:flex;gap:.35rem;flex-wrap:wrap;align-items:center}
.stage{display:inline-flex;align-items:center;gap:.3rem;padding:.15rem .5rem;border-radius:8px;font-size:.76rem;
background:var(--surface);border:1px solid var(--line2);color:var(--text2);white-space:nowrap}
.stage.alert,.stage.warn{border-color:var(--warning);color:var(--warn-ink)}
.stage.crit{border-color:var(--critical);color:var(--critical-ink);background:rgba(208,59,59,.1)}
.stage .arr{color:var(--muted)}
.run-detail{margin:0 0 .6rem;padding:.6rem .8rem;border-radius:10px;background:var(--surface);border:1px solid var(--line)}
.run-detail div{display:grid;grid-template-columns:7rem 1fr;gap:.6rem;padding:.25rem 0;font-size:.84rem}
.run-detail b{color:var(--purple-ink)}
@media (max-width:760px){.run{grid-template-columns:1fr auto}.run .stages{grid-column:1/-1}}
/* devices */
.devgrid{display:grid;gap:1rem;grid-template-columns:repeat(auto-fill,minmax(270px,1fr))}
.dev{display:flex;flex-direction:column;gap:.6rem}
.dev-top{display:flex;gap:.75rem;align-items:center}
.dev-ic{display:grid;place-items:center;width:2.6rem;height:2.6rem;border-radius:12px;font-size:1.3rem;background:var(--raised);border:1px solid var(--line2);flex:none}
.dev-name{font-weight:700;overflow-wrap:anywhere}
.dev-status{display:flex;align-items:center;gap:.4rem;font-size:.8rem;color:var(--text2)}
.dev-tags{display:flex;gap:.35rem;flex-wrap:wrap}
.dev-doing{font-size:.86rem;padding:.55rem .7rem;border-radius:10px;background:var(--surface);border:1px solid var(--line)}
.dev-doing b{display:block;font-size:.72rem;color:var(--muted);font-weight:600;text-transform:uppercase;letter-spacing:.04em;margin-bottom:.1rem}
.dev-meta{font-size:.78rem;color:var(--muted)}
/* test lab */
.scenarios{display:grid;gap:1rem;grid-template-columns:repeat(3,minmax(0,1fr))}
@media (max-width:1000px){.scenarios{grid-template-columns:repeat(2,minmax(0,1fr))}}
@media (max-width:620px){.scenarios{grid-template-columns:1fr}}
.results .result-grid{display:grid;gap:.75rem;grid-template-columns:repeat(2,minmax(0,1fr))}
@media (max-width:980px){.results .result-grid{grid-template-columns:1fr}}
.lab-actions{display:flex;gap:.75rem;align-items:center;flex-wrap:wrap;justify-content:flex-end}
.lab-msg{font-size:.84rem;color:var(--warn-ink);max-width:28rem;text-align:right}
.scn{display:flex;flex-direction:column;gap:.55rem}
.scn-top{display:flex;gap:.6rem;align-items:center}
.scn-ic{font-size:1.5rem}
.scn-name{font-weight:700}
.scn p{margin:0;color:var(--text2);font-size:.85rem}
.scn .exp{font-size:.8rem;color:var(--muted)}
.scn .agents{display:flex;gap:.3rem;flex-wrap:wrap}
.scn-foot{display:flex;justify-content:space-between;align-items:center;gap:.5rem;margin-top:auto;padding-top:.5rem;border-top:1px solid var(--line)}
.results{display:grid;gap:.75rem;margin-top:1rem}
.result{border-left:3px solid var(--line2)}
.result.passed{border-left-color:var(--good)}.result.failed,.result.error{border-left-color:var(--critical)}
.result.running{border-left-color:var(--purple)}
.result-head{display:flex;gap:.6rem;align-items:center;flex-wrap:wrap}
.result-head .name{font-weight:700}
.checks{list-style:none;margin:.6rem 0 0;padding:0;display:grid;gap:.3rem}
.checks li{display:grid;grid-template-columns:1.4rem 1fr;gap:.4rem;font-size:.86rem}
.checks .ck{font-weight:800;text-align:center}
.checks .ok{color:var(--good-ink)}.checks .no{color:var(--critical-ink)}.checks .na{color:var(--muted)}
.checks .d{color:var(--muted);font-size:.78rem;margin-left:.3rem}
.stepper{display:flex;gap:0;margin-top:.8rem;flex-wrap:wrap}
.step{flex:1;min-width:120px;position:relative;padding:1.55rem .75rem .2rem 0;font-size:.8rem;color:var(--muted)}
.step::before{content:"";position:absolute;left:0;top:0;width:1rem;height:1rem;border-radius:50%;border:2px solid var(--line2);
background:var(--bg);box-sizing:border-box}
.step::after{content:"";position:absolute;left:1.3rem;right:.3rem;top:.45rem;height:2px;background:var(--line2)}
.step:last-child::after{display:none}
.step.done{color:var(--text)}
.step.done::before{background:var(--purple);border-color:var(--purple)}
.step.done::after{background:var(--purple)}
.step.now{color:var(--purple-ink);font-weight:650}
.step.now::before{border-color:var(--purple2);animation:pulse 1.4s ease-out infinite}
.step.fail{color:var(--critical-ink)}
.step.fail::before{background:var(--critical);border-color:var(--critical)}
.followup-note{margin-top:.4rem;font-size:.82rem;color:var(--text2)}
.followup-actions{display:flex;gap:.5rem;margin-top:.6rem;flex-wrap:wrap;align-items:center}
/* KPIs */
.kpis{display:grid;gap:1rem;grid-template-columns:repeat(6,minmax(0,1fr));margin-bottom:1rem}
@media (max-width:1100px){.kpis{grid-template-columns:repeat(3,minmax(0,1fr))}}
@media (max-width:560px){.kpis{grid-template-columns:repeat(2,minmax(0,1fr))}}
.kpi{padding:.9rem 1rem}
.kpi .label{color:var(--text2);font-size:.8rem}
.kpi .value{font-size:1.8rem;font-weight:700;line-height:1.15;margin-top:.15rem}
.kpi .hint{color:var(--muted);font-size:.76rem}
/* charts */
.chart{position:relative;width:100%;height:190px;margin-top:.6rem}
.chart svg{display:block;width:100%;height:100%;overflow:visible}
.chart .gridline{stroke:var(--line);stroke-width:1}
.chart .axis{fill:var(--muted);font-size:11px;font-variant-numeric:tabular-nums}
.chart .bar{fill:var(--series)}
.chart .bar.hot{fill:var(--purple-ink)}
.chart .line{fill:none;stroke:var(--series);stroke-width:2;stroke-linejoin:round;stroke-linecap:round}
.chart .area{fill:var(--series-wash);stroke:none}
.chart .thr{stroke:var(--critical);stroke-width:1.5}
.chart .thr-label{fill:var(--critical-ink);font-size:11px;font-weight:600}
.chart .esc{fill:var(--critical);stroke:var(--surface);stroke-width:2}
.chart .enddot{fill:var(--series);stroke:var(--surface);stroke-width:2}
.chart .cross{stroke:var(--text2);stroke-width:1}
.chart .hit{fill:transparent}
.chart .empty{fill:var(--muted);font-size:12px}
details{margin-top:.5rem}
summary{cursor:pointer;color:var(--text2);font-size:.82rem}
details.system{margin-top:1rem}
details.system>summary{font-size:.92rem;font-weight:650;color:var(--text)}
details.system .grid{margin-top:1rem}
.tip{position:fixed;z-index:30;pointer-events:none;background:var(--raised);color:var(--text);border:1px solid var(--line2);
border-radius:10px;padding:.5rem .65rem;font-size:.8rem;box-shadow:0 10px 30px rgba(0,0,0,.4);min-width:9rem}
.tip .t{font-weight:650;margin-bottom:.2rem}
.tip .r{display:flex;justify-content:space-between;gap:1rem;color:var(--text2)}
.tip .r b{color:var(--text);font-variant-numeric:tabular-nums}
/* tables & lists */
.tablewrap{overflow-x:auto}
table{width:100%;border-collapse:collapse;font-size:.84rem}
th{text-align:left;font-weight:600;color:var(--muted);padding:.45rem .5rem;border-bottom:1px solid var(--line2);white-space:nowrap;font-size:.78rem}
td{padding:.45rem .5rem;border-bottom:1px solid var(--line);vertical-align:top}
td.num,th.num{text-align:right;font-variant-numeric:tabular-nums}
td:first-child{white-space:nowrap}
tr:last-child td{border-bottom:0}
.empty-note{color:var(--muted);padding:.6rem 0;font-size:.86rem}
.timeline{list-style:none;margin:.4rem 0 0;padding:0;max-height:520px;overflow:auto}
.timeline>li{display:grid;grid-template-columns:2rem 1fr auto;gap:.6rem;padding:.55rem 0;border-bottom:1px solid var(--line)}
.timeline>li:last-child{border-bottom:0}
.timeline .ic{display:grid;place-items:center;width:1.9rem;height:1.9rem;border-radius:9px;background:var(--raised);font-size:.95rem}
.timeline .tx{min-width:0;overflow-wrap:anywhere}
.timeline .meta{color:var(--muted);font-size:.76rem;white-space:nowrap}
.timeline ul{margin:.2rem 0 0;padding-left:1rem;color:var(--text2);font-size:.8rem}
.conns{list-style:none;margin:.3rem 0 0;padding:0;max-height:260px;overflow:auto}
.conns li{display:flex;justify-content:space-between;gap:.75rem;padding:.38rem 0;border-bottom:1px solid var(--line)}
.conns li:last-child{border-bottom:0}
.conns code{overflow-wrap:anywhere}
.conns .meta{color:var(--muted);font-size:.76rem;white-space:nowrap}
.kv{display:grid;grid-template-columns:auto 1fr;gap:.4rem 1rem;margin:0;font-size:.86rem}
.kv dt{color:var(--muted)}.kv dd{margin:0;overflow-wrap:anywhere}
.plain{list-style:none;margin:0;padding:0;font-size:.86rem}
.plain li{padding:.35rem 0;border-bottom:1px solid var(--line)}
.plain li:last-child{border-bottom:0}
.plain .meta{color:var(--muted);font-size:.76rem;display:block}
.foot{margin-top:2rem;color:var(--muted);font-size:.8rem;text-align:center}
@media (max-width:600px){main{padding:1rem}.top{position:static;padding:.6rem 1rem}.headline{order:3;flex-basis:100%}
.nav{top:0;flex-wrap:nowrap;overflow-x:auto;justify-content:flex-start}html{scroll-padding-top:60px}}
/* live test window */
.live{position:fixed;right:20px;bottom:20px;z-index:40;width:min(460px,calc(100vw - 32px));max-height:min(74vh,680px);
display:flex;flex-direction:column;border-radius:16px;overflow:hidden;
background:linear-gradient(180deg,#1e1a29,#15131b);border:1px solid rgba(167,139,250,.45);
box-shadow:0 0 0 1px rgba(139,92,246,.15),0 18px 50px rgba(0,0,0,.55),0 0 40px rgba(139,92,246,.18)}
.live-head{display:flex;align-items:center;gap:.5rem;padding:.65rem .75rem .65rem .9rem;border-bottom:1px solid var(--line);
background:rgba(139,92,246,.10)}
.live-dot{width:.6rem;height:.6rem;border-radius:50%;background:var(--muted);flex:none}
.live-dot.on{background:var(--purple2);animation:pulse 1.4s ease-out infinite}
.live-dot.stop{background:var(--critical)}.live-dot.ok{background:var(--good)}
.live-title{font-weight:700;flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.live-prog{font-size:.75rem;color:var(--text2);white-space:nowrap}
.icon-btn{padding:.15rem .5rem;font-size:1rem;line-height:1;background:transparent;border-color:transparent;color:var(--text2)}
.icon-btn:hover{background:var(--surface2);border-color:var(--line2)}
.live.min .live-body,.live.min .live-path,.live.min .live-foot{display:none}
.live-body{display:flex;flex-direction:column;gap:.6rem;padding:.7rem .9rem .8rem;overflow:auto;min-height:0;flex:1}
.live-path{display:flex;align-items:flex-start;gap:0;overflow-x:auto;padding:.7rem .6rem .55rem;flex:none;
border-bottom:1px solid var(--line);background:rgba(13,12,17,.35)}
.pnode{display:flex;flex-direction:column;align-items:center;gap:.25rem;min-width:3.6rem;flex:1;position:relative}
.pnode:not(:last-child)::after{content:"";position:absolute;top:1rem;left:calc(50% + 1.05rem);right:calc(-50% + 1.05rem);
height:2px;background:var(--line2)}
.pnode.done:not(:last-child)::after,.pnode.warn:not(:last-child)::after{background:var(--purple)}
.pnode .pic{display:grid;place-items:center;width:2rem;height:2rem;border-radius:50%;font-size:.95rem;
background:var(--surface);border:2px solid var(--line2);transition:all .25s}
.pnode .plab{font-size:.64rem;color:var(--muted);text-align:center;line-height:1.15}
.pnode.active .pic{border-color:var(--purple2);background:var(--purple-wash);animation:pulse 1.2s ease-out infinite}
.pnode.active .plab{color:var(--purple-ink);font-weight:650}
.pnode.done .pic{border-color:var(--purple);background:rgba(139,92,246,.28)}
.pnode.done .plab,.pnode.warn .plab{color:var(--text2)}
.pnode.warn .pic{border-color:var(--warning);background:rgba(250,178,25,.14)}
.pnode.alert .pic{border-color:var(--critical);background:rgba(208,59,59,.22)}
.pnode.alert .plab,.pnode.fail .plab{color:var(--critical-ink);font-weight:650}
.pnode.fail .pic{border-color:var(--critical);background:rgba(208,59,59,.22)}
.pnode.skipped .pic{border-style:dashed;opacity:.45}
.pnode.skipped .plab{opacity:.6}
.live-attack{border:1px solid var(--line);border-radius:10px;background:var(--bg);padding:.55rem .65rem;font-size:.8rem}
.live-attack .lbl{color:var(--muted);font-size:.7rem;text-transform:uppercase;letter-spacing:.05em;font-weight:650;margin-bottom:.25rem}
.live-attack .ev{display:flex;gap:.4rem;align-items:baseline;flex-wrap:wrap;padding:.15rem 0}
.live-attack .ev code{color:var(--critical-ink)}
.live-attack .ev .arrow{color:var(--muted)}
.live-attack .cmd{display:block;color:var(--muted);font-size:.72rem;overflow-wrap:anywhere;margin:.05rem 0 .2rem}
.live-log{list-style:none;margin:0;padding:0;display:grid;gap:.35rem}
.live-log li{display:grid;grid-template-columns:1.5rem 1fr;gap:.45rem;font-size:.82rem;line-height:1.4;
padding:.4rem .5rem;border-radius:9px;background:var(--surface);border:1px solid var(--line);animation:slidein .3s ease-out}
@keyframes slidein{from{opacity:0;transform:translateY(4px)}to{opacity:1;transform:none}}
.live-log li .ic{text-align:center}
.live-log li .ms{color:var(--muted);font-size:.7rem;margin-left:.3rem}
.live-log li.working{border-color:var(--purple);background:var(--purple-wash)}
.live-log li.working .ic{animation:pulse 1.2s ease-out infinite;border-radius:50%}
.live-log li.warn{border-color:rgba(250,178,25,.5)}
.live-log li.crit,.live-log li.stop{border-color:var(--critical);background:rgba(208,59,59,.12)}
.live-log li.good{border-color:rgba(12,163,12,.6);background:rgba(12,163,12,.10)}
.live-log li.lstep{background:transparent;border-style:dashed;color:var(--text2)}
.live-log li b{font-weight:650}
.live-foot{display:flex;gap:.5rem;align-items:center;flex-wrap:wrap;flex:none;padding:.6rem .9rem;
border-top:1px solid var(--line);background:rgba(13,12,17,.35)}
.live-foot:empty{display:none}
.live-foot .muted{font-size:.78rem}
@media (max-width:600px){.live{right:8px;left:8px;bottom:8px;width:auto;max-height:62vh}}
@media (prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}html{scroll-behavior:auto}}
"""

DASHBOARD_JS = r"""
"use strict";
const $ = (id) => document.getElementById(id);
const SVG = "http://www.w3.org/2000/svg";
const enc = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)))
  .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const dec = (s) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")
  + "===".slice((s.length + 3) % 4)), (c) => c.charCodeAt(0));

// ---------- DOM helpers (text only: nothing untrusted ever becomes HTML) ----------
function el(tag, props, ...kids) {
  const n = document.createElement(tag);
  if (props) for (const [k, v] of Object.entries(props)) {
    if (v == null || v === false) continue;
    if (k === "class") n.className = v;
    else if (k === "text") n.textContent = v;
    else if (k.startsWith("on")) n.addEventListener(k.slice(2), v);
    else n.setAttribute(k, v);
  }
  for (const k of kids.flat()) if (k != null && k !== false) n.append(k instanceof Node ? k : String(k));
  return n;
}
function sv(tag, attrs) {
  const n = document.createElementNS(SVG, tag);
  for (const [k, v] of Object.entries(attrs || {})) n.setAttribute(k, v);
  return n;
}
const nf = new Intl.NumberFormat();
const num = (v) => (v == null ? "—" : nf.format(v));
const plural = (n, w) => n + " " + w + (n === 1 ? "" : "s");
const clock = (ts) => new Date(ts * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
const clockS = (ts) => new Date(ts * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
function ago(ts, now) {
  if (!ts) return "never";
  const s = Math.max(0, Math.round((now || Date.now() / 1000) - ts));
  if (s < 5) return "just now";
  if (s < 60) return s + "s ago";
  if (s < 3600) return Math.floor(s / 60) + "m ago";
  if (s < 86400) return Math.floor(s / 3600) + "h " + Math.floor((s % 3600) / 60) + "m ago";
  return new Date(ts * 1000).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
}
function dur(s) {
  s = Math.max(0, Math.round(s));
  if (s < 3600) return Math.floor(s / 60) + "m";
  if (s < 86400) return Math.floor(s / 3600) + "h " + Math.floor((s % 3600) / 60) + "m";
  return Math.floor(s / 86400) + "d " + Math.floor((s % 86400) / 3600) + "h";
}
const isoTs = (iso) => (iso ? Date.parse(iso) / 1000 : null);
const testTag = () => el("span", { class: "tag test", text: "TEST" });
function table(headers, rows, emptyText) {
  if (!rows.length) return el("div", { class: "empty-note", text: emptyText || "Nothing yet." });
  return el("table", null,
    el("thead", null, el("tr", null, headers.map((h) =>
      el("th", { class: h.num ? "num" : null, scope: "col", text: h.label || h })))),
    el("tbody", null, rows.map((r) => el("tr", null, r.map((c, i) =>
      el("td", { class: headers[i].num ? "num" : null }, c == null ? "—" : c))))));
}
function scoreBadge(score, thr) {
  const cls = score >= thr ? "score crit" : score >= 50 ? "score serious" : "score";
  return el("span", { class: cls, title: score >= thr ? "at or above the alert threshold" : null, text: String(score) });
}

// ---------- API ----------
async function api(path, body) {
  const opts = { cache: "no-store", credentials: "same-origin", headers: {} };
  if (body !== undefined) {
    opts.method = "POST";
    opts.headers = { "Content-Type": "application/json", "X-SOC-Dashboard": "1" };
    opts.body = JSON.stringify(body);
  }
  const r = await fetch(path, opts);
  let data = null;
  try { data = await r.json(); } catch (_) {}
  if (!r.ok) {
    const e = new Error((data && typeof data.detail === "string") ? data.detail : "HTTP " + r.status);
    e.status = r.status;
    throw e;
  }
  return data;
}

// ---------- sign-in ----------
function say(text, kind) { const s = $("login-status"); s.textContent = text; s.className = "status " + (kind || ""); }
function showLogin() {
  $("app").hidden = true; $("nav").hidden = true; $("login").hidden = false;
  $("logout").hidden = true; $("who").hidden = true; $("headline").replaceChildren();
  if (!(window.isSecureContext && window.PublicKeyCredential)) {
    const b = $("insecure"); b.hidden = false;
    b.textContent = "Passkeys only work over HTTPS. Open the Hub's https://…ts.net/dashboard address.";
    $("signin").disabled = true;
  }
}
async function signIn() {
  const btn = $("signin"); btn.disabled = true;
  try {
    say("Preparing…", "wait");
    const { login_id, options } = await api("/dashboard/api/login/options", {});
    options.challenge = dec(options.challenge);
    (options.allowCredentials || []).forEach((c) => (c.id = dec(c.id)));
    say("Confirm with your fingerprint or PIN…", "wait");
    const cred = await navigator.credentials.get({ publicKey: options });
    const r = cred.response;
    await api("/dashboard/api/login/verify", {
      login_id,
      webauthn_assertion: {
        credential_id: cred.id, client_data_json: enc(r.clientDataJSON),
        authenticator_data: enc(r.authenticatorData), signature: enc(r.signature),
        user_handle: r.userHandle && r.userHandle.byteLength ? enc(r.userHandle) : null,
      },
    });
    say("Signed in.", "ok");
    await refresh();
  } catch (e) {
    say(e.name === "NotAllowedError" ? "Cancelled or timed out." : "Sign-in failed: " + e.message, "err");
  } finally { btn.disabled = false; }
}
async function signOut() {
  try { await api("/dashboard/api/logout", {}); } catch (_) {}
  stopPolling(); showLogin(); say("", "");
}

// ---------- header ----------
function renderHeader(d) {
  const realPending = d.pending.filter((p) => !p.test).length;
  const testPending = d.pending.length - realPending;
  const busy = Object.entries(d.agents).filter(([, a]) => a.busy).map(([k]) => k);
  const offline = d.endpoints.filter((e) => e.state === "offline").length;
  let node;
  if (realPending) node = el("span", { class: "hl alert" }, el("span", { class: "dot bad pulse" }),
    plural(realPending, "action") + " waiting for your passkey");
  else if (testPending) node = el("span", { class: "hl busy" }, el("span", { class: "dot purple pulse" }),
    "Test attack waiting for your passkey");
  else if (d.tests.running) node = el("span", { class: "hl busy" }, el("span", { class: "dot purple pulse" }), "Running test attacks…");
  else if (busy.length) node = el("span", { class: "hl busy" }, el("span", { class: "dot purple pulse" }),
    AGENTS[busy[0]] ? AGENTS[busy[0]].name + " is working…" : "Agents working…");
  else if (offline) node = el("span", { class: "hl" }, el("span", { class: "dot warn" }), plural(offline, "endpoint") + " offline");
  else node = el("span", { class: "hl" }, el("span", { class: "dot good" }), "All quiet · agents standing by");
  $("headline").replaceChildren(node);
  $("who").textContent = "🔑 " + d.session.label; $("who").hidden = false;
  $("logout").hidden = false; $("nav").hidden = false;
}

// ---------- pending approvals ----------
let pendingState = [], fetchedAt = 0;
function renderPending(d) {
  pendingState = d.pending; fetchedAt = Date.now() / 1000;
  $("pending-wrap").hidden = !d.pending.length;
  $("pending").replaceChildren(...d.pending.map((p) => el("div", { class: "pcard" + (p.test ? " test" : "") },
    el("div", { class: "big-score" }, String(p.threat_score), el("small", { text: "threat" })),
    el("div", null,
      el("div", { class: "what" }, p.test ? testTag() : null, p.test ? " " : null,
        "Approve ", el("code", { text: p.action }), " on ", el("code", { text: p.target_ip || "no target" }),
        " for ", el("code", { text: p.endpoint_id }), "?"),
      el("ul", null, (p.attack_signatures.length ? p.attack_signatures : ["No signature given"]).map((s) => el("li", { text: s })))),
    el("div", { class: "side" },
      el("div", { class: "ttl", "data-ttl": p.challenge_id }),
      el("div", { class: "actions" },
        el("a", { class: "btn " + (p.test ? "primary" : "danger"), href: "/warden/approve/" + encodeURIComponent(p.challenge_id),
                  text: "Review & approve" }),
        el("button", { text: "Deny", onclick: (ev) => deny(p.challenge_id, ev.currentTarget) }))))));
  tickPending();
}
function tickPending() {
  const now = Date.now() / 1000;
  for (const p of pendingState) {
    const n = document.querySelector('[data-ttl="' + CSS.escape(p.challenge_id) + '"]');
    if (!n) continue;
    const left = Math.max(0, Math.round(p.seconds_left - (now - fetchedAt)));
    n.textContent = left ? "⏱ " + Math.floor(left / 60) + ":" + String(left % 60).padStart(2, "0") : "expired";
  }
}
async function deny(cid, btn) {
  if (btn) btn.disabled = true;
  try { await api("/warden/deny/" + encodeURIComponent(cid), {}); } catch (_) {}
  refresh();
}

// ---------- agents ----------
const AGENTS = {
  gatekeeper: { name: "Gatekeeper", icon: "🚪", role: "Drops known-safe apps, strips prompt injections, catches spoofing" },
  detective: { name: "Detective", icon: "🔎", role: "Remembers every connection and spots new ones" },
  strategist: { name: "Strategist", icon: "🧠", role: "Scores the threat 0–100 with malware rules + Gemini" },
  warden: { name: "Warden", icon: "⚖️", role: "Logs it, or pauses and asks for your passkey" },
  enforcer: { name: "Enforcer", icon: "🧱", role: "Applies approved blocks on each endpoint's firewall" },
};
const ORDER = ["gatekeeper", "detective", "strategist", "warden", "enforcer"];
function agentStats(k, s) {
  switch (k) {
    case "gatekeeper": return [[num(s.checked), "checked"], [num(s.dropped), "known-safe"], [num(s.injections + s.findings), "threats caught"]];
    case "detective": return [[num(s.lookups), "lookups"], [num(s.novel), "new"], [num(s.lookups - s.novel), "recognized"]];
    case "strategist": return [[num(s.runs), "scored"], [String(s.max_score), "highest"], [num(s.gemini), "by Gemini"]];
    case "warden": return [[num(s.escalated), "escalated"], [num(s.approved), "approved"], [num(s.denied + s.expired), "denied/expired"]];
    default: return [[num(s.blocks), "blocks"], [num(s.failed), "failed"], [num(s.endpoints), "checking in"]];
  }
}
function renderAgents(d) {
  const now = d.now;
  $("flow").replaceChildren(...ORDER.map((k) => {
    const meta = AGENTS[k], a = d.agents[k] || {}, last = a.last;
    let state, dotCls, cls = "agent", nowText, when = "";
    const recent = last && now - last.ts < 8;
    const waiting = k === "warden" && d.pending.length;
    if (a.busy) {
      state = "Working"; dotCls = "purple pulse"; cls += " active";
      nowText = "Analyzing a batch from " + a.busy.endpoint_id + (a.busy.test ? " (test)" : "") + "…";
    } else if (waiting) {
      state = "Waiting for you"; dotCls = "bad pulse"; cls += " alert";
      nowText = plural(d.pending.length, "action") + " paused until you approve or deny with your passkey.";
    } else if (k === "enforcer") {
      const polling = a.polling || [];
      state = polling.length ? "Standing guard" : "Not connected"; dotCls = polling.length ? "good" : "warn";
      nowText = polling.length ? "Checking for approved orders on " + polling.map((p) => p.endpoint_id).join(", ") + " every 10 s."
        : "No endpoint enforcer has checked in recently.";
      if (last) when = "Last: " + enforcerText(last) + " · " + ago(last.ts, now);
      if (last && now - last.ts < 8) cls += " active";
    } else if (last) {
      state = recent ? "Just ran" : "Idle"; dotCls = recent ? "purple pulse" : "good";
      if (recent) cls += " active";
      if (last.status === "crit" && now - last.ts < 600) { state = "Raised an alert"; dotCls = "bad"; cls += " alert"; }
      nowText = last.summary; when = ago(last.ts, now) + " · " + last.endpoint_id;
    } else { state = "Waiting for telemetry"; dotCls = ""; nowText = "No batches yet."; }
    return el("article", { class: cls, "aria-label": meta.name },
      el("div", { class: "agent-top" }, el("div", { class: "agent-ic", "aria-hidden": "true", text: meta.icon }),
        el("div", null, el("div", { class: "agent-name", text: meta.name }), el("div", { class: "agent-role", text: meta.role }))),
      el("div", { class: "agent-state" }, el("span", { class: "dot " + dotCls }), state,
        last && last.test && !a.busy ? testTag() : null),
      el("div", { class: "agent-now", text: nowText, title: nowText }),
      when ? el("div", { class: "agent-when", text: when }) : null,
      el("div", { class: "agent-stats", title: "Last 24 hours, real traffic" },
        agentStats(k, a.stats || {}).map(([v, l]) => el("div", null, el("b", { text: v }), el("span", { text: l })))));
  }));
}
function enforcerText(e) {
  if (e.kind === "enforced") return "blocked " + e.target_ip + " on " + e.endpoint_id;
  if (e.kind === "enforce_failed") return "failed to block " + e.target_ip;
  return "picked up an order for " + e.target_ip;
}

// ---------- live pipeline feed ----------
const openRuns = new Set();
function stageChip(t) {
  const s = t.stats || {};
  const ic = (AGENTS[t.agent] || { icon: "•" }).icon;
  let text;
  switch (t.agent) {
    case "gatekeeper": text = (s.checked - s.dropped) + "/" + s.checked + " kept" + (s.injections + s.findings ? " · " + (s.injections + s.findings) + " threats" : ""); break;
    case "detective": text = s.novel ? s.novel + " new" : "all known"; break;
    case "strategist": text = "score " + s.score + (s.llm === "ok" ? " (AI)" : ""); break;
    case "warden": text = t.status === "crit" ? "⏸ needs you"
      : /already waiting/.test(t.summary) ? "already waiting" : /denied .* last 30 min/.test(t.summary) ? "recently denied"
      : "logged"; break;
    default: text = "all safe";
  }
  return el("span", { class: "stage " + (t.status || ""), title: t.summary }, el("span", { "aria-hidden": "true", text: ic }), text);
}
function renderFeed(d) {
  if (!d.runs.length) { $("feed").replaceChildren(el("li", { class: "empty-note", text: "Waiting for the first batch of telemetry…" })); return; }
  $("feed").replaceChildren(...d.runs.slice(0, 20).map((r) => {
    const key = r.ts + "|" + r.endpoint_id;
    const trace = r.trace || [];
    const chips = [];
    trace.forEach((t, i) => { if (i) chips.push(el("span", { class: "arr", "aria-hidden": "true", text: "→" })); chips.push(stageChip(t)); });
    const row = el("button", { class: "run", "aria-expanded": openRuns.has(key) ? "true" : "false",
      onclick: () => { openRuns.has(key) ? openRuns.delete(key) : openRuns.add(key); renderFeed(last); } },
      el("span", { class: "t", text: clockS(r.ts) }),
      el("span", { class: "ep" }, r.test ? testTag() : null, el("code", { text: r.endpoint_id })),
      el("span", { class: "stages" }, chips),
      scoreBadge(r.score || 0, d.health.threshold));
    const detail = openRuns.has(key) ? el("div", { class: "run-detail" }, trace.map((t) =>
      el("div", null, el("b", { text: (AGENTS[t.agent] || { name: "Pipeline" }).name }),
        el("span", null, t.summary, el("span", { class: "muted", text: "  · " + t.ms + " ms" }))))) : null;
    return el("li", null, row, detail);
  }));
}

// ---------- devices ----------
function device(icon, name, tags, status, doing, meta) {
  return el("article", { class: "card dev" },
    el("div", { class: "dev-top" }, el("div", { class: "dev-ic", "aria-hidden": "true", text: icon }),
      el("div", null, el("div", { class: "dev-name", text: name }),
        el("div", { class: "dev-status" }, el("span", { class: "dot " + status[0] }), status[1]))),
    el("div", { class: "dev-tags" }, tags.map((t) => el("span", { class: "tag", text: t }))),
    el("div", { class: "dev-doing" }, el("b", { text: "Doing now" }), doing),
    meta ? el("div", { class: "dev-meta", text: meta }) : null);
}
function renderDevices(d) {
  const now = d.now, h = d.health, A = d.agents;
  const busy = ORDER.find((k) => A[k] && A[k].busy);
  const lastRun = d.runs.find((r) => !r.test) || d.runs[0];
  const cards = [];
  // When the Hub also runs the shipper it reports as an endpoint named like the Hub: show one card.
  const self = d.endpoints.find((e) => e.endpoint_id === d.hub_name);
  const selfPolling = self && self.last_poll && now - self.last_poll <= 60;
  const hubDoing = busy ? "Running the " + AGENTS[busy].name + " on a batch from " + A[busy].busy.endpoint_id + "…"
      : lastRun ? "Analyzed a batch from " + lastRun.endpoint_id + " " + ago(lastRun.ts, now) + "; waiting for the next one."
      : "Waiting for telemetry.";
  cards.push(device("🖥️", d.hub_name + " (Hub)",
    ["Hub", "Runs the AI agents", "Memory", "Signs orders"].concat(self ? ["Protected endpoint"] : []),
    ["good", "Online · up " + dur(now - d.hub_started_at)],
    hubDoing + (self ? " Also protecting itself: telemetry " + ago(self.last_ingest, now) + ", enforcer "
      + (selfPolling ? "checking in." : "NOT checking in.") : ""),
    (h.chroma ? num(h.memory_fingerprints) + " connections remembered" : "Memory (ChromaDB) unreachable") + " · signing key " + h.execution_key_id
      + (self ? " · " + plural(self.escalations, "alert") + ", " + plural(self.blocks, "block") + " on this machine"
              : " · not protecting itself yet (run shipper\\install-endpoint.ps1)")));
  for (const e of d.endpoints.filter((x) => x !== self)) {
    const st = { online: ["good", "Online"], idle: ["warn", "Idle"], offline: ["bad", "Offline"] }[e.state];
    const polling = e.last_poll && now - e.last_poll <= 60;
    const doing = e.state === "offline" ? "Not reporting. Last seen " + ago(e.last_seen, now) + "."
      : "Sending telemetry every 10 s (last " + ago(e.last_ingest, now) + "). "
        + (polling ? "Enforcer checking for orders (last " + ago(e.last_poll, now) + ")." : "Enforcer not checking in.");
    cards.push(device("💻", e.endpoint_id, ["Endpoint", "Telemetry shipper", "Firewall enforcer"], st, doing,
      num(e.events) + " connections reported · " + plural(e.escalations, "alert") + " · " + plural(e.blocks, "block")));
  }
  const realPending = d.pending.filter((p) => !p.test).length;
  for (const p of d.passkeys) {
    cards.push(device("📱", p.label, ["Warden approver", "Passkey (FIDO2)", "Discord alerts"],
      d.pending.length ? ["bad pulse", "Needs you"] : ["good", "Ready"],
      d.pending.length ? "Waiting for you to approve or deny " + plural(d.pending.length, "action")
        + (realPending ? "" : " (test)") + "." : "Standing by. Approves blocks and signs you in to this dashboard.",
      (p.device_type === "multi_device" ? "Synced passkey" : "Device-bound passkey") + " · last used "
        + (p.last_used_at ? ago(isoTs(p.last_used_at), now) : "never")));
  }
  const gem = { ok: ["good", "Working"], failing: ["warn", "Failing"], off: ["", "Not configured"], unknown: ["", "No calls yet"] }[h.gemini];
  cards.push(device("✨", "Gemini", ["Cloud AI", "Strategist's model"], gem,
    h.gemini === "ok" ? "Scoring each batch with " + h.gemini_model + "."
      : h.gemini === "failing" ? "Requests are failing (" + (h.gemini_status || "?").replace("error:", "") + "), so the Strategist uses its built-in rules."
      : h.gemini === "off" ? "No API key, so the Strategist uses its built-in rules." : "Waiting for the first batch.",
    "Model: " + h.gemini_model));
  const dl = d.discord_last;
  cards.push(device("💬", "Discord", ["Alert channel", "Notifies your phone"],
    !h.discord ? ["bad", "Not configured"] : dl && !dl.ok ? ["bad", "Last post failed"] : ["good", "Connected"],
    dl ? "Last sent: " + dl.what + " " + ago(dl.at, now) + (dl.ok ? "." : " (failed: " + (dl.error || "?") + ").")
      : h.discord ? "Ready. Nothing sent since the Hub started." : "No webhook, so you won't get alerts.", null));
  const tr = d.tests.runs[0];
  cards.push(device("🧪", "Test lab", ["Virtual endpoint", "Test attacks only"],
    d.tests.running ? ["purple pulse", "Running"] : ["", "Virtual"],
    d.tests.running ? "Sending a test attack through the agents…"
      : tr ? "Last test: " + tr.name + " " + (tr.status === "passed" ? "passed" : tr.status) + " " + ago(tr.finished_at || tr.started_at, now) + "."
      : "Idle. Use the Test lab below to fire a test attack.",
    "Endpoint " + d.tests.endpoint_id + " · documentation-only IPs · no real firewall changes"));
  $("devgrid").replaceChildren(...cards);
}

// ---------- test lab ----------
let testBusy = false;
async function runTest(id) {
  testBusy = true; renderTests(last); $("lab-msg").textContent = "";
  try { await api("/dashboard/api/tests/run", { scenario: id }); live.dismissed = false; openLive(); }
  catch (e) { $("lab-msg").textContent = "Couldn't start: " + e.message; }
  finally { testBusy = false; setTimeout(refresh, 400); }
}
const STEPS = [["awaiting_passkey", "Passkey approval"], ["approved", "Order signed"], ["picked_up", "Enforcer picked up"], ["enforced", "Verified & blocked (simulated)"]];
const FAIL = { denied: "Denied by you. Nothing executed (also a pass).", expired: "Approval window expired: auto-denied. Nothing executed.",
  rejected: "The approval was rejected", enforce_failed: "The enforcer rejected the order", order_expired: "No enforcer picked up the order" };
// How many steps each stage completes (index of the last finished step).
const DONE_THROUGH = { awaiting_passkey: -1, approved: 1, picked_up: 2, enforced: 3 };
function stepper(f, now) {
  const failed = FAIL[f.stage];
  const through = failed ? Math.max(-1, ...(f.history || []).map((h) => DONE_THROUGH[h.stage] ?? -1))
                         : DONE_THROUGH[f.stage] ?? -1;
  const steps = STEPS.map(([, label], i) => {
    const cls = "step" + (i <= through ? " done" : i === through + 1 ? (failed ? " fail" : " now") : "");
    return el("div", { class: cls, text: label });
  });
  const kids = [el("div", { class: "stepper" }, steps)];
  if (failed) kids.push(el("div", { class: "followup-note", text: FAIL[f.stage] + (f.detail && f.stage.match(/rejected|failed/) ? ": " + f.detail : "") }));
  else if (f.stage === "enforced") kids.push(el("div", { class: "followup-note", text: "✓ " + f.detail }));
  else if (f.stage === "awaiting_passkey") {
    const left = Math.max(0, Math.round((f.expires_at || 0) - now));
    kids.push(el("div", { class: "followup-actions" },
      el("a", { class: "btn primary", href: "/warden/approve/" + encodeURIComponent(f.challenge_id), text: "Approve with passkey" }),
      el("button", { text: "Deny", onclick: (ev) => deny(f.challenge_id, ev.currentTarget) }),
      el("span", { class: "muted small", text: left ? "⏱ " + Math.floor(left / 60) + ":" + String(left % 60).padStart(2, "0") + " left · check Discord on your phone" : "expiring…" })));
  } else kids.push(el("div", { class: "followup-note", text: f.detail || "" }));
  return kids;
}
function renderTests(d) {
  if (!d) return;
  const T = d.tests, busy = T.running || testBusy;
  $("run-all").disabled = busy;
  $("run-all").textContent = busy ? "Running…" : "Run all tests";
  const lastBy = {};
  for (const r of T.runs) if (!lastBy[r.scenario]) lastBy[r.scenario] = r;
  $("scenarios").replaceChildren(...T.scenarios.map((s) => {
    const r = lastBy[s.id];
    const res = !r ? el("span", { class: "muted small", text: "Not run yet" })
      : r.status === "running" ? el("span", { class: "tag test", text: "Running…" })
      : el("span", { class: "tag " + (r.status === "passed" ? "good" : "crit"), text: verdict(r) });
    return el("article", { class: "card scn" },
      el("div", { class: "scn-top" }, el("span", { class: "scn-ic", "aria-hidden": "true", text: s.icon }), el("span", { class: "scn-name", text: s.name })),
      el("p", { text: s.tagline }),
      el("div", { class: "agents" }, s.agents.map((a) => el("span", { class: "tag", text: AGENTS[a].icon + " " + AGENTS[a].name }))),
      el("div", { class: "exp", text: "Expect: " + s.expected }),
      el("div", { class: "scn-foot" }, res, el("button", { class: "primary", disabled: busy ? "" : null, text: "Run",
        onclick: () => runTest(s.id) })));
  }));
  const latest = Object.values(lastBy).sort((a, b) => b.started_at - a.started_at);
  $("results").replaceChildren(...(latest.length ? [el("h3", { text: "Latest result for each test" })] : []),
    el("div", { class: "result-grid" }, latest.map((r) => {
    return el("article", { class: "card result " + r.status },
      el("div", { class: "result-head" }, el("span", { "aria-hidden": "true", text: r.icon }), el("span", { class: "name", text: r.name }),
        r.status === "running" ? el("span", { class: "tag test", text: "Running…" })
          : el("span", { class: "tag " + (r.status === "passed" ? "good" : "crit"), text: verdict(r) }),
        r.discord === true ? el("span", { class: "tag", text: "💬 Sent to Discord" })
          : r.discord === false ? el("span", { class: "tag warn", title: "No webhook, or the post failed", text: "💬 Not sent to Discord" }) : null,
        r.scores.length ? el("span", { class: "muted small", text: "score " + r.scores.join(" → ") }) : null,
        el("span", { class: "muted small", text: ago(r.started_at, d.now) })),
      r.error ? el("div", { class: "followup-note", text: r.error }) : null,
      el("ul", { class: "checks" }, r.checks.map((c) => el("li", null,
        el("span", { class: "ck " + (c.ok === true ? "ok" : c.ok === false ? "no" : "na"), text: c.ok === true ? "✓" : c.ok === false ? "✗" : "–" }),
        el("span", null, c.label, c.detail ? el("span", { class: "d", text: "(" + c.detail + ")" }) : null)))),
      r.followup ? stepper(r.followup, d.now) : null);
  })));
}
function verdict(r) {
  if (r.status === "error") return "Error";
  const ran = r.checks.filter((c) => c.ok !== null), ok = ran.filter((c) => c.ok).length;
  const skipped = r.checks.length - ran.length;
  return (r.status === "passed" ? "✓ Passed " : "✗ Failed ") + ok + "/" + ran.length + (skipped ? " · " + skipped + " skipped" : "");
}

// ---------- KPIs & charts ----------
function renderKpis(d) {
  const k = d.kpis;
  const tile = (label, value, hint) => el("div", { class: "card kpi" },
    el("div", { class: "label", text: label }), el("div", { class: "value", text: value }), el("div", { class: "hint", text: hint }));
  $("kpis").replaceChildren(
    tile("Connections seen", num(k.events_24h), num(k.batches_24h) + " batches · 24 h"),
    tile("Analyzed", num(k.analyzed_24h), "after dropping safe apps"),
    tile("Highest score", String(k.max_score_24h), "alerts at " + d.health.threshold),
    tile("Escalations", num(k.escalations_24h), num(k.approvals_24h) + " approved"),
    tile("Blocked IPs", num(k.blocks_total), "by enforcers"),
    tile("Injections stopped", num(k.injections_24h), "by the Gatekeeper"));
}
const tip = () => $("tip");
function showTip(ev, title, rows) {
  const t = tip();
  t.replaceChildren(el("div", { class: "t", text: title }),
    ...rows.map(([k, v]) => el("div", { class: "r" }, el("span", { text: k }), el("b", { text: v }))));
  t.hidden = false;
  const w = t.offsetWidth, h = t.offsetHeight;
  let x = ev.clientX + 14, y = ev.clientY - h - 10;
  if (x + w > innerWidth - 8) x = ev.clientX - w - 14;
  if (y < 8) y = ev.clientY + 16;
  t.style.left = x + "px"; t.style.top = y + "px";
}
function hideTip() { tip().hidden = true; }
function niceMax(v) {
  if (v <= 5) return 5;
  const p = Math.pow(10, Math.floor(Math.log10(v)));
  for (const m of [1, 2, 2.5, 5, 10]) if (m * p >= v) return m * p;
  return 10 * p;
}
function frame(box, yMax, yTicks, fmtY) {
  const W = Math.max(280, box.clientWidth), H = box.clientHeight || 190;
  const m = { l: 40, r: 10, t: 12, b: 24 };
  const svg = sv("svg", { viewBox: `0 0 ${W} ${H}`, role: "img" });
  const pw = W - m.l - m.r, ph = H - m.t - m.b;
  const y = (v) => m.t + ph - (v / yMax) * ph;
  for (const t of yTicks) {
    svg.append(sv("line", { class: "gridline", x1: m.l, x2: W - m.r, y1: y(t), y2: y(t) }));
    const lab = sv("text", { class: "axis", x: m.l - 8, y: y(t) + 4, "text-anchor": "end" });
    lab.textContent = fmtY(t); svg.append(lab);
  }
  return { svg, W, H, m, pw, ph, y };
}
function xLabels(f, series) {
  const band = f.pw / series.length;
  [0, 15, 30, 45].forEach((i) => {
    const t = sv("text", { class: "axis", x: f.m.l + i * band + band / 2, y: f.H - 6, "text-anchor": "middle" });
    t.textContent = clock(series[i].t); f.svg.append(t);
  });
  const t = sv("text", { class: "axis", x: f.m.l + f.pw, y: f.H - 6, "text-anchor": "end" });
  t.textContent = "now"; f.svg.append(t);
  return band;
}
function barPath(x, y, w, y0) {
  const r = Math.min(4, w / 2, y0 - y);
  return `M${x},${y0}V${y + r}Q${x},${y} ${x + r},${y}H${x + w - r}Q${x + w},${y} ${x + w},${y + r}V${y0}Z`;
}
function volumeChart(series) {
  const box = $("chart-volume");
  const max = Math.max(0, ...series.map((s) => s.events));
  const yMax = niceMax(max);
  const f = frame(box, yMax, [0, yMax / 2, yMax], (v) => nf.format(v));
  f.svg.setAttribute("aria-label", "Bar chart of connections received per minute over the last hour");
  const band = xLabels(f, series);
  const bw = Math.max(1, Math.min(24, band - 2));
  const y0 = f.y(0);
  const bars = series.map((s, i) => {
    if (!s.events) return null;
    const x = f.m.l + i * band + (band - bw) / 2, yv = f.y(s.events);
    const p = sv("path", { class: "bar", d: barPath(x, Math.min(yv, y0 - 1), bw, y0) });
    f.svg.append(p); return p;
  });
  series.forEach((s, i) => {
    const hit = sv("rect", { class: "hit", x: f.m.l + i * band, y: f.m.t, width: band, height: f.ph });
    hit.addEventListener("mousemove", (ev) => {
      bars.forEach((b, j) => b && b.classList.toggle("hot", j === i));
      showTip(ev, clock(s.t) + "–" + clock(s.t + 60), [["Connections", num(s.events)], ["Analyzed", num(s.analyzed)], ["Batches", num(s.batches)]]);
    });
    hit.addEventListener("mouseleave", () => { bars.forEach((b) => b && b.classList.remove("hot")); hideTip(); });
    f.svg.append(hit);
  });
  if (!max) {
    const t = sv("text", { class: "empty", x: f.m.l + f.pw / 2, y: f.m.t + f.ph / 2, "text-anchor": "middle" });
    t.textContent = "No telemetry in the last hour"; f.svg.append(t);
  }
  box.replaceChildren(f.svg);
  $("table-volume").replaceChildren(table(
    ["Minute", { label: "Connections", num: true }, { label: "Analyzed", num: true }, { label: "Batches", num: true }],
    series.filter((s) => s.batches).reverse().map((s) => [clock(s.t), num(s.events), num(s.analyzed), num(s.batches)]),
    "No telemetry in the last hour."));
}
function scoreChart(series, thr) {
  const box = $("chart-score");
  const f = frame(box, 100, [0, 50, 100], String);
  f.svg.setAttribute("aria-label", "Line chart of the highest threat score per minute over the last hour, alert threshold " + thr);
  const band = xLabels(f, series);
  const cx = (i) => f.m.l + i * band + band / 2;
  f.svg.append(sv("line", { class: "thr", x1: f.m.l, x2: f.m.l + f.pw, y1: f.y(thr), y2: f.y(thr) }));
  const tl = sv("text", { class: "thr-label", x: f.m.l + 4, y: f.y(thr) - 5, "text-anchor": "start" });
  tl.textContent = "alert ≥ " + thr; f.svg.append(tl);
  let seg = [];
  const flush = () => {
    if (seg.length) {
      const d = seg.map(([x, y], k) => (k ? "L" : "M") + x + "," + y).join("");
      if (seg.length > 1) f.svg.append(sv("path", { class: "area", d: d + `L${seg[seg.length - 1][0]},${f.y(0)}L${seg[0][0]},${f.y(0)}Z` }));
      f.svg.append(sv("path", { class: "line", d }));
    }
    seg = [];
  };
  series.forEach((s, i) => { if (s.max_score == null) flush(); else seg.push([cx(i), f.y(s.max_score)]); });
  flush();
  const lastI = series.map((s) => s.max_score != null).lastIndexOf(true);
  if (lastI >= 0) f.svg.append(sv("circle", { class: "enddot", cx: cx(lastI), cy: f.y(series[lastI].max_score), r: 4 }));
  series.forEach((s, i) => { if (s.escalations) f.svg.append(sv("circle", { class: "esc", cx: cx(i), cy: f.y(s.max_score), r: 5.5 })); });
  const cross = sv("line", { class: "cross", y1: f.m.t, y2: f.m.t + f.ph, visibility: "hidden" });
  f.svg.append(cross);
  series.forEach((s, i) => {
    const hit = sv("rect", { class: "hit", x: f.m.l + i * band, y: f.m.t, width: band, height: f.ph });
    hit.addEventListener("mousemove", (ev) => {
      cross.setAttribute("x1", cx(i)); cross.setAttribute("x2", cx(i)); cross.setAttribute("visibility", "visible");
      showTip(ev, clock(s.t) + "–" + clock(s.t + 60), [["Highest score", s.max_score == null ? "no data" : String(s.max_score)],
        ["Escalations", num(s.escalations)], ["Batches", num(s.batches)]]);
    });
    hit.addEventListener("mouseleave", () => { cross.setAttribute("visibility", "hidden"); hideTip(); });
    f.svg.append(hit);
  });
  if (lastI < 0) {
    const t = sv("text", { class: "empty", x: f.m.l + f.pw / 2, y: f.m.t + f.ph / 2 + 20, "text-anchor": "middle" });
    t.textContent = "No scored batches in the last hour"; f.svg.append(t);
  }
  box.replaceChildren(f.svg);
  $("thr").textContent = thr;
  $("table-score").replaceChildren(table(
    ["Minute", { label: "Highest score", num: true }, { label: "Escalations", num: true }],
    series.filter((s) => s.max_score != null).reverse().map((s) => [clock(s.t), String(s.max_score), num(s.escalations)]),
    "No scored batches in the last hour."));
}

// ---------- history ----------
const KINDS = {
  hub_started: ["⏻", (e) => "Hub started (" + plural(e.passkeys, "passkey") + ", signing key " + e.key_id + ")"],
  escalated: ["🛑", (e) => `Warden escalated: ${e.action} ${e.target_ip || "(no target)"} on ${e.endpoint_id}, score ${e.threat_score}` + (e.discord === false ? " (Discord alert FAILED)" : "")],
  approved: ["✅", (e) => `Approved by ${e.approved_by}: ${e.action} ${e.target_ip || ""} on ${e.endpoint_id}`],
  approval_rejected: ["🚫", (e) => `Approval attempt rejected for ${e.target_ip || "?"}: ${e.reason}`],
  denied: ["⛔", (e) => `Denied: ${e.action} ${e.target_ip || ""} on ${e.endpoint_id}`],
  challenge_expired: ["⌛", (e) => `Approval window expired, auto-denied: ${e.target_ip || "(no target)"} on ${e.endpoint_id}`],
  order_picked_up: ["📥", (e) => `Enforcer on ${e.endpoint_id} picked up the order for ${e.target_ip}`],
  enforced: ["🧱", (e) => (e.test ? `Simulated block of ${e.target_ip} (test lab)` : `Blocked ${e.target_ip} on ${e.endpoint_id}`) + (e.status === "already_applied" ? " (already in place)" : "")],
  enforce_failed: ["❌", (e) => `Enforcement ${e.status} for ${e.target_ip} on ${e.endpoint_id}: ${e.detail || "no detail"}`],
  order_expired: ["⚠️", (e) => `Approved order for ${e.target_ip} expired before ${e.endpoint_id} picked it up. Nothing was blocked.`],
  passkey_enrolled: ["🔑", (e) => `Passkey enrolled: ${e.label} (${e.device_type})`],
  dashboard_login: ["🔓", (e) => `Dashboard sign-in with ${e.label}`],
  dashboard_login_failed: ["🔒", (e) => `Dashboard sign-in failed: ${e.reason}`],
  test_run: ["🧪", (e) => `Test "${e.name}": ${e.status} (${e.passed}/${e.total} checks)`],
};
function renderTimeline(d) {
  const items = d.timeline.filter((e) => KINDS[e.kind]);
  if (!items.length) { $("timeline").replaceChildren(el("li", { class: "empty-note", text: "No events yet." })); return; }
  $("timeline").replaceChildren(...items.slice(0, 80).map((e) => {
    const [ic, fn] = KINDS[e.kind];
    return el("li", null, el("span", { class: "ic", "aria-hidden": "true", text: ic }),
      el("div", { class: "tx" }, e.test ? [testTag(), " "] : null, fn(e),
        e.signatures && e.signatures.length ? el("ul", null, e.signatures.map((s) => el("li", { text: s }))) : null),
      el("span", { class: "meta", title: new Date(e.ts * 1000).toLocaleString(), text: ago(e.ts, d.now) }));
  }));
}
function renderBlocks(d) {
  $("blocks").replaceChildren(table(
    ["IP", "Endpoint", "Blocked", "Approved by", { label: "Score", num: true }],
    d.blocks.map((b) => [el("code", { text: b.ip }), el("code", { text: b.endpoint_id }), ago(b.applied_at, d.now),
      b.approved_by || "—", b.threat_score == null ? "—" : scoreBadge(b.threat_score, d.health.threshold)]),
    "No IPs blocked. Blocks only happen after you approve one with your passkey."));
}
function renderNewConns(d) {
  if (!d.new_connections.length) { $("newconns").replaceChildren(el("li", { class: "empty-note", text: "Nothing new: everything matches what the Hub has learned." })); return; }
  $("newconns").replaceChildren(...d.new_connections.map((c) => el("li", null, el("code", { text: c.connection }),
    el("span", { class: "meta", text: (d.endpoints.length > 1 ? c.endpoint_id + " · " : "") + ago(c.ts, d.now) }))));
}
function renderSystem(d) {
  const h = d.health;
  const kv = [
    ["Alert threshold", h.threshold + " / 100"], ["Approval window", h.approval_timeout + " s"],
    ["Passkey mode", h.assertion_mode === "webauthn" ? "Real signatures (webauthn)" : "SIMULATED"],
    ["Order signing key", h.execution_key_id],
    ["Gemini", h.gemini === "off" ? "No API key: built-in rules" : h.gemini_model + " · " + (h.gemini_status || "no calls yet")],
    ["Memory", h.chroma ? num(h.memory_fingerprints) + " connections remembered" : "ChromaDB unreachable"],
    ["Hub started", ago(d.hub_started_at, d.now)],
    ["Queued orders", d.orders.length ? d.orders.map((o) => o.target_ip + (o.picked_up ? " (picked up)" : " (waiting)")).join(", ") : "none"],
  ];
  $("system").replaceChildren(...kv.flatMap(([k, v]) => [el("dt", { text: k }), el("dd", { text: v })]));
  $("passkeys").replaceChildren(...(d.passkeys.length ? d.passkeys.map((p) => el("li", null,
    el("strong", { text: p.label }), " ", el("span", { class: "mono muted", text: p.id + "…" }),
    el("span", { class: "meta", text: (p.device_type || "") + " · last used " + (p.last_used_at ? ago(isoTs(p.last_used_at), d.now) : "never") })))
    : [el("li", { class: "empty-note", text: "None enrolled." })]));
}

// ---------- live test window ----------
const live = { open: false, timer: null, dismissed: false, lastSeq: -1, data: null, stick: true };
const PATH = [["endpoint", "💻", "Endpoint"], ["gatekeeper", "🚪", "Gatekeeper"], ["detective", "🔎", "Detective"],
  ["strategist", "🧠", "Strategist"], ["warden", "⚖️", "Warden"], ["passkey", "📱", "Your passkey"], ["enforcer", "🧱", "Enforcer"]];
const FOLLOW = {
  awaiting_passkey: ["📱", "", "<b>Waiting for your passkey.</b> The attack is frozen until you approve or deny it, below or from the 🧪 TEST alert on your phone."],
  approved: ["✅", "good", "<b>Approved with your passkey.</b> The Hub signed a one-time execution order for exactly this block."],
  picked_up: ["📥", "", "<b>The enforcer picked up the signed order</b> and is checking its signature."],
  enforced: ["🧱", "good", "<b>Signature verified, block applied.</b> (Simulated: test IPs only, no real firewall changed.)"],
  denied: ["⛔", "good", "<b>Denied.</b> The attack never ran: nothing executes without your approval."],
  expired: ["⌛", "good", "<b>No approval in time, so it was auto-denied.</b> Nothing ran: the Warden fails safe."],
  rejected: ["❌", "crit", "<b>The approval was rejected:</b> "],
  enforce_failed: ["❌", "crit", "<b>The enforcer refused the order:</b> "],
  order_expired: ["⚠️", "crit", "<b>No enforcer picked up the order in time.</b> Nothing was blocked."],
};
// Text from the server is set with textContent; only these fixed strings use <b>.
function richText(node, html, extra) {
  const parts = html.split(/(<b>|<\/b>)/); let bold = false;
  for (const p of parts) {
    if (p === "<b>") bold = true; else if (p === "</b>") bold = false;
    else if (p) node.append(bold ? el("b", { text: p }) : document.createTextNode(p));
  }
  if (extra) node.append(document.createTextNode(extra));
  return node;
}
function openLive() {
  if (!live.open) live.lastSeq = -1;
  live.open = true; $("live").hidden = false; $("live").classList.remove("min");
  pollLive();
}
function closeLive() {   // stays closed until you start another test yourself
  live.open = false; live.dismissed = true; $("live").hidden = true; clearTimeout(live.timer);
}
async function pollLive() {
  clearTimeout(live.timer);
  if (!live.open) return;
  let d = null;
  try { d = await api("/dashboard/api/tests/live"); } catch (_) {}
  if (d) { live.data = d; renderLive(d); }
  const f = d && d.run && d.run.followup;
  const busy = d && (d.running || (f && ["awaiting_passkey", "approved", "picked_up"].includes(f.stage)));
  live.timer = setTimeout(pollLive, busy ? 600 : 3000);
}
function nodeStates(run) {
  const ev = run.live || [];
  const batch = Math.max(1, ...ev.filter((e) => e.batch).map((e) => e.batch));
  const st = {};
  if (ev.some((e) => e.kind === "attack")) st.endpoint = "done";
  for (const e of ev.filter((x) => x.batch === batch)) {
    if (e.kind === "agent_start" && !st[e.agent]) st[e.agent] = "active";
    if (e.kind === "agent_done") {
      if (e.agent === "pipeline") { ["detective", "strategist", "warden"].forEach((a) => (st[a] = "skipped")); continue; }
      st[e.agent] = e.status === "crit" ? "alert" : e.status === "ok" ? "done" : "warn";
    }
  }
  if (run.escalates) {
    const stage = run.followup ? run.followup.stage : null;
    const order = ["awaiting_passkey", "approved", "picked_up", "enforced"];
    const i = order.indexOf(stage);
    if (stage === "awaiting_passkey") st.passkey = "active";
    else if (i > 0) { st.passkey = "done"; st.enforcer = stage === "enforced" ? "done" : "active"; }
    else if (["denied", "expired", "rejected"].includes(stage)) { st.passkey = stage === "rejected" ? "fail" : "done"; st.enforcer = "skipped"; }
    else if (["enforce_failed", "order_expired"].includes(stage)) { st.passkey = "done"; st.enforcer = "fail"; }
  }
  return st;
}
function renderLive(d) {
  const run = d.run;
  if (!run) { $("live-title").textContent = "Live test"; $("live-log").replaceChildren(el("li", null, el("span", { class: "ic", text: "…" }), "Starting…")); return; }
  const thr = d.threshold;
  $("live-title").textContent = run.icon + " " + run.name;
  $("live-progress").textContent = d.running && d.session && d.session.total > 1 ? "Test " + d.session.index + " of " + d.session.total : "";
  const f = run.followup;
  const active = run.status === "running" || (f && ["awaiting_passkey", "approved", "picked_up"].includes(f.stage));
  const bad = run.status !== "passed" || (f && ["rejected", "enforce_failed", "order_expired"].includes(f.stage));
  $("live-dot").className = "live-dot " + (active ? "on" : bad ? "stop" : "ok");

  // path strip
  const st = nodeStates(run);
  const path = PATH.filter(([k]) => run.escalates || !["passkey", "enforcer"].includes(k));
  $("live-path").replaceChildren(...path.map(([k, ic, lab]) => el("div", { class: "pnode " + (st[k] || "") },
    el("span", { class: "pic", "aria-hidden": "true", text: ic }), el("span", { class: "plab", text: lab }))));

  // the attack being sent
  const atk = [...(run.live || [])].reverse().find((e) => e.kind === "attack");
  $("live-attack").replaceChildren(...(atk ? [
    el("div", { class: "lbl", text: "The attack" + (atk.of > 1 ? " · batch " + atk.batch + " of " + atk.of : "") }),
    el("div", { class: "muted small", text: run.tagline }),
    ...atk.events.map((e) => el("div", null,
      el("div", { class: "ev" }, el("code", { text: e.process }), el("span", { class: "arrow", text: "→" }), el("code", { text: e.dst }),
        e.user && /root|admin/i.test(e.user) ? el("span", { class: "tag crit", text: "user " + e.user }) : null),
      e.path ? el("span", { class: "cmd mono", text: e.path }) : null,
      e.cmdline && e.cmdline !== e.path ? el("span", { class: "cmd mono", text: "› " + e.cmdline }) : null))] : []));

  // step log
  const done = new Set((run.live || []).filter((e) => e.kind === "agent_done").map((e) => e.agent + "|" + e.batch));
  const items = [];
  for (const e of run.live || []) {
    if (e.kind === "start") items.push(["▶", "lstep", "Test started. Expected: " + e.expected]);
    else if (e.kind === "attack") items.push(["💻", "lstep", (e.of > 1 ? "Batch " + e.batch + ": the" : "The") + " test endpoint sends "
      + e.events.length + " connection" + (e.events.length === 1 ? "" : "s") + " to the Hub."]);
    else if (e.kind === "agent_start" && !done.has(e.agent + "|" + e.batch))
      items.push([(AGENTS[e.agent] || { icon: "•" }).icon, "working", (AGENTS[e.agent] || { name: "Pipeline" }).name + " is analyzing…"]);
    else if (e.kind === "agent_done") {
      const a = AGENTS[e.agent] || { icon: "✓", name: "Pipeline" };
      const li = el("li", { class: e.status === "crit" ? "crit" : e.status === "warn" || e.status === "alert" ? "warn" : "" },
        el("span", { class: "ic", "aria-hidden": "true", text: a.icon }),
        el("span", null, el("b", { text: a.name + ": " }), e.summary, el("span", { class: "ms", text: e.ms + " ms" })));
      items.push(li);
    } else if (e.kind === "batch_done") {
      const dec = String(e.decision || "");
      if (dec.startsWith("pending")) items.push(["🛑", "stop", "<b>Attack stopped.</b> Score " + e.score + " ≥ " + thr
        + ": the Warden paused it before anything ran" + (e.target_ip ? " and proposed blocking " + e.target_ip : "") + "."]);
      else if (dec === "already_pending") items.push(["🔁", "good", "<b>Same threat again, no second alert.</b> One approval is already waiting for it."]);
      else if (dec === "all_events_known_safe") items.push(["✅", "good", "<b>Nothing to stop:</b> every connection was a known-safe app."]);
      else items.push(["📝", e.score >= 50 ? "warn" : "good", "<b>Logged, not blocked:</b> score " + e.score + " is below " + thr
        + (e.score >= 50 ? ", but it's too suspicious to learn as normal." : ".")]);
    } else if (e.kind === "withdrawn") items.push(["🧹", "lstep", "Test cleanup: the paused approval was withdrawn (only the Full attack chain test asks for your passkey)."]);
    else if (e.kind === "followup" && FOLLOW[e.stage]) {
      const [ic, cls, txt] = FOLLOW[e.stage];
      items.push([ic, cls, txt, ["rejected", "enforce_failed"].includes(e.stage) ? e.detail : ""]);
    } else if (e.kind === "checks") items.push([e.status === "passed" ? "🏁" : "❗", e.status === "passed" ? "good" : "crit",
      e.status === "error" ? "<b>Test error:</b> " : "<b>Automated checks " + (e.status === "passed" ? "passed" : "FAILED") + "</b>: "
        + e.passed + " of " + e.ran + " checks" + (e.total > e.ran ? " (" + (e.total - e.ran) + " skipped)" : "") + ".", e.error || ""]);
  }
  const log = $("live-log"), body = $("live-body");
  const seq = (run.live || []).length;
  log.replaceChildren(...items.map((it) => {
    if (it instanceof Node) return it;
    const li = el("li", { class: it[1] }, el("span", { class: "ic", "aria-hidden": "true", text: it[0] }));
    li.append(richText(el("span"), it[2], it[3]));
    return li;
  }));
  const follow = seq !== live.lastSeq && (live.stick || live.lastSeq < 0);
  live.lastSeq = seq;

  // footer: act on the attack
  const foot = [];
  if (f && f.stage === "awaiting_passkey") {
    const left = Math.max(0, Math.round((f.expires_at || 0) - d.now));
    foot.push(el("a", { class: "btn primary", href: "/warden/approve/" + encodeURIComponent(f.challenge_id), text: "Approve with passkey" }),
      el("button", { text: "Deny (stop it)", onclick: (ev) => deny(f.challenge_id, ev.currentTarget).then(pollLive) }),
      el("span", { class: "muted", text: "⏱ " + Math.floor(left / 60) + ":" + String(left % 60).padStart(2, "0") }));
  } else if (!d.running) {
    foot.push(el("a", { class: "btn", href: "#testlab", text: "See all results" }));
  }
  $("live-foot").replaceChildren(...foot);
  // Follow new steps (after the footer has settled, since it changes the log's height),
  // unless you've scrolled up to read something.
  if (follow) requestAnimationFrame(() => {
    live.autoScroll = true; body.scrollTop = body.scrollHeight; live.stick = true;
    requestAnimationFrame(() => { live.autoScroll = false; });
  });
}

// ---------- loop ----------
let last = null, timer = null, ticker = null;
function render(d) {
  last = d;
  renderHeader(d); renderPending(d); renderAgents(d); renderFeed(d); renderDevices(d); renderTests(d);
  renderKpis(d); volumeChart(d.series); scoreChart(d.series, d.health.threshold);
  renderTimeline(d); renderBlocks(d); renderNewConns(d); renderSystem(d);
  if (d.tests.running && !live.open && !live.dismissed) openLive();   // e.g. a test started from another tab
  $("foot").textContent = "Updated " + clockS(d.now) + " · live (every 3 s) · session ends " + clock(d.session.expires_at);
}
async function refresh() {
  try {
    const d = await api("/dashboard/api/summary");
    $("login").hidden = true; $("app").hidden = false;
    render(d); startPolling();
  } catch (e) {
    if (e.status === 401) { stopPolling(); showLogin(); }
    else $("foot").textContent = "Couldn't reach the Hub (" + e.message + "). Retrying…";
  }
}
function startPolling() {
  if (!timer) timer = setInterval(() => { if (!document.hidden) refresh(); }, 3000);
  if (!ticker) ticker = setInterval(tickPending, 1000);
}
function stopPolling() { clearInterval(timer); clearInterval(ticker); timer = ticker = null; }

document.addEventListener("DOMContentLoaded", () => {
  $("signin").addEventListener("click", signIn);
  $("logout").addEventListener("click", signOut);
  $("run-all").addEventListener("click", () => runTest("all"));
  $("live-close").addEventListener("click", closeLive);
  $("live-body").addEventListener("scroll", () => {
    if (live.autoScroll) return;   // ignore our own scrolling; only you can unstick it
    const b = $("live-body");
    live.stick = b.scrollHeight - b.scrollTop - b.clientHeight < 40;
  });
  $("live-min").addEventListener("click", () => {
    const min = $("live").classList.toggle("min");
    $("live-min").textContent = min ? "▢" : "–";
    $("live-min").setAttribute("aria-label", min ? "Expand live view" : "Minimize live view");
  });
  document.addEventListener("visibilitychange", () => { if (!document.hidden && timer) refresh(); });
  let rz = null;
  addEventListener("resize", () => { clearTimeout(rz); rz = setTimeout(() => last && render(last), 150); });
  refresh();
});
"""
