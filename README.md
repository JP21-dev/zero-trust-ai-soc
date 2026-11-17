# Zero-Trust Multi-Agent AI SOC

A self-hosted, home-lab **Security Operations Center** where four AI agents watch your
Windows machines' network activity, and **nothing gets blocked until you approve it with
a passkey on your phone**.

```
 Endpoints (Windows)            Hub (Docker, Tailscale-only)                     Your phone
 ────────────────────           ─────────────────────────────────────            ──────────
 shipper ── new connections ──► 1. Gatekeeper  drop known-safe apps, strip
   every 10 s                   │              prompt injections, catch disguises
                                2. Detective   "seen this before?" (ChromaDB)
                                3. Strategist  score 0-100: malware rules + Gemini
                                │
                                4. Warden      < 85: log (and learn if clean)
                                               ≥ 85: PAUSE ─── Discord alert ───► 🛑
                                                                                  approve with
                                 signed order ◄── verify passkey (WebAuthn) ◄──── fingerprint
 enforcer ◄── polls ─────────── order queue
   checks Ed25519 signature
   Windows Firewall block ──── result ──► Discord 🛡️ + dashboard
```

It comes with a live dashboard (dark, purple, passkey sign-in) that shows each agent
working in real time, every device and its role, and a **test lab** that fires fake attacks
through the real pipeline and posts pass/fail to Discord.

> **Status: hobby / educational project.** It is a learning tool and a second layer, not a
> replacement for Microsoft Defender or a commercial EDR. Read [Limitations](#limitations)
> before relying on it.

## Features

- **Human-in-the-loop by design.** The AI can only *propose*. Every block needs a FIDO2
  passkey signature (fingerprint/PIN) over that exact action, within 120 s, or it is denied.
- **Signed, single-use execution orders.** Approved actions become Ed25519-signed orders.
  Endpoints verify them against a pinned public key and reject anything altered, expired,
  replayed, simulated, or aimed at the Hub/tailnet.
- **Prompt-injection hardening.** Telemetry is untrusted data: injections are stripped
  (including leetspeak, spacing and Unicode tricks) before the LLM sees it, the LLM's output
  is schema-validated, and it can only *raise* the deterministic score, never lower it.
- **Works without an LLM.** Built-in rules catch common malware behavior: programs in
  Temp/Downloads/Public, attacker ports (4444, 1337, Cobalt Strike, Tor…), Windows admin
  tools calling out, hidden/encoded PowerShell, download cradles, and fake system binaries
  (e.g. `svchost.exe` outside `C:\Windows`).
- **Memory that can't be poisoned.** Only clean, low-score connections are learned as
  normal; anything with a red flag is never learned.
- **No alert spam.** One open approval per threat; a denied threat is muted for 30 minutes.
- **Zero-trust networking.** Everything is reachable only over your Tailscale tailnet. The
  vector DB has no network egress at all. Containers are read-only, non-root, no capabilities.
- **Dashboard + test lab.** 10 attack scenarios (prompt injection, masquerading, plain
  malware, hidden PowerShell, fake svchost, memory, full attack chain, and a false-alarm
  check), with results posted to Discord.

## What you need

| Role | What | Notes |
|---|---|---|
| **Hub** | Any always-on machine with Docker | Tested on Windows 11 + Docker Desktop (WSL2) |
| **Endpoints** | Windows 10/11 machines to protect | The Hub can protect itself too |
| **Phone** | Anything with passkeys (Android 9+, iOS 16+) | Approves actions, receives alerts |
| **Tailscale** | On the Hub, every endpoint, and the phone | With MagicDNS + HTTPS certificates enabled |
| **Discord** | A server where you can create a webhook | Optional but strongly recommended |
| **Gemini API key** | From [AI Studio](https://aistudio.google.com) | Optional; built-in rules work without it |

## Setup

### 1. Hub

```powershell
git clone https://github.com/JP21-dev/zero-trust-ai-soc.git
cd zero-trust-ai-soc
Copy-Item .env.example .env
```

Edit `.env`:

- `TAILSCALE_IP`: the Hub's Tailscale IPv4 (`tailscale ip -4`)
- `WEBAUTHN_RP_ID` / `WEBAUTHN_ORIGIN`: the Hub's MagicDNS name, e.g.
  `soc-hub.your-tailnet.ts.net` / `https://soc-hub.your-tailnet.ts.net`

Create the secrets (see [`secrets/README.md`](secrets/README.md) for details):

```powershell
function New-Token([int]$n = 48) { $b = [byte[]]::new($n); [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b); [Convert]::ToBase64String($b).TrimEnd('=').Replace('+','-').Replace('/','_') }
Set-Content -NoNewline -Encoding ascii secrets\shipper_token.txt (New-Token)
Set-Content -NoNewline -Encoding ascii secrets\action_signing_secret.txt (New-Token)
Set-Content -NoNewline -Encoding ascii secrets\execution_signing_key.txt (New-Token 32)
Set-Content -NoNewline -Encoding ascii secrets\gemini_api_key.txt 'YOUR_KEY_OR_LEAVE_EMPTY'
Set-Content -NoNewline -Encoding ascii secrets\discord_webhook_url.txt 'https://discord.com/api/webhooks/...'
icacls secrets /inheritance:r /grant:r "${env:USERNAME}:(OI)(CI)F"
```

Start it, and put HTTPS in front of it with Tailscale (passkeys require HTTPS):

```powershell
docker compose up -d --build
tailscale serve --bg --https=443 http://127.0.0.1:8080
docker compose logs soc-orchestrator | Select-String key_id   # note the signing key_id
```

### 2. Enroll your phone's passkey

```powershell
docker compose exec soc-orchestrator python -m app.passkeys enroll-code
```

On your phone (on the tailnet), open `https://<hub>.ts.net/warden/enroll`, paste the code,
and create the passkey. You'll get a 🔑 notice in Discord.

### 3. Protect endpoints

From an **admin PowerShell** in the `shipper` folder:

```powershell
# On the Hub itself (URLs and token are read from the project folder):
powershell -ExecutionPolicy Bypass -File .\install-endpoint.ps1 -ExpectedKeyId <key_id>

# On any other Windows machine (copy the shipper folder over; you'll paste the token):
powershell -ExecutionPolicy Bypass -File .\install-endpoint.ps1 `
    -HubUrl http://<hub-tailscale-ip>:8080/ingest `
    -HubKeyUrl https://<hub>.ts.net/warden/public-key -ExpectedKeyId <key_id>
```

The installer uses an all-users Python, locks the install folder so normal users can't
modify code that runs as SYSTEM, pins the Hub's key, does a dry run, and registers a
startup task. Add `-DryRunEnforcement` to log blocks without touching the firewall first.

### 4. Open the dashboard

`https://<hub>.ts.net/dashboard`: sign in with your passkey, then try **Test lab → Run all tests**.

## Limitations

Be honest with yourself about what this does **not** do:

- **Network activity only.** It sees new outbound/inbound connections and the process behind
  them. It does not see file encryption (ransomware), file writes, registry, logins, USB,
  or connections shorter than the 10 s sampling interval.
- **Rules need two red flags on one connection to alert.** A program in `Program Files`
  calling out on port 443 looks like any normal app.
- **Blocks are per endpoint and Windows-only.** A block on one machine doesn't protect
  others. On a Docker Desktop Hub, Windows Firewall does not cover the containers' WSL2 traffic.
- **Shared shipper token.** Every endpoint uses the same token (orders are still signed per
  endpoint, so one endpoint can't act on another's).
- **Blocks don't expire** and the dashboard isn't told about `--unblock`.
- **Single operator.** One set of passkeys; no user management.
- Tested by its author on a small home tailnet. Expect rough edges.

## Repository layout

```
docker-compose.yml        Hub: orchestrator + ChromaDB, Tailscale-only ports
.env.example              Hub settings template (copy to .env)
secrets/                  Docker secrets (git-ignored; see secrets/README.md)
orchestrator/app/
  main.py                 FastAPI + LangGraph pipeline (the four agents), Warden, APIs
  passkeys.py             WebAuthn enrollment/verification (py_webauthn)
  dashboard_*.py          Dashboard pages, passkey sign-in
  testlab.py              Test-attack scenarios
  activity.py             History for the dashboard
shipper/
  shipper.py              Endpoint telemetry shipper
  enforcer.py             Verifies signed orders, applies Windows Firewall blocks
  install-endpoint.ps1    One-command Windows installer
```

## Security

See [SECURITY.md](SECURITY.md) for the threat model and how to report a vulnerability.

## License

MIT. See [LICENSE](LICENSE).
