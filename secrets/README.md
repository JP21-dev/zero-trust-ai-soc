# secrets/

Docker secrets, mounted read-only at `/run/secrets/<name>` in the orchestrator.
Git-ignored. One value per file, no trailing newline.

| File | Contents | Required? |
|---|---|---|
| `gemini_api_key.txt` | Gemini API key | No. If empty, the Strategist falls back to local heuristic scoring |
| `discord_webhook_url.txt` | Full Discord webhook URL (it is a bearer credential) | No, but you get no Warden alerts without it |
| `shipper_token.txt` | Bearer token each endpoint's shipper sends to `POST /ingest` | Yes. The orchestrator refuses to start without it |
| `action_signing_secret.txt` | HMAC key that signs Warden challenges (at least 32 characters) | Yes. The orchestrator refuses to start without it |
| `execution_signing_key.txt` | Ed25519 private key seed (32 bytes, base64url) that signs approved execution orders | Yes. The orchestrator refuses to start without it |
| `abusech_auth_key.txt` | Free abuse.ch Auth-Key (https://auth.abuse.ch/) for the daily MalwareBazaar known-malware list and ThreatFox malware domains / C2 servers | No. Leave it empty and the Hub uses only EICAR, your custom list and the built-in test domain |

## Creating them (PowerShell, from the SoC folder)

Paste values you already have:

```powershell
Set-Content -NoNewline -Encoding ascii secrets\gemini_api_key.txt 'YOUR_KEY'
Set-Content -NoNewline -Encoding ascii secrets\discord_webhook_url.txt 'https://discord.com/api/webhooks/...'
```

Generate the two random ones (48 bytes from the OS crypto RNG, base64url):

```powershell
function New-Token([int]$n = 48) { $b = [byte[]]::new($n); [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b); [Convert]::ToBase64String($b).TrimEnd('=').Replace('+','-').Replace('/','_') }
Set-Content -NoNewline -Encoding ascii secrets\shipper_token.txt (New-Token)
Set-Content -NoNewline -Encoding ascii secrets\action_signing_secret.txt (New-Token)
Set-Content -NoNewline -Encoding ascii secrets\execution_signing_key.txt (New-Token 32)
```

Each endpoint needs a copy of `shipper_token.txt`; `shipper/install-endpoint.ps1` installs it.
Never copy `action_signing_secret.txt` or `execution_signing_key.txt` anywhere. The
enforcer only needs the matching **public** key, served at `GET /warden/public-key`.

Then restrict the folder to your user account:

```powershell
icacls secrets /inheritance:r /grant:r "${env:USERNAME}:(OI)(CI)F"
```
