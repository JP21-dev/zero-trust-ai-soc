# Security

## Reporting a vulnerability

Please **don't open a public issue** for security problems. Use GitHub's
**"Report a vulnerability"** button (Security tab → Advisories) to report privately.
Include what you found, how to reproduce it, and the impact.

## Threat model (short version)

**Trusted:** the Hub host and its Docker daemon, the operator's enrolled passkeys, and the
pinned Hub public key on each endpoint.

**Untrusted:** all telemetry (it may be attacker-written), the LLM's output, the network
between devices (mitigated by Tailscale), and anyone on the tailnet who isn't the operator.

Key properties the code is designed to keep:

1. **No action without a passkey.** The Warden only creates a pending, HMAC-signed,
   single-use challenge. Executing anything requires a WebAuthn assertion with user
   verification from an enrolled passkey, bound to the Hub's HTTPS origin, within the window.
2. **Endpoints trust signatures, not the Hub's API.** Orders are Ed25519-signed; endpoints
   verify the exact signed bytes with a key pinned at install, and refuse orders that are
   expired, replayed, for another endpoint, not passkey-approved, or aimed at
   loopback/tailnet/the Hub.
3. **Telemetry can't steer the AI down.** Prompt injections are stripped before the LLM;
   the LLM's score can only raise the deterministic floor; its target IP must appear in
   the telemetry.
4. **Nothing is exposed beyond the tailnet.** Ports bind to the Tailscale IP (and
   127.0.0.1 for `tailscale serve`); ChromaDB has no published ports and no egress.
5. **Enrollment needs Hub access.** New passkeys require a one-time code minted inside
   the container; every enrollment, sign-in and approval is announced in Discord.

## Operator responsibilities

- Keep `secrets/` private. Never share `action_signing_secret.txt` or
  `execution_signing_key.txt`; endpoints only need the shipper token and the public key.
- Treat the Discord webhook URL as a secret (anyone with it can post to your channel).
- Keep Docker, Tailscale and the base images updated. Pin the ChromaDB image tag once things work.
- Review Discord notices: an approval, enrollment or sign-in you didn't make is an incident.
