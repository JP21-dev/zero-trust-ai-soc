"""Per-endpoint shipper tokens.

A token is "<endpoint_id>.<mac>", where mac = HMAC-SHA256(action_signing_secret,
"soc-endpoint-token|<endpoint_id>") in base64url. The key never leaves the Hub, so a
machine holding its own token (or the old shared token) can't mint one for another
machine. The Hub checks that every request's endpoint_id matches the token's.

  docker exec soc-orchestrator python -m app.tokens issue <endpoint_id>
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import re
import sys

from app.config import get_settings

_EP = re.compile(r"^[a-z0-9._-]{1,64}$")
_TOKEN = re.compile(r"^([a-z0-9._-]{1,64})\.([A-Za-z0-9_-]{43})$")


def _key() -> bytes:
    secret = get_settings().action_signing_secret
    if secret is None:
        raise RuntimeError("action_signing_secret is missing")
    return secret.get_secret_value().encode()


def _mac(endpoint_id: str) -> str:
    d = hmac.new(_key(), b"soc-endpoint-token|" + endpoint_id.encode(), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(d).rstrip(b"=").decode()


def issue(endpoint_id: str) -> str:
    ep = endpoint_id.strip().lower()
    if not _EP.match(ep):
        raise ValueError("endpoint id must be 1-64 chars of a-z 0-9 . _ -")
    return f"{ep}.{_mac(ep)}"


def endpoint_of(token: str | None) -> str | None:
    """The endpoint a valid per-endpoint token belongs to, else None."""
    m = _TOKEN.match(token or "")
    if not m:
        return None
    return m.group(1) if hmac.compare_digest(m.group(2), _mac(m.group(1))) else None


if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[1] != "issue":
        sys.exit("usage: python -m app.tokens issue <endpoint_id>")
    print(issue(sys.argv[2]))
