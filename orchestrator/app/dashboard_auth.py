"""Dashboard sign-in: an enrolled passkey, then a short-lived session cookie.

Being on the tailnet is not enough to read the dashboard (it shows command
lines, IPs and pending challenge IDs). Sign-in is a WebAuthn assertion from an
already-enrolled passkey, over a fresh random login challenge. That challenge
is never a Warden challenge_id, so a dashboard sign-in can't approve anything,
and an approval assertion can't be replayed as a sign-in.

Sessions:
  * random 256-bit token in a __Host- cookie: Secure, HttpOnly, SameSite=Strict, Path=/
  * only its SHA-256 is kept, in memory: a Hub restart signs everyone out
  * expire after DASHBOARD_SESSION_HOURS (default 12)
"""
from __future__ import annotations

import hashlib
import secrets
import time
from typing import Any

from app import passkeys

COOKIE_NAME = "__Host-soc_dash"
LOGIN_TTL = 120
MAX_LOGINS = 32
MAX_SESSIONS = 16

_logins: dict[str, float] = {}              # login challenge (b64url) -> expiry
_sessions: dict[str, dict[str, Any]] = {}   # sha256(token) -> session


class LoginError(Exception):
    """Sign-in failed. The message is safe to show to the client."""


def _sweep(now: float) -> None:
    for k in [k for k, exp in _logins.items() if exp <= now]:
        del _logins[k]
    for k in [k for k, s in _sessions.items() if s["expires_at"] <= now]:
        del _sessions[k]


def begin_login() -> dict[str, Any]:
    if not passkeys.has_credentials():
        raise LoginError("no passkey enrolled yet; enroll one at /warden/enroll")
    now = time.time()
    _sweep(now)
    if len(_logins) >= MAX_LOGINS:
        raise LoginError("too many sign-ins in progress; try again in a minute")
    login_id = passkeys.b64url(secrets.token_bytes(32))
    _logins[login_id] = now + LOGIN_TTL
    return {"login_id": login_id,
            "options": passkeys.authentication_options(login_id, LOGIN_TTL * 1000)}


async def finish_login(login_id: str, *, credential_id: str, client_data_json: str,
                       authenticator_data: str, signature: str, user_handle: str | None,
                       session_hours: float) -> tuple[str, dict[str, Any]]:
    expires = _logins.pop(login_id, None)   # single use
    if expires is None or time.time() >= expires:
        raise LoginError("sign-in expired; try again")
    try:
        approval = await passkeys.verify_signature(
            challenge_id=login_id, credential_id=credential_id, client_data_json=client_data_json,
            authenticator_data=authenticator_data, signature=signature, user_handle=user_handle)
    except passkeys.PasskeyError as exc:
        raise LoginError(str(exc)) from None

    now = time.time()
    _sweep(now)
    if len(_sessions) >= MAX_SESSIONS:   # drop the oldest
        del _sessions[min(_sessions, key=lambda k: _sessions[k]["created_at"])]
    token = secrets.token_urlsafe(32)
    session = {"created_at": now, "expires_at": now + session_hours * 3600,
               "label": approval.get("credential_label") or "passkey"}
    _sessions[hashlib.sha256(token.encode()).hexdigest()] = session
    return token, session


def check_session(token: str | None) -> dict[str, Any] | None:
    if not token or len(token) > 128:
        return None
    s = _sessions.get(hashlib.sha256(token.encode()).hexdigest())
    if s is None or time.time() >= s["expires_at"]:
        return None
    return s


def end_session(token: str | None) -> None:
    if token:
        _sessions.pop(hashlib.sha256(token.encode()).hexdigest(), None)
