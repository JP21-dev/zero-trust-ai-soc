"""Passkey store, enrollment codes, and the WebAuthn ceremonies (py_webauthn).

Trust model:
  * Enrolling a passkey requires a one-time enrollment code that only someone
    with Docker access on the Hub can mint:
        docker exec soc-orchestrator python -m app.passkeys enroll-code
    Being on the tailnet is NOT enough to enroll a passkey.
  * Approving a Warden challenge requires a signature from an enrolled passkey
    with user verification (biometric/PIN) over that exact challenge, bound to
    the Hub's HTTPS origin. The sign counter is checked to catch cloned
    authenticators.

Data lives in WARDEN_DATA_DIR (a Docker volume), as small JSON files written
atomically:
  passkeys.json         enrolled credentials (public keys only; nothing secret)
  enrollment_code.json  SHA-256 of the current one-time code + its expiry

CLI (run inside the container):
  python -m app.passkeys enroll-code [--minutes 15]
  python -m app.passkeys list
  python -m app.passkeys revoke <credential-id-prefix>
"""
from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import hmac
import json
import os
import secrets
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers.exceptions import InvalidAuthenticationResponse, InvalidRegistrationResponse
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    AuthenticatorTransport,
    CredentialDeviceType,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from app.config import get_settings

settings = get_settings()

DATA_DIR = Path(settings.warden_data_dir)
STORE_FILE = DATA_DIR / "passkeys.json"
ENROLL_FILE = DATA_DIR / "enrollment_code.json"
USER_ID = b"soc-warden-admin"          # single-operator system
USER_NAME = "soc-warden-admin"
REG_SESSION_TTL = 300
MAX_REG_SESSIONS = 16


class PasskeyError(Exception):
    """Ceremony failed. The message is safe to show to the client."""


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# ---------------------------------------------------------------------------
# Storage
# ---------------------------------------------------------------------------
def _read_json(path: Path, default: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return default


def _write_json_atomic(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


_store_lock = asyncio.Lock()


def list_credentials() -> list[dict[str, Any]]:
    """Re-read on every call: the file is tiny, and CLI revocations apply at once."""
    return _read_json(STORE_FILE, [])


def has_credentials() -> bool:
    return bool(list_credentials())


def _find(cred_id: str) -> dict[str, Any] | None:
    return next((c for c in list_credentials() if hmac.compare_digest(c["id"], cred_id)), None)


def _descriptors() -> list[PublicKeyCredentialDescriptor]:
    out = []
    for c in list_credentials():
        transports = []
        for t in c.get("transports") or []:
            try:
                transports.append(AuthenticatorTransport(t))
            except ValueError:
                pass
        out.append(PublicKeyCredentialDescriptor(id=b64url_decode(c["id"]), transports=transports or None))
    return out


# ---------------------------------------------------------------------------
# Enrollment codes (minted by CLI, consumed by a successful registration)
# ---------------------------------------------------------------------------
def mint_enrollment_code(minutes: int) -> str:
    code = secrets.token_urlsafe(18)
    _write_json_atomic(ENROLL_FILE, {
        "sha256": hashlib.sha256(code.encode()).hexdigest(),
        "expires_at": int(time.time()) + minutes * 60,
    })
    return code


def _check_enrollment_code(code: str) -> str:
    """Return the code's hash if valid. Does not consume it."""
    rec = _read_json(ENROLL_FILE, None)
    if not rec or time.time() >= rec["expires_at"]:
        raise PasskeyError("no active enrollment code (mint one on the Hub)")
    digest = hashlib.sha256(code.encode()).hexdigest()
    if not hmac.compare_digest(digest, rec["sha256"]):
        raise PasskeyError("wrong enrollment code")
    return digest


def _consume_enrollment_code(digest: str) -> None:
    rec = _read_json(ENROLL_FILE, None)
    if not rec or not hmac.compare_digest(rec["sha256"], digest):
        raise PasskeyError("enrollment code was already used or replaced")
    ENROLL_FILE.unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# Registration ceremony
# ---------------------------------------------------------------------------
_reg_sessions: dict[str, tuple[bytes, float, str]] = {}   # session -> (challenge, expiry, code hash)


def registration_options(code: str) -> dict[str, Any]:
    digest = _check_enrollment_code(code)
    now = time.time()
    for sid in [s for s, v in _reg_sessions.items() if v[1] <= now]:
        del _reg_sessions[sid]
    if len(_reg_sessions) >= MAX_REG_SESSIONS:
        raise PasskeyError("too many enrollments in progress; try again in a few minutes")

    challenge = secrets.token_bytes(32)
    opts = generate_registration_options(
        rp_id=settings.webauthn_rp_id,
        rp_name=settings.warden_rp_name,
        user_id=USER_ID,
        user_name=USER_NAME,
        user_display_name="SOC Warden operator",
        challenge=challenge,
        timeout=120_000,
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.PREFERRED,
            user_verification=UserVerificationRequirement.REQUIRED,
        ),
        exclude_credentials=_descriptors(),   # don't enroll the same passkey twice
    )
    session_id = secrets.token_urlsafe(16)
    _reg_sessions[session_id] = (challenge, now + REG_SESSION_TTL, digest)
    return {"session_id": session_id, "options": json.loads(options_to_json(opts))}


async def register(session_id: str, credential: dict[str, Any], label: str) -> dict[str, Any]:
    session = _reg_sessions.pop(session_id, None)   # single use
    if session is None or time.time() >= session[1]:
        raise PasskeyError("enrollment session expired; start again")
    challenge, _, digest = session
    try:
        v = verify_registration_response(
            credential=credential,
            expected_challenge=challenge,
            expected_rp_id=settings.webauthn_rp_id,
            expected_origin=settings.webauthn_origin.rstrip("/"),
            require_user_verification=True,
        )
    except InvalidRegistrationResponse as exc:
        raise PasskeyError(f"registration rejected: {exc}") from None

    synced = v.credential_device_type == CredentialDeviceType.MULTI_DEVICE
    if synced and not settings.warden_allow_synced_passkeys:
        raise PasskeyError("synced (multi-device) passkeys are not allowed; "
                           "use a device-bound passkey or security key")

    record = {
        "id": b64url(v.credential_id),
        "public_key": b64url(v.credential_public_key),
        "sign_count": v.sign_count,
        "label": label[:64] or "passkey",
        "aaguid": v.aaguid,
        "device_type": v.credential_device_type.value,
        "backed_up": v.credential_backed_up,
        "transports": (credential.get("response") or {}).get("transports") or [],
        "created_at": _now_iso(),
        "last_used_at": None,
    }
    async with _store_lock:
        _consume_enrollment_code(digest)   # raises if someone else used it first
        creds = list_credentials()
        if any(c["id"] == record["id"] for c in creds):
            raise PasskeyError("this passkey is already enrolled")
        creds.append(record)
        _write_json_atomic(STORE_FILE, creds)
    return {k: record[k] for k in ("id", "label", "device_type", "backed_up", "created_at")}


# ---------------------------------------------------------------------------
# Authentication ceremony (approving a Warden challenge)
# ---------------------------------------------------------------------------
def authentication_options(challenge_id: str, timeout_ms: int) -> dict[str, Any]:
    """The challenge the phone signs is the Warden challenge itself (32 random bytes)."""
    opts = generate_authentication_options(
        rp_id=settings.webauthn_rp_id,
        challenge=b64url_decode(challenge_id),
        timeout=max(5_000, min(timeout_ms, 120_000)),
        allow_credentials=_descriptors(),
        user_verification=UserVerificationRequirement.REQUIRED,
    )
    return json.loads(options_to_json(opts))


async def verify_signature(*, challenge_id: str, credential_id: str, client_data_json: str,
                           authenticator_data: str, signature: str,
                           user_handle: str | None) -> dict[str, Any]:
    """Check the passkey signature. Returns the approval record for the order."""
    async with _store_lock:
        cred = _find(credential_id)
        if cred is None:
            raise PasskeyError("passkey is not enrolled (or was revoked)")
        response: dict[str, Any] = {
            "clientDataJSON": client_data_json,
            "authenticatorData": authenticator_data,
            "signature": signature,
        }
        if user_handle:
            response["userHandle"] = user_handle
        try:
            v = verify_authentication_response(
                credential={"id": credential_id, "rawId": credential_id, "type": "public-key",
                            "response": response, "clientExtensionResults": {}},
                expected_challenge=b64url_decode(challenge_id),
                expected_rp_id=settings.webauthn_rp_id,
                expected_origin=settings.webauthn_origin.rstrip("/"),
                credential_public_key=b64url_decode(cred["public_key"]),
                credential_current_sign_count=cred["sign_count"],
                require_user_verification=True,
            )
        except InvalidAuthenticationResponse as exc:
            raise PasskeyError(f"signature rejected: {exc}") from None

        creds = list_credentials()
        for c in creds:
            if c["id"] == cred["id"]:
                c["sign_count"] = v.new_sign_count
                c["last_used_at"] = _now_iso()
        _write_json_atomic(STORE_FILE, creds)

    return {
        "method": "webauthn",
        "credential_id": cred["id"][:128],
        "credential_label": cred["label"],
        "device_type": cred.get("device_type"),
        "sign_count": v.new_sign_count,
        "user_verified": True,
        "signature_checked": True,
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def _cli() -> None:
    p = argparse.ArgumentParser(prog="python -m app.passkeys")
    sub = p.add_subparsers(dest="cmd", required=True)
    e = sub.add_parser("enroll-code", help="mint a one-time passkey enrollment code")
    e.add_argument("--minutes", type=int, default=15)
    sub.add_parser("list", help="list enrolled passkeys")
    r = sub.add_parser("revoke", help="remove an enrolled passkey")
    r.add_argument("id_prefix")
    args = p.parse_args()

    if args.cmd == "enroll-code":
        code = mint_enrollment_code(max(1, min(args.minutes, 60)))
        origin = settings.webauthn_origin.rstrip("/")
        print(f"Enrollment code (single use, {args.minutes} min): {code}")
        print(f"Open on your phone: {origin}/warden/enroll")
    elif args.cmd == "list":
        creds = list_credentials()
        if not creds:
            print("no passkeys enrolled")
        for c in creds:
            print(f"{c['id'][:16]}…  {c['label']:<20} {c['device_type']:<14} "
                  f"created {c['created_at']}  last used {c['last_used_at'] or 'never'}")
    elif args.cmd == "revoke":
        creds = list_credentials()
        keep = [c for c in creds if not c["id"].startswith(args.id_prefix)]
        if len(creds) - len(keep) != 1:
            sys.exit(f"prefix matched {len(creds) - len(keep)} passkeys; need exactly 1")
        _write_json_atomic(STORE_FILE, keep)
        print("revoked")


if __name__ == "__main__":
    _cli()
