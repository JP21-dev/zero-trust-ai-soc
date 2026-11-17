"""Enforcer: applies Hub-signed execution orders on this endpoint.

The shipper calls Enforcer.poll() once per cycle. For each order the Hub hands
back, the enforcer trusts NOTHING the Hub's HTTP response says. It only acts on
the Ed25519-signed payload bytes, and only if:

  * the signature verifies with the Hub public key PINNED on this machine
    (python shipper.py --pin-hub-key, done once over HTTPS);
  * it is a v1 soc.execution_order for THIS endpoint_id;
  * it is inside its validity window (60 s clock-skew allowance);
  * it was approved with a real passkey signature (approval.method == "webauthn"),
    unless SOC_ALLOW_SIMULATED_ORDERS=1 for development;
  * the action is supported (block_ip) and the target is a sane, routable IP
    that isn't the tailnet or the Hub (so an order can never cut the SOC off);
  * its order_id has never been applied before (persisted, survives restarts).

Blocks are applied as Windows Firewall rules (inbound + outbound, all profiles)
via netsh, and reported back to the Hub. On non-Windows systems, or with
SOC_ENFORCE_DRY_RUN=1, a log-only backend records what it would have done.
"""
from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import logging
import os
import re
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlencode, urlparse

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

log = logging.getLogger("soc-shipper")

IS_WINDOWS = sys.platform == "win32"
CLOCK_SKEW = 60
SUPPORTED_ACTIONS = {"block_ip"}
TAILNET = (ipaddress.ip_network("100.64.0.0/10"), ipaddress.ip_network("fd7a:115c:a1e0::/48"))
RULE_PREFIX = "SOC-Warden"
_SAFE_NAME = re.compile(r"^[A-Za-z0-9._-]+$")


class OrderRejected(Exception):
    pass


def _b64url_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


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
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


# ---------------------------------------------------------------------------
# Pinned Hub key
# ---------------------------------------------------------------------------
class PinnedKey:
    def __init__(self, data: dict[str, Any]) -> None:
        if data.get("alg") != "Ed25519":
            raise ValueError("pinned key is not Ed25519")
        raw = _b64url_decode(str(data.get("public_key_b64url", "")))
        if len(raw) != 32:
            raise ValueError("pinned key must be 32 bytes")
        key_id = hashlib.sha256(raw).hexdigest()[:16]
        if data.get("key_id") != key_id:
            raise ValueError("pinned key_id doesn't match the key")
        self.key_id = key_id
        self.public_key_b64url = data["public_key_b64url"]
        self._key = Ed25519PublicKey.from_public_bytes(raw)

    @classmethod
    def load(cls, path: Path) -> "PinnedKey":
        return cls(json.loads(path.read_text(encoding="utf-8-sig")))

    def verify(self, signature: bytes, payload: bytes) -> None:
        self._key.verify(signature, payload)   # raises InvalidSignature


def pin_hub_key(url: str, path: Path) -> PinnedKey:
    """One-time trust-on-first-use fetch. HTTPS only, so the ts.net certificate
    authenticates the Hub. Compare the printed key_id with the Hub's startup log."""
    if urlparse(url).scheme != "https":
        raise ValueError("pin the key over https:// only")
    with urllib.request.urlopen(url, timeout=30) as resp:
        data = json.loads(resp.read())
    key = PinnedKey(data)
    _write_json_atomic(path, {"alg": "Ed25519", "key_id": key.key_id,
                              "public_key_b64url": key.public_key_b64url,
                              "pinned_from": url, "pinned_at": _now_iso()})
    return key


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------
def validate_target(ip_text: Any, protected: set[str]) -> str:
    try:
        ip = ipaddress.ip_address(str(ip_text))
    except ValueError:
        raise OrderRejected(f"target is not an IP address: {ip_text!r}") from None
    if ip.is_loopback or ip.is_unspecified or ip.is_multicast or ip.is_link_local or ip.is_reserved:
        raise OrderRejected(f"refusing to block special address {ip}")
    if any(ip in net for net in TAILNET):
        raise OrderRejected(f"refusing to block tailnet address {ip} (would cut off the SOC)")
    if str(ip) in protected:
        raise OrderRejected(f"refusing to block protected address {ip}")
    return str(ip)


class OrderVerifier:
    def __init__(self, key: PinnedKey, endpoint_id: str, *, allow_simulated: bool = False,
                 protected_ips: set[str] | None = None) -> None:
        self.key = key
        self.endpoint_id = endpoint_id
        self.allow_simulated = allow_simulated
        self.protected = protected_ips or set()

    def verify(self, signed: dict[str, Any], now: float | None = None) -> dict[str, Any]:
        """Return the verified order, built ONLY from the signed payload bytes."""
        now = time.time() if now is None else now
        try:
            payload = _b64url_decode(signed["payload_b64url"])
            signature = _b64url_decode(signed["signature_b64url"])
        except (KeyError, TypeError, ValueError):
            raise OrderRejected("malformed order envelope") from None
        if signed.get("alg") != "Ed25519" or signed.get("key_id") != self.key.key_id:
            raise OrderRejected("order is not signed with the pinned Hub key")
        try:
            self.key.verify(signature, payload)
        except InvalidSignature:
            raise OrderRejected("signature does not verify") from None

        try:
            order = json.loads(payload)
        except ValueError:
            raise OrderRejected("signed payload is not JSON") from None
        if not isinstance(order, dict) or order.get("v") != 1 or order.get("type") != "soc.execution_order":
            raise OrderRejected("not a v1 execution order")
        if order.get("key_id") != self.key.key_id:
            raise OrderRejected("payload key_id mismatch")
        if order.get("endpoint_id") != self.endpoint_id:
            raise OrderRejected(f"order is for {order.get('endpoint_id')!r}, not this endpoint")
        try:
            nbf, exp = int(order["not_before"]), int(order["expires_at"])
        except (KeyError, TypeError, ValueError):
            raise OrderRejected("order has no validity window") from None
        if now < nbf - CLOCK_SKEW:
            raise OrderRejected("order is not valid yet (check this machine's clock)")
        if now > exp + CLOCK_SKEW:
            raise OrderRejected("order has expired")

        approval = order.get("approval") or {}
        real = approval.get("method") == "webauthn" and approval.get("signature_checked") is True
        if not real and not (self.allow_simulated and approval.get("method") == "webauthn-simulated"):
            raise OrderRejected(f"approval method {approval.get('method')!r} is not accepted")
        if approval.get("user_verified") is not True:
            raise OrderRejected("approval lacked user verification")

        if order.get("action") not in SUPPORTED_ACTIONS:
            raise OrderRejected(f"unsupported action {order.get('action')!r}")
        order["target_ip"] = validate_target(order.get("target_ip"), self.protected)
        if not _SAFE_NAME.match(str(order.get("order_id", ""))):
            raise OrderRejected("bad order_id")
        return order


# ---------------------------------------------------------------------------
# Firewall backends
# ---------------------------------------------------------------------------
def rule_name(direction: str, ip: str, order_id: str) -> str:
    name = f"{RULE_PREFIX}-{direction}-{ip.replace(':', '_')}-{order_id[:10]}"
    if not _SAFE_NAME.match(name):   # no spaces/quotes, so argv quoting can't be abused
        raise OrderRejected("unsafe rule name")
    return name


class WindowsFirewall:
    """netsh advfirewall; needs an elevated process."""
    name = "windows-firewall"

    def _netsh(self, *args: str) -> None:
        r = subprocess.run(["netsh", "advfirewall", "firewall", *args], capture_output=True,
                           text=True, timeout=30, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        if r.returncode != 0:
            raise RuntimeError((r.stdout + r.stderr).strip()[:300] or f"netsh exit {r.returncode}")

    def block(self, ip: str, order_id: str) -> list[str]:
        names = []
        for direction in ("out", "in"):
            name = rule_name(direction, ip, order_id)
            self._netsh("add", "rule", f"name={name}", f"dir={direction}", "action=block",
                        f"remoteip={ip}", "enable=yes", "profile=any",
                        f"description={RULE_PREFIX}-order-{order_id}")
            names.append(name)
        return names

    def unblock(self, name: str) -> None:
        if not name.startswith(RULE_PREFIX) or not _SAFE_NAME.match(name):
            raise ValueError("only SOC-Warden rules can be removed")
        self._netsh("delete", "rule", f"name={name}")


class LogOnlyFirewall:
    """Non-Windows or SOC_ENFORCE_DRY_RUN=1: record what would happen."""
    name = "log-only"

    def __init__(self) -> None:
        self.applied: list[str] = []

    def block(self, ip: str, order_id: str) -> list[str]:
        names = [rule_name(d, ip, order_id) for d in ("out", "in")]
        log.warning("DRY RUN: would block %s (rules %s)", ip, ", ".join(names))
        self.applied.extend(names)
        return names

    def unblock(self, name: str) -> None:
        log.warning("DRY RUN: would remove rule %s", name)


def default_firewall() -> WindowsFirewall | LogOnlyFirewall:
    if IS_WINDOWS and os.environ.get("SOC_ENFORCE_DRY_RUN", "0") != "1":
        return WindowsFirewall()
    return LogOnlyFirewall()


# ---------------------------------------------------------------------------
# Enforcer
# ---------------------------------------------------------------------------
class Enforcer:
    def __init__(self, *, hub_base_url: str, token: str, endpoint_id: str, state_dir: Path,
                 key: PinnedKey, allow_simulated: bool = False,
                 protected_ips: set[str] | None = None, firewall=None) -> None:
        self.base = hub_base_url.rstrip("/")
        self.token = token
        self.endpoint_id = endpoint_id
        self.verifier = OrderVerifier(key, endpoint_id, allow_simulated=allow_simulated,
                                      protected_ips=protected_ips)
        self.firewall = firewall or default_firewall()
        self.applied_file = state_dir / "applied_orders.json"
        self.blocks_file = state_dir / "blocks.json"

    # --- hub I/O ---
    def _request(self, method: str, path: str, body: dict | None = None) -> Any:
        data = None if body is None else json.dumps(body).encode()
        req = urllib.request.Request(self.base + path, data=data, method=method, headers={
            "X-SOC-Token": self.token, "User-Agent": "soc-shipper/1",
            **({"Content-Type": "application/json"} if data else {})})
        with urllib.request.urlopen(req, timeout=20) as resp:
            return json.loads(resp.read() or b"{}")

    def poll(self) -> int:
        """Fetch and handle orders. Returns how many orders were seen."""
        try:
            resp = self._request("GET", "/warden/orders?" + urlencode({"endpoint_id": self.endpoint_id}))
        except (urllib.error.URLError, OSError, ValueError) as exc:
            log.debug("order poll failed: %s", exc)
            return 0
        orders = resp.get("orders") if isinstance(resp, dict) else None
        for signed in orders or []:
            if isinstance(signed, dict):
                self.handle(signed)
        return len(orders or [])

    def _ack(self, order_id: str, status: str, detail: str = "") -> None:
        if not _SAFE_NAME.match(order_id or ""):
            return
        try:
            self._request("POST", f"/warden/orders/{order_id}/ack",
                          {"endpoint_id": self.endpoint_id, "status": status, "detail": detail[:500]})
        except urllib.error.HTTPError as exc:
            if exc.code == 404:   # already acked, expired, or a forged order the Hub never issued
                log.info("hub has no open order %s to ack", order_id)
            else:
                log.warning("ack for order %s failed: HTTP %d", order_id, exc.code)
        except (urllib.error.URLError, OSError, ValueError) as exc:
            log.warning("ack for order %s failed: %s", order_id, exc)

    # --- the decision ---
    def handle(self, signed: dict[str, Any]) -> str:
        claimed_id = str((signed.get("order") or {}).get("order_id", ""))   # unverified: ack routing only
        try:
            order = self.verifier.verify(signed)
        except OrderRejected as exc:
            log.error("REJECTED order %s: %s", claimed_id or "?", exc)
            self._ack(claimed_id, "rejected", str(exc))
            return "rejected"

        oid, ip = order["order_id"], order["target_ip"]
        applied = _read_json(self.applied_file, {})
        if oid in applied:
            log.info("order %s already applied; re-acking", oid)
            self._ack(oid, "already_applied")
            return "already_applied"

        try:
            rules = self.firewall.block(ip, oid)
        except Exception as exc:   # netsh failure, not elevated, ...
            log.error("FAILED to apply order %s (block %s): %s", oid, ip, exc)
            self._ack(oid, "failed", str(exc))
            return "failed"

        now = time.time()
        applied = {k: v for k, v in applied.items() if v > now - 86400}   # keep a day past expiry
        applied[oid] = int(order["expires_at"])
        _write_json_atomic(self.applied_file, applied)
        blocks = _read_json(self.blocks_file, [])
        blocks.append({"ip": ip, "order_id": oid, "rules": rules, "applied_at": _now_iso(),
                       "approved_by": (order.get("approval") or {}).get("credential_label"),
                       "threat_score": order.get("threat_score"), "backend": self.firewall.name})
        _write_json_atomic(self.blocks_file, blocks)
        log.warning("ENFORCED order %s: blocked %s via %s", oid, ip, self.firewall.name)
        self._ack(oid, "applied", f"{self.firewall.name}: {', '.join(rules)}")
        return "applied"


# ---------------------------------------------------------------------------
# Operator commands
# ---------------------------------------------------------------------------
def list_blocks(state_dir: Path) -> list[dict[str, Any]]:
    return _read_json(state_dir / "blocks.json", [])


def unblock(state_dir: Path, ip: str, firewall=None) -> int:
    fw = firewall or default_firewall()
    blocks = list_blocks(state_dir)
    keep, removed = [], 0
    for b in blocks:
        if b["ip"] == ip:
            for name in b["rules"]:
                fw.unblock(name)
            removed += 1
        else:
            keep.append(b)
    _write_json_atomic(state_dir / "blocks.json", keep)
    return removed
