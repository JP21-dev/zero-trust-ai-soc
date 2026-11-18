"""Self-update for the endpoint agent.

About every 5 minutes the agent asks the Hub for the current release and installs
it only if YOUR passkey approved it. The WebAuthn challenge your phone signed is the
SHA-256 of the release manifest, and this file checks that signature itself against
the passkey public keys pinned at install time (hub_pubkey.json). A Hub that's been
taken over can't produce a release your endpoints accept.

A release is installed when:
  * the passkey signature, origin, RP ID and user-verification flag all check out;
  * its number is higher than the installed one and it isn't one that failed here;
  * requirements.txt is unchanged (a new Python package needs the installer);
  * every downloaded file matches the manifest's SHA-256 and size.

Then the changed files are backed up, swapped in, and the agent exits with
RESTART_CODE so agent_launcher.py starts the new version. If the new version
doesn't come up healthy, the launcher puts the backup back.
"""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import shutil
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlencode

log = logging.getLogger("soc-shipper")

RELEASE_FILES = ("shipper.py", "enforcer.py", "sysmon.py", "winlog.py", "updater.py", "sysmon-config.xml")
RESTART_CODE = 75
MAX_FILE_BYTES = 2 * 2**20
FLAG_USER_PRESENT, FLAG_USER_VERIFIED = 0x01, 0x04


class ReleaseRejected(Exception):
    pass


def _b64d(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _sha_file(path: Path) -> str | None:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return None


def _write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".upd.")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(data, f)
    os.replace(tmp, path)


def _read_json(path: Path, default: Any = None) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, ValueError):
        return default


def _check_signature(spki_b64: str, signature: bytes, data: bytes) -> None:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
    key = serialization.load_der_public_key(_b64d(spki_b64))
    try:
        if isinstance(key, ec.EllipticCurvePublicKey):
            key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
        elif isinstance(key, ed25519.Ed25519PublicKey):
            key.verify(signature, data)
        elif isinstance(key, rsa.RSAPublicKey):
            key.verify(signature, data, padding.PKCS1v15(), hashes.SHA256())
        else:
            raise ReleaseRejected("unsupported passkey algorithm")
    except InvalidSignature:
        raise ReleaseRejected("the passkey signature doesn't verify") from None


def verify_release(release: dict[str, Any], pin: dict[str, Any]) -> dict[str, Any]:
    """Check your passkey approved exactly this manifest. Returns the manifest."""
    keys = {k["id"]: k["spki"] for k in pin.get("passkeys") or [] if isinstance(k, dict) and k.get("spki")}
    origin, rp_id = pin.get("origin"), pin.get("rp_id")
    if not keys or not origin or not rp_id:
        raise ReleaseRejected("no passkeys pinned on this endpoint; re-run the installer")
    try:
        mbytes = _b64d(release["manifest_b64url"])
        a = release["assertion"]
        client_data_raw, auth_data = _b64d(a["client_data_json"]), _b64d(a["authenticator_data"])
        signature, cred_id = _b64d(a["signature"]), str(a["credential_id"])
        client_data = json.loads(client_data_raw)
        manifest = json.loads(mbytes)
    except (KeyError, TypeError, ValueError) as exc:
        raise ReleaseRejected(f"malformed release ({type(exc).__name__})") from None
    if cred_id not in keys:
        raise ReleaseRejected("approved by a passkey this endpoint doesn't trust")
    if client_data.get("type") != "webauthn.get" or client_data.get("crossOrigin"):
        raise ReleaseRejected("not a WebAuthn approval")
    if client_data.get("challenge") != _b64e(hashlib.sha256(mbytes).digest()):
        raise ReleaseRejected("the passkey approved a different release")
    if client_data.get("origin") != origin:
        raise ReleaseRejected("approved on a different website")
    if len(auth_data) < 37 or auth_data[:32] != hashlib.sha256(rp_id.encode()).digest():
        raise ReleaseRejected("approval is for a different Hub (RP ID)")
    if not auth_data[32] & FLAG_USER_PRESENT or not auth_data[32] & FLAG_USER_VERIFIED:
        raise ReleaseRejected("approval wasn't confirmed with a fingerprint or PIN")
    _check_signature(keys[cred_id], signature, auth_data + hashlib.sha256(client_data_raw).digest())
    if manifest.get("type") != "soc.agent_release" or manifest.get("v") != 1 or not isinstance(manifest.get("seq"), int):
        raise ReleaseRejected("not an agent release manifest")
    if manifest.get("origin") != origin or manifest.get("rp_id") != rp_id:
        raise ReleaseRejected("manifest is for a different Hub")
    files = manifest.get("files")
    if not isinstance(files, dict) or set(files) - set(RELEASE_FILES):
        raise ReleaseRejected("manifest lists files a self-update may not replace")
    for meta in files.values():
        if not (isinstance(meta, dict) and isinstance(meta.get("sha256"), str) and len(meta["sha256"]) == 64
                and isinstance(meta.get("size"), int) and 0 < meta["size"] <= MAX_FILE_BYTES):
            raise ReleaseRejected("manifest has a malformed file entry")
    return manifest


class Updater:
    def __init__(self, *, hub_base_url: str, token: str, endpoint_id: str, state_dir: Path,
                 install_dir: Path, pin_file: Path, request=None, apply_sysmon=None) -> None:
        self.base = hub_base_url.rstrip("/")
        self.token = token
        self.endpoint_id = endpoint_id
        self.install = install_dir
        self.pin_file = pin_file
        self.dir = state_dir / "updates"
        self.request = request or self._request
        self.apply_sysmon = apply_sysmon or _apply_sysmon_config
        self.reported: set[tuple[int, str]] = set()

    # ------------------------------------------------------------ state
    def installed(self) -> int:
        return int((_read_json(self.dir / "installed.json") or {}).get("seq") or 0)

    def pending(self) -> dict[str, Any] | None:
        return _read_json(self.dir / "pending.json")

    def bad(self) -> set[int]:
        return set(_read_json(self.dir / "bad_releases.json", []) or [])

    # ------------------------------------------------------------ hub I/O
    def _request(self, path: str, body: dict | None = None, raw: bool = False) -> Any:
        data = None if body is None else json.dumps(body).encode()
        req = urllib.request.Request(self.base + path, data=data, method="POST" if data else "GET", headers={
            "X-SOC-Token": self.token, "User-Agent": "soc-shipper/1",
            **({"Content-Type": "application/json"} if data else {})})
        with urllib.request.urlopen(req, timeout=30) as resp:
            content = resp.read(MAX_FILE_BYTES + 1)
        return content if raw else json.loads(content or b"{}")

    def report(self, status: str, seq: int, detail: str = "") -> None:
        if (seq, status) in self.reported:
            return
        try:
            self.request("/releases/report", {"endpoint_id": self.endpoint_id, "seq": seq,
                                              "status": status, "detail": detail[:500]})
            self.reported.add((seq, status))
        except (urllib.error.URLError, OSError, ValueError) as exc:
            log.warning("update: couldn't report %s for release #%d: %s", status, seq, type(exc).__name__)

    # ------------------------------------------------------------ the check
    def check(self, under_launcher: bool) -> bool:
        """True = a new version was installed; exit with RESTART_CODE."""
        self.report_last_result()
        if self.pending():
            return False   # a previous update is still being checked by the launcher
        try:
            resp = self.request("/releases/current?" + urlencode({"endpoint_id": self.endpoint_id}))
        except urllib.error.HTTPError as exc:
            if exc.code != 404:   # 404: an older Hub without the Deployer
                log.warning("update: Hub answered HTTP %d", exc.code)
            return False
        except (urllib.error.URLError, OSError, ValueError) as exc:
            log.debug("update check failed: %s", exc)
            return False
        release = resp.get("release") if isinstance(resp, dict) else None
        if not release:
            return False
        seq_claim = int(release.get("seq") or 0) if isinstance(release.get("seq"), int) else 0
        if seq_claim and (seq_claim <= self.installed() or seq_claim in self.bad()):
            return False
        try:
            manifest = verify_release(release, _read_json(self.pin_file, {}) or {})
        except ReleaseRejected as exc:
            log.error("update: REFUSED release #%s: %s", seq_claim or "?", exc)
            self.report("rejected", seq_claim, str(exc))
            return False
        seq = manifest["seq"]
        if seq <= self.installed() or seq in self.bad():
            return False
        for name, sha in (manifest.get("requires") or {}).items():
            if _sha_file(self.install / name) != sha:
                self.report("needs_installer", seq, f"{name} changed; re-run the installer for this release")
                return False
        changed = [n for n, meta in manifest["files"].items() if _sha_file(self.install / n) != meta["sha256"]]
        if not changed:
            self._finish(seq, manifest)
            self.report("up_to_date", seq, "already running this build")
            return False
        if not under_launcher:
            self.report("needs_installer", seq, "this agent isn't started by agent_launcher.py; re-run the installer")
            return False
        try:
            self._install(seq, manifest, changed)
        except ReleaseRejected as exc:
            log.error("update: release #%d not installed: %s", seq, exc)
            self.report("failed", seq, str(exc))
            return False
        log.warning("update: installed release #%d (%s); restarting", seq, ", ".join(changed))
        return True

    def _install(self, seq: int, manifest: dict[str, Any], changed: list[str]) -> None:
        stage = self.dir / f"stage-{seq}"
        shutil.rmtree(stage, ignore_errors=True)
        stage.mkdir(parents=True)
        for n in changed:
            meta = manifest["files"][n]
            try:
                data = self.request(f"/releases/{seq}/files/{quote(n)}?" + urlencode({"endpoint_id": self.endpoint_id}),
                                    raw=True)
            except (urllib.error.URLError, OSError) as exc:
                raise ReleaseRejected(f"couldn't download {n}: {type(exc).__name__}") from None
            if len(data) != meta["size"] or hashlib.sha256(data).hexdigest() != meta["sha256"]:
                raise ReleaseRejected(f"{n} doesn't match the approved release")
            (stage / n).write_bytes(data)
        backup = self.dir / "backup"
        shutil.rmtree(backup, ignore_errors=True)
        backup.mkdir(parents=True)
        new_files = []
        for n in changed:
            if (self.install / n).exists():
                shutil.copy2(self.install / n, backup / n)
            else:
                new_files.append(n)
        # Written BEFORE the swap, so a crash halfway is rolled back by the launcher.
        _write_json(self.dir / "pending.json", {
            "seq": seq, "from_seq": self.installed(), "applied_at": time.time(), "files": changed,
            "new_files": new_files, "backup": str(backup), "sysmon_config": "sysmon-config.xml" in changed})
        for n in changed:
            os.replace(stage / n, self.install / n)
        shutil.rmtree(stage, ignore_errors=True)
        self._update_pins(manifest)
        if "sysmon-config.xml" in changed:
            self.apply_sysmon(self.install / "sysmon-config.xml")

    def _update_pins(self, manifest: dict[str, Any]) -> None:
        """A release signed by a trusted passkey may update the trusted passkey list
        (that's how a passkey you enroll later becomes trusted here)."""
        keys = [k for k in manifest.get("passkeys") or [] if isinstance(k, dict) and k.get("id") and k.get("spki")]
        if not keys:
            return
        pin = _read_json(self.pin_file, {}) or {}
        if pin.get("passkeys") != keys:
            _write_json(self.pin_file, {**pin, "passkeys": keys})

    def _finish(self, seq: int, manifest: dict[str, Any]) -> None:
        _write_json(self.dir / "installed.json", {"seq": seq, "at": time.time()})
        self._update_pins(manifest)

    def mark_healthy(self) -> None:
        """Called by the new version once it's running and has talked to the Hub."""
        p = self.pending()
        if not p:
            return
        _write_json(self.dir / "installed.json", {"seq": p["seq"], "at": time.time()})
        (self.dir / "pending.json").unlink(missing_ok=True)
        log.warning("update: release #%d is healthy", p["seq"])
        self.report("applied", p["seq"], "updated " + ", ".join(p.get("files") or []))

    def report_last_result(self) -> None:
        """Tell the Hub about a rollback the launcher did while we weren't running."""
        r = _read_json(self.dir / "last_result.json")
        if r and not r.get("reported"):
            self.report(r.get("status", "rolled_back"), int(r.get("seq") or 0), str(r.get("detail") or ""))
            if (int(r.get("seq") or 0), r.get("status", "rolled_back")) in self.reported:
                _write_json(self.dir / "last_result.json", {**r, "reported": True})


def _apply_sysmon_config(path: Path) -> None:
    windir = Path(os.environ.get("SystemRoot", r"C:\Windows"))
    for exe in (windir / "Sysmon64.exe", windir / "Sysmon.exe"):
        if exe.exists():
            r = subprocess.run([str(exe), "-c", str(path)], capture_output=True, timeout=60,
                               creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            if r.returncode:
                log.warning("update: Sysmon rejected the new config (exit %d)", r.returncode)
            return
