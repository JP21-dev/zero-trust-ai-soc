"""Agent releases: what the Deployer offers to endpoints once you approve it.

A release is a manifest (release number, each agent file's SHA-256 and size, the
pinned passkeys) plus the WebAuthn assertion your passkey made over it. The
challenge you sign is the SHA-256 of the manifest itself, so each endpoint can
check the approval on its own (shipper/updater.py) without trusting the Hub.

Files are copied out of the Hub's shipper folder when a release is proposed and
served from that copy, so a later edit to the folder can't change a release.
"""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import secrets
import shutil
import tempfile
import time
from pathlib import Path
from typing import Any

log = logging.getLogger("soc.releases")

# What a self-update may replace. agent_launcher.py is left out on purpose: it does
# the rollback, so only the installer changes it.
RELEASE_FILES = ("shipper.py", "enforcer.py", "sysmon.py", "winlog.py", "updater.py", "sysmon-config.xml")
# Compared, never shipped: a new Python dependency needs the installer.
REQUIRES = ("requirements.txt",)
MAX_FILE_BYTES = 2 * 2**20
KEEP_RELEASES = 3


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def challenge_for(manifest_bytes: bytes) -> str:
    """The WebAuthn challenge for a release: base64url(SHA-256(manifest))."""
    return _b64url(hashlib.sha256(manifest_bytes).digest())


def files_digest(hashes: dict[str, str]) -> str:
    return hashlib.sha256("".join(f"{n}:{hashes.get(n)}\n" for n in sorted(hashes)).encode()).hexdigest()


def _write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".rel.")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(data, f)
    os.replace(tmp, path)


class ReleaseStore:
    def __init__(self, source_dir: Path, data_dir: Path) -> None:
        self.src = source_dir
        self.dir = data_dir / "releases"
        self.current_file = self.dir / "current.json"
        self.state_file = self.dir / "state.json"
        self.current: dict[str, Any] | None = None
        self.state: dict[str, Any] = {"denied": None}
        try:
            self.current = json.loads(self.current_file.read_text(encoding="utf-8"))
        except FileNotFoundError:
            pass
        except (OSError, ValueError) as exc:
            log.error("releases: can't read %s: %s", self.current_file.name, type(exc).__name__)
        try:
            self.state.update(json.loads(self.state_file.read_text(encoding="utf-8")))
        except (OSError, ValueError):
            pass

    # ------------------------------------------------------------ what's there
    def hub_files(self) -> dict[str, bytes] | None:
        """The Hub's copy of every release file, or None if one is missing or too big."""
        out = {}
        for name in RELEASE_FILES + REQUIRES:
            try:
                data = (self.src / name).read_bytes()
            except OSError:
                return None
            if len(data) > MAX_FILE_BYTES:
                return None
            out[name] = data
        return out

    @staticmethod
    def hashes(files: dict[str, bytes]) -> dict[str, str]:
        return {n: hashlib.sha256(b).hexdigest() for n, b in files.items()}

    def manifest(self, release: dict[str, Any] | None = None) -> dict[str, Any] | None:
        rel = release or self.current
        if not rel:
            return None
        return json.loads(base64.urlsafe_b64decode(rel["manifest_b64url"] + "=" * (-len(rel["manifest_b64url"]) % 4)))

    def current_digest(self) -> str | None:
        m = self.manifest()
        if not m:
            return None
        return files_digest({**{n: v["sha256"] for n, v in m["files"].items()}, **m["requires"]})

    # ------------------------------------------------------------ proposing
    def build(self, files: dict[str, bytes], passkeys: list[dict[str, str]], origin: str,
              rp_id: str) -> dict[str, Any]:
        """Snapshot the files and write the manifest your passkey will sign."""
        seq = int((self.manifest() or {}).get("seq") or 0) + 1
        hashes = self.hashes(files)
        manifest = {
            "v": 1, "type": "soc.agent_release", "seq": seq, "created_at": int(time.time()),
            "nonce": secrets.token_urlsafe(16),   # every request gets its own challenge
            "files": {n: {"sha256": hashes[n], "size": len(files[n])} for n in RELEASE_FILES},
            "requires": {n: hashes[n] for n in REQUIRES},
            "passkeys": [{"id": p["id"], "spki": p["spki"]} for p in passkeys],
            "origin": origin.rstrip("/"), "rp_id": rp_id,
        }
        mbytes = canonical(manifest)
        staged = self.dir / f"staged-{seq}-{hashlib.sha256(mbytes).hexdigest()[:12]}"
        shutil.rmtree(staged, ignore_errors=True)
        staged.mkdir(parents=True)
        for n in RELEASE_FILES:
            (staged / n).write_bytes(files[n])
        changed = [n for n in RELEASE_FILES + REQUIRES
                   if hashes[n] != ((self.manifest() or {}).get("files", {}).get(n, {}).get("sha256")
                                    or (self.manifest() or {}).get("requires", {}).get(n))]
        return {"seq": seq, "manifest_bytes": mbytes, "challenge_id": challenge_for(mbytes),
                "staged": str(staged), "digest": files_digest(hashes), "changed": changed,
                "needs_installer": [n for n in REQUIRES if n in changed and self.current]}

    def approve(self, proposal: dict[str, Any], assertion: dict[str, Any], approved_by: str) -> dict[str, Any]:
        seq = proposal["seq"]
        final = self.dir / str(seq)
        shutil.rmtree(final, ignore_errors=True)
        os.replace(proposal["staged"], final)
        self.current = {
            "seq": seq,
            "manifest_b64url": _b64url(proposal["manifest_bytes"]),
            "assertion": {k: assertion[k] for k in ("credential_id", "client_data_json", "authenticator_data",
                                                    "signature")},
            "approved_at": int(time.time()), "approved_by": approved_by[:64],
        }
        _write_json(self.current_file, self.current)
        self.set_denied(None)
        self._prune(seq)
        return self.current

    def set_denied(self, digest: str | None) -> None:
        self.state["denied"] = digest
        try:
            _write_json(self.state_file, self.state)
        except OSError as exc:
            log.error("releases: can't save state: %s", exc)

    def _prune(self, seq: int) -> None:
        for p in self.dir.iterdir() if self.dir.exists() else []:
            if p.is_dir() and (p.name.startswith("staged-") or (p.name.isdigit() and int(p.name) <= seq - KEEP_RELEASES)):
                shutil.rmtree(p, ignore_errors=True)

    # ------------------------------------------------------------ serving
    def file(self, seq: int, name: str) -> bytes | None:
        if name not in RELEASE_FILES or not self.current or seq != self.current["seq"]:
            return None
        try:
            return (self.dir / str(seq) / name).read_bytes()
        except OSError:
            return None
