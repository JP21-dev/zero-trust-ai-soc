"""Agent self-check: is the code running on each endpoint the code you installed?

Every ~10 minutes each shipper reports the SHA-256 of its own files (POST /integrity).
The Hub compares them with its own copy of the shipper folder (mounted read-only at
AGENT_RELEASE_DIR) and remembers every version it has ever served
(<data>/agent_versions.json), so each file is one of:

  ok        identical to the Hub's current copy
  outdated  an older version the Hub once had: re-run the installer to update
  modified  a version the Hub has never had: someone changed the agent's code
  missing   the endpoint says the file is gone

Limitation: the report comes from the agent itself, so an attacker who already runs as
SYSTEM could make a modified agent report the right hashes. This catches an edited or
deleted file, not a careful attacker.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import tempfile
from pathlib import Path
from typing import Any

log = logging.getLogger("soc.agentcheck")

AGENT_FILES = ("shipper.py", "enforcer.py", "sysmon.py", "winlog.py", "updater.py", "agent_launcher.py",
               "sysmon-config.xml")


class AgentReleases:
    def __init__(self, release_dir: Path, data_dir: Path) -> None:
        self.release_dir = release_dir
        self.history_file = data_dir / "agent_versions.json"
        self.history: dict[str, list[str]] = {}
        self._cache: dict[str, tuple[tuple[float, int], str]] = {}
        try:
            raw = json.loads(self.history_file.read_text(encoding="utf-8"))
            self.history = {k: [h for h in v if isinstance(h, str)][-50:] for k, v in raw.items()
                            if k in AGENT_FILES and isinstance(v, list)}
        except FileNotFoundError:
            pass
        except (OSError, ValueError, AttributeError) as exc:
            log.error("agentcheck: can't read %s: %s", self.history_file.name, type(exc).__name__)

    def current(self) -> dict[str, str]:
        """file -> sha256 of the Hub's copy (files it doesn't have are left out)."""
        out: dict[str, str] = {}
        for name in AGENT_FILES:
            p = self.release_dir / name
            try:
                st = p.stat()
                key = (st.st_mtime, st.st_size)
                hit = self._cache.get(name)
                if hit and hit[0] == key:
                    out[name] = hit[1]
                    continue
                sha = hashlib.sha256(p.read_bytes()).hexdigest()
            except OSError:
                continue
            self._cache[name] = (key, sha)
            out[name] = sha
        self._remember(out)
        return out

    def _remember(self, cur: dict[str, str]) -> None:
        changed = False
        for name, sha in cur.items():
            seen = self.history.setdefault(name, [])
            if sha not in seen:
                seen.append(sha)
                del seen[:-50]
                changed = True
        if changed:
            try:
                self.history_file.parent.mkdir(parents=True, exist_ok=True)
                fd, tmp = tempfile.mkstemp(dir=self.history_file.parent, prefix=".agents.")
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    json.dump(self.history, f)
                os.replace(tmp, self.history_file)
            except OSError as exc:
                log.error("agentcheck: can't save version history: %s", exc)

    def classify(self, reported: dict[str, str | None]) -> dict[str, Any]:
        cur = self.current()
        if not cur:
            return {"state": "unverifiable", "files": {}, "why": "the Hub has no copy of the shipper folder"}
        files: dict[str, str] = {}
        for name in AGENT_FILES:
            if name not in reported:
                continue   # an agent version that doesn't have this file
            sha = (reported[name] or "").lower()
            if not sha:
                files[name] = "missing"
            elif sha == cur.get(name):
                files[name] = "ok"
            elif sha in self.history.get(name, []):
                files[name] = "outdated"
            else:
                files[name] = "modified"
        states = set(files.values())
        state = ("modified" if states & {"modified", "missing"} else
                 "outdated" if "outdated" in states else "ok")
        return {"state": state, "files": files}
