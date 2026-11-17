"""Tamper-evident, append-only audit log of every security-relevant Hub event.

Each line is {"n", "prev", "h", "e"} where h = SHA-256(prev + canonical(e)). Changing,
deleting or reordering any entry breaks every hash after it, and verify() finds the
first bad entry. The history file used by the dashboard (activity.jsonl) is compacted;
this one never is (notable events are only dozens a day).

Someone with full control of the Hub could rewrite the whole chain consistently. That's
why the Hub also posts a checkpoint (entry count + head hash) to Discord at startup and
daily: those messages live off the machine, so a rewritten history won't match them.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
import time
from pathlib import Path
from typing import Any

log = logging.getLogger("soc.audit")
GENESIS = "0" * 64


def _canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def chain_hash(prev: str, entry: dict[str, Any]) -> str:
    return hashlib.sha256(prev.encode() + _canonical(entry)).hexdigest()


class AuditLog:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.head = GENESIS
        self.count = 0
        self.broken_at: int | None = None
        self.checked_at: float | None = None
        self._lock = threading.Lock()

    def verify(self) -> dict[str, Any]:
        """Re-check the whole chain from the start. Appends keep going from the file's end."""
        prev, n, broken, last_h = GENESIS, 0, None, GENESIS
        try:
            with open(self.path, encoding="utf-8") as f:
                for line in f:
                    if not line.strip():
                        continue
                    n += 1
                    try:
                        rec = json.loads(line)
                        ok = (rec.get("n") == n and rec.get("prev") == prev
                              and rec.get("h") == chain_hash(prev, rec.get("e")))
                        last_h = rec.get("h") or last_h
                    except (ValueError, AttributeError, TypeError):
                        ok = False
                    if not ok and broken is None:
                        broken = n
                    prev = rec.get("h", prev) if ok else last_h
        except FileNotFoundError:
            pass
        with self._lock:
            self.head, self.count, self.broken_at, self.checked_at = last_h, n, broken, time.time()
        if broken:
            log.critical("audit: chain BROKEN at entry %d of %d: history was modified", broken, n)
        else:
            log.info("audit: chain verified, %d entries, head %s", n, last_h[:16])
        return self.status()

    def append(self, entry: dict[str, Any]) -> None:
        with self._lock:
            h = chain_hash(self.head, entry)
            rec = {"n": self.count + 1, "prev": self.head, "h": h, "e": entry}
            try:
                new = not self.path.exists()
                with open(self.path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(rec, separators=(",", ":"), ensure_ascii=False) + "\n")
                if new:
                    os.chmod(self.path, 0o600)
            except OSError as exc:
                log.error("audit: can't append: %s", type(exc).__name__)
                return
            self.head, self.count = h, self.count + 1

    def status(self) -> dict[str, Any]:
        return {"entries": self.count, "head": self.head, "verified": self.broken_at is None,
                "broken_at": self.broken_at, "checked_at": self.checked_at}
