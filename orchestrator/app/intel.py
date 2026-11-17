"""Known-malware file fingerprints (SHA-256) for the Strategist.

Three sources, merged in memory:
  * built-in   the EICAR antivirus test file, a harmless standard file every
               antivirus treats as malware, so you can test detection safely;
  * custom     <data>/intel/custom_sha256.txt, one "sha256 [label]" per line,
               for fingerprints you want treated as malware;
  * MalwareBazaar (abuse.ch) "recent" export, downloaded once a day and kept for
               30 days in <data>/intel/malwarebazaar.json. Download only: nothing
               about your machines is ever sent. Needs a FREE abuse.ch Auth-Key
               (https://auth.abuse.ch/) in secrets/abusech_auth_key.txt; without one
               the feed is simply skipped. INTEL_FEED_ENABLED=false turns it off.
"""
from __future__ import annotations

import csv
import io
import json
import logging
import os
import re
import tempfile
import time
from pathlib import Path
from typing import Any

log = logging.getLogger("soc.intel")

EICAR = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
# abuse.ch now requires a free Auth-Key (https://auth.abuse.ch/), which goes in the URL path.
FEED_URL = "https://mb-api.abuse.ch/v2/files/exports/{key}/recent.csv"
KEEP_DAYS = 30
MAX_ENTRIES = 200_000
_SHA = re.compile(r"^[0-9a-f]{64}$")


class Intel:
    def __init__(self, data_dir: Path) -> None:
        self.dir = data_dir / "intel"
        self.custom_file = self.dir / "custom_sha256.txt"
        self.feed_file = self.dir / "malwarebazaar.json"
        self.feed: dict[str, list] = {}      # sha -> [family, first_seen_ts]
        self.custom: dict[str, str] = {}
        self.last_update: float | None = None
        self.last_error: str | None = None
        self.last_added = 0

    # ---------------------------------------------------------------- loading
    def load(self) -> None:
        self._load_custom()
        try:
            data = json.loads(self.feed_file.read_text(encoding="utf-8"))
            self.feed = {k: v for k, v in data.get("hashes", {}).items() if _SHA.match(k)}
            self.last_update = data.get("updated_at")
        except FileNotFoundError:
            pass
        except (OSError, ValueError) as exc:
            log.error("intel: can't read %s: %s", self.feed_file.name, type(exc).__name__)
        log.info("intel: %d MalwareBazaar fingerprints, %d custom", len(self.feed), len(self.custom))

    def _load_custom(self) -> None:
        self.custom = {}
        try:
            for line in self.custom_file.read_text(encoding="utf-8").splitlines():
                parts = line.strip().split(None, 1)
                if parts and _SHA.match(parts[0].lower()):
                    self.custom[parts[0].lower()] = (parts[1] if len(parts) > 1 else "custom list")[:120]
        except FileNotFoundError:
            pass

    # ---------------------------------------------------------------- lookups
    def lookup(self, sha256: str | None) -> dict[str, str] | None:
        if not sha256:
            return None
        sha = sha256.lower()
        if sha == EICAR:
            return {"source": "built-in", "label": "EICAR antivirus test file (harmless)"}
        if sha in self.custom:
            return {"source": "custom list", "label": self.custom[sha]}
        if sha in self.feed:
            fam = self.feed[sha][0] or "unnamed malware"
            return {"source": "MalwareBazaar", "label": fam}
        return None

    def status(self) -> dict[str, Any]:
        return {"feed": len(self.feed), "custom": len(self.custom), "updated_at": self.last_update,
                "last_error": self.last_error, "last_added": self.last_added}

    # ---------------------------------------------------------------- feed
    def parse_feed(self, text: str) -> dict[str, list]:
        rows = [line for line in text.splitlines() if line and not line.startswith("#")]
        out: dict[str, list] = {}
        for row in csv.reader(io.StringIO("\n".join(rows)), skipinitialspace=True):
            if len(row) < 9:
                continue
            sha, family = row[1].strip().strip('"').lower(), row[8].strip().strip('"')
            if _SHA.match(sha):
                out[sha] = [None if family in ("", "n/a") else family[:80], time.time()]
        return out

    async def refresh(self, http, auth_key: str | None = None) -> None:
        self._load_custom()
        if not auth_key:
            self.last_error = "needs a free abuse.ch Auth-Key (secrets/abusech_auth_key.txt)"
            return
        if not re.fullmatch(r"[A-Za-z0-9_-]{8,128}", auth_key):
            self.last_error = "the abuse.ch Auth-Key has an unexpected format"
            return
        try:
            resp = await http.get(FEED_URL.format(key=auth_key), timeout=120, follow_redirects=True,
                                  headers={"User-Agent": "soc-hub-intel/1"})
            if resp.status_code in (401, 403):
                raise ValueError(f"abuse.ch rejected the Auth-Key (HTTP {resp.status_code})")
            resp.raise_for_status()
            body = resp.content
            if body[:2] == b"PK":   # some exports come zipped
                import zipfile
                with zipfile.ZipFile(io.BytesIO(body)) as z:
                    body = z.read(z.namelist()[0])
            fresh = self.parse_feed(body.decode("utf-8", "replace"))
            if not fresh:
                raise ValueError("feed had no fingerprints (format change?)")
        except Exception as exc:
            # Never let the key (it's in the URL) reach logs or the dashboard.
            self.last_error = f"{type(exc).__name__}: {str(exc).replace(auth_key, '<key>')[:160]}"
            log.warning("intel: MalwareBazaar refresh failed: %s", self.last_error)
            return
        cutoff = time.time() - KEEP_DAYS * 86400
        before = len(self.feed)
        merged = {k: v for k, v in self.feed.items() if (v[1] or 0) >= cutoff}
        for k, v in fresh.items():
            merged.setdefault(k, v)
        if len(merged) > MAX_ENTRIES:
            merged = dict(sorted(merged.items(), key=lambda kv: kv[1][1] or 0)[-MAX_ENTRIES:])
        self.feed, self.last_update, self.last_error = merged, time.time(), None
        self.last_added = max(0, len(merged) - before)
        self._save()
        log.info("intel: MalwareBazaar refreshed: %d fingerprints (%+d)", len(merged), len(merged) - before)

    def _save(self) -> None:
        self.dir.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=self.dir, prefix=".mb.")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump({"updated_at": self.last_update, "hashes": self.feed}, f)
        os.replace(tmp, self.feed_file)
