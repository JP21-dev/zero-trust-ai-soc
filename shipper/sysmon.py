"""Reads Microsoft Sysmon events and turns the interesting ones into telemetry.

Sysmon (a free Microsoft Sysinternals tool, installed by install-endpoint.ps1 with
sysmon-config.xml) writes to the "Microsoft-Windows-Sysmon/Operational" event log.
Every SYSMON_EVERY cycles the shipper reads the records added since last time with
Windows' own `wevtutil` (no extra Python packages) and maps them to Hub events:

  Sysmon 1   process launch          -> "process"   (with SHA-256 + parent)
  Sysmon 11  file created            -> "file"      (the shipper hashes runnable files)
  Sysmon 15  file downloaded (ADS)   -> "file"      (Sysmon's own SHA-256 of the file)
  Sysmon 12/13/14 auto-start keys    -> "registry"
  Sysmon 10  something opened LSASS  -> "lsass"
  Sysmon 8   remote thread created   -> "injection"
  Sysmon 6   driver loaded           -> "driver"    (only unsigned/invalid ones)
  Sysmon 25  process tampering       -> "tamper"

To keep the Hub's view meaningful and the traffic small, routine noise is dropped
here: launches of programs installed under C:\\Windows or Program Files (unless
they're script hosts/admin tools or started by an Office app), Windows-to-Windows
remote threads, LSASS access by Windows/Defender components, and repeats of the
same launch within 15 minutes.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import subprocess
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

log = logging.getLogger("soc-shipper")

CHANNEL = "Microsoft-Windows-Sysmon/Operational"
NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
MAX_PER_READ = 2000
MAX_HASH_BYTES = 64 * 2**20
DEDUP_SECONDS = 900

SYSTEM_ROOTS = ("c:\\windows\\", "c:\\program files\\", "c:\\program files (x86)\\")
TRUSTED_LSASS_READERS = ("c:\\windows\\", "c:\\programdata\\microsoft\\windows defender\\",
                         "c:\\program files\\windows defender\\")
WATCH_PROCESSES = {   # admin tools / script hosts: always interesting when launched
    "powershell.exe", "pwsh.exe", "cmd.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe",
    "bitsadmin.exe", "wscript.exe", "cscript.exe", "msbuild.exe", "installutil.exe", "wmic.exe",
    "regasm.exe", "regsvcs.exe", "msiexec.exe", "hh.exe", "schtasks.exe", "sc.exe", "net.exe", "net1.exe",
    "reg.exe", "vssadmin.exe", "bcdedit.exe", "wevtutil.exe", "whoami.exe", "nltest.exe",
}
OFFICE_APPS = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "onenote.exe", "msaccess.exe",
               "mspub.exe", "visio.exe", "acrord32.exe", "acrobat.exe"}
RUNNABLE = re.compile(r"\.(exe|dll|scr|com|pif|msi|msp|ps1|psm1|vbs|vbe|js|jse|wsf|hta|bat|cmd|lnk|jar|cpl|iso|img)$", re.I)
LIMITS = {"process_name": 260, "exe_path": 1024, "user": 256, "cmdline": 4096, "parent_name": 260,
          "parent_path": 1024, "parent_cmdline": 4096, "file_path": 1024, "reg_key": 1024,
          "reg_value": 2048, "target_process": 1024, "signer": 256, "rule": 128, "granted_access": 32}


def _base(path: str | None) -> str:
    return re.split(r"[\\/]", path or "")[-1].lower()


def _under(path: str | None, roots: tuple[str, ...]) -> bool:
    p = (path or "").lower()
    return any(p.startswith(r) for r in roots)


def _sha_from(hashes: str | None) -> str | None:
    m = re.search(r"SHA256=([0-9A-Fa-f]{64})", hashes or "")
    return m.group(1).lower() if m else None


def _iso(utc: str | None) -> str:
    try:
        return datetime.strptime((utc or "")[:19], "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc) \
            .isoformat().replace("+00:00", "Z")
    except ValueError:
        return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def parse_events(xml_text: str) -> list[tuple[int, int, dict[str, str]]]:
    """wevtutil /f:xml output -> [(record_id, event_id, {field: value})]."""
    if not xml_text.strip():
        return []
    root = ET.fromstring("<Events>" + xml_text + "</Events>")
    out = []
    for ev in root.findall("e:Event", NS):
        try:
            eid = int(ev.findtext("e:System/e:EventID", default="0", namespaces=NS))
            rid = int(ev.findtext("e:System/e:EventRecordID", default="0", namespaces=NS))
        except ValueError:
            continue
        data = {d.get("Name"): (d.text or "") for d in ev.findall("e:EventData/e:Data", NS)}
        out.append((rid, eid, data))
    return out


class SysmonReader:
    def __init__(self, state_dir: Path, include_cmdline: bool = True, runner=None) -> None:
        self.state_file = state_dir / "sysmon_state.json"
        self.include_cmdline = include_cmdline
        self.run = runner or self._wevtutil
        self.last_id: int | None = None
        self.seen: dict[str, float] = {}
        self.hash_cache: dict[tuple, str | None] = {}
        self.available: bool | None = None
        try:
            self.last_id = int(json.loads(self.state_file.read_text())["last_record_id"])
        except (OSError, ValueError, KeyError, TypeError):
            self.last_id = None

    # ---------------------------------------------------------------- I/O
    @staticmethod
    def _wevtutil(args: list[str]) -> str:
        r = subprocess.run(["wevtutil", *args], capture_output=True, timeout=30,
                           creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        if r.returncode != 0:
            raise RuntimeError((r.stderr or r.stdout).decode("utf-8", "replace").strip()[:200])
        return r.stdout.decode("utf-8", "replace")

    def _save(self) -> None:
        try:
            tmp = self.state_file.with_suffix(".tmp")
            tmp.write_text(json.dumps({"last_record_id": self.last_id}))
            os.replace(tmp, self.state_file)
        except OSError as exc:
            log.warning("sysmon: can't save position: %s", exc)

    def read(self) -> list[dict[str, Any]]:
        try:
            if self.last_id is None:   # first run: start from now, don't replay history
                newest = parse_events(self.run(["qe", CHANNEL, "/rd:true", "/c:1", "/f:xml"]))
                self.last_id = newest[0][0] if newest else 0
                self._save()
                self.available = True
                log.info("sysmon: reading from record %d onward", self.last_id)
                return []
            raw = self.run(["qe", CHANNEL, f"/q:*[System[EventRecordID>{self.last_id}]]",
                            f"/c:{MAX_PER_READ}", "/f:xml"])
        except (OSError, RuntimeError, subprocess.SubprocessError, ET.ParseError) as exc:
            if self.available is not False:
                log.warning("sysmon: can't read %s (%s). Is Sysmon installed?", CHANNEL, str(exc)[:120])
            self.available = False
            return []
        self.available = True
        try:
            records = parse_events(raw)
        except ET.ParseError as exc:
            log.warning("sysmon: unparsable batch skipped: %s", exc)
            return []
        events = []
        for rid, eid, data in records:
            self.last_id = max(self.last_id, rid)
            try:
                ev = self.convert(eid, data)
            except Exception:   # one odd record must never stop the shipper
                log.exception("sysmon: couldn't convert event %s", eid)
                ev = None
            if ev:
                events.append(self._clip(ev))
        if records:
            self._save()
        now = time.time()
        self.seen = {k: t for k, t in self.seen.items() if now - t < DEDUP_SECONDS}
        return events

    # ---------------------------------------------------------------- mapping
    def _clip(self, ev: dict[str, Any]) -> dict[str, Any]:
        if not self.include_cmdline:
            ev.pop("cmdline", None)
            ev.pop("parent_cmdline", None)
        for k, n in LIMITS.items():
            if isinstance(ev.get(k), str):
                ev[k] = ev[k][:n]
        ev["process_name"] = ev.get("process_name") or "unknown"
        return {k: v for k, v in ev.items() if v not in (None, "")}

    def _dup(self, key: str) -> bool:
        if key in self.seen:
            return True
        self.seen[key] = time.time()
        return False

    def _hash(self, path: str) -> str | None:
        try:
            st = os.stat(path)
        except OSError:
            return None
        key = (path.lower(), st.st_mtime, st.st_size)
        if key in self.hash_cache:
            return self.hash_cache[key]
        sha = None
        if st.st_size <= MAX_HASH_BYTES:
            try:
                h = hashlib.sha256()
                with open(path, "rb") as f:
                    for chunk in iter(lambda: f.read(1 << 20), b""):
                        h.update(chunk)
                sha = h.hexdigest()
            except OSError:
                sha = None
        if len(self.hash_cache) > 5000:
            self.hash_cache.clear()
        self.hash_cache[key] = sha
        return sha

    def convert(self, eid: int, d: dict[str, str]) -> dict[str, Any] | None:
        base = {"timestamp": _iso(d.get("UtcTime")), "rule": d.get("RuleName") if d.get("RuleName") not in ("-", "") else None}
        if eid == 1:   # process create
            image, parent = d.get("Image", ""), d.get("ParentImage", "")
            name = _base(image)
            interesting = (not _under(image, SYSTEM_ROOTS) or name in WATCH_PROCESSES
                           or _base(parent) in OFFICE_APPS)
            if not interesting:
                return None
            sha = _sha_from(d.get("Hashes"))
            if self._dup(f"1|{image.lower()}|{parent.lower()}|{sha}|{hash(d.get('CommandLine'))}"):
                return None
            return {**base, "event_type": "process", "process_name": name, "exe_path": image,
                    "pid": int(d["ProcessId"]) if d.get("ProcessId", "").isdigit() else None,
                    "user": d.get("User"), "cmdline": d.get("CommandLine"), "sha256": sha,
                    "parent_name": _base(parent), "parent_path": parent, "parent_cmdline": d.get("ParentCommandLine")}
        if eid in (11, 15):   # file created / downloaded (alternate data stream)
            target = d.get("TargetFilename", "")
            if eid == 15:
                target = re.sub(r":[^:\\]*$", "", target)   # strip ':Zone.Identifier'
                sha = _sha_from(d.get("Hash"))
            else:
                if not RUNNABLE.search(target) and "\\startup\\" not in target.lower():
                    return None
                sha = self._hash(target)
            if self._dup(f"f|{target.lower()}|{sha}"):
                return None
            image = d.get("Image", "")
            return {**base, "event_type": "file", "process_name": _base(image), "exe_path": image,
                    "user": d.get("User"), "file_path": target, "sha256": sha}
        if eid in (12, 13, 14):   # registry (config only logs auto-start locations)
            image = d.get("Image", "")
            key = d.get("TargetObject", "")
            if self._dup(f"r|{key.lower()}|{d.get('Details', '')}"):
                return None
            return {**base, "event_type": "registry", "process_name": _base(image), "exe_path": image,
                    "user": d.get("User"), "reg_key": key, "reg_value": d.get("Details") or d.get("NewName"),
                    "sha256": self._hash(image) if image and not _under(image, SYSTEM_ROOTS) else None}
        if eid == 10:   # process access (config limits it to LSASS with read-memory rights)
            src = d.get("SourceImage", "")
            if _under(src, TRUSTED_LSASS_READERS):
                return None
            if self._dup(f"l|{src.lower()}"):
                return None
            return {**base, "event_type": "lsass", "process_name": _base(src), "exe_path": src,
                    "user": d.get("SourceUser"), "target_process": d.get("TargetImage"),
                    "granted_access": d.get("GrantedAccess"), "sha256": self._hash(src)}
        if eid == 8:   # CreateRemoteThread
            src, tgt = d.get("SourceImage", ""), d.get("TargetImage", "")
            if _under(src, ("c:\\windows\\",)) and _under(tgt, ("c:\\windows\\",)):
                return None
            if self._dup(f"i|{src.lower()}|{tgt.lower()}"):
                return None
            return {**base, "event_type": "injection", "process_name": _base(src), "exe_path": src,
                    "user": d.get("SourceUser"), "target_process": tgt, "sha256": self._hash(src)}
        if eid == 6:   # driver loaded
            signed = (d.get("Signed", "").lower() == "true") and d.get("SignatureStatus", "") == "Valid"
            if signed:
                return None
            img = d.get("ImageLoaded", "")
            return {**base, "event_type": "driver", "process_name": _base(img) or "driver", "exe_path": img,
                    "file_path": img, "sha256": _sha_from(d.get("Hashes")), "signed": False,
                    "signer": d.get("Signature")}
        if eid == 25:   # process tampering
            image = d.get("Image", "")
            if self._dup(f"t|{image.lower()}"):
                return None
            return {**base, "event_type": "tamper", "process_name": _base(image), "exe_path": image,
                    "user": d.get("User"), "rule": d.get("Type") or base["rule"]}
        return None
