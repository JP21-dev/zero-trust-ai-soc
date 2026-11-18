"""Reads Windows' own event logs for things Sysmon doesn't cover.

Like sysmon.py, it uses Windows' built-in `wevtutil` (no extra packages), remembers
where it stopped per log (winlog_state.json), and on its very first run starts at
the newest record instead of replaying history.

  Microsoft Defender  (Microsoft-Windows-Windows Defender/Operational)
    5001 / 5010 / 5012   protection turned off                 -> defender  rule=realtime_off / protection_off
    5007                 settings changed: an exclusion added  -> defender  rule=exclusion_added
                         or protection disabled by a setting   -> defender  rule=protection_off / tamper_protection_off
    5013                 Tamper Protection blocked a change    -> defender  rule=tamper_blocked
    1116 / 1121          threat detected / ASR rule blocked    -> defender  rule=detection
    1118 / 1119          Defender couldn't remove a threat     -> defender  rule=action_failed
  System
    7045                 a new service was installed           -> service
  Security  (needs the audit policies install-endpoint.ps1 turns on)
    4698                 a new scheduled task                  -> task
    4720                 a local account was created           -> account   rule=account_created
    4732                 added to Administrators / Remote      -> account   rule=admin_added / rdp_user_added
                         Desktop Users (other groups ignored)
    4625                 failed logins, COUNTED here: one      -> logon     count=failures in the last 10 min
                         event when a source passes 3, 10, 25, 100 or 500 failures

Routine noise is dropped here: Windows' own built-in scheduled tasks, and repeats of
the same Defender event within 15 minutes.
"""
from __future__ import annotations

import collections
import hashlib
import ipaddress
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

NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
DEFENDER = "Microsoft-Windows-Windows Defender/Operational"
CHANNELS: dict[str, tuple[str, tuple[int, ...]]] = {
    "defender": (DEFENDER, (1116, 1118, 1119, 1121, 5001, 5007, 5010, 5012, 5013)),
    "system": ("System", (7045,)),
    "security": ("Security", (4625, 4698, 4720, 4732)),
}
MAX_PER_READ = 500
MAX_HASH_BYTES = 64 * 2**20
DEDUP_SECONDS = 900
FAIL_WINDOW = 600
FAIL_STEPS = (3, 10, 25, 100, 500)
SYSTEM_ROOTS = ("c:\\windows\\", "c:\\program files\\", "c:\\program files (x86)\\")
GROUPS = {"S-1-5-32-544": ("admin_added", "Administrators"), "S-1-5-32-555": ("rdp_user_added", "Remote Desktop Users")}
LIMITS = {"process_name": 260, "exe_path": 1024, "user": 256, "cmdline": 4096, "file_path": 1024,
          "object_name": 512, "detail": 1024, "rule": 128}

_EXCLUSION = re.compile(r"\\Exclusions\\(Paths|Extensions|Processes|IpAddresses|TemporaryPaths)\\(.+?)\s*=\s*", re.I)
_DISABLE = re.compile(r"\\(DisableRealtimeMonitoring|DisableBehaviorMonitoring|DisableIOAVProtection|"
                      r"DisableOnAccessProtection|DisableScriptScanning|DisableAntiSpyware|DisableAntiVirus)"
                      r"\s*=\s*0x0*1\b", re.I)
_TAMPER_OFF = re.compile(r"\\TamperProtection\s*=\s*0x0*[04]\b", re.I)


def _base(path: str | None) -> str:
    return re.split(r"[\\/]", path or "")[-1].lower()


def _under(path: str | None, roots: tuple[str, ...]) -> bool:
    p = (path or "").lower()
    return any(p.startswith(r) for r in roots)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def parse_records(xml_text: str) -> list[tuple[int, int, str, dict[str, str]]]:
    """wevtutil /f:xml output -> [(record_id, event_id, iso_time, {field: value})]."""
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
        tc = ev.find("e:System/e:TimeCreated", NS)
        ts = (tc.get("SystemTime") if tc is not None else None) or ""
        try:
            iso = datetime.fromisoformat(ts[:19]).replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")
        except ValueError:
            iso = _now_iso()
        data = {d.get("Name"): (d.text or "").strip() for d in ev.findall("e:EventData/e:Data", NS) if d.get("Name")}
        out.append((rid, eid, iso, data))
    return out


def exe_from_command(cmd: str | None) -> str:
    """The program a service ImagePath / task command runs, as a normal Windows path."""
    c = os.path.expandvars((cmd or "").strip())
    if c.startswith('"'):
        exe = c[1:].split('"', 1)[0]
    else:
        m = re.match(r"(.+?\.(?:exe|sys|dll|com|bat|cmd|ps1|vbs|js|scr))(?=\s|$)", c, re.I)
        exe = m.group(1) if m else c.split(" ", 1)[0]
    exe = re.sub(r"^\\\?\?\\", "", exe)
    windir = os.environ.get("SystemRoot", r"C:\Windows")
    if exe.lower().startswith("\\systemroot\\"):
        exe = windir + exe[len("\\SystemRoot"):]
    elif exe.lower().startswith("system32\\"):
        exe = windir + "\\" + exe
    return exe


def _sid_name(sid: str) -> str | None:
    """S-1-5-21-... -> MACHINE\\user, via LookupAccountSidW (Windows only)."""
    try:
        import ctypes
        from ctypes import wintypes
        advapi = ctypes.windll.advapi32
        psid = ctypes.c_void_p()
        if not advapi.ConvertStringSidToSidW(ctypes.c_wchar_p(sid), ctypes.byref(psid)):
            return None
        try:
            name, dom = ctypes.create_unicode_buffer(256), ctypes.create_unicode_buffer(256)
            n, dn, use = wintypes.DWORD(256), wintypes.DWORD(256), wintypes.DWORD()
            ok = advapi.LookupAccountSidW(None, psid, name, ctypes.byref(n), dom, ctypes.byref(dn), ctypes.byref(use))
            return (f"{dom.value}\\{name.value}" if dom.value else name.value) if ok else None
        finally:
            ctypes.windll.kernel32.LocalFree(psid)
    except Exception:
        return None


def _task_command(xml_text: str) -> tuple[str | None, str]:
    """(command, arguments) of a task's first Exec action, from its TaskContent XML."""
    body = re.sub(r"^\s*<\?xml[^>]*\?>", "", xml_text or "")
    try:
        root = ET.fromstring(body)
    except ET.ParseError:
        return None, ""
    for el in root.iter():
        if el.tag.endswith("}Exec") or el.tag == "Exec":
            cmd = args = None
            for c in el:
                if c.tag.endswith("Command"):
                    cmd = (c.text or "").strip()
                elif c.tag.endswith("Arguments"):
                    args = (c.text or "").strip()
            if cmd:
                return cmd, args or ""
    return None, ""


class WinLogReader:
    def __init__(self, state_dir: Path, include_cmdline: bool = True, runner=None, resolve_sid=None) -> None:
        self.state_file = state_dir / "winlog_state.json"
        self.include_cmdline = include_cmdline
        self.run = runner or self._wevtutil
        self.resolve_sid = resolve_sid or _sid_name
        self.last: dict[str, int] = {}
        self.available: dict[str, bool] = {}
        self.seen: dict[str, float] = {}
        self.hash_cache: dict[tuple, str | None] = {}
        self.fails: dict[str, collections.deque] = {}
        self.fail_reported: dict[str, int] = {}
        try:
            raw = json.loads(self.state_file.read_text())
            self.last = {k: int(v) for k, v in raw.items() if k in CHANNELS}
        except (OSError, ValueError, AttributeError, TypeError):
            self.last = {}

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
            tmp.write_text(json.dumps(self.last))
            os.replace(tmp, self.state_file)
        except OSError as exc:
            log.warning("winlog: can't save position: %s", exc)

    def status(self) -> dict[str, str]:
        """For --dry-run: which logs this account can read."""
        out = {}
        for key, (channel, _ids) in CHANNELS.items():
            try:
                self.run(["qe", channel, "/rd:true", "/c:1", "/f:xml"])
                out[key] = "ok"
            except Exception:
                out[key] = "unreadable"
        return out

    def read(self) -> list[dict[str, Any]]:
        events: list[dict[str, Any]] = []
        changed = False
        for key, (channel, ids) in CHANNELS.items():
            try:
                if key not in self.last:   # first run: start from now
                    newest = parse_records(self.run(["qe", channel, "/rd:true", "/c:1", "/f:xml"]))
                    self.last[key] = newest[0][0] if newest else 0
                    changed = True
                    self.available[key] = True
                    log.info("winlog: reading %s from record %d onward", channel, self.last[key])
                    continue
                q = "*[System[(" + " or ".join(f"EventID={i}" for i in ids) + f") and EventRecordID>{self.last[key]}]]"
                records = parse_records(self.run(["qe", channel, f"/q:{q}", f"/c:{MAX_PER_READ}", "/f:xml"]))
            except (OSError, RuntimeError, subprocess.SubprocessError, ET.ParseError) as exc:
                if self.available.get(key) is not False:
                    log.warning("winlog: can't read %s (%s)", channel, str(exc)[:120])
                self.available[key] = False
                continue
            self.available[key] = True
            for rid, eid, ts, data in records:
                self.last[key] = max(self.last[key], rid)
                changed = True
                try:
                    ev = self.convert(key, eid, ts, data)
                except Exception:   # one odd record must never stop the shipper
                    log.exception("winlog: couldn't convert %s event %s", key, eid)
                    ev = None
                if ev:
                    events.append(self._clip(ev))
        events += [self._clip(e) for e in self._failed_logon_events()]
        if changed:
            self._save()
        now = time.time()
        self.seen = {k: t for k, t in self.seen.items() if now - t < DEDUP_SECONDS}
        return events

    # ---------------------------------------------------------------- helpers
    def _clip(self, ev: dict[str, Any]) -> dict[str, Any]:
        if not self.include_cmdline:
            ev.pop("cmdline", None)
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

    def _hash(self, path: str | None) -> str | None:
        if not path or _under(path, SYSTEM_ROOTS):
            return None
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
        if len(self.hash_cache) > 2000:
            self.hash_cache.clear()
        self.hash_cache[key] = sha
        return sha

    # ---------------------------------------------------------------- mapping
    def convert(self, key: str, eid: int, ts: str, d: dict[str, str]) -> dict[str, Any] | None:
        if key == "defender":
            return self._defender(eid, ts, d)
        if key == "system" and eid == 7045:
            image = d.get("ImagePath", "")
            exe = exe_from_command(image)
            return {"timestamp": ts, "event_type": "service", "process_name": _base(exe) or "unknown",
                    "exe_path": exe, "cmdline": image, "object_name": d.get("ServiceName"),
                    "detail": f"{d.get('StartType', '?')}, {d.get('ServiceType', '?')}, runs as {d.get('AccountName', '?')}",
                    "sha256": self._hash(exe)}
        if key == "security":
            if eid == 4698:
                name = d.get("TaskName", "")
                cmd, args = _task_command(d.get("TaskContent", ""))
                exe = exe_from_command(cmd) if cmd else ""
                if name.lower().startswith("\\microsoft\\") and (not exe or _under(exe, SYSTEM_ROOTS)):
                    return None   # Windows' own built-in tasks
                return {"timestamp": ts, "event_type": "task", "process_name": _base(exe) or "com-handler",
                        "exe_path": exe or None, "cmdline": f"{cmd} {args}".strip() if cmd else None,
                        "object_name": name, "user": self._who(d), "sha256": self._hash(exe)}
            if eid == 4720:
                return {"timestamp": ts, "event_type": "account", "process_name": "windows-security",
                        "rule": "account_created", "user": self._who(d),
                        "object_name": f"{d.get('TargetDomainName', '')}\\{d.get('TargetUserName', '?')}".lstrip("\\")}
            if eid == 4732:
                kind = GROUPS.get(d.get("TargetSid", "").upper())
                if not kind:
                    return None
                sid = d.get("MemberSid", "")
                member = d.get("MemberName", "")
                member = member if member not in ("", "-") else (self.resolve_sid(sid) or sid or "?")
                return {"timestamp": ts, "event_type": "account", "process_name": "windows-security",
                        "rule": kind[0], "user": self._who(d), "object_name": member,
                        "detail": f"{d.get('TargetUserName') or kind[1]} ({d.get('TargetSid')})"}
            if eid == 4625:
                self._count_failure(d)
        return None

    @staticmethod
    def _who(d: dict[str, str]) -> str | None:
        user, dom = d.get("SubjectUserName", ""), d.get("SubjectDomainName", "")
        return f"{dom}\\{user}" if dom and user else user or None

    def _defender(self, eid: int, ts: str, d: dict[str, str]) -> dict[str, Any] | None:
        base = {"timestamp": ts, "event_type": "defender", "process_name": "MsMpEng.exe"}
        ev: dict[str, Any] | None = None
        if eid in (5001, 5010, 5012):
            what = {5001: "Real-time protection turned off", 5010: "Spyware scanning turned off",
                    5012: "Virus scanning turned off"}[eid]
            ev = {**base, "rule": "realtime_off" if eid == 5001 else "protection_off", "object_name": what,
                  "detail": f"Defender event {eid}"}
        elif eid == 5013:
            ev = {**base, "rule": "tamper_blocked",
                  "object_name": (d.get("Value") or d.get("New Value") or "a change to Defender's settings")[:200],
                  "detail": "Tamper Protection blocked it (event 5013)"}
        elif eid == 5007:
            new, old = d.get("New Value", ""), d.get("Old Value", "")
            m = _EXCLUSION.search(new)
            if m and m.group(0) not in old:
                kind, value = m.group(1), m.group(2).strip()
                looks_path = kind.lower() in ("paths", "processes", "temporarypaths") and re.match(r"^[A-Za-z]:\\", value)
                ev = {**base, "rule": "exclusion_added", "object_name": f"{kind}: {value}",
                      "file_path": value if looks_path else None, "detail": new}
            elif _DISABLE.search(new):
                ev = {**base, "rule": "protection_off", "object_name": _DISABLE.search(new).group(1) + " set",
                      "detail": new}
            elif _TAMPER_OFF.search(new):
                ev = {**base, "rule": "tamper_protection_off", "object_name": "Tamper Protection turned off",
                      "detail": new}
        elif eid in (1116, 1121, 1118, 1119):
            path = ""
            for part in (d.get("Path") or "").split(";"):
                part = re.sub(r"^(?:file|containerfile):_", "", part.strip())
                if re.match(r"^[A-Za-z]:\\", part):
                    path = part
                    break
            proc = d.get("Process Name", "")
            proc = proc if re.match(r"^[A-Za-z]:\\", proc) else ""
            threat = d.get("Threat Name") or ("Attack surface reduction rule " + d.get("ID", "")).strip()
            ev = {**base, "rule": "detection" if eid in (1116, 1121) else "action_failed",
                  "process_name": _base(proc) or "MsMpEng.exe", "exe_path": proc or None,
                  "object_name": threat, "file_path": path or None, "sha256": self._hash(path) if path else None,
                  "detail": "; ".join(x for x in (f"severity {d['Severity Name']}" if d.get("Severity Name") else "",
                                                  d.get("Category Name", ""),
                                                  f"action {d['Action Name']}" if d.get("Action Name") else "",
                                                  f"event {eid}") if x)}
        if ev and self._dup(f"d|{ev['rule']}|{ev.get('object_name')}|{ev.get('file_path')}"):
            return None
        return ev

    def _count_failure(self, d: dict[str, str]) -> None:
        ip = d.get("IpAddress", "")
        try:
            addr = ipaddress.ip_address(ip)
            src = None if addr.is_loopback or addr.is_unspecified else str(addr)
        except ValueError:
            src = None
        key = src or "local"
        q = self.fails.setdefault(key, collections.deque(maxlen=2000))
        q.append((time.time(), d.get("TargetUserName") or "?", d.get("LogonType") or "?"))

    def _failed_logon_events(self) -> list[dict[str, Any]]:
        now, out = time.time(), []
        for key in list(self.fails):
            q = self.fails[key]
            while q and now - q[0][0] > FAIL_WINDOW:
                q.popleft()
            if not q:
                del self.fails[key]
                self.fail_reported.pop(key, None)
                continue
            n = len(q)
            step = max((s for s in FAIL_STEPS if n >= s), default=0)
            if step <= self.fail_reported.get(key, 0):
                continue
            self.fail_reported[key] = step
            users = list(dict.fromkeys(u for _, u, _ in q))
            types = sorted({t for _, _, t in q})
            out.append({"timestamp": _now_iso(), "event_type": "logon", "process_name": "windows-security",
                        "rule": "failed_logons", "count": n, "dst_ip": None if key == "local" else key,
                        "object_name": ", ".join(users[:5]) + (f" +{len(users) - 5} more" if len(users) > 5 else ""),
                        "detail": "logon type " + ", ".join(types)})
        return out
