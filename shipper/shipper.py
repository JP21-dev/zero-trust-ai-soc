#!/usr/bin/env python3
"""SOC telemetry shipper + enforcer host for a Windows endpoint (laptop, desktop, or the Hub itself).

Every 10 seconds it samples the machine's network connections with psutil and
POSTs any NEW ones (with the owning process) to the Hub's /ingest endpoint.

Why it stays well under 1% CPU:
  * One psutil.net_connections() call per cycle. That's one OS table read.
  * Diffing: only connections not seen in the previous sample become events,
    so process details (exe, user, cmdline) are looked up only for those, and
    cached per (pid, process start time).
  * Nothing is sent when nothing changed. That also keeps the Hub from calling
    the LLM every 10 seconds for the same long-lived connections.
  * Standard library HTTP, no thread pool, sleeps on an Event between cycles,
    and it lowers its own scheduling priority at startup.

Safety while roaming:
  * The token is only ever sent when this machine has a Tailscale (100.64.0.0/10)
    address. If Tailscale is down, a 100.x route could go out the café Wi-Fi's
    default gateway, and plain HTTP would leak the token and telemetry. So
    batches are held in a bounded buffer instead.
  * The token is read from a file, never from the command line (visible to every
    process on the box).

Configuration: environment variables, falling back to <SOC_STATE_DIR>/config.json
({"hub_url": ..., "hub_key_url": ...}), which install-endpoint.ps1 writes.
  SOC_HUB_URL         REQUIRED. The Hub's ingest URL on your tailnet,
                      e.g. http://100.x.y.z:8080/ingest   (config.json: hub_url)
  SOC_TOKEN_FILE      default %PROGRAMDATA%\\SOCShipper\\token.txt (Windows)
                              /etc/soc-shipper/token (other)
  SOC_ENDPOINT_ID     default: this machine's hostname
  SOC_INTERVAL        seconds between samples, default 10
  SOC_INCLUDE_CMDLINE 1 (default) or 0. Command lines feed the Hub's prompt-
                      injection and spoofing checks, but can contain secrets.
  SOC_LOG_LEVEL       default INFO

Windows event logs (see sysmon.py and winlog.py), every ~20 s:
  SOC_SYSMON          1 (default) or 0. Sysmon process/file/registry/DNS/... events.
  SOC_WINLOG          1 (default) or 0. Defender, new services and tasks, failed
                      logins, new accounts and admins, from Windows' own logs.

Agent self-check: every ~10 min (and at start) the shipper reports the SHA-256 of
its own files to the Hub (POST /integrity), which alerts if they don't match any
version it shipped.

Self-update (see updater.py): about every 5 minutes the shipper asks the Hub for
the current release and installs it only if your passkey signed it. Needs
agent_launcher.py (the scheduled task runs it), which restarts the agent on the
new version and rolls it back if it doesn't come up healthy.
  SOC_AUTO_UPDATE     1 (default) or 0

Enforcement (see enforcer.py): each cycle the shipper also asks the Hub for
approved execution orders, verifies their Ed25519 signature against the pinned
Hub key, and applies them as Windows Firewall rules.
  SOC_STATE_DIR       default %PROGRAMDATA%\\SOCShipper (holds config, pinned key, applied orders, blocks)
  SOC_HUB_KEY_URL     REQUIRED for enforcement. The Hub's HTTPS public-key URL,
                      e.g. https://soc-hub.your-tailnet.ts.net/warden/public-key
                      (config.json: hub_key_url)
  SOC_ENFORCE         1 (default) or 0
  SOC_ENFORCE_DRY_RUN 1 = log what would be blocked, change nothing
  SOC_ALLOW_SIMULATED_ORDERS  0 (default). 1 accepts dev-mode approvals. Never in production.

Usage:
  python shipper.py                 run forever
  python shipper.py --dry-run       take two samples, print the batch, send nothing
  python shipper.py --pin-hub-key   fetch + pin the Hub's order-signing key (once, over HTTPS)
  python shipper.py --list-blocks   show firewall blocks this enforcer applied
  python shipper.py --unblock IP    remove the SOC-Warden rules for IP

Requires: Python 3.9+, psutil, cryptography. Run it elevated (or as SYSTEM): it
needs that to see every process's user and path, and to add firewall rules.
"""
from __future__ import annotations

import argparse
import collections
import hashlib
import ipaddress
import json
import logging
import os
import re
import signal
import socket
import sys
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import psutil

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
IS_WINDOWS = sys.platform == "win32"
DEFAULT_TOKEN_FILE = (
    os.path.join(os.environ.get("PROGRAMDATA", r"C:\ProgramData"), "SOCShipper", "token.txt")
    if IS_WINDOWS else "/etc/soc-shipper/token"
)
STATE_DIR = Path(os.environ.get("SOC_STATE_DIR") or (
    os.path.join(os.environ.get("PROGRAMDATA", r"C:\ProgramData"), "SOCShipper")
    if IS_WINDOWS else "/var/lib/soc-shipper"))
CONFIG_FILE = STATE_DIR / "config.json"


def _load_config() -> dict:
    try:
        cfg = json.loads(CONFIG_FILE.read_text(encoding="utf-8-sig"))
    except FileNotFoundError:
        return {}
    except (OSError, ValueError) as exc:
        sys.exit(f"cannot read {CONFIG_FILE}: {exc}")
    if not isinstance(cfg, dict):
        sys.exit(f"{CONFIG_FILE} must contain a JSON object")
    return cfg


_CFG = _load_config()
HUB_URL = os.environ.get("SOC_HUB_URL") or _CFG.get("hub_url") or ""
HUB_KEY_URL = os.environ.get("SOC_HUB_KEY_URL") or _CFG.get("hub_key_url") or ""
# Presence: on the Hub's own shipper only (install-endpoint.ps1 sets it there). Once a
# minute it tells the Hub which tailnet machines Tailscale sees online, so the Hub can
# tell "laptop asleep" apart from "laptop online but its agent stopped".
REPORT_PRESENCE = (os.environ.get("SOC_REPORT_PRESENCE") or str(_CFG.get("report_presence", ""))).lower() in ("1", "true")
TAILSCALE_CLI = (os.environ.get("SOC_TAILSCALE_CLI") or _CFG.get("tailscale_cli")
                 or (r"C:\Program Files\Tailscale\tailscale.exe" if IS_WINDOWS else "tailscale"))
PRESENCE_EVERY = 6          # cycles (~60 s)
INTEGRITY_EVERY = 60        # cycles (~10 min)
UPDATE_EVERY = 30           # cycles (~5 min)
AUTO_UPDATE = os.environ.get("SOC_AUTO_UPDATE", "1") != "0"
LAUNCHER_PID = int(os.environ.get("SOC_LAUNCHER_PID") or 0)
HUB_OK = False              # talked to the Hub successfully since this process started
AGENT_FILES = ("shipper.py", "enforcer.py", "sysmon.py", "winlog.py", "updater.py", "agent_launcher.py",
               "sysmon-config.xml")
TOKEN_FILE = os.environ.get("SOC_TOKEN_FILE", DEFAULT_TOKEN_FILE)
INTERVAL = max(1.0, float(os.environ.get("SOC_INTERVAL", "10")))
INCLUDE_CMDLINE = os.environ.get("SOC_INCLUDE_CMDLINE", "1") != "0"
HUB_KEY_FILE = STATE_DIR / "hub_pubkey.json"
ENFORCE = os.environ.get("SOC_ENFORCE", "1") != "0"
ALLOW_SIMULATED_ORDERS = os.environ.get("SOC_ALLOW_SIMULATED_ORDERS", "0") == "1"

MAX_BATCH = 500             # Hub limit per request
MAX_BUFFERED = 5000         # events kept while the Hub is unreachable; oldest dropped
HTTP_TIMEOUT = 60           # Hub may wait on the LLM before answering
BACKOFF_MAX = 300
STATS_EVERY = 60            # cycles between self-reported CPU stats (10 min)
TAILSCALE_NET = ipaddress.ip_network("100.64.0.0/10")
TAILSCALE_NET6 = ipaddress.ip_network("fd7a:115c:a1e0::/48")

# Must match the Hub's limits (orchestrator/app/main.py: TelemetryEvent)
LIMITS = {"process_name": 260, "exe_path": 1024, "user": 256, "cmdline": 4096}

log = logging.getLogger("soc-shipper")


def _endpoint_id() -> str:
    raw = os.environ.get("SOC_ENDPOINT_ID") or socket.gethostname()
    clean = re.sub(r"[^A-Za-z0-9._-]", "-", raw.lower())[:64]
    return clean or "unknown-endpoint"


ENDPOINT_ID = _endpoint_id()


def _read_token() -> str:
    try:
        with open(TOKEN_FILE, encoding="utf-8-sig") as f:   # -sig: tolerate a BOM
            token = f.read().strip()
    except OSError as exc:
        sys.exit(f"cannot read token file {TOKEN_FILE}: {exc}")
    if len(token) < 32:
        sys.exit(f"token in {TOKEN_FILE} is shorter than 32 characters")
    return token


# ---------------------------------------------------------------------------
# Sampling
# ---------------------------------------------------------------------------
ConnKey = tuple  # (pid, type, laddr, raddr)


class ProcessInfoCache:
    """pid -> event fields, invalidated when the pid is reused by a new process."""

    def __init__(self) -> None:
        self._cache: dict[int, tuple[float, dict]] = {}

    def get(self, pid: int) -> dict | None:
        try:
            proc = psutil.Process(pid)
            started = proc.create_time()
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return None
        hit = self._cache.get(pid)
        if hit and hit[0] == started:
            return hit[1]

        info: dict = {"pid": pid}
        with proc.oneshot():
            for field, getter in (("process_name", proc.name), ("exe_path", proc.exe),
                                  ("user", proc.username)):
                try:
                    value = getter()
                except (psutil.Error, OSError):
                    value = None
                if value:
                    info[field] = value[: LIMITS[field]]
            if INCLUDE_CMDLINE:
                try:
                    cmd = " ".join(proc.cmdline())
                except (psutil.Error, OSError):
                    cmd = ""
                if cmd:
                    info["cmdline"] = cmd[: LIMITS["cmdline"]]
        info.setdefault("process_name", f"pid-{pid}")
        self._cache[pid] = (started, info)
        return info

    def prune(self, live_pids: set[int]) -> None:
        for pid in [p for p in self._cache if p not in live_pids]:
            del self._cache[pid]


def _skip_remote(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip.split("%", 1)[0])
    except ValueError:
        return True
    return addr.is_loopback or addr.is_unspecified or addr.is_link_local or addr.is_multicast


class Sampler:
    def __init__(self) -> None:
        self.previous: set[ConnKey] = set()
        self.procs = ProcessInfoCache()
        self.own_pid = os.getpid()

    def sample(self) -> list[dict]:
        """Return events for connections that appeared since the last sample."""
        try:
            conns = psutil.net_connections(kind="inet")
        except psutil.AccessDenied:
            log.error("access denied listing connections; run elevated")
            return []

        current: set[ConnKey] = set()
        for c in conns:
            if not c.raddr or not c.pid or c.pid == self.own_pid:
                continue   # listening sockets, kernel-owned, or our own POSTs
            if _skip_remote(c.raddr.ip):
                continue
            current.add((c.pid, c.type, tuple(c.laddr) if c.laddr else (), tuple(c.raddr)))

        new = current - self.previous
        self.previous = current
        self.procs.prune({k[0] for k in current})

        now = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
        events = []
        for pid, ctype, _laddr, raddr in new:
            info = self.procs.get(pid)
            if info is None:
                continue   # process already exited
            events.append({
                "timestamp": now,
                **info,
                "dst_ip": raddr[0].split("%", 1)[0],
                "dst_port": raddr[1],
                "protocol": "tcp" if ctype == socket.SOCK_STREAM
                            else "udp" if ctype == socket.SOCK_DGRAM else "other",
            })
        return events


# ---------------------------------------------------------------------------
# Sending
# ---------------------------------------------------------------------------
def tailscale_is_up() -> bool:
    """True if any local interface holds a Tailscale address."""
    for addrs in psutil.net_if_addrs().values():
        for a in addrs:
            if a.family not in (socket.AF_INET, socket.AF_INET6):
                continue
            try:
                ip = ipaddress.ip_address(a.address.split("%", 1)[0])
            except ValueError:
                continue
            if ip in TAILSCALE_NET or ip in TAILSCALE_NET6:
                return True
    return False


class Sender:
    def __init__(self, token: str) -> None:
        self.token = token
        self.buffer: collections.deque[dict] = collections.deque(maxlen=MAX_BUFFERED)
        self.backoff = 0.0
        self.retry_at = 0.0
        self.sent = 0
        self.dropped_overflow = 0

    def enqueue(self, events: list[dict]) -> None:
        overflow = len(self.buffer) + len(events) - MAX_BUFFERED
        if overflow > 0:
            self.dropped_overflow += overflow
            log.warning("buffer full, dropping %d oldest events", overflow)
        self.buffer.extend(events)

    def flush(self) -> None:
        if not self.buffer or time.monotonic() < self.retry_at:
            return
        if not tailscale_is_up():
            log.info("tailscale is down; holding %d events", len(self.buffer))
            return self._fail()
        while self.buffer:
            batch = [self.buffer.popleft() for _ in range(min(MAX_BATCH, len(self.buffer)))]
            ok, retry = self._post(batch)
            if ok:
                self.sent += len(batch)
                self.backoff = 0.0
                continue
            if retry:
                self.buffer.extendleft(reversed(batch))   # keep original order
                return self._fail()
            # Not retryable (e.g. 422): retrying can't help, so drop it.
            log.error("hub rejected a batch of %d events; dropped", len(batch))

    def _fail(self) -> None:
        self.backoff = min(BACKOFF_MAX, max(INTERVAL, self.backoff * 2))
        self.retry_at = time.monotonic() + self.backoff

    def _post(self, events: list[dict]) -> tuple[bool, bool]:
        """(sent ok?, worth retrying?)"""
        body = json.dumps({"endpoint_id": ENDPOINT_ID, "events": events},
                          separators=(",", ":")).encode()
        req = urllib.request.Request(HUB_URL, data=body, method="POST", headers={
            "Content-Type": "application/json",
            "X-SOC-Token": self.token,
            "User-Agent": "soc-shipper/1",
        })
        try:
            with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
                result = json.loads(resp.read() or b"{}")
        except urllib.error.HTTPError as exc:
            if exc.code == 401:
                log.error("hub says 401: token is wrong. Check %s", TOKEN_FILE)
                return False, True    # keep the data and back off; fix the token
            if exc.code in (413, 422):
                return False, False
            log.warning("hub returned HTTP %d", exc.code)
            return False, True
        except (urllib.error.URLError, OSError, ValueError) as exc:
            log.warning("hub unreachable: %s", getattr(exc, "reason", exc))
            return False, True

        global HUB_OK
        HUB_OK = True
        level = logging.WARNING if result.get("challenge_ids") else logging.INFO
        log.log(level, "sent %d events: score=%s decision=%s", len(events),
                result.get("threat_score"), result.get("decision"))
        return True, False


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------
def lower_priority() -> None:
    try:
        me = psutil.Process()
        me.nice(psutil.BELOW_NORMAL_PRIORITY_CLASS if IS_WINDOWS else 10)
    except (psutil.Error, OSError, AttributeError):
        pass


def check_hub_url() -> None:
    if not HUB_URL:
        sys.exit(f"no Hub URL configured: set SOC_HUB_URL, or hub_url in {CONFIG_FILE} "
                 "(install-endpoint.ps1 writes it), e.g. http://100.x.y.z:8080/ingest")
    u = urlparse(HUB_URL)
    host = u.hostname or ""
    if u.scheme not in ("http", "https") or not host:
        sys.exit(f"SOC_HUB_URL is not a valid URL: {HUB_URL}")
    if u.scheme == "http":
        try:
            on_tailnet = ipaddress.ip_address(host) in TAILSCALE_NET
        except ValueError:
            on_tailnet = host.endswith(".ts.net")
        if not on_tailnet:
            sys.exit("refusing plain http to a host outside the tailnet: " + host)


def hub_base_url() -> str:
    u = urlparse(HUB_URL)
    return f"{u.scheme}://{u.netloc}"


def build_enforcer(token: str):
    """Return an Enforcer, or None (with a loud log line) if it can't run safely."""
    if not ENFORCE:
        log.warning("enforcement disabled (SOC_ENFORCE=0): approved orders will NOT be applied")
        return None
    try:
        import enforcer   # needs `cryptography`; imported lazily so shipping works without it
    except ImportError as exc:
        log.error("enforcement disabled: %s (pip install cryptography)", exc)
        return None
    try:
        key = enforcer.PinnedKey.load(HUB_KEY_FILE)
    except (OSError, ValueError) as exc:
        log.error("enforcement disabled: no valid pinned Hub key at %s (%s). "
                  "Run: python shipper.py --pin-hub-key", HUB_KEY_FILE, exc)
        return None
    host = urlparse(HUB_URL).hostname or ""
    e = enforcer.Enforcer(hub_base_url=hub_base_url(), token=token, endpoint_id=ENDPOINT_ID,
                          state_dir=STATE_DIR, key=key, allow_simulated=ALLOW_SIMULATED_ORDERS,
                          protected_ips={host})
    log.info("enforcement on: hub key_id=%s backend=%s%s", key.key_id, e.firewall.name,
             " (ACCEPTING SIMULATED APPROVALS)" if ALLOW_SIMULATED_ORDERS else "")
    return e


def _clean_host(name: str) -> str:
    """Same normalization as this machine's own endpoint id, so names line up on the Hub."""
    return re.sub(r"[^A-Za-z0-9._-]", "-", (name or "").lower())[:64]


def tailscale_presence() -> dict | None:
    """Which tailnet machines Tailscale currently sees online (from `tailscale status --json`)."""
    import subprocess
    try:
        out = subprocess.run([TAILSCALE_CLI, "status", "--json"], capture_output=True, timeout=15,
                             creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        data = json.loads(out.stdout or b"{}")
    except (OSError, subprocess.SubprocessError, ValueError) as exc:
        log.warning("presence: can't read tailscale status: %s", type(exc).__name__)
        return None
    peers = []
    for p in list((data.get("Peer") or {}).values())[:256]:
        host = _clean_host(p.get("HostName", ""))
        if host:
            peers.append({"host": host, "online": bool(p.get("Online")), "last_seen": p.get("LastSeen"),
                          "os": (p.get("OS") or "")[:32], "name": (p.get("DNSName") or "").split(".")[0][:64]})
    return {"endpoint_id": ENDPOINT_ID, "peers": peers}


def report_presence(token: str) -> None:
    body = tailscale_presence()
    if body is None:
        return
    req = urllib.request.Request(hub_base_url() + "/presence", data=json.dumps(body).encode(), method="POST",
                                 headers={"Content-Type": "application/json", "X-SOC-Token": token})
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
            resp.read()
    except urllib.error.HTTPError as exc:
        log.warning("presence: Hub answered HTTP %d", exc.code)
    except (urllib.error.URLError, OSError) as exc:
        log.warning("presence: can't reach the Hub: %s", type(exc).__name__)


def agent_manifest() -> dict:
    """SHA-256 of this agent's own files (None = the file is gone)."""
    here = Path(__file__).resolve().parent
    out: dict = {}
    for name in AGENT_FILES:
        try:
            out[name] = hashlib.sha256((here / name).read_bytes()).hexdigest()
        except OSError:
            out[name] = None
    return out


def report_integrity(token: str) -> None:
    global HUB_OK
    body = json.dumps({"endpoint_id": ENDPOINT_ID, "files": agent_manifest()}).encode()
    req = urllib.request.Request(hub_base_url() + "/integrity", data=body, method="POST",
                                 headers={"Content-Type": "application/json", "X-SOC-Token": token})
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
            state = json.loads(resp.read() or b"{}").get("state")
        HUB_OK = True
        if state not in ("ok", None):
            log.warning("self-check: the Hub says this agent's code is %s", state)
    except urllib.error.HTTPError as exc:
        if exc.code != 404:   # 404: an older Hub without the self-check
            log.warning("self-check: Hub answered HTTP %d", exc.code)
    except (urllib.error.URLError, OSError, ValueError) as exc:
        log.warning("self-check: can't reach the Hub: %s", type(exc).__name__)


def run(dry_run: bool) -> None:
    check_hub_url()
    sampler = Sampler()

    if dry_run:
        sampler.sample()   # baseline: the first sample marks everything as "new"
        sampler.previous = set()
        events = sampler.sample()
        print(json.dumps({"endpoint_id": ENDPOINT_ID, "events": events[:MAX_BATCH]}, indent=2))
        sysmon_state = "off"
        if IS_WINDOWS and os.environ.get("SOC_SYSMON", "1") != "0":
            from sysmon import CHANNEL, SysmonReader
            try:
                SysmonReader._wevtutil(["gli", CHANNEL])
                sysmon_state = "readable"
            except Exception:
                sysmon_state = "unreadable"
        winlog_state = "off"
        if IS_WINDOWS and os.environ.get("SOC_WINLOG", "1") != "0":
            from winlog import WinLogReader
            st = WinLogReader(STATE_DIR).status()
            winlog_state = ",".join(f"{k}:{v}" for k, v in st.items())
        print(f"# {len(events)} events, tailscale_up={tailscale_is_up()}, sysmon={sysmon_state}, "
              f"winlog={winlog_state}", file=sys.stderr)
        return

    token = _read_token()
    sender = Sender(token)
    enf = build_enforcer(token)
    reader = None
    if IS_WINDOWS and os.environ.get("SOC_SYSMON", "1") != "0":
        from sysmon import SysmonReader
        reader = SysmonReader(STATE_DIR, include_cmdline=INCLUDE_CMDLINE)
    logs = None
    if IS_WINDOWS and os.environ.get("SOC_WINLOG", "1") != "0":
        from winlog import WinLogReader
        logs = WinLogReader(STATE_DIR, include_cmdline=INCLUDE_CMDLINE)
    upd = None
    if AUTO_UPDATE:
        try:
            import updater
            upd = updater.Updater(hub_base_url=hub_base_url(), token=token, endpoint_id=ENDPOINT_ID,
                                  state_dir=STATE_DIR, install_dir=Path(__file__).resolve().parent,
                                  pin_file=HUB_KEY_FILE)
        except ImportError as exc:
            log.error("self-update disabled: %s", exc)
    started_at = time.monotonic()
    update_pending = bool(upd and upd.pending())
    restart = False
    lower_priority()
    stop = threading.Event()
    for sig in (signal.SIGINT, signal.SIGTERM, getattr(signal, "SIGBREAK", None)):
        if sig is not None:
            signal.signal(sig, lambda *_: stop.set())

    me = psutil.Process()
    me.cpu_percent(None)   # start the CPU measurement window
    log.info("shipping to %s as %s every %.0fs (cmdline=%s, presence=%s)",
             HUB_URL, ENDPOINT_ID, INTERVAL, INCLUDE_CMDLINE, REPORT_PRESENCE)

    cycle = 0
    next_tick = time.monotonic()
    while not stop.is_set():
        events = sampler.sample()
        if reader is not None and cycle % 2 == 0:   # Sysmon every ~20 s
            events += reader.read()
        if logs is not None and cycle % 2 == 1:     # Windows logs every ~20 s, in between
            try:
                events += logs.read()
            except Exception:   # never let log reading kill telemetry
                log.exception("winlog read crashed")
        if events:
            sender.enqueue(events)
        sender.flush()
        if enf is not None and tailscale_is_up():
            try:
                enf.poll()
            except Exception:   # never let enforcement kill telemetry
                log.exception("enforcer poll crashed")
        if cycle % INTEGRITY_EVERY == 0 and tailscale_is_up():
            try:
                report_integrity(token)
            except Exception:
                log.exception("self-check report crashed")
        if LAUNCHER_PID and not psutil.pid_exists(LAUNCHER_PID):
            log.warning("agent_launcher.py is gone (task stopped?); exiting")
            break
        if update_pending:   # a just-installed release: tell the launcher it works
            up = time.monotonic() - started_at
            if up >= 60 and (HUB_OK or (up >= 180 and not tailscale_is_up())):
                upd.mark_healthy()
                update_pending = False
        if upd is not None and not update_pending and cycle % UPDATE_EVERY == 3 and tailscale_is_up():
            try:
                if upd.check(under_launcher=bool(LAUNCHER_PID)):
                    restart = True
                    break
            except Exception:   # never let updating kill telemetry
                log.exception("update check crashed")
        if REPORT_PRESENCE and cycle % PRESENCE_EVERY == 0 and tailscale_is_up():
            try:
                report_presence(token)
            except Exception:   # never let presence reporting kill telemetry
                log.exception("presence report crashed")

        cycle += 1
        if cycle % STATS_EVERY == 0:
            cpu = me.cpu_percent(None) / (psutil.cpu_count() or 1)
            log.info("stats: cpu=%.3f%% of machine, rss=%.1f MiB, sent=%d, buffered=%d, "
                     "dropped_overflow=%d", cpu, me.memory_info().rss / 2**20,
                     sender.sent, len(sender.buffer), sender.dropped_overflow)

        next_tick += INTERVAL
        delay = next_tick - time.monotonic()
        if delay < 0:            # fell behind (laptop slept); don't burst to catch up
            next_tick = time.monotonic()
            delay = 0
        stop.wait(delay)
    log.info("stopped")
    if restart:
        sys.exit(75)   # updater.RESTART_CODE: agent_launcher.py starts the new version


def main() -> None:
    parser = argparse.ArgumentParser(description="SOC telemetry shipper")
    parser.add_argument("--dry-run", action="store_true",
                        help="print one batch of current connections and exit")
    parser.add_argument("--pin-hub-key", action="store_true",
                        help="fetch the Hub's order-signing public key over HTTPS and pin it")
    parser.add_argument("--list-blocks", action="store_true",
                        help="list firewall blocks applied by this enforcer")
    parser.add_argument("--unblock", metavar="IP", help="remove SOC-Warden firewall rules for IP")
    parser.add_argument("--list-quarantine", action="store_true", help="list files this enforcer quarantined")
    parser.add_argument("--restore", metavar="SHA256_PREFIX", help="put a quarantined file back where it was")
    args = parser.parse_args()
    logging.basicConfig(level=os.environ.get("SOC_LOG_LEVEL", "INFO"),
                        format="%(asctime)s %(levelname)s %(message)s")

    if args.list_quarantine or args.restore:
        import enforcer
        if args.list_quarantine:
            items = enforcer.list_quarantine(STATE_DIR)
            for q in items:
                print(f"{q['sha256'][:16]}…  {q['quarantined_at']}  {q['original_path']}  "
                      f"(approved by {q.get('approved_by')}, score {q.get('threat_score')})")
            print(f"{len(items)} quarantined file(s)")
        else:
            try:
                print("restored to", enforcer.restore(STATE_DIR, args.restore))
            except enforcer.QuarantineError as exc:
                sys.exit(f"not restored: {exc}")
        return
    if args.pin_hub_key or args.list_blocks or args.unblock:
        import enforcer
        if args.pin_hub_key:
            if not HUB_KEY_URL:
                sys.exit(f"no Hub key URL configured: set SOC_HUB_KEY_URL, or hub_key_url in {CONFIG_FILE}, "
                         "e.g. https://soc-hub.your-tailnet.ts.net/warden/public-key")
            key = enforcer.pin_hub_key(HUB_KEY_URL, HUB_KEY_FILE)
            print(f"Pinned Hub key_id {key.key_id} to {HUB_KEY_FILE}")
            pk = json.loads(HUB_KEY_FILE.read_text(encoding="utf-8")).get("passkeys") or []
            print(f"Pinned {len(pk)} passkey(s) that can approve agent updates")
            print("Check it matches the Hub log line 'execution orders are signed with "
                  "Ed25519 key_id=...'")
        elif args.list_blocks:
            blocks = enforcer.list_blocks(STATE_DIR)
            for b in blocks:
                print(f"{b['ip']:<40} order {b['order_id']}  {b['applied_at']}  "
                      f"score {b.get('threat_score')}  approved by {b.get('approved_by')}")
            print(f"{len(blocks)} block(s)")
        else:
            n = enforcer.unblock(STATE_DIR, args.unblock)
            print(f"removed {n} block(s) for {args.unblock}")
        return
    run(args.dry_run)


if __name__ == "__main__":
    main()
