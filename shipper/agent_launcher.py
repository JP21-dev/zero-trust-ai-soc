"""Starts the SOC agent, keeps it running, and finishes or undoes self-updates.

The SOCShipper scheduled task runs this file, which runs shipper.py as a child:
  * exit code 75: updater.py just installed a release, so start the new version now;
  * any other exit: start it again after a pause (10 s, doubling up to 5 minutes);
  * after an update, if the new version exits, or hasn't reported healthy within
    10 minutes, put the previous files back, remember that release as bad here,
    and start the previous version again.

Only the installer replaces this file, never a self-update, so a broken release
can't break the rollback.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
STATE = Path(os.environ.get("SOC_STATE_DIR") or Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData")) / "SOCShipper")
UPDATES = STATE / "updates"
RESTART_CODE = 75
HEALTH_TIMEOUT = 600
NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


def _read(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _write(path: Path, data) -> None:
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data), encoding="utf-8")
    os.replace(tmp, path)


def rollback(pending: dict, why: str, install_dir: Path = HERE, updates: Path = UPDATES) -> None:
    backup = Path(pending.get("backup") or updates / "backup")
    for name in pending.get("files") or []:
        if "/" in name or "\\" in name:
            continue
        target = install_dir / name
        if (backup / name).exists():
            shutil.copy2(backup / name, target)
        elif name in (pending.get("new_files") or []):
            target.unlink(missing_ok=True)
    if pending.get("sysmon_config"):
        windir = Path(os.environ.get("SystemRoot", r"C:\Windows"))
        for exe in (windir / "Sysmon64.exe", windir / "Sysmon.exe"):
            if exe.exists():
                subprocess.run([str(exe), "-c", str(install_dir / "sysmon-config.xml")],
                               capture_output=True, timeout=60, creationflags=NO_WINDOW)
                break
    bad = _read(updates / "bad_releases.json") or []
    if pending.get("seq") not in bad:
        bad.append(pending.get("seq"))
    _write(updates / "bad_releases.json", bad)
    _write(updates / "last_result.json", {"seq": pending.get("seq"), "status": "rolled_back",
                                           "detail": why, "at": time.time()})
    (updates / "pending.json").unlink(missing_ok=True)


def main() -> None:
    UPDATES.mkdir(parents=True, exist_ok=True)
    delay = 10
    while True:
        started = time.time()
        child = subprocess.Popen([sys.executable, str(HERE / "shipper.py")], cwd=str(HERE),
                                 env={**os.environ, "SOC_LAUNCHER_PID": str(os.getpid())},
                                 creationflags=NO_WINDOW)
        code = None
        while code is None:
            try:
                code = child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pending = _read(UPDATES / "pending.json")
                if pending and time.time() - float(pending.get("applied_at") or 0) > HEALTH_TIMEOUT:
                    child.kill()
                    child.wait()
                    rollback(pending, "the new version didn't report healthy within 10 minutes")
                    code = -1
        pending = _read(UPDATES / "pending.json")
        if code == RESTART_CODE:
            delay = 10
            continue
        if pending:
            rollback(pending, f"the new version stopped (exit code {code})")
            delay = 10
            continue
        if code == -1:
            continue
        if time.time() - started > 600:
            delay = 10
        time.sleep(delay)
        delay = min(300, delay * 2)


if __name__ == "__main__":
    main()
