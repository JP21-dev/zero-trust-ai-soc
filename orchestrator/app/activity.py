"""Hub activity history: what the dashboard shows.

Two kinds of records, kept in memory and appended to one JSONL file in the
Warden data volume so a restart doesn't wipe the dashboard:

  batch    one per POST /ingest (counts, score, decision, new connections)
  notable  everything a human cares about: escalations, approvals, denials,
           expiries, enforcement results, passkey enrollments, dashboard logins

Endpoint "last seen" comes from both ingest and the enforcer's order polling.
Enforcer polls are tracked in memory only (they happen every 10 s and carry no
information worth persisting).

Everything recorded here may contain attacker-controlled text (process names,
LLM signatures). The dashboard renders it with textContent, never as HTML.
"""
from __future__ import annotations

import json
import logging
import os
import threading
import time
from collections import deque
from pathlib import Path
from typing import Any

log = logging.getLogger("soc.activity")

BATCH_WINDOW = 24 * 3600     # keep a day of batches (chart + KPIs)
MAX_BATCHES = 20_000         # hard cap whatever the rate
MAX_NOTABLE = 1_000
MAX_ENDPOINTS = 64
COMPACT_EVERY = 2_000        # rewrite the file after this many appends
ONLINE_SECONDS = 60
IDLE_SECONDS = 600


def _clip(value: Any, limit: int = 200) -> Any:
    if isinstance(value, str):
        return value[:limit]
    return value


class Activity:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.batches: deque[dict[str, Any]] = deque(maxlen=MAX_BATCHES)
        self.notable: deque[dict[str, Any]] = deque(maxlen=MAX_NOTABLE)
        self.endpoints: dict[str, dict[str, Any]] = {}
        self.blocks: dict[str, dict[str, Any]] = {}   # "endpoint|ip" -> block
        self.started_at = time.time()
        self.busy: dict[str, dict[str, Any]] = {}     # agent -> {"since", "endpoint_id", "test"}
        self._lock = threading.Lock()
        self._appends = 0

    # ------------------------------------------------------------ live agents
    def agent_busy(self, agent: str, endpoint_id: str, test: bool) -> None:
        self.busy[agent] = {"since": time.time(), "endpoint_id": endpoint_id, "test": test}

    def agent_idle(self, agent: str) -> None:
        self.busy.pop(agent, None)

    # ------------------------------------------------------------------ load
    def load(self) -> None:
        try:
            lines = self.path.read_text(encoding="utf-8").splitlines()
        except FileNotFoundError:
            return
        except OSError as exc:
            log.error("activity: cannot read %s: %s", self.path, type(exc).__name__)
            return
        cutoff = time.time() - BATCH_WINDOW
        n = 0
        for line in lines:
            try:
                ev = json.loads(line)
            except ValueError:
                continue
            if not isinstance(ev, dict) or "kind" not in ev or "ts" not in ev:
                continue
            if ev["kind"] == "batch" and ev["ts"] < cutoff:
                self._apply_endpoint(ev)   # still counts toward "last seen"
                continue
            self._apply(ev)
            n += 1
        log.info("activity: restored %d records from %s", n, self.path.name)

    # ---------------------------------------------------------------- record
    def record(self, kind: str, **data: Any) -> dict[str, Any]:
        ev = {"ts": round(time.time(), 3), "kind": kind,
              **{k: _clip(v) for k, v in data.items()}}
        with self._lock:
            self._apply(ev)
            self._append(ev)
        return ev

    def touch_poll(self, endpoint_id: str) -> None:
        with self._lock:
            ep = self._endpoint(endpoint_id)
            if ep is not None:
                ep["last_poll"] = time.time()

    # -------------------------------------------------------------- internals
    def _endpoint(self, endpoint_id: str) -> dict[str, Any] | None:
        ep = self.endpoints.get(endpoint_id)
        if ep is None:
            if len(self.endpoints) >= MAX_ENDPOINTS:
                return None
            ep = self.endpoints[endpoint_id] = {
                "endpoint_id": endpoint_id, "first_seen": time.time(), "last_ingest": None,
                "last_poll": None, "batches": 0, "events": 0, "max_score": 0,
                "escalations": 0, "blocks": 0}
        return ep

    def _apply_endpoint(self, ev: dict[str, Any]) -> None:
        ep_id = ev.get("endpoint_id")
        if not isinstance(ep_id, str) or ev.get("test"):
            return
        ep = self._endpoint(ep_id)
        if ep is None:
            return
        ep["first_seen"] = min(ep["first_seen"], ev["ts"])
        if ev["kind"] == "batch":
            ep["last_ingest"] = max(ep["last_ingest"] or 0, ev["ts"])
            ep["batches"] += 1
            ep["events"] += int(ev.get("received") or 0)
            ep["max_score"] = max(ep["max_score"], int(ev.get("score") or 0))
        elif ev["kind"] == "escalated":
            ep["escalations"] += 1
        elif ev["kind"] == "enforced":
            ep["blocks"] += 1

    def _apply(self, ev: dict[str, Any]) -> None:
        self._apply_endpoint(ev)
        if ev["kind"] == "batch":
            self.batches.append(ev)
            return
        self.notable.append(ev)
        if ev["kind"] == "enforced" and ev.get("target_ip") and not ev.get("test"):
            key = f"{ev.get('endpoint_id')}|{ev['target_ip']}"
            self.blocks[key] = {
                "endpoint_id": ev.get("endpoint_id"), "ip": ev["target_ip"],
                "order_id": ev.get("order_id"), "applied_at": ev["ts"],
                "approved_by": ev.get("approved_by"), "threat_score": ev.get("threat_score"),
                "status": ev.get("status")}

    def _append(self, ev: dict[str, Any]) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(json.dumps(ev, separators=(",", ":")) + "\n")
            self._appends += 1
            if self._appends >= COMPACT_EVERY:
                self._compact()
        except OSError as exc:
            log.error("activity: cannot write %s: %s", self.path, type(exc).__name__)

    def _compact(self) -> None:
        """Rewrite the file with only what's still in memory (atomic replace)."""
        self._appends = 0
        cutoff = time.time() - BATCH_WINDOW
        keep = sorted([*self.notable, *(b for b in self.batches if b["ts"] >= cutoff)],
                      key=lambda e: e["ts"])
        tmp = self.path.with_suffix(".jsonl.tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            for ev in keep:
                f.write(json.dumps(ev, separators=(",", ":")) + "\n")
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, self.path)

    # -------------------------------------------------------------- snapshot
    def snapshot(self, now: float | None = None) -> dict[str, Any]:
        now = now or time.time()
        with self._lock:
            all_batches = [b for b in self.batches if b["ts"] >= now - BATCH_WINDOW]
            notable = list(self.notable)
            busy = {k: dict(v) for k, v in self.busy.items()}
            endpoints = [dict(e) for e in self.endpoints.values()]
            blocks = sorted((dict(b) for b in self.blocks.values()),
                            key=lambda b: b["applied_at"], reverse=True)
        batches = [b for b in all_batches if not b.get("test")]   # real traffic only for stats

        for ep in endpoints:
            seen = max(ep["last_ingest"] or 0, ep["last_poll"] or 0)
            ep["last_seen"] = seen or None
            age = now - seen if seen else None
            ep["state"] = ("online" if age is not None and age <= ONLINE_SECONDS else
                           "idle" if age is not None and age <= IDLE_SECONDS else "offline")
        endpoints.sort(key=lambda e: e["last_seen"] or 0, reverse=True)

        # Per-minute series for the last 60 minutes (oldest first).
        start = (int(now) // 60 - 59) * 60
        series = [{"t": start + i * 60, "events": 0, "analyzed": 0, "batches": 0,
                   "max_score": None, "escalations": 0} for i in range(60)]
        for b in batches:
            i = (int(b["ts"]) - start) // 60
            if 0 <= i < 60:
                s = series[i]
                s["events"] += int(b.get("received") or 0)
                s["analyzed"] += int(b.get("analyzed") or 0)
                s["batches"] += 1
                s["max_score"] = max(s["max_score"] or 0, int(b.get("score") or 0))
                if str(b.get("decision", "")).startswith("pending_fido2"):
                    s["escalations"] += 1

        day = [n for n in notable if n["ts"] >= now - BATCH_WINDOW and not n.get("test")]
        kpis = {
            "events_24h": sum(int(b.get("received") or 0) for b in batches),
            "analyzed_24h": sum(int(b.get("analyzed") or 0) for b in batches),
            "batches_24h": len(batches),
            "escalations_24h": sum(n["kind"] == "escalated" for n in day),
            "approvals_24h": sum(n["kind"] == "approved" for n in day),
            "blocks_total": len(blocks),
            "injections_24h": sum(int(b.get("injections") or 0) for b in batches),
            "max_score_24h": max((int(b.get("score") or 0) for b in batches), default=0),
        }

        # Newest novel connections, de-duplicated.
        seen_fp: set[str] = set()
        new_conns: list[dict[str, Any]] = []
        for b in reversed(batches):
            for fp in b.get("new_connections") or []:
                key = f"{b.get('endpoint_id')}|{fp}"
                if key in seen_fp:
                    continue
                seen_fp.add(key)
                new_conns.append({"ts": b["ts"], "endpoint_id": b.get("endpoint_id"),
                                  "connection": fp, "score": b.get("score")})
                if len(new_conns) >= 40:
                    break
            if len(new_conns) >= 40:
                break

        last = batches[-1] if batches else None
        return {
            "endpoints": endpoints,
            "blocks": blocks,
            "series": series,
            "kpis": kpis,
            "agents": self._agents(all_batches, batches, day, endpoints, busy, now),
            "timeline": list(reversed(notable))[:150],
            "recent_batches": list(reversed(batches))[:40],
            "runs": [{k: b.get(k) for k in ("ts", "endpoint_id", "test", "received", "score", "decision",
                                            "trace", "target_ip", "new_connections")}
                     for b in reversed(all_batches[-30:])],
            "new_connections": new_conns,
            "last_llm_status": last.get("llm_status") if last else None,
            "last_batch_at": last["ts"] if last else None,
            "hub_started_at": self.started_at,
        }

    @staticmethod
    def _agents(all_batches, batches, day, endpoints, busy, now) -> dict[str, Any]:
        """Per-agent card data: what it's doing now, what it did last, and 24 h totals."""
        out: dict[str, Any] = {}
        for name in ("gatekeeper", "detective", "strategist", "warden"):
            last = None
            for b in reversed(all_batches):
                entry = next((t for t in b.get("trace") or [] if t.get("agent") == name), None)
                if entry:
                    last = {**entry, "ts": b["ts"], "endpoint_id": b.get("endpoint_id"),
                            "test": bool(b.get("test"))}
                    break
            entries = [t for b in batches for t in b.get("trace") or [] if t.get("agent") == name]
            s = lambda k: sum(int((t.get("stats") or {}).get(k) or 0) for t in entries)
            stats: dict[str, Any] = {"runs": len(entries)}
            if name == "gatekeeper":
                stats.update(checked=s("checked"), dropped=s("dropped"), injections=s("injections"),
                             findings=s("findings"))
            elif name == "detective":
                stats.update(lookups=s("lookups"), novel=s("novel"))
            elif name == "strategist":
                llm = [str((t.get("stats") or {}).get("llm")) for t in entries]
                stats.update(gemini=llm.count("ok"), rules=len(llm) - llm.count("ok"),
                             max_score=max((int((t.get("stats") or {}).get("score") or 0) for t in entries),
                                           default=0))
            else:
                kinds = [n["kind"] for n in day]
                stats.update(escalated=kinds.count("escalated"), approved=kinds.count("approved"),
                             denied=kinds.count("denied"), expired=kinds.count("challenge_expired"))
            out[name] = {"busy": busy.get(name), "last": last, "stats": stats}

        # The Enforcer runs on each endpoint; its state comes from order polling + acks.
        enf_events = [n for n in day if n["kind"] in ("order_picked_up", "enforced", "enforce_failed")]
        last_enf = next((n for n in reversed(day) if n["kind"] in ("enforced", "enforce_failed",
                                                                    "order_picked_up")), None)
        polling = [e for e in endpoints if e.get("last_poll") and now - e["last_poll"] <= 60]
        out["enforcer"] = {
            "busy": None, "last": last_enf,
            "polling": [{"endpoint_id": e["endpoint_id"], "last_poll": e["last_poll"]} for e in polling],
            "stats": {"blocks": sum(n["kind"] == "enforced" for n in enf_events),
                      "failed": sum(n["kind"] == "enforce_failed" for n in enf_events),
                      "endpoints": len(polling)},
        }
        return out
