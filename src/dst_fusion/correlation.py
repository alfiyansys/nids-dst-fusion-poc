"""5-tuple flow correlation and correlation-window fusion.

Ported from the Go production module (``internal/fusion/deduplicator.go``,
``state.go`` and ``engine.go`` in the Hyper-Parser fusion package): the
SHA-256 flow key, the TTL-bounded window cache, and the three correlation
outcomes (cross-engine match, same-engine repeat, expiry without a pair).

The original runs as a streaming worker with a periodic flush ticker against
live traffic. This port is an offline/batch variant for notebook use: given
an already-time-ordered sequence of alerts, it reproduces the exact same
matching and Dempster combination decisions the production pipeline would
make, by sweeping expired cache entries up to each alert's timestamp (and
once more at the end of the stream) instead of on a wall-clock ticker.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Iterable, Optional

from .dst import DST, HYP_TP, MassFunction, belief, plausibility

DEFAULT_WINDOW_SECONDS = 5.0
DEFAULT_FUSED_SENSOR_ID = "hyper-fused"


@dataclass
class Alert:
    """A single-engine alert as it would arrive at the Fusion Engine."""

    ts: float
    sensor_id: str  # "snort" | "suricata"
    priority: int
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    proto: str
    flow_id: Optional[str] = None  # analysis-only label, not used for correlation
    signature: Optional[str] = None


@dataclass
class FusedEvent:
    """An event as it would be forwarded to the Defense Center (Mode C)."""

    ts: float
    flow_key: str
    kind: str  # "fused" | "single_snort" | "single_suricata"
    engines: str
    belief_tp: float
    plausibility_tp: float
    conflict_k: float
    flow_id: Optional[str] = None
    signature: Optional[str] = None


@dataclass
class _Entry:
    alert: Alert
    sensor_id: str
    expires_at: float
    mass: MassFunction


def flow_key(src_ip: str, dst_ip: str, src_port: int, dst_port: int, proto: str) -> str:
    """SHA-256 flow key truncated to 8 bytes hex, over the 5-tuple.

    Identical construction to ``Deduplicator.flowKey`` in deduplicator.go.
    """
    raw = f"{src_ip}|{dst_ip}|{src_port}|{dst_port}|{proto}"
    digest = hashlib.sha256(raw.encode("utf-8")).digest()
    return digest[:8].hex()


class Correlator:
    """Offline port of Engine + Deduplicator + WindowCache."""

    def __init__(self, window_seconds: float = DEFAULT_WINDOW_SECONDS, dst: Optional[DST] = None):
        self.window_seconds = window_seconds
        self.dst = dst or DST()
        self._cache: dict[str, _Entry] = {}

    def process_stream(self, alerts: Iterable[Alert]) -> list[FusedEvent]:
        """Replay a time-ordered alert stream through the correlation window.

        Returns every event the Defense Center would have received: fused
        cross-engine events plus single-engine events emitted once their
        window expires without a match (Mode C's event count).
        """
        ordered = sorted(alerts, key=lambda a: a.ts)
        out: list[FusedEvent] = []
        for alert in ordered:
            self._expire_up_to(alert.ts, out)
            fused = self._process_one(alert)
            if fused is not None:
                out.append(fused)
        if ordered:
            self._expire_up_to(ordered[-1].ts + self.window_seconds, out)
        return out

    def _process_one(self, alert: Alert) -> Optional[FusedEvent]:
        key = flow_key(alert.src_ip, alert.dst_ip, alert.src_port, alert.dst_port, alert.proto)
        incoming_mass = self.dst.alert_mass(alert.sensor_id, alert.priority)

        existing = self._cache.get(key)
        if existing is None:
            self._cache[key] = _Entry(
                alert=alert,
                sensor_id=alert.sensor_id,
                expires_at=alert.ts + self.window_seconds,
                mass=incoming_mass,
            )
            return None

        if existing.sensor_id == alert.sensor_id:
            # Same-engine repeat: update the held entry and extend the TTL.
            self._cache[key] = _Entry(
                alert=alert,
                sensor_id=alert.sensor_id,
                expires_at=alert.ts + self.window_seconds,
                mass=incoming_mass,
            )
            return None

        # Cross-engine match: both BPAs allocate mass only to {TP} and Theta,
        # so K = 0 and Bel({TP}) is strictly higher than either engine alone.
        combined, k = self.dst.combine(existing.mass, incoming_mass)
        del self._cache[key]
        return FusedEvent(
            ts=alert.ts,
            flow_key=key,
            kind="fused",
            engines=f"{existing.sensor_id}+{alert.sensor_id}",
            belief_tp=belief(combined, HYP_TP),
            plausibility_tp=plausibility(combined, HYP_TP),
            conflict_k=k,
            flow_id=alert.flow_id,
            signature=alert.signature,
        )

    def _expire_up_to(self, now: float, out: list[FusedEvent]) -> None:
        expired_keys = [k for k, e in self._cache.items() if e.expires_at <= now]
        if not expired_keys:
            return
        silence = self.dst.silence()
        for key in expired_keys:
            entry = self._cache.pop(key)
            combined, k = self.dst.combine(entry.mass, silence)
            out.append(
                FusedEvent(
                    ts=entry.expires_at,
                    flow_key=key,
                    kind=f"single_{entry.sensor_id}",
                    engines=entry.sensor_id,
                    belief_tp=belief(combined, HYP_TP),
                    plausibility_tp=plausibility(combined, HYP_TP),
                    conflict_k=k,
                    flow_id=entry.alert.flow_id,
                    signature=entry.alert.signature,
                )
            )
