"""Calibrated synthetic dataset reproducing the paper's Table 2 (6,000-flow test).

**What this is, and is not.** The paper's Table 2 comes from replaying a
deterministic PCAP (``nids_test.pcap``, 6,000 flows) at 200 pps against a
live Snort + Suricata + tap0 pipeline in three modes; only the aggregate
result counts were kept, not the raw capture. This module does not attempt
to reconstruct that capture. Instead it generates a synthetic flow-and-alert
dataset whose category composition is back-solved algebraically from Table 2
itself, then replays it through the *same* ported DST + correlation code
used elsewhere in this repository (:mod:`dst_fusion.dst`,
:mod:`dst_fusion.correlation`) to reproduce those published numbers from
first principles and to produce the supporting visualizations in
``notebooks/dst_fusion_analysis.ipynb``. Treat it as a reproducibility /
illustration aid, not a re-run of the original experiment.

**Back-solving the constants.** Table 2 reports Mode A (Snort-only) = 5,000,
Mode B (raw sidecar union) = 10,000, and Mode C (DST-fused) = 6,047, with a
98.8% fusion rate. Modeling the traffic as three flow categories --
``DUAL`` (both engines detect it, e.g. the paper's Telnet/SMB case),
``SNORT_ONLY``, and ``SURICATA_ONLY`` (the paper's RDP case, invisible to
Mode A) -- and allowing a small fraction of ``DUAL`` flows to have their
two alerts land more than one correlation window apart (so they time out as
two separate single-engine events instead of fusing), the system

    Mode A = DUAL + SNORT_ONLY                            = 5,000
    Mode B = 2 * DUAL + SNORT_ONLY + SURICATA_ONLY         = 10,000
    Mode C = DUAL + SNORT_ONLY + SURICATA_ONLY + UNMATCHED = 6,047
    fusion_rate = (DUAL - UNMATCHED) / DUAL                = 0.988

has the solution below (rounded to the nearest whole flow), which also
implies SNORT_ONLY == SURICATA_ONLY and a total flow count of 5,999 -- within
1 flow of the paper's stated "6,000 flows", consistent with "~6,000" being a
rounded input description while 6,047 is the precise measured output. This
is one self-consistent decomposition of Table 2, not a claim about the
original traffic's true composition, which is not recoverable.
"""
from __future__ import annotations

import random
from dataclasses import dataclass
from typing import Iterator

from .correlation import Alert, Correlator, FusedEvent

DUAL_FLOWS = 4001
UNMATCHED_DUAL_FLOWS = 48
SNORT_ONLY_FLOWS = 999
SURICATA_ONLY_FLOWS = 999

CORRELATION_WINDOW_SECONDS = 5.0
REPLAY_DURATION_SECONDS = 60.0
DEFAULT_SEED = 20260327

DUAL_CATEGORIES = ("Telnet", "SMB")  # named in the paper as Mode B's doubled categories
SNORT_ONLY_CATEGORY = "FTP Brute Force"  # illustrative label -- not named in the paper
SURICATA_ONLY_CATEGORY = "RDP"  # the paper's named Mode-A blind spot

SRC_IP = "10.0.0.50"
DST_IP = "192.168.1.100"


@dataclass
class SimulationResult:
    alerts: list[Alert]
    events: list[FusedEvent]

    @property
    def mode_a(self) -> int:
        """Snort-only pipeline: every raw Snort alert."""
        return sum(1 for a in self.alerts if a.sensor_id == "snort")

    @property
    def mode_b(self) -> int:
        """Sidecar without dedup: every raw alert from either engine."""
        return len(self.alerts)

    @property
    def mode_c(self) -> int:
        """Hyper-Parser + DST fusion: events actually forwarded."""
        return len(self.events)

    @property
    def fusion_rate(self) -> float:
        """Share of DUAL-category flows that fused within the window."""
        dual_ids = {a.flow_id for a in self.alerts if a.flow_id and a.flow_id.startswith("dual-")}
        fused_ids = {e.flow_id for e in self.events if e.kind == "fused" and e.flow_id}
        return len(fused_ids) / len(dual_ids) if dual_ids else float("nan")

    @property
    def event_reduction_vs_mode_b(self) -> float:
        return 1.0 - self.mode_c / self.mode_b


def _alloc_ports() -> Iterator[int]:
    port = 40000
    while True:
        port += 1
        yield port


def simulate_alerts(seed: int = DEFAULT_SEED) -> list[Alert]:
    """Build the calibrated alert stream (see module docstring for the model)."""
    rng = random.Random(seed)
    ports = _alloc_ports()
    alerts: list[Alert] = []

    unmatched_idx = set(rng.sample(range(DUAL_FLOWS), UNMATCHED_DUAL_FLOWS))
    for i in range(DUAL_FLOWS):
        flow_id = f"dual-{i}"
        category = DUAL_CATEGORIES[i % len(DUAL_CATEGORIES)]
        dst_port = 23 if category == "Telnet" else 445
        src_port = next(ports)
        base_ts = rng.uniform(0.0, REPLAY_DURATION_SECONDS)
        if i in unmatched_idx:
            gap = rng.uniform(CORRELATION_WINDOW_SECONDS + 0.5, CORRELATION_WINDOW_SECONDS + 10.0)
        else:
            gap = rng.uniform(0.05, CORRELATION_WINDOW_SECONDS - 0.5)
        common = dict(src_ip=SRC_IP, dst_ip=DST_IP, src_port=src_port, dst_port=dst_port, proto="TCP")
        alerts.append(Alert(ts=base_ts, sensor_id="snort", priority=2, flow_id=flow_id,
                             signature=f"{category} detected (Snort)", **common))
        alerts.append(Alert(ts=base_ts + gap, sensor_id="suricata", priority=2, flow_id=flow_id,
                             signature=f"{category} detected (Suricata)", **common))

    for i in range(SNORT_ONLY_FLOWS):
        alerts.append(Alert(
            ts=rng.uniform(0.0, REPLAY_DURATION_SECONDS), sensor_id="snort", priority=2,
            src_ip=SRC_IP, dst_ip=DST_IP, src_port=next(ports), dst_port=21, proto="TCP",
            flow_id=f"snort-only-{i}", signature=f"{SNORT_ONLY_CATEGORY} detected (Snort)",
        ))

    for i in range(SURICATA_ONLY_FLOWS):
        alerts.append(Alert(
            ts=rng.uniform(0.0, REPLAY_DURATION_SECONDS), sensor_id="suricata", priority=2,
            src_ip=SRC_IP, dst_ip=DST_IP, src_port=next(ports), dst_port=3389, proto="TCP",
            flow_id=f"suricata-only-{i}", signature=f"{SURICATA_ONLY_CATEGORY} detected (Suricata)",
        ))

    return sorted(alerts, key=lambda a: a.ts)


def run_simulation(seed: int = DEFAULT_SEED, window_seconds: float = CORRELATION_WINDOW_SECONDS) -> SimulationResult:
    """Generate the calibrated dataset and replay it through the real correlator."""
    alerts = simulate_alerts(seed)
    events = Correlator(window_seconds=window_seconds).process_stream(alerts)
    return SimulationResult(alerts=alerts, events=events)
