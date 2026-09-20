"""Dempster-Shafer Theory (DST) sensor fusion.

Ported from the Go production module used by the Hyper-Parser fusion engine
(``internal/fusion/dst.go`` in the Mata Elang Hyper-Parser codebase), which
is the system this repository's accompanying paper reports on. The port is
kept numerically identical — same mass constants, same combination rule, same
belief/plausibility definitions — so results computed here match production.

Frame of discernment: Theta = {TruePositive, FalsePositive}, encoded as a
2-bit mask so that intersection is a plain bitwise AND:

    HYP_TP        = 0b01   {TruePositive}
    HYP_FP        = 0b10   {FalsePositive}
    HYP_UNCERTAIN = 0b11   Theta (full ignorance / open world)

References
----------
[1] A. P. Dempster, "Upper and lower probabilities induced by a multivalued
    mapping," Annals of Mathematical Statistics, vol. 38, no. 2, 1967.
[2] G. Shafer, A Mathematical Theory of Evidence, Princeton Univ. Press, 1976.
[3] K. Sentz and S. Ferson, "Combination of Evidence in Dempster-Shafer
    Theory," Sandia National Laboratories, SAND2002-0835, 2002.
[4] A. Valdes and K. Skinner, "Probabilistic alert correlation," RAID 2001.
"""
from __future__ import annotations

from dataclasses import dataclass, field

HYP_NONE = 0
HYP_TP = 1
HYP_FP = 2
HYP_UNCERTAIN = HYP_TP | HYP_FP

MassFunction = dict[int, float]

_SUBSETS = (HYP_TP, HYP_FP, HYP_UNCERTAIN)


@dataclass
class DST:
    """Per-engine reliability parameters used to derive mass functions.

    ``engine_mass`` is the base m({TP}) for a medium-priority alert from that
    engine. ``silence_mass`` is m({FP}) assigned when an engine does NOT fire
    within the correlation window — absence of corroboration is treated as
    weak FP evidence ([4] Sec. 4).

    Defaults mirror ``NewDST()`` in dst.go: Snort and Suricata are treated as
    near-equal, conservative sources; neither is assumed dominant.
    """

    engine_mass: dict[str, float] = field(
        default_factory=lambda: {"snort": 0.70, "suricata": 0.65}
    )
    silence_mass: float = 0.15

    def alert_mass(self, sensor_id: str, priority: int) -> MassFunction:
        """BPA for an engine that fired an alert at the given priority.

        Mass goes only to {TP} and Theta; m({FP}) = 0, since a firing alert
        is never itself evidence of being a false positive. The {TP} mass is
        scaled by priority (P1 x1.20, P2 x1.00, P3 x0.80, P4+ x0.60), clamped
        to [0.05, 0.95], with the remainder assigned to Theta (ignorance).
        """
        base = self.engine_mass.get(sensor_id, 0.60)
        tp = _clamp(base * _priority_scale(priority), 0.05, 0.95)
        return {HYP_TP: tp, HYP_UNCERTAIN: 1.0 - tp}

    def silence(self) -> MassFunction:
        """BPA representing a sensor's silence during the correlation window."""
        return {HYP_FP: self.silence_mass, HYP_UNCERTAIN: 1.0 - self.silence_mass}

    def combine(self, m1: MassFunction, m2: MassFunction) -> tuple[MassFunction, float]:
        """Dempster's orthogonal sum m1 (+) m2 ([1] eq. 3.3, [3] Sec. 3.1).

        Returns the normalised combined BPA and the conflict factor
        K in [0, 1). K = 0 means the two sources fully agree (no disjoint
        mass); K -> 1 means near-total disagreement.
        """
        raw: MassFunction = {}
        k = 0.0
        for a in _SUBSETS:
            ma = m1.get(a, 0.0)
            if ma == 0.0:
                continue
            for b in _SUBSETS:
                mb = m2.get(b, 0.0)
                if mb == 0.0:
                    continue
                intersection = a & b
                if intersection == HYP_NONE:
                    k += ma * mb
                else:
                    raw[intersection] = raw.get(intersection, 0.0) + ma * mb

        if k >= 1.0:
            raise ValueError("dst: complete conflict (K=1); combination is undefined")

        norm = 1.0 - k
        return {h: m / norm for h, m in raw.items()}, k


def belief(m: MassFunction, h: int) -> float:
    """Bel(A) = sum of m(B) for all non-empty B subset-of A ([2] Sec. 2.3)."""
    return sum(mass for subset, mass in m.items() if subset != HYP_NONE and (subset & ~h) == 0)


def plausibility(m: MassFunction, h: int) -> float:
    """Pl(A) = sum of m(B) for all B with B intersect A non-empty ([2] Sec. 2.4)."""
    return sum(mass for subset, mass in m.items() if subset != HYP_NONE and (subset & h) != 0)


def _priority_scale(priority: int) -> float:
    return {1: 1.20, 2: 1.00, 3: 0.80}.get(priority, 0.60)


def _clamp(value: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, value))
