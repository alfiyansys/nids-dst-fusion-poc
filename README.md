# nids-dst-fusion-poc

[![notebook](https://github.com/alfiyansys/nids-dst-fusion-poc/actions/workflows/notebook.yml/badge.svg)](https://github.com/alfiyansys/nids-dst-fusion-poc/actions/workflows/notebook.yml)

Python proof-of-concept and analysis notebook for the sensor-fusion
mechanism described in:

> **Dempster-Shafer Theory-Based Sensor Fusion for Belief Quantification in
> Multi-Engine Network Intrusion Detection Systems**
> M. Alfiyan Syamsuddin (manuscript in preparation)

The paper's Fusion Engine is a Go module running inside the
[Hyper-Parser](https://github.com/mata-elang-stable) pipeline on the Mata
Elang NIDS platform. This repository ports that module's core algorithm to
Python (`dst_fusion/`), verifies it against the paper's own reported
numbers, and uses it to generate every figure referenced from the paper.

## What's here

```
dst_fusion/            Python port of the production DST fusion engine
  dst.py                 Mass functions, Dempster's combination rule, Belief/Plausibility
  correlation.py          5-tuple flow key, TTL correlation window, fusion outcomes
  loaders.py              Parsers for real Snort/Suricata JSON log formats
  simulate.py              Calibrated 6,000-flow dataset reproducing the paper's Table 2

data/fusible-sample/    Real Snort + Suricata JSON output (synthetic content,
                        genuine engine schema), used in the notebook to
                        demonstrate the correlator against real log formats

notebooks/
  dst_fusion_analysis.ipynb   End-to-end walkthrough + every figure below

figures/                PNG output of the notebook, committed so they render
                        without needing to run anything
```

## Why a port, not the original Go code

The point of this repository is to make the fusion mechanism's *behavior*
independently checkable and visualizable, from a paper reader's machine,
without needing the full Hyper-Parser Go build or the private infrastructure
it was tested on. `dst_fusion/dst.py` and `dst_fusion/correlation.py` are
deliberately kept numerically identical to the production module (same
constants, same combination rule, same window semantics). See each file's
module docstring for exactly which Go file and functions they mirror.

## Results reproduced here

| | Paper (Table 2) | This repo (`run_simulation()`) |
|---|---|---|
| Mode A (Snort only) | 5,000 | 5,000 |
| Mode B (sidecar, no dedup) | 10,000 | 10,000 |
| Mode C (DST fusion) | 6,047 | 6,047 |
| Fusion rate | 98.8% | 98.8% |
| Bel(TP), fused | 0.895 | 0.895 |
| Bel(TP), Snort alone | 0.665 | 0.665 |
| Bel(TP), Suricata alone | 0.612 | 0.612 |

Every number in the right column is *computed* by running
`dst_fusion.simulate.run_simulation()`. None of it is hardcoded to match
the left column; see the caveat below for how that's possible.

**Important caveat.** The paper's Table 2 comes from replaying a
deterministic PCAP (`nids_test.pcap`, 6,000 flows) through a live
Snort + Suricata + tap0 pipeline; that raw capture was never kept as a
versioned artifact, only its aggregate results were. `dst_fusion/simulate.py`
does not attempt to reconstruct the original traffic. Instead it back-solves
a synthetic flow-category composition *algebraically from Table 2's own
published numbers* (see that module's docstring for the derivation), then
replays the resulting synthetic alert stream through the same ported
DST + correlation code used everywhere else in this repository. It is a
reproducibility aid that shows the algorithm can produce those results from
first principles, not a re-run of the original experiment.

The `data/fusible-sample/` walkthrough in the notebook, by contrast, uses
**real** Snort/Suricata output (synthetic in content, genuine in format) with
no back-solving involved.

## Figures

| | |
|---|---|
| `fig_bpa_mass_assignment.png` | Per-engine, per-priority basic probability assignment |
| `fig_belief_by_priority.png` | Fused vs. single-engine Bel(TP) across all four priority levels |
| `fig_three_modes_comparison.png` | Table 2's event-volume comparison, Mode A/B/C |
| `fig_event_breakdown.png` | Mode C's fused / single-Snort / single-Suricata composition |
| `fig_belief_distribution.png` | Bel(TP) distribution across the simulated 6,000-flow test |

## Running it

Requires [uv](https://docs.astral.sh/uv/).

```bash
uv sync
uv run jupyter execute notebooks/dst_fusion_analysis.ipynb   # re-run headless
uv run jupyter notebook notebooks/dst_fusion_analysis.ipynb  # open interactively
```

Or use the package directly:

```python
from dst_fusion.simulate import run_simulation

result = run_simulation()
print(result.mode_a, result.mode_b, result.mode_c, result.fusion_rate)
```

`uv.lock` pins exact dependency versions, and `simulate.run_simulation()`
uses a fixed seed, so results are deterministic across machines.

## License

MIT, see [LICENSE](LICENSE).
