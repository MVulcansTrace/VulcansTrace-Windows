# Expertise Snapshot

> **1 page:** the subsystem, why it matters, and where the proof lives in the codebase.

---

## Implementation Overview

A **port scan detection engine** for VulcansTrace that identifies likely reconnaissance from firewall logs. It groups activity by source IP, counts distinct destination IP and port pairs — first globally as a pre-check, then per time window — and emits structured findings for analyst review.

---

## Key Metrics

| Metric | Value |
|--------|-------|
| Algorithm complexity | O(n log n) time, O(n) space |
| Scan types detected | Horizontal + Vertical (detected but not classified) |
| Sensitivity profiles | Low / Medium / High presets |
| Default medium threshold | 15 distinct targets in 5 minutes |
| Resource protection | Optional truncation with warnings in custom profiles |

---

## Why It Matters

- Detects suspicious probing activity before it becomes a more serious incident
- Balances sensitivity with analyst fatigue through configurable profiles
- Produces explainable findings instead of opaque scoring
- Shows security thinking around limitations, evasion, and operational trade-offs

---

## Key Evidence

- [PortScanDetector.cs](../../../VulcansTrace.Engine/Detectors/PortScanDetector.cs): detection pipeline, tuple counting, bucketing, truncation, and finding creation
- [AnalysisProfileProvider.cs](../../../VulcansTrace.Engine/Configuration/AnalysisProfileProvider.cs): built-in Low, Medium, and High presets
- [PortScanDetectorTests.cs](../../../VulcansTrace.Tests/Engine/Detectors/PortScanDetectorTests.cs): above-threshold, below-threshold, multi-source, and truncation coverage
- [AnalysisProfileProviderTests.cs](../../../VulcansTrace.Tests/Engine/AnalysisProfileProviderTests.cs): verifies profile thresholds like 30, 15, and 8

---

## Key Design Choices

- **Distinct `(DstIp, DstPort)` tuples** so the detector can catch both horizontal and vertical scans
- **Global pre-check** so low-variety sources are skipped before more expensive window analysis; eligibility is checked on the full source set before truncation, so this is mathematically lossless even with custom profiles
- **Medium severity by default** because reconnaissance should be investigated, but not treated like confirmed compromise (note: on the Low profile, Medium-severity findings are filtered out by the pipeline's severity gate; only Medium and High profiles surface standalone port scan findings — however, if the same host triggers Beaconing + LateralMovement, RiskEscalator promotes port scan findings to Critical, which passes every profile's severity gate)
- **Risk escalation awareness** — if the same source IP also triggers Beaconing and LateralMovement findings, the pipeline's RiskEscalator promotes the port scan finding to Critical severity
- **Truncation with warnings** so custom profiles can bound per-source cost transparently instead of failing silently; the trade-off is reduced per-window completeness, but global eligibility is preserved

