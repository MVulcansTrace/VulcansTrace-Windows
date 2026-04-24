# Expertise Snapshot

> **1 page:** the subsystem, why it matters, and where the proof lives in the codebase.

---

## Implementation Overview

A **flood detection engine** for VulcansTrace that identifies volumetric event spikes from a single source IP in firewall logs. It groups entries by source, sorts chronologically, slides a two-pointer window across each source's timeline, and emits structured findings when event density exceeds a configurable threshold.

---

## Key Metrics

| Metric | Value |
|--------|-------|
| Detection method | Two-pointer sliding window + event count |
| Sensitivity profiles | Low (400 events), Medium (200), High (100) in 60 seconds |
| Severity | High (Critical when correlated with Beaconing + LateralMovement) |
| Cross-detector correlation | Beaconing + LateralMovement on same host escalates Flood to Critical via RiskEscalator |
| Test coverage | 8 test methods covering threshold, boundary, disabled, empty, multi-source, and time-spread scenarios |

---

## Why It Matters

- Detects availability-relevant behavior — high event volumes that may indicate service degradation or denial-of-service attempts
- Sliding window catches floods that span fixed bucket boundaries instead of splitting them into separate intervals
- Cross-detector correlation raises confidence: Beaconing + LateralMovement on the same host escalates all findings for that host, including Flood, to Critical
- Documented limitations: DDoS, slow-rate attacks, and spoofed sources are documented gaps with specific improvement paths

---

## Key Evidence

- [FloodDetector.cs](../../../VulcansTrace.Engine/Detectors/FloodDetector.cs): grouping, sorting, sliding window, threshold check, and finding creation
- [AnalysisProfileProvider.cs](../../../VulcansTrace.Engine/Configuration/AnalysisProfileProvider.cs): built-in Low, Medium, and High presets
- [RiskEscalator.cs](../../../VulcansTrace.Engine/RiskEscalator.cs): cross-detector correlation (Beaconing + LateralMovement -> Critical)
- [FloodDetectorTests.cs](../../../VulcansTrace.Tests/Engine/Detectors/FloodDetectorTests.cs): above-threshold, below-threshold, boundary, disabled, empty, multi-source, and time-spread coverage
- [RiskEscalatorTests.cs](../../../VulcansTrace.Tests/Engine/RiskEscalatorTests.cs): escalation and correlation scenarios

---

## Key Design Choices

- **Sliding window over buckets** because floods do not respect clock boundaries — buckets split attacks at aligned edges
- **Per-source grouping** because aggregate counts hide the one noisy source — isolation enables attribution
- **Event count over rate** because the window already constrains time — simpler, deterministic, exactly reproducible
- **One finding per source** because duplicate alerts for the same flooding host add no investigative value
- **Inclusive threshold (`>=`)** because boundary precision matters for both detection and testing

