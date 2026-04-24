# Expertise Snapshot

> **1 page:** the subsystem, why it matters, and where the proof lives in the codebase.

---

## Implementation Overview

A **beaconing detection engine** for VulcansTrace that identifies command-and-control communication by analyzing the statistical regularity of network connections. It groups traffic by (SrcIp, DstIp, DstPort) channel, computes inter-arrival intervals, trims outliers symmetrically, and applies population standard deviation to distinguish automated C2 behavior from human traffic.

---

## Key Metrics

| Metric | Value |
|--------|-------|
| Algorithm complexity | O(n log n) time, O(n) space |
| Pipeline steps | 9 (toggle, group, cap, events gate, duration gate, intervals, trim, mean-bounds, stdDev threshold) |
| Sensitivity profiles | Low / Medium / High presets |
| Default Medium std dev threshold | 5.0 seconds |
| C2 sweet spot (Medium) | 30s–900s mean interval (varies by profile: Low 60s–900s, High 10s–900s) |
| Configuration parameters | 8 per profile (1 toggle + 7 thresholds) |
| Escalation | Beaconing + LateralMovement from same host → all findings for that host → Critical |

---

## Why It Matters

- Detects compromised hosts that are under active adversary control — one of the highest-priority SOC signals
- Uses defensible statistics (population std dev) rather than heuristics
- Correlates with lateral movement findings for risk escalation
- Produces structured, explainable findings with quantitative evidence

---

## Key Evidence

- [BeaconingDetector.cs](../../../VulcansTrace.Engine/Detectors/BeaconingDetector.cs): 9-step detection pipeline from tuple grouping through finding emission
- [AnalysisProfile.cs](../../../VulcansTrace.Engine/AnalysisProfile.cs): eight beaconing-specific configuration parameters (1 toggle + 7 thresholds) in an immutable record
- [AnalysisProfileProvider.cs](../../../VulcansTrace.Engine/Configuration/AnalysisProfileProvider.cs): built-in Low, Medium, and High presets
- [RiskEscalator.cs](../../../VulcansTrace.Engine/RiskEscalator.cs): cross-correlation logic for Beaconing + LateralMovement escalation
- [BeaconingDetectorTests.cs](../../../VulcansTrace.Tests/Engine/Detectors/BeaconingDetectorTests.cs): regular beaconing, gating, trimming, sample-cap, and noisy-periodic coverage

---

## Key Design Choices

- **Tuple-based grouping** so each destination channel gets its own statistical verdict, preventing dilution from mixed traffic
- **Symmetric outlier trimming** so network jitter and occasional anomalies don't inflate std dev
- **Mean interval bounds** encoding domain knowledge — C2 often lives in the 30-to-900-second sweet spot on Medium (60s–900s on Low, 10s–900s on High), screening out many very fast or very slow channels without semantically classifying them
- **Correlation-based escalation** — Medium severity for uncorrelated beaconing (filtered from output on Low intensity), Critical when LateralMovement from the same host confirms active attack progression, escalating all findings for that host
