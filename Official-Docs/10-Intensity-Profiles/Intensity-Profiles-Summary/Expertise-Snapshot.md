# Expertise Snapshot

> **1 page:** the subsystem, why it matters, and where the proof lives in the codebase.

---

## Implementation Overview

A **three-tier intensity profile system** for VulcansTrace that maps operational context (Low/Medium/High) to fully configured detection profiles. A Simple Factory produces immutable records with 20+ parameters controlling six detectors, and the pipeline orders risk escalation before severity filtering so that correlated compromise indicators survive even conservative output settings.

---

## Key Metrics

| Metric | Value |
|--------|-------|
| Profiles | 3 (Low, Medium, High) |
| Parameters per profile | 20+ (thresholds, enable flags, policy ports, severity gate) |
| Detectors controlled | 6 (PortScan, Flood, LateralMovement, Beaconing, PolicyViolation, Novelty) |
| Parameters that vary | 8 (thresholds + Novelty enable + severity gate) |
| Parameters constant | 15 (enable flags, time windows, policy ports, sampling caps, entry cap) |
| Pipeline stages | 4 (select, detect, escalate, filter) |
| Cross-detector correlation | Beaconing + LateralMovement → Critical via RiskEscalator |

---

## Why It Matters

- Analysts switch sensitivity with one selection instead of tuning 20+ individual parameters
- Escalation-before-filtering ensures correlated compromise indicators are never hidden
- Policy ports stay constant because they are organizational decisions, not sensitivity knobs
- Immutable records prevent configuration drift between detectors

---

## Key Evidence

- [AnalysisProfileProvider.cs](../../../VulcansTrace.Engine/Configuration/AnalysisProfileProvider.cs): Simple Factory with all three profiles
- [AnalysisProfile.cs](../../../VulcansTrace.Engine/AnalysisProfile.cs): immutable record with 20+ properties
- [SentryAnalyzer.cs](../../../VulcansTrace.Engine/SentryAnalyzer.cs): pipeline orchestrator — profile selection, detector dispatch, escalation, filtering
- [RiskEscalator.cs](../../../VulcansTrace.Engine/RiskEscalator.cs): cross-detector correlation promoting to Critical
- [AnalysisProfileProviderTests.cs](../../../VulcansTrace.Tests/Engine/AnalysisProfileProviderTests.cs): threshold values, monotonic sensitivity, constant policy ports, immutability
- [SentryAnalyzerTests.cs](../../../VulcansTrace.Tests/Engine/SentryAnalyzerTests.cs): severity filtering verified across Low, Medium, and High

---

## Key Design Choices

- **Escalate before filter** because filtering first would hide the Medium-severity Beaconing finding that triggers the cross-detector correlation
- **Constant time windows** because attack speed is a property of the attacker, not the defender's intensity selection
- **Constant policy ports** because organizational rules about admin ports should not change when an analyst switches to High
- **Simple Factory over manual config** because scattered threshold settings create inconsistency between detectors
