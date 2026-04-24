# Expertise Snapshot

> **1 page:** the subsystem, why it matters, and where the proof lives in the codebase.

---

## Implementation Overview

A **defense-in-depth test suite** for VulcansTrace that validates six detectors, a multi-stage analysis pipeline, cryptographic evidence integrity, and a WPF desktop application. The suite uses threshold boundary tests for statistical detectors, scenario tests for rule-based detectors, integration tests for cross-detector correlation, and robustness tests for fault tolerance.

---

## Key Metrics

| Metric | Value |
|--------|-------|
| Test files | 23 |
| Test methods | 188 |
| Detector test files | 6 (PortScan, Beaconing, Flood, LateralMovement, PolicyViolation, Novelty) |
| Core test files | 3 (log parsing, domain models, SHA-256/HMAC integrity) |
| Engine pipeline test files | 4 (analyzer orchestration, profile thresholds, IP classification, risk escalation) |
| Integration test files | 1 (parameterized cross-detector correlation) |
| Robustness test files | 1 (fault tolerance, cancellation, high-volume) |
| Evidence test files | 4 (HMAC, ZIP, formatters, timestamp clamping) |
| WPF test files | 3 (full-stack integration, display encoding, validation rules) |
| Functional test files | 1 (comprehensive multi-profile validation) |
| Test infrastructure files | 1 (`FakeDialogService.cs`) |
| Inline test doubles | 4 (`FakeDetector`, `CrashingDetector`, `WorkingDetector`, `EscalationTestDetector`) |
| Maximum test volume | 5,000 entries (robustness test) |

---

## Why It Matters

- Paired threshold tests verify every statistical detector fires when it should and stays silent when it should not
- Integration tests verify cross-detector correlation — Beaconing + LateralMovement escalates to Critical
- Robustness tests verify a crashing detector does not take down the pipeline
- HMAC-SHA256 evidence integrity tests verify tamper-evident evidence packages
- Full-stack WPF tests verify the complete analyze + export workflow end-to-end

---

## Key Evidence

- [PortScanDetectorTests.cs](../../../VulcansTrace.Tests/Engine/Detectors/PortScanDetectorTests.cs): threshold boundary, multi-source, truncation (285 lines)
- [BeaconingDetectorTests.cs](../../../VulcansTrace.Tests/Engine/Detectors/BeaconingDetectorTests.cs): statistical detection, outlier trim, sample cap (552 lines)
- [SentryAnalyzerIntegrationTests.cs](../../../VulcansTrace.Tests/Engine/SentryAnalyzerIntegrationTests.cs): composite attack, escalation, parameterized timing (206 lines)
- [SentryAnalyzerRobustnessTests.cs](../../../VulcansTrace.Tests/Engine/SentryAnalyzerRobustnessTests.cs): crash tolerance, cancellation, high-volume (109 lines)
- [EvidenceBuilderTests.cs](../../../VulcansTrace.Tests/Evidence/EvidenceBuilderTests.cs): HMAC integrity, ZIP structure, determinism (776 lines)
- [MainViewModelIntegrationTests.cs](../../../VulcansTrace.Tests/Wpf/MainViewModelIntegrationTests.cs): full-stack WPF workflow (502 lines)

---

## Key Design Choices

- **Paired threshold tests** because either below-threshold or above-threshold alone is insufficient — a detector that never fires passes every below-threshold test
- **Fakes over mocks** because testing focuses on orchestration outputs, not interaction sequences — fakes survive refactoring
- **Parameterized integration tests** because C2 beacons don't always arrive at exactly 60 seconds — real-world timing varies
- **Three test categories** because unit catches logic bugs, integration catches orchestration bugs, robustness catches crash bugs
