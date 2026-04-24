# Expertise Snapshot

> **1 page:** the subsystem, why it matters, and where the proof lives in the codebase.

---

## Implementation Overview

A **novelty detection engine** for VulcansTrace that identifies singleton external connections from firewall logs. It filters for external destinations, groups by (DstIp, DstPort) tuple, counts occurrences, and emits structured Low-severity findings for tuples that appear exactly once in the dataset.

---

## Key Metrics

| Metric | Value |
|--------|-------|
| Detection method | Tuple counting — GroupBy (DstIp, DstPort), flag count == 1 |
| Implementation size | 57 lines — the second-smallest detector in VulcansTrace (PolicyViolationDetector is 53) |
| Time complexity | O(n) — no sorting, no sliding windows, no sampling |
| Space complexity | O(n) worst case — O(e) external entries + O(u) unique tuples + O(f) findings |
| Severity | Low (Critical when correlated with Beaconing + LateralMovement) |
| Profile gating | Disabled at Low, filtered at Medium (unless escalated to Critical), visible at High |
| Cross-detector correlation | Beaconing + LateralMovement on same host → all findings escalate to Critical |

---

## Why It Matters

- Fills a blind spot — pattern-based detectors (port scan, beaconing) miss one-time connections
- External-only filtering removes internal noise (DHCP, printing, DNS)
- Tuple grouping preserves service-level detail — same IP, different ports are different signals
- Low severity communicates deliberate uncertainty — signal, not verdict
- Profile-gating respects analyst capacity — novelty findings only reach the analyst at High intensity (or via escalation to Critical)

---

## Key Evidence

- [NoveltyDetector.cs](../../../VulcansTrace.Engine/Detectors/NoveltyDetector.cs): guard clauses, external filtering, tuple counting, singleton finding creation
- [AnalysisProfileProvider.cs](../../../VulcansTrace.Engine/Configuration/AnalysisProfileProvider.cs): built-in Low, Medium, and High presets that gate novelty by intensity
- [RiskEscalator.cs](../../../VulcansTrace.Engine/RiskEscalator.cs): cross-detector correlation (Beaconing + LateralMovement → Critical)
- [NoveltyDetectorTests.cs](../../../VulcansTrace.Tests/Engine/Detectors/NoveltyDetectorTests.cs): 8 tests — singleton, repeated, disabled, empty, internal-only, mixed, same-IP-diff-ports, diff-IP-same-port
- [SentryAnalyzerIntegrationTests.cs](../../../VulcansTrace.Tests/Engine/SentryAnalyzerIntegrationTests.cs): end-to-end intensity visibility tests
- [RiskEscalatorTests.cs](../../../VulcansTrace.Tests/Engine/RiskEscalatorTests.cs): escalation scenarios including Novelty promoted to Critical

---

## Key Design Choices

- **External-only filter** because internal singletons are routine noise (DHCP, printing, DNS) — keeps the signal clean
- **Tuple grouping (DstIp, DstPort)** because same server on different ports is a different service — preserves service-level granularity
- **Count == 1 exactly** because it has precise semantics and reduces false positives from legitimate retries
- **Severity = Low** because most singletons are benign — communicates deliberate uncertainty
- **Profile-gating** because novelty's high false-positive rate would flood analysts in conservative environments

