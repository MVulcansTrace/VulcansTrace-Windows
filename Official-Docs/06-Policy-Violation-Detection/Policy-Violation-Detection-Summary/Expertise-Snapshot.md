# Expertise Snapshot

> **1 page:** the subsystem, why it matters, and where the proof lives in the codebase.

---

## Implementation Overview

An **egress policy violation detector** for VulcansTrace that flags internal-to-external log entries on configured disallowed ports. It applies a three-condition filter (source internal, destination external, port disallowed) in a single pass through firewall logs, emitting one structured finding per violation with no aggregation.

---

## Key Metrics

| Metric | Value |
|--------|-------|
| Lines of code | 53 (simplest detector in VulcansTrace) |
| Time complexity | O(n) — single linear scan |
| Disallowed ports (default) | 21 (FTP), 23 (Telnet), 445 (SMB) |
| Enabled in profiles | All three (Low, Medium, High) |
| Severity | High (Critical when correlated with Beaconing + LateralMovement) |
| Per-entry cost | O(1) — three short-circuit checks |
| Findings per violation | One — no aggregation |

---

## Why It Matters

- Catches the gap between firewall rules and organizational policy — a firewall ALLOW can still be a policy violation
- Narrow policy-risk signal — internal-to-external on disallowed ports is actionable, while still requiring analyst interpretation
- Full investigative visibility — one finding per entry preserves every destination and connection
- Cross-detector correlation — if a host also has Beaconing + LateralMovement findings, RiskEscalator promotes everything to Critical
- documented limitations — protocol tunneling, allowed-port evasion, and static lists are documented with compensating controls

---

## Key Evidence

- [PolicyViolationDetector.cs](../../../VulcansTrace.Engine/Detectors/PolicyViolationDetector.cs): 53-line detector — gate checks, HashSet initialization, three-condition filter, finding creation
- [AnalysisProfileProvider.cs](../../../VulcansTrace.Engine/Configuration/AnalysisProfileProvider.cs): all three profiles enable policy with ports [21, 23, 445]
- [IpClassification.cs](../../../VulcansTrace.Engine/Net/IpClassification.cs): RFC 1918, IPv4 loopback, and IPv6 internal/external classification
- [RiskEscalator.cs](../../../VulcansTrace.Engine/RiskEscalator.cs): cross-detector correlation (Beaconing + LateralMovement → Critical for all findings on that host)
- [PolicyViolationDetectorTests.cs](../../../VulcansTrace.Tests/Engine/Detectors/PolicyViolationDetectorTests.cs): 9 unit tests — happy path, allowed-port traffic, disabled policy, empty logs, external/internal traffic, multiple violations, empty port list, null config
- [SentryAnalyzerIntegrationTests.cs](../../../VulcansTrace.Tests/Engine/SentryAnalyzerIntegrationTests.cs): end-to-end pipeline validation

---

## Key Design Choices

- **IP classification over log fields** because organizational policy is not the firewall's allow/deny decision — the detector does not require `Action=ALLOW`
- **One finding per entry** because aggregation hides attack scope — 50 disallowed-port log entries to 50 servers means 50 investigation leads
- **HashSet for port lookup** because O(1) matters at scale — 1 million entries checked in constant time per entry
- **High severity hardcoded** because policy violations and risky outbound access warrant prompt analyst attention
- **Null-coalescing on config** because missing configuration should produce zero findings, not crash the detector

