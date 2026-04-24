# Expertise Snapshot

> **1 page:** the subsystem, why it matters, and where the proof lives in the codebase.

---

## Implementation Overview

A **cross-detector correlation engine** for VulcansTrace that identifies high-confidence compromise patterns by grouping findings by source host and checking for multi-category behaviors. When a host exhibits both Beaconing and LateralMovement, all findings for that host are promoted to Critical severity before the pipeline's severity filter can hide them.

---

## Key Metrics

| Metric | Value |
|---|---|
| Correlation method | Host-grouped category matching via HashSet |
| Correlation rule | Beaconing + LateralMovement → Critical |
| Time complexity | O(n) — linear-time grouping via GroupBy + HashSet |
| Space complexity | O(n) — 1:1 output count |
| Output mutability | Immutable — `with` expression creates new records |
| Pipeline position | After all detectors, before MinSeverityToShow filter |
| Cross-tactic coverage | Correlates findings analysts may map to MITRE ATT&CK T1071 + T1021 |

---

## Why It Matters

- Correlates weak signals into high-confidence compromise indicators
- Prevents severity filtering from hiding critical multi-tactic attacks
- Escalates full incident context, not just triggering categories
- Immutable escalation eliminates mutation bugs in threat classification

---

## Key Evidence

- [RiskEscalator.cs](../../../VulcansTrace.Engine/RiskEscalator.cs): host grouping, category HashSet, boolean correlation check, immutable escalation via `with`
- [SentryAnalyzer.cs](../../../VulcansTrace.Engine/SentryAnalyzer.cs): pipeline integration — escalation runs before severity filtering
- [Finding.cs](../../../VulcansTrace.Core/Finding.cs): sealed record with init-only properties enabling immutable escalation
- [RiskEscalatorTests.cs](../../../VulcansTrace.Tests/Engine/RiskEscalatorTests.cs): 9 tests — empty input, Beaconing-only, LateralMovement-only, same-host escalation, mixed hosts, already-Critical, empty SourceHost, case-insensitive, third-category escalation

---

## Key Design Choices

- **Host-level grouping over global correlation** because the compromised host is the entity exhibiting the attack behavior — grouping by destination or globally would produce false positives
- **Full-context escalation over category-only escalation** because related findings on a compromised host (PolicyViolation, Novelty) may be part of the broader incident
- **Escalation before filtering** because the severity filter would hide Medium Beaconing findings on restrictive profiles before the correlation engine could promote them
- **Immutable `with` expression** because direct mutation is a compile error — safety is structural, not conventional
