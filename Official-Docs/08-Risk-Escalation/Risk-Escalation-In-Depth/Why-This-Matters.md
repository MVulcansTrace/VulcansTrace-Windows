# Why This Matters

---

## The Security Problem

Security teams face alert fatigue daily. Individual detectors produce findings at varying severity levels — Beaconing at Medium, Lateral Movement at High, Port Scans at Medium — and each finding in isolation has a plausible benign explanation. An analyst reviewing a Medium-severity Beaconing alert might reasonably deprioritize it as software updates. A High-severity Lateral Movement alert might be admin tooling. Both explanations are wrong when the same host is exhibiting both behaviors simultaneously.

The correlation gap is the real problem: the strongest compromise signal in this pipeline — a single host showing both Beaconing and LateralMovement findings at the same time — is invisible when detectors report independently. No individual detector sees the full picture. The analyst has to connect the dots manually, and under alert fatigue, that connection often does not happen fast enough.

| Scenario | Individual Signal | Confidence |
|---|---|---|
| Beaconing alone | Possible C2-adjacent behavior, but could be updates | Low to Medium |
| Lateral Movement alone | Possible pivoting-adjacent behavior, but could be admin work | Medium |
| Both on the same host | Higher-confidence compromise pattern | High |

---

## Implementation Overview

The **post-detection correlation engine** in VulcansTrace identifies high-confidence compromise patterns by grouping findings by source host and checking for multi-category behaviors:

1. **Groups all findings by source host** using `SourceHost` as the correlation key
2. **Checks each host group** for the Beaconing + LateralMovement combination via a case-insensitive `HashSet`
3. **Escalates all non-Critical findings** on matching hosts to `Severity.Critical` using an immutable `with` expression
4. **Runs after all detectors** but before the `MinSeverityToShow` filter, so promoted findings always survive filtering

**Key metrics:**

- One correlation rule: Beaconing + LateralMovement on the same host
- Time complexity: O(n) — linear GroupBy pass plus per-group HashSet lookup
- Output count: 1:1 with input — no findings added or removed, only severity changed
- Cross-tactic coverage: correlates findings analysts may map to MITRE ATT&CK T1071 with findings they may map to T1021

---

## Operational Benefits

| Capability | Business Value |
|---|---|
| **Cross-detector correlation** | Combines independent detector outputs into higher-confidence compromise signals without manual analysis |
| **Pre-filter escalation** | Promoted findings reach the analyst regardless of profile severity thresholds |
| **Full-context escalation** | All findings on a correlated host are promoted, giving analysts the complete picture |
| **Immutable records** | Original findings are preserved — no mutation, no side effects, safe for concurrent access |
| **Deterministic output** | Same input always produces the same output, supporting reproducible analysis |
| **Zero configuration** | Escalation runs unconditionally for all profiles — no tuning required |

---

## Security Principles Applied

| Principle | Where It Appears |
|---|---|
| **Cross-signal correlation** | Grouping by host and checking for multi-category patterns rather than treating findings independently |
| **Alert fatigue mitigation** | Promoting correlated findings to Critical ensures they rise above the noise floor |
| **Defense in depth** | Detectors find individual threats, correlation adds context, filter reduces noise — three independent layers |
| **Pipeline ordering** | Escalation before filtering prevents the severity filter from hiding findings that should be promoted |
| **Immutable data flow** | `with` expressions create new records rather than mutating originals, preserving audit integrity |
| **Documented limitations** | Documented gaps: single hardcoded rule, no audit trail, batch-only processing, empty-host edge case |

---

## Implementation Evidence

- [RiskEscalator.cs](../../../VulcansTrace.Engine/RiskEscalator.cs): host grouping, category HashSet, boolean correlation check, immutable escalation via `with`
- [SentryAnalyzer.cs](../../../VulcansTrace.Engine/SentryAnalyzer.cs): pipeline wiring — escalation runs before severity filtering
- [Finding.cs](../../../VulcansTrace.Core/Finding.cs): sealed record with `init`-only properties — `Severity`, `Category`, `SourceHost`, and six other fields
- [Severity.cs](../../../VulcansTrace.Core/Severity.cs): ordered enum — `Info < Low < Medium < High < Critical`
- [RiskEscalatorTests.cs](../../../VulcansTrace.Tests/Engine/RiskEscalatorTests.cs): 9 tests covering empty input, Beaconing-only, LateralMovement-only, same-host escalation, mixed hosts, already-Critical, empty SourceHost, case-insensitive matching, and third-category escalation

---

## Elevator Pitch

> *"The correlation engine combines independent detector outputs into higher-confidence compromise signals by grouping findings by source host and checking for the combination of Beaconing and LateralMovement categories.*
>
> *When both are present on the same host, that host becomes a much higher-priority compromise candidate. The escalator is not proving a raw network fact on its own; it is correlating two detector categories that analysts often interpret as C2-adjacent behavior and lateral movement activity. All non-Critical findings for that host are escalated to Critical, not just the two triggering categories, because full context on a compromised host matters for triage.*
>
> *The pipeline ordering is critical: escalation runs after all detectors complete but before the severity filter applies. If filtering ran first, a Medium-severity Beaconing finding on the Low profile would be hidden before the correlation engine ever saw it. By escalating first, promoted findings always survive the filter regardless of the configured threshold.*
>
> *The implementation uses C# `with` expressions on sealed records, so every escalation creates a new Finding rather than mutating the original. There is no audit trail currently — the original severity is lost after escalation — and the correlation rule is hardcoded rather than configurable. Both are documented limitations with clear improvement paths."*

---

## Security Takeaways

1. **Correlation closes the gap between individual detectors and operational reality** — no single detector sees the full attack, but together they tell a story
2. **Host-level grouping is the right correlation key** — the compromised host is the entity under attack, not the destination or the category
3. **Pipeline ordering is a security decision** — filtering before escalation would suppress the very findings that need promotion
4. **Full-context escalation serves analysts** — promoting only the triggering categories would hide related activity on the same host
5. **Documented limitations matter** — the single rule, missing audit trail, and edge cases are documented, not ignored

