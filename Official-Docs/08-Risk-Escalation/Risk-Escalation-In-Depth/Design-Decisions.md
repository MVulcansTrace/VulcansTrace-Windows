# Design Decisions

Every major choice in the correlation engine has a security rationale, a performance implication, and an operational impact.

---

## Decision 1: Group by SourceHost (Not TargetHost or Global)

**Decision:** Group findings by `f.SourceHost ?? string.Empty` as the correlation key.

**Rationale:** Grouping by source host aligns with the compromised-host threat model — the entity exhibiting the attack behavior is the host itself, not the destination or global activity.

| Grouping Strategy | Correlation Question | Risk |
|---|---|---|
| SourceHost | What behaviors did this machine exhibit? | Correct — matches the threat model |
| TargetHost | What happened to this destination? | Wrong — multiple sources targeting one target is not the same attack |
| Global | What happened across the network? | Wrong — unrelated hosts with different categories would false-positive |

**Trade-off:** Misses cross-host correlation patterns (e.g., Host A beaconing to the same C2 that Host B is spreading from). That is a different detection problem requiring network-level analysis.

---

## Decision 2: Escalate All Findings for the Host (Not Just Triggering Categories)

**Decision:** When the correlation rule matches, escalate every non-Critical finding in the host group, including categories that did not trigger the rule.

**Rationale:** Escalating the full host group provides analysts with complete incident context — a `PolicyViolation` or `Novelty` finding on a matched host may be part of the broader attack narrative.

```text
Host 192.168.1.100 (matched host):
  - Beaconing (Medium)       → Critical (triggering category)
  - LateralMovement (High)   → Critical (triggering category)
  - PolicyViolation (High)   → Critical (escalated — full context)
  - Novelty (Low)            → Critical (escalated — singleton external destination may add context)
```

**Trade-off:** May escalate unrelated findings on hosts that happen to share a SourceHost with a true compromise. In practice, this is acceptable because the host-level correlation already indicates high confidence.

---

## Decision 3: Case-Insensitive Category Matching

**Decision:** `ToHashSet(StringComparer.OrdinalIgnoreCase)` for category comparison.

**Rationale:** Case-insensitive matching prevents false negatives from inconsistent casing across detector implementations.

All six detectors currently produce consistent PascalCase categories (`"Beaconing"`, `"LateralMovement"`), so this is defensive programming rather than a response to an observed problem. If a new detector or a refactored one produced `"beaconing"` or `"BEACONING"`, the correlation would continue working.

**Trade-off:** Negligible performance cost. HashSet with a comparer is still O(1) per lookup.

---

## Decision 4: Immutable Escalation via `with` Expression

**Decision:** `f with { Severity = Severity.Critical }` instead of direct mutation.

**Rationale:** The `Finding` record has `init`-only properties, making direct assignment a compile error — immutability is enforced structurally rather than by convention.

```csharp
// Does not compile — Severity is init-only
f.Severity = Severity.Critical;

// Compiles — creates a new record with one property changed
result.Add(f with { Severity = Severity.Critical });
```

**Trade-off:** Creates a new record for every escalated finding. The original finding is preserved in memory (within the group) but is not added to the result list when escalated. This is a minor allocation cost that prevents mutation bugs and supports evidence integrity.

---

## Decision 5: Only Escalate Below Critical

**Decision:** `f.Severity < Severity.Critical` as the escalation guard.

**Rationale:** Re-wrapping an already-Critical finding creates an unnecessary copy with no functional change — this guard preserves the original reference for findings that need no change.

**Trade-off:** None meaningful. This is a pure optimization that preserves reference identity for findings that need no change.

---

## Decision 6: Empty String for Null SourceHost

**Decision:** `f.SourceHost ?? string.Empty` in the GroupBy lambda.

**Rationale:** Normalizing null to empty string prevents pipeline crashes and ensures every finding participates in correlation — lost alerts are worse than potential false correlations.

**Trade-off:** Findings with null or empty SourceHost values are grouped together. If one has Beaconing and another has LateralMovement, they escalate even though they may not be from the same host. This is a known edge case documented in the test suite (`Escalate_WithEmptySourceHost_DoesNotCrash`).

---

## Summary

| Decision | Security Principle | Operational Impact |
|---|---|---|
| Group by SourceHost | Entity-level correlation | Matches the compromised-host threat model |
| Escalate all findings | Full-context triage | Analysts see the complete picture, not a subset |
| Case-insensitive matching | Defense in depth | Detector output variations do not break correlation |
| Immutable `with` expression | Evidence integrity | Original findings are never mutated |
| Only escalate below Critical | Idempotency | No unnecessary copies, references preserved |
| Empty string for null SourceHost | Graceful degradation | No lost alerts, documented edge case |

---

## Implementation Evidence

- [RiskEscalator.cs](../../../VulcansTrace.Engine/RiskEscalator.cs): all six decisions are visible in the implementation
- [RiskEscalatorTests.cs](../../../VulcansTrace.Tests/Engine/RiskEscalatorTests.cs): tests cover each decision — mixed hosts, case-insensitive matching, already-Critical handling, empty SourceHost
