# Correlation Algorithm

---

## The Security Problem

After all detectors run, the pipeline holds a flat list of findings. Each finding has a `SourceHost`, a `Category`, and a `Severity`. The Beaconing detector may have produced a Medium-severity finding for host 192.168.1.100. The LateralMovement detector may have produced a High-severity finding for the same host. Neither finding alone is Critical, and on a restrictive analysis profile, the Beaconing finding might be filtered out entirely. The correlation algorithm exists to detect this multi-behavior pattern and promote it before filtering can hide it.

---

## Implementation Overview

A deterministic, O(n) correlation pipeline processes findings in four steps: guard, group, check, escalate.

### Stage 1: Guard Clause

```csharp
if (findings.Count == 0)
    return Array.Empty<Finding>();
```

An early exit prevents unnecessary work when input is empty — no grouping, no allocation, no iteration. This keeps the method predictable for edge cases.

### Stage 2: Group by Source Host

```csharp
var byHost = findings.GroupBy(f => f.SourceHost ?? string.Empty);
```

Grouping by `SourceHost` aligns with the compromised-host threat model — the question is "what behaviors did this machine exhibit?", not "what happened to this destination?" or "what happened globally?"

The `?? string.Empty` normalizes null values to empty string. `SourceHost` is typed as non-nullable `string` with NRTs enabled, so this is defense-in-depth — if a future change or reflection-based construction produced a null, the code handles it gracefully rather than throwing.

| SourceHost Value | Group Key | Behavior |
|---|---|---|
| `"192.168.1.100"` | `"192.168.1.100"` | Normal case |
| `null` | `""` | Normalized, grouped with other nulls |
| `""` | `""` | Grouped with nulls |

**Edge case:** Findings with empty SourceHost values are grouped together. If one has Beaconing and another has LateralMovement, they will escalate even though they may not be from the same host. This is a documented trade-off of choosing graceful handling over dropping or crashing on malformed findings.

### Stage 3: Category Combination Check

```csharp
var categories = group.Select(f => f.Category).ToHashSet(StringComparer.OrdinalIgnoreCase);

var hasBeacon = categories.Contains("Beaconing");
var hasLateral = categories.Contains("LateralMovement");
var shouldEscalate = hasBeacon && hasLateral;
```

A `HashSet` provides O(1) category lookup and `OrdinalIgnoreCase` prevents false negatives from casing differences in detector output. All six detectors currently use consistent PascalCase, so this is belt-and-suspenders — but if a new detector or a refactored one produced `"beaconing"` instead of `"Beaconing"`, the correlation would still work.

| Beaconing | LateralMovement | Result |
|---|---|---|
| No | No | No escalation |
| Yes | No | No escalation |
| No | Yes | No escalation |
| **Yes** | **Yes** | **Escalate all non-Critical to Critical** |

## Stage 4: Escalate with Immutability

```csharp
foreach (var f in group)
{
    if (shouldEscalate && f.Severity < Severity.Critical)
        result.Add(f with { Severity = Severity.Critical });
    else
        result.Add(f);
}
```

Escalating all non-Critical findings for matching hosts provides full context for triage. A `PolicyViolation` or `Novelty` finding on the same compromised host may be part of the broader incident. The `f.Severity < Severity.Critical` guard prevents re-wrapping already-Critical findings — the original reference is preserved instead.

The `with` expression creates a new `Finding` record, leaving the original unchanged. This is enforced by the language: `Severity` is `init`-only, so direct assignment (`f.Severity = Severity.Critical`) would not compile. Immutability is a structural guarantee, not a convention.

---

## Pipeline Context

The algorithm runs inside `SentryAnalyzer.Analyze()` at a specific point in the pipeline:

```text
1. Parse raw log         → LogEntry objects
2. Load profile          → AnalysisProfile for Low/Medium/High
3. Run all detectors     → flat list of Findings
4. RiskEscalator.Escalate()  ← THIS ALGORITHM
5. MinSeverityToShow filter  → removes findings below threshold
6. Output                → AnalysisResult
```

Escalation runs before filtering to ensure promoted findings always reach the analyst. If the filter ran first, Medium-severity Beaconing findings on the Low profile (where `MinSeverityToShow = High`) would be discarded before the correlation engine could see them. The ordering ensures that findings worth promoting are always visible to the escalator.

```csharp
var escalated = _riskEscalator.Escalate(allFindings);
result.AddFindings(escalated.Where(f => f.Severity >= profile.MinSeverityToShow));
```

### Visibility Impact

| Scenario | Original | After Escalation | Filter Result (Medium profile) |
|---|---|---|---|
| Correlated host, Novelty finding | Low | Critical | Visible |
| Correlated host, Beaconing finding | Medium | Critical | Visible |
| Uncorrelated host, Novelty finding | Low | Low | Filtered out |
| Uncorrelated host, Beaconing finding | Medium | Medium | Visible |

---

## Complexity

| Metric | Value | Reason |
|---|---|---|
| Time | O(n) | Two linear sweeps: GroupBy + one iteration per finding |
| Space | O(n) | Output list holds one entry per input finding |
| Per-group lookup | O(1) | HashSet for category membership |
| Record creation | O(1) per escalation | `with` copies all fields, modifies one |

---

## Design Rationale

The stateless, linear-time design ensures deterministic output and fast processing. The same input always produces the same output — no internal state, no randomness, no ordering dependency. The `sealed` class keyword prevents subclassing, and the lack of fields means the instance is inherently thread-safe. There is nothing to configure, nothing to tune, and nothing that can drift between calls.

The trade-off is extensibility. Adding a second correlation rule (e.g., PortScan + Flood) currently requires modifying the source code. A rule-engine approach with external configuration would be more flexible but adds complexity that is not justified for a single rule.

---

## Implementation Evidence

- [RiskEscalator.cs](../../../../VulcansTrace.Engine/RiskEscalator.cs): full implementation — guard clause, GroupBy, HashSet, boolean check, escalation loop
- [SentryAnalyzer.cs](../../../../VulcansTrace.Engine/SentryAnalyzer.cs): pipeline wiring
- [RiskEscalatorTests.cs](../../../../VulcansTrace.Tests/Engine/RiskEscalatorTests.cs): 9 tests covering all algorithm stages

---

## Security Takeaways

1. **Host-level grouping matches the threat model** — the compromised host is the entity under investigation
2. **Case-insensitive matching prevents false negatives** — detector output should not break correlation due to casing
3. **Full-context escalation gives analysts the complete picture** — related findings on the same host surface together
4. **Pipeline ordering is a correctness property** — filtering before escalation would suppress correlatable findings
5. **Immutability preserves evidence integrity** — the original finding is never mutated, only copied with a new severity
