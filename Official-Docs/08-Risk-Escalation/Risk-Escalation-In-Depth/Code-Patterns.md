# Code Patterns

The main implementation patterns used in the correlation engine.

---

## Pattern 1: Stateless Sealed Class

```csharp
public sealed class RiskEscalator
{
    public IReadOnlyList<Finding> Escalate(IReadOnlyList<Finding> findings)
    {
        // ...
    }
}
```

A `sealed` class with no fields ensures the correlation logic is deterministic — same input always produces the same output — and safe to reuse across calls. No instance state means no configuration drift between calls and no shared mutable data inside the escalator itself.

---

## Pattern 2: GroupBy → HashSet → Boolean Check

```csharp
var byHost = findings.GroupBy(f => f.SourceHost ?? string.Empty);
foreach (var group in byHost)
{
    var categories = group.Select(f => f.Category)
        .ToHashSet(StringComparer.OrdinalIgnoreCase);
    var hasBeacon = categories.Contains("Beaconing");
    var hasLateral = categories.Contains("LateralMovement");
    var shouldEscalate = hasBeacon && hasLateral;
    // ...
}
```

This is the core correlation pattern: group by entity, extract a property set, check for a combination. The HashSet uses `StringComparer.OrdinalIgnoreCase`, making category matching case-insensitive — `"Beaconing"` and `"beaconing"` are treated equivalently, reducing false negatives from inconsistent casing in detector output. The HashSet gives O(1) lookups for each category check. Adding a new correlation rule would mean adding another `categories.Contains()` call and combining it into the `shouldEscalate` boolean.

**Test Evidence:** `Escalate_WithDifferentCategoryCasing_EscalatesCorrectly` verifies that lowercase `"beaconing"` and uppercase `"LATERALMOVEMENT"` still trigger escalation.

---

## Pattern 3: Copy-on-Write via `with` Expression

```csharp
if (shouldEscalate && f.Severity < Severity.Critical)
    result.Add(f with { Severity = Severity.Critical });
else
    result.Add(f);
```

The `with` expression creates a new `Finding` record with `Severity` changed and all other properties preserved. This is the C# record syntax for immutable copy-on-write. The original `Finding` instance is never mutated — it is either reused as-is (`else` branch) or replaced by a new copy (`if` branch).

The `Severity` property is `init`-only on the `Finding` record, so direct assignment (`f.Severity = ...`) would not compile. Immutability is enforced by the type system.

---

## Pattern 4: Pre-Allocated Result List

```csharp
var result = new List<Finding>(findings.Count);
```

Pre-allocating the result list avoids resizing during the single-pass iteration because the output count is always 1:1 with the input — no findings are added or removed, only severity is changed.

---

## Pattern 5: Guard Clause for Empty Input

```csharp
if (findings.Count == 0)
    return Array.Empty<Finding>();
```

Returns a static empty array rather than allocating a new `List<Finding>` for the trivial case. This keeps the method predictable and allocation-free for empty input.

---

## Pattern 6: Pipeline Integration Point

```csharp
// SentryAnalyzer.cs
var escalated = _riskEscalator.Escalate(allFindings);
result.AddFindings(escalated.Where(f => f.Severity >= profile.MinSeverityToShow));
```

The escalator is injected into `SentryAnalyzer` via constructor and called at a specific point in the pipeline — after all detectors run, before the severity filter applies. This is not a pattern inside the escalator itself, but it is the most important integration constraint: the pipeline order determines whether escalation is effective.

---

## Implementation Evidence

- [RiskEscalator.cs](../../../VulcansTrace.Engine/RiskEscalator.cs): patterns 1-5 are the entire implementation
- [SentryAnalyzer.cs](../../../VulcansTrace.Engine/SentryAnalyzer.cs): pattern 6 — pipeline wiring
- [Finding.cs](../../../VulcansTrace.Core/Finding.cs): the record type that supports pattern 3 — sealed record with init-only properties
