# Code Patterns

---

## Pattern 1: Strategy Pattern — IDetector

```csharp
public sealed class LateralMovementDetector : IDetector
{
    public IEnumerable<Finding> Detect(
        IReadOnlyList<LogEntry> entries,
        AnalysisProfile profile,
        CancellationToken cancellationToken)
}
```

**Why:** Detectors are interchangeable behind the `IDetector` interface. `SentryAnalyzer` runs all detectors uniformly, so the pipeline stays modular and extensible. New detection rules can be added without changing the orchestration path.

**Security Angle:** Modularity helps isolate detector responsibilities and makes behavior easier to test, review, and evolve safely.

---

## Pattern 2: Upfront Filtering with HashSet Lookups

```csharp
var adminPorts = profile.AdminPorts ?? Array.Empty<int>();
var adminSet = new HashSet<int>(adminPorts);

var filtered = entries.Where(e =>
    IpClassification.IsInternal(e.SrcIp) &&
    IpClassification.IsInternal(e.DstIp) &&
    e.DstPort.HasValue &&
    adminSet.Contains(e.DstPort.Value));
```

**Why:** `HashSet<int>` provides O(1) port lookup, keeping filtering cheap even when entry counts are large.

**Effect:** Removes traffic categories that can never match this detector before grouping, sorting, or window analysis begins.

---

## Pattern 3: Two-Pointer Sliding Window

```csharp
int start = 0;
for (int end = 0; end < ordered.Count; end++)
{
    while (start < end &&
           (ordered[end].Timestamp - ordered[start].Timestamp)
               .TotalMinutes > windowMinutes)
    {
        start++;
    }

    var hosts = ordered
        .Skip(start).Take(end - start + 1)
        .Select(e => e.DstIp).Distinct().ToList();

    if (hosts.Count >= profile.LateralMinHosts)
    {
        findings.Add(new Finding { /* ... */ });
        break;
    }
}
```

**Why:** Both boundaries advance monotonically through the sorted data. The two-pointer approach was chosen to avoid the reset-and-rescan overhead that a naive implementation would require.

**Trade-off:** `Distinct()` rebuilds per iteration, making it O(m²) worst case per source. A frequency dictionary would bring this to O(m), but the current implementation is simple and correct.

---

## Pattern 4: Structured Finding Output

```csharp
var minTime = ordered[start].Timestamp;
var maxTime = ordered[end].Timestamp;

new Finding
{
    Category = "LateralMovement",
    Severity = Severity.High,
    SourceHost = srcGroup.Key,
    Target = "multiple internal hosts",
    TimeRangeStart = minTime,
    TimeRangeEnd = maxTime,
    ShortDescription = $"Lateral movement from {srcGroup.Key}",
    Details = $"Contacted {hosts.Count} internal hosts on admin ports."
};
```

**Why:** Every field serves an analyst workflow. The finding structure was designed to make triage faster — Category for filtering, Severity for prioritization, SourceHost for blocking, TimeRange for correlation, Details for investigation scope.

> **Pipeline note:** The detector emits `Severity.High`, but downstream stages (`RiskEscalator` and `MinSeverityToShow` filtering in `SentryAnalyzer`) may modify or hide findings before the user sees them.

---

## Pattern 5: Early Exit Gates

```csharp
if (!profile.EnableLateralMovement || entries.Count == 0)
    return Enumerable.Empty<Finding>();
```

**Why:** Each gate prevents unnecessary computation. The detector returns immediately when disabled or when the dataset is empty.

---

## Pattern 6: Cooperative Cancellation

```csharp
cancellationToken.ThrowIfCancellationRequested();
```

**Why:** Log analysis can be long-running. Cancellation was added between source groups to keep the WPF UI responsive when users load large log files.

---

## Comparison With Other Detectors

| Pattern | PortScan | Beaconing | LateralMovement |
|--------|----------|-----------|-----------------|
| Window type | Bucketed | Statistical | Sliding |
| Resource limit | Truncation + warning | Sample cap | Filtering only |
| Per-source limit | Max entries per source | N most recent | One finding then break |
| Complexity | O(Σ m log m) | O(Σ m log m) | O(Σ mᵢ²) ≤ O(n × m) |

---

## Security Takeaways

1. **Strategy pattern = modular security** — detectors are independently testable and replaceable
2. **Upfront filtering reduces wasted work** — irrelevant data never reaches the more expensive per-source analysis
3. **Structured findings = analyst efficiency** — every field maps to a triage action
4. **Early exits = unnecessary-work prevention** — disabled detectors and empty datasets skip all computation immediately
