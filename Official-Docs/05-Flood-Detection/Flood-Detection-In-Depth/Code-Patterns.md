# Code Patterns

---

## Pattern 1: Strategy Pattern — IDetector

```csharp
public sealed class FloodDetector : IDetector
{
    public IEnumerable<Finding> Detect(
        IReadOnlyList<LogEntry> entries,
        AnalysisProfile profile,
        CancellationToken cancellationToken)
}
```

**Why:** Detectors are interchangeable behind the `IDetector` interface. `SentryAnalyzer` runs all detectors uniformly, so the pipeline is modular and extensible. New detection rules can be added without modifying the orchestration path.

**Security Angle:** Modularity helps isolate detector responsibilities and makes behavior easier to test, review, and evolve safely.

---

## Pattern 2: Early-Exit Gate

```csharp
if (!profile.EnableFlood || entries.Count == 0)
    return Enumerable.Empty<Finding>();
```

**Why:** Disabled detectors or empty datasets should never enter the expensive grouping and sorting path. The compound gate prevents wasted computation when the detector cannot produce findings.

**Effect:** Returns immediately, allocates nothing, skips all downstream work.

---

## Pattern 3: Per-Source Grouping with Chronological Sort

```csharp
var bySrc = entries.GroupBy(e => e.SrcIp);
foreach (var srcGroup in bySrc)
{
    cancellationToken.ThrowIfCancellationRequested();
    var ordered = srcGroup.OrderBy(e => e.Timestamp).ToList();
    if (ordered.Count == 0) continue;
    // ...
}
```

**Why:** Flood detection measures one IP's volumetric behavior in isolation. Grouping by source prevents one high-volume source from affecting the analysis of every other source.

---

## Pattern 4: Two-Pointer Sliding Window

```csharp
int start = 0;
for (int end = 0; end < ordered.Count; end++)
{
    while (start < end &&
           (ordered[end].Timestamp - ordered[start].Timestamp).TotalSeconds > windowSeconds)
    {
        start++;
    }
    int windowCount = end - start + 1;
    if (windowCount >= profile.FloodMinEvents)
    {
        // Create finding and break
    }
}
```

**Why:** Both boundaries advance monotonically through the sorted data — each event enters the window once and leaves once. The two-pointer approach achieves O(n) per-source scanning with an amortized-O(1) inner loop that only advances, never resets.

---

## Pattern 5: Structured Finding Output

```csharp
new Finding
{
    Category = "Flood",
    Severity = Severity.High,
    SourceHost = srcIp,
    Target = "multiple hosts/ports",
    TimeRangeStart = minTime,
    TimeRangeEnd = maxTime,
    ShortDescription = $"Flood detected from {srcIp}",
    Details = $"Detected {windowCount} events within {windowSeconds} seconds."
};
```

**Why:** Every field serves an analyst workflow. The finding structure was designed to make triage faster — Category for filtering, Severity for prioritization, SourceHost for blocking, TimeRange for correlation, Details for investigation scope.

---

## Pattern 6: Cooperative Cancellation

```csharp
cancellationToken.ThrowIfCancellationRequested();
```

**Why:** Log analysis can be long-running on large datasets. Cancellation was added between source groups to keep the WPF app responsive when users load large log files or switch analysis profiles.

---

## Comparison With Other Detectors

| Pattern | PortScan | Beaconing | LateralMovement | Flood |
|--------|----------|-----------|-----------------|-------|
| Window type | Bucketed | Statistical | Sliding | Sliding |
| Analysis unit | Per source | Per (src, dst, port) | Per source | Per source |
| Per-source limit | Max entries per source | Sample cap | One finding then break | One finding then break |
| Complexity | O(n log n) | O(n log n) | O(n × m) worst case* | O(n log n) |

*\*LateralMovement's inner loop calls `Distinct()` to count unique hosts per window, yielding O(m²) per source and O(n × m) overall. Flood and LateralMovement share the same two-pointer skeleton, but Flood's simple window-count check avoids this cost.*

---

## Security Takeaways

1. **Strategy pattern = modular security** — detectors are independently testable and replaceable
2. **Early exits reduce wasted work** — disabled or empty inputs never reach grouping, sorting, or window scanning
3. **Structured findings = analyst efficiency** — every field maps to a triage action
4. **Two-pointer window = efficient detection** — O(n) amortized per-source scanning; the inner loop only advances, never resets
