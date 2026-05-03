# Code Patterns

---

## Pattern 1: Strategy Pattern — IDetector

```csharp
public sealed class NoveltyDetector : IDetector
{
    public IEnumerable<Finding> Detect(
        IReadOnlyList<LogEntry> entries,
        AnalysisProfile profile,
        CancellationToken cancellationToken)
}
```

**Why:** Detectors are interchangeable behind the `IDetector` interface. `SentryAnalyzer` runs all detectors uniformly — the pipeline is modular and extensible. New detection rules can be added without modifying existing code.

**Security Angle:** Modularity is a security property. New detectors don't risk breaking existing ones.

---

## Pattern 2: Fail-Fast Guard Clauses

```csharp
if (!profile.EnableNovelty || entries.Count == 0)
    return Enumerable.Empty<Finding>();

var externalEntries = entries.Where(e => IpClassification.IsExternal(e.DstIp) && e.DstPort.HasValue).ToList();
if (externalEntries.Count == 0)
    return Enumerable.Empty<Finding>();
```

**Why:** There is no point running the counting logic when the detector is disabled, the dataset is empty, or there are no external destinations. Two early-return statements covering three gate conditions avoid unnecessary computation in high-volume log processing.

**Effect:** The most expensive operations (GroupBy, ToDictionary, emission loop) only run when all three gates pass.

---

## Pattern 3: LINQ GroupBy + ToDictionary for Counting

```csharp
var counts = externalEntries
    .GroupBy(e => (e.DstIp, e.DstPort!.Value))
    .ToDictionary(g => g.Key, g => g.Count());
```

**Why:** `GroupBy` with a value-tuple key is used because (DstIp, DstPort) is the correct granularity — same IP, different ports are different services — and `ToDictionary` gives O(1) lookup during the emission pass. This builds an occurrence map efficiently in a single pass.

**Key detail:** The dictionary key is a `ValueTuple<string, int>`, which uses structural equality. This means `("203.0.113.42", 443)` and `("203.0.113.42", 22)` are different keys, preserving service-level granularity.

---

## Pattern 4: Structured Finding Output

```csharp
new Finding
{
    Category = "Novelty",
    Severity = Severity.Low,
    SourceHost = e.SrcIp,
    Target = $"{e.DstIp}:{e.DstPort}",
    TimeRangeStart = e.Timestamp,
    TimeRangeEnd = e.Timestamp,
    ShortDescription = "Novel external destination",
    Details = $"Single observed connection to {e.DstIp}:{e.DstPort}."
}
```

**Why:** Most fields serve an analyst workflow. The finding structure was designed to make triage faster — Category for filtering, Severity for prioritization, SourceHost for attribution, Target for enrichment, TimeRange for correlation, Details for investigation scope. The remaining fields (`Id` for deduplication, `ShortDescription` for display) support the presentation layer.

**Notable characteristic:** `TimeRangeStart == TimeRangeEnd` because a singleton is a single event, not a duration. Unlike Port Scan or Beaconing findings that span a time range, Novelty findings represent a point in time.

**Escalation caveat:** The `RiskEscalator` can escalate Novelty findings from Low to Critical if the same source host also triggers both Beaconing and LateralMovement findings. Severity is Low by default, but not guaranteed.

---

## Pattern 5: Cooperative Cancellation

```csharp
cancellationToken.ThrowIfCancellationRequested();
```

**Why:** Log datasets can be large and every detector participates in the same cooperative cancellation model. Cancellation was added inside the emission loop to stop work promptly when the caller cancels analysis.

---

## Pattern 6: Profile-Driven Gating

```csharp
if (!profile.EnableNovelty || entries.Count == 0)
    return Enumerable.Empty<Finding>();
```

**Why:** Novelty's high false-positive rate makes it inappropriate for conservative analysis environments. The detector is gated behind the `EnableNovelty` flag to let the analyst's chosen intensity level control whether this detector runs at all.

**Visibility note:** At Low intensity, the detector is disabled entirely (`EnableNovelty = false`). At Medium intensity, the detector runs but `MinSeverityToShow = Medium` silently filters out all Low-severity Novelty findings before they reach the UI. Novelty findings are only user-visible at High intensity, where `MinSeverityToShow = Info`.

---

## Comparison With Other Detectors

| Pattern | PortScan | Beaconing | LateralMovement | Novelty |
|--------|----------|-----------|-----------------|---------|
| Window type | Sliding | Statistical | Sliding | None (full dataset) |
| Grouping key | Source IP | Source-dest-port triple | Source IP | Dest (IP, port) |
| Time complexity | O(n log n) | O(n log n) | O(n × m) typical; O(n²) worst | O(n) |
| Per-source limit | Max entries per source | Sample cap | One finding then break | None |
| Severity | Medium | Medium | High | Low |

---

## Security Takeaways

1. **Strategy pattern = modular security** — detectors are independently testable and replaceable
2. **Fail-fast guards = resource protection** — disabled detectors consume zero CPU
3. **Tuple grouping = service-level precision** — same IP, different ports are different signals
4. **Structured findings = analyst efficiency** — most fields map to a triage action
