# Code Patterns

---

## Pattern 1: Strategy Pattern — IDetector

```csharp
public sealed class PolicyViolationDetector : IDetector
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

## Pattern 2: Early-Exit Gates

```csharp
if (!profile.EnablePolicy || entries.Count == 0)
    return Enumerable.Empty<Finding>();
```

**Why:** There is no work to do when the detector is disabled or the dataset is empty. A compound early-exit gate returns immediately with zero allocation in the common disabled-or-empty case.

**Effect:** No iteration or finding creation when the gate triggers; it also skips the local HashSet/List setup for the disabled-or-empty case.

---

## Pattern 3: HashSet Lookups for Port Filtering

```csharp
var disallowed = new HashSet<int>(profile.DisallowedOutboundPorts ?? Array.Empty<int>());

// Later, inside the loop:
if (!e.DstPort.HasValue || !disallowed.Contains(e.DstPort.Value))  // O(1) average
    continue;
```

**Why:** `HashSet<int>` is used because the port check scales efficiently regardless of the number of tested ports when evaluating traffic that survives the IP filtering gates. This keeps per-entry cost constant.

**Effect:** If a payload violates policy against 100 banned ports, the engine executes exactly 1 hash lookup instead of up to 100 array comparisons.

---

## Pattern 4: Short-Circuit Three-Condition Filter

```csharp
if (!IpClassification.IsInternal(e.SrcIp))    // Condition 1
    continue;

if (!IpClassification.IsExternal(e.DstIp))    // Condition 2
    continue;

if (!e.DstPort.HasValue || !disallowed.Contains(e.DstPort.Value))  // Condition 3
    continue;
```

**Why:** Conditions are ordered by logical exclusivity, filtering out irrelevant IP flow directions before reaching the port criteria. This reduces total computational volume (i.e., avoiding the port check entirely on irrelevant IPs) by rejecting the vast majority of entries early.

| Scenario | Checks Executed |
|----------|-----------------|
| External source | 1 (early exit) |
| Internal source, internal dest | 2 (early exit) |
| All conditions true | 3 (full check) |

---

## Pattern 5: Structured Finding Output

```csharp
new Finding
{
    Category = "PolicyViolation",
    Severity = Severity.High,
    SourceHost = e.SrcIp,
    Target = $"{e.DstIp}:{e.DstPort}",
    TimeRangeStart = e.Timestamp,
    TimeRangeEnd = e.Timestamp,
    ShortDescription = $"Disallowed outbound port from {e.SrcIp}",
    Details = $"Outbound connection to {e.DstIp}:{e.DstPort} on a disallowed port."
};
```

**Why:** Every field serves an analyst workflow. The finding structure was designed to make triage faster — Category for filtering, Severity for prioritization, SourceHost for investigation pivoting, Target for IOC matching, TimeRange for correlation, Details for response context.

---

## Pattern 6: Null-Coalescing Defensive Initialization

```csharp
var disallowed = new HashSet<int>(
    profile.DisallowedOutboundPorts ?? Array.Empty<int>());
```

**Why:** Missing configuration should produce zero findings, not crash the detector. The null-coalescing pattern fails safe regardless of how the profile was constructed.

| Configuration | Result |
|---------------|--------|
| Ports configured: [21, 23, 445] | HashSet with 3 elements |
| Empty list: [] | Empty HashSet — no violations |
| Null | Empty HashSet — no violations |

---

## Pattern 7: Cooperative Cancellation

```csharp
cancellationToken.ThrowIfCancellationRequested();
```

**Why:** Log analysis can be long-running. Cancellation was added inside the loop to keep the application responsive when users load large log files.

---

## Comparison With Other Detectors

| Pattern | PortScan | Beaconing | LateralMovement | PolicyViolation |
|--------|----------|-----------|-----------------|-----------------|
| Window type | Bucketed | Statistical | Sliding | None (linear scan) |
| Grouping | By source | By tuple | By source | None |
| Per-source limit | Max entries | Sample cap | One finding then break | None (all violations) |
| Complexity | O(n log n)ᵃ | O(n log n)ᵇ | O(n × m)ᶜ | **O(n)** |
| Aggregation | Yes | Yes | Yes | **No** |

> **ᵃ** PortScan: `OrderBy` per source group dominates at O(m log m) per group.
> **ᵇ** Beaconing: `OrderBy` to sort entries by timestamp, then `Sort` on intervals — both O(m log m) per tuple group.
> **ᶜ** LateralMovement: sliding window loop is O(m) iterations per source, each computing `Distinct()` over up to O(m) entries in the window — O(m²) per source, bounded by O(n × m) overall.

---

## Security Takeaways

1. **Strategy pattern = modular security** — detectors are independently testable and replaceable
2. **HashSet = performance at scale** — O(1) lookups prevent the port check from becoming a bottleneck
3. **Short-circuit evaluation = efficient filtering** — most entries are rejected cheaply
4. **Structured findings = analyst efficiency** — every field maps to a triage action
5. **Early exits reduce wasted work** — disabled detectors and empty datasets avoid unnecessary setup and scanning
