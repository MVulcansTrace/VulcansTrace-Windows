# Code Patterns

---

## Pattern 1: Simple Factory — AnalysisProfileProvider

```csharp
public sealed class AnalysisProfileProvider
{
    public AnalysisProfile GetProfile(IntensityLevel level)
    {
        int[] adminPorts = [445, 3389, 22];
        int[] disallowedOutbound = [21, 23, 445];

        return level switch
        {
            IntensityLevel.Low => new AnalysisProfile { ... },
            IntensityLevel.Medium => new AnalysisProfile { ... },
            IntensityLevel.High => new AnalysisProfile { ... },
            _ => throw new ArgumentOutOfRangeException(nameof(level), level, null)
        };
    }
}
```

**Rationale:** The factory ensures all 20+ threshold values are set consistently across every detector — preventing mismatched configurations where detectors operate at different sensitivities on the same analysis run.

**Effect:** One method call replaces 20+ manual property assignments. The switch expression makes profile differences immediately visible.

---

## Pattern 2: Immutable Record — AnalysisProfile

```csharp
public sealed record AnalysisProfile
{
    public bool EnablePortScan { get; init; }
    public int PortScanMinPorts { get; init; }
    public Severity MinSeverityToShow { get; init; } = Severity.Medium;
    // ... 20 more properties
}
```

**Why:** The profile is a sealed record with init-only properties because shared mutable configuration is a classic bug source — one detector changing a threshold would silently affect all subsequent detectors, for the purpose of guaranteeing that every detector operates on the exact same configuration it received.

**Effect:** The compiler enforces immutability. Custom overrides create new records via the `with` expression, leaving the original untouched.

---

## Pattern 3: Escalate-Before-Filter Pipeline

```csharp
// Simplified — actual implementation includes try/catch fault isolation
// and IProducesWarnings collection (see SentryAnalyzer.cs)
var allFindings = new List<Finding>();
foreach (var detector in _detectors)
{
    var detected = detector.Detect(entries, profile, cancellationToken);
    allFindings.AddRange(detected);
}

var escalated = _riskEscalator.Escalate(allFindings);

result.AddFindings(
    escalated.Where(f => f.Severity >= profile.MinSeverityToShow));
```

**Why:** Escalation is ordered before filtering because filtering first would hide the Medium-severity Beaconing finding that triggers the correlation with LateralMovement, for the purpose of ensuring that cross-detector compromise signals always reach the analyst regardless of profile selection.

**Effect:** On Low profile, a standalone Medium-severity Beaconing finding is filtered out. But if the same host also has LateralMovement, the escalation promotes both to Critical, and Critical >= High (Low's gate) means the finding survives.

---

## Pattern 4: Enable-Flag Gates

```csharp
if (!profile.EnablePortScan || entries.Count == 0)
    return Enumerable.Empty<Finding>();
```

**Why:** Early-exit gates are added because disabled detectors should not allocate resources processing data, for the purpose of keeping analysis fast when specific detection types are turned off.

**Effect:** Novelty detection on Low profile returns immediately without processing any entries. The empty-dataset check prevents unnecessary sorting and grouping.

---

## Pattern 5: Profile Override via `with` Expression

```csharp
var baseProfile = _profileProvider.GetProfile(intensity);
var profile = baseProfile with { PortScanMaxEntriesPerSource = 50000 };
```

**Why:** Targeted overrides are supported because some operational contexts need one or two parameter changes without defining an entirely new profile, for the purpose of enabling advanced customization while keeping the default path simple.

**Effect:** The `with` expression creates a new record that copies all properties from the base profile and overrides only the specified ones. The original profile remains unchanged.

---

## Pattern 6: Cooperative Cancellation

```csharp
cancellationToken.ThrowIfCancellationRequested();
```

**Why:** Cancellation checks are added between detector iterations, and the built-in detectors also honor the token internally, because log analysis can process large datasets, for the purpose of keeping the WPF UI responsive when users load large log files.

**Effect:** Users can cancel a long-running analysis without killing the application. The `OperationCanceledException` propagates cleanly through the pipeline.

---

## Pattern 7: Structured Finding Output

```csharp
new Finding
{
    Category = "PortScan",
    Severity = Severity.Medium,
    SourceHost = srcIp,
    Target = "multiple hosts/ports",
    TimeRangeStart = minTime,
    TimeRangeEnd = maxTime,
    ShortDescription = $"Port scan detected from {srcIp}",
    Details = $"Detected {distinctTargets} distinct destinations within {profile.PortScanWindowMinutes} minutes."
};
```

**Rationale:** The finding structure ensures every field serves an analyst workflow — Category for filtering, Severity for prioritization, SourceHost for blocking, TimeRange for correlation, Details for investigation scope — making triage faster.

**Effect:** The WPF UI, evidence exporters, and severity filter all operate on the same structured finding. No parsing of free-text descriptions needed.

---

## Comparison Across Detectors

| Pattern | PortScan | Flood | Beaconing | Lateral | Policy | Novelty |
|---------|----------|-------|-----------|---------|--------|---------|
| Window type | Bucketed | Sliding | Statistical | Sliding | N/A | N/A |
| Finding severity | Medium | High | Medium | High | High | Low |
| Visible on Low | No* | Yes | No* | Yes | Yes | No |
| Per-source limit | Max entries per source | One finding then break | Sample cap | One finding then break | None | None |

\* Visible on Low if escalated to Critical by RiskEscalator

---

## Security Takeaways

1. **Simple Factory = consistent configuration** — one method call sets all 20+ parameters correctly
2. **Immutable records = configuration safety** — no detector can mutate the shared profile
3. **Escalate-before-filter = correlation visibility** — compromise indicators survive conservative profiles
4. **Enable-flag gates = resource protection** — disabled detectors return immediately
5. **Structured findings = analyst efficiency** — every field maps to a triage action
