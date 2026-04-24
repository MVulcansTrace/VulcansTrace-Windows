# Code Patterns

---

## The Security Problem

Detection code becomes harder to trust when grouping, thresholding, and safety guards are all expressed differently. Consistent implementation patterns matter because they keep the detector explainable, testable, and easier to audit.

---

## Implementation Overview

The detector relies on a small set of repeatable patterns:

| Pattern | Where It Appears | Why It Matters |
|---------|------------------|----------------|
| **Strategy interface** | `IDetector` implementation | Keeps the analysis pipeline modular |
| **Source-first grouping** | `entries.GroupBy(e => e.SrcIp)` | Attributes behavior to one host at a time |
| **Distinct tuple counting** | `(DstIp, DstPort)` with `Distinct()` | Catches horizontal and vertical scans |
| **Early-exit gate** | Source-level global pre-check | Skips low-variety traffic cheaply |
| **Fixed-window bucketing** | Aligned `DateTime` grouping | Makes burst activity measurable and predictable |
| **Warning-backed truncation** | Optional max-entries cap | Bounds per-source work transparently |
| **Structured finding output** | `Finding` object creation | Produces explainable evidence for analysts |

---

## How It Works (Technical)

### Strategy Pattern — `IDetector`

```csharp
public sealed class PortScanDetector : IDetector, IProducesWarnings
{
    public IEnumerable<Finding> Detect(
        IReadOnlyList<LogEntry> entries,
        AnalysisProfile profile,
        CancellationToken cancellationToken)
}
```

**Why:** Detectors are interchangeable. `SentryAnalyzer` treats all detectors uniformly, which keeps the pipeline modular and extensible.

**Security Angle:** Modularity is a security property. New detection rules do not risk breaking existing ones just because they share a common orchestration pipeline.

---

### Distinct Tuple Counting

The detector counts distinct `(DstIp, DstPort)` tuples both at the source level and again inside each time bucket.

That pattern matters because:

- same port across many hosts still counts
- many ports on one host still counts
- repeated hits to the same host and port do not inflate the breadth artificially

---

### Early Exit Gate

Before bucketing by time, the detector does a source-level distinct-target count. If that count is already below threshold, it skips the window pass entirely.

That keeps the common “obviously not a scan” case cheap without changing detector behavior when the full source set is analyzed.

---

### Fixed-Window Bucketing

Each source's timestamps are grouped into aligned time buckets using the configured `PortScanWindowMinutes`.

This gives the detector:

- predictable output
- simple implementation
- a clear explanation for why one burst triggered and another did not

---

### Warning-Backed Truncation

```csharp
if (maxEntries > 0 && ordered.Count > maxEntries)
{
    ordered = ordered.Take(maxEntries).ToList();
    _warnings.Add($"Port scan analysis for {srcIp} truncated to {maxEntries} events out of {totalForSource}.");
}
```

**Why:** Three scenarios require this: compromised hosts flooding logs, attackers deliberately DoS-ing analysis, or legitimate high-volume sources. First `N` chronologically preserves timeline. Warning ensures no silent data loss.

**Security Angle:** Availability engineering. This guard bounds per-source work when it is enabled, but it does so by intentionally accepting reduced completeness on the discarded events.

> **Note:** All shipped intensity profiles set `PortScanMaxEntriesPerSource` to `null` (unlimited), so truncation activates only when a custom profile specifies a cap.

---

### Structured Finding Output

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

**Why:** Every field serves an analyst workflow: `Category` for filtering, `Severity` for triage, `SourceHost` for blocking, `TimeRange` for correlation, and `Details` for investigation.

**Downstream behavior:** `RiskEscalator` raises the finding to Critical only if the same host also has Beaconing and LateralMovement. `MinSeverityToShow` then controls whether the user sees it.

---

## Implementation Evidence

- [PortScanDetector.cs](../../../VulcansTrace.Engine/Detectors/PortScanDetector.cs): grouping, tuple counting, bucketing, truncation, and finding creation
- [PortScanDetectorTests.cs](../../../VulcansTrace.Tests/Engine/Detectors/PortScanDetectorTests.cs): threshold, multi-source, and truncation coverage
- [AnalysisProfileProvider.cs](../../../VulcansTrace.Engine/Configuration/AnalysisProfileProvider.cs): built-in thresholds and defaults

---

## Security Takeaways

1. **Strategy pattern = modular security** — detectors are interchangeable and independently testable
2. **Distinct tuple counting = breadth-aware detection** — the detector measures scan scope, not just event volume
3. **Truncation + warnings = graceful degradation** — systems survive adversarial conditions without hiding the trade-off
4. **Early exits and fixed buckets = predictable cost and behavior** — the detector stays explainable under load
