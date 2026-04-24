# Detection Algorithm

---

## The Security Problem

Flood attacks can produce a distinctive pattern in firewall logs: a single source IP generates an abnormally high number of connection events within a short time period. The detector needs to identify this volumetric burst per source while distinguishing it from normal traffic patterns and events that are spread evenly over time.

---

## Implementation Overview

A 5-step detection pipeline implemented in [FloodDetector.cs](../../../../VulcansTrace.Engine/Detectors/FloodDetector.cs):

```text
Raw LogEntries
    |
    v
Step A: Toggle Gate -------------- Why: Skip detection when disabled or input is empty
    |
    v
Step B: Group By Source ---------- Why: Isolate each IP for independent analysis
    |
    v
Step C: Sort Chronologically ----- Why: Required for sliding window correctness
    |
    v
Step D: Slide Window & Check ----- Why: Catch boundary-spanning floods efficiently
    |
    v
Step E: Create Finding ----------- Why: Package detection as actionable alert
    |
    v
IEnumerable<Finding> with Severity.High
```

---

## Step A: Toggle Gate

**Process:** The detector checks whether flood detection is enabled and whether the input contains any entries.

```csharp
if (!profile.EnableFlood || entries.Count == 0)
    return Enumerable.Empty<Finding>();
```

**Rationale:** This early-exit gate avoids all downstream computation when flood detection is disabled or there is nothing to analyze.

| Condition | Result |
|-----------|--------|
| `EnableFlood == false` | Return empty, skip all processing |
| `entries.Count == 0` | Return empty, skip all processing |
| Both pass | Continue to grouping (Step B) |

---

## Step B: Source Grouping

**Process:** The detector groups all log entries by source IP address.

```csharp
var bySrc = entries.GroupBy(e => e.SrcIp);
foreach (var srcGroup in bySrc)
{
    cancellationToken.ThrowIfCancellationRequested();
    var srcIp = srcGroup.Key;
    var ordered = srcGroup.OrderBy(e => e.Timestamp).ToList();
    if (ordered.Count == 0) continue;
    // ... sliding window scan ...
}
```

**Rationale:** Per-source grouping isolates the noisy IP so that one high-volume source does not dilute the signal from normal sources. Flood detection measures the behavior of one source, not aggregate traffic.

| Edge Case | Handling |
|-----------|----------|
| Empty input | Handled by Step A toggle gate |
| Single event | Processed normally; `windowCount = 1` cannot meet any built-in profile threshold |
| Same timestamp | All events are still counted inside the same time window when they fall within `FloodWindowSeconds` |

**Complexity:** O(n) for GroupBy.

---

## Step C: Chronological Sort

**Process:** Each source group is sorted chronologically before the sliding window scan.

```csharp
var ordered = srcGroup.OrderBy(e => e.Timestamp).ToList();
```

**Rationale:** The two-pointer sliding window (Step D) requires chronological ordering to correctly identify bursts. Unsorted data would produce incorrect window boundaries and miss floods that span the sort boundary.

**Complexity:** O(m log m) per source, dominated by O(n log n) overall.

---

## Step D: Slide Window & Check

**Process:** The detector slides a two-pointer window across each source's chronologically sorted events, tracking event density.

```csharp
var windowSeconds = profile.FloodWindowSeconds;
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
        // Create finding...
        break;
    }
}
```

**Rationale:** Floods can span arbitrary time boundaries. A sliding window was chosen to catch attacks that bucketed approaches would split and miss.

```text
Attack: 120 events from 10:59:30 to 11:00:29 (60 seconds)

Bucketed: 10:59:00-11:00:00 = 60 events  |  11:00:00-11:01:00 = 60 events -> MISSED
Sliding:  Window at 11:00:29 spans all 120 events                  -> DETECTED (High profile)
```

| Pointer | Role | Movement |
|---------|------|----------|
| `end` | Right edge of window | Advances through all events |
| `start` | Left edge of window | Advances when window exceeds configured duration |

**Key insight:** Each event enters the window once (when `end` reaches it) and leaves once (when `start` passes it). The sliding-window scan itself is O(n) per source.

**Important:** The window contracts only when the span is strictly **greater than** `windowSeconds`, so events exactly `windowSeconds` apart remain in the same window.

### Threshold Check

**Process:** The detector compares the event count in the current window against the configured threshold.

```csharp
if (windowCount >= profile.FloodMinEvents)
```

**Rationale:** The `>=` comparison ensures boundary precision in both detection and testing. Exactly meeting the threshold qualifies as a flood.

| Condition | Result |
|-----------|--------|
| `windowCount < FloodMinEvents` | Continue scanning |
| `windowCount >= FloodMinEvents` | Create finding (Severity: **High**), break |

**Threshold values by profile:**

| Profile | MinEvents | Approx. Rate | Use Case |
|---------|-----------|-------------|----------|
| Low | 400 | ~6.7 events/sec | High-traffic environments |
| Medium | 200 | ~3.3 events/sec | General enterprise |
| High | 100 | ~1.7 events/sec | Critical infrastructure |

**Note:** The detector checks raw event count inside the configured window, not a calculated rate. The rates above are conversions for analyst intuition.

---

## Step E: Finding Creation

**Process:** The detector creates a structured finding with attribution, timeline, and event count, then breaks to prevent duplicate alerts for the same source.

```csharp
findings.Add(new Finding
{
    Category = "Flood",
    Severity = Severity.High,
    SourceHost = srcIp,
    Target = "multiple hosts/ports",
    TimeRangeStart = minTime,
    TimeRangeEnd = maxTime,
    ShortDescription = $"Flood detected from {srcIp}",
    Details = $"Detected {windowCount} events within {windowSeconds} seconds."
});

break; // one finding per src is enough for v1
```

**Rationale:** Duplicate alerts for the same flooding host add no investigative value. Output is limited to one finding per source to prevent alert fatigue while still triggering the response workflow.

**Finding fields:**

| Field | Value | Purpose |
|-------|-------|---------|
| `Category` | `"Flood"` | Filter by detection type |
| `Severity` | `Severity.High` | Prioritize in analyst queue |
| `SourceHost` | Source IP | Enable targeted blocking |
| `Target` | `"multiple hosts/ports"` | Descriptive label (v1 does not analyze actual destinations) |
| `TimeRangeStart` | First event in window | Correlation with other logs |
| `TimeRangeEnd` | Last event in window | Scope the attack window |
| `ShortDescription` | `"Flood detected from {srcIp}"` | One-line summary for alerting |
| `Details` | Event count and configured window | Exact count for investigation |

**Note:** The `Details` field reports the configured `FloodWindowSeconds` (60), not the actual event time span. The actual span is available in `TimeRangeStart`/`TimeRangeEnd`.

---

## Complexity Analysis

| Metric | Value | Why |
|--------|-------|-----|
| **Time (group + sort)** | O(n log n) | Sorting dominates |
| **Time (window scan)** | O(n) | Two-pointer scan per source |
| **Space** | O(n) | Grouped entries and sorted lists |
| **Early exit** | Per source | Breaks after first detection |

---

## Downstream Pipeline

After the detector creates a finding:

1. **RiskEscalator** — If the same source host also has both Beaconing and LateralMovement findings, all findings for that host, including Flood, are escalated to Critical
2. **MinSeverityToShow filter** — Flood findings start at High severity, so they remain visible in all built-in profiles

```text
FloodDetector (emit Severity.High)
    |
    v
RiskEscalator (escalate all findings for host to Critical if Beaconing + LateralMovement present)
    |
    v
MinSeverityToShow filter (High passes all built-in profiles)
    |
    v
Analyst-visible finding
```

---

## Implementation Evidence

- [FloodDetector.cs](../../../../VulcansTrace.Engine/Detectors/FloodDetector.cs): grouping, sorting, sliding window, threshold check, and finding creation
- [AnalysisProfile.cs](../../../../VulcansTrace.Engine/AnalysisProfile.cs): threshold and configuration model
- [AnalysisProfileProvider.cs](../../../../VulcansTrace.Engine/Configuration/AnalysisProfileProvider.cs): built-in Low, Medium, and High presets
- [FloodDetectorTests.cs](../../../../VulcansTrace.Tests/Engine/Detectors/FloodDetectorTests.cs): above-threshold, below-threshold, disabled, empty, multi-source, time-spread, and boundary coverage

