# Detection Algorithm

---

## The Security Problem

After initial compromise, attackers often pivot through the internal network over ports commonly associated with remote administration, such as 445, 3389, and 22. This spread pattern is visible in firewall logs as one source IP connecting to many distinct internal destinations in a short time window. The detector needs to identify this burst of distinct-host activity while ignoring normal admin traffic that targets a small set of known hosts.

---

## Implementation Overview

A 4-step detection pipeline implemented in [LateralMovementDetector.cs](../../../../VulcansTrace.Engine/Detectors/LateralMovementDetector.cs):

```text
Raw LogEntries
    |
    v
Step A: Feature Toggle ----------- Why: Skip if lateral movement detection is disabled
    |
    v
Step B: Filter Traffic ------------ Why: Remove irrelevant noise
    |
    v
Step C: Slide Window Per Source --- Why: Catch boundary-spanning attacks
    |
    v
Step D: Threshold Check ----------- Why: Create actionable finding
    |
    v
IEnumerable<Finding> with Severity.High
```

---

## Step A: Toggle Gate

**Process:** If `profile.EnableLateralMovement` is false or entries are empty, return immediately.

**Rationale:** Zero-cost disable. Teams that don't need lateral movement detection pay nothing. In the WPF UI, analysts can toggle this per-analysis via the **Advanced Options** expander (defaults to checked).

**Security Angle:** Defense in depth — the detector is one layer that can be toggled without affecting the rest of the pipeline.

---

## Step B: Traffic Filtering

**Process:** The detector filters all log entries to keep only internal-to-internal traffic on configured admin ports.

```csharp
var filtered = entries.Where(e =>
    IpClassification.IsInternal(e.SrcIp) &&
    IpClassification.IsInternal(e.DstIp) &&
    e.DstPort.HasValue &&
    adminSet.Contains(e.DstPort.Value));
```

**Rationale:** This filter removes external traffic, web browsing, and application noise that can never match this detector's lateral movement pattern, making the more expensive per-source window scan operate on a smaller, relevant dataset.

**What gets filtered out:**

| Traffic Type | Filtered? | Reason |
|-------------|-----------|--------|
| External attacker scanning | Excluded | Not internal source |
| Internal user browsing web | Excluded | Not admin ports |
| Server reply traffic | Excluded | Ephemeral destination ports |
| Actual lateral movement | Kept | Internal-to-internal on admin ports |

**IP Classification:** `IpClassification.IsInternal()` covers IPv4 RFC1918 ranges (10.x, 172.16-31.x, 192.168.x), IPv4 loopback (127.0.0.0/8), and IPv6 local ranges (::1, fc00::/7, fe80::/10).

---

## Step C: Sliding Window Per Source

**Process:** The detector groups filtered entries by source IP, sorts chronologically, then slides a two-pointer window across each source's activity.

```csharp
var bySrc = filtered.GroupBy(e => e.SrcIp);
foreach (var srcGroup in bySrc)
{
    cancellationToken.ThrowIfCancellationRequested();

    var ordered = srcGroup.OrderBy(e => e.Timestamp).ToList();
    if (ordered.Count == 0) continue;

    var windowMinutes = profile.LateralWindowMinutes;

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
            .Skip(start)
            .Take(end - start + 1)
            .Select(e => e.DstIp)
            .Distinct()
            .ToList();
    }
}
```

**Rationale:** A sliding window was chosen because lateral movement can span arbitrary time boundaries — an attacker pivoting from 10:58 through 12:02 would get split across two 5-minute buckets. This catches boundary-spanning attacks that bucketed approaches would miss.

```text
Attack: 10:58, 10:59, 11:01, 11:02, 11:03 (5 hosts in 5 minutes)

Bucketed: 10:55-11:00 → 2 hosts  |  11:00-11:05 → 3 hosts → Both miss
Sliding: At 11:03, window [10:58-11:03] → 5 hosts → Detected
```

**Complexity:** O(m log m) for sorting plus O(m²) for the window scan (Distinct() rebuilds per iteration). Filtering and early exit help keep m smaller in practice, but the code does not enforce a per-source cap the way Port Scan and Beaconing do.

---

## Step D: Threshold Check and Finding Creation

**Process:** For each window position, the detector counts distinct destination hosts. If the count meets or exceeds the configured threshold, it creates a finding and stops processing that source.

```csharp
var hosts = ordered
    .Skip(start)
    .Take(end - start + 1)
    .Select(e => e.DstIp)
    .Distinct()
    .ToList();

if (hosts.Count >= profile.LateralMinHosts)
{
    var minTime = ordered[start].Timestamp;
    var maxTime = ordered[end].Timestamp;

    findings.Add(new Finding
    {
        Category = "LateralMovement",
        Severity = Severity.High,
        SourceHost = srcGroup.Key,
        Target = "multiple internal hosts",
        TimeRangeStart = minTime,
        TimeRangeEnd = maxTime,
        ShortDescription = $"Lateral movement from {srcGroup.Key}",
        Details = $"Contacted {hosts.Count} internal hosts on admin ports."
    });
    break; // One finding per source
}
```

**Rationale:** Output is limited to one finding per source because duplicate alerts for the same compromised host add no investigative value. This prevents alert fatigue while still triggering the response workflow.

---

## Complexity Analysis

| Metric | Value | Why |
|--------|-------|-----|
| **Time (filter + group)** | O(n) | Single pass |
| **Time (sort per source)** | O(Σ mᵢ log mᵢ) ≤ O(n log m) | Each source sorted independently; m = max group size |
| **Time (window scan)** | O(Σ mᵢ²) ≤ O(n × m) worst case | Distinct() per iteration; mᵢ = entries for source i |
| **Space** | O(n) | Grouped entries |
| **Early exit** | Per source | Breaks after first detection |

**Key optimization:** Filtering removes categories of traffic that can never match this detector before the expensive window scan runs.

**Profile variance:** `LateralMinHosts` ranges from 3 (High intensity) to 4 (Medium) to 6 (Low), configured via `AnalysisProfileProvider`. Lower thresholds increase sensitivity at the cost of more findings.

---

## Downstream Pipeline

After the detector creates a finding:

1. **RiskEscalator** — If the same source host also has a Beaconing finding, all findings from that source host are escalated to Critical
2. **MinSeverityToShow filter** — LateralMovement findings (High) appear in all built-in profiles

---

## Implementation Evidence

- [LateralMovementDetector.cs](../../../../VulcansTrace.Engine/Detectors/LateralMovementDetector.cs): filtering, sliding window, distinct-host counting, and finding creation
- [IpClassification.cs](../../../../VulcansTrace.Engine/Net/IpClassification.cs): internal IP classification for both IPv4 and IPv6
- [AnalysisProfile.cs](../../../../VulcansTrace.Engine/AnalysisProfile.cs): threshold and configuration model
- [LateralMovementDetectorTests.cs](../../../../VulcansTrace.Tests/Engine/Detectors/LateralMovementDetectorTests.cs): above-threshold, below-threshold, disabled-flag, empty-input, external-traffic, non-admin-port, multi-source, and time-spread coverage
