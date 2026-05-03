# Detection Algorithm

---

## The Security Problem

Organizations have security policies that define which outbound connections are prohibited. These policies exist independently of what the firewall allows or blocks. An internal-to-external log entry on a disallowed port may reflect an allowed connection, a denied attempt, or a misconfiguration that still deserves review. The detector needs to identify these egress-policy events using IP classification and port configuration, not the firewall's decision metadata.

---

## Implementation Overview

A 4-step detection pipeline implemented in [PolicyViolationDetector.cs](../../../../VulcansTrace.Engine/Detectors/PolicyViolationDetector.cs):

```text
Raw LogEntries
    |
    v
Step A: Toggle Gate --------------- Why: Skip when disabled or empty
    |
    v
Step B: Setup --------------------- Why: Build O(1) port lookup
    |
    v
Step C: Three-Condition Filter ---- Why: Source internal, dest external, port disallowed
    |
    v
Step D: Finding Creation ---------- Why: One structured finding per violation
    |
    v
IEnumerable<Finding> with Severity.High
```

---

## Step A: Toggle Gate

**Process:** The detector checks if detection is enabled and logs exist.

```csharp
if (!profile.EnablePolicy || entries.Count == 0)
    return Enumerable.Empty<Finding>();
```

**Rationale:** The early-exit gate prevents wasted CPU cycles when the detector has nothing to do. There is no point initializing data structures or iterating entries when detection is disabled or the dataset is empty.

| Condition | Result |
|-----------|--------|
| `EnablePolicy == false` | Return empty, skip all processing |
| `entries.Count == 0` | Return empty, skip all processing |
| Both pass | Continue to setup (Step B) |

---

## Step B: Setup

**Process:** The detector initializes the disallowed-port HashSet.

```csharp
var findings = new List<Finding>();
var disallowed = new HashSet<int>(profile.DisallowedOutboundPorts ?? Array.Empty<int>());
```

**Rationale:** The null-coalescing pattern (`?? Array.Empty<int>()`) is defensive programming. In practice, `AnalysisProfileProvider` always provides a non-null `DisallowedOutboundPorts`, but the detector handles the edge case gracefully — empty set means no findings, not an exception.

**HashSet initialization:** The port list is loaded into `HashSet<int>` because O(1) lookup matters when processing large numbers of log entries. This keeps the per-entry cost constant regardless of how many ports are configured.

| Data Structure | Lookup Complexity | For 100 ports, 1M entries |
|----------------|-------------------|---------------------------|
| `List<int>` | O(n) | Up to 100 million comparisons |
| `HashSet<int>` | Average-case O(1) | 1 million hash lookups |

---

## Step C: Three-Condition Filter

**Process:** For each log entry, the detector applies three conditions in sequence. If any fails, it skips to the next entry.

```csharp
// Annotated for clarity — comments map each check to its condition number
foreach (var e in entries)
{
    cancellationToken.ThrowIfCancellationRequested();

    if (!IpClassification.IsInternal(e.SrcIp))       // Condition 1
        continue;

    if (!IpClassification.IsExternal(e.DstIp))        // Condition 2
        continue;

    if (!e.DstPort.HasValue || !disallowed.Contains(e.DstPort.Value))  // Condition 3
        continue;

    // All three passed → create finding
}
```

**Rationale:** The three-condition filter uses short-circuit evaluation because most log entries fail early — external sources are filtered on the first check, internal-to-internal traffic on the second. This minimizes unnecessary computation on the vast majority of entries.

### Condition 1: Source IP Internal

```csharp
if (!IpClassification.IsInternal(e.SrcIp))
    continue;
```

| IP Range | Classification |
|----------|----------------|
| 10.0.0.0/8 | Internal (RFC 1918 Class A) |
| 172.16.0.0/12 | Internal (RFC 1918 Class B) |
| 192.168.0.0/16 | Internal (RFC 1918 Class C) |
| 127.0.0.0/8 | Internal (IPv4 loopback) |
| ::1 | Internal (IPv6 loopback) |
| fc00::/7 | Internal (IPv6 ULA) |
| fe80::/10 | Internal (IPv6 link-local) |

Outbound policy applies only to hosts the organization controls. External hosts connecting elsewhere are outside jurisdiction.

### Condition 2: Destination IP External

```csharp
if (!IpClassification.IsExternal(e.DstIp))
    continue;
```

| Traffic Pattern | Handling | Detector |
|----------------|----------|----------|
| Internal → External | Egress policy check | This detector |
| Internal → Internal | Outside egress scope | LateralMovementDetector |
| External → Internal | Outside egress scope | Other detections |

### Condition 3: Destination Port Non-Null and Disallowed

```csharp
if (!e.DstPort.HasValue || !disallowed.Contains(e.DstPort.Value))
    continue;
```

This is a compound check: entries without a destination port are skipped first, then the port value is checked against the disallowed set. O(1) HashSet lookup — this is where Step B's initialization pays off. Default disallowed ports: 21 (FTP), 23 (Telnet), 445 (SMB).

### What Is NOT Checked (and Why)

| Field | Why Not Checked |
|-------|-----------------|
| Direction | IP classification provides the organizational perspective, which is more reliable than the firewall's label |
| Action | Organizational policy is not the same as the firewall's allow/deny decision — an ALLOW can still violate policy, and the detector also does not suppress DENY attempts |
| Protocol | Port-based signal only |
| Payload | No inspection capability at the network-log layer |

---

## Step D: Finding Creation

**Process:** For each entry that passes all three conditions, the detector creates a structured Finding object.

```csharp
findings.Add(new Finding
{
    Category = "PolicyViolation",
    Severity = Severity.High,
    SourceHost = e.SrcIp,
    Target = $"{e.DstIp}:{e.DstPort}",
    TimeRangeStart = e.Timestamp,
    TimeRangeEnd = e.Timestamp,
    ShortDescription = $"Disallowed outbound port from {e.SrcIp}",
    Details = $"Outbound connection to {e.DstIp}:{e.DstPort} on a disallowed port."
});
```

**Rationale:** One finding per violation is chosen because aggregation hides attack scope — if an internal host generates 50 disallowed-port entries to 50 different destinations, that is 50 investigative leads, not one summary count. This gives analysts complete visibility into every destination.

**Point event timestamps:** `TimeRangeStart` and `TimeRangeEnd` are identical because each finding represents a single connection, not a pattern over time. This differs from detectors like Beaconing that track intervals.

**Important:** The current `Details` string says "Outbound connection...", but the detector does not validate successful session establishment. It simply surfaces any qualifying internal-to-external log entry on a disallowed port.

---

## Complexity Analysis

| Metric | Value | Why |
|--------|-------|-----|
| **Time (gate + init)** | O(k) | k = number of disallowed ports |
| **Time (scan)** | O(n) | Single pass through entries |
| **Space** | O(m) | m = number of violations found |
| **Per-entry cost** | O(1) | Three short-circuit checks + optional finding creation |

This is the simplest detector in VulcansTrace — no grouping, no sorting, no state tracking, no aggregation.

---

## Downstream Pipeline

After the detector creates findings:

1. **RiskEscalator** — If the same source host also has both Beaconing and LateralMovement findings, all findings for that host (including PolicyViolation) escalate to Critical
2. **MinSeverityToShow filter** — PolicyViolation findings (High) appear in all built-in profiles because High meets or exceeds every MinSeverityToShow threshold

---

## Implementation Evidence

- [PolicyViolationDetector.cs](../../../../VulcansTrace.Engine/Detectors/PolicyViolationDetector.cs): full 53-line implementation
- [IpClassification.cs](../../../../VulcansTrace.Engine/Net/IpClassification.cs): internal/external IP classification for IPv4 and IPv6
- [AnalysisProfile.cs](../../../../VulcansTrace.Engine/AnalysisProfile.cs): `EnablePolicy` and `DisallowedOutboundPorts` configuration
- [AnalysisProfileProvider.cs](../../../../VulcansTrace.Engine/Configuration/AnalysisProfileProvider.cs): built-in profiles with policy enabled and ports [21, 23, 445]
- [PolicyViolationDetectorTests.cs](../../../../VulcansTrace.Tests/Engine/Detectors/PolicyViolationDetectorTests.cs): 9 tests covering happy path, disabled, empty, traffic direction, multiple violations, null config
