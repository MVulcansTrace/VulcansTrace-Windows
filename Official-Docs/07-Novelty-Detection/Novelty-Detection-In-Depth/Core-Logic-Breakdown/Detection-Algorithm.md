# Detection Algorithm

---

## The Security Problem

Pattern-based detectors like port scan and beaconing look for repeated behavior across many targets or over time. But a destination that appears exactly once in the current dataset is invisible to those detectors. A C2 server that checks in once before regular beaconing begins, an exfiltration test to an endpoint that appears only once in the analyzed corpus, or infrastructure setup for a future attack phase can all produce a single connection that pattern-based analysis will not catch.

The detector needs to count how many times each external destination tuple appears and flag the ones that appear exactly once — without making a determination about intent, because a singleton connection is a weak signal that requires analyst investigation.

---

## Implementation Overview

A 4-step detection pipeline implemented in [NoveltyDetector.cs](../../../../VulcansTrace.Engine/Detectors/NoveltyDetector.cs):

```text
Raw LogEntries
    |
    v
Step A: Toggle Gate -------------- Why: Skip when disabled or empty
    |
    v
Step B: External Filter ------- Why: Remove internal noise
    |
    v
Step C: Tuple Counting -------- Why: Build occurrence map per destination service
    |
    v
Step D: Singleton Emission ---- Why: Create findings for count == 1
    |
    v
IEnumerable<Finding> with Severity.Low
```

---

## Step A: Toggle Gate

**Process:** Early-return when detection is disabled or the dataset is empty.

```csharp
if (!profile.EnableNovelty || entries.Count == 0)
    return Enumerable.Empty<Finding>();
```

**Rationale:** There is no point running the counting logic when the detector is disabled or the dataset is empty.

**Gate behavior by intensity:**

| Intensity | EnableNovelty | Guard Result | Downstream Visibility |
|-----------|---------------|--------------|----------------------|
| Low | `false` | Gate fails — detector returns immediately | No findings emitted |
| Medium | `true` | Gate passes — detector runs | Findings emitted but filtered by MinSeverityToShow |
| High | `true` | Gate passes — detector runs | Findings visible (Low >= Info) |

---

## Step B: External Filter

**Process:** Filter all log entries to keep only those with an external destination IP and a valid destination port.

```csharp
var externalEntries = entries
    .Where(e => IpClassification.IsExternal(e.DstIp) && e.DstPort.HasValue)
    .ToList();
if (externalEntries.Count == 0)
    return Enumerable.Empty<Finding>();
```

**Rationale:** Internal one-time connections are routine noise — DHCP renewals, print jobs, DNS queries, file access — while external singletons are noteworthy because the organization has no established relationship with that destination. An external-only filter keeps the signal clean by excluding the high volume of internal routine traffic.

**What gets filtered:**

| Traffic Type | Filtered? | Reason |
|-------------|-----------|--------|
| Internal-to-internal singletons | Excluded | DHCP, printing, DNS, NTP — noise |
| External singletons | Kept | First-contact destinations — signal |
| Loopback (127.x.x.x) | Kept | Not classified as internal by `IpClassification` |
| Link-local (169.254.x.x) | Kept | Not classified as internal by `IpClassification` |

**Edge case:** IPv4 loopback and link-local addresses are not classified as internal by `IpClassification`, so they pass through the filter. IPv6 loopback (::1) and link-local (fe80::/10) are classified as internal.

---

## Step C: Tuple Counting

**Process:** Group external entries by (DstIp, DstPort) and count occurrences.

```csharp
var counts = externalEntries
    .GroupBy(e => (e.DstIp, e.DstPort!.Value))
    .ToDictionary(g => g.Key, g => g.Count());
```

**Rationale:** The same server on different ports is a different service — a C2 server might run HTTPS on 443 and a backdoor on 8443. Grouping by (DstIp, DstPort) tuple rather than just DstIp preserves service-level granularity that IP-only grouping would lose.

**What is in the tuple:** DstIp and DstPort.
**What is not in the tuple:** SrcIp (counting is global, not per-source), Protocol (TCP/UDP counted together), Timestamp (counts span the entire dataset).

**Example dictionary output:**

```text
4 external entries → {
  ("203.0.113.42", 443): 2,
  ("198.51.100.7", 8443): 1,
  ("203.0.113.42", 22): 1
}
```

Two singletons detected: 198.51.100.7:8443 and 203.0.113.42:22.

---

## Step D: Singleton Emission

**Process:** Iterate external entries, look up each tuple's count, and create a finding when count == 1.

```csharp
var findings = new List<Finding>();
foreach (var e in externalEntries)
{
    cancellationToken.ThrowIfCancellationRequested();
    var key = (e.DstIp, e.DstPort!.Value);
    if (counts[key] != 1)
        continue;
    findings.Add(new Finding
    {
        Category = "Novelty",
        Severity = Severity.Low,
        SourceHost = e.SrcIp,
        Target = $"{e.DstIp}:{e.DstPort}",
        TimeRangeStart = e.Timestamp,
        TimeRangeEnd = e.Timestamp,
        ShortDescription = "Novel external destination",
        Details = $"Single observed connection to {e.DstIp}:{e.DstPort}."
    });
}
return findings;
```

**Rationale:** A strict singleton boundary has clear semantics — the destination appeared once in the entire dataset. A count of 2 could be a legitimate retry, an emerging pattern, or an attacker testing twice. Forcing the boundary at 1 reduces false positives at the cost of missing "low and slow" attackers who make two connections. This keeps the detector's claim precise. Severity is set to Low because novelty has a high false-positive rate — most singletons are legitimate (CDN edges, one-time downloads, cloud API calls). This communicates that the finding is a signal for investigation, not a verdict.

**Cardinality:** One finding per singleton entry in the dataset. Multiple findings are possible if multiple singletons exist. If the same tuple appears in 2+ logs, no finding is created.

---

## Complexity Analysis

| Metric | Value | Why |
|--------|-------|-----|
| **Time (guards)** | O(1) | Property and count checks |
| **Time (filter)** | O(n) | Single pass over all entries |
| **Time (GroupBy + Count)** | O(e) | Over external entries only |
| **Time (emission loop)** | O(e) | Dictionary lookup is O(1) |
| **Total time** | O(n) | Dominated by the filter pass |
| **Space** | O(n) worst case | external entries + dictionary + findings |

**Key advantage:** No sorting, no sliding windows, no sampling. Novelty is among the simplest detectors algorithmically in VulcansTrace.

---

## Downstream Pipeline

After the detector creates findings:

1. **RiskEscalator** — Groups findings by SourceHost. If a host has both Beaconing and LateralMovement findings, ALL findings for that host escalate to Critical, including Novelty.
2. **MinSeverityToShow filter** — Novelty findings (Low) appear only at High intensity where MinSeverityToShow = Info.

```text
NoveltyDetector (Low)
    → RiskEscalator (Low → Critical if Beaconing + LateralMovement also present)
    → MinSeverityToShow filter (visible only at High intensity unless escalated)
```

---

## Implementation Evidence

- [NoveltyDetector.cs](../../../../VulcansTrace.Engine/Detectors/NoveltyDetector.cs): toggle gate, external filtering, tuple counting, singleton finding creation (57 lines)
- [IpClassification.cs](../../../../VulcansTrace.Engine/Net/IpClassification.cs): `IsExternal()` classification for both IPv4 and IPv6
- [AnalysisProfile.cs](../../../../VulcansTrace.Engine/AnalysisProfile.cs): `EnableNovelty` flag and `MinSeverityToShow` configuration
- [NoveltyDetectorTests.cs](../../../../VulcansTrace.Tests/Engine/Detectors/NoveltyDetectorTests.cs): 8 tests covering singleton, repeated, disabled, empty, internal-only, mixed, same-IP-different-ports, and different-IP-same-port scenarios

