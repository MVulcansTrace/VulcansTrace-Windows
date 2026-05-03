# Attack Scenario

---

## The Security Problem

During incident response, bursty connection attempts can be easy to spot but harder to classify. Analysts need to know whether the activity is broad enough and fast enough to look like reconnaissance instead of normal administration or background chatter.

---

## Worked Example

An internal host (`10.0.0.5`) rapidly probes 4 hosts on 4 ports in 75 seconds:

```text
2024-01-15 12:00:00 ALLOW TCP 10.0.0.5 192.168.1.1 50000 22 SEND
2024-01-15 12:00:05 ALLOW TCP 10.0.0.5 192.168.1.1 50001 80 SEND
2024-01-15 12:00:10 ALLOW TCP 10.0.0.5 192.168.1.1 50002 443 SEND
2024-01-15 12:00:15 ALLOW TCP 10.0.0.5 192.168.1.1 50003 3389 SEND
... (continues across 4 hosts × 4 ports = 16 entries)
```

**16 distinct targets in 75 seconds.** Methodical: same 4 ports (SSH, HTTP, HTTPS, RDP) on each host. Both horizontal and vertical scanning are present.

The detector behavior is:

1. Keep all 16 events for source `10.0.0.5`
2. Pass the global distinct-target pre-check
3. Evaluate the burst inside one 5-minute sliding window
4. Emit one Medium port-scan finding for that source and time range

---

## Detection Walkthrough

| Step | Result |
|------|--------|
| **A: Group** | `10.0.0.5` → 16 entries |
| **B: Global Check** | 16 distinct tuples >= 15 (Medium threshold) → Proceed |
| **C: Window** | All 16 entries fall within one 5-minute sliding window |
| **D: Detect** | 16 >= 15 → Finding created |

---

## The Finding

<!-- Conceptual output — the DateTime values below illustrate the expected
     result for this specific scenario. In the actual implementation,
     TimeRangeStart and TimeRangeEnd are computed from the log data
     (min/max timestamps in the matching window), not constructed as literals. -->

```csharp
new Finding
{
    Category = "PortScan",
    Severity = Severity.Medium,
    SourceHost = "10.0.0.5",
    Target = "multiple hosts/ports",
    TimeRangeStart = new DateTime(2024, 1, 15, 12, 0, 0),    // min timestamp in window
    TimeRangeEnd = new DateTime(2024, 1, 15, 12, 1, 15),     // max timestamp in window
    ShortDescription = "Port scan detected from 10.0.0.5",
    Details = "Detected 16 distinct destinations within 5 minutes."
}
```

---

## Design Rationale

This example shows why the detector counts distinct `(DstIp, DstPort)` tuples instead of only ports or only hosts. The same burst demonstrates:

- horizontal scanning across multiple hosts
- vertical scanning across multiple services
- time concentration that looks like recon rather than background noise

The result is one explainable finding instead of a pile of disconnected events.

---

## Security Value

| Detector Behavior | Security Benefit |
|-------------------|------------------|
| **Distinct tuple counting** | Catches both host breadth and service breadth |
| **Sliding time window** | Catches bursts without relying on wall-clock bucket boundaries |
| **Structured finding output** | Gives analysts attribution, time range, and scope |
| **Low-profile suppression note** | Explains why a true detection may still be hidden from the user |

---

## Profile Sensitivity: The "Low Profile Trap"

| Profile | Threshold | This Scan (16 targets) | Result |
|---------|-----------|------------------------|--------|
| Low | 30 | 16 < 30 | **MISSED** |
| Medium | 15 | 16 >= 15 | **DETECTED** |
| High | 8 | 16 >= 8 | **DETECTED** |

An attacker can scan 29 targets within any 5-minute window in a Low-profile environment without triggering detector logic at all.

> **Double suppression at Low profile:** The Low profile does not just set a high threshold. It also sets `MinSeverityToShow = Severity.High`. Since `PortScanDetector` always creates findings at `Severity.Medium`, any PortScan finding that does exceed the Low threshold of 30 targets would still be suppressed by the severity filter in `SentryAnalyzer` unless some other correlated findings cause `RiskEscalator` to raise it to `Critical`.

---

## Security Takeaways

1. **Recon is pattern-driven** — the suspicious signal comes from breadth plus timing, not one event alone
2. **Structured findings beat raw event piles** — analysts get one scoped result they can reason about
3. **Profile settings shape visibility as much as detector logic** — a true detection can still be hidden downstream
