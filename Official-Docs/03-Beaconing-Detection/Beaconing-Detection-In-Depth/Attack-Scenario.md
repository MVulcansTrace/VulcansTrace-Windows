# Attack Scenario: Catching a C2 Beacon

---

## The Attack

A compromised internal host (`192.168.1.50`) calls back to an attacker-controlled server (`203.0.113.42`) on port 443 every 90 seconds:

```
2024-01-15 10:00:00 ALLOW TCP 192.168.1.50 203.0.113.42 51001 443 SEND
2024-01-15 10:01:30 ALLOW TCP 192.168.1.50 203.0.113.42 51002 443 SEND
2024-01-15 10:03:00 ALLOW TCP 192.168.1.50 203.0.113.42 51003 443 SEND
2024-01-15 10:04:30 ALLOW TCP 192.168.1.50 203.0.113.42 51004 443 SEND
2024-01-15 10:06:00 ALLOW TCP 192.168.1.50 203.0.113.42 51005 443 SEND
2024-01-15 10:07:30 ALLOW TCP 192.168.1.50 203.0.113.42 51006 443 SEND
2024-01-15 10:09:00 ALLOW TCP 192.168.1.50 203.0.113.42 51007 443 SEND
2024-01-15 10:10:30 ALLOW TCP 192.168.1.50 203.0.113.42 51008 443 SEND
2024-01-15 10:12:00 ALLOW TCP 192.168.1.50 203.0.113.42 51009 443 SEND
2024-01-15 10:13:30 ALLOW TCP 192.168.1.50 203.0.113.42 51010 443 SEND
```

**10 connections, 90 seconds apart, spanning 13.5 minutes.** Perfect metronome — the hallmark of automated C2 beaconing.

---

## Detection Walkthrough

| Step | Action | Result |
|------|--------|--------|
| **A: Toggle** | EnableBeaconing = true | Proceed |
| **B: Group** | Group by (192.168.1.50, 203.0.113.42, 443) | 10 entries |
| **C: Order + Cap** | Sort chronologically; 10 < 200 max | All samples kept |
| **D: Min Events** | 10 >= 6 (Medium) | Proceed |
| **E: Min Duration** | 810s >= 120s | Proceed |
| **F: Intervals** | Compute consecutive gaps | [90, 90, 90, 90, 90, 90, 90, 90, 90] |
| **G: Trim** | Sort → trim 10% from each end | Remove 1 from low, 1 from high → [90, 90, 90, 90, 90, 90, 90] |
| **H: Mean Bounds** | Mean = 90s (in 30–900 range) | Proceed |
| **I: StdDev Gate** | StdDev = 0.0 (≤ 5.0) | **BEACON DETECTED** |

---

## The Finding

```csharp
new Finding
{
    Category = "Beaconing",
    Severity = Severity.Medium,
    SourceHost = "192.168.1.50",
    Target = "203.0.113.42:443",
    TimeRangeStart = new DateTime(2024, 1, 15, 10, 0, 0),
    TimeRangeEnd = new DateTime(2024, 1, 15, 10, 13, 30),
    ShortDescription = "Regular beaconing from 192.168.1.50",
    Details = "Average interval ~90.0s, std dev ~0.0s over 10 events."
}
```

---

## Escalation: What Happens When Lateral Movement Appears

If the same host (`192.168.1.50`) also shows lateral movement findings, RiskEscalator raises **all** findings for that host to Critical:

| Scenario | Severity | Rationale |
|----------|----------|-----------|
| Beaconing only | Medium | Compromised host, contained scope |
| Beaconing + LateralMovement | Critical | Compromised host actively probing the network |

---

## Profile Sensitivity

| Profile | StdDev Threshold | Min Events | This Beacon (stdDev = 0) | Result |
|---------|-----------------|------------|--------------------------|--------|
| Low | 3.0 | 8 | 0.0 <= 3.0, 10 >= 8 | **DETECTED** |
| Medium | 5.0 | 6 | 0.0 <= 5.0, 10 >= 6 | **DETECTED** |
| High | 8.0 | 4 | 0.0 <= 8.0, 10 >= 4 | **DETECTED** |

This perfect beacon triggers on all profiles. Jitter-tolerant malware that adds random delays would produce higher std dev and may evade Low but not High.

---

## Implementation Evidence

- [BeaconingDetector.cs](../../../VulcansTrace.Engine/Detectors/BeaconingDetector.cs): the full 9-step pipeline
- [RiskEscalator.cs](../../../VulcansTrace.Engine/RiskEscalator.cs): Beaconing + LateralMovement escalation to Critical
- [BeaconingDetectorTests.cs](../../../VulcansTrace.Tests/Engine/Detectors/BeaconingDetectorTests.cs): test method `Detect_WithRegularBeaconing_ReturnsFinding` covers an equivalent beaconing pattern (same count and interval)


