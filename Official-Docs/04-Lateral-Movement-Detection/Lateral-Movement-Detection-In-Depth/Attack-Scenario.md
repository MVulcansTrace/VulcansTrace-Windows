# Attack Scenario: Watch It Catch a Synthetic Pivot

---

## The Attack

A compromised internal host (`192.168.1.100`) pivots through the network, contacting 7 internal hosts on admin ports in 6 minutes:

```text
12:00:00  192.168.1.100 → 192.168.1.10:445   TCP  ALLOW
12:01:00  192.168.1.100 → 192.168.1.11:3389  TCP  ALLOW
12:02:00  192.168.1.100 → 192.168.1.12:22    TCP  ALLOW
12:03:00  192.168.1.100 → 192.168.1.13:445   TCP  ALLOW
12:04:00  192.168.1.100 → 192.168.1.14:3389  TCP  ALLOW
12:05:00  192.168.1.100 → 192.168.1.15:445   TCP  ALLOW
12:06:00  192.168.1.100 → 192.168.1.16:22    TCP  ALLOW
```

Mixed admin ports (ports commonly associated with SMB, RDP, and SSH) across sequential targets — classic post-compromise pivoting behavior.

---

## Detection Walkthrough

### Step A: Traffic Filtering

```text
Filter: IsInternal(SrcIp) && IsInternal(DstIp) && DstPort in [445, 3389, 22]

12:00  .100 → .10:445    ✓ Internal, internal, admin port
12:01  .100 → .11:3389   ✓ Internal, internal, admin port
12:02  .100 → .12:22     ✓ Internal, internal, admin port
12:03  .100 → .13:445    ✓ Internal, internal, admin port
12:04  .100 → .14:3389   ✓ Internal, internal, admin port
12:05  .100 → .15:445    ✓ Internal, internal, admin port
12:06  .100 → .16:22     ✓ Internal, internal, admin port

Result: 7 of 7 entries pass
```

### Step B: Sliding Window Scan (Medium profile: 4 hosts / 10 min)

```text
end=0  Window [12:00] → 1 distinct host → 1 < 4 → Continue
end=1  Window [12:00-12:01] → 2 distinct hosts → 2 < 4 → Continue
end=2  Window [12:00-12:02] → 3 distinct hosts → 3 < 4 → Continue
end=3  Window [12:00-12:03] → 4 distinct hosts → 4 ≥ 4 → TRIGGERED
```

### Step C: Finding Created

The detector creates one finding and breaks. Events at 12:04, 12:05, and 12:06 are not processed further for this source.

---

## The Finding

```csharp
new Finding
{
    Category = "LateralMovement",
    Severity = Severity.High,
    SourceHost = "192.168.1.100",
    Target = "multiple internal hosts",
    TimeRangeStart = new DateTime(2024, 1, 15, 12, 0, 0),
    TimeRangeEnd = new DateTime(2024, 1, 15, 12, 3, 0),
    ShortDescription = "Lateral movement from 192.168.1.100",
    Details = "Contacted 4 internal hosts on admin ports."
}
```

---

## Profile Sensitivity

| Profile | Threshold | Triggered At | Hosts in Finding |
|---------|-----------|-------------|-----------------|
| Low (6) | 6 hosts | 12:05 (6th distinct host) | 6 hosts |
| Medium (4) | 4 hosts | 12:03 (4th distinct host) | 4 hosts |
| High (3) | 3 hosts | 12:02 (3rd distinct host) | 3 hosts |

Higher sensitivity catches the attack earlier but risks false positives from legitimate admin activity.
