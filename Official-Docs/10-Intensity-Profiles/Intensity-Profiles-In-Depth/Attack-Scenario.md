# Attack Scenario: Seeing the Pipeline in Action

---

## The Attack

A compromised internal host (`192.168.1.100`) exhibits three behaviors simultaneously over a 10-minute window:

```text
12:00:00  192.168.1.100 → 192.168.1.10:445   TCP  ALLOW   (lateral: SMB)
12:01:00  192.168.1.100 → 192.168.1.11:3389  TCP  ALLOW   (lateral: RDP)
12:02:00  192.168.1.100 → 192.168.1.12:22    TCP  ALLOW   (lateral: SSH)
12:03:00  192.168.1.100 → 192.168.1.13:445   TCP  ALLOW   (lateral: SMB)
12:03:30  192.168.1.100 → 203.0.113.50:8443   TCP  ALLOW  (C2 beacon)
12:04:00  192.168.1.100 → 203.0.113.50:8443   TCP  ALLOW  (C2 beacon)
12:04:30  192.168.1.100 → 203.0.113.50:8443   TCP  ALLOW  (C2 beacon)
12:05:00  192.168.1.100 → 203.0.113.50:8443   TCP  ALLOW  (C2 beacon)
12:06:00  192.168.1.100 → 203.0.113.50:8443   TCP  ALLOW  (C2 beacon)
```

Mixed lateral movement on admin ports plus regular C2 beaconing to an external host — a realistic post-compromise pattern.

---

## Pipeline Walkthrough

### Step A: Profile Selection

The analyst selects **Medium** intensity for routine monitoring:

```csharp
var profile = provider.GetProfile(IntensityLevel.Medium);
// LateralMinHosts = 4, BeaconMinEvents = 6, MinSeverityToShow = Medium
```

### Step B: Detector Execution

Three detectors evaluate the traffic:

**LateralMovementDetector:**

```text
Filter: IsInternal(SrcIp) && IsInternal(DstIp) && DstPort in [445, 3389, 22]
Entries passing: 4 (the .10, .11, .12, .13 connections)

Sliding window at 12:03: 4 distinct hosts in 3 minutes ≥ 4 threshold → TRIGGERED
Finding: LateralMovement, Severity.High, Source=192.168.1.100
```

**BeaconingDetector:**

```text
Tuple: (192.168.1.100, 203.0.113.50, 8443)
Events: 5 in 2.5 minutes (12:03:30 → 12:06:00)
Check: 5 < BeaconMinEvents (6) → NOT TRIGGERED (blocked at the event count gate)
```

The beacon fails the event count gate on Medium (needs 6). BeaconingDetector also checks event duration (`BeaconMinDurationSeconds`), mean interval range (`BeaconMinIntervalSeconds`–`BeaconMaxIntervalSeconds`), and interval regularity (`BeaconStdDevThreshold`), but for this traffic the event count is the blocking gate. On High profile (`BeaconMinEvents = 4`), the 5 events pass the count gate; the 150-second duration exceeds the 120-second minimum; and after 10% outlier trimming the 30-second intervals have zero standard deviation, which passes the `BeaconStdDevThreshold = 8.0` regularity check.

**PortScanDetector:**

```text
Source 192.168.1.100: 5 distinct (DstIp, DstPort) targets
Check: 5 < PortScanMinPorts (15 on Medium) → NOT TRIGGERED
```

Too few targets to constitute a scan on Medium.

### Step C: Risk Escalation

```text
Findings for 192.168.1.100:
├── LateralMovement finding (Severity.High)

No Beaconing finding exists → no escalation triggered
Result: LateralMovement stays at Severity.High
```

If the analyst had selected **High** profile, BeaconMinEvents would be 4, the beacon would trigger, and both findings would escalate to Critical.

### Step D: Severity Filtering

```text
Profile: MinSeverityToShow = Severity.Medium
Finding: LateralMovement, Severity.High → High >= Medium → SHOWN
```

---

## Profile Sensitivity Comparison

| Profile | Lateral Hosts Threshold | Lateral Triggered? | Beacon Events Threshold | Beacon Triggered? | Escalated to Critical? | Findings Shown |
|---------|------------------------|--------------------|-----------------------|-------------------|----------------------|---------------|
| Low (6 hosts) | 6 | No (only 4 hosts) | 8 events | No (only 5 events) | No | 0 findings |
| Medium (4 hosts) | 4 | Yes | 6 events | No (only 5 events) | No | 1 finding (Lateral.High) |
| High (3 hosts) | 3 | Yes | 4 events | Yes (5 events) | Yes | 2 findings (both Critical) |

On Low profile, this attack produces no visible findings because 4 distinct hosts do not meet the 6-host threshold and 5 beacon events do not meet the 8-event threshold. This is the sensitivity trade-off in action — conservative output means some real attacks fall below the bar.

On High profile, both detectors trigger, the escalation promotes everything to Critical, and the analyst gets the strongest possible compromise signal.
