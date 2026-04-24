# Attack Scenario: Watch It Catch a Synthetic Flood

---

## The Attack

A source host (`10.0.0.5`) floods multiple targets with 250 connection events in ~50 seconds:

```text
12:00:00.000  10.0.0.5 -> 192.168.1.1:80   TCP  ALLOW
12:00:00.200  10.0.0.5 -> 192.168.1.2:443  TCP  ALLOW
12:00:00.400  10.0.0.5 -> 192.168.1.1:80   TCP  ALLOW
12:00:00.600  10.0.0.5 -> 192.168.1.3:25   TCP  ALLOW
12:00:00.800  10.0.0.5 -> 192.168.1.2:443  TCP  ALLOW
... (246 more events to various targets)
12:00:39.600  10.0.0.5 -> 192.168.1.1:80   TCP  ALLOW
12:00:39.800  10.0.0.5 -> 192.168.1.2:443  TCP  ALLOW
```

Various targets from a single source — classic volumetric flood behavior.

---

## Detection Walkthrough

### Step A: Source Grouping and Chronological Sort

```text
Groups created:
  10.0.0.5       -> [250 events, sorted by timestamp]
  10.0.0.6       -> [15 events]
  192.168.1.1    -> [8 events]
```

Only `10.0.0.5` has enough events to potentially trigger. The other groups are harmless.

### Step B: Sliding Window Scan & Threshold Check (Medium profile: 200 events / 60 seconds)

```text
end=0    Window [12:00:00.000]                  -> 1 event   -> Continue
end=50   Window [12:00:00.000 - 12:00:10.000]  -> 51 events -> Continue
end=100  Window [12:00:00.000 - 12:00:20.000]  -> 101 events -> Continue
end=150  Window [12:00:00.000 - 12:00:30.000]  -> 151 events -> Continue
end=199  Window [12:00:00.000 - 12:00:39.800]  -> 200 events -> THRESHOLD MET (200 >= 200)
```

### Step C: Finding Created

The detector creates one finding and breaks. The remaining 50 events (200-249) are not processed further for this source.

---

## The Finding

```text
Category:          Flood
Severity:          High
SourceHost:        10.0.0.5
Target:            multiple hosts/ports
TimeRangeStart:    12:00:00.000
TimeRangeEnd:      12:00:39.800
ShortDescription:  Flood detected from 10.0.0.5
Details:           Detected 200 events within 60 seconds.
```

---

## Profile Sensitivity

| Profile | Threshold | Triggered At | Events in Finding |
|---------|-----------|-------------|-------------------|
| Low (400) | 400 events | Not triggered (250 < 400) | No finding |
| Medium (200) | 200 events | 12:00:39.800 (200th event) | 200 events |
| High (100) | 100 events | 12:00:19.800 (100th event) | 100 events |

Higher sensitivity catches the attack sooner but risks flagging legitimate traffic bursts.
