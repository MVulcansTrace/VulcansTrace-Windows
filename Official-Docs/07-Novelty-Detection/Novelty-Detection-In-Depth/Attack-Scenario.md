# Attack Scenario: Watch It Catch a Singleton Connection

---

## The Scenario

An internal workstation (`192.168.1.50`) makes several connections in quick succession:

```text
Time                  SrcIp          DstIp          DstPort
2024-01-15 10:00:01  192.168.1.50   203.0.113.42   443
2024-01-15 10:00:02  192.168.1.50   203.0.113.42   443    (same tuple)
2024-01-15 10:00:03  192.168.1.50   198.51.100.7   8443   (unique)
2024-01-15 10:00:04  192.168.1.50   192.168.1.10   445    (internal)
```

Mixed traffic: a repeated connection, a one-time external connection, and an internal connection.

---

## Detection Walkthrough

### Step A: Guard Clauses

```text
EnableNovelty?  → true (assumes High intensity; Medium also enables novelty but filters out its Low-severity findings via MinSeverityToShow)  ✓ PASS
entries.Count?  → 4 > 0                           ✓ PASS
externalEntries.Count? → 3 > 0                    ✓ PASS
```

### Step B: External Filter

```text
10:00:01  192.168.1.50 → 203.0.113.42:443    ✓ External
10:00:02  192.168.1.50 → 203.0.113.42:443    ✓ External
10:00:03  192.168.1.50 → 198.51.100.7:8443   ✓ External
10:00:04  192.168.1.50 → 192.168.1.10:445    ✗ Internal → filtered

Result: 3 of 4 entries pass
```

### Step C: Tuple Counting

```text
("203.0.113.42", 443)  → count = 2
("198.51.100.7", 8443) → count = 1  ← NOVELTY
```

### Step D: Singleton Emission

Only entry 3 (198.51.100.7:8443) has count == 1. Entry 1 and 2 are skipped (count = 2).

---

## The Finding

```csharp
new Finding
{
    Category = "Novelty",
    Severity = Severity.Low,
    SourceHost = "192.168.1.50",
    Target = "198.51.100.7:8443",
    TimeRangeStart = new DateTime(2024, 1, 15, 10, 0, 3),
    TimeRangeEnd = new DateTime(2024, 1, 15, 10, 0, 3),
    ShortDescription = "Novel external destination",
    Details = "Single observed connection to 198.51.100.7:8443."
}
```

One finding. One singleton. One signal for investigation.

---

## Alternative Scenarios

### Scenario A: Attacker Makes Multiple Beacons

```text
192.168.1.50 → 203.0.113.42:443  (5 times, 60-second intervals)
Result: count = 5 → not a singleton → NO FINDING
```

The attacker's regular beaconing is invisible to Novelty. With 5 evenly-spaced connections at High intensity (BeaconMinEvents = 4), BeaconingDetector would flag the periodic pattern as C2 behavior.

### Scenario B: Fast Flux DNS

```text
192.168.1.50 → 198.51.100.7:443  (once)
192.168.1.50 → 198.51.100.8:443  (once)
Result: count = 1 each → TWO FINDINGS
```

Rotating infrastructure creates multiple singletons. Novelty flags each one but cannot determine they are related.

### Scenario C: Legitimate One-Time Download

```text
192.168.1.50 → 104.16.132.229:443  (once)
Result: count = 1 → ONE FINDING
```

The analyst investigates and determines it is a legitimate software download. The finding served its purpose — it surfaced the signal for review.

