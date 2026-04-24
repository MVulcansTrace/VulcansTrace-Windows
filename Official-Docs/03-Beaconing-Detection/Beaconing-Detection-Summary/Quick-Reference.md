# Quick Reference

---

## Detection Algorithm (9 Steps)

Step A: Toggle Gate — skip if EnableBeaconing is false or entries are empty
Step B: Group by (SrcIp, DstIp, DstPort) — isolate each channel
Step C: Chronological sort + cap at BeaconMaxSamplesPerTuple (tail)
Step D: Skip if count < BeaconMinEvents
Step E: Skip if duration < BeaconMinDurationSeconds
Step F: Compute inter-arrival intervals in seconds
Step G: Symmetric outlier trimming at BeaconTrimPercent
Step H: Mean interval bounds gate — reject if outside [Min, Max]
Step I: StdDev threshold gate — emit Finding if ≤ threshold

> **Note:** A defensive zero-intervals guard (`if (intervals.Count == 0) continue;`) exists between Steps F and G in the code. It is unreachable with default profiles (MinEvents ≥ 4 guarantees ≥ 3 intervals) and is not counted as a primary algorithm step.

---

## Configuration Parameters

| Parameter | Low | Medium | High |
|-----------|-----|--------|------|
| EnableBeaconing | true | true | true |
| BeaconMinEvents | 8 | 6 | 4 |
| BeaconStdDevThreshold | 3.0 | 5.0 | 8.0 |
| BeaconMinIntervalSeconds | 60 | 30 | 10 |
| BeaconMaxIntervalSeconds | 900 | 900 | 900 |
| BeaconMaxSamplesPerTuple | 200 | 200 | 200 |
| BeaconMinDurationSeconds | 120 | 120 | 120 |
| BeaconTrimPercent | 0.1 | 0.1 | 0.1 |

---

## Downstream Pipeline

```text
BeaconingDetector (Medium) → RiskEscalator → MinSeverityToShow filter
```

Beaconing alone stays Medium. Beaconing + LateralMovement on same host → Critical.

---

## Finding Structure

| Field | Value |
|-------|-------|
| Category | "Beaconing" |
| Severity | Medium (Critical when correlated with LateralMovement) |
| SourceHost | Source IP |
| Target | "{DstIp}:{DstPort}" |
| TimeRangeStart | First beacon timestamp |
| TimeRangeEnd | Last beacon timestamp |
| ShortDescription | "Regular beaconing from {SrcIp}" |
| Details | "Average interval ~Xs, std dev ~Ys over N events." |

---

## Complexity

| Metric | Value |
|--------|-------|
| Time (worst) | O(n log n) |
| Time (average) | O(n log(n/t)) |
| Space | O(n) |

---

## MITRE ATT&CK

| Scenario | Technique |
|----------|-----------|
| Analyst-mapped C2 over application layer protocols | T1071 |
| Analyst-mapped C2 over HTTP/HTTPS | T1071.001 |
| Analyst-mapped C2 over DNS | T1071.004 |
| Analyst-mapped C2 on non-standard port | T1571 |

> **Note:** These are analyst-applied mappings based on surrounding evidence. The detector itself analyzes timing on `(SrcIp, DstIp, DstPort)` tuples and does not classify HTTP, DNS, FTP, mail, or port semantics directly. The full mapping discussion is in the In-Depth MITRE-ATTACK-Mapping file.

---

## Key Formulas

Population StdDev = sqrt(Sum((x - mu)^2) / n)
TrimCount = Ceiling(n * TrimPercent)
CV (enhancement, not yet implemented) = StdDev / Mean

---

## Evasion Summary

| Technique | Status | Countermeasure |
|-----------|--------|---------------|
| Jitter-tolerant malware | Depends on profile | Higher sensitivity profiles, coefficient of variation |
| Domain flux | Missed | Cross-tuple correlation by source IP + timing |
| DNS tunneling | Missed | DNS-specific analysis layer |
| No payload inspection | Missed | Deep packet inspection integration |
| Single-host scope | Missed | Subnet-level correlation |

---

## File References

| File | Purpose |
|------|---------|
| BeaconingDetector.cs | Detector implementation |
| IDetector.cs | Strategy interface |
| Finding.cs | Output model |
| AnalysisProfile.cs | Configuration (7 thresholds + 1 toggle) |
| AnalysisProfileProvider.cs | Low/Medium/High presets |
| RiskEscalator.cs | Downstream escalation |
| BeaconingDetectorTests.cs | Test coverage (12 methods) |
| RiskEscalatorTests.cs | Escalation coverage |
