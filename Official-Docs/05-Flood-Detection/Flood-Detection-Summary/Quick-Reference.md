# Quick Reference

---

## Detection Algorithm (5 Steps)

Step A: Toggle Gate — Skip detection when EnableFlood is false or input is empty
Step B: Group — Group entries by source IP for independent analysis
Step C: Sort — Sort each group chronologically (required for sliding window)
Step D: Slide & Check — Two-pointer window, count events, check threshold
Step E: Create Finding — Package as structured alert, break per source

---

## Configuration Parameters

| Parameter | Low | Medium | High |
|-----------|-----|--------|------|
| EnableFlood | true | true | true |
| FloodMinEvents | 400 | 200 | 100 |
| FloodWindowSeconds | 60 | 60 | 60 |

---

## Downstream Pipeline

```text
FloodDetector (High)
    → RiskEscalator (High → Critical if Beaconing + LateralMovement are also present for the same host)
    → MinSeverityToShow filter (visible in all built-in profiles)
```

---

## Finding Structure

| Field | Value |
|-------|-------|
| Category | "Flood" |
| Severity | High (Critical if correlated) |
| SourceHost | Source IP |
| Target | "multiple hosts/ports" (descriptive label, not analyzed) |
| TimeRangeStart | First event in window |
| TimeRangeEnd | Last event in window |
| ShortDescription | "Flood detected from {srcIp}" |
| Details | "Detected N events within {FloodWindowSeconds} seconds." |

---

## Complexity

| Metric | Value |
|--------|-------|
| Time (group + sort) | O(n log n) |
| Time (per source window scan) | O(n) |
| Space | O(n) |
| Early exit | Per source after first detection |

---

## MITRE ATT&CK

| Technique | ID | Coverage |
|-----------|-----|----------|
| Network Denial of Service | T1498 | Partial — event count is a proxy, not bandwidth measurement |
| Direct Network Flood | T1498.001 | Partial — single-source bursts caught; destination concentration and distributed floods are not analyzed |
| Reflection Amplification | T1498.002 | Contextual only |
| OS Exhaustion Flood | T1499.001 | Adjacent/contextual |
| Service Exhaustion Flood | T1499.002 | Adjacent/contextual |

---

## Evasion Summary

| Technique | Status | Countermeasure |
|-----------|--------|---------------|
| Rate limiting | Missed | Cumulative tracking over longer windows |
| DDoS (distributed) | Missed | Destination aggregation |
| Pulsed attacks | Missed | Burst-pattern analysis |
| Protocol mixing | Still detected | N/A |
| Spoofed sources | Partial | Destination or timing correlation |

---

## File References

| File | Purpose |
|------|---------|
| FloodDetector.cs | Detector implementation |
| IDetector.cs | Strategy interface |
| AnalysisProfile.cs | Configuration model |
| AnalysisProfileProvider.cs | Low/Medium/High presets |
| RiskEscalator.cs | Cross-detector escalation |
| FloodDetectorTests.cs | Unit test coverage |
| RiskEscalatorTests.cs | Escalation test coverage |

---

## Test Coverage

| Test | Scenario |
|------|----------|
| `Detect_WithFloodAboveThreshold_ReturnsFinding` | 250 events in 60s -> 1 finding |
| `Detect_WithFloodBelowThreshold_ReturnsNoFindings` | 50 events in 60s -> no findings |
| `Detect_WithFloodDisabled_ReturnsNoFindings` | 250 events, flood disabled -> no findings |
| `Detect_WithEmptyLog_ReturnsNoFindings` | Empty input -> no findings |
| `Detect_WithMultipleSourceIps_ReturnsFindingsForEach` | Two flooding sources -> 2 findings |
| `Detect_WithEventsSpreadOutOverTime_ReturnsNoFindings` | 250 events over ~125s -> no findings |
| `Detect_WhenExactlyAtThreshold_CreatesFinding` | Exactly 200 events -> 1 finding |
| `Detect_WhenOneBelowThreshold_ReturnsNoFindings` | 199 events -> no findings |
