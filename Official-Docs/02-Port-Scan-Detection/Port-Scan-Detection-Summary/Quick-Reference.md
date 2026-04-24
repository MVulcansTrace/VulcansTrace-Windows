# Quick Reference

---

## Core Metrics

| Metric | Value |
|--------|-------|
| Detector | `PortScanDetector` |
| Signal | Distinct `(DstIp, DstPort)` tuples per source |
| Output model | `Finding` |
| Fixed severity | `Severity.Medium` |
| Default medium threshold | 15 distinct targets in 5 minutes |
| Resource protection | Optional truncation with warnings in custom profiles |

---

## Detection Algorithm (5 Steps)

Step A: Toggle Gate — skip if EnablePortScan is false or entries are empty
Step B: Group by Source IP -> Order each group by Timestamp
Step C: Count distinct (DstIp, DstPort) tuples -> Skip if below threshold
Step D: Divide into fixed time buckets
Step E: Count per bucket -> Create Finding if at or above threshold

---

## Configuration Parameters

| Parameter | Low | Medium | High |
|-----------|-----|--------|------|
| EnablePortScan | true | true | true |
| PortScanMinPorts | 30 | 15 | 8 |
| PortScanWindowMinutes | 5 | 5 | 5 |
| PortScanMaxEntriesPerSource | null | null | null |

Built-in profiles leave truncation disabled. A custom profile can set `PortScanMaxEntriesPerSource`, which bounds per-source work but can hide later evidence for that source.

---

## Downstream Pipeline

```text
PortScanDetector (Medium) → RiskEscalator → MinSeverityToShow filter
```

PortScan alone stays Medium. Beaconing + LateralMovement on same host → all findings (including PortScan) escalate to Critical.

---

## Finding Structure

| Field | Value |
|-------|-------|
| Category | "PortScan" |
| Severity | Medium (Critical when Beaconing + LateralMovement co-occur on same host) |
| SourceHost | Source IP |
| Target | "multiple hosts/ports" |
| TimeRangeStart | Earliest entry timestamp in window |
| TimeRangeEnd | Latest entry timestamp in window |
| ShortDescription | "Port scan detected from {srcIp}" |
| Details | "Detected N distinct destinations within W minutes." |

---

## Complexity

| Metric | Value |
|--------|-------|
| Time (worst) | O(n log n) |
| Space | O(n) |

---

## MITRE ATT&CK

| Scenario | Technique |
|----------|-----------|
| External scanning | T1595 (`T1595.001` for range-based IP-block scanning) |
| Internal enumeration | T1046 |

---

## Evasion Summary

| Technique | Status | Countermeasure |
|-----------|--------|---------------|
| Slow scanning | Missed | Cumulative tracking across windows |
| Distributed scanning | Missed | Subnet/ASN/timing correlation |
| Bucket-boundary split | Missed | Sliding or overlapping windows |
| Port decoys | Often still detected | Weighted scoring for context |
| SYN stealth | Depends on telemetry | Connection state analysis |

---

## File References

| File | Purpose |
|------|---------|
| PortScanDetector.cs | Detector implementation |
| IDetector.cs | Strategy interface |
| Finding.cs | Output model |
| AnalysisProfile.cs | Configuration |
| RiskEscalator.cs | Downstream escalation |
| PortScanDetectorTests.cs | Test coverage |
