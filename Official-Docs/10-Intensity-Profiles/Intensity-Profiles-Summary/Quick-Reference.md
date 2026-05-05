# Quick Reference

---

## Pipeline (4 Steps)

Step A: Select Profile — Low/Medium/High → fully configured AnalysisProfile
Step B: Run Detectors — same profile passed to all 6 detectors
Step C: Escalate Findings — Beaconing + LateralMovement on same host → all findings Critical
Step D: Filter by Severity — findings below MinSeverityToShow are removed

---

## Profile Thresholds

| Parameter | Low | Medium | High |
|-----------|-----|--------|------|
| **Enable flags** | | | |
| EnablePortScan | true | true | true |
| EnableFlood | true | true | true |
| EnableLateralMovement | true | true | true |
| EnableBeaconing | true | true | true |
| EnablePolicy | true | true | true |
| EnableNovelty | **false** | true | true |
| **Port Scan** | | | |
| PortScanMinPorts | 30 | 15 | 8 |
| PortScanWindowMinutes | 5 | 5 | 5 |
| PortScanMaxEntriesPerSource | null | null | null |
| **Flood** | | | |
| FloodMinEvents | 400 | 200 | 100 |
| FloodWindowSeconds | 60 | 60 | 60 |
| **Lateral Movement** | | | |
| LateralMinHosts | 6 | 4 | 3 |
| LateralWindowMinutes | 10 | 10 | 10 |
| **Beaconing** | | | |
| BeaconMinEvents | 8 | 6 | 4 |
| BeaconStdDevThreshold | 3.0 | 5.0 | 8.0 |
| BeaconMinIntervalSeconds | 60 | 30 | 10 |
| BeaconMaxIntervalSeconds | 900 | 900 | 900 |
| BeaconMaxSamplesPerTuple | 200 | 200 | 200 |
| BeaconMinDurationSeconds | 120 | 120 | 120 |
| BeaconTrimPercent | 0.1 | 0.1 | 0.1 |
| **Policy (constant)** | | | |
| AdminPorts | [445, 3389, 22] | [445, 3389, 22] | [445, 3389, 22] |
| DisallowedOutboundPorts | [21, 23, 445] | [21, 23, 445] | [21, 23, 445] |
| **Output** | | | |
| MinSeverityToShow | High | Medium | Info |

---

## Detector Severities and Visibility

| Detector | Finding Severity | Low | Medium | High |
|----------|-----------------|-----|--------|------|
| PortScan | Medium | No* | Yes | Yes |
| Flood | High | Yes | Yes | Yes |
| LateralMovement | High | Yes | Yes | Yes |
| Beaconing | Medium | No* | Yes | Yes |
| PolicyViolation | High | Yes | Yes | Yes |
| Novelty | Low | No | No* | Yes |

\* Visible if escalated to Critical by RiskEscalator

---

## Use-Case Mapping

| Scenario | Recommended Profile | Rationale |
|----------|---------------------|-----------|
| Critical threat triage | Low | Conservative output, high-confidence findings only |
| Investigation review | Medium | Balance coverage with workload |
| Deep hunt / forensics | High | Maximize visibility and weaker signals |
| Threat hunting | High | Explore the full detection surface |
| Tuning period | High | See what the detectors can emit before narrowing |

---

## File References

| File | Purpose |
|------|---------|
| AnalysisProfileProvider.cs | Simple Factory — Low/Medium/High profiles |
| AnalysisProfile.cs | Immutable record with 20+ properties |
| IntensityLevel.cs | Enum (Low/Medium/High) |
| SentryAnalyzer.cs | Pipeline orchestrator |
| RiskEscalator.cs | Cross-detector escalation |
| AnalysisProfileProviderTests.cs | Threshold and profile tests |
| SentryAnalyzerTests.cs | Severity filtering tests |
| IntensityComparisonTests.cs | End-to-end profile behavior with isolated IPs |
| SampleData.cs | Synthetic log for WPF "Load demo data" demo |
