# Quick Reference

---

## Test Suite at a Glance

| Category | Files | Key Tests |
|----------|-------|-----------|
| Detector unit tests | 6 | Threshold boundaries, statistical detection, scenario tests |
| Analyzer unit tests | 1 | Severity filtering, risk escalation with test doubles |
| Integration tests | 1 | Composite attack, cross-detector correlation, parameterized beacons |
| Robustness tests | 1 | Crash tolerance, cancellation, high-volume (5K entries) |
| Evidence tests | 4 | HMAC integrity, ZIP structure, formatters, timestamps |
| Parser tests | 1 | Native `pfirewall.log` rows, ignored `#Fields:` headers, ICMP placeholder ports, trailing fields, IPv6, malformed lines |
| Core model tests | 1 | Domain model validation |
| Core integrity tests | 1 | SHA-256/HMAC cryptographic integrity |
| Profile tests | 1 | Intensity monotonicity, immutability |
| Risk escalator tests | 1 | Beaconing + Lateral = Critical escalation |
| IP classification tests | 1 | RFC 1918, IPv6, mapped addresses |
| WPF tests | 3 | Full-stack analyze + export, STA threading, validation rules |
| Functional tests | 1 | End-to-end smoke test with synthetic multi-pattern log input |

---

## Test Strategy Summary

| Detector Type | Examples | Test Approach |
|---------------|----------|--------------|
| Threshold | PortScan, Flood, LateralMovement | Threshold boundary (above + below) |
| Statistical | Beaconing | Statistical (interval variance + outlier trimming) |
| Rule-based | PolicyViolation | Scenario (allowed vs. disallowed) |
| Rule-based | Novelty | Scenario (one-off vs. repeated) |
| Pipeline | SentryAnalyzer | Integration (composite attack) |
| Infrastructure | EvidenceBuilder, Parser | Edge-case + integrity |

---

## Test Doubles

| Double | Location | Purpose |
|--------|----------|---------|
| `FakeDetector` | `SentryAnalyzerTests.cs` | 4 findings at different severities |
| `CrashingDetector` | `SentryAnalyzerRobustnessTests.cs` | Throws for fault tolerance |
| `WorkingDetector` | `SentryAnalyzerRobustnessTests.cs` | Continues when others crash |
| `EscalationTestDetector` | `SentryAnalyzerTests.cs` | Beaconing + LateralMovement |
| `FakeDialogService` | `Wpf/FakeDialogService.cs` | Captures dialogs, avoids modals |

---

## Threshold Test Matrix

| Detector | Below Threshold | Above Threshold | Profile (Medium) |
|----------|----------------|----------------|-----------------|
| PortScan | 5 ports | 20 ports | 15 ports |
| Beaconing | Irregular intervals | Regular 90s intervals | stdDev threshold |
| Flood | Low volume | High volume | Event count in window |
| LateralMovement | 3 hosts | 8 hosts | 4 host threshold† |

> **† Note:** LateralMovement unit tests use a custom `AnalysisProfile` with `LateralMinHosts = 6`, not the Medium profile's value of 4. The behavioral outcome is the same (3 < threshold → no finding, 8 > threshold → finding), but the threshold in the test is 6, not 4.

---

## Integration Test Findings

| Finding | Category | Severity (before escalation) |
|---------|----------|------------------------------|
| Port scan from 10.0.0.10 | PortScan | Medium |
| C2 beacon from 10.0.0.20 | Beaconing | Medium → Critical |
| Lateral movement from 10.0.0.20 | LateralMovement | High → Critical |
| Outbound SMB violation #1 | PolicyViolation | High |
| Outbound SMB violation #2 | PolicyViolation | High |

---

## MITRE ATT&CK Coverage

| Technique | ID | Detector |
|-----------|-----|----------|
| Network Service Discovery | T1046 | PortScanDetector |
| Application Layer Protocol | T1071 | BeaconingDetector |
| Remote Services | T1021 | LateralMovementDetector |
| Network Denial of Service | T1498 | FloodDetector |
| Exfiltration Over Alternative Protocol | T1048 | PolicyViolationDetector |
| *(VulcansTrace-specific)* | — | NoveltyDetector |

---

## Evasion Gaps

| Gap | Status | Priority |
|-----|--------|----------|
| Slow scanning | No test | Medium |
| Beacon jitter | Partial (outlier trim) | Medium |
| Slow-rate DoS | No test | High |
| Domain fronting | No test | High |
| Multi-channel beaconing | No test | Medium |
| Living off the land | No test | High |
| Non-admin pivoting | No test | Medium |
| Distributed scanning | Partial (multi-source) | Medium |

---

## Performance Coverage

| Volume | Status |
|--------|--------|
| 20-300 entries (unit) | Covered |
| 5,000 entries (robustness) | Covered |
| 100K+ entries (stress) | Not tested |
| Latency benchmarks | Not measured |
| Memory profiling | Not measured |

---

## File References

| File | Purpose |
|------|---------|
| `VulcansTrace.Tests/Engine/Detectors/*.cs` | 6 detector test files |
| `VulcansTrace.Tests/Engine/SentryAnalyzerTests.cs` | Analyzer with test doubles |
| `VulcansTrace.Tests/Engine/SentryAnalyzerIntegrationTests.cs` | Cross-detector correlation |
| `VulcansTrace.Tests/Engine/SentryAnalyzerRobustnessTests.cs` | Fault tolerance + cancellation |
| `VulcansTrace.Tests/Evidence/EvidenceBuilderTests.cs` | HMAC + ZIP integrity |
| `VulcansTrace.Tests/Evidence/MarkdownFormatterTests.cs` | Markdown output formatting |
| `VulcansTrace.Tests/Evidence/HtmlFormatterTests.cs` | HTML output formatting |
| `VulcansTrace.Tests/Evidence/CsvFormatterTests.cs` | CSV output formatting |
| `VulcansTrace.Tests/Core/WindowsFirewallLogParserTests.cs` | Parser edge cases |
| `VulcansTrace.Tests/Core/CoreModelsTests.cs` | Domain model validation |
| `VulcansTrace.Tests/Core/IntegrityHasherTests.cs` | SHA-256/HMAC integrity |
| `VulcansTrace.Tests/Engine/AnalysisProfileProviderTests.cs` | Profile thresholds |
| `VulcansTrace.Tests/Engine/RiskEscalatorTests.cs` | Risk escalation logic |
| `VulcansTrace.Tests/Engine/IpClassificationTests.cs` | IP classification (RFC 1918, IPv6) |
| `VulcansTrace.Tests/Wpf/MainViewModelIntegrationTests.cs` | Full-stack WPF |
| `VulcansTrace.Tests/Wpf/MainViewModelTextTests.cs` | ViewModel text display |
| `VulcansTrace.Tests/Wpf/NonNegativeIntValidationRuleTests.cs` | WPF validation rules |
