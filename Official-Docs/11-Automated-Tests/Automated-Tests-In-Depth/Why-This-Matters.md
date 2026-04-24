# Why This Matters

---

## The Security Problem

Security detection tools have asymmetric failure costs:

- A **false positive** (Type I error) wastes analyst time and erodes trust in the tool over time
- A **false negative** (Type II error) means a real attack goes undetected, which can lead to a data breach

Both failure modes are dangerous, but they require different testing strategies. Preventing false positives demands **below-threshold tests** that verify the detector stays silent on normal traffic. Preventing false negatives demands **above-threshold tests** that verify the detector fires on attack traffic. Either test alone is insufficient — a detector that never fires passes every below-threshold test, and a detector that always fires passes every above-threshold test.

---

## Implementation Overview

The **defense-in-depth test suite** for VulcansTrace covers the six detectors, analysis pipeline, and evidence packaging layer with distinct test strategies for each failure mode:

The test suite covers:

1. **Detector unit tests** — threshold boundary tests for statistical detectors, scenario tests for rule-based detectors
2. **Pipeline integration tests** — cross-detector correlation, severity escalation, parameterized beacon patterns
3. **Robustness tests** — fault tolerance (crashing detectors), cooperative cancellation, high-volume correctness
4. **Evidence integrity tests** — HMAC-SHA256 signing, ZIP packaging, timestamp clamping, deterministic output
5. **Parser edge-case tests** — native `pfirewall.log` rows, ignored `#Fields:` headers, ICMP placeholder ports, trailing fields, IPv6, malformed lines, line-ending and whitespace edge cases
6. **WPF integration tests** — full-stack analysis + export with STA thread and Dispatcher

**Key metrics:**

- 23 test files across Core, Engine, Evidence, Wpf, and functional layers
- 189 test methods covering unit, integration, robustness, and functional categories
- 6 detector test files with threshold, statistical, and scenario coverage
- 1 integration test file with composite attack scenarios across all detectors
- 1 robustness test file with fault-tolerance and cancellation coverage
- Evidence tests verify cryptographic HMAC integrity

---

## Operational Benefits

| Capability | Business Value |
|-----------|----------------|
| Symmetric failure testing | Prevents both false positives (wasted analyst time) and false negatives (missed attacks) |
| Defense in depth test categories | Different test types catch different failure modes |
| Test isolation via fakes | Tests survive refactoring; focus on outputs, not implementation details |
| Evidence integrity verification | Tamper-evident packages support post-export integrity checks |
| Cooperative cancellation | Analysts control long-running operations |

---

## Security Principles Applied

| Principle | Where It Appears |
|-----------|-----------------|
| **Symmetric failure testing** | Every statistical detector has both below-threshold and above-threshold tests |
| **Defense in depth** | Six primary test categories (unit, integration, robustness, evidence, parser, WPF) plus functional tests catch different failure modes |
| **Isolation via test doubles** | Analyzer tests use fakes to test orchestration independent of detector logic |
| **Evidence integrity** | HMAC-SHA256 verification ensures tamper-evident evidence packages |
| **Cooperative cancellation** | Analysts can abort long-running analysis mid-stream without data corruption |
| **Documented limitations** | Evasion gaps, cloud-scale limitations, and missing stress tests are documented |

---

## Implementation Evidence

- [PortScanDetectorTests.cs](../../../VulcansTrace.Tests/Engine/Detectors/PortScanDetectorTests.cs): above-threshold, below-threshold, multi-source, truncation, and disabled-state coverage (285 lines, 7 tests)
- [BeaconingDetectorTests.cs](../../../VulcansTrace.Tests/Engine/Detectors/BeaconingDetectorTests.cs): regular intervals, irregular intervals, outlier trimming, sample cap, mixed traffic (552 lines, 12 tests)
- [SentryAnalyzerIntegrationTests.cs](../../../VulcansTrace.Tests/Engine/SentryAnalyzerIntegrationTests.cs): composite signals across all detectors with RiskEscalator correlation (206 lines, 3 tests)
- [SentryAnalyzerRobustnessTests.cs](../../../VulcansTrace.Tests/Engine/SentryAnalyzerRobustnessTests.cs): crashing detector, cancellation, high-volume (109 lines, 3 tests)
- [EvidenceBuilderTests.cs](../../../VulcansTrace.Tests/Evidence/EvidenceBuilderTests.cs): HMAC integrity, ZIP structure, timestamp clamping, determinism (776 lines, 21 tests)
- [WindowsFirewallLogParserTests.cs](../../../VulcansTrace.Tests/Core/WindowsFirewallLogParserTests.cs): native `pfirewall.log` rows, ignored `#Fields:` headers, ICMP placeholder ports, trailing fields, IPv6, malformed lines, timestamp variants, and line-ending edge cases (591 lines, 27 tests)
- [MainViewModelIntegrationTests.cs](../../../VulcansTrace.Tests/Wpf/MainViewModelIntegrationTests.cs): full-stack analyze + export with STA thread, including analyzed-log snapshot export consistency (502 lines, 5 tests)

---

## Elevator Pitch

> *"The defense-in-depth test suite proves that every detector triggers when it should and stays silent when it should not — addressing the asymmetric failure costs of security detection tools where false positives waste analyst time and false negatives mean missed attacks.*
>
> *Statistical detectors like PortScan, Beaconing, Flood, and LateralMovement get threshold boundary tests: below-threshold to prevent false positives, above-threshold to ensure detection fires. Rule-based detectors like PolicyViolation and Novelty get scenario tests for allowed versus disallowed traffic.*
>
> *The analyzer is isolated from detector logic using test doubles — fake implementations that return predictable findings — because when testing orchestration, real detector logic is a distraction. Integration tests run composite attack logs through all six detectors plus the RiskEscalator to verify that Beaconing + LateralMovement from the same host escalates to Critical severity.*
>
> *Robustness tests verify that a crashing detector does not take down the pipeline, that cooperative cancellation works, and that 5,000-entry logs produce correct results. Evidence integrity tests verify the HMAC-SHA256 signature on evidence packages — the signature proves the manifest has not been tampered with.*
>
> *Every testing decision is grounded in the specific failure mode it prevents. The suite is not exhaustive — the gaps are documented explicitly, including slow-scanning evasion, missing stress tests, and cloud-scale limitations."*

---

## Security Takeaways

1. **Symmetric failure testing is non-negotiable** — both below-threshold and above-threshold tests are needed; either one alone is insufficient
2. **Multiple test categories catch different bugs** — unit (logic), integration (orchestration), robustness (crashes), evidence (crypto), parser (edge cases), WPF (full-stack)
3. **Test doubles isolate concerns** — analyzer behavior is tested independently of detector logic
4. **Evidence integrity is testable** — HMAC signatures can be verified programmatically
5. **Documented limitations matter** — documenting gaps in test coverage is as important as documenting coverage

