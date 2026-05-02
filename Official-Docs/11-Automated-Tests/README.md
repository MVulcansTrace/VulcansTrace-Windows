# Automated Testing

This folder contains technical documentation for the automated test suite.

Documentation is organized for two audiences:

- Quick-review readers who need a fast summary of the subsystem and why it matters
- Technical reviewers who want to inspect the testing strategy, patterns, and implementation details

## Start Here

- [Expertise Snapshot](./Automated-Tests-Summary/Expertise-Snapshot.md): 1-page overview for quick review
- [Why This Matters](./Automated-Tests-In-Depth/Why-This-Matters.md): business value, security framing, and project context
- [Testing Algorithm](./Automated-Tests-In-Depth/Core-Logic-Breakdown/Testing-Algorithm.md): the five-step testing pipeline and its trade-offs
- [Design Decisions](./Automated-Tests-In-Depth/Design-Decisions.md): why key testing choices were made
- [Code Patterns](./Automated-Tests-In-Depth/Code-Patterns.md): repeatable implementation patterns that support testability
- [Attack Scenario](./Automated-Tests-In-Depth/Attack-Scenario.md): a worked example showing how tests catch detection regressions
- [Evasion and Limitations](./Automated-Tests-In-Depth/Evasion-and-Limitations.md): blind spots and improvement paths
- [Test Coverage by Threat Behavior](./Automated-Tests-In-Depth/Test-Coverage-by-Threat-Behavior.md): automated coverage for ATT&CK-related detector behavior

## System Capabilities

- Testing philosophy: balancing false-positive prevention against false-negative prevention through threshold boundary tests and comprehensive coverage
- Defense in depth: six primary test categories (unit, integration, robustness, evidence, parser, WPF) plus functional tests that catch different failure modes
- Test engineering: threshold boundary testing, statistical detection testing, cooperative cancellation, and test doubles for isolation
- Evidence integrity: cryptographic HMAC-SHA256 verification in automated tests
- Communication: explaining testing decisions in language that works for both recruiters and engineers

## Implementation Evidence

- [VulcansTrace.Tests/Engine/Detectors/](../../VulcansTrace.Tests/Engine/Detectors/): six detector test files with threshold, boundary, and scenario coverage
- [SentryAnalyzerTests.cs](../../VulcansTrace.Tests/Engine/SentryAnalyzerTests.cs): analyzer unit tests with inline test doubles
- [SentryAnalyzerIntegrationTests.cs](../../VulcansTrace.Tests/Engine/SentryAnalyzerIntegrationTests.cs): cross-detector integration tests with parameterized beacon patterns
- [SentryAnalyzerRobustnessTests.cs](../../VulcansTrace.Tests/Engine/SentryAnalyzerRobustnessTests.cs): fault-tolerance, cancellation, and high-volume tests
- [EvidenceBuilderTests.cs](../../VulcansTrace.Tests/Evidence/EvidenceBuilderTests.cs): ZIP packaging, HMAC integrity, timestamp clamping, and determinism tests
- [WindowsFirewallLogParserTests.cs](../../VulcansTrace.Tests/Core/WindowsFirewallLogParserTests.cs): parser edge-case coverage including native `pfirewall.log` rows, ignored `#Fields:` headers, ICMP placeholder ports, trailing fields, IPv6, and malformed lines
- [MainViewModelIntegrationTests.cs](../../VulcansTrace.Tests/Wpf/MainViewModelIntegrationTests.cs): full-stack WPF integration with STA thread and Dispatcher
- [FindingsViewModelTests.cs](../../VulcansTrace.Tests/Wpf/FindingsViewModelTests.cs): Novelty grouping logic and ViewModel state management
- [IntensityComparisonTests.cs](../../VulcansTrace.Tests/Engine/IntensityComparisonTests.cs): end-to-end profile behavior using isolated attacker IPs
- [ThresholdOverrideValidationTests.cs](../../VulcansTrace.Tests/Engine/ThresholdOverrideValidationTests.cs): threshold override input validation and boundary checks

