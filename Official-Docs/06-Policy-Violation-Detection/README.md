# Policy Violation Detection

This folder contains technical documentation for the policy violation detector.

Documentation is organized for two audiences:

- Quick-review readers who need a fast summary of the subsystem and why it matters
- Technical reviewers who want to inspect the algorithm, trade-offs, and implementation details

## Start Here

- [Expertise Snapshot](./Policy-Violation-Detection-Summary/Expertise-Snapshot.md): 1-page overview for quick review
- [Why This Matters](./Policy-Violation-Detection-In-Depth/Why-This-Matters.md): business value, security framing, and project context
- [Detection Algorithm](./Policy-Violation-Detection-In-Depth/Core-Logic-Breakdown/Detection-Algorithm.md): the core detection pipeline and its trade-offs
- [Design Decisions](./Policy-Violation-Detection-In-Depth/Design-Decisions.md): why key implementation choices were made
- [Code Patterns](./Policy-Violation-Detection-In-Depth/Code-Patterns.md): repeatable implementation patterns that support testability
- [Attack Scenario](./Policy-Violation-Detection-In-Depth/Attack-Scenario.md): a worked example showing the detector catching policy-violating egress traffic
- [Evasion and Limitations](./Policy-Violation-Detection-In-Depth/Evasion-and-Limitations.md): blind spots and improvement paths
- [MITRE ATT&CK Mapping](./Policy-Violation-Detection-In-Depth/MITRE-ATTACK-Mapping.md): mapping to the ATT&CK framework

## System Capabilities

- Detection engineering: translating firewall events into narrow egress-policy findings
- Security judgment: choosing IP classification over log fields, one-finding-per-entry for full visibility, and High severity calibrated to the threat
- Trade-off awareness: balancing detection coverage, alert fatigue risk, and performance at scale
- Communication: explaining technical decisions in language that balances accessibility with technical precision

## Implementation Evidence

- [PolicyViolationDetector.cs](../../VulcansTrace.Engine/Detectors/PolicyViolationDetector.cs): 53-line linear-scan detector with three-condition filter and structured finding output
- [AnalysisProfile.cs](../../VulcansTrace.Engine/AnalysisProfile.cs): `EnablePolicy` and `DisallowedOutboundPorts` configuration model
- [AnalysisProfileProvider.cs](../../VulcansTrace.Engine/Configuration/AnalysisProfileProvider.cs): built-in Low, Medium, and High profiles, all enabling policy detection with ports [21, 23, 445]
- [IpClassification.cs](../../VulcansTrace.Engine/Net/IpClassification.cs): RFC 1918, IPv4 loopback, and IPv6 internal/external classification
- [RiskEscalator.cs](../../VulcansTrace.Engine/RiskEscalator.cs): cross-detector correlation that escalates to Critical when Beaconing + LateralMovement co-occur
- [PolicyViolationDetectorTests.cs](../../VulcansTrace.Tests/Engine/Detectors/PolicyViolationDetectorTests.cs): 9 unit tests covering happy path, allowed-port traffic, disabled policy, empty logs, external/internal traffic, multiple violations, empty/null port lists
- [SentryAnalyzerIntegrationTests.cs](../../VulcansTrace.Tests/Engine/SentryAnalyzerIntegrationTests.cs): end-to-end pipeline validation including policy violation findings

