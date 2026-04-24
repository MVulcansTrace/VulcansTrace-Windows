# Novelty Detection

This folder contains technical documentation for the novelty detector.

Documentation is organized for two audiences:

- Quick-review readers who need a fast summary of the subsystem and why it matters
- Technical reviewers who want to inspect the algorithm, trade-offs, and implementation details

## Start Here

- [Expertise Snapshot](./Novelty-Detection-Summary/Expertise-Snapshot.md): 1-page overview for quick review
- [Why This Matters](./Novelty-Detection-In-Depth/Why-This-Matters.md): business value, security framing, and project context
- [Detection Algorithm](./Novelty-Detection-In-Depth/Core-Logic-Breakdown/Detection-Algorithm.md): the core detection pipeline and its trade-offs
- [Design Decisions](./Novelty-Detection-In-Depth/Design-Decisions.md): why key implementation choices were made
- [Code Patterns](./Novelty-Detection-In-Depth/Code-Patterns.md): repeatable implementation patterns that support testability
- [Attack Scenario](./Novelty-Detection-In-Depth/Attack-Scenario.md): a worked example showing the detector catching one-off connection anomalies
- [Evasion and Limitations](./Novelty-Detection-In-Depth/Evasion-and-Limitations.md): blind spots and improvement paths
- [MITRE ATT&CK Mapping](./Novelty-Detection-In-Depth/MITRE-ATTACK-Mapping.md): mapping to the ATT&CK framework

## System Capabilities

- Detection engineering: translating firewall events into structured weak-signal findings for forensic review
- Security judgment: calibrating severity, profile-gating, and cross-detector escalation with analyst workflow in mind
- Trade-off awareness: balancing detection coverage, false-positive risk, and performance at O(n) complexity
- Communication: explaining technical decisions in language that balances accessibility with technical precision

## Implementation Evidence

- [NoveltyDetector.cs](../../VulcansTrace.Engine/Detectors/NoveltyDetector.cs): guard clauses, external filtering, tuple counting, singleton finding creation
- [AnalysisProfile.cs](../../VulcansTrace.Engine/AnalysisProfile.cs): detector configuration model including `EnableNovelty` flag
- [AnalysisProfileProvider.cs](../../VulcansTrace.Engine/Configuration/AnalysisProfileProvider.cs): built-in Low, Medium, and High profiles that gate novelty by intensity
- [RiskEscalator.cs](../../VulcansTrace.Engine/RiskEscalator.cs): cross-detector correlation that escalates to Critical when Beaconing + LateralMovement co-occur on the same host
- [NoveltyDetectorTests.cs](../../VulcansTrace.Tests/Engine/Detectors/NoveltyDetectorTests.cs): singleton detection, repeated-destination, disabled, empty, internal-only, mixed, and multi-port coverage
- [RiskEscalatorTests.cs](../../VulcansTrace.Tests/Engine/RiskEscalatorTests.cs): escalation scenarios including Novelty findings promoted to Critical
- [SentryAnalyzerIntegrationTests.cs](../../VulcansTrace.Tests/Engine/SentryAnalyzerIntegrationTests.cs): end-to-end intensity-based visibility tests confirming standalone Novelty appears at High intensity, while Medium filters Low-severity Novelty unless escalation changes severity

