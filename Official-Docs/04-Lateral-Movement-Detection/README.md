# Lateral Movement Detection

This folder contains technical documentation for the lateral movement detector.

Documentation is organized for two audiences:

- Quick-review readers who need a fast summary of the subsystem and why it matters
- Technical reviewers who want to inspect the algorithm, trade-offs, and implementation details

## Start Here

- [Expertise Snapshot](./Lateral-Movement-Detection-Summary/Expertise-Snapshot.md): 1-page overview for quick review
- [Why This Matters](./Lateral-Movement-Detection-In-Depth/Why-This-Matters.md): business value, security framing, and project context
- [Detection Algorithm](./Lateral-Movement-Detection-In-Depth/Core-Logic-Breakdown/Detection-Algorithm.md): the core detection pipeline and its trade-offs
- [Design Decisions](./Lateral-Movement-Detection-In-Depth/Design-Decisions.md): why key implementation choices were made
- [Code Patterns](./Lateral-Movement-Detection-In-Depth/Code-Patterns.md): repeatable implementation patterns that support testability
- [Attack Scenario](./Lateral-Movement-Detection-In-Depth/Attack-Scenario.md): a worked example showing the detector catching a synthetic post-compromise lateral-movement pattern
- [Evasion and Limitations](./Lateral-Movement-Detection-In-Depth/Evasion-and-Limitations.md): blind spots and improvement paths
- [MITRE ATT&CK Mapping](./Lateral-Movement-Detection-In-Depth/MITRE-ATTACK-Mapping.md): mapping to the ATT&CK framework

## System Capabilities

- Detection engineering: translating firewall events into actionable post-compromise findings
- Security judgment: choosing sliding windows, admin-port filtering, and severity with analyst workflow in mind
- Trade-off awareness: balancing detection coverage, false-positive risk, and performance
- Communication: explaining technical decisions in language that balances accessibility with technical precision

## Implementation Evidence

- [LateralMovementDetector.cs](../../VulcansTrace.Engine/Detectors/LateralMovementDetector.cs): traffic filtering, sliding window, distinct-host counting, and finding creation
- [AnalysisProfile.cs](../../VulcansTrace.Engine/AnalysisProfile.cs): detector configuration model
- [AnalysisProfileProvider.cs](../../VulcansTrace.Engine/Configuration/AnalysisProfileProvider.cs): built-in Low, Medium, and High profiles
- [RiskEscalator.cs](../../VulcansTrace.Engine/RiskEscalator.cs): cross-detector correlation that escalates to Critical when Beaconing + LateralMovement co-occur
- [LateralMovementDetectorTests.cs](../../VulcansTrace.Tests/Engine/Detectors/LateralMovementDetectorTests.cs): above-threshold, below-threshold, disabled-flag, empty-input, multi-source, external-traffic, non-admin-port, and time-spread coverage
- [RiskEscalatorTests.cs](../../VulcansTrace.Tests/Engine/RiskEscalatorTests.cs): escalation and correlation scenarios

