# Flood Detection

This folder contains technical documentation for the flood detector.

Documentation is organized for two audiences:

- Quick-review readers who need a fast summary of the subsystem and why it matters
- Technical reviewers who want to inspect the algorithm, trade-offs, and implementation details

## Start Here

- [Expertise Snapshot](./Flood-Detection-Summary/Expertise-Snapshot.md): 1-page overview for quick review
- [Why This Matters](./Flood-Detection-In-Depth/Why-This-Matters.md): business value, security framing, and project context
- [Detection Algorithm](./Flood-Detection-In-Depth/Core-Logic-Breakdown/Detection-Algorithm.md): the core detection pipeline and its trade-offs
- [Design Decisions](./Flood-Detection-In-Depth/Design-Decisions.md): why key implementation choices were made
- [Code Patterns](./Flood-Detection-In-Depth/Code-Patterns.md): repeatable implementation patterns that support testability
- [Attack Scenario](./Flood-Detection-In-Depth/Attack-Scenario.md): a worked example showing the detector catching a synthetic volumetric flood pattern
- [Evasion and Limitations](./Flood-Detection-In-Depth/Evasion-and-Limitations.md): blind spots and improvement paths
- [MITRE ATT&CK Mapping](./Flood-Detection-In-Depth/MITRE-ATTACK-Mapping.md): mapping to the ATT&CK framework

## System Capabilities

- Detection engineering: translating volumetric log patterns into actionable flood findings
- Security judgment: choosing sliding windows, per-source grouping, and severity with analyst workflow in mind
- Trade-off awareness: balancing detection coverage, false-positive risk, and performance
- Communication: explaining technical decisions in language that balances accessibility with technical precision

## Implementation Evidence

- [FloodDetector.cs](../../VulcansTrace.Engine/Detectors/FloodDetector.cs): source grouping, sliding window, threshold check, and finding creation
- [AnalysisProfile.cs](../../VulcansTrace.Engine/AnalysisProfile.cs): detector configuration model
- [AnalysisProfileProvider.cs](../../VulcansTrace.Engine/Configuration/AnalysisProfileProvider.cs): built-in Low, Medium, and High profiles
- [RiskEscalator.cs](../../VulcansTrace.Engine/RiskEscalator.cs): cross-detector correlation that escalates to Critical when Beaconing + LateralMovement co-occur
- [FloodDetectorTests.cs](../../VulcansTrace.Tests/Engine/Detectors/FloodDetectorTests.cs): above-threshold, below-threshold, disabled, empty, multi-source, time-spread, and boundary coverage
- [RiskEscalatorTests.cs](../../VulcansTrace.Tests/Engine/RiskEscalatorTests.cs): escalation and correlation scenarios

