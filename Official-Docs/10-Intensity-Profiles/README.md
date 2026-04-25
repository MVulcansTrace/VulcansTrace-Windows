# Intensity Profiles

This folder contains technical documentation for the intensity profile system.

Documentation is organized for two audiences:

- Quick-review readers who need a fast summary of the subsystem and why it matters
- Technical reviewers who want to inspect the algorithm, trade-offs, and implementation details

## Start Here

- [Expertise Snapshot](./Intensity-Profiles-Summary/Expertise-Snapshot.md): 1-page overview for quick review
- [Why This Matters](./Intensity-Profiles-In-Depth/Why-This-Matters.md): business value, security framing, and project context
- [Profile Pipeline Algorithm](./Intensity-Profiles-In-Depth/Core-Logic-Breakdown/Profile-Pipeline-Algorithm.md): the four-step pipeline and its trade-offs
- [Design Decisions](./Intensity-Profiles-In-Depth/Design-Decisions.md): why key implementation choices were made
- [Code Patterns](./Intensity-Profiles-In-Depth/Code-Patterns.md): repeatable implementation patterns that support testability
- [Attack Scenario](./Intensity-Profiles-In-Depth/Attack-Scenario.md): a worked example showing how profile selection changes detection output
- [Evasion and Limitations](./Intensity-Profiles-In-Depth/Evasion-and-Limitations.md): blind spots and improvement paths
- [Detection Coverage and Profile Tuning](./Intensity-Profiles-In-Depth/Detection-Coverage-and-Profile-Tuning.md): how profile choice changes coverage across detector behaviors

## System Capabilities

- Detection engineering: translating operational context (incident response vs. routine monitoring) into tuned detection thresholds
- Security judgment: choosing which parameters stay constant and which vary by intensity, with analyst workload in mind
- Pipeline design: ordering risk escalation before severity filtering so that correlated findings survive conservative profiles
- Trade-off awareness: balancing detection sensitivity, false-positive risk, and analyst capacity across three profiles

## Implementation Evidence

- [AnalysisProfileProvider.cs](../../VulcansTrace.Engine/Configuration/AnalysisProfileProvider.cs): Simple Factory returning Low, Medium, and High profiles with all thresholds
- [AnalysisProfile.cs](../../VulcansTrace.Engine/AnalysisProfile.cs): immutable record with 20+ init-only properties controlling the built-in detector set
- [IntensityLevel.cs](../../VulcansTrace.Engine/IntensityLevel.cs): enum driving profile selection
- [SentryAnalyzer.cs](../../VulcansTrace.Engine/SentryAnalyzer.cs): pipeline orchestrator executing detectors, escalating, and filtering by severity
- [RiskEscalator.cs](../../VulcansTrace.Engine/RiskEscalator.cs): cross-detector correlation that escalates to Critical when Beaconing + LateralMovement co-occur
- [AnalysisProfileProviderTests.cs](../../VulcansTrace.Tests/Engine/AnalysisProfileProviderTests.cs): threshold values, monotonic sensitivity, constant policy ports, immutability coverage
- [SentryAnalyzerTests.cs](../../VulcansTrace.Tests/Engine/SentryAnalyzerTests.cs): severity filtering across all three intensity levels

