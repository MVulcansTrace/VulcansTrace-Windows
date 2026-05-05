# Port Scan Detection

This folder contains technical documentation for the port scan detector.

Documentation is organized for two audiences:

- Quick-review readers who need a fast summary of the subsystem and why it matters
- Technical reviewers who want to inspect the algorithm, trade-offs, and implementation details

## Start Here

- [Expertise Snapshot](./Port-Scan-Detection-Summary/Expertise-Snapshot.md): 1-page overview for quick review
- [Why This Matters](./Port-Scan-Detection-In-Depth/Why-This-Matters.md): business value, security framing, and project context
- [Detection Algorithm](./Port-Scan-Detection-In-Depth/Core-Logic-Breakdown/Detection-Algorithm.md): the core detection pipeline and its trade-offs
- [Design Decisions](./Port-Scan-Detection-In-Depth/Design-Decisions.md): why key implementation choices were made
- [Code Patterns](./Port-Scan-Detection-In-Depth/Code-Patterns.md): repeatable implementation patterns that support testability
- [Attack Scenario](./Port-Scan-Detection-In-Depth/Attack-Scenario.md): a worked example showing the detector catching reconnaissance activity
- [Evasion and Limitations](./Port-Scan-Detection-In-Depth/Evasion-and-Limitations.md): blind spots and improvement paths
- [MITRE ATT&CK Mapping](./Port-Scan-Detection-In-Depth/MITRE-ATTACK-Mapping.md): mapping to the ATT&CK framework
- [Industry Context](./Port-Scan-Detection-In-Depth/Industry-Context.md): how this detection concept relates to enterprise security tools and workflows

## System Capabilities

- Detection engineering: translating raw firewall events into actionable reconnaissance findings
- Security judgment: choosing thresholds, severity, and safeguards with analyst workflow in mind
- Trade-off awareness: balancing performance, explainability, and detection coverage
- Communication: explaining technical decisions in language that balances accessibility with technical precision

## Implementation Evidence

- [PortScanDetector.cs](../../VulcansTrace.Engine/Detectors/PortScanDetector.cs): grouping, tuple counting, windowing, truncation, and finding creation
- [AnalysisProfile.cs](../../VulcansTrace.Engine/AnalysisProfile.cs): detector configuration model
- [AnalysisProfileProvider.cs](../../VulcansTrace.Engine/Configuration/AnalysisProfileProvider.cs): built-in Low, Medium, and High profiles
- [PortScanDetectorTests.cs](../../VulcansTrace.Tests/Engine/Detectors/PortScanDetectorTests.cs): above-threshold, below-threshold, multi-source, and truncation coverage
- [AnalysisProfileProviderTests.cs](../../VulcansTrace.Tests/Engine/AnalysisProfileProviderTests.cs): threshold values for each intensity level
- [RiskEscalator.cs](../../VulcansTrace.Engine/RiskEscalator.cs): cross-detector correlation that escalates to Critical when Beaconing + LateralMovement co-occur on the same host

