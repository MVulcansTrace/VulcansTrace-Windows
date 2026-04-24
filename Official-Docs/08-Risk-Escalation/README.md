# Risk Escalation

This folder contains technical documentation for the risk escalation engine.

Documentation is organized for two audiences:

- Quick-review readers who need a fast summary of the subsystem and why it matters
- Technical reviewers who want to inspect the correlation algorithm, trade-offs, and implementation details

## Start Here

- [Expertise Snapshot](./Risk-Escalation-Summary/Expertise-Snapshot.md): 1-page overview for quick review
- [Why This Matters](./Risk-Escalation-In-Depth/Why-This-Matters.md): business value, security framing, and project context
- [Correlation Algorithm](./Risk-Escalation-In-Depth/Core-Logic-Breakdown/Correlation-Algorithm.md): the core escalation pipeline and its trade-offs
- [Design Decisions](./Risk-Escalation-In-Depth/Design-Decisions.md): why key implementation choices were made
- [Code Patterns](./Risk-Escalation-In-Depth/Code-Patterns.md): repeatable implementation patterns that support testability
- [Attack Scenario](./Risk-Escalation-In-Depth/Attack-Scenario.md): a worked example showing how correlation escalates multi-behavior compromise signals
- [Evasion and Limitations](./Risk-Escalation-In-Depth/Evasion-and-Limitations.md): blind spots and improvement paths
- [MITRE ATT&CK Mapping](./Risk-Escalation-In-Depth/MITRE-ATTACK-Mapping.md): cross-tactic correlation against the ATT&CK framework

## System Capabilities

- Correlation engineering: combining individual detector outputs into higher-confidence compromise signals
- Security judgment: choosing host-level grouping, full-context escalation, and pipeline ordering with analyst workflow in mind
- Trade-off awareness: balancing a single hardcoded rule against extensibility, completeness, and audit gaps
- Communication: explaining correlation logic and trade-offs in language that works for both recruiters and engineers

## Implementation Evidence

- [RiskEscalator.cs](../../VulcansTrace.Engine/RiskEscalator.cs): host grouping, category matching, immutable escalation via `with`
- [SentryAnalyzer.cs](../../VulcansTrace.Engine/SentryAnalyzer.cs): pipeline integration — escalation runs before severity filtering
- [Finding.cs](../../VulcansTrace.Core/Finding.cs): immutable record with `init`-only properties
- [Severity.cs](../../VulcansTrace.Core/Severity.cs): ordered enum — Info, Low, Medium, High, Critical
- [AnalysisProfile.cs](../../VulcansTrace.Engine/AnalysisProfile.cs): `MinSeverityToShow` threshold applied after escalation
- [RiskEscalatorTests.cs](../../VulcansTrace.Tests/Engine/RiskEscalatorTests.cs): empty input, Beaconing-only, LateralMovement-only, same-host escalation, mixed hosts, already-Critical, empty SourceHost, case-insensitive, third-category escalation

