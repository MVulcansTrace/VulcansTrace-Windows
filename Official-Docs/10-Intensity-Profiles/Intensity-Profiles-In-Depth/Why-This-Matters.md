# Why This Matters

---

## The Security Problem

Security operations teams face a fundamental tension: catch everything and drown in false positives, or filter aggressively and miss real attacks. The right sensitivity depends on the operational context.

| Context | What the Analyst Needs | Wrong Sensitivity Means |
|---------|----------------------|------------------------|
| Active incident response | Every possible indicator | Missed attacker activity |
| Routine 24/7 monitoring | Balanced coverage and workload | Alert fatigue from noise |
| Conservative triage / low-noise review | High-confidence findings only | False positives waste time and attention |

A port scan that triggers at 8 distinct `(DstIp, DstPort)` targets during a breach is critical intelligence. The same threshold during routine monitoring would flood the queue with false positives from network scanners and monitoring tools.

---

## Implementation Overview

The **three-tier intensity profile system** in VulcansTrace enables context-driven detection sensitivity without manual threshold tuning:

The system:

1. **Maps an intensity level** (Low, Medium, High) to a fully configured `AnalysisProfile` via a Simple Factory (`AnalysisProfileProvider`)
2. **Tunes detector thresholds** per profile — port scan sensitivity (30/15/8 distinct `(DstIp, DstPort)` targets), flood thresholds (400/200/100 events), lateral movement hosts (6/4/3), and beaconing parameters
3. **Controls detector enablement** — Novelty detection is disabled on Low because singleton external destinations in the current dataset are too noisy for conservative output
4. **Filters output by severity** — Low shows only High and Critical findings, Medium adds Medium-severity (Low-severity findings remain hidden), High shows everything including Info and Low severity
5. **Orders escalation before filtering** — RiskEscalator promotes correlated findings to Critical before the severity filter, ensuring compromise indicators survive even conservative profiles

---

## Operational Benefits

| Capability | Business Value |
|-----------|----------------|
| One-selection sensitivity switching | No manual threshold tuning — Low/Medium/High maps to complete profiles |
| Context-driven detection | Same engine serves triage, routine monitoring, and deep hunting |
| Alert fatigue prevention | Conservative profiles filter noise; aggressive profiles show everything |
| Escalation before filtering | Correlated compromise indicators survive even conservative profiles |
| Constant policy ports | Organizational policy decisions are separate from sensitivity tuning |

---

## Security Principles Applied

| Principle | Where It Appears |
|-----------|-----------------|
| **Defense in depth** | Profile selects thresholds, detectors apply them, RiskEscalator adds correlation, severity filter controls output |
| **Least surprise** | Escalation runs before filtering so correlated findings always survive, even on conservative profiles |
| **Separation of concerns** | Policy ports (admin, disallowed outbound) are constant across profiles because they represent organizational decisions, not sensitivity tuning |
| **Fail open toward visibility** | High profile shows everything including Info-severity findings; Low filters conservatively but never hides escalated findings |
| **Operational alignment** | Profile selection can be matched to different SOC work modes: conservative triage, balanced investigation, and deep hunting |

---

## Implementation Evidence

- [AnalysisProfileProvider.cs](../../../VulcansTrace.Engine/Configuration/AnalysisProfileProvider.cs): Simple Factory with all three profiles and their thresholds
- [AnalysisProfile.cs](../../../VulcansTrace.Engine/AnalysisProfile.cs): immutable record with 20+ detector configuration properties
- [SentryAnalyzer.cs](../../../VulcansTrace.Engine/SentryAnalyzer.cs): pipeline orchestrator selecting the profile, running detectors, escalating findings, and filtering by severity
- [RiskEscalator.cs](../../../VulcansTrace.Engine/RiskEscalator.cs): escalation before filtering so Critical findings survive `MinSeverityToShow`
- [AnalysisProfileProviderTests.cs](../../../VulcansTrace.Tests/Engine/AnalysisProfileProviderTests.cs): threshold values, monotonic sensitivity, constant policy ports
- [SentryAnalyzerTests.cs](../../../VulcansTrace.Tests/Engine/SentryAnalyzerTests.cs): severity filtering verified across Low, Medium, and High intensity

---

## Elevator Pitch

> *"The three-tier intensity profile system enables the same detection engine to serve conservative triage, routine investigation, and deep hunting — making sensitivity switching a one-selection operation instead of a 20-parameter configuration exercise.*
>
> *The system uses a Simple Factory — `AnalysisProfileProvider` — that maps Low, Medium, or High intensity to a fully configured profile. Low gives conservative detection: port scans need 30 distinct `(DstIp, DstPort)` targets, Novelty detection is off, and only High/Critical findings appear. Medium is the balanced middle profile. High turns everything up: port scans trigger at 8 distinct targets, Novelty is on, and all severities are visible.*
>
> *Time windows stay constant across profiles because attacks don't get faster when you select High — what changes is the threshold of what counts as suspicious. Policy port lists stay constant because they represent organizational rules, not sensitivity settings. The only detector that gets disabled is Novelty on Low, because singleton external destinations in the current dataset are inherently noisy.*
>
> *The critical pipeline ordering is escalation before filtering. When a host has both Beaconing and LateralMovement findings, the RiskEscalator ensures every finding for that host reaches Critical severity — findings below Critical are promoted, and those already at Critical pass through unchanged. That happens before the severity filter runs, so even on Low profile, the correlated findings survive. This means conservative output doesn't hide compromise indicators."*

---

## Security Takeaways

1. **Context determines sensitivity** — the right threshold depends on whether you are hunting a breach or reporting to executives
2. **Policy is not sensitivity** — admin ports and disallowed outbound ports are organizational decisions that should not change with the intensity level
3. **Escalation before filtering** — the pipeline ordering ensures that correlated compromise indicators survive even the most conservative profile
4. **One parameter that varies vs. many that stay constant** — only thresholds and severity filtering change; time windows, policy ports, and detector enablement (except Novelty) are stable
5. **Immutable profiles prevent configuration drift** — sealed records with init-only properties mean no detector can accidentally modify the profile mid-analysis
