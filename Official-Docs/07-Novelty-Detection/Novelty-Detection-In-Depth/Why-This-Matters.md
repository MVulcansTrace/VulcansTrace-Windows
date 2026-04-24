# Why This Matters

---

## The Security Problem

Most network detection focuses on strong signals: many targets from one source (port scan), regular periodic connections (beaconing), or internal spread (lateral movement). But there is a category of connection that none of those detectors catch: a destination that appears exactly once in the analyzed data.

A one-time external connection could be:

- A C2 server checking in for the first time before regular beaconing begins
- A data exfiltration test to an endpoint that appears only once in the current dataset
- Infrastructure setup for a future attack phase
- Or a legitimate one-time download, CDN edge node, or cloud API call

The challenge is that most of these are benign. The detector cannot distinguish malicious from legitimate — but it can surface the signal so an analyst can make that determination with enrichment and context.

---

## Implementation Overview

The **novelty detection engine** in VulcansTrace uses firewall logs to identify singleton external destinations within the current dataset, surfacing those one-time connections as structured Low-severity findings for forensic review rather than high-confidence alerting.

The detector:

1. **Filters firewall logs** to external destinations only, removing the noise of internal one-time connections (DHCP, printing, DNS)
2. **Groups by (DstIp, DstPort) tuple** to count occurrences at the service level, not just the host level
3. **Emits a Low-severity finding** for each tuple that appears exactly once in the dataset
4. **Integrates with the profile-gating system** — disabled at Low intensity, filtered at Medium, visible at High
5. **Integrates with RiskEscalator** so that if the same host also has Beaconing and LateralMovement findings, all findings for that host escalate to Critical

**Key metrics:**

- 57 lines of implementation — second only to PolicyViolationDetector (53 lines) as the smallest detector in VulcansTrace
- O(n) time complexity with no sorting, no sliding windows, no sampling
- Profile-gated visibility: detector output is only user-visible at High intensity unless escalated or a custom profile lowers MinSeverityToShow
- Cross-detector correlation: Novelty findings can escalate to Critical via host-level Beaconing + LateralMovement correlation

---

## Operational Benefits

| Capability | Business Value |
|-----------|----------------|
| **First-contact detection** | Surfaces external destinations that appear exactly once — a blind spot for pattern-based detectors |
| **Forensic lead generation** | Low severity positions findings as investigation starting points, not urgent alerts |
| **Profile-gated noise control** | Disabled at Low intensity, filtered at Medium — novelty only appears when the analyst asks for thorough analysis |
| **Cross-detector correlation** | If the same host has Beaconing + LateralMovement, novelty findings escalate to Critical automatically |
| **Structured findings** | Analysts get attribution (source IP), destination (IP:port), timestamp, and evidence for enrichment |
| **Minimal performance impact** | O(n) linear scan with no sorting or complex data structures |

---

## Security Principles Applied

| Principle | Where It Appears |
|-----------|-----------------|
| **Weak-signal detection** | Singleton counting catches what strong-signal detectors miss |
| **Accurate risk communication** | Low severity communicates uncertainty — signal, not verdict |
| **Alert fatigue prevention** | Profile-gating means novelty only appears at the analyst's chosen depth |
| **Cross-signal correlation** | RiskEscalator combines multiple detector outputs into higher-confidence findings |
| **Defense in depth** | Novelty complements Port Scan, Beaconing, and Lateral Movement detection |
| **Documented limitations** | Documented evasion paths, edge cases, and what the detector cannot determine |

---

## Implementation Evidence

- [NoveltyDetector.cs](../../../VulcansTrace.Engine/Detectors/NoveltyDetector.cs): guard clauses, external filtering, tuple counting, singleton finding creation
- [AnalysisProfile.cs](../../../VulcansTrace.Engine/AnalysisProfile.cs): `EnableNovelty` flag and `MinSeverityToShow` configuration
- [AnalysisProfileProvider.cs](../../../VulcansTrace.Engine/Configuration/AnalysisProfileProvider.cs): built-in Low, Medium, and High presets that gate novelty by intensity
- [RiskEscalator.cs](../../../VulcansTrace.Engine/RiskEscalator.cs): host-level Beaconing + LateralMovement escalation to Critical
- [NoveltyDetectorTests.cs](../../../VulcansTrace.Tests/Engine/Detectors/NoveltyDetectorTests.cs): 8 tests covering singleton, repeated, disabled, empty, internal-only, mixed, multi-port, and multi-IP scenarios
- [SentryAnalyzerIntegrationTests.cs](../../../VulcansTrace.Tests/Engine/SentryAnalyzerIntegrationTests.cs): end-to-end visibility tests confirming standalone Novelty appears at High intensity, while Medium filters Low-severity Novelty unless escalation changes severity

---

## Elevator Pitch

> *"The novelty detector identifies one-time external connections — a blind spot for pattern-based detectors like port scan and beaconing — surfacing singleton destinations in the current dataset as forensic leads during threat hunting.*
>
> *The detector filters for external destinations only because internal one-time connections are routine noise — DHCP renewals, print jobs, DNS queries. It groups by (DstIp, DstPort) tuple rather than just IP because the same server on different ports is a different service, and a C2 server might run HTTPS on 443 and a backdoor on 8443 simultaneously.*
>
> *Severity is set to Low because most singletons are legitimate — CDN edge nodes, one-time downloads, cloud API calls. The detector is not a verdict; it is an invitation to investigate. It is disabled at Low intensity to avoid flooding analysts in conservative environments, and filtered at Medium unless escalation promotes it.*
>
> *If the same host also shows Beaconing and LateralMovement behavior, the pipeline escalates all findings for that host to Critical — meaning a singleton connection can become part of the highest-severity correlated signal the current pipeline produces. Every design decision trades off sensitivity against noise, and those trade-offs are documented explicitly."*

---

## Security Takeaways

1. **Singleton detection is a blind-spot filler** — it catches what volume-based and pattern-based detectors miss
2. **External-only filtering is a signal-to-noise choice** — internal singletons are routine; external singletons are noteworthy
3. **Low severity is calibrated intentionally** — most singletons are benign, and the severity communicates that uncertainty
4. **Profile-gating respects analyst capacity** — novelty only appears when the analyst asks for thorough analysis
5. **Cross-detector correlation raises confidence** — Novelty + Beaconing + LateralMovement on the same host can become part of the pipeline's highest-severity correlated result

