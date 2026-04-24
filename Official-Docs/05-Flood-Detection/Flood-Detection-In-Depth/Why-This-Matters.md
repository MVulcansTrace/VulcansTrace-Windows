# Why This Matters

---

## The Security Problem

Flood attacks — whether Denial of Service, botnet participation, or a compromised host generating storm-level traffic — show up in firewall logs as a single source IP producing an unusually high number of connection events in a short window. Left undetected, this traffic can degrade or entirely block access to critical services.

| MITRE ATT&CK Technique | ID | When It Applies |
|------------------------|-----|-----------------|
| Network Denial of Service | T1498 | Primary mapping when a source generates a volumetric event burst consistent with flooding behavior |
| Direct Network Flood | T1498.001 | Analyst-applied mapping when that burst is understood as direct flood behavior from surrounding context |
| Endpoint Denial of Service | T1499 | Adjacent/contextual only — firewall event spikes can be consistent with endpoint or service exhaustion, but do not prove it |

**The business impact of undetected flood activity:**

- Services become unavailable to legitimate users
- A compromised host participating in a botnet indicates broader infection
- Sustained volumetric attacks can cascade across dependent systems
- Response time matters — every minute of undetected flooding compounds the damage

---

## Implementation Overview

The **flood detection engine** in VulcansTrace uses firewall logs to identify event-volume evidence of flooding behavior, surfacing that evidence as a structured, actionable finding before the damage compounds.

The detector:

1. **Groups firewall log entries** by source IP so each source is analyzed independently
2. **Sorts each group chronologically** to prepare for time-window analysis
3. **Slides a two-pointer window** across each source's event timeline, counting events within the window
4. **Emits a High-severity finding** when event count within the window meets or exceeds the configured threshold
5. **Is processed by the pipeline's RiskEscalator** — when the same host also produces Beaconing and LateralMovement findings, all findings from that host (including Flood) are escalated to Critical

**Key metrics:**

- Three built-in sensitivity profiles: Low (400 events), Medium (200 events), High (100 events) in a 60-second window
- Sliding window catches floods that span bucket boundaries instead of splitting them across fixed intervals
- One finding per source prevents alert fatigue
- Cross-detector correlation raises severity when flood activity co-occurs with C2 or lateral spread

---

## Operational Benefits

| Capability | Business Value |
|-----------|----------------|
| **Availability-impact detection** | Gives analysts a signal that a service or host may be under active volumetric attack |
| **Configurable sensitivity** | Teams can tune the event threshold to match their environment's traffic patterns |
| **Cross-detector correlation** | When Beaconing and LateralMovement findings exist for the same host, the pipeline escalates all findings from that host — including any Flood finding — to Critical |
| **Structured findings** | Analysts get attribution (source IP), timeline (window range), and event count for rapid triage |
| **Per-source isolation** | One high-volume source does not affect the analysis of other sources |
| **Evasion awareness** | Documents what the detector misses and how to compensate |

---

## Security Principles Applied

| Principle | Where It Appears |
|-----------|-----------------|
| **Attack-phase alignment** | Detects impact-phase flood indicators; primary ATT&CK alignment is T1498, while T1499 remains contextual rather than directly proven |
| **Accurate risk communication** | High severity for volumetric threat; Critical only when correlated with post-compromise signals |
| **Alert fatigue prevention** | One finding per source; configurable thresholds to match environment noise levels |
| **Cross-signal correlation** | RiskEscalator combines multiple detector outputs into higher-severity findings when correlated threat patterns are detected |
| **Per-source attribution** | Grouping by source IP enables targeted investigation and blocking |
| **Documented limitations** | Documented evasion paths (DDoS, slow-rate attacks, spoofing) with compensating controls |

---

## Implementation Evidence

- [FloodDetector.cs](../../../VulcansTrace.Engine/Detectors/FloodDetector.cs): source grouping, sliding window, threshold check, and finding creation
- [AnalysisProfile.cs](../../../VulcansTrace.Engine/AnalysisProfile.cs): `EnableFlood`, `FloodMinEvents`, and `FloodWindowSeconds` configuration
- [AnalysisProfileProvider.cs](../../../VulcansTrace.Engine/Configuration/AnalysisProfileProvider.cs): built-in Low, Medium, and High presets
- [RiskEscalator.cs](../../../VulcansTrace.Engine/RiskEscalator.cs): Beaconing + LateralMovement escalation to Critical
- [FloodDetectorTests.cs](../../../VulcansTrace.Tests/Engine/Detectors/FloodDetectorTests.cs): above-threshold, below-threshold, disabled, empty, multi-source, time-spread, and boundary coverage
- [RiskEscalatorTests.cs](../../../VulcansTrace.Tests/Engine/RiskEscalatorTests.cs): escalation and correlation scenarios

---

## Elevator Pitch

> *"The flood detection engine identifies volumetric event spikes from a single source — one of the clearest availability-impact signals visible in firewall logs — giving analysts a high-severity finding when an attacker or compromised host starts overwhelming network resources.*
>
> *The detector groups log entries by source IP and slides a time window across each source's event timeline, counting events within the window. A sliding window is used instead of fixed time buckets because floods do not respect clock boundaries — an attack spanning 10:59:30 to 11:00:29 would be split across two minute buckets and missed, but the sliding window catches it.*
>
> *Default thresholds are set per sensitivity profile: 100 events for High, 200 for Medium, 400 for Low, all within a 60-second window. The detector emits one finding per source to prevent alert fatigue. Severity is High because flooding represents potential active availability impact. If the same host also shows beaconing and lateral movement, the pipeline escalates to Critical — that combination means C2-like timing plus internal spread, which triggers escalation of all findings for that host, including any flood activity.*
>
> *Every design decision trades off sensitivity against false positives, and those trade-offs are documented explicitly — including what the detector cannot catch."*

---

## Security Takeaways

1. **Flood detection is availability defense** — catching volumetric attacks protects service uptime
2. **Per-source grouping is essential** — aggregate counts hide the one noisy source among many normal ones
3. **Sliding windows catch what buckets miss** — attacks that span time boundaries still get detected
4. **Cross-detector correlation raises severity** — Beaconing + LateralMovement on the same host triggers escalation of all findings for that host, including Flood, to Critical
5. **Documented limitations matter** — knowing what you miss is as important as knowing what you catch

