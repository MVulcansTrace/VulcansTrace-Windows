# Why This Matters

---

## The Security Problem

Lateral movement is what happens after an attacker gets in. They already bypassed the perimeter, and now they are spreading through the internal network using tools like RDP, SMB, and SSH to reach high-value targets. By the time you see it, the attacker is already inside.

| MITRE ATT&CK Technique | ID | When It Applies |
|------------------------|-----|-----------------|
| Remote Desktop Protocol | T1021.001 | Analyst-applied mapping when repeated internal port-3389 spread is understood as RDP-related remote service use |
| SMB/Windows Admin Shares | T1021.002 | Analyst-applied mapping when repeated internal port-445 spread is understood as SMB/admin-share activity |
| SSH | T1021.004 | Analyst-applied mapping when repeated internal port-22 spread is understood as SSH-based remote service use |

**The business impact of undetected lateral movement:**

- Attackers reach domain controllers, file servers, and databases
- Each new compromised host expands the breach exponentially
- Ransomware uses lateral movement to deploy across the entire network
- By the time you detect exfiltration, the lateral spread happened days ago

---

## Implementation Overview

The **lateral movement detection engine** in VulcansTrace uses firewall logs to identify network-level evidence of pivoting behavior, surfacing that evidence as a structured, actionable finding before the attacker reaches their objective.

The detector:

1. **Filters firewall logs** to internal-to-internal traffic on administrative ports (default: ports commonly associated with SMB/445, RDP/3389, SSH/22)
2. **Groups by source IP** and sorts each group chronologically
3. **Slides a time window** across each source's activity, counting distinct destination hosts
4. **Emits a High-severity finding** when a source contacts enough distinct internal hosts within the window
5. **Integrates with RiskEscalator** so that Beaconing + LateralMovement from the same host escalates to Critical

**Key metrics:**

- Three built-in sensitivity profiles: Low (6 hosts), Medium (4 hosts), High (3 hosts) in a 10-minute window
- Sliding window catches attacks that span arbitrary time boundaries
- One finding per source prevents alert fatigue
- Cross-detector correlation raises confidence when C2 and lateral spread co-occur

---

## Operational Benefits

| Capability | Business Value |
|-----------|----------------|
| **Post-compromise detection** | Gives analysts a signal that an attacker is actively spreading, not just probing |
| **Configurable sensitivity** | Teams can tune the host threshold to match their environment's noise level |
| **Cross-detector correlation** | Beaconing + LateralMovement on the same host escalates to Critical automatically |
| **Structured findings** | Analysts get attribution (source IP), timeline (window range), and scope (host count) |
| **Admin-port focus** | Keeps false positives manageable by filtering out HTTP, DNS, and application noise, while remaining a port-based approximation rather than a protocol classifier |
| **Evasion awareness** | Documents what the detector misses and how to compensate |

---

## Security Principles Applied

| Principle | Where It Appears |
|-----------|-----------------|
| **Attack-phase alignment** | Internal-to-internal filter targets post-compromise behavior, not initial access |
| **Accurate risk communication** | High severity for active spread, not reconnaissance |
| **Alert fatigue prevention** | One finding per source; Medium severity reserved for lower-confidence patterns (e.g., beaconing without lateral movement) |
| **Cross-signal correlation** | RiskEscalator combines multiple detector outputs into higher-confidence findings |
| **Defense in depth** | Parser validates data, detector finds patterns, RiskEscalator escalates severity when correlated threats are found, severity filter removes noise below threshold |
| **Documented limitations** | Documented evasion paths and compensating controls |

---

## Implementation Evidence

- [LateralMovementDetector.cs](../../../VulcansTrace.Engine/Detectors/LateralMovementDetector.cs): traffic filter, sliding window, distinct-host counting, and finding creation
- [AnalysisProfile.cs](../../../VulcansTrace.Engine/AnalysisProfile.cs): `LateralMinHosts`, `LateralWindowMinutes`, and `AdminPorts` configuration
- [AnalysisProfileProvider.cs](../../../VulcansTrace.Engine/Configuration/AnalysisProfileProvider.cs): built-in Low, Medium, and High presets
- [RiskEscalator.cs](../../../VulcansTrace.Engine/RiskEscalator.cs): Beaconing + LateralMovement escalation to Critical
- [LateralMovementDetectorTests.cs](../../../VulcansTrace.Tests/Engine/Detectors/LateralMovementDetectorTests.cs): threshold, filtering, multi-source, and time-spread coverage
- [RiskEscalatorTests.cs](../../../VulcansTrace.Tests/Engine/RiskEscalatorTests.cs): escalation and correlation scenarios

---

## Elevator Pitch

> *"The lateral movement detector identifies internal spread on admin ports — one of the clearest post-compromise signals visible in firewall logs — giving analysts a high-severity finding when a compromised host starts pivoting.*
>
> *The detector filters for internal-to-internal traffic on administrative ports — by default, ports commonly associated with SMB, RDP, and SSH. A sliding window is used instead of fixed time buckets because lateral movement doesn't respect arbitrary time boundaries. The window counts distinct destination hosts, not total connections, because spread is the signal — one host hit ten times isn't pivoting, but ten different hosts hit once each is.*
>
> *Severity is set to High because lateral movement means the attacker already bypassed the perimeter and is actively spreading. If the same host also shows beaconing behavior, the pipeline escalates all findings for that host to Critical — that combination is consistent with C2 communication plus internal pivoting, which is one of the highest-confidence compromise signals this pipeline can produce from firewall logs. The detector itself is still port-based: ATT&CK sub-technique labels are analyst-applied context, not direct tool or protocol identification.*
>
> *Thresholds are configurable per environment. Medium requires 4 distinct hosts in 10 minutes. Low requires 6 for conservative environments. High requires 3 for aggressive detection. Every design decision trades off sensitivity against false positives, and those trade-offs are documented explicitly."*

---

## Security Takeaways

1. **Lateral movement detection is post-compromise warning** — the attacker is already inside, and speed matters
2. **Admin-port filtering is a signal-to-noise choice** — it focuses on common pivot-port signals while keeping FPs manageable
3. **Sliding windows catch what buckets miss** — attacks that span time boundaries still get detected
4. **Cross-detector correlation raises confidence** — Beaconing + LateralMovement is a higher-confidence compromise signal than either finding alone
5. **Documented limitations matter** — knowing what you miss is as important as knowing what you catch

