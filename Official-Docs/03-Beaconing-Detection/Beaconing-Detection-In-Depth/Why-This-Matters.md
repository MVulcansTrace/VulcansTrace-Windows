# Why This Matters

---

## The Security Problem

After an attacker compromises a host, they need a persistent communication channel back to their infrastructure — a command-and-control (C2) link. Most malware establishes this channel by "calling home" at regular intervals, creating a timing pattern that looks nothing like normal human behavior.

Unlike port scanning (which is reconnaissance), beaconing means the host is already compromised and under active adversary control. This makes it one of the highest-priority signals a defender can detect.

| MITRE ATT&CK Technique | ID | When It Applies |
|------------------------|-----|-----------------|
| Application Layer Protocol | T1071 | Analyst-applied mapping when the beaconing channel is understood as command-and-control over an application-layer protocol |
| Non-Standard Port | T1571 | Analyst-applied mapping when surrounding evidence shows command-and-control on an unexpected port |

**The business impact of undetected beaconing:**

- Attackers maintain persistent access to compromised hosts for weeks or months
- Data exfiltration occurs through the same channel used for command delivery
- The compromised host becomes a staging point for lateral movement
- By the time you detect lateral movement, the attacker has been inside the network for days

---

## Implementation Overview

The **beaconing detection engine** in VulcansTrace:

1. **Groups traffic by channel** — isolating each (SrcIp, DstIp, DstPort) tuple so patterns are analyzed per destination, not diluted across mixed traffic
2. **Computes inter-arrival intervals** between consecutive connections in each channel
3. **Trims outlier intervals** symmetrically to reduce the impact of network jitter and occasional timing anomalies
4. **Applies population standard deviation** as the core regularity test — automated tools tick like clocks, while human behavior is irregular
5. **Filters by mean interval range** — only channels with average intervals in the C2 "sweet spot" are considered (30s–900s on the default Medium profile; 60s–900s on Low, 10s–900s on High), which screens out many very fast or very slow channels without semantically identifying health checks
6. **Emits structured Findings** with Medium severity, escalated to Critical by RiskEscalator when correlated with lateral movement

**Key metrics:**

- O(n log n) worst-case time complexity
- Three sensitivity profiles with thresholds verified in dedicated tests
- Eight configurable parameters per profile (1 toggle + 7 thresholds) for precise tuning
- Cross-correlation escalation: Beaconing + LateralMovement = Critical

---

## Operational Benefits

| Capability | Business Value |
|-----------|----------------|
| **C2 detection** | Identifies compromised hosts that are under active adversary control |
| **Statistical rigor** | Uses standard deviation rather than heuristics — defensible in incident reports |
| **Configurable sensitivity** | Lets teams tune to their environment instead of relying on one fixed threshold |
| **Correlation escalation** | Beaconing + LateralMovement on the same host triggers Critical — real attack signal |
| **Structured findings** | Produces alerts with attribution, timing, and statistical evidence for triage |
| **Documented limitations** | Acknowledges jitter-tolerant evasion and points toward compensating controls |

---

## Security Principles Applied

| Principle | Where It Appears |
|-----------|-----------------|
| **Defense in Depth** | Parser validates data → Detector finds timing patterns → RiskEscalator escalates severity when correlated threats are found → Severity filter removes below-threshold findings |
| **Statistical Foundation** | Population standard deviation with symmetric trimming — defensible and explainable |
| **Accurate Risk Communication** | Severity=Medium for uncorrelated beaconing, escalated to Critical when context demands it |
| **Resource Protection** | Sample cap bounds the interval/statistics work after sorting, even though the tuple is still sorted first |
| **Separation of Concerns** | Detector identifies the pattern, RiskEscalator escalates severity, severity filter controls visibility |

---

## Implementation Evidence

- [BeaconingDetector.cs](../../../VulcansTrace.Engine/Detectors/BeaconingDetector.cs): tuple grouping, interval computation, outlier trimming, statistical analysis, and finding emission
- [AnalysisProfile.cs](../../../VulcansTrace.Engine/AnalysisProfile.cs): eight beaconing-specific configuration parameters (1 toggle + 7 thresholds)
- [AnalysisProfileProvider.cs](../../../VulcansTrace.Engine/Configuration/AnalysisProfileProvider.cs): built-in Low, Medium, and High presets
- [RiskEscalator.cs](../../../VulcansTrace.Engine/RiskEscalator.cs): cross-correlation logic for Beaconing + LateralMovement escalation
- [BeaconingDetectorTests.cs](../../../VulcansTrace.Tests/Engine/Detectors/BeaconingDetectorTests.cs): regular beaconing, irregular intervals, gating, trimming, sample cap, and mixed-traffic coverage
- [AnalysisProfileProviderTests.cs](../../../VulcansTrace.Tests/Engine/AnalysisProfileProviderTests.cs): threshold monotonicity across profiles

---

## Elevator Pitch

> *"The beaconing detection engine identifies command-and-control communication in firewall logs. After an attacker compromises a host, they need a persistent channel back to their infrastructure. Most malware calls home at regular intervals — like a metronome — creating a timing fingerprint that stands out from normal human traffic.*
>
> *The detector works by grouping connections into channels — same source, same destination IP and port — then computing the time gaps between consecutive connections. Outliers are trimmed from both ends to handle network jitter, then population standard deviation is calculated. If the intervals are regular enough and fall in the C2 sweet spot — between 30 seconds and 15 minutes on the Medium profile — the channel is flagged as beaconing. That interval screen removes many very fast or very slow channels, but it does not semantically identify "health check" versus "C2" by itself.*
>
> *Standard deviation is used because it is defensible. When an analyst writes up an incident report saying \"the host contacted the C2 server every 90 seconds with a standard deviation of 0,\" that is a clear, quantitative indicator of automation.*
>
> *Severity starts at Medium because beaconing alone means the host is compromised, but the scope is contained. However, if the same host also shows lateral movement, RiskEscalator raises it to Critical — because that combination means the attacker is using the compromised host to probe deeper into the network."*

---

## Security Takeaways

1. **Beaconing is a post-compromise signal** — detecting it means the host is already under adversary control, making it one of the highest-priority alerts
2. **Statistical regularity is the fingerprint** — automated tools produce timing patterns that standard deviation exposes reliably
3. **Correlation adds context** — Beaconing + LateralMovement on the same host reflects real attack progression and warrants Critical severity
4. **Interval bounds filter noise** — the C2 sweet spot (30s–900s on the default Medium profile) screens out many very fast or very slow channels, but regular in-range software can still overlap
5. **Documented limitations matter** — jitter-tolerant malware can evade the std dev threshold, and compensating controls exist for that gap

