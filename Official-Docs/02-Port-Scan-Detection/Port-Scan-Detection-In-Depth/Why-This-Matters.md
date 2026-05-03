# Why This Matters

---

## The Security Problem

Port scanning is a common reconnaissance technique used to map hosts, identify exposed services, and look for likely entry points. In practice, defenders care about it because it often appears before exploitation, lateral movement, or broader network discovery.

| MITRE ATT&CK Technique | ID | When It Applies |
|------------------------|-----|-----------------|
| Active Scanning | T1595 | External, pre-compromise probing of victim infrastructure |
| Scanning IP Blocks | T1595.001 | Range-based external scanning |
| Network Service Discovery | T1046 | Internal, post-compromise enumeration from a foothold |

**The business impact of undetected scanning:**

- Attackers map your entire network without you knowing
- Open services (SSH, RDP, HTTP) are identified for exploitation
- Attackers gain the intelligence they need for a targeted breach
- By the time you detect the exploit, the recon happened days or weeks ago

---

## Implementation Overview

The **port scan detection engine** in VulcansTrace:

1. **Analyzes parsed firewall logs** to find single-source IPs targeting multiple hosts/ports within configurable time windows
2. **Counts distinct (DstIp, DstPort) tuples** — catching both horizontal scans (same port, many hosts) and vertical scans (same host, many ports)
3. **Emits structured Findings** with severity, attribution, timeline, and context for analyst triage
4. **Uses configurable profiles** (Low/Medium/High) to balance sensitivity against false positives based on environment noise
5. **Handles edge cases deliberately** — low-activity sources are filtered early, and high-volume sources can optionally be truncated with warnings via a configurable cap (`PortScanMaxEntriesPerSource`) in a custom profile

**Key metrics:**
- O(n log n) worst-case time complexity (dominant cost is per-group sorting)
- Three built-in sensitivity profiles with thresholds verified in tests
- Global pre-check has a mathematical no-false-negative guarantee because eligibility is evaluated on the full source set before any truncation is applied

---

## Operational Benefits

| Capability | Business Value |
|-----------|----------------|
| **Reconnaissance detection** | Gives analysts an earlier signal to investigate suspicious probing behavior |
| **Configurable sensitivity** | Lets teams tune detection to their own traffic patterns instead of relying on one fixed threshold |
| **False-positive awareness** | Accounts for noisy infrastructure and analyst fatigue |
| **Structured findings** | Produces alerts with attribution, timing, and scope instead of a vague warning |
| **Evasion awareness** | Documents blind spots and points toward compensating controls |
| **Scale-ready thinking** | Separates the core algorithm from how it would evolve in a larger environment |

---

## Security Principles Applied

| Principle | Where It Appears |
|-----------|-----------------|
| **Defense in Depth** | Parser validates data → Detector finds patterns → RiskEscalator escalates severity when correlated threats are found → Severity filter removes below-threshold findings |
| **Fail-Soft Design** | High-volume sources can be truncated (configurable), not rejected — analysis continues |
| **Accurate Risk Communication** | Severity=Medium for recon (not Critical) — prevents alert fatigue; note that the Low profile's severity filter hides Medium findings by default |
| **Resource Protection** | Early exits reduce unnecessary work, and configurable truncation can cap per-source cost when `PortScanMaxEntriesPerSource` is set in a custom profile, without hiding qualifying sources from the global gate |
| **Transparency** | Warnings emitted when truncation is active — no silent data loss |
| **Separation of Concerns** | Parser validates, detector analyzes, escalator escalates severity, filter controls visibility |

---

## Implementation Evidence

- [PortScanDetector.cs](../../../VulcansTrace.Engine/Detectors/PortScanDetector.cs): source grouping, tuple counting, sliding-window scanning, truncation, and `Severity.Medium` findings
- [AnalysisProfile.cs](../../../VulcansTrace.Engine/AnalysisProfile.cs): detector settings including `PortScanMinPorts`, `PortScanWindowMinutes`, and `PortScanMaxEntriesPerSource`
- [AnalysisProfileProvider.cs](../../../VulcansTrace.Engine/Configuration/AnalysisProfileProvider.cs): built-in Low, Medium, and High presets
- [PortScanDetectorTests.cs](../../../VulcansTrace.Tests/Engine/Detectors/PortScanDetectorTests.cs): above-threshold, below-threshold, multi-source, and truncation coverage
- [AnalysisProfileProviderTests.cs](../../../VulcansTrace.Tests/Engine/AnalysisProfileProviderTests.cs): verifies the threshold values used by each intensity profile

---

## Elevator Pitch

> *"The port scan detection engine identifies network reconnaissance — the first stage of most attacks. It analyzes firewall logs to find single-source IPs targeting multiple hosts and ports within configurable time windows.*
>
> *Distinct destination IP:port tuples are counted because that captures both horizontal scans — same port across many hosts, which is network mapping — and vertical scans — many ports on one host, which is service enumeration.*
>
> *Configurable sensitivity profiles let teams tune detection to their environment. Medium uses 15 targets in 5 minutes, while Low and High adjust the threshold in opposite directions depending on how noisy the environment is.*
>
> *Every design decision has a security rationale: sliding windows to avoid wall-clock boundary misses, Medium severity to prevent alert fatigue, and optional truncation with warnings when a team needs to bound analysis cost while staying transparent about reduced coverage.*
>
> *The algorithm is intentionally simple to audit and explain. The same core idea can evolve toward streaming or distributed analysis if the environment changes."*

---

## Security Takeaways

1. **Reconnaissance detection is early warning** — catching scans gives defenders time to harden *before* exploitation
2. **Tuple counting is comprehensive** — horizontal + vertical scans both represent real attack patterns
3. **Configuration is security** — wrong thresholds mean missed attacks or analyst burnout
4. **Documented limitations matter** — knowing blind spots is as valuable as detection capability
5. **Security engineering is deliberate** — every choice has a rationale, not just "it works"
