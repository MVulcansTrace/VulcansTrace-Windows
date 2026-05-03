# Why This Matters

---

## The Security Problem

Egress policy enforcement catches what perimeter firewalls often miss. An organization may prohibit outbound FTP even if a legacy rule still permits it, or it may want visibility into repeated attempts on ports that should never be used externally. Either way, an internal-to-external log entry on a disallowed port is worth investigating.

| MITRE ATT&CK Technique | ID | When It Applies |
|------------------------|-----|-----------------|
| Exfiltration Over Alternative Protocol | T1048 | Analyst-applied mapping when disallowed-port egress is understood as alternate-protocol use |
| Exfiltration Over Unencrypted Non-C2 Protocol | T1048.003 | Analyst-applied mapping when FTP/Telnet findings are interpreted as unencrypted exfil-related activity |

**The business impact of undetected egress violations:**

- Data leaves the organization through insecure channels (FTP, Telnet)
- Malware uses legacy protocols for command-and-control or file staging
- Insiders bypass security controls using protocols they know are unmonitored
- Misconfigured applications expose the organization without triggering traditional alerts

---

## Implementation Overview

The **egress policy violation detector** in VulcansTrace uses firewall logs to identify internal-to-external log entries on ports the organization has flagged as disallowed, surfacing each individual violation as a high-severity finding with full investigative context.

The detector:

1. **Gates on profile configuration** — checks `EnablePolicy` flag and empty log guard before any work
2. **Loads disallowed ports into a HashSet** — O(1) lookup for each log entry
3. **Applies a three-condition filter** — source internal, destination external, port disallowed
4. **Emits one finding per violation** — no aggregation, no deduplication, every violation visible
5. **Sets severity to High** — calibrated to the threat level, not over-escalated

**Key metrics:**

- 53 lines of code — the simplest detector in VulcansTrace, intentionally
- Default disallowed ports: 21 (FTP), 23 (Telnet), 445 (SMB)
- Enabled in all three built-in profiles (Low, Medium, High)
- O(n) time complexity — single pass through log entries
- Findings visible in all three built-in profiles because High exceeds every default MinSeverityToShow threshold

---

## Operational Benefits

| Capability | Business Value |
|-----------|----------------|
| **Narrow policy-risk signals** | Internal-to-external traffic on disallowed ports is actionable, while still requiring analyst interpretation for intent |
| **Configurable port list** | Teams customize `DisallowedOutboundPorts` to match their security policy |
| **One finding per violation** | Analysts see every destination, not a collapsed count that hides attack scope |
| **Structured output** | SourceHost, Target, timestamps, and details give immediate pivot points for investigation |
| **Cross-detector correlation** | If the same host also has Beaconing + LateralMovement findings, RiskEscalator promotes everything to Critical |
| **Fail-safe defaults** | Null or empty port list produces zero findings, not crashes |

---

## Security Principles Applied

| Principle | Where It Appears |
|-----------|-----------------|
| **Organizational policy over firewall rules** | Detector uses IP classification, not Action/Direction fields — a firewall ALLOW can still be a policy violation |
| **Fail-safe configuration** | Null-coalescing on `DisallowedOutboundPorts` prevents crashes; empty set = no findings |
| **Alert precision** | Three-condition filter produces a narrow policy-risk signal rather than broad speculation |
| **Full investigative visibility** | One finding per entry preserves target diversity and attack scope |
| **Documented limitations** | Documented blind spots: protocol tunneling, allowed-port evasion, static list, no payload inspection |

---

## Implementation Evidence

- [PolicyViolationDetector.cs](../../../VulcansTrace.Engine/Detectors/PolicyViolationDetector.cs): gate checks, HashSet initialization, three-condition filter, and finding creation
- [AnalysisProfile.cs](../../../VulcansTrace.Engine/AnalysisProfile.cs): `EnablePolicy` and `DisallowedOutboundPorts` configuration
- [AnalysisProfileProvider.cs](../../../VulcansTrace.Engine/Configuration/AnalysisProfileProvider.cs): all three profiles enable policy with ports [21, 23, 445]
- [IpClassification.cs](../../../VulcansTrace.Engine/Net/IpClassification.cs): RFC 1918, IPv4 loopback, and IPv6 internal/external classification
- [RiskEscalator.cs](../../../VulcansTrace.Engine/RiskEscalator.cs): cross-detector escalation logic
- [PolicyViolationDetectorTests.cs](../../../VulcansTrace.Tests/Engine/Detectors/PolicyViolationDetectorTests.cs): 9 tests covering happy path, allowed ports, disabled policy, empty logs, traffic direction, multiple violations, empty ports, and null config

---

## Elevator Pitch

> *"The policy violation detector identifies internal-to-external log entries on disallowed ports — a narrow egress-policy signal available in firewall logs — giving analysts a finding for every individual violation with full investigative context.*
>
> *The detector is intentionally simple — 53 lines, single pass, three conditions: source internal, destination external, port disallowed. IP classification is used instead of the Direction and Action log fields because organizational policy is not the same as the firewall's allow/deny decision. A firewall may ALLOW FTP outbound and still violate policy, and repeated DENY entries on disallowed external ports are still operationally relevant because the detector does not require Action=ALLOW.*
>
> *Severity is set to High because these events can indicate policy violations, risky outbound access, or potentially malicious activity. Every qualifying log entry gets its own finding — no aggregation — so if an internal host generates 50 disallowed-port entries to 50 different destinations, analysts see all 50 targets, not one summary record.*
>
> *The port list is configurable per environment. Default covers FTP (21), Telnet (23), and SMB (445) — protocols that are rarely needed for outbound traffic and carry elevated risk when they appear. The detector integrates with RiskEscalator so that if a host with policy violations also shows beaconing and lateral movement, everything for that host escalates to Critical."*

---

## Security Takeaways

1. **Egress policy catches what perimeter controls miss** — organizational policy and technical enforcement are different layers
2. **IP classification is more reliable than log fields** — organizational scope, not the firewall's perspective
3. **One finding per entry preserves investigative detail** — aggregation hides target diversity and attack scope
4. **Simplicity is a feature, not a limitation** — 53 lines, deterministic, same input always produces the same output
5. **Documented limitations matter** — protocol tunneling, allowed-port evasion, and static lists are documented gaps with compensating controls

