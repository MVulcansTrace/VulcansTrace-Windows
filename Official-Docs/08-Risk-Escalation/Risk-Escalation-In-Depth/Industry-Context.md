# Industry Context

## The Security Problem

A single detector firing on a host is a weak signal. An analyst seeing a beaconing alert might deprioritize it. But if the same host also shows lateral movement patterns, the combined signal is much stronger -- it suggests the host is compromised and actively being used as a pivot point.

Cross-signal risk escalation is the logic that turns multiple weak signals into one stronger signal. This is the core concept behind XDR (Extended Detection and Response).

## Enterprise Approaches

Enterprise platforms may correlate independent detection signals across data sources to increase confidence in host-level risk. Examples of tools that operate in this space include:

- **XDR platforms** (CrowdStrike Falcon, Microsoft Defender XDR, SentinelOne Singularity, Palo Alto Cortex XDR) correlate endpoint, network, identity, email, and cloud signals to produce unified incident scores. A host that triggers both C2 and lateral movement detections may be escalated to a higher severity or flagged as a confirmed compromise.

- **SIEM platforms with risk-based alerting** (Splunk ES, Microsoft Sentinel) may assign risk scores to hosts and trigger elevated alerts when cumulative risk exceeds a threshold. Multiple low-severity findings on the same asset accumulate into a higher-severity alert.

- **SOAR platforms** (Palo Alto XSOAR, Splunk SOAR, Swimlane) may orchestrate multi-signal correlation as part of automated investigation playbooks, enriching findings with threat intelligence and asset context before escalating.

## How VulcansTrace Approaches This

VulcansTrace implements a single correlation rule:

- If a host has findings in both the **Beaconing** and **Lateral Movement** categories, all findings for that host are escalated to **Critical** severity.

This is intentionally simple. The rule encodes the security insight that C2 activity combined with internal pivoting behavior on the same host is a strong indicator of active compromise (MITRE TA0011 Command and Control + TA0008 Lateral Movement co-occurring on one asset).

## Key Differences

| Dimension | VulcansTrace | Enterprise tools |
|---|---|---|
| Correlation scope | Single host, two detector categories | Multi-host, multi-source, many signal types |
| Number of rules | One (Beaconing + Lateral Movement) | Dozens to hundreds of correlation rules |
| Enrichment | None (IP and port only) | Threat intelligence, asset inventory, user identity, vulnerability data |
| Response | Severity escalation only | May include automated containment, SOAR playbook execution, ticket creation |
| Tuning | Hardcoded rule | Typically configurable per environment |

## What This Means For Reviewers

This component demonstrates understanding of:

- Why single-detector alerts are weaker than correlated signals
- The security logic behind combining C2 and lateral movement indicators
- Immutable escalation (original findings preserved; escalated versions are new objects)
- Honest scoping (one rule, no cross-host correlation, no ML-driven anomaly scoring)

The concept overlaps with how XDR platforms and SIEM risk-based alerting operate. Enterprise tools apply the same principle -- multiple weak signals becoming one strong signal -- at greater scale, with more data sources, and with automated response capabilities. VulcansTrace implements the foundational logic that those systems build on.
