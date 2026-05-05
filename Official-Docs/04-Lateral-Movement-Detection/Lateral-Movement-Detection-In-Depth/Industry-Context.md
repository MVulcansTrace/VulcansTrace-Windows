# Industry Context

## The Security Problem

After gaining initial access, adversaries often move laterally through the internal network to reach high-value targets (MITRE TA0008 -- Lateral Movement, technique T1021 -- Remote Services). Common tools for lateral movement include RDP, SMB, PSExec, WMI, and SSH -- all of which use well-known administrative ports.

Detecting unusual internal connection patterns on administrative ports is a key signal for identifying compromised hosts that are being used as pivot points.

## Enterprise Approaches

Enterprise platforms may detect lateral movement through endpoint instrumentation, network monitoring, and identity correlation. Examples of tools that operate in this space include:

- **EDR/XDR platforms** (CrowdStrike Falcon, Microsoft Defender for Endpoint, SentinelOne) may detect lateral movement by monitoring process creation, credential use, service installation, and remote session initiation at the endpoint level, providing rich context beyond network connections.

- **NDR platforms** (Darktrace, Vectra AI, ExtraHop) may analyze east-west (internal-to-internal) traffic patterns to detect unusual internal traversal, often using behavioral baselines to distinguish normal admin activity from adversarial pivoting.

- **SIEM platforms** (Splunk, Microsoft Sentinel) may correlate authentication logs, network connection logs, and endpoint telemetry to identify lateral movement chains across multiple hosts.

## How VulcansTrace Approaches This

VulcansTrace filters for internal-to-internal connections on configurable administrative ports, then applies a sliding window:

1. Filters to entries where source is internal AND destination is internal AND destination port is in the admin port set
2. Groups by source IP
3. Applies a time window and counts distinct destination hosts
4. Emits a finding when distinct internal targets exceed the threshold within the window

This detects a single internal host connecting to many other internal hosts on admin ports in a short period, which is consistent with pivoting behavior.

## Key Differences

| Dimension | VulcansTrace | Enterprise tools |
|---|---|---|
| Data source | Windows Firewall log (network connections only) | Endpoint process telemetry, authentication logs, network flows |
| Visibility | Connection attempts (success and blocked) | May include process lineage, credential context, command-line arguments |
| Coverage | Network-level admin port connections only | May detect application-layer lateral movement (WMI, PSExec, DCOM) |
| Response | Emits a finding for analyst review | May include automated isolation, credential rotation, SOAR playbook triggers |

## What This Means For Reviewers

This detector demonstrates understanding of:

- Why internal east-west traffic on admin ports is a high-value detection signal
- Sliding-window detection applied to lateral movement patterns
- The limitation of firewall-log-only visibility (no process context, no authentication context)
- Honest scoping (cannot detect application-layer lateral movement, share enumeration, or external-to-internal intrusion)
