# Industry Context

## The Security Problem

Port scanning (MITRE T1046 -- Network Service Discovery) is typically one of the first steps in a targeted attack. An adversary probes the target network to identify open ports, running services, and potential entry points before executing exploitation or lateral movement.

Detecting scanning behavior early provides an opportunity to block reconnaissance before it progresses to more damaging phases.

## Enterprise Approaches

Enterprise platforms may detect port scanning through multiple data sources and methods. Examples of tools that operate in this space include:

- **SIEM platforms** (Splunk, Microsoft Sentinel, Elastic Security) may use scheduled correlation searches that count distinct destination ports or IPs per source within a time window. These are typically threshold-based queries using SPL, KQL, or EQL.

- **NDR platforms** (Darktrace, Vectra AI, ExtraHop) may analyze network flow data to detect scanning patterns, including horizontal sweeps (many hosts, one port) and vertical scans (one host, many ports), often using statistical baselines to distinguish scanning from normal service discovery.

- **Firewall and IDS/IPS systems** (Fortinet, Palo Alto, Suricata, Snort) may include built-in port scan detection rules that flag sources contacting many destinations in a short period, sometimes with automated blocking.

## How VulcansTrace Approaches This

VulcansTrace uses a sliding-window algorithm:

1. Groups log entries by source IP
2. Sorts each group chronologically
3. Applies a configurable time window
4. Counts distinct (destination IP, destination port) tuples within the window
5. Emits a finding when the count exceeds the configured threshold

This detects a source IP contacting many unique destination IP:port combinations within a short period, which is consistent with scanning behavior.

## Key Differences

| Dimension | VulcansTrace | Enterprise tools |
|---|---|---|
| Data source | Windows Firewall log (single host) | Network flow data, IDS alerts, endpoint telemetry across the estate |
| Scan classification | Generic (many targets in a window) | May classify scan type (horizontal, vertical, stealthy, decoy) |
| Response | Emits a finding for analyst review | May include automated blocking, firewall rule updates, SOAR playbook triggers |
| Context | IP and port only | May include service fingerprinting, OS detection, threat intelligence enrichment |

## What This Means For Reviewers

This detector demonstrates understanding of:

- Sliding-window detection algorithms (a common pattern in enterprise SIEM correlation rules)
- Configurable thresholds for sensitivity tuning
- The trade-off between detection speed and false positive rate
- Honest scoping (cannot classify scan type, cannot distinguish authorized scanning from hostile reconnaissance)
