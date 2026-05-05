# Industry Context

## The Security Problem

Beacon-like traffic patterns are high-value hunting signals because repeated outbound communication can indicate command-and-control behavior. However, periodic traffic is not proof of compromise by itself; software updates, telemetry, backups, and monitoring agents can also create regular intervals.

This detector (MITRE T1071 -- Application Layer Protocol) looks for statistical regularity in outbound connection timing, which is one signal among many that analysts use to prioritize investigation.

## Enterprise Approaches

Enterprise EDR, NDR, and SIEM platforms may detect similar behavior using broader telemetry, correlation rules, baselines, ML-assisted analytics, and analyst workflows. Examples of tools that operate in this space include:

- **SIEM platforms** (Splunk, Microsoft Sentinel, Elastic Security) may use scheduled correlation searches over log data to flag endpoints with unusually regular outbound connection intervals. These are typically threshold-based SPL or KQL queries run on indexed data.

- **EDR/XDR platforms** (CrowdStrike Falcon, Microsoft Defender for Endpoint, SentinelOne) may use ML models trained on endpoint network telemetry to identify C2 beaconing across millions of connections, often enriched with process context.

- **NDR platforms** (Darktrace, Vectra AI, ExtraHop) may use network metadata analysis, statistical anomaly detection, or unsupervised ML to identify regular communication patterns that deviate from learned baselines.

## How VulcansTrace Approaches This

VulcansTrace uses inter-arrival interval analysis:

1. Groups connections by (source IP, destination IP, destination port)
2. Computes time gaps between consecutive connections
3. Trims outliers symmetrically (configurable percentage from both ends)
4. Calculates mean and standard deviation of the trimmed intervals
5. Flags groups where the mean interval falls within a configured range AND the standard deviation is below a threshold

This is a statistical approach that reasons over timing and repetition. The detection concept overlaps with enterprise tools that analyze inter-arrival regularity.

## Key Differences

| Dimension | VulcansTrace | Enterprise tools |
|---|---|---|
| Data source | Windows Firewall log on a single host | Endpoint telemetry, network flows, cloud logs |
| Scale | Hundreds to thousands of connections | Millions of connections across an estate |
| Method | Configurable statistical thresholds | May include ML models, behavioral baselines, and analyst workflows |
| Context | IP and port only (no process, no DNS, no user) | May include process lineage, DNS resolution, user identity, asset context |
| Response | Emits a finding for analyst review | May include automated containment, threat intelligence enrichment, and SOAR playbook triggers |

## What This Means For Reviewers

This detector demonstrates understanding of:

- Statistical detection engineering (not just threshold counting)
- The trade-off between sensitivity and false positives (configurable std-dev and interval bounds)
- Outlier handling (symmetric trimming to avoid skew from startup/shutdown bursts)
- Honest scoping (protocol-agnostic; cannot classify C2 protocol or detect content-level indicators)

The approach is sound for its data source. Enterprise tools have richer context and more data, which enables ML-driven detection and automated response. VulcansTrace shows the foundational reasoning that those tools build on.
