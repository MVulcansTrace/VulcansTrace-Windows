# Industry Context

## The Security Problem

Denial-of-service attacks (MITRE T1498 -- Network Denial of Service) overwhelm a target with traffic volume, causing service degradation or outage. At the single-host level, a flood of connection attempts may indicate the host is being targeted, or that malware on the host is participating in a botnet-driven attack.

Detecting high-volume connection bursts provides visibility into potential DoS activity and botnet participation.

## Enterprise Approaches

Enterprise platforms may detect flood and DoS behavior through network flow analysis, rate monitoring, and traffic baselines. Examples of tools that operate in this space include:

- **Firewall and IDS/IPS systems** (Fortinet, Palo Alto, Suricata) may include built-in rate-limiting rules and flood detection that can block offending sources in real time.

- **NDR platforms** (Darktrace, Vectra AI, ExtraHop) may use volumetric baselines to detect traffic anomalies, distinguishing between legitimate traffic spikes (batch jobs, backups) and hostile floods.

- **DDoS protection services** (Cloudflare, Akamai, AWS Shield) operate at the network edge to absorb and mitigate volumetric attacks before they reach the target.

## How VulcansTrace Approaches This

VulcansTrace uses a simple volumetric threshold within a sliding window:

1. Groups all entries by source IP
2. Applies a time window (in seconds)
3. Counts raw event volume within the window
4. Emits a finding when count exceeds the threshold

This detects a single source IP producing a burst of connection events in a short period.

## Key Differences

| Dimension | VulcansTrace | Enterprise tools |
|---|---|---|
| Data source | Windows Firewall log (single host) | Network flow data, edge traffic, ISP-level visibility |
| Detection | Raw event count in a window | May include traffic rate analysis, protocol distribution, packet-level inspection |
| Impact assessment | None (cannot determine if service was disrupted) | May measure latency, availability, and business impact |
| Response | Emits a finding for analyst review | May include automated rate limiting, source blocking, traffic scrubbing |

## What This Means For Reviewers

This detector demonstrates understanding of:

- Volumetric detection using sliding windows
- The limitation of count-only detection (cannot distinguish DoS from legitimate high-volume activity)
- Honest scoping (no impact assessment, no protocol-level analysis, no mitigation capability)
