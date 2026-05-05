# Industry Context

## The Security Problem

Organizations define acceptable use policies that restrict outbound network traffic. Common policy violations include connections to external hosts on unencrypted or legacy protocols (Telnet, FTP) that may indicate data exfiltration, unauthorized tool usage, or misconfigured software.

Policy violation detection supports compliance monitoring and may surface activity that other detection categories miss.

## Enterprise Approaches

Enterprise platforms may enforce and detect policy violations through firewall rules, proxy filtering, DLP (Data Loss Prevention), and SIEM correlation. Examples of tools that operate in this space include:

- **Next-generation firewalls** (Fortinet FortiGate, Palo Alto PA-Series) may enforce application-level policies that block or alert on unauthorized outbound protocols, often with deep packet inspection to identify the actual application regardless of port.

- **SIEM platforms** (Splunk, Microsoft Sentinel) may use correlation rules to flag outbound connections on prohibited ports, typically correlating with asset inventory to distinguish known exceptions from violations.

- **DLP and proxy platforms** (Zscaler, Palo Alto Prisma SASE, Symantec DLP) may inspect outbound traffic content and block or alert on policy violations, including data exfiltration attempts.

## How VulcansTrace Approaches This

VulcansTrace uses a straightforward filter:

1. Iterates every log entry
2. Checks if the source is internal AND the destination is external AND the destination port is in the disallowed set
3. Emits one finding per matching entry

No grouping, no windowing, no thresholds beyond the configured port list. Each violation is reported individually.

## Key Differences

| Dimension | VulcansTrace | Enterprise tools |
|---|---|---|
| Enforcement | Detection only (no blocking) | May include inline blocking, proxy interception, and automated remediation |
| Depth | Port-based filter only | May include deep packet inspection, application identification, content analysis |
| Context | IP and port only | May include user identity, asset classification, exception management |
| Exfiltration detection | None (firewall logs lack payload data) | DLP tools may detect sensitive data in outbound traffic |

## What This Means For Reviewers

This detector demonstrates understanding of:

- Policy-based detection as a complement to threat-based detection
- Simple, transparent logic (easy to audit and explain)
- Honest scoping (port-only, no content analysis, no data volume awareness, no exception management)
