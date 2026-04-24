# MITRE ATT&CK Mapping

---

## Technique Mapping

| Technique | ID | When It Applies |
|-----------|-----|-----------------|
| Application Layer Protocol | T1071 | Analyst-applied mapping when surrounding evidence shows command-and-control over an application-layer protocol |
| Web Protocols | T1071.001 | Analyst-applied mapping when the beaconing channel is understood as HTTP/HTTPS-based C2 |
| File Transfer Protocols | T1071.002 | Analyst-applied mapping when the channel is understood as FTP-based C2 |
| Mail Protocols | T1071.003 | Analyst-applied mapping when the channel is understood as mail-protocol C2 |
| DNS | T1071.004 | Analyst-applied mapping when the channel is understood as DNS-based C2 |
| Publish/Subscribe Protocols | T1071.005 | Analyst-applied mapping when the channel is understood as pub/sub-protocol C2 |
| Non-Standard Port | T1571 | Analyst-applied mapping when command-and-control is using an unexpected port |

> **Note:** `BeaconingDetector` itself does not inspect application-layer protocol, DNS content, or port semantics. It groups by `(SrcIp, DstIp, DstPort)` and scores timing regularity, so these ATT&CK mappings come from analyst context layered on top of the timing finding.

---

## Why Beaconing Maps to Command and Control

Beaconing is the behavioral signature of the **Command and Control (C2) phase** in the attack lifecycle. After initial compromise, the attacker needs a persistent channel to deliver commands and receive data. The regular timing pattern is a side effect of how most C2 frameworks implement polling:

- **Persistent access:** The malware calls home at fixed intervals to check for new commands
- **Command receipt:** The interval determines how quickly the attacker can issue instructions
- **Data exfiltration:** Many C2 channels use the same beacon for data delivery
- **Sleep and avoid detection:** The interval is a balance between responsiveness and stealth

---

## Attack Lifecycle Position

```
Reconnaissance → Initial Access → Execution → Persistence → ... → C2 → Exfiltration / Lateral Movement
                                                                     ↑ VulcansTrace detects here
```

**Defensive value of C2 detection:**

- Strongly suggests a host is compromised (not just "suspicious") — regular beaconing is a high-fidelity C2 indicator, but legitimate applications can produce similar patterns
- Identifies the destination IP and port for investigation, potential blocking, and threat intel
- Enables correlation with lateral movement for escalation
- Provides timing evidence for incident timeline reconstruction

---

## Detection Coverage

| Beacon Type | Covered | Why |
|-------------|---------|-----|
| Fixed-interval HTTP/HTTPS | **Yes, if the traffic appears as regular connections in the logs** | Low std dev triggers the detector on all profiles, but Low profile's severity gate filters out standalone Medium-severity findings unless they are escalated |
| Lightly randomized intervals | **Partial** | Outcome depends on the actual interval set, trimming, and profile thresholds |
| Heavily randomized intervals | **Often no** | Larger jitter is less likely to survive the std dev threshold, especially on stricter profiles |
| Domain flux | **No** | Rotating destinations split across tuples — each group has fewer events than `BeaconMinEvents` |
| DNS tunneling | **No, as content analysis** | Connection timing may still be visible, but the detector has no DNS query content fields for tunnel-specific inspection |
| Domain fronting | **No** | Traffic to the same CDN IP blends with legitimate traffic; timing alone cannot distinguish C2 from normal usage |

---

## Security Takeaways

1. **ATT&CK provides a common reference model** — mapping detections helps analysts align findings with standard terminology for SOCs
2. **C2 detection suggests likely compromise** — unlike reconnaissance indicators, this strongly implies the breach has already happened, but legitimate applications can produce similar patterns
3. **Coverage is partial by design** — timing analysis catches protocol-agnostic patterns but misses content-level evasion
4. **Layered detection fills gaps** — DPI, DNS analysis, and threat intel complement timing-based C2 detection

