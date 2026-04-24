# MITRE ATT&CK Mapping

This document maps the intensity profile system to the detection techniques it tunes across the built-in detector set.

---

## Technique Coverage by Detector

| Detector | Technique | ID | Severity | Visible On Low |
|----------|-----------|-----|----------|---------------|
| PortScan | Network Service Discovery | T1046 | Medium | No |
| Flood | Network Denial of Service | T1498 | High | Yes |
| LateralMovement | Remote Services via configured admin ports (analyst-applied context) | T1021 (port-associated context; not sub-technique classification) | High | Yes |
| Beaconing | Application Layer Protocol | T1071 | Medium | No* |
| PolicyViolation | Exfiltration Over Alternative Protocol | T1048 (indirect; T1048.003 applies to FTP/Telnet) | High | Yes |
| Novelty | Singleton external `(DstIp, DstPort)` targets in the current dataset | N/A (weak-signal reconnaissance/novelty indicator) | Low | No |

\* Beaconing is escalated to Critical when the same host also triggers LateralMovement (RiskEscalator correlates both categories)

---

## Intensity Profile Effect on Coverage

| Technique | Low Profile | Medium Profile | High Profile |
|-----------|-------------|----------------|--------------|
| T1046 (Port Scan) | 30+ distinct `(DstIp, DstPort)` targets | 15+ distinct targets | 8+ distinct targets |
| T1021 (Lateral Movement) | 6+ hosts in 10 min | 4+ hosts | 3+ hosts |
| T1071 (Beaconing) | 8+ events, 3.0 stdDev | 6+ events, 5.0 stdDev | 4+ events, 8.0 stdDev |
| T1498 (Flood) | 400+ events in 60s | 200+ events | 100+ events |
| Novel connections | Disabled | Enabled | Enabled |

---

## Attack Lifecycle Position

```text
Recon → Initial Access → Execution → Persistence → PrivEsc → Defense Evasion
  ↑T1046                                                       ↓
                                    Lateral Movement ← DETECTED HERE → T1021
                                                      ↓
                                  Collection → C2 → Exfiltration → Impact
                                                ↑T1071        ↑T1048
```

The intensity profile system tunes detection across three lifecycle stages:

1. **Reconnaissance (T1046):** Port scan detection with variable sensitivity
2. **Lateral Movement (T1021):** Post-compromise pivot detection with variable host thresholds
3. **Command and Control (T1071):** Beaconing detection with variable regularity tolerance

---

## Coverage Gaps

| Technique | ID | Status | Reason |
|-----------|-----|--------|--------|
| DCOM | T1021.003 | Not detected by default profiles | Port 135 alone is an approximation; DCOM uses dynamic ports |
| WinRM | T1021.006 | Not detected by default profiles | Ports 5985/5986 not in default admin set |
| VNC | T1021.005 | Not detected by default profiles | Port 5900 not in default admin set |
| Cloud services | T1021.007 | Not detected | Outside current IP-and-port model |
| Encrypted C2 | T1573 | Indirect | Beaconing detects timing patterns regardless of encryption |

**Extending coverage:**

```csharp
var custom = baseProfile with
{
    AdminPorts = [445, 3389, 22, 5985, 5986, 135]
};
```

Port additions work best for techniques with stable service ports. DCOM/RPC behavior is more complex than a single-port match.

---

## Related Tactics

| Tactic | ID | Relationship |
|--------|-----|-------------|
| Credential Access | TA0006 | Often precedes lateral movement (pass-the-hash, Mimikatz) |
| Command and Control | TA0011 | May coexist — correlate Beaconing + LateralMovement via RiskEscalator |
| Exfiltration | TA0010 | Follows lateral movement — requires separate detection |
| Initial Access | TA0001 | Precedes lateral movement; PortScan may be reconnaissance |

---

## Operational Impact

- Enables threat detection with documented algorithmic approaches
- Supports MITRE ATT&CK mapping for security operations alignment
- Provides tunable sensitivity through configurable thresholds
---

## Security Takeaways

1. **ATT&CK provides a common reference model** — mapping detections helps analysts align findings with standard terminology
2. **Profile selection affects coverage depth** — High catches weaker signals per technique
3. **Coverage gaps are documented** — DCOM, WinRM, and cloud services need additional context
4. **Default ports cover the primary tools** — SMB, RDP, SSH are the most common pivot vectors

