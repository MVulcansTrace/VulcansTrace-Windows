# MITRE ATT&CK Mapping

---

## Technique Mapping

| Technique | ID | Port | What the Detector Catches |
|-----------|-----|------|--------------------------|
| Remote Services | T1021 | Various | Parent technique analysts can map to when the overall pattern reflects internal remote-service pivoting |
| Remote Desktop Protocol | T1021.001 | 3389 | Port-3389 spread across multiple internal hosts, when analysts judge the traffic to be RDP-related |
| SMB/Windows Admin Shares | T1021.002 | 445 | Port-445 spread across multiple internal hosts, when analysts judge the traffic to be SMB/admin-share-related |
| SSH | T1021.004 | 22 | Port-22 spread across multiple internal hosts, when analysts judge the traffic to be SSH-related |

> **Note:** The detector is port-based, not protocol-aware. It filters for internal-to-internal traffic whose destination port is in `AdminPorts`, then counts distinct destination hosts in a sliding window. ATT&CK sub-technique labels are analyst-applied context layered on top of that network pattern.

---

## Attack Lifecycle Position

```text
Recon → Initial Access → Execution → Persistence → PrivEsc → Defense Evasion
                                                      ↓
                                    Lateral Movement ← [DETECTED HERE]
                                                      ↓
                                  Collection → C2 → Exfiltration → Impact
```

> **Note:** This is a simplified chain — Resource Development, Credential Access, and Discovery tactics are omitted for brevity.

**Why this position matters:**

- Late-stage detection — attacker already has a foothold
- Pre-exfiltration — still time to contain before data loss
- Active spreading — each minute means more compromised systems

---

## Coverage Matrix

| Technique | Detected? | Notes |
|-----------|-----------|-------|
| T1021.001 (RDP) | Yes, as a port-based approximation | Port 3389 in default admin set |
| T1021.002 (SMB) | Yes, as a port-based approximation | Port 445 in default admin set |
| T1021.004 (SSH) | Yes, as a port-based approximation | Port 22 in default admin set |
| T1021.003 (Distributed Component Object Model) | No | Adding port 135 is an approximation; DCOM uses dynamic ports |
| T1021.006 (Windows Remote Management) | No | Ports 5985/5986 not in default set; addable via configuration |
| T1021.005 (VNC) | No | Port 5900 not in default set |
| T1021.007 (Cloud Services) | No | Outside current IP-and-port model |
| T1021.008 (Direct Cloud VM Connections) | No | Outside current IP-and-port model |

**Extending coverage:**

```csharp
var profile = new AnalysisProfile
{
    AdminPorts = new[] { 445, 3389, 22, 5985, 5986, 135 }
};
```

Port additions work best for techniques with stable service ports (WinRM, VNC). DCOM/RPC behavior is more complex than a single-port match.

---

## Context Determines the Mapping

This detector only operates after an internal-to-internal filter:

- **Internal compromised host** pivoting to internal targets → T1021 (Lateral Movement), with sub-techniques inferred from ports and surrounding evidence
- **External source** scanning internal hosts → out of scope for this detector, because `IsInternal(SrcIp)` filtering removes that traffic before analysis

The detector identifies the network pattern that survives its filters. The analyst still provides the operational context.

---

## Related Tactics (Not Directly Detected)

| Tactic | ID | Relationship |
|--------|-----|-------------|
| Credential Access | TA0006 | Often precedes lateral movement (pass-the-hash, Mimikatz) |
| Command and Control | TA0011 | May coexist — `RiskEscalator` automatically escalates **all findings from a host** to Critical when both Beaconing and Lateral Movement are detected from the same source host |
| Exfiltration | TA0010 | Follows lateral movement — requires separate detection |
| Initial Access | TA0001 | Precedes lateral movement |

---

## Security Takeaways

1. **ATT&CK provides a common reference model** — mapping detections helps analysts align findings with standard terminology
2. **Context determines the mapping** — same pattern, different technique based on source position
3. **Coverage gaps are documented** — DCOM, WinRM, cloud services need additional context
4. **Default ports cover common pivot-port signals** — ports commonly associated with SMB, RDP, and SSH

