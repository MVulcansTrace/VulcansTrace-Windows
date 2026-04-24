# MITRE ATT&CK Mapping

---

## Technique Mapping

| Technique | ID | Port | What the Detector Catches |
|-----------|-----|------|--------------------------|
| Exfiltration Over Alternative Protocol | **T1048** | 445, + custom | Analyst-applied mapping when disallowed-port egress is interpreted as alternate-protocol use |
| Exfiltration Over Unencrypted Non-C2 Protocol | **T1048.003** | 21, 23 | Analyst-applied mapping when FTP/Telnet findings are interpreted as unencrypted exfil-related activity |

> **Note:** The detector is port-and-IP based only. It does not inspect payloads, bytes transferred, encryption state, protocol semantics, or operator intent. ATT&CK mappings here are analyst-applied interpretations layered on top of the observed network pattern.

> **Why SMB maps to T1048 and not T1048.003:** SMB3 supports encryption, so SMB traffic is not inherently "unencrypted." Port 445 in the default list is treated as a broader egress-policy risk signal rather than proof of a specific unencrypted exfiltration method.

---

## Attack Lifecycle Position

```text
Initial Access → Execution → Persistence → Collection → [POSSIBLE EGRESS RISK] → Impact
                                                        ↑
                                                  VulcansTrace may contribute context here
```

> **Not every finding is malicious.** The detector flags internal→external traffic on disallowed ports, which can be consistent with exfiltration or C2 but also with misconfigured applications and policy non-compliance. The ATT&CK mapping below reflects analyst interpretation, not detector-native classification.

**Why this position matters:**

- Post-compromise signal — the attacker already has access to an internal host
- May indicate risky egress behavior that deserves triage
- May contribute context to exfiltration or C2 investigations, although this detector only observes the port-based signal
- Elevated severity — the detector assigns High severity; whether the event warrants immediate investigation is an analyst triage decision

---

## Why These Specific Ports

### Port 21 — FTP

| Risk | Details |
|------|---------|
| Cleartext credentials | Username/password visible in packets |
| No integrity checking | Files can be modified in transit |
| Anonymous access | May be enabled on some servers, increasing misuse risk |
| Multi-channel behavior | Control/data channels complicate filtering and monitoring |

### Port 23 — Telnet

| Risk | Details |
|------|---------|
| Entire session unencrypted | Everything visible in packets |
| Trivial credential interception | Network sniffing reveals login |
| Remote access | Direct shell access if compromised |
| Legacy systems | Often found on embedded devices |

### Port 445 — SMB

| Risk | Details |
|------|---------|
| Worm propagation | WannaCry, NotPetya, EternalBlue |
| File sharing | Data exfiltration vector |
| Historic exploit surface | SMB has been tied to major exploitation and worm activity |
| Rarely needed externally | Outbound SMB to internet destinations is usually high-signal |

---

## Coverage Matrix

| Technique | Detected? | Notes |
|-----------|-----------|-------|
| T1048.003 (Unencrypted Exfil) | Analyst-applied / partial | FTP (21) and Telnet (23) are in the default list, but intent and transfer content are not observed |
| T1048 (Alternative Protocol) | Analyst-applied / partial | Only ports explicitly in `DisallowedOutboundPorts`; alternative-protocol use is inferred from context |
| T1071 (Application Layer Protocol) | No | Would require adding HTTP/HTTPS ports — impractical due to noise |
| T1573 (Encrypted Channel) | No | Cannot detect without payload inspection |

**Extending coverage:**

```csharp
// Extend an existing tuned profile to preserve all other detector settings
var profile = baseProfile with
{
    DisallowedOutboundPorts = new[] { 21, 23, 445, 25, 69 }
    // Add: SMTP (25) for email exfil, TFTP (69) for trivial file transfer
};
```

Port additions work best for protocols with stable, well-known port numbers.

---

## Context Determines the Mapping

Same disallowed-port pattern, different ATT&CK context:

- **Internal host → external FTP endpoint** → May be mapped to T1048.003 if surrounding evidence supports unencrypted exfiltration
- **Internal host → external SMB endpoint** → May indicate anomalous outbound SMB activity or policy non-compliance
- **Internal host → external Telnet endpoint** → May indicate risky legacy-protocol use, but intent still requires analyst judgment

The detector identifies the network pattern. The analyst still provides the operational context and determines whether the finding maps to exfiltration, C2, misconfiguration, or simple policy non-compliance.

---

## Defense-in-Depth Position

```text
┌─────────────────────────────────────────────────────────────┐
│                     Network Boundary                        │
├─────────────────────────────────────────────────────────────┤
│  Firewall Rules     │ Blocks based on port/IP               │
├─────────────────────────────────────────────────────────────┤
│  DLP Systems        │ Content-aware blocking                │
├─────────────────────────────────────────────────────────────┤
│  VulcansTrace       │ Detects internal→external on          │
│  Policy Detector    │ configured disallowed ports           │
├─────────────────────────────────────────────────────────────┤
│  SIEM Correlation   │ Patterns across multiple events       │
└─────────────────────────────────────────────────────────────┘
```

This detector provides the **policy layer** — catching the gap between what the firewall allows and what organizational policy prohibits.

---

## Security Takeaways

1. **ATT&CK provides a common reference model** — mapping detections helps analysts align findings with standard terminology for any SOC
2. **Default ports cover common egress-policy risk signals** — FTP, Telnet, and SMB on external destinations
3. **Context determines the mapping** — same pattern can mean different things depending on the environment
4. **Coverage gaps are documented** — encrypted channels and application-layer protocols require different tools
5. **Extensible by configuration** — teams add ports based on their threat model, not code changes

