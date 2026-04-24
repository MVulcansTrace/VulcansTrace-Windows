# MITRE ATT&CK Mapping

---

## Technique Mapping

| Technique | ID | When It Applies |
|-----------|-----|-----------------|
| Active Scanning | T1595 | External, pre-compromise probing |
| Scanning IP Blocks | T1595.001 | Range-based external scanning |
| Network Service Discovery | T1046 | Internal, post-compromise enumeration |

> **Note:** The code references T1046 in the `PortScanDetector` doc comment. T1595 and T1595.001 are analyst-applied mappings based on source context — the detector does not classify by tactic internally.

---

## Why Context Determines the Mapping

Same traffic, different ATT&CK technique:

- **External source** (203.0.113.50) scanning your servers → T1595 (Reconnaissance)
- **Internal source** (192.168.1.50, compromised host) scanning internal servers → T1046 (Discovery)

> **Note:** This distinction is analyst-applied context. The detector does not call `IpClassification` to distinguish external from internal sources (unlike LateralMovementDetector and PolicyViolationDetector which do). The SOC determines the tactic.

The detector sees the pattern; the analyst provides context.

---

## Attack Lifecycle Position

```
External: Reconnaissance → Initial Access → Execution → ...
                       ↑ VulcansTrace detects the scan pattern here;
                         analyst maps to Reconnaissance (T1595)

Internal: Initial Access → Discovery → Lateral Movement → ...
                               ↑ VulcansTrace detects the same scan pattern here;
                                 analyst maps to Discovery (T1046)
```

**Defensive value of early detection:**
- Catching recon gives defenders time to harden BEFORE exploitation
- Scan patterns reveal attacker behavior (e.g., scan speed, target range) that can help identify the type of activity
- Source IPs can be added to blocklists

---

## Security Takeaways

1. **ATT&CK provides a common reference model** — mapping detections helps analysts align findings with standard terminology
2. **Context determines the mapping** — the same finding can be mapped to different ATT&CK techniques depending on source position, which the analyst provides
3. **Early warning is highest-value detection** — recon is the first stage
4. **Coverage boundaries matter** — passive recon, app-layer, credential attacks need different tools

