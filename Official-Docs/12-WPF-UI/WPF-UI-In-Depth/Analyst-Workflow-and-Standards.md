# Analyst Workflow and Standards

This document maps the WPF UI to the standards and workflow concerns that matter for analyst triage, incident response, and evidence handoff.

---

## Capability Mapping

The WPF UI does not detect attacks. It presents detection results, keeps the analyst workflow responsive, and exposes evidence export controls for post-analysis handoff.

| Capability | Security Function | Relevant Framework |
|-----------|-------------------|-------------------|
| Background thread analysis | UI responsiveness during analysis | NIST SP 800-61 (Incident Handling) |
| Cancellation support | Analyst control over long-running operations | Usability security principle |
| Severity-based filtering | Alert prioritization | NIST CSF DE.CM (Security Continuous Monitoring) |
| Evidence packaging | Secure handoff to external tools | NIST SP 800-86 (Forensic Techniques) |
| Sortable findings table | Triage efficiency | NIST CSF DE.AE (Anomalies and Events) |
| Multi-format export | Stakeholder communication | NIST CSF RS.CO (Communications) |

---

## NIST CSF Alignment

The UI supports multiple cybersecurity framework functions:

| Function | UI Contribution |
|----------|-----------------|
| **Detect (DE)** | Findings table displays severity, source, targets, and time range for each detection |
| **Respond (RS)** | Evidence packaging enables secure handoff to response teams |
| **Recover (RC)** | Analysis results and exported evidence support post-incident review |

---

## NIST SP 800-61 Alignment

The UI supports the incident handling lifecycle:

| Phase | UI Contribution |
|-------|-----------------|
| **Preparation** | Profile selection (Low/Medium/High intensity) configures detection sensitivity |
| **Detection & Analysis** | Findings table with sorting, filtering, and severity visualization |
| **Containment, Eradication, Recovery** | Evidence export provides data for response actions |
| **Post-Incident Activity** | Exported reports support lessons-learned documentation |

---

## Evidence Handoff Context

The UI exposes evidence export, but the cryptographic integrity model lives in the Evidence Packaging subsystem. See [Evidence Integrity and Standards](../../09-Evidence-Packaging/Evidence-Packaging-In-Depth/Evidence-Integrity-and-Standards.md) for the detailed SHA-256, HMAC-SHA256, NIST, and Federal Rules of Evidence discussion.

---

## Analyst Workflow as a Security Capability

```text
Threat: Analyst fatigue and missed findings
          ↓
Layer 1: Severity filtering → Focus on high-priority findings first
          ↓
Layer 2: Sortable columns → Quick triage by source, target, or time
          ↓
Layer 3: Background analysis → UI remains responsive during long operations
          ↓
Layer 4: Cancellation → Abort wrong analysis without waiting
          ↓
Layer 5: Evidence packaging → Secure handoff preserves investigation work
```

The UI provides all five layers. Analyst effectiveness is maintained even during large-scale analysis.

---

## Detector Findings Presented by the UI

The UI displays findings from all six detectors. The table below lists the attack tactics that VulcansTrace detects and presents through the UI:

| Tactic | ID | Detector | UI Presentation |
|--------|-----|----------|-----------------|
| Discovery | TA0007 | PortScanDetector | Findings table with target count and port list |
| Command and Control | TA0011 | BeaconingDetector | Findings table with interval statistics and destination |
| Lateral Movement | TA0008 | LateralMovementDetector | Findings table with host spread and admin ports |
| Impact | TA0040 | FloodDetector | Findings table with event count and time range |
| Exfiltration | TA0010 | PolicyViolationDetector | Findings table with disallowed port and destination |
| Discovery | TA0007 | NoveltyDetector | Findings table with singleton destinations (High intensity only) |

> **Note:** The UI also displays escalation status — findings from hosts with both Beaconing and LateralMovement are escalated to Critical severity by the RiskEscalator component.

---

## Security Takeaways

1. **UI responsiveness is a security feature** — frozen tools get closed, and analysts lose visibility
2. **Analyst control reduces errors** — cancellation and filtering prevent frustration-driven mistakes
3. **Evidence packaging enables secure handoff** — cryptographic integrity supports post-export integrity checks during handoff
4. **Severity-based presentation supports triage** — analysts focus on highest-risk findings first
5. **Explicit scope matters** — the UI documents what it displays and what filters may hide

