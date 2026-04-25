# Evidence Integrity and Standards

This document maps the evidence packaging pipeline to the standards, controls, and framework language that matter for evidence integrity and post-export handoff.

---

## Capability Mapping

The evidence packaging pipeline does not detect attacks. It protects the *output* of detection by making exported reports, raw logs, and manifest metadata verifiable after handoff.

| Capability | Security Function | Relevant Framework |
|-----------|-------------------|-------------------|
| SHA-256 per-file hashing | Evidence integrity verification | NIST SP 800-61 (Incident Handling) |
| HMAC-SHA256 manifest signing | Keyed manifest verification | FRE 901 (Authentication) |
| Multi-format output | Stakeholder communication | NIST CSF RS.CO (Communications) |
| Warning preservation | Analysis transparency | NIST SP 800-61 (Incident Handling) |
| Timestamp normalization | Temporal consistency | ISO 8601, ZIP format specification |
| Deterministic builds | Independent verification | NIST SP 800-86 (Integrating Forensic Techniques into Incident Response) |

---

## NIST SP 800-61 Alignment

The pipeline supports the incident handling lifecycle:

| Phase | Pipeline Contribution |
|-------|----------------------|
| **Detection & Analysis** | Multi-format output enables different analysis workflows |
| **Containment, Eradication, Recovery** | Cryptographic hashes enable evidence preservation during response |
| **Post-Incident Activity** | Signed archives support lessons-learned documentation and audit |

---

## Federal Rules of Evidence (FRE) Mapping

| Rule | What It Requires | How The Pipeline Supports It |
|------|-----------------|---------------------------|
| **FRE 901** (Authentication) | Evidence must be what the proponent claims | SHA-256 hashes + HMAC signature verify integrity and key-possession; full legal authentication requires key management and audit controls |
| **FRE 901(b)(9)** (Process Authentication) | Evidence produced by a process or system must be authenticated | SHA-256 hashes authenticate file content; HMAC signature verifies the manifest was signed with the expected key — proving who held the key requires operational controls outside the pipeline |
| **FRE 1001** (Definitions for ESI) | Electronically stored information is defined and discoverable | All outputs (CSV, HTML, Markdown, raw text) and the integrity manifest (JSON) qualify as ESI under FRE 1001; multiple formats can make review and exchange easier, while admissibility remains a legal determination |
| **FRE 1002** (Best Evidence) | Original content required | Raw log preserved as `log.txt` with SHA-256 integrity fingerprint |

---

## Defense Evasion Countermeasures

The pipeline specifically counters these defense evasion techniques:

| Threat | Scope | How The Pipeline Counters It |
|--------|-------|------------------------------|
| **Post-export file modification** | N/A (integrity control) | SHA-256 per-file detects any modification to packaged files after export |
| **Manifest tampering** | N/A (tool-specific) | HMAC-SHA256 requires signing key to produce valid signature |
| **ZIP timestamp manipulation** | N/A (format constraint) | ZIP timestamps normalized to valid range; `createdUtc` in signed manifest is authoritative |
| **Log injection into rendered output** | N/A (output hardening) | CSV injection prevention (formula prefix), XSS encoding (HTML), Markdown escaping (special characters) |

> **Important scope note:** SHA-256 hashes and HMAC signatures protect the evidence package *after export*. They do **not** detect tampering of source logs *before* they were loaded into VulcansTrace. For on-host indicator removal (e.g., T1070.004 File Deletion), implement event log monitoring or source system forensics.

---

## Detector Coverage Feeding the Pipeline

All six VulcansTrace detectors feed this pipeline. The table below lists those with explicit MITRE ATT&CK tactic or technique mappings in the codebase:

| Tactic | ID | MITRE-Mapped Detector |
|--------|-----|-----------------------------------|
| Discovery | TA0007 | PortScanDetector (T1046 Network Service Discovery) |
| Command and Control | TA0011 | BeaconingDetector (T1071 Application Layer Protocol) |
| Lateral Movement | TA0008 | LateralMovementDetector (T1021 Remote Services) |
| Impact | TA0040 | FloodDetector (T1498 Network Denial of Service) |

> **Not shown above:** NoveltyDetector feeds the pipeline with weak-signal coverage of T1046 (Network Service Discovery), T1071 (Application Layer Protocol), and T1568 (Dynamic Resolution) — see the Novelty Detection module's MITRE mapping for details. PolicyViolationDetector feeds the pipeline mapped to T1048 (Exfiltration Over Alternative Protocol), including sub-technique T1048.003.

> **Note:** The pipeline also preserves warnings from detectors (e.g., truncation notices from PortScanDetector). These support analysis transparency — they help analysts understand what the tool did *not* examine, not defense evasion by adversaries.

---

## Integrity Verification as a Security Capability

```text
Threat: Evidence tampering during handoff
          ↓
Layer 1: SHA-256 per-file  → Detect which file was modified
          ↓
Layer 2: HMAC-SHA256       → Detect manifest tampering
          ↓
Layer 3: Procedural controls → Timestamp reconciliation, handoff logs
```

The pipeline provides Layers 1 and 2. Layer 3 is an operational responsibility that the tool supports (bundle metadata timestamp normalization aids reconciliation) but cannot enforce (no handoff logging).

---

## Security Takeaways

1. **Evidence packaging maps to forensic standards** — NIST, FRE, and ISO-style timestamp conventions
2. **Integrity supports the detection workflow** — tamper-evident evidence exposes post-export manipulation
3. **Multi-format output supports diverse stakeholders** — different audiences need different access methods (CSV for analysis, HTML for review, Markdown for documentation)
4. **Explicit scope matters** — the pipeline documents what it proves and what it cannot prove

