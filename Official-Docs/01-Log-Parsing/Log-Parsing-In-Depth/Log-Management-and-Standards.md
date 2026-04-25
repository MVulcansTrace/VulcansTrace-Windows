# Log Management and Standards

This document maps the log parsing pipeline to the standards and security practices that matter for data ingestion, evidence integrity, and downstream detection quality.

---

## Capability Mapping

The log parser does not detect attacks. It structures the input that all detectors depend on, preserves raw-line context, and rejects malformed data before it can distort downstream findings.

| Capability | Security Function | Relevant Framework |
|-----------|-------------------|-------------------|
| Multi-format timestamp parsing | Log normalization | NIST SP 800-92 (Log Management) |
| IP/port validation | Input sanitization | OWASP Input Validation |
| Fail-soft parsing | Availability during ingestion | NIST SP 800-61 (Incident Handling) |
| Raw line preservation | Forensic traceability | NIST SP 800-86 (Forensic Techniques) |
| Immutable records | Data integrity | Secure coding best practices |
| Field alignment tracking | Parsing correctness | NIST SP 800-92 (Log Management) |

---

## NIST SP 800-92 Alignment

The parser supports the log management lifecycle:

| Phase | Parser Contribution |
|-------|---------------------|
| **Log Collection** | Accepts Windows Firewall log format with multiple timestamp layouts |
| **Log Storage** | Immutable `LogEntry` records preserve parsed state without drift |
| **Log Analysis** | Structured data enables downstream detector analysis |
| **Log Disposal** | Not applicable (in-memory parsing, no persistent storage) |

---

## Federal Rules of Evidence (FRE) Mapping

| Rule | What It Requires | How The Parser Supports It |
|------|-----------------|---------------------------|
| **FRE 901** (Authentication) | Evidence must be what the proponent claims | `RawLine` preservation enables analysts to verify parsed data against source |
| **FRE 901(b)(9)** (Process Authentication) | Evidence produced by a process must be authenticated | Deterministic parsing with explicit error tracking supports process verification |
| **FRE 1001** (Definitions for ESI) | Electronically stored information is defined and discoverable | `LogEntry` records qualify as ESI; raw line preservation maintains connection to source |

---

## Data Quality as a Security Capability

```text
Threat: Poisoned input data
          ↓
Layer 1: Timestamp validation → Reject malformed timestamps
          ↓
Layer 2: IP/port validation → Reject invalid addresses and ports
          ↓
Layer 3: Fail-soft parsing → Skip bad rows without crashing
          ↓
Layer 4: Raw line preservation → Enable forensic verification
```

The parser provides all four layers. Bad data is rejected at ingestion, not propagated to detectors.

---

## Related Attack Tactics (Context)

All six detectors depend on this parser. The table below lists the attack tactics that VulcansTrace detects using parsed log data:

| Tactic | ID | Detector |
|--------|-----|----------|
| Discovery | TA0007 | PortScanDetector (T1046 Network Service Discovery) |
| Discovery | TA0007 | NoveltyDetector (T1046 Network Service Discovery) |
| Command and Control | TA0011 | BeaconingDetector (T1071 Application Layer Protocol) |
| Lateral Movement | TA0008 | LateralMovementDetector (T1021 Remote Services) |
| Impact | TA0040 | FloodDetector (T1498 Network Denial of Service) |
| Exfiltration | TA0010 | PolicyViolationDetector (T1048 Exfiltration Over Alternative Protocol) |

> **Note:** The parser itself does not classify attacks — it provides clean, structured data that enables detectors to identify these patterns.

---

## Input Validation as a Security Boundary

| Validation Stage | What It Checks | Security Impact |
|-----------------|----------------|-----------------|
| Timestamp format | Exact layout matching | Prevents timestamp injection and parsing ambiguity |
| Placeholder detection | `-` values indicate missing fields | Rejects entries with absent IP or port fields |
| IP syntax | `IPAddress.TryParse` | Rejects malformed addresses |
| Port range | 0-65535 enforcement | Rejects impossible port values |
| Field alignment | Explicit index tracking | Handles variable timestamp token counts correctly |

---

## Security Takeaways

1. **Parsing is part of the security boundary** — poisoned input compromises all downstream detection
2. **Fail-soft design maintains availability** — one bad row does not break the entire analysis
3. **Raw line preservation enables verification** — analysts can trace findings back to source
4. **Deterministic parsing supports reproducibility** — same input always produces same output
5. **Explicit scope matters** — the parser documents what it validates and what it cannot verify

