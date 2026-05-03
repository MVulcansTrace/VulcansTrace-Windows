# Quick Reference

---

## Detection Algorithm (4 Steps)

Step A: Toggle Gate — Skip detection when EnablePolicy is false or input is empty
Step B: Setup — Load disallowed ports into HashSet for O(1) lookup
Step C: Three-Condition Filter — Source internal, dest external, port non-null and disallowed
Step D: Finding Creation — One structured finding per violation

---

## Configuration Parameters

| Parameter | Low | Medium | High |
|-----------|-----|--------|------|
| EnablePolicy | true | true | true |
| DisallowedOutboundPorts | [21, 23, 445] | [21, 23, 445] | [21, 23, 445] |

---

## Downstream Pipeline

```text
PolicyViolationDetector (High)
    → RiskEscalator (High → Critical if Beaconing + LateralMovement are also present for the same host)
    → MinSeverityToShow filter (visible in all profiles)
```

---

## Finding Structure

| Field | Value |
|-------|-------|
| Category | "PolicyViolation" |
| Severity | High (Critical if correlated) |
| SourceHost | e.SrcIp (internal host) |
| Target | e.DstIp:e.DstPort (external destination) |
| TimeRangeStart | e.Timestamp (point event) |
| TimeRangeEnd | e.Timestamp (same as start) |
| ShortDescription | "Disallowed outbound port from {SrcIp}" |
| Details | "Outbound connection to {DstIp}:{DstPort} on a disallowed port." |

> **Note:** The `Details` text reflects the current finding string in code. The detector itself does not verify successful session establishment; it flags qualifying internal-to-external log entries on disallowed ports regardless of `Action`.

---

## Complexity

| Metric | Value |
|--------|-------|
| Time (gate + init) | O(k) where k = number of ports |
| Time (scan) | O(n) — single pass |
| Per-entry cost | O(1) — three short-circuit checks |
| Space | O(m) where m = number of violations |
| Lines of code | 53 |

---

## IP Classification

| Range | Classification |
|-------|---------------|
| 10.0.0.0/8 | Internal |
| 172.16.0.0/12 | Internal |
| 192.168.0.0/16 | Internal |
| 127.0.0.0/8 | Internal (IPv4 loopback) |
| ::1 | Internal (IPv6 loopback) |
| fc00::/7 | Internal (IPv6 ULA) |
| fe80::/10 | Internal (IPv6 link-local) |
| All other valid IP addresses | External |

---

## MITRE ATT&CK

| Technique | ID | Coverage |
|-----------|-----|----------|
| Exfiltration Over Alternative Protocol | T1048 | Analyst-applied context for disallowed-port egress patterns |
| Exfil Over Unencrypted Non-C2 Protocol | T1048.003 | Analyst-applied context for FTP/Telnet-related findings |

> **Note:** These ATT&CK rows are analyst-applied interpretations. The detector itself only checks `SrcIp` internal, `DstIp` external, and `DstPort` in `DisallowedOutboundPorts`.

---

## Evasion Summary

| Technique | Status | Countermeasure |
|-----------|--------|---------------|
| Protocol tunneling on allowed ports | Missed | DPI, TLS inspection |
| Port hopping (non-listed ports) | Missed | Threat-model-driven port updates |
| DNS exfiltration | Missed | DNS monitoring |
| Alert fatigue from misconfigured apps | All violations reported | SIEM aggregation downstream |
| IPv6 Target ambiguity | Finding created but format unclear | Bracket notation for IPv6 |

---

## File References

| File | Purpose |
|------|---------|
| PolicyViolationDetector.cs | Detector implementation (53 lines) |
| IDetector.cs | Strategy interface |
| AnalysisProfile.cs | Configuration model |
| AnalysisProfileProvider.cs | Low/Medium/High presets |
| IpClassification.cs | Internal/external IP classification |
| Finding.cs | Output record structure |
| RiskEscalator.cs | Cross-detector escalation |
| SentryAnalyzer.cs | Pipeline orchestration |
| PolicyViolationDetectorTests.cs | 9 unit tests |
| SentryAnalyzerIntegrationTests.cs | End-to-end pipeline tests |
