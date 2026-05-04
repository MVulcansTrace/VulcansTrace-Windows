# Quick Reference

---

## Detection Algorithm (4 Steps)

Step A: Toggle Gate — skip if EnableLateralMovement is false or entries are empty
Step B: Filter — Internal-to-internal on admin ports only
Step C: Slide — Two-pointer window per source, counting distinct hosts
Step D: Check — If distinct hosts >= threshold → Create finding, break

---

## Configuration Parameters

| Parameter | Low | Medium | High |
|-----------|-----|--------|------|
| EnableLateralMovement | true | true | true |
| LateralMinHosts | 6 | 4 | 3 |

> **WPF UI override:** The Advanced Options expander exposes an **Enable lateral movement detection** check box that overrides the profile value at analysis time. It defaults to checked (enabled) for all intensities.
| LateralWindowMinutes | 10 | 10 | 10 |
| AdminPorts | [445, 3389, 22] | [445, 3389, 22] | [445, 3389, 22] |

---

## Downstream Pipeline

```text
LateralMovementDetector (High)
    → RiskEscalator (High → Critical if Beaconing + LateralMovement on same host)
    → MinSeverityToShow filter (visible in all profiles)
```

---

## Finding Structure

| Field | Value |
|-------|-------|
| Category | "LateralMovement" |
| Severity | High (Critical if correlated) |
| SourceHost | Pivoting host IP |
| Target | "multiple internal hosts" |
| TimeRangeStart | Earliest entry timestamp in window |
| TimeRangeEnd | Latest entry timestamp in window |
| ShortDescription | "Lateral movement from {sourceIp}" |
| Details | "Contacted N internal hosts on admin ports." |

---

## Complexity

| Metric | Value |
|--------|-------|
| Time (filter + sort) | O(n) filter + O(m log m) sort per source |
| Time (per source) | O(m²) worst case — Distinct() per iteration |
| Space | O(n) |
| Typical reduction | Traffic that cannot match the detector is filtered before the window scan |

---

## MITRE ATT&CK

| Technique | ID | Port | Detected? |
|-----------|-----|------|-----------|
| Remote Services (parent) | T1021 | Various | — |
| RDP | T1021.001 | 3389 | Yes, as a port-based approximation |
| SMB/Admin Shares | T1021.002 | 445 | Yes, as a port-based approximation |
| DCOM | T1021.003 | 135 | No (dynamic ports) |
| SSH | T1021.004 | 22 | Yes, as a port-based approximation |
| VNC | T1021.005 | 5900 | No |
| WinRM | T1021.006 | 5985/5986 | No (addable via config) |
| Cloud Services | T1021.007 | — | No |

> **Note:** These ATT&CK rows are analyst-applied mappings. The detector itself does not identify RDP, SMB, SSH, PsExec, or pass-the-hash directly; it matches internal-to-internal spread on configured destination ports.

---

## Evasion Summary

| Technique | Status | Countermeasure |
|-----------|--------|---------------|
| Slow pivoting | Missed | 24-hour cumulative tracking |
| Non-admin ports | Missed | Extend AdminPorts per environment |
| Living off the land | Partial | Add 5985/5986, 135; pair with endpoint telemetry |
| Proxy pivoting | Partial | Network flow analysis / hub-node anomaly detection |
| Distributed pivoting | Missed | Cross-source subnet correlation |
| Pass-the-hash | Sometimes detected | Resulting SMB spread may trigger; endpoint auth-log correlation |

---

## File References

| File | Purpose |
|------|---------|
| LateralMovementDetector.cs | Detector implementation |
| IDetector.cs | Strategy interface |
| AnalysisProfile.cs | Configuration model |
| AnalysisProfileProvider.cs | Low/Medium/High presets |
| IpClassification.cs | Internal IP classification |
| RiskEscalator.cs | Cross-detector escalation |
| LateralMovementDetectorTests.cs | Unit test coverage |
| RiskEscalatorTests.cs | Escalation test coverage |
