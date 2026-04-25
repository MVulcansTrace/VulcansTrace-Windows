# Test Coverage by Threat Behavior

This document maps automated test coverage to the detector behaviors that analysts may relate to MITRE ATT&CK techniques. The tests validate VulcansTrace behavior; they are not themselves a detection capability.

---

## Detector Behavior Coverage

| Technique | ID | Detector | Test Coverage | Detection Quality |
|-----------|-----|----------|---------------|-------------------|
| Network Service Discovery | T1046 | PortScanDetector | Above/below threshold, multi-source, truncation | High |
| Application Layer Protocol | T1071 | BeaconingDetector | Regular/irregular intervals, outlier trim, sample cap | High |
| Remote Services | T1021 | LateralMovementDetector | Above/below threshold, multi-source, time-spread | High |
| Network Denial of Service | T1498 | FloodDetector | Above/below threshold, window-based | Medium |
| Exfiltration Over Alternative Protocol | T1048 | PolicyViolationDetector | Disallowed port scenarios | Medium |
| *(VulcansTrace-specific)* | — | NoveltyDetector | One-off destination, repeated destination | Medium |

---

## Test Evidence by Detector Behavior

### T1046 — Network Service Discovery

```csharp
// PortScanDetectorTests.cs
Detect_WithPortScanAboveThreshold_ReturnsFinding              // 20 ports > 15 threshold
Detect_WithPortScanBelowThreshold_ReturnsNoFindings           // 5 ports < 15 threshold
Detect_WithMultipleSourceIps_ReturnsFindingsForEach           // Coordinated scanning
Detect_WithTruncation_EmitsWarning                            // Truncation warnings
```

**Coverage:** Threshold boundary, disabled state, empty input, multi-source, truncation warnings.

### T1071 — Application Layer Protocol

```csharp
// BeaconingDetectorTests.cs
Detect_WithRegularBeaconing_ReturnsFinding          // 90s intervals, stdDev ~0
Detect_WithIrregularIntervals_ReturnsNoFindings     // Mixed intervals, high stdDev
Detect_WithOutlierTrimStillFlagsBeacon              // Outliers removed, beacon still detected
Detect_RespectsSampleCap                            // Sample cap enforcement
```

**Coverage:** Regular detection, irregular rejection, insufficient events, boundary conditions, outlier trimming, sample cap, mixed traffic.

### T1021 — Remote Services

```csharp
// LateralMovementDetectorTests.cs
Detect_WithLateralMovementAboveThreshold_ReturnsFinding   // Internal-to-internal on admin ports
Detect_WithExternalToInternalTraffic_ReturnsNoFindings          // External source → internal targets correctly filtered
```

**Coverage:** Admin port access, internal-to-internal, external filtering, multi-source, time spread. This is port-associated remote-service behavior, not protocol- or tool-level verification.

### T1498 — Network Denial of Service

```csharp
// FloodDetectorTests.cs
Detect_WithFloodAboveThreshold_ReturnsFinding       // High volume in window
Detect_WithFloodBelowThreshold_ReturnsNoFindings     // Low volume in window
```

**Coverage:** Volume threshold, time window, disabled state. This is source-volume flood behavior, not destination-aware proof of a single-target direct network flood. Limitation: slow-rate DoS not covered.

### T1048 — Exfiltration Over Alternative Protocol

```csharp
// PolicyViolationDetectorTests.cs
Detect_WithPolicyViolation_ReturnsFinding             // FTP/21
Detect_WithAllowedPort_ReturnsNoFindings             // HTTPS/443
```

**Note:** This is an indirect mapping. PolicyViolationDetector flags outbound connections to disallowed ports (FTP/21, Telnet/23, SMB/445) — unencrypted legacy protocols that adversaries use to exfiltrate data outside the main C2 channel. Sub-technique T1048.003 (Exfiltration Over Unencrypted Non-C2 Protocol) applies directly to FTP and Telnet.

---

## Attack Lifecycle Coverage

```text
Recon → Initial Access → Execution → Persistence → PrivEsc → Defense Evasion
    ↓                                                    ↓
  [T1046]                                    Lateral Movement ← [T1021]
                                                                ↓
                                            Collection → C2 → Exfiltration → Impact
                                                          [T1071]    [T1048]    [T1498]
```

**Integration test coverage:** `SentryAnalyzerIntegrationTests.cs` verifies that T1071 + T1021 findings from the same host trigger cross-detector correlation via `RiskEscalator`, escalating to Critical severity.

---

## Coverage Matrix

| Technique | Detected? | Test Verified? | Limitations |
|-----------|-----------|---------------|-------------|
| T1046 (Network Service Discovery) | Yes | Yes | Slow scanning evades 5-minute window |
| T1071.001 (Web Protocols) | Partial | Partial | Encrypted HTTPS hides payload |
| T1021.001 (RDP) | Contextual | Indirect | Port 3389 in default admin set; tests verify admin-port behavior, not RDP protocol semantics |
| T1021.002 (SMB) | Contextual | Indirect | Port 445 in default admin set; tests verify admin-port behavior, not SMB share semantics |
| T1021.004 (SSH) | Contextual | Indirect | Port 22 in default admin set; tests verify admin-port behavior, not SSH session semantics |
| T1021.003 (DCOM) | No | No | Dynamic ports not covered |
| T1021.006 (WinRM) | No | No | Ports 5985/5986 not in default set |
| T1498.001 (Direct Network Flood) | Contextual | Indirect | Tests verify source-volume flood behavior; the detector is not single-target aware |
| T1048 (Exfiltration Over Alternative Protocol) | Indirect | Yes | Only disallowed-port violations |

---

## Correlated Threat Escalation

```text
If Beaconing (T1071) + LateralMovement (T1021) from same host:
    → RiskEscalator promotes ALL findings for that host to Critical
    → Highest-severity automated finding the pipeline produces
```

**Test coverage:** Verified in `SentryAnalyzerIntegrationTests.cs` — the composite attack test asserts that findings for host `10.0.0.20` are escalated to Critical when both detectors fire.

---

## Operational Impact

- Enables threat detection with documented algorithmic approaches
- Shows which ATT&CK-related detector behaviors are covered by automated tests
- Provides tunable sensitivity through configurable thresholds
---

## Security Takeaways

1. **ATT&CK provides a common reference model** — mapping detector test coverage helps align validation work with standard terminology
2. **Five tactic areas have detector behavior covered by tests** — Discovery, C2, Lateral Movement, Exfiltration, Impact
3. **RiskEscalator adds cross-technique correlation** — T1071 + T1021 = Critical
4. **Coverage gaps are documented** — DCOM, WinRM, cloud services, and slow-rate attacks need additional context

