# MITRE ATT&CK Mapping

The correlation engine correlates findings from detectors whose outputs analysts may map to MITRE ATT&CK techniques across multiple tactics. While individual detectors may be associated with one or more techniques, the correlation engine itself only sees detector categories and host grouping. It does not classify raw traffic directly.

---

## Cross-Tactic Correlation

```text
Command & Control (TA0011)
  └── T1071: Application Layer Protocol
        └── Beaconing detector → Medium severity

Lateral Movement (TA0008)
  └── T1021: Remote Services
        └── LateralMovement detector → High severity

Cross-Tactic Correlation
  └── Beaconing + LateralMovement findings on same host → Critical severity
```

| Tactic | Technique Context | ID | Detector | Individual Severity |
|---|---|---|---|---|
| Command & Control | Application Layer Protocol | T1071 | BeaconingDetector | Medium |
| Lateral Movement | Remote Services | T1021 | LateralMovementDetector | High |
| **Cross-Tactic** | **Co-occurring findings often mapped to T1071 + T1021** | **N/A (correlation rule)** | **RiskEscalator** | **Critical** |

---

## Why This Combination Is High-Confidence

An individual Beaconing finding may be analyst-interpreted as behavior adjacent to T1071 because it reflects periodic communication with an external endpoint — possibly C2, possibly software updates. An individual LateralMovement finding may be analyst-interpreted as behavior adjacent to T1021 because it reflects internal host-to-admin-port connections — possibly pivoting, possibly admin tooling.

When both detector findings originate from the same host, the confidence increases significantly. A machine showing both periodic external communication and internal admin-port activity may be exhibiting two distinct phases of the attack lifecycle:

```text
Kill Chain Position:
  ... → Installation → Command & Control (T1071) → Lateral Movement (T1021) → ...
                          ↑                            ↑
                     Beaconing detected          LateralMovement detected
                          └──────── same host ────────┘
                                        ↓
                              Critical: likely active compromise
```

This is not a new ATT&CK technique — it is a higher-confidence observation that two existing techniques are co-occurring on the same asset.
It is also not proof of those techniques by itself; the ATT&CK mapping is analyst-applied context layered onto the underlying detector outputs.

---

## Detection Coverage

### What the Correlation Engine Escalates

| Pattern | Tactic(s) | Escalation |
|---|---|---|
| Beaconing + LateralMovement (same host) | TA0011 + TA0008 | → Critical |

### What Individual Detectors Find Without Escalation

| Pattern | Detector | Severity |
|---|---|---|
| Beaconing (any host) | BeaconingDetector | Medium |
| Lateral Movement (any host) | LateralMovementDetector | High |
| Port Scan (any host) | PortScanDetector | Medium |
| Flood (any host) | FloodDetector | High |
| Policy Violation | PolicyViolationDetector | High |
| Novelty (singleton external destination in current dataset) | NoveltyDetector | Low |

### What the Correlation Engine Does NOT Escalate

| Pattern | Why Not |
|---|---|
| PortScan + Flood (same host) | Not a configured correlation rule |
| Beaconing + PortScan (same host) | Not a configured correlation rule |
| Any cross-host combination | Correlation is per-host only |
| Single-category findings | No multi-behavior pattern to correlate |

---

## Potential Future Correlation Rules

These are not implemented. They represent multi-behavior patterns that could justify escalation if added to the correlation engine:

| Pattern | ATT&CK Mapping | Potential Severity | Rationale |
|---|---|---|---|
| PortScan + Flood | TA0007 + TA0040 | High | Aggressive reconnaissance + denial of service |
| Novelty + Beaconing | TA0007 + TA0011 | High | Singleton external destination + periodic external communication |
| PortScan + LateralMovement | TA0007 + TA0008 | High | Reconnaissance followed by internal spread |

These would require adding the category-pair checks to the `shouldEscalate` boolean in `RiskEscalator.cs`.

---

## Implementation Evidence

- [RiskEscalator.cs](../../../VulcansTrace.Engine/RiskEscalator.cs): the correlation rule that checks for `"Beaconing"` and `"LateralMovement"` categories
- [RiskEscalatorTests.cs](../../../VulcansTrace.Tests/Engine/RiskEscalatorTests.cs): `Escalate_WithBeaconingAndLateralMovementOnSameHost_EscalatesToCritical` validates the cross-tactic pattern
