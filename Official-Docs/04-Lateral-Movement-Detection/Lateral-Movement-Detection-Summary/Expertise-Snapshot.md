# Expertise Snapshot

> **1 page:** the subsystem, why it matters, and where the proof lives in the codebase.

---

## Implementation Overview

A **lateral movement detection engine** for VulcansTrace that identifies post-compromise internal pivoting from firewall logs. It filters for internal-to-internal traffic on admin ports, slides a time window per source, and emits structured findings when a source contacts enough distinct internal hosts.

---

## Key Metrics

| Metric | Value |
|--------|-------|
| Detection method | Sliding window + distinct-host counting |
| Admin ports covered | Default ports commonly associated with SMB/445, RDP/3389, SSH/22 (extensible) |
| Sensitivity profiles | Low (6 hosts), Medium (4), High (3) in 10 min |
| Severity | High (Critical when Beaconing + LateralMovement co-occur on same host) |
| Cross-detector correlation | Beaconing + LateralMovement → all findings for that host escalated to Critical via RiskEscalator |

---

## Why It Matters

- Detects active attacker spread — the phase after initial compromise but before data exfiltration
- Sliding window catches boundary-spanning attacks that bucketed approaches miss
- Cross-detector correlation raises confidence: C2-like timing plus pivoting escalates findings for that host to Critical
- Documented limitations: slow pivoting, non-admin ports, and proxy pivoting are documented gaps

---

## Key Evidence

- [LateralMovementDetector.cs](../../../VulcansTrace.Engine/Detectors/LateralMovementDetector.cs): filtering, sliding window, distinct-host counting, and finding creation
- [AnalysisProfileProvider.cs](../../../VulcansTrace.Engine/Configuration/AnalysisProfileProvider.cs): built-in Low, Medium, and High presets
- [RiskEscalator.cs](../../../VulcansTrace.Engine/RiskEscalator.cs): cross-detector correlation (Beaconing + LateralMovement → Critical)
- [LateralMovementDetectorTests.cs](../../../VulcansTrace.Tests/Engine/Detectors/LateralMovementDetectorTests.cs): threshold, multi-source, external-traffic, and time-spread coverage
- [RiskEscalatorTests.cs](../../../VulcansTrace.Tests/Engine/RiskEscalatorTests.cs): escalation and correlation scenarios

---

## Key Design Choices

- **Sliding window over buckets** because lateral movement spans arbitrary time boundaries — buckets split attacks at aligned edges
- **Distinct hosts over connections** because spread is the defining signal — ten connections to one host is normal
- **Admin ports only** because ports commonly associated with SMB/RDP/SSH are useful pivot signals — all-port analysis drowns in noise
- **One finding per source** because duplicate alerts for the same host do not help analysts

