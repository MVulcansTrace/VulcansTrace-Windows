# Evasion and Limitations

Gaps, edge cases, and improvement paths for the correlation engine.

---

## Known Limitations

### Single Hardcoded Correlation Rule

This rule represents the highest-confidence correlation pattern currently implemented in VulcansTrace, but it means that other multi-behavior patterns go uncorrelated.

| Pattern | Currently Escalated? | Rationale |
|---|---|---|
| Beaconing + LateralMovement (same host) | Yes | Active C2 + internal spread |
| PortScan + Flood (same host) | No | Could indicate aggressive reconnaissance + DoS |
| Novelty + Beaconing (same host) | No | First-time external connection + C2 pattern |
| Three-category combo containing Beaconing+LateralMovement | Yes (all findings) | Core rule triggers, escalates all findings on host |
| Three-category combo without both required categories | No | Missing Beaconing and/or LateralMovement |

**Improvement path:** Externalize correlation rules into a configurable collection — each rule specifies required categories and target severity. This would allow adding rules without modifying the engine.

### No Audit Trail

When a finding is escalated, the `with` expression creates a new record with `Severity = Critical`, but the original severity value is not preserved. There is no `OriginalSeverity` field, no `EscalationReason` field, and no history of severity changes on the `Finding` record.

```csharp
// What happens today
f with { Severity = Severity.Critical }  // original severity is lost

// What a full audit trail would require
f with { Severity = Severity.Critical, OriginalSeverity = f.Severity, EscalationReason = "Beaconing+LateralMovement" }
```

This trade-off was accepted because adding audit fields to the `Finding` record changes the data model across the entire application. It is the right improvement to make, but it is not a change taken lightly.

**Impact:** Analysts see the final severity, not how it got there. In a triage workflow this is acceptable. In a compliance or forensic context, it is a gap.

### Empty-Host Edge Case

Findings with null or empty `SourceHost` values are grouped together under `""`. If one has Beaconing and another has LateralMovement, they escalate even though they may not be from the same host.

This approach was chosen because the alternatives are worse: throwing on null would crash the pipeline, and skipping null-host findings would lose alerts. The test suite explicitly covers this case (`Escalate_WithEmptySourceHost_DoesNotCrash`).

### Batch-Only Processing

The engine processes all findings in a single batch after every detector has completed. There is no streaming mode, no incremental updates, and no way to correlate findings across analysis runs. For the current desktop WPF application with in-memory log data, batch processing is appropriate. For a cloud-scale SIEM ingesting millions of events per hour, it would not be.

### No Severity Decay or Time Awareness

The correlation engine does not consider time proximity between findings. A Beaconing finding from Monday and a LateralMovement finding from Friday will still trigger escalation on the same host. For a real-time monitoring system, time-bounded correlation (e.g., both findings within 24 hours) would reduce false positives from unrelated incidents on the same host.

---

## What Attackers Can Exploit

### Single-Behavior Attacks

An attacker who only beacons (without moving laterally) or only moves laterally (without C2 beaconing) will not trigger escalation. Each finding remains at its detector-assigned severity.

**Mitigation:** This is by design — single-behavior patterns have plausible benign explanations and should not be Critical. Beaconing and LateralMovement findings remain at their detector-assigned severity (Medium and High respectively) and are visible to analysts with the default profile.

### Distributed Attacks Across Hosts

An attacker who beacons from Host A and moves laterally from Host B will not trigger correlation, because the engine groups by `SourceHost`, not by attack campaign.

**Mitigation:** Campaign-level correlation requires a different data model (e.g., shared C2 infrastructure, common certificates, or threat intelligence feeds). This is outside the scope of host-level correlation.

### Timing-Based Evasion

An attacker who spaces beaconing and lateral movement across different analysis windows (in a streaming or periodic analysis system) could avoid correlation. In the current batch model where all findings are processed at once, this is not applicable, but it would become relevant in an incremental or streaming architecture.

**Mitigation:** Time-bounded correlation windows (e.g., "both behaviors within 7 days") would address this in a streaming architecture.

---

## What Scales and What Does Not

| Aspect | Scales Well | Scaling Concern |
|---|---|---|
| Multi-pass linear algorithm | O(n) time across GroupBy, ToHashSet, and inner loop passes | — |
| HashSet lookups | O(1) per category check | — |
| Host-based grouping | Parallelizable across hosts | — |
| Memory usage | — | All findings held in memory simultaneously |
| Set allocations | — | `ToHashSet` allocates a new set per host group during category checking |
| Record copies | — | Every escalation allocates a new `Finding` record |

For the current use case (desktop analysis of a single firewall log), memory and allocation costs are negligible. For a cloud-scale deployment, the architecture would need streaming correlation, partitioned by host, with a time-bounded window.

---

## Implementation Evidence

- [RiskEscalator.cs](../../../VulcansTrace.Engine/RiskEscalator.cs): the single hardcoded rule and empty-host handling
- [RiskEscalatorTests.cs](../../../VulcansTrace.Tests/Engine/RiskEscalatorTests.cs): edge case coverage including empty SourceHost and already-Critical findings
- [Finding.cs](../../../VulcansTrace.Core/Finding.cs): the record without audit trail fields

