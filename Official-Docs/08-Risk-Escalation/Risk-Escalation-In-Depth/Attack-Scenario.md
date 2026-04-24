# Attack Scenario

A synthetic worked example showing how the correlation engine turns individual detector outputs into a higher-confidence compromise signal by escalating matched hosts to Critical severity.

---

## The Scenario

Three hosts on the 192.168.1.0/24 network. This scenario uses analyst-friendly narrative around underlying detector findings so the escalation behavior is easy to follow.

```text
Host 192.168.1.100 (developer workstation, MATCHED HOST)
  → Beaconing finding from periodic external communication to 203.0.113.50
  → LateralMovement finding from internal admin-port activity on 3389

Host 192.168.1.101 (file server, NOT COMPROMISED)
  → Beaconing-like pattern from a cloud sync client (false positive)

Host 192.168.1.1   (gateway router)
  → Port scan behavior from routine network monitoring
```

---

## Detector Output (Before Escalation)

After all detectors run, the pipeline holds these findings:

| SourceHost | Category | Severity | Details |
|---|---|---|---|
| 192.168.1.100 | Beaconing | Medium | Periodic connections to 203.0.113.50:443 |
| 192.168.1.100 | LateralMovement | High | Contacted 5 internal hosts on admin ports |
| 192.168.1.101 | Beaconing | Medium | Periodic connections to 52.96.166.130:443 |
| 192.168.1.1 | PortScan | Medium | Contacted 47 ports on 192.168.1.50 |

An analyst scanning this list sees two Medium alerts, one High alert, and one Medium alert. The Medium Beaconing on 192.168.1.100 looks identical to the Medium Beaconing on 192.168.1.101 — both could be software updates. The High LateralMovement on 192.168.1.100 could be admin tooling. Nothing demands immediate attention.

---

## Correlation Engine Processing

### Group by SourceHost

```text
Group "192.168.1.100": [Beaconing(Medium), LateralMovement(High)]
Group "192.168.1.101": [Beaconing(Medium)]
Group "192.168.1.1":   [PortScan(Medium)]
```

### Check Each Group

| Host | Categories | Has Beaconing? | Has Lateral? | Escalate? |
|---|---|---|---|---|
| 192.168.1.100 | Beaconing, LateralMovement | Yes | Yes | **Yes** |
| 192.168.1.101 | Beaconing | Yes | No | No |
| 192.168.1.1 | PortScan | No | No | No |

### Step C: Escalate

Only host 192.168.1.100 matches. Both findings are escalated to Critical.

> **Note:** Escalation applies to *all* findings on a matched host, not just the Beaconing and LateralMovement findings. If 192.168.1.100 had a third-category finding (e.g., a Novelty or PortScan), that finding would also be escalated to Critical. In this scenario the host has exactly two findings, so "both findings" and "all findings" are equivalent.

---

## After Escalation

| SourceHost | Category | Severity | Changed? |
|---|---|---|---|
| 192.168.1.100 | Beaconing | **Critical** | Escalated from Medium |
| 192.168.1.100 | LateralMovement | **Critical** | Escalated from High |
| 192.168.1.101 | Beaconing | Medium | No change |
| 192.168.1.1 | PortScan | Medium | No change |

On the Low analysis profile (where `MinSeverityToShow = High`), all Medium findings would be filtered out — only the two Critical findings from 192.168.1.100 would reach the analyst. The Medium Beaconing on 192.168.1.101 and the Medium PortScan on 192.168.1.1 would both be hidden. Without escalation, the same Low profile would hide both Beaconing findings entirely, and the analyst would see only one High LateralMovement finding for 192.168.1.100 with much less cross-detector context.

---

## Analyst Response

| Priority | Action | Finding |
|---|---|---|
| **1 — Immediate** | Isolate 192.168.1.100 from the network | Critical: Beaconing + LateralMovement |
| 2 — Investigate | Verify whether 192.168.1.101's beaconing is a false positive | Medium: Beaconing (cloud sync) |
| 3 — Check | Review whether 192.168.1.1's port scan is authorized scanning | Medium: PortScan (monitoring tool) |

The correlation engine did not reduce the finding count or add new findings. It changed the severity of the two findings on the matched host so they demand immediate attention, even on the most restrictive analysis profile.

---

## Implementation Evidence

- [RiskEscalator.cs](../../../VulcansTrace.Engine/RiskEscalator.cs): the correlation logic that processes this scenario
- [RiskEscalatorTests.cs](../../../VulcansTrace.Tests/Engine/RiskEscalatorTests.cs): `Escalate_WithBeaconingAndLateralMovementOnSameHost_EscalatesToCritical` and `Escalate_WithMixedFindings_EscalatesOnlyCorrectHost` test this exact pattern
