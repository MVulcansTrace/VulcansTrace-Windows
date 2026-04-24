# Attack Scenario: Egress Policy Violation in Action

---

## The Attack

A synthetic internal host (`192.168.1.100`) produces three internal-to-external log entries on disallowed ports over 3 minutes:

```text
2024-01-15 12:00:00 ALLOW TCP 192.168.1.100 50000 203.0.113.50 21 OUTBOUND
2024-01-15 12:01:00 ALLOW TCP 192.168.1.100 50001 198.51.100.77 23 OUTBOUND
2024-01-15 12:02:00 ALLOW TCP 192.168.1.100 50002 93.184.216.34 445 OUTBOUND
```

Three different disallowed-port patterns — FTP, Telnet, SMB. In this worked example the rows are `ALLOW`, but the detector would also flag matching `DENY` entries because it does not filter on `Action`.

---

## Detection Walkthrough

### Step A: Gate and Setup

```text
EnablePolicy?       → true     ✓ (proceed)
Entries.Count > 0?  → true     ✓ (proceed)
Load disallowed ports into HashSet<int>: { 21, 23, 445 }
```

> **Same defaults across all profiles.** `AnalysisProfileProvider` assigns the same disallowed set `[21, 23, 445]` to Low, Medium, and High profiles. Only the thresholds for other detectors and `MinSeverityToShow` vary by profile — the policy violation port list does not.

> **Null-safety defensive pattern.** The detector does not assume `DisallowedOutboundPorts` is populated. The code uses `profile.DisallowedOutboundPorts ?? Array.Empty<int>()` when building the HashSet. If the property is `null`, the HashSet is empty and no entries can pass the port check — the detector silently produces zero findings rather than crashing. This is explicitly tested.

### Step B: Three-Condition Filter

```text
Entry 1: 192.168.1.100 → 203.0.113.50:21
  Source internal?    192.168.1.100 → ✓ (RFC 1918)
  Dest external?      203.0.113.50  → ✓ (public IP)
  Port disallowed?    21            → ✓ (in HashSet)
  → PASS — create finding

Entry 2: 192.168.1.100 → 198.51.100.77:23
  Source internal?    192.168.1.100 → ✓ (RFC 1918)
  Dest external?      198.51.100.77 → ✓ (public IP)
  Port disallowed?    23            → ✓ (in HashSet)
  → PASS — create finding

Entry 3: 192.168.1.100 → 93.184.216.34:445
  Source internal?    192.168.1.100 → ✓ (RFC 1918)
  Dest external?      93.184.216.34 → ✓ (public IP)
  Port disallowed?    445           → ✓ (in HashSet)
  → PASS — create finding
```

### Step C: Findings Created

3 findings — one per violation, preserving full destination detail.

---

## The Findings

### Finding 1: FTP

```text
Category:         PolicyViolation
Severity:         High
SourceHost:       192.168.1.100
Target:           203.0.113.50:21
TimeRangeStart:   2024-01-15T12:00:00
TimeRangeEnd:     2024-01-15T12:00:00
ShortDescription: Disallowed outbound port from 192.168.1.100
Details:          Outbound connection to 203.0.113.50:21 on a disallowed port.
```

### Finding 2: Telnet

```text
Category:         PolicyViolation
Severity:         High
SourceHost:       192.168.1.100
Target:           198.51.100.77:23
TimeRangeStart:   2024-01-15T12:01:00
TimeRangeEnd:     2024-01-15T12:01:00
ShortDescription: Disallowed outbound port from 192.168.1.100
Details:          Outbound connection to 198.51.100.77:23 on a disallowed port.
```

### Finding 3: SMB

```text
Category:         PolicyViolation
Severity:         High
SourceHost:       192.168.1.100
Target:           93.184.216.34:445
TimeRangeStart:   2024-01-15T12:02:00
TimeRangeEnd:     2024-01-15T12:02:00
ShortDescription: Disallowed outbound port from 192.168.1.100
Details:          Outbound connection to 93.184.216.34:445 on a disallowed port.
```

---

## Risk Escalation Interaction

The findings above show `Severity: High`, which is accurate for this isolated scenario. However, the full pipeline includes a `RiskEscalator` that runs after all detectors complete.

`RiskEscalator` groups findings by `SourceHost` and checks whether a single host has **both** a Beaconing finding **and** a LateralMovement finding. When that pattern is detected, every finding for that host — including PolicyViolation findings — is escalated from its original severity to **Critical**.

In this scenario, the host `192.168.1.100` only produced PolicyViolation findings, so no escalation occurs. But if a broader analysis of the same time window also triggered Beaconing and LateralMovement for this host, all three PolicyViolation findings would be promoted to Critical severity before the severity filter is applied.

```text
RiskEscalator logic (simplified):
  Group findings by SourceHost
  If group contains BOTH "Beaconing" AND "LateralMovement" categories:
    → Escalate ALL findings for that host to Critical
  Otherwise:
    → Pass findings through unchanged
```

This means the final severity a user sees is not guaranteed to be High — it depends on what other detectors found for the same host.

---

## Why One Finding Per Entry Matters

If these 3 violations were aggregated into a single summary finding, an analyst would see:

> "192.168.1.100 had 3 policy violations"

With one finding per entry, the analyst sees:

> "192.168.1.100 generated three policy-violation findings targeting external FTP, Telnet, and SMB endpoints"

That is three different investigation paths, three different potential IOCs, and three different potential attack vectors. The Target field in each finding is a pivot point for threat intel lookups.

---

## Profile Visibility

| Profile | MinSeverityToShow | PolicyViolation (High) Visible? |
|---------|-------------------|--------------------------------|
| Low | High | Yes — High >= High |
| Medium | Medium | Yes — High >= Medium |
| High | Info | Yes — High >= Info |

PolicyViolation findings are visible at all intensity levels.
