# Design Decisions

Every major choice in this detector has a security rationale, a performance implication, and an operational impact.

---

## Decision 1: IP Classification Over Direction/Action Fields

**Decision:** Filter using `IpClassification.IsInternal(SrcIp)` and `IpClassification.IsExternal(DstIp)` instead of checking the `Direction` or `Action` log fields.

**Why:** Organizational policy is not the same as the firewall's allow/deny decision. The filter uses IP classification to catch violations that firewalls allow but policy prohibits.

| Scenario | Action Field | Policy Violation? |
|----------|-------------|-------------------|
| FTP connection, firewall allowed | ALLOW | YES — still violates policy |
| FTP connection, firewall blocked | DENY | Attempt may still be noteworthy |
| HTTPS connection, firewall allowed | ALLOW | No — 443 is typically allowed |

**Trade-off:** Because `Action` is not checked, the detector cannot distinguish successful outbound connections from blocked attempts. That keeps the logic simple but means analysts must interpret whether a finding reflects an allowed session, a denied attempt, or repeated policy-risk activity.

---

## Decision 2: One Finding Per Violation (No Aggregation)

**Decision:** Every qualifying log entry gets its own Finding object. No deduplication, no grouping by host or destination.

**Why:** Aggregation hides attack scope — 50 disallowed-port log entries to 50 different servers means 50 investigative leads. One finding per entry gives analysts complete visibility into every destination and connection.

| Approach | Pros | Cons |
|----------|------|------|
| **One per entry (chosen)** | Full visibility, all destinations visible | Possible alert fatigue with misconfigured apps |
| Aggregate by host | Cleaner dashboards | Loses target diversity |
| Dedupe by (src, dst, port) | Reduces noise | May hide attack persistence |

**Trade-off:** A misconfigured application making thousands of violations will produce thousands of findings. The right fix is correcting the application, not hiding the alerts.

---

## Decision 3: HashSet for Port Lookup

**Decision:** `new HashSet<int>(profile.DisallowedOutboundPorts ?? Array.Empty<int>())` for O(1) port membership checks.

**Why:** The port check scales efficiently with a HashSet. This keeps per-entry cost constant when evaluating traffic that survives the earlier IP filtering gates regardless of how many ports are configured.

| Data Structure | Lookup | Payload Evaluated against 100 ports |
|----------------|--------|-------------------------------------|
| `List<int>` | O(n) | Up to 100 array comparisons |
| `HashSet<int>` | O(1) avg | 1 hash lookup |

**Trade-off:** Slightly higher memory due to hash buckets, but negligible for a small number of ports (3 in the default profiles).

---

## Decision 4: Severity = High (Hardcoded)

**Decision:** All detector-created findings have `Severity.High`.

**Why:** A disallowed port contact may indicate exfiltration, malware C2, or insider threat activity — the detector confirms only that a prohibited port was reached, and the threat categorization is analyst interpretation. Severity is set to High to communicate urgency proportional to the risk without automatically escalating to Critical.

| Detection | Severity | Rationale |
|-----------|----------|-----------|
| Port Scan | Medium | Reconnaissance — planning, not acting |
| Beaconing | Medium | Suspicious pattern — needs confirmation |
| **Policy Violation** | **High** | **Potential active threat — investigate now** |
| Beaconing + Lateral | Critical | Higher-confidence correlated compromise signal — all findings for the host escalate, including Flood and PolicyViolation (via RiskEscalator) |

**Trade-off:** May generate false positives from misconfigured applications. Mitigated by configurable port list and profile tuning.

---

## Decision 5: Early Exit Gates

**Decision:** Guard the entire method with `!profile.EnablePolicy || entries.Count == 0`.

**Why:** There is no point initializing data structures when the detector is disabled or the dataset is empty. The early-exit gates return immediately with zero overhead in the common disabled-or-empty case.

---

## Decision 6: Null-Coalescing on Port Configuration

**Decision:** `profile.DisallowedOutboundPorts ?? Array.Empty<int>()`.

**Why:** A missing configuration should produce zero findings, not crash the detector. The null-coalescing pattern fails safe — no false positives, no exceptions, regardless of how the profile was constructed.

In practice, `AnalysisProfileProvider` always supplies a non-null array, but the defensive pattern handles custom profiles and edge cases gracefully.

---

## Decision 7: Egress Only (Not Ingress or Lateral)

**Decision:** Filter for internal source AND external destination only.

**Why:** Internal-to-internal connections (lateral movement) and external-to-internal connections (initial access) are fundamentally different threat models. The detector is scoped to egress traffic to keep each detector focused on one attack phase.

| Traffic Pattern | Attack Phase | Covered By |
|----------------|-------------|------------|
| External → Internal | Initial Access | Firewall, IDS |
| Internal → External | Egress / Policy | This detector |
| Internal → Internal | Lateral Movement | LateralMovementDetector |

---

## Decision 8: Cancellation Support

**Decision:** `cancellationToken.ThrowIfCancellationRequested()` inside the foreach loop.

**Why:** Log analysis can process large datasets and may take time. Cooperative cancellation was added to allow users to cancel long-running analyses rather than waiting for completion.

---

## Summary

| Decision | Security Principle | Operational Impact |
|----------|-------------------|-------------------|
| IP classification over log fields | Policy ≠ firewall decision | Catches what firewalls allow |
| One finding per entry | Full investigative visibility | Analysts see every destination |
| HashSet port lookup | Performance at scale | O(1) average per entry regardless of list size |
| High severity | Urgent risk communication | Prompts prompt investigation |
| Early exit gates | Resource protection | Zero overhead when disabled |
| Null-coalescing config | Fail-safe defaults | No crashes on edge cases |
| Egress only | Attack-phase alignment | Focused on the right threat model |
| Cancellation support | Availability | Responsive UI on large datasets |
