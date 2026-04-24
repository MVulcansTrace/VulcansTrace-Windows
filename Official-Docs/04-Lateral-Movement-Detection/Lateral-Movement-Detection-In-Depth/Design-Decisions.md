# Design Decisions

Every major choice in this detector has a security rationale, a performance implication, and an operational impact.

---

## Decision 1: Internal-to-Internal Traffic Only

**Decision:** Filter for `IsInternal(SrcIp) && IsInternal(DstIp)` before any analysis.

**Why:** Lateral movement is a post-compromise behavior where the attacker pivots from one internal host to another. This filter distinguishes internal spread from initial access and egress traffic.

| Traffic Pattern | Attack Phase | Covered By |
|-----------------|-------------|------------|
| External → Internal | Initial Access | Firewall, IDS |
| Internal → External | Egress / C2 | BeaconingDetector (not direction-filtered; analyzes all tuples) |
| Internal → Internal | Lateral Movement | This detector |

**Trade-off:** Misses cross-boundary pivoting (e.g., on-prem to cloud via internal routes).

---

## Decision 2: Admin Ports Only

**Decision:** Analyze connections only to configured admin ports (default: ports commonly associated with 445/SMB, 3389/RDP, 22/SSH).

**Why:** Ports commonly associated with SMB, RDP, and SSH are useful pivot signals. The port set is restricted to keep the signal clean by excluding the massive volume of HTTP, DNS, and application traffic.

| Port Category | Examples | Signal Level |
|--------------|----------|-------------|
| Admin ports | 445, 3389, 22 | High — actual pivot tools |
| Web ports | 80, 443 | Low — application noise |
| Infrastructure | 53, 123 | Low — not pivot tools |

**Trade-off:** This remains a port-based approximation. It misses non-standard pivoting on HTTP, WinRM, or custom ports and does not prove which protocol or tool actually generated the traffic. Extendable via `AdminPorts` configuration.

---

## Decision 3: Sliding Window (Not Bucketed)

**Decision:** Two-pointer sliding window instead of fixed time buckets.

**Why:** Lateral movement can span arbitrary time boundaries. A sliding window was chosen to catch attacks that bucketed windows would split and miss.

```text
Attack: 11:58, 11:59, 12:01, 12:02, 12:03 (5 hosts in 5 minutes)

Bucketed: 2 hosts + 3 hosts = both below threshold → Missed
Sliding:  5 hosts in one continuous window → Detected
```

**Trade-off:** Slightly more complex code than buckets. The `Distinct()` call per iteration makes it O(m²) per source in the worst case, though filtering and early exit keep it tractable.

---

## Decision 4: Distinct Hosts (Not Total Connections)

**Decision:** Count unique destination IPs, not total connections.

**Why:** Spread is the defining characteristic of lateral movement. Distinct hosts are counted to distinguish attacker pivoting from legitimate repeated access to the same server.

| Behavior | Pattern | Result |
|----------|---------|--------|
| Admin to file server | 10 connections to 1 host | Not flagged |
| Attacker pivoting | 1 connection to 3–6+ hosts | Flagged (threshold: 3 on High, 4 on Medium, 6 on Low) |

**Trade-off:** Does not capture repeated brute-force attempts against a single host. That is a different attack pattern covered by other tools.

---

## Decision 5: Severity = High (Hardcoded)

**Decision:** All detector-created findings have `Severity.High`.

**Why:** Lateral movement indicates the attacker already bypassed perimeter defenses and is actively spreading. Severity is set to High to communicate urgency proportional to the risk without automatically escalating to Critical.

| Detection | Severity | Rationale |
|-----------|----------|-----------|
| Port Scan | Medium | Reconnaissance — planning, not acting |
| Beaconing | Medium | Suspicious pattern — needs confirmation |
| **Lateral Movement** | **High** | **Active spread — respond now** |
| Beaconing + Lateral | Critical | Correlated threat signals — all findings for the host escalate, including Flood and PolicyViolation (via RiskEscalator) |

**Trade-off:** May generate false positives from admin workstations or backup servers. Mitigated by configurable thresholds.

---

## Decision 6: One Finding Per Source

**Decision:** `break` after creating the first finding for each source IP.

**Why:** Duplicate alerts for the same host add no investigative value. Output is limited to one finding per source to prevent alert fatigue while still triggering the response workflow.

---

## Decision 7: Cancellation Support

**Decision:** `CancellationToken` check between source groups.

**Why:** The analysis runs on a background thread via `Task.Run`. Cooperative cancellation was added so the UI can cancel in-progress work when the user changes parameters or closes the window, releasing resources promptly and avoiding stale results.

---

## Summary

| Decision | Security Principle | Operational Impact |
|----------|-------------------|-------------------|
| Internal-to-internal | Attack-phase alignment | Focuses on correct threat |
| Admin ports only | Signal-to-noise optimization | Reduces false positives |
| Sliding window | Boundary-attack detection | Catches what buckets miss |
| Distinct hosts | Spread-pattern matching | Measures the right thing |
| High severity | Urgent risk communication | Triggers prompt response |
| One finding per source | Alert fatigue prevention | Cleaner analyst queue |
| Cancellation support | Availability | Prompt resource release |
