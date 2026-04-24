# Design Decisions

> **Every design choice in this detector has a statistical rationale, a performance consideration, and an operational impact.**

---

## Decision 1: Population Standard Deviation as the Core Metric

**Decision:** Population standard deviation (not sample std dev, not coefficient of variation, not entropy).

**Why:** Population std dev is the most direct measure of interval regularity. A perfect beacon with 90-second intervals produces std dev = 0. Human traffic produces std dev >> 0. The metric is simple, well-understood, and defensible in incident reports.

**Security Rationale:** When an analyst writes "the host contacted the C2 server every 90 seconds with a standard deviation of 0," that is a clear, quantitative indicator of automation. Population std dev was chosen over coefficient of variation or entropy because it is the most direct measure of regularity — a perfect beacon produces std dev = 0, and that number is immediately defensible in an incident report.

---

## Decision 2: Symmetric Outlier Trimming at 10%

**Decision:** Remove `BeaconTrimPercent` (10%) of intervals from each end of the sorted distribution.

**Why:** Network jitter, retransmissions, and occasional delays create outliers that inflate std dev. Symmetric trimming removes these extremes without biasing the central tendency. The `Math.Ceiling` implementation ensures at least one interval is trimmed when the count warrants it.

**Security Rationale:** Makes the detector more tolerant of benign jitter and occasional anomalies. A channel with mostly regular intervals but a few outliers can still get flagged correctly. 10% symmetric trimming was chosen because removing extremes from both ends prevents directional bias — but it is not a full defense against deliberate, sustained jitter.

---

## Decision 3: Tuple-Based Grouping — (SrcIp, DstIp, DstPort)

**Decision:** Group by the 3-tuple `(SrcIp, DstIp, DstPort)` rather than source IP alone.

**Why:** A compromised host may browse the web normally while beaconing to a C2 server on a specific port. Source-IP-only grouping mixes these patterns and dilutes the statistical signal. Each channel needs its own verdict.

**Security Rationale:** Precise attribution enables targeted firewall rules, threat intel enrichment per destination, and focused incident response. The 3-tuple was chosen over source-IP-only grouping because a compromised host browses the web, checks email, and beacons to a C2 server all from the same IP — mixing those patterns would dilute the statistical signal.

---

## Decision 4: Mean Interval Bounds — The C2 Sweet Spot

**Decision:** Require the mean interval to fall within `[BeaconMinIntervalSeconds, BeaconMaxIntervalSeconds]`.

| Bound | Value | Rationale |
|-------|-------|-----------|
| Minimum | 10–60s (profile-dependent) | Screens out many very fast heartbeats, though regular in-range health checks can still overlap statistically |
| Maximum | 900s (all profiles) | Scheduled tasks are 3600s+ — too slow for C2 |

**Why:** C2 malware needs responsive communication — fast enough for command delivery, slow enough to avoid drawing attention. The bounds encode this domain knowledge.

**Security Rationale:** Without mean bounds, a heartbeat every 5 seconds (monitoring) or a cron job every hour (scheduled backup) could trigger a false positive. The bounds are set at 10–60s minimum and 900s maximum because C2 malware often lives in that sweet spot. This is a coarse screen, not a semantic classifier — very regular in-range health checks can still satisfy the same bounds.

---

## Decision 5: Medium Severity with Correlation Escalation

**Decision:** Beaconing findings start at Medium. RiskEscalator raises to Critical only if the same host also shows LateralMovement. When escalation triggers, **all** findings from that host are raised to Critical — not just the Beaconing finding — because the host-level correlation indicates active compromise regardless of individual finding category.

**Security Rationale:** Beaconing means the host is compromised but the scope may be contained. Medium = investigate soon, don't page at 3am. If the attacker is also probing laterally, the combination warrants immediate attention. The severity decision is separated from the escalation decision because uncorrelated beaconing and active attack progression are different threat levels — combining them under one severity would either over-alert or under-alert.

> **Profile visibility caveat:** The Low intensity profile sets `MinSeverityToShow = High`, so standalone Medium-severity Beaconing findings are **filtered from results** at that level. Only Beaconing findings escalated to Critical (via correlation with LateralMovement) reach the user on the Low profile. On Medium and High profiles, uncorrelated Beaconing findings are visible.

**Business Value:** This reflects SOC operational reality. Alert fatigue is a real security problem. Correlation-based escalation produces fewer but higher-quality Critical alerts.

---

## Decision 6: Tail Sampling (Most Recent N)

**Decision:** When capping samples per tuple, keep the most recent entries rather than the earliest.

**Why:** If beaconing is ongoing, the latest samples are most representative of current behavior and the finding the analyst will investigate.

**Security Rationale:** Unlike PortScanDetector (which keeps earliest samples to preserve attack timeline), beaconing benefits from recency because C2 channels are sustained. The trade-off is that older history for that tuple is dropped once the cap is exceeded.

---

## Summary

| Decision | Security Principle | Operational Impact |
|----------|-------------------|-------------------|
| Population std dev | Quantifiable, defensible detection | Analysts can cite exact metrics in incident reports |
| Symmetric trimming | More tolerant of jitter and outliers | Fewer false negatives on noisy channels |
| Tuple grouping | Precise attribution | Targeted response per destination channel |
| Mean interval bounds | Domain knowledge filtering | Screens out many very fast or very slow channels, but in-range periodic software can still overlap |
| Medium + escalation | Accurate risk communication | Prevents alert fatigue; Critical only when context demands; Low profile filters uncorrelated Beaconing |
| Tail sampling | Recency-weighted analysis | Focuses on ongoing rather than historical behavior |
