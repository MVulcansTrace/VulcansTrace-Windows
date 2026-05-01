# Design Decisions

Every major choice in this detector has a security rationale, a performance implication, and an operational impact.

---

## Decision 1: External-Only Filtering

**Decision:** Filter for `IpClassification.IsExternal(e.DstIp)` before any counting.

**Why:** Internal one-time connections are routine — DHCP renewals, print jobs, DNS queries, file access — while external singletons represent destinations the organization has no established relationship with. This filter keeps the signal clean by excluding the high volume of internal routine traffic.

| Traffic Type | Signal Level | Why |
|-------------|-------------|-----|
| Internal singletons | Noise | DHCP, printing, DNS, NTP are routine |
| External singletons | Signal | First-contact destination, unknown intent |

**Trade-off:** Misses internal reconnaissance — an internal host contacting an internal destination once could be an attacker probing, but the noise floor makes that impractical to detect at this layer.

---

## Decision 2: (DstIp, DstPort) Tuple Grouping

**Decision:** Group by `(DstIp, DstPort)` rather than just `DstIp`.

**Why:** The same server on different ports is a different service. Grouping by destination tuple preserves service-level granularity that IP-only grouping would lose.

**Example where it matters:**

```text
Same C2 server, three services:
  203.0.113.42:443  → HTTPS beacon
  203.0.113.42:22   → SSH backdoor
  203.0.113.42:8443 → Custom exfil protocol

IP-only grouping:  count = 3 → not a singleton → missed
Tuple grouping:    count = 1 each → three singletons → detected
```

**Trade-off:** Counting is global — two different sources each connecting once to the same tuple produces count = 2, so neither gets flagged. The detector does not distinguish which host made the connection when counting.

---

## Decision 3: Count Must Equal 1

**Decision:** Only exact singletons emit findings. Not count <= 2, not count <= 3.

**Why:** Count == 1 has clear, deterministic semantics — the destination appeared once in the entire dataset. This keeps the detector's claim precise and reduces false positives from legitimate retries.

| Count | Meaning | Finding? |
|-------|---------|----------|
| 1 | Truly novel in this dataset | Yes |
| 2 | Could be a legitimate retry or emerging pattern | No |
| 3+ | Established connection pattern | No |

**Trade-off:** Misses "low and slow" attackers who make exactly two connections. BeaconingDetector covers regular periodic patterns, but a two-time probe falls into a gap between detectors.

---

## Decision 4: Severity = Low (Hardcoded)

**Decision:** All detector-created findings have `Severity.Low`.

**Why:** Novelty has a high false-positive rate — most singletons are legitimate CDN edges, one-time downloads, or cloud API calls. Severity is set to Low to communicate that the finding is a signal for investigation, not a verdict requiring immediate action.

| Severity | Meaning | Appropriate For |
|----------|---------|-----------------|
| Critical | Active compromise | Confirmed breach |
| High | Imminent threat | Lateral movement |
| Medium | Suspicious activity | Port scan |
| **Low** | **Anomaly worth monitoring** | **Singleton connections** |
| Info | Notable event | Configuration changes |

**Trade-off:** Low severity means findings are filtered at Medium intensity. Analysts must switch to High intensity to see standalone novelty findings, or they appear via escalation when their source host is also flagged for both Beaconing and LateralMovement (the only escalation path, which raises severity to Critical).

---

## Decision 5: Profile-Gated Visibility

**Decision:** Novelty is disabled at Low intensity and filtered at Medium intensity.

**Why:** Novelty's high false-positive rate would flood analysts in conservative environments. Profile-gating gives analysts control over the noise level based on their current analysis depth.

| Intensity | EnableNovelty | MinSeverityToShow | Standalone Novelty Visible? |
|-----------|---------------|-------------------|----------------------------|
| Low | `false` | High | No — detector does not run |
| Medium | `true` | Medium | No — Low < Medium, filtered |
| High | `true` | Info | Yes — Low >= Info |

**Key distinction:** "Not shown" can happen for two different reasons. At Low intensity, the detector never runs. At Medium intensity, the detector runs and creates findings, but SentryAnalyzer filters them out — unless a finding's source host is also flagged for both Beaconing and LateralMovement, in which case RiskEscalator raises it to Critical and it passes the filter. This is a common source of confusion — the answer to "why don't I see novelty findings?" depends on which intensity level is active and whether cross-detector correlation applies.

---

## Decision 6: Cancellation Support

**Decision:** `cancellationToken.ThrowIfCancellationRequested()` inside the emission loop.

**Why:** Log analysis can process large datasets and every detector receives the same cancellation token. Cooperative cancellation was added to allow the analysis pipeline to stop promptly when the caller cancels.

---

## Decision 7: Cross-Detector Suppression (PortScan → Novelty)

**Decision:** `SentryAnalyzer` removes Novelty findings from any source host that also produced a `PortScan` finding.

**Why:** Port scanning inherently generates many singleton connections — each probed port is a distinct `(DstIp, DstPort)` tuple contacted exactly once. Without suppression, a single port scan produces one PortScan finding and dozens of Novelty findings, drowning the analyst in noise. The NoveltyDetector cannot distinguish a scan target from a genuine first-contact anomaly because both look like singletons at the network layer.

**Trade-off:** A host that both port-scans AND makes a legitimate novel connection to a different destination will have that legitimate novelty suppressed. This is accepted because the host is already flagged for hostile reconnaissance, making its other connections lower-priority signals.

---

## Summary

| Decision | Security Principle | Operational Impact |
|----------|-------------------|-------------------|
| External-only filter | Signal-to-noise optimization | Reduces false positives |
| Tuple grouping | Service-level granularity | Catches multi-port activity |
| Count == 1 | Precise semantics | Deliberately weak signal |
| Severity = Low | Accurate risk communication | Filtered unless escalated or High intensity |
| Profile-gating | Alert fatigue prevention | Analyst controls noise level |
| Cancellation | Availability | Cancellable background analysis |
| Cross-detector suppression | Noise reduction from correlated activity | Prevents scan floods from masking real anomalies |

