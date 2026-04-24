# Design Decisions

Every major choice in this detector has a security rationale, a performance implication, and an operational impact.

---

## Decision 1: Per-Source Analysis (Not Aggregate)

**Decision:** Group by `SrcIp` and analyze each source independently.

**Why:** A flood is defined by one IP's behavior, not total network volume. Per-source grouping isolates the noisy source so that 200 events from IP A do not penalize IP B.

| Pattern | Aggregate View | Per-Source View |
|---------|---------------|-----------------|
| 250 from IP A, 20 from IP B | 270 total (A and B mixed) | A = 250 (flood), B = 20 (normal) |
| 10 IPs x 25 events each | 250 total (looks like flood) | Each = 25 (no flood) |

**Trade-off:** Distributed attacks (DDoS) where each IP stays below threshold are not detected. Planned compensating control: aggregate-by-destination detection in a future detector.

---

## Decision 2: Sliding Window (Not Bucketed)

**Decision:** Two-pointer sliding window instead of fixed time buckets.

**Why:** Floods can start and end at any time. A sliding window was chosen to catch boundary-spanning attacks that bucketed windows would split and miss.

```text
Attack: 120 events from 10:59:30 to 11:00:29 (60 seconds)

Bucketed: 60 + 60 = both below 100 threshold -> MISSED (High profile)
Sliding:  120 in continuous window           -> DETECTED
```

**Trade-off:** Slightly more complex than bucketed counting, but the sliding window scan is O(n) per source (plus an O(n log n) sort of events by timestamp). No additional data structures required.

---

## Decision 3: Event Count (Not Rate-Based)

**Decision:** Count raw events within the configured window rather than computing a per-second rate.

**Why:** The sliding window already constrains the time range. Events are counted directly to keep the threshold check simple, deterministic, and exactly reproducible — same input always produces the same output.

| Approach | Check | Complexity |
|----------|-------|------------|
| Event count | `windowCount >= FloodMinEvents` | O(1) per window position |
| Rate-based | `windowCount / spanSeconds >= rateThreshold` | O(1), but floating-point comparison and edge cases |

**Trade-off:** The `Details` field reports the configured window size, not the actual event span. The actual span is available in `TimeRangeStart`/`TimeRangeEnd` for analysts who need it.

---

## Decision 4: Inclusive Threshold (`>=`)

**Decision:** Trigger detection when `windowCount >= FloodMinEvents`, meaning exactly at threshold counts.

**Why:** Drawing the line exactly at the threshold is the most predictable boundary. Inclusive comparison makes the detector's behavior clear to analysts and exactly testable in the test suite.

| Event Count | Threshold 200 | Result |
|-------------|---------------|--------|
| 199 | 199 < 200 | No finding |
| 200 | 200 >= 200 | Finding created |
| 201 | 201 >= 200 | Finding created |

**Trade-off:** None meaningful. This is the standard choice for threshold detectors and matches the test suite's boundary tests.

---

## Decision 5: Severity = High (Hardcoded)

**Decision:** All detector-created findings have `Severity.High`.

**Why:** Flood activity represents potential availability impact that deserves urgent review. Severity is set to High to communicate urgency proportional to the risk without automatically escalating to Critical.

| Detection | Severity | Rationale |
|-----------|----------|-----------|
| Port Scan | Medium | Reconnaissance — planning, not acting |
| Beaconing | Medium | Suspicious pattern — needs confirmation |
| **Flood** | **High** | **Active volumetric impact — respond now** |
| Beaconing + Lateral | Critical | Higher-confidence correlated compromise signal — all findings for the host escalate, including Flood and PolicyViolation (via RiskEscalator) |

**Trade-off:** May generate false positives from backup servers or monitoring tools during maintenance windows. Mitigated by configurable thresholds.

---

## Decision 6: One Finding Per Source

**Decision:** `break` after creating the first finding for each source IP.

**Why:** A sustained flood from one IP produces many overlapping windows that would all exceed threshold. Output is limited to one finding per source to prevent alert fatigue — the analyst needs to block one host, not dismiss ten duplicate alerts.

**Trade-off:** The detector reports only the first flood window. If an attacker floods for 5 minutes, the finding shows the first detected window, not the full duration or multiple pulses.

---

## Decision 7: Fixed Window Duration Across Profiles

**Decision:** All three built-in profiles use 60-second windows. Only `FloodMinEvents` varies.

**Why:** Tuning one variable is simpler and less error-prone than tuning two simultaneously. The window size is kept constant to make profile selection intuitive — analysts choose sensitivity by event threshold, not by juggling window size and threshold together.

| Profile | FloodMinEvents | FloodWindowSeconds |
|---------|----------------|-------------------|
| Low | 400 | 60 |
| Medium | 200 | 60 |
| High | 100 | 60 |

**Trade-off:** Custom `AnalysisProfile` instances can override `FloodWindowSeconds`, but the built-in profiles keep it fixed at 60 seconds.

---

## Decision 8: Cancellation Support

**Decision:** `CancellationToken` check between source groups.

**Why:** Log analysis runs on a background thread via `Task.Run` in the WPF app. Cooperative cancellation was added to let the user abort long-running analysis of large log files without waiting for it to finish.

---

## Summary

| Decision | Security Principle | Operational Impact |
|----------|-------------------|-------------------|
| Per-source analysis | Accurate attribution | Isolates the flood source |
| Sliding window | Boundary-attack detection | Catches what buckets miss |
| Event count | Deterministic detection | Same input = same output |
| Inclusive threshold | Boundary precision | Testable at exact boundary |
| High severity | Urgent risk communication | Triggers prompt response |
| One finding per source | Alert fatigue prevention | Cleaner analyst queue |
| Fixed window duration | Simplicity | One knob to tune per profile |
| Cancellation support | Availability | Responsive UI |
