# Evasion Techniques & Limitations

> **Understanding blind spots enables compensating controls for each limitation.**

---

## Known Limitations

| Evasion | Status | Enhancement |
|---------|--------|-------------|
| Slow scanning | Missed — per-window thresholds (no cross-window accumulation) | Cumulative tracking across windows |
| Distributed scanning | Missed — per-source only | Subnet/ASN/timing correlation |
| Bucket-boundary split | Missed when burst activity is divided across aligned buckets | Sliding or overlapping windows |
| Port decoys | **Often still detected** — tuples count everything | Weighted scoring for context |
| SYN stealth | Depends on telemetry | Connection state analysis |

---

## Slow Scanning: Speed vs. Stealth

The detector uses a two-stage filter: a source-level gate counts total distinct targets across all analyzed entries for that source, then per-window thresholds are applied independently. Slow scans evade because each individual window stays below threshold — no cross-window accumulation exists.

```
Fast Scan (detected):    20 targets in 5 minutes (Medium/High profile — Low requires 30)
Slow Scan (evades):     3 targets per window across 6 windows = 18 total, never triggers
```

**Fix:** Cumulative tracking — rolling 24-hour distinct target count per source. Trade-off: may flag legitimate long-running processes.

---

## Distributed Scanning: Divide and Conquer

```text
Single Source: 20 targets → Detected (Medium/High profile — Low requires 30)
Distributed:   5 targets each from 4 IPs → All below threshold
```

**Fix:** Subnet correlation — group by /24 subnet + time window, Trade-off: cross-partition complexity.

---

## Improvement Roadmap

```text
Phase 1: Cumulative Tracking (catch slow scans)
Phase 2: Subnet Correlation (catch distributed scans)
Phase 3: Weighted Port Scoring (add context)
Phase 4: Connection State Analysis (telemetry-dependent)
Phase 5: ML Baselines (adaptive detection)
```

---

## Profile Visibility Note

Port scan findings are always emitted at Medium severity. Under the Low analysis profile, `MinSeverityToShow` is set to High — so standalone PortScan findings are silently filtered out. The exception is correlated escalation: if the same source IP also triggers both Beaconing and LateralMovement findings, RiskEscalator promotes all findings for that host (including PortScan) to Critical, which passes the Low profile's severity filter. Without this escalation, the detector detects, but the pipeline hides.

## Custom-Profile Note

If a team enables `PortScanMaxEntriesPerSource`, the detector also accepts a completeness trade-off on very large sources. That cap can prevent resource exhaustion, but it can also hide later events that would have changed the result.

---

## Security Takeaways

1. **Evasion trades speed for stealth** — slow scans are harder to catch but also slower to gather intel
2. **Defense in depth** — each layer catches what others miss
3. **Documented limitations support compensating controls** — knowing blind spots enables compensating controls
4. **Clear improvement path** — each evasion has a specific enhancement

