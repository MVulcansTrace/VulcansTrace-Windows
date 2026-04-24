# Evasion Techniques and Limitations

Understanding blind spots enables compensating controls for each limitation.

---

## Known Evasion Techniques

| Evasion | How It Works | Detection Status | Compensating Control |
|---------|-------------|-----------------|---------------------|
| **Rate limiting** | Attacker stays below threshold per window | Missed | Cumulative tracking over longer windows |
| **DDoS (distributed sources)** | Many IPs, few events each | Missed — per-source analysis only | Aggregate by destination |
| **Pulsed attacks** | Burst below threshold, pause, repeat | Missed — each pulse below threshold | Pattern analysis across windows |
| **Protocol mixing** | Vary protocols across the flood | Still detected — counts all events regardless of protocol | N/A |
| **Spoofed source IPs** | Attacker varies source address | Partial — per-source grouping dilutes each spoofed IP | Correlate by destination or timing |

---

## Rate Limiting: Staying Below Threshold

```text
Medium profile: FloodMinEvents = 200, FloodWindowSeconds = 60

Attack strategy:
- Send 150 events in 60 seconds
- Any 60-second window: 150 events
- Never exceeds threshold
- Result: UNDETECTED

But: 150 events/minute = 9,000 events/hour of cumulative pressure
```

**Why it evades:** The detector checks a single sliding window. It does not track cumulative volume over longer periods.

**Mitigation:** Cumulative tracking over longer windows (10+ minutes). Compare current rate to a historical baseline and alert on significant deviation. Trade-off: increases false positives from legitimate batch operations.

---

## DDoS: Distributed Sources

```text
Medium profile: FloodMinEvents = 200, FloodWindowSeconds = 60

Attack strategy:
- 50 different source IPs
- Each IP sends 4 events in 60 seconds
- Total: 200 events reaching the target
- Per-source: 4 events (well below threshold)
- Result: UNDETECTED
```

**Why it evades:** Current detector analyzes per-source, not per-destination. Each IP individually is harmless. The destination sees the full flood, but the detector does not.

**Mitigation:** Destination aggregation — group by `DstIp` and flag when many unique sources converge on one target. This is a fundamentally different detection strategy and would be a separate detector.

---

## Pulsed Attacks: Burst and Pause

```text
Medium profile: FloodMinEvents = 200, FloodWindowSeconds = 60

Attack strategy:
- Burst: 90 events in 30 seconds
- Pause: 60 seconds
- Burst: 90 events in 30 seconds
- Any 60-second window: max 90 events
- Result: UNDETECTED
```

**Why it evades:** Each individual pulse is below threshold. The detector has no memory of past pulses.

**Mitigation:** Track rate of change in event volume and identify periodic burst patterns. Alert on rapid increases even if below threshold. Trade-off: more complex logic and higher false-positive risk from legitimate bursty applications.

---

## What This Detector Cannot Do

| Limitation | Why |
|-----------|-----|
| Confirm actual service disruption | Firewall logs show connection events, not service health |
| Measure bandwidth or packet volume | Event count is a proxy, not a direct bandwidth measurement |
| Identify specific flood technique (SYN vs. UDP vs. ICMP) | Detector counts all events regardless of protocol fields |
| Attribute spoofed sources | Source IP in logs may not be the real attacker |
| Detect distributed attacks | Per-source analysis cannot aggregate across sources |
| Track flood duration beyond first window | One finding per source; no multi-window tracking |

---

## Performance Characteristics

| Metric | Value |
|--------|-------|
| Time complexity | O(n log n) — sorting dominates |
| Space complexity | O(n) — grouped entries |
| Sliding window per source | O(n) — each event visited at most twice |
| Early exit | Per source after first detection |

The algorithm is efficient enough for moderate log volumes, but sorting is still the dominant cost at scale. Parallelization across source groups is a possible future optimization, not something the current implementation does.

---

## Improvement Roadmap

```text
Phase 1: Cumulative tracking over longer windows     -> Catch slow-rate attacks
Phase 2: Destination aggregation (separate detector)  -> Catch DDoS patterns
Phase 3: Burst-pattern detection                      -> Catch pulsed attacks
Phase 4: Adaptive baselines per source                -> Environment-specific thresholds
Phase 5: Source allowlisting                          -> Reduce false positives from known infrastructure
```

---

## Why Limitations Matter

Every detector has blind spots. Knowing where the detector fails is the first step toward building compensating controls. A detector that claims to catch everything is one that cannot be trusted.

---

## Security Takeaways

1. **Rate limiting trades volume for stealth** — slow floods are harder to catch but also slower to cause impact
2. **Per-source analysis misses distributed attacks** — DDoS requires a fundamentally different detection approach
3. **Protocol mixing does not evade this detector** — it counts all events regardless of protocol
4. **Event count is a proxy, not proof** — firewall log volume approximates flood behavior but does not confirm service impact
5. **Each limitation has a specific improvement path** — documented and implementable

