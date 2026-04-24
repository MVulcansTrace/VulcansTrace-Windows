# Evasion Techniques and Limitations

Understanding blind spots enables compensating controls for each limitation.

---

## Visibility Caveat

Before discussing evasion, it is critical to understand when Novelty findings are actually visible to the user. The detector emits findings at **`Severity.Low`**, but `SentryAnalyzer` filters results by `MinSeverityToShow` from the active `AnalysisProfile`:

| Intensity | Novelty Enabled? | Min Severity to Show | Novelty Findings Visible? |
|-----------|-----------------|----------------------|--------------------------|
| Low | No (`EnableNovelty = false`) | High | Never runs |
| Medium | Yes | Medium | Filtered out — `Low < Medium` (unless escalated to Critical via Beaconing + LateralMovement correlation) |
| High | Yes | Info | Visible |

At the **Medium** profile, Novelty runs but its findings are silently discarded by severity filtering. The evasions below are only meaningful when running at **High** intensity or with a custom profile that lowers `MinSeverityToShow` to `Low` or `Info`.

---

## Known Evasion Techniques

| Evasion | How It Works | Detection Status | Compensating Control |
|---------|-------------|-----------------|---------------------|
| **Multiple beacons** | 2+ connections to same destination | Not detected | BeaconingDetector catches regular periodic patterns (requires 4+ events at High intensity, 6+ at Medium, 8+ at Low, over a 2-minute minimum duration; does not cover the 2-beacon case at any profile) |
| **Fast flux DNS** | Rotating IPs fragment campaign into singletons | Partially detected | Each rotating IP is flagged individually; DNS analysis needed for correlation |
| **Domain fronting** | CDN hides true destination behind popular IP | Not detected — CDN IP may have count > 1 | TLS inspection and traffic analysis |
| **Delay between beacons** | Log rotation resets history; same dest becomes "novel" again | Not addressed | Persistent first-seen database or time-windowed novelty |
| **Popular services** | C2 via well-known IP:port; count > 1 from other users | Not detected | Behavioral analysis and threat intel enrichment |
| **Shared destination from multiple sources** | Two hosts each connect once to same tuple → count = 2 | Not detected | Per-source counting (design change) |

---

## Multiple Beacons: The Simplest Evasion

```text
Attacker connects to C2 twice:
  192.168.1.50 → 203.0.113.42:443  (first beacon)
  192.168.1.50 → 203.0.113.42:443  (second beacon)
Result: count = 2 → not a singleton → NO FINDING
```

**Why it evades:** The detector's strict count == 1 boundary means any destination contacted twice is no longer novel. This is by design — most two-time connections are legitimate retries.

**Mitigation:** BeaconingDetector covers regular periodic patterns but requires 4+ events over 2+ minutes (profile-dependent). For irregular two-time connections, neither NoveltyDetector nor BeaconingDetector provides coverage. A looser threshold (count <= 2) would catch this but would increase false positives significantly.

---

## Fast Flux DNS: Flagged But Fragmented

```text
Attacker uses fast flux:
  192.168.1.50 → 198.51.100.7:443  (once, rotating IP)
  192.168.1.50 → 198.51.100.8:443  (once, rotating IP)
  192.168.1.50 → 198.51.100.9:443  (once, rotating IP)
Result: THREE separate findings (each is a singleton)
```

**Why it is partial:** Novelty flags each rotating IP as a separate singleton. It cannot determine they are related because it tracks IP:port tuples, not domains. An analyst would need DNS correlation or threat intel to connect the dots.

---

## Delay Between Beacons: The Batch Boundary Problem

```text
Batch 1 (Monday):  192.168.1.50 → 203.0.113.42:443  → count = 1 → FINDING
Batch 2 (Tuesday): 192.168.1.50 → 203.0.113.42:443  → count = 1 → FINDING (again!)
```

**Why it evades the intent:** Novelty is relative to the current log corpus, not a persistent first-seen database. Log rotation means the same destination can appear "novel" in every batch.

**Mitigation:** A persistent first-seen database or time-windowed novelty ("first seen in last N hours") would solve this. This is an architectural change, not a simple tuning adjustment.

---

## What This Detector Cannot Do

| Limitation | Why |
|-----------|-----|
| Determine intent | Network metadata cannot distinguish malicious from legitimate singletons |
| Identify C2 protocol | Firewall logs show ports, not payloads |
| Correlate across batches | No persistent state between analysis runs |
| Detect internal reconnaissance | Internal singletons are filtered as noise |
| See through encrypted tunnels | Payloads are opaque at the network layer |
| Handle per-source counting | Counting is global — multiple sources contribute to the same tuple count |
| Classify scan types | Protocol-agnostic; only counts occurrences |

---

## Improvement Roadmap

```text
Phase 1: Persistent first-seen database    → Solve batch-boundary problem
Phase 2: Per-source counting               → Catch shared-destination scenarios
Phase 3: Time-windowed novelty             → "First seen in last N hours" semantics
Phase 4: Destination enrichment            → ASN, geolocation, reputation scoring
Phase 5: Cross-detector singleton scoring   → Weight singletons higher when correlated with other findings
```

---

## Why Limitations Matter

Every detector has blind spots. Novelty is a weak-signal detector by design. It surfaces singleton destinations from the current dataset for analyst investigation, and it documents what it cannot determine. A detector that claims to catch everything is one that cannot be trusted.

---

## Security Takeaways

1. **Count == 1 is a strict boundary** — any repeated connection evades the detector
2. **Batch-relative analysis has limits** — log rotation resets novelty state
3. **Popular services hide attackers** — well-known destinations have count > 1
4. **Network detection has limits** — endpoint and DNS correlation fill the gaps
5. **Clear improvement path** — each evasion has a specific, implementable enhancement

