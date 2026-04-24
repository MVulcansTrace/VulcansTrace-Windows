# MITRE ATT&CK Mapping

---

## Technique Mapping

| Technique | ID | What the Detector Catches |
|-----------|-----|--------------------------|
| Network Denial of Service | T1498 | Partial (primary mapping) — volumetric event bursts per source IP |
| Direct Network Flood | T1498.001 | Analyst-applied mapping when a single-source burst is understood as direct flood behavior from surrounding context |
| Reflection Amplification | T1498.002 | Contextual only — no reflector/amplification pattern detection |
| OS Exhaustion Flood | T1499.001 | Adjacent/contextual — high event volume may coexist with OS exhaustion, but the detector does not measure host state |
| Service Exhaustion Flood | T1499.002 | Adjacent/contextual — service exhaustion may coexist with high event volume, but the detector does not measure service health |

> **Note:** The detector is source-volume-based, not destination-aware, bandwidth-aware, or service-health-aware. It groups by `SrcIp`, sorts by `Timestamp`, and counts raw events inside a sliding window. ATT&CK sub-techniques beyond broad flood behavior are analyst-applied context layered on top of that pattern.

---

## Attack Lifecycle Position

```text
Recon -> Resource Development -> Initial Access -> Execution -> Persistence -> PrivEsc
  -> Defense Evasion -> Credential Access -> Discovery -> Lateral Movement
  -> Collection -> C2 -> Exfiltration -> [IMPACT]
```

> Simplified lifecycle shown for context; not every ATT&CK tactic is represented.

**Flood detection position:** Impact phase — the final stage where the attacker degrades or denies availability.

**Why this position matters:**

- Last-stage detection — the event pattern suggests availability may be under threat
- Response time is critical — every minute of flooding compounds the impact
- May indicate botnet participation — a compromised host used in someone else's attack

---

## Coverage Matrix

| Technique | Detected? | Notes |
|-----------|-----------|-------|
| T1498 (Network DoS) | Partial | Event count is a proxy; no bandwidth or service-impact measurement |
| T1498.001 (Direct Flood) | Partial | Single-source bursts caught; destination concentration and distributed floods are not analyzed |
| T1498.002 (Reflection/Amplification) | Contextual | May alert if a reflector IP generates high volume; no pattern analysis |
| T1499.001 (OS Exhaustion) | Adjacent/contextual | High event counts can coexist with OS exhaustion; no host-state or SYN-specific logic |
| T1499.002 (Service Exhaustion) | Adjacent/contextual | High event counts can coexist with service exhaustion; no service-health visibility and slow-rate attacks often stay below threshold |

---

## Attacker Perspective

**What attackers know:**
- Rate-based detection exists
- Thresholds may be tuned to the environment

**Attacker countermeasures:**
1. **Rate shaping** — Stay below the configured threshold
2. **Distributed sources** — Use many IPs (DDoS)
3. **Pulsed attacks** — Burst, pause, repeat
4. **Slow-rate techniques** — Low-and-slow service exhaustion

**Defensive recommendations:**
1. Combine with NetFlow analysis for bandwidth-level detection
2. Aggregate by destination for DDoS detection
3. Implement cumulative tracking for slow-rate attacks
4. Layer with endpoint monitoring for service-health confirmation

---

## Context Determines the Mapping

Same source-volume pattern, different analyst context:

- **External source** flooding a public service → T1498 (Network DoS)
- **Internal compromised host** generating storm-level traffic → botnet participation indicator or internal-source flood behavior; T1499 requires additional endpoint/service context
- **Multiple sources** converging on one target → DDoS (not currently detected by per-source analysis)

The detector identifies the volumetric pattern. The analyst still provides the operational context.

---

## Finding Integration

| Finding Field | MITRE Use |
|---------------|-----------|
| `SourceHost` | Observed source or reflector IP for triage; not reliable attacker attribution |
| `TimeRangeStart/End` | Attack timeline construction |
| `Severity` | Prioritization (Impact = High; escalated to Critical if correlated with Beaconing + Lateral Movement) |
| `Details` | Detection context and analyst validation |

---

## Security Takeaways

1. **ATT&CK provides a common reference model** — mapping detections helps analysts align findings with standard terminology
2. **Context determines the mapping** — same pattern, different technique based on source and intent
3. **Coverage boundaries matter** — event count is a proxy indicator, not proof of bandwidth exhaustion
4. **Primary coverage is T1498/T1498.001** — adjacent techniques documented as gaps

