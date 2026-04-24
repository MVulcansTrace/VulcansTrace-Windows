# MITRE ATT&CK Mapping

---

## Technique Mapping

| Technique | ID | Relationship | What Novelty Sees |
|-----------|-----|-------------|-------------------|
| Network Service Discovery | T1046 | Weak signal | One-off outbound probes from a compromised host can appear as singletons |
| Application Layer Protocol | T1071 | Weak signal | Initial or infrequent C2 connections may appear as singletons before regular beaconing begins |
| Dynamic Resolution | T1568 | Weak signal | Rotating infrastructure can create singleton destinations for each new IP |

---

## Caveats

Novelty does not directly detect any ATT&CK technique. It flags singleton external (DstIp, DstPort) tuples. Whether that singleton represents reconnaissance, C2, exfiltration, or a legitimate download is outside the detector's scope.

Specifically, Novelty:

- Cannot identify protocols or analyze payloads
- Cannot distinguish malicious from legitimate traffic
- Cannot correlate across analysis batches or time windows
- Cannot determine the intent behind a single connection

---

## Visibility by Profile

Novelty findings are emitted at `Severity.Low`. Whether they reach the user depends on the analysis profile:

| Profile | Novelty Enabled | Min Severity to Show | Novelty Visible? |
|---------|----------------|----------------------|------------------|
| Low     | No             | High                 | No — detector disabled |
| Medium  | Yes            | Medium               | No — Low < Medium, filtered out |
| High    | Yes            | Info                 | Yes |

On the **Medium** intensity profile (the balanced general-use profile), NoveltyDetector runs and produces findings, but standalone findings are silently discarded by the severity filter (`MinSeverityToShow = Severity.Medium`). However, if the same source host also has both Beaconing and LateralMovement findings, RiskEscalator promotes all findings for that host — including Novelty — to Critical, which passes the filter.

Novelty findings are only visible when running at **High** intensity, or when using a custom profile with `MinSeverityToShow` set to `Low` or `Info`.

---

## What Each Technique Looks Like

### T1046 — Network Service Discovery

```text
Compromised host probes external services:
  192.168.1.100 → 203.0.113.42:443  (once)
  192.168.1.100 → 198.51.100.7:80   (once)

Novelty: Two singleton findings. Cannot determine these are reconnaissance.
Port Scan: Does not detect — only 2 destinations, below threshold.
```

### T1071 — Application Layer Protocol (C2 Check-in)

```text
Initial C2 connection before regular beaconing:
  192.168.1.100 → 203.0.113.42:443  (once, then regular beacons begin)

Novelty: One singleton finding if only one log entry exists for this destination.
         If a future batch includes additional connections to the same (DstIp, DstPort),
         the count exceeds 1 and it is no longer flagged. The detector is stateless —
         each analysis only sees the entries in the current batch.
BeaconingDetector: Catches the regular pattern once beacons begin.
```

### T1568 — Dynamic Resolution

```text
Fast flux DNS creates rotating destination IPs:
  192.168.1.100 → 198.51.100.7:443  (once)
  192.168.1.100 → 198.51.100.8:443  (once)
  192.168.1.100 → 198.51.100.9:443  (once)

Novelty: Three singleton findings. Cannot correlate them as the same campaign.
DNS analysis (not in VulcansTrace): Would resolve to the same domain.
```

---

## Defense-in-Depth Position

Novelty is one layer in a detection stack:

```text
Coverage tier 1: Port Scan Detector    → primary for T1046 (many-destination scanning)
Coverage tier 2: Beaconing Detector    → primary for T1071 (regular periodic C2)
Coverage tier 3: Novelty Detector      → catches singleton blind spots
Coverage tier 4: Lateral Movement      → post-compromise internal spread
Coverage tier 5: Flood Detector        → volumetric attack detection
                  ---------------------
Coverage tier 6: DNS Analysis          → not in VulcansTrace (needed for T1568)
Coverage tier 7: Threat Intel          → not in VulcansTrace (needed for reputation)
```

Novelty complements the stronger detectors by catching the cases they miss — specifically, destinations that appear too few times to trigger volume or pattern thresholds.

---

## Context Determines the Mapping

Same singleton-outbound pattern, different ATT&CK context:

- **Internal compromised host** contacting external singleton → T1046 or T1071 (depends on intent)
- **Fast flux rotation** creating many singletons → T1568 (Dynamic Resolution)

The detector identifies the outbound singleton network pattern it can observe. The analyst provides the operational context.

---

## Security Takeaways

1. **Novelty has weak ATT&CK coverage** — it flags singletons, not techniques
2. **Complementary, not primary** — Port Scan and Beaconing are the primary detectors for these techniques
3. **Findings are invisible at Low and Medium profiles** — at Low intensity the detector is disabled entirely (`EnableNovelty = false`); at Medium intensity the detector runs but findings are filtered out (Low < Medium); use High intensity or a custom profile to see Novelty output
4. **Coverage gaps are documented** — DNS analysis and threat intel are needed for T1568
5. **Context determines the mapping** — same pattern, different technique based on source position and intent

