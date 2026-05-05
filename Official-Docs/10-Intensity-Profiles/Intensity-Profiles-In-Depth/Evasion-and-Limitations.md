# Evasion and Limitations

Gaps, blind spots, and compensating controls for the intensity profile system.

---

## Profile-Related Limitations

### RiskEscalator Masks Profile Differences on Multi-Behavior Hosts

When a single source host exhibits **both Beaconing and LateralMovement**, the `RiskEscalator` promotes **every** finding for that host to `Critical` — regardless of its original severity or detector.

**Consequence:** Profile differences become invisible for that host. On Low profile, a standalone PortScan finding (Medium severity) would normally be filtered out. But if that same host also shows Beaconing + LateralMovement, the PortScan finding is escalated to Critical and survives the Low filter. Every finding on the host is Critical, making it impossible to compare how the raw detectors behave at different sensitivity levels.

**Mitigation in tests:** `IntensityComparisonTests.cs` deliberately isolates each attack behavior to a **unique source IP** so that RiskEscalator never fires. This proves profile-specific threshold behavior without correlation masking the results. The WPF "Load demo data" link uses the same isolated-IP dataset (`SampleData.IntensityComparison`) to demonstrate clean profile differences in the UI.

**Operational implication:** When evaluating profile sensitivity, use isolated attacker data or manually inspect pre-escalation findings. Correlated hosts are compromised-host signals, not profile-sensitivity signals.

### Low Profile Misses Real Attacks

The Low profile requires high thresholds (30 distinct `(DstIp, DstPort)` targets, 6 lateral hosts, 8 beacon events). Real attacks that fall below these thresholds produce no visible findings.

**Example:** An attacker pivoting to 4 internal hosts in 10 minutes triggers on Medium (threshold 4) but not on Low (threshold 6).

**Mitigation:** Use Low for conservative triage or low-noise review, not as the only monitoring view. Active monitoring should run at Medium or High. The escalation-before-filter pipeline ensures that if any finding does trigger on Low, correlated compromise indicators survive the severity gate.

### Novelty Gaps on Low

Novelty detection is disabled on Low profile. Singleton external `(DstIp, DstPort)` targets in the current dataset are not reported.

**Mitigation:** On Medium and High profiles (where Novelty is enabled), if the same host also triggers both Beaconing and LateralMovement, the escalation mechanism promotes all findings for that host (including Novelty) to Critical. On High, Novelty findings are already visible at Low severity without escalation; on Medium, they require this escalation to survive the Medium severity gate. On Low, this safety net does not exist because Novelty is off entirely — there is no Novelty finding to promote.

---

## Threshold-Aware Evasion

### Slow Scanning Below Threshold

An attacker who spaces port scans to stay below `PortScanMinPorts` distinct `(DstIp, DstPort)` targets per 5-minute window evades detection on all profiles.

```text
Attacker scans 7 distinct `(DstIp, DstPort)` targets per 5-minute window on High (threshold 8) → NOT DETECTED
Attacker scans 7 distinct `(DstIp, DstPort)` targets per 5-minute window on Medium (threshold 15) → NOT DETECTED
```

**Mitigation:** Cumulative tracking across multiple windows. Track distinct `(DstIp, DstPort)` targets over a 24-hour period with a separate threshold. Trade-off: increases false positives from network management tools.

### Slow Lateral Movement

An attacker pivoting to one host per hour never accumulates enough distinct hosts in the 10-minute sliding window, regardless of profile.

**Mitigation:** A cumulative 24-hour distinct-host tracker with a separate threshold. Trade-off: backup servers and monitoring tools legitimately touch many hosts daily, increasing noise.

### Beaconing with High Jitter

An attacker introducing random jitter above the `BeaconStdDevThreshold` defeats the regularity check. These thresholds apply to standard deviation calculated after trimming outliers from each end (10% trim parameter via `BeaconTrimPercent`, ceiling-rounded per end). On Medium, 5.0 seconds of trimmed standard deviation is tolerated; on Low, only 3.0.

**Mitigation:** Statistical approaches that model the distribution shape rather than just standard deviation. Seasonal decomposition can detect periodicity even with high jitter. Trade-off: significantly more complex and computationally expensive.

---

## Detection Model Limitations

| Limitation | Why |
|-----------|-----|
| No payload inspection | Firewall logs show ports and IPs, not process names or content |
| No endpoint correlation | Network metadata cannot see authentication methods or process trees |
| No encrypted-traffic analysis | HTTPS and SSH payloads are opaque at the network layer |
| No cloud identity boundaries | RFC1918 classification breaks in VPC/VNet environments |
| No cross-source correlation | Lateral movement analysis is per-source only; distributed pivoting is missed |
| No baseline learning | Thresholds are static per profile; no adaptive baseline per host or network |

---

## Profile Design Trade-offs

| Trade-off | Accepted Because | Compensating Control |
|-----------|-----------------|---------------------|
| Low profile misses sub-threshold attacks | Low is a conservative triage mode, not a complete monitoring view | Use Medium/High for monitoring |
| High profile produces more false positives | During incident response, false positives are acceptable | Triage by severity and category |
| Static thresholds (no ML baselines) | Deterministic rules are interpretable and tunable | Same input = same output; analysts can reason about thresholds |
| One finding per source (Lateral, Flood) | Duplicate alerts add no investigative value | Time range and details capture the scope |
| Fixed PortScan window duration | Keeps scan detection deterministic and tunable | Slow scans still require cumulative tracking |

---

## Cloud-Scale Considerations

The current profile system assumes on-premises firewall logs with RFC1918 IP ranges. Cloud environments introduce challenges:

| Challenge | Impact | Status |
|-----------|--------|--------|
| VPC internal traffic uses private IPs | Lateral movement detection works | Covered |
| Cloud NAT masks true source IPs | Attribution breaks for egress traffic | Known limitation |
| Kubernetes pod networks use wide ranges | Internal classification may need expansion | Configuration change needed |
| Cloud flow logs have different schemas | Parser would need adaptation | Separate concern |
| Auto-scaling generates legitimate burst traffic | Flood thresholds may need cloud-specific profiles | Override via `with` expression |

---

## Improvement Roadmap

```text
Phase 1: Cumulative 24-hour tracking for slow attacks
Phase 2: Adaptive per-host baselines for environment-specific thresholds
Phase 3: Cross-source subnet correlation for distributed attacks
Phase 4: Cloud-aware IP classification (VPC, subnet tags)
Phase 5: Statistical periodicity detection for high-jitter beacons
```

---

## Why Limitations Matter

Every detection system has blind spots. The intensity profile system makes explicit trade-offs between sensitivity and noise, and those trade-offs have consequences. A system that claims to catch everything at every sensitivity level is one that cannot be trusted.
