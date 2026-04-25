# Evasion and Limitations

Gaps, blind spots, and compensating controls for the test suite.

---

## Known Evasion Techniques

| Evasion | How It Works | Test Status | Compensating Control |
|---------|-------------|-------------|---------------------|
| **Slow scanning** | 1 port/minute stays below 5-minute window | No test | Multi-window correlation, longer analysis windows |
| **Beacon jitter** | Add random delay to C2 intervals, raising stdDev above threshold | Partial (outlier trim test) | Increase stdDev threshold or use ML-based detection |
| **Domain fronting** | Route C2 through legitimate CDN; timing pattern still detectable but attribution harder | No test | Correlate timing to CDN endpoints, threat intel feeds |
| **Multi-channel beaconing** | Split C2 across protocols; per-tuple analysis misses combined pattern | No test | Cross-protocol correlation from same source |
| **Slow-rate DoS** | Sustained traffic just below flood threshold | No test | Long-window analysis, cumulative volume tracking |
| **Living off the land** | Use legitimate admin tools (PsExec, WMI, PowerShell remoting) | No test | Endpoint detection (EDR), process execution logs |
| **Non-admin pivoting** | Lateral movement over HTTP, WinRM, custom ports | No test | Extend `AdminPorts` per environment |
| **Distributed scanning** | Multiple sources each scan below threshold | Partial (multi-source test exists) | Subnet-level correlation |

---

## Slow Scanning: Speed vs. Stealth

```text
Fast scan (detected):    20 ports in 3 minutes → triggers in 5-minute window
Slow scan (evades):      1 port per minute → 5 ports per window, never hits threshold
```

**Why it evades:** PortScanDetector uses a 5-minute window. At Medium intensity, the threshold is 15 ports. One port per minute produces only 5 ports per window.

**Why no test exists:** The detector does not implement multi-window correlation, so there is nothing to test yet. A slow-scanning test would need to be written alongside the multi-window feature.

**Mitigation:** Cumulative 24-hour tracking with a separate threshold. Trade-off: increases false positives from network monitoring tools that legitimately scan.

---

## Beacon Jitter: Noise vs. Periodicity

```text
Regular beacon:  90s, 90s, 90s, 90s (stdDev ~0) → Detected
Jittered beacon: 65s, 115s, 72s, 108s (stdDev ~22s) → May evade at all intensity levels
```

**Why it evades:** The BeaconingDetector checks standard deviation against `BeaconStdDevThreshold` (3.0 / 5.0 / 8.0 per Low / Medium / High intensity profile). A jittered stdDev of ~22 seconds exceeds all thresholds.

**Test coverage:** The outlier trimming test (`Detect_WithOutlierTrimStillFlagsBeacon`) verifies that removing extreme outliers preserves detection. Large-jitter evasion is not tested.

**Mitigation:** Increase the stdDev threshold (trades false-positive resistance for detection sensitivity). Or use ML-based periodicity detection that tolerates jitter.

---

## Slow-Rate DoS: Volume Below the Radar

```text
Fast flood (detected):   500 packets in 10 seconds → triggers flood threshold
Slow-rate DoS (evades):  100 packets/minute sustained → below volume threshold per window
```

**Why it evades:** FloodDetector uses short time windows. Slow-rate traffic does not accumulate enough events per window.

**Test coverage:** None. A slow-rate DoS test would require a test case spanning multiple windows with sustained but sub-threshold traffic.

**Mitigation:** Long-window analysis (hourly/daily), sustained elevated traffic detection, correlation with service performance metrics.

---

## What This Test Suite Cannot Verify

| Limitation | Why |
|-----------|-----|
| Non-standard pivoting ports | Default profile uses fixed admin ports (445, 3389, 22); custom profiles can override |
| Encrypted tunnel detection | Payloads are opaque at the network layer |
| Credential theft | Network metadata cannot see authentication methods |
| Cloud identity boundaries | RFC1918 IP classification breaks in VPC/VNet environments |
| Performance at scale | No stress tests beyond 5,000 entries |

---

## Test Coverage Gaps

### Critical Gaps

| Gap | Risk | Recommended Action |
|-----|------|-------------------|
| Slow-rate DoS | High — service degradation undetected | Add long-window flood test |
| Slow scanning | Medium — reconnaissance undetected | Add multi-window correlation test |
| Domain fronting | High — C2 communication undetected | Add CDN timing analysis test |

### Medium Gaps

| Gap | Risk | Recommended Action |
|-----|------|-------------------|
| Large beacon jitter | Medium — C2 evasion | Add high-jitter detection test |
| Multi-channel beaconing | Medium — split C2 | Add cross-protocol correlation test |
| Living off the land | High — lateral movement with legitimate tools | Integrate EDR correlation tests |

### Performance Gaps

| Gap | Current Coverage | Target |
|-----|-----------------|--------|
| High-volume stress | 5,000 entries (robustness test) | 100K+ entries |
| Latency measurement | None | <60s analysis time target |
| Memory profiling | None | <1GB memory target |
| Multi-tenant isolation | None | Cross-tenant data leakage tests |

---

## Improvement Roadmap

```text
Phase 1: Slow-scanning test + multi-window correlation feature
Phase 2: Slow-rate DoS test + long-window flood feature
Phase 3: Large-jitter beacon test + adaptive stdDev threshold
Phase 4: Performance benchmarks at 100K+ entries
Phase 5: Cross-protocol correlation test + multi-channel beacon detection
```

---

## Why Limitations Matter

Every test suite has blind spots. Knowing where the test suite falls short is the first step toward building compensating coverage. A test suite that claims to verify everything is one that cannot be trusted.

---

## Security Takeaways

1. **Evasion trades speed for stealth** — slow scanning is harder to catch but also slower to gather intelligence
2. **Jitter is the most practical evasion** — attackers can add randomness without special tools
3. **Cross-protocol correlation is the hardest gap** — requires architectural changes, not just a new test
4. **Performance at scale is untested** — 5,000 entries is not enterprise scale
5. **Each gap has a specific, implementable improvement path**

