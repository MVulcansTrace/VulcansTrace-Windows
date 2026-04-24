# Evasion Techniques and Limitations

Understanding blind spots enables compensating controls for each limitation.

---

## Known Evasion Techniques

| Evasion | How It Works | Detection Status | Compensating Control |
|---------|-------------|-----------------|---------------------|
| **Slow pivoting** | One host per hour; never accumulates enough in the window | Missed | Longer-horizon cumulative tracking |
| **Non-admin ports** | HTTP/HTTPS, custom ports for pivoting | Not detected | Extend `AdminPorts` per environment |
| **Living off the land** | WMI, WinRM, PowerShell remoting | Partial — depends on ports used | Add 5985/5986, 135; pair with endpoint telemetry |
| **Proxy pivoting** | Route through compromised jump host | Partial — only proxy connection visible | Network flow analysis |
| **Distributed pivoting** | Multiple sources, few hosts each | Missed — per-source analysis only | Cross-source subnet correlation |
| **Pass-the-hash** | Credential reuse over SMB | May still be detected if it produces internal SMB spread across enough hosts in the window | Endpoint auth-log correlation |

---

## Slow Pivoting: Speed vs. Stealth

```text
Fast pivot (detected):    6 hosts in 5 minutes
Slow pivot (evades):      1 host every 15 minutes → max 1 host in any 10-min window
                          Below all profile thresholds (High=3, Medium=4, Low=6)
```

**Why it evades:** The default 10-minute sliding window (`LateralWindowMinutes`, configurable via `AnalysisProfile`) cannot accumulate enough distinct hosts when the attacker spaces connections across hours. This holds across all three built-in profiles (Low, Medium, High all use 10 minutes).

**Mitigation:** A cumulative 24-hour distinct-host tracker with a separate threshold. Trade-off: increases false positives from backup servers and monitoring tools that legitimately touch many hosts daily.

---

## Non-Admin Ports: Signal vs. Coverage

```text
Attacker pivots via HTTP:  192.168.1.100 → .10:80, .11:80, .12:80, .13:80
Result: Not in AdminPorts → UNDETECTED
```

**Why it evades:** The port filter excludes HTTP, HTTPS, and custom application ports. Adding these ports would drown the analysis in noise.

**Mitigation:** Targeted port additions based on environment — WinRM (5985/5986) for Windows enterprises, Kubernetes ports (6443, 2379) for container environments. Each addition should be justified by threat modeling, not added speculatively.

---

## Proxy Pivoting: Visibility Ceiling

```text
Attacker → 192.168.1.50 (compromised) → final targets

Network logs show: 192.168.1.50 → .10:445, .11:445, .12:445
Only the jump host's spread is detected. Final targets are invisible.
```

**Why it evades:** The detector sees network connections, not the intent behind them. A proxying host generates the same pattern as direct lateral movement.

**Mitigation:** Hub-node anomaly detection — flag hosts that suddenly become high-degree nodes. Correlate inbound + outbound connection patterns.

---

## What This Detector Cannot Do

| Limitation | Why |
|-----------|-----|
| Identify specific technique (PsExec vs. manual RDP) | Firewall logs show ports, not process names |
| Detect credential theft | Network metadata cannot see authentication methods |
| See through encrypted tunnels | Payloads are opaque at the network layer |
| Catch physical-access lateral movement | No network footprint to detect |
| Detect second movement phase from same source | Detector stops processing a source after the first finding (`break` statement) |
| Handle cloud identity boundaries | RFC1918 classification may miss non-RFC1918 internal addresses used in some cloud VPC/VNet environments |

---

## Improvement Roadmap

```text
Phase 1: Cumulative 24-hour tracking     → Catch slow pivoting
Phase 2: Source allowlisting              → Reduce false positives from known infrastructure
Phase 3: Cross-source subnet correlation  → Catch distributed pivoting
Phase 4: Frequency dictionary optimization → O(m) instead of O(m²) per source
Phase 5: Adaptive baselines per host      → Environment-specific thresholds
```

---

## Why Limitations Matter

Every detector has blind spots. Knowing where the detector fails is the first step toward building compensating controls. A detector that claims to catch everything is one that cannot be trusted.

---

## Security Takeaways

1. **Evasion trades speed for stealth** — slow pivoting is harder to catch but also slower to gather intelligence
2. **Port selection is a trade-off** — broader coverage means more noise
3. **Network detection has limits** — endpoint and auth-log correlation fills the gaps
4. **Clear improvement path** — each evasion has a specific, implementable enhancement

