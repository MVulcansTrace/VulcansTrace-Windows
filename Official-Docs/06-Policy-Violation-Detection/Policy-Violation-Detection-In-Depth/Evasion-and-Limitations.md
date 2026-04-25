# Evasion and Limitations

Understanding blind spots enables compensating controls for each limitation.

---

## Known Evasion Techniques

| Evasion | How It Works | Detection Status | Compensating Control |
|---------|-------------|-----------------|---------------------|
| **Protocol tunneling on allowed ports** | Exfiltrate via HTTPS (443) or other allowed ports | Not detected | DPI, TLS inspection, behavioral analysis |
| **Port hopping** | Rotate through ports not on the disallowed list | Not detected | Dynamic port-list updates, behavioral baselines |
| **DNS exfiltration** | Encode data in DNS queries on port 53 | Not detected | DNS monitoring, query-length analysis |
| **Rate-based noise** | Flood with thousands of violations to cause alert fatigue | All violations reported by detector (no rate limiting); all pass shipped-profile severity filters | SIEM aggregation, dashboard grouping, time-window dedup |
| **IPv6 address ambiguity** | IPv6 Target format lacks brackets (e.g., `2001:db8::2:21`) | Finding created but Target string is ambiguous | Bracket notation for IPv6 in Target field |

---

## Protocol Tunneling: The Biggest Gap

```text
Attacker exfiltrates via HTTPS:  192.168.1.100 → 203.0.113.50:443
Result: Port 443 not in DisallowedOutboundPorts → UNDETECTED
```

**Why it evades:** The detector is port-based. It does not inspect payloads or verify that the protocol on port 443 is actually HTTPS. An attacker can tunnel any protocol through any allowed port.

**Mitigation:** This is a fundamental limitation of port-based detection. Compensating controls include deep packet inspection (DPI), TLS inspection proxies, and behavioral analysis that looks at connection timing, volume, and destination reputation.

---

## Static Port List: Known Unknowns

```text
New threat on port 8443:  192.168.1.100 → malicious-server:8443
Result: 8443 not in DisallowedOutboundPorts → UNDETECTED
```

**Why it evades:** The port list is configured at analysis time and does not adapt to new threats.

**Mitigation:** Regular threat-model reviews to update `DisallowedOutboundPorts`. Environment-specific additions — WinRM (5985/5986), Kubernetes API (6443) — should be justified by threat modeling, not added speculatively.

---

## Alert Fatigue: The Operational Trade-Off

```text
Misconfigured app: 192.168.1.100 → 203.0.113.50:21 (× 10,000 connections)
Result: 10,000 findings, one per violation
```

**Why this matters:** A misconfigured application making thousands of FTP connections produces thousands of findings. The detector has no deduplication or rate limiting.

**Pipeline note:** Policy violations are emitted at **High** severity, so they survive the pipeline's `MinSeverityToShow` filter under all shipped profiles (Low→High, Medium→Medium, High→Info). A custom profile with `MinSeverityToShow=Critical` would suppress standalone policy violations — but that is a configuration choice, not a detector behavior.

**Mitigation:** This is an intentional trade-off. The right fix is correcting the application, not hiding the alerts. Downstream systems (SIEM, dashboards) can aggregate by SourceHost for display purposes. The detector preserves full detail so aggregation decisions are made with complete information.

---

## What This Detector Cannot Do

| Limitation | Why |
|-----------|-----|
| Verify actual protocol on a port | Firewall logs show ports, not payloads |
| Detect data volume or transfer size | Windows Firewall logs do not record bytes |
| See through encrypted tunnels | Payloads are opaque at the network-log layer |
| Distinguish malicious from misconfigured | Same network pattern, different intent |
| Adapt to new threats automatically | Static port list requires manual updates |
| Identify specific attack technique | Cannot tell C2 from exfiltration from admin error |

---

## Cloud-Scale Considerations

| Cloud Environment | Challenge | Impact |
|-------------------|-----------|--------|
| NAT or proxy layers | Logged addresses may not reflect the original endpoint | Classification may apply to translated addresses instead of the host of interest |
| Kubernetes overlays | Pod-to-pod traffic uses overlay networks | Internal classification may miss container traffic |
| Environment-specific private ranges | Some environments may need additional internal-range logic beyond the built-in checks | Static defaults may be insufficient without extension |

**Mitigation for non-default environments:** Extend `IpClassification` with environment-specific ranges when needed, or supplement this detector with environment-native telemetry when address translation or overlay networking changes what the logs represent.

---

## IPv6 Target Format Ambiguity

```csharp
Target = $"{e.DstIp}:{e.DstPort}"
```

For IPv4, this produces familiar `203.0.113.50:21`. For IPv6, the same string concatenation produces `2001:db8::2:21` — it is unclear whether `:21` is the port or part of the address.

**Mitigation:** Use bracket notation for IPv6: `[2001:db8::2]:21`. This is a known formatting issue in the current implementation, not a detection gap.

---

## Improvement Roadmap

```text
Phase 1: IPv6 bracket notation in Target field    → Remove ambiguity
Phase 2: Rate-limiting per source                  → Reduce alert fatigue from misconfigured apps
Phase 3: Destination reputation enrichment         → Prioritize findings by external IP risk
Phase 4: Adaptive port-list updates                → Respond to new threats faster
Phase 5: Cloud-aware IP classification             → Support VPC/VNet environments
```

---

## Why Limitations Matter

Every detector has blind spots. Knowing where the detector fails is the first step toward building compensating controls. A detector that claims to catch everything is one that cannot be trusted.

---

## Security Takeaways

1. **Port-based detection is inherently limited** — it does not verify actual protocol or payload
2. **Static lists require active maintenance** — threat-model reviews keep the configuration relevant
3. **Alert fatigue is an operational trade-off** — full visibility vs. clean dashboards (all violations pass shipped-profile severity filters)
4. **Cloud environments need extended classification** — RFC 1918 is not sufficient everywhere
5. **Each limitation has a specific compensating control** — DPI, behavioral analysis, SIEM aggregation

