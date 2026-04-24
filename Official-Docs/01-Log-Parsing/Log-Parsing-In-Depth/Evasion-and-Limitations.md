# Evasion And Limitations

---

## The Security Problem

Any parser lives at the boundary between strict validation and real-world messiness. If it is too loose, bad data can pollute later analysis. If it is too strict, legitimate edge cases may be dropped. Knowing that boundary is part of good security engineering.

---

## Current Limitations

| Limitation | What It Means In Practice | Likely Enhancement Path |
|-----------|----------------------------|-------------------------|
| **Exact timestamp whitelist only** | Unlisted timestamp formats are rejected even if they look plausible | Add formats intentionally, not via liberal parsing |
| **No timezone or offset parsing** | Parsed timestamps are labeled `Local` rather than converted from offsets | Add explicit offset-aware parsing if future log sources require it |
| **Timestamps still use an exact whitelist** | Native local timestamps and the accepted compatibility formats work, but other plausible layouts still fail closed | Add new formats only when tied to real evidence sources and tests |
| **IP validation is syntactic, not semantic** | The parser checks address format, not routability or network meaning | Add higher-level validation in later analysis stages if needed |
| **IPs are stored as strings** | Great for preservation and display, less convenient for subnet math | Add derived `IPAddress` handling only where richer network analysis is needed |
| **Native trailing fields are modeled but lightly consumed** | The parser now captures packet size, TCP slots, ICMP fields, info, and path, but most detectors still rely only on the core fields | Expand downstream usage only where those fields materially improve analysis |

---

## Why These Trade-Offs Are Acceptable Here

These limits reflect the parser's main job: creating dependable structured events from Windows Firewall logs, not solving every possible network-normalization problem at once.

That means the implementation prioritizes:

- explicit, testable rules
- stable output for downstream detectors
- traceability back to the original line
- predictable failure modes

---

## What I Would Improve Next

1. Support additional timestamp formats only when tied to real input sources and tests.
2. Consider optional normalized IP objects for future subnet or enrichment features.
3. Expand detector usage of packet size or ICMP metadata only where those fields materially improve signal quality.
4. Add richer native-field validation if future evidence sources depend on it.

---

## Evidence

- [WindowsFirewallLogParser.cs](../../../VulcansTrace.Core/Parsing/WindowsFirewallLogParser.cs): exact timestamp formats, `SpecifyKind(..., Local)`, placeholder handling, and extra-column behavior
- [WindowsFirewallLogParserTests.cs](../../../VulcansTrace.Tests/Core/WindowsFirewallLogParserTests.cs): alternate timestamp coverage, hyphen placeholder rejection, invalid IP checks, and extra-column parsing
- [LogEntry.cs](../../../VulcansTrace.Core/LogEntry.cs): raw-string IP storage and immutable event shape

---

## Security Takeaways

1. **Every parser draws a boundary** between accepted and rejected data
2. **Limitation analysis is part of effective security engineering**
3. **Extension paths should follow real evidence sources, not vague future-proofing**

