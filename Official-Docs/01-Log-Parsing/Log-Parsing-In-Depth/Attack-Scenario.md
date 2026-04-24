# Attack Scenario

---

## The Security Problem

During incident response, logs are often incomplete, noisy, or partially corrupted. Sometimes the cause is harmless formatting drift. Sometimes it may be a hostile or malformed entry. In either case, the security team still needs the rest of the evidence.

---

## Worked Example

Imagine a firewall log import with mixed quality input:

```text
2024-01-15 10:30:15 ALLOW TCP 192.168.1.100 203.0.113.10 54321 443 59 - - - - - - - RECEIVE
2024/01/15 10:30:16 ALLOW TCP 10.0.0.5 8.8.8.8 12345 53 60 - - - - - - - SEND
2024-01-15 10:30:17 ALLOW TCP not.an.ip 203.0.113.10 54321 443 48 - - - - - - - RECEIVE
2024-01-15 10:30:18 ALLOW TCP 172.16.0.50 192.168.1.200 3389 3389 60 - - - - - - - RECEIVE
```

The parser behavior is:

1. Parse the first line successfully into a `LogEntry`
2. Reject the second line as an invalid timestamp
3. Reject the third line as an invalid IP
4. Parse the fourth line successfully into a `LogEntry`

That means the investigation keeps two valid records instead of losing the whole batch.

---

## Design Rationale

Fail-soft parsing preserves usable evidence even when some rows are bad. A parser that crashes on the first malformed line turns a single bad row into a pipeline-wide failure.

The parser therefore:

- increments ignored-line counts
- records a specific parse error
- continues to the next row

---

## Security Value

| Parser Behavior | Security Benefit |
|-----------------|------------------|
| **Specific parse errors** | Investigators can see what failed and why |
| **Good rows still parsed** | Detectors keep working on the evidence that remains valid |
| **Raw line preserved on success** | Analysts can verify parsed fields against the source text |
| **Immediate cancellation support** | User-controlled stop remains distinct from bad-data handling |

---

## Evidence

- [WindowsFirewallLogParserTests.cs](../../../VulcansTrace.Tests/Core/WindowsFirewallLogParserTests.cs): includes malformed-line, invalid timestamp, invalid IP, placeholder, and mixed-whitespace scenarios
- [WindowsFirewallLogParser.cs](../../../VulcansTrace.Core/Parsing/WindowsFirewallLogParser.cs): main loop shows the repeated pattern of logging, skipping, and continuing

---

## Security Takeaways

1. **Fail-soft parsing protects investigations** from brittle ingestion behavior
2. **Error context has investigative value** when it names the type of failure
3. **Availability is a security concern** when parsing sits in front of all detection logic
