# Quick Reference

---

## Core Metrics

| Metric | Value |
|--------|-------|
| Parser | `WindowsFirewallLogParser` |
| Output model | `LogEntry` |
| Timestamp layouts | Common two-token `pfirewall.log` + accepted one-token ISO variant |
| Exact formats | 4 |
| IP validation | Placeholder + `IPAddress.TryParse` |
| Port validation | Protocol-aware gate → Parse → Range |
| Return type | `IReadOnlyList<LogEntry>` |

---

## Accepted Timestamp Formats

| Format | Example |
|--------|---------|
| `yyyy-MM-dd HH:mm:ss` | `2024-01-15 10:30:15` |
| `yyyy-MM-dd HH:mm:ss.FFFFFFF` | `2024-01-15 10:30:15.1234567` |
| `yyyy-MM-ddTHH:mm:ss` | `2024-01-15T10:30:15` |
| `yyyy-MM-ddTHH:mm:ss.FFFFFFF` | `2024-01-15T10:30:15.1234567` |

---

## Validation Gates

| Gate | Validation | Result On Failure |
|------|------------|------------------|
| 1 | Blank/comment line | Ignore silently |
| 2 | Minimum part count | Parse error + skip |
| 3 | Timestamp parse | Parse error + skip |
| 4 | Required fields after timestamp | Parse error + skip |
| 5 | IP placeholder check | Parse error + skip |
| 6 | IP format check | Parse error + skip |
| 7 | Source port validation | Parse error + skip |
| 8 | Destination port validation | Parse error + skip |
| 9 | Record construction safety net | Parse error + skip |

---

## Main Patterns

| Pattern | Purpose |
|---------|---------|
| Two-layout timestamp parsing | Keep field alignment correct across timestamp shapes |
| TryParse with discard | Validate IPs without storing parsed objects |
| Gate → Parse → Range | Make port failures explicit and testable |
| Fail-soft loop | Preserve good evidence when some rows are bad |
| Immutable record | Keep parsed data stable after creation |
| Read-only collection | Expose results safely to callers |

---

## Known Limitations

| Limitation | Current Behavior |
|-----------|------------------|
| Timezones/offsets | Not parsed; timestamps are labeled `Local` |
| Non-whitelisted timestamp variants | Still rejected outside the exact compatibility list |
| Semantic IP checks | Not performed |
| Native trailing fields | Common fields are captured, but not all downstream logic uses them yet |

---

## Key Evidence

| File | Why It Matters |
|------|----------------|
| [WindowsFirewallLogParser.cs](../../../VulcansTrace.Core/Parsing/WindowsFirewallLogParser.cs) | Core parser logic |
| [LogEntry.cs](../../../VulcansTrace.Core/LogEntry.cs) | Immutable parsed-event model |
| [WindowsFirewallLogParserTests.cs](../../../VulcansTrace.Tests/Core/WindowsFirewallLogParserTests.cs) | Behavioral proof |
