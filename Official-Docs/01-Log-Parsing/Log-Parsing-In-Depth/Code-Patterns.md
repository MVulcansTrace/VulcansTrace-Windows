# Code Patterns

---

## The Security Problem

Parsers become fragile when each validation rule is implemented differently. Consistent patterns matter because they make the code easier to reason about, easier to test, and less likely to fail in surprising ways.

---

## Implementation Overview

The parser relies on a small set of implementation patterns:

| Pattern | Where It Appears | Why It Matters |
|---------|------------------|----------------|
| **Two-layout timestamp parsing** | `TryParseTimestamp` | Handles both one-token and two-token timestamp layouts cleanly |
| **TryParse with discard** | IP validation | Validates format without carrying unnecessary parsed objects |
| **Gate → Parse → Range** | Port validation | Separates placeholders, syntax failures, and impossible values |
| **Fail-soft loop** | Main parse loop | Logs errors, skips bad lines, and keeps good evidence |
| **Immutable records** | `LogEntry` | Makes parsed entries safer to share across the app |
| **Read-only return type** | `Parse(...)` signature | Exposes results without mutation rights |

---

## How It Works (Technical)

### Two-Layout Timestamp Parsing

`TryParseTimestamp` supports:

- `yyyy-MM-dd HH:mm:ss`
- `yyyy-MM-dd HH:mm:ss.FFFFFFF`
- `yyyy-MM-ddTHH:mm:ss`
- `yyyy-MM-ddTHH:mm:ss.FFFFFFF`

It also returns `actionIndex`, which tells the caller where the action field begins after parsing the timestamp.

### TryParse With Discard

For IP validation, the parser uses `IPAddress.TryParse(..., out _)` because only the validity check matters. The stored model preserves the original string.

### Gate → Parse → Range

Port validation is intentionally staged:

1. Reject `-` placeholders
2. Parse integer with `InvariantCulture`
3. Enforce `0-65535`

That structure makes failure modes clearer and easier to diagnose.

### Fail-Soft Loop

The parser increments ignored counts, records specific parse errors, and continues unless cancellation is requested.

### Immutable Model And Read-Only Output

`LogEntry` uses `init` properties and the parser returns `IReadOnlyList<LogEntry>`, which keeps downstream usage simple and safe.

---

## Implementation Evidence

- [WindowsFirewallLogParser.cs](../../../VulcansTrace.Core/Parsing/WindowsFirewallLogParser.cs): timestamp parsing, staged validation, and fail-soft loop
- [LogEntry.cs](../../../VulcansTrace.Core/LogEntry.cs): immutable parsed-event record
- [WindowsFirewallLogParserTests.cs](../../../VulcansTrace.Tests/Core/WindowsFirewallLogParserTests.cs): confirms valid parsing, malformed-line rejection, IPv6 support, and multiple timestamp variants

---

## Security Takeaways

1. **Consistent validation patterns reduce accidental parser drift**
2. **Immutable models make parsed evidence safer to share**
3. **Explicit failure modes improve forensic review**
4. **A small number of well-chosen patterns often beats a large amount of clever code**
