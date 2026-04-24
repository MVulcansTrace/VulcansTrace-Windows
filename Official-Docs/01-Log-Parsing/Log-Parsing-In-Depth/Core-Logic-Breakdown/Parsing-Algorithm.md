# Parsing Algorithm

---

## The Security Problem

Firewall logs arrive as plain text, not structured objects. That means the parser has to answer three questions repeatedly:

1. Is this line real data or something to ignore?
2. If it is data, where do the actual fields begin?
3. If a field is malformed, do we stop or keep going?

The parser must solve those problems while preserving data quality and keeping the import usable during investigations.

---

## Implementation Overview

A parsing pipeline implemented in [WindowsFirewallLogParser.cs](../../../../VulcansTrace.Core/Parsing/WindowsFirewallLogParser.cs):

```text
Raw log text
    |
    v
Split into lines
    |
    v
Step A: Trim and skip blanks/comments
    |
    v
Step B: Parse timestamp and determine actionIndex
    |
    v
Step C: Validate counts and extract core fields
    |
    v
Step D: Validate IPs and ports
    |
    v
Step E: Create immutable LogEntry or record parse error
```

---

## Step A: Trim And Skip Non-Data

**Process:** The parser iterates through pre-split lines, trims each row, and silently skips blank lines or comments.

**Rationale:** Firewall logs often contain headers, comments, and formatting noise. Treating those as normal input would generate useless errors and distract from actual parsing failures.

**Security Angle:** This keeps error tracking focused on suspicious or malformed data instead of expected metadata.

---

## Step B: Parse Timestamp And Determine Field Alignment

**Process:** The parser attempts timestamp parsing in two ways:

- accepted one-token ISO form like `2024-01-15T10:30:15`
- common two-token space-separated form like `2024-01-15 10:30:15`

If parsing succeeds, the method returns both the `DateTime` and an `actionIndex` telling the caller where the action field begins.

**Rationale:** The timestamp format changes where the rest of the fields start. Rather than guessing positions later, the parser locks that alignment in early.

**Security Angle:** Correct alignment prevents malformed timestamps from shifting later fields and corrupting the meaning of the line.

---

## Step C: Validate Counts And Extract Core Fields

**Process:** The parser ensures the line has enough parts before and after timestamp parsing, then extracts:

- action
- protocol
- source IP
- destination IP
- source port
- destination port
- optional direction token from the remaining trailing fields when recognized

**Rationale:** Count checks are cheap and stop obviously broken rows before more detailed validation runs. Direction is handled separately because native `pfirewall.log` rows place many fields between `dst-port` and the final `SEND` or `RECEIVE` token.

**Security Angle:** Early rejection prevents truncated or malformed rows from creating partial records that would mislead downstream analysis.

---

## Step D: Validate IPs And Ports

**Process:** The parser runs staged validation:

- IPs: placeholder check, then `IPAddress.TryParse`
- Ports: protocol-aware placeholder gate, integer parse, then `0-65535` range check

**Rationale:** Each stage catches a different failure mode. Placeholders, invalid syntax, and impossible numeric values are not the same problem and should not be treated as if they were. ICMP-style rows are allowed to keep null ports because the protocol does not use them.

**Security Angle:** The staged design improves data quality and produces more specific parse-error messages for investigators.

---

## Step E: Emit `LogEntry` Or Record A Failure

**Process:** The parser creates an immutable `LogEntry` record with the parsed fields, common native trailing fields, and the original `RawLine`. If anything unexpected goes wrong during record construction, the exception is caught, the error is logged, and parsing continues.

**Rationale:** The parser should preserve good evidence even when some rows are unusable.

**Security Angle:** This is the core fail-soft behavior. The parser does not trade all visibility for one bad row.

---

## Complexity And Behavior

| Metric | Value | Why |
|--------|-------|-----|
| **Time** | O(n) over the number of lines | Each line is processed once |
| **Space** | O(v + e) | Stores valid entries plus parse errors |
| **Output model** | `IReadOnlyList<LogEntry>` | Read-only downstream consumption |
| **Cancellation** | Throw at next iteration on request | User intent should stop long parses promptly |

---

## Implementation Evidence

- [WindowsFirewallLogParser.cs](../../../../VulcansTrace.Core/Parsing/WindowsFirewallLogParser.cs): full parser pipeline, including `TryParseTimestamp`, `TryParsePort`, and the fail-soft loop
- [WindowsFirewallLogParserTests.cs](../../../../VulcansTrace.Tests/Core/WindowsFirewallLogParserTests.cs): sample log parsing, malformed rows, hyphen placeholders, alternate timestamp formats, and IPv6 support
- [LogEntry.cs](../../../../VulcansTrace.Core/LogEntry.cs): immutable output model used by the parser
