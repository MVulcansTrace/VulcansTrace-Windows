# Expertise Snapshot

> **1 page:** the subsystem, why it matters, and where the proof lives in the codebase.

---

## Implementation Overview

A **Windows Firewall log parser** for VulcansTrace that turns raw log text into structured `LogEntry` records. It handles multiple timestamp layouts, validates IPs and ports, records parse errors, and keeps processing when some rows are malformed.

---

## Key Metrics

| Metric | Value |
|--------|-------|
| Timestamp layouts | 2 token-layout variants (one-token and two-token) |
| Exact timestamp formats | 4 |
| IP support | IPv4 + IPv6 |
| Output contract | `IReadOnlyList<LogEntry>` |
| Error handling | Fail-soft with parse-error tracking |
| Traceability | Original source line preserved |

---

## Why It Matters

- Gives downstream detectors clean, structured data instead of raw text
- Preserves useful evidence even when some rows are malformed
- Produces explicit parse-error messages that help debugging and investigation
- Shows security thinking around validation, resilience, and traceability

---

## Key Evidence

- [WindowsFirewallLogParser.cs](../../../VulcansTrace.Core/Parsing/WindowsFirewallLogParser.cs): parser pipeline, timestamp handling, validation, and fail-soft loop
- [LogEntry.cs](../../../VulcansTrace.Core/LogEntry.cs): immutable parsed-event model with raw-line preservation
- [WindowsFirewallLogParserTests.cs](../../../VulcansTrace.Tests/Core/WindowsFirewallLogParserTests.cs): valid parsing, malformed rows, placeholders, IPv6, and alternate timestamps

---

## Key Design Choices

- **Exact timestamp parsing with `actionIndex`** so field alignment remains correct across multiple layouts
- **Staged IP and port validation** so placeholders, invalid syntax, and range failures are handled explicitly
- **Fail-soft parsing** so one bad row does not break the rest of the import
- **Immutable `LogEntry` records with `RawLine`** so parsed data stays stable and traceable

