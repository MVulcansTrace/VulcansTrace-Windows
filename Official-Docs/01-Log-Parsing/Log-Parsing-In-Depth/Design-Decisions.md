# Design Decisions

Every major choice in this parser has a security rationale, a performance implication, and an operational impact.

---

## Decision 1: Multi-Timestamp Layout Support

**Decision:** Accept both one-token and two-token timestamp formats, with exact format matching for each.

**Rationale:** Native `pfirewall.log` commonly uses a two-token local timestamp, but the parser intentionally accepts a small whitelist of additional exact layouts for compatibility with normalized inputs and tests.

| Layout | Example | Why It Matters |
|--------|---------|----------------|
| One-token | `2024-01-15T10:30:00.123` | Accepted compatibility format for normalized inputs and tests |
| Two-token | `2024-01-15 10:30:00` | Common native `pfirewall.log` layout |

**Security Rationale:** Exact format matching (not liberal parsing) prevents ambiguous timestamps that could misrepresent attack timing. The `actionIndex` calculation adjusts field alignment based on timestamp token count.

**Trade-off:** Non-whitelisted timestamp formats are rejected. This is intentional — unknown formats should fail explicitly rather than parse incorrectly.

---

## Decision 2: Staged IP and Port Validation

**Decision:** Validate IPs and ports in multiple stages: placeholder check, syntax validation, then range enforcement, with protocol-aware handling for portless ICMP-style rows.

**Rationale:** Different failure modes require different handling. A placeholder `-` can indicate broken data, but for ICMP-style rows it can also mean the protocol simply has no ports. The parser now keeps those rows by representing ports as nullable fields while still rejecting malformed placeholders for protocols that require ports.

| Stage | Check | Outcome |
|-------|-------|---------|
| IP placeholder gate | `srcIp == "-"` or `dstIp == "-"` | Reject row — missing IP address |
| IP syntax | `IPAddress.TryParse()` | Reject malformed addresses |
| Port placeholder gate | `srcPort == "-"` or `dstPort == "-"` | Reject row unless the protocol is ICMP-style |
| Port syntax | `int.TryParse()` | Reject non-numeric ports |
| Port range | `0 <= port <= 65535` | Reject impossible values |

**Security Rationale:** Staged validation keeps malformed data out of downstream detectors. Each stage has a specific failure mode and error message.

**Trade-off:** More validation code than a single `TryParse` call. The benefit is meaningful error messages and correct handling of edge cases like ICMP.

---

## Decision 3: Direction From Recognized Trailing Tokens

**Decision:** Resolve `Direction` from recognized trailing tokens such as `SEND`, `RECEIVE`, `INBOUND`, or `OUTBOUND` instead of assuming it always appears immediately after `dst-port`.

**Rationale:** Simplified test fixtures put direction directly after `dst-port`, but native `pfirewall.log` rows place additional fields like `size`, TCP flags, and `info` before the final path token. Scanning the trailing fields keeps both shapes usable without expanding the model yet.

**Security Rationale:** This avoids mislabeling native `pfirewall.log` rows while preserving a stable `LogEntry` contract for downstream consumers.

**Trade-off:** The parser now models the common native trailing fields, but downstream detectors still focus on the core event shape rather than every native column.

---

## Decision 4: Fail-Soft Parsing Loop

**Decision:** Log malformed rows with specific errors and continue parsing instead of throwing on the first bad line.

**Rationale:** Real-world logs are noisy. Comments, blank lines, mixed whitespace, and malformed rows all appear in the same file. A fail-hard parser would reject entire files due to single bad lines.

```csharp
// Simplified illustration of the fail-soft pattern.
// The actual implementation inlines each validation check
// directly in the Parse() method rather than calling a
// separate TryParseLine helper.

if (string.IsNullOrEmpty(trimmed) || trimmed.StartsWith("#"))
{
    ignoredLines++;
    continue;  // skip blanks and comments silently
}

// ... timestamp, IP, and port validation gates ...

if (!TryParsePort(dstPortRaw, out var dstPort))
{
    ignoredLines++;
    parseErrors.Add($"Line {totalLines}: Invalid destination port '{dstPortRaw}'. Content: {trimmed}");
    continue;  // log error, skip this row, keep going
}

entries.Add(entry);  // only reached if all gates pass
```

**Security Rationale:** Availability during incident response. Investigators get structured data from valid rows instead of a complete failure.

**Trade-off:** Parse errors are collected in memory. Very large files with many errors could grow the error list significantly. In practice, this is acceptable because the alternative is zero visibility.

---

## Decision 5: Immutable LogEntry Records

**Decision:** Use `record` type with `init`-only properties for parsed log entries.

**Rationale:** Parsed data should not drift after creation. Immutability prevents accidental mutation and makes the data safe to share across detectors and UI layers.

```csharp
public sealed record LogEntry
{
    public required DateTime Timestamp { get; init; }
    public string Action { get; init; } = "";
    public string Protocol { get; init; } = "";
    public string SrcIp { get; init; } = "";
    public int? SrcPort { get; init; }
    public string DstIp { get; init; } = "";
    public int? DstPort { get; init; }
    public int? PacketSize { get; init; }
    public string Path { get; init; } = "";
    public string Direction { get; init; } = "";
    public string RawLine { get; init; } = "";
    // ... TcpFlags, TcpSyn, TcpAck, TcpWin, IcmpType, IcmpCode, Info omitted for brevity
}
```

**Security Rationale:** Immutable records eliminate a class of bugs where parsed data is accidentally modified between parsing and analysis.

**Trade-off:** Cannot fix parsing mistakes in-place. If a field needs correction, a new record must be created. This is acceptable because the parser should get it right the first time.

---

## Decision 6: IReadOnlyList Return Type

**Decision:** Return `IReadOnlyList<LogEntry>` instead of `List<LogEntry>` or `LogEntry[]`.

**Rationale:** Callers need read access to parsed entries, not mutation rights. The interface communicates intent and prevents accidental modification.

**Security Rationale:** Read-only downstream consumption prevents detectors from accidentally corrupting parsed data.

**Trade-off:** Callers who need to modify must create their own copy. This is acceptable because mutation is not the expected use case.

---

## Decision 7: RawLine Preservation

**Decision:** Store the original raw line in each `LogEntry` record.

**Rationale:** Investigators may need to verify parsed data against the source text. Raw line preservation enables traceability and debugging.

**Security Rationale:** Forensic integrity. When a finding is questioned, analysts can verify the parsed fields against the original log line.

**Trade-off:** Slightly larger memory footprint per entry. Acceptable because traceability is more valuable than the memory savings.

---

## Decision 8: Cancellation Support

**Decision:** Accept `CancellationToken` and check it during parsing.

**Rationale:** Large log files can take time to parse. Cooperative cancellation allows the UI to abort long-running imports when the user changes parameters or closes the window.

**Security Rationale:** Availability. Users are not trapped waiting for a long import to complete.

**Trade-off:** Slight overhead from cancellation checks. Negligible compared to the benefit of responsive UI.

---

## Summary

| Decision | Security Principle | Operational Impact |
|----------|-------------------|-------------------|
| Multi-timestamp layout support | Format flexibility with exact matching | Handles native rows plus small compatibility variants without ambiguity |
| Staged IP and port validation | Input sanitization at ingestion | Meaningful errors, no poisoned data downstream |
| Direction from recognized trailing tokens | Schema compatibility at ingestion | Supports simplified fixtures and native `pfirewall.log` rows |
| Fail-soft parsing loop | Availability during messy imports | Investigation continues despite bad rows |
| Immutable LogEntry records | Data integrity | Safe sharing across detectors and UI |
| IReadOnlyList return type | Read-only downstream consumption | Prevents accidental mutation |
| RawLine preservation | Forensic traceability | Analysts can verify findings against source |
| Cancellation support | Availability | Responsive UI on large datasets |
