# Design Decisions

Every major choice in this pipeline has a security rationale, a performance implication, and an operational impact.

---

## Decision 1: Two-Layer Cryptographic Model (SHA-256 + HMAC-SHA256)

**Decision:** SHA-256 per file plus HMAC-SHA256 over the manifest, rather than a single hash or a single signature.

**Rationale:** A two-layer model provides defense in depth because an attacker who modifies a finding file could also update the corresponding SHA-256 hash in the manifest — requiring the signing key to produce a valid manifest means hash-only modifications are caught by the HMAC.

| Layer | Protects Against | Requires To Verify |
|-------|-----------------|-------------------|
| SHA-256 per file | Accidental corruption, tampering of individual files | Just the file bytes |
| HMAC-SHA256 | Manifest tampering (including hash replacement) | The signing key |

**Trade-off:** HMAC proves the manifest was signed by someone holding the key, not *who* that someone is. For identity-level proof, a digital signature (e.g., RSA-PSS with a certificate) would be needed — but that adds key management complexity that is out of scope for this tool.

---

## Decision 2: External Manifest File (Not ZIP Comment or Embedded Metadata)

**Decision:** `manifest.json` as a separate entry in the ZIP archive.

**Rationale:** A standalone JSON manifest enables independent parsing by any JSON tool and cryptographic signing as a discrete unit — ZIP comments are trivially modifiable and ZIP entry metadata has format-specific limitations.

| Alternative | Rationale |
|-------------|-----------|
| ZIP archive comment | Easily overwritten, no standard format |
| ZIP entry metadata | Format-specific, not machine-readable |
| Embedded in HTML | Would require re-signing on format change |

**Trade-off:** The manifest includes not only file hashes but also the `warnings` array from the analysis result and the `createdUtc` timestamp. Note that the manifest's `files` array covers only the four content files (`findings.csv`, `log.txt`, `report.html`, `summary.md`) — it does not self-reference the `manifest.json` or `manifest.hmac` entries, since those are derived from the content hashes and cannot include themselves. The HMAC signature then protects this manifest as a discrete unit.

---

## Decision 3: Complete Package Structure (Six Files)

**Decision:** Every evidence package contains exactly six files with fixed roles.

**Rationale:** A fixed structure ensures evidence integrity requires knowing exactly what was produced — auditors can verify all expected components exist and match the manifest.

| File | Purpose |
|------|---------|
| `findings.csv` | Tabular findings export with CSV quoting/escaping, formula injection protection, and an optional warnings tail section |
| `log.txt` | Original raw log content as provided |
| `report.html` | Styled HTML report for browser viewing |
| `summary.md` | Markdown summary for documentation systems |
| `manifest.json` | File inventory with SHA-256 hashes, lengths, createdUtc, and warnings array |
| `manifest.hmac` | HMAC-SHA256 signature (lowercase hex, UTF-8 encoded) |

**Trade-off:** Adding new output formats requires modifying the builder's file dictionary. The fixed structure ensures completeness but sacrifices extensibility.

---

## Decision 4: Alphabetical File Ordering

**Decision:** Content file operations (hashing, manifest entries, ZIP entry insertion) process files in alphabetical order. The `manifest.json` and `manifest.hmac` entries are appended after the content files, since they depend on the content hashes and must be produced last.

**Rationale:** Alphabetical ordering ensures determinism requires a predictable sequence — the same set of files always produces the same manifest JSON and the same ZIP byte layout regardless of dictionary enumeration order.

---

## Decision 5: Constructor Injection (Not Static Methods)

**Decision:** `EvidenceBuilder` receives `CsvFormatter`, `HtmlFormatter`, `MarkdownFormatter`, and `IntegrityHasher` via constructor injection.

**Rationale:** Constructor-injected services enable unit tests to verify one formatter at a time and keep dependencies explicit — each formatter has its own dedicated test class; `EvidenceBuilder` integration tests exercise the full pipeline end-to-end. Adding a new export format would still require changing the builder's constructor and file dictionary, but the responsibilities stay clearly separated.

```csharp
public sealed class EvidenceBuilder
{
    private readonly IntegrityHasher _hasher;
    private readonly CsvFormatter _csvFormatter;
    private readonly MarkdownFormatter _markdownFormatter;
    private readonly HtmlFormatter _htmlFormatter;
    // ...
}
```

**Trade-off:** This is not a classic Builder pattern (fluent API with step-by-step construction). It is a service-composition pattern — the builder orchestrates injected formatters through a fixed pipeline.

---

## Decision 6: UTF-8 Byte Arrays (Not Temp Files)

**Decision:** All intermediate content is held as `byte[]` in memory, with no temporary file writes.

**Rationale:** In-memory byte arrays prevent partial-write artifacts and cleanup failures — the operation is atomic, either the complete ZIP byte array is returned or nothing is persisted.

**Trade-off:** Memory usage scales with content size. For very large log files, this could pressure the Large Object Heap. Streaming to disk could reduce memory pressure, but it would complicate the current in-memory all-or-nothing build model.

---

## Decision 7: Lowercase Hex Encoding

**Decision:** Both SHA-256 hashes and HMAC output are encoded as lowercase hex strings.

**Rationale:** Lowercase hex encoding matches `sha256sum`, `hashlib.sha256().hexdigest()`, and many forensic verification tools produce lowercase by default — ensuring compatibility with standard verification tooling without case conversion.

---

## Decision 8: Timestamp Normalization (UTC + ZIP-Range Clamping)

**Decision:** All timestamps are converted to UTC and clamped to the ZIP-valid range (1980-01-01 through 2107-12-31 23:59:58).

**Rationale:** Timestamp normalization prevents the ZIP format's limited date range from causing runtime exceptions — `DateTime` values outside that range cause `ArgumentOutOfRangeException` — ensuring the pipeline never crashes on edge-case timestamps while producing consistent, UTC-based results across time zones.

| DateTimeKind | Treatment |
|-------------|-----------|
| `Utc` | Used directly |
| `Local` | Converted via `ToUniversalTime()` |
| `Unspecified` | Treated as UTC |

**Timestamp source priority:** When no explicit `analysisTimestampUtc` parameter is provided, the builder selects the timestamp from the `AnalysisResult` using a fallback chain: `TimeRangeEnd` → `TimeRangeStart` → `DateTime.UnixEpoch` (1970-01-01, which clamps to the ZIP minimum 1980-01-01). This ensures every package has a valid timestamp even when the source log has no parseable time range.

---

## Decision 9: Indented JSON (Not Minified)

**Decision:** `JsonSerializerOptions.WriteIndented = true` for manifest serialization.

**Rationale:** Indented JSON enables evidence archives to be inspected by humans during legal review or compliance audit — the manifest is readable without a formatting tool, and the size overhead is negligible relative to the content files.

---

## Decision 10: Cooperative Cancellation

**Decision:** The `Build` method checks `CancellationToken` between major stages and inside the per-file hashing and ZIP-writing loops, allowing callers to cancel a long-running build at multiple points.

**Rationale:** Cancellation support in the pipeline enables evidence packages for very large logs to be cancelled — keeping the UI responsive and giving users control over long-running exports.

---

## Summary

| Decision | Security Principle | Operational Impact |
|----------|-------------------|-------------------|
| Two-layer crypto | Defense in depth | File + manifest integrity |
| External manifest | Machine-readable transparency | JSON-parseable by any tool |
| Complete package structure | Completeness guarantee | Six fixed files, auditable |
| Alphabetical order (content files) | Determinism | Reproducible builds |
| Constructor injection | Testability and isolated responsibilities | Explicit dependencies; new formats require builder changes |
| In-memory byte arrays | Atomic operations | No partial-write artifacts |
| Lowercase hex | Tooling compatibility | Works with standard verification tools |
| Timestamp normalization | Defensive programming | Never crashes on edge-case dates |
| Indented JSON | Human readability | Legal and compliance review friendly |
| Cooperative cancellation | Responsive UX | Long-running exports can be cancelled |
