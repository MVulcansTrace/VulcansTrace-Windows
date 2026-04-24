# Quick Reference

---

## Packaging Pipeline (4 Steps)

Step A: Generate Reports — 3 formats via pluggable formatters + raw log
Step B: Compute Hashes — SHA-256 per file in alphabetical order
Step C: Build Manifest — JSON inventory + HMAC-SHA256 signature
Step D: Create ZIP — MemoryStream-backed, optimal compression

---

## ZIP Archive Contents

| Entry | Source | Purpose |
|-------|--------|---------|
| `findings.csv` | CsvFormatter | Spreadsheet-friendly CSV findings export with optional warnings section |
| `log.txt` | Raw log input | Raw log snapshot as provided to the builder |
| `report.html` | HtmlFormatter | Styled report for managers and browsers |
| `summary.md` | MarkdownFormatter | GFM for developers and GitHub |
| `manifest.json` | Builder | File inventory with hashes + warnings |
| `manifest.hmac` | Builder | HMAC-SHA256 hex signature of manifest |

---

## Two-Layer Cryptographic Model

| Layer | Algorithm | Protects | Requires To Verify |
|-------|-----------|----------|-------------------|
| File integrity | SHA-256 | Individual file modification | File bytes only |
| Keyed manifest verification | HMAC-SHA256 | Manifest tampering | Signing key |

---

## Output Security Protections

| Protection | Threat | Mechanism |
|-----------|--------|-----------|
| CSV injection | `=`, `+`, `-`, `@` formula execution | Prefix with `'` |
| XSS | Script injection in HTML | `WebUtility.HtmlEncode()` |
| Markdown corruption | Table/format breakage | Backslash-escape 7 special chars |
| Bundle timestamp crash | Out-of-range DateTime | Clamp ZIP/manifest timestamp to 1980-01-01 – 2107-12-31 23:59:58 |

---

## Manifest Structure

```json
{
  "createdUtc": "ISO 8601 UTC",
  "files": [
    { "file": "name", "sha256": "hex", "length": N }
  ],
  "warnings": [ "string" ]
}
```

---

## Timestamp Normalization

| DateTimeKind | Treatment |
|-------------|-----------|
| `Utc` | Used directly |
| `Local` | `ToUniversalTime()` |
| `Unspecified` | Treated as UTC |
| Out of range | Clamped to ZIP bounds (1980-01-01 – 2107-12-31 23:59:58) |

---

## Complexity

| Metric | Value |
|--------|-------|
| Time (formatting) | O(f) — linear in finding count |
| Time (hashing) | O(n) — linear in total bytes |
| Time (ZIP) | O(n) — linear in total bytes |
| Space | O(n) — all content in memory |
| Overall | O(n) time, O(n) space |

---

## Determinism Guarantees

| Factor | Control |
|--------|---------|
| File order | Alphabetical (`StringComparer.OrdinalIgnoreCase`) |
| Hash order | Alphabetical |
| JSON format | Indented, consistent serialization |
| Timestamps | UTC-normalized, ZIP-clamped |
| Compression | Current .NET ZIP implementation under fixed inputs, as verified by tests |

---

## Test Coverage

| Test File | Count | Covers |
|-----------|-------|--------|
| EvidenceBuilderTests | 21 | ZIP structure, HMAC, determinism, timestamps, cancellation |
| CsvFormatterTests | 10 | Quoting/escaping, formula injection, dates, warnings |
| HtmlFormatterTests | 5 | HTML encoding, warnings, parse errors |
| MarkdownFormatterTests | 5 | Escaping, structure, warnings |
| IntegrityHasherTests | 9 | SHA-256 correctness, HMAC correctness, determinism, key sensitivity |

---

## File References

| File | Purpose |
|------|---------|
| EvidenceBuilder.cs | Pipeline orchestrator (205 lines) |
| CsvFormatter.cs | CSV output (75 lines) |
| HtmlFormatter.cs | HTML output (88 lines) |
| MarkdownFormatter.cs | Markdown output (92 lines) |
| IntegrityHasher.cs | SHA-256 + HMAC primitives (35 lines) |
| AnalysisResult.cs | Domain model consumed by pipeline |
| EvidenceViewModel.cs | WPF export UX (key gen, save, clipboard) |
