# Packaging Algorithm

---

## The Security Problem

When a security analysis tool produces findings, those findings can become evidence. Without cryptographic protection, there is no easy way to show the output has not been modified since the tool generated it. Without multiple formats, different audiences must manually convert results. Without reproducible builds, byte-for-byte comparison across exports is harder to reason about.

The pipeline must:

- Generate reports in formats that serve analysts, managers, developers, and automated systems simultaneously
- Protect every file with a cryptographic fingerprint
- Produce a signed manifest that proves the entire package is intact
- Produce byte-for-byte identical output given identical input and timestamp

---

## Implementation Overview

A 4-step packaging pipeline implemented in [EvidenceBuilder.cs](../../../../VulcansTrace.Evidence/EvidenceBuilder.cs):

```text
AnalysisResult + Raw Log + Signing Key + Timestamp
    |
    v
Step A: Generate Reports -------- Why: 3 generated formats + raw log, multi-audience, output-secured
    |
    v
Step B: Compute Hashes ---------- Why: Per-file SHA-256 integrity fingerprints
    |
    v
Step C: Build Manifest ---------- Why: Machine-readable inventory with HMAC signature
    |
    v
Step D: Create ZIP -------------- Why: Portable, compressed, tamper-evident archive
    |
    v
byte[] (6-entry ZIP archive)
```

---

## Step A: Multi-Format Generation

**Process:** The builder transforms the `AnalysisResult` into four byte-array representations via three pluggable formatters plus raw log preservation.

| File | Source | Format | Audience |
|------|--------|--------|----------|
| `findings.csv` | `CsvFormatter.ToCsv(result)` | Spreadsheet-friendly CSV findings table with optional warnings tail section | Analysts, spreadsheets, manual review |
| `report.html` | `HtmlFormatter.ToHtml(result)` | Standalone HTML with dark CSS | Managers, browsers, email |
| `summary.md` | `MarkdownFormatter.ToMarkdown(result)` | GitHub-flavored Markdown | Developers, GitHub, documentation |
| `log.txt` | Raw log string as-provided | Plain text | Raw evidence, audit trail |

**Rationale:** Four simultaneous output formats serve each audience consumes evidence differently — analysts need structured CSV for filtering, managers need visual HTML for skimming, developers need Markdown for documentation, and everyone needs the raw log for independent verification, for the purpose of eliminating manual format conversion from the evidence workflow.

**Output security applied during generation:**

| Attack Vector | Protection | Where |
|---------------|-----------|-------|
| CSV formula injection | Prefix `=`, `+`, `-`, `@` with `'` | CsvFormatter |
| XSS via HTML | `WebUtility.HtmlEncode()` on 4 finding fields + warning text | HtmlFormatter |
| Markdown table corruption | Backslash-escape `\`, `|`, `*`, `_`, `` ` ``, `[`, `]` | MarkdownFormatter |
| Bundle timestamp crash/misread | UTC normalization + ZIP-range clamping for `createdUtc` and ZIP entry times | EvidenceBuilder |

**Byte array storage:** All four content entries are held as `byte[]` in a case-insensitive dictionary (`StringComparer.OrdinalIgnoreCase`) before hashing and ZIP creation. Byte arrays were chosen over temp files because the builder assembles the complete archive in memory before returning it, for the purpose of keeping the export path self-contained.

---

## Step B: Integrity Hashing

**Process:** The builder computes SHA-256 for each of the four content files in alphabetical order, collecting hash, filename, and byte length into manifest entries.

```text
For each file in alphabetical order (findings.csv, log.txt, report.html, summary.md):
    sha256 = IntegrityHasher.ComputeSha256(fileBytes)
    entry  = { file: name, sha256: hexString, length: bytes.Length }
```

**Rationale:** Per-file SHA-256 hashing enables each file in the archive needs an independent integrity fingerprint, for the purpose of enabling verifiers to detect which specific file was modified without re-verifying the entire archive.

**Alphabetical processing order:** Files are hashed in sorted order because the manifest entries appear in a predictable sequence, for the purpose of making the manifest deterministic — same files always produce same manifest JSON.

**Hex encoding:** Hashes are stored as lowercase hex strings because lowercase hex is conventional in many verification tools, for the purpose of keeping the manifest easy to compare with standard SHA-256 outputs such as `sha256sum` and Python `hashlib`.

**SHA-256 properties that matter:**

| Property | Why It Matters For Evidence |
|----------|---------------------------|
| 256-bit output | Computationally infeasible to find collisions |
| Avalanche effect | Changing 1 bit changes ~50% of the output |
| Deterministic | Same bytes always produce same hash |
| One-way | Cannot recover the original from the hash |

---

## Step C: Manifest Construction

**Process:** The builder constructs a JSON manifest containing the UTC creation timestamp, the file inventory with hashes, and all analysis warnings. Then the builder signs the manifest bytes with HMAC-SHA256.

```json
{
  "createdUtc": "2024-01-15T12:30:00Z",
  "files": [
    { "file": "findings.csv", "sha256": "a1b2c3...", "length": 2048 },
    { "file": "log.txt",      "sha256": "d4e5f6...", "length": 5120 },
    { "file": "report.html",  "sha256": "g7h8i9...", "length": 4096 },
    { "file": "summary.md",   "sha256": "j0k1l2...", "length": 1024 }
  ],
  "warnings": [
    "MaxEntriesPerSource exceeded for 192.168.1.100"
  ]
}
```

**Manifest structure:**

| Field | Purpose |
|-------|---------|
| `createdUtc` | Temporal anchor — when the package was built |
| `files[].file` | Filename for cross-reference |
| `files[].sha256` | Integrity fingerprint for that file |
| `files[].length` | Byte count for size verification |
| `warnings[]` | Pipeline transparency — what limitations applied |

**Rationale:** A separate JSON manifest file provides independence because ZIP comments are easily modified without detection, for the purpose of making the inventory independently verifiable and machine-readable by any JSON parser.

**HMAC-SHA256 signing:** After serializing the manifest to indented JSON with UTF-8 encoding, the pipeline computes `HMAC-SHA256(manifestBytes, signingKey)` and writes the result as `manifest.hmac` — a lowercase hex string file. This second layer ensures an attacker who modifies a finding file could also update the manifest's corresponding hash, for the purpose of requiring the signing key to produce a valid manifest — hash-only modifications are caught by the HMAC.

**Indented JSON:** Indented output (`JsonSerializerOptions.WriteIndented = true`) was chosen over minified JSON because evidence archives may be inspected by humans during legal review, for the purpose of making the manifest readable without a formatting tool.

---

## Step D: ZIP Archive Creation

**Process:** The builder writes all six entries (four content files, manifest.json, manifest.hmac) into a `MemoryStream`-backed `ZipArchive` with optimal compression and normalized timestamps.

```text
MemoryStream → ZipArchive (CompressionLevel.Optimal)
    Add: findings.csv    (content, normalized timestamp)
    Add: log.txt         (content, normalized timestamp)
    Add: report.html     (content, normalized timestamp)
    Add: summary.md      (content, normalized timestamp)
    Add: manifest.json   (manifest bytes, normalized timestamp)
    Add: manifest.hmac   (hmac hex, normalized timestamp)
    → ToArray() → byte[]
```

**Rationale:** ZIP creation around a `MemoryStream` ensures the builder should return either a complete ZIP byte array or an exception, for the purpose of keeping the packaging operation all-or-nothing within the builder itself.

**Timestamp normalization:** Bundle metadata timestamps are normalized before writing. This applies to `manifest.json` `createdUtc` and ZIP entry `LastWriteTime` values, not to the report timestamps already stored in `AnalysisResult`. The algorithm:

1. Use the caller-provided `analysisTimestampUtc` if supplied
2. Otherwise fall back to `result.TimeRangeEnd`
3. Otherwise fall back to `result.TimeRangeStart`
4. Otherwise fall back to `DateTime.UnixEpoch`
5. Convert to UTC (`Kind.Local` → `ToUniversalTime()`, `Kind.Unspecified` → treat as UTC)
6. Clamp to ZIP valid range: 1980-01-01 through 2107-12-31 23:59:58

Timestamp normalization ensures the ZIP format only supports dates from 1980 to 2107, and `DateTime` values outside that range cause `ArgumentOutOfRangeException`, for the purpose of ensuring the pipeline never crashes on edge-case bundle timestamps while still producing consistent, UTC-based ZIP metadata.

**Compression:** `CompressionLevel.Optimal` is used for all entries. Optimal was chosen over fastest because evidence archives are typically built once and stored long-term, for the purpose of minimizing storage and transfer costs at the cost of slightly longer build time.

---

## Complexity Analysis

| Metric | Value | Why |
|--------|-------|-----|
| **Time (formatting)** | O(f) where f = finding count | Linear pass over findings per formatter |
| **Time (hashing)** | O(n) where n = total bytes | SHA-256 processes each byte once |
| **Time (manifest)** | O(w) where w = warning count | Fixed file count; warnings serialized linearly |
| **Time (ZIP creation)** | O(n) | Compression processes each byte once |
| **Space** | O(n) | All content held in memory as byte arrays |
| **Overall** | O(n) time, O(n) space | Dominated by content size, not finding count |

---

## Determinism

The pipeline is deterministic because evidence verification benefits from reproducible output. In the current implementation and test suite, if two parties build from the same `AnalysisResult`, raw log, signing key, and timestamp, they get byte-for-byte identical ZIP archives.

Determinism is ensured by:

| Factor | How It Is Controlled |
|--------|---------------------|
| File order | Alphabetical sorting of content dictionary |
| Hash order | Alphabetical processing |
| JSON formatting | Indented, consistent serialization |
| Timestamps | Normalized to UTC, clamped to ZIP range |
| Compression | Current .NET ZIP implementation under fixed inputs, as verified by tests |

Tested explicitly: `Build_WithSameInputAndTimestamp_IsDeterministic` asserts byte-array equality.

---

## Implementation Evidence

- [EvidenceBuilder.cs](../../../../VulcansTrace.Evidence/EvidenceBuilder.cs): 4-step pipeline, manifest construction, HMAC signing, ZIP creation (205 lines)
- [CsvFormatter.cs](../../../../VulcansTrace.Evidence/Formatters/CsvFormatter.cs): spreadsheet-friendly CSV findings export with formula injection protection and optional warnings tail section (75 lines)
- [HtmlFormatter.cs](../../../../VulcansTrace.Evidence/Formatters/HtmlFormatter.cs): XSS-safe HTML report (88 lines)
- [MarkdownFormatter.cs](../../../../VulcansTrace.Evidence/Formatters/MarkdownFormatter.cs): escaped GFM output (92 lines)
- [IntegrityHasher.cs](../../../../VulcansTrace.Core/Security/IntegrityHasher.cs): SHA-256 and HMAC-SHA256 primitives (35 lines)
- [EvidenceBuilderTests.cs](../../../../VulcansTrace.Tests/Evidence/EvidenceBuilderTests.cs): 21 tests covering ZIP structure, HMAC validity, determinism, timestamp edge cases, cancellation

---

## Operational Impact

- Enables cryptographically verifiable evidence export — SHA-256 file hashes and HMAC-SHA256 manifest signing protect the package from post-export modification
- Supports multi-audience reporting from a single analysis run — CSV for analysts, HTML for managers, Markdown for developers, raw log for independent verification
- Provides deterministic builds so byte-for-byte identical output given identical input supports independent verification and comparison

---

## Security Takeaways

1. **Two-layer cryptography provides defense in depth** — file hashes and manifest signing are independent failure detectors
2. **Output formats are attack surfaces** — CSV injection and XSS target the analyst's workstation, not the tool
3. **Determinism supports verification** — reproducible builds make independent comparison and validation easier when the same inputs are available
4. **Timestamp normalization prevents crashes** — edge-case dates are clamped, not rejected
5. **Warning preservation is transparency** — reviewers can see what limitations applied during analysis
