# Why This Matters

---

## The Security Problem

Security analysis results can become evidence. When an incident escalates to legal review or compliance audit, the analysis output needs strong post-export integrity controls. Without cryptographic protection:

- Anyone with file access can modify findings and claim the original was wrong
- There is no way to prove the archive contents match what the tool produced
- Opposing counsel can challenge the authenticity of every finding
- There is no machine-readable way to verify integrity without the original tool

| Risk | Without Evidence Packaging | With This Pipeline |
|------|---------------------------|-------------------|
| Findings modified post-export | No detection | SHA-256 hash mismatch on any file |
| Manifest tampered with | No detection | HMAC-SHA256 signature invalid |
| Inconsistent bundle metadata timestamps | Easy to misread across systems | UTC normalization with ZIP-range clamping for `createdUtc` and ZIP entry times |
| Multi-audience distribution | Manual format conversion | 3 generated views plus raw log packaged together |

---

## Implementation Overview

The **evidence packaging engine** in VulcansTrace produces cryptographically signed, tamper-evident ZIP archives containing multi-format analysis output:

The pipeline:

1. **Generates three formatted reports** via pluggable formatters — CSV for spreadsheets, HTML for browsers, Markdown for GitHub — and bundles the original raw log alongside them
2. **Computes SHA-256 hashes** for each file to create per-file integrity fingerprints
3. **Builds a JSON manifest** that inventories every file with its hash, size, and all analysis warnings
4. **Signs the manifest with HMAC-SHA256** and creates the final ZIP archive

The result is a 6-entry ZIP (findings.csv, log.txt, report.html, summary.md, manifest.json, manifest.hmac) that is deterministic, cryptographically signed, and verifiable by anyone with the signing key.

**Key metrics:**

- 4 output files from a single build operation — 3 formatted views from `AnalysisResult` plus the original raw log
- 2-layer cryptographic model: SHA-256 per file + HMAC-SHA256 over the manifest
- 4 output-security protections: CSV injection, XSS, Markdown escaping, bundle-metadata timestamp normalization
- Deterministic builds: same analysis result, raw log, signing key, and timestamp produce byte-for-byte identical ZIPs in the current implementation and test suite
- 50 test methods across 5 test files covering the full pipeline

---

## Operational Benefits

| Capability | Business Value |
|-----------|----------------|
| Cryptographic integrity | Supports integrity-sensitive legal and compliance workflows when paired with key management and handoff controls |
| Multi-format output | Analysts, managers, and auditors each get their preferred view |
| Deterministic builds | Reproducible output enables independent verification |
| Output security | CSV injection and XSS protections defend analyst workstations |
| Warning preservation | Analysts see analysis limitations, not just findings |

---

## Security Principles Applied

| Principle | Where It Appears |
|-----------|-----------------|
| **Cryptographic integrity** | SHA-256 per file + HMAC-SHA256 over the manifest |
| **Defense in depth (two-layer model)** | File hashes catch modification; HMAC catches manifest tampering |
| **Output security** | CSV injection, XSS, Markdown escaping, and bundle-metadata timestamp normalization |
| **Deterministic builds** | Alphabetical file ordering, normalized timestamps, indented JSON |
| **Transparency** | Warnings preserved inside the archive for reviewer awareness |
| **Explicit scope** | HMAC proves keyed manifest verification, not signer identity — documented explicitly |

---

## Implementation Evidence

- [EvidenceBuilder.cs](../../../VulcansTrace.Evidence/EvidenceBuilder.cs): 4-step pipeline, manifest construction, HMAC signing, ZIP creation (205 lines)
- [CsvFormatter.cs](../../../VulcansTrace.Evidence/Formatters/CsvFormatter.cs): spreadsheet-friendly CSV findings export with formula injection protection and optional warnings tail section (75 lines)
- [HtmlFormatter.cs](../../../VulcansTrace.Evidence/Formatters/HtmlFormatter.cs): XSS-safe HTML report (88 lines)
- [MarkdownFormatter.cs](../../../VulcansTrace.Evidence/Formatters/MarkdownFormatter.cs): escaped GFM output (92 lines)
- [IntegrityHasher.cs](../../../VulcansTrace.Core/Security/IntegrityHasher.cs): SHA-256 and HMAC-SHA256 primitives (35 lines)
- [EvidenceBuilderTests.cs](../../../VulcansTrace.Tests/Evidence/EvidenceBuilderTests.cs): 21 tests — ZIP structure, HMAC, determinism, timestamps, cancellation
- [CsvFormatterTests.cs](../../../VulcansTrace.Tests/Evidence/CsvFormatterTests.cs): 10 tests — escaping, quoting, formula injection
- [HtmlFormatterTests.cs](../../../VulcansTrace.Tests/Evidence/HtmlFormatterTests.cs): 5 tests — HTML encoding, warnings, parse errors
- [MarkdownFormatterTests.cs](../../../VulcansTrace.Tests/Evidence/MarkdownFormatterTests.cs): 5 tests — escaping, structure, warnings
- [IntegrityHasherTests.cs](../../../VulcansTrace.Tests/Core/IntegrityHasherTests.cs): 9 tests — SHA-256 and HMAC-SHA256 correctness, determinism, key sensitivity

---

## Elevator Pitch

> *"The evidence packaging pipeline transforms analysis results into a tamper-evident ZIP archive that supports integrity-sensitive legal and compliance workflows when paired with operational controls.*
>
> *The pipeline has four steps. First, it generates three formatted report views — CSV, HTML, and Markdown — from the analysis results, and bundles the original raw log alongside them, because different audiences need different views of the same findings. Each formatter applies output security: the CSV formatter prevents formula injection, the HTML formatter encodes against XSS, and the Markdown formatter escapes special characters. Separately, the builder normalizes bundle metadata timestamps to UTC and clamps them to the ZIP-valid range; human-readable report timestamps preserve the values already present in `AnalysisResult`.*
>
> *Second, it computes SHA-256 hashes for every file in alphabetical order. Third, it builds a JSON manifest that records each file's hash and size, plus any warnings the analysis produced. Fourth, it signs the manifest with HMAC-SHA256 and writes everything into a ZIP archive.*
>
> *The result is a two-layer cryptographic model: SHA-256 catches any modification to individual files, and HMAC catches any tampering with the manifest that records those hashes. The current implementation is deterministic in the tested configuration — when the same analysis result, raw log, signing key, and timestamp are used, it produces byte-for-byte identical output."*

---

## Security Takeaways

1. **Evidence packaging is a post-export integrity problem** — the output needs tamper-evident handoff controls once analysis is complete
2. **Two-layer cryptography provides defense in depth** — file hashes plus manifest signing means two independent failure detectors
3. **Output formats are an attack surface** — CSV injection and XSS are real second-order attacks against analyst workstations
4. **Tested deterministic builds aid independent verification** — reproducible output is easier to compare when the same inputs are available
5. **Explicit scope is critical** — HMAC proves the manifest was signed, not who signed it; that distinction matters in legal contexts

