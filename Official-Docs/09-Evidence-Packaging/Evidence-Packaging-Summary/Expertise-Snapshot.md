# Expertise Snapshot

> **1 page:** the subsystem, why it matters, and where the proof lives in the codebase.

---

## Implementation Overview

A **cryptographic evidence packaging pipeline** for VulcansTrace that transforms analysis results into a tamper-evident, multi-format ZIP archive with a two-layer integrity model — SHA-256 per file plus HMAC-SHA256 manifest signing.

---

## Key Metrics

| Metric | Value |
|--------|-------|
| Output formats | 3 (CSV, HTML, Markdown) + raw log preservation |
| Cryptographic layers | 2 (SHA-256 per file + HMAC-SHA256 over manifest) |
| Output-security protections | 4 (CSV injection, XSS, Markdown escaping, bundle timestamp normalization) |
| ZIP archive entries | 6 (3 reports + raw log + manifest.json + manifest.hmac) |
| Build determinism | Byte-for-byte identical given the same analysis result, raw log, signing key, and timestamp |
| Test coverage | 50 test methods (53 expanded tests) across 5 test files |

---

## Why It Matters

- Produces tamper-evident archives that support integrity-sensitive handoff and audit review
- Three generated formats plus raw log preservation serve multiple audiences without manual conversion
- Deterministic builds enable independent verification
- Scope note: HMAC verifies key possession, not signer identity

---

## Key Evidence

- [EvidenceBuilder.cs](../../../VulcansTrace.Evidence/EvidenceBuilder.cs): 4-step packaging pipeline, manifest construction, HMAC signing, ZIP creation (205 lines)
- [CsvFormatter.cs](../../../VulcansTrace.Evidence/Formatters/CsvFormatter.cs): spreadsheet-friendly CSV export with formula injection protection and optional warnings tail section (75 lines)
- [HtmlFormatter.cs](../../../VulcansTrace.Evidence/Formatters/HtmlFormatter.cs): XSS-safe HTML report (88 lines)
- [MarkdownFormatter.cs](../../../VulcansTrace.Evidence/Formatters/MarkdownFormatter.cs): escaped GFM output (92 lines)
- [IntegrityHasher.cs](../../../VulcansTrace.Core/Security/IntegrityHasher.cs): SHA-256 and HMAC-SHA256 primitives (35 lines)
- [EvidenceBuilderTests.cs](../../../VulcansTrace.Tests/Evidence/EvidenceBuilderTests.cs): 21 tests — ZIP structure, HMAC, determinism, timestamps, cancellation
- [IntegrityHasherTests.cs](../../../VulcansTrace.Tests/Core/IntegrityHasherTests.cs): 9 tests — SHA-256 and HMAC-SHA256 correctness, determinism, key sensitivity

---

## Key Design Choices

- **Two-layer cryptography** because an attacker who modifies a file would also update its hash in the manifest — HMAC requires the signing key to produce a valid signature, so hash-only manipulation is detected
- **Three generated formats plus raw log archive** because analysts, managers, developers, and auditors all need different views of the same findings
- **Deterministic builds via alphabetical ordering** because evidence verification requires reproducible output
- **Constructor-injected formatters** because each format's escaping rules should be isolated and independently testable

