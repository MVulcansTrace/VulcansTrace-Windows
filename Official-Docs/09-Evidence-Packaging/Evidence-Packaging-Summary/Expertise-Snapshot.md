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
| Test coverage | Focused tests across 5 files; use `dotnet test --list-tests` for current expanded counts |

---

## Why It Matters

- Produces tamper-evident archives that support integrity-sensitive handoff and audit review
- Three generated formats plus raw log preservation serve multiple audiences without manual conversion
- Deterministic builds enable independent verification
- Scope note: HMAC verifies key possession, not signer identity

---

## Key Evidence

- [EvidenceBuilder.cs](../../../VulcansTrace.Evidence/EvidenceBuilder.cs): 4-step packaging pipeline, manifest construction, HMAC signing, ZIP creation
- [CsvFormatter.cs](../../../VulcansTrace.Evidence/Formatters/CsvFormatter.cs): spreadsheet-friendly CSV export with formula injection protection and optional warnings tail section
- [HtmlFormatter.cs](../../../VulcansTrace.Evidence/Formatters/HtmlFormatter.cs): XSS-safe HTML report
- [MarkdownFormatter.cs](../../../VulcansTrace.Evidence/Formatters/MarkdownFormatter.cs): escaped GFM output
- [IntegrityHasher.cs](../../../VulcansTrace.Core/Security/IntegrityHasher.cs): SHA-256 and HMAC-SHA256 primitives
- [EvidenceBuilderTests.cs](../../../VulcansTrace.Tests/Evidence/EvidenceBuilderTests.cs): ZIP structure, HMAC, determinism, timestamps, cancellation
- [IntegrityHasherTests.cs](../../../VulcansTrace.Tests/Core/IntegrityHasherTests.cs): SHA-256 and HMAC-SHA256 correctness, determinism, key sensitivity

---

## Key Design Choices

- **Two-layer cryptography** because an attacker who modifies a file would also update its hash in the manifest — HMAC requires the signing key to produce a valid signature, so hash-only manipulation is detected
- **Three generated formats plus raw log archive** because analysts, managers, developers, and auditors all need different views of the same findings
- **Deterministic builds via alphabetical ordering** because evidence verification requires reproducible output
- **Constructor-injected formatters** because each format's escaping rules should be isolated and independently testable

