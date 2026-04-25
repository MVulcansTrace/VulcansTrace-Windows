# Evidence Packaging

This folder contains technical documentation for the evidence packaging pipeline.

Documentation is organized for two audiences:

- Quick-review readers who need a fast summary of the subsystem and why it matters
- Technical reviewers who want to inspect the algorithm, trade-offs, and implementation details

## Start Here

- [Expertise Snapshot](./Evidence-Packaging-Summary/Expertise-Snapshot.md): 1-page overview for quick review
- [Why This Matters](./Evidence-Packaging-In-Depth/Why-This-Matters.md): business value, security framing, and project context
- [Packaging Algorithm](./Evidence-Packaging-In-Depth/Core-Logic-Breakdown/Packaging-Algorithm.md): the 4-step pipeline and its trade-offs
- [Design Decisions](./Evidence-Packaging-In-Depth/Design-Decisions.md): why key implementation choices were made
- [Code Patterns](./Evidence-Packaging-In-Depth/Code-Patterns.md): repeatable implementation patterns that support testability
- [Attack Scenario](./Evidence-Packaging-In-Depth/Attack-Scenario.md): a worked example showing evidence packaging for a multi-finding investigation
- [Evasion and Limitations](./Evidence-Packaging-In-Depth/Evasion-and-Limitations.md): blind spots and improvement paths
- [Evidence Integrity and Standards](./Evidence-Packaging-In-Depth/Evidence-Integrity-and-Standards.md): post-export integrity, evidence handoff, and standards context

## System Capabilities

- Cryptographic integrity engineering: SHA-256 per-file hashing plus HMAC-SHA256 manifest signing in a two-layer model
- Security-first output design: CSV injection prevention, XSS encoding, Markdown escaping, and bundle-metadata timestamp normalization
- Multi-audience reporting: three generated report formats (CSV, HTML, Markdown) plus raw log preservation from a single analysis result
- Deterministic builds: the current implementation produces byte-for-byte identical ZIP archives when the analysis result, raw log, signing key, and timestamp are the same
- Trade-off awareness: documents what HMAC verifies and what it does not, what timestamps survive, and what the ZIP format cannot do

## Implementation Evidence

- [EvidenceBuilder.cs](../../VulcansTrace.Evidence/EvidenceBuilder.cs): 4-step packaging pipeline, manifest construction, HMAC signing, ZIP creation
- [CsvFormatter.cs](../../VulcansTrace.Evidence/Formatters/CsvFormatter.cs): spreadsheet-friendly CSV export with formula injection protection and optional warnings tail section
- [HtmlFormatter.cs](../../VulcansTrace.Evidence/Formatters/HtmlFormatter.cs): dark-themed HTML report with XSS encoding
- [MarkdownFormatter.cs](../../VulcansTrace.Evidence/Formatters/MarkdownFormatter.cs): GitHub-flavored Markdown with special character escaping
- [IntegrityHasher.cs](../../VulcansTrace.Core/Security/IntegrityHasher.cs): SHA-256 and HMAC-SHA256 cryptographic primitives
- [AnalysisResult.cs](../../VulcansTrace.Core/AnalysisResult.cs): domain model consumed by the pipeline
- [EvidenceBuilderTests.cs](../../VulcansTrace.Tests/Evidence/EvidenceBuilderTests.cs): 21 tests — ZIP structure, HMAC, determinism, timestamps, cancellation
- [CsvFormatterTests.cs](../../VulcansTrace.Tests/Evidence/CsvFormatterTests.cs): 10 test methods (13 expanded tests) — escaping, quoting, formula injection
- [HtmlFormatterTests.cs](../../VulcansTrace.Tests/Evidence/HtmlFormatterTests.cs): 5 tests — HTML encoding, warnings, parse errors
- [MarkdownFormatterTests.cs](../../VulcansTrace.Tests/Evidence/MarkdownFormatterTests.cs): 5 tests — escaping, structure, warnings
- [IntegrityHasherTests.cs](../../VulcansTrace.Tests/Core/IntegrityHasherTests.cs): 9 tests — SHA-256 and HMAC-SHA256 correctness, determinism, key sensitivity

