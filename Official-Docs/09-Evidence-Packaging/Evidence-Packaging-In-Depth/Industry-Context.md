# Industry Context

## The Security Problem

When a security analysis is complete, the results may need to be shared with other analysts, management, legal counsel, or external parties. If the evidence can be modified after export without detection, its value in incident response, compliance review, or legal proceedings is undermined.

Evidence integrity packaging ensures that exported artifacts can be verified as unchanged after they leave the analysis tool. This is a foundational requirement in digital forensics and incident response.

## Enterprise Approaches

Enterprise forensic and IR tools may implement evidence integrity through cryptographic hashing, digital signatures, and chain-of-custody tracking. Examples of tools and standards in this space include:

- **Disk forensics tools** (EnCase Forensic, Magnet AXIOM, FTK) create forensic images with built-in hash verification (MD5, SHA-1, SHA-256) to prove the image matches the source media. These tools are designed for court admissibility and legal defensibility.

- **Enterprise IR platforms** may produce time-stamped, hash-verified investigation packages that preserve analyst findings alongside raw evidence for handoff between teams or to external parties.

- **Standards frameworks** provide the legal and procedural context:
  - NIST SP 800-61 (Incident Handling) defines evidence preservation requirements
  - NIST SP 800-86 (Integrating Forensic Techniques into Incident Response) addresses forensic soundness
  - FRE 901 (Authentication) requires evidence to be authenticated before admission
  - FRE 1002 (Best Evidence) governs the use of duplicates and originals

## How VulcansTrace Approaches This

VulcansTrace packages analysis results into a ZIP archive with layered integrity protection:

1. **SHA-256 per file** -- every file in the archive is hashed before packaging
2. **Manifest aggregation** -- a JSON manifest records each file's SHA-256 hash and byte length
3. **HMAC-SHA256 manifest signature** -- the manifest is signed with an ephemeral key, and the signature is stored alongside the manifest
4. **Deterministic builds** -- same input + same timestamp produces identical output bytes
5. **Output hardening** -- CSV prevents formula injection, HTML uses XSS encoding, Markdown escapes special characters

This layered approach means any post-export modification to any file can be detected by re-computing the SHA-256 and comparing against the manifest, and any manifest tampering can be detected by re-computing the HMAC.

## Key Differences

| Dimension | VulcansTrace | Enterprise forensic tools |
|---|---|---|
| Scope | Analysis results from a single tool | Full disk images, memory captures, mobile extractions, cloud snapshots |
| Key management | Ephemeral per-export key (not stored) | May integrate with HSMs, key vaults, or sealed evidence procedures |
| Legal standing | Self-contained integrity proof; not court-validated | Court-tested, chain-of-custody workflows, examiner testimony support |
| Data types | Log analysis findings in text formats | Disk sectors, memory pages, mobile filesystems, cloud audit trails |
| Verification | Re-compute SHA-256 and HMAC manually or programmatically | Built-in verification UI, automated validation, audit logging |

## What This Means For Reviewers

This component demonstrates understanding of:

- Why evidence integrity matters beyond the analysis itself
- Layered cryptographic protection (hash per file + HMAC on manifest)
- The difference between integrity proof and identity proof (HMAC proves the manifest is unchanged, not who signed it)
- Output format security (formula injection, XSS, Markdown injection)
- Honest scoping (source log tampering before loading is not in scope; key management is the operator's responsibility)

The concept overlaps with how enterprise forensic tools handle evidence packaging. Enterprise tools operate at greater scale, with richer data types, integrated key management, and court-tested workflows. VulcansTrace implements the foundational integrity logic that those systems build on, aligned with NIST SP 800-61, NIST SP 800-86, and FRE 901/1002 requirements.
