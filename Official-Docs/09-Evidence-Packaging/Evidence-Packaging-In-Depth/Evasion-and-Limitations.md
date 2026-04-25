# Evasion and Limitations

Gaps, blind spots, and improvement paths for the evidence packaging pipeline.

---

## Known Limitations

| Limitation | Impact | Compensating Control |
|-----------|--------|---------------------|
| **HMAC does not prove identity** | Anyone with the signing key can produce a valid archive | Key management: store in HSM or vault; pair with audit logs |
| **Pre-export tampering undetectable** | If raw logs were modified before loading, the pipeline hashes the modified version | Log source authentication (syslog TLS, agent attestation) |
| **Key compromise voids integrity** | If the signing key is leaked, an attacker can forge valid archives | Key rotation, access logging, HSM-backed keys |
| **ZIP format limitations** | ZIP timestamps are 2-second resolution (ZIP format specification), range 1980-01-01 to 2107-12-31 23:59:58 | Timestamp normalization with clamping; `manifest.json` stores full-resolution UTC |
| **In-memory processing** | Large logs consume proportionally large memory | Streaming architecture for datasets exceeding available memory |
| **No encryption at rest** | ZIP contents are readable by anyone with file access | Pre-encryption by the caller; future AES-256 ZIP extension |

---

## Evasion Scenarios

### Pre-Export Log Tampering

```text
Attacker modifies raw logs before VulcansTrace loads them.
VulcansTrace hashes the modified logs → hashes are valid but contents are wrong.
```

**Why it works:** The pipeline's integrity scope starts at export time. It cannot verify that the input log was not tampered with before loading.

**Mitigation:** Log source authentication — TLS-protected syslog, agent attestation, write-once storage. The pipeline provides export integrity; upstream systems provide collection integrity.

### Signing Key Compromise

```text
Attacker obtains the signing key.
Rebuilds the entire archive with modified findings.
HMAC validates because the key is correct.
```

**Why it works:** HMAC verifies that the manifest matches a shared key, not *which* key holder produced it. A compromised key cannot be distinguished from a legitimate one.

**Mitigation:** Key management hygiene — store in a vault (Azure Key Vault, AWS KMS), rotate after each export, log key usage. For environments requiring identity proof, upgrade to certificate-backed digital signatures (RSA-PSS, ECDSA).

### Manifest + File Replacement

```text
Attacker replaces both manifest.json and manifest.hmac with their own versions.
Without the key: HMAC mismatch → detected.
With the key: HMAC matches → undetected by cryptography alone.
```

**Why it works:** Cryptographic verification can only confirm key possession, not intent. An insider with the key can produce a fully valid fraudulent archive.

**Mitigation:** Procedural controls — handoff logs, timestamp reconciliation, dual-key ceremonies, independent archive witnesses.

### ZIP Timestamp Manipulation

```text
Attacker changes ZIP entry timestamps using a ZIP editor.
manifest.json still shows the original createdUtc.
```

**Why it works:** ZIP entry timestamps are external to the cryptographic model. They are not hashed or signed.

**Mitigation:** The `manifest.json` `createdUtc` field is the authoritative timestamp, stored inside the HMAC-signed manifest. ZIP timestamps are cosmetic; the manifest timestamp is the forensic record.

---

## Cloud-Scale Considerations

| Challenge | Impact | Mitigation |
|-----------|--------|-----------|
| Large log volumes (GB+) | In-memory processing does not scale | Streaming architecture, chunked processing |
| Concurrent export requests | Memory contention | Per-request isolation, back-pressure |
| Key management at scale | Key distribution to verifiers | KMS integration, key-per-team isolation |
| Data residency requirements | ZIP must stay in compliant region | Region-locked export endpoints |
| Long-term archive integrity | Key loss prevents future verification | Escrow keys, multi-party key storage |

---

## Performance Limitations

| Scenario | Bottleneck | Current Handling |
|----------|-----------|-----------------|
| Very large logs (>500 MB, illustrative threshold) | MemoryStream can roughly double memory usage in the worst case | Current implementation may need caller-side guardrails or a future streaming path |
| Many thousands of findings | CSV/HTML formatting is O(f) | Linear — scales with finding count |
| Repeated exports | Full pipeline runs each time | No incremental/delta support |

---

## Improvement Roadmap

```text
Phase 1: AES-256 ZIP encryption          → Protect contents at rest            (planned, not yet implemented)
Phase 2: Streaming ZIP creation           → Reduce memory for large datasets   (planned, not yet implemented)
Phase 3: Certificate-backed signatures    → Establish signer identity, not just key possession (planned, not yet implemented)
Phase 4: Key rotation and escrow          → Long-term verification capability  (planned, not yet implemented)
Phase 5: Parallel hashing                 → Multi-core SHA-256 for large files (planned, not yet implemented)
```

---

## Why Limitations Matter

Every cryptographic system has boundaries. A security tool that claims to prove things it cannot prove is more dangerous than one that is clear about its scope. HMAC verifies key possession and manifest integrity; it does not establish who produced the archive. That distinction matters in legal contexts, and the distinction should be documented explicitly.

---

## Security Takeaways

1. **Integrity scope starts at export** — pre-export tampering requires upstream controls
2. **HMAC verifies key possession, not identity** — identity requires certificates
3. **Key management is the hard problem** — cryptography is the easy part
4. **ZIP timestamps are cosmetic** — the manifest's `createdUtc` is the forensic record
5. **Memory vs. atomicity is a real trade-off** — streaming could reduce memory pressure but would complicate the current all-or-nothing in-memory model

