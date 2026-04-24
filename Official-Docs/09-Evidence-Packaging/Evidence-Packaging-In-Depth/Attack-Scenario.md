# Attack Scenario: Chain of Custody in Practice

---

## The Incident

A port scan is detected from `192.168.1.100` against internal infrastructure. The SOC analyst runs VulcansTrace, confirms the finding, and needs to hand the evidence to their manager, who will hand it to legal counsel, who will hand it to external counsel for potential litigation.

---

## Phase 1: Collection

The analyst loads the firewall log into VulcansTrace and runs the analysis. The tool produces an `AnalysisResult` with one Critical-severity Port Scan finding. The analyst clicks Export Evidence.

**What the pipeline produces:**

```text
VulcansTrace_Evidence.zip   ← default filename (analyst saves as evidence-2024-01-15.zip)
├── findings.csv      → 1 finding row with Category, Severity, SourceHost, Target, TimeStart, TimeEnd, ShortDescription
├── log.txt           → Raw firewall log as loaded
├── report.html       → Styled HTML report with summary stats and findings table
├── summary.md        → GFM Markdown with stats, severity counts, findings table
├── manifest.json     → { createdUtc, files[4], warnings[] }
└── manifest.hmac     → HMAC-SHA256 hex string (64 characters)
```

In the current WPF export flow, a new signing key (32 random bytes) is generated for the export and displayed as a masked string. The analyst can click **Copy Signing Key** to copy the hex-encoded key to the clipboard, then store it in the SOC's secure credential manager.

---

## Phase 2: Transfer to SOC Manager

The analyst emails the ZIP to their manager. Before opening, the manager wants to verify the archive has not been tampered with in transit.

**Verification:**

```python
import hmac, hashlib, json

with open("evidence-2024-01-15.zip", "rb") as f:
    zip_bytes = f.read()

# Extract manifest.json and manifest.hmac from ZIP
manifest = extract_from_zip(zip_bytes, "manifest.json")
hmac_hex  = extract_from_zip(zip_bytes, "manifest.hmac").decode().strip()

# Re-compute HMAC with the stored signing key
key = bytes.fromhex("<analyst's stored key>")
expected = hmac.new(key, manifest, hashlib.sha256).hexdigest()

if hmac_hex == expected:
    print("Manifest signature valid — no tampering detected")
else:
    print("ALERT: Manifest signature mismatch")
```

**What the HMAC proves:** The manifest was signed by someone holding the key. If someone modified `manifest.json` in transit, the HMAC would not match.

**What the HMAC does not prove:** That the analyst (and not someone else with the key) signed it. Identity requires a certificate-backed digital signature, which is out of scope.

---

## Phase 3: Transfer to Legal Counsel

The SOC manager needs to confirm that individual files inside the archive match their recorded hashes.

**Verification of a single file:**

```python
import hashlib

csv_content = extract_from_zip(zip_bytes, "findings.csv")
actual_hash = hashlib.sha256(csv_content).hexdigest()

manifest_data = json.loads(manifest)
csv_entry = next(f for f in manifest_data["files"] if f["file"] == "findings.csv")

if actual_hash == csv_entry["sha256"]:
    print(f"findings.csv integrity confirmed ({len(csv_content)} bytes)")
else:
    print("ALERT: findings.csv has been modified")
```

**What the SHA-256 proves:** This specific byte sequence is the same one that was hashed during packaging. Any modification — even a single bit — produces a completely different hash due to the avalanche effect.

---

## Phase 4: Transfer to External Counsel

External counsel receives the ZIP and wants to confirm the complete post-export integrity story:

1. Open `manifest.json` — readable JSON with creation timestamp, file inventory, and warnings
2. Verify each file's SHA-256 independently
3. Verify the manifest's HMAC with the signing key
4. Confirm the creation timestamp is consistent with the incident timeline
5. Review `warnings[]` to understand any analysis limitations

**What they can confirm:**
- Every file in the archive matches its recorded hash
- The manifest was signed with the correct key
- The creation timestamp is consistent
- Any pipeline warnings are transparent

**What they cannot confirm:**
- That the raw log was not tampered with before it was loaded into VulcansTrace
- That the person who exported the archive is who they claim to be
- That the signing key has not been shared or compromised

---

## Phase 5: Tampering Detection Scenarios

### Scenario A: File Modification

An attacker changes the severity in `findings.csv` from Critical to Low.

```text
manifest.json says:  sha256 = "a1b2c3..."
actual file sha256:  "x9y8z7..."  ← MISMATCH
```

**Detection:** SHA-256 mismatch on the findings.csv entry. The manifest signature is still valid because the manifest was not modified.

### Scenario B: Manifest Modification

An attacker changes the hash in `manifest.json` to match their modified file.

```text
manifest.hmac says:  "d4e5f6..."
recomputed HMAC:      "m3n4o5..."  ← MISMATCH (attacker lacks the signing key)
```

**Detection:** HMAC mismatch. The attacker cannot produce a valid HMAC without the signing key.

### Scenario C: Complete Repackaging

An attacker with the signing key rebuilds the entire archive from scratch.

```text
All hashes valid. HMAC valid. But:
- createdUtc does not match the incident timeline
- warnings[] is empty (original had warnings)
- ZIP timestamps differ from the handoff records
```

**Detection:** Not cryptographic — requires procedural controls (timestamp comparison, handoff logs, warning reconciliation). This is why HMAC scope is documented explicitly.

### Scenario D: Benign Corruption

A network glitch flips a bit during file transfer.

```text
manifest.json says:  sha256 = "a1b2c3..."
actual file sha256:  "a1b2c4..."  ← 1 character different (avalanche effect)
```

**Detection:** SHA-256 mismatch. Accidental corruption is detected with the same mechanism as intentional tampering.
