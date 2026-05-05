# Attack Scenario

A worked example showing how the WPF UI architecture supports an analyst during an active incident investigation.

---

## Scenario: Lateral Movement Triage

An analyst receives a tip that suspicious activity was detected on a Windows server. They export the Windows Firewall log from the server and load it into VulcansTrace using the **Load File...** button (or paste it directly into the text box).

### Step 1: Log Ingestion

The analyst loads the raw firewall log. If using **Load File...**, `OpenFileDialog` returns the path, `File.ReadAllText` reads the content asynchronously, and `LogText` is set. If pasting, `LogText` updates via two-way binding with `UpdateSourceTrigger=PropertyChanged`, so every character triggers the binding. The `AnalyzeCommand.CanExecute` predicate re-evaluates automatically via `CommandManager.RequerySuggested` — once `_logText` is non-empty and `_selectedIntensity` is set, the Analyze button enables.

### Step 2: Analysis

The analyst selects "High - Deep Hunt / Forensics" intensity and clicks Analyze. (The Advanced expander exposes two overrides: a **Port scan max events/source** text box — setting it to a value greater than 0 caps per-source port scan entries and emits a warning when the cap is reached — and an **Enable lateral movement detection** check box, which defaults to checked. For this scenario, both are left at their defaults.) The UI flow:

1. `CanAnalyze()` returns `true` — not busy, has log text, has intensity
2. `IsBusy = true` — progress bar appears, Analyze button disables, Cancel button enables
3. `logSnapshot` captures the text — stable analysis and export input even if the analyst edits the text box
4. `Task.Run` dispatches to `AnalyzeWithOverrides`, which calls `SentryAnalyzer.Analyze`
5. Six detectors run: PortScan, Flood, LateralMovement, Beaconing, PolicyViolation, Novelty
6. `RiskEscalator` checks for cross-detector correlation (e.g., Beaconing + LateralMovement → Critical)
7. Findings below the profile's `MinSeverityToShow` threshold are removed before returning results (at High intensity this threshold is `Info`, so nothing is filtered out; at lower intensities, low-severity findings are dropped)

The analyst watches the progress indicator until results arrive.

### Step 3: Findings Review

`MainViewModel` delegates to child ViewModels:

- `Evidence.SetEvidenceContext(result, logSnapshot, timestamp)` — prepares export context with the same raw log that was analyzed; `CanExportEvidence()` returns `true` via automatic `CommandManager` re-evaluation, making the Export button available
- `Findings.LoadResults(result)` — populates the DataGrid with wrapped `FindingItemViewModel` rows

The summary shows: **"Found 7 issues, 4 High/Critical."**

The DataGrid displays all 7 findings. The advisor message reads: **"Multiple High/Critical issues detected. Triage those first, then sweep the rest."**

If the log had unparseable lines, the UI would also display a parse errors panel showing up to 200 individual errors (with a count of any remaining). A warnings panel appears when detectors emit warnings (e.g., when a port scan cap truncates results). Both panels are visible above the findings tabs.

### Step 4: Severity Filtering

The analyst changes the severity dropdown to "High & Critical only." `SelectedSeverityFilter` setter calls `ItemsView.Refresh()`, which re-evaluates `FilterFindings` for each item. Items with severity below `Severity.High` are hidden. The DataGrid now shows 4 rows — the urgent ones.

The source `Items` collection still contains all 7 findings. Nothing is removed.

### Step E: IP Investigation

The analyst sees a LateralMovement finding from `10.0.0.5` and wants to check all related activity. They type `10.0.0.5` in the search box. `SearchText` setter calls `ItemsView.Refresh()`, which checks 4 fields per item (case-insensitive):

- `finding.Category.Contains("10.0.0.5", StringComparison.OrdinalIgnoreCase)` — no match
- `finding.SourceHost.Contains("10.0.0.5", StringComparison.OrdinalIgnoreCase)` — matches the LateralMovement finding
- `finding.Target.Contains("10.0.0.5", StringComparison.OrdinalIgnoreCase)` — matches two PortScan findings where `10.0.0.5` was the target
- `finding.ShortDescription.Contains("10.0.0.5", StringComparison.OrdinalIgnoreCase)` — matches additional findings

The DataGrid narrows to findings related to that IP — both as source and target — across multiple detection categories.

### Step 6: Evidence Export

The analyst clicks Export Evidence. The export flow:

1. `GenerateSigningKeyBytes()` creates a 32-byte key from `RandomNumberGenerator` (CSPRNG)
2. `EvidenceBuilder.BuildAsync` packages findings.csv, log.txt, report.html, summary.md
3. SHA-256 hashes computed for each file, written into `manifest.json`
4. HMAC-SHA256 signature over the manifest, written into `manifest.hmac`
5. Save dialog appears — analyst chooses a location
6. ZIP written to disk
7. After the ZIP is saved, `SigningKey` is set and the UI shows the masked signing key (asterisks matching key hex length) — analyst clicks Copy Signing Key to clipboard

The analyst sends the ZIP to the incident response team via a secure channel and shares the signing key via a separate out-of-band channel (e.g., encrypted messaging). The team verifies:

1. Recompute HMAC on `manifest.json` using the shared key
2. Compare with `manifest.hmac`
3. Recompute SHA-256 hashes for each file
4. Compare with entries in `manifest.json`

If any file or the manifest was modified after export, verification fails.

> **Integrity scope:** SHA-256 hashes and HMAC signatures protect the evidence package from modification *after* export. They do **not** detect tampering of the original source logs *before* they were loaded into VulcansTrace, and HMAC-SHA256 does not prove the identity of the signer without secure key management and audit logging.

### Step 7: Cancellation (Alternate Path)

If the analyst realizes they pasted the wrong log during analysis:

1. They click Cancel
2. `CancelCommand.Execute` calls `_cancellationTokenSource.Cancel()`
3. `SentryAnalyzer` checks the token before parsing and before each detector
4. `OperationCanceledException` propagates back to `AnalyzeAsync`
5. UI shows "Analysis cancelled by user." — no partial findings displayed
6. The analyst loads the correct log (via Load File or paste) and clicks Analyze again

---

## Why The Architecture Matters For This Scenario

| Architecture Choice | Scenario Impact |
|---|---|
| `Task.Run` background analysis | Analyst sees progress and can cancel — not frozen |
| Log snapshot | Analysis and exported `log.txt` use the correct input even if the analyst edits the text box |
| `ICollectionView` filtering | Severity + IP filtering narrows to relevant findings without losing data |
| Source collection untouched | All 7 findings are exported regardless of the current filter state |
| Per-export CSPRNG key | Each export has an independent integrity check |
| Key masking | The signing key is not visible on the analyst's screen |
| `CancellationToken` | Wrong-log analysis is aborted cleanly with no partial results |
| Advisor message | Analyst gets immediate guidance on triage priority |

---

## Implementation Evidence

- [MainViewModel.cs](../../../VulcansTrace.Wpf/ViewModels/MainViewModel.cs): analysis orchestration, cancellation, child ViewModel delegation
- [FindingsViewModel.cs](../../../VulcansTrace.Wpf/ViewModels/FindingsViewModel.cs): severity + text filtering on 4 fields
- [EvidenceViewModel.cs](../../../VulcansTrace.Wpf/ViewModels/EvidenceViewModel.cs): CSPRNG key generation, export orchestration, key masking
- [EvidenceBuilder.cs](../../../VulcansTrace.Evidence/EvidenceBuilder.cs): SHA-256 hashes, HMAC-SHA256 signature, ZIP packaging
- [MainViewModelIntegrationTests.cs](../../../VulcansTrace.Tests/Wpf/MainViewModelIntegrationTests.cs): end-to-end analysis + export + snapshot consistency scenarios
