# Quick Reference

## MVVM Layers

| Layer | File(s) | Responsibility |
|-------|---------|----------------|
| View | `MainWindow.xaml` | XAML UI and data binding; composition lives in `MainWindow.xaml.cs` |
| Composition Root | `MainWindow.xaml.cs` | Wires engine, services, and ViewModel |
| ViewModel | `MainViewModel.cs` | Analysis orchestration, async workflow |
| ViewModel | `FindingsViewModel.cs` | Findings display, filtering, counters |
| ViewModel | `EvidenceViewModel.cs` | Cryptographic export, key management |
| Model | `SentryAnalyzer`, detectors, `EvidenceBuilder` | Detection logic, evidence generation |

## Key Properties (Data Binding)

| ViewModel | Property | XAML Binding |
|-----------|----------|-------------|
| MainViewModel | `LogText` | `TextBox.Text` (TwoWay, PropertyChanged) |
| MainViewModel | `IsBusy` | StackPanel visibility (ProgressBar + "Working..." text) |
| MainViewModel | `AnalyzeCommand` | Button.Command |
| FindingsViewModel | `ItemsView` | DataGrid.ItemsSource (filtered) |
| FindingsViewModel | `SearchText` | Search TextBox.Text |
| FindingsViewModel | `SelectedSeverityFilter` | Severity ComboBox |
| EvidenceViewModel | `MaskedSigningKey` | Signing key display |
| EvidenceViewModel | `ExportEvidenceCommand` | Export Button.Command |

## Commands

| Command | ViewModel | CanExecute Logic |
|---------|-----------|-----------------|
| `AnalyzeCommand` | MainViewModel | `!_isBusy && !string.IsNullOrWhiteSpace(_logText) && _selectedIntensity != null` |
| `CancelCommand` | MainViewModel | `_isBusy && _cancellationTokenSource != null && !_cancellationTokenSource.IsCancellationRequested` |
| `ExportEvidenceCommand` | EvidenceViewModel | `_lastResult != null && !IsBusy` |
| `CancelExportCommand` | EvidenceViewModel | `_isBusy && _cancellationTokenSource != null && !_cancellationTokenSource.IsCancellationRequested` (defined in the ViewModel, not currently bound in XAML) |
| `CopySigningKeyCommand` | EvidenceViewModel | `!string.IsNullOrEmpty(SigningKey)` |

## ViewModelBase Pattern

```
SetField<T>(ref field, value, [CallerMemberName])
  1. EqualityComparer check — skip if unchanged
  2. Update backing field
  3. Raise PropertyChanged
  4. Return bool (true = changed)
```

## RelayCommand Pattern

| Part | Purpose |
|------|---------|
| `_execute` delegate | Action to perform on click |
| `_canExecute` delegate | Controls button enabled state |
| `CommandManager.RequerySuggested` | Automatic CanExecute re-evaluation |
| `RaiseCanExecuteChanged()` | Explicit refresh when needed |

## Analysis Workflow

```
User clicks Analyze
  → CanAnalyze() check
  → IsBusy = true
  → Capture logSnapshot = _logText
  → Task.Run(AnalyzeWithOverrides)
  → On success: Evidence.SetEvidenceContext → Findings.LoadResults → Build summary
  → On cancel: Show "cancelled by user", no partial results
  → On error: Show exception message
  → IsBusy = false
```

## Evidence Export Workflow

```
User clicks Export Evidence
  → CanExportEvidence() check
  → GenerateNewSigningKey() — 32 bytes from CSPRNG
  → EvidenceBuilder.BuildAsync — SHA-256 hashes + HMAC-SHA-256 signature
  → Save dialog → Write ZIP to disk
  → Key masked in UI (asterisks), copy to clipboard for sharing
```

---

## Evidence Bundle Structure

```text
evidence.zip
├── findings.csv
├── log.txt
├── report.html
├── summary.md
├── manifest.json    — File hashes (SHA-256), timestamps, and warnings
└── manifest.hmac    — HMAC-SHA-256 of manifest.json
```

## Filtering

| Filter | Mechanism | Scope |
|--------|-----------|-------|
| Severity dropdown | `SeverityFilterOption.MinSeverity` enum comparison | Hide below threshold |
| Text search | `Contains()` on 4 fields: category, source host, target, short description | Case-insensitive match |
| Implementation | `ICollectionView.Filter` + `Refresh()` | View projection only — source untouched |

## File Counts

| Category | Count |
|----------|-------|
| ViewModel files | 8 (3 state-bearing + `RelayCommand` + `ViewModelBase` + helpers) |
| Service files | 2 (`IDialogService` + `WpfDialogService`) |
| Validation files | 1 (`NonNegativeIntValidationRule`) |
| Test files | 3 + 1 infrastructure (integration, text, validation + FakeDialogService) |
