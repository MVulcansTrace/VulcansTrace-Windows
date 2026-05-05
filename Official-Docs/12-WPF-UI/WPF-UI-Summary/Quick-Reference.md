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
| MainViewModel | `LoadFileCommand` | Button.Command ("Load File...") |
| MainViewModel | `LoadDemoDataCommand` | TextBlock.InputBindings ("Load demo data" link) |
| MainViewModel | `BotIntroText` | Intro header text block |
| MainViewModel | `HasAdvisorMessage` | Advisor message panel visibility |
| MainViewModel | `AdvisorMessage` | Advisor message text block |
| MainViewModel | `SummaryText` | Analysis summary text block |
| MainViewModel | `AnalysisDurationText` | Timing badge in summary row (e.g., "482 ms") |
| MainViewModel | `HasAnalysisDuration` | Timing badge visibility |
| MainViewModel | `PortScanMaxEntriesPerSource` | Override text box (TwoWay) |
| MainViewModel | `EnableLateralMovement` | Override check box (TwoWay) |
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
| `CancelExportCommand` | EvidenceViewModel | `_isBusy && _cancellationTokenSource != null && !_cancellationTokenSource.IsCancellationRequested` |
| `CopySigningKeyCommand` | EvidenceViewModel | `!string.IsNullOrEmpty(SigningKey)` |
| `LoadFileCommand` | MainViewModel | `!_isBusy` — opens `OpenFileDialog`, reads selected file into `LogText` |
| `LoadDemoDataCommand` | MainViewModel | always enabled — loads `SampleData.IntensityComparison` into the log text box |

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
  → On success: Evidence.SetEvidenceContext(logSnapshot) → Findings.LoadResults → Build summary → Set AnalysisDurationText from Stopwatch
  → On cancel: Show "cancelled by user", no partial results
  → On error: Show exception message
  → IsBusy = false
```

## Evidence Export Workflow

```
User clicks Export Evidence
  → CanExportEvidence() check
  → GenerateSigningKeyBytes() — 32 bytes from CSPRNG
  → EvidenceBuilder.BuildAsync — SHA-256 hashes + HMAC-SHA256 signature
  → Save dialog → Write ZIP to disk
  → SigningKey set after successful save
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
└── manifest.hmac    — HMAC-SHA256 of manifest.json
```

## Layout

| Element | Description |
|---------|-------------|
| Window chrome | `WindowStyle="None"` with custom `WindowChrome` (`GlassFrameThickness="0"`, `CaptionHeight="0"`, `ResizeBorderThickness="6"`, `CornerRadius="8"`) |
| Title bar | Custom grid with app icon, brand text, minimize/maximize/close buttons |
| Main grid | Three columns: left panel (~400px), GridSplitter (6px), right panel (remaining space) |
| GridSplitter | `Width="6"`, `Background="Transparent"` — resizes left/right panels |
| Action buttons | WrapPanel with 4 buttons: Analyze (90px), Cancel (80px), Export Evidence (120px), Cancel Export (110px), all `Padding="8,6"`. Plus "Load File..." button (opens `OpenFileDialog`) and a muted "Load demo data" text link below the log input. |
| Advanced Options | Expander with two overrides: Port scan max events/source (`TextBox`), Enable lateral movement detection (`CheckBox`) |
| DataGrid columns | Category, Severity (chip style), Source, Target, Start, End, Description, **Details button** (70px) |
| Category tooltip | `ToolTip="{Binding GroupDetails}"`, `ShowDuration="15000"` — shows grouped Novelty destinations |
| ToolTip style | Dark theme (`BackgroundCardBrush`, `BorderStrongBrush`, `CornerRadius="6"`) defined in `DarkTheme.xaml` |

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
| Test files | 4 + 1 infrastructure (integration, text, validation, findings + FakeDialogService) |
