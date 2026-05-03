# UI Architecture

---

## The Engineering Problem

Security analysis tools live or die by their workflow. An analyst pastes a firewall log, runs detection, reviews findings, and exports evidence for the incident response team. If the UI freezes during analysis, the analyst loses time. If filtering removes findings from the export, the evidence is incomplete. If the signing key is predictable, the evidence bundle can be forged.

VulcansTrace's WPF UI solves these problems through three design commitments:

1. **Responsive analysis** — CPU-bound detection runs on a background thread with cancellation support
2. **Safe filtering** — `ICollectionView` filters the view without touching the source collection, so export always includes all findings
3. **Cryptographic export integrity** — per-export HMAC-SHA256 signing with a CSPRNG-generated key

---

## Implementation Overview

The **desktop analysis interface** for VulcansTrace uses MVVM with manual composition — external frameworks add dependencies with larger attack surfaces — giving analysts a complete workflow from log ingestion through filtered triage to signed evidence export.

**Key metrics:**

- ~70 lines of hand-rolled MVVM infrastructure (`ViewModelBase` + `RelayCommand`)
- 3 state-bearing ViewModels coordinated through composition, with `ViewModelBase` used only for shared property-change plumbing
- Full `CancellationToken` support for analysis and evidence export
- 4-field case-insensitive search across findings
- Per-export cryptographic independence — no key reuse between bundles

---

## Pipeline Stage 1: Composition Root

**File:** `VulcansTrace.Wpf/MainWindow.xaml.cs`

The composition root in the code-behind keeps the dependency graph small (~25 lines of wiring) and fixed at compile time — making all dependencies visible in one auditable location.

```csharp
var parser = new WindowsFirewallLogParser();
var profileProvider = new AnalysisProfileProvider();
var detectors = new IDetector[]
{
    new PortScanDetector(),
    new FloodDetector(),
    new LateralMovementDetector(),
    new BeaconingDetector(),
    new PolicyViolationDetector(),
    new NoveltyDetector()
};
var riskEscalator = new RiskEscalator();
var analyzer = new SentryAnalyzer(parser, profileProvider, detectors, riskEscalator);

var hasher = new IntegrityHasher();
var csvFormatter = new CsvFormatter();
var markdownFormatter = new MarkdownFormatter();
var htmlFormatter = new HtmlFormatter();
_evidenceBuilder = new EvidenceBuilder(hasher, csvFormatter, markdownFormatter, htmlFormatter);

_viewModel = new MainViewModel(analyzer, _evidenceBuilder, new WpfDialogService(), profileProvider);
DataContext = _viewModel;
```

**Rationale:**

- All 6 detectors are visible in one array — auditable at a glance
- Constructor injection makes dependencies immutable after construction
- `DataContext = _viewModel` is the bridge that enables all XAML data binding
- No DI container, no reflection, no configuration parsing — explicit construction only

---

## Pipeline Stage 2: ViewModelBase — Property Change Notification

**File:** `VulcansTrace.Wpf/ViewModels/ViewModelBase.cs`

`ViewModelBase` with an equality-checked `SetField` helper ensures WPF data binding requires `INotifyPropertyChanged` for UI updates — preventing redundant notifications when a property is set to its current value.

```csharp
public abstract class ViewModelBase : INotifyPropertyChanged
{
    public event PropertyChangedEventHandler? PropertyChanged;

    protected bool SetField<T>(ref T field, T value, [CallerMemberName] string? propertyName = null)
    {
        if (EqualityComparer<T>.Default.Equals(field, value))
            return false;

        field = value;
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        return true;
    }
    protected void RaisePropertyChanged(string propertyName) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
}
```

**Rationale:**

- Equality check prevents UI thrashing when properties are set to their current value
- `[CallerMemberName]` auto-fills the property name — refactoring-safe, no string literals
- `bool` return enables conditional chaining (e.g., `if (SetField(ref _searchText, value)) ItemsView.Refresh();`)
- `RaisePropertyChanged` handles dependent properties like `MaskedSigningKey` when `SigningKey` changes

**Security relevance:** Reliable property notification ensures analysts see real-time state updates during analysis — progress indicators, severity badges, and signing key readiness all depend on timely `PropertyChanged` events.

---

## Pipeline Stage 3: RelayCommand — Button Actions Without Code-Behind

**File:** `VulcansTrace.Wpf/ViewModels/RelayCommand.cs`

`RelayCommand` with two delegates and `CommandManager` integration enables XAML buttons to use `ICommand` binding for MVVM — keeping command logic in the ViewModel where it is testable.

```csharp
public sealed class RelayCommand : ICommand
{
    private readonly Action<object?> _execute;
    private readonly Func<object?, bool>? _canExecute;

    public RelayCommand(Action<object?> execute, Func<object?, bool>? canExecute = null)
    {
        _execute = execute ?? throw new ArgumentNullException(nameof(execute));
        _canExecute = canExecute;
    }

    public bool CanExecute(object? parameter) => _canExecute?.Invoke(parameter) ?? true;
    public void Execute(object? parameter) => _execute(parameter);

    public event EventHandler? CanExecuteChanged
    {
        add => CommandManager.RequerySuggested += value;
        remove => CommandManager.RequerySuggested -= value;
    }

    public void RaiseCanExecuteChanged() => CommandManager.InvalidateRequerySuggested();
}
```

**Rationale:**

- Two-delegate pattern separates action from permission — `Execute` does the work, `CanExecute` controls button state
- `CommandManager.RequerySuggested` provides automatic re-evaluation on common UI events (focus change, mouse click, key press)
- `RaiseCanExecuteChanged()` supports explicit refresh when automatic re-query is not enough
- `sealed` class prevents inheritance — encourages composition over inheritance

**Security relevance:** `CanExecute` logic acts as a first-line guard for operations — `AnalyzeCommand` won't fire without log text, `ExportEvidenceCommand` won't fire without analysis results, `CancelCommand` won't fire when not analyzing. This prevents invalid states like double-analysis or exporting incomplete evidence.

---

## Pipeline Stage 4: MainViewModel — Analysis Orchestration

**File:** `VulcansTrace.Wpf/ViewModels/MainViewModel.cs`

`MainViewModel` is the orchestration layer that coordinates the full analysis workflow with async execution and cancellation — CPU-bound detection work would freeze the single WPF UI thread — keeping analysts in control of long-running scans.

```csharp
private async Task AnalyzeAsync()
{
    // guard clause and status updates omitted for brevity
    IsBusy = true;

    _cancellationTokenSource?.Dispose();
    _cancellationTokenSource = new CancellationTokenSource();
    var token = _cancellationTokenSource.Token;

    AnalysisResult result;
    string logSnapshot;
    try
    {
        var intensity = _selectedIntensity.Level;
        logSnapshot = _logText;
        result = await Task.Run(() => AnalyzeWithOverrides(intensity, logSnapshot, token), token);
    }
    catch (OperationCanceledException)
    {
        IsBusy = false;
        SummaryText = "Analysis cancelled by user.";
        AdvisorMessage = "Analysis cancelled.";
        return;
    }
    catch (Exception ex)
    {
        IsBusy = false;
        SummaryText = $"Analysis failed: {ex.Message}";
        AdvisorMessage = "Analysis failed.";
        return;
    }

    _lastResult = result;
    var lastAnalysisTimestampUtc = result.TimeRangeEnd?.ToUniversalTime()
        ?? result.TimeRangeStart?.ToUniversalTime()
        ?? DateTime.UnixEpoch;
    Evidence.SetEvidenceContext(_lastResult, logSnapshot, lastAnalysisTimestampUtc);
    Findings.LoadResults(result);
    // ... build summary, update advisor message, set busy false
}
```

**Rationale:**

- `Task.Run` offloads to a thread pool thread — UI stays responsive for the progress indicator and analysis cancel button
- `logSnapshot` captures `_logText` before dispatching — analyzer and evidence export use the same stable input even if the user edits the text box
- `AnalyzeWithOverrides` conditionally applies the `PortScanMaxEntriesPerSource` profile override before calling `SentryAnalyzer.Analyze` — the override is applied only when the cap is set to a value greater than zero
- Error handling surfaces exceptions clearly — analysts know when analysis failed and why
- Cancellation produces clean early exit — no partial results corrupt the display

---

## Pipeline Stage 5: FindingsViewModel — Filtering and Display

**File:** `VulcansTrace.Wpf/ViewModels/FindingsViewModel.cs`

`FindingsViewModel` with `ICollectionView` filtering avoids LINQ `.Where()` which creates new collections each time — keeping the source collection intact so that filtering never excludes findings from evidence export.

```csharp
public ICollectionView ItemsView { get; }

public FindingsViewModel()
{
    ItemsView = CollectionViewSource.GetDefaultView(Items);
    ItemsView.Filter = FilterFindings;

    // Severity filter initialization
    SeverityFilters.Add(new SeverityFilterOption("All severities", null));
    SeverityFilters.Add(new SeverityFilterOption("High & Critical only", Severity.High));
    SeverityFilters.Add(new SeverityFilterOption("Critical only", Severity.Critical));
    SelectedSeverityFilter = SeverityFilters[0];
}

private bool FilterFindings(object item)
{
    if (item is not FindingItemViewModel finding)
        return false;

    if (_selectedSeverityFilter?.MinSeverity != null &&
        Enum.TryParse<Severity>(finding.Severity, out var sev) &&
        sev < _selectedSeverityFilter.MinSeverity.Value)
        return false;

    if (string.IsNullOrWhiteSpace(_searchText))
        return true;

    return finding.Category.Contains(_searchText, StringComparison.OrdinalIgnoreCase) ||
           finding.SourceHost.Contains(_searchText, StringComparison.OrdinalIgnoreCase) ||
           finding.Target.Contains(_searchText, StringComparison.OrdinalIgnoreCase) ||
           finding.ShortDescription.Contains(_searchText, StringComparison.OrdinalIgnoreCase);
}
```

**Rationale:**

- `ICollectionView` is a view projection — items are hidden, not removed
- Search checks 4 fields (category, source host, target, short description) — analysts can search by IP without specifying which field
- Severity filter uses enum comparison — `Severity` is ordered (Info=0 through Critical=4) so `<` works
- Parse errors capped at 200 with overflow message — prevents UI overload from severely malformed logs
- `LoadResults` replaces all data atomically — no stale findings from previous analysis

**Security relevance:** The source `Items` collection is never modified by filtering. Evidence export builds from `AnalysisResult` directly, not from the filtered view. Filtering cannot accidentally exclude findings from the evidence bundle.

---

## Pipeline Stage 6: EvidenceViewModel — Cryptographic Export

**File:** `VulcansTrace.Wpf/ViewModels/EvidenceViewModel.cs`

`EvidenceViewModel` with per-export CSPRNG key generation and HMAC-SHA256 signing prevents key reuse which would weaken integrity protection across bundles — making each exported ZIP independently verifiable by the incident response team.

```csharp
private static byte[] GenerateSigningKeyBytes()
{
    var keyBytes = new byte[32];
    using (var rng = RandomNumberGenerator.Create())
    {
        rng.GetBytes(keyBytes);
    }

    return keyBytes;
}

public string MaskedSigningKey =>
    string.IsNullOrEmpty(_signingKey)
        ? string.Empty
        : new string('*', _signingKey.Length);
```

`ExportEvidenceAsync` converts the generated bytes to hex and assigns `SigningKey` only after the export is successfully written and the analysis context still matches.

**Rationale:**

- `RandomNumberGenerator` is a CSPRNG — keys are unpredictable, unlike `System.Random`
- 32 bytes = 256 bits, matching HMAC-SHA256 output size for full security strength
- Key is masked as asterisks in the UI (length matches hex key) — prevents shoulder-surfing
- Copy to clipboard is available for out-of-band sharing with the IR team
- No key persistence — each export is cryptographically independent
- `StatusChanged` event notifies parent ViewModel of export progress

**Security relevance:** The exported ZIP contains per-file SHA-256 hashes and an HMAC-SHA256 signature over the manifest. Recipients with the key can verify the bundle was not modified after export. This protects post-export integrity only — it does not prove source-log authenticity or establish chain of custody before the log was loaded.

---

## Operational Benefits

| Capability | Business Value |
|-----------|----------------|
| **Responsive analysis** | Analysts can cancel long-running scans and switch to urgent tasks |
| **Safe filtering** | Filtering the UI never excludes findings from the exported evidence bundle |
| **Signed evidence export** | Incident response teams can verify the exported ZIP was not modified |
| **Severity-based triage** | Analysts filter to High/Critical first for faster incident response |
| **Multi-field search** | Investigators correlate findings by IP, category, or description without specifying which field |
| **Dialog abstraction** | `IDialogService` removes modal dialog popups from tests and keeps dialog behavior mockable |

---

## Security Principles Applied

| Principle | Where It Appears |
|-----------|-----------------|
| **Minimal dependencies** | Hand-rolled MVVM — no external framework for a smaller attack surface |
| **CSPRNG for key generation** | `RandomNumberGenerator` instead of `System.Random` for HMAC signing keys |
| **Defense in depth** | Filtering in the UI layer, detection in the engine, integrity in the export |
| **Key masking** | Signing key displayed as asterisks matching key hex length to prevent shoulder-surfing |
| **No key persistence** | Each export generates a fresh key; no storage reduces attack surface |
| **Explicit composition** | All dependencies wired in one auditable location — no framework magic |

---

## Implementation Evidence

- [MainWindow.xaml.cs](../../../../VulcansTrace.Wpf/MainWindow.xaml.cs): composition root
- [ViewModelBase.cs](../../../../VulcansTrace.Wpf/ViewModels/ViewModelBase.cs): equality-checked `SetField`
- [RelayCommand.cs](../../../../VulcansTrace.Wpf/ViewModels/RelayCommand.cs): two-delegate command with `CommandManager`
- [MainViewModel.cs](../../../../VulcansTrace.Wpf/ViewModels/MainViewModel.cs): async analysis orchestration
- [FindingsViewModel.cs](../../../../VulcansTrace.Wpf/ViewModels/FindingsViewModel.cs): `ICollectionView` filtering
- [EvidenceViewModel.cs](../../../../VulcansTrace.Wpf/ViewModels/EvidenceViewModel.cs): CSPRNG key generation; HMAC signing delegated to `EvidenceBuilder`
- [MainViewModelIntegrationTests.cs](../../../../VulcansTrace.Tests/Wpf/MainViewModelIntegrationTests.cs): end-to-end analysis + export + snapshot consistency + key regeneration

---

## Elevator Pitch

> *"The WPF desktop UI uses hand-rolled MVVM for VulcansTrace — external frameworks add dependencies with larger attack surfaces — keeping the attack surface small while giving analysts a responsive triage workflow.*
>
> *"The architecture has three layers: the visible UI is XAML with a thin composition root in code-behind, the ViewModels coordinate analysis and display, and the Models handle detection and evidence. `ViewModelBase` and `RelayCommand` were written from scratch — about 70 lines — because CommunityToolkit.Mvvm would add a NuGet package whose internals would need to be trusted, and the custom implementation does exactly what the app needs.*
>
> *`MainViewModel` runs analysis on a background thread via `Task.Run` with cancellation, because CPU-bound detection would freeze the UI. Before dispatching, a log snapshot is captured so the analyzer and exported `log.txt` use the exact input that was present when Analyze was clicked — even if the user edits the text box while analysis runs.*
>
> *`FindingsViewModel` uses `ICollectionView` for filtering instead of LINQ because LINQ creates new collections each time a filter changes, and the source collection needs to stay intact for evidence export. The filter checks severity and searches four fields: category, source host, target, and description.*
>
> *`EvidenceViewModel` generates a unique 256-bit signing key per export using `RandomNumberGenerator` — a CSPRNG, not `System.Random` which is predictable. The key signs the manifest via HMAC-SHA256 so the incident response team can verify the bundle wasn't modified after export. The key is masked in the UI to prevent shoulder-surfing, and never persisted."*

---

## Security Takeaways

1. **Hand-rolled MVVM = smaller attack surface** — ~70 lines vs. a full framework dependency
2. **ICollectionView is safe for evidence** — filtering is a view projection, not data modification
3. **CSPRNG keys prevent HMAC forgery** — predictable keys would let an attacker forge valid signatures
4. **Log snapshot protects analysis/export consistency** — analyzer and `log.txt` use the same stable input
5. **Cancellation prevents wasted work** — analysts abort wrong-log analysis before results corrupt triage
