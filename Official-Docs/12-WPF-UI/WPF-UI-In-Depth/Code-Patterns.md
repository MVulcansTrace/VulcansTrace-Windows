# Code Patterns

This document summarizes the main implementation patterns in the VulcansTrace WPF UI. It captures the patterns that matter for understanding the architecture.

---

## Pattern 1: Equality-Checked Property Notification

**File:** `VulcansTrace.Wpf/ViewModels/ViewModelBase.cs`

```csharp
protected bool SetField<T>(ref T field, T value, [CallerMemberName] string? propertyName = null)
{
    if (EqualityComparer<T>.Default.Equals(field, value))
        return false;

    field = value;
    PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    return true;
}
```

**Rationale:** WPF data binding requires `INotifyPropertyChanged` for UI updates. The equality check prevents redundant notifications and unnecessary UI rendering when a property is set to its current value. The `bool` return enables conditional chaining.

**Usage:**

```csharp
public string SearchText
{
    get => _searchText;
    set
    {
        if (SetField(ref _searchText, value))
        {
            ItemsView.Refresh();
        }
    }
}
```

---

## Pattern 2: Delegate-Based Command

**File:** `VulcansTrace.Wpf/ViewModels/RelayCommand.cs`

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

**Rationale:** XAML buttons bind to `ICommand` properties instead of click event handlers. The two-delegate pattern separates action from permission. `CommandManager.RequerySuggested` provides automatic state re-evaluation.

**Usage:**

```csharp
AnalyzeCommand = new RelayCommand(
    async _ => await AnalyzeAsync(),
    _ => CanAnalyze()
);
```

---

## Pattern 3: Child ViewModel Composition

**Files:** `VulcansTrace.Wpf/ViewModels/MainViewModel.cs`

```csharp
Findings = new FindingsViewModel();
Evidence = new EvidenceViewModel(evidenceBuilder, dialogService);
Evidence.StatusChanged += (s, msg) => SummaryText = msg;
```

**Rationale:** Each child ViewModel owns its responsibilities and state. The parent coordinates workflow and delegates results downward via method calls (`LoadResults`, `SetEvidenceContext`). Children notify the parent upward via events (`StatusChanged`). No messaging framework needed.

---

## Pattern 4: ICollectionView Filtering

**File:** `VulcansTrace.Wpf/ViewModels/FindingsViewModel.cs`

```csharp
ItemsView = CollectionViewSource.GetDefaultView(Items);
ItemsView.Filter = FilterFindings;
```

**Rationale:** `ICollectionView` wraps the source collection with a filter predicate. `Refresh()` re-evaluates the predicate for each item without creating a new collection. Note: evidence export builds from `AnalysisResult` directly (via `EvidenceBuilder.BuildAsync`), not from this UI collection, so filtering can never exclude findings from the export regardless of the filtering mechanism.

---

## Pattern 5: Async Background Analysis with Cancellation

**File:** `VulcansTrace.Wpf/ViewModels/MainViewModel.cs`

```csharp
_cancellationTokenSource = new CancellationTokenSource();
var token = _cancellationTokenSource.Token;
var intensity = _selectedIntensity.Level;
var logSnapshot = _logText;
result = await Task.Run(() => AnalyzeWithOverrides(intensity, logSnapshot, token), token);
```

**Rationale:** `Task.Run` offloads CPU-bound detection from the UI thread. The `CancellationToken` lets analysts abort long-running analysis. The `logSnapshot` captures a stable input before background dispatch. `async/await` marshals the result back to the UI thread automatically.

---

## Pattern 6: Per-Export CSPRNG Key Generation

**File:** `VulcansTrace.Wpf/ViewModels/EvidenceViewModel.cs`

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
```

**Rationale:** Each export gets a fresh 256-bit key from a CSPRNG. No key reuse between bundles. No key persistence. `ExportEvidenceAsync` sets `SigningKey` after a successful save, then the key is masked in the UI (asterisks matching key hex length) and available via clipboard copy for out-of-band sharing.

---

## Pattern 7: Service Abstraction for Testability

**File:** `VulcansTrace.Wpf/Services/IDialogService.cs`

```csharp
public interface IDialogService
{
    void ShowMessage(string message, string title);
    void ShowError(string message, string title);
    string? ShowSaveFileDialog(string title, string filter, string defaultFileName);
}
```

**Rationale:** ViewModels that call `MessageBox.Show` or `SaveFileDialog` directly require a running WPF dispatcher. `IDialogService` abstracts dialog operations so ViewModels can be unit tested with a `FakeDialogService` that records calls instead of showing dialogs.

---

## Pattern 8: Immutable Profile Override

**File:** `VulcansTrace.Wpf/ViewModels/MainViewModel.cs`

```csharp
private AnalysisResult AnalyzeWithOverrides(IntensityLevel intensity, string logText, CancellationToken token)
{
    var baseProfile = _profileProvider.GetProfile(intensity);
    var profile = PortScanMaxEntriesPerSource > 0
        ? baseProfile with { PortScanMaxEntriesPerSource = PortScanMaxEntriesPerSource }
        : baseProfile;

    return _analyzer.Analyze(logText, intensity, token, profile);
}
```

**Rationale:** `AnalysisProfile` is a record, so the `with` expression creates a modified copy without mutating the original. The base profile from `AnalysisProfileProvider` stays untouched.

---

## Key Data Bindings

```
DataContext (MainViewModel)
├── LogText                    → TextBox.Text
├── IsBusy                     → StackPanel.Visibility (wrapping ProgressBar + Working text)
├── SummaryText                → Status TextBlock
├── AdvisorMessage             → Advisor TextBlock
├── HasAdvisorMessage          → Advisor panel Visibility
├── BotIntroText               → Bot intro TextBlock
├── AnalyzeCommand             → Analyze Button.Command
├── CancelCommand              → Cancel Button.Command
├── Intensities                → ComboBox.ItemsSource
├── SelectedIntensity          → ComboBox.SelectedItem
├── PortScanMaxEntriesPerSource → TextBox.Text (with validation rule)
├── Findings (FindingsViewModel)
│   ├── ItemsView              → DataGrid.ItemsSource (filtered)
│   ├── SearchText             → Search TextBox.Text
│   ├── SelectedSeverityFilter → Severity ComboBox
│   ├── SeverityFilters        → Severity ComboBox.ItemsSource
│   ├── FindingsCount          → Badge TextBlock
│   ├── HighCriticalCount      → Badge TextBlock
│   ├── WarningCount           → Warnings Badge TextBlock
│   ├── ParseErrorCount        → Parse Errors Badge TextBlock
│   ├── HasWarnings            → Warnings panel Visibility
│   ├── HasParseErrors         → Parse Errors panel Visibility
│   ├── Warnings               → ItemsControl (inline) + ListBox (tab)
│   ├── ParseErrors            → ItemsControl (inline) + ListBox (tab)
│   └── Items                  → Source collection for ItemsView (export uses AnalysisResult directly)
└── Evidence (EvidenceViewModel)
    ├── ExportEvidenceCommand   → Export Button.Command
    ├── MaskedSigningKey        → Key display TextBlock
    └── CopySigningKeyCommand   → Copy Key Button.Command
```

---

## Implementation Evidence

- [ViewModelBase.cs](../../../VulcansTrace.Wpf/ViewModels/ViewModelBase.cs): equality-checked `SetField`
- [RelayCommand.cs](../../../VulcansTrace.Wpf/ViewModels/RelayCommand.cs): delegate-based command
- [MainViewModel.cs](../../../VulcansTrace.Wpf/ViewModels/MainViewModel.cs): async analysis, composition, profile override
- [FindingsViewModel.cs](../../../VulcansTrace.Wpf/ViewModels/FindingsViewModel.cs): ICollectionView filtering
- [EvidenceViewModel.cs](../../../VulcansTrace.Wpf/ViewModels/EvidenceViewModel.cs): CSPRNG key, HMAC export
- [IDialogService.cs](../../../VulcansTrace.Wpf/Services/IDialogService.cs): dialog abstraction
- [FakeDialogService.cs](../../../VulcansTrace.Tests/Wpf/FakeDialogService.cs): test double
