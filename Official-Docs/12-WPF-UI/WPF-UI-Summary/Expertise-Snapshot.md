# Expertise Snapshot

> **1 page:** the subsystem, why it matters, and where the proof lives in the codebase.

---

## Implementation Overview

A **WPF desktop UI** for VulcansTrace using hand-rolled MVVM with no external MVVM framework dependencies. The UI coordinates firewall log analysis, real-time findings filtering, and cryptographic evidence export through a three-ViewModel composition: `MainViewModel` orchestrates the workflow, `FindingsViewModel` manages filtered display, and `EvidenceViewModel` handles HMAC-signed export.

---

## Key Metrics

| Metric | Value |
|--------|-------|
| Architecture pattern | MVVM with manual composition |
| Framework code | ~70 lines (`ViewModelBase` + `RelayCommand`) |
| ViewModels | 3 state-bearing (`MainViewModel`, `FindingsViewModel`, `EvidenceViewModel`) |
| Detection pipeline integration | 6 detectors wired through `SentryAnalyzer` |
| Export integrity | HMAC-SHA256 with 256-bit CSPRNG key, per-export regeneration |
| Filtering | `ICollectionView` with severity filter + text search across 4 fields (category, source host, target, short description) |
| Cancellation | User-facing analysis cancellation plus ViewModel-level export cancellation support |

---

## Why It Matters

- Hand-rolled MVVM avoids external dependencies — smaller attack surface, easier auditing for a security tool
- `Task.Run` with cancellation keeps the UI responsive during heavy detection work — analysts can abort and switch to urgent tasks
- `ICollectionView` filtering does not modify the source collection — evidence export builds from `AnalysisResult` directly, so filtering never excludes findings from the export
- HMAC-SHA256 signing with CSPRNG keys gives each export an independent integrity check

---

## Key Evidence

- [MainWindow.xaml.cs](../../../VulcansTrace.Wpf/MainWindow.xaml.cs): composition root wiring 6 detectors, analyzer, risk escalator, and evidence builder with formatters
- [MainViewModel.cs](../../../VulcansTrace.Wpf/ViewModels/MainViewModel.cs): async analysis with shared analysis/export log snapshot, cancellation, and child ViewModel delegation
- [FindingsViewModel.cs](../../../VulcansTrace.Wpf/ViewModels/FindingsViewModel.cs): `ICollectionView` filtering with severity + text search
- [EvidenceViewModel.cs](../../../VulcansTrace.Wpf/ViewModels/EvidenceViewModel.cs): CSPRNG key generation, HMAC export, key masking
- [MainViewModelIntegrationTests.cs](../../../VulcansTrace.Tests/Wpf/MainViewModelIntegrationTests.cs): end-to-end analysis, export, snapshot consistency, key regeneration, parse-error cap

---

## Key Design Choices

- **Hand-rolled MVVM** because external frameworks add dependencies with larger attack surfaces, for the purpose of keeping the security tool auditable and dependency-free
- **`ICollectionView` over LINQ filtering** because LINQ creates new collections each time, for the purpose of keeping the source collection intact for evidence export
- **Per-export CSPRNG key** because key reuse weakens HMAC protection across bundles, for the purpose of making each export cryptographically independent
- **Log snapshot capture** because users can edit the text box during analysis, for the purpose of ensuring both the analyzer and exported `log.txt` use the exact input that was present when Analyze was clicked
