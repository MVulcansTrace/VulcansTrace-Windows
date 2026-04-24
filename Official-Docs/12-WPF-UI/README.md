# WPF UI

This folder contains technical documentation for the WPF desktop UI.

Documentation is organized for two audiences:

- Quick-review readers who need a fast summary of the subsystem and why it matters
- Technical reviewers who want to inspect the MVVM architecture, binding design, and cryptographic export integration

## Start Here

- [Expertise Snapshot](./WPF-UI-Summary/Expertise-Snapshot.md): 1-page overview for quick review
- [Why This Matters](./WPF-UI-In-Depth/Why-This-Matters.md): business value, security framing, and project context
- [UI Architecture](./WPF-UI-In-Depth/Core-Logic-Breakdown/UI-Architecture.md): the full MVVM pipeline and its trade-offs
- [Design Decisions](./WPF-UI-In-Depth/Design-Decisions.md): why key implementation choices were made
- [Code Patterns](./WPF-UI-In-Depth/Code-Patterns.md): repeatable implementation patterns that support testability
- [Attack Scenario](./WPF-UI-In-Depth/Attack-Scenario.md): a worked example showing the UI workflow during an active investigation
- [Evasion and Limitations](./WPF-UI-In-Depth/Evasion-and-Limitations.md): blind spots and improvement paths
- [MITRE ATT&CK Mapping](./WPF-UI-In-Depth/MITRE-ATTACK-Mapping.md): mapping to the ATT&CK framework

## System Capabilities

- MVVM architecture: hand-rolled `ViewModelBase` and `RelayCommand` (~70 lines total) instead of a framework, because fewer dependencies means smaller attack surface for a security tool
- Async analysis with cancellation: `Task.Run` offloads detection work from the UI thread, and `CancellationToken` support lets analysts abort long-running scans
- Real-time findings filtering: `ICollectionView` filters without modifying the source collection; evidence export builds from `AnalysisResult` directly, so filtering never excludes findings from the export
- Cryptographic evidence export: per-export HMAC-SHA-256 signing with a CSPRNG-generated key, key masking to prevent shoulder-surfing, and no key persistence

## Implementation Evidence

- [MainWindow.xaml.cs](../../VulcansTrace.Wpf/MainWindow.xaml.cs): composition root — wires all detectors, analyzer, and evidence builder
- [MainViewModel.cs](../../VulcansTrace.Wpf/ViewModels/MainViewModel.cs): analysis orchestration, async workflow, cancellation, child ViewModel coordination
- [ViewModelBase.cs](../../VulcansTrace.Wpf/ViewModels/ViewModelBase.cs): `INotifyPropertyChanged` with equality-checked `SetField` helper
- [RelayCommand.cs](../../VulcansTrace.Wpf/ViewModels/RelayCommand.cs): `ICommand` with `CommandManager.RequerySuggested` integration
- [FindingsViewModel.cs](../../VulcansTrace.Wpf/ViewModels/FindingsViewModel.cs): `ICollectionView` filtering, multi-field search, severity filter
- [EvidenceViewModel.cs](../../VulcansTrace.Wpf/ViewModels/EvidenceViewModel.cs): CSPRNG key generation, HMAC export, key masking, cancellation
- [IDialogService.cs](../../VulcansTrace.Wpf/Services/IDialogService.cs): dialog abstraction for testability
- [MainViewModelIntegrationTests.cs](../../VulcansTrace.Tests/Wpf/MainViewModelIntegrationTests.cs): end-to-end analysis + export, per-export key regeneration, parse-error cap, port-scan cap warning
- [MainViewModelTextTests.cs](../../VulcansTrace.Tests/Wpf/MainViewModelTextTests.cs): encoding artifact prevention
- [NonNegativeIntValidationRuleTests.cs](../../VulcansTrace.Tests/Wpf/NonNegativeIntValidationRuleTests.cs): XAML validation rule coverage

