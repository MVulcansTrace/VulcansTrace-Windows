# Evasion and Limitations

This document covers what the WPF UI architecture does not handle and where the design makes deliberate trade-offs. 

---

## Platform Coupling

### WPF-Specific Types in ViewModel Layer

`RelayCommand` depends on `CommandManager.RequerySuggested`, which is a WPF-specific API. `EvidenceViewModel` calls `Clipboard.SetText`, which requires a WPF dispatcher. These couplings mean the ViewModel layer is not fully portable to other UI frameworks (Avalonia, MAUI, Blazor).

**Impact:** The ViewModels cannot be reused in a non-WPF application without refactoring the command and clipboard implementations.

**Mitigation:** `IDialogService` already abstracts dialog operations. The same pattern could be applied to clipboard access (`IClipboardService`) if framework portability became a requirement. The core detection logic in the engine has zero WPF dependencies.

### CommandManager Global Re-Query

`CommandManager.RequerySuggested` triggers CanExecute re-evaluation for all commands on common UI events. This is appropriate for 5 commands but would not scale to an application with hundreds of commands — the global re-query would create measurable overhead.

**Impact:** Not a problem at current scale. Would require switching to explicit `CanExecuteChanged` raising in a larger application.

---

## Data Integrity Gaps

### Evidence Snapshot Divergence

`MainViewModel.AnalyzeAsync` captures `var logSnapshot = _logText` before dispatching to the background thread, ensuring the analyzer sees stable input. However, `Evidence.SetEvidenceContext(_lastResult, _logText, lastAnalysisTimestampUtc)` passes the live `_logText` field — not the snapshot.

**Impact:** If the analyst edits the text box while the analysis is running (between the `logSnapshot` capture and the `SetEvidenceContext` call), the exported `log.txt` in the ZIP can differ from the text that was actually analyzed. After analysis completes, `SetEvidenceContext` stores its own copy in `EvidenceViewModel._logSnapshot`, so further edits do not affect the export.

**Mitigation:** The analysis snapshot could be preserved and passed to `SetEvidenceContext` instead of the live field. The current trade-off accepts this gap for simplicity — the divergence window is limited to the duration of the analysis Task.Run, and the exported evidence reflects the log text at analysis-completion time, which may be the analyst's corrected version.

### ICollectionView Refresh Is O(n)

`ItemsView.Refresh()` re-evaluates the filter predicate for every item on each filter change. This is linear in the number of findings.

**Impact:** For typical firewall log analysis (tens to low hundreds of findings), refresh is near-instant. For extremely large result sets (thousands of findings), profiling would be needed to confirm acceptable performance.

**Mitigation:** WPF's `ICollectionView` supports sorting and grouping that could reduce the filtered set, but the fundamental O(n) re-evaluation remains. For current workloads, this is the right trade-off.

---

## Security Limitations

### Post-Export Integrity Only

HMAC-SHA-256 signing protects the exported ZIP bundle against modification after export. It does not:

- Prove the source log was authentic before it was loaded into VulcansTrace
- Establish chain of custody between the firewall and the application
- Prevent the analyst from modifying the log text before analysis or export
- Detect files added to the ZIP that are not listed in the manifest

**Impact:** The integrity guarantee covers the export-to-verification path only. Pre-export chain of custody requires additional controls (log collection agents, SIEM integration, write-once storage).

### HMAC Requires Key Sharing

HMAC-SHA-256 uses a shared secret. Both the analyst and the verifier need the key. Key sharing is out-of-band (clipboard copy, encrypted message) and not managed by the application.

**Impact:** If the key is intercepted during sharing, an attacker could forge a valid HMAC signature. If the key is lost, the evidence bundle cannot be verified.

**When RSA would be better:** Legal proceedings, external auditor verification, or scenarios where the verifier should not receive a secret key. RSA signatures with PKI certificates provide non-repudiation without key sharing.

### No Key Persistence

Signing keys are generated per-export and never stored. This is a security feature (smaller attack surface, no stored secrets) but means the analyst must share the key immediately or lose the ability to verify.

**Impact:** If the analyst closes the application before sharing the key, that export cannot be verified. The key exists only in memory during the application session.

---

## Threading and Concurrency

### Async Void at ICommand Boundary

`ICommand.Execute` returns `void`. The `AnalyzeCommand` wraps `async _ => await AnalyzeAsync()`, which means the async delegate is invoked as fire-and-forget at the command boundary. The method handles its own exceptions internally via try/catch.

**Impact:** Unhandled exceptions inside `AnalyzeAsync` are caught by the internal try/catch and surfaced to the analyst. However, any exception that escapes the catch block would be lost because there is no `Task` to observe it.

**Mitigation:** The try/catch in `AnalyzeAsync` explicitly catches `OperationCanceledException` and `Exception`, covering all expected failure modes.

### UI Thread Assumption for ViewModel State

All ViewModel property access assumes the UI thread. `PropertyChanged` events are raised on whatever thread calls `SetField`; they are not automatically marshaled to the dispatcher by the ViewModel base class. The current implementation stays safe by capturing `logSnapshot` before `Task.Run` dispatches and applying results back on the UI thread after `await` resumes.

**Impact:** No race conditions in the current implementation because the background thread receives only the captured `logSnapshot` string — it never mutates bound ViewModel state after `Task.Run` dispatches. Adding background-thread updates to bound properties or collections would require explicit dispatcher marshaling or synchronization.

---

## Composition Root Scaling

The manual composition root in `MainWindow.xaml.cs` works well for ~25 lines of wiring. If the application grew to support plugin detectors, dynamic detector loading, or complex object lifetimes (scoped, singleton, transient), a DI container would be more appropriate.

**Impact:** Adding a new detector currently requires editing the composition root array — a one-line change, but a code change nonetheless. A plugin architecture would need dynamic registration.

**When to switch:** Hundreds of dependencies, plugin loading, or complex lifetimes would justify a DI container.

---

## Implementation Evidence

- [MainViewModel.cs](../../../VulcansTrace.Wpf/ViewModels/MainViewModel.cs): log snapshot capture, exception handling
- [EvidenceViewModel.cs](../../../VulcansTrace.Wpf/ViewModels/EvidenceViewModel.cs): per-export key, no persistence, Clipboard coupling
- [RelayCommand.cs](../../../VulcansTrace.Wpf/ViewModels/RelayCommand.cs): CommandManager coupling
- [MainWindow.xaml.cs](../../../VulcansTrace.Wpf/MainWindow.xaml.cs): manual composition root
- [MainViewModelIntegrationTests.cs](../../../VulcansTrace.Tests/Wpf/MainViewModelIntegrationTests.cs): per-export key regeneration test

