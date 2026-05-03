# Design Decisions

Every major choice in the WPF UI has a security rationale, a performance implication, and an operational impact.

---

## Decision 1: Manual Composition Root in Code-Behind

**Decision:** Composition root in `MainWindow.xaml.cs` keeps the dependency graph small (~25 lines) and fixed at compile time.

**Rationale:** All dependencies are visible in one auditable location with no framework magic.

**Trade-off:** Child ViewModels (`Findings`, `Evidence`) are created inside `MainViewModel`, not in the composition root. This keeps the parent-child relationship explicit but means `MainViewModel` has two construction responsibilities. For this application size, the simplicity is worth it.

---

## Decision 2: Hand-Rolled MVVM Instead of a Framework

**Decision:** `ViewModelBase` and `RelayCommand` built from scratch (~60 lines combined) rather than using CommunityToolkit.Mvvm or MVVM Light.

**Rationale:** Adding NuGet packages would introduce dependencies whose internals would need to be trusted. Keeping the security tool dependency-free and easily auditable is prioritized over framework convenience.

**Trade-off:** `RelayCommand` uses `CommandManager.RequerySuggested`, which is WPF-specific. A framework-agnostic implementation would raise `CanExecuteChanged` manually, but that requires more plumbing for no practical benefit in a WPF-only app.

---

## Decision 3: Background Thread Analysis via Task.Run

**Decision:** Use `Task.Run` for analysis instead of running on the UI thread.

**Rationale:** Background analysis ensures WPF's single UI thread is not blocked by CPU-bound detection work. The analyst stays in control with an animated progress bar, working cancel button, and responsive UI during analysis.

**Trade-off:** `Task.Run` incurs a thread pool dispatch. For the workload sizes in VulcansTrace, this is negligible. The alternative — running on the UI thread with `async/await` — does not help for CPU-bound work because `async/await` does not offload execution; `Task.Run` is needed to move CPU work to a thread-pool thread.

---

## Decision 4: Cooperative Cancellation Support

**Decision:** Accept `CancellationToken` in analysis and export workflows, catch `OperationCanceledException` specifically.

**Rationale:** Long-running operations can be stopped when analysts switch priorities. This gives analysts an escape hatch for wrong-log analysis and resource-intensive scans.

**Implementation:** Analysis shows "cancelled by user" and returns early without updating findings. No partial results corrupt the display.

**Trade-off:** The XAML exposes separate analysis and export cancel buttons. Each command only enables while its corresponding operation owns an active cancellation token.

---

## Decision 5: Log Snapshot Capture Before Analysis

**Decision:** Capture log snapshot (`var logSnapshot = _logText`) before dispatching to the background thread.

**Rationale:** Ensures the analyzer sees stable input. Users can edit the text box while analysis runs without affecting the analysis.

**Implementation:** The same snapshot is passed to `Evidence.SetEvidenceContext` after analysis completes, so the exported raw log matches the text that was analyzed even if the user edits the text box while analysis is running.

**Trade-off:** The application still cannot prove the pasted log was authentic before the user clicked Analyze. Pre-analysis chain of custody belongs to log collection and storage controls outside the WPF UI.

---

## Decision 6: ICollectionView for Filtering

**Decision:** Use `ICollectionView` for findings filtering instead of LINQ `.Where()`.

**Rationale:** LINQ `.Where()` creates new collections on each filter change. `ICollectionView` avoids unnecessary allocations. Evidence export builds from `AnalysisResult` directly (via `EvidenceBuilder.BuildAsync`), not from `FindingsViewModel.Items`, so filtering can never exclude findings from the export regardless of the filtering mechanism.

**Trade-off:** `ItemsView.Refresh()` re-evaluates every item — O(n) per filter change. Appropriate for current result sizes, but profiling needed if findings grow into thousands.

---

## Decision 7: Multi-Field Text Search

**Decision:** Text search checks 4 fields (category, source host, target, short description).

**Rationale:** Analysts investigating by IP address should not need to specify which field to match. This supports rapid triage workflows.

**Trade-off:** Slightly more work per filter operation. Acceptable because search usability is more valuable than the marginal performance savings.

---

## Decision 8: CSPRNG for Signing Key Generation

**Decision:** Use `RandomNumberGenerator` for HMAC key generation, not `System.Random`.

**Rationale:** `System.Random` is predictable from its seed. CSPRNG produces HMAC signing keys that an attacker cannot predict or reproduce.

**Security Rationale:** Cryptographic integrity requires unpredictable keys.

---

## Decision 9: Key Masking in UI

**Decision:** Display asterisks matching the key's hex length (64 characters for 32-byte key) instead of the actual key.

**Rationale:** Reduces casual observation of the HMAC key via shoulder-surfing.

**Security Rationale:** Defense in depth. The key is not secret (HMAC is symmetric), but masking reduces accidental exposure.

---

## Decision 10: No Key Persistence

**Decision:** Generate a fresh key for each export. Do not persist keys to disk.

**Rationale:** Key storage would expand the attack surface. Each exported bundle is cryptographically independent, so a compromised key cannot verify old bundles.

**Trade-off:** Verifiers must receive the key out-of-band for each bundle. This is acceptable because the target audience is internal incident response teams who can share keys via secure channels.

---

## Decision 11: HMAC-SHA256 Instead of RSA Signature

**Decision:** Use HMAC-SHA256 for evidence signing, not RSA signatures with PKI.

**Rationale:** HMAC targets the internal incident response team who receives the shared secret out-of-band. This keeps the implementation simple while providing strong post-export integrity checks.

**Trade-off:** HMAC requires key sharing between analyst and verifier. If evidence needed to be verifiable by external parties (court, auditors), RSA signatures with PKI would be appropriate.

---

## Summary

| Decision | Security Principle | Operational Impact |
|----------|-------------------|-------------------|
| Manual composition root | Auditability | All dependencies visible in one location |
| Hand-rolled MVVM | Dependency-free security tool | No external trust required |
| Background thread analysis | Availability | UI remains responsive during analysis |
| Cooperative cancellation | Analyst control | Escape hatch for long-running operations |
| Log snapshot capture | Analysis/export consistency | User edits don't affect in-progress analysis or exported raw log |
| ICollectionView filtering | Memory efficiency | No allocations on filter change |
| Multi-field text search | Triage efficiency | Analysts find findings faster |
| CSPRNG key generation | Cryptographic security | Unpredictable signing keys |
| Key masking | Shoulder-surfing defense | Reduced casual key exposure |
| No key persistence | Attack surface reduction | Each bundle cryptographically independent |
| HMAC over RSA | Simplicity for internal use | Shared secret model fits IR team workflow |
