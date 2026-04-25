# Design Decisions

Every major choice in this test suite has a security rationale, a maintenance implication, and an operational impact.

---

## Decision 1: Three Engine Test Categories (Unit, Integration, Robustness)

**Decision:** Three distinct engine test categories targeting different failure modes.

**Rationale:** Three engine test categories catch bugs the others miss — unit tests catch detector logic bugs, integration tests catch orchestration bugs, robustness tests catch crash and cancellation bugs — achieving defense in depth in the analysis pipeline test suite.

| Category | Catches | Impact if Missing |
|----------|---------|-------------------|
| **Unit** | Detector logic bugs — threshold off by one, wrong severity | Detector never triggers or always triggers |
| **Integration** | Orchestration bugs — severity filtering broken, escalation missing | Wrong findings shown to analyst |
| **Robustness** | Error handling bugs — one detector crashes the pipeline | System unavailable during attacks |

**Trade-off:** Three categories means more test code to maintain. The alternative — only integration tests — would miss detector-specific logic bugs because the integration test might not exercise the exact boundary.

---

## Decision 2: Paired Threshold Tests

**Decision:** For each statistical detector, the test suite writes both a below-threshold test and an above-threshold test.

**Rationale:** Paired tests are necessary because either test alone is insufficient — a below-threshold test passes if the detector never fires, an above-threshold test passes if the detector always fires — proving the threshold boundary is correctly calibrated.

| Detector | Below-Threshold Test | Above-Threshold Test |
|----------|---------------------|---------------------|
| PortScan | 5 ports < 15 | 20 ports > 15 |
| Beaconing | Irregular intervals | Regular 90s intervals |
| Flood | Low volume in window | High volume in window |
| LateralMovement | 3 hosts < 6 | 8 hosts > 6 |

**Trade-off:** Twice the test methods per detector. Worth it because threshold calibration is the highest-risk logic in each detector.

---

## Decision 3: Fakes Over Mocks for Analyzer Tests

**Decision:** Inline fake detector implementations (`FakeDetector`, `CrashingDetector`, `WorkingDetector`, `EscalationTestDetector`) for analyzer-focused tests, instead of mocking frameworks.

**Rationale:** Fakes test the outputs the analyzer produces from given detector inputs, not whether specific detector methods were called in a specific order — testing orchestration behavior in isolation without coupling tests to implementation details.

| Aspect | Mocks | Fakes |
|--------|-------|-------|
| What they verify | Method call sequences | Output behavior |
| Coupling | Tied to implementation | Decoupled from implementation |
| Debugging | Stack traces through framework | Plain code, easy to step through |
| Maintenance | Breaks when implementation changes | Survives refactoring |

**Trade-off:** Fakes require writing a small class. Mocks require a framework dependency. For this project, the fake classes are small, focused implementations (typically under 70 lines).

---

## Decision 4: Parameterized Integration Tests

**Decision:** `[Theory]` with `[MemberData]` for integration tests that run the same assertion against multiple beacon timing patterns.

```csharp
// SentryAnalyzerIntegrationTests.cs
public static IEnumerable<object[]> BeaconOffsetData()
{
    yield return new object[] { new[] { 0, 60, 122, 180 } };
    yield return new object[] { new[] { 0, 70, 140, 210 } };
}
```

**Rationale:** Parameterized tests handle varying beacon timing patterns in the real world — the detector must handle multiple patterns — validating cross-detector correlation with different timing inputs without duplicating test code.

**Trade-off:** Slightly harder to debug individual failures because the test method runs multiple times. Clearer than maintaining separate test methods for each pattern.

---

## Decision 5: Cancellation Tests

**Decision:** Explicit tests for cooperative cancellation at pipeline checkpoints.

**Rationale:** Cancellation tests ensure security analysts can abort analysis when they select the wrong file or when an urgent incident requires pivoting — keeping the desktop application responsive during long-running analysis.

| Scenario | Without Cancellation | With Cancellation |
|----------|---------------------|-------------------|
| Wrong file selected | Wait 30 minutes | Cancel in 2 seconds |
| Urgent incident | Stuck waiting | Pivot immediately |
| Resource contention | App hogs CPU/RAM | Free resources |

**Trade-off:** Cancellation checks add code to production methods. The checks are simple (`ThrowIfCancellationRequested`) and the operational benefit is significant.

---

## Decision 6: HMAC-SHA256 Evidence Integrity Tests

**Decision:** Tests that verify the HMAC signature on evidence packages is cryptographically valid.

**Rationale:** HMAC verification tests ensure security evidence is tamper-evident during incident review and handoff — the signature proves the manifest has not been modified since it was signed — enabling repeatable integrity checks on evidence packages.

**Security properties tested:**

1. **Integrity:** Manifest changes produce a different HMAC
2. **Authenticity:** Different signing keys produce different HMACs, ensuring key-dependent signatures
3. **Determinism:** Same input + same timestamp produces identical ZIP bytes

**Trade-off:** The tests depend on a specific HMAC implementation. If the hashing algorithm changes, the tests need updating. This is acceptable because the HMAC algorithm is a deliberate design choice, not an implementation detail.

---

## Decision 7: Inline Test Doubles (Not Shared Infrastructure)

**Decision:** Test doubles defined as private inner classes inside the test files that use them, rather than shared infrastructure files.

**Rationale:** Inline test doubles serve specific test file needs — `FakeDetector` and `EscalationTestDetector` support analyzer orchestration checks, `CrashingDetector` and `WorkingDetector` support robustness checks, and `BlockingDetector` supports WPF snapshot timing checks — keeping test code co-located with the tests that consume it.

**Trade-off:** If multiple test files needed the same double, it would need extraction. Currently only `FakeDialogService` is shared across WPF test files.

---

## Summary

| Decision | Security Principle | Maintenance Impact |
|----------|-------------------|--------------------|
| Three test categories | Defense in depth | More test code, fewer production bugs |
| Paired threshold tests | Symmetric failure testing | Twice the tests, calibrated boundaries |
| Fakes over mocks | Decoupled testing | Refactoring-friendly, easy to debug |
| Parameterized integration | Real-world timing patterns | One method, multiple scenarios |
| Cancellation tests | Operational responsiveness | Simple production code changes |
| HMAC integrity tests | Evidence tamper-evidence | Algorithm-coupled but deliberate |
| Inline test doubles | Co-located test code | No shared infrastructure to maintain |
