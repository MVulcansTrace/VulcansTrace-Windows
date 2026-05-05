# Profile Pipeline Algorithm

---

## The Security Problem

Firewall log analysis needs different sensitivity levels depending on the operational context. During a breach, analysts need every possible indicator. During routine monitoring, they need high-confidence findings that do not waste their time. The configuration that connects these contexts involves 20+ parameters across six detectors. Asking analysts to tune each one individually would be error-prone and inconsistent.

---

## Implementation Overview

A four-step pipeline implemented in [SentryAnalyzer.cs](../../../../VulcansTrace.Engine/SentryAnalyzer.cs) and [AnalysisProfileProvider.cs](../../../../VulcansTrace.Engine/Configuration/AnalysisProfileProvider.cs):

```text
Step A: Select Profile -------- Why: Map operational context to thresholds
    |
    v
Step B: Run Detectors --------- Why: Apply thresholds to log entries
    |
    v
Step C: Escalate Findings ----- Why: Correlate cross-detector signals
    |
    v
Step D: Filter by Severity ---- Why: Control output volume by context
    |
    v
AnalysisResult with context-appropriate findings
```

---

## Step A: Profile Selection

**Process:** The analyst selects an `IntensityLevel` (Low, Medium, High). The `AnalysisProfileProvider` factory returns a fully configured `AnalysisProfile` record.

```csharp
var profile = overrideProfile ?? _profileProvider.GetProfile(intensity);
```

The factory ensures all 20+ threshold values are set consistently across every detector — preventing mismatched configurations where one detector runs aggressively while another runs conservatively on the same data.

**What gets configured:**

| Category | What Varies by Profile | What Stays Constant |
|----------|----------------------|-------------------|
| Detector enable flags | `EnableNovelty` (false on Low, true on Medium/High) | All 5 others always enabled |
| Thresholds | PortScanMinPorts (30/15/8), FloodMinEvents (400/200/100), LateralMinHosts (6/4/3), BeaconMinEvents (8/6/4), BeaconStdDevThreshold (3.0/5.0/8.0), BeaconMinIntervalSeconds (60/30/10) | All time windows (PortScanWindowMinutes=5, FloodWindowSeconds=60, LateralWindowMinutes=10, BeaconMaxIntervalSeconds=900), BeaconMaxSamplesPerTuple=200, BeaconMinDurationSeconds=120, BeaconTrimPercent=0.1, PortScanMaxEntriesPerSource=unbounded |
| Policy ports | Never changes | AdminPorts=[445, 3389, 22], DisallowedOutboundPorts=[21, 23, 445] |
| Output filtering | `MinSeverityToShow` (High/Medium/Info) | — |

**Rationale:** Thresholds vary but time windows stay constant because attacks do not get faster when you select High intensity. What changes is the threshold of what counts as suspicious — not the time window in which it happens. Policy ports are constant because they represent organizational decisions (which ports are administrative, which outbound ports are disallowed), not sensitivity tuning.

---

## Step B: Detector Execution

**Process:** The same `AnalysisProfile` instance is passed to each configured detector. In the built-in analyzer configuration, that means all six detectors read the thresholds they need and produce findings.

```csharp
foreach (var detector in _detectors)
{
    cancellationToken.ThrowIfCancellationRequested();
    var detected = detector.Detect(entries, profile, cancellationToken);
    allFindings.AddRange(detected);
}
```

> **Note:** Simplified for clarity — the actual implementation wraps each detector call in `try/catch` for fault isolation so a crashed detector does not kill the entire run, and collects warnings from detectors that implement `IProducesWarnings`.

Uniform dispatch ensures every detector must operate on the same sensitivity context — preventing a situation where PortScan detects at High sensitivity while Beaconing runs at Low sensitivity on the same analysis run.

**Each detector's severity assignment:**

| Detector | Severity | Visible On |
|----------|----------|-----------|
| PortScan | Medium | Medium, High |
| Flood | High | Low, Medium, High |
| LateralMovement | High | Low, Medium, High |
| Beaconing | Medium | Medium, High |
| PolicyViolation | High | Low, Medium, High |
| Novelty | Low | High only |

**Key detail:** On Low profile, PortScan and Beaconing findings (Medium severity) are filtered out unless the RiskEscalator promotes them to Critical in the next step. Flood, LateralMovement, and PolicyViolation findings (High severity) always survive because High >= `MinSeverityToShow` on all profiles.

---

## Step C: Risk Escalation

**Process:** After all detectors finish, the `RiskEscalator` groups findings by source host. If a host has both Beaconing and LateralMovement findings, every finding for that host is promoted to `Severity.Critical`.

```csharp
var escalated = _riskEscalator.Escalate(allFindings);
```

The escalation step ensures Beaconing + LateralMovement on the same host means C2 communication plus active internal spread — producing the highest-confidence compromise signal in the pipeline.

**Host-level escalation scope:**

```text
Host 192.168.1.50 has:
├── Beaconing finding (Medium) → escalated to Critical
├── LateralMovement finding (High) → escalated to Critical
├── PortScan finding (Medium) → escalated to Critical
└── Novelty finding (Low) → escalated to Critical
```

Every finding on a compromised host gets escalated — not just the triggering pair. This ensures analysts see the complete picture when correlation indicates compromise.

> **Important side effect:** Because *all* findings on the host become Critical, profile differences are masked for multi-behavior hosts. A PortScan finding that would normally be filtered on Low profile survives because it was escalated along with the correlated Beaconing + LateralMovement pair. When comparing profile sensitivity, use isolated source IPs (as in `IntensityComparisonTests.cs`) or inspect pre-escalation output.

---

## Step D: Severity Filtering

**Process:** After escalation, findings are filtered by `MinSeverityToShow` from the profile.

```csharp
result.AddFindings(
    escalated.Where(f => f.Severity >= profile.MinSeverityToShow));
```

The severity filter runs after escalation because filtering first would hide the Medium-severity Beaconing finding that triggers the correlation — ensuring that cross-detector compromise indicators always reach the analyst regardless of profile selection.

**Filter effect per profile:**

| Profile | MinSeverityToShow | Shows | Filters Out |
|---------|-------------------|-------|-------------|
| Low | High | High, Critical | Info, Low, Medium |
| Medium | Medium | Medium, High, Critical | Info, Low |
| High | Info | Everything | Nothing |

**Critical insight:** Even on Low profile, a host with Beaconing + LateralMovement findings has all findings escalated to Critical (Critical >= High), so they survive. Conservative output does not mean hiding compromise — it means hiding low-confidence noise.

---

## Complexity Analysis

| Metric | Value | Why |
|--------|-------|-----|
| Profile creation | O(1) | Simple Factory with switch expression |
| Detector execution | Depends on the configured detectors | The profile system itself is constant-time here; detector work dominates total cost |
| Risk escalation | O(n) | Group by host, check category set |
| Severity filtering | O(n) | Single Where clause |

---

## Implementation Evidence

- [AnalysisProfileProvider.cs](../../../../VulcansTrace.Engine/Configuration/AnalysisProfileProvider.cs): factory with Low/Medium/High profiles
- [AnalysisProfile.cs](../../../../VulcansTrace.Engine/AnalysisProfile.cs): immutable record with 20+ properties
- [SentryAnalyzer.cs](../../../../VulcansTrace.Engine/SentryAnalyzer.cs): pipeline orchestrator — profile selection, detector dispatch, escalation, filtering
- [RiskEscalator.cs](../../../../VulcansTrace.Engine/RiskEscalator.cs): cross-detector correlation and severity promotion
- [AnalysisProfileProviderTests.cs](../../../../VulcansTrace.Tests/Engine/AnalysisProfileProviderTests.cs): 11 test methods verifying thresholds, enable flags, monotonic sensitivity, constant policy ports
- [SentryAnalyzerTests.cs](../../../../VulcansTrace.Tests/Engine/SentryAnalyzerTests.cs): severity filtering across all three intensity levels
- [IntensityComparisonTests.cs](../../../../VulcansTrace.Tests/Engine/IntensityComparisonTests.cs): end-to-end profile behavior using isolated attacker IPs (9 tests: theory data + individual detector verification)
- [SampleData.cs](../../../../VulcansTrace.Wpf/SampleData.cs): synthetic firewall log with isolated IPs, used by the WPF "Load demo data" link

---

## Operational Impact

- Enables one-switch sensitivity control across six detectors and 20+ parameters — analysts choose Low/Medium/High instead of tuning individual thresholds
- Supports escalation-before-filter ordering so that cross-detector compromise signals survive even on the most conservative profile
- Provides immutable profiles that prevent any detector from accidentally changing thresholds mid-analysis
---

## Security Takeaways

1. **Factory centralizes configuration** — all 20+ parameters set in one place, all detectors receive consistent settings
2. **Escalation-before-filter is a security property** — it ensures cross-detector compromise signals survive conservative output settings
3. **Policy ports are not sensitivity knobs** — they represent organizational rules and should not change with the intensity level
4. **Time windows are constant for a reason** — attack speed is a property of the attacker, not the defender's configuration
5. **Immutable profiles prevent mutation** — no detector can accidentally change thresholds mid-analysis
