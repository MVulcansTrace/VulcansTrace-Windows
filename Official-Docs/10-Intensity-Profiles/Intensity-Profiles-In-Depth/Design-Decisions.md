# Design Decisions

Every major choice in the intensity profile system has a security rationale, an analyst-facing impact, and a clear trade-off.

---

## Decision 1: Simple Factory Over Manual Configuration

**Decision:** A `AnalysisProfileProvider` class that maps an enum to a fully configured profile, instead of requiring analysts to set 20+ individual parameters.

**Rationale:** The factory pattern prevents scattered configuration from creating inconsistency — one detector running aggressively while another runs conservatively on the same analysis — ensuring every detector receives identical sensitivity settings from a single source of truth.

**Trade-off:** The three built-in profiles cover the most common scenarios. Custom overrides are supported via the `overrideProfile` parameter using the `with` expression, but most teams will use Low, Medium, or High directly.

---

## Decision 2: Thresholds Vary, Time Windows Stay Constant

**Decision:** Detection thresholds vary by profile. Time windows are constant across all profiles.

**Why:** Time windows are kept constant because the speed of an attack is a property of the attacker, not the defender's intensity selection — ensuring the time window always matches the actual attack pattern regardless of how aggressively we are detecting.

```text
PortScanMinPorts:  30 (Low) → 15 (Medium) → 8 (High)    ← varies
PortScanWindowMinutes:  5 → 5 → 5                         ← constant
```

**Trade-off:** Advanced users who want shorter windows for aggressive detection must create a custom override profile.

---

## Decision 3: Policy Ports Never Change

**Decision:** `AdminPorts` ([445, 3389, 22]) and `DisallowedOutboundPorts` ([21, 23, 445]) are identical across Low, Medium, and High profiles.

**Rationale:** Policy ports represent organizational decisions about which services are administrative and which outbound connections are disallowed. Keeping them constant separates policy from sensitivity tuning so that an analyst switching to High does not accidentally start detecting on non-administrative ports.

**Trade-off:** Organizations that use WinRM (5985/5986) or DCOM (135) for lateral movement must create custom override profiles. The default set covers ports commonly associated with SMB, RDP, and SSH, but the detector itself remains port-based rather than protocol-aware.

---

## Decision 4: Escalation Before Filtering

**Decision:** `RiskEscalator.Escalate()` runs on all findings before `MinSeverityToShow` filters the output.

**Rationale:** Ordering the pipeline this way prevents filtering from hiding Medium-severity Beaconing findings before they could be correlated with LateralMovement — ensuring that cross-detector compromise indicators (Beaconing + LateralMovement = Critical) always reach the analyst regardless of profile selection.

```text
Correct order:  Select → Detect → Escalate → Filter
Wrong order:    Detect → Filter → Escalate  ← Medium Beaconing filtered before correlation
```

**Trade-off:** On Low profile, a host with only a Medium-severity Beaconing finding (no LateralMovement) gets filtered out. Medium-severity findings only survive the conservative filter when escalated through correlation; standalone High-severity findings from Flood, LateralMovement, and PolicyViolation detectors also survive independently.

---

## Decision 5: Novelty Disabled on Low

**Decision:** `EnableNovelty` is `false` on Low profile, `true` on Medium and High. This is the only detector enable flag that varies across profiles.

**Rationale:** Novelty is disabled on Low because singleton external `(DstIp, DstPort)` targets in the current dataset are inherently noisy — every new external service, software update check, or CDN rotation can generate Novelty findings — keeping conservative output clean for low-noise triage where false positives damage credibility.

**Trade-off:** On Low profile, a genuinely novel connection to a suspicious destination is not reported — and since the Novelty detector is disabled, no Novelty finding is produced at all. If that same host also shows both Beaconing and LateralMovement, the escalation mechanism promotes those correlated findings to Critical, which survives the Low profile filter.

---

## Decision 6: MinSeverityToShow Ranges from High to Info

**Decision:** Low profile shows High+Critical only, Medium shows Medium+, High shows everything including Info.

**Rationale:** These severity gates map directly to the operational context — executives need high-confidence findings only, routine monitoring needs balanced coverage, and incident response needs complete visibility — matching output volume to analyst capacity and audience expectations.

**Trade-off:** High profile's `MinSeverityToShow = Info` is forward-looking. Currently no detector emits Info-severity findings, so the Info level is unused. High and Medium differ in the severity gate only for Low-severity Novelty findings (visible at High, filtered at Medium); the primary practical difference between High and Medium is in the detection thresholds.

---

## Decision 7: Immutable Profile Records

**Decision:** `AnalysisProfile` is a `sealed record` with `init`-only properties. No detector can modify it.

**Rationale:** Immutability prevents shared mutable configuration bugs — one detector incrementing a threshold would affect all subsequent detectors — guaranteeing that every detector operates on the same configuration it received at the start of the analysis.

**Trade-off:** Custom overrides require creating a new record via the `with` expression rather than mutating the existing one. This is intentional — it preserves the original profile for comparison.

---

## Decision 8: Override via `with` Expression

**Decision:** `SentryAnalyzer.Analyze()` accepts an optional `overrideProfile` parameter. When provided, it bypasses the factory entirely.

**Rationale:** The override mechanism supports targeted modifications (e.g., raising `PortScanMaxEntriesPerSource` for very large logs) without creating an entirely new profile — enabling advanced customization while keeping the default path simple.

```csharp
var baseProfile = provider.GetProfile(IntensityLevel.High);
var custom = baseProfile with { PortScanMaxEntriesPerSource = 50000 };
```

**Trade-off:** The WPF UI currently only supports the `PortScanMaxEntriesPerSource` override. Full custom profile editing would require a configuration UI.

---

## Summary

| Decision | Security Principle | Operational Impact |
|----------|-------------------|-------------------|
| Simple Factory | Centralized configuration | Consistency across detectors |
| Vary thresholds, constant windows | Separate sensitivity from attack speed | Meaningful tuning without distorting time |
| Constant policy ports | Policy vs. sensitivity separation | Analyst does not accidentally change organizational rules |
| Escalate before filter | Correlation visibility | Compromise indicators survive conservative profiles |
| Novelty off on Low | Noise control | Cleaner low-noise triage |
| Severity gate by context | Output volume control | Matches analyst capacity |
| Immutable records | Configuration safety | No mid-analysis mutation |
| Override via `with` | Extensibility | Advanced customization without factory changes |
