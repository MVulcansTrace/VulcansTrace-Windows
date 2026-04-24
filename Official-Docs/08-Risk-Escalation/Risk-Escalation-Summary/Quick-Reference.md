# Quick Reference

---

## Correlation Algorithm (4 Stages)

Stage 1: Guard — return empty if no findings
Stage 2: Group — GroupBy SourceHost (null normalized to empty string)
Stage 3: Check — HashSet of categories, look for Beaconing AND LateralMovement
Stage 4: Escalate — `f with { Severity = Severity.Critical }` for all non-Critical in matching groups

---

## Correlation Rule

| Condition | Result |
|---|---|
| Beaconing + LateralMovement (same host) | Escalate all non-Critical → Critical |
| Beaconing only | No escalation |
| LateralMovement only | No escalation |
| Any other combination | No escalation |

---

## Downstream Pipeline

```text
Detectors → RiskEscalator → MinSeverityToShow filter → Output
               ↑                    ↑
          Escalation           Severity threshold
         happens here        applied here (after)
```

---

## Finding Structure

| Field | Type | Escalation Impact |
|---|---|---|
| Id | Guid | Preserved |
| Category | string | Preserved |
| Severity | Severity | **Changed to Critical** |
| SourceHost | string | Preserved (correlation key) |
| Target | string | Preserved |
| TimeRangeStart | DateTime | Preserved |
| TimeRangeEnd | DateTime | Preserved |
| ShortDescription | string | Preserved |
| Details | string | Preserved |

---

## Severity Enum

| Level | Ordinal | Escalation Behavior |
|---|---|---|
| Info | 0 | Escalated to Critical if host matches |
| Low | 1 | Escalated to Critical if host matches |
| Medium | 2 | Escalated to Critical if host matches |
| High | 3 | Escalated to Critical if host matches |
| Critical | 4 | No change (guard: `< Critical`) |

---

## MinSeverityToShow Thresholds

| Profile | MinSeverityToShow | Escalated Critical Passes? |
|---|---|---|
| Low | High | Yes (Critical >= High) |
| Medium | Medium | Yes (Critical >= Medium) |
| High | Info | Yes (Critical >= Info) |

---

## Complexity

| Metric | Value |
|---|---|
| Time | O(n) |
| Space | O(n) |
| Per-group lookup | O(1) — HashSet |
| Escalation per finding | O(1) — `with` copy |

---

## Test Coverage

> Short labels for readability — actual method names follow the `Escalate_With...` pattern.

| Test | Full Method Name | What It Validates |
|---|---|---|
| EmptyFindings | `Escalate_WithEmptyFindings_ReturnsEmptyList` | Guard clause returns empty |
| BeaconingOnly | `Escalate_WithBeaconingOnly_NoEscalation` | Single category does not escalate |
| LateralOnly | `Escalate_WithLateralMovementOnly_NoEscalation` | Single category does not escalate |
| BothOnSameHost | `Escalate_WithBeaconingAndLateralMovementOnSameHost_EscalatesToCritical` | Core escalation scenario |
| MixedFindings | `Escalate_WithMixedFindings_EscalatesOnlyCorrectHost` | Selective escalation across hosts |
| AlreadyCritical | `Escalate_WithAlreadyCriticalFindings_PreservesCritical` | Already-Critical findings remain Critical |
| EmptySourceHost | `Escalate_WithEmptySourceHost_DoesNotCrash` | Null/empty hosts grouped together |
| DifferentCasing | `Escalate_WithDifferentCategoryCasing_EscalatesCorrectly` | Case-insensitive matching works |
| ThirdCategoryOnCompromisedHost | `Escalate_WithThirdCategoryOnCompromisedHost_EscalatesAllFindings` | All findings escalated, not just triggers |

---

## File References

| File | Purpose |
|---|---|
| RiskEscalator.cs | Correlation engine implementation |
| SentryAnalyzer.cs | Pipeline wiring (escalation before filter) |
| Finding.cs | Immutable record (9 properties) |
| Severity.cs | Ordered enum (Info through Critical) |
| AnalysisProfile.cs | MinSeverityToShow configuration |
| RiskEscalatorTests.cs | 9 unit tests |
