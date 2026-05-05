# VulcansTrace

![.NET 9](https://img.shields.io/badge/.NET-9-512BD4)
![Build](https://github.com/MVulcansTrace/VulcansTrace-Windows/actions/workflows/build.yml/badge.svg)
![Tests](https://img.shields.io/badge/tests-266%2F266-brightgreen)
![License](https://img.shields.io/badge/license-Apache%202.0-blue)

VulcansTrace is a Windows desktop security analysis tool that parses Windows Firewall logs, runs multiple behavioral detectors, correlates related findings, and packages investigation results into HMAC-signed evidence exports. **All analysis runs locally, logs never leave the machine.**

![VulcansTrace Architecture](./VulcansTrace-Infograph.png)

This repository is structured to be easy for both recruiters and technical reviewers to inspect:

- The code shows the production-facing implementation across parsing, detection, evidence packaging, testing, and WPF UI layers.
- [Official-Docs](./Official-Docs/README.md) contains recruiter-friendly and technical case studies for the main parts of the system.

> **Portfolio edition note:** VulcansTrace began as a local learning/build project in 2024 and evolved through iterative development, bug fixes, refactors, test expansion, UI work, documentation corrections, and portfolio packaging. This repository is a cleaned public portfolio edition organized for reviewability; the visible history is curated to present the final architecture, runnable code, tests, and documentation clearly.

## Why This Project Stands Out

- End-to-end ownership: raw firewall text goes in, structured findings and integrity-protected investigation artifacts come out.
- Security focus: the project centers on threat detection, forensic traceability, and honest handling of trade-offs and limitations.
- Strong engineering proof: the solution builds cleanly and the automated test suite covers parser, detector, evidence, and WPF workflows.
- Clear communication: the documentation is organized for both quick recruiter review and deeper engineering evaluation.

## Core Capabilities

- Windows Firewall log parsing with validation, raw-line preservation, and parse-error reporting
- Detection for port scans, beaconing, lateral movement, flood behavior, policy violations, and novelty
- Cross-signal risk escalation when findings align on the same host
- Intensity profiles that trade off completeness, cost, and analyst noise
- Evidence export in multiple formats with integrity support for investigator handoff
- WPF desktop UI with MVVM patterns, asynchronous analysis, filtering, and export workflow

## Architecture

- [VulcansTrace.Core](./VulcansTrace.Core): domain models, parsing, and shared security utilities
- [VulcansTrace.Engine](./VulcansTrace.Engine): detectors, risk escalation, profile configuration, and analysis orchestration
- [VulcansTrace.Evidence](./VulcansTrace.Evidence): evidence builder plus Markdown, HTML, and CSV formatters
- [VulcansTrace.Wpf](./VulcansTrace.Wpf): Windows desktop UI built with WPF and MVVM-style ViewModels
- [VulcansTrace.Tests](./VulcansTrace.Tests): xUnit coverage across core logic, engine behavior, evidence packaging, and UI workflows
- [Official-Docs](./Official-Docs/README.md): GitHub-facing portfolio documentation for the major subsystems

## Start Here

**New to this repo?** Read the [Executive Summary](./Official-Docs/00-Executive-Summary/README.md) first (about 60 seconds).

If you are reviewing this repo quickly, use this path:

1. Read the [Executive Summary](./Official-Docs/00-Executive-Summary/README.md) for a one-page overview.
2. Read [Official-Docs](./Official-Docs/README.md) for the full portfolio index.
3. Open [Port Scan Detection](./Official-Docs/02-Port-Scan-Detection/README.md) for a representative detector case study.
4. Open [Risk Escalation](./Official-Docs/08-Risk-Escalation/README.md) to see how findings are correlated into higher-confidence host risk.
5. Open [Evidence Packaging](./Official-Docs/09-Evidence-Packaging/README.md) to see how results are turned into shareable HMAC-signed artifacts.

## Running The Project

This repository targets `.NET 9` and the desktop application is Windows-only because it uses WPF.

```powershell
dotnet build VulcansTrace.sln
dotnet test VulcansTrace.Tests\VulcansTrace.Tests.csproj
dotnet run --project VulcansTrace.Wpf
```

## Technical Proof

- Solution entry point: [VulcansTrace.sln](./VulcansTrace.sln)
- Desktop app: [VulcansTrace.Wpf](./VulcansTrace.Wpf)
- Detection engine: [VulcansTrace.Engine](./VulcansTrace.Engine)
- Evidence packaging: [VulcansTrace.Evidence](./VulcansTrace.Evidence)
- Tests: [VulcansTrace.Tests](./VulcansTrace.Tests)

Recent validation in this workspace:

- `dotnet build VulcansTrace.sln --configuration Release --no-restore` succeeded with `0` warnings and `0` errors on May 5, 2026.
- `dotnet test VulcansTrace.Tests\\VulcansTrace.Tests.csproj --configuration Release --no-restore --verbosity minimal` passed `266/266` tests on May 5, 2026.
- `dotnet list VulcansTrace.sln package --vulnerable --include-transitive` reported no vulnerable packages on May 5, 2026.
- Synthetic realistic-volume benchmark (50K lines, High intensity): 482 ms, 20 findings across all 6 detectors, zero warnings. See [Performance Benchmark](./Official-Docs/13-Performance-Benchmark/README.md).

## Live Demos

### Core Analysis Workflow

![Core Analysis Workflow](gifs/01_Core_analysis_gif.gif)

### Intensity Profile Deep Dive

![Intensity Profile Deep Dive](gifs/02_Intensity_deep_dive_gif.gif)

### Evidence Export

![Evidence Export](gifs/03_Evidence_export_gif.gif)

## Documentation Map

- [Executive Summary](./Official-Docs/00-Executive-Summary/README.md) - one-page overview for new reviewers
- [1 - Log Parsing](./Official-Docs/01-Log-Parsing/README.md)
- [2 - Port Scan Detection](./Official-Docs/02-Port-Scan-Detection/README.md)
- [3 - Beaconing Detection](./Official-Docs/03-Beaconing-Detection/README.md)
- [4 - Lateral Movement Detection](./Official-Docs/04-Lateral-Movement-Detection/README.md)
- [5 - Flood Detection](./Official-Docs/05-Flood-Detection/README.md)
- [6 - Policy Violation Detection](./Official-Docs/06-Policy-Violation-Detection/README.md)
- [7 - Novelty Detection](./Official-Docs/07-Novelty-Detection/README.md)
- [8 - Risk Escalation](./Official-Docs/08-Risk-Escalation/README.md)
- [9 - Evidence Packaging](./Official-Docs/09-Evidence-Packaging/README.md)
- [10 - Intensity Profiles](./Official-Docs/10-Intensity-Profiles/README.md)
- [11 - Automated Tests](./Official-Docs/11-Automated-Tests/README.md)
- [12 - WPF UI](./Official-Docs/12-WPF-UI/README.md)
- [13 - Performance Benchmark](./Official-Docs/13-Performance-Benchmark/README.md)
- [Security Policy](./SECURITY.md)

## What Reviewers Should Expect

- Honest documentation that explains both strengths and current limitations
- A codebase organized by responsibility instead of a single monolith
- Tests that exercise detectors, integration paths, evidence formatting, and desktop workflows
- A portfolio presentation that stays grounded in the current implementation rather than inflated claims
