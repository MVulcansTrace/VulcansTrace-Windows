# Official Docs

This folder is the GitHub-facing documentation index for VulcansTrace.

It is designed for two audiences:

- Recruiters and hiring managers who need a fast understanding of what the project does and why it matters
- Technical reviewers who want to inspect the real implementation choices, supporting code, and test evidence

## Start Here

**[Executive Summary](./00-Executive-Summary/README.md)** -- a one-page overview of the project, what it proves, and where to go next. Read this first.

## Recommended Review Path

If you only have a few minutes, read these first:

1. [2 - Port Scan Detection](./02-Port-Scan-Detection/README.md): a strong example of the detection-engineering style used across the project
2. [8 - Risk Escalation](./08-Risk-Escalation/README.md): shows how separate findings are correlated into higher-confidence host risk
3. [9 - Evidence Packaging](./09-Evidence-Packaging/README.md): shows how analysis output is turned into signed investigator-facing artifacts
4. [12 - WPF UI](./12-WPF-UI/README.md): shows how the system is surfaced in a desktop product workflow

If you want the full end-to-end story, read in this order:

1. [1 - Log Parsing](./01-Log-Parsing/README.md)
2. [2 - Port Scan Detection](./02-Port-Scan-Detection/README.md)
3. [3 - Beaconing Detection](./03-Beaconing-Detection/README.md)
4. [4 - Lateral Movement Detection](./04-Lateral-Movement-Detection/README.md)
5. [5 - Flood Detection](./05-Flood-Detection/README.md)
6. [6 - Policy Violation Detection](./06-Policy-Violation-Detection/README.md)
7. [7 - Novelty Detection](./07-Novelty-Detection/README.md)
8. [8 - Risk Escalation](./08-Risk-Escalation/README.md)
9. [9 - Evidence Packaging](./09-Evidence-Packaging/README.md)
10. [10 - Intensity Profiles](./10-Intensity-Profiles/README.md)
11. [11 - Automated Tests](./11-Automated-Tests/README.md)
12. [12 - WPF UI](./12-WPF-UI/README.md)

## Supplemental

- [13 - Performance Benchmark](./13-Performance-Benchmark/README.md): synthetic realistic-volume benchmark with embedded attack patterns

## What These Docs Cover

- How raw Windows Firewall logs are parsed into structured records
- How individual detectors identify suspicious patterns from network telemetry
- How higher-confidence host risk is inferred from correlated findings
- How intensity profiles change cost, noise, and completeness trade-offs
- How results are packaged into evidence artifacts for reporting and handoff
- How the WPF application exposes the workflow to an analyst
- How the automated test suite supports confidence in the implementation

## How The Case Studies Are Organized

Each numbered folder uses a consistent entry-point pattern, while individual deep-dive pages vary by subsystem so the documentation fits the code rather than forcing every topic into the same security framework.

- `README.md`: the entry point for that topic
- `*-Summary`: accessible snapshots, quick references, and concise overviews
- `*-In-Depth`: technical walkthroughs, design decisions, worked examples, limitations, standards context, and implementation evidence where they are relevant

## Best Entry Points By Interest

- Parser and data-ingestion work: [1 - Log Parsing](./01-Log-Parsing/README.md)
- Detection engineering: [2 - Port Scan Detection](./02-Port-Scan-Detection/README.md)
- Statistical signal analysis: [3 - Beaconing Detection](./03-Beaconing-Detection/README.md)
- Threat correlation: [8 - Risk Escalation](./08-Risk-Escalation/README.md)
- Evidence and reporting: [9 - Evidence Packaging](./09-Evidence-Packaging/README.md)
- Product and UI engineering: [12 - WPF UI](./12-WPF-UI/README.md)
- Quality and verification: [11 - Automated Tests](./11-Automated-Tests/README.md)

## Grounding Principle

These documents were written to stay close to the actual code and tests in the repository. They are meant to explain the implementation clearly, not to oversell it.
