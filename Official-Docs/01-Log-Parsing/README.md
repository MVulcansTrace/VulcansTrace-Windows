# Log Parsing

This folder contains technical documentation for the Windows Firewall log parser.

Documentation is organized for two audiences:

- Quick-review readers who need a fast summary of the subsystem and why it matters
- Technical reviewers who want to inspect the parsing pipeline, validation strategy, and trade-offs

## Start Here

- [Expertise Snapshot](./Log-Parsing-Summary/Expertise-Snapshot.md): 1-page overview for quick review
- [Why This Matters](./Log-Parsing-In-Depth/Why-This-Matters.md): project context, business value, and security framing
- [Parsing Algorithm](./Log-Parsing-In-Depth/Core-Logic-Breakdown/Parsing-Algorithm.md): the core parser pipeline and validation flow
- [Design Decisions](./Log-Parsing-In-Depth/Design-Decisions.md): why the parser favors resilience, traceability, and strict validation
- [Code Patterns](./Log-Parsing-In-Depth/Code-Patterns.md): the main implementation patterns used throughout the parser
- [Attack Scenario](./Log-Parsing-In-Depth/Attack-Scenario.md): a worked example showing why fail-soft parsing matters in a real investigation
- [Evasion and Limitations](./Log-Parsing-In-Depth/Evasion-and-Limitations.md): constraints and extension paths
- [Log Management and Standards](./Log-Parsing-In-Depth/Log-Management-and-Standards.md): ingestion, validation, and evidence-quality standards context

## System Capabilities

- Data ingestion engineering: turning messy firewall text into structured `LogEntry` records
- Security judgment: validating hostile inputs without losing good evidence
- Forensic thinking: preserving raw lines, error context, and traceability for later review
- Communication: explaining parsing logic and trade-offs in language that balances accessibility with technical precision

## Implementation Evidence

- [WindowsFirewallLogParser.cs](../../VulcansTrace.Core/Parsing/WindowsFirewallLogParser.cs): timestamp parsing, validation gates, fail-soft loop, and record creation
- [LogEntry.cs](../../VulcansTrace.Core/LogEntry.cs): immutable parsed event model with raw-line preservation
- [WindowsFirewallLogParserTests.cs](../../VulcansTrace.Tests/Core/WindowsFirewallLogParserTests.cs): sample-log parsing, malformed lines, placeholders, IPv6, timestamp variants, and parse-error behavior

