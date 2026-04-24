# Code Patterns

---

## Pattern 1: Service Composition via Constructor Injection

```csharp
public sealed class EvidenceBuilder
{
    private readonly IntegrityHasher _hasher;
    private readonly CsvFormatter _csvFormatter;
    private readonly MarkdownFormatter _markdownFormatter;
    private readonly HtmlFormatter _htmlFormatter;

    public EvidenceBuilder(
        IntegrityHasher hasher,
        CsvFormatter csvFormatter,
        MarkdownFormatter markdownFormatter,
        HtmlFormatter htmlFormatter)
    {
        _hasher = hasher;
        _csvFormatter = csvFormatter;
        _markdownFormatter = markdownFormatter;
        _htmlFormatter = htmlFormatter;
    }
}
```

**Rationale:** Constructor-injected formatters enable each formatter has its own escaping rules and test surface, for the purpose of enabling independent testing, explicit dependencies, and formatter replacement. Adding a new output format would still require builder changes, but the responsibilities remain separated instead of being mixed into one large method.

**Not a classic Builder:** This is service composition, not the GoF Builder pattern. There is no fluent API or step-by-step construction. The builder orchestrates injected services through a fixed 4-step pipeline.

---

## Pattern 2: Pluggable Formatter Pipeline

```text
AnalysisResult ──→ CsvFormatter.ToCsv()               → string
               ──→ HtmlFormatter.ToHtml()             → string
               ──→ MarkdownFormatter.ToMarkdown()     → string
               ──→ Raw log string                     → string
                                 ↓
               EvidenceBuilder: Encoding.UTF8.GetBytes() → byte[]
                                 ↓
               findings.csv · report.html · summary.md · log.txt
```

**Rationale:** Separate formatter classes provide each output format has distinct escaping requirements, structure, and audience, for the purpose of keeping CSV quoting, HTML encoding, and Markdown escaping isolated in testable units rather than mixed into the builder.

---

## Pattern 3: CSV Injection Prevention

```csharp
private static string Escape(string value)
{
    if (value == null) return "";
    var sanitized = value;
    if (!string.IsNullOrEmpty(sanitized))
    {
        var first = sanitized[0];
        if (first == '=' || first == '+' || first == '-' || first == '@')
        {
            sanitized = "'" + sanitized;
        }
    }

    if (sanitized.Contains('"') || sanitized.Contains(',') || sanitized.Contains('\n') || sanitized.Contains('\r'))
    {
        var escaped = sanitized.Replace("\"", "\"\"");
        return $"\"{escaped}\"";
    }

    return sanitized;
}
```

**Rationale:** Formula injection prevention protects CSV files opened in Excel or Google Sheets interpret `=`, `+`, `-`, and `@` as formula triggers, for the purpose of preventing an attacker-controlled finding from executing arbitrary formulas on an analyst's workstation.

| Dangerous Prefix | Attack Example | Prevention |
|-----------------|---------------|-----------|
| `=` | `=1+1` | Prefixed with `'` |
| `+` | `+1|cmd` | Prefixed with `'` |
| `-` | `-1+1` | Prefixed with `'` |
| `@` | `@SUM(...)` | Prefixed with `'` |

---

## Pattern 4: XSS Prevention via HTML Encoding

```csharp
foreach (var f in result.Findings)
{
    sb.AppendLine("<tr>");
    sb.AppendLine($"<td>{System.Net.WebUtility.HtmlEncode(f.Category)}</td>");
    sb.AppendLine($"<td>{f.Severity}</td>");  // enum — not attacker-controlled
    sb.AppendLine($"<td>{System.Net.WebUtility.HtmlEncode(f.SourceHost)}</td>");
    sb.AppendLine($"<td>{System.Net.WebUtility.HtmlEncode(f.Target)}</td>");
    sb.AppendLine($"<td>{f.TimeRangeStart:O}</td>");
    sb.AppendLine($"<td>{f.TimeRangeEnd:O}</td>");
    sb.AppendLine($"<td>{System.Net.WebUtility.HtmlEncode(f.ShortDescription)}</td>");
    sb.AppendLine("</tr>");
}
```

**Rationale:** HTML encoding in every user-provided field prevents in the HTML report because findings contain attacker-controlled data (IP addresses, descriptions), for the purpose of preventing cross-site scripting when the report is opened in a browser.

Four finding fields are encoded inline: `Category`, `SourceHost`, `Target`, `ShortDescription`. Warning text is also encoded. `Severity` is an enum and not attacker-controlled, so it renders as-is.

---

## Pattern 5: Markdown Special Character Escaping

```csharp
private static string Escape(string value)
{
    if (string.IsNullOrEmpty(value))
        return string.Empty;

    // Replace newlines to avoid breaking table rows
    var sanitized = value.Replace("\r\n", "<br>").Replace("\n", "<br>");

    // Escape markdown special characters used in tables and emphasis
    string[] specials = ["\\", "|", "*", "_", "`", "[", "]"];
    foreach (var s in specials)
    {
        sanitized = sanitized.Replace(s, $"\\{s}");
    }

    return sanitized;
}
```

**Rationale:** Markdown escaping ensures pipe characters break GFM table formatting and asterisks inject unintended bold/italic markup, for the purpose of ensuring the Markdown report renders correctly on GitHub and in any GFM viewer.

---

## Pattern 6: Timestamp Normalization Pipeline

```text
Input DateTime
    ↓
1. If Kind == Local       → ToUniversalTime()
2. If Kind == Unspecified → Treat as UTC
3. If Kind == Utc         → Use directly
    ↓
4. If < 1980-01-01        → Clamp to 1980-01-01
5. If > 2107-12-31        → Clamp to 2107-12-31 23:59:58
    ↓
Normalized UTC DateTime (ZIP-safe)
```

**Rationale:** The normalization pipeline handles the ZIP format only supports a limited date range and different `DateTimeKind` values produce different binary representations, for the purpose of ensuring deterministic bundle metadata timestamps across machines, time zones, and edge-case inputs. This normalization applies to ZIP entry times and `manifest.json` `createdUtc`, while formatter output preserves the timestamps already present in `AnalysisResult`.

---

## Pattern 7: Atomic MemoryStream ZIP Creation

```csharp
using var ms = new MemoryStream();
using (var zip = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
{
    // Add all 6 entries
}
return ms.ToArray();
```

**Rationale:** ZIP creation on a `MemoryStream` ensures the archive must be complete before it reaches the filesystem, for the purpose of preventing partial writes — if any step fails, no incomplete file is left behind.

---

## Pattern 8: Deterministic Build via Ordering

```csharp
// Simplified — actual code inlines Encoding.UTF8.GetBytes() + formatter calls
var files = new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase)
{
    ["findings.csv"]  = Encoding.UTF8.GetBytes(_csvFormatter.ToCsv(result)),
    ["log.txt"]       = Encoding.UTF8.GetBytes(rawLog ?? string.Empty),
    ["report.html"]   = Encoding.UTF8.GetBytes(_htmlFormatter.ToHtml(result)),
    ["summary.md"]    = Encoding.UTF8.GetBytes(_markdownFormatter.ToMarkdown(result))
};

foreach (var kvp in files.OrderBy(f => f.Key, StringComparer.OrdinalIgnoreCase))
{
    // Hash, manifest, ZIP — all in alphabetical order
}
```

**Rationale:** Alphabetical ordering in every multi-file operation guarantees dictionary enumeration order is not guaranteed in .NET, for the purpose of ensuring byte-for-byte identical output given identical input — tested explicitly in `Build_WithSameInputAndTimestamp_IsDeterministic`.

---

## Security Protections Summary

| Protection | Threat | Where | Tested By |
|-----------|--------|-------|-----------|
| Formula injection prefix | CSV macro execution | CsvFormatter | CsvFormatterTests (4 theory cases) |
| HTML encoding | XSS in browser | HtmlFormatter | HtmlFormatterTests (`<>&"'`) |
| Markdown escaping | Table/format corruption | MarkdownFormatter | MarkdownFormatterTests (6 of 7 characters tested; `_` untested) |
| Timestamp clamping | ZIP format crash | EvidenceBuilder | EvidenceBuilderTests (3 edge cases) |

---

## Security Takeaways

1. **Output formats are attack surfaces** — CSV injection and XSS target the consumer, not the producer
2. **Constructor injection = testable security** — each protection is unit-testable in isolation
3. **Deterministic builds are a verifiability property** — reproducible output is easier to compare and validate
4. **In-memory processing supports the current all-or-nothing builder model** — the builder returns complete ZIP bytes or throws
