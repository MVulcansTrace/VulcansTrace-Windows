using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using VulcansTrace.Core;
using VulcansTrace.Core.Security;
using VulcansTrace.Evidence.Formatters;

namespace VulcansTrace.Evidence;

/// <summary>
/// Builds cryptographically signed evidence packages from analysis results.
/// </summary>
/// <remarks>
/// Creates a ZIP archive containing:
/// <list type="bullet">
/// <item><c>findings.csv</c> - Findings in CSV format</item>
/// <item><c>log.txt</c> - Original log file (as provided)</item>
/// <item><c>report.html</c> - HTML report</item>
/// <item><c>summary.md</c> - Markdown summary</item>
/// <item><c>manifest.json</c> - File hashes and metadata</item>
/// <item><c>manifest.hmac</c> - HMAC-SHA256 signature for integrity verification</item>
/// </list>
/// <para>
/// <strong>Integrity Scope:</strong> SHA-256 hashes and HMAC signatures protect the evidence 
/// package from modification AFTER export. They do NOT detect tampering of the original source 
/// logs BEFORE they were loaded into VulcansTrace. For T1070 (Indicator Removal) detection, 
/// implement event log monitoring (e.g., Windows Event ID 1102) or source system forensics.
/// </para>
/// <para>
/// <strong>HMAC Limitations:</strong> HMAC-SHA256 proves the manifest was signed with the expected 
/// key and was not modified. It does NOT prove the identity of the signer or team attribution 
/// without secure key management, access controls, and audit logging.
/// </para>
/// </remarks>
public sealed class EvidenceBuilder
{
    private readonly IntegrityHasher _hasher;
    private readonly CsvFormatter _csvFormatter;
    private readonly MarkdownFormatter _markdownFormatter;
    private readonly HtmlFormatter _htmlFormatter;
    private static readonly DateTimeOffset ZipMinTimestamp = new DateTimeOffset(new DateTime(1980, 1, 1, 0, 0, 0, DateTimeKind.Utc));
    private static readonly DateTimeOffset ZipMaxTimestamp = new DateTimeOffset(new DateTime(2107, 12, 31, 23, 59, 58, DateTimeKind.Utc));

    /// <summary>
    /// Initializes a new instance of the <see cref="EvidenceBuilder"/> class.
    /// </summary>
    /// <param name="hasher">The integrity hasher for computing SHA-256 and HMAC signatures.</param>
    /// <param name="csvFormatter">Formatter for CSV output.</param>
    /// <param name="markdownFormatter">Formatter for Markdown output.</param>
    /// <param name="htmlFormatter">Formatter for HTML output.</param>
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

    /// <summary>
    /// Builds an evidence package synchronously.
    /// </summary>
    /// <param name="result">The analysis result to package.</param>
    /// <param name="rawLog">The original raw log content.</param>
    /// <param name="signingKey">The secret key for HMAC signing.</param>
    /// <param name="analysisTimestampUtc">Optional timestamp override for file dates.</param>
    /// <returns>A byte array containing the ZIP file contents.</returns>
    public byte[] Build(AnalysisResult result, string rawLog, byte[] signingKey, DateTime? analysisTimestampUtc = null) =>
        Build(result, rawLog, signingKey, analysisTimestampUtc, CancellationToken.None);

    /// <summary>
    /// Builds an evidence package asynchronously.
    /// </summary>
    /// <param name="result">The analysis result to package.</param>
    /// <param name="rawLog">The original raw log content.</param>
    /// <param name="signingKey">The secret key for HMAC signing.</param>
    /// <param name="analysisTimestampUtc">Optional timestamp override for file dates.</param>
    /// <param name="cancellationToken">Token to cancel the build operation.</param>
    /// <returns>A task representing the async operation, containing the ZIP file bytes.</returns>
    public async Task<byte[]> BuildAsync(AnalysisResult result, string rawLog, byte[] signingKey, DateTime? analysisTimestampUtc = null, CancellationToken cancellationToken = default)
    {
        return await Task.Run(() => Build(result, rawLog, signingKey, analysisTimestampUtc, cancellationToken), cancellationToken);
    }

    /// <summary>
    /// Builds an evidence package with cancellation support.
    /// </summary>
    /// <param name="result">The analysis result to package.</param>
    /// <param name="rawLog">The original raw log content.</param>
    /// <param name="signingKey">The secret key for HMAC signing.</param>
    /// <param name="analysisTimestampUtc">Optional timestamp override for file dates.</param>
    /// <param name="cancellationToken">Token to cancel the build operation.</param>
    /// <returns>A byte array containing the ZIP file contents.</returns>
    public byte[] Build(AnalysisResult result, string rawLog, byte[] signingKey, DateTime? analysisTimestampUtc, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var timestampOffset = NormalizeTimestamp(result, analysisTimestampUtc);
        cancellationToken.ThrowIfCancellationRequested();

        var files = new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase)
        {
            ["findings.csv"]  = Encoding.UTF8.GetBytes(_csvFormatter.ToCsv(result)),
            ["log.txt"]       = Encoding.UTF8.GetBytes(rawLog ?? string.Empty),
            ["report.html"]   = Encoding.UTF8.GetBytes(_htmlFormatter.ToHtml(result)),
            ["summary.md"]    = Encoding.UTF8.GetBytes(_markdownFormatter.ToMarkdown(result))
        };
        cancellationToken.ThrowIfCancellationRequested();

        var manifestEntries = new List<object>();

        foreach (var kvp in files.OrderBy(k => k.Key, StringComparer.OrdinalIgnoreCase))
        {
            cancellationToken.ThrowIfCancellationRequested();
            var hash = _hasher.ComputeSha256(kvp.Value);
            var hashHex = Convert.ToHexString(hash).ToLowerInvariant();

            manifestEntries.Add(new
            {
                file = kvp.Key,
                sha256 = hashHex,
                length = kvp.Value.Length
            });
        }

        var manifest = new
        {
            createdUtc = timestampOffset.UtcDateTime,
            files = manifestEntries,
            warnings = result.Warnings
        };

        var manifestJson = JsonSerializer.SerializeToUtf8Bytes(manifest, new JsonSerializerOptions
        {
            WriteIndented = true
        });
        cancellationToken.ThrowIfCancellationRequested();

        var manifestHmac = _hasher.ComputeHmacSha256(manifestJson, signingKey);
        cancellationToken.ThrowIfCancellationRequested();

        using var ms = new MemoryStream();
        using (var zip = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
        {
            foreach (var kvp in files.OrderBy(k => k.Key, StringComparer.OrdinalIgnoreCase))
            {
                cancellationToken.ThrowIfCancellationRequested();
                var entry = zip.CreateEntry(kvp.Key, CompressionLevel.Optimal);
                entry.LastWriteTime = timestampOffset;
                using var entryStream = entry.Open();
                entryStream.Write(kvp.Value, 0, kvp.Value.Length);
            }

            var manifestEntry = zip.CreateEntry("manifest.json", CompressionLevel.Optimal);
            manifestEntry.LastWriteTime = timestampOffset;
            using (var entryStream = manifestEntry.Open())
            {
                cancellationToken.ThrowIfCancellationRequested();
                entryStream.Write(manifestJson, 0, manifestJson.Length);
            }

            var hmacEntry = zip.CreateEntry("manifest.hmac", CompressionLevel.Optimal);
            hmacEntry.LastWriteTime = timestampOffset;
            using (var entryStream = hmacEntry.Open())
            {
                cancellationToken.ThrowIfCancellationRequested();
                // Write as lowercase hex string for interoperability
                var hmacHex = Encoding.UTF8.GetBytes(Convert.ToHexString(manifestHmac).ToLowerInvariant());
                entryStream.Write(hmacHex, 0, hmacHex.Length);
            }
        }

        return ms.ToArray();
    }

    private static DateTimeOffset NormalizeTimestamp(AnalysisResult result, DateTime? providedUtc)
    {
        DateTime EnsureUtc(DateTime dt) =>
            dt.Kind switch
            {
                DateTimeKind.Utc => dt,
                DateTimeKind.Local => dt.ToUniversalTime(),
                _ => DateTime.SpecifyKind(dt, DateTimeKind.Utc)
            };

        DateTimeOffset candidate = providedUtc.HasValue
            ? new DateTimeOffset(EnsureUtc(providedUtc.Value))
            : result.TimeRangeEnd.HasValue
                ? new DateTimeOffset(EnsureUtc(result.TimeRangeEnd.Value))
                : result.TimeRangeStart.HasValue
                    ? new DateTimeOffset(EnsureUtc(result.TimeRangeStart.Value))
                    : new DateTimeOffset(DateTime.SpecifyKind(DateTime.UnixEpoch, DateTimeKind.Utc));

        if (candidate < ZipMinTimestamp) return ZipMinTimestamp;
        if (candidate > ZipMaxTimestamp) return ZipMaxTimestamp;
        return candidate;
    }
}
