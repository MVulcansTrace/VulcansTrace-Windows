using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using VulcansTrace.Core;
using VulcansTrace.Core.Security;
using VulcansTrace.Evidence;
using VulcansTrace.Evidence.Formatters;
using Xunit;

namespace VulcansTrace.Tests.Evidence;

public class EvidenceBuilderTests
{
    [Fact]
    public void Build_WithNullResult_ThrowsArgumentNullException()
    {
        var hasher = new IntegrityHasher();
        var csvFormatter = new CsvFormatter();
        var markdownFormatter = new MarkdownFormatter();
        var htmlFormatter = new HtmlFormatter();
        var builder = new EvidenceBuilder(hasher, csvFormatter, markdownFormatter, htmlFormatter);

        Assert.Throws<ArgumentNullException>(() =>
            builder.Build(null!, "log", Encoding.UTF8.GetBytes("key")));
    }

    [Fact]
    public void Build_WithEmptyResult_CreatesZipWithAllEntries()
    {
        // Arrange
        var hasher = new IntegrityHasher();
        var csvFormatter = new CsvFormatter();
        var markdownFormatter = new MarkdownFormatter();
        var htmlFormatter = new HtmlFormatter();
        var builder = new EvidenceBuilder(hasher, csvFormatter, markdownFormatter, htmlFormatter);

        var result = new AnalysisResult();
        var rawLog = "test log content";
        var signingKey = Encoding.UTF8.GetBytes("test-key");

        // Act
        var zipBytes = builder.Build(result, rawLog, signingKey);

        // Assert
        Assert.True(zipBytes.Length > 0);

        using var ms = new MemoryStream(zipBytes);
        using var zip = new ZipArchive(ms, ZipArchiveMode.Read);

        var entries = zip.Entries.ToList();
        Assert.Equal(6, entries.Count);

        var entryNames = entries.Select(e => e.Name.ToLowerInvariant()).ToList();
        Assert.Contains("log.txt", entryNames);
        Assert.Contains("summary.md", entryNames);
        Assert.Contains("findings.csv", entryNames);
        Assert.Contains("report.html", entryNames);
        Assert.Contains("manifest.json", entryNames);
        Assert.Contains("manifest.hmac", entryNames);
    }

    [Fact]
    public void Build_WithFindings_CreatesManifestWithCorrectHashes()
    {
        // Arrange
        var hasher = new IntegrityHasher();
        var csvFormatter = new CsvFormatter();
        var markdownFormatter = new MarkdownFormatter();
        var htmlFormatter = new HtmlFormatter();
        var builder = new EvidenceBuilder(hasher, csvFormatter, markdownFormatter, htmlFormatter);

        var result = new AnalysisResult();
        result.AddFinding(new Finding
        {
            Category = "TestCategory",
            Severity = Severity.High,
            SourceHost = "192.168.1.100",
            Target = "target",
            TimeRangeStart = new DateTime(2024, 1, 1, 12, 0, 0),
            TimeRangeEnd = new DateTime(2024, 1, 1, 12, 5, 0),
            ShortDescription = "Test finding"
        });

        var rawLog = "test log content";
        var signingKey = Encoding.UTF8.GetBytes("test-key");

        // Act
        var zipBytes = builder.Build(result, rawLog, signingKey);

        // Assert
        using var ms = new MemoryStream(zipBytes);
        using var zip = new ZipArchive(ms, ZipArchiveMode.Read);

        var manifestEntry = zip.GetEntry("manifest.json");
        Assert.NotNull(manifestEntry);

        using var manifestStream = manifestEntry!.Open();
        using var reader = new StreamReader(manifestStream);
        var manifestJson = reader.ReadToEnd();

        Assert.Contains("createdUtc", manifestJson);
        Assert.Contains("files", manifestJson);
        Assert.Contains("log.txt", manifestJson);
        Assert.Contains("summary.md", manifestJson);
        Assert.Contains("findings.csv", manifestJson);
        Assert.Contains("report.html", manifestJson);
        Assert.Contains("sha256", manifestJson);
        Assert.Contains("length", manifestJson);
    }

    [Fact]
    public void Build_UsesUtcManifestTimestampWithoutLocalShift()
    {
        var hasher = new IntegrityHasher();
        var csvFormatter = new CsvFormatter();
        var markdownFormatter = new MarkdownFormatter();
        var htmlFormatter = new HtmlFormatter();
        var builder = new EvidenceBuilder(hasher, csvFormatter, markdownFormatter, htmlFormatter);

        var result = new AnalysisResult
        {
            TimeRangeStart = new DateTime(2024, 1, 1, 12, 0, 0, DateTimeKind.Unspecified),
            TimeRangeEnd = new DateTime(2024, 1, 1, 13, 0, 0, DateTimeKind.Unspecified)
        };

        var zipBytes = builder.Build(result, "log", Encoding.UTF8.GetBytes("key"));

        using var ms = new MemoryStream(zipBytes);
        using var zip = new ZipArchive(ms, ZipArchiveMode.Read);
        var manifestEntry = zip.GetEntry("manifest.json");
        Assert.NotNull(manifestEntry);

        using var manifestStream = manifestEntry!.Open();
        using var reader = new StreamReader(manifestStream);
        using var doc = JsonDocument.Parse(reader.ReadToEnd());

        var createdUtc = doc.RootElement.GetProperty("createdUtc").GetDateTime();

        var expected = DateTime.SpecifyKind(result.TimeRangeEnd!.Value, DateTimeKind.Utc);
        Assert.Equal(expected, createdUtc);
        Assert.Equal(DateTimeKind.Utc, createdUtc.Kind);
    }

    [Fact]
    public void Build_WithMarkdownEscaping_PreservesEscapedContent()
    {
        // Arrange
        var hasher = new IntegrityHasher();
        var csvFormatter = new CsvFormatter();
        var markdownFormatter = new MarkdownFormatter();
        var htmlFormatter = new HtmlFormatter();
        var builder = new EvidenceBuilder(hasher, csvFormatter, markdownFormatter, htmlFormatter);

        var result = new AnalysisResult();
        result.AddFinding(new Finding
        {
            Category = "Port|Scan",
            Severity = Severity.High,
            SourceHost = "srv\\core",
            Target = "external:80*80",
            TimeRangeStart = new DateTime(2024, 1, 1, 12, 0, 0, DateTimeKind.Utc),
            TimeRangeEnd = new DateTime(2024, 1, 1, 12, 5, 0, DateTimeKind.Utc),
            ShortDescription = "Desc with [link]\nand `code`"
        });

        var rawLog = "log";
        var key = Encoding.UTF8.GetBytes("key");
        var fixedTimestamp = new DateTime(2024, 2, 1, 0, 0, 0, DateTimeKind.Utc);

        // Act
        var zipBytes = builder.Build(result, rawLog, key, fixedTimestamp);

        // Assert
        using var ms = new MemoryStream(zipBytes);
        using var zip = new ZipArchive(ms, ZipArchiveMode.Read);

        var mdEntry = zip.GetEntry("summary.md");
        Assert.NotNull(mdEntry);
        using var mdStream = mdEntry!.Open();
        using var reader = new StreamReader(mdStream);
        var markdown = reader.ReadToEnd();

        Assert.Contains("Port\\|Scan", markdown);
        Assert.Contains("srv\\\\core", markdown);
        Assert.Contains("external:80\\*80", markdown);
        Assert.Contains("\\[link\\]", markdown);
        Assert.Contains("<br>", markdown);
        Assert.Contains("\\`code\\`", markdown);
    }

    [Fact]
    public void Build_WithSigningKey_CreatesValidHmac()
    {
        // Arrange
        var hasher = new IntegrityHasher();
        var csvFormatter = new CsvFormatter();
        var markdownFormatter = new MarkdownFormatter();
        var htmlFormatter = new HtmlFormatter();
        var builder = new EvidenceBuilder(hasher, csvFormatter, markdownFormatter, htmlFormatter);

        var result = new AnalysisResult();
        var rawLog = "test log content";
        var signingKey = Encoding.UTF8.GetBytes("test-key");

        // Act
        var zipBytes = builder.Build(result, rawLog, signingKey);

        // Assert
        using var ms = new MemoryStream(zipBytes);
        using var zip = new ZipArchive(ms, ZipArchiveMode.Read);

        var manifestEntry = zip.GetEntry("manifest.json");
        var hmacEntry = zip.GetEntry("manifest.hmac");

        Assert.NotNull(manifestEntry);
        Assert.NotNull(hmacEntry);

        using var manifestStream = manifestEntry!.Open();
        var manifestBytes = new byte[manifestEntry.Length];
        manifestStream.ReadExactly(manifestBytes);

        using var hmacStream = hmacEntry!.Open();
        var hmacBytes = new byte[hmacEntry.Length];
        hmacStream.ReadExactly(hmacBytes);

        // Verify HMAC is valid (stored as lowercase hex string)
        var expectedHmac = hasher.ComputeHmacSha256(manifestBytes, signingKey);
        var expectedHmacHex = Convert.ToHexString(expectedHmac).ToLowerInvariant();
        var actualHmacHex = Encoding.UTF8.GetString(hmacBytes);
        Assert.Equal(expectedHmacHex, actualHmacHex);
    }

    [Fact]
    public void Build_WithDifferentSigningKeys_ProducesDifferentHmacs()
    {
        // Arrange
        var hasher = new IntegrityHasher();
        var csvFormatter = new CsvFormatter();
        var markdownFormatter = new MarkdownFormatter();
        var htmlFormatter = new HtmlFormatter();
        var builder = new EvidenceBuilder(hasher, csvFormatter, markdownFormatter, htmlFormatter);

        var result = new AnalysisResult();
        var rawLog = "test log content";
        var key1 = Encoding.UTF8.GetBytes("key-one");
        var key2 = Encoding.UTF8.GetBytes("key-two");

        // Act
        var zip1 = builder.Build(result, rawLog, key1);
        var zip2 = builder.Build(result, rawLog, key2);

        // Assert
        using var ms1 = new MemoryStream(zip1);
        using var zip1Archive = new ZipArchive(ms1, ZipArchiveMode.Read);
        var hmac1 = zip1Archive.GetEntry("manifest.hmac")!;

        using var ms2 = new MemoryStream(zip2);
        using var zip2Archive = new ZipArchive(ms2, ZipArchiveMode.Read);
        var hmac2 = zip2Archive.GetEntry("manifest.hmac")!;

        using var hmac1Stream = hmac1.Open();
        var hmac1Bytes = new byte[hmac1.Length];
        hmac1Stream.ReadExactly(hmac1Bytes);

        using var hmac2Stream = hmac2.Open();
        var hmac2Bytes = new byte[hmac2.Length];
        hmac2Stream.ReadExactly(hmac2Bytes);

        Assert.NotEqual(hmac1Bytes, hmac2Bytes);
    }

    [Fact]
    public void Build_WithNullRawLog_HandlesGracefully()
    {
        // Arrange
        var hasher = new IntegrityHasher();
        var csvFormatter = new CsvFormatter();
        var markdownFormatter = new MarkdownFormatter();
        var htmlFormatter = new HtmlFormatter();
        var builder = new EvidenceBuilder(hasher, csvFormatter, markdownFormatter, htmlFormatter);

        var result = new AnalysisResult();
        string? rawLog = null;
        var signingKey = Encoding.UTF8.GetBytes("test-key");

        // Act
        var zipBytes = builder.Build(result, rawLog ?? string.Empty, signingKey);

        // Assert
        using var ms = new MemoryStream(zipBytes);
        using var zip = new ZipArchive(ms, ZipArchiveMode.Read);

        var logEntry = zip.GetEntry("log.txt");
        Assert.NotNull(logEntry);
        Assert.Equal(0, logEntry!.Length);
    }

    [Fact]
    public void Build_WithComplexResult_IncludesAllDataInZip()
    {
        // Arrange
        var hasher = new IntegrityHasher();
        var csvFormatter = new CsvFormatter();
        var markdownFormatter = new MarkdownFormatter();
        var htmlFormatter = new HtmlFormatter();
        var builder = new EvidenceBuilder(hasher, csvFormatter, markdownFormatter, htmlFormatter);

        var result = new AnalysisResult
        {
            TotalLines = 1000,
            ParsedLines = 950,
            IgnoredLines = 50,
            TimeRangeStart = new DateTime(2024, 1, 1, 12, 0, 0),
            TimeRangeEnd = new DateTime(2024, 1, 1, 13, 0, 0)
        };

        result.AddFinding(new Finding
        {
            Category = "PortScan",
            Severity = Severity.Critical,
            SourceHost = "192.168.1.100",
            Target = "multiple",
            TimeRangeStart = new DateTime(2024, 1, 1, 12, 0, 0),
            TimeRangeEnd = new DateTime(2024, 1, 1, 12, 30, 0),
            ShortDescription = "Port scan detected"
        });

        var rawLog = "2024-01-01 12:00:00 ALLOW TCP 192.168.1.100 10.0.0.1 12345 80 SEND";
        var signingKey = Encoding.UTF8.GetBytes("test-key");

        // Act
        var zipBytes = builder.Build(result, rawLog, signingKey);

        // Assert
        using var ms = new MemoryStream(zipBytes);
        using var zip = new ZipArchive(ms, ZipArchiveMode.Read);

        // Check log content
        var logEntry = zip.GetEntry("log.txt");
        using (var logStream = logEntry!.Open())
        using (var reader = new StreamReader(logStream))
        {
            var logContent = reader.ReadToEnd();
            Assert.Equal(rawLog, logContent);
        }

        // Check CSV content
        var csvEntry = zip.GetEntry("findings.csv");
        using (var csvStream = csvEntry!.Open())
        using (var reader = new StreamReader(csvStream))
        {
            var csvContent = reader.ReadToEnd();
            Assert.Contains("PortScan", csvContent);
            Assert.Contains("Critical", csvContent);
        }

        // Check Markdown content
        var mdEntry = zip.GetEntry("summary.md");
        using (var mdStream = mdEntry!.Open())
        using (var reader = new StreamReader(mdStream))
        {
            var mdContent = reader.ReadToEnd();
            Assert.Contains("# VulcansTrace Analysis Summary", mdContent);
            Assert.Contains("Total lines: 1000", mdContent);
        }

        // Check HTML content
        var htmlEntry = zip.GetEntry("report.html");
        using (var htmlStream = htmlEntry!.Open())
        using (var reader = new StreamReader(htmlStream))
        {
            var htmlContent = reader.ReadToEnd();
            Assert.Contains("<!DOCTYPE html>", htmlContent);
            Assert.Contains("VulcansTrace Analysis Report", htmlContent);
        }
    }

    [Fact]
    public void Build_WithWarnings_EmitsWarningsInManifestAndCsv()
    {
        var hasher = new IntegrityHasher();
        var csvFormatter = new CsvFormatter();
        var markdownFormatter = new MarkdownFormatter();
        var htmlFormatter = new HtmlFormatter();
        var builder = new EvidenceBuilder(hasher, csvFormatter, markdownFormatter, htmlFormatter);

        var result = new AnalysisResult();
        result.AddWarning("Port scan truncated to 5 events");

        var zipBytes = builder.Build(result, "log", Encoding.UTF8.GetBytes("key"));

        using var ms = new MemoryStream(zipBytes);
        using var zip = new ZipArchive(ms, ZipArchiveMode.Read);

        var manifestEntry = zip.GetEntry("manifest.json");
        using (var manifestStream = manifestEntry!.Open())
        using (var reader = new StreamReader(manifestStream))
        {
            var manifestJson = reader.ReadToEnd();
            using var doc = JsonDocument.Parse(manifestJson);
            var warnings = doc.RootElement.GetProperty("warnings");
            Assert.Equal(1, warnings.GetArrayLength());
            Assert.Equal("Port scan truncated to 5 events", warnings[0].GetString());
        }

        var csvEntry = zip.GetEntry("findings.csv");
        using (var csvStream = csvEntry!.Open())
        using (var reader = new StreamReader(csvStream))
        {
            var csv = reader.ReadToEnd();
            Assert.Contains("Warnings", csv);
            Assert.Contains("Port scan truncated to 5 events", csv);
        }
    }

    [Fact]
    public void Build_WithoutWarnings_ManifestContainsEmptyWarningsArray()
    {
        var hasher = new IntegrityHasher();
        var csvFormatter = new CsvFormatter();
        var markdownFormatter = new MarkdownFormatter();
        var htmlFormatter = new HtmlFormatter();
        var builder = new EvidenceBuilder(hasher, csvFormatter, markdownFormatter, htmlFormatter);

        var result = new AnalysisResult();
        var zipBytes = builder.Build(result, "log", Encoding.UTF8.GetBytes("key"));

        using var ms = new MemoryStream(zipBytes);
        using var zip = new ZipArchive(ms, ZipArchiveMode.Read);

        var manifestEntry = zip.GetEntry("manifest.json");
        using var manifestStream = manifestEntry!.Open();
        using var reader = new StreamReader(manifestStream);
        var manifestJson = reader.ReadToEnd();

        using var doc = JsonDocument.Parse(manifestJson);
        var warnings = doc.RootElement.GetProperty("warnings");
        Assert.Equal(JsonValueKind.Array, warnings.ValueKind);
        Assert.Equal(0, warnings.GetArrayLength());
    }

    [Fact]
    public void Build_WithSameInputAndTimestamp_IsDeterministic()
    {
        // Arrange
        var hasher = new IntegrityHasher();
        var csvFormatter = new CsvFormatter();
        var markdownFormatter = new MarkdownFormatter();
        var htmlFormatter = new HtmlFormatter();
        var builder = new EvidenceBuilder(hasher, csvFormatter, markdownFormatter, htmlFormatter);

        var result = new AnalysisResult
        {
            TimeRangeStart = new DateTime(2024, 1, 1, 12, 0, 0, DateTimeKind.Utc),
            TimeRangeEnd = new DateTime(2024, 1, 1, 13, 0, 0, DateTimeKind.Utc)
        };
        var rawLog = "log line";
        var key = Encoding.UTF8.GetBytes("key");
        var fixedTimestamp = new DateTime(2024, 2, 1, 0, 0, 0, DateTimeKind.Utc);

        // Act
        var zip1 = builder.Build(result, rawLog, key, fixedTimestamp);
        var zip2 = builder.Build(result, rawLog, key, fixedTimestamp);

        // Assert
        Assert.Equal(zip1, zip2);
    }

    [Fact]
    public void Build_WithDifferentTimestamps_ProducesDifferentBundles()
    {
        // Arrange
        var hasher = new IntegrityHasher();
        var csvFormatter = new CsvFormatter();
        var markdownFormatter = new MarkdownFormatter();
        var htmlFormatter = new HtmlFormatter();
        var builder = new EvidenceBuilder(hasher, csvFormatter, markdownFormatter, htmlFormatter);

        var result = new AnalysisResult();
        var rawLog = "log line";
        var key = Encoding.UTF8.GetBytes("key");
        var ts1 = new DateTime(2024, 2, 1, 0, 0, 0, DateTimeKind.Utc);
        var ts2 = new DateTime(2024, 2, 2, 0, 0, 0, DateTimeKind.Utc);

        // Act
        var zip1 = builder.Build(result, rawLog, key, ts1);
        var zip2 = builder.Build(result, rawLog, key, ts2);

        // Assert
        Assert.NotEqual(zip1, zip2);
    }

    [Fact]
    public void Build_WithoutTimestamp_UsesResultTimeRangeEnd()
    {
        // Arrange
        var hasher = new IntegrityHasher();
        var csvFormatter = new CsvFormatter();
        var markdownFormatter = new MarkdownFormatter();
        var htmlFormatter = new HtmlFormatter();
        var builder = new EvidenceBuilder(hasher, csvFormatter, markdownFormatter, htmlFormatter);

        var expectedUtc = new DateTime(2024, 3, 1, 12, 0, 0, DateTimeKind.Utc);
        var result = new AnalysisResult
        {
            TimeRangeStart = expectedUtc.AddMinutes(-5),
            TimeRangeEnd = expectedUtc
        };
        var rawLog = "log line";
        var key = Encoding.UTF8.GetBytes("key");

        // Act
        var zipBytes = builder.Build(result, rawLog, key);

        // Assert
        using var ms = new MemoryStream(zipBytes);
        using var zip = new ZipArchive(ms, ZipArchiveMode.Read);

        var manifestEntry = zip.GetEntry("manifest.json");
        using var manifestStream = manifestEntry!.Open();
        using var reader = new StreamReader(manifestStream);
        var manifestJson = reader.ReadToEnd();

        using var doc = JsonDocument.Parse(manifestJson);
        var createdUtc = doc.RootElement.GetProperty("createdUtc").GetDateTime();

        Assert.Equal(expectedUtc, createdUtc);
    }

    [Fact]
    public async Task BuildAsync_WithValidInputs_ProducesZip()
    {
        var hasher = new IntegrityHasher();
        var csvFormatter = new CsvFormatter();
        var markdownFormatter = new MarkdownFormatter();
        var htmlFormatter = new HtmlFormatter();
        var builder = new EvidenceBuilder(hasher, csvFormatter, markdownFormatter, htmlFormatter);

        var result = new AnalysisResult();
        result.AddWarning("warn");
        var zipBytes = await builder.BuildAsync(result, "log", Encoding.UTF8.GetBytes("key"), DateTime.UtcNow, CancellationToken.None);

        Assert.True(zipBytes.Length > 0);
    }

    [Fact]
    public async Task BuildAsync_WithCanceledToken_Throws()
    {
        var hasher = new IntegrityHasher();
        var csvFormatter = new CsvFormatter();
        var markdownFormatter = new MarkdownFormatter();
        var htmlFormatter = new HtmlFormatter();
        var builder = new EvidenceBuilder(hasher, csvFormatter, markdownFormatter, htmlFormatter);

        var result = new AnalysisResult();
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            builder.BuildAsync(result, "log", Encoding.UTF8.GetBytes("key"), DateTime.UtcNow, cts.Token));
    }

    [Fact]
    public void Build_WithAncientTimestamp_ClampsToZipMinimum()
    {
        // Arrange
        var hasher = new IntegrityHasher();
        var csvFormatter = new CsvFormatter();
        var markdownFormatter = new MarkdownFormatter();
        var htmlFormatter = new HtmlFormatter();
        var builder = new EvidenceBuilder(hasher, csvFormatter, markdownFormatter, htmlFormatter);

        var result = new AnalysisResult
        {
            TimeRangeEnd = new DateTime(1970, 6, 15, 12, 0, 0, DateTimeKind.Utc) // Ancient log
        };
        var rawLog = "log line";
        var key = Encoding.UTF8.GetBytes("key");

        // Act
        var zipBytes = builder.Build(result, rawLog, key);

        // Assert
        using var ms = new MemoryStream(zipBytes);
        using var zip = new ZipArchive(ms, ZipArchiveMode.Read);

        var manifestEntry = zip.GetEntry("manifest.json");
        using var manifestStream = manifestEntry!.Open();
        using var reader = new StreamReader(manifestStream);
        var manifestJson = reader.ReadToEnd();

        using var doc = JsonDocument.Parse(manifestJson);
        var createdUtc = doc.RootElement.GetProperty("createdUtc").GetDateTime();

        // Should be clamped to 1980-01-01 (ZIP minimum)
        Assert.Equal(new DateTime(1980, 1, 1, 0, 0, 0, DateTimeKind.Utc), createdUtc);
    }

    [Fact]
    public void Build_WithFutureTimestamp_ClampsToZipMaximum()
    {
        // Arrange
        var hasher = new IntegrityHasher();
        var csvFormatter = new CsvFormatter();
        var markdownFormatter = new MarkdownFormatter();
        var htmlFormatter = new HtmlFormatter();
        var builder = new EvidenceBuilder(hasher, csvFormatter, markdownFormatter, htmlFormatter);

        var result = new AnalysisResult
        {
            TimeRangeEnd = new DateTime(2200, 1, 1, 0, 0, 0, DateTimeKind.Utc) // Far future
        };
        var rawLog = "log line";
        var key = Encoding.UTF8.GetBytes("key");

        // Act
        var zipBytes = builder.Build(result, rawLog, key);

        // Assert
        using var ms = new MemoryStream(zipBytes);
        using var zip = new ZipArchive(ms, ZipArchiveMode.Read);

        var manifestEntry = zip.GetEntry("manifest.json");
        using var manifestStream = manifestEntry!.Open();
        using var reader = new StreamReader(manifestStream);
        var manifestJson = reader.ReadToEnd();

        using var doc = JsonDocument.Parse(manifestJson);
        var createdUtc = doc.RootElement.GetProperty("createdUtc").GetDateTime();

        // Should be clamped to 2107-12-31 23:59:58 (ZIP maximum)
        Assert.Equal(new DateTime(2107, 12, 31, 23, 59, 58, DateTimeKind.Utc), createdUtc);
    }

    [Fact]
    public void Build_WithMissingTimestamp_FallsBackToUnixEpochClampedTo1980()
    {
        // Arrange
        var hasher = new IntegrityHasher();
        var csvFormatter = new CsvFormatter();
        var markdownFormatter = new MarkdownFormatter();
        var htmlFormatter = new HtmlFormatter();
        var builder = new EvidenceBuilder(hasher, csvFormatter, markdownFormatter, htmlFormatter);

        var result = new AnalysisResult(); // No TimeRangeStart or TimeRangeEnd
        var rawLog = "log line";
        var key = Encoding.UTF8.GetBytes("key");

        // Act
        var zipBytes = builder.Build(result, rawLog, key);

        // Assert
        using var ms = new MemoryStream(zipBytes);
        using var zip = new ZipArchive(ms, ZipArchiveMode.Read);

        var manifestEntry = zip.GetEntry("manifest.json");
        using var manifestStream = manifestEntry!.Open();
        using var reader = new StreamReader(manifestStream);
        var manifestJson = reader.ReadToEnd();

        using var doc = JsonDocument.Parse(manifestJson);
        var createdUtc = doc.RootElement.GetProperty("createdUtc").GetDateTime();

        // UnixEpoch (1970-01-01) clamped to ZIP minimum (1980-01-01)
        Assert.Equal(new DateTime(1980, 1, 1, 0, 0, 0, DateTimeKind.Utc), createdUtc);
    }

    [Fact]
    public void Build_WithLocalTimeKind_ConvertsToUtc()
    {
        // Arrange
        var hasher = new IntegrityHasher();
        var csvFormatter = new CsvFormatter();
        var markdownFormatter = new MarkdownFormatter();
        var htmlFormatter = new HtmlFormatter();
        var builder = new EvidenceBuilder(hasher, csvFormatter, markdownFormatter, htmlFormatter);

        // Use a specific local time - 2024-01-01 12:00:00 local
        var localTime = new DateTime(2024, 1, 1, 12, 0, 0, DateTimeKind.Local);
        var expectedUtc = localTime.ToUniversalTime();

        var result = new AnalysisResult
        {
            TimeRangeEnd = localTime
        };
        var rawLog = "log line";
        var key = Encoding.UTF8.GetBytes("key");

        // Act
        var zipBytes = builder.Build(result, rawLog, key);

        // Assert
        using var ms = new MemoryStream(zipBytes);
        using var zip = new ZipArchive(ms, ZipArchiveMode.Read);

        var manifestEntry = zip.GetEntry("manifest.json");
        using var manifestStream = manifestEntry!.Open();
        using var reader = new StreamReader(manifestStream);
        var manifestJson = reader.ReadToEnd();

        using var doc = JsonDocument.Parse(manifestJson);
        var createdUtc = doc.RootElement.GetProperty("createdUtc").GetDateTime();

        Assert.Equal(expectedUtc, createdUtc);
        Assert.Equal(DateTimeKind.Utc, createdUtc.Kind);
    }

    [Fact]
    public void Build_WithUnspecifiedKind_AssumesUtc()
    {
        // Arrange
        var hasher = new IntegrityHasher();
        var csvFormatter = new CsvFormatter();
        var markdownFormatter = new MarkdownFormatter();
        var htmlFormatter = new HtmlFormatter();
        var builder = new EvidenceBuilder(hasher, csvFormatter, markdownFormatter, htmlFormatter);

        var unspecifiedTime = new DateTime(2024, 3, 20, 14, 30, 0, DateTimeKind.Unspecified);

        var result = new AnalysisResult
        {
            TimeRangeEnd = unspecifiedTime
        };
        var rawLog = "log line";
        var key = Encoding.UTF8.GetBytes("key");

        // Act
        var zipBytes = builder.Build(result, rawLog, key);

        // Assert
        using var ms = new MemoryStream(zipBytes);
        using var zip = new ZipArchive(ms, ZipArchiveMode.Read);

        var manifestEntry = zip.GetEntry("manifest.json");
        using var manifestStream = manifestEntry!.Open();
        using var reader = new StreamReader(manifestStream);
        var manifestJson = reader.ReadToEnd();

        using var doc = JsonDocument.Parse(manifestJson);
        var createdUtc = doc.RootElement.GetProperty("createdUtc").GetDateTime();

        // Unspecified kind is treated as UTC (same time value, just marked as UTC)
        Assert.Equal(new DateTime(2024, 3, 20, 14, 30, 0, DateTimeKind.Utc), createdUtc);
        Assert.Equal(DateTimeKind.Utc, createdUtc.Kind);
    }

    [Fact]
    public void Build_WithExplicitTimestamp_OverridesResultTimestamp()
    {
        // Arrange
        var hasher = new IntegrityHasher();
        var csvFormatter = new CsvFormatter();
        var markdownFormatter = new MarkdownFormatter();
        var htmlFormatter = new HtmlFormatter();
        var builder = new EvidenceBuilder(hasher, csvFormatter, markdownFormatter, htmlFormatter);

        var resultTime = new DateTime(2024, 1, 1, 12, 0, 0, DateTimeKind.Utc);
        var explicitTime = new DateTime(2024, 6, 15, 18, 30, 0, DateTimeKind.Utc);

        var result = new AnalysisResult
        {
            TimeRangeEnd = resultTime
        };
        var rawLog = "log line";
        var key = Encoding.UTF8.GetBytes("key");

        // Act
        var zipBytes = builder.Build(result, rawLog, key, explicitTime);

        // Assert
        using var ms = new MemoryStream(zipBytes);
        using var zip = new ZipArchive(ms, ZipArchiveMode.Read);

        var manifestEntry = zip.GetEntry("manifest.json");
        using var manifestStream = manifestEntry!.Open();
        using var reader = new StreamReader(manifestStream);
        var manifestJson = reader.ReadToEnd();

        using var doc = JsonDocument.Parse(manifestJson);
        var createdUtc = doc.RootElement.GetProperty("createdUtc").GetDateTime();

        // Explicit timestamp should take priority
        Assert.Equal(explicitTime, createdUtc);
    }
}
