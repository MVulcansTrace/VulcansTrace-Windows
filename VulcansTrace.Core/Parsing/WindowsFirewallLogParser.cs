using System.Globalization;
using System.Linq;
using System.Threading;

namespace VulcansTrace.Core.Parsing;

/// <summary>
/// Parses Windows Firewall log files into structured log entries.
/// </summary>
/// <remarks>
/// Supports multiple timestamp formats and gracefully handles malformed lines by tracking parse errors.
/// </remarks>
public sealed class WindowsFirewallLogParser
{
    private const int NativeTrailingFieldCount = 9;

    private static readonly string[] TimestampFormats =
    {
        "yyyy-MM-dd HH:mm:ss",
        "yyyy-MM-dd HH:mm:ss.FFFFFFF",
        "yyyy-MM-ddTHH:mm:ss",
        "yyyy-MM-ddTHH:mm:ss.FFFFFFF"
    };

    private static readonly string[] DirectionTokens =
    {
        "SEND",
        "RECEIVE",
        "INBOUND",
        "OUTBOUND"
    };

    /// <summary>
    /// Parses raw log content into a collection of log entries.
    /// </summary>
    /// <param name="rawLog">The raw log file content.</param>
    /// <param name="totalLines">Output: total number of lines processed.</param>
    /// <param name="ignoredLines">Output: number of lines ignored (comments, headers, invalid).</param>
    /// <param name="parseErrors">Output: detailed error messages for lines that failed to parse.</param>
    /// <param name="cancellationToken">Token to cancel the parsing operation.</param>
    /// <returns>A read-only list of successfully parsed log entries.</returns>
    public IReadOnlyList<LogEntry> Parse(
        string? rawLog,
        out int totalLines,
        out int ignoredLines,
        out List<string> parseErrors,
        CancellationToken cancellationToken = default)
    {
        totalLines = 0;
        ignoredLines = 0;
        parseErrors = new List<string>();
        var entries = new List<LogEntry>();

        if (string.IsNullOrWhiteSpace(rawLog))
            return entries;

        var lines = rawLog.Split(new[] { "\r\n", "\n" }, StringSplitOptions.None);

        foreach (var line in lines)
        {
            cancellationToken.ThrowIfCancellationRequested();
            totalLines++;

            var trimmed = line.Trim();
            if (string.IsNullOrEmpty(trimmed) || trimmed.StartsWith("#"))
            {
                ignoredLines++;
                continue;
            }

            var parts = trimmed.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 8)
            {
                ignoredLines++;
                parseErrors.Add($"Line {totalLines}: Insufficient parts (expected at least 8, found {parts.Length}). Content: {trimmed}");
                continue;
            }

            if (!TryParseTimestamp(parts, out var timestamp, out var actionIndex))
            {
                ignoredLines++;
                parseErrors.Add($"Line {totalLines}: Invalid timestamp. Content: {trimmed}");
                continue;
            }

            // Ensure the remaining required fields exist even if extra columns are present.
            var requiredFieldsCount = actionIndex + 6;
            if (parts.Length < requiredFieldsCount)
            {
                ignoredLines++;
                parseErrors.Add($"Line {totalLines}: Insufficient parts (expected at least {requiredFieldsCount}, found {parts.Length}). Content: {trimmed}");
                continue;
            }

            var action = parts[actionIndex];
            var protocol = parts[actionIndex + 1];
            var srcIp = parts[actionIndex + 2];
            var dstIp = parts[actionIndex + 3];
            var srcPortRaw = parts[actionIndex + 4];
            var dstPortRaw = parts[actionIndex + 5];
            var trailingStartIndex = actionIndex + 6;
            var trailingFields = ExtractTrailingFields(parts, trailingStartIndex);
            var direction = trailingFields.Path;

            if (IsPlaceholder(srcIp) || IsPlaceholder(dstIp))
            {
                ignoredLines++;
                parseErrors.Add($"Line {totalLines}: Missing source or destination IP. Content: {trimmed}");
                continue;
            }

            if (!System.Net.IPAddress.TryParse(srcIp, out _) || !System.Net.IPAddress.TryParse(dstIp, out _))
            {
                ignoredLines++;
                parseErrors.Add($"Line {totalLines}: Invalid source or destination IP. Content: {trimmed}");
                continue;
            }

            if (!TryParsePort(protocol, srcPortRaw, out var srcPort))
            {
                ignoredLines++;
                parseErrors.Add($"Line {totalLines}: Invalid source port '{srcPortRaw}'. Content: {trimmed}");
                continue;
            }

            if (!TryParsePort(protocol, dstPortRaw, out var dstPort))
            {
                ignoredLines++;
                parseErrors.Add($"Line {totalLines}: Invalid destination port '{dstPortRaw}'. Content: {trimmed}");
                continue;
            }

            try
            {
                var entry = new LogEntry
                {
                    Timestamp = timestamp,
                    Action = action,
                    Protocol = protocol,
                    SrcIp = srcIp,
                    SrcPort = srcPort,
                    DstIp = dstIp,
                    DstPort = dstPort,
                    PacketSize = trailingFields.PacketSize,
                    TcpFlags = trailingFields.TcpFlags,
                    TcpSyn = trailingFields.TcpSyn,
                    TcpAck = trailingFields.TcpAck,
                    TcpWin = trailingFields.TcpWin,
                    IcmpType = trailingFields.IcmpType,
                    IcmpCode = trailingFields.IcmpCode,
                    Info = trailingFields.Info,
                    Path = trailingFields.Path,
                    Direction = direction,
                    RawLine = line
                };

                entries.Add(entry);
            }
            catch (Exception ex)
            {
                ignoredLines++;
                parseErrors.Add($"Line {totalLines}: {ex.Message}. Content: {trimmed}");
            }
        }

        return entries;
    }

    private static bool TryParseTimestamp(IReadOnlyList<string> parts, out DateTime timestamp, out int actionIndex)
    {
        // Case 1: timestamp is already combined in first token (e.g., 2024-01-01T12:00:00)
        if (DateTime.TryParseExact(parts[0], TimestampFormats, CultureInfo.InvariantCulture, DateTimeStyles.None, out var parsedSingle))
        {
            timestamp = DateTime.SpecifyKind(parsedSingle, DateTimeKind.Local);
            actionIndex = 1;
            return true;
        }

        // Case 2: timestamp is split across the first two tokens (e.g., 2024-01-01 12:00:00)
        if (parts.Count >= 2)
        {
            var combined = $"{parts[0]} {parts[1]}";
            if (DateTime.TryParseExact(combined, TimestampFormats, CultureInfo.InvariantCulture, DateTimeStyles.None, out var parsedCombined))
            {
                timestamp = DateTime.SpecifyKind(parsedCombined, DateTimeKind.Local);
                actionIndex = 2;
                return true;
            }
        }

        timestamp = default;
        actionIndex = -1;
        return false;
    }

    private static bool TryParsePort(string protocol, string value, out int? port)
    {
        if (IsPlaceholder(value))
        {
            if (AllowsMissingPorts(protocol))
            {
                port = null;
                return true;
            }

            port = default;
            return false;
        }

        if (!int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsedPort))
        {
            port = default;
            return false;
        }

        if (parsedPort < 0 || parsedPort > 65535)
        {
            port = default;
            return false;
        }

        port = parsedPort;
        return true;
    }

    private static TrailingFields ExtractTrailingFields(IReadOnlyList<string> parts, int trailingStartIndex)
    {
        if (parts.Count <= trailingStartIndex)
            return TrailingFields.Empty;

        var remaining = parts.Count - trailingStartIndex;
        if (remaining >= NativeTrailingFieldCount && IsDirectionToken(parts[trailingStartIndex + 8]))
        {
            return new TrailingFields(
                TryParseOptionalInt(parts[trailingStartIndex]),
                parts[trailingStartIndex + 1],
                parts[trailingStartIndex + 2],
                parts[trailingStartIndex + 3],
                parts[trailingStartIndex + 4],
                parts[trailingStartIndex + 5],
                parts[trailingStartIndex + 6],
                parts[trailingStartIndex + 7],
                parts[trailingStartIndex + 8]);
        }

        for (var i = parts.Count - 1; i >= trailingStartIndex; i--)
        {
            if (IsDirectionToken(parts[i]))
                return new TrailingFields(null, "", "", "", "", "", "", "", parts[i]);
        }

        return TrailingFields.Empty;
    }

    private static bool IsPlaceholder(string value) =>
        string.Equals(value, "-", StringComparison.Ordinal);

    private static bool IsDirectionToken(string value) =>
        DirectionTokens.Any(token => string.Equals(token, value, StringComparison.OrdinalIgnoreCase));

    private static bool AllowsMissingPorts(string protocol) =>
        protocol.StartsWith("ICMP", StringComparison.OrdinalIgnoreCase);

    private static int? TryParseOptionalInt(string value)
    {
        if (IsPlaceholder(value))
            return null;

        return int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsed)
            ? parsed
            : null;
    }

    private readonly record struct TrailingFields(
        int? PacketSize,
        string TcpFlags,
        string TcpSyn,
        string TcpAck,
        string TcpWin,
        string IcmpType,
        string IcmpCode,
        string Info,
        string Path)
    {
        public static TrailingFields Empty => new(null, "", "", "", "", "", "", "", "");
    }
}
