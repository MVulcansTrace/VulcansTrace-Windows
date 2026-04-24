using VulcansTrace.Core;
using VulcansTrace.Core.Parsing;

namespace VulcansTrace.Tests.Core;

public class WindowsFirewallLogParserTests
{
    private readonly WindowsFirewallLogParser _parser = new();

    [Fact]
    public void Parse_WithSampleLog_ReturnsCorrectEntriesAndCounts()
    {
        // Arrange - simplified fixture format with direction immediately after dst-port
        var rawLog = @"# This is a comment line
2024-01-15 10:30:15 ALLOW TCP 192.168.1.100 203.0.113.10 54321 443 RECEIVE
2024-01-15 10:30:16 DROP UDP 10.0.0.5 8.8.8.8 12345 53 SEND

# Version: 1.5
2024-01-15 10:31:00 ALLOW TCP 172.16.0.50 192.168.1.200 3389 3389 RECEIVE";

        // Act
        var entries = _parser.Parse(rawLog, out var totalLines, out var ignoredLines, out _);

        // Assert
        Assert.Equal(6, totalLines); // 3 valid lines + 2 comments + 1 blank = 6
        Assert.Equal(3, ignoredLines); // 2 comments + 1 blank
        Assert.Equal(3, entries.Count);

        // Verify first entry
        var first = entries[0];
        Assert.Equal(new DateTime(2024, 1, 15, 10, 30, 15), first.Timestamp);
        Assert.Equal("ALLOW", first.Action);
        Assert.Equal("TCP", first.Protocol);
        Assert.Equal("192.168.1.100", first.SrcIp);
        Assert.Equal(54321, first.SrcPort);
        Assert.Equal("203.0.113.10", first.DstIp);
        Assert.Equal(443, first.DstPort);
        Assert.Equal("RECEIVE", first.Direction);
        Assert.Equal("RECEIVE", first.Path);
        Assert.Contains("2024-01-15 10:30:15 ALLOW TCP 192.168.1.100 203.0.113.10 54321 443 RECEIVE", first.RawLine);

        // Verify second entry
        var second = entries[1];
        Assert.Equal("DROP", second.Action);
        Assert.Equal("UDP", second.Protocol);
        Assert.Equal("10.0.0.5", second.SrcIp);
        Assert.Equal(12345, second.SrcPort);
        Assert.Equal("8.8.8.8", second.DstIp);
        Assert.Equal(53, second.DstPort);
        Assert.Equal("SEND", second.Direction);

        // Verify third entry
        var third = entries[2];
        Assert.Equal("ALLOW", third.Action);
        Assert.Equal("TCP", third.Protocol);
        Assert.Equal("172.16.0.50", third.SrcIp);
        Assert.Equal(3389, third.SrcPort);
        Assert.Equal("192.168.1.200", third.DstIp);
        Assert.Equal(3389, third.DstPort);
        Assert.Equal("RECEIVE", third.Direction);
    }

    [Fact]
    public void Parse_WithValidTimestamp_SetsTimestampKindToLocal()
    {
        // Arrange - simplified fixture format with direction immediately after dst-port
        var rawLog = "2024-01-15 10:30:15 ALLOW TCP 192.168.1.100 203.0.113.10 54321 443 RECEIVE";

        // Act
        var entries = _parser.Parse(rawLog, out var totalLines, out var ignoredLines, out _);

        // Assert
        Assert.Equal(1, totalLines);
        Assert.Equal(0, ignoredLines);
        Assert.Single(entries);
        Assert.Equal(DateTimeKind.Local, entries[0].Timestamp.Kind);
    }

    [Fact]
    public void Parse_WithEmptyLog_ReturnsNoEntriesAndZeroCounts()
    {
        // Arrange
        var rawLog = "";

        // Act
        var entries = _parser.Parse(rawLog, out var totalLines, out var ignoredLines, out _);

        // Assert
        Assert.Equal(0, totalLines);
        Assert.Equal(0, ignoredLines);
        Assert.Empty(entries);
    }

    [Fact]
    public void Parse_WithNullLog_ReturnsNoEntriesAndZeroCounts()
    {
        // Arrange
        string? rawLog = null;

        // Act
        var entries = _parser.Parse(rawLog, out var totalLines, out var ignoredLines, out _);

        // Assert
        Assert.Equal(0, totalLines);
        Assert.Equal(0, ignoredLines);
        Assert.Empty(entries);
    }

    [Fact]
    public void Parse_WithOnlyCommentsAndBlanks_ReturnsNoEntriesAndCorrectCounts()
    {
        // Arrange
        var rawLog = @"# Version: 1.5

# This is a comment
# Another comment

";

        // Act
        var entries = _parser.Parse(rawLog, out var totalLines, out var ignoredLines, out _);

        // Assert
        Assert.Equal(6, totalLines); // 3 comments + 3 blank lines
        Assert.Equal(6, ignoredLines); // All lines ignored
        Assert.Empty(entries);
    }

    [Fact]
    public void Parse_WithMalformedLines_IgnoresMalformedLines()
    {
        // Arrange - simplified fixture format with direction immediately after dst-port
        var rawLog = @"# Comment line
2024-01-15 10:30:15 ALLOW TCP 192.168.1.100 203.0.113.10 54321 443 RECEIVE
MALFORMED LINE WITHOUT PROPER FORMAT
2024-01-15 10:30:16 DROP UDP 10.0.0.5 8.8.8.8 12345 53 SEND
INCOMPLETE LINE WITH ONLY PARTS
2024-01-15 INVALID_DATE_FORMAT ALLOW TCP 192.168.1.100 203.0.113.10 54321 443 RECEIVE";

        // Act
        var entries = _parser.Parse(rawLog, out var totalLines, out var ignoredLines, out var parseErrors);

        // Assert
        Assert.Equal(6, totalLines); // 1 comment + 5 data lines
        Assert.Equal(4, ignoredLines); // 1 comment + 3 malformed (malformed, incomplete, invalid_date)
        Assert.Equal(2, entries.Count); // Only 2 valid entries
        Assert.Equal(3, parseErrors.Count); // 3 specific parsing errors
    }

    [Fact]
    public void Parse_WithDifferentLineEndings_HandlesCorrectly()
    {
        // Arrange - simplified fixture format
        var rawLog = "2024-01-15 10:30:15 ALLOW TCP 192.168.1.100 203.0.113.10 54321 443 RECEIVE\r\n" +
                    "# Comment line\n" +
                    "2024-01-15 10:30:16 DROP UDP 10.0.0.5 8.8.8.8 12345 53 SEND";

        // Act
        var entries = _parser.Parse(rawLog, out var totalLines, out var ignoredLines, out _);

        // Assert
        Assert.Equal(3, totalLines);
        Assert.Equal(1, ignoredLines); // Only the comment line
        Assert.Equal(2, entries.Count);
    }

    [Fact]
    public void Parse_WithExtraWhitespace_HandlesCorrectly()
    {
        // Arrange - simplified fixture format
        var rawLog = @"   2024-01-15 10:30:15    ALLOW   TCP   192.168.1.100   203.0.113.10   54321   443   RECEIVE

            # Comment with leading spaces
            2024-01-15 10:30:16 DROP UDP 10.0.0.5 8.8.8.8 12345 53 SEND   ";

        // Act
        var entries = _parser.Parse(rawLog, out var totalLines, out var ignoredLines, out _);

        // Assert
        Assert.Equal(4, totalLines); // 2 data + 1 comment + 1 blank
        Assert.Equal(2, ignoredLines); // 1 comment + 1 blank
        Assert.Equal(2, entries.Count);

        // Verify first entry has correct data despite extra spaces
        var first = entries[0];
        Assert.Equal("ALLOW", first.Action);
        Assert.Equal("TCP", first.Protocol);
        Assert.Equal("192.168.1.100", first.SrcIp);
        Assert.Equal(54321, first.SrcPort);
        Assert.Equal("203.0.113.10", first.DstIp);
        Assert.Equal(443, first.DstPort);
        Assert.Equal("RECEIVE", first.Direction);
    }

    [Fact]
    public void Parse_WithMalformedLines_PopulatesParseErrorsCorrectly()
    {
        // Arrange - simplified fixture format with direction immediately after dst-port
        var rawLog = @"# Valid comment
Line with too few parts
2024-01-15 INVALID_TIME ALLOW TCP 1.1.1.1 2.2.2.2 1234 5678 SEND
2024-01-15 10:00:00 ALLOW TCP 3.3.3.3 4.4.4.4 NOT_A_PORT 9012 SEND";

        // Act
        var entries = _parser.Parse(rawLog, out var totalLines, out var ignoredLines, out var parseErrors);

        // Assert
        Assert.Equal(4, totalLines);
        Assert.Equal(4, ignoredLines); // 1 comment + 3 malformed lines
        Assert.Empty(entries);
        Assert.Equal(3, parseErrors.Count);

        Assert.Contains("Line 2: Insufficient parts (expected at least 8, found 5). Content: Line with too few parts", parseErrors);
        Assert.True(parseErrors.Any(e => e.Contains("Line 3: Invalid timestamp.")), "DateTime parsing error not found for line 3.");
        Assert.True(parseErrors.Any(e => e.Contains("Line 4: Invalid source port 'NOT_A_PORT'.")), "Port parsing error not found for line 4.");
    }

    [Fact]
    public void Parse_WithTcpHyphenPlaceholders_IgnoresEntriesAndReportsErrors()
    {
        // Arrange - simplified fixture format with direction immediately after dst-port
        var rawLog = @"2024-01-15 10:30:15 ALLOW TCP 192.168.1.100 203.0.113.10 - 443 RECEIVE
2024-01-15 10:30:16 ALLOW TCP - 203.0.113.10 12345 443 RECEIVE
2024-01-15 10:30:17 ALLOW TCP 192.168.1.100 203.0.113.10 12345 - RECEIVE";

        // Act
        var entries = _parser.Parse(rawLog, out var totalLines, out var ignoredLines, out var parseErrors);

        // Assert
        Assert.Equal(3, totalLines);
        Assert.Equal(3, ignoredLines);
        Assert.Empty(entries);
        Assert.Equal(3, parseErrors.Count);
        Assert.Contains(parseErrors, e => e.Contains("Missing source or destination IP"));
        Assert.Contains(parseErrors, e => e.Contains("Invalid source port '-'"));
        Assert.Contains(parseErrors, e => e.Contains("Invalid destination port '-'"));
    }

    [Fact]
    public void Parse_WithNativePfirewallTrailingFields_ParsesCoreFieldsAndFinalDirection()
    {
        // Arrange - native pfirewall.log-style trailing fields with path token at the end
        var rawLog = "2024-01-15 10:30:15 ALLOW TCP 192.168.1.100 203.0.113.10 54321 443 59 - - - - - - - RECEIVE";

        // Act
        var entries = _parser.Parse(rawLog, out var totalLines, out var ignoredLines, out var parseErrors);

        // Assert
        Assert.Equal(1, totalLines);
        Assert.Equal(0, ignoredLines);
        Assert.Single(entries);
        Assert.Empty(parseErrors);

        var entry = entries[0];
        Assert.Equal("ALLOW", entry.Action);
        Assert.Equal("TCP", entry.Protocol);
        Assert.Equal("192.168.1.100", entry.SrcIp);
        Assert.Equal(54321, entry.SrcPort);
        Assert.Equal("203.0.113.10", entry.DstIp);
        Assert.Equal(443, entry.DstPort);
        Assert.Equal(59, entry.PacketSize);
        Assert.Equal("-", entry.TcpFlags);
        Assert.Equal("-", entry.TcpSyn);
        Assert.Equal("-", entry.TcpAck);
        Assert.Equal("-", entry.TcpWin);
        Assert.Equal("-", entry.IcmpType);
        Assert.Equal("-", entry.IcmpCode);
        Assert.Equal("-", entry.Info);
        Assert.Equal("RECEIVE", entry.Path);
        Assert.Equal("RECEIVE", entry.Direction);
    }

    [Fact]
    public void Parse_WithMixedWhitespace_ParsesCorrectly()
    {
        // Arrange - tabs and spaces mixed, simplified fixture format
        var rawLog = "2024-01-15\t10:30:15\tALLOW\tTCP\t192.168.1.100\t203.0.113.10\t54321\t443\tRECEIVE";

        // Act
        var entries = _parser.Parse(rawLog, out var totalLines, out var ignoredLines, out var parseErrors);

        // Assert
        Assert.Equal(1, totalLines);
        Assert.Equal(0, ignoredLines);
        Assert.Single(entries);
        Assert.Empty(parseErrors);
    }

    [Fact]
    public void Parse_WithInvalidTimestamp_IgnoresOnlyBadLine()
    {
        // Arrange - first line has slash-based date that should fail parsing
        var rawLog = @"2024/01/15 10:30:15 ALLOW TCP 192.168.1.100 203.0.113.10 54321 443 RECEIVE
2024-01-15 10:30:16 ALLOW TCP 10.0.0.5 8.8.8.8 12345 53 SEND";

        // Act
        var entries = _parser.Parse(rawLog, out var totalLines, out var ignoredLines, out var parseErrors);

        // Assert
        Assert.Equal(2, totalLines);
        Assert.Equal(1, ignoredLines);
        Assert.Single(entries);
        Assert.Single(parseErrors);
        Assert.Contains("Invalid timestamp", parseErrors[0]);
    }

    [Fact]
    public void Parse_WithIpv6Addresses_ParsesSuccessfully()
    {
        var rawLog = "2024-01-15 10:30:15 ALLOW TCP 2001:db8::1 2001:db8::2 54321 443 RECEIVE";

        var entries = _parser.Parse(rawLog, out var totalLines, out var ignoredLines, out var parseErrors);

        Assert.Equal(1, totalLines);
        Assert.Equal(0, ignoredLines);
        Assert.Single(entries);
        Assert.Empty(parseErrors);

        var entry = entries[0];
        Assert.Equal("2001:db8::1", entry.SrcIp);
        Assert.Equal("2001:db8::2", entry.DstIp);
    }

    [Fact]
    public void Parse_WithIcmpPlaceholderPorts_ParsesAndCapturesNativeFields()
    {
        var rawLog = "2024-01-15 10:30:15 ALLOW ICMP 192.168.1.100 203.0.113.10 - - 84 - - - - 8 0 - SEND";

        var entries = _parser.Parse(rawLog, out var totalLines, out var ignoredLines, out var parseErrors);

        Assert.Equal(1, totalLines);
        Assert.Equal(0, ignoredLines);
        Assert.Single(entries);
        Assert.Empty(parseErrors);

        var entry = entries[0];
        Assert.Null(entry.SrcPort);
        Assert.Null(entry.DstPort);
        Assert.Equal(84, entry.PacketSize);
        Assert.Equal("8", entry.IcmpType);
        Assert.Equal("0", entry.IcmpCode);
        Assert.Equal("SEND", entry.Path);
        Assert.Equal("SEND", entry.Direction);
    }

    [Fact]
    public void Parse_WithFieldsHeaderAndNativeTcpRow_IgnoresHeaderAndParsesRow()
    {
        var rawLog = @"#Version: 1.5
#Software: Microsoft Windows Firewall
#Time Format: Local
#Fields: date time action protocol src-ip dst-ip src-port dst-port size tcpflags tcpsyn tcpack tcpwin icmptype icmpcode info path pid
2026-04-18 14:12:37 DROP UDP 192.168.1.10 192.168.1.20 1234 1235 123 - - - - - - - RECEIVE 1289";

        var entries = _parser.Parse(rawLog, out var totalLines, out var ignoredLines, out var parseErrors);

        Assert.Equal(5, totalLines);
        Assert.Equal(4, ignoredLines);
        Assert.Single(entries);
        Assert.Empty(parseErrors);

        var entry = entries[0];
        Assert.Equal("DROP", entry.Action);
        Assert.Equal("UDP", entry.Protocol);
        Assert.Equal("192.168.1.10", entry.SrcIp);
        Assert.Equal("192.168.1.20", entry.DstIp);
        Assert.Equal(1234, entry.SrcPort);
        Assert.Equal(1235, entry.DstPort);
        Assert.Equal(123, entry.PacketSize);
        Assert.Equal("RECEIVE", entry.Path);
        Assert.Equal("RECEIVE", entry.Direction);
    }

    [Fact]
    public void Parse_WithFieldsHeaderAndNativeIcmpRow_IgnoresHeaderAndParsesRow()
    {
        var rawLog = @"#Version: 1.5
#Fields: date time action protocol src-ip dst-ip src-port dst-port size tcpflags tcpsyn tcpack tcpwin icmptype icmpcode info path pid
2026-04-18 14:12:37 ALLOW ICMP 192.168.1.10 203.0.113.40 - - 84 - - - - 8 0 - SEND 4321";

        var entries = _parser.Parse(rawLog, out var totalLines, out var ignoredLines, out var parseErrors);

        Assert.Equal(3, totalLines);
        Assert.Equal(2, ignoredLines);
        Assert.Single(entries);
        Assert.Empty(parseErrors);

        var entry = entries[0];
        Assert.Null(entry.SrcPort);
        Assert.Null(entry.DstPort);
        Assert.Equal(84, entry.PacketSize);
        Assert.Equal("8", entry.IcmpType);
        Assert.Equal("0", entry.IcmpCode);
        Assert.Equal("SEND", entry.Path);
        Assert.Equal("SEND", entry.Direction);
    }

    [Fact]
    public void Parse_WithNativeTrailingPid_IgnoresPidAndCapturesKnownNativeFields()
    {
        var rawLog = "2026-04-18 14:12:37 DROP UDP 192.168.1.10 192.168.1.20 1234 1235 123 - - - - - - - RECEIVE 1289";

        var entries = _parser.Parse(rawLog, out var totalLines, out var ignoredLines, out var parseErrors);

        Assert.Equal(1, totalLines);
        Assert.Equal(0, ignoredLines);
        Assert.Single(entries);
        Assert.Empty(parseErrors);

        var entry = entries[0];
        Assert.Equal(123, entry.PacketSize);
        Assert.Equal("-", entry.Info);
        Assert.Equal("RECEIVE", entry.Path);
        Assert.Equal("RECEIVE", entry.Direction);
        Assert.DoesNotContain("1289", entry.Path);
    }

    [Fact]
    public void Parse_WithNativeTrailingFieldsAndNoRecognizedPath_ParsesCoreFieldsButLeavesPathEmpty()
    {
        var rawLog = "2026-04-18 14:12:37 ALLOW TCP 192.168.1.10 203.0.113.40 5000 443 60 0x12 1 1 64240 - - note MAYBE 777";

        var entries = _parser.Parse(rawLog, out var totalLines, out var ignoredLines, out var parseErrors);

        Assert.Equal(1, totalLines);
        Assert.Equal(0, ignoredLines);
        Assert.Single(entries);
        Assert.Empty(parseErrors);

        var entry = entries[0];
        Assert.Equal(5000, entry.SrcPort);
        Assert.Equal(443, entry.DstPort);
        Assert.Equal("", entry.Path);
        Assert.Equal("", entry.Direction);
        Assert.Null(entry.PacketSize);
    }

    [Fact]
    public void Parse_WithMalformedNativeTrailingFields_KeepsCoreFieldsAndCapturesWhatItCan()
    {
        var rawLog = "2026-04-18 14:12:37 ALLOW TCP 192.168.1.10 203.0.113.40 5000 443 NOT_A_SIZE 0x12 1 1 64240 - - detail SEND";

        var entries = _parser.Parse(rawLog, out var totalLines, out var ignoredLines, out var parseErrors);

        Assert.Equal(1, totalLines);
        Assert.Equal(0, ignoredLines);
        Assert.Single(entries);
        Assert.Empty(parseErrors);

        var entry = entries[0];
        Assert.Equal(5000, entry.SrcPort);
        Assert.Equal(443, entry.DstPort);
        Assert.Null(entry.PacketSize);
        Assert.Equal("0x12", entry.TcpFlags);
        Assert.Equal("detail", entry.Info);
        Assert.Equal("SEND", entry.Path);
        Assert.Equal("SEND", entry.Direction);
    }

    [Fact]
    public void Parse_WithFieldsHeaderThatDisagreesWithRow_StillUsesCurrentPositionalParsing()
    {
        var rawLog = @"#Fields: date time action protocol dst-ip src-ip dst-port src-port size tcpflags tcpsyn tcpack tcpwin icmptype icmpcode info path pid
2026-04-18 14:12:37 ALLOW TCP 192.168.1.10 203.0.113.40 5000 443 60 - - - - - - - SEND 999";

        var entries = _parser.Parse(rawLog, out var totalLines, out var ignoredLines, out var parseErrors);

        Assert.Equal(2, totalLines);
        Assert.Equal(1, ignoredLines);
        Assert.Single(entries);
        Assert.Empty(parseErrors);

        var entry = entries[0];
        Assert.Equal("192.168.1.10", entry.SrcIp);
        Assert.Equal("203.0.113.40", entry.DstIp);
        Assert.Equal(5000, entry.SrcPort);
        Assert.Equal(443, entry.DstPort);
    }


    [Fact]
    public void Parse_WithInvalidIp_RecordsParseError()
    {
        var rawLog = "2024-01-15 10:30:15 ALLOW TCP not.an.ip 203.0.113.10 54321 443 RECEIVE";

        var entries = _parser.Parse(rawLog, out var totalLines, out var ignoredLines, out var parseErrors);

        Assert.Equal(1, totalLines);
        Assert.Equal(1, ignoredLines);
        Assert.Empty(entries);
        Assert.Single(parseErrors);
        Assert.Contains("Invalid source or destination IP", parseErrors[0]);
    }

    [Fact]
    public void Parse_WithIsoTimestampFormat_ParsesSuccessfully()
    {
        // ISO format: yyyy-MM-ddTHH:mm:ss (T separator instead of space)
        var rawLog = "2024-01-15T10:30:15 ALLOW TCP 192.168.1.100 203.0.113.10 54321 443 RECEIVE";

        var entries = _parser.Parse(rawLog, out var totalLines, out var ignoredLines, out var parseErrors);

        Assert.Equal(1, totalLines);
        Assert.Equal(0, ignoredLines);
        Assert.Single(entries);
        Assert.Empty(parseErrors);

        var entry = entries[0];
        Assert.Equal(new DateTime(2024, 1, 15, 10, 30, 15), entry.Timestamp);
        Assert.Equal(DateTimeKind.Local, entry.Timestamp.Kind);
        Assert.Equal("ALLOW", entry.Action);
    }

    [Fact]
    public void Parse_WithSpaceSeparatedFractionalSeconds_ParsesSuccessfully()
    {
        // Space-separated format with fractional seconds: yyyy-MM-dd HH:mm:ss.FFFFFFF
        var rawLog = "2024-01-15 10:30:15.1234567 ALLOW TCP 192.168.1.100 203.0.113.10 54321 443 RECEIVE";

        var entries = _parser.Parse(rawLog, out var totalLines, out var ignoredLines, out var parseErrors);

        Assert.Equal(1, totalLines);
        Assert.Equal(0, ignoredLines);
        Assert.Single(entries);
        Assert.Empty(parseErrors);

        var entry = entries[0];
        // Verify the fractional seconds are preserved (1234567 ticks = ~123.4567 ms)
        var expected = new DateTime(2024, 1, 15, 10, 30, 15).AddTicks(1234567);
        Assert.Equal(expected, entry.Timestamp);
        Assert.Equal(DateTimeKind.Local, entry.Timestamp.Kind);
    }

    [Fact]
    public void Parse_WithIsoFractionalSeconds_ParsesSuccessfully()
    {
        // ISO format with fractional seconds: yyyy-MM-ddTHH:mm:ss.FFFFFFF
        var rawLog = "2024-01-15T10:30:15.9876543 ALLOW TCP 192.168.1.100 203.0.113.10 54321 443 RECEIVE";

        var entries = _parser.Parse(rawLog, out var totalLines, out var ignoredLines, out var parseErrors);

        Assert.Equal(1, totalLines);
        Assert.Equal(0, ignoredLines);
        Assert.Single(entries);
        Assert.Empty(parseErrors);

        var entry = entries[0];
        // Verify the fractional seconds are preserved (9876543 ticks = ~987.6543 ms)
        var expected = new DateTime(2024, 1, 15, 10, 30, 15).AddTicks(9876543);
        Assert.Equal(expected, entry.Timestamp);
        Assert.Equal(DateTimeKind.Local, entry.Timestamp.Kind);
    }

    [Fact]
    public void Parse_WithAllFourTimestampFormats_ParsesEachCorrectly()
    {
        // Test all 4 supported formats in one log
        var rawLog = @"2024-01-15 10:30:15 ALLOW TCP 192.168.1.1 10.0.0.1 1001 80 RECEIVE
2024-01-15 10:30:15.5000000 ALLOW TCP 192.168.1.2 10.0.0.2 1002 81 RECEIVE
2024-01-15T10:30:15 ALLOW TCP 192.168.1.3 10.0.0.3 1003 82 RECEIVE
2024-01-15T10:30:15.2500000 ALLOW TCP 192.168.1.4 10.0.0.4 1004 83 RECEIVE";

        var entries = _parser.Parse(rawLog, out var totalLines, out var ignoredLines, out var parseErrors);

        Assert.Equal(4, totalLines);
        Assert.Equal(0, ignoredLines);
        Assert.Equal(4, entries.Count);
        Assert.Empty(parseErrors);

        // Verify each timestamp parsed correctly (using AddTicks for fractional precision)
        var baseTime = new DateTime(2024, 1, 15, 10, 30, 15);
        Assert.Equal(baseTime, entries[0].Timestamp);
        Assert.Equal(baseTime.AddTicks(5000000), entries[1].Timestamp); // .5000000 = 5000000 ticks
        Assert.Equal(baseTime, entries[2].Timestamp);
        Assert.Equal(baseTime.AddTicks(2500000), entries[3].Timestamp); // .2500000 = 2500000 ticks
    }

    [Fact]
    public void Parse_WithSimplifiedDirectionFollowedByExtraColumns_PreservesDirection()
    {
        var rawLog = "2024-01-15 10:30:15 ALLOW TCP 192.168.1.100 203.0.113.10 54321 443 RECEIVE EXTRA_COLUMN MORE_DATA";

        var entries = _parser.Parse(rawLog, out var totalLines, out var ignoredLines, out var parseErrors);

        Assert.Equal(1, totalLines);
        Assert.Equal(0, ignoredLines);
        Assert.Single(entries);
        Assert.Empty(parseErrors);
        Assert.Equal("RECEIVE", entries[0].Direction);
    }
}
