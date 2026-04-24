namespace VulcansTrace.Core;

/// <summary>
/// Represents a single parsed Windows Firewall log entry.
/// </summary>
/// <remarks>
/// Immutable record created by the parser. Contains timestamp, network details, and protocol information.
/// </remarks>
public sealed record LogEntry
{
    /// <summary>The timestamp of the log entry.</summary>
    public required DateTime Timestamp { get; init; }
    
    /// <summary>The firewall action (ALLOW/DROP).</summary>
    public string Action { get; init; } = "";
    
    /// <summary>The network protocol (TCP/UDP/ICMP).</summary>
    public string Protocol { get; init; } = "";
    
    /// <summary>The source IP address.</summary>
    public string SrcIp { get; init; } = "";
    
    /// <summary>The source port number when the protocol uses ports.</summary>
    public int? SrcPort { get; init; }
    
    /// <summary>The destination IP address.</summary>
    public string DstIp { get; init; } = "";
    
    /// <summary>The destination port number when the protocol uses ports.</summary>
    public int? DstPort { get; init; }

    /// <summary>The packet size field from native pfirewall rows when present.</summary>
    public int? PacketSize { get; init; }

    /// <summary>The raw TCP flags field from native pfirewall rows when present.</summary>
    public string TcpFlags { get; init; } = "";

    /// <summary>The raw TCP SYN field from native pfirewall rows when present.</summary>
    public string TcpSyn { get; init; } = "";

    /// <summary>The raw TCP ACK field from native pfirewall rows when present.</summary>
    public string TcpAck { get; init; } = "";

    /// <summary>The raw TCP window field from native pfirewall rows when present.</summary>
    public string TcpWin { get; init; } = "";

    /// <summary>The raw ICMP type field from native pfirewall rows when present.</summary>
    public string IcmpType { get; init; } = "";

    /// <summary>The raw ICMP code field from native pfirewall rows when present.</summary>
    public string IcmpCode { get; init; } = "";

    /// <summary>The info field from native pfirewall rows when present.</summary>
    public string Info { get; init; } = "";

    /// <summary>The final path token from native pfirewall rows when present, such as SEND or RECEIVE.</summary>
    public string Path { get; init; } = "";

    /// <summary>A compatibility alias for the recognized trailing path or direction token.</summary>
    public string Direction { get; init; } = "";
    
    /// <summary>The original unparsed log line.</summary>
    public string RawLine { get; init; } = "";
}
