using VulcansTrace.Core;

namespace VulcansTrace.Wpf.ViewModels;

/// <summary>
/// ViewModel wrapper for a single finding row in the DataGrid.
/// Supports both raw findings and grouped aggregates (e.g., multiple Novelty entries collapsed).
/// </summary>
public sealed class FindingItemViewModel
{
    public string Category { get; set; }
    public string Severity { get; }
    public string SourceHost { get; }
    public string Target { get; }
    public DateTime TimeStart { get; }
    public DateTime TimeEnd { get; }
    public string ShortDescription { get; }

    /// <summary>True when this row represents a grouped aggregate of multiple findings.</summary>
    public bool IsGrouped { get; }

    /// <summary>Number of findings collapsed into this grouped row.</summary>
    public int GroupCount { get; }

    /// <summary>Detailed list of targets for grouped rows (shown in tooltip).</summary>
    public string GroupDetails { get; }

    public FindingItemViewModel(Finding finding)
    {
        Category = finding.Category;
        Severity = finding.Severity.ToString();
        SourceHost = finding.SourceHost;
        Target = finding.Target;
        TimeStart = finding.TimeRangeStart;
        TimeEnd = finding.TimeRangeEnd;
        ShortDescription = finding.ShortDescription;
        IsGrouped = false;
        GroupCount = 1;
        GroupDetails = string.Empty;
    }

    /// <summary>
    /// Creates a grouped aggregate row for multiple findings from the same source.
    /// </summary>
    public FindingItemViewModel(
        string category,
        string severity,
        string sourceHost,
        string target,
        DateTime timeStart,
        DateTime timeEnd,
        string shortDescription,
        int groupCount,
        string groupDetails)
    {
        Category = category;
        Severity = severity;
        SourceHost = sourceHost;
        Target = target;
        TimeStart = timeStart;
        TimeEnd = timeEnd;
        ShortDescription = shortDescription;
        IsGrouped = true;
        GroupCount = groupCount;
        GroupDetails = groupDetails;
    }
}
