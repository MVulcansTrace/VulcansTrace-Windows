using VulcansTrace.Core;

namespace VulcansTrace.Wpf.ViewModels;

public sealed class FindingItemViewModel
{
    public string Category { get; }
    public string Severity { get; }
    public string SourceHost { get; }
    public string Target { get; }
    public DateTime TimeStart { get; }
    public DateTime TimeEnd { get; }
    public string ShortDescription { get; }

    public FindingItemViewModel(Finding finding)
    {
        Category = finding.Category;
        Severity = finding.Severity.ToString();
        SourceHost = finding.SourceHost;
        Target = finding.Target;
        TimeStart = finding.TimeRangeStart;
        TimeEnd = finding.TimeRangeEnd;
        ShortDescription = finding.ShortDescription;
    }
}