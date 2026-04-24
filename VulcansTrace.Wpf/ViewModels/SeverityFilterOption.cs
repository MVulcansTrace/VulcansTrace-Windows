using VulcansTrace.Core;

namespace VulcansTrace.Wpf.ViewModels;

public sealed class SeverityFilterOption
{
    public string Display { get; }
    public Severity? MinSeverity { get; }

    public SeverityFilterOption(string display, Severity? minSeverity)
    {
        Display = display;
        MinSeverity = minSeverity;
    }

    public override string ToString() => Display;
}
