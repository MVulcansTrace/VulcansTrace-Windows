using VulcansTrace.Engine;

namespace VulcansTrace.Wpf.ViewModels;

public sealed class IntensityOption
{
    public string Display { get; }
    public IntensityLevel Level { get; }

    public IntensityOption(string display, IntensityLevel level)
    {
        Display = display;
        Level = level;
    }

    public override string ToString() => Display;
}