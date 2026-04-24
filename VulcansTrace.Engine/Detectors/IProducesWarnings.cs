namespace VulcansTrace.Engine.Detectors;

/// <summary>
/// Implemented by detectors that can generate non-fatal warnings during analysis.
/// </summary>
/// <remarks>
/// Warnings are collected and included in the analysis result without stopping the analysis.
/// </remarks>
public interface IProducesWarnings
{
    /// <summary>Gets the collection of warnings generated during the last detection run.</summary>
    IReadOnlyList<string> Warnings { get; }
}
