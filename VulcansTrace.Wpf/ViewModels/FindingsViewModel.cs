using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Windows.Data;
using VulcansTrace.Core;

namespace VulcansTrace.Wpf.ViewModels;

/// <summary>
/// ViewModel for displaying, filtering, and managing security findings.
/// </summary>
public sealed class FindingsViewModel : ViewModelBase
{
    private const int MaxParseErrorsToDisplay = 200;

    private string _searchText = "";
    private SeverityFilterOption? _selectedSeverityFilter;
    private int _findingsCount;
    private int _highCriticalCount;
    private int _warningCount;
    private int _parseErrorCount;
    private bool _hasWarnings;
    private bool _hasParseErrors;

    /// <summary>Gets the collection of findings to display.</summary>
    public ObservableCollection<FindingItemViewModel> Items { get; } = new();

    /// <summary>Gets the filtered view of findings.</summary>
    public ICollectionView ItemsView { get; }

    /// <summary>Gets the collection of parse errors.</summary>
    public ObservableCollection<string> ParseErrors { get; } = new();

    /// <summary>Gets the collection of warnings.</summary>
    public ObservableCollection<string> Warnings { get; } = new();

    /// <summary>Gets the available severity filter options.</summary>
    public ObservableCollection<SeverityFilterOption> SeverityFilters { get; } = new();

    /// <summary>Gets or sets the search text for filtering findings.</summary>
    public string SearchText
    {
        get => _searchText;
        set
        {
            if (SetField(ref _searchText, value))
            {
                ItemsView.Refresh();
            }
        }
    }

    /// <summary>Gets or sets the selected severity filter.</summary>
    public SeverityFilterOption? SelectedSeverityFilter
    {
        get => _selectedSeverityFilter;
        set
        {
            if (SetField(ref _selectedSeverityFilter, value))
            {
                ItemsView.Refresh();
            }
        }
    }

    /// <summary>Gets the total number of findings.</summary>
    public int FindingsCount
    {
        get => _findingsCount;
        private set => SetField(ref _findingsCount, value);
    }

    /// <summary>Gets the count of High and Critical severity findings.</summary>
    public int HighCriticalCount
    {
        get => _highCriticalCount;
        private set => SetField(ref _highCriticalCount, value);
    }

    /// <summary>Gets the number of warnings.</summary>
    public int WarningCount
    {
        get => _warningCount;
        private set
        {
            if (SetField(ref _warningCount, value))
            {
                HasWarnings = value > 0;
            }
        }
    }

    /// <summary>Gets the number of parse errors.</summary>
    public int ParseErrorCount
    {
        get => _parseErrorCount;
        private set
        {
            if (SetField(ref _parseErrorCount, value))
            {
                HasParseErrors = value > 0;
            }
        }
    }

    /// <summary>Gets whether there are any warnings.</summary>
    public bool HasWarnings
    {
        get => _hasWarnings;
        private set => SetField(ref _hasWarnings, value);
    }

    /// <summary>Gets whether there are any parse errors.</summary>
    public bool HasParseErrors
    {
        get => _hasParseErrors;
        private set => SetField(ref _hasParseErrors, value);
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="FindingsViewModel"/> class.
    /// </summary>
    public FindingsViewModel()
    {
        ItemsView = CollectionViewSource.GetDefaultView(Items);
        ItemsView.Filter = FilterFindings;

        // Initialize severity filters
        SeverityFilters.Add(new SeverityFilterOption("All severities", null));
        SeverityFilters.Add(new SeverityFilterOption("High & Critical only", Severity.High));
        SeverityFilters.Add(new SeverityFilterOption("Critical only", Severity.Critical));
        SelectedSeverityFilter = SeverityFilters[0];
    }

    /// <summary>
    /// Loads findings and statistics from an analysis result.
    /// </summary>
    /// <param name="result">The analysis result to load.</param>
    public void LoadResults(AnalysisResult result)
    {
        if (System.Windows.Application.Current?.Dispatcher?.CheckAccess() == false)
        {
            System.Windows.Application.Current.Dispatcher.Invoke(() => LoadResults(result));
            return;
        }

        // Clear previous data
        Items.Clear();
        ParseErrors.Clear();
        Warnings.Clear();

        // Load findings — group Novelty entries by source host to reduce grid noise
        var groupedFindings = GroupNoveltyFindings(result.Findings);
        foreach (var vm in groupedFindings)
        {
            Items.Add(vm);
        }

        // Load parse errors (with limit)
        var totalParseErrors = result.ParseErrorCount;
        var errorsToDisplay = result.ParseErrors;
        var displayLimit = Math.Min(MaxParseErrorsToDisplay, errorsToDisplay.Count);

        for (var i = 0; i < displayLimit; i++)
        {
            ParseErrors.Add(errorsToDisplay[i]);
        }

        if (totalParseErrors > displayLimit)
        {
            var remaining = totalParseErrors - displayLimit;
            ParseErrors.Add($"...and {remaining} more parse errors not shown.");
        }

        // Load warnings
        foreach (var warning in result.Warnings)
        {
            Warnings.Add(warning);
        }

        // Update statistics
        FindingsCount = result.Findings.Count;
        HighCriticalCount = result.Findings.Count(f => f.Severity >= Severity.High);
        WarningCount = result.Warnings.Count;
        ParseErrorCount = result.ParseErrorCount;
    }

    /// <summary>
    /// Clears all findings and resets statistics.
    /// </summary>
    public void Clear()
    {
        Items.Clear();
        ParseErrors.Clear();
        Warnings.Clear();
        FindingsCount = 0;
        HighCriticalCount = 0;
        WarningCount = 0;
        ParseErrorCount = 0;
    }

    /// <summary>
    /// Groups Novelty findings by source host. When a host has 2+ Novelty findings,
    /// they are collapsed into a single aggregate row to reduce UI noise.
    /// Other finding categories are passed through unchanged.
    /// </summary>
    private static IEnumerable<FindingItemViewModel> GroupNoveltyFindings(IReadOnlyList<Finding> findings)
    {
        var noveltyGroups = findings
            .Where(f => f.Category.Equals("Novelty", StringComparison.OrdinalIgnoreCase))
            .GroupBy(f => f.SourceHost ?? string.Empty)
            .ToDictionary(g => g.Key, g => g.ToList());

        foreach (var finding in findings)
        {
            // Pass non-Novelty findings through unchanged
            if (!finding.Category.Equals("Novelty", StringComparison.OrdinalIgnoreCase))
            {
                yield return new FindingItemViewModel(finding);
                continue;
            }

            // Only emit the grouped aggregate once per host
            var host = finding.SourceHost ?? string.Empty;
            if (!noveltyGroups.TryGetValue(host, out var hostFindings))
                continue;

            // Remove from dictionary so we only emit once
            noveltyGroups.Remove(host);

            if (hostFindings.Count == 1)
            {
                // Single Novelty finding — show as-is
                yield return new FindingItemViewModel(hostFindings[0]);
            }
            else
            {
                // Multiple Novelty findings — collapse into aggregate row
                var targets = hostFindings.Select(f => f.Target).ToList();
                var minTime = hostFindings.Min(f => f.TimeRangeStart);
                var maxTime = hostFindings.Max(f => f.TimeRangeEnd);

                var countLabel = hostFindings.Count > 1 ? $" (×{hostFindings.Count})" : "";
                yield return new FindingItemViewModel(
                    category: $"Novelty{countLabel}",
                    severity: hostFindings[0].Severity.ToString(),
                    sourceHost: host,
                    target: $"{hostFindings.Count} unique external destinations",
                    timeStart: minTime,
                    timeEnd: maxTime,
                    shortDescription: $"Novel external destinations from {host}",
                    groupCount: hostFindings.Count,
                    groupDetails: string.Join("\n", targets));
            }
        }
    }

    private bool FilterFindings(object item)
    {
        if (item is not FindingItemViewModel finding)
            return false;

        // Apply severity filter
        if (_selectedSeverityFilter?.MinSeverity != null &&
            Enum.TryParse<Severity>(finding.Severity, out var sev) &&
            sev < _selectedSeverityFilter.MinSeverity.Value)
        {
            return false;
        }

        // Apply text search
        if (string.IsNullOrWhiteSpace(_searchText))
            return true;

        return finding.Category.Contains(_searchText, StringComparison.OrdinalIgnoreCase) ||
               finding.SourceHost.Contains(_searchText, StringComparison.OrdinalIgnoreCase) ||
               finding.Target.Contains(_searchText, StringComparison.OrdinalIgnoreCase) ||
               finding.ShortDescription.Contains(_searchText, StringComparison.OrdinalIgnoreCase);
    }
}
