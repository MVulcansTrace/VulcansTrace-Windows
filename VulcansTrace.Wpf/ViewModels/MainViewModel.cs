using System.Collections.ObjectModel;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Input;
using VulcansTrace.Core;
using VulcansTrace.Engine;
using VulcansTrace.Engine.Configuration;
using VulcansTrace.Evidence;
using VulcansTrace.Wpf.Services;

namespace VulcansTrace.Wpf.ViewModels;

/// <summary>
/// Main ViewModel coordinating analysis operations and child ViewModels.
/// </summary>
public sealed class MainViewModel : ViewModelBase
{
    private readonly SentryAnalyzer _analyzer;
    private readonly AnalysisProfileProvider _profileProvider;
    private CancellationTokenSource? _cancellationTokenSource;

    private string _logText = "";
    private string _summaryText = "";
    private string _botIntroText = "";
    private string _advisorMessage = "";
    private int _portScanCap;
    private bool _isBusy;
    private bool _hasAdvisorMessage;
    private IntensityOption? _selectedIntensity;
    private AnalysisResult? _lastResult;

    /// <summary>Gets the last analysis result.</summary>
    public AnalysisResult? LastResult => _lastResult;

    // Child ViewModels
    
    /// <summary>Gets the child ViewModel for evidence/export operations.</summary>
    public EvidenceViewModel Evidence { get; }
    
    /// <summary>Gets the child ViewModel for findings display and filtering.</summary>
    public FindingsViewModel Findings { get; }

    /// <summary>Gets the available intensity options.</summary>
    public ObservableCollection<IntensityOption> Intensities { get; } = new();

    /// <summary>Gets or sets the raw log text to analyze.</summary>
    public string LogText
    {
        get => _logText;
        set
        {
            if (SetField(ref _logText, value))
            {
                if (string.IsNullOrWhiteSpace(value))
                {
                    AdvisorMessage = string.Empty;
                }
            }
        }
    }

    /// <summary>Gets or sets the summary status text.</summary>
    public string SummaryText
    {
        get => _summaryText;
        set => SetField(ref _summaryText, value);
    }

    /// <summary>Gets or sets the bot intro text.</summary>
    public string BotIntroText
    {
        get => _botIntroText;
        set => SetField(ref _botIntroText, value);
    }

    /// <summary>Gets the advisor message.</summary>
    public string AdvisorMessage
    {
        get => _advisorMessage;
        private set
        {
            if (SetField(ref _advisorMessage, value))
            {
                HasAdvisorMessage = !string.IsNullOrWhiteSpace(value);
            }
        }
    }

    /// <summary>Gets whether there is an advisor message.</summary>
    public bool HasAdvisorMessage
    {
        get => _hasAdvisorMessage;
        private set => SetField(ref _hasAdvisorMessage, value);
    }

    /// <summary>Gets or sets whether an analysis is in progress.</summary>
    public bool IsBusy
    {
        get => _isBusy;
        set => SetField(ref _isBusy, value);
    }

    /// <summary>Gets or sets the selected intensity option.</summary>
    public IntensityOption? SelectedIntensity
    {
        get => _selectedIntensity;
        set => SetField(ref _selectedIntensity, value);
    }

    /// <summary>Gets or sets the port scan max entries per source override.</summary>
    public int PortScanMaxEntriesPerSource
    {
        get => _portScanCap;
        set => SetField(ref _portScanCap, value);
    }

    /// <summary>Gets the analyze command.</summary>
    public ICommand AnalyzeCommand { get; }
    
    /// <summary>Gets the cancel command.</summary>
    public ICommand CancelCommand { get; }

    /// <summary>
    /// Initializes a new instance of the <see cref="MainViewModel"/> class.
    /// </summary>
    public MainViewModel(
        SentryAnalyzer analyzer, 
        EvidenceBuilder evidenceBuilder,
        IDialogService dialogService,
        AnalysisProfileProvider profileProvider)
    {
        _analyzer = analyzer;
        _profileProvider = profileProvider;

        // Initialize child ViewModels
        Findings = new FindingsViewModel();
        Evidence = new EvidenceViewModel(evidenceBuilder, dialogService);
        Evidence.StatusChanged += (s, msg) => SummaryText = msg;

        BotIntroText = "Hi, I'm VulcansTrace. Paste a Windows Firewall log, choose scan intensity, and I'll flag port scans, floods, lateral movement, beaconing, policy violations, and novelty destinations.";
        SummaryText = "Paste a Windows Firewall log and choose an intensity to begin.";

        Intensities.Add(new IntensityOption("Low - Critical Threat Triage", IntensityLevel.Low));
        Intensities.Add(new IntensityOption("Medium - Investigation Review", IntensityLevel.Medium));
        Intensities.Add(new IntensityOption("High - Deep Hunt / Forensics", IntensityLevel.High));
        SelectedIntensity = Intensities[0];
        PortScanMaxEntriesPerSource = 0;

        AnalyzeCommand = new RelayCommand(async _ => await AnalyzeAsync(), _ => CanAnalyze());
        CancelCommand = new RelayCommand(_ => CancelAnalysis(), _ => CanCancel());
    }

    private bool CanAnalyze() =>
        !_isBusy && !string.IsNullOrWhiteSpace(_logText) && _selectedIntensity != null;

    private bool CanCancel() => _isBusy && _cancellationTokenSource != null && !_cancellationTokenSource.IsCancellationRequested;

    private void CancelAnalysis()
    {
        _cancellationTokenSource?.Cancel();
    }

    private async Task AnalyzeAsync()
    {
        if (_selectedIntensity == null || string.IsNullOrWhiteSpace(_logText))
        {
            SummaryText = "Paste a log and select an intensity first.";
            return;
        }

        IsBusy = true;
        SummaryText = "Analyzing log...";
        AdvisorMessage = "Analyzing...";
        
        // Prepare cancellation token
        _cancellationTokenSource?.Dispose();
        _cancellationTokenSource = new CancellationTokenSource();
        var token = _cancellationTokenSource.Token;

        AnalysisResult result;
        string logSnapshot;
        try
        {
            var intensity = _selectedIntensity.Level;
            logSnapshot = _logText;
            result = await Task.Run(() => AnalyzeWithOverrides(intensity, logSnapshot, token), token);
        }
        catch (OperationCanceledException)
        {
            IsBusy = false;
            SummaryText = "Analysis cancelled by user.";
            AdvisorMessage = "Analysis cancelled.";
            return;
        }
        catch (Exception ex)
        {
            IsBusy = false;
            SummaryText = $"Analysis failed: {ex.Message}";
            AdvisorMessage = "Analysis failed.";
            return;
        }

        _lastResult = result;
        var lastAnalysisTimestampUtc = result.TimeRangeEnd?.ToUniversalTime()
            ?? result.TimeRangeStart?.ToUniversalTime()
            ?? DateTime.UnixEpoch;

        // Delegate to child ViewModels
        Evidence.SetEvidenceContext(_lastResult, logSnapshot, lastAnalysisTimestampUtc);
        Findings.LoadResults(result);

        // Build summary text
        var total = Findings.FindingsCount;
        var highOrCritical = Findings.HighCriticalCount;

        SummaryText = total == 0
            ? "No findings at the current intensity."
            : $"Found {total} issues, {highOrCritical} High/Critical.";

        if (Findings.ParseErrorCount > 0)
        {
            SummaryText += $" ({Findings.ParseErrorCount} parse errors)";
        }
        if (Findings.WarningCount > 0)
        {
            SummaryText += $" ({Findings.WarningCount} warnings)";
        }

        UpdateAdvisorMessage(result, highOrCritical, total);

        BotIntroText = _selectedIntensity.Level switch
        {
            IntensityLevel.Low =>
                "Low intensity: only clear, high-confidence threats are shown.",
            IntensityLevel.Medium =>
                "Medium intensity: balanced investigation of suspicious activity.",
            IntensityLevel.High =>
                "High intensity: deep hunt mode, including subtle and borderline patterns.",
            _ => BotIntroText
        };

        IsBusy = false;
    }

    private AnalysisResult AnalyzeWithOverrides(IntensityLevel intensity, string logText, CancellationToken token)
    {
        // Get base profile and create modified copy using with expression (immutable)
        var baseProfile = _profileProvider.GetProfile(intensity);
        var profile = PortScanMaxEntriesPerSource > 0
            ? baseProfile with { PortScanMaxEntriesPerSource = PortScanMaxEntriesPerSource }
            : baseProfile;

        return _analyzer.Analyze(logText, intensity, token, profile);
    }

    private void UpdateAdvisorMessage(AnalysisResult result, int highCritical, int totalFindings)
    {
        if (result == null)
        {
            AdvisorMessage = string.Empty;
            return;
        }

        if (result.ParseErrorCount > 0 && totalFindings == 0)
        {
            AdvisorMessage = "Fix parse errors in the log and re-run to surface findings.";
            return;
        }

        if (totalFindings == 0)
        {
            AdvisorMessage = "No findings at this intensity. Try High intensity or adjust filters.";
            return;
        }

        if (highCritical >= 3)
        {
            AdvisorMessage = "Multiple High/Critical issues detected. Triage those first, then sweep the rest.";
        }
        else if (highCritical > 0)
        {
            AdvisorMessage = "Prioritize High/Critical findings, then review remaining events.";
        }
        else if (result.Warnings.Count > 0)
        {
            AdvisorMessage = "Findings detected; review warnings for any truncated or skipped activity.";
        }
        else
        {
            AdvisorMessage = "Findings detected. Review sources/targets to determine next steps.";
        }

        if (result.ParseErrorCount > 0)
        {
            AdvisorMessage += " Fix remaining parse errors to improve coverage.";
        }
    }
}
