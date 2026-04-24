using System.IO;
using System.Text;
using System.Windows;
using VulcansTrace.Core.Parsing;
using VulcansTrace.Core.Security;
using VulcansTrace.Engine;
using VulcansTrace.Engine.Configuration;
using VulcansTrace.Engine.Detectors;
using VulcansTrace.Evidence;
using VulcansTrace.Evidence.Formatters;
using VulcansTrace.Wpf.Services;
using VulcansTrace.Wpf.ViewModels;
using Microsoft.Win32;

namespace VulcansTrace.Wpf;

/// <summary>
/// Interaction logic for MainWindow.xaml
/// </summary>
public partial class MainWindow : Window
{
    private readonly MainViewModel _viewModel;
    private readonly EvidenceBuilder _evidenceBuilder;

    public MainWindow()
    {
        InitializeComponent();

        // Wire up the complete engine chain
        var parser = new WindowsFirewallLogParser();
        var profileProvider = new AnalysisProfileProvider();
        var detectors = new IDetector[]
        {
            new PortScanDetector(),
            new FloodDetector(),
            new LateralMovementDetector(),
            new BeaconingDetector(),
            new PolicyViolationDetector(),
            new NoveltyDetector()
        };
        var riskEscalator = new RiskEscalator();
        var analyzer = new SentryAnalyzer(parser, profileProvider, detectors, riskEscalator);

        // Wire up evidence building
        var hasher = new IntegrityHasher();
        var csvFormatter = new CsvFormatter();
        var markdownFormatter = new MarkdownFormatter();
        var htmlFormatter = new HtmlFormatter();
        _evidenceBuilder = new EvidenceBuilder(hasher, csvFormatter, markdownFormatter, htmlFormatter);

        _viewModel = new MainViewModel(analyzer, _evidenceBuilder, new WpfDialogService(), profileProvider);
        DataContext = _viewModel;
    }
}
