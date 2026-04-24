using System.Linq;
using VulcansTrace.Core.Security;
using VulcansTrace.Engine;
using VulcansTrace.Engine.Configuration;
using VulcansTrace.Engine.Detectors;
using VulcansTrace.Evidence;
using VulcansTrace.Evidence.Formatters;
using VulcansTrace.Wpf.ViewModels;
using Xunit;

namespace VulcansTrace.Tests.Wpf;

public class MainViewModelTextTests
{
    [Fact]
    public void Intensities_UsePlainAsciiHyphens_NoEncodingArtifacts()
    {
        var parser = new VulcansTrace.Core.Parsing.WindowsFirewallLogParser();
        var profileProvider = new AnalysisProfileProvider();
        var detectors = new IDetector[] { };
        var riskEscalator = new RiskEscalator();
        var analyzer = new SentryAnalyzer(parser, profileProvider, detectors, riskEscalator);

        var hasher = new IntegrityHasher();
        var csv = new CsvFormatter();
        var md = new MarkdownFormatter();
        var html = new HtmlFormatter();
        var evidenceBuilder = new EvidenceBuilder(hasher, csv, md, html);

        var vm = new MainViewModel(analyzer, evidenceBuilder, new FakeDialogService(), profileProvider);

        Assert.DoesNotContain(vm.Intensities.Select(i => i.Display), display => display.Contains('â'));
        Assert.All(vm.Intensities.Select(i => i.Display), display => Assert.Contains(" - ", display));
    }
}
