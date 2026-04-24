using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Threading;
using VulcansTrace.Core.Security;
using VulcansTrace.Engine;
using VulcansTrace.Engine.Configuration;
using VulcansTrace.Engine.Detectors;
using VulcansTrace.Evidence;
using VulcansTrace.Evidence.Formatters;
using VulcansTrace.Wpf.ViewModels;
using Xunit;

namespace VulcansTrace.Tests.Wpf;

public class MainViewModelIntegrationTests
{
    [Fact]
    public async Task AnalyzeAndExportEvidence_PopulatesFindingsAndExports()
    {
        var tcs = new TaskCompletionSource<bool>();
        var thread = new Thread(() =>
        {
            var dispatcher = Dispatcher.CurrentDispatcher;
            SynchronizationContext.SetSynchronizationContext(new DispatcherSynchronizationContext(dispatcher));

            dispatcher.InvokeAsync(async () =>
            {
                try
                {
                    await RunScenarioAsync();
                    tcs.SetResult(true);
                }
                catch (Exception ex)
                {
                    tcs.SetException(ex);
                }
                finally
                {
                    dispatcher.InvokeShutdown();
                }
            });

            Dispatcher.Run();
        })
        {
            IsBackground = true
        };
        thread.SetApartmentState(ApartmentState.STA);

        thread.Start();
        await tcs.Task;
    }

    private static async Task RunScenarioAsync()
    {
        // Arrange: build full engine stack
        var parser = new VulcansTrace.Core.Parsing.WindowsFirewallLogParser();
        var profileProvider = new AnalysisProfileProvider();
        var detectors = new IDetector[]
        {
            new PolicyViolationDetector()
        };
        var riskEscalator = new RiskEscalator();
        var analyzer = new SentryAnalyzer(parser, profileProvider, detectors, riskEscalator);

        var hasher = new IntegrityHasher();
        var csvFormatter = new CsvFormatter();
        var markdownFormatter = new MarkdownFormatter();
        var htmlFormatter = new HtmlFormatter();
        var evidenceBuilder = new EvidenceBuilder(hasher, csvFormatter, markdownFormatter, htmlFormatter);

        var dialog = new FakeDialogService();
        var vm = new MainViewModel(analyzer, evidenceBuilder, dialog, profileProvider);

        vm.LogText = "2024-01-01 12:00:00 ALLOW TCP 192.168.1.100 203.0.113.50 50000 21 60 - - - - - - - SEND";
        vm.SelectedIntensity = vm.Intensities.First(i => i.Level == IntensityLevel.High);

        vm.AnalyzeCommand.Execute(null);

        await WaitForCompletion(vm, timeoutMs: 2000);

        Assert.NotEmpty(vm.Findings.Items);
        Assert.Equal("PolicyViolation", vm.Findings.Items.First().Category);
        Assert.Contains("Found", vm.SummaryText);

        var tempPath = Path.GetTempFileName();
        try
        {
            dialog.SavePath = tempPath;
            vm.Evidence.ExportEvidenceCommand.Execute(null);
            await WaitForExport(vm, tempPath, timeoutMs: 2000);
            Assert.True(File.Exists(tempPath));
            Assert.True(new FileInfo(tempPath).Length > 0);
            Assert.Contains("saved", vm.SummaryText, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            if (File.Exists(tempPath))
                File.Delete(tempPath);
        }

        Assert.NotNull(dialog.LastMessage);
        Assert.True(string.IsNullOrEmpty(dialog.LastError));
    }

    [Fact]
    public async Task Analyze_WithPortScanCap_EmitsWarning()
    {
        var tcs = new TaskCompletionSource<bool>();
        var thread = new Thread(() =>
        {
            var dispatcher = Dispatcher.CurrentDispatcher;
            SynchronizationContext.SetSynchronizationContext(new DispatcherSynchronizationContext(dispatcher));

            dispatcher.InvokeAsync(async () =>
            {
                try
                {
                    await RunPortScanCapScenarioAsync();
                    tcs.SetResult(true);
                }
                catch (Exception ex)
                {
                    tcs.SetException(ex);
                }
                finally
                {
                    dispatcher.InvokeShutdown();
                }
            });

            Dispatcher.Run();
        })
        {
            IsBackground = true
        };
        thread.SetApartmentState(ApartmentState.STA);

        thread.Start();
        await tcs.Task;
    }

    private static async Task RunPortScanCapScenarioAsync()
    {
        var parser = new VulcansTrace.Core.Parsing.WindowsFirewallLogParser();
        var profileProvider = new AnalysisProfileProvider();
        var detectors = new IDetector[]
        {
            new PortScanDetector()
        };
        var riskEscalator = new RiskEscalator();
        var analyzer = new SentryAnalyzer(parser, profileProvider, detectors, riskEscalator);

        var hasher = new IntegrityHasher();
        var csvFormatter = new CsvFormatter();
        var markdownFormatter = new MarkdownFormatter();
        var htmlFormatter = new HtmlFormatter();
        var evidenceBuilder = new EvidenceBuilder(hasher, csvFormatter, markdownFormatter, htmlFormatter);

        var dialog = new FakeDialogService();
        var vm = new MainViewModel(analyzer, evidenceBuilder, dialog, profileProvider);

        vm.PortScanMaxEntriesPerSource = 9;
        vm.LogText = @"2024-01-01 12:00:00 ALLOW TCP 10.0.0.1 10.0.0.10 50000 21 OUTBOUND
2024-01-01 12:00:10 ALLOW TCP 10.0.0.1 10.0.0.11 50001 22 OUTBOUND
2024-01-01 12:00:20 ALLOW TCP 10.0.0.1 10.0.0.12 50002 23 OUTBOUND
2024-01-01 12:00:30 ALLOW TCP 10.0.0.1 10.0.0.13 50003 25 OUTBOUND
2024-01-01 12:00:40 ALLOW TCP 10.0.0.1 10.0.0.14 50004 53 OUTBOUND
2024-01-01 12:00:50 ALLOW TCP 10.0.0.1 10.0.0.15 50005 80 OUTBOUND
2024-01-01 12:01:00 ALLOW TCP 10.0.0.1 10.0.0.16 50006 110 OUTBOUND
2024-01-01 12:01:10 ALLOW TCP 10.0.0.1 10.0.0.17 50007 135 OUTBOUND
2024-01-01 12:01:20 ALLOW TCP 10.0.0.1 10.0.0.18 50008 139 OUTBOUND
2024-01-01 12:01:30 ALLOW TCP 10.0.0.1 10.0.0.19 50009 445 OUTBOUND";
        vm.SelectedIntensity = vm.Intensities.First(i => i.Level == IntensityLevel.High);

        vm.AnalyzeCommand.Execute(null);
        await WaitForCompletion(vm, timeoutMs: 2000);

        Assert.NotEmpty(vm.Findings.Items);
        Assert.Contains(vm.Findings.Items, f => f.Category == "PortScan");
        Assert.NotEmpty(vm.Findings.Warnings);
        Assert.Contains("warnings", vm.SummaryText, StringComparison.OrdinalIgnoreCase);
    }


    [Fact]
    public async Task ExportEvidence_RegeneratesSigningKeyPerExport()
    {
        var tcs = new TaskCompletionSource<bool>();
        var thread = new Thread(() =>
        {
            var dispatcher = Dispatcher.CurrentDispatcher;
            SynchronizationContext.SetSynchronizationContext(new DispatcherSynchronizationContext(dispatcher));

            dispatcher.InvokeAsync(async () =>
            {
                try
                {
                    await RunPerExportKeyScenarioAsync();
                    tcs.SetResult(true);
                }
                catch (Exception ex)
                {
                    tcs.SetException(ex);
                }
                finally
                {
                    dispatcher.InvokeShutdown();
                }
            });

            Dispatcher.Run();
        })
        {
            IsBackground = true
        };
        thread.SetApartmentState(ApartmentState.STA);

        thread.Start();
        await tcs.Task;
    }

    private static async Task RunPerExportKeyScenarioAsync()
    {
        var parser = new VulcansTrace.Core.Parsing.WindowsFirewallLogParser();
        var profileProvider = new AnalysisProfileProvider();
        var detectors = new IDetector[]
        {
            new PolicyViolationDetector()
        };
        var riskEscalator = new RiskEscalator();
        var analyzer = new SentryAnalyzer(parser, profileProvider, detectors, riskEscalator);

        var hasher = new IntegrityHasher();
        var csvFormatter = new CsvFormatter();
        var markdownFormatter = new MarkdownFormatter();
        var htmlFormatter = new HtmlFormatter();
        var evidenceBuilder = new EvidenceBuilder(hasher, csvFormatter, markdownFormatter, htmlFormatter);

        var dialog = new FakeDialogService();
        var vm = new MainViewModel(analyzer, evidenceBuilder, dialog, profileProvider);

        vm.LogText = "2024-01-01 12:00:00 ALLOW TCP 192.168.1.100 203.0.113.50 50000 21 60 - - - - - - - SEND";
        vm.SelectedIntensity = vm.Intensities.First(i => i.Level == IntensityLevel.High);

        vm.AnalyzeCommand.Execute(null);
        await WaitForCompletion(vm, timeoutMs: 2000);

        dialog.SavePath = Path.GetTempFileName();
        vm.Evidence.ExportEvidenceCommand.Execute(null);
        await WaitForExport(vm, dialog.SavePath, timeoutMs: 2000);
        var firstMasked = vm.Evidence.MaskedSigningKey;
        Assert.False(string.IsNullOrWhiteSpace(firstMasked));
        Assert.Equal(firstMasked, new string('*', firstMasked.Length));
        var firstKey = vm.Evidence.SigningKey;

        dialog.SavePath = Path.GetTempFileName();
        vm.Evidence.ExportEvidenceCommand.Execute(null);
        await WaitForExport(vm, dialog.SavePath, timeoutMs: 2000);
        var secondKey = vm.Evidence.SigningKey;

        Assert.NotEqual(firstKey, secondKey); // regenerated per export
    }

    [Fact]
    public async Task Analyze_WithManyParseErrors_CapsDisplayedAndTogglesBanner()
    {
        var tcs = new TaskCompletionSource<bool>();
        var thread = new Thread(() =>
        {
            var dispatcher = Dispatcher.CurrentDispatcher;
            SynchronizationContext.SetSynchronizationContext(new DispatcherSynchronizationContext(dispatcher));

            dispatcher.InvokeAsync(async () =>
            {
                try
                {
                    await RunParseErrorCapScenarioAsync();
                    tcs.SetResult(true);
                }
                catch (Exception ex)
                {
                    tcs.SetException(ex);
                }
                finally
                {
                    dispatcher.InvokeShutdown();
                }
            });

            Dispatcher.Run();
        })
        {
            IsBackground = true
        };
        thread.SetApartmentState(ApartmentState.STA);

        thread.Start();
        await tcs.Task;
    }

    private static async Task RunParseErrorCapScenarioAsync()
    {
        var parser = new VulcansTrace.Core.Parsing.WindowsFirewallLogParser();
        var profileProvider = new AnalysisProfileProvider();
        var detectors = Array.Empty<IDetector>();
        var riskEscalator = new RiskEscalator();
        var analyzer = new SentryAnalyzer(parser, profileProvider, detectors, riskEscalator);

        var hasher = new IntegrityHasher();
        var csvFormatter = new CsvFormatter();
        var markdownFormatter = new MarkdownFormatter();
        var htmlFormatter = new HtmlFormatter();
        var evidenceBuilder = new EvidenceBuilder(hasher, csvFormatter, markdownFormatter, htmlFormatter);

        var dialog = new FakeDialogService();
        var vm = new MainViewModel(analyzer, evidenceBuilder, dialog, profileProvider);

        var sb = new StringBuilder();
        for (var i = 0; i < 300; i++)
        {
            sb.AppendLine("INVALID LINE");
        }

        vm.LogText = sb.ToString();
        vm.SelectedIntensity = vm.Intensities.First(i => i.Level == IntensityLevel.Medium);

        vm.AnalyzeCommand.Execute(null);
        await WaitForCompletion(vm, timeoutMs: 2000);

        Assert.True(vm.Findings.HasParseErrors);
        Assert.Equal(300, vm.Findings.ParseErrorCount);
        Assert.Equal(201, vm.Findings.ParseErrors.Count);
        Assert.Contains("parse errors not shown", vm.Findings.ParseErrors.Last(), StringComparison.OrdinalIgnoreCase);

        vm.LogText = "2024-01-01 00:00:00 ALLOW TCP 10.0.0.1 10.0.0.2 1000 2000 INBOUND";
        vm.AnalyzeCommand.Execute(null);
        await WaitForCompletion(vm, timeoutMs: 2000);

        Assert.False(vm.Findings.HasParseErrors);
        Assert.Equal(0, vm.Findings.ParseErrorCount);
        Assert.Empty(vm.Findings.ParseErrors);
    }


    private static async Task WaitForCompletion(MainViewModel vm, int timeoutMs)
    {
        var sw = Stopwatch.StartNew();
        while (sw.ElapsedMilliseconds < timeoutMs)
        {
            if (!vm.IsBusy && vm.LastResult != null)
                break;
            await Task.Delay(10);
        }
    }

    private static async Task WaitForExport(MainViewModel vm, string path, int timeoutMs)
    {
        var sw = Stopwatch.StartNew();
        while (sw.ElapsedMilliseconds < timeoutMs)
        {
            // Note: vm.IsBusy is no longer true during export; vm.Evidence.IsBusy is.
            if (!vm.Evidence.IsBusy && File.Exists(path))
            {
                return;
            }
            await Task.Delay(10);
        }

        throw new TimeoutException("Export did not complete within the expected time.");
    }
}
