using System;
using System.Linq;
using VulcansTrace.Core;
using VulcansTrace.Wpf.ViewModels;
using Xunit;

namespace VulcansTrace.Tests.Wpf;

public class FindingsViewModelTests
{
    [Fact]
    public void LoadResults_WithNoveltyFindings_GroupsBySourceHost()
    {
        var vm = new FindingsViewModel();
        var result = new AnalysisResult();

        // Add 3 Novelty findings from same host
        for (int i = 0; i < 3; i++)
        {
            result.AddFinding(new Finding
            {
                Category = "Novelty",
                Severity = Severity.Low,
                SourceHost = "10.0.0.99",
                Target = $"1.2.3.4:{1000 + i}",
                TimeRangeStart = DateTime.Now,
                TimeRangeEnd = DateTime.Now,
                ShortDescription = "Novel external destination"
            });
        }

        // Add 1 Novelty from different host
        result.AddFinding(new Finding
        {
            Category = "Novelty",
            Severity = Severity.Low,
            SourceHost = "192.168.1.50",
            Target = "5.6.7.8:443",
            TimeRangeStart = DateTime.Now,
            TimeRangeEnd = DateTime.Now,
            ShortDescription = "Novel external destination"
        });

        // Add a non-Novelty finding
        result.AddFinding(new Finding
        {
            Category = "PortScan",
            Severity = Severity.Medium,
            SourceHost = "10.0.0.99",
            Target = "multiple hosts/ports",
            TimeRangeStart = DateTime.Now,
            TimeRangeEnd = DateTime.Now,
            ShortDescription = "Port scan detected"
        });

        vm.LoadResults(result);

        // Should have 3 items: grouped Novelty (3) + single Novelty (1) + PortScan (1)
        Assert.Equal(3, vm.Items.Count);

        // The grouped Novelty should have GroupCount = 3
        var groupedNovelty = vm.Items.FirstOrDefault(i => i.IsGrouped);
        Assert.NotNull(groupedNovelty);
        Assert.Equal(3, groupedNovelty.GroupCount);
        Assert.Equal("10.0.0.99", groupedNovelty.SourceHost);

        // The single Novelty should not be grouped
        var singleNovelty = vm.Items.FirstOrDefault(i => !i.IsGrouped && i.Category == "Novelty");
        Assert.NotNull(singleNovelty);
        Assert.Equal("192.168.1.50", singleNovelty.SourceHost);

        // PortScan should pass through unchanged
        var portScan = vm.Items.FirstOrDefault(i => i.Category == "PortScan");
        Assert.NotNull(portScan);
        Assert.False(portScan.IsGrouped);
    }

    [Fact]
    public void LoadResults_WithNoFindings_ClearsItems()
    {
        var vm = new FindingsViewModel();
        vm.LoadResults(new AnalysisResult());
        Assert.Empty(vm.Items);
        Assert.Equal(0, vm.FindingsCount);
        Assert.False(vm.HasItems);
    }

    [Fact]
    public void LoadResults_WithFindings_SetsHasItemsTrue()
    {
        var vm = new FindingsViewModel();
        var result = new AnalysisResult();
        result.AddFinding(new Finding
        {
            Category = "PortScan",
            Severity = Severity.Medium,
            SourceHost = "10.0.0.1",
            Target = "multiple hosts/ports",
            TimeRangeStart = DateTime.Now,
            TimeRangeEnd = DateTime.Now,
            ShortDescription = "Port scan detected"
        });

        vm.LoadResults(result);

        Assert.True(vm.HasItems);
    }

    [Fact]
    public void Clear_SetsHasItemsFalse()
    {
        var vm = new FindingsViewModel();
        var result = new AnalysisResult();
        result.AddFinding(new Finding
        {
            Category = "PortScan",
            Severity = Severity.Medium,
            SourceHost = "10.0.0.1",
            Target = "multiple hosts/ports",
            TimeRangeStart = DateTime.Now,
            TimeRangeEnd = DateTime.Now,
            ShortDescription = "Port scan detected"
        });

        vm.LoadResults(result);
        Assert.True(vm.HasItems);

        vm.Clear();
        Assert.False(vm.HasItems);
    }

    [Fact]
    public void SearchText_WhenNoFilteredItems_SetsHasItemsFalse()
    {
        var vm = new FindingsViewModel();
        var result = new AnalysisResult();
        result.AddFinding(new Finding
        {
            Category = "PortScan",
            Severity = Severity.Medium,
            SourceHost = "10.0.0.1",
            Target = "multiple hosts/ports",
            TimeRangeStart = DateTime.Now,
            TimeRangeEnd = DateTime.Now,
            ShortDescription = "Port scan detected"
        });

        vm.LoadResults(result);
        vm.SearchText = "does-not-match";

        Assert.False(vm.HasItems);
        Assert.True(vm.ItemsView.IsEmpty);
    }

    [Fact]
    public void SelectedSeverityFilter_WhenNoFilteredItems_SetsHasItemsFalse()
    {
        var vm = new FindingsViewModel();
        var result = new AnalysisResult();
        result.AddFinding(new Finding
        {
            Category = "PortScan",
            Severity = Severity.Medium,
            SourceHost = "10.0.0.1",
            Target = "multiple hosts/ports",
            TimeRangeStart = DateTime.Now,
            TimeRangeEnd = DateTime.Now,
            ShortDescription = "Port scan detected"
        });

        vm.LoadResults(result);
        vm.SelectedSeverityFilter = vm.SeverityFilters.Single(f => f.MinSeverity == Severity.Critical);

        Assert.False(vm.HasItems);
        Assert.True(vm.ItemsView.IsEmpty);
    }
}
