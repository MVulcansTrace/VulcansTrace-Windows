using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Windows;
using System.Windows.Input;
using System.Windows.Interop;
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

public partial class MainWindow : Window
{
    private readonly MainViewModel _viewModel;
    private readonly EvidenceBuilder _evidenceBuilder;

    public MainWindow()
    {
        InitializeComponent();

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

        var hasher = new IntegrityHasher();
        var csvFormatter = new CsvFormatter();
        var markdownFormatter = new MarkdownFormatter();
        var htmlFormatter = new HtmlFormatter();
        _evidenceBuilder = new EvidenceBuilder(hasher, csvFormatter, markdownFormatter, htmlFormatter);

        _viewModel = new MainViewModel(analyzer, _evidenceBuilder, new WpfDialogService(), profileProvider);
        DataContext = _viewModel;

        SourceInitialized += OnSourceInitialized;
        StateChanged += OnStateChanged;
    }

    protected override void OnClosed(EventArgs e)
    {
        StateChanged -= OnStateChanged;
        base.OnClosed(e);
    }

    private void OnSourceInitialized(object? sender, EventArgs e)
    {
        var handle = new WindowInteropHelper(this).Handle;
        HwndSource.FromHwnd(handle)?.AddHook(WndProc);
    }

    private IntPtr WndProc(IntPtr hwnd, int msg, IntPtr wParam, IntPtr lParam, ref bool handled)
    {
        if (msg == WM_GETMINMAXINFO)
        {
            var mmi = Marshal.PtrToStructure<MINMAXINFO>(lParam);
            var monitor = MonitorFromWindow(hwnd, MONITOR_DEFAULTTONEAREST);
            if (monitor != IntPtr.Zero)
            {
                var info = new MONITORINFO { cbSize = Marshal.SizeOf<MONITORINFO>() };
                GetMonitorInfo(monitor, ref info);
                mmi.ptMaxPosition.x = info.rcWork.left;
                mmi.ptMaxPosition.y = info.rcWork.top;
                mmi.ptMaxSize.x = info.rcWork.right - info.rcWork.left;
                mmi.ptMaxSize.y = info.rcWork.bottom - info.rcWork.top;
                Marshal.StructureToPtr(mmi, lParam, true);
            }
            handled = true;
        }
        return IntPtr.Zero;
    }

    private void OnStateChanged(object? sender, EventArgs e)
    {
        // Remove rounded corners when maximized to avoid gap at edges
        var border = (System.Windows.Controls.Border)((System.Windows.Controls.Grid)Content).Parent;
        border.CornerRadius = WindowState == WindowState.Maximized
            ? new CornerRadius(0)
            : new CornerRadius(8);
    }

    private void TitleBar_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
    {
        if (e.ClickCount == 2)
        {
            WindowState = WindowState == WindowState.Maximized ? WindowState.Normal : WindowState.Maximized;
            return;
        }

        try
        {
            DragMove();
        }
        catch (InvalidOperationException)
        {
            // DragMove was interrupted (e.g. by a rapid double-click or state transition)
        }
    }

    private void MinimizeButton_Click(object sender, RoutedEventArgs e)
    {
        WindowState = WindowState.Minimized;
    }

    private void MaximizeButton_Click(object sender, RoutedEventArgs e)
    {
        WindowState = WindowState == WindowState.Maximized ? WindowState.Normal : WindowState.Maximized;
    }

    private void CloseButton_Click(object sender, RoutedEventArgs e)
    {
        Close();
    }

    private void DetailsButton_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not System.Windows.Controls.Button button) return;
        if (button.DataContext is not FindingItemViewModel vm) return;

        var message = string.IsNullOrWhiteSpace(vm.GroupDetails)
            ? vm.ShortDescription
            : $"{vm.ShortDescription}\n\nDestinations:\n{vm.GroupDetails}";

        var dialog = new DetailsDialog(
            $"{vm.Category} — {vm.Severity}",
            message);
        dialog.Owner = this;
        dialog.ShowDialog();
    }

    #region Win32 interop for correct maximize

    private const int WM_GETMINMAXINFO = 0x0024;
    private const int MONITOR_DEFAULTTONEAREST = 2;

    [StructLayout(LayoutKind.Sequential)]
    private struct POINT { public int x, y; }

    [StructLayout(LayoutKind.Sequential)]
    private struct MINMAXINFO
    {
        public POINT ptReserved, ptMaxSize, ptMaxPosition, ptMinTrackSize, ptMaxTrackSize;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct RECT { public int left, top, right, bottom; }

    [StructLayout(LayoutKind.Sequential)]
    private struct MONITORINFO
    {
        public int cbSize;
        public RECT rcMonitor, rcWork;
        public uint dwFlags;
    }

    [DllImport("user32.dll")]
    private static extern IntPtr MonitorFromWindow(IntPtr hwnd, int dwFlags);

    [DllImport("user32.dll")]
    private static extern bool GetMonitorInfo(IntPtr hMonitor, ref MONITORINFO lpmi);

    #endregion
}
