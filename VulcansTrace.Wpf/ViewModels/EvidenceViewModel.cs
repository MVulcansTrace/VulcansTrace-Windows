using System.IO;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Input;
using VulcansTrace.Core;
using VulcansTrace.Evidence;
using VulcansTrace.Wpf.Services;

namespace VulcansTrace.Wpf.ViewModels;

public sealed class EvidenceViewModel : ViewModelBase
{
    private readonly EvidenceBuilder _evidenceBuilder;
    private readonly IDialogService _dialogService;
    private CancellationTokenSource? _cancellationTokenSource;

    private string _signingKey = "";
    private bool _isBusy;
    private AnalysisResult? _lastResult;
    private string _logSnapshot = "";
    private DateTime? _analysisTimestamp;

    public string SigningKey
    {
        get => _signingKey;
        private set
        {
            if (SetField(ref _signingKey, value))
            {
                RaisePropertyChanged(nameof(MaskedSigningKey));
            }
        }
    }

    public string MaskedSigningKey =>
        string.IsNullOrEmpty(_signingKey)
            ? string.Empty
            : new string('*', _signingKey.Length);

    public bool IsBusy
    {
        get => _isBusy;
        private set => SetField(ref _isBusy, value);
    }

    public ICommand ExportEvidenceCommand { get; }
    public ICommand CancelExportCommand { get; }
    public ICommand CopySigningKeyCommand { get; }

    // Event to notify parent (MainViewModel) to update status text
    public event EventHandler<string>? StatusChanged;

    public EvidenceViewModel(EvidenceBuilder evidenceBuilder, IDialogService dialogService)
    {
        _evidenceBuilder = evidenceBuilder;
        _dialogService = dialogService;

        ExportEvidenceCommand = new RelayCommand(async _ => await ExportEvidenceAsync(), _ => CanExportEvidence());
        CancelExportCommand = new RelayCommand(_ => CancelExport(), _ => CanCancel());
        CopySigningKeyCommand = new RelayCommand(_ => CopySigningKey(), _ => !string.IsNullOrEmpty(SigningKey));
    }

    public void SetEvidenceContext(AnalysisResult result, string logText, DateTime? timestamp)
    {
        _lastResult = result;
        _logSnapshot = logText;
        _analysisTimestamp = timestamp;
        // CommandManager automatically re-queries command state
    }

    private bool CanExportEvidence() => _lastResult != null && !IsBusy;
    private bool CanCancel() => _isBusy && _cancellationTokenSource != null && !_cancellationTokenSource.IsCancellationRequested;

    private void CancelExport()
    {
        _cancellationTokenSource?.Cancel();
    }

    private async Task ExportEvidenceAsync()
    {
        if (_lastResult == null) return;

        IsBusy = true;
        StatusChanged?.Invoke(this, "Exporting evidence bundle...");
        
        _cancellationTokenSource?.Dispose();
        _cancellationTokenSource = new CancellationTokenSource();
        var token = _cancellationTokenSource.Token;
        // CommandManager automatically re-queries command state

        var signingKeyBytes = GenerateNewSigningKey();

        byte[] zipBytes;
        try
        {
            // Use local copies to avoid race conditions if analysis runs again
            var result = _lastResult;
            var log = _logSnapshot;
            var ts = _analysisTimestamp;

            zipBytes = await _evidenceBuilder.BuildAsync(result, log, signingKeyBytes, ts, token);
        }
        catch (Exception ex)
        {
            if (ex is OperationCanceledException)
            {
                StatusChanged?.Invoke(this, "Export cancelled by user.");
            }
            else
            {
                _dialogService.ShowError($"Failed to build evidence bundle: {ex.Message}", "VulcansTrace");
                StatusChanged?.Invoke(this, "Export failed.");
            }
            IsBusy = false;
            return;
        }

        var fileName = _dialogService.ShowSaveFileDialog(
            "Save Evidence Bundle",
            "ZIP files (*.zip)|*.zip|All files (*.*)|*.*",
            "VulcansTrace_Evidence.zip");

        if (!string.IsNullOrEmpty(fileName))
        {
            try
            {
                await File.WriteAllBytesAsync(fileName, zipBytes, token);
                if (!token.IsCancellationRequested)
                {
                    _dialogService.ShowMessage("Evidence bundle saved.", "VulcansTrace");
                    StatusChanged?.Invoke(this, "Evidence bundle saved.");
                }
            }
            catch (Exception ex)
            {
                if (ex is OperationCanceledException)
                {
                    StatusChanged?.Invoke(this, "Export cancelled by user.");
                }
                else
                {
                    _dialogService.ShowError($"Failed to save file: {ex.Message}", "VulcansTrace");
                    StatusChanged?.Invoke(this, "Export failed.");
                }
            }
        }
        else
        {
            StatusChanged?.Invoke(this, "Export cancelled by user.");
        }

        IsBusy = false;
        _cancellationTokenSource?.Dispose();
        _cancellationTokenSource = null;
        // CommandManager automatically re-queries command state
    }

    private byte[] GenerateNewSigningKey()
    {
        var keyBytes = new byte[32];
        using (var rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(keyBytes);
        }

        SigningKey = Convert.ToHexString(keyBytes);
        return keyBytes;
    }

    private void CopySigningKey()
    {
        try
        {
            Clipboard.SetText(SigningKey);
            _dialogService.ShowMessage("Signing key copied to clipboard.", "VulcansTrace");
        }
        catch (Exception ex)
        {
            _dialogService.ShowError($"Failed to copy signing key: {ex.Message}", "VulcansTrace");
        }
    }
}
