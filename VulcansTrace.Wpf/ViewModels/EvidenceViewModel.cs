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
    private int _contextVersion;

    public string SigningKey
    {
        get => _signingKey;
        private set
        {
            if (SetField(ref _signingKey, value))
            {
                RaisePropertyChanged(nameof(MaskedSigningKey));
                CommandManager.InvalidateRequerySuggested();
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
        private set
        {
            if (SetField(ref _isBusy, value))
            {
                CommandManager.InvalidateRequerySuggested();
            }
        }
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

        ExportEvidenceCommand = new RelayCommand(
            async _ =>
            {
                try
                {
                    await ExportEvidenceAsync();
                }
                catch (Exception ex)
                {
                    _dialogService.ShowError($"Export failed: {ex.Message}", "VulcansTrace");
                    StatusChanged?.Invoke(this, "Export failed.");
                    IsBusy = false;
                }
            },
            _ => CanExportEvidence());
        CancelExportCommand = new RelayCommand(_ => CancelExport(), _ => CanCancel());
        CopySigningKeyCommand = new RelayCommand(_ => CopySigningKey(), _ => !string.IsNullOrEmpty(SigningKey));
    }

    public void SetEvidenceContext(AnalysisResult result, string logText, DateTime? timestamp)
    {
        _lastResult = result;
        _logSnapshot = logText;
        _analysisTimestamp = timestamp;
        _contextVersion++;
        SigningKey = string.Empty;
        CommandManager.InvalidateRequerySuggested();
    }

    public void ClearEvidenceContext()
    {
        _lastResult = null;
        _logSnapshot = string.Empty;
        _analysisTimestamp = null;
        _contextVersion++;
        SigningKey = string.Empty;
        CommandManager.InvalidateRequerySuggested();
    }

    private bool CanExportEvidence() => _lastResult != null && !IsBusy;
    private bool CanCancel() => _isBusy && _cancellationTokenSource != null && !_cancellationTokenSource.IsCancellationRequested;

    private void CancelExport()
    {
        _cancellationTokenSource?.Cancel();
    }

    private async Task ExportEvidenceAsync()
    {
        var result = _lastResult;
        if (result == null) return;

        var log = _logSnapshot;
        var ts = _analysisTimestamp;
        var contextVersion = _contextVersion;

        IsBusy = true;
        SigningKey = string.Empty;
        StatusChanged?.Invoke(this, "Exporting evidence bundle...");
        
        _cancellationTokenSource?.Dispose();
        _cancellationTokenSource = new CancellationTokenSource();
        var token = _cancellationTokenSource.Token;
        // CommandManager automatically re-queries command state

        var signingKeyBytes = GenerateSigningKeyBytes();

        byte[] zipBytes;
        try
        {
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
            _cancellationTokenSource?.Dispose();
            _cancellationTokenSource = null;
            return;
        }

        var fileName = _dialogService.ShowSaveFileDialog(
            "Save Evidence Bundle",
            "ZIP files (*.zip)|*.zip|All files (*.*)|*.*",
            "VulcansTrace_Evidence.zip");

        if (!string.IsNullOrEmpty(fileName))
        {
            string? tempFileName = null;
            try
            {
                tempFileName = GetTemporaryExportPath(fileName);
                await File.WriteAllBytesAsync(tempFileName, zipBytes, token);
                token.ThrowIfCancellationRequested();
                File.Move(tempFileName, fileName, overwrite: true);
                tempFileName = null;

                if (_contextVersion == contextVersion)
                {
                    SigningKey = Convert.ToHexString(signingKeyBytes);
                }

                _dialogService.ShowMessage("Evidence bundle saved.", "VulcansTrace");
                StatusChanged?.Invoke(this, "Evidence bundle saved.");
            }
            catch (Exception ex)
            {
                DeleteTemporaryExportFile(tempFileName);
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

    private static byte[] GenerateSigningKeyBytes()
    {
        var keyBytes = new byte[32];
        using (var rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(keyBytes);
        }

        return keyBytes;
    }

    private static string GetTemporaryExportPath(string fileName)
    {
        var destinationPath = Path.GetFullPath(fileName);
        var directory = Path.GetDirectoryName(destinationPath) ?? Environment.CurrentDirectory;
        var name = Path.GetFileName(destinationPath);
        return Path.Combine(directory, $".{name}.{Guid.NewGuid():N}.tmp");
    }

    private static void DeleteTemporaryExportFile(string? tempFileName)
    {
        if (string.IsNullOrEmpty(tempFileName))
            return;

        try
        {
            if (File.Exists(tempFileName))
            {
                File.Delete(tempFileName);
            }
        }
        catch
        {
            // Best-effort cleanup only; the export result has already failed or was cancelled.
        }
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
