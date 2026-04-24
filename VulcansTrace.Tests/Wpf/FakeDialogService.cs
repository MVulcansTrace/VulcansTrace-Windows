using VulcansTrace.Wpf.Services;

namespace VulcansTrace.Tests.Wpf;

public sealed class FakeDialogService : IDialogService
{
    public string? LastMessage { get; private set; }
    public string? LastError { get; private set; }
    public string? SavePath { get; set; } = "fake.zip";

    public void ShowMessage(string message, string title) => LastMessage = message;

    public void ShowError(string message, string title) => LastError = message;

    public string? ShowSaveFileDialog(string title, string filter, string defaultFileName) => SavePath;
}
