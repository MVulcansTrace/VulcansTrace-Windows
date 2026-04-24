namespace VulcansTrace.Wpf.Services;

public interface IDialogService
{
    void ShowMessage(string message, string title);
    void ShowError(string message, string title);
    string? ShowSaveFileDialog(string title, string filter, string defaultFileName);
}
