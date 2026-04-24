using System;
using System.Windows.Input;

namespace VulcansTrace.Wpf.ViewModels;

/// <summary>
/// A simple relay command implementation that delegates execution to provided delegates.
/// </summary>
/// <remarks>
/// Integrates with WPF's CommandManager.RequerySuggested for automatic CanExecuteChanged notifications.
/// </remarks>
public sealed class RelayCommand : ICommand
{
    private readonly Action<object?> _execute;
    private readonly Func<object?, bool>? _canExecute;

    /// <summary>
    /// Initializes a new instance of the <see cref="RelayCommand"/> class.
    /// </summary>
    /// <param name="execute">The action to execute.</param>
    /// <param name="canExecute">Optional predicate to determine if the command can execute.</param>
    public RelayCommand(Action<object?> execute, Func<object?, bool>? canExecute = null)
    {
        _execute = execute ?? throw new ArgumentNullException(nameof(execute));
        _canExecute = canExecute;
    }

    /// <inheritdoc/>
    public bool CanExecute(object? parameter) => _canExecute?.Invoke(parameter) ?? true;

    /// <inheritdoc/>
    public void Execute(object? parameter) => _execute(parameter);

    /// <summary>
    /// Occurs when changes occur that affect whether or not the command should execute.
    /// Uses CommandManager.RequerySuggested for automatic WPF integration.
    /// </summary>
    public event EventHandler? CanExecuteChanged
    {
        add => CommandManager.RequerySuggested += value;
        remove => CommandManager.RequerySuggested -= value;
    }

    /// <summary>
    /// Raises the <see cref="CanExecuteChanged"/> event to notify the UI to re-query command state.
    /// </summary>
    public void RaiseCanExecuteChanged() => CommandManager.InvalidateRequerySuggested();
}