using SecureVNC.Shared.Hosting;

namespace SecureVNC.Manager;

/// <summary>
/// Unlocks SecureVNC Manager with a SecureVNC user: name + password + Google Authenticator code,
/// the same check as a remote connection (the code is used up, like any other login).
/// </summary>
internal sealed class LoginDialog : Form
{
    private const int MaxAttempts = 5;
    private readonly TextBox _name = new() { Width = 240 };
    private readonly TextBox _password = new() { Width = 240, UseSystemPasswordChar = true };
    private readonly TextBox _code = new() { Width = 120, MaxLength = 7, Font = new Font("Consolas", 14f) };
    private readonly Label _error = new() { AutoSize = true, ForeColor = Color.Firebrick, MaximumSize = new Size(420, 0) };
    private readonly Func<string, string, string, string?> _verify;
    private int _failures;

    /// <param name="verify">user, password, code -> null when accepted, otherwise the message to show.</param>
    public LoginDialog(string reason, Func<string, string, string, string?> verify)
    {
        _verify = verify;
        Text = "SecureVNC Manager - locked";
        Icon = SystemIcons.Shield;
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = MinimizeBox = false;
        StartPosition = FormStartPosition.CenterScreen;
        ShowInTaskbar = true;
        AutoScaleMode = AutoScaleMode.Dpi;
        AutoSize = true;
        AutoSizeMode = AutoSizeMode.GrowAndShrink;
        Font = new Font("Segoe UI", 9.5f);

        var layout = new TableLayoutPanel { ColumnCount = 2, AutoSize = true, Padding = new Padding(14), Dock = DockStyle.Fill };
        void Row(string label, Control c)
        {
            layout.Controls.Add(new Label { Text = label, AutoSize = true, Anchor = AnchorStyles.Left, Margin = new Padding(3, 8, 10, 3) });
            layout.Controls.Add(c);
        }
        void Wide(Control c)
        {
            layout.Controls.Add(c);
            layout.SetColumnSpan(c, 2);
        }

        Wide(new Label { Text = reason, AutoSize = true, MaximumSize = new Size(420, 0), Margin = new Padding(3, 0, 3, 10) });
        Row("User name:", _name);
        Row("Password:", _password);
        Row("Code from the app:", _code);
        Wide(_error);

        var ok = new Button { Text = "Unlock", AutoSize = true, Padding = new Padding(8, 2, 8, 2) };
        var cancel = new Button { Text = "Cancel", AutoSize = true, DialogResult = DialogResult.Cancel };
        ok.Click += (_, _) => TryUnlock();
        var buttons = new FlowLayoutPanel { FlowDirection = FlowDirection.RightToLeft, AutoSize = true, Dock = DockStyle.Fill, Margin = new Padding(0, 10, 0, 0) };
        buttons.Controls.Add(cancel);
        buttons.Controls.Add(ok);
        Wide(buttons);

        AcceptButton = ok;
        CancelButton = cancel;
        Controls.Add(layout);
    }

    public string? UserName { get; private set; }

    private void TryUnlock()
    {
        var name = _name.Text.Trim();
        UseWaitCursor = true;
        string? problem;
        try
        {
            problem = _verify(name, _password.Text, _code.Text.Replace(" ", ""));
        }
        finally
        {
            UseWaitCursor = false;
        }

        if (problem is null)
        {
            Log.Info($"Manager unlocked by '{name}'");
            UserName = name;
            DialogResult = DialogResult.OK;
            return;
        }

        _failures++;
        Log.Info($"Manager: failed unlock attempt {_failures} for '{name}'");
        _password.Clear();
        _code.Clear();
        if (_failures >= MaxAttempts)
        {
            MessageBox.Show(this, "Too many failed attempts.", "SecureVNC", MessageBoxButtons.OK, MessageBoxIcon.Error);
            DialogResult = DialogResult.Cancel;
            return;
        }
        Thread.Sleep(1000 * _failures);   // slows down guessing
        _error.Text = problem;
        _password.Focus();
    }
}
