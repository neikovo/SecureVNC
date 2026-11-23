using SecureVNC.Shared.Central;

namespace SecureVNC.Manager;

internal enum MasterPasswordMode { Create, Unlock, Change }

/// <summary>Sets, enters or changes the auth server's master password.</summary>
internal sealed class MasterPasswordDialog : Form
{
    private readonly MasterPasswordMode _mode;
    private readonly Func<string, string, string?> _apply;   // (old or entered, new) -> error or null
    private readonly TextBox _old = new() { Width = 280, UseSystemPasswordChar = true };
    private readonly TextBox _new = new() { Width = 280, UseSystemPasswordChar = true };
    private readonly TextBox _repeat = new() { Width = 280, UseSystemPasswordChar = true };
    private readonly Label _error = new() { AutoSize = true, ForeColor = Color.Firebrick, MaximumSize = new Size(520, 0) };

    public MasterPasswordDialog(MasterPasswordMode mode, Func<string, string, string?> apply, bool migrating = false)
    {
        _mode = mode;
        _apply = apply;
        Text = mode switch
        {
            MasterPasswordMode.Create => "SecureVNC Auth Server - set master password",
            MasterPasswordMode.Unlock => "SecureVNC Auth Server - locked",
            _ => "Change master password",
        };
        Icon = SystemIcons.Shield;
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = MinimizeBox = false;
        StartPosition = FormStartPosition.CenterScreen;
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

        string intro = mode switch
        {
            MasterPasswordMode.Create =>
                (migrating ? "This auth server's keys are protected only by Windows. Set a master password to seal them. " : "") +
                "The master password encrypts the organization CA, the administrators' authenticator secrets and the join key. " +
                "It is not stored anywhere: after every restart the auth server stays locked until someone enters it here.\n\n" +
                "Write it down and keep it in a safe place. It CANNOT be recovered: without it the auth server cannot be " +
                "unlocked and every computer would have to join a new one.",
            MasterPasswordMode.Unlock =>
                "The auth server is locked (it was restarted or locked by an administrator). Until it is unlocked nobody can " +
                "log in to any computer. Enter the master password.",
            _ => "Enter the current master password and the new one. Keep the new one in a safe place.",
        };
        Wide(new Label { Text = intro, AutoSize = true, MaximumSize = new Size(520, 0), Margin = new Padding(3, 0, 3, 10) });

        if (mode is MasterPasswordMode.Unlock or MasterPasswordMode.Change) Row(mode == MasterPasswordMode.Change ? "Current master password:" : "Master password:", _old);
        if (mode is MasterPasswordMode.Create or MasterPasswordMode.Change)
        {
            Row("New master password:", _new);
            Row("Repeat:", _repeat);
            Wide(new Label { Text = $"At least {Vault.MinPasswordLength} characters; a sentence of several words is good.", AutoSize = true, ForeColor = SystemColors.GrayText });
        }
        Wide(_error);

        var ok = new Button { Text = mode == MasterPasswordMode.Unlock ? "Unlock" : "Save", AutoSize = true, Padding = new Padding(8, 2, 8, 2) };
        var cancel = new Button { Text = "Cancel", AutoSize = true, DialogResult = DialogResult.Cancel };
        ok.Click += (_, _) => Apply();
        var buttons = new FlowLayoutPanel { FlowDirection = FlowDirection.RightToLeft, AutoSize = true, Dock = DockStyle.Fill, Margin = new Padding(0, 10, 0, 0) };
        buttons.Controls.Add(cancel);
        buttons.Controls.Add(ok);
        Wide(buttons);
        AcceptButton = ok;
        CancelButton = cancel;
        Controls.Add(layout);
    }

    private void Apply()
    {
        _error.Text = "";
        if (_mode is MasterPasswordMode.Create or MasterPasswordMode.Change)
        {
            if (Vault.CheckNewPassword(_new.Text) is { } problem) { _error.Text = problem; _new.Focus(); return; }
            if (_new.Text != _repeat.Text) { _error.Text = "The passwords do not match."; _repeat.Focus(); return; }
        }
        UseWaitCursor = true;
        string? error;
        try
        {
            error = _apply(_old.Text, _new.Text);
        }
        catch (Exception ex)
        {
            error = ex.Message;
        }
        finally
        {
            UseWaitCursor = false;
        }
        if (error is null)
        {
            DialogResult = DialogResult.OK;
            return;
        }
        _error.Text = error;
        _old.Clear();
        (_mode == MasterPasswordMode.Create ? _new : _old).Focus();
    }
}
