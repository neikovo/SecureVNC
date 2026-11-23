using SecureVNC.Shared.Central;
using SecureVNC.Shared.Hosting;

namespace SecureVNC.Manager;

/// <summary>Joins this computer to a SecureVNC Auth Server (address, CA fingerprint and join key from the Auth Console).</summary>
internal sealed class JoinDialog : Form
{
    private readonly TextBox _server = new() { Width = 300 };
    private readonly TextBox _fingerprint = new() { Width = 460, Font = new Font("Consolas", 9f) };
    private readonly TextBox _joinKey = new() { Width = 300, Font = new Font("Consolas", 10f) };
    private readonly Label _error = new() { AutoSize = true, ForeColor = Color.Firebrick, MaximumSize = new Size(600, 0) };

    public JoinDialog()
    {
        Text = "Join auth server";
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = MinimizeBox = false;
        StartPosition = FormStartPosition.CenterParent;
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

        Wide(new Label
        {
            Text = "Copy these from the SecureVNC Auth Console on the server. The fingerprint makes sure this computer talks only " +
                   "to your auth server, never to an impostor.",
            AutoSize = true, MaximumSize = new Size(600, 0), Margin = new Padding(3, 0, 3, 10),
        });
        Row("Auth server (name or IP):", _server);
        Row("CA fingerprint:", _fingerprint);
        Row("Join key:", _joinKey);
        Wide(_error);

        var ok = new Button { Text = "Join", AutoSize = true, Padding = new Padding(8, 2, 8, 2) };
        var cancel = new Button { Text = "Cancel", AutoSize = true, DialogResult = DialogResult.Cancel };
        ok.Click += (_, _) => DoJoin();
        var buttons = new FlowLayoutPanel { FlowDirection = FlowDirection.RightToLeft, AutoSize = true, Dock = DockStyle.Fill, Margin = new Padding(0, 10, 0, 0) };
        buttons.Controls.Add(cancel);
        buttons.Controls.Add(ok);
        Wide(buttons);
        AcceptButton = ok;
        CancelButton = cancel;
        Controls.Add(layout);
    }

    private void DoJoin()
    {
        _error.Text = "";
        if (_server.Text.Trim().Length == 0) { _error.Text = "Enter the auth server's name or IP address."; return; }
        if (CentralProtocol.NormalizeFingerprint(_fingerprint.Text).Length != 64) { _error.Text = "The fingerprint must have 32 pairs (64 hex digits)."; return; }
        if (CentralProtocol.NormalizeJoinKey(_joinKey.Text).Length < 20) { _error.Text = "Enter the join key."; return; }

        UseWaitCursor = true;
        try
        {
            CentralClient.Join(_server.Text.Trim(), _fingerprint.Text.Trim(), _joinKey.Text.Trim(), Log.Info);
            DialogResult = DialogResult.OK;
        }
        catch (Exception ex)
        {
            _error.Text = ex.Message.Contains("RemoteCertificateValidationCallback")
                ? "The server's certificate does not match this fingerprint (or the name/IP is not in its certificate). Not joined."
                : $"Could not join: {ex.Message}";
        }
        finally
        {
            UseWaitCursor = false;
        }
    }
}
