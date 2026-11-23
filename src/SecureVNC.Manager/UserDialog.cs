using System.Security.Cryptography;
using QRCoder;
using SecureVNC.Shared.Hosting;
using SecureVNC.Shared.Security;

namespace SecureVNC.Manager;

internal enum UserDialogMode { Add, NewAuthenticator, Password }

/// <summary>Add a user, enroll a new Google Authenticator secret, or change a password.</summary>
internal sealed class UserDialog : Form
{
    private readonly UserDialogMode _mode;
    private readonly string? _existingName;
    private readonly byte[]? _secret;
    private readonly TextBox _name = new() { Width = 260 };
    private readonly TextBox _password = new() { Width = 260, UseSystemPasswordChar = true };
    private readonly TextBox _repeat = new() { Width = 260, UseSystemPasswordChar = true };
    private readonly TextBox _code = new() { Width = 120, MaxLength = 7, Font = new Font("Consolas", 14f) };
    private readonly Label _error = new() { AutoSize = true, ForeColor = Color.Firebrick, MaximumSize = new Size(560, 0) };

    public UserDialog(UserDialogMode mode, string? existingName = null, string? intro = null)
    {
        _mode = mode;
        _existingName = existingName;
        Text = mode switch
        {
            UserDialogMode.Add => "Add user",
            UserDialogMode.NewAuthenticator => $"New authenticator for {existingName}",
            _ => $"Change password for {existingName}",
        };
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = MinimizeBox = false;
        StartPosition = FormStartPosition.CenterParent;
        AutoScaleMode = AutoScaleMode.Dpi;
        AutoSize = true;
        AutoSizeMode = AutoSizeMode.GrowAndShrink;
        Font = new Font("Segoe UI", 9.5f);

        var layout = new TableLayoutPanel { ColumnCount = 2, AutoSize = true, Padding = new Padding(14), Dock = DockStyle.Fill };
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));

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

        if (intro is not null) Wide(new Label { Text = intro, AutoSize = true, MaximumSize = new Size(560, 0), Margin = new Padding(3, 0, 3, 10) });

        if (mode == UserDialogMode.Add)
        {
            Row("User name:", _name);
            Wide(new Label { Text = UserStore.NameRules, AutoSize = true, ForeColor = SystemColors.GrayText });
        }
        if (mode is UserDialogMode.Add or UserDialogMode.Password)
        {
            Row("Password:", _password);
            Row("Repeat password:", _repeat);
            Wide(new Label { Text = "At least 10 characters.", AutoSize = true, ForeColor = SystemColors.GrayText });
        }

        if (mode is UserDialogMode.Add or UserDialogMode.NewAuthenticator)
        {
            _secret = Totp.NewSecret();
            Wide(new Label
            {
                Text = "Open Google Authenticator on the phone, tap +, choose \"Scan a QR code\" and scan this:",
                AutoSize = true, MaximumSize = new Size(560, 0), Margin = new Padding(3, 14, 3, 6),
            });
            var qrBox = new PictureBox { SizeMode = PictureBoxSizeMode.Zoom, Size = new Size(240, 240), Anchor = AnchorStyles.None };
            Wide(qrBox);
            if (mode == UserDialogMode.Add) _name.TextChanged += (_, _) => qrBox.Image = Qr(_name.Text.Trim());
            qrBox.Image = Qr(existingName ?? "");

            var key = Base32.Encode(_secret);
            Wide(new Label { Text = "Or enter this key manually (time based, 6 digits):", AutoSize = true, Margin = new Padding(3, 8, 3, 0) });
            Wide(new TextBox
            {
                Text = string.Join(" ", key.Chunk(4).Select(c => new string(c))),
                ReadOnly = true, Width = 420, Font = new Font("Consolas", 10.5f), BorderStyle = BorderStyle.None, BackColor = SystemColors.Control,
            });
            Row("Code from the app:", _code);
        }

        Wide(_error);

        var ok = new Button { Text = mode == UserDialogMode.Add ? "Create user" : "Save", AutoSize = true, Padding = new Padding(8, 2, 8, 2) };
        var cancel = new Button { Text = "Cancel", AutoSize = true, DialogResult = DialogResult.Cancel };
        ok.Click += (_, _) => Save();
        var buttons = new FlowLayoutPanel { FlowDirection = FlowDirection.RightToLeft, AutoSize = true, Dock = DockStyle.Fill, Margin = new Padding(0, 10, 0, 0) };
        buttons.Controls.Add(cancel);
        buttons.Controls.Add(ok);
        Wide(buttons);

        AcceptButton = ok;
        CancelButton = cancel;
        Controls.Add(layout);
    }

    public string? CreatedName { get; private set; }

    private Image Qr(string name)
    {
        var account = $"{(name.Length > 0 ? name : "user")}@{Environment.MachineName}";
        using var data = new QRCodeGenerator().CreateQrCode(Totp.BuildUri("SecureVNC", account, _secret), QRCodeGenerator.ECCLevel.M);
        var png = new PngByteQRCode(data).GetGraphic(8);
        return Image.FromStream(new MemoryStream(png));
    }

    private void Save()
    {
        try
        {
            _error.Text = "";
            var store = UserStore.Load();
            string name = _mode == UserDialogMode.Add ? _name.Text.Trim() : _existingName!;

            if (_mode == UserDialogMode.Add)
            {
                if (!UserStore.IsValidName(name)) { Fail("User name: " + UserStore.NameRules, _name); return; }
                if (store.Find(name) is not null) { Fail($"User '{name}' already exists.", _name); return; }
            }
            if (_mode is UserDialogMode.Add or UserDialogMode.Password)
            {
                if (UserStore.CheckPassword(_password.Text) is { } problem) { Fail(problem, _password); return; }
                if (_password.Text != _repeat.Text) { Fail("The passwords do not match.", _repeat); return; }
            }

            long step = 0;
            if (_secret is not null)
            {
                step = Totp.Verify(_secret, _code.Text.Replace(" ", ""), DateTimeOffset.UtcNow);
                if (step < 0)
                {
                    Fail("Wrong code. Type the 6 digits currently shown in the app. If it keeps failing, check that the phone's clock is set automatically.", _code);
                    return;
                }
            }

            switch (_mode)
            {
                case UserDialogMode.Add:
                    store.Users.Add(UserStore.CreateRecord(name, _password.Text, _secret!, step));
                    break;
                case UserDialogMode.NewAuthenticator:
                {
                    var u = store.Find(name) ?? throw new InvalidOperationException($"User '{name}' no longer exists.");
                    var fresh = UserStore.CreateRecord(name, "unused-placeholder", _secret!, step);
                    u.TotpSecret = fresh.TotpSecret;
                    u.LastTotpStep = step;
                    break;
                }
                case UserDialogMode.Password:
                {
                    var u = store.Find(name) ?? throw new InvalidOperationException($"User '{name}' no longer exists.");
                    u.PasswordHash = PasswordHasher.Hash(_password.Text);
                    break;
                }
            }
            store.Save();
            Log.Info($"Manager: {_mode} for user '{name}'");
            CreatedName = name;
            DialogResult = DialogResult.OK;
        }
        catch (Exception ex)
        {
            Fail(ex.Message, null);
        }
    }

    private void Fail(string message, Control? focus)
    {
        _error.Text = message;
        focus?.Focus();
    }

    protected override void Dispose(bool disposing)
    {
        if (_secret is not null) CryptographicOperations.ZeroMemory(_secret);
        base.Dispose(disposing);
    }
}
