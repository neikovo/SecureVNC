using System.Runtime.InteropServices;

namespace SecureVNC.Server;

/// <summary>
/// "Request help" from the tray icon. The agent runs as SYSTEM on the user's desktop, so this window is kept minimal:
/// one text field and two buttons - no file dialogs, no links, nothing that could start another program.
/// </summary>
internal sealed class HelpRequestDialog : Form
{
    private readonly TextBox _text = new() { Width = 380, MaxLength = Shared.Help.HelpRequests.MaxTextLength };

    public HelpRequestDialog()
    {
        Text = "Request help";
        Icon = SystemIcons.Shield;
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = MinimizeBox = false;
        StartPosition = FormStartPosition.CenterScreen;
        TopMost = true;
        ShowInTaskbar = true;
        AutoScaleMode = AutoScaleMode.Dpi;
        AutoSize = true;
        AutoSizeMode = AutoSizeMode.GrowAndShrink;
        Font = new Font("Segoe UI", 10f);

        var layout = new FlowLayoutPanel { FlowDirection = FlowDirection.TopDown, AutoSize = true, Padding = new Padding(16), WrapContents = false };
        layout.Controls.Add(new Label
        {
            Text = "Your administrator will get a message that you need help and will connect to this computer.",
            AutoSize = true, MaximumSize = new Size(380, 0), Margin = new Padding(3, 0, 3, 12),
        });
        layout.Controls.Add(new Label { Text = "What is the problem? (optional)", AutoSize = true });
        layout.Controls.Add(_text);

        var send = new Button { Text = "Send", AutoSize = true, Padding = new Padding(10, 3, 10, 3), DialogResult = DialogResult.OK };
        var cancel = new Button { Text = "Cancel", AutoSize = true, Padding = new Padding(6, 3, 6, 3), DialogResult = DialogResult.Cancel };
        var buttons = new FlowLayoutPanel { FlowDirection = FlowDirection.RightToLeft, AutoSize = true, Width = 380, Margin = new Padding(0, 14, 0, 0) };
        buttons.Controls.Add(cancel);
        buttons.Controls.Add(send);
        layout.Controls.Add(buttons);
        AcceptButton = send;
        CancelButton = cancel;
        Controls.Add(layout);
    }

    public string Description => _text.Text;
}

/// <summary>The Windows user signed in on this session (the agent itself runs as SYSTEM).</summary>
internal static class SessionUser
{
    public static string Name()
    {
        int session = System.Diagnostics.Process.GetCurrentProcess().SessionId;
        if (WTSQuerySessionInformationW(IntPtr.Zero, session, 5 /* WTSUserName */, out var buffer, out _))
        {
            try
            {
                var name = Marshal.PtrToStringUni(buffer);
                if (!string.IsNullOrEmpty(name)) return name;
            }
            finally
            {
                WTSFreeMemory(buffer);
            }
        }
        return Environment.UserName;
    }

    [DllImport("wtsapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool WTSQuerySessionInformationW(IntPtr server, int sessionId, int infoClass, out IntPtr buffer, out int bytes);

    [DllImport("wtsapi32.dll")]
    private static extern void WTSFreeMemory(IntPtr memory);
}
