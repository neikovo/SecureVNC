namespace SecureVNC.Client;

internal static class Program
{
    [STAThread]
    private static void Main(string[] args)
    {
        ApplicationConfiguration.Initialize();
        using var single = new Mutex(true, @"Local\SecureVNC.Client", out bool first);
        var form = new ConnectForm(startHidden: args.Contains("--tray"), listenForHelp: first);
        if (args.Contains("--tray"))
        {
            // Started with Windows: only the tray icon, waiting for help requests.
            _ = form.Handle;
            Application.Run();
        }
        else
        {
            Application.Run(form);
        }
    }
}
