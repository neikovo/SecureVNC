; SecureVNC setup program (Inno Setup 6). Build with scripts\build-installer.ps1.
; One SecureVNC-Setup.exe: choose Server, Client or both. Server part creates the local certificate,
; the Windows service, the firewall rule and the Ctrl+Alt+Del policy (configure-server.ps1), then opens
; SecureVNC Manager to create the first user (QR code for Google Authenticator).

#ifndef AppVersion
  #define AppVersion "1.0.0"
#endif
#define Dist "..\dist"

[Setup]
AppId={{B9CA1213-CF64-46CB-AE8A-F261C881EC21}
AppName=SecureVNC
AppVersion={#AppVersion}
AppVerName=SecureVNC {#AppVersion}
AppPublisher=SecureVNC
DefaultDirName={autopf}\SecureVNC
DefaultGroupName=SecureVNC
DisableProgramGroupPage=yes
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
OutputDir={#Dist}
OutputBaseFilename=SecureVNC-Setup-{#AppVersion}
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
CloseApplications=yes
SetupLogging=yes
UninstallDisplayName=SecureVNC

[Types]
Name: "full";   Description: "Server and client"
Name: "server"; Description: "Server only - this computer will be controlled remotely"
Name: "client"; Description: "Client only - connect to other computers"
Name: "custom"; Description: "Custom"; Flags: iscustom

[Components]
Name: "server"; Description: "SecureVNC Server - allow secure remote access to THIS computer"; Types: full server
Name: "client"; Description: "SecureVNC Client - connect to other computers";                  Types: full client

[Tasks]
Name: "desktopicon"; Description: "Desktop shortcut for SecureVNC Client"; Components: client

[Files]
Source: "{#Dist}\Server\*"; DestDir: "{app}\Server"; Excludes: "install-server.ps1,uninstall-server.ps1"; \
    Components: server; Flags: ignoreversion recursesubdirs
Source: "{#Dist}\Client\SecureVNC.Client.exe"; DestDir: "{app}\Client"; Components: client; Flags: ignoreversion

[Icons]
Name: "{group}\SecureVNC Client";      Filename: "{app}\Client\SecureVNC.Client.exe";  Components: client
Name: "{autodesktop}\SecureVNC Client"; Filename: "{app}\Client\SecureVNC.Client.exe"; Tasks: desktopicon
Name: "{group}\SecureVNC Manager";     Filename: "{app}\Server\SecureVNC.Manager.exe"; Components: server

[Run]
Filename: "{app}\Server\SecureVNC.Manager.exe"; Parameters: "--first-run"; Description: "Open SecureVNC Manager (users, certificate)"; \
    Components: server; Flags: postinstall runascurrentuser nowait skipifsilent
Filename: "{app}\Client\SecureVNC.Client.exe"; Description: "Start SecureVNC Client"; \
    Components: client; Flags: postinstall nowait skipifsilent unchecked

[UninstallRun]
Filename: "powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\Server\configure-server.ps1"" -Remove"; \
    Components: server; Flags: runhidden waituntilterminated; RunOnceId: "RemoveSecureVncService"

[UninstallDelete]
Type: files; Name: "{app}\Server\setup.log"

[Code]
const
  PublicNetworkExitCode = 10;

function ServiceInstalled(): Boolean;
var
  Code: Integer;
begin
  Result := Exec(ExpandConstant('{sys}\sc.exe'), 'query SecureVNC', '', SW_HIDE, ewWaitUntilTerminated, Code) and (Code = 0);
end;

// Files of a running service/agent cannot be replaced: stop them before copying.
function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  Code: Integer;
begin
  Result := '';
  if WizardIsComponentSelected('server') and ServiceInstalled() then
  begin
    Exec(ExpandConstant('{sys}\net.exe'), 'stop SecureVNC', '', SW_HIDE, ewWaitUntilTerminated, Code);
    Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /IM SecureVNC.Server.exe', '', SW_HIDE, ewWaitUntilTerminated, Code);
    Sleep(500);
  end;
end;

procedure ConfigureServer();
var
  Code: Integer;
  Script, LogFile, Params: String;
begin
  Script := ExpandConstant('{app}\Server\configure-server.ps1');
  LogFile := ExpandConstant('{app}\Server\setup.log');
  Params := '-NoProfile -ExecutionPolicy Bypass -Command "& ''' + Script + ''' *> ''' + LogFile + '''; exit $LASTEXITCODE"';
  WizardForm.StatusLabel.Caption := 'Creating the local certificate and starting the SecureVNC service...';
  if not Exec('powershell.exe', Params, '', SW_HIDE, ewWaitUntilTerminated, Code) then
    Code := -1;
  Log('configure-server.ps1 exit code ' + IntToStr(Code));

  if Code = PublicNetworkExitCode then
    MsgBox('SecureVNC is installed, but this computer''s network is set to "Public", where Windows blocks incoming connections.' + #13#10#13#10 +
      'If this is your home or office network, open Settings > Network & internet > (your network) and set "Network profile type" to Private.',
      mbInformation, MB_OK)
  else if Code <> 0 then
    MsgBox('Setting up the SecureVNC service failed (code ' + IntToStr(Code) + ').' + #13#10#13#10 +
      'Details: ' + LogFile, mbError, MB_OK);
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if (CurStep = ssPostInstall) and WizardIsComponentSelected('server') then
    ConfigureServer();
end;

// Users, keys and certificates stay by default, so a reinstall keeps working with the same clients.
procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  Data: String;
begin
  Data := ExpandConstant('{commonappdata}\SecureVNC');
  if (CurUninstallStep = usPostUninstall) and DirExists(Data) and not UninstallSilent() then
    if MsgBox('Also delete SecureVNC users, keys and certificates (' + Data + ')?' + #13#10#13#10 +
        'Choose No if you will install SecureVNC again: clients keep trusting this computer and users keep their authenticator.',
        mbConfirmation, MB_YESNO or MB_DEFBUTTON2) = IDYES then
      DelTree(Data, True, True, True);
end;
