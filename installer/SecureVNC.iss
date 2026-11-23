; SecureVNC setup program (Inno Setup 6). Build with scripts\build-installer.ps1.
; One SecureVNC-Setup.exe: Server, Client, Auth Server, or a combination.
;  - Server: local certificate, Windows service, firewall rule, Ctrl+Alt+Del policy (configure-server.ps1);
;    optionally joins a SecureVNC Auth Server; then SecureVNC Manager opens.
;  - Auth Server: central administrators (configure-auth.ps1); then the Auth Console opens.
; Silent install of a computer that uses an auth server:
;   SecureVNC-Setup.exe /VERYSILENT /COMPONENTS=server /AUTHSERVER=srv01 /AUTHFP=AB:CD:... /JOINKEY=XXXX-XXXX-...

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
Name: "auth";   Description: "Auth Server - central administrator accounts (install on one server)"
Name: "custom"; Description: "Custom"; Flags: iscustom

[Components]
Name: "server"; Description: "SecureVNC Server - allow secure remote access to THIS computer"; Types: full server
Name: "client"; Description: "SecureVNC Client - connect to other computers";                  Types: full client
Name: "auth";   Description: "SecureVNC Auth Server - central administrators for many computers"; Types: auth

[Tasks]
Name: "desktopicon"; Description: "Desktop shortcut for SecureVNC Client"; Components: client

[Files]
Source: "{#Dist}\Server\*"; DestDir: "{app}\Server"; Excludes: "install-server.ps1,uninstall-server.ps1"; \
    Components: server; Flags: ignoreversion recursesubdirs
Source: "{#Dist}\Client\SecureVNC.Client.exe"; DestDir: "{app}\Client"; Components: client; Flags: ignoreversion
Source: "{#Dist}\Auth\*"; DestDir: "{app}\Auth"; Components: auth; Flags: ignoreversion recursesubdirs

[Icons]
Name: "{group}\SecureVNC Client";       Filename: "{app}\Client\SecureVNC.Client.exe";  Components: client
Name: "{autodesktop}\SecureVNC Client"; Filename: "{app}\Client\SecureVNC.Client.exe";  Tasks: desktopicon
Name: "{group}\SecureVNC Manager";      Filename: "{app}\Server\SecureVNC.Manager.exe"; Components: server
Name: "{group}\SecureVNC Auth Console"; Filename: "{app}\Auth\SecureVNC.Manager.exe"; Parameters: "--auth"; Components: auth

[Run]
Filename: "{app}\Auth\SecureVNC.Manager.exe"; Parameters: "--auth --first-run"; Description: "Open SecureVNC Auth Console (administrators, join key)"; \
    Components: auth; Flags: postinstall runascurrentuser nowait skipifsilent
Filename: "{app}\Server\SecureVNC.Manager.exe"; Parameters: "--first-run"; Description: "Open SecureVNC Manager (users, certificate)"; \
    Components: server; Flags: postinstall runascurrentuser nowait skipifsilent
Filename: "{app}\Client\SecureVNC.Client.exe"; Description: "Start SecureVNC Client"; \
    Components: client; Flags: postinstall nowait skipifsilent unchecked

[UninstallRun]
Filename: "powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\Server\configure-server.ps1"" -Remove"; \
    Components: server; Flags: runhidden waituntilterminated; RunOnceId: "RemoveSecureVncService"
Filename: "powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\Auth\configure-auth.ps1"" -Remove"; \
    Components: auth; Flags: runhidden waituntilterminated; RunOnceId: "RemoveSecureVncAuthService"

[UninstallDelete]
Type: files; Name: "{app}\Server\setup.log"
Type: files; Name: "{app}\Auth\setup.log"

[Code]
const
  PublicNetworkExitCode = 10;
  JoinFailedExitCode = 11;

var
  CentralPage: TInputQueryWizardPage;

procedure InitializeWizard();
begin
  CentralPage := CreateInputQueryPage(wpSelectTasks,
    'Central authentication (optional)',
    'Use a SecureVNC Auth Server for the administrator accounts?',
    'Leave empty to keep users on this computer (you create them in SecureVNC Manager).' + #13#10 +
    'Or copy the values from the SecureVNC Auth Console on your server: administrators kept there can then log in here.');
  CentralPage.Add('Auth server (name or IP):', False);
  CentralPage.Add('CA fingerprint:', False);
  CentralPage.Add('Join key:', False);
  CentralPage.Values[0] := ExpandConstant('{param:AUTHSERVER|}');
  CentralPage.Values[1] := ExpandConstant('{param:AUTHFP|}');
  CentralPage.Values[2] := ExpandConstant('{param:JOINKEY|}');
end;

function ShouldSkipPage(PageID: Integer): Boolean;
begin
  Result := (PageID = CentralPage.ID) and not WizardIsComponentSelected('server');
end;

function NextButtonClick(CurPageID: Integer): Boolean;
begin
  Result := True;
  if (CurPageID = CentralPage.ID) and (Trim(CentralPage.Values[0]) <> '') and
     ((Trim(CentralPage.Values[1]) = '') or (Trim(CentralPage.Values[2]) = '')) then
  begin
    MsgBox('Enter the CA fingerprint and the join key too, or leave all three empty.', mbError, MB_OK);
    Result := False;
  end;
end;

function ServiceInstalled(Name: String): Boolean;
var
  Code: Integer;
begin
  Result := Exec(ExpandConstant('{sys}\sc.exe'), 'query ' + Name, '', SW_HIDE, ewWaitUntilTerminated, Code) and (Code = 0);
end;

// Files of a running service/agent cannot be replaced: stop them before copying.
function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  Code: Integer;
begin
  Result := '';
  if WizardIsComponentSelected('server') and ServiceInstalled('SecureVNC') then
  begin
    Exec(ExpandConstant('{sys}\net.exe'), 'stop SecureVNC', '', SW_HIDE, ewWaitUntilTerminated, Code);
    Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /IM SecureVNC.Server.exe', '', SW_HIDE, ewWaitUntilTerminated, Code);
  end;
  if WizardIsComponentSelected('auth') and ServiceInstalled('SecureVNCAuth') then
    Exec(ExpandConstant('{sys}\net.exe'), 'stop SecureVNCAuth', '', SW_HIDE, ewWaitUntilTerminated, Code);
  Sleep(500);
end;

function Quote(S: String): String;
begin
  StringChangeEx(S, '''', '''''', True);
  Result := '''' + S + '''';
end;

function RunScript(Script, Arguments, LogFile: String): Integer;
var
  Params: String;
begin
  Params := '-NoProfile -ExecutionPolicy Bypass -Command "& ' + Quote(Script) + ' ' + Arguments + ' *> ' + Quote(LogFile) + '; exit $LASTEXITCODE"';
  if not Exec('powershell.exe', Params, '', SW_HIDE, ewWaitUntilTerminated, Result) then
    Result := -1;
  Log(Script + ' exit code ' + IntToStr(Result));
end;

procedure ConfigureServer();
var
  Code: Integer;
  Arguments, LogFile: String;
begin
  LogFile := ExpandConstant('{app}\Server\setup.log');
  Arguments := '';
  if Trim(CentralPage.Values[0]) <> '' then
    Arguments := '-AuthServer ' + Quote(Trim(CentralPage.Values[0])) +
                 ' -AuthFingerprint ' + Quote(Trim(CentralPage.Values[1])) +
                 ' -JoinKey ' + Quote(Trim(CentralPage.Values[2]));
  WizardForm.StatusLabel.Caption := 'Creating the certificate and starting the SecureVNC service...';
  Code := RunScript(ExpandConstant('{app}\Server\configure-server.ps1'), Arguments, LogFile);

  if Code = PublicNetworkExitCode then
    MsgBox('SecureVNC is installed, but this computer''s network is set to "Public", where Windows blocks incoming connections.' + #13#10#13#10 +
      'If this is your home or office network, open Settings > Network & internet > (your network) and set "Network profile type" to Private.',
      mbInformation, MB_OK)
  else if Code = JoinFailedExitCode then
    MsgBox('SecureVNC is installed, but joining the auth server failed (wrong address, fingerprint or join key, or the server is not reachable).' + #13#10#13#10 +
      'Join later in SecureVNC Manager. Details: ' + LogFile, mbError, MB_OK)
  else if Code <> 0 then
    MsgBox('Setting up the SecureVNC service failed (code ' + IntToStr(Code) + ').' + #13#10#13#10 +
      'Details: ' + LogFile, mbError, MB_OK);
end;

procedure ConfigureAuth();
var
  Code: Integer;
  LogFile: String;
begin
  LogFile := ExpandConstant('{app}\Auth\setup.log');
  WizardForm.StatusLabel.Caption := 'Creating the organization CA and starting the SecureVNC Auth Server...';
  Code := RunScript(ExpandConstant('{app}\Auth\configure-auth.ps1'), '', LogFile);
  if Code <> 0 then
    MsgBox('Setting up the SecureVNC Auth Server failed (code ' + IntToStr(Code) + ').' + #13#10#13#10 +
      'Details: ' + LogFile, mbError, MB_OK);
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
  begin
    if WizardIsComponentSelected('auth') then ConfigureAuth();
    if WizardIsComponentSelected('server') then ConfigureServer();
  end;
end;

// Users, keys and certificates stay by default, so a reinstall keeps working with the same clients.
procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  Data, AuthData: String;
begin
  if (CurUninstallStep <> usPostUninstall) or UninstallSilent() then Exit;
  Data := ExpandConstant('{commonappdata}\SecureVNC');
  AuthData := ExpandConstant('{commonappdata}\SecureVNC-Auth');
  if DirExists(Data) then
    if MsgBox('Also delete SecureVNC users, keys and certificates (' + Data + ')?' + #13#10#13#10 +
        'Choose No if you will install SecureVNC again: clients keep trusting this computer and users keep their authenticator.',
        mbConfirmation, MB_YESNO or MB_DEFBUTTON2) = IDYES then
      DelTree(Data, True, True, True);
  if DirExists(AuthData) then
    if MsgBox('Also delete the Auth Server data: administrators, organization CA, joined computers, audit (' + AuthData + ')?' + #13#10#13#10 +
        'WARNING: every joined computer would have to join a new auth server. Choose No unless you are sure.',
        mbConfirmation, MB_YESNO or MB_DEFBUTTON2) = IDYES then
      DelTree(AuthData, True, True, True);
end;
