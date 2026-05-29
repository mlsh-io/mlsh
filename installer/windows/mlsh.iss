; mlsh Inno Setup Installer Script
; Requires Inno Setup 6+
; Build: iscc mlsh.iss

#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif

[Setup]
AppName=mlsh
AppVersion={#AppVersion}
AppVerName=mlsh {#AppVersion}
AppPublisher=mlsh.io
AppPublisherURL=https://mlsh.io
AppSupportURL=https://github.com/mlsh-io/mlsh/issues
DefaultDirName={autopf}\mlsh
DefaultGroupName=mlsh
OutputBaseFilename=mlsh-{#AppVersion}-windows-amd64-setup
Compression=lzma2/ultra64
SolidCompression=yes
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
ChangesEnvironment=yes
; Admin is required to register mlshtund as a Windows service. Users may still
; downgrade to a per-user install (without the service) via the elevation dialog.
PrivilegesRequired=admin
PrivilegesRequiredOverridesAllowed=dialog
MinVersion=10.0
OutputDir=output
WizardStyle=modern
DisableProgramGroupPage=yes
; Branding icon (MLSH hexagon), shared with the tray app's embedded icon.
SetupIconFile=..\..\mlsh-systray\resources\app.ico
UninstallDisplayIcon={app}\mlsh-systray.exe
; The {userstartup} autostart shortcut is intentional and gated to non-admin
; installs (Check: not IsAdminInstallMode); silence the per-user-area warning.
UsedUserAreasWarning=no

[Files]
Source: "bin\mlsh.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "bin\mlshtund.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "bin\wintun.dll"; DestDir: "{app}"; Flags: ignoreversion
Source: "bin\LICENSE.txt"; DestDir: "{app}\licenses"; DestName: "wintun-LICENSE.txt"; Flags: ignoreversion
; MLSH tray app + its Qt runtime, deployed by windeployqt in CI into systray\.
; The whole tree lands in {app} so mlsh-systray.exe sits next to mlsh.exe.
Source: "systray\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
; Qt LGPLv3 compliance: ship Qt's license text + an attribution/relink notice.
Source: "..\..\mlsh-systray\licenses\Qt-LICENSE.txt"; DestDir: "{app}\licenses"; Flags: ignoreversion
Source: "..\..\mlsh-systray\licenses\Qt-NOTICE.txt"; DestDir: "{app}\licenses"; Flags: ignoreversion

[Tasks]
; Only offered on an admin install; registers + starts the LocalSystem service.
Name: "service"; Description: "Run mlshtund as a Windows service (starts at boot)"; Check: IsAdminInstallMode
; Launch the tray app automatically at login.
Name: "systrayautostart"; Description: "Start the MLSH tray app at login"; GroupDescription: "Startup:"

[Icons]
Name: "{group}\MLSH"; Filename: "{app}\mlsh-systray.exe"
Name: "{group}\Uninstall mlsh"; Filename: "{uninstallexe}"
; Autostart shortcut: all users on an admin install, current user otherwise.
Name: "{commonstartup}\MLSH"; Filename: "{app}\mlsh-systray.exe"; Tasks: systrayautostart; Check: IsAdminInstallMode
Name: "{userstartup}\MLSH"; Filename: "{app}\mlsh-systray.exe"; Tasks: systrayautostart; Check: not IsAdminInstallMode

[Registry]
; Add to user PATH (non-admin) or system PATH (admin)
Root: HKCU; Subkey: "Environment"; ValueType: expandsz; ValueName: "Path"; \
  ValueData: "{olddata};{app}"; Check: NeedsAddPath('{app}') and not IsAdminInstallMode
Root: HKLM; Subkey: "SYSTEM\CurrentControlSet\Control\Session Manager\Environment"; \
  ValueType: expandsz; ValueName: "Path"; \
  ValueData: "{olddata};{app}"; Check: NeedsAddPath('{app}') and IsAdminInstallMode

[Code]
function NeedsAddPath(Param: string): Boolean;
var
  OrigPath: string;
  InstallDir: string;
begin
  InstallDir := ExpandConstant(Param);
  if IsAdminInstallMode then
    RegQueryStringValue(HKLM, 'SYSTEM\CurrentControlSet\Control\Session Manager\Environment', 'Path', OrigPath)
  else
    RegQueryStringValue(HKCU, 'Environment', 'Path', OrigPath);
  Result := Pos(';' + Uppercase(InstallDir) + ';', ';' + Uppercase(OrigPath) + ';') = 0;
end;

// Stop a running mlshtund service before files are copied so its executable
// and wintun.dll aren't locked during an upgrade. `mlsh tunnel install`
// (run afterwards) reconfigures and restarts it.
procedure CurStepChanged(CurStep: TSetupStep);
var
  ResultCode: Integer;
begin
  if (CurStep = ssInstall) then
  begin
    // Close a running tray app so its Qt DLLs aren't locked during an upgrade.
    Exec(ExpandConstant('{sys}\taskkill.exe'), '/IM mlsh-systray.exe /F', '',
      SW_HIDE, ewWaitUntilTerminated, ResultCode);
    if IsAdminInstallMode then
    begin
      Exec(ExpandConstant('{sys}\sc.exe'), 'stop mlshtund', '', SW_HIDE,
        ewWaitUntilTerminated, ResultCode);
      // Give the service a moment to exit and release the binary.
      Sleep(2000);
    end;
  end;
end;

[Run]
; Register + start the tunnel service (admin install + task selected).
Filename: "{app}\mlsh.exe"; Parameters: "tunnel install"; Flags: runhidden waituntilterminated; Tasks: service; StatusMsg: "Installing the mlsh tunnel service..."
; Launch the tray app after install. runasoriginaluser so it runs as the
; logged-in user, not the elevated installer account.
Filename: "{app}\mlsh-systray.exe"; Description: "Launch MLSH"; Flags: nowait postinstall skipifsilent runasoriginaluser

[UninstallRun]
; Close the tray app, then stop + remove the service before files are deleted.
Filename: "{sys}\taskkill.exe"; Parameters: "/IM mlsh-systray.exe /F"; Flags: runhidden; RunOnceId: "StopMlshTray"
Filename: "{app}\mlsh.exe"; Parameters: "tunnel uninstall"; Flags: runhidden waituntilterminated; RunOnceId: "RemoveMlshService"
