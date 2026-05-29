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

[Files]
Source: "bin\mlsh.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "bin\mlshtund.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "bin\wintun.dll"; DestDir: "{app}"; Flags: ignoreversion
Source: "bin\LICENSE.txt"; DestDir: "{app}\licenses"; DestName: "wintun-LICENSE.txt"; Flags: ignoreversion

[Tasks]
; Only offered on an admin install; registers + starts the LocalSystem service.
Name: "service"; Description: "Run mlshtund as a Windows service (starts at boot)"; Check: IsAdminInstallMode

[Icons]
Name: "{group}\mlsh"; Filename: "{app}\mlsh.exe"
Name: "{group}\Uninstall mlsh"; Filename: "{uninstallexe}"

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
  if (CurStep = ssInstall) and IsAdminInstallMode then
  begin
    Exec(ExpandConstant('{sys}\sc.exe'), 'stop mlshtund', '', SW_HIDE,
      ewWaitUntilTerminated, ResultCode);
    // Give the service a moment to exit and release the binary.
    Sleep(2000);
  end;
end;

[Run]
; Register + start the tunnel service (admin install + task selected).
Filename: "{app}\mlsh.exe"; Parameters: "tunnel install"; Flags: runhidden waituntilterminated; Tasks: service; StatusMsg: "Installing the mlsh tunnel service..."
Filename: "{app}\mlsh.exe"; Parameters: "--version"; Flags: nowait postinstall skipifsilent runhidden

[UninstallRun]
; Stop + remove the service before files are deleted (runs early in uninstall).
Filename: "{app}\mlsh.exe"; Parameters: "tunnel uninstall"; Flags: runhidden waituntilterminated; RunOnceId: "RemoveMlshService"
