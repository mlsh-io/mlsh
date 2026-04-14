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
PrivilegesRequired=lowest
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

[Run]
Filename: "{app}\mlsh.exe"; Parameters: "--version"; Flags: nowait postinstall skipifsilent runhidden
