; Derycode Cybersecurity - Windows installer (Stage 8)
; Prerequisite: run `pyinstaller packaging/dcs.spec` first.
; Build with Inno Setup 6: compile this script.

[Setup]
AppName=Derycode Cybersecurity
AppVersion=1.0.0
AppPublisher=Derycode Organization
DefaultDirName={autopf}\DerycodeCybersecurity
DefaultGroupName=Derycode Cybersecurity
OutputBaseName=DerycodeCybersecurity-Setup
OutputDir=..\dist-installer
Compression=lzma2
SolidCompression=yes
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=admin

[Files]
Source: "..\dist\DerycodeCybersecurity\*"; DestDir: "{app}"; Flags: recursesubdirs

[Icons]
Name: "{group}\Derycode Cybersecurity"; Filename: "{app}\DerycodeCybersecurity.exe"
Name: "{commondesktop}\Derycode Cybersecurity"; Filename: "{app}\DerycodeCybersecurity.exe"

[Run]
Filename: "{app}\DerycodeCybersecurity.exe"; Description: "Launch Derycode Cybersecurity"; Flags: nowait postinstall skipifsilent

[UninstallDelete]
Type: filesandordirs; Name: "{app}"
