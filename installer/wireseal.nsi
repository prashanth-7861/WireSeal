; WireSeal NSIS Installer Script
; Build: makensis /DVERSION=0.1.0 installer\wireseal.nsi
;
; Requires NSIS 3.x (Unicode mode).
; No external plugins needed — PATH modification uses PowerShell via ExecWait.

Unicode True

;---------------------------------------------------------------------------
; Defines (overridden from command line with /D flags)
;---------------------------------------------------------------------------
!ifndef VERSION
  !define VERSION "dev"
!endif
!ifndef SRCBINARY
  !define SRCBINARY "..\dist\release\wireseal-windows-x86_64.exe"
!endif

!define APPNAME   "WireSeal"
!define PUBLISHER "WireSeal Contributors"
!define URL       "https://github.com/prashanth-7861/WireSeal"
!define EXENAME   "wireseal.exe"
!define REGKEY    "Software\Microsoft\Windows\CurrentVersion\Uninstall\WireSeal"
!define INSTREGKEY "Software\WireSeal"

Name "${APPNAME} ${VERSION}"
OutFile "..\dist\release\wireseal-${VERSION}-windows-x86_64-setup.exe"
InstallDir "$PROGRAMFILES64\WireSeal"
InstallDirRegKey HKLM "${INSTREGKEY}" "Install_Dir"
RequestExecutionLevel admin
SetCompressor /SOLID lzma
BrandingText "${APPNAME} ${VERSION} — WireGuard automation"

;---------------------------------------------------------------------------
; Pages
;---------------------------------------------------------------------------
!include "MUI2.nsh"

!define MUI_ABORTWARNING
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

!insertmacro MUI_LANGUAGE "English"

;---------------------------------------------------------------------------
; Install section
;---------------------------------------------------------------------------
Section "WireSeal (required)" SecMain
  SectionIn RO

  SetOutPath "$INSTDIR"

  ; Copy the single-file binary
  File /oname=${EXENAME} "${SRCBINARY}"

  ; Create uninstaller
  WriteUninstaller "$INSTDIR\uninstall.exe"

  ; Add $INSTDIR to the system PATH via PowerShell (handles duplicates safely)
  ExecWait '$WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -ExecutionPolicy Bypass -Command \
    "$p = [Environment]::GetEnvironmentVariable(\"PATH\", \"Machine\"); \
     $parts = $p -split \";\"; \
     if ($parts -notcontains \"$INSTDIR\") { \
       [Environment]::SetEnvironmentVariable(\"PATH\", \"$p;$INSTDIR\", \"Machine\") \
     }"'

  ; Broadcast WM_SETTINGCHANGE so running shells pick up the new PATH
  SendMessage ${HWND_BROADCAST} ${WM_WININICHANGE} 0 "STR:Environment" /TIMEOUT=5000

  ; Add/Remove Programs entry
  WriteRegStr   HKLM "${REGKEY}" "DisplayName"     "${APPNAME}"
  WriteRegStr   HKLM "${REGKEY}" "Publisher"       "${PUBLISHER}"
  WriteRegStr   HKLM "${REGKEY}" "URLInfoAbout"    "${URL}"
  WriteRegStr   HKLM "${REGKEY}" "DisplayVersion"  "${VERSION}"
  WriteRegStr   HKLM "${REGKEY}" "InstallLocation" "$INSTDIR"
  WriteRegStr   HKLM "${REGKEY}" "DisplayIcon"     "$INSTDIR\${EXENAME}"
  WriteRegStr   HKLM "${REGKEY}" "UninstallString" '"$INSTDIR\uninstall.exe"'
  WriteRegDWORD HKLM "${REGKEY}" "NoModify"        1
  WriteRegDWORD HKLM "${REGKEY}" "NoRepair"        1

  ; Store install location for future reference
  WriteRegStr HKLM "${INSTREGKEY}" "Install_Dir" "$INSTDIR"
SectionEnd

;---------------------------------------------------------------------------
; Uninstall section
;---------------------------------------------------------------------------
Section "Uninstall"
  ; Remove files
  Delete "$INSTDIR\${EXENAME}"
  Delete "$INSTDIR\uninstall.exe"
  RMDir  "$INSTDIR"

  ; Remove $INSTDIR from system PATH via PowerShell
  ExecWait '$WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -ExecutionPolicy Bypass -Command \
    "[Environment]::SetEnvironmentVariable(\"PATH\", \
      (([Environment]::GetEnvironmentVariable(\"PATH\", \"Machine\") -split \";\") | \
       Where-Object { $_ -ne \"$INSTDIR\" }) -join \";\", \"Machine\")"'

  SendMessage ${HWND_BROADCAST} ${WM_WININICHANGE} 0 "STR:Environment" /TIMEOUT=5000

  ; Remove registry entries
  DeleteRegKey HKLM "${REGKEY}"
  DeleteRegKey /ifempty HKLM "${INSTREGKEY}"
SectionEnd
