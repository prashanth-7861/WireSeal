; WireSeal NSIS Installer Script
; Build: makensis /DVERSION=0.1.0 /DSRCBINARY=path\to\WireSeal.exe installer\wireseal.nsi
;
; Requires NSIS 3.x (Unicode mode).

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

!define APPNAME     "WireSeal"
!define PUBLISHER   "WireSeal Contributors"
!define URL         "https://github.com/prashanth-7861/WireSeal"
!define EXENAME     "WireSeal.exe"
!define REGKEY      "Software\Microsoft\Windows\CurrentVersion\Uninstall\WireSeal"
!define INSTREGKEY  "Software\WireSeal"

Name "${APPNAME} ${VERSION}"
OutFile "..\dist\release\wireseal-${VERSION}-windows-x86_64-setup.exe"
InstallDir "$PROGRAMFILES64\WireSeal"
InstallDirRegKey HKLM "${INSTREGKEY}" "Install_Dir"
RequestExecutionLevel admin
SetCompressor /SOLID lzma
BrandingText "${APPNAME} ${VERSION}"

;---------------------------------------------------------------------------
; Pages
;---------------------------------------------------------------------------
!include "MUI2.nsh"

!define MUI_ABORTWARNING

; Installer pages
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES

; Finish page — offer to launch the app
!define MUI_FINISHPAGE_RUN "$INSTDIR\${EXENAME}"
!define MUI_FINISHPAGE_RUN_TEXT "Launch ${APPNAME}"
!insertmacro MUI_PAGE_FINISH

; Uninstaller pages
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

  ; ── Start Menu shortcuts ──
  CreateDirectory "$SMPROGRAMS\${APPNAME}"
  CreateShortCut  "$SMPROGRAMS\${APPNAME}\${APPNAME}.lnk" "$INSTDIR\${EXENAME}" \
                  "" "$INSTDIR\${EXENAME}" 0
  CreateShortCut  "$SMPROGRAMS\${APPNAME}\Uninstall ${APPNAME}.lnk" "$INSTDIR\uninstall.exe"

  ; ── Desktop shortcut ──
  CreateShortCut "$DESKTOP\${APPNAME}.lnk" "$INSTDIR\${EXENAME}" \
                 "" "$INSTDIR\${EXENAME}" 0

  ; ── Add $INSTDIR to PATH (for CLI usage from terminal) ──
  ExecWait '$WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -ExecutionPolicy Bypass -Command \
    "$p = [Environment]::GetEnvironmentVariable(\"PATH\", \"Machine\"); \
     $parts = $p -split \";\"; \
     if ($parts -notcontains \"$INSTDIR\") { \
       [Environment]::SetEnvironmentVariable(\"PATH\", \"$p;$INSTDIR\", \"Machine\") \
     }"'
  SendMessage ${HWND_BROADCAST} ${WM_WININICHANGE} 0 "STR:Environment" /TIMEOUT=5000

  ; ── Add/Remove Programs entry ──
  WriteRegStr   HKLM "${REGKEY}" "DisplayName"     "${APPNAME}"
  WriteRegStr   HKLM "${REGKEY}" "Publisher"        "${PUBLISHER}"
  WriteRegStr   HKLM "${REGKEY}" "URLInfoAbout"     "${URL}"
  WriteRegStr   HKLM "${REGKEY}" "DisplayVersion"   "${VERSION}"
  WriteRegStr   HKLM "${REGKEY}" "InstallLocation"  "$INSTDIR"
  WriteRegStr   HKLM "${REGKEY}" "DisplayIcon"      "$INSTDIR\${EXENAME}"
  WriteRegStr   HKLM "${REGKEY}" "UninstallString"  '"$INSTDIR\uninstall.exe"'
  WriteRegDWORD HKLM "${REGKEY}" "NoModify"         1
  WriteRegDWORD HKLM "${REGKEY}" "NoRepair"         1

  ; Estimated size (in KB) for Add/Remove Programs
  ${GetSize} "$INSTDIR" "/S=0K" $0 $1 $2
  IntFmt $0 "0x%08X" $0
  WriteRegDWORD HKLM "${REGKEY}" "EstimatedSize" $0

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

  ; Remove Start Menu shortcuts
  Delete "$SMPROGRAMS\${APPNAME}\${APPNAME}.lnk"
  Delete "$SMPROGRAMS\${APPNAME}\Uninstall ${APPNAME}.lnk"
  RMDir  "$SMPROGRAMS\${APPNAME}"

  ; Remove Desktop shortcut
  Delete "$DESKTOP\${APPNAME}.lnk"

  ; Remove $INSTDIR from system PATH
  ExecWait '$WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -ExecutionPolicy Bypass -Command \
    "[Environment]::SetEnvironmentVariable(\"PATH\", \
      (([Environment]::GetEnvironmentVariable(\"PATH\", \"Machine\") -split \";\") | \
       Where-Object { $_ -ne \"$INSTDIR\" }) -join \";\", \"Machine\")"'
  SendMessage ${HWND_BROADCAST} ${WM_WININICHANGE} 0 "STR:Environment" /TIMEOUT=5000

  ; Remove registry entries
  DeleteRegKey HKLM "${REGKEY}"
  DeleteRegKey /ifempty HKLM "${INSTREGKEY}"
SectionEnd
