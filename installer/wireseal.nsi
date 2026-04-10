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
; SRCDIR is the root of the PyInstaller onedir output (dist\WireSeal\).
; It must contain WireSeal.exe at the top and _internal\ beneath it.
; The whole tree is installed recursively with `File /r`.
!ifndef SRCDIR
  !define SRCDIR "..\dist\WireSeal"
!endif
!ifndef CLIBINARY
  !define CLIBINARY "..\dist\release\wireseal-cli-windows-x86_64.exe"
!endif

!define APPNAME     "WireSeal"
!define PUBLISHER   "WireSeal Contributors"
!define URL         "https://github.com/prashanth-7861/WireSeal"
!define EXENAME     "WireSeal.exe"
!define CLINAME     "wireseal.exe"
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
!include "FileFunc.nsh"

!define MUI_ABORTWARNING

; Installer pages
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES

; Finish page — offer to launch the app (de-elevated via explorer.exe so
; that WebView2 can render; it refuses to work inside an elevated process).
!define MUI_FINISHPAGE_RUN_FUNCTION LaunchApp
!define MUI_FINISHPAGE_RUN_TEXT "Launch ${APPNAME}"
!insertmacro MUI_PAGE_FINISH

Function LaunchApp
  ; Spawn through explorer so the child process gets the normal user token,
  ; not the admin token inherited from the installer.
  Exec '"$WINDIR\explorer.exe" "$INSTDIR\${EXENAME}"'
FunctionEnd

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

  ; Recursively install the full PyInstaller onedir tree:
  ;   $INSTDIR\WireSeal.exe
  ;   $INSTDIR\_internal\          (Python runtime + pywebview + all deps)
  ;     ├── webview\                 (native webview package — Python sources on disk)
  ;     ├── clr_loader\              (pythonnet ffi helpers)
  ;     ├── python312.dll
  ;     └── ...
  ;
  ; Switching from onefile to onedir eliminates the runtime extraction bug
  ; that was preventing pywebview from loading.
  File /r "${SRCDIR}\*.*"

  ; Copy the CLI binary (for terminal usage)
  File /oname=${CLINAME} "${CLIBINARY}"

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
  ExecWait '$WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe \
    -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -Command \
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
  ; Remove the entire onedir tree (WireSeal.exe + _internal\ + all deps).
  ; The whole directory was installed with `File /r`, so we RMDir /r the
  ; installation root. This is safe because the installer owns $INSTDIR.
  Delete "$INSTDIR\uninstall.exe"
  RMDir /r "$INSTDIR\_internal"
  Delete "$INSTDIR\${EXENAME}"
  Delete "$INSTDIR\${CLINAME}"
  RMDir  "$INSTDIR"

  ; Remove Start Menu shortcuts
  Delete "$SMPROGRAMS\${APPNAME}\${APPNAME}.lnk"
  Delete "$SMPROGRAMS\${APPNAME}\Uninstall ${APPNAME}.lnk"
  RMDir  "$SMPROGRAMS\${APPNAME}"

  ; Remove Desktop shortcut
  Delete "$DESKTOP\${APPNAME}.lnk"

  ; Remove $INSTDIR from system PATH
  ExecWait '$WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe \
    -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -Command \
    "[Environment]::SetEnvironmentVariable(\"PATH\", \
      (([Environment]::GetEnvironmentVariable(\"PATH\", \"Machine\") -split \";\") | \
       Where-Object { $_ -ne \"$INSTDIR\" }) -join \";\", \"Machine\")"'
  SendMessage ${HWND_BROADCAST} ${WM_WININICHANGE} 0 "STR:Environment" /TIMEOUT=5000

  ; Remove registry entries
  DeleteRegKey HKLM "${REGKEY}"
  DeleteRegKey /ifempty HKLM "${INSTREGKEY}"
SectionEnd
