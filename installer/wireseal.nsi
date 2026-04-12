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
; CLI binary lives in its own bin\ subdirectory to prevent a case-insensitive
; filename collision with the GUI bootloader on NTFS (Windows treats
; "WireSeal.exe" and "wireseal.exe" as the same file, so co-locating them
; would cause the CLI onefile binary to overwrite the GUI onedir bootloader).
!define CLISUBDIR   "bin"
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

!define MUI_ICON   "..\assets\wireseal.ico"
!define MUI_UNICON "..\assets\wireseal.ico"
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

  ; Clean up any stale CLI binary from a pre-fix install where the CLI lived
  ; in $INSTDIR and collided case-insensitively with WireSeal.exe. On a fresh
  ; install this is a no-op; on an upgrade it removes the broken artifact.
  ; We do NOT delete "$INSTDIR\wireseal.exe" because on NTFS that is the same
  ; inode as WireSeal.exe which was just installed by File /r above.

  ; Install the CLI binary into its own bin\ subdirectory so it cannot
  ; collide with the GUI bootloader. $INSTDIR\bin is added to PATH below
  ; so users can still run `wireseal` from a terminal.
  CreateDirectory "$INSTDIR\${CLISUBDIR}"
  SetOutPath "$INSTDIR\${CLISUBDIR}"
  File /oname=${CLINAME} "${CLIBINARY}"
  SetOutPath "$INSTDIR"

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

  ; ── Add $INSTDIR\bin to PATH (for `wireseal` CLI usage from terminal) ──
  ; Also scrub a stale $INSTDIR entry from a pre-fix install, in case the
  ; old installer added $INSTDIR directly (which now contains only the GUI).
  ExecWait '$WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe \
    -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -Command \
    "$p = [Environment]::GetEnvironmentVariable(\"PATH\", \"Machine\"); \
     $parts = @($p -split \";\" | Where-Object { $_ -and $_ -ne \"$INSTDIR\" }); \
     if ($parts -notcontains \"$INSTDIR\bin\") { $parts += \"$INSTDIR\bin\" }; \
     [Environment]::SetEnvironmentVariable(\"PATH\", ($parts -join \";\"), \"Machine\")"'
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
  ; Remove the entire onedir tree (WireSeal.exe + _internal\ + bin\ + all deps).
  ; The whole directory was installed with `File /r` + the CLI into bin\, so
  ; we explicitly clean each known subtree. This is safe because the installer
  ; owns $INSTDIR.
  Delete "$INSTDIR\uninstall.exe"
  RMDir /r "$INSTDIR\_internal"
  Delete "$INSTDIR\${CLISUBDIR}\${CLINAME}"
  RMDir  "$INSTDIR\${CLISUBDIR}"
  Delete "$INSTDIR\${EXENAME}"
  RMDir  "$INSTDIR"

  ; Remove Start Menu shortcuts
  Delete "$SMPROGRAMS\${APPNAME}\${APPNAME}.lnk"
  Delete "$SMPROGRAMS\${APPNAME}\Uninstall ${APPNAME}.lnk"
  RMDir  "$SMPROGRAMS\${APPNAME}"

  ; Remove Desktop shortcut
  Delete "$DESKTOP\${APPNAME}.lnk"

  ; Remove $INSTDIR and $INSTDIR\bin from system PATH (both entries are
  ; stripped so pre-fix installs that added $INSTDIR directly are cleaned up).
  ExecWait '$WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe \
    -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -Command \
    "[Environment]::SetEnvironmentVariable(\"PATH\", \
      (([Environment]::GetEnvironmentVariable(\"PATH\", \"Machine\") -split \";\") | \
       Where-Object { $_ -and $_ -ne \"$INSTDIR\" -and $_ -ne \"$INSTDIR\bin\" }) -join \";\", \"Machine\")"'
  SendMessage ${HWND_BROADCAST} ${WM_WININICHANGE} 0 "STR:Environment" /TIMEOUT=5000

  ; Remove registry entries
  DeleteRegKey HKLM "${REGKEY}"
  DeleteRegKey /ifempty HKLM "${INSTREGKEY}"
SectionEnd
