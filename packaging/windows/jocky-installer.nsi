; JOCKY Windows Installer Script (NSIS)
; Produces: jocky-setup-x86_64.exe
; Build: makensis jocky-installer.nsi

!define APP_NAME     "JOCKY"
!define APP_VERSION  "1.0.0"
!define APP_EXE      "jocky-compile.exe"
!define PUBLISHER    "NTRO Hackathon 26148"
!define URL          "https://github.com/vmmuthu31/jocky"
!define INSTALL_DIR  "$PROGRAMFILES64\JOCKY"
!define UNINSTALLER  "uninstall.exe"

Name "${APP_NAME} ${APP_VERSION}"
OutFile "jocky-setup-${APP_VERSION}-x86_64.exe"
InstallDir "${INSTALL_DIR}"
InstallDirRegKey HKLM "Software\JOCKY" ""
RequestExecutionLevel admin
SetCompressor /SOLID lzma

;------------------------------------------------------------
; Pages
Page directory
Page instfiles
UninstPage uninstConfirm
UninstPage instfiles

;------------------------------------------------------------
Section "JOCKY Compiler (required)" SecMain
  SectionIn RO
  SetOutPath "$INSTDIR"

  ; Copy binary
  File "..\..\compiler\target\x86_64-pc-windows-msvc\release\jocky-compile.exe"

  ; Copy examples
  SetOutPath "$INSTDIR\examples"
  File /r "..\..\examples\*.*"

  ; Copy docs
  SetOutPath "$INSTDIR\docs"
  File "..\..\docs\getting-started.md"
  File "..\..\docs\cli-reference.md"
  File "..\..\docs\installation.md"
  File "..\..\README.md"

  ; Write registry keys for uninstaller
  WriteRegStr HKLM "Software\JOCKY" "" "$INSTDIR"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\JOCKY" \
    "DisplayName" "${APP_NAME} ${APP_VERSION}"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\JOCKY" \
    "UninstallString" "$INSTDIR\${UNINSTALLER}"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\JOCKY" \
    "Publisher" "${PUBLISHER}"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\JOCKY" \
    "URLInfoAbout" "${URL}"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\JOCKY" \
    "DisplayVersion" "${APP_VERSION}"

  ; Add to system PATH via registry
  ReadRegStr $R0 HKLM "SYSTEM\CurrentControlSet\Control\Session Manager\Environment" "Path"
  WriteRegExpandStr HKLM "SYSTEM\CurrentControlSet\Control\Session Manager\Environment" "Path" "$R0;$INSTDIR"
  SendMessage ${HWND_BROADCAST} ${WM_WININICHANGE} 0 "STR:Environment" /TIMEOUT=5000

  ; Write uninstaller
  WriteUninstaller "$INSTDIR\${UNINSTALLER}"

  ; Start menu shortcuts
  CreateDirectory "$SMPROGRAMS\JOCKY"
  CreateShortCut "$SMPROGRAMS\JOCKY\JOCKY Terminal.lnk" \
    "cmd.exe" '/k "jocky-compile --help"' "" "" SW_SHOWNORMAL
  CreateShortCut "$SMPROGRAMS\JOCKY\Uninstall JOCKY.lnk" \
    "$INSTDIR\${UNINSTALLER}"
SectionEnd

;------------------------------------------------------------
Section "Uninstall"
  ; Remove from PATH
  EnVar::SetHKLM
  EnVar::DeleteValue "PATH" "$INSTDIR"

  ; Remove files
  Delete "$INSTDIR\jocky-compile.exe"
  Delete "$INSTDIR\${UNINSTALLER}"
  RMDir /r "$INSTDIR\examples"
  RMDir /r "$INSTDIR\docs"
  RMDir "$INSTDIR"

  ; Remove registry keys
  DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\JOCKY"
  DeleteRegKey HKLM "Software\JOCKY"

  ; Remove Start menu
  Delete "$SMPROGRAMS\JOCKY\*.lnk"
  RMDir "$SMPROGRAMS\JOCKY"

  MessageBox MB_OK "JOCKY has been uninstalled."
SectionEnd

;------------------------------------------------------------
Function .onInstSuccess
  MessageBox MB_YESNO "JOCKY ${APP_VERSION} installed.$\n$\nOpen a terminal to get started?" IDNO done
    Exec "cmd.exe /k jocky-compile --help"
  done:
FunctionEnd
