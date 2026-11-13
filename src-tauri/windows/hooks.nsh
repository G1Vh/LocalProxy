; LocalProxy NSIS hooks. Relies on the Tauri template's $UpdateMode and
; MAINBINARYNAME; re-check them when bumping @tauri-apps/cli.

!macro NSIS_HOOK_PREUNINSTALL
  ; A real uninstall (not an update): put the Windows proxy settings and
  ; HTTP_PROXY variables back, and drop the autostart entry.
  ${If} $UpdateMode <> 1
    ExecWait '"$INSTDIR\${MAINBINARYNAME}.exe" --restore-system'
    DeleteRegValue HKCU "Software\Microsoft\Windows\CurrentVersion\Run" "LocalProxy"
    DeleteRegValue HKCU "Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" "LocalProxy"
    ; The TUN service, if it was ever installed (asks for admin rights).
    ReadRegStr $0 HKLM "SYSTEM\CurrentControlSet\Services\LocalProxyTun" "ImagePath"
    ${If} $0 != ""
      ExecShellWait "runas" "$INSTDIR\localproxy-tunnel.exe" "service uninstall" SW_HIDE
    ${EndIf}
  ${EndIf}
!macroend
