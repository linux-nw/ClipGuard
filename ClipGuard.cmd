@echo off
rem Start ClipGuard.
rem   Without parameters:  starts ClipGuard hidden in the tray (shield icon next to the clock).
rem   With parameters:  passes them on to clipguard.ps1, e.g.  ClipGuard.cmd -SelbstTest
chcp 65001 >nul

if "%~1"=="" (
    start "" /min powershell.exe -NoProfile -STA -WindowStyle Hidden -ExecutionPolicy Bypass -File "%~dp0clipguard.ps1"
    echo   ClipGuard laeuft jetzt im Tray.
    timeout /t 2 >nul
    exit /b 0
)

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0clipguard.ps1" %*
exit /b %ERRORLEVEL%
