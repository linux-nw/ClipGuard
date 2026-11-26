@echo off
rem ClipGuard starten.
rem   Ohne Parameter:  startet ClipGuard unsichtbar im Tray (Schild-Symbol neben der Uhr).
rem   Mit Parametern:  reicht sie an clipguard.ps1 weiter, z.B.  ClipGuard.cmd -SelbstTest
chcp 65001 >nul

if "%~1"=="" (
    start "" /min powershell.exe -NoProfile -STA -WindowStyle Hidden -ExecutionPolicy Bypass -File "%~dp0clipguard.ps1"
    echo   ClipGuard laeuft jetzt im Tray.
    timeout /t 2 >nul
    exit /b 0
)

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0clipguard.ps1" %*
exit /b %ERRORLEVEL%
