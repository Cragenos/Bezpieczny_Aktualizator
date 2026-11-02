@echo off
set /p signer=Enter the independently verified SHA-256 signer fingerprint:
powershell.exe -NoProfile -ExecutionPolicy AllSigned -File "%~dp0Install-OfflineUpdates.ps1" -ExpectedSignerSha256 "%signer%"
set "result=%ERRORLEVEL%"
echo.
echo Installer exit code: %result%
pause
exit /b %result%
