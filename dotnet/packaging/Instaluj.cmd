@echo off
rem Instalator Bezpiecznego Aktualizatora - uruchamia Install.ps1 (sprawdza podpisy, instaluje .NET i aplikację).
setlocal
set "PSModulePath=%SystemRoot%\System32\WindowsPowerShell\v1.0\Modules"
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "%~dp0Install.ps1" %*
set "InstallExitCode=%ERRORLEVEL%"
if not "%InstallExitCode%"=="0" pause
exit /b %InstallExitCode%
