@echo off
rem Instalator Bezpiecznego Aktualizatora - uruchamia Install.ps1 (sprawdza podpisy, instaluje .NET i aplikację).
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Install.ps1" %*
if errorlevel 1 pause
