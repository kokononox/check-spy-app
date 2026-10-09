@echo off
cd /d "%~dp0"
powershell.exe -NoLogo -NoProfile -STA -ExecutionPolicy Bypass -File "%~dp0Monitor.ps1" -Advanced
if errorlevel 1 pause
