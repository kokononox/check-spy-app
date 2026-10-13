@echo off
setlocal
cd /d "%~dp0"
title Targeted Request Capture 1.0
if not exist "runtime\python.exe" (
 echo ERROR: Extract the entire ZIP first. Portable runtime is missing.
 pause
 exit /b 1
)
"runtime\python.exe" -u collect.py
set "code=%errorlevel%"
echo.
echo Tool finished with exit code %code%.
echo If there was an error, keep this window open and read it.
pause
exit /b %code%
