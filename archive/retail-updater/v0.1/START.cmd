@echo off
cd /d "%~dp0"
where py >nul 2>nul
if not errorlevel 1 (
  py -3 checker.py
) else (
  python checker.py
)
if errorlevel 1 (
  echo Could not run. Python 3.9+ with tkinter is required. No packages need installing.
  pause
)
