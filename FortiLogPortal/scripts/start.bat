@echo off
REM Radar Marista - start
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0start.ps1" %*
pause
