@echo off
REM Radar Marista - test
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0test.ps1" %*
pause
