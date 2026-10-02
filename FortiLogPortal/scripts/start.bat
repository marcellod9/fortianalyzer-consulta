@echo off
REM FortiLogPortal - start
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0start.ps1" %*
pause
