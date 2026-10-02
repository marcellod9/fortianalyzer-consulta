@echo off
REM FortiLogPortal - test
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0test.ps1" %*
pause
