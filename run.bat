@echo off
rem ============================================================
rem  DST IP Join Helper - GUI launcher
rem  This file is intentionally ASCII-only: cmd.exe decodes .bat
rem  files using the console codepage (cp936 on Chinese Windows),
rem  so non-ASCII text here would be garbled.
rem ============================================================
setlocal enabledelayedexpansion
set "HERE=%~dp0"
set "PYW="
set "PYWARGS="

rem 1) Project virtual environment (recommended)
if exist "%HERE%.venv\Scripts\pythonw.exe" set "PYW=%HERE%.venv\Scripts\pythonw.exe"

rem 2) Standard per-user install location
if not defined PYW if exist "%LOCALAPPDATA%\Programs\Python\pythonw.exe" set "PYW=%LOCALAPPDATA%\Programs\Python\pythonw.exe"

rem 3) The py launcher, which reliably skips the 0-byte Microsoft Store stubs
if not defined PYW (
  where pyw.exe >nul 2>nul
  if !errorlevel! equ 0 (
    set "PYW=pyw.exe"
    set "PYWARGS=-3"
  )
)

rem 4) Last resort: plain PATH lookup
if not defined PYW (
  for %%I in (pythonw.exe) do if not "%%~$PATH:I"=="" set "PYW=%%~$PATH:I"
)

if not defined PYW (
  echo.
  echo Python 3 was not found on this machine.
  echo Install Python 3.10 or newer from https://www.python.org and try again.
  echo.
  pause
  exit /b 1
)

start "" "%PYW%" %PYWARGS% "%HERE%main.py" %*
exit /b 0
