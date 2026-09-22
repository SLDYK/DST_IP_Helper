@echo off
rem ============================================================
rem  DST UDP Relay - plain UDP forwarder (no protocol parsing).
rem
rem  This file is intentionally ASCII-only: cmd.exe decodes .bat
rem  files using the console codepage (cp936 on Chinese Windows),
rem  so non-ASCII text here would be garbled.
rem
rem  PAIR THIS WITH A FRIEND. Both sides run this same script.
rem
rem  Host side  (auto-detect DST ports, listen on [::]:20000):
rem      run_relay.bat --auto-ports --auto-base 20000
rem
rem  Host side  (manual, if auto-detect finds nothing):
rem      run_relay.bat --map "[::]:20000=127.0.0.1:10999"
rem
rem  Guest side (local 127.0.0.1:10999 -> host public address):
rem      run_relay.bat --map 127.0.0.1:10999=[2001:db8::1]:20000
rem
rem  Restrict who may connect (recommended on the host side):
rem      run_relay.bat --map "[::]:20000=127.0.0.1:10999" --allow 2409:8a60::/32
rem
rem  Extra arguments are passed straight through to the relay.
rem  See all options with:  run_relay.bat --help
rem ============================================================
setlocal enabledelayedexpansion
set "HERE=%~dp0"
set "PY="
set "PYARGS="

rem 1) Project virtual environment (recommended)
if exist "%HERE%.venv\Scripts\python.exe" set "PY=%HERE%.venv\Scripts\python.exe"

rem 2) Standard per-user install location
if not defined PY if exist "%LOCALAPPDATA%\Programs\Python\python.exe" set "PY=%LOCALAPPDATA%\Programs\Python\python.exe"

rem 3) The py launcher, which reliably skips the 0-byte Microsoft Store stubs
if not defined PY (
  where py.exe >nul 2>nul
  if !errorlevel! equ 0 (
    set "PY=py.exe"
    set "PYARGS=-3"
  )
)

rem 4) Whatever python.exe is on PATH
if not defined PY (
  for %%I in (python.exe) do if not "%%~$PATH:I"=="" set "PY=%%~$PATH:I"
)

if not defined PY (
  echo.
  echo Python 3 was not found on this machine.
  echo Install Python 3.10 or newer from https://www.python.org and try again.
  echo.
  pause
  exit /b 1
)

pushd "%HERE%"
"%PY%" %PYARGS% -m dst_ip_join.relay %*
set "RC=%ERRORLEVEL%"
popd
echo.
pause
exit /b %RC%
