@echo off
rem ============================================================
rem  DST IP Join Helper - console launcher
rem  ASCII only on purpose (cmd.exe reads .bat as cp936 here).
rem  Pass options through, e.g.:
rem      run_cli.bat --dry-run
rem      run_cli.bat --ports 10999,10998
rem      run_cli.bat --cleanup
rem ============================================================
setlocal enabledelayedexpansion
set "HERE=%~dp0"
set "PY="
set "PYARGS="

rem 1) Project virtual environment (recommended)
if exist "%HERE%.venv\Scripts\python.exe" set "PY=%HERE%.venv\Scripts\python.exe"

rem 2) Standard per-user install location
if not defined PY if exist "%LOCALAPPDATA%\Programs\Python\python.exe" set "PY=%LOCALAPPDATA%\Programs\Python\python.exe"

if not defined PY (
  where py.exe >nul 2>nul
  if !errorlevel! equ 0 (
    set "PY=py.exe"
    set "PYARGS=-3"
  )
)

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

"%PY%" %PYARGS% "%HERE%cli.py" %*
echo.
pause
exit /b 0
