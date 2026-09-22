@echo off
rem ============================================================
rem  Build the single-file GUI exe with Nuitka.
rem  ASCII only on purpose (cmd.exe reads .bat as cp936 here).
rem
rem  Requirements:
rem    - .venv with nuitka installed:
rem        .venv\Scripts\python.exe -m pip install nuitka ordered-set zstandard
rem    - A C compiler: MSVC (Visual Studio with "Desktop development
rem      with C++") or MinGW. Nuitka auto-detects MSVC via vswhere.
rem
rem  Usage:
rem    build.bat                 onefile exe -> dist\...
rem    build.bat --no-onefile    directory build (starts faster)
rem    build.bat --keep-output   keep intermediate files
rem
rem  All arguments are forwarded to build_nuitka.py (see --help).
rem ============================================================
setlocal
cd /d "%~dp0"

set "PY=%CD%\.venv\Scripts\python.exe"
if not exist "%PY%" (
    echo [ERROR] .venv\Scripts\python.exe not found.
    echo Create it first: python -m venv .venv
    exit /b 1
)

"%PY%" -c "import nuitka" >nul 2>nul
if errorlevel 1 (
    echo [ERROR] nuitka is not installed in .venv.
    echo Run: .venv\Scripts\python.exe -m pip install nuitka ordered-set zstandard
    exit /b 1
)

"%PY%" "%CD%\build_nuitka.py" %*
rem build_nuitka.py already reports success/failure itself.
if errorlevel 1 (
    echo.
    echo [ERROR] Build failed.
    exit /b 1
)

endlocal
