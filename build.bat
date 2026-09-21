@echo off
rem Build the single-file GUI exe with PyInstaller. ASCII only (cmd reads cp936).
setlocal
cd /d "%~dp0"

if not exist ".venv\Scripts\pyinstaller.exe" (
    echo [ERROR] .venv\Scripts\pyinstaller.exe not found.
    echo Run: .venv\Scripts\python.exe -m pip install pyinstaller
    exit /b 1
)

".venv\Scripts\pyinstaller.exe" build_exe.spec --noconfirm %*
if errorlevel 1 (
    echo [ERROR] Build failed.
    exit /b 1
)

echo.
echo [OK] Built: dist\*.exe
endlocal
