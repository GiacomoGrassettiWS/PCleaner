@echo off
REM Build a standalone PCleaner.exe with PyInstaller.
REM The .exe will be created in the "dist" folder.
REM
REM Requires: pip install pyinstaller

echo Building PCleaner.exe ...
python -m PyInstaller --noconfirm --clean ^
    --onefile ^
    --windowed ^
    --name PCleaner ^
    --icon icon.ico ^
    --add-data "icon.ico;." ^
    pcleaner.py

if errorlevel 1 (
    echo.
    echo Build FAILED. Make sure PyInstaller is installed:  pip install pyinstaller
    pause
    exit /b 1
)

echo.
echo Done. Your executable is here:  dist\PCleaner.exe
pause
