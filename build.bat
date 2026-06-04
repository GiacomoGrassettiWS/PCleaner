@echo off
REM Build a standalone DiskCleaner.exe with PyInstaller.
REM The .exe will be created in the "dist" folder.
REM
REM Requires: pip install pyinstaller

echo Building DiskCleaner.exe ...
python -m PyInstaller --noconfirm --clean ^
    --onefile ^
    --windowed ^
    --name DiskCleaner ^
    disk_cleaner.py

if errorlevel 1 (
    echo.
    echo Build FAILED. Make sure PyInstaller is installed:  pip install pyinstaller
    pause
    exit /b 1
)

echo.
echo Done. Your executable is here:  dist\DiskCleaner.exe
pause
