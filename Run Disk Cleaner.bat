@echo off
REM Launch the app without the black console window.
REM To scan system folders without "access denied" errors, run this
REM file as Administrator (right-click -> Run as administrator).
start "" pythonw "%~dp0disk_cleaner.py"
