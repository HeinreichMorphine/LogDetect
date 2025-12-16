@echo off
echo Starting LogDetect Forensics Tool...
python main.py
if %errorlevel% neq 0 (
    echo.
    echo An error occurred. Please check if Python is installed and requirements are met.
    pause
)
