@echo off
echo ========================================================
echo   Pushing AEGIS-SOC to GitHub (Muhammad9985/AEGIS-SOC)
echo ========================================================
echo.
git push -u origin main
echo.
if %ERRORLEVEL% EQU 0 (
    echo [SUCCESS] Repository pushed to https://github.com/Muhammad9985/AEGIS-SOC
) else (
    echo [NOTE] If repository does not exist on GitHub yet:
    echo 1. Go to https://github.com/new
    echo 2. Repository name: AEGIS-SOC
    echo 3. Keep it Public and DO NOT initialize with README/license (already created)
    echo 4. Click 'Create repository'
    echo 5. Run this script again!
)
pause
