@echo off
title Blog Restore Tool
echo ========================================
echo    NEXTECHDAILY BLOG RESTORE
echo ========================================
echo.
echo 📁 Available backups:
echo.

:: List all backups with numbers
setlocal enabledelayedexpansion
set count=0
for %%f in (database\backups\*.db) do (
    set /a count+=1
    echo [!count!] %%~nxf
    set "file!count!=%%f"
)

echo.
if %count%==0 (
    echo ❌ No backups found!
    pause
    exit /b
)

:: Ask user which backup to restore
set /p choice="Enter backup number to restore (or 0 to cancel): "

if "%choice%"=="0" (
    echo Restore cancelled.
    pause
    exit /b
)

:: Get selected file
set "selected=!file%choice%!"

:: Confirm restore
echo.
echo ⚠️ WARNING: This will replace your current database!
echo Current database: database\blog.db
echo Will restore from: %selected%
echo.
set /p confirm="Are you sure? (y/n): "

if /i "%confirm%"=="y" (
    :: Create emergency backup first
    copy database\blog.db database\backups\pre-restore-backup-%DATE:~-4%-%DATE:~-10,2%-%DATE:~-7,2%.db > nul
    echo ✅ Created pre-restore backup
    
    :: Restore selected backup
    copy "%selected%" database\blog.db > nul
    echo ✅ Database restored from %selected%
) else (
    echo Restore cancelled.
)

echo.
pause