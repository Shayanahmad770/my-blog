@echo off
title Blog Backup Tool
echo ========================================
echo    NEXTECHDAILY BLOG BACKUP
echo ========================================
echo.

:: Get current date for filename
set year=%DATE:~-4%
set month=%DATE:~-10,2%
set day=%DATE:~-7,2%
set filename=blog-backup-%year%-%month%-%day%

:: Create backup
echo 📦 Backing up database...
copy database\blog.db database\backups\%filename%.db > nul

:: Check if backup was successful
if exist database\backups\%filename%.db (
    echo ✅ SUCCESS! Backup created: %filename%.db
    echo 📁 Location: database\backups\%filename%.db
    
    :: Show backup size
    echo 📊 Size: %~z0 bytes
) else (
    echo ❌ ERROR: Backup failed!
)

echo.
echo ========================================
echo Backups in folder:
dir database\backups\*.db /b

echo.
echo ========================================
echo Press any key to exit...
pause > nul