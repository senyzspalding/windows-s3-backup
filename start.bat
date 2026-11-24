@echo off
title CloudVault Backup
echo.
echo  ==========================================
echo    CloudVault — Encrypted Home Backup
echo  ==========================================
echo.

:: Check Python
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python is not installed or not in PATH.
    echo Download Python from https://python.org
    pause
    exit /b 1
)

:: Install dependencies
pip show boto3 >nul 2>&1
if errorlevel 1 (
    echo Installing boto3...
    pip install boto3 --quiet
)

pip show cryptography >nul 2>&1
if errorlevel 1 (
    echo Installing cryptography...
    pip install cryptography --quiet
)

pip show keyring >nul 2>&1
if errorlevel 1 (
    echo Installing keyring...
    pip install keyring --quiet
)

:: Launch
echo Starting CloudVault...
start "" python cloudvault.py
