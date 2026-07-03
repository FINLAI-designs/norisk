@echo off
REM ===================================================================
REM  NoRisk Clean-Room-Launcher  (E2E-Rollout-Test, 2026-06-16)
REM  Startet die GEBAUTE norisk.exe als "Kunde bei Null":
REM    - FINLAI_HOME -> frischer Temp-Ordner  => ignoriert die echte
REM      ~/.finlai (Owner-Dev-Lizenz, license.json, users.json, DB)
REM    - FINLAI_DEV geleert                    => kein Dev-Bypass
REM    - Warnung, falls license.json neben der EXE liegt (Frozen-Migration)
REM  Kein PowerShell (umgeht den Bitdefender-ATD-Start-Quirk).
REM  Platzierung: im norisk-Repo-Root; %~dp0 zeigt auf dist\norisk\.
REM ===================================================================
setlocal
set "FINLAI_HOME=%TEMP%\norisk_cleanroom_%RANDOM%%RANDOM%"
set "FINLAI_DEV="
mkdir "%FINLAI_HOME%" 2>nul

echo [clean-room] FINLAI_HOME=%FINLAI_HOME%
echo [clean-room] FINLAI_DEV=(leer)

if exist "%~dp0dist\norisk\license.json" (
  echo [WARN] license.json liegt neben der EXE - Frozen-Migration koennte greifen!
)
if not exist "%~dp0dist\norisk\norisk.exe" (
  echo [FEHLER] dist\norisk\norisk.exe nicht gefunden. Erst bauen.
  endlocal & exit /b 1
)

echo [clean-room] Starte norisk.exe (isoliert) ...
start "" "%~dp0dist\norisk\norisk.exe"
endlocal
