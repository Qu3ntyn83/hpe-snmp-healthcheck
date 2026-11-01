@echo off
rem #Powerscripting - HPE ProLiant SNMP-Healthcheck - https://powerscripting.de
rem Doppelklick  = grafische Oberflaeche (ohne Konsolenfenster)
rem Mit Parametern = Kommandozeilenmodus, z. B.:
rem   HPE-SNMP-Healthcheck.cmd -Target 10.0.10.21 -Community public
if "%~1"=="" (
  start "" powershell.exe -NoProfile -STA -ExecutionPolicy Bypass -WindowStyle Hidden -File "%~dp0HPE-SNMP-Walk.ps1" -Gui
  exit /b 0
)
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0HPE-SNMP-Walk.ps1" %*
exit /b %ERRORLEVEL%
