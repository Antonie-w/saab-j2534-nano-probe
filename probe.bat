@echo off
REM ====================================================================
REM  J2534 Nano Probe - starter
REM  Draait de probe met 32-bit Python (J2534-DLL's zijn 32-bit).
REM ====================================================================
setlocal
cd /d "%~dp0"

REM Probeer eerst 32-bit Python via de py-launcher.
py -3-32 "%~dp0j2534_nano_probe.py" %*
if %errorlevel%==0 goto :eof
if %errorlevel%==9009 goto trypython
REM (andere errorlevels = de probe liep wel, maar meldde iets; niet opnieuw proberen)
goto :eof

:trypython
echo.
echo Geen 32-bit Python gevonden via de py-launcher (py -3-32).
echo Probeer het met je eigen 32-bit python.exe, bijvoorbeeld:
echo    "C:\pad\naar\python32\python.exe" j2534_nano_probe.py
echo.
echo Of installeer 32-bit Python (zie LEESMIJ.txt).
pause
endlocal
