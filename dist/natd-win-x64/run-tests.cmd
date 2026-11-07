@echo off
rem SPDX-License-Identifier: GPL-2.0-or-later
rem Copyright (C) 2026 avwarez
rem natd - tests on real Windows. No administrator rights are needed:
rem all the traffic stays on loopback (127.0.0.x), which the firewall does not filter.
setlocal
cd /d "%~dp0"
set FAIL=0

echo.
echo == 1/3  Library logic (natd_tests.exe, no network)
natd_tests.exe > natd_tests.log 2>&1
if errorlevel 1 (set FAIL=1& echo    FAILED - see natd_tests.log) else (echo    OK)
findstr /c:"checks," natd_tests.log

echo.
echo == 2/3  Winsock adapter (natd_io_tests.exe, loopback)
natd_io_tests.exe > natd_io_tests.log 2>&1
if errorlevel 1 (set FAIL=1& echo    FAILED - see natd_io_tests.log) else (echo    OK)
type natd_io_tests.log

echo.
echo == 3/3  Real discovery: two reflectors on 127.0.0.2 and 127.0.0.3, probe on 127.0.0.1
taskkill /im natd_reflector.exe /f >nul 2>&1
start "" /b cmd /c "natd_reflector.exe --ip 127.0.0.2 --ports 23478-23493 --partner 127.0.0.3:23478 > reflector0.log 2>&1"
start "" /b cmd /c "natd_reflector.exe --ip 127.0.0.3 --ports 23478-23493 --partner 127.0.0.2:23478 > reflector1.log 2>&1"
ping -n 3 127.0.0.1 >nul
natd_probe.exe --bind 127.0.0.1 --reflector 127.0.0.2:23478-23493 --reflector 127.0.0.3:23478-23493 --grid 1,2 --timeout 60 > probe.log 2>&1
if errorlevel 1 (set FAIL=1& echo    FAILED - see probe.log) else (echo    OK)
rem Two instances: one taskkill each (some environments, e.g. Wine, stop one per call).
taskkill /im natd_reflector.exe /f >nul 2>&1
taskkill /im natd_reflector.exe /f >nul 2>&1
findstr /c:"final predictability" probe.log > probe_final.log
findstr /c:"predictability=Stable" probe_final.log >nul || (set FAIL=1& echo    expected predictability=Stable)
findstr /c:"behindNat=0" probe_final.log >nul || (set FAIL=1& echo    expected behindNat=0)
findstr /c:"lifetimeMeasured=1" probe_final.log >nul || (set FAIL=1& echo    expected lifetimeMeasured=1)
type probe.log

echo.
if %FAIL%==0 (echo RESULT: all tests passed) else (echo RESULT: something failed - send the .log files)
echo.
pause
exit /b %FAIL%
