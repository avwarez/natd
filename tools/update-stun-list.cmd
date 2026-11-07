@echo off
rem SPDX-License-Identifier: GPL-2.0-or-later
rem Copyright (C) 2026 avwarez
rem Refreshes the STUN server list used by natd_probe (--stun-list).
rem   tools\update-stun-list.cmd [dir-with-natd_stunlist.exe] [output-file]
rem Downloads a public list checked hourly (curl.exe ships with Windows 10 1803+),
rem then keeps only the servers that answer correctly from here. On failure the
rem previous list is left untouched.
setlocal
set BIN=%~1
if "%BIN%"=="" set BIN=%~dp0..
set OUT=%~2
if "%OUT%"=="" set OUT=stun-servers.txt
if "%NATD_STUN_LIST_URL%"=="" set NATD_STUN_LIST_URL=https://raw.githubusercontent.com/pradt2/always-online-stun/master/valid_hosts.txt
set RAW=%TEMP%\natd-stun-raw-%RANDOM%.txt
curl.exe -fsSL --max-time 30 "%NATD_STUN_LIST_URL%" -o "%RAW%" || (echo download failed & exit /b 1)
"%BIN%\natd_stunlist.exe" --in "%RAW%" --out "%OUT%" --keep 24 --min 10
set RC=%ERRORLEVEL%
del "%RAW%" 2>nul
exit /b %RC%
