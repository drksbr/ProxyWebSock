@echo off
setlocal ENABLEEXTENSIONS

rem Resolve repo root from this script's location
for %%I in ("%~dp0..") do set "REPO_ROOT=%%~fI"
set "BINDIR=%REPO_ROOT%\bin"
set "BINARY=%BINDIR%\intratun-windows-amd64.exe"

if not exist "%BINARY%" (
  echo Binary not found at "%BINARY%".
  echo Build it first with: make release
  exit /b 1
)

"%BINARY%" agent --relay=wss://relay.neurocirurgiahgrs.com.br/tunnel --id=agente01 --token=troque-esta-senha --dial-timeout-ms=30000 --max-frame=8192 --read-buf=16384 --write-buf=16384 --log-level=error

endlocal
