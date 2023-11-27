
@echo off
IF EXIST "C:\Program Files (x86)\LAPS\CSE\AdmPwd.dll" EXIT

MSIEXEC /QN /I \\%DN%\NETLOGON\LAPS\LAPS.x86.msi