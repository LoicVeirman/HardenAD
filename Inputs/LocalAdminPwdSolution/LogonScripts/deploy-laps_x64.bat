@Echo off
IF EXIST "C:\Program Files\LAPS\CSE\AdmPwd.dll" EXIT
MSIEXEC /QN /I \\%DN%\NETLOGON\LAPS\LAPS.x64.msi
exit