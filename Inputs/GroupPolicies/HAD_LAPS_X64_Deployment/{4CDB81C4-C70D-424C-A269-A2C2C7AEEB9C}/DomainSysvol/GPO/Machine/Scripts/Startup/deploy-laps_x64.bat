@Echo off
IF EXIST "C:\Program Files\LAPS\CSE\AdmPwd.dll" EXIT
IF NOT EXIST "C:\_adm" mkdir C:\_adm

copy %~dp0LAPS.x64.msi c:\_adm\LAPS.x64.msi
MSIEXEC /QN /I c:\_adm\LAPS.x64.msi
Exit