@Echo off
IF EXIST "C:\Program Files\LAPS\CSE\AdmPwd.dll" EXIT

IF NOT EXIST %windir%\HardenAD\LAPS mkdir %windir%\HardenAD\LAPS

copy %~dp0LAPS.x86.msi %windir%\HardenAD\LAPS\LAPS.x86.msi

MSIEXEC /QN /I %windir%\HardenAD\LAPS\LAPS.x86.msi
Exit

