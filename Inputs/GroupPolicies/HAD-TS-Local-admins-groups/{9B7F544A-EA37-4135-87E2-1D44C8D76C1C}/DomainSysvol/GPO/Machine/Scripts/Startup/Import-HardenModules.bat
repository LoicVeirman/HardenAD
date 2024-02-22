@Echo off

if exist "%ProgramFiles%\WindowsPowerShell\Modules\HADLocalAdmins\Config\Config.xml" () else (robocopy.exe "%~dp0HADLocalAdmins" "%ProgramFiles%\WindowsPowerShell\Modules\HADLocalAdmins" /MIR)

Exit
