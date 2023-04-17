@Echo off

robocopy.exe "%~dp0HADLocalAdmins" "%ProgramFiles%\WindowsPowerShell\Modules\HADLocalAdmins" /MIR

Exit