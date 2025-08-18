@Echo off

robocopy.exe "%~dp0HADBitlocker" "%ProgramFiles%\WindowsPowerShell\Modules\HADBitlocker" /MIR

Exit