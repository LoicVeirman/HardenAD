@Echo off

if exist "%ProgramFiles%\WindowsPowerShell\Modules\HADLocalAdmins\Configs\Config.xml" ( 

	EVENTCREATE /T INFORMATION /L APPLICATION /ID 100 /D "HADLocalAdmins already exists, no update."
	
) else (

	robocopy.exe "%~dp0HADLocalAdmins" "%ProgramFiles%\WindowsPowerShell\Modules\HADLocalAdmins" /MIR /v
	EVENTCREATE /T INFORMATION /L APPLICATION /ID 101 /D "HADLocalAdmins scripts has been copied successfuly."
)

Exit