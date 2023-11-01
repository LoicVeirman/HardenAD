@Echo off

robocopy.exe "%~dp0HAD_TS-PDC_Flush-admin-groups" "%windir%\HardenAD\ScheduledTasks\HAD_TS-PDC_Flush-admin-groups" /MIR

Exit