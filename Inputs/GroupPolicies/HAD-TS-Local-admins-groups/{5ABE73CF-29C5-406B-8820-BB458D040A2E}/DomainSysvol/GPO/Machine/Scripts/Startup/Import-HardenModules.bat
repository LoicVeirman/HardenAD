@Echo off

robocopy.exe "%~dp0Set-LocalAdminGroups" "%winDir%\HardenAD\ScheduledTasks\Set-LocalAdminGroups" /MIR
robocopy.exe "%~dp0Event-Viewer" "%ProgramData%\Microsoft\Event Viewer\Views\Harden AD" /MIR

Exit