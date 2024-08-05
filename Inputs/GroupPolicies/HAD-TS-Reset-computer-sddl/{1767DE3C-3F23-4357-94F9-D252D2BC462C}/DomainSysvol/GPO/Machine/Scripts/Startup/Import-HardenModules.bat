@Echo off

robocopy.exe "%~dp0Reset-ComputerSDDL" "%WinDir%\HardenAD\ScheduledTasks\Reset-ComputerSDDL" /MIR
robocopy.exe "%~dp0Reconcile-ComputerSDDL" "%WinDir%\HardenAD\ScheduledTasks\Reconcile-ComputerSDDL" /MIR
robocopy.exe "%~dp0Event-Viewer" "%ProgramData%\Microsoft\Event Viewer\Views\Harden AD" /MIR

Exit