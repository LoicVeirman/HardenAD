<# 
    .SYNOPSIS
    Set SDDL on Microsoft-Windows-PowerShell/Operational/

    .DESCRIPTION
    PowerShell information stored in the eventviewer are required to proceed with forensic analysis (security or stability). As the contained data are sensible, the default ACLs must be hardened.
    This script remove the ability from Everyone to read the event log.

    .NOTES
    Version 2.0.0 by L.Veirman.
#>
Param()

## Function Log Debug File
$DbgFile = 'Debug_{0}.log' -f $MyInvocation.MyCommand
$dbgMess = @()

## Start Debug Trace
$dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "****"
$dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "**** FUNCTION STARTS"
$dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "****"

## Indicates caller and options used
$dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Function caller..........: " + (Get-PSCallStack)[1].Command

Try {
    # Microsoft-Windows-PowerShell/Operationnal log name, reg path and current SDDL for logging purpose
    $EvtLogName = 'Microsoft-Windows-PowerShell/Operational'
    $RegLogPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\winevt\Channels\$EvtLogName"
    $EvtLogSDDL = ((wevtutil gl $EvtLogName) -like 'channelAccess*').Split(' ')[1]
    
    # Pushing to log data for better log result analysis in case of trouble
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---- #### TARGET EVENT LOG NAME: $($EvtLogName)"
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---- #### TARGET REGISTRY PATH.: $($RegLogPath)"
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---- #### TARGET RUNNING SDDL..: $($EvtLogSDDL)"
    foreach ($dACL in (ConvertFrom-SddlString $EvtLogSDDL).DiscretionaryAcl)
    {
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---- #### .....................: $($dACL)"
    }
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "----"

    # Get SSDL from the security event log, which is protectected as we need.
    $Sddl = ((wevtutil gl security) -like 'channelAccess*').Split(' ')[1]

    # Append log for debug purpose
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---- >>>> Reading SDDL from SECURITY event log: $($sddl)"
    foreach ($dACL in (ConvertFrom-SddlString $Sddl).DiscretionaryAcl)
    {
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---- >>>> ....................................: $($dACL)"
    }
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "----"

    # Push SDDL to the Microsoft-Windows-PowerShell/Operationnal log
    Set-ItemProperty -Path $RegLogPath -Name ChannelAccess -Value $Sddl -ErrorAction Stop

    # Log
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---- ++++ Success: SDDL pushed without error to $($RegLogPath)"
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "----"

    # Control result
    $EvtLogSDDL = ((wevtutil gl $EvtLogName) -like 'channelAccess*').Split(' ')[1]
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---- <<<< TARGET NEW RUNNING SDDL..: $($EvtLogSDDL)"
    foreach ($dACL in (ConvertFrom-SddlString $EvtLogSDDL).DiscretionaryAcl)
    {
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---- <<<< .........................: $($dACL)"
    }
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "----"

    if ($EvtLogSDDL -eq $Sddl) 
    {
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---- ---> Success: control find expected SDDL on $($EvtLogName)"
        $result = 0
        $ResMess = "Success"
    }
    Else 
    {
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---- !!!! Control failed. SDDL are not as expected."
        $result = 2
        $ResMess = "SDDL mismatch on check!"
    }
}
Catch {
    # Manage error.
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "!!!! FATAL ERROR: The script break before processing all commands!"
    $result = 2
    $ResMess = $_.ToString()
}

## Exit log to file
if (-not(test-path "$($env:ProgramData)\HardenAD\Logs\"))
{
	[void](New-Item -Name "Logs" -ItemType Directory -Path "$($env:ProgramData)\HardenAD" -force)
}
$dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Script return RESULT.: $($Result)"
$dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Script return MESSAGE: $($ResMess)"
$dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "=== | INIT  ROTATIVE  LOG "
if (Test-Path "$($env:ProgramData)\HardenAD\Logs\$DbgFile") 
{
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Rotate log file......: 1000 last entries kept" 
    $Backup = Get-Content "$($env:ProgramData)\HardenAD\Logs\$DbgFile" -Tail 1000 
    $Backup | Out-File "$($env:ProgramData)\HardenAD\Logs\$DbgFile" -Force
}
$dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "=== | STOP  ROTATIVE  LOG "
$dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ****")
$dbgMess += (Get-Date -UFormat "%Y-%m-%d %T **** FUNCTION ENDS")
$dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ****")
$DbgMess | Out-File "$($env:ProgramData)\HardenAD\Logs\$DbgFile" -Append

# return result to caller
exit $result