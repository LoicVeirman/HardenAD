# Default behavior when an error is met.
# Can be overwritten in function by using -ErrorAction.
$ErrorActionPreference = 'Stop'

#region Set-NetLogonContent
Function Set-NetLogonContent
{
    <#
        .SYNOPSIS
        Copy the content of ./Inputs/NetLogon to /windir/sysvol/domain/policy/scripts/HardenAD.

        .DESCRIPTION
        Allow to update netlogon with necessary scripts or files that can be then called back by a GPO with no need of reboot (startup script)

        .NOTES
        Version 01.00.000 -- Script creation
    #>
    Param()

    Try {
        ## Function Log Debug File
        $DbgFile = 'Debug_{0}.log' -f $MyInvocation.MyCommand
        $dbgMess = @()

        ## Start Debug Trace
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "****"
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "**** FUNCTION STARTS"
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "****"

        ## Indicates caller and options used
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Function caller..........: " + (Get-PSCallStack)[1].Command

        ## retrieving NetLogon local path
        $NetLogonPath = (Get-SmbShare NetLogon -ErrorAction Stop).Path 
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> NetLong Local Path.......: $($NetLogonPath)"

        ## Check if folder exists
        if (Test-Path "$($NetLogonPath)\HardenAD") 
        {
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Folder HardenAD exists in $($NetLogonPath)"
        }
        Else 
        {
            New-Item -Name HardenAD -ItemType Directory -Path $NetLogonPath
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---+ Folder HardenAD created in $($NetLogonPath)"
        }

        ## Copying files / folders
        foreach ($item in (Get-ChildItem .\Inputs\NetLogon)) 
        {
            Copy-Item -LiteralPath $item.FullName -Destination "$($NetLogonPath)\HardenAD" -Recurse -ErrorAction Stop -Force
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---+ Item $item copied to $netLogonPath"
        }

        ## Exit 
        $result = 0
        $resMess = "Success"
    }
    Catch {
        $result = 2
        $resMess = $_.ToString()
    }

    # Exit log to file
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> function return RESULT: $Result"
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> function return RESULT: $ResMess"
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "=== | INIT  ROTATIVE  LOG "
    if (Test-Path .\Logs\Debug\$DbgFile) 
    {
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Rotate log file......: 1000 last entries kept" 
        $Backup = Get-Content .\Logs\Debug\$DbgFile -Tail 1000 
        $Backup | Out-File .\Logs\Debug\$DbgFile -Force
    }
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "=== | STOP  ROTATIVE  LOG "
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ****")
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T **** FUNCTION ENDS")
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ****")
    $DbgMess | Out-File .\Logs\Debug\$DbgFile -Append

    # return
    return (New-Object -TypeName psobject -Property @{ResultCode = $result ; ResultMesg = $ResMess ; TaskExeLog = $ResMess })
}
#endregion