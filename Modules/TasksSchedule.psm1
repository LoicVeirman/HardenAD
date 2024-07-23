<#
    This module will manage tasks scheduling to maintain them.
#>
Function Set-TSLocalAdminGroups {
    <#
        .SYNOPSIS
        This function will setup the configuration.xml file from ./Inputs/GroupPolicies/HAD-TS-Local-admins-groups.

        .DESCRIPTION
        This function will setup the configuration.xml file from ./Inputs/GroupPolicies/HAD-TS-Local-admins-groups.
        The file is used by the task scheduler to dynamically manage local admin groups. It needs to be updated before the GPO is imported.

        .PARAMETER GpoBackupID
        The GPO folder name where the script is located.

        .NOTES
        Version 01.00.000
    #>
    Param(
        [Parameter(Mandatory, Position = 0)]
        [String]
        $GpoBackupID
    )

    ## Function Log Debug File
    $DbgFile = 'Debug_{0}.log' -f $MyInvocation.MyCommand
    $dbgMess = @()

    ## Start Debug Trace
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "****"
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "**** FUNCTION STARTS"
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "****"

    ## Indicates caller and options used
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Function caller..........: " + (Get-PSCallStack)[1].Command

    ## Script path
    $zeScript = ".\Inputs\GroupPolicies\HAD-TS-Local-admins-groups\$GpoBackupID\DomainSysvol\GPO\Machine\Scripts\Startup\Set-LocalAdminGroups\Set-LocalAdminGroups.ps1"

    ## Report parameters to log
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Parameter GpoBackupID....: $($GpoBackupID)"
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Parameter zeScript.......: $($zeScript)"

    ## Check if the script file is present
    $isPresent = Test-Path $zeScript

    ## If the script is present, then we can call it to generate the dynamic configuration file.
    if ($isPresent) {
        try {
            $void = & $zeScript -UpdateConfig -xmlSourcePath .\Configs\TasksSequence_HardenAD.xml
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---- --- The script has be run. The file is now generated."
            $Result = 0
        }
        Catch {
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---- !!! Error: failed to generate the dynamic configuration file!"
            $Result = 2
        }
    }
    Else {
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---- !!! Error: the script Set-LocalAdminGroups.ps1 is not present!"
        $Result = 2
    }
    ## Exit
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> function return RESULT: $Result"
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "=== | INIT  ROTATIVE  LOG "
    if (Test-Path .\Logs\Debug\$DbgFile) {
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Rotate log file......: 1000 last entries kept" 
        if (((Get-WMIObject win32_operatingsystem).name -notlike "*2008*")) {
            $Backup = Get-Content .\Logs\Debug\$DbgFile -Tail 1000 
            $Backup | Out-File .\Logs\Debug\$DbgFile -Force
        }
    }
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "=== | STOP  ROTATIVE  LOG "
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ****")
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T **** FUNCTION ENDS")
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ****")
    $DbgMess | Out-File .\Logs\Debug\$DbgFile -Append

    return (New-Object -TypeName psobject -Property @{ResultCode = $result ; ResultMesg = $ResMess ; TaskExeLog = $ResMess })
}