#region Set-GpoCentralStore
Function Set-GpoCentralStore {
    <#
        .Synopsis
        Enable the Centralized GPO repository (aka Central Store), or ensure it is so.
        
        .Description
        Will perform a query to ensure that the GPO Central Store is enable. If not, it will do so if requested.
        Return 0 if the states is as expected, else return 2.
        
        .Notes
        Version:    01.00 -- contact@hardenad.net 
                    01.01 -- contact@hardenad.net 
                    01.02 -- contact@hardenad.net
        
        history:    19.08.31 Script creation
                    21.06.06 Removed parameter DesiredState
                    24.04.18 Added bugFix for error https://learn.microsoft.com/en-us/troubleshoot/windows-server/group-policy/winstoreui-conflict-with-windows-10-1151-admx-file
    #>
    param(
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
    
    ## Getting existing Sysvol base path
    if (((Get-WMIObject win32_operatingsystem).name -like "*2008*")) {
        Import-Module ActiveDirectory
        $sysVolBasePath = ((net share | Where-Object { $_ -like "SYSVOL*" }) -split " " | Where-Object { $_ -ne "" })[1]
    }
    else {
        $sysVolBasePath = (Get-SmbShare SYSVOL).path
    }

    # Getting domain name
    $domName = (Get-AdDomain).DNSRoot

    # Testing if the path is as expected (i.e. centralStore)
    if (Test-Path "$sysVolBasePath\$domName\Policies\PolicyDefinitions") {
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Central Store path is present"
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Central Store path is already enabled"
        $result = 0
    }
    else {
        # We need to enable the central store
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Central Store path is not enable yet"
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Robocopy C:\Windows\PolicyDefinitions $sysVolBasePath\$domName\Policies\PolicyDefinitions /MIR (start)"

        $NoEchoe = Robocopy "C:\Windows\PolicyDefinitions" "$sysVolBasePath\$domName\Policies\PolicyDefinitions" /MIR
            
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Robocopy C:\Windows\PolicyDefinitions $sysVolBasePath\$domName\Policies\PolicyDefinitions /MIR (finish)"

        # Test if copies sounds good.
        $SourceItemsCount = (Get-ChildItem "C:\Windows\PolicyDefinitions" -File -Recurse).count
        $TargetItemsCount = (Get-ChildItem "$sysVolBasePath\$domName\Policies\PolicyDefinitions" -File -Recurse).count
        
        if ($TargetItemsCount -eq $SourceItemsCount) {
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> file copy as worked as expected ($TargetItemsCount files found in the CentralStore - same as the source repository)."
            $result = 0
        }
        else {
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---! Error while copying file: found $TargetITemsCount files in the centralStore but there is $SourceItemsCount files in c:\Windows\PolicyDefinitions."
            $ResMess = "Error while copying files to new location (warning)"
            $result = 1
        }
    }

    # Upgrading existing CentralStore to the latest version.
    $HardenPolicyDefinition = Get-Item .\Inputs\PolicyDefinitions
    $GPOCentralStore = "$sysVolBasePath\$domName\Policies"

    if (Test-Path $GPOCentralStore) {
        # Rename the current repository
        $UniqueId = (Get-Date -Format yyyy-MM-yy_HHmmss)
        try {
            Rename-Item "$GPOCentralStore\PolicyDefinitions" "$GPOCentralStore\PolicyDefinitions-$UniqueId" -ErrorAction SilentlyContinue
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> PolicyDefinitions has been renamed to PolicyDefinitions-$UniqueID"
            $result = 0
        }
        catch {
            $global:err = "Error in Renaming the current repository."
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---! Error while renaming PolicyDefinitions folder."
            $ResMess = "Error while renaming PolicyDefinition to PolicyDefinitions-$UniqueId"
            $result = 1
        }
        
        # Update the central with the latest repository release
        if ($result -eq 0) {
            try {
                Copy-Item $HardenPolicyDefinition.FullName -Destination "$sysVolBasePath\$domName\Policies" -Recurse -Force -ErrorAction SilentlyContinue
                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> PolicyDefinitions has been copied to $sysVolBasePath\$domName\Policies"
                $result = 0
            }
            catch {
                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---! Error while copying $($HardenPolicyDefinition.Name)."
                $ResMess = "Error while copying PolicyDefinitions to $sysVolBasePath\$domName\Policies"
                $result = 2
            }
        }

        # Add to the CentralStore any admx/adml file missing from the previous one (existing will not be overwriten).
        # Robocopy options: /E to recurse subdirs, inclunding empty ones, /XC to exclude overwriting file with a different size, XN to exclude overwriting file newer than the repo, XO to exclude overwrting file older than the repo.
        $NoEchoe = Robocopy "$GPOCentralStore\PolicyDefinitions-$UniqueId" "$GPOCentralStore\PolicyDefinitions" /E /XC /XN /XO

        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> PolicyDefinitions has been updated from any directory/files missing from PolicyDefinition-$UniqueID"
    }
    ## Fix for https://learn.microsoft.com/en-us/troubleshoot/windows-server/group-policy/winstoreui-conflict-with-windows-10-1151-admx-file
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> ### BUGFIX: winstoreui error message in GPMC"

    Try {
        $bugFix = Get-ChildItem $GPOCentralStore\PolicyDefinitions -File -Filter "winstoreui.adm?" -Recurse
        $bugFix | Remove-Item -Force -Confirm:$false -ErrorAction Stop
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Found $($bugFix.count) winstoreui.admx/l file(s) and removed them successfully from the central store"
    }
    Catch {
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---! Found $($bugFix.count) winstoreui.admx/l file(s) to remove from central store but failed to delete them!"
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
#endregion

#region New-ScheduleTasks
Function New-ScheduleTasks {
    <#
        .Synopsis
        Add Schedule Tasks as defined in TasksSequence_HardenAD.xml.
        
        .Description
        The tasks schedule are defined in the TasksSequence_HardenAD.xml and created (if not present) on the running system.
        The tasks files will be positionned in the directory path specified in <TaskSchedules>.BaseDir.
        The tasks will be generated from a xml backup file which contains all static data. Only the command (%command%), the attributes (%attributes%) and the description (%description%) 
        will be replaced by the config file content.
    
        .Notes
        Version: 01.00 -- contact@hardenad.net 
        history: 2021.08.05 Script creation
    #>
    param(
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
    
    ## Check if OS is compliant
    if ((Get-WMIObject win32_operatingsystem).name -like "*2008*") {
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> OS is compliant..........: NO - Windows 2008/R2 detected."
        $result = 2
        $ResMess = "2008 or 2008 R2: not compliant."
    }
    else {
        $result = 0
    }

    ## Get xml data
    Try {
        $cfgXml = [xml](Get-Content .\Configs\TasksSequence_HardenAD.xml -Encoding utf8)
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Load xml.................: .\Configs\TasksSequence_HardenAD.xml (success)"
    }
    Catch {
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Load xml.................: .\Configs\TasksSequence_HardenAD.xml (failed)" 
        $result = 2
        $ResMess = "Failed to load configuration file"
    }

    if ($result -ne 2) {
        $SchXml = $cfgXml.settings.TaskSchedules
    
        ## Get tasks base dir
        $SchDir = $SchXml.BaseDir

        ## Check if the directory exists, else create it
        if (-not(Test-Path $SchDir)) {
            try {
                $null = New-Item -Path $SchDir -ItemType Directory
                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> New dir....: $SchDir (success)" 
            }
            Catch {
                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> New dir....: $SchDir (Failed!)" 
                $result = 2
                $ResMess = "Failed to create the Schedule tasks base directory"
            }
        }

        ## This section will be executed only if the base directory exists.
        if ($result -ne 2) {
            ## Import data from repo
            Robocopy.exe .\Inputs\ScheduleTasks\TasksSchedulesScripts $SchDir /MIR | Out-Null
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> Repository (.\Inputs\ScheduleTasks\TasksSchedulesScripts) copied to $SchDir"

            ## Collect existing schedules
            $CurSchTasks = Get-ScheduledTask -TaskName *
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> Existing scheduled tasks recovered from system"

            ## Parsing tasks and adding if needed
            foreach ($task in $SchXml.SchedTask) {
                $TaskName = $task.Name
                $TaskBack = $task.xml
                $TaskDesc = $task.SchedDsc
                $TaskPath = $task.SchedPth
                $command = $task.SchedCmd
                $Parameters = $task.SchedArg
                $Directory = $task.SchedDir -replace '%BaseDir%', $SchDir

                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> Schedule tasks data: Name.......=$TaskName"
                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> Schedule tasks data: Backup.....=$TaskBack"
                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> Schedule tasks data: Description=$TaskDesc"
                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> Schedule tasks data: Path.......=$TaskPath"
                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> Schedule tasks data: Command....=$command"
                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> Schedule tasks data: Parameters.=$Parameters"
                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> Schedule tasks data: Directory..=$Directory"

                ## rewriting xml backup file with specific values
                $rawXml = Get-Content .\Inputs\ScheduleTasks\TasksSchedulesXml\$TaskBack
                $rawXml = $rawXml -replace '%description%', $TaskDesc
                $rawXml = $rawXml -replace '%command%', $command
                $rawXml = $rawXml -replace '%arguments%', $Parameters
                $rawXml = $rawXml -replace '%basePath%', $Directory
                $rawXml | Out-File .\Inputs\ScheduleTasks\TasksSchedulesXml\_$TaskBack -Encoding unicode -Force

                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> Xml rewrited with customized value in .\Inputs\ScheduleTasks\TasksSchedulesXml\_$TaskBack"

                ## Check if the tasks already exists
                if ($CurSchTasks.TaskName -match $TaskName) {
                    $FlagExists = $true
                }
                else {
                    $FlagExists = $false
                }
                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> Schedule tasks already exists: $FlagExists"

                ## Importing schedule
                Try {
                    if (-not($FlagExists)) {
                        $install = Register-ScheduledTask -TaskPath $TaskPath -TaskName $TaskName -Xml (Get-Content .\Inputs\ScheduleTasks\TasksSchedulesXml\_$TaskBack | Out-String) -Force
                    }
                    else {
                        $install = @{State = "Ready" }
                    }

                    if ($install.State -eq "Ready") { 
                        $result = 0 
                    }
                    else { 
                        $result = 1
                        $ResMess += "(failed to import: $TaskName)"
                    }
                    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> Task Creation result: $install"
                }
                Catch {
                    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> Task Creation failed: probably because it already exists."
                    $result = 1
                    $ResMess += "(failed to import: $TaskName)"
                }  
            }
        }
    }
    ## return a warning if 2k8
    if ($ResMess -eq "2008 or 2008 R2: not compliant.") {
        $result = 1
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
#endregion

#region Set-TSlocalAdminGroups
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
#endregion