##################################################################
## Set-GpoCentralStore                                          ##
## -------------------                                          ##
## This function will set the GPO store within the SYSVOL share ##
##                                                              ##
## Version: 01.00.000                                           ##
##  Author: contact@hardenad.net                                ##
##################################################################
Function Set-GpoCentralStore {
    <#
        .Synopsis
         Enable the Centralized GPO repository (aka Central Store), or ensure it is so.
        
        .Description
         Will perform a query to ensure that the GPO Central Store is enable. If not, it will do so if requested.
         Return 0 if the states is as expected, else return 2.
        
        .Notes
         Version: 01.00 -- contact@hardenad.net 
                  01.01 -- contact@hardenad.net 
         
         history: 19.08.31 Script creation
                  21.06.06 Removed parameter DesiredState
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
    
    ## Test if already enabled
    if (((Get-WMIObject win32_operatingsystem).name -like "*2008*")) {
        Import-Module ActiveDirectory
        $sysVolBasePath = ((net share | Where-Object { $_ -like "SYSVOL*" }) -split " " | Where-Object { $_ -ne "" })[1]
    }
    else {
        $sysVolBasePath = (Get-SmbShare SYSVOL).path
    }

    $domName = (Get-AdDomain).DNSRoot

    if (Test-Path "$sysVolBasePath\$domName\Policies\PolicyDefinitions") {
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Central Store path is present"
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Central Store path is already enabled"
        $result = 0
    }
    else {
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Central Store path is not enable yet"
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Robocopy C:\Windows\PolicyDefinitions $sysVolBasePath\$domName\Policies\PolicyDefinitions /MIR (start)"

        $NoEchoe = Robocopy "C:\Windows\PolicyDefinitions" "$sysVolBasePath\$domName\Policies\PolicyDefinitions" /MIR
            
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Robocopy C:\Windows\PolicyDefinitions $sysVolBasePath\$domName\Policies\PolicyDefinitions /MIR (finish)"
        if ((Get-ChildItem "$sysVolBasePath\$domName\Policies\PolicyDefinitions" -Recurse).count -gt 10) {
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Seems copying has worked."
            $result = 0
        }
        else {
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---! Error while copying file."
            $ResMess = "Error while copying file to new location"
            $result = 2
        }
    }

    ## Installation of custom or external ADMX/ADML
    $ADMXFiles = Get-ChildItem $PSScriptRoot\..\Inputs\PolicyDefinitions -File
    $ADMLFiles_US = Get-ChildItem $PSScriptRoot\..\Inputs\PolicyDefinitions\en-US -File
    $ADMLFiles_FR = Get-ChildItem $PSScriptRoot\..\Inputs\PolicyDefinitions\fr-FR -File
    $GPOCentralStore = "$sysVolBasePath\$domName\Policies\PolicyDefinitions"

    if (Test-Path $GPOCentralStore) {
        foreach ($ADMXFile in $ADMXFiles) {
            try {
                Copy-Item $ADMXFile.FullName -Destination $GPOCentralStore -Force
                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> $($ADMXFile.Name) has been copied to central store"
                $result = 0
            }
            catch {
                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---! Error while copying $($ADMXFile.Name)."
                $ResMess = "Error while copying $($ADMXFile.Name) to new location"
                $result = 2
            }
        }
        foreach ($ADMLFile in $ADMLFiles_US) {
            try {
                Copy-Item $ADMLFile.FullName -Destination "$GPOCentralStore\en-US" -Force
                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> $($ADMLFile.Name) has been copied to central store"
                $result = 0
            }
            catch {
                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---! Error while copying $($ADMLFile.Name)."
                $ResMess = "Error while copying $($ADMLFile.Name) to new location"
                $result = 2
            }
        }
        
        if (!(Test-Path "$GPOCentralStore\fr-FR")) {
            try {
                $null = New-Item -Path "$GPOCentralStore\fr-FR" -ItemType Directory
                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> New directory : $GPOCentralStore\fr-FR (success)" 
            }
            Catch {
                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> New directory : $GPOCentralStore\fr-FR (Failed!)" 
                $result = 2
            }
        }
        
        foreach ($ADMLFile in $ADMLFiles_FR) {
            try {
                Copy-Item $ADMLFile.FullName -Destination "$GPOCentralStore\fr-FR" -Force
                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> $($ADMLFile.Name) has been copied to central store"
                $result = 0
            }
            catch {
                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---! Error while copying $($ADMLFile.Name)."
                $ResMess = "Error while copying $($ADMLFile.Name) to new location"
                $result = 2
            }
        }  
    }

    ## Exit
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> function return RESULT: $Result"
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "===| INIT  ROTATIVE  LOG "
    if (Test-Path .\Logs\Debug\$DbgFile) {
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Rotate log file......: 1000 last entries kept" 
        if (((Get-WMIObject win32_operatingsystem).name -notlike "*2008*")) {
            $Backup = Get-Content .\Logs\Debug\$DbgFile -Tail 1000 
            $Backup | Out-File .\Logs\Debug\$DbgFile -Force
        }
    }
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "===| STOP  ROTATIVE  LOG "
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ****")
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T **** FUNCTION ENDS")
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ****")
    $DbgMess | Out-File .\Logs\Debug\$DbgFile -Append

    return (New-Object -TypeName psobject -Property @{ResultCode = $result ; ResultMesg = $ResMess ; TaskExeLog = $ResMess })
}

##################################################################
## New-ScheduleTasks                                            ##
## -----------------                                            ##
## This function will add a new schedule tasks from config file ##
##                                                              ##
## Version: 01.00.000                                           ##
##  Author: contact@hardenad.net                                ##
##################################################################
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
         
         history: 21.08.05 Script creation
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
        $cfgXml = [xml](Get-Content .\Configs\TasksSequence_HardenAD.xml)
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
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "===| INIT  ROTATIVE  LOG "
    if (Test-Path .\Logs\Debug\$DbgFile) {
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Rotate log file......: 1000 last entries kept" 
        if (((Get-WMIObject win32_operatingsystem).name -notlike "*2008*")) {
            $Backup = Get-Content .\Logs\Debug\$DbgFile -Tail 1000 
            $Backup | Out-File .\Logs\Debug\$DbgFile -Force
        }
    }
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "===| STOP  ROTATIVE  LOG "
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ****")
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T **** FUNCTION ENDS")
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ****")
    $DbgMess | Out-File .\Logs\Debug\$DbgFile -Append

    return (New-Object -TypeName psobject -Property @{ResultCode = $result ; ResultMesg = $ResMess ; TaskExeLog = $ResMess })
}
##################################################################
## Set-LapsScripts                                              ##
## ---------------                                              ##
## This function will update scripts deployment used by LAPS.   ##
##                                                              ##
## Version: 01.01.000                                           ##
##  Author: contact@hardenad.net                                ##
##################################################################
Function Set-LapsScripts {
    <#
        .Synopsis
         The deployment script needs to be update to fetch with the running domain.
        
        .Description
         The deployment script needs to be update to fetch with the running domain. 
         The script will be overwritten and replace %DN% by the domain FQDN.

        .Notes
         Version: 01.00 -- contact@hardenad.net 
         Version: 01.01 -- contact@hardenad.net 
         
         history: 21.08.06 Script creation
                  21.11.21 Added admx/adml file to CentralStore repo
    #>
    param(
        [Parameter(mandatory = $true, Position = 0)]
        [String]
        $ScriptDir
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
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Parameter ScriptDir......: $ScriptDir"
    $result = 0

    ## When dealing with 2008R2, we need to import AD module first
    if ((Get-WMIObject win32_operatingsystem).name -like "*2008*") {
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> is windows 2008/R2.......: True"
        
        Try { 
            Import-Module ActiveDirectory
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> OS is 2008/R2, added AD module."    
        } 
        Catch {
            $noError = $false
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---! ERROR! OS is 2008/R2, but the script could not add AD module." 
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> variable noError.........: $noError"
        }
        
    }
    else {

        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> is windows 2008/R2.......: False"
    }


    ## Get script local position
    Switch -Regex ($ScriptDir) {
        #.NETLOGON
        "NETLOGON" {
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> The target location path refers to..: NETLOGON"
            if (((Get-WMIObject win32_operatingsystem).name -like "*2008*")) {
                $NetLogonD = (Get-WmiObject -Class Win32_Share -Filter "Name='NETLOGON'").Path
            }
            else {
                $NetLogonD = (Get-SmbShare -Name NetLogon).Path
            }
            $ScriptDir = $ScriptDir -replace "NETLOGON", $NetLogonD 
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> the script files will be located to.: $ScriptDir"
        }
        #.SYSVOL
        "SYSVOL" {
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> The target location path refers to..: SYSVOL"
            if (((Get-WMIObject win32_operatingsystem).name -like "*2008*")) {
                $sysVolD = (Get-WmiObject -Class Win32_Share -Filter "Name='SYSVOL'").Path
            }
            else {
                $SysVolD = (Get-SmbShare -Name SYSVOL).Path
            }
            $ScriptDir = $ScriptDir -replace "SYSVOL", $SysVolD 
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> the script files will be located to.: $ScriptDir"
        }
        #.UNC Path
        Default {
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> The target location path refers to..: UNC PATH"
            $ScriptDir = $ScriptDir -replace "RootDN", (Get-ADDomain).DistinguishedName
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> the script files will be located to.: $ScriptDir"
        }
    }

    ## Create repository directory if needed
    if (-not(Test-Path $ScriptDir)) {
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> The target location path exists.....: False"
        Try {
            New-Item -Path $ScriptDir -ItemType Directory | Out-Null
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> The target location path exists.....: created successfully"
        }
        Catch {
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> The target location path exists.....: Error! could not create the directory target!"
            $result = 2
            $ResMess = "Error! could not create the directory target!"
        }
    }
    Else {
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> The target location path exists.....: True"
    }

    ## Duplicate file to the target destination
    if ($result -ne 2) {
        Robocopy.exe .\Inputs\LocalAdminPwdSolution\Binaries $ScriptDir /IS | Out-Null
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> binary files copied"
        Robocopy.exe .\Inputs\LocalAdminPwdSolution\LogonScripts $ScriptDir /IS | Out-Null
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> script files copied"
    }

    ## Rewriting script file
    foreach ($file in (Get-ChildItem -Path $ScriptDir | Where-Object { $_.Name -like "*.bat" })) {
        $newFile = @()
        Try {
            (Get-Content $file.fullName) -Replace '%DN%', (Get-ADDomain).DnsRoot | Set-Content $File.FullName 
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> rewritten file " + $file.Name + " (success)"
        }
        Catch {
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> rewritten file " + $file.Name + " (failed!)"
            $result = 1
            $ResMess += "(Failed to rewrite the file " + $file.name + ")"
        }
    }

    ## Deploying ADML and ADMX files to the Central Repository Store
    if ($result -eq 0) {
        if (((Get-WMIObject win32_operatingsystem).name -like "*2008*")) {
            Import-Module ActiveDirectory
            $sysVolBasePath = ((net share | ? { $_ -like "SYSVOL*" }) -split " " | ? { $_ -ne "" })[1]
        }
        else {
            $sysVolBasePath = (Get-SmbShare SYSVOL).path
        }

        $domName = (Get-AdDomain).DNSRoot
        
        Robocopy.exe .\Inputs\LocalAdminPwdSolution\PolicyDefinitions $sysVolBasePath\$domName\Policies\PolicyDefinitions /s | Out-Null
        
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> PolicyDefinitions files copied."
    }
    else {
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "ERR ---> PolicyDefinitions files not copied due to a previous error!"
    }

    ## Exit
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> function return RESULT: $Result"
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "===| INIT  ROTATIVE  LOG "
    if (Test-Path .\Logs\Debug\$DbgFile) {
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Rotate log file......: 1000 last entries kept" 
        if (((Get-WMIObject win32_operatingsystem).name -notlike "*2008*")) {
            $Backup = Get-Content .\Logs\Debug\$DbgFile -Tail 1000 
            $Backup | Out-File .\Logs\Debug\$DbgFile -Force
        }
    }
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "===| STOP  ROTATIVE  LOG "
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ****")
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T **** FUNCTION ENDS")
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ****")
    $DbgMess | Out-File .\Logs\Debug\$DbgFile -Append

    return (New-Object -TypeName psobject -Property @{ResultCode = $result ; ResultMesg = $ResMess ; TaskExeLog = $ResMess })
}

##################################################################
## Install-Laps                                                 ##
## ------------                                                 ##
## This function will install LAPS and PShell add-on on the     ##
## local system.                                                ##
##                                                              ##
## Version: 01.00.000                                           ##
##  Author: contact@hardenad.net                                ##
##################################################################
Function Install-LAPS {
    <#
        .Synopsis
         To be deployed, LAPS need to update the AD Schema first.
        
        .Description
         The script first update the schema, then it will install the management tool.

        .Notes
         Version: 01.00 -- contact@hardenad.net 
		 Version: 01.01 -- contact@hardenad.net 
         
         history: 21.08.22 Script creation
				  16.07.22 Update to use dynamic translation - removed debug log
    #>
    param(
        [Parameter(mandatory = $true, Position = 0)]
        [ValidateSet('ForceDcIsSchemaOwner', 'IgnoreDcIsSchemaOwner')]
        [String]
        $SchemaOwnerMode
    )

    $result = 0

    ## When dealing with 2008R2, we need to import AD module first
    if ((Get-WMIObject win32_operatingsystem).name -like "*2008*") {
        Try { 
            Import-Module ActiveDirectory
        } 
        Catch {
            $noError = $false
            $result = 2
            $ResMess = "AD module not available."
        }
    }

    ## Check prerequesite: running user must be member of the Schema Admins group and running computer should be Schema Master owner.
    $CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $isSchemaAdm = Get-ADGroupMember -Recursive ((Get-ADDomain).DomainSID.value + "-518") | Where-Object { $_.SID -eq $CurrentUser.User }

    $CurrentCptr = $env:COMPUTERNAME
    $isSchemaOwn = (Get-ADForest).SchemaMaster -eq ($currentCptr + "." + (Get-ADDomain).DnsRoot)


    ## Check if a bypass has been requested for the schema master owner condition
    if ($SchemaOwnerMode -eq 'IgnoreDcIsSchameOwner') {
        $isSchemaOwn = $true
    }

    if ($isSchemaAdm -and $isSchemaOwn) {
        ## User has suffisant right, the script will then proceed.
        ## First, we need to install the pShell add-ons to be able to update the schema.
        Try {
            Start-Process -FilePath "$env:systemroot\system32\msiexec.exe" `
                -WorkingDirectory .\Inputs\LocalAdminPwdSolution\Binaries `
                -ArgumentList '/i laps.x64.msi ADDLOCAL=Management.UI,Management.PS,Management.ADMX /quiet /norestart' `
                -NoNewWindow `
                -Wait
        }
        Catch {
            $result = 2
            $ResMess = "ERROR! the command line has failed!"
        }
        
        ## If the install is a success, then let's update the schema
        if ($result -eq 0) {
            Try {
                Import-Module AdmPwd.PS -ErrorAction Stop -WarningAction Stop
                $null = Update-AdmPwdADSchema
            }
            Catch {
                $result = 1
                $ResMess = "LAPS installed but the schema extension has failed (warning: .Net 4.0 or greater requiered)"
            }
        }
        Else {
            $result = 1
            $ResMess = "The schema extension has been canceled"
        }
    }
    Else {
        $result = 2
        $ResMess = "The user is not a Schema Admins (group membership with recurse has failed)"
    }

    ## Exit
    return (New-Object -TypeName psobject -Property @{ResultCode = $result ; ResultMesg = $ResMess ; TaskExeLog = $ResMess })
}

##################################################################
## Set-LapsPermissions                                          ##
## -------------------                                          ##
## This function will configure permissions upon the domain to  ##
## allow groups to handle password secrets vault.               ##
##                                                              ##
## Version: 01.00.000                                           ##
##  Author: contact@hardenad.net                                ##
##################################################################
Function Set-LapsPermissions {
    <#
        .Synopsis
         Once deployed, the LAPS engine requires some additional permission to properly work.
        
        .Description
         The script will delegate permission upon target OU. It refers to TasksSequence_HardenAD.xml.

        .Notes
         Version: 01.00 -- contact@hardenad.net 
				  01.01 -- contact@hardenad.net 
				  
         history: 21.11.27 Script creation
				  22.07.16 Updated to use dynamic trnaslation. Removed log lines.
    #>
    param(
        [Parameter(mandatory = $true, Position = 0)]
        [ValidateSet('DEFAULT', 'CUSTOM')]
        [String]
        $RunMode
    )
    $result = 0

    ## When dealing with 2008R2, we need to import AD module first
    if ((Get-WMIObject win32_operatingsystem).name -like "*2008*") {
        Try { 
            Import-Module ActiveDirectory
        } 
        Catch {
            $noError = $false
            $result = 2
            $ResMess = "AD module not available."
        }
    }

    ## Check prerequesite: the ADMPWD.PS module has to be present. 
    if (-not(Get-Module -ListAvailable -Name "AdmPwd.PS")) {
        $result = 2
        $ResMess = "AdmPwd.PS module missing."
    }
    
    ## Begin permissions setup, if allowed to.
    if ($result -ne 2) {
        # - Default mode
        if ($RunMode -eq "DEFAULT") {
            #.Loading module
            Try {
                Import-Module AdmPwd.PS -ErrorAction Stop
            }
            Catch {
                $result = 2
                $ResMess = "Failed to load module AdmPwd.PS."
            }

            #.Adding permissions at the root level. This will be the only action.
            #.All permissions belong then to native object reader/writer, such as domain admins.
            if ($result -ne 2) {
                Try {
                    $rootDN = (Get-ADDomain).DistinguishedName
                    Set-AdmPwdComputerSelfPermission -OrgUnit $rootDN -ErrorAction Stop | Out-Null
                }
                Catch {
                    $result = 2
                    $ResMess = "Failed to apply Computer Self Permission on all Organizational Units."
                }
            }
        }
        # - Custom mode
        Else {
            #.Loading module
            Try {
                Import-Module AdmPwd.PS -ErrorAction Stop
            }
            Catch {
                $result = 2
                $ResMess = "Failed to load module AdmPwd.PS."
            }

            #.If no critical issue, the following loop will proceed with fine delegation
            if ($result -ne 2) {
                #.Get xml data
                Try {
                    $cfgXml = [xml](Get-Content .\Configs\TasksSequence_HardenAD.xml)
                }
                Catch {
                    $ResMess = "Failed to load configuration file"
                    $result = 2
                }
            }
            if ($result -ne 2) {
                #.Granting SelfPermission
                $Translat = $cfgXml.Settings.Translation
                $Granting = $cfgXml.Settings.LocalAdminPasswordSolution.AdmPwdSelfPermission
                foreach ($Granted in $Granting) {
                    Try {
                        $TargetOU = $Granted.Target
                        foreach ($transID in $translat.wellKnownID) {
                            $TargetOU = $TargetOU -replace $TransID.translateFrom, $TransID.translateTo
                        }
                        Set-AdmPwdComputerSelfPermission -OrgUnit $TargetOU -ErrorAction Stop | Out-Null
                    }
                    Catch {
                        $result = 1
                        $ResMess = "Failed to apply Permission on one or more OU."
                        Write-Host $_.Exception.Message
                        Write-Host $TargetOU
                        Pause
                    }
                }
                #.Getting Domain Netbios name
                $NBname = (Get-ADDomain).netBiosName

                #.Granting Password Reading Permission
                $Granting = $cfgXml.Settings.LocalAdminPasswordSolution.AdmPwdPasswordReader
                foreach ($Granted in $Granting) {
                    Try {
                        $TargetOU = $Granted.Target
                        $GrantedId = $Granted.Id
                        foreach ($transID in $translat.wellKnownID) {
                            $TargetOU = $TargetOU -replace $TransID.translateFrom, $TransID.translateTo
                            $GrantedId = $GrantedId -replace $TransID.translateFrom, $TransID.translateTo
                        }
                        Set-AdmPwdReadPasswordPermission -Identity:$TargetOU -AllowedPrincipals $GrantedId
                    }
                    Catch {
                        $result = 1
                        $ResMess = "Failed to apply Permission on one or more OU."
                    }
                }

                #.Granting Password Reset Permission
                $Granting = $cfgXml.Settings.LocalAdminPasswordSolution.AdmPwdPasswordReset
                foreach ($Granted in $Granting) {
                    Try {
                        $TargetOU = $Granted.Target
                        $GrantedId = $Granted.Id
                        foreach ($transID in $translat.wellKnownID) {
                            $TargetOU = $TargetOU -replace $TransID.translateFrom, $TransID.translateTo
                            $GrantedId = $GrantedId -replace $TransID.translateFrom, $TransID.translateTo
                        }
                        Set-AdmPwdResetPasswordPermission -Identity:$TargetOU -AllowedPrincipals $GrantedId
                    }
                    Catch {
                        $result = 1
                        $ResMess = "Failed to apply Permission on one or more OU."
                    }
                }
            }
        }
    }

    ## Exit
    return (New-Object -TypeName psobject -Property @{ResultCode = $result ; ResultMesg = $ResMess ; TaskExeLog = $ResMess })
}

##################################################################
## Get-PingCastle                                               ##
## -------------------                                          ##
## This function will download PingCastle and                   ##
## execute an audit                                             ##
## Version: 01.00.000                                           ##
##  Author: contact@hardenad.net                                ##
##################################################################
Function Get-PingCastle {
    <#
        .Synopsis
         This function Download the latest release and execute and audit with PingCastle.
        
        .Description
         This function execute PingCastle with parameter --healthcheck --no-enum-limit  --level Full      
        
        .Notes
         Version: 01.01 -- contact@hardenad.net 
         
         history: 21.12.16 Add Download latest release form Github
         history: 21.12.15 Script creation
    #>
    param(
        [Parameter(mandatory = $false)]
        [String]
        $Arguments
    )

    ## Default keepass password
    if (-not($Arguments)) {
        $Arguments = '--healthcheck --no-enum-limit  --level Full'
    }
    

    ## Function Log Debug File
    $DbgFile = 'Debug_{0}.log' -f $MyInvocation.MyCommand
    $dbgMess = @()

    ## Start Debug Trace
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "****"
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "**** FUNCTION STARTS"
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "****"
    
    ## Indicates caller and options used
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Function caller..........: " + (Get-PSCallStack)[1].Command

    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Test Internet connectivity  " 

    $OriginalProgressPreference = $Global:ProgressPreference
    $Global:ProgressPreference = 'SilentlyContinue'
    $test = Test-NetConnection
    
    switch ($test.PingSucceeded) {
        'True' {
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Test Internet connectivity OK " 
           
            $repo = "vletoux/pingcastle"
            $file = "PingCastle.zip"
            
            $releases = "https://api.github.com/repos/$repo/releases"
           
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Define repository to  $releases " 

            $tag = (Invoke-WebRequest $releases | ConvertFrom-Json)[0].tag_name 
            
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Find latest  release to PingCastle to $tag " 

            $name = $file.Split(".")[0]
            $zip = "$name`_$tag.zip"
            
            $download = "https://github.com/$repo/releases/download/$tag/$zip"
            
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Downoad the file $zip " 

            Invoke-WebRequest $download -Out $zip
            
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Extract the File $Zip to the folder $name " 
            Expand-Archive $zip -DestinationPath $name -Force 
            
            Remove-Item $zip -Recurse -Force -ErrorAction SilentlyContinue 
            
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Cleaning the download file $Zip " 

            Start-Process -FilePath .\$name\PingCastle.exe -ArgumentList "$Arguments" -WindowStyle Minimized -Wait

            $result = 0

        }
        'False' {

            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Test Internet connectivity KO ;( " 

            $result = 1

        }
        Default {}
    }


    ## Exit
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> function return RESULT: $Result"
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "===| INIT  ROTATIVE  LOG "
    if (Test-Path .\Logs\Debug\$DbgFile) {
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Rotate log file......: 1000 last entries kept" 
        if (((Get-WMIObject win32_operatingsystem).name -notlike "*2008*")) {
            $Backup = Get-Content .\Logs\Debug\$DbgFile -Tail 1000 
            $Backup | Out-File .\Logs\Debug\$DbgFile -Force
        }
    }
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "===| STOP  ROTATIVE  LOG "
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ****")
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T **** FUNCTION ENDS")
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ****")
    $DbgMess | Out-File .\Logs\Debug\$DbgFile -Append

    return (New-Object -TypeName psobject -Property @{ResultCode = $result ; ResultMesg = $ResMess ; TaskExeLog = $ResMess })

}

Function Set-LocAdmTaskScripts {
    <#
        .Synopsis
         The deployment script needs to be update to fetch with the running domain.
        
        .Description
         The deployment script needs to be update to fetch with the running domain. 
         The script will be overwritten and replace %DN% by the domain FQDN.

        .Notes
         Version: 01.00 -- contact@hardenad.net 
         Version: 01.01 -- contact@hardenad.net 
         
         history: 21.08.06 Script creation
                  21.11.21 Added admx/adml file to CentralStore repo
    #>
    param(
        [Parameter(mandatory = $true, Position = 0)]
        [String]
        $ScriptDir
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
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Parameter ScriptDir......: $ScriptDir"
    $result = 0

    ## loading configuration file
    Try {
        $xmlFile = [xml](Get-Content .\Configs\TasksSequence_HardenAD.xml)
        $Result = 0
    }
    Catch {
        $Result = 2
    }
    
    ## Recovering DomainDns Name
    $AllTranslation = $xmlFile.Settings.Translation.wellKnownID
    $DomainDns = ($AllTranslation | where-Object { $_.translateFrom -eq "%domaindns%" }).translateTo

    ## When dealing with 2008R2, we need to import AD module first
    if ((Get-WMIObject win32_operatingsystem).name -like "*2008*") {
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> is windows 2008/R2.......: True"
        
        Try { 
            Import-Module ActiveDirectory
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> OS is 2008/R2, added AD module."    
        } 
        Catch {
            $noError = $false
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---! ERROR! OS is 2008/R2, but the script could not add AD module." 
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> variable noError.........: $noError"
        }
        
    }
    else {

        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> is windows 2008/R2.......: False"
    }


    ## Get script local position
    #.SYSVOL
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> The target location path refers to..: SYSVOL"
    if (((Get-WMIObject win32_operatingsystem).name -like "*2008*")) {
        $sysVolD = (Get-WmiObject -Class Win32_Share -Filter "Name='SYSVOL'").Path
    }
    else {
        $SysVolD = (Get-SmbShare -Name SYSVOL).Path
    }
    $ScriptDir = $ScriptDir -replace "SYSVOL", $SysVolD
    $ScriptDir = $ScriptDir -replace "%domaindns%", $DomainDns 
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> the script files will be located to.: $ScriptDir"

    ## rewriting xml backup file with specific values
    $rawXml = Get-Content .\Inputs\GroupPolicies\`{88019C86-A81F-4C38-85B9-CD62970E8201`}\DomainSysvol\GPO\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml
    $rawXml = $rawXml -replace '%ScriptDir%', $ScriptDir
    $rawXml | Out-File .\Inputs\GroupPolicies\`{88019C86-A81F-4C38-85B9-CD62970E8201`}\DomainSysvol\GPO\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml-Encoding unicode -Force
    $rawXml = Get-Content .\Inputs\GroupPolicies\`{88019C86-A81F-4C38-85B9-CD62970E8201`}\DomainSysvol\GPO\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml.backup
    $rawXml = $rawXml -replace '%ScriptDir%', $ScriptDir
    $rawXml | Out-File .\Inputs\GroupPolicies\`{88019C86-A81F-4C38-85B9-CD62970E8201`}\DomainSysvol\GPO\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml.backup -Encoding unicode -Force

    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> Xml rewrited with customized value in .\Inputs\GroupPolicies\`{88019C86-A81F-4C38-85B9-CD62970E8201`}\DomainSysvol\GPO\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml"
    
    ## Create repository directory if needed
    if (-not(Test-Path $ScriptDir)) {
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> The target location path exists.....: False"
        Try {
            New-Item -Path $ScriptDir -ItemType Directory | Out-Null
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> The target location path exists.....: created successfully"
        }
        Catch {
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> The target location path exists.....: Error! could not create the directory target!"
            $result = 2
            $ResMess = "Error! could not create the directory target!"
        }
    }
    Else {
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> The target location path exists.....: True"
    }

    ## Duplicate file to the target destination
    if ($result -ne 2) {
        Robocopy.exe .\Inputs\GroupPolicies\`{88019C86-A81F-4C38-85B9-CD62970E8201`}\DomainSysvol\GPO\Machine\Scripts\ScheduledTasks $ScriptDir /IS | Out-Null
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> Loc Adm Script files copied"
    }

    ## Exit
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> function return RESULT: $Result"
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "===| INIT  ROTATIVE  LOG "
    if (Test-Path .\Logs\Debug\$DbgFile) {
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Rotate log file......: 1000 last entries kept" 
        if (((Get-WMIObject win32_operatingsystem).name -notlike "*2008*")) {
            $Backup = Get-Content .\Logs\Debug\$DbgFile -Tail 1000 
            $Backup | Out-File .\Logs\Debug\$DbgFile -Force
        }
    }
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "===| STOP  ROTATIVE  LOG "
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ****")
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T **** FUNCTION ENDS")
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ****")
    $DbgMess | Out-File .\Logs\Debug\$DbgFile -Append

    return (New-Object -TypeName psobject -Property @{ResultCode = $result ; ResultMesg = $ResMess ; TaskExeLog = $ResMess })
}

Export-ModuleMember -Function *