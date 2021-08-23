##################################################################
## Set-GpoCentralStore                                          ##
## -------------------                                          ##
## This function will set the GPO store within the SYSVOL share ##
##                                                              ##
## Version: 01.00.000                                           ##
##  Author: loic.veirman@mssec.fr                               ##
##################################################################
Function Set-GpoCentralStore
{
    <#
        .Synopsis
         Enable the Centralized GPO repository (aka Central Store), or ensure it is so.
        
        .Description
         Will perform a query to ensure that the GPO Central Store is enable. If not, it will do so if requested.
         Return 0 if the states is as expected, else return 2.
        
        .Notes
         Version: 01.00 -- Loic.veirman@mssec.fr
                  01.01 -- Loic.veirman@mssec.fr
         
         history: 19.08.31 Script creation
                  21.06.06 REmoved parameter DesiredState
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
    if (((Get-WMIObject win32_operatingsystem).name -like "*2008*"))
    {
        Import-Module ActiveDirectory
        $sysVolBasePath = ((net share | ? { $_ -like "SYSVOL*" }) -split " " | ? { $_ -ne "" })[1]
    } else {
        $sysVolBasePath = (Get-SmbShare SYSVOL).path
    }

    $domName = (Get-AdDomain).DNSRoot

    if (Test-Path "$sysVolBasePath\$domName\Policies\PolicyDefinitions")
    {
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Central Store path is present"
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Central Store path is already enabled"
        $result = 0
    } else {
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Central Store path is not enable yet"
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Robocopy C:\Windows\PolicyDefinitions $sysVolBasePath\$domName\Policies\PolicyDefinitions /MIR (start)"

        $NoEchoe = Robocopy "C:\Windows\PolicyDefinitions" "$sysVolBasePath\$domName\Policies\PolicyDefinitions" /MIR
            
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Robocopy C:\Windows\PolicyDefinitions $sysVolBasePath\$domName\Policies\PolicyDefinitions /MIR (finish)"
        if ((Get-ChildItem "$sysVolBasePath\$domName\Policies\PolicyDefinitions" -Recurse).count -gt 10)
        {
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Seems copying has worked."
            $result = 0
        } else {
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---! Error while copying file."
            $ResMess  = "Error while copying file to new location"
            $result = 2
        }
    }

    ## Exit
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> function return RESULT: $Result"
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "===| INIT  ROTATIVE  LOG "
    if (Test-Path .\Logs\Debug\$DbgFile)
    {
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Rotate log file......: 1000 last entries kept" 
        if (((Get-WMIObject win32_operatingsystem).name -notlike "*2008*"))
        {
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
##  Author: loic.veirman@mssec.fr                               ##
##################################################################
Function New-ScheduleTasks
{
    <#
        .Synopsis
         Add Schedule Tasks as defined in TasksSequence_HardenAD.xml.
        
        .Description
         The tasks schedule are defined in the TasksSequence_HardenAD.xml and created (if not present) on the running system.
         The tasks files will be positionned in the directory path specified in <TaskSchedules>.BaseDir.
         The tasks will be generated from a xml backup file which contains all static data. Only the command (%command%), the attributes (%attributes%) and the description (%description%) 
         will be replaced by the config file content.
    
        .Notes
         Version: 01.00 -- Loic.veirman@mssec.fr
         
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
    if ((Get-WMIObject win32_operatingsystem).name -like "*2008*")
    {
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> OS is compliant..........: NO - Windows 2008/R2 detected."
        $result = 2
        $ResMess = "2008 or 2008 R2: not compliant."
    } else {
        $result = 0
    }

    ## Get xml data
    Try {
        $cfgXml = [xml](Get-Content .\Configs\TasksSequence_HardenAD.xml)
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Load xml.................: .\Configs\TasksSequence_HardenAD.xml (success)"
    } Catch {
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Load xml.................: .\Configs\TasksSequence_HardenAD.xml (failed)" 
        $result = 2
        $ResMess = "Failed to load configuration file"
    }

    if ($result -ne 2)
    {
        $SchXml = $cfgXml.settings.TaskSchedules
    
        ## Get tasks base dir
        $SchDir = $SchXml.BaseDir

        ## Check if the directory exists, else create it
        if (-not(Test-Path $SchDir)) 
        {
            try {
                $null = New-Item -Path $SchDir -ItemType Directory
                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> New dir....: $SchDir (success)" 
            } Catch {
                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> New dir....: $SchDir (Failed!)" 
                $result = 2
                $ResMess = "Failed to create the Schedule tasks base directory"
            }
        }

        ## This section will be executed only if the base directory exists.
        if ($result -ne 2)
        {
            ## Import data from repo
            Robocopy.exe .\Inputs\ScheduleTasks\TasksSchedulesScripts $SchDir /MIR | Out-Null
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> Repository (.\Inputs\ScheduleTasks\TasksSchedulesScripts) copied to $SchDir"

            ## Collect existing schedules
            $CurSchTasks = Get-ScheduledTask -TaskName *
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> Existing scheduled tasks recovered from system"

            ## Parsing tasks and adding if needed
            foreach ($task in $SchXml.SchedTask)
            {
                $TaskName   = $task.Name
                $TaskBack   = $task.xml
                $TaskDesc   = $task.SchedDsc
                $TaskPath   = $task.SchedPth
                $command    = $task.SchedCmd
                $Parameters = $task.SchedArg
                $Directory  = $task.SchedDir -replace '%BaseDir%',$SchDir

                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> Schedule tasks data: Name.......=$TaskName"
                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> Schedule tasks data: Backup.....=$TaskBack"
                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> Schedule tasks data: Description=$TaskDesc"
                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> Schedule tasks data: Path.......=$TaskPath"
                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> Schedule tasks data: Command....=$command"
                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> Schedule tasks data: Parameters.=$Parameters"
                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> Schedule tasks data: Directory..=$Directory"

                ## rewriting xml backup file with specific values
                $rawXml = Get-Content .\Inputs\ScheduleTasks\TasksSchedulesXml\$TaskBack
                $rawXml = $rawXml -replace '%description%',$TaskDesc
                $rawXml = $rawXml -replace '%command%',$command
                $rawXml = $rawXml -replace '%arguments%',$Parameters
                $rawXml = $rawXml -replace '%basePath%',$Directory
                $rawXml | Out-File .\Inputs\ScheduleTasks\TasksSchedulesXml\_$TaskBack -Encoding unicode -Force

                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> Xml rewrited with customized value in .\Inputs\ScheduleTasks\TasksSchedulesXml\_$TaskBack"

                ## Check if the tasks already exists
                if ($CurSchTasks.TaskName -match $TaskName)
                {
                    $FlagExists = $true
                } else {
                    $FlagExists = $false
                }
                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> Schedule tasks already exists: $FlagExists"

                ## Importing schedule
                Try   {
                    if (-not($FlagExists))
                    {
                        $install = Register-ScheduledTask -TaskPath $TaskPath -TaskName $TaskName -Xml (Get-Content .\Inputs\ScheduleTasks\TasksSchedulesXml\_$TaskBack | Out-String) -Force
                    } else {
                        $install = @{State="Ready"}
                    }

                    if ($install.State -eq "Ready") 
                    { 
                        $result = 0 
                    } else { 
                        $result = 1
                        $ResMess += "(failed to import: $TaskName)"
                    }
                    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> Task Creation result: $install"
                } Catch {
                    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> Task Creation failed: probably because it already exists."
                    $result = 1
                    $ResMess += "(failed to import: $TaskName)"
                }  
            }
        }
    }
    ## return a warning if 2k8
    if ($ResMess -eq "2008 or 2008 R2: not compliant.") 
    {
        $result = 1
    }

    ## Exit
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> function return RESULT: $Result"
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "===| INIT  ROTATIVE  LOG "
    if (Test-Path .\Logs\Debug\$DbgFile)
    {
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Rotate log file......: 1000 last entries kept" 
        if (((Get-WMIObject win32_operatingsystem).name -notlike "*2008*"))
        {
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
## Version: 01.00.000                                           ##
##  Author: loic.veirman@mssec.fr                               ##
##################################################################
Function Set-LapsScripts
{
    <#
        .Synopsis
         The deployment script needs to be update to fetch with the running domain.
        
        .Description
         The deployment script needs to be update to fetch with the running domain. 
         The script will be overwritten and replace %RootDN% by the domain FQDN.

        .Notes
         Version: 01.00 -- Loic.veirman@mssec.fr
         
         history: 21.08.06 Script creation
    #>
    param(
        [Parameter(mandatory=$true,Position=0)]
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
    if ((Get-WMIObject win32_operatingsystem).name -like "*2008*")
    {
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> is windows 2008/R2.......: True"
        
        Try   { 
                Import-Module ActiveDirectory
                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> OS is 2008/R2, added AD module."    
                } 
        Catch {
                $noError = $false
                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---! ERROR! OS is 2008/R2, but the script could not add AD module." 
                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> variable noError.........: $noError"
                }
        
    } else {

        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> is windows 2008/R2.......: False"
    }


    ## Get script local position
    Switch -Regex ($ScriptDir)
    {
        #.NETLOGON
        "NETLOGON" {
            $dbgMess  += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> The target location path refers to..: NETLOGON"
            if (((Get-WMIObject win32_operatingsystem).name -like "*2008*"))
            {
                $NetLogonD = (Get-WmiObject -Class Win32_Share -Filter "Name='NETLOGON'").Path
            } else {
                $NetLogonD = (Get-SmbShare -Name NetLogon).Path
            }
            $ScriptDir = $ScriptDir -replace "NETLOGON",$NetLogonD 
            $dbgMess  += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> the script files will be located to.: $ScriptDir"
        }
        #.SYSVOL
        "SYSVOL" {
            $dbgMess  += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> The target location path refers to..: SYSVOL"
            if (((Get-WMIObject win32_operatingsystem).name -like "*2008*"))
            {
                $sysVolD = (Get-WmiObject -Class Win32_Share -Filter "Name='SYSVOL'").Path
            } else {
                $SysVolD = (Get-SmbShare -Name SYSVOL).Path
            }
            $ScriptDir = $ScriptDir -replace "SYSVOL",$SysVolD 
            $dbgMess  += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> the script files will be located to.: $ScriptDir"
        }
        #.UNC Path
        Default {
            $dbgMess  += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> The target location path refers to..: UNC PATH"
            $ScriptDir = $ScriptDir -replace "RootDN",(Get-ADDomain).DistinguishedName
            $dbgMess  += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> the script files will be located to.: $ScriptDir"
        }
    }

    ## Create repository directory if needed
    if (-not(Test-Path $ScriptDir))
    {
        $dbgMess  += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> The target location path exists.....: False"
        Try {
            New-Item -Path $ScriptDir -ItemType Directory | Out-Null
            $dbgMess  += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> The target location path exists.....: created successfully"
        } Catch {
            $dbgMess  += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> The target location path exists.....: Error! could not create the directory target!"
            $result  = 2
            $ResMess = "Error! could not create the directory target!"
        }
    } Else {
        $dbgMess  += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> The target location path exists.....: True"
    }

    ## Duplicate file to the target destination
    if ($result -ne 2)
    {
        Robocopy.exe .\Inputs\LocalAdminPwdSolution\Binaries $ScriptDir /IS | Out-Null
        $dbgMess  += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> binary files copied"
        Robocopy.exe .\Inputs\LocalAdminPwdSolution\LogonScripts $ScriptDir /IS | Out-Null
        $dbgMess  += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> script files copied"
    }

    ## Rewriting script file
    foreach ($file in (Get-ChildItem -Path $ScriptDir | Where-Object { $_.Name -like "*.bat"}))
    {
        $newFile = @()
        Try {
            (Get-Content $file.fullName) -Replace '%RootDN%',(Get-ADDomain).DnsRoot | Set-Content $File.FullName 
            $dbgMess  += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> rewritten file " + $file.Name + " (success)"
        }
        Catch {
            $dbgMess  += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> rewritten file " + $file.Name + " (failed!)"
            $result   = 1
            $ResMess += "(Failed to rewrite the file " + $file.name + ")"
        }
    }

    ## Exit
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> function return RESULT: $Result"
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "===| INIT  ROTATIVE  LOG "
    if (Test-Path .\Logs\Debug\$DbgFile)
    {
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Rotate log file......: 1000 last entries kept" 
        if (((Get-WMIObject win32_operatingsystem).name -notlike "*2008*"))
        {
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
##  Author: loic.veirman@mssec.fr                               ##
##################################################################
Function Install-LAPS
{
    <#
        .Synopsis
         To be deployed, LAPS need to update the AD Schema first.
        
        .Description
         The script first update the schema, then it will install the management tool.

        .Notes
         Version: 01.00 -- Loic.veirman@mssec.fr
         
         history: 21.08.22 Script creation
    #>
    param(
        [Parameter(mandatory=$true,Position=0)]
        [ValidateSet('ForceDcIsSchemaOwner','IgnoreDcIsSchemaOwner')]
        [String]
        $SchemaOwnerMode
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
    $result = 0

    ## When dealing with 2008R2, we need to import AD module first
    if ((Get-WMIObject win32_operatingsystem).name -like "*2008*")
    {
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> is windows 2008/R2.......: True"
        
        Try   { 
                Import-Module ActiveDirectory
                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> OS is 2008/R2, added AD module."    
                } 
        Catch {
                $noError = $false
                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---! ERROR! OS is 2008/R2, but the script could not add AD module." 
                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> variable noError.........: $noError"
                $result  = 2
                $ResMess = "AD module not available."
                }
    } else {
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> is windows 2008/R2.......: False"
    }

    ## Check prerequesite: running user must be member of the Schema Admins group and running computer should be Schema Master owner.
    $CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $isSchemaAdm = Get-ADGroupMember -Recursive ((Get-ADDomain).DomainSID.value + "-518") | Where-Object { $_.SID -eq $CurrentUser.User }

    $CurrentCptr = $env:COMPUTERNAME
    $isSchemaOwn = (Get-ADForest).SchemaMaster -eq ($currentCptr + "." + (Get-ADDomain).DnsRoot)


    ## Check if a bypass has been requested for the schema master owner condition
    if ($SchemaOwnerMode -eq 'IgnoreDcIsSchameOwner')
    {
        $isSchemaOwn = $true
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> is Schema Master owner...: $isSchemaOwn (enforced for bypass)"
    } else {

        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> is Schema Master owner...: $isSchemaOwn"
    }

    if ($isSchemaAdm -and $isSchemaOwn)
    {
        ## User has suffisant right, the script will then proceed.
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> is Schema Administrator..: True"

        ## First, we need to install the pShell add-ons to be able to update the schema.
        $ExeCmd = ".\Inputs\LocalAdminPwdSolution\Binaries\LAPS.x64.msi"
        $Params = "ADDLOCAL=Management.UI,Management.PS,Management.ADMX"

        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> command line: & msiexec /i $ExeCmd $Params /quiet /norestart"

        Try {
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> command line: === begin === "

            Start-Process -FilePath "$env:systemroot\system32\msiexec.exe" `
                          -WorkingDirectory .\Inputs\LocalAdminPwdSolution\Binaries `
                          -ArgumentList '/i laps.x64.msi ADDLOCAL=Management.UI,Management.PS,Management.ADMX /quiet /norestart' `
                          -NoNewWindow `
                          -Wait
            
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> command line: === done! === "
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> installation is successfull."

        } Catch {
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> command line: === Error === "
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> installation failed!"
            $result  = 2
            $ResMess = "ERROR! the command line has failed!"
        }
        
        ## If the install is a success, then let's update the schema
        if ($result -eq 0)
        {
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> Proceding to schema extension"
            Try {
                Import-Module AdmPwd.PS -ErrorAction Stop -WarningAction Stop
                $null = Update-AdmPwdADSchema
                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> schema extension is successfull"

            } Catch {
                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> schema extension failed (warning: .Net 4.0 or greater requiered)"
                $result  = 1
                $ResMess = "LAPS installed but the schema extension has failed (warning: .Net 4.0 or greater requiered)"
            }
        } Else {
                $result  = 1
                $ResMess = "The schema extension has been canceled"
        }

    } Else {
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> is Schema Administrator..: False"
        $result  = 2
        $ResMess = "The user is not a Schema Admins (group membership with recurse has failed)"
    }

    ## Exit
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> function return RESULT: $Result"
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "===| INIT  ROTATIVE  LOG "
    if (Test-Path .\Logs\Debug\$DbgFile)
    {
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Rotate log file......: 1000 last entries kept" 
        if (((Get-WMIObject win32_operatingsystem).name -notlike "*2008*"))
        {
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