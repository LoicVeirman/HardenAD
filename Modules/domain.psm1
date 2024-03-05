##################################################################
## Set-msDSmachineAccountQuota                                  ##
## ---------------------------                                  ##
## This function will set the attribute msDSMachineAccountquota ##
## to the specified value.                                      ##
##                                                              ##
## Version: 01.00.000                                           ##
##  Author: contact@hardenad.net                                ##
##################################################################
Function Set-msDSMachineAccountQuota
{
     <#
        .Synopsis
         Unallow users to add computers to the domain.
        
        .Description
         Security Measure: please modify the Sequence File to make this happen.
        
        .Parameter DsiAgreement
         YES if the DSI is informed and agreed.

        .Notes
         Version: 02.00 -- contact@hardenad.net
         history: 12/04/2021 Script creation
                  04/06/2021 removed parameter dsiAgreement (handled by the caller).
                             added parameter newValue that specify the msDSmachineAccountQuota setings
    #>
    param(
        [Parameter(mandatory=$true,position=0)]
        [int]
        $newValue
    )

    ## Function Log Debug File
    $DbgFile = 'Debug_{0}.log' -f $MyInvocation.MyCommand
    $dbgMess = @()

    ## Start Debug Trace
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "****"
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "**** FUNCTION STARTS"
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "****"

    ## Indicates caller and options used
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Function caller..............: " + (Get-PSCallStack)[1].Command
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> parameter newVlaue...........: $newValue"    

    ## When dealing with 2008R2, we need to import AD module first
    if ((Get-WMIObject win32_operatingsystem).name -like "*2008*")
    {
        Try { 
            Import-Module ActiveDirectory
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> OS is 2008/R2, added AD module."    
        } Catch {
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---! ERROR! OS is 2008/R2, but the script could not add AD module."   
        }
    }
    ## Setting the new value
    Try   {
            Start-Sleep -Milliseconds 50
            Set-ADDomain -Identity (Get-ADDomain) -Replace @{"ms-DS-MachineAccountQuota"="$newValue"}
            $result = 0
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> msDSmachineAccountQuota has been set to $newValue"    
          }
    Catch {
            $result = 2
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---! ERROR: msDSmachineAccountQuota cloud not be set to $newValue!"    
          }

    ## Checking the new value.
    if ($result -eq 0)
    {
        $checkedValue = (Get-ADObject (Get-ADDomain).distinguishedName -Properties ms-DS-MachineAccountQuota).'ms-DS-MachineAccountQuota'
        if ($checkedValue -eq $NewValue)
        { 
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> msDSmachineAccountQuota has been verified successfully and the current value is $checkedValue"    
        } else {
            $result = 1 
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---! ERROR: msDSmachineAccountQuota was not verified properly, the value is not $newValue but $checkedValue"    
        }
    }

    ## Exit
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Function return RESULT: $result"
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "===| INIT  ROTATIVE  LOG "
    if (Test-Path .\Logs\Debug\$DbgFile)
    {
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Rotate log file......: 1000 last entries kept" 
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

    return (New-Object -TypeName psobject -Property @{ResultCode = $result ; ResultMesg = $null ; TaskExeLog = $null })
}

##################################################################
## Set-ADRecycleBin                                             ##
## ----------------                                             ##
## This function will enable the AD Recycle Bin.                ##
##                                                              ##
## Version: 01.00.000                                           ##
##  Author: contact@hardenad.net                                ##
##################################################################
Function Set-ADRecycleBin
{
    <#
        .Synopsis
         Enable the Recycle Bin, or ensure it is so.
        
        .Description
         Will perform a query to ensure that the AD Recycle Bin is enable, then enabled it.
         Return 0 if successfull, 2 if the control indicates that the option is not activated.
        
        .Notes
         Version: 02.00 -- contact@hardenad.net
         history: 19.08.31 Script creation
                  21.06.05 Version 2.0.0
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
    
    ## When dealing with 2008R2, we need to import AD module first
    if ((Get-WMIObject win32_operatingsystem).name -like "*2008*")
    {
        Try { 
            Import-Module ActiveDirectory
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> OS is 2008/R2, added AD module."    
        } Catch {
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---! ERROR! OS is 2008/R2, but the script could not add AD module."   
        }
    }
    ## Test Options current settings
    if ((Get-ADOptionalFeature -Filter 'name -like "Recycle Bin Feature"').EnabledScopes) 
    {
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Active Directory Recycle Bin is already enabled"
        $result = 0
    }
    else
    {
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Active Directory Recycle Bin is not enabled yet"
        
        Try 
        {
            Enable-ADOptionalFeature 'Recycle Bin Feature' -Scope ForestOrConfigurationSet -Target (Get-ADForest).Name -WarningAction SilentlyContinue -Confirm:$false | Out-Null

            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Enable-ADOptionalFeature 'Recycle Bin Feature' -Scope ForestOrConfigurationSet -Target " + (Get-ADForest).Name + ' -WarningAction SilentlyContinue -Confirm:$false'
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Active Directory Recycle Bin is enabled"
            
            $result = 0
        }
        catch 
        {
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---! Error while configuring the active directory Recycle Bin"
            
            $result = 2
        }

        ##Ensure result is as expected
        if ($result -eq 0)
        {
            if ((Get-ADOptionalFeature -Filter 'name -like "Recycle Bin Feature"').EnabledScopes) {
                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> The active directory Recycle Bin is enabled as expected."
            } else {
                $result = 2
                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---! Error: the active directory Recycle Bin has not the expected status!"
            }
        }    
    }    
    ## Exit
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> function return RESULT: $Result"
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "===| INIT  ROTATIVE  LOG "
    if (Test-Path .\Logs\Debug\$DbgFile)
    {
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Rotate log file......: 1000 last entries kept" 
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

    return (New-Object -TypeName psobject -Property @{ResultCode = $result ; ResultMesg = $null ; TaskExeLog = $null })
}

##################################################################
## Set-SiteLinkNotify                                           ##
## ------------------                                           ##
## This function will set the Notify Option on each replication ##
## Link.                                                        ##
##                                                              ##
## Version: 01.00.000                                           ##
##  Author: contact@hardenad.net                                ##
##################################################################
Function Set-SiteLinkNotify
{
    <#
        .Synopsis
         Enable the Notify Option, or ensure it is so.
        
        .Description
         Enable the Notify Option, or ensure it is so.
         Return TRUE if the states is as expected, else return FALSE.
        
        .Notes
         Version: 
            01.00 -- contact@hardenad.net
            01.01 -- contact@hardenad.net
         
         history: 
            01.00 -- Script creation
            01.01 -- Fix replink auto discver
            01.02 -- Removed DesiredState parameter
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
    
    ## When dealing with 2008R2, we need to import AD module first
    if ((Get-WMIObject win32_operatingsystem).name -like "*2008*")
    {
        Try { 
            Import-Module ActiveDirectory
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> OS is 2008/R2, added AD module."    
        } Catch {
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---! ERROR! OS is 2008/R2, but the script could not add AD module."   
        }
    }

    #.Only if not 2008 or 2008 R2.
    if (((Get-WMIObject win32_operatingsystem).name -notlike "*2008*"))
    {
    #.List of rep link
    $RepSiteLinks = Get-ADReplicationSiteLink -Filter * 

    #.For each of them...
    foreach ($RepSiteLink in $RepSiteLinks)
        {
            #.Check if already enabled.
            if ((Get-ADReplicationSiteLink $RepSiteLink.Name -Properties *).options) 
            {
                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Urgent Replication Options are already enabled with value " + (Get-ADReplicationSiteLink $RepSiteLink.Name -Properties *).options + " for " + $RepSiteLink.Name
                $Result = 0
            } 
            Else 
            {
                try
                {
                    Set-ADReplicationSiteLink $RepSiteLink -Replace @{'Options'=1} -WarningAction SilentlyContinue | Out-Null
                    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Urgent Replication Options is now enabled with value " + (Get-ADReplicationSiteLink $RepSiteLink.Name -Properties *).options + " for " + $RepSiteLink.Name
                    $Result = 1
                }
                Catch
                {
                    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---! Urgent Replication failed to be enabled with value 1 for " + $RepSiteLink.Name
                    $Result = 2
                }
            }
            #.Check if successfully enabled.
            if ($Result -eq 1)
            {
                if ((Get-ADReplicationSiteLink $RepSiteLink.Name -Properties *).options) 
                { 
                    $Result = 0
                    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Urgent Replication Options on "+ $RepSiteLink.Name + " is properly set"
                } else { 
                    $Result = 2
                    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Urgent Replication Options are already enabled with value " + (Get-ADReplicationSiteLink $RepSiteLink.Name -Properties *).options + " for " + $RepSiteLink.Name
                }
            }
        }
    } Else {
        $Result = 1
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---! Windows 2008 and 2008 R2 are not compliant with this function."
        $ResMess = "2008/R2 is not compliant with this function"
    }
    ## Exit
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> function return RESULT: $Result"
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "===| INIT  ROTATIVE  LOG "
    if (Test-Path .\Logs\Debug\$DbgFile)
    {
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Rotate log file......: 1000 last entries kept" 
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
## Set-DefaultObjectLocation                                    ##
## -------------------------                                    ##
## This function will relocate the default location for a       ##
## specific kind of object.                                     ##
##                                                              ##
## Version: 01.00.000                                           ##
##  Author: contact@hardenad.net                                ##
##################################################################
Function Set-DefaultObjectLocation
{
    <#
        .Synopsis
         Redirect default location to a specific point.
        
        .Description
         use REDIRCMP or REDIRUSR to fix default location of objects.
         Return TRUE if the states is as expected, else return FALSE.
        
        .Notes
         Version: 
            01.00 -- contact@hardenad.net
         
         history: 
            01.00 -- Script creation
    #>
    param(
        [Parameter(mandatory=$true,position=0)]
        [ValidateSet("User","Computer")]
        [String]
        $ObjectType,

        [Parameter(mandatory=$true,position=1)]
        [String]
        $OUPath
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
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Parameter ObjectType.....: " + $ObjectType
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Parameter OUPath.........: " + $OUPath

    ## When dealing with 2008R2, we need to import AD module first
    if ((Get-WMIObject win32_operatingsystem).name -like "*2008*")
    {
        Try { 
            Import-Module ActiveDirectory
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> OS is 2008/R2, added AD module."    
        } Catch {
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---! ERROR! OS is 2008/R2, but the script could not add AD module."   
        }
    }
    ## dynamic OU path rewriting
    $OUPath2 = $OUPath -replace 'RootDN',(Get-ADDomain).DistinguishedName

    ## Checking object class
    switch ($ObjectType)
    {
        "User"     {
                        ## User
                        Try {
                            $null = redirusr $OUPath2
                            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> REDIRUSR $OUPath2 (success)" 
                            $result = 0
                        }
                        Catch {
                            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---! REDIRUSR $OUPath2 (failure)" 
                            $result = 2
                        }
                   }
        "Computer" {
                        ##Computer
                        Try {
                            $null = redircmp $OUPath2
                            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> REDIRUSR $OUPath2 (success)" 
                            $result = 0
                        }
                        Catch {
                            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---! REDIRUSR $OUPath2 (failure)" 
                            $result = 2
                        }
                   }
        Default    {
                        ## Bad input !
                        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---! ERROR! ObjectClass is unknown."
                        $result = 2
                   }
    }
    
    ## Exit
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> function return RESULT: $Result"
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "===| INIT  ROTATIVE  LOG "
    if (Test-Path .\Logs\Debug\$DbgFile)
    {
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Rotate log file......: 1000 last entries kept" 
        if (-not((Get-WMIObject win32_operatingsystem).name -like "*2008*"))
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
## Set-ADFunctionalLevel                                        ##
## ---------------------------                                  ##
## This function will raise Forest and Domain Functional Level  ##
## to a specific level, or the newest possible                  ##
##                                                              ##
## Version: 01.00.000                                           ##
##  Author: contact@hardenad.net                                ##
##################################################################
Function Set-ADFunctionalLevel
{
     <#
        .Synopsis
         Raise Foreset and Domain Functional Level, if possible
        
        .Description
         Security Measure: please modify the Sequence File to make this happen.
         Run PreRequisite checks before implementing action
        
        .Parameter DsiAgreement
         YES if the DSI is informed and agreed.
        .Notes
         Version: 01.00 -- contact@hardenad.net
         history: 
    #>
    param(
        [Parameter(mandatory=$true,position=0)]
        [ValidateSet("Domain","Forest")]
        [String]
        $TargetScope,

        [Parameter(mandatory=$true,position=1)]
        [ValidateSet("2008R2","2012","2012R2","2016","Last")]
        [String]
        $TargetLevel
    )

    ## TargetLevel and OS Version
    $OSlevelAndVersion = @{
        '2008'  ='6.0'
        '2008R2'='6.1'
        '2012'  ='6.2'
        '2012R2'='6.3'
        '2016'  ='10.0*'
    }


    ## Function Log Debug File
    $DbgFile = 'Debug_{0}.log' -f $MyInvocation.MyCommand
    $dbgMess = @()

    ## Start Debug Trace
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "****"
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "**** FUNCTION STARTS"
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "****"

    ## Indicates caller and options used
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Function caller..............: " + (Get-PSCallStack)[1].Command
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> parameter TargetScope........: $TargetScope"    
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> parameter TargetLevel........: $TargetLevel"  

    ## When dealing with 2008R2, we need to import AD module first
    if ((Get-WMIObject win32_operatingsystem).name -like "*2008*")
    {
        Try { 
            Import-Module ActiveDirectory
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> OS is 2008/R2, added AD module."    
        } Catch {
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---! ERROR! OS is 2008/R2, but the script could not add AD module."   
        }
    }

    ## checking preRequisites : run on FSMO, OS newer or equal to TargetLevel, Replication OK if several DCs
    $blnPreRequisitesOK = $true
    If($TargetScope -like "Domain") {
        try {
            $DomainObj = Get-ADDomain
            $CurrentDomainLevel = $DomainObj.DomainMode
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Current Level : $CurrentDomainLevel" 

            # Skip Upgrade from 2000 or 2003 as it may need specific manual actions
            If (($CurrentDomainLevel -like "Windows2000Domain") -or ($CurrentDomainLevel -like "Windows2003Domain") -or (($CurrentDomainLevel -like "Windows2003InterimDomain"))) {
                $blnPreRequisitesOK = $false
                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---! ERROR! Upgrade from current Domain level is not supported by this script"  
            }
        }
        catch {
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---! ERROR! Some issue occured when getting domain / DC Info : $($_.Exception.Message)" 
            $blnPreRequisitesOK = $false
        }

        If($blnPreRequisitesOK) {
            # Check OS of all DCs of the current domain 
            [array]$AllDomainControllers = Get-ADDomainController -Filter * | Select-Object Name,HostName,OperatingSystem,OperatingSystemVersion
            $intLowestOSVersion = 9999
            $AllDomainControllers | ForEach-Object {
                $DCName = $_.HostName
                $OSversion = $_.OperatingSystemVersion
                $intOSVersion = [int]($OSversion.Substring(0,$OSversion.IndexOf(".")+2).Replace(".",""))
                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> DC: $DCName | OS: $OSversion | intVersion: $intOSVersion"
                If($TargetLevel -like "Last") {
                    If($intOSVersion -lt $intLowestOSVersion) {
                        $intLowestOSVersion = $intOSVersion
                        $LowestOSVersion = $OSversion
                        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> LowestOSVersion: $LowestOSVersion"
                    }
                } 
                Else {
                    $intTargetOSVersion = [int](($OSlevelAndVersion[$TargetLevel]).Substring(0,($OSlevelAndVersion[$TargetLevel]).IndexOf(".")+2).Replace(".",""))
                    If($intOSVersion -lt $intTargetOSVersion) { 
                        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---! ERROR! OperatingSystem of '$DCName' is '$($_.OperatingSystem)', which is too low for target Domain Level ($($OSlevelAndVersion[$TargetLevel]))" 
                        #Unused variable
                        #$blnPreRequisitesOK = $false
                    }
                }
            }

            # Check AD Replication
            If($AllDomainControllers.Count -gt 1) {
                $RepFailures = Get-ADReplicationFailure -Target $DomainObj.DnsRoot -Scope Domain
                If($RepFailures) {
                    $blnPreRequisitesOK = $false
                    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---! ERROR! Some DCs have replication issues"                  
                }
            }

            # Check Current DC FSMO
            $ADServerObj = Get-ADDomainController
            If($ADServerObj.OperationMasterRoles  -notcontains "PDCEmulator") {
                $blnPreRequisitesOK = $false
                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---! ERROR! Current DomainController is not PDCEmulator"  
            }

            # If TargetLevel is Last, set it to the lowest OS found amongst Domain Controllers
            If($TargetLevel -like "Last") {
                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> TargetLevel is Last -> Set to LowestOSVersion ($LowestOSVersion)"
                $LowestOSVersion = $LowestOSVersion.Substring(0,$LowestOSVersion.IndexOf(".")+2) + "*"
                $TargetLevel = ($OSlevelAndVersion.GetEnumerator() | Where-Object {$_.Value -like $LowestOSVersion}).Name
                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Set Target Level to $TargetLevel (Lowest OS found is $LowestOSVersion)" 

            }

        }

    }
    Else {
        # check PreRequisites for Forest Functional Update
        try {
            $ForestObj = Get-ADForest
            $CurrentForestLevel = $ForestObj.ForestMode
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Current Forest Functional Level : $CurrentForestLevel " 

            # Skip Upgrade from 2000 or 2003 as it may need specific manual actions
            If (($CurrentForestLevel -like "Windows2000Forest") -or ($CurrentForestLevel -like "Windows2003Forest") -or (($CurrentForestLevel -like "Windows2003InterimForest"))) {
                $blnPreRequisitesOK = $false
                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---! ERROR! Upgrade from current Forest level is not supported by this script"  
            }
        }
        catch {
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---! ERROR! Some issue occured when getting domain / DC Info : $($_.Exception.Message)" 
            $blnPreRequisitesOK = $false
        }   

        If($blnPreRequisitesOK) {
            # Check DFL of all domains of the Forest
            # If Target is 'Last' we get the lowest DFL to have the possible target. Otherwise we check if all DFL are equal or above FFL target
            $LowestFL = "2099"
            foreach ($DomainDns in $ForestObj.Domains) {
                Try {
                    $DflLabel = [string](Get-ADDomain $DomainDns).DomainMode
                    $DflShort = ($DflLabel.Replace("Windows","")).Replace("Domain","")
                    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Domain $DomainDns : DFL = $DflLabel ($DflShort)" 
                    If($TargetLevel -like "Last") {
                        If($DflShort -lt $LowestFL) {$LowestFL = $DflShort}
                    } 
                    Else {
                        If($DflShort -lt $TargetLevel) { 
                            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---! ERROR! Domain Functional Lever of '$DomainDns' is '$DflLabel', which is too low for target Forest Level" 
                            $blnPreRequisitesOK = $false
                        }
                    }

                }
                catch {
                    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---! ERROR! Some issue occured when getting domain $DomainDns" 
                    $blnPreRequisitesOK = $false
                }     
            }

            # Check Current DC FSMO
            $ADServerObj = Get-ADDomainController
            If($ADServerObj.OperationMasterRoles  -notcontains "PDCEmulator") {
                $blnPreRequisitesOK = $false
                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---! ERROR! Current DomainController is not PDCEmulator"  
            }
            If($ADServerObj.Domain -ne $ADServerObj.Forest) {
                $blnPreRequisitesOK = $false
                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---! ERROR! Current DomainController is not in the root domain"           
            }

            # set Target Level if parameter is Last 
            If($TargetLevel -like "Last") { $TargetLevel = $LowestFL}
        }

    }

    # Process Upgrade
    If($blnPreRequisitesOK) {
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> All PreRequisites OK : Upgrade $TargetScope to $TargetLevel Functional Level"

        If($TargetScope -like "Domain") {
            $TargetMode = "Windows" + $TargetLevel + "Domain"

            If($TargetMode -like $CurrentDomainLevel) {
                # Skip operation if Target = Current   
                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> IGNORED : DFL is already at $TargetMode (no change needed)"
                $Result = 3 
                $ResultMsg = "IGNORED : DFL is already at $TargetMode (no change needed)" 
            }
            Else {
                Try {
                    Set-ADDomainMode -identity $DomainObj.DnsRoot -DomainMode $TargetMode -Confirm:$false -ErrorAction Stop | Out-Null
                    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> SUCCESS : DFL Updated to $TargetMode"
                    $Result = 0 
                    $ResultMsg = "SUCCESS : Domain Funtional Level Updated to $TargetMode"

                    If($AllDomainControllers.Count -gt 1) {
                        # Force Replication on All DCs of the domain
                        $DomainDN = $DomainObj.DistinguishedName
                        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Force Replication on All DCs of the domain"
                        $AllDomainControllers | Foreach-Object {
                            repadmin /syncall $_.HostName $DomainDN /e /A | Out-Null
                        }

                        # Check if well replicated on all DCs
                        Start-Sleep -Seconds 5
                        $FLRefNb = (Get-ADObject -Identity $DomainDN -Properties msDS-Behavior-Version -Server $ADServerObj.HostName).'msDS-Behavior-Version'
                        $AllDomainControllers | Foreach-Object {
                            $DChostName = $_.HostName
                            $FLNb = (Get-ADObject -Identity $DomainDN -Properties msDS-Behavior-Version -Server $DChostName).'msDS-Behavior-Version'
                            If($FLNb -ne $FLRefNb) {
                                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---! WARNING! Domain Functional not replicated on $DChostName"
                                #Unused variable 
                                #$Result = 1
                            }
                        }
                    }

                }
                catch {
                    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---! ERROR! Domain Functional Level upgrade Failed : $($_.Exception.Message)" 
                    $ResultMsg = "DFL upgrade Failed : $($_.Exception.Message)"
                    $Result = 2
                }
            }


        }
        Else {
            $TargetMode = "Windows" + $TargetLevel + "Forest"
            If($TargetMode -like $CurrentForestLevel) {
                # Skip operation if Target = Current   
                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> IGNORED : FFL is already at $TargetMode (no change needed)"
                $Result = 3 
                $ResultMsg = "IGNORED : FFL is already at $TargetMode (no change needed)" 
            }
            Else {
                Try {
                    Set-ADForestMode -Identity $ForestObj.RootDomain -ForestMode $TargetMode -Confirm:$false -ErrorAction Stop | Out-Null
                    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> SUCCESS : FFL Updated to $TargetMode"
                    $Result = 0  
                    $ResultMsg = "SUCCESS : Forest Funtional Level Updated to $TargetMode"
                }
                catch {
                    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---! ERROR! Forest Functional Level upgrade Failed : $($_.Exception.Message)" 
                    $ResultMsg = "FFL upgrade Failed : $($_.Exception.Message)"
                    $Result = 2
                }
            }

        }

    }
    Else {
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Some PreRequisites failed : Upgrade $TargetScope to $TargetLevel Functional Level is SKIPPED (no action done)"
        $ResultMsg = "Some PreRequisites failed : Upgrade $TargetScope to $TargetLevel Functional Level is SKIPPED (no action done)"
        $Result = 1
    }


    ## Exit
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Function return RESULT: $result"
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "===| INIT  ROTATIVE  LOG "
    if (Test-Path .\Logs\Debug\$DbgFile)
    {
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Rotate log file......: 1000 last entries kept" 
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

    return (New-Object -TypeName psobject -Property @{ResultCode = $result ; ResultMesg = $ResultMsg ; TaskExeLog = $null })
}

Export-ModuleMember -Function *