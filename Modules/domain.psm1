##################################################################
## Set-msDSmachineAccountQuota                                  ##
## ---------------------------                                  ##
## This function will set the attribute msDSMachineAccountquota ##
## to the specified value.                                      ##
##                                                              ##
## Version: 01.00.000                                           ##
##  Author: loic.veirman@mssec.fr                               ##
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
         Version: 02.00 -- Loic.veirman@mssec.fr
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
##  Author: loic.veirman@mssec.fr                               ##
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
         Version: 02.00 -- Loic.veirman@mssec.fr
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
            $NoEchoe = Enable-ADOptionalFeature 'Recycle Bin Feature' -Scope ForestOrConfigurationSet -Target (Get-ADForest).Name -WarningAction SilentlyContinue -Confirm:$false

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
##  Author: loic.veirman@mssec.fr                               ##
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
            01.00 -- Loic.veirman@mssec.fr
            01.01 -- Loic.veirman@mssec.fr
         
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
                    $NoEchoe = Set-ADReplicationSiteLink $RepSiteLink -Replace @{'Options'=1} -WarningAction SilentlyContinue
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
##  Author: loic.veirman@mssec.fr                               ##
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
            01.00 -- Loic.veirman@mssec.fr
         
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

Export-ModuleMember -Function *