##################################################################
## Set-AdminOU                                                  ##
## -----------                                                  ##
## This function will create the Administration Organizational  ##
## unit.                                                        ##
##                                                              ##
## Version: 01.00.000                                           ##
##  Author: loic.veirman@mssec.fr                               ##
##################################################################
Function Set-TreeOU
{
    <#
        .Synopsis
         Check and create, if needed, the administration organizational unit.
        
        .Description
         An Administration Organizational Unit will handle every object related to the tiering model.
        
        .Parameter Skeleton
         xml content exported from TaskXSequence_HardenAD.xml file.

        .Parameter ClassName
         Class name use to select a specific model within the skeleton.

        .Notes
         Version: 01.00.000 -- Loic.veirman@mssec.fr
         history: 2021/06.08 - Script creation
    #>
    param(
        [Parameter(mandatory=$true,Position=0)]
        [String]
        $ClassName
    )

    ## Function to loop OU creation
    Function CreateOU ($OUObject,$OUPath)
    {
        $dbgMess = @()
        
        ## Testing if OU is already present
        if ([adsi]::exists(("LDAP://OU=" + $OUOBject.Name + "," + $OUPath)))
        {
            $hrOUs = (("OU=" + $OUOBject.Name + "," + $OUPath) -split "," -replace "OU=","") -replace "DC=",""
            for ($i = $hrOUs.count -1 ; $i -ge 0 ; $i--)
            {
                $hrOUname += " | " + $hrOUs[$i] 
            }
            
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> === $hrOUname (already exists)"

        } Else {
            $hrOUs = (("OU=" + $OUOBject.Name + "," + $OUPath) -split "," -replace "OU=","") -replace "DC=",""
            for ($i = $hrOUs.count -1 ; $i -ge 0 ; $i--)
            {
                $hrOUname += " | " + $hrOUs[$i] 
            }
            Try   {
                    New-ADOrganizationalUnit -Name $OUObject.Name -Path $OUPath -Description $OUObject.Description -ErrorAction Stop
                    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> +++ $hrOUname (success)"
                  } 
            Catch {
                    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> !!! $hrOUname (failure)"
                  }
        }
        
        ## Looking for sub organizational unit(s)...        
        if ($OUOBject.ChildOU)
        {
            $newPath = "OU=" + $OUObject.Name + "," + $OUPath
            $OUObject.ChildOU | foreach { $dbgMess += CreateOU $_ $newPath }
        }
        ## Return logs
        return $dbgMess
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
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> parameter ClassName......: $ClassName"    

    ## Import xml file with OU build requierment
    Try { 
        [xml]$xmlSkeleton = Get-Content (".\Configs\TasksSequence_HardenAD.xml") -ErrorAction Stop
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> xml skeleton file........: loaded successfully"
        $xmlLoaded = $true
    } Catch {
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---! FAILED loading xml skeleton file "
        $xmlLoaded = $false
    }

    ## If xml loaded, begining check and create...
    if ($xmlLoaded)
    {
        ## Log loop start
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> variable XmlLoaded.......: $xmlLoaded"
        
        ## Creating a variable to monitor failing tasks
        $noError = $true

        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> variable noError.........: $noError"
        
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

        if ($noError)
        {
            ## Getting root DNS name
            $DomainRootDN = (Get-ADDomain).DistinguishedName
     
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Parameter DomainRootDN...: $DomainRootDN"

            ## Getting specified schema
            $xmlData = $xmlSkeleton.settings.OrganizationalUnits.ouTree.OU | Where-Object { $_.class -eq $ClassName }
     
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> xml data loaded (" + $xmlData.ChildOU.count + " child's OU - class=$ClassName)"

            ## if we got data, begining creation loop
            if ($xmlData)
            {
                if ([adsi]::exists(("LDAP://OU=" + $xmlData.Name + "," + $DomainRootDN)))
                {
                    ## OU Present
                    $hrOUs = (("OU=" + $xmlData.Name + "," + $DomainRootDN) -split "," -replace "OU=","") -replace "DC=",""
                    for ($i = $hrOUs.count -1 ; $i -ge 0 ; $i--)
                    {
                        $hrOUname += " | " + $hrOUs[$i] 
                    }
                    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> === $hrOUname  already exists"

                } Else {
                    ## Create Root OU
                    $hrOUs = (("OU=" + $xmlData.Name + "," + $DomainRootDN) -split "," -replace "OU=","") -replace "DC=",""
                    for ($i = $hrOUs.count -1 ; $i -ge 0 ; $i--)
                    {
                        $hrOUname += " | " + $hrOUs[$i] 
                    }
                    Try   {
                            New-ADOrganizationalUnit -Name $xmlData.Name -Description $xmlData.Description -Path $DomainRootDN
                            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> +++ $hrOUname created"
                          }
                    Catch {
                            # Failed at creating!
                            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> !!! $hrOUname could not be created!"
                          }
                }
                
                ## Now creating all childs OU
                foreach ($OU in $xmlData.ChildOU)
                {
                   $dbgMess += CreateOU $OU ("OU=" + $xmlData.Name + "," + $DomainRootDN)
                }

                $result = 0

            } else {
     
                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---! Warning: xmlData is empty!"
                $result = 1
            }

        } else {

            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---! Error: could not proceed!"
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
## New-M365OrganizationalUnits                                  ##
## ---------------------------                                  ##
## This function will create the Microsoft 365 Organizational   ##
## units as per user choice.                                    ##
##                                                              ##
## Version: 01.00.000                                           ##
##  Author: loic.veirman@mssec.fr                               ##
##################################################################
Function New-M365OrganizationalUnits
{
   <#
        .Synopsis
         Check and create, if needed, the organizational unit structure required for syncing purpose with Microsoft 365.
        
        .Description
         Will add a specific OU for syncing purpose with M365 - two modes are available with two options:
           1. Mode "SyncByDefault": will generate OU for non-syncing purpose - in this scenario, all objets are synced by design and not syncing them is an exception
           2. Mode "SyncByChoice": will generate OU for syncing purpose - in this scenario, no objects are synced by default and administrators will move selected objects as needed
         
         Wathever the scenario will be, you can choose to let the script create all the OU by discovering objects (mode auto) : in such case, only one mode could be used. 
         Or, you can specify which OU should be modified by using the child element "target" - in such case, each target can be set in any mode.
        
        .Parameter OUName
         Use this parameter to specify the OU name that will be created specifically for syncing purpose with Microsft 365.

        .Parameter CreationMode
         Switch between automatic or manual mode. 
         - Automatic mode will cross the OU tree and generate the sync OU each time it founds a user/computers/groups object within it.
         - Manual mode will use <traget> inputs from the TasksSequence_HardenAD.xml (<Microsoft365>) 

        .Parameter SearchBase
         Used in conjunction with automatic mode to set a base DN from which the script will loop into. If not specified and automatic mode is selected, the RootDN will be used.

        .Notes
         Version: 01.00.000 -- Loic.veirman@mssec.fr
         history: 2021/06.08 - Script creation
    #>
    param(
        [Parameter(mandatory=$true,Position=0)]
        [String]
        $OUName,

        [Parameter(mandatory=$true,Position=1)]
        [ValidateSet("Automatic","Manual")]
        [String]
        $CreationMode,

        [Parameter(mandatory=$False,Position=2)]
        [String]
        $SearchBase

    )
    ## Function: SEARCH-OU
    function Search-OU ($OUPath)
    {
        #.Search for objects in OU
        $ObjectU= Get-ADUser -Filter * -SearchBase $OUPath -SearchScope OneLevel
        $ObjectC = Get-ADComputer -Filter * -SearchBase $OUPath -SearchScope OneLevel
        $ObjectG = Get-ADGroup -Filter * -SearchBase $OUPath -SearchScope OneLevel

        #.if objects found, create the m365 org. unit
        if ($ObjectU -or $ObjectC -or $ObjectG)
        {
            if ([adsi]::Exists(("LDAP://OU=" + $OUName + "," + $OUPath)))
            {
                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> [ANALYZING]: $OUPath - objects found and OU exists (skipped)"
            }
            else
            {
                Try
                {
                    if ($OUPath -notlike "OU=Domain Controllers,*")
                    {
                        New-ADOrganizationalUnit -Name $OUName -Path $OUPath -ProtectedFromAccidentalDeletion $False | Out-Null
                        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> [ANALYZING]: $OUPath - objects found and OU created (success)"
                    }
                    else
                    {
                        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> [ANALYZING]: $OUPath - OU Domain Controllers detected (skipped)"
                    }
                }
                Catch
                {
                    $result = 1
                    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> [ANALYZING]: $OUPath - objects found and OU not created (failed)"
                    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> variable result..........: $result"
                }
            }
        }
        else
        {
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> [ANALYZING]: $OUPath - No objects found (skipped)"
        }
        #.Looking at next child OU, if any. To be compatible with PowerShell 2.0, we need to check $childOUs also.
        $ChildOUs = Get-ADOrganizationalUnit -Filter * -SearchBase $OUPath -SearchScope OneLevel
        if ($childOUs)
        {
            foreach ($ChildOU in $ChildOUs)
            {
                Search-OU -OUPath $ChildOU
            }
        }
        #.return logs
        return $dbgMess
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
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> parameter OUName.........: $OUName"    
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> parameter CreationMode...: $CreationMode"    
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> parameter SearchBase.....: $SearchBase"    

    ## Import xml file with OU build requierment
    Try 
    { 
        [xml]$xmlSkeleton = Get-Content (".\Configs\TasksSequence_HardenAD.xml") -ErrorAction Stop
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> xml skeleton file........: loaded successfully"
        $xmlLoaded = $true
    } 
    Catch 
    {
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---! FAILED loading xml skeleton file "
        $xmlLoaded = $false
    }

    ## When dealing with 2008R2, we need to import AD module first
    $noError = $true
    if ((Get-WMIObject win32_operatingsystem).name -like "*2008*")
    {
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> is windows 2008/R2.......: True"
        
        Try   
        { 
            Import-Module ActiveDirectory
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> OS is 2008/R2, added AD module."    
        } 
        Catch 
        {
            $noError = $false
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---! ERROR! OS is 2008/R2, but the script could not add AD module." 
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> variable noError.........: $noError"
        }
    } 
    else 
    {
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> is windows 2008/R2.......: False"
    }

    ## If xml loaded, build OUs
    If ($xmlLoaded -and $noError)
    {
        ## Success Flag
        $result = 0
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> variable result..........: $result"

        Switch($CreationMode)
        {
            ## Automatic mode
            "Automatic"
            {
                #.Log
                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> [START]..................: automatic mode"
                #.Check prerequesite on SearchBase
                if (-not($SearchBase) -or $SearchBase -eq "")
                {
                    $SearchBase = (Get-ADDomain).DistinguishedName
                }
                else
                {
                    $SearchBase = $SearchBase -replace 'RootDN',((Get-ADDomain).distinguishedName)
                }
                
                #.Check if the base OU exists
                if ([adsi]::exists(("LDAP://" + $SearchBase)))
                {
                    #.Log
                    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> [CHECK]..................: $SearchBase exists"
                    #.Parse OU tree and look for objects
                    $dbgMess += Search-OU -OUPath $SearchBase
                    #.Dealing if warning encountered while processing
                    if ($DbgFile -match 'variable result..........: 1')
                    {
                        $result = 1
                    }
                }
                else
                {
                    $result = 2
                    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> [CHECK]..................: $SearchBase does not exists (error)"
                    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> variable resultCode......: $resultCode"
                }
            }
            ## Manual mode
            "Manual"
            {
                #.Log
                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> [START]..................: manual mode"
                
                #.Getting Targets
                $Targets = $xmlSkeleton.Settings.Microsoft365.target

                #.Looping targets
                foreach ($ztarget in $Targets)
                {
                    $Target = $ztarget -replace 'RootDN',((Get-ADDomain).distinguishedName)
                    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> [ANALYZING]..................: $target"
                    if ([adsi]::Exists(("LDAP://" + $target)))
                    {
                        if ([adsi]::Exists(("LDAP://OU=" + $OUName + "," + $target)))
                        {
                            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> [ANALYZING]..................: $target (already exists)"
                        }
                        else
                        {
                            try
                            {
                                New-ADOrganizationalUnit -Name $OUName -Path $target -ProtectedFromAccidentalDeletion $false | Out-Null
                                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> [ANALYZING]..................: $target created (success)"                                              
                            }
                            catch
                            {
                                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> [ANALYZING]..................: $target not created (failed)"
                                $Result = 1
                            }
                        }
                    }
                    else
                    {
                        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> [ANALYZING]..................: $target does not exists (error)"
                        $Result = 2
                    }
                }
            }
        }
    }
    else
    {
        $result = 2
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Prerequesites............: Failed (error)"
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> variable resultCode......: $resultCode"
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