##################################################################
## New-GpoObject                                                ##
## -------------                                                ##
## This function will import a new gpo from a backup file.      ##
##                                                              ##
## Version: 01.00.000                                           ##
##  Author: loic.veirman@mssec.fr                               ##
##################################################################
Function New-GpoObject
{
    <#
        .Synopsis
         Add all GPOs from the TasksSequence_HardenAD.xml.
        
        .Description
         The TasksSequence_HardenAD.xml file contain a section named <GPO>: this section will be readen by the script and every input will be added to the target domain.
        
        .Notes
         Version: 
            01.00 -- Loic.veirman@mssec.fr
         
         history: 
            01.00 -- Script creation
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
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Function caller.............: " + (Get-PSCallStack)[1].Command
    
    ## When dealing with 2008R2, we need to import AD module first
    if ((Get-WMIObject win32_operatingsystem).name -like "*2008*")
    {
        Try { 
            Import-Module ActiveDirectory
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> OS is 2008/R2, added AD module."    
        } Catch {
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---! ERROR! OS is 2008/R2, but the script could not add AD module."   
        }
        Try { 
            Import-Module GroupPolicy
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> OS is 2008/R2, added GroupPolicy module."    
        } Catch {
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---! ERROR! OS is 2008/R2, but the script could not add GroupPolicy module."   
        }
    }
    
    ## Get Current Location
    $curDir = (Get-Location).Path
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> parameter curDir............: $curDir"

    ## loading configuration file
    Try {
        $xmlFile  = [xml](Get-Content .\Configs\TasksSequence_HardenAD.xml)
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> TasksSequence_HardenAD.xml..: loaded successfully"
        $Result = 0
    } Catch {
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> TasksSequence_HardenAD.xml..: error! load failed!"
        $Result = 2
    }
    
    ## Recovering GPOs data
    $GpoData = $xmlFile.Settings.GroupPolicies.GPO
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Total number of GPO found...: " + $GpoData.Count

    ## Analyzing and processing
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> Analyze begins"

    if ($Result -ne 2)
    {
        foreach ($Gpo in $GpoData)
        {
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> ========================"
        
            #.Recovering data
            $gpName = $Gpo.Name
            $gpDesc = $Gpo.Description
            $gpVali = $Gpo.Validation
            $gpBack = $Gpo.GpoBackup.ID
        
            #.Logging
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> GPO name.......: $gpName"
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> GPO description: $gpDesc"
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> GPO backup ID..: $gpBack"
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> GPO validation.: $gpVali"
        
            #.Check if the GPO already exists
            $gpChek = Get-GPO -Name $gpName -ErrorAction SilentlyContinue

            if ($gpChek)
            {
                #.GPO exists, so updating comment to keep a trace of gpContent rewriting.
                #.Not working yet.
                #(Get-GPO $gpChek.ID).Description += "`nGPO replaced by backup from HardenAD on " + (Get-Date -Format "yyyy/MM//dd at hh:mm:ss")
                #.Set flag
                $gpFlag = $true
                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> GPO exists.....: true"
            } Else {
                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> GPO exists.....: false"
                #.Create empty GPO
                Try {
                    $null = New-Gpo -Name $gpName -Comment $gpDesc -ErrorAction SilentlyContinue
                    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> GPO creation...: success"
                    $gpFlag = $true
                } Catch {
                    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> GPO creation...: failed!"
                    $gpFlag = $false
                    $result = 1
                    $errMess += " Failed to create at least one GPO."
                }
            }

            #.If no issue, time to import data, set deny mermission and, if needed, link the GPO
            if ($gpFlag)
            {
                #.Import backup
                try {
                    $null = Import-GPO -BackupId $gpBack -TargetName $gpName -MigrationTable $curDir\Inputs\GroupPolicies\translated.migtable -Path $curDir\Inputs\GroupPolicies -ErrorAction Stop
                    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> GPO import.....: success"
                    $importFlag = $true
                } Catch {
                    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> GPO import.....: failed!"
                    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> GPO import.....: [debug]  Import-GPO -BackupID '$gpBack' -TargetName $GpName -MigrationTable $curDir\Inputs\GroupPolicies\translated.migtable -Path $curDir\Inputs\GroupPolicies -ErrorAction Stop"
                    $result = 1
                    $errMess += " Failed to import at least one GPO."
                    $importFlag = $false
                }

                #.Assign Wmi Filter, if any
                if ($importFlag)
                {
                    #.check for filter data
                    $gpFilter = $Gpo.GpoFilter
                    if ($gpFilter)
                    {
                        #.Prepare data
                        $FilterName = $gpFilter.WMI
                        $DomainName = (Get-ADDomain).DnsRoot
                        $GpoRawData = Get-GPO -Name $gpName 
                        $wmiFilter  = Get-ADObject -Filter { msWMI-Name -eq $FilterName } -ErrorAction SilentlyContinue
                        $GpoDN      = "CN={" + $GpoRawData.Id + "},CN=Policies,CN=System," + (Get-ADDomain).DistinguishedName
                        $wmiLinkVal = "[" + $DomainName + ";" + $wmiFilter.Name + ";0]"

                        #.log this
                        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> WMI Filter.....: [debug]FilterName = $FilterName"
                        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> WMI Filter.....: [debug]DomainName = $DomainName"
                        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> WMI Filter.....: [debug]wmiFilter  = $wmiFilter"
                        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> WMI Filter.....: [debug]GpoDN      = $GpoDN"
                        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> WMI Filter.....: [debug]wmiLinkVal = $wmiLinkVal"

                        #.Check if there is already a value
                        $hasFilter = (Get-ADObject $GpoDN -Properties gPCWQLFilter).gPCWQLFilter

                        Try {
                            if ($hasFilter)
                            {
                                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> WMI Filter.....: this GPO has a Filter in place"
                                Set-ADObject $GpoDN -replace @{gPCWQLFilter=$wmiLinkVal}
                                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> WMI Filter.....: filter $FilterName applied (replace)"
                            } else {
                                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> WMI Filter.....: this GPO has no Filter in place"
                                Set-ADObject $GpoDN -Add @{gPCWQLFilter=$wmiLinkVal}
                                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> WMI Filter.....: filter $FilterName applied (add)"
                            }
                        } Catch {
                                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> WMI Filter.....: Error! Could not set the wmi filter!"
                                $Result = 1
                        }
                    } else {
                        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> WMI Filter.....: none"
                    }
                }

                #.Set Deny permission
                #.The if is only here for legacy compatibility with 2k8r2 and pShell 2.0.
                if($GPO.GpoDeny)
                {
                    foreach ($deniedID in $GPO.GpoDeny)
                    {
                        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> DENY ID........: " + $DeniedID.ID
                    
                        $targetID = ($deniedID.ID -replace '%domSid%',((Get-ADDomain).domainSID)) -replace '%SecPri%','S-1-5'
                    
                        $isSID = $false
                        $isPRI = $false

                        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> DENY ID........: translated to $targetID" 

                        if ($targetID -match ((Get-ADDomain).domainSID))  
                        { 
                            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> DENY ID........: the specified ID is a SID"
                            $isSID = $true
                            $DenyID = Get-ADObject -filter { objectsid -eq $targetID } -Properties samAccountName
                            $NtAcct = (Get-ADDomain).NetBIOSName + "\" + $DenyID.samAccountName
                            $NBName = [System.Security.Principal.NTAccount]$NtAccount
                        
                            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> DENY ID........:  matched to $NBName"
                        } 

                        if ($targetID -match "S-1-5")
                        {
                            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> DENY ID........: the specified ID is a principal security"
                            $isPRI = $true
                            $sidAcc = new-object System.Security.Principal.SecurityIdentifier($targetID)
                            $NBName = $sidAcc.Translate([System.Security.Principal.NTAccount])
                        
                            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> DENY ID........:  matched to $NBName"
                        }
        
                        if ( -not ($isSID) -and -not ($isPRI))
                        { 
                            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> DENY ID........: the specified ID is a samAccountName"

                            $DenyID = Get-ADObject -filter { SamAccountName -eq $targetID } -Properties samAccountName
                            $NtAcct = (Get-ADDomain).NetBIOSName + "\" + $DenyID.samAccountName
                            $NBName = [System.Security.Principal.NTAccount]$NtAccount
                        
                            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> DENY ID........:  matched to $NBName"
                        }

                        #.Applying deny permission
                        Try {
                            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> DENY ID........: Start new ACL rule"

                            $mygpo  = Get-GPO -Name $GpName
                            $adgpo  = [ADSI]("LDAP://CN=`{$($mygpo.Id.guid)`},CN=Policies,CN=System," + (Get-ADDomain).DistinguishedName)

                            $rule   = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($NBName, "ExtendedRight", "Deny", [Guid]"edacfd8f-ffb3-11d1-b41d-00a0c968f939")
        
                            $acl = $adgpo.ObjectSecurity
                            $acl.AddAccessRule($rule)
                            $adgpo.CommitChanges()

                            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> DENY ID........: Deny Permission applied successfully"
                        } Catch {
                            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> DENY ID........: Deny Permission failed to be applied!"
                            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> DENY ID........: [DEBUG] ADGPO = [ADSI](LDAP://CN=`{" + $mygpo.Id.guid + "`},CN=Policies,CN=System," + (Get-ADDomain).DistinguishedName + ")"
                            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> DENY ID........: [DEBUG] RULE  = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($NBName, ""ExtendedRight"", ""Deny"", [Guid]""edacfd8f-ffb3-11d1-b41d-00a0c968f939"")"
                            $result = 1
                            $errMess += " Error: could not apply the deny permission on one or more GPO"
                        }
                    }
                }
                #.Linking to the target OU
                if ($gpVali -eq "yes")
                {
                    foreach ($gpLink in $GPO.GpoLink)
                    {
                       $gpPath = $gpLink.Path -replace 'RootDN',((Get-ADDomain).DistinguishedName)
                        #.Test if already linked
                        $gpLinked = Get-ADObject -Filter { DistinguishedName -eq $gpPath } -Properties gpLink | Select-Object -ExpandProperty gpLink | Where-Object { $_ -Match ("LDAP://CN={" + (Get-Gpo -Name $gpName).ID + "},") }
                        if ($gpLinked)
                        {
                            Try {
                                $null = Set-GPLink -Name $gpName -Target $gpPath -LinkEnabled $gpLink.Enabled -Enforced $gpLink.enforced -ErrorAction Stop
                            
                                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> GPO LINK.......: Successfully updated link to $gpPath (Enabled: " + $gpLink.Enabled + ",Enforced: " + $gpLink.Enforced + ")"

                            } Catch {
                                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> GPO LINK.......: Failed! Not linked to $gpPath"
                                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> GPO LINK.......: [DEBUG] gpPath = """ + $gpLink.Path + """ -replace 'RootDN',(" + (Get-ADDomain).DistinguishedName + ")"
                                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> GPO LINK.......: [DEBUG] gpPath = ""$gpPath"""
                                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> GPO LINK.......: [DEBUG] Execute: Set-GPLink -Name ""$gpName"" -Target ""$gpPath"" -LinkEnabled " + $gpLink.Enabled + " -Enforced " + $gpLink.enforced + " -ErrorAction Stop"
                                $result = 1
                                $errMess += " Error: could not link one or more GPO"
                            }
                        } Else {
                            Try {
                                $null = New-GPLink -Name $gpName -Target $gpPath -LinkEnabled $gpLink.Enabled -Enforced $gpLink.enforced -ErrorAction Stop
                            
                                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> GPO LINK.......: Successfully linked to $gpPath (Enabled: " + $gpLink.Enabled + ",Enforced: " + $gpLink.Enforced + ")"

                            } Catch {
                                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> GPO LINK.......: Failed! Not linked to $gpPath"
                                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> GPO LINK.......: [DEBUG] gpPath = """ + $gpLink.Path + """ -replace 'RootDN',(" + (Get-ADDomain).DistinguishedName + ")"
                                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> GPO LINK.......: [DEBUG] gpPath = ""$gpPath"""
                                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> GPO LINK.......: [DEBUG] Execute: New-GPLink -Name ""$gpName"" -Target ""$gpPath"" -LinkEnabled " + $gpLink.Enabled + " -Enforced " + $gpLink.enforced + " -ErrorAction Stop"
                                $result = 1
                                $errMess += " Error: could not link one or more GPO"
                            }
                        }
                    }
                } else {
                    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> GPO LINK.......: authorization not granted by the script (skipped)"
                }
            }
        }

    } Else {
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> ERROR: operation canceled"
        $errMess = "Failed to load powerShell modules - canceled."
    }

    ##########
    ## Exit ##
    ##########
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

    ## Return function results
    return (New-Object -TypeName psobject -Property @{ResultCode = $result ; ResultMesg = $ResMess ; TaskExeLog = $ResMess })
}

##################################################################
## Convert-MigrationTable                                       ##
## ----------------------                                       ##
## This function will prepare the migration table file for GPO  ##
## import                                                       ##
##                                                              ##
## Version: 01.00.000                                           ##
##  Author: loic.veirman@mssec.fr                               ##
##################################################################
Function Convert-MigrationTable
{
    <#
        .SYNPOSIS
            This function will replace the specified name in a .migTable file to the target one.

        .DETAILS
            GPO imported from a dev domain will contains unknown principals. To remediate this when restoring parameters,
            this function search on %objectName% and replace it with the corresponding SID in the target domain.
            The function return the XML data.

        .PARAMETER ObjectToTranslate
            Object name to translate.

        .PARAMETER ObjectCategory
            is User, Group, ...

        .PARAMETER XmlData
            Xml file to use for replacement

        .NOTES
            Version: 01.00
            Author.: loic.veirman@mssec.fr - MSSEC
            Desc...: Function creation.
    #>

    Param(
        [Parameter(mandatory=$true)]
        [String]
        $ObjectToTranslate,

        [Parameter(mandatory=$true)]
        [ValidateSet('User','Group','Domain','UNCPath')]
        [String]
        $ObjectCategory,

        [Parameter(mandatory=$true)]
        $xmlData
    )

    ## Function Log Debug File
    $DbgFile = 'Debug_{0}.log' -f $MyInvocation.MyCommand
    $dbgMess = @()

    ## Start Debug Trace
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "****"
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "**** FUNCTION STARTS"
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "****"

    ## Indicates caller and options used
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Function caller...............: " + (Get-PSCallStack)[1].Command
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> parameter ObjectToTranslate...: $ObjectToTranslate"
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> parameter ObjectCategory......: $ObjectCategory"

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


    ## Switch on category
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "------> Switching on ObjectCategory"
    Switch ($ObjectCategory)
    {
        'User'    { $result = $xmlData -replace "%$ObjectToTranslate%",(Get-ADUser  $ObjectToTranslate).SID 
                    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "------> debug: new User.: " + (Get-ADUser  $ObjectToTranslate).SID 
                  }
        'Group'   { $result = $xmlData -replace "%$ObjectToTranslate%",(Get-ADGroup $ObjectToTranslate).SID 
                    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "------> debug: new Group: " + (Get-ADGroup $ObjectToTranslate).SID 
                  }
        'Domain'  { $result = $xmlData -replace "%$ObjectToTranslate%",((Get-ADDomain).NetBIOSName + "\$ObjectToTranslate")
                    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "------> debug: new SName: " + (Get-ADDomain).NetBIOSName + "\$ObjectToTranslate"
                  }
        'UNCPath' { $result = $xmlData -replace "%$ObjectToTranslate%",(Get-ADDomain).DNSRoot
                    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "------> debug: new UNCp.: " + (Get-ADDomain).DNSRoot
                  }
    }

    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "------> Switching done"
    
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

    ## Return translated xml
    return $result
}

##################################################################
## Update-PreferenceXML                                         ##
## --------------------                                         ##
## This function will modify GPO backup files by replacing SID  ##
## from another domain to the production domain one.            ##
##                                                              ##
## Version: 01.00.000                                           ##
##  Author: loic.veirman@mssec.fr                               ##
##################################################################
Function Update-PreferenceXML
{
    <#
        .SYNPOSIS
            This function will look after XML file in "preference" folder and replace any identified occurences.

        .DETAILS
            GPO imported from a dev domain will contains unknowns principal. To remediate this when restoring parameters,
            this function search on %objectName% and replace it with the corresponding SID in the target domain.
            The function return the XML data.

        .NOTES
            Version: 01.00
            Author.: loic.veirman@mssec.fr - MSSEC
            Desc...: Function creation.
    #>
	
	Param (
        [Parameter(mandatory=$true)]
        [string]
        $SourcePrefTable
	)
	
	## Function Log Debug File
	$DbgFile = 'Debug_{0}.log' -f $MyInvocation.MyCommand
	$dbgMess = @()
	
	## Start Debug Trace
	$dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "****"
	$dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "**** FUNCTION STARTS"
	$dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "****"
	
	## Indicates caller and options used
	$dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Function caller...............: " + (Get-PSCallStack)[1].Command
	
	## Ensure that a translation table is present
	if (Test-Path .\inputs\GroupPolicies\$SourcePrefTable)
	{
		$dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Reference base prefTable......: .\inputs\GroupPolicies\$SourcePrefTable is present."
		$refTable = Get-Content .\inputs\GroupPolicies\$SourcePrefTable
		$noError  = $true
	}
	else
	{
		$dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Reference base prefTable......: .\inputs\GroupPolicies\$SourcePrefTable is missing!"
		$noError = $false
	}

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

	
	## if no error, generating in memeory a translation table
	if ($noError)
    {
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> starting translation process..:"
	    $newIDs = @()
	    foreach ($line in $refTable)
	    {
		    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "------> Raw data: $line"
		
            $rawData  = $line -Split ';'
		    $newName  = $rawData[1] -replace ($rawData[1] -split '\\')[0],(Get-ADDomain).NetBIOSName
		
            switch ($rawData[0])
		    {
			    "Group" { $newSid = (Get-ADGroup -Identity ($rawData[1] -split "\\")[1]).SID }
			    "User"  { $newSid = (Get-ADUser  -Identity ($rawData[1] -split "\\")[1]).SID }
			    Default { $newSid = $null }
		    }
		    $newIDs += ($line + ";$newName;$newSid") -replace "\\","\\"

		    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "------> New data: $line;$newName;$newSid"
	    }
	
	    ## Begining to look at replacement...
        ## This is a legacy code, written specifically to be compatible with PShell 2.0
	    $BackupGPOs = Get-ChildItem .\inputs\GroupPolicies | Where-Object { $_.PSIsContainer -eq $true }

	    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "------> Analyzing GPOs:"

        foreach ($GPO in $BackupGPOs)
	    {
		    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---------> Dealing with GPO id " + $GPO.Name + ":"

		    $Looking = ".\inputs\groupPolicies\" + $GPO.Name + "\DomainSysvol\GPO\Machine\Preferences"

		    if (Test-Path $Looking)
		    {
			    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "------------> Folder Machine Preferences is present: looking for XML..."
			
                #$xmls = Get-ChildItem -Recurse -Path $Looking\*.xml
			    $xmls = Get-ChildItem -Recurse -Path ($Looking) | where { $_.Name -like "*.xml" }

                if ($xmls)
			    {
				    foreach ($xml in $xmls)
				    {
					    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---------------> working on " + $xml.FullName
					
					    $rawXML = Get-Content $xml.FullName

                        foreach ($line in $newIDs)
					    {
						    $lineData = $line -split ";"
						
                            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "------------------> replacing " + $lineData[1] + " with " +  $lineData[3] + " and " + $lineData[2] + " with " + $lineData[4]
                            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "------------------> Before: " + $rawXML 
                            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "------------------> After.: " + (($rawXML -replace "\\","\\") -replace ($lineData[1]),($lineData[3])) -replace ($lineData[2]),($lineData[4])

                            #.The '\' is considered as an escapment character and need to be doubled. 
                            #.Once the conversion is done, you'll have to remove the double \\ added.
                            $rawXML = (($rawXML -replace $lineData[1],$lineData[3]) -replace $lineData[2],$lineData[4]) -replace "\\\\","\"

					    }
					    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "------------------> rewriting file " + $xml.FullName
					
                        Set-Content -Path $xml.FullName -Value $rawXML 
				    }
			    }
			    else
			    {
				    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---------------> no XML found"
			    }
		    }
		    else
		    {
			    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "------------> Folder Machine Preferences is not present"
		    }
		
		    $Looking = ".\inputs\GroupPolicies\" + $GPO.Name + "\DomainSysvol\GPO\User\Preferences"

		    if (Test-Path $Looking)
		    {
			    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "------------> Folder User Preferences is present: looking for XML..."

			    #$xmls = Get-ChildItem -Recurse -Path $Looking\*.xml
                $xmls = Get-ChildItem -Recurse -Path ($Looking) | where { $_.Name -like "*.xml" }

			    if ($xmls)
			    {
				    foreach ($xml in $xmls)
				    {
					    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---------------> working on " + $xml.FullName

					    $rawXML = Get-Content $xml.FullName

					    foreach ($line in $newIDs)
					    {
						    $lineData = $line -split ";"
						
                            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "------------------> replacing " + $lineData[1] + " with " + $lineData[3] + " and " + $lineData[2] + " with " + $lineData[4]
                            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "------------------> Avant: " + $rawXML 
                            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "------------------> Apres: " + (($rawXML -replace "\\","\\") -replace $lineData[1],$lineData[3]) -replace $lineData[2],$lineData[4]
						
                            #.The '\' is considered as an escapment character and need to be doubled. 
                            #.Once the conversion is done, you'll have to remove the double \\ added.
                            $rawXML = (($rawXML -replace $lineData[1],$lineData[3]) -replace $lineData[2],$lineData[4]) -replace "\\\\","\"
					    }

					    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "------------------> rewriting file " + $xml.FullName

                        Set-Content -Path $xml.FullName -Value $rawXML 
				    }
			    }
			    else
			    {
				    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---------------> no XML found"
			    }
		    }
		    else
		    {
			    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "------------> Folder User Preferences is not present"
		    }
		
	    }
        $Result = 0
    }
    Else 
    {
	    $Result = 2
        $ResMess = "File missing"
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
	
	## Return translated xml
	return (New-Object -TypeName psobject -Property @{ResultCode = $result ; ResultMesg = $ResMess ; TaskExeLog = $ResMess })
}

##################################################################
## Publish-MigrationTable                                       ##
## ----------------------                                       ##
## This function will generate a migration table file for GPO   ##
## import                                                       ##
##                                                              ##
## Version: 01.00.000                                           ##
##  Author: loic.veirman@mssec.fr                               ##
##################################################################
Function Publish-MigrationTable
{
    <#
        .SYNPOSIS
            This function generate the .migtable file to be used by GPO.

        .DETAILS
            the .migtable file is generic and contains value to be translated before being used by New-GpoObject.

        .PARAMETER SourceMigTable
            Source file to read from.

        .NOTES
            Version: 01.00
            Author.: loic.veirman@mssec.fr - MSSEC
            Desc...: Function creation.
    #>

    Param(
        [Parameter(mandatory=$true)]
        [String]
        $SourceMigTable
    )

    ## Function Log Debug File
    $DbgFile = 'Debug_{0}.log' -f $MyInvocation.MyCommand
    $dbgMess = @()

    ## Start Debug Trace
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "****"
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "**** FUNCTION STARTS"
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "****"

    ## Indicates caller and options used
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Function caller................: " + (Get-PSCallStack)[1].Command
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> parameter SourceMigTable.......: $SourceMigTable"

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

    ## Loading file
    $resultat = 0
    if (Test-Path .\Inputs\GroupPolicies\$SourceMigTable)
    {
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> -------------------------------> Source File is present"
        Try   {
                $xmlData = Get-Content .\Inputs\GroupPolicies\$SourceMigTable -ErrorAction Stop
                $LoadFile = $true
                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> -------------------------------> Source File loaded to xmlData"
              }
        Catch {
                $LoadFile = $false
                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> -------------------------------> Source File could not be loaeded!"
                $resultat = 1
              }
    }
    else
    {
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> -------------------------------! Source File is missing!"
        $LoadFile = $false
        $resultat = 2
    }

    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Parameter LoadFile.............: $LoadFile"

    ## Loading translation table
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Loading file...................: TasksSequence_HardenAD.xml"
    Try   {
            $xmlFile = [xml](Get-Content .\Configs\TasksSequence_HardenAD.xml -ErrorAction Stop)
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> -------------------------------> TasksSequence_HardenAD.xml loaded successfully"
            $LoadXml = $true
          }
    Catch {
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> -------------------------------! TasksSequence_HardenAD.xml could not be loaded!"
            $LoadXml = $false
            $resultat++
          }

    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Parameter LoadXml..............: $LoadXml"

    ## Translating
    if ($LoadXml -and $LoadFile)
    {
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> [Begin migTable translation]"
        foreach ($element in ($xmlFile.settings.GroupPolicies.translation.Object))
        {
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Translating raw data....: [" + $element.class + "] " + $element.name 

            $obj = $element.name
            $Cat = $element.class

            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> ------> Object Name......: $obj"
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> ------> Object Category..: $Cat"

            $xmlData = Convert-MigrationTable -ObjectToTranslate $obj -ObjectCategory $Cat -xmlData $xmlData
        }

        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> [End xml translation]"
    }

    ## Exporting
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Exporting file.................: begin"
    try   {
            $noEchoe  = $xmlData | Out-File .\Inputs\GroupPolicies\translated.migtable -Force 
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Exporting file.................: success"
          }
    Catch {
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Exporting file.................: failed!"
            $resultat = 2
          }
    
    ## Exit
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> function return RESULT: $Resultat"
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

    ## Return translated xml
    return (New-Object -TypeName psobject -Property @{ResultCode = $resultat ; ResultMesg = $ResMess ; TaskExeLog = $ResMess })
}

##################################################################
## Import-WmiFilters                                            ##
## -----------------                                            ##
## This function will import wmi filters from backup files.     ##
##                                                              ##
## Version: 01.00.000                                           ##
##  Author: loic.veirman@mssec.fr                               ##
##################################################################
Function Import-WmiFilters
{
        <#
        .SYNPOSIS
            This function import OMF files to the domain and add requiered wmi filter.

        .DETAILS
            This function import OMF files to the domain and add requiered wmi filter.

        .NOTES
            Version: 01.00
            Author.: loic.veirman@mssec.fr - MSSEC
            Desc...: Function creation.
    #>

    Param(
        [Parameter(mandatory=$true)]
        [String]
        $sourceDomain
    )

    ## Function Log Debug File
    $DbgFile = 'Debug_{0}.log' -f $MyInvocation.MyCommand
    $dbgMess = @()

    ## Start Debug Trace
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "****"
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "**** FUNCTION STARTS"
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "****"

    ## Indicates caller and options used
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Function caller................: " + (Get-PSCallStack)[1].Command

    ## When dealing with 2008R2, we need to import AD module first
    if ((Get-WMIObject win32_operatingsystem).name -like "*2008*")
    {
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> is windows 2008/R2.............: True"
        
        Try   { 
                Import-Module ActiveDirectory
                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> OS is 2008/R2, added AD module."    
              } 
        Catch {
                $noError = $false
                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---! ERROR! OS is 2008/R2, but the script could not add AD module." 
                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> variable noError.........: $noError"
                }
    } else {
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> is windows 2008/R2..........: False"
    }

    ## Get Current Location
    $curDir = (Get-Location).Path
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> parameter curDir............: $curDir"

    ## loading configuration file
    Try {
        $xmlFile  = [xml](Get-Content .\Configs\TasksSequence_HardenAD.xml)
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> TasksSequence_HardenAD.xml..: loaded successfully"
        $Resultat = 0
    } Catch {
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> TasksSequence_HardenAD.xml..: error! load failed!"
        $Resultat = 2
        $ResMess = "could not load xml configuration file."
    }

    if ($resultat -ne 2)
    {
        ## Begin WMI filter importation
        $WmiFilters = $xmlFile.settings.groupPolicies.wmiFilters
        $CurrWmiFtr = Get-ADObject -Filter { ObjectClass -eq 'msWMI-Som' } -Properties *
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Number of WMI Filters found.: " + $WmiFilters.Filter.count

        foreach ($filterData in $WmiFilters.filter)
        {
            ## Check if already exists
            ## some interesting stuff: http://woshub.com/group-policy-filtering-using-wmi-filters/
            if ($CurrWmiFtr.'msWMI-Name' -match $filterData.Name)
            {
                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> " + $filterData.Name + ": already exists (no additionnal step)"
            } else {
                ## Tips really usefull from the-wabbit: 
                ## https://serverfault.com/questions/919297/importing-gpo-wmi-filter-mof-file
                
                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> " + $filterData.Name + ": not present"

                $mofPath = $curDir + "\inputs\GroupPolicies\WmiFilters\" + $filterData.Source

                #.Rewriting data to fetch to the new domain
                (Get-Content $mofPath) -Replace $sourceDomain,((Get-ADDomain).DNSRoot) | Out-File $mofPath -Force

                try {
                    $null = Start-Process "mofcomp.exe" -ArgumentList "-N:root\Policy",$mofPath -Wait
                    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> " + $filterData.Name + ": successfully added to the domain"
                } Catch {
                    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> " + $filterData.Name + ": error! Could not add the filter!"
                    $Resultat = 1
                    $ResMess = "Some filter were not imported successfully."
                }
            }
        }
    }

    ## Exit
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> function return RESULT: $Resultat"
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

    ## Return translated xml
    return (New-Object -TypeName psobject -Property @{ResultCode = $resultat ; ResultMesg = $ResMess ; TaskExeLog = $ResMess })
}

Export-ModuleMember -Function * 