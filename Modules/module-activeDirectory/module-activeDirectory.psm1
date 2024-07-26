#region SET-HardenACL
Function Set-HardenACL { 
    <#
        .SYNOPSIS
        Function use to setup ACL for delegation purpose

        .DESCRIPTION
        This function has 2 modes :
        1 : We use the -inheritedObjects argument and the ACL will be inherited only by this type of object (ex : User has full controll over all child objects of type group)
        2 : We use the -ObjectType argument and the ACL will apply to this type of object (ex : User can create/delete all Child objects of type group)

        .PARAMETER TargetDN
        DN of the object on whoch we put the ACL

        .PARAMETER Trustee
        Name of the group/user which will have the ACL

        .PARAMETER Right
        Right(s) to give with the ACL

        .PARAMETER RightType
        Allow or Deny

        .PARAMETER Inheritance
        Inheritance : All / Descendents objects

        .PARAMETER InheritedObjects
        Which type of object will inherit

        .PARAMETER ObjectType
        To which type of object the acl will apply (group, user, computer, member or contact)

        .NOTES
        Version derived from Harden AD Enterprise 2.8.0
    #>
    param(
        [Parameter(Position = 1 , Mandatory = $true, HelpMessage = "DN of the object on whoch we put the ACL")]
        [ValidateNotNullOrEmpty()]
        [string]
        $TargetDN,
    
        [Parameter(Position = 2 , Mandatory = $true, HelpMessage = "Name of the group/user which will have the ACL")]
        [ValidateNotNullOrEmpty()]
        [string]
        $Trustee,
        [Parameter(Position = 3 , Mandatory = $true, HelpMessage = "Right(s) to give with the ACL")]
        [ValidateNotNullOrEmpty()]
        [string]
        $Right,
    
        [Parameter(Position = 4 , Mandatory = $true, HelpMessage = "Allow or Deny")]
        [ValidateNotNullOrEmpty()]
        [string]
        $RightType,
    
        [Parameter(Position = 5 , Mandatory = $true, HelpMessage = "Inheritance : All / Descendents objects")]
        [ValidateNotNullOrEmpty()]
        [string]
        $Inheritance,
    
        [Parameter(Position = 6  , Mandatory = $false, HelpMessage = "Which type of object will inherit")]
        [string]
        $InheritedObjects,
    
        [Parameter(Position = 7  , Mandatory = $false, HelpMessage = "To which type of object the acl will apply")]
        [ValidateSet("group", "user", "computer", "contact", "member")]
        [string]
        $ObjectType,
        [Parameter(Position = 8, Mandatory = $false, HelpMessage = "Audit ACL")]
        [switch]
        $AuditSwitch
    )
    #.Move location to AD to simplify AD manipulation
    Push-Location AD:
    try {            
        if ($inheritedObjects -ne "" -and $Null -ne $inheritedObjects) {
            switch ($inheritedObjects) {
                "group" { $inheritanceguid = New-Object Guid bf967a9c-0de6-11d0-a285-00aa003049e2 }
                "user" { $inheritanceguid = New-Object Guid bf967aba-0de6-11d0-a285-00aa003049e2 }
                "computer" { $inheritanceguid = New-Object Guid bf967a86-0de6-11d0-a285-00aa003049e2 }
                "contact" { $inheritanceguid = New-Object Guid 5cb41ed0-0e4c-11d0-a286-00aa003049e2 }
                "member" { $inheritanceguid = New-Object Guid bf9679c0-0de6-11d0-a285-00aa003049e2 }
            }
        }
        else {
            $inheritanceguid = New-Object Guid 00000000-0000-0000-0000-000000000000
        }

        if ($ObjectType -ne "" -and $Null -ne $ObjectType) {
            switch ($ObjectType) {
                "group" { $Objectguid = New-Object Guid bf967a9c-0de6-11d0-a285-00aa003049e2 }
                "user" { $Objectguid = New-Object Guid bf967aba-0de6-11d0-a285-00aa003049e2 }
                "computer" { $Objectguid = New-Object Guid bf967a86-0de6-11d0-a285-00aa003049e2 }
                "contact" { $Objectguid = New-Object Guid 5cb41ed0-0e4c-11d0-a286-00aa003049e2 }
                "member" { $Objectguid = New-Object Guid bf9679c0-0de6-11d0-a285-00aa003049e2 }
            }
        }
        else {
            $Objectguid = New-Object Guid 00000000-0000-0000-0000-000000000000
        }

        switch ($Trustee) {
            ("Authenticated Users") { 
                $SID = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-11")
            }
            Default {
                $group = Get-ADGroup $trustee
                $SID = New-Object System.Security.Principal.SecurityIdentifier $($group.SID)
            }
        }
        
        $identity = [System.Security.Principal.IdentityReference] $SID
        $adRights = [System.DirectoryServices.ActiveDirectoryRights] $right
        $inheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance] $inheritance

        if ($AuditSwitch) {
            $acl = Get-Acl ("AD:\" + $targetDN) -Audit

            $type = [System.Security.AccessControl.AuditFlags] $rightType
            $Parameters = $identity, $adRights, $type, $Objectguid, $inheritanceType, $inheritanceguid

            $ace = New-Object System.DirectoryServices.ActiveDirectoryAuditRule($Parameters)
            $acl.AddAuditRule($ace)
        }
        else {
            $acl = Get-Acl ("AD:\" + $targetDN)
            
            $type = [System.Security.AccessControl.AccessControlType] $rightType
            $Parameters = $identity, $adRights, $type, $Objectguid, $inheritanceType, $inheritanceguid
            
            $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($Parameters)
            $acl.AddAccessRule($ace)
        }

        Set-Acl -AclObject $acl -Path ("AD:\" + ($targetDN)) -ErrorAction SilentlyContinue
        
        $Result = $true
    }
    catch {
        $Result = $False
    }
    #.Reset location 
    Pop-Location
    #.Return result
    Return $Result
}
#endregion

#region Push-DelegationModel
Function Push-DelegationModel {
    <#
        .SYNOPSIS
        Apply the delegation model to the domain.
        
        .DESCRIPTION
        Read <DelegationACEs> and apply permission.

        .NOTES
        Version: 
            01.00 -- contact@hardenad.net 
        
        history: 
            01.00 -- Script creation        
    #>
    Param(
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

    ## Main action
    ## Import xml file with OU build requierment
    Try { 
        [xml]$xmlSkeleton = Get-Content (".\Configs\TasksSequence_HardenAD.xml") -ErrorAction Stop
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> xml skeleton file........: loaded successfully"
        $xmlLoaded = $true
    }
    Catch {
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---! FAILED loading xml skeleton file "
        $xmlLoaded = $false
    }    

    ## If xml loaded, begining check and create...
    if ($xmlLoaded) {
        ## Log loop start
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> variable XmlLoaded.......: $xmlLoaded"
        
        ## Creating a variable to monitor failing tasks
        $noError = $true
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> variable noError.........: $noError"
        
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

        ## if Everything run smoothly, let's begin.
        if ($noError) {
            ## Getting root DNS name
            $DomainRootDN = (Get-ADDomain).DistinguishedName
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Parameter DomainRootDN...: $DomainRootDN"

            ## Getting specified schema for ACL
            $xmlData = $xmlSkeleton.settings.DelegationACEs.ACL
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> .........................: xml data loaded (" + $xmlData.count + " ACL(s))"
            
            ## if we got data, begining creation loop
            if ($xmlData) {
                #-Failing Creation index
                $ErrIdx = 0
                
                #.Begin object creation loop
                foreach ($HADacl in $xmlData) {
                    Switch ($HADacl.InheritedObjects) {
                        "" {
                            if ($HADacl.Audit) {
                                Set-HardenACL -TargetDN        ($HADacl.TargetDN -replace "RootDN", $DomainRootDN) `
                                    -Trustee          $HADacl.Trustee `
                                    -Right            $HADacl.Right`
                                    -RightType        $HADacl.RightType`
                                    -Inheritance      $HADacl.Inheritance`
                                    -ObjectType       $HADacl.ObjectType `
                                    -AuditSwitch
                            }
                            else {
                                $result = Set-HardenACL -TargetDN        ($HADacl.TargetDN -replace "RootDN", $DomainRootDN) `
                                    -Trustee          $HADacl.Trustee `
                                    -Right            $HADacl.Right`
                                    -RightType        $HADacl.RightType`
                                    -Inheritance      $HADacl.Inheritance`
                                    -ObjectType       $HADacl.ObjectType
                            }
                        }
                        Default {
                            if ($HADacl.Audit) {
                                $result = Set-HardenACL -TargetDN        ($HADacl.TargetDN -replace "RootDN", $DomainRootDN) `
                                    -Trustee          $HADacl.Trustee `
                                    -Right            $HADacl.Right `
                                    -RightType        $HADacl.RightType `
                                    -Inheritance      $HADacl.Inheritance `
                                    -InheritedObjects $HADacl.InheritedObjects `
                                    -AuditSwitch
                            }
                            else {
                                $result = Set-HardenACL -TargetDN        ($HADacl.TargetDN -replace "RootDN", $DomainRootDN) `
                                    -Trustee          $HADacl.Trustee `
                                    -Right            $HADacl.Right`
                                    -RightType        $HADacl.RightType`
                                    -Inheritance      $HADacl.Inheritance`
                                    -InheritedObjects $HADacl.InheritedObjects
                            }
                        }
                    }
                    if ($result) {
                        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> +++ ACL added: TargetDN= " + ($HADacl.TargetDN -replace "RootDN", $DomainRootDN)
                        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--->                 Trustee= " + $HADacl.Trustee
                        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--->                   Right= " + $HADacl.Right
                        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--->               RightType= " + $HADacl.RightType
                        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--->             Inheritance= " + $HADacl.Inheritance
                        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--->        InheritedObjects= " + $HADacl.InheritedObjects
                        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--->              ObjectType= " + $HADacl.ObjectType
                    }
                    Else {
                        $ErrIdx++
                        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---! !!! ACL ERROR: TargetDN= " + ($HADacl.TargetDN -replace "RootDN", $DomainRootDN)
                        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---!                 Trustee= " + $HADacl.Trustee
                        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---!                   Right= " + $HADacl.Right
                        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---!               RightType= " + $HADacl.RightType
                        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---!             Inheritance= " + $HADacl.Inheritance
                        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---!        InheritedObjects= " + $HADacl.InheritedObjects
                        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---!              ObjectType= " + $HADacl.ObjectType
                    }
                }

            }
            else {
        
                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---! Warning: xmlData is empty!"
                $result = 1
                $ResMess = "No Data to deal with"
            }

            ## Getting specified schema for SDDL
            $xmlData = $xmlSkeleton.settings.DelegationACEs.SDDL
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> .........................: xml data loaded (" + $xmlData.count + " SDDL(s))"

            ## if we got data, begining creation loop
            if ($xmlData) {
                #.Begin object creation loop
                foreach ($HADacl in $xmlData) {
                    # Custom Rights
                    $result = Set-HardenSDDL -TargetDN ($HADacl.TargetDN -replace "RootDN", $DomainRootDN) -Trustee $HADacl.Trustee -CustomAccessRule $HADacl.CustomAccessRule

                    if ($result) {
                        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> +++ Cus. Rule: TargetDN= " + $HADacl.TargetDN
                        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--->                 Trustee= " + $HADacl.Trustee
                        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--->                   Right= " + $HADacl.CustomAccessRule
                    }
                    Else {
                        $ErrIdx++
                        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> !!! Cus. Rule addition failed!"
                        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> !!! Cus. Rule: TargetDN= " + $HADacl.TargetDN
                        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--->                 Trustee= " + $HADacl.Trustee
                        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--->                   Right= " + $HADacl.CustomAccessRule
                    }
                }
                #-Success: no issue
                if ($ErrIdx -eq 0) { 
                    $result = 0 
                    $ResMess = "no error"
                }
                #-Warning: some were not created and generate an error
                if ($ErrIdx -gt 0 -and $ErrIdx -lt $xmlData.count) { 
                    $result = 1
                    $ResMess = "$ErrIdx out of " + $xmlData.count + " failed"
                }
                #-Error: none were created!
                if ($ErrIdx -ge $xmlData.count) { 
                    $result = 2
                    $ResMess = "error when creating ACEs!"
                }

            }
            else {
        
                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---! Warning: xmlData is empty!"
                $result = 1
                $ResMess = "No Data to deal with"
            }
        }
        else {
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---! Error: could not proceed!"
            $result = 2
            $ResMess = "prerequesite failure"
        }   
    }

    ## Exit
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> function return RESULT: $Result"
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "===| INIT  ROTATIVE  LOG "
    if (Test-Path .\Logs\Debug\$DbgFile) {
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Rotate log file......: 1000 last entries kept" 
        if (-not((Get-WMIObject win32_operatingsystem).name -like "*2008*")) {
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
#endregion

#region New-ADguidMap
Function New-ADDGuidMap {
    <#
        .SYNOPSIS
            Creates a guid map for the delegation part
        .DESCRIPTION
            Creates a guid map for the delegation part
        .EXAMPLE
            PS C:\> New-ADDGuidMap
        .OUTPUTS
            Hashtable
        .NOTES
            Author: Constantin Hager
            Date: 06.08.2019
    #>
    $rootdse = Get-ADRootDSE
    $guidmap = @{ }
    $GuidMapParams = @{
        SearchBase = ($rootdse.SchemaNamingContext)
        LDAPFilter = "(schemaidguid=*)"
        Properties = ("lDAPDisplayName", "schemaIDGUID")
    }
    Get-ADObject @GuidMapParams | ForEach-Object { $guidmap[$_.lDAPDisplayName] = [System.GUID]$_.schemaIDGUID }
    return $guidmap
}
#endregion

#region New-ADextendedRightMap
Function New-ADDExtendedRightMap {
    <#
        .SYNOPSIS
            Creates a extended rights map for the delegation part
        .DESCRIPTION
            Creates a extended rights map for the delegation part
        .EXAMPLE
            PS C:\> New-ADDExtendedRightsMap
        .NOTES
            Author: Constantin Hager
            Date: 06.08.2019
    #>
    $rootdse = Get-ADRootDSE
    $ExtendedMapParams = @{
        SearchBase = ($rootdse.ConfigurationNamingContext)
        LDAPFilter = "(&(objectclass=controlAccessRight)(rightsguid=*))"
        Properties = ("displayName", "rightsGuid")
    }
    $extendedrightsmap = @{ }
    Get-ADObject @ExtendedMapParams | ForEach-Object { $extendedrightsmap[$_.displayName] = [System.GUID]$_.rightsGuid }
    return $extendedrightsmap
}
#endregion

#region Set-HardenSDDL
Function Set-HardenSDDL {
    <#
        .SYNOPSIS
        Function use to setup ACL for delegation purpose - Custom Rules

        .DESCRIPTION
        This function will add custom rules to delegate fine tune rulset (ExtendRight). 
        Accepted value:
        > Computer_DomJoin: allow to join a system upon an existing computer object within the target OU.  

        .PARAMETER TargetDN
        DN of the object on whoch we put the ACL.

        .PARAMETER Trustee
        Name of the group which will be pushed in through SDDL.

        .PARAMETER CustomAccessRule
        Which delegation ruleset to apply to the TargetDN.

        .NOTES
        Version 01.00 - 2024/02/27
    #>
    param(
        [Parameter(Position = 1 , Mandatory = $true, HelpMessage = "DN of the object on which we put the ACL")]
        [ValidateNotNullOrEmpty()]
        [string]
        $TargetDN,
    
        [Parameter(Position = 2 , Mandatory = $true, HelpMessage = "Name of the group which will inherit the ACL granting")]
        [ValidateNotNullOrEmpty()]
        [string]
        $Trustee,

        [Parameter(Position = 3 , Mandatory = $true, HelpMessage = "Right(s) to give with the ACL")]
        [ValidateNotNullOrEmpty()]
        [ValidateSet("Computer_DomJoin")]
        [string]
        $CustomAccessRule
    )   

    #.Guid mappings
    $GuidMap = New-ADDGuidMap
    $ExtendedRight = New-ADDExtendedRightMap

    #.Getting the TargetDN's ACL 
    $acl = Get-Acl -Path "AD:\$TargetDN" 

    Switch ($CustomAccessRule) {
        "Computer_DomJoin" {
            #.Convert Trustee to NT Account.
            $TrusteeSID = (Get-ADGroup $Trustee).SID

            #.Read all properties
            $Acee = New-Object DirectoryServices.ActiveDirectoryAccessRule $TrusteeSID, "ReadProperty,WriteProperty, GenericExecute", "Allow", $([GUID]::Empty), "All", $([GUID]::Empty)
            $acl.AddAccessRule($Acee)
            
            #.Reset password
            $Acee = New-Object DirectoryServices.ActiveDirectoryAccessRule $TrusteeSID, "ExtendedRight", "Allow", $ExtendedRight["reset password"], "Descendents", $GuidMap["computer"]
            $acl.AddAccessRule($Acee)

            #.Write DNS HostName
            $Acee = New-Object DirectoryServices.ActiveDirectoryAccessRule $TrusteeSID, "ExtendedRight", "Allow", $ExtendedRight["Validated write to DNS host name"], "Descendents", $GuidMap["computer"]
            $acl.AddAccessRule($Acee)

            #.Write SPN
            $Acee = New-Object DirectoryServices.ActiveDirectoryAccessRule $TrusteeSID, "ExtendedRight", "Allow", $ExtendedRight["Validated write to service principal name"], "Descendents", $GuidMap["computer"]
            $acl.AddAccessRule($Acee)

            #.Write Account Restriction
            $Acee = New-Object DirectoryServices.ActiveDirectoryAccessRule $TrusteeSID, "ExtendedRight", "Allow", $ExtendedRight["Account Restrictions"], "Descendents", $GuidMap["computer"]
            $acl.AddAccessRule($Acee)
        }
    }    

    try {
        $null = Set-ACL -Path "AD:\$TargetDN" -AclObject $acl -ErrorAction STOP
        $Result = $true
    }
    catch {
        $Result = $false
    }

    #.Return result
    Return $Result
}
#endregion

#region Set-msdsMachineAccountQuota
Function Set-msDSMachineAccountQuota {
    <#
        .Synopsis
        Unallow users to add computers to the domain.
        
        .Description
        Security Measure: please modify the Sequence File to make this happen.
        
        .Parameter DsiAgreement
        YES if the DSI is informed and agreed.

        .Notes
        Version:    02.00 -- contact@hardenad.net
        history:    2021/04/12  Script creation
                    2021/06/04  Removed parameter dsiAgreement (handled by the caller).
                                Added parameter newValue that specify the msDSmachineAccountQuota setings
    #>
    param(
        [Parameter(mandatory = $true, position = 0)]
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
    if ((Get-WMIObject win32_operatingsystem).name -like "*2008*") {
        Try { 
            Import-Module ActiveDirectory
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> OS is 2008/R2, added AD module."    
        }
        Catch {
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---! ERROR! OS is 2008/R2, but the script could not add AD module."   
        }
    }
    ## Setting the new value
    Try {
        Start-Sleep -Milliseconds 50
        Set-ADDomain -Identity (Get-ADDomain) -Replace @{"ms-DS-MachineAccountQuota" = "$newValue" }
        $result = 0
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> msDSmachineAccountQuota has been set to $newValue"    
    }
    Catch {
        $result = 2
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---! ERROR: msDSmachineAccountQuota cloud not be set to $newValue!"    
    }

    ## Checking the new value.
    if ($result -eq 0) {
        $checkedValue = (Get-ADObject (Get-ADDomain).distinguishedName -Properties ms-DS-MachineAccountQuota).'ms-DS-MachineAccountQuota'
        if ($checkedValue -eq $NewValue) { 
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> msDSmachineAccountQuota has been verified successfully and the current value is $checkedValue"    
        }
        else {
            $result = 1 
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---! ERROR: msDSmachineAccountQuota was not verified properly, the value is not $newValue but $checkedValue"    
        }
    }

    ## Exit
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Function return RESULT: $result"
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "===| INIT  ROTATIVE  LOG "
    if (Test-Path .\Logs\Debug\$DbgFile) {
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
#endregion

#region Set-ADrecycleBin
Function Set-ADRecycleBin {
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
    if ((Get-WMIObject win32_operatingsystem).name -like "*2008*") {
        Try { 
            Import-Module ActiveDirectory
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> OS is 2008/R2, added AD module."    
        }
        Catch {
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---! ERROR! OS is 2008/R2, but the script could not add AD module."   
        }
    }
    ## Test Options current settings
    if ((Get-ADOptionalFeature -Filter 'name -like "Recycle Bin Feature"').EnabledScopes) {
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Active Directory Recycle Bin is already enabled"
        $result = 0
    }
    else {
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Active Directory Recycle Bin is not enabled yet"
        
        Try {
            $NoEchoe = Enable-ADOptionalFeature 'Recycle Bin Feature' -Scope ForestOrConfigurationSet -Target (Get-ADForest).Name -WarningAction SilentlyContinue -Confirm:$false

            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Enable-ADOptionalFeature 'Recycle Bin Feature' -Scope ForestOrConfigurationSet -Target " + (Get-ADForest).Name + ' -WarningAction SilentlyContinue -Confirm:$false'
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Active Directory Recycle Bin is enabled"
            
            $result = 0
        }
        catch {
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---! Error while configuring the active directory Recycle Bin"
            
            $result = 2
        }

        ##Ensure result is as expected
        if ($result -eq 0) {
            if ((Get-ADOptionalFeature -Filter 'name -like "Recycle Bin Feature"').EnabledScopes) {
                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> The active directory Recycle Bin is enabled as expected."
            }
            else {
                $result = 2
                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---! Error: the active directory Recycle Bin has not the expected status!"
            }
        }    
    }    
    ## Exit
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> function return RESULT: $Result"
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "===| INIT  ROTATIVE  LOG "
    if (Test-Path .\Logs\Debug\$DbgFile) {
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
#endregion

#region Set-SiteLinkNotify
Function Set-SiteLinkNotify {
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
            01.01 -- Fix replink auto discover
            01.02 -- Removed DesiredState parameter
            01.03 -- Added manually created site link (0x8 for instant rep)
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
    if ((Get-WMIObject win32_operatingsystem).name -like "*2008*") {
        Try { 
            Import-Module ActiveDirectory
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> OS is 2008/R2, added AD module."    
        }
        Catch {
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---! ERROR! OS is 2008/R2, but the script could not add AD module."   
        }
    }

    #.Only if not 2008 or 2008 R2.
    if (((Get-WMIObject win32_operatingsystem).name -notlike "*2008*")) {
        #.List of rep link
        $RepSiteLinks = Get-ADReplicationSiteLink -Filter * 

#.For each of them...
        foreach ($RepSiteLink in $RepSiteLinks) {
            #.Check if already enabled.
            if ((Get-ADReplicationSiteLink $RepSiteLink.Name -Properties *).options) {
                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Urgent Replication Options are already enabled with value " + (Get-ADReplicationSiteLink $RepSiteLink.Name -Properties *).options + " for " + $RepSiteLink.Name
                $Result = 0
            } 
            Else {
                try {
                    $NoEchoe = Set-ADReplicationSiteLink $RepSiteLink -Replace @{'Options' = 1 } -WarningAction SilentlyContinue
                    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Urgent Replication Options is now enabled with value " + (Get-ADReplicationSiteLink $RepSiteLink.Name -Properties *).options + " for " + $RepSiteLink.Name
                    $Result = 1
                }
                Catch {
                    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---! Urgent Replication failed to be enabled with value 1 for " + $RepSiteLink.Name
                    $Result = 2
                }
            }
            #.Check if successfully enabled.
            if ($Result -eq 1) {
                if ((Get-ADReplicationSiteLink $RepSiteLink.Name -Properties *).options) { 
                    $Result = 0
                    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Urgent Replication Options on " + $RepSiteLink.Name + " is properly set"
                }
                else { 
                    $Result = 2
                }
            }
        }
    }
    Else {
        $Result = 1
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---! Windows 2008 and 2008 R2 are not compliant with this function."
        $ResMess = "2008/R2 is not compliant with this function"
    }
    ## Exit
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> function return RESULT: $Result"
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "===| INIT  ROTATIVE  LOG "
    if (Test-Path .\Logs\Debug\$DbgFile) {
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
#endregion

#region Set-DefaultObjectLocation
Function Set-DefaultObjectLocation {
    <#
        .Synopsis
        Redirect default location to a specific point.
        
        .Description
        use REDIRCMP or REDIRUSR to fix default location of objects.
        Return TRUE if the states is as expected, else return FALSE.
        
        .Notes
        Version:    01.00 -- contact@hardenad.net
        history:    01.00 -- Script creation
                    01.01 -- Adapt to match relocation in any path
    #>
    param(
        [Parameter(mandatory = $true, position = 0)]
        [ValidateSet("User", "Computer")]
        [String]
        $ObjectType,

        [Parameter(mandatory = $true, position = 1)]
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
    if ((Get-WMIObject win32_operatingsystem).name -like "*2008*") {
        Try { 
            Import-Module ActiveDirectory
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> OS is 2008/R2, added AD module."    
        }
        Catch {
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---! ERROR! OS is 2008/R2, but the script could not add AD module."   
        }
    }
    ## dynamic OU path rewriting
    $OUPath2 = $OUPath -replace 'RootDN', (Get-ADDomain).DistinguishedName

    ## Checking object class
    switch ($ObjectType) {
        "User" {
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
        Default {
            ## Bad input !
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---! ERROR! ObjectClass is unknown."
            $result = 2
        }
    }
    
    ## Exit
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> function return RESULT: $Result"
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "===| INIT  ROTATIVE  LOG "
    if (Test-Path .\Logs\Debug\$DbgFile) {
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Rotate log file......: 1000 last entries kept" 
        if (-not((Get-WMIObject win32_operatingsystem).name -like "*2008*")) {
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
#endregion

#region Set-ADfunctionalLevel
Function Set-ADFunctionalLevel {
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
    #>
    param(
        [Parameter(mandatory = $true, position = 0)]
        [ValidateSet("Domain", "Forest")]
        [String]
        $TargetScope,

        [Parameter(mandatory = $true, position = 1)]
        [ValidateSet("2008R2", "2012", "2012R2", "2016", "Last")]
        [String]
        $TargetLevel
    )

    ## TargetLevel and OS Version
    $OSlevelAndVersion = @{
        '2008'   = '6.0'
        '2008R2' = '6.1'
        '2012'   = '6.2'
        '2012R2' = '6.3'
        '2016'   = '10.0*'
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
    if ((Get-WMIObject win32_operatingsystem).name -like "*2008*") {
        Try { 
            Import-Module ActiveDirectory
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> OS is 2008/R2, added AD module."    
        }
        Catch {
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---! ERROR! OS is 2008/R2, but the script could not add AD module."   
        }
    }

    ## checking preRequisites : run on FSMO, OS newer or equal to TargetLevel, Replication OK if several DCs
    $blnPreRequisitesOK = $true
    If ($TargetScope -like "Domain") {
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

        If ($blnPreRequisitesOK) {
            # Check OS of all DCs of the current domain 
            [array]$AllDomainControllers = Get-ADDomainController -Filter * | Select-Object Name, HostName, OperatingSystem, OperatingSystemVersion
            $intLowestOSVersion = 9999
            $AllDomainControllers | ForEach-Object {
                $DCName = $_.HostName
                $OSversion = $_.OperatingSystemVersion
                $intOSVersion = [int]($OSversion.Substring(0, $OSversion.IndexOf(".") + 2).Replace(".", ""))
                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> DC: $DCName | OS: $OSversion | intVersion: $intOSVersion"
                If ($TargetLevel -like "Last") {
                    If ($intOSVersion -lt $intLowestOSVersion) {
                        $intLowestOSVersion = $intOSVersion
                        $LowestOSVersion = $OSversion
                        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> LowestOSVersion: $LowestOSVersion"
                    }
                } 
                Else {
                    $intTargetOSVersion = [int](($OSlevelAndVersion[$TargetLevel]).Substring(0, ($OSlevelAndVersion[$TargetLevel]).IndexOf(".") + 2).Replace(".", ""))
                    If ($intOSVersion -lt $intTargetOSVersion) { 
                        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---! ERROR! OperatingSystem of '$DCName' is '$($_.OperatingSystem)', which is too low for target Domain Level ($($OSlevelAndVersion[$TargetLevel]))" 
                        $blnPreRequisitesOK = $false
                    }
                }
            }

            # Check AD Replication
            If ($AllDomainControllers.Count -gt 1) {
                $RepFailures = Get-ADReplicationFailure -Target $DomainObj.DnsRoot -Scope Domain
                If ($RepFailures) {
                    $blnPreRequisitesOK = $false
                    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---! ERROR! Some DCs have replication issues"                  
                }
            }

            # Check Current DC FSMO
            $ADServerObj = Get-ADDomainController
            If ($ADServerObj.OperationMasterRoles -notcontains "PDCEmulator") {
                $blnPreRequisitesOK = $false
                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---! ERROR! Current DomainController is not PDCEmulator"  
            }

            # If TargetLevel is Last, set it to the lowest OS found amongst Domain Controllers
            If ($TargetLevel -like "Last") {
                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> TargetLevel is Last -> Set to LowestOSVersion ($LowestOSVersion)"
                $LowestOSVersion = $LowestOSVersion.Substring(0, $LowestOSVersion.IndexOf(".") + 2) + "*"
                $TargetLevel = ($OSlevelAndVersion.GetEnumerator() | Where-Object { $_.Value -like $LowestOSVersion }).Name
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

        If ($blnPreRequisitesOK) {
            # Check DFL of all domains of the Forest
            # If Target is 'Last' we get the lowest DFL to have the possible target. Otherwise we check if all DFL are equal or above FFL target
            $LowestFL = "2099"
            foreach ($DomainDns in $ForestObj.Domains) {
                Try {
                    $DflLabel = [string](Get-ADDomain $DomainDns).DomainMode
                    $DflShort = ($DflLabel.Replace("Windows", "")).Replace("Domain", "")
                    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Domain $DomainDns : DFL = $DflLabel ($DflShort)" 
                    If ($TargetLevel -like "Last") {
                        If ($DflShort -lt $LowestFL) { $LowestFL = $DflShort }
                    } 
                    Else {
                        If ($DflShort -lt $TargetLevel) { 
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
            If ($ADServerObj.OperationMasterRoles -notcontains "PDCEmulator") {
                $blnPreRequisitesOK = $false
                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---! ERROR! Current DomainController is not PDCEmulator"  
            }
            If ($ADServerObj.Domain -ne $ADServerObj.Forest) {
                $blnPreRequisitesOK = $false
                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---! ERROR! Current DomainController is not in the root domain"           
            }
            # set Target Level if parameter is Last 
            If ($TargetLevel -like "Last") { $TargetLevel = $LowestFL }
        }
    }

    # Process Upgrade
    If ($blnPreRequisitesOK) {
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> All PreRequisites OK : Upgrade $TargetScope to $TargetLevel Functional Level"

        If ($TargetScope -like "Domain") {
            $TargetMode = "Windows" + $TargetLevel + "Domain"

            If ($TargetMode -like $CurrentDomainLevel) {
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

                    If ($AllDomainControllers.Count -gt 1) {
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
                            If ($FLNb -ne $FLRefNb) {
                                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---! WARNING! Domain Functional not replicated on $DChostName" 
                                $Result = 1
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
            If ($TargetMode -like $CurrentForestLevel) {
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
    if (Test-Path .\Logs\Debug\$DbgFile) {
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
#endregion

#region Install-LAPS
Function Install-LAPS {
    <#
        .Synopsis
        To be deployed, LAPS need to update the AD Schema first.
        
        .Description
        The script first update the schema, then it will install the management tool.

        .Notes
        Version: 01.00 -- contact@hardenad.net 
		Version: 01.01 -- contact@hardenad.net 
        
        history:    21.08.22 Script creation
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
    ## Load Task sequence
    $xmlSkeleton = [xml](Get-Content ".\Configs\TasksSequence_HardenAD.xml" -Encoding utf8)
    $RootDomainDns = ($xmlSkeleton.Settings.Translation.wellKnownID | Where-Object { $_.translateFrom -eq "%Rootdomaindns%" }).translateTo

    ## Check prerequesite: running user must be member of the Schema Admins group and running computer should be Schema Master owner.
    $CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $isSchemaAdm = Get-ADGroupMember -Recursive ((Get-ADDomain -Server $RootDomainDns).DomainSID.value + "-518") -Server $RootDomainDns | Where-Object { $_.SID -eq $CurrentUser.User }

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
        $result = 5
        if (-not $isSchemaAdm) {
            $ResMess = "The user is not a Schema Admins (group membership with recurse has failed)"
        } Else {
            $ResMess = "The current domain controler is not the schema master"
        }
    }

    ## Exit
    return (New-Object -TypeName psobject -Property @{ResultCode = $result ; ResultMesg = $ResMess ; TaskExeLog = $ResMess })
}
#endregion

#region Set-LAPSpermissions
Function Set-LapsPermissions {
    <#
        .Synopsis
        Once deployed, the LAPS engine requires some additional permission to properly work.
        
        .Description
        The script will delegate permission upon target OU. It refers to TasksSequence_HardenAD.xml.

        .Notes
        Version:    01.00 -- contact@hardenad.net 
                    01.01 -- contact@hardenad.net 
        history:    21.11.27 Script creation
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
        try {
            Start-Process -FilePath "$env:systemroot\system32\msiexec.exe" `
                -WorkingDirectory .\Inputs\LocalAdminPwdSolution\Binaries `
                -ArgumentList '/i laps.x64.msi ADDLOCAL=Management.UI,Management.PS,Management.ADMX /quiet /norestart' `
                -NoNewWindow `
                -Wait
        }
        catch {
            $result = 2
            $ResMess = "AdmPwd.PS module missing."
        }
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
                    $cfgXml = [xml](Get-Content .\Configs\TasksSequence_HardenAD.xml -Encoding utf8)
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
                        # Write-Host $_.Exception.Message
                        # Write-Host $TargetOU
                        # Pause
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
#endregion

#region Import-WmiFilters
Function Import-WmiFilters {
    <#
        .SYNPOSIS
            This function import OMF files to the domain and add requiered wmi filter.

        .DETAILS
            This function import OMF files to the domain and add requiered wmi filter.

        .NOTES
            Version: 01.00
            Author.: contact@hardenad.net
            Desc...: Function creation.
            
            Version: 01.01
            Author.: contact@hardenad.net
            Desc...: modified the way wmi filter is imported. 
                     Added a check for WMI filter being present after import.

            Version: 02.00
            Author.: contact@hardenad.net
            Desc...: New release which will replace domain=xxxx.yyy by the running domain
                     No more parameters needed.
            
            Version: 02.01
            Author.: contact@hardenad.net
            Desc...: removed all debuf data.

            Version: 02.02
            Author.: contact@hardenad.net
            Desc...: added debug log file.
    #>

    Param(
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
    if ((Get-WMIObject win32_operatingsystem).name -like "*2008*") {
        Try { 
            Import-Module ActiveDirectory
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> OS is 2008/R2, added AD module."    
        } 
        Catch {
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---! ERROR! OS is 2008/R2, but the script could not add AD module." 
        }
    }
    ## Get Current Location
    $curDir = (Get-Location).Path
    
    ## loading configuration file
    Try {
        $xmlFile = [xml](Get-Content .\Configs\TasksSequence_HardenAD.xml -Encoding utf8)
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> xml skeleton file........: loaded successfully"
        $Resultat = 0
    }
    Catch {
        $Resultat = 2
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---! FAILED loading xml skeleton file "
    }

    if ($resultat -ne 2) {
        ## Begin WMI filter importation
        $WmiFilters = $xmlFile.settings.groupPolicies.WmiFilters
        $CurrWmiFtr = Get-ADObject -Filter { ObjectClass -eq 'msWMI-Som' } -Properties *
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Starting WMI Filter importation"

        foreach ($filterData in $WmiFilters.Filter) {
            ## Check if already exists
            ## some interesting stuff: http://woshub.com/group-policy-filtering-using-wmi-filters/
            if ($CurrWmiFtr.'msWMI-Name' -match $filterData.Name) {
                #. already exists (no additionnal step)
            }
            else {
                ## Tips really usefull from the-wabbit: 
                ## https://serverfault.com/questions/919297/importing-gpo-wmi-filter-mof-file
                $mofPath = $curDir + "\inputs\GroupPolicies\WmiFilters\" + $filterData.Source

                #.Rewriting data to fetch to the new domain (version 2.0)
                if (Test-Path ($mofPath + ".tmp")) {
                    $null = Remove-Item ($mofPath + ".tmp") -Force
                }
                $readMof = Get-Content $mofPath
                $outData = @()
                foreach ($line in $readMof) {
                    if ($line -like "*Domain = *") {
                        $outData += ($line -split """")[0] + """" + (Get-ADDomain).DNSRoot + """;"
                    
                    }
                    else {
                        $outData += $line
                    }
                }
                $outData | Out-File ($mofPath + ".tmp") 
                $Output = $mofPath + ".tmp"

                try {
                    $noSplash = mofcomp.exe -N:root\Policy ($Output) | Out-Null
                    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> WMI Filter $Output  imported successfully."

                }
                Catch {
                    $Resultat = 1
                    
                    $ResMess = "Some filter were not imported successfully."
                    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---! WMI Filter $Output failed to be imported."
                }
                
                Remove-Item ($Output) -Force

                #.Checking import status
                $CheckWmiFtr = Get-ADObject -Filter { ObjectClass -eq 'msWMI-Som' } -Properties *
                if ($CheckWmiFtr.'msWMI-Name' -match $filterData.Name) {
                    #. check OK - The wmi Filter is present.
                    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> WMI Filter " + $filterData.Name + " has been correctly found when checking the import result."
                }
                Else {
                    $Resultat = 1
                    $ResMess = "Some filter failed to be found when checking the import result."
                    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---! WMI Filter " + $filterData.Name + " failed to be found when checking the import result."
                }
            }
        }
    }

    ## Exit
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> function return RESULT: $Resultat"
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "===| INIT  ROTATIVE  LOG "
    if (Test-Path .\Logs\Debug\$DbgFile) {
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
    ## Return translated xml
    return (New-Object -TypeName psobject -Property @{ResultCode = $resultat ; ResultMesg = $ResMess ; TaskExeLog = $ResMess })
}
#endregion

#region New-GpoObject
Function New-GpoObject {
    <#
        .Synopsis
        Add all GPOs from the TasksSequence_HardenAD.xml.
        
        .Description
        The TasksSequence_HardenAD.xml file contain a section named <GPO>: this section will be readen by the script and every input will be added to the target domain.
        
        .Notes
        Version: 
            01.00 -- contact@hardenad.net 
        
        history: 
            01.00 -- Script creation
            01.01 -- Added Security Filter option
            02.00 -- Uses new functions 2.0
            02.01 -- Added Debug log
            02.02 -- Fixed bug that let unvalited GPO being imported anyway
            02.03 -- Added ability to store in Deny and Apply sub-OU
    #>
    param(
    )

    ## Set Debug log file path and create it if not exists
    $DebugLogPath = ".\Logs\Debug\Debug_{0}.log" -f $MyInvocation.MyCommand
    if (!(Test-Path $DebugLogPath)) {
        New-Item -ItemType File -Path $DebugLogPath -Force | Out-Null
    }

    ## Function Log Debug File
    

    ## Start Debug Trace
    Write-DebugMessage "****"
    Write-DebugMessage "**** FUNCTION STARTS"
    Write-DebugMessage "****"

    ## Indicates caller and options used
    $caller = "---> Function caller..........: " + (Get-PSCallStack)[1].Command
    Write-DebugMessage $caller

    ## When dealing with 2008R2, we need to import AD module first
    if ((Get-WMIObject win32_operatingsystem).name -like "*2008*") {
        Import-Module ActiveDirectory -ErrorAction Stop
        Import-Module GroupPolicy -ErrorAction Stop
        Write-DebugMessage "---> OS is 2008/R2, added AD module."
        Write-DebugMessage "---> OS is 2008/R2, added GroupPolicy module."
    }
    
    ## Get Current Location
    $curDir = (Get-Location).Path

    ## loading configuration file
    Try {
        $xmlFile = [xml](Get-Content .\Configs\TasksSequence_HardenAD.xml -Encoding utf8 -ErrorAction Stop)
        Write-DebugMessage "---> xml skeleton file........: loaded successfully"
        $Result = 0
    }
    Catch {
        $Result = 2
        Write-DebugMessage "---! FAILED loading xml skeleton file "
    }
    
    ## Recovering GPOs data
    $GpoData = $xmlFile.Settings.GroupPolicies.GPO
    Write-DebugMessage "---> Recovering GPOs data from xml file : success"

    # Recovering GPOs GUID and Name
    # hashtable : GUID = GPO Folder Name
    $gpoGuidNameHashTable = @{}

    Get-ChildItem ".\Inputs\GroupPolicies" -Directory | ForEach-Object {
        Get-ChildItem $_.FullName -Directory | ForEach-Object {
            $gpoGuidNameHashTable.Add($_.Name, $_.Parent.Name)
        }
    }

    ## Analyzing and processing
    if ($Result -ne 2) {
        foreach ($Gpo in $GpoData) {
            #.Recovering data
            #.New attribute : overwrite - this one let the script knows if an existing GPO should be replaced or not.
            $gpName = $Gpo.Name
            $gpDesc = $Gpo.Description
            $gpVali = $Gpo.Validation
            $gpBack = $Gpo.BackupID
        
            # Get the GPO folder name from the GUID
            $gpFolderName = $gpoGuidNameHashTable[$gpBack]

            if($null -eq $gpFolderName) {
                Write-DebugMessage "---> GPO with GUID $gpBack not found in Inputs\GroupPolicies folder."
                continue
            }

            #.Check if the GPO already exists
            $gpChek = Get-GPO -Name $gpName -ErrorAction SilentlyContinue

            if ($gpChek -or $gpVali -eq "No") {
                if ($gpChek) {
                    Write-DebugMessage "---> GPO $gpName already exists."
                }
                if ($gpVali -eq "No") {
                    Write-DebugMessage "---> GPO $gpName is set to not be imported (validation=No)."
                }
                #GPO Exists - Set flag according to the overwrite attribute.
                $gpFlag = $false
                $result = 0
            }
            Else {
                #.Create empty GPO
                Write-DebugMessage " "
                Write-DebugMessage "---> Creating GPO $gpName"
                Try {
                    $null = New-Gpo -Name $gpName -Comment $gpDesc -ErrorAction SilentlyContinue
                    Write-DebugMessage "---> GPO $gpName has been created."
                    $gpFlag = $true
                }
                Catch {
                    $gpFlag = $false
                    Write-DebugMessage "---! Error when creating GPO $gpName "
                    $result = 1
                }
            }

            #.If no issue, time to import data, set deny mermission and, if needed, link the GPO
            if ($gpFlag) {
                $null = Convert-MigrationTable    -GpoName "$gpFolderName\$gpBack"
                $null = Convert-GpoPreferencesXml -GpoName "$gpFolderName\$gpBack"
                Write-DebugMessage "---> Trying to import datas of GPO in folder $gpFolderName :"

                #.Import backup
                try {
                    # Case 1 : no translated.migtable
                    $MigTableFile = "$curDir\Inputs\GroupPolicies\$gpFolderName\$gpBack\translated.migtable"
                    if (-not(Test-Path $MigTableFile)) {
                        Write-DebugMessage "---> Importing datas of GPO without translated.migtable"
                        $null = Import-GPO -BackupId $gpBack -TargetName $gpName -Path $curDir\Inputs\GroupPolicies\$gpFolderName -ErrorAction Stop
                        Write-DebugMessage "---> Success"
                        $importFlag = $true
                    }
                    # Case 2 : translated.migtable
                    else {
                        Write-DebugMessage "---> Importing datas of GPO with translated.migtable"
                        $null = Import-GPO -BackupId $gpBack -TargetName $gpName -MigrationTable $MigTableFile -Path $curDir\Inputs\GroupPolicies\$gpFolderName -ErrorAction Stop
                        Write-DebugMessage "---> Success"
                        $importFlag = $true
                    }
                    Write-DebugMessage "---> Datas of GPO in folder $gpFolderName has been imported."
                }
                Catch {
                    $result = 1
                    $errMess += " Failed to import at least one GPO : $($_.ToString())"
                    $errMess += ""
                    Write-DebugMessage "---! Failed to import Datas of GPO in folder $gpFolderName"
                    $importFlag = $false
                }

                #.Assign Wmi Filter, if any
                if ($importFlag) {
                    #.check for filter data
                    $gpFilter = $Gpo.GpoFilter
                    if ($gpFilter) {
                        #.Prepare data
                        $FilterName = $gpFilter.WMI
                        $DomainName = (Get-ADDomain).DnsRoot
                        $GpoRawData = Get-GPO -Name $gpName 
                        $wmiFilter = Get-ADObject -Filter { msWMI-Name -eq $FilterName } -ErrorAction SilentlyContinue
                        $GpoDN = "CN={" + $GpoRawData.Id + "},CN=Policies,CN=System," + (Get-ADDomain).DistinguishedName
                        $wmiLinkVal = "[" + $DomainName + ";" + $wmiFilter.Name + ";0]"

                        #.Check if there is already a value
                        $hasFilter = (Get-ADObject $GpoDN -Properties gPCWQLFilter).gPCWQLFilter

                        Try {
                            if ($hasFilter) {
                                Set-ADObject $GpoDN -replace @{gPCWQLFilter = $wmiLinkVal }
                            }
                            else {
                                Set-ADObject $GpoDN -Add @{gPCWQLFilter = $wmiLinkVal }
                            }
                            Write-DebugMessage "---> WMI Filter of GPO $gpName has been set."
                        }
                        Catch {
                            $Result = 1
                            Write-DebugMessage "---!Error while setting WMI Filter of GPO $gpName."
                        }
                    } 
                }

                #.Set Deny and apply permission
                #.The if is only here for legacy compatibility with 2k8r2 and pShell 2.0.
                if (-not($Gpo.GpoMode)) {
                    $mode = "BOTH"
                    $Tier = "tier0"
                }
                else {
                    $mode = $Gpo.GpoMode.Mode
                    $Tier = $Gpo.GpoMode.Tier
                }
                
                $GrpName = $xmlFile.Settings.GroupPolicies.GlobalGpoSettings.GroupName
                $GrpName = ($GrpName -replace "%tier%", $xmlFile.Settings.GroupPolicies.GlobalGpoSettings.$Tier) -replace "%GpoName%", $GpName

                #.Cheking if any translation is requiered
                foreach ($translate in $xmlFile.Settings.Translation.wellKnownID) {
                    $GrpName = $GrpName -replace $translate.translateFrom, $translate.TranslateTo
                }

                #.Shrinking GroupName 
                #.We use space as known separator. Each word will start with an uppercase.
                #.At a final Step, keywords are reduced to abreviations. A dictionnary is involved.
                #.Shorten words...
                foreach ($keyword in $xmlFile.settings.Translation.Keyword) {
                    Try {
                        $GrpName = $GrpName -replace $keyword.longName, $keyword.shortenName
                    }
                    catch {
                        #To write
                    }
                }
                #.Space
                $NewGrpName = $null
                foreach ($word in ($GrpName -split " ")) {
                    try {
                        $NewGrpName += $word.substring(0, 1).toupper() + $word.substring(1)
                    }
                    catch {
                        #To write
                    }     
                }
                $SrcGrpName = $newGrpName

                #.Cheking if any translation is requiered (updated in 2.9.9)
                $GrpPath = $xmlFile.Settings.GroupPolicies.GlobalGpoSettings.OU
                $DenyOU  = "OU=%OU-ADM-GPO-DENY%"
                $ApplyOU = "OU=%OU-ADM-GPO-APPLY%"
                foreach ($translate in $xmlFile.Settings.Translation.wellKnownID) {
                    $GrpPath = $GrpPath -replace $translate.translateFrom, $translate.TranslateTo
                    $DenyOU  = $DenyOU  -replace $translate.translateFrom, $translate.TranslateTo
                    $ApplyOU = $ApplyOU -replace $translate.translateFrom, $translate.TranslateTo
                }

                if ($mode -eq "BOTH" -or $mode -eq "DENY") {
                    $GrpName = $SrcGrpName -replace "%mode%", "DENY"
                    Try {
                        $null = Get-ADGroup $GrpName -ErrorAction stop
                        $notExist = $False
                    }
                    Catch {
                        #.Expected when group is not existing
                        $notExist = $true
                    }
                    if ($notExist) {
                        Try {
                            $null = New-ADGroup -Name $GrpName -Path "$DenyOU,$GrpPath" -Description "DENY GPO: $GpName" -GroupCategory Security -GroupScope DomainLocal -ErrorAction SilentlyContinue
                        }
                        Catch {
                            #.Failed Creation, set error code to Error
                            $result = 1
                            $errMess += " Error: failed to create GPO group $grpName"
                            Write-DebugMessage "---! Error: failed to create GPO group $grpName"
                        }
                    }

                    $NtAcct = (Get-ADDomain).NetBIOSName + "\" + $GrpName
                    $NBName = [System.Security.Principal.NTAccount]$NtAcct

                    #.Applying deny permission
                    Try {
                        $mygpo = Get-GPO -Name $GpName
                        $adgpo = [ADSI]("LDAP://CN=`{$($mygpo.Id.guid)`},CN=Policies,CN=System," + (Get-ADDomain).DistinguishedName)
                        $rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($NBName, "ExtendedRight", "Deny", [Guid]"edacfd8f-ffb3-11d1-b41d-00a0c968f939")
        
                        $acl = $adgpo.ObjectSecurity
                        $acl.AddAccessRule($rule)
                        $adgpo.CommitChanges()
                        Write-DebugMessage "---> Deny permission has been applied on GPO $GpName"
                    }
                    Catch {
                        $result = 1
                        $errMess += " Error: could not apply the deny permission on one or more GPO"
                        Write-DebugMessage "---!Error while applying  Deny permission on GPO $GpName"
                    }
                }

                #.v1.1: added Security Filter
                if ($mode -eq "BOTH" -or $mode -eq "APPLY") {
                    $GrpName = $SrcGrpName -replace "%mode%", "APPLY"

                    Try {
                        $null = Get-ADGroup $GrpName -ErrorAction stop
                        $notExist = $False
                    }
                    Catch {
                        #.Expected when group is not existing
                        $notExist = $true
                    }
                    if ($notExist) {
                        Try {
                            $null = New-ADGroup -Name $GrpName -Path "$ApplyOU,$GrpPath" -Description "APPLY GPO: $GpName" -GroupCategory Security -GroupScope DomainLocal -ErrorAction SilentlyContinue
                        }
                        Catch {
                            #.Failed Creation, set error code to Error
                            $result = 1
                            $errMess += " Error: failed to create GPO group $grpName"
                            Write-DebugMessage "---! Error: failed to create GPO group $grpName"
                        }
                    }

                    #.adding new security filter permissions
                    $NtAcct = (Get-ADDomain).NetBIOSName + "\" + $GrpName
                    $NBName = [System.Security.Principal.NTAccount]$NtAcct

                    #.Applying Security Filter
                    Try {
                        #.Adding new Security Filter
                        Set-GPPermission -Name $gpName -PermissionLevel GpoApply -TargetName $NBName -TargetType Group -Confirm:$false
                        Write-DebugMessage "---> Apply permission has been applied on $GpName"
                    }
                    Catch {
                        $result = 1
                        $errMess += " Error: could not apply the apply permission on one or more GPO"
                        Write-DebugMessage "---! Error while setting Apply permission on $GpName"
                    }

                    #.recover group name to adapt with AD running language
                    $AuthUsers = (Get-ADObject -LDAPFilter "(&(objectSID=S-1-5-11))" -Properties msDS-PrincipalName)."msDS-PrincipalName"

                    #.reset permission for Authenticated Users
                    Try {
                        Set-GPPermission -Name $GpName -PermissionLevel GpoRead -TargetName $AuthUsers -TargetType Group -Confirm:$false -Replace
                        Write-DebugMessage "---> Permission for authenticated users has been reset on $GpName"
                    }
                    Catch {
                        $result = 1
                        $errMess += " Error: failed to rewrite S-1-5-11 from security filter list"
                        Write-DebugMessage "---! ERROR while resetting Permission for authenticated on $GpName"
                    }
                }

                #.Linking to the target OU (in any case)
                if ($gpVali -eq "yes" -or $gpVali -eq "no") {
                    foreach ($gpLink in $GPO.GpoLink) {
                        $gpPath = $gpLink.Path -replace 'RootDN', ((Get-ADDomain).DistinguishedName)
                        #.Test if already linked
                        $gpLinked = Get-ADObject -Filter { DistinguishedName -eq $gpPath } -Properties gpLink | Select-Object -ExpandProperty gpLink | Where-Object { $_ -Match ("LDAP://CN={" + (Get-Gpo -Name $gpName).ID + "},") }
                        if ($gpLinked) {
                            Try {
                                $null = Set-GPLink -Name $gpName -Target $gpPath -LinkEnabled $gpLink.Enabled -Enforced $gpLink.enforced -ErrorAction 
                                Write-DebugMessage "---> GPO $GpName has been linked to OU $gpPath"
                            }
                            Catch {
                                $result = 1
                                $errMess += " Error: could not link one or more GPO"
                                Write-DebugMessage "---! ERROR while linking GPO $GpName to OU $gpPath"
                            }
                        }
                        Else {
                            Try {
                                $null = New-GPLink -Name $gpName -Target $gpPath -LinkEnabled $gpLink.Enabled -Enforced $gpLink.enforced -ErrorAction Stop
                                Write-DebugMessage "---> GPO $GpName has been linked to OU $gpPath"
                            }
                            Catch {
                                $result = 1
                                $errMess += " Error: could not link one or more GPO"
                                Write-DebugMessage "---! ERROR while linking GPO $GpName to OU $gpPath"
                            }
                        }
                    }
                }
            }
        }

    }
    Else {
        $errMess = "Failed to load powerShell modules - canceled."
        Write-DebugMessage "---! ERROR while loading PowerShell modules"
    }

    ## Exit
    Write-DebugMessage "---> function return RESULT: $result"
    Write-DebugMessage "===| INIT  ROTATIVE  LOG "
    
    Write-DebugMessage "===| STOP  ROTATIVE  LOG "
    Write-DebugMessage "**** "
    Write-DebugMessage "**** FUNCTION ENDS"
    Write-DebugMessage "**** "
    ## Return function results
    return (New-Object -TypeName psobject -Property @{ResultCode = $result ; ResultMesg = $ErrMess ; TaskExeLog = $ErrMess })
}
#endregion

#region New-AdministrationAccounts
Function New-AdministrationAccounts {
    <#
        .Synopsis
        Create Tier 0 and Tier 1/2 user accounts.
        
        .Description
        from the XML file, the script will look at child elements "user" from within the element "accounts".
        for each of them, the object will be checked and, if needed, created or updated accordingly.
        the "Path" parameter indicate the object location: use ROOTDN to dynamically add your domain DistinguishedName (DC=...,DC=...).
        
        .Parameter KeepassPwd
        Use this parameter to specify a custom password. If not, the default one will be used (not safe).
        
        .Notes
        Version: 
            01.00 -- contact@hardenad.net 
        
        history: 
            01.00 -- Script creation
    #>
    param(
        [Parameter(mandatory = $false)]
        [String]
        $KeepassPwd
    )

    ## Default keepass password
    if (-not($KeepassPwd)) {
        $KeepassPwd = 'H4rd3n@D!!'
    }

    ## Function dynamic OU path rewriting
    Function Rewrite-OUPath ([String]$OUPath) {
        $OUPath2 = $OUPath -replace 'RootDN', (Get-ADDomain).DistinguishedName
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> [OUPath2]: new variable set with [OUPath] data and ROOTDN replaced. New value: $OUPath2"    
        return $OUPath2
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

    ## Main action
    ## Import xml file with OU build requierment
    Try { 
        $xmlSkeleton = [xml](Get-Content .\Configs\TasksSequence_HardenAD.xml -Encoding utf8 -ErrorAction Stop)
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> xml skeleton file........: loaded successfully"
        $xmlLoaded = $true
    }
    Catch {
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "-!!! FAILED loading xml skeleton file "
        $xmlLoaded = $false
    }    

    ## If xml loaded, begining check and create...
    if ($xmlLoaded) {
        ## Log loop start
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> variable XmlLoaded.......: $xmlLoaded"
        
        ## Creating a variable to monitor failing tasks
        $noError = $true
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> variable noError.........: $noError"
        
        ## When dealing with 2008R2, we need to import AD module first
        if ((Get-WMIObject win32_operatingsystem).name -like "*2008*") {
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> is windows 2008/R2.......: True"
        
            Try { 
                Import-Module ActiveDirectory
                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> OS is 2008/R2, added AD module."    
            } 
            Catch {
                $noError = $false
                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "-!!! ERROR! OS is 2008/R2, but the script could not add AD module." 
                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> variable noError.........: $noError"
            }
        }
        else {

            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> is windows 2008/R2.......: False"
        }

        ## if Everything run smoothly, let's begin.
        if ($noError) {
            ## Getting root DNS name
            $DomainRootDN = (Get-ADDomain).DistinguishedName
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Parameter DomainRootDN...: $DomainRootDN"

            ## Getting specified schema
            $xmlData = $xmlSkeleton.settings.accounts.user
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> xml data loaded (" + $xmlData.count + " account(s))"

            ## Getting Password Parameter Settings
            $xmlParam = Select-Xml $xmlSkeleton -XPath "//*/Translation/wellKnownID[@objectClass='param']" | Select-Object -ExpandProperty "Node"
            $pwdLength = ($xmlParam | Where-Object { $_.translateFrom -eq '%pwdLength%' }).translateTo
            $pwdNANC = ($xmlParam | Where-Object { $_.translateFrom -eq '%pwdNonAlphaNumChar%' }).translateTo

            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Password Length.......................: $pwdLength"
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Number of non alpha numeric characters: $pwdNANC"

            ## if we got data, begining creation loop
            if ($xmlData) {
                #-Failing Creation index
                $ErrIdx = 0
            
                #-Reacling Keepass binaries to avoid issue with read-only permissions
                $path = (Get-Location).Path + "\Tools\KeePass-2.48.1\"
                $pathdb = (Get-Location).Path + "\Outputs\"
                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> binaries path=$path"
                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> database path=$pathdb"
                $GrpName = (Get-ADGroup -filter { Sid -eq "S-1-5-32-545" }).sAMAccountname
                $AceUser = "BUILTIN\" + $GrpName
                Try {
                    $acl = Get-Acl $path
                    $ArgumentsList = $AceUser, , "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow"
                    $AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule -ArgumentList $ArgumentsList
                    $acl.SetAccessRule($AccessRule)
                    Set-Acl $path $acl
                    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> $AceUser now has FULLCONTROL permission on $path"
                }
                Catch {
                    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "-!!! ERROR! $AceUser : FULLCONTROL permission on $path failed to be applied!"
                }
                Try {
                    $acl = Get-Acl $pathdb
                    $acl.SetAccessRule($AccessRule)
                    Set-Acl $pathdb $acl 
                    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> $AceUser now has FULLCONTROL permission on $pathdb"
                }
                Catch {
                    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "-!!! ERROR! $AceUser : FULLCONTROL permission on $pathdb failed to be applied!"
                }

                #-Loading Keepass Binaries
                $KpsFlag = $true
                Try {
                    [Reflection.Assembly]::LoadFile("$path\KeePass.exe") | Out-Null
                    [Reflection.Assembly]::LoadFile("$path\KeePass.XmlSerializers.dll") | Out-Null
                    $IoConnectionInfo = New-Object KeePassLib.Serialization.IOConnectionInfo
                    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> keepass binaries loaded"
                }
                Catch {
                    $KpsFlag = $false
                    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "-!!! keepass binaries not found!"
                }
                if ($KpsFlag) {
                    #-Opening database
                    Try {
                        $IoConnectionInfo.Path = $pathdb + "\HardenAD.kdbx"
                        $Key = New-Object KeePassLib.Keys.CompositeKey
                        $Key.AddUserKey((New-Object KeePassLib.Keys.KcpPassword($KeepassPwd)))
                        $KDBX = New-Object KeePassLib.PwDatabase
                        $KDBX.Open($IoConnectionInfo, $Key, $null)
                        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> database opened"
                    }
                    Catch {
                        $KpsFlag = $false
                        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "-!!! keepass database not found!"
                    }
                }
                foreach ($account in $xmlData) {
                    #-Create a LDAP search filter
                    $Searcher = New-Object System.DirectoryServices.DirectorySearcher($DomainRootDN)
                    $Searcher.Filter = "(&(ObjectClass=User)(sAMAccountName=" + $account.sAMAccountName + "))"

                    if ($Searcher.FindAll() -ne $null) {
                        ## Account is Present
                        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> === " + $account.DisplayName + " already exists"

                    }
                    Else {
                        ## Create User
                        Try {
                            #-Generate a random password
                            $NewPwd = $null
                            
                            Add-Type -AssemblyName 'System.Web'

                            $NewPwd = [System.Web.Security.Membership]::GeneratePassword($pwdLength, $pwdNANC)
                            $SecPwd = ConvertTo-SecureString -AsPlainText $NewPwd -Force
                            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> +++ Password generated"

                            #-Create new user object
                            New-ADUser  -Name $account.DisplayName -AccountNotDelegated $true -AccountPassword $SecPwd -Description $account.description `
                                -DisplayName $account.displayName -Enabled $true -GivenName $account.GivenName -SamAccountName $account.sAMAccountName `
                                -Surname $account.surname -UserPrincipalName ($account.sAMAccountName + "@" + (Get-Addomain).DNSRoot) `
                                -Path (Rewrite-OUPath $account.Path) -ErrorAction Stop

                            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> +++ user created: " + $account.displayName
                        
                            #-Export Password
                            if ($KpsFlag) {
                                Try {
                                    [KeePassLib.PwEntry]$KeePassEntry = (New-Object -TypeName 'KeePassLib.PwEntry'($true, $true))
                                    $KeePassEntry.Uuid = [KeePassLib.PwUuid]::New($true)
                                    $KeePassEntry.Strings.Set('Title'   , (New-Object -TypeName 'KeePassLib.Security.ProtectedString'($true, (Get-Date -format "dd-MM-yyyy_HH:mm")   )))
                                    $KeePassEntry.Strings.Set('UserName', (New-Object -TypeName 'KeePassLib.Security.ProtectedString'($true, $account.sAMAccountName)))
                                    $KeePassEntry.Strings.Set('Password', (New-Object -TypeName 'KeePassLib.Security.ProtectedString'($true, $NewPwd)))
                                    $ParentGroup = $KDBX.RootGroup
                                    $ParentGroup.AddEntry($KeePassEntry, $true, $false)
                                    $ParentGroup.Touch($true, $true)
                                    $KDBX.Save($null)
                                    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--->     password stored in keepass database successfully."
                                }
                                Catch {
                                    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "-!!!     ERROR: password could not be stored in the keepass database!"
                                    ($NewPwd + "`t" + $account.DisplayName) | Out-File .\Outputs\AccountsPassword.txt -Append
                                    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--->     password stored in text file as fallback solution."
                                }
                            } 
                            Else {
                                ($NewPwd + "`t" + $account.DisplayName) | Out-File .\Outputs\AccountsPassword.txt -Append
                                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--->     password stored in text file."
                            }
                        } 
                        Catch {
                            # Failed at creating!
                            $ErrIdx++
                            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> !!! user could not be created! (" + $account.sAMAccountName + ")"
                        }
                    }
                }
                
                #-Success: no issue
                if ($ErrIdx -eq 0) { 
                    $result = 0 
                    $ResMess = "no error"
                }
                #-Warning: some were not created and generate an error
                if ($ErrIdx -gt 0 -and $ErrIdx -lt $xmlData.count) { 
                    $result = 1
                    $ResMess = "$ErrIdx out of " + $xmlData.count + " failed"
                }
                #-Error: none were created!
                if ($ErrIdx -ge $xmlData.count) { 
                    $result = 2
                    $ResMess = "error when creating accounts"
                }

            }
            else {
     
                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "-!!! Warning: xmlData is empty!"
                $result = 1
                $ResMess = "No Data to deal with"
            }

        }
        else {

            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "-!!! Error: could not proceed!"
            $result = 2
            $ResMess = "prerequesite failure"
        }   
    }

    ## Exit
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> function return RESULT: $Result"
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "===| INIT  ROTATIVE  LOG "
    if (Test-Path .\Logs\Debug\$DbgFile) {
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Rotate log file......: 1000 last entries kept" 
        if (-not((Get-WMIObject win32_operatingsystem).name -like "*2008*")) {
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
#endregion

#region New-AdministrationGroups
Function New-AdministrationGroups {
    <#
        .Synopsis
        Create Tier 0 and Tier 1/2 group objects.
        
        .Description
        from the XML file, the script will look at child elements "group" and their descendant "members" from within the element "groups".
        for each of them, the object will be checked and, if needed, created or updated accordingly.
        the "Path" parameter indicate the object location: use ROOTDN to dynamically add your domain DistinguishedName (DC=...,DC=...).
        
        .Notes
        Version: 
            01.01 -- contact@hardenad.net 
        
        history: 
            01.00 -- Script creation
            01.01 -- Add a child domain use case to avoid the group EA creation in childs.
    #>
    param(
    )

    ## Function dynamic OU path rewriting
    Function Rewrite-OUPath ([String]$OUPath) {
        $OUPath2 = $OUPath -replace 'RootDN', (Get-ADDomain).DistinguishedName
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> [OUPath2]: new variable set with [OUPath] data and ROOTDN replaced. New value: $OUPath2"    
        return $OUPath2
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

    ## Main action
    ## Import xml file with OU build requierment
    Try { 
        $xmlSkeleton = [xml](Get-Content .\Configs\TasksSequence_HardenAD.xml -Encoding utf8 -ErrorAction Stop)
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> xml skeleton file........: loaded successfully"
        $xmlLoaded = $true
    }
    Catch {
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "-!!! FAILED loading xml skeleton file "
        $xmlLoaded = $false
    }    

    ## If xml loaded, begining check and create...
    if ($xmlLoaded) {
        ## Log loop start
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> variable XmlLoaded.......: $xmlLoaded"
        
        ## Creating a variable to monitor failing tasks
        $noError = $true
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> variable noError.........: $noError"
        
        ## When dealing with 2008R2, we need to import AD module first
        if ((Get-WMIObject win32_operatingsystem).name -like "*2008*") {
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> is windows 2008/R2.......: True"
        
            Try { 
                Import-Module ActiveDirectory
                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> OS is 2008/R2, added AD module."    
            } 
            Catch {
                $noError = $false
                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "-!!! ERROR! OS is 2008/R2, but the script could not add AD module." 
                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> variable noError.........: $noError"
            }
        }
        else {

            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> is windows 2008/R2.......: False"
        }

        ## if Everything run smoothly, let's begin.
        if ($noError) {
            ## Getting root DNS name
            $DomainRootDN = (Get-ADDomain).DistinguishedName
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Parameter DomainRootDN...: $DomainRootDN"

            ## Getting root domain name
            $ForestDomain = (Get-ADDomain).Forest
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Parameter ForestDomain...: $ForestDomain"

            ## Getting specified schema
            $xmlData = @()
            $xmlData += $xmlSkeleton.settings.groups.group
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> .........................: xml data loaded (" + $xmlData.count + " group(s))"

            ## if we got data, begining creation loop
            if ($xmlData) {
                #-Failing Creation index
                $ErrIdx = 0
                
                #.Begin object creation loop
                foreach ($account in $xmlData) {
                    #-Ensure this is not EA in a child domain
                    if ($account.Name -eq 'Enterprise Admins' -or $account.Name -like 'Administrateurs de l*') {
                        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Enterprise Admins Group: Detected."
                        if ($ForestDomain -ne ($xmlSkeleton.Settings.Translation.wellKnownID | Where-Object { $_.translateFrom -eq '%domaindns%' }).translateTo) {
                            ## Do not create it, move to next group.
                            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Enterprise Admins Group: working in a child domain! Skipping."
                            continue
                        }
                        Else {
                            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Enterprise Admins Group: root domain - will manage from here."
                        }
                    }
                    #-Create a LDAP search filter
                    $Searcher = New-Object System.DirectoryServices.DirectorySearcher($DomainRootDN)
                    $Searcher.Filter = "(&(ObjectClass=Group)(sAMAccountName=" + $account.Name + "))"

                    #.Check if the object already exists
                    if ($Searcher.FindAll() -ne $null) {
                        ## Account is Present
                        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> .........................: === " + $account.Name + " already exists"
                        $AddUser = $true
                    }
                    Else {
                        ## Create Group
                        Try {
                            #-Create new group object
                            New-ADGroup -Name $account.Name -Description $account.description -Path (Rewrite-OUPath $account.Path) -GroupCategory $account.Category -GroupScope $account.Scope -ErrorAction Stop 
                            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> +++ group created: " + $account.Name
                            $AddUser = $true
                        } 
                        Catch {
                            # Failed at creating!
                            $ErrIdx++
                            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> .........................: !!! group could not be created! (" + $account.Name + ")"
                            $AddUser = $false
                        }
                    }

                    #.Logging AddUser value
                    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Parameter AddUser........: $AddUser"
                    #.Adding members to group, if any
                    if ($AddUser) {
                        #.Collection members forthis specific group
                        $members = $account.Member
                        #.create a collection object with all members
                        $MbrsList = @()
                        foreach ($member in $members) {
                            $MbrsList += $member.sAMAccountName
                            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> .........................: +++ adding member: " + $member.SAMAccountName
                        }
                        #.Adding members
                        Try {
                            if ($members) {
                                Add-ADGroupMember -Identity $account.Name -Members $MbrsList | Out-Null
                                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> .........................: +++ all members added successfully."
                            }
                            Else {
                                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> .........................: === No members to add."
                            }
                        }
                        Catch {
                            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> .........................: !!! Failed to add new members!"
                            $ErrIdx++
                        }
                    }
                    Else {
                        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> .........................: !!! members could not be added! (" + $account.Name + ")"
                    }
                }
                
                #-Success: no issue
                if ($ErrIdx -eq 0) { 
                    $result = 0 
                    $ResMess = "no error"
                }
                #-Warning: some were not created and generate an error
                if ($ErrIdx -gt 0 -and $ErrIdx -lt $xmlData.count) { 
                    $result = 1
                    $ResMess = "$ErrIdx out of " + $xmlData.count + " failed"
                }
                #-Error: none were created!
                if ($ErrIdx -ge $xmlData.count) { 
                    $result = 2
                    $ResMess = "error when creating accounts"
                }
            }
            else {
     
                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "-!!! Warning: xmlData is empty!"
                $result = 1
                $ResMess = "No Data to deal with"
            }
        }
        else {

            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "-!!! Error: could not proceed!"
            $result = 2
            $ResMess = "prerequesite failure"
        }   
    }

    ## Exit
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> function return RESULT: $Result"
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "===| INIT  ROTATIVE  LOG "
    if (Test-Path .\Logs\Debug\$DbgFile) {
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Rotate log file......: 1000 last entries kept" 
        if (-not((Get-WMIObject win32_operatingsystem).name -like "*2008*")) {
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
#endregion

#region Reset-GroupMembership
Function Reset-GroupMembership {
    <#
        .Synopsis
        Reset or update group members, based on <DefaultMembers> input.
        
        .Description
        The TasksSequence_HardenAD.xmpl file contains the mandatory members of each groups to flush/update. 
        
        .Notes
        Version: 
            01.00 -- contact@hardenad.net 
			02.00 -- contact@hardenad.net 
            03.00 -- contact@hardenad.net
        history: 
            01.00 -- Script creation
            01.01 -- Removed unecessary xmlSkeleton call. Added use case managment when a group is empty.
			02.00 -- Removed logging data. Added Dynamic replacement for input data.
            03.00 -- Added call management per group to update or replace. Logging is back, too.
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

    $Result = 0
    ## Main action
    ## Import xml file with OU build requierment
    Try { 
        $xmlSkeleton = [xml](Get-Content .\Configs\TasksSequence_HardenAD.xml -ErrorAction Stop -Encoding utf8)
        $xmlLoaded = $true
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> XML Skeleton loaded successfully (TasksSequence_HardenAD.xml)"
    }
    Catch {
        $xmlLoaded = $false
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "-!!! Error: XML Skeleton could not be loaded (TasksSequence_HardenAD.xml)"
    }

    ## If xml loaded, begining check and create...
    if ($xmlLoaded) {
        ## Creating a variable to monitor failing tasks
        $noError = $true
        
        ## When dealing with 2008R2, we need to import AD module first
        if ((Get-WMIObject win32_operatingsystem).name -like "*2008*") {
            Try { 
                Import-Module ActiveDirectory
            } 
            Catch {
                $noError = $false
                $Result = 2
                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "-!!! Error: could not load the ActiveDirectory module on a 2k8 system"
            }
        } 
        
        if ($noError) {
            ## recover XML data
            $xmlGroups = $xmlSkeleton.Settings.DefaultMembers
            $Translat = $xmlSkeleton.Settings.Translation

            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> New parameter: xmlGroups (xmlSkeleton.Settings.DefaultMembers)"
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> New parameter: Translat  (xmlSkeleton.Settings.Translation   )"

            ## Recover domain data
            $DomainSID = (Get-ADDomain).DomainSID

            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> New parameter: DomainSID=$DomainSID"

            ## Reset loop
            foreach ($group in $xmlGroups.group) {
                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> WORKING ON: $($group.target)"
                #.Group identity
                $GroupID = $group.target -replace '%domainSid%', $DomainSID
                $Action = $group.AllowedTo

                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---- --> GroupID is...: '$GroupID'"
                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---- --> AllowedTo....: $Action"

                #.Create mandatory members list
                $mbrLists = @()
                foreach ($member in $group.Member) {
                    ## Convert %DomainSID% if needded
                    $mbrTranslated = $member -replace '%domainsid%', $DomainSID
                    
                    ## Dynamic replacement
                    foreach ($transID in $translat.wellKnownID) {
                        $mbrTranslated = $mbrTranslated -replace $TransID.translateFrom, $TransID.translateTo
                    }
                    
                    ## Double test to discover the object class and run the proper command
                    ##This is not a clean approach but... It works :)
                    $test = $false
                    # is user ?
                    try {
                        $mbrObj = Get-ADUser $mbrTranslated
                        $test = $true
                        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---- --> Allowed user.....: $($mbrObj.samAccountName)"
                    }
                    Catch {
                        $test = $false
                    }
                    
                    # is group ?
                    if (-not($test)) {
                        try {
                            $mbrObj = Get-ADGroup $mbrTranslated
                            $test = $true
                            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---- --> Allowed group....: $($mbrObj.samAccountName)"
                        }
                        Catch {
                            $test = $false
                        }
                    }

                    ## Adding object to a table for a futur comparison with existing members
                    if ($test) {
                        $mbrLists += $mbrObj
                    }
                }

                ## Get the Group Object
                Try {
                    $groupTarget = Get-ADGroup $GroupID -ErrorAction SilentlyContinue
                    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---- --> Retrieved group members from $($groupTarget) and analyzing them..."
                    $isOK = $true
                }
                Catch {
                    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---- !!! ERROR: $groupID could not be found in the domain!"
                    $Result = 1
                    $isOK = $false
                }

                ## Get the Group members
                if ($isOK) {
                    $MbrInIt = @()
                    $MbrInIt += Get-ADGroupMember $groupTarget

                    ## Cleaning group and adding missing users
                    foreach ($badID in (Compare-Object $MbrInIt $mbrLists -IncludeEqual)) {
                        ## Side Indicator: should not be in
                        if ($badID.SideIndicator -eq "<=" -and $Action -eq 'Enforce') {
                            # Action allow to remove an unwanted member
                            Try {
                                Remove-ADGroupMember -Identity $groupID -Members $badID.InputObject -Confirm:$false
                                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---- <<< REMOVED: $($badID.InputObject)"
                            }
                            Catch {
                                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---- !!! ERROR..: $($badID.InputObject) could not be removed from group!"
                                $Result = 1
                            }
                        }
                        ## Side Indicator: should be in
                        if ($badID.SideIndicator -eq "=>") {
                            # Well, dude, get in :)
                            Try {
                                Add-ADGroupMember -Identity $groupID -Members $badID.InputObject -Confirm:$false
                                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---- >>> ADDED..: $($badID.InputObject)"
                            }
                            Catch {
                                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---- !!! ERROR..: $($badID.InputObject) could not be added to group!"
                                $Result = 1
                            }
                        }
                        ## Side Indicator: allowed to be in
                        if ($badID.SideIndicator -eq "==") {
                            # Just a trapping for the log
                            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---- === KEEP...: $($badID.InputObject)"
                        }

                    }
                }
            }
        }
    }

    #.Exit
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> function return RESULT: $Result"
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "===| INIT  ROTATIVE  LOG "
    if (Test-Path .\Logs\Debug\$DbgFile) {
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Rotate log file......: 1000 last entries kept" 
        if (-not((Get-WMIObject win32_operatingsystem).name -like "*2008*")) {
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
#endregion

#region Add-SourceToDestGrps
function Add-SourceToDestGrps {
    param (
        [Parameter(Mandatory)]
        [string]
        $SrcDomDns,
        
        [Parameter(Mandatory)]
        [string]
        $DestDomDns,

        [Parameter(Mandatory)]
        [pscredential]$Cred
    )

    $res = @()

    #.Loading the configuration xml file
    $xmlSkeleton = [xml](Get-Content ".\Configs\TasksSequence_HardenAD.xml" -Encoding utf8)
    
    #.Retrieving dynamic data...
    [string]$OUadmin = ($xmlSkeleton.Settings.Translation.wellKnownID | Where-Object { $_.translateFrom -eq "%OU-Adm%" }).translateTo
    [string]$OUtier0 = ($xmlSkeleton.Settings.Translation.wellKnownID | Where-Object { $_.translateFrom -eq "%OU-Adm-Groups-T0%" }).translateTo
    [string]$OUtier1 = ($xmlSkeleton.Settings.Translation.wellKnownID | Where-Object { $_.translateFrom -eq "%OU-Adm-Groups-T1%" }).translateTo
    [string]$OUtier2 = ($xmlSkeleton.Settings.Translation.wellKnownID | Where-Object { $_.translateFrom -eq "%OU-Adm-Groups-T2%" }).translateTo
    [string]$OUt1Leg = ($xmlSkeleton.Settings.Translation.wellKnownID | Where-Object { $_.translateFrom -eq "%OU-Adm-Groups-T1L%" }).translateTo
    [string]$OUt2Leg = ($xmlSkeleton.Settings.Translation.wellKnownID | Where-Object { $_.translateFrom -eq "%OU-Adm-Groups-T2L%" }).translateTo
    [string]$GrpGlob = ($xmlSkeleton.Settings.Translation.wellKnownID | Where-Object { $_.translateFrom -eq "%prefix-global%" }).translateTo
    [string]$GrpDloc = ($xmlSkeleton.Settings.Translation.wellKnownID | Where-Object { $_.translateFrom -eq "%prefix-DomLoc%" }).translateTo
    [string]$T0 = ($xmlSkeleton.Settings.Translation.wellKnownID | Where-Object { $_.translateFrom -eq "%isT0%" }).translateTo
    [string]$T1 = ($xmlSkeleton.Settings.Translation.wellKnownID | Where-Object { $_.translateFrom -eq "%isT1%" }).translateTo
    [string]$T2 = ($xmlSkeleton.Settings.Translation.wellKnownID | Where-Object { $_.translateFrom -eq "%isT2%" }).translateTo
    [string]$T1L = ($xmlSkeleton.Settings.Translation.wellKnownID | Where-Object { $_.translateFrom -eq "%isT1Leg%" }).translateTo
    [string]$T2L = ($xmlSkeleton.Settings.Translation.wellKnownID | Where-Object { $_.translateFrom -eq "%isT2Leg%" }).translateTo

    #.Getting domain details
    $Src_Domain = Get-ADDomain -Server $SrcDomDns
    $Dest_Domain = Get-ADDomain -Server $DestDomDns

    #.Filtering on administration OU to avoid false positive and speed-up the script execution time
    $Src_AdministrationOU = Get-ADOrganizationalUnit -Filter { Name -eq $OUadmin } -Server $Src_Domain.DNSRoot
    $Dest_AdministrationOU = Get-ADOrganizationalUnit -Filter { Name -eq $OUAdmin } -Server $Dest_Domain.DNSRoot

    #.Creating array for matching purpose
    $arrTier = @($t0, $T1, $T2, $T1L, $T2L)
    $arrOUph = @($OUtier0, $OUtier1, $OUtier2, $OUt1Leg, $OUt2Leg)

    #.Looping accross tiers
    #foreach ($Tier in @($T0, $T1, $T2, $T1L, $T2L)) 
    for ($i = 0 ; $i -lt $arrTier.count ; $i++) {
        #.Flushing groups data
        $Src_GSGroups = $null
        $Dest_GSGroups = $null

        #.Building Lookup structure
        $LookupLSTX = "$GrpDloc$($arrTier[$i])"
        $LookupGS = "$GrpGlob$($arrTier[$i])*"
        $LookupGroupOU = $arrOUph[$i]

        #.Finding objects
        $Src_GroupsOU = Get-ADOrganizationalUnit -Filter { Name -eq $LookupGroupOU } -SearchBase $Src_AdministrationOU.DistinguishedName  -Server $Src_Domain.DNSRoot
        $Dest_GroupsOU = Get-ADOrganizationalUnit -Filter { Name -eq $LookupGroupOU } -SearchBase $Dest_AdministrationOU.DistinguishedName -Server $Dest_Domain.DNSRoot
      
        #.Filling-up group membership
        if ($Src_GroupsOU -and $Dest_GroupsOU) {
            #.Find source and destination domain local groups 
            $Src_LSTX = Get-ADGroup -Filter { Name -eq $LookupLSTX } -SearchBase $Src_GroupsOU.DistinguishedName  -SearchScope OneLevel -Server $Src_Domain.DNSRoot
            $Dest_LSTX = Get-ADGroup -Filter { Name -eq $LookupLSTX } -SearchBase $Dest_GroupsOU.DistinguishedName -SearchScope OneLevel -Server $Dest_Domain.DNSRoot

            #.Find source and destination global groups
            $Src_GSGroups = Get-ADGroup -Filter { Name -like $LookupGS } -SearchBase $Src_GroupsOU.DistinguishedName  -SearchScope OneLevel -Server $Src_Domain.DNSRoot
            $Dest_GSGroups = Get-ADGroup -Filter { Name -like $LookupGS } -SearchBase $Dest_GroupsOU.DistinguishedName -SearchScope OneLevel -Server $Dest_Domain.DNSRoot

            if ($Src_LSTX -and $Dest_GSGroups) {
                $Dest_GSGroups | ForEach-Object {
                    try {
                        Add-ADGroupMember -Identity $Src_LSTX -Members $_ -Credential $Cred
                    } 
                    catch {
                        $res += "$($Src_LSTX.DistinguishedName): $($_.Exception.Message)"
                    } 
                }
            }

            if ( $Dest_LSTX -and $Src_GSGroups) {
                $Src_GSGroups | ForEach-Object {
                    try {
                        Get-ADGroup $Dest_LSTX -Server $DestDomDns -Credential $Cred | Add-ADGroupMember -Members (Get-ADGroup $_ -Server $SrcDomDns) -Credential $Cred
                    }
                    catch {
                        $res += "$($Dest_LSTX.DistinguishedName): $($_.Exception.Message)"
                    }
                }
            }
        }
    }
    return $res
}
#endregion

#region Add-ManagerToEA
function Add-ManagerToEA {
    <#
        .Synopsis
        This function is used to add T0 manager to the Enterprise Admins group. 

        .Parameter SrcDomain
        Source Domain Name (root domain)

        .parameter Cred
        PSCredential of a root domain EA admin.

        .Notes
        Version: 01.02.000
        Author: contact@hardenad.net
        History:
            01.01.000: replaced the static group name for T0 Manager by a dynamic querie to the Translation section.
            01.02.000: fixed issue with cross domain group creation.  
    #>
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]
        $SrcDomain,

        [pscredential]
        $Cred
    )
    #.Loading the configuration xml file
    $xmlSkeleton = [xml](Get-Content ".\Configs\TasksSequence_HardenAD.xml" -Encoding utf8)
    
    #.Retrieving Enterprise Admins group name, Tier 0 Managers group name and RootDomainDNS
    [string]$EAName = ($xmlSkeleton.Settings.Translation.wellKnownID | Where-Object { $_.translateFrom -eq "%EnterpriseAdmins%" }).translateTo
    [string]$T0Mngr = ($xmlSkeleton.Settings.Translation.wellKnownID | Where-Object { $_.translateFrom -eq "%t0-managers%" }).translateTo

    #.Getting domain objects to ensure that we query the Root Domain in a multi domain environment.
    $RootDomainDns = (Get-ADForest).RootDomain
    $RootEA = Get-ADGroup -Identity $EAName -Server $RootDomainDns -ErrorAction Stop
    $GST0Man = Get-ADGroup -Identity $T0Mngr -Server $SrcDomain     -ErrorAction Stop

    #.Adding the group Tier 0 Managers to the Group Enterprise Admins
    Try {
        Get-ADGroup $RootEA.DistinguishedName -Server $RootDomainDns -Credential $Cred | Add-ADGroupMember -Members (Get-ADGroup $GST0Man -Server $SrcDomain)
        $result = 0
    }
    Catch {
        $result = 2
    }
    #.Return result
    return $result
}
#endregion

#region Add-GroupsOverDomain
function Add-GroupsOverDomain {
    <#
        .Synopsis
        Used to determine which domain will be available for cross integration.

        .Notes
        Author:     
            contact@hardenad.net
        history:
            01.00.000   Script creation
            01.01.000   Replaced the static group name for T0 Manager by a dynamic query to the <translation> section.
            01.02.000   Fixed issue with cross domain group creation.
    #>
    # Vérifier qu'il y a plusieurs domaine dans la forêt
    $DbgFile = 'Debug_{0}.log' -f $MyInvocation.MyCommand
    $dbgMess = @()

    ## Start Debug Trace
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "****"
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "**** FUNCTION STARTS"
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "****"

    ## Indicates caller and options used
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Function caller..........: " + (Get-PSCallStack)[1].Command

    #.Loading the configuration xml file
    Try {
        $xmlSkeleton = [xml](Get-Content .\Configs\TasksSequence_HardenAD.xml -Encoding utf8)
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Successfuly loaded TasksSequence_HardenAD.xml to memory" + (Get-PSCallStack)[1].Command
    }
    Catch {
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "-!!! !!! Error: could not load TasksSequence_HardenAD.xml file!" + (Get-PSCallStack)[1].Command
    }

    #.Retrieving Enterprise Admins group name and Tier 0 Managers group name
    [string]$T0Mngr = ($xmlSkeleton.Settings.Translation.wellKnownID | Where-Object { $_.translateFrom -eq "%t0-managers%" }).translateTo
    
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Tier 0 Manager group name: $T0Mngr" + (Get-PSCallStack)[1].Command

    #.Initialize result value.
    $result = 0

    $Forest = Get-ADForest

    if ($Forest.Domains.Count -eq 1 -and $Forest.Domains -eq $Forest.RootDomain) {
        $result = 0
    }
    else {
        $AllDomains = $Forest.Domains
        $ValidDomains = @()

        #.Ask for EA Admin cred.
        $EAadmin = Get-Credential -Message "Provide a Tier 0 Manager account from $($Forest.RootDomain)"

        foreach ($Domain in $AllDomains) {
            try {
                $res = [bool](Get-ADGroup -Filter { Name -eq $T0Mngr } -Server $Domain)
            }
            catch [Microsoft.ActiveDirectory.Management.ADServerDownException] {
                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> .........................: !!! ($($Domain)) could not be joined!"
                Continue
            }
            if ($res) {
                $ValidDomains += $Domain
                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> .........................: +++ ($($Domain)) will be used for cross integration!"
            }
            else {
                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> .........................: !!! Harden AD don't seems to be deployed on ($($Domain))!"
            }
        }
        if ($ValidDomains.Count -gt 1) {
            for ($i = 0; $i -lt $ValidDomains.Count; $i++) {

                Add-ManagerToEA -SrcDomain $ValidDomains[$i] -Cred $EAadmin
    
                for ($j = $i + 1; $j -lt $ValidDomains.Count; $j++) {
                    # Cross ajout des groupes aux bons endroits
                    $res = Add-SourceToDestGrps -SrcDomDns $ValidDomains[$i] -DestDomDns $ValidDomains[$j] -Cred $EAadmin
                    if ($res.Count -eq 0) {
                        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> .........................: +++ The cross integration worked as expected!"
                        $ResMess = "Cross integration works successfully."
                        $Result = 0
                    }
                    else {
                        foreach ($value in $res) {
                            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> .........................: !!! cross integration has encountered an error with: ($($Value))!"
                        }
                        $ResMess = "An error occured with at least one domain."
                        $Result = 2
                    }
                }
            }    
        }
    }

    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> function return RESULT: $Result"
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "===| INIT  ROTATIVE  LOG "
    if (Test-Path .\Logs\Debug\$DbgFile) {
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Rotate log file......: 1000 last entries kept" 
        if (-not((Get-WMIObject win32_operatingsystem).name -like "*2008*")) {
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

#endregion

#region Set-TreeOU
Function Set-TreeOU {
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
        Version: 01.00.000 -- contact@hardenad.net 
        history: 2021/06.08 - Script creation
    #>
    param(
        [Parameter(mandatory = $true, Position = 0)]
        [String]
        $ClassName
    )

    ## Function to loop OU creation
    Function CreateOU ($OUObject, $OUPath) {
        $dbgMess = @()
        
        ## Testing if OU is already present
        if ([adsi]::exists(("LDAP://OU=" + $OUOBject.Name + "," + $OUPath))) {
            $hrOUs = (("OU=" + $OUOBject.Name + "," + $OUPath) -split "," -replace "OU=", "") -replace "DC=", ""
            for ($i = $hrOUs.count - 1 ; $i -ge 0 ; $i--) {
                $hrOUname += " | " + $hrOUs[$i] 
            }
            
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> === $hrOUname (already exists)"

        }
        Else {
            $hrOUs = (("OU=" + $OUOBject.Name + "," + $OUPath) -split "," -replace "OU=", "") -replace "DC=", ""
            for ($i = $hrOUs.count - 1 ; $i -ge 0 ; $i--) {
                $hrOUname += " | " + $hrOUs[$i] 
            }
            Try {
                New-ADOrganizationalUnit -Name $OUObject.Name -Path $OUPath -Description $OUObject.Description -ErrorAction Stop
                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> +++ $hrOUname (success)"
            } 
            Catch {
                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> !!! $hrOUname (failure)"
            }
        }
        
        ## Looking for sub organizational unit(s)...        
        if ($OUOBject.ChildOU) {
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
    }
    Catch {
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---! FAILED loading xml skeleton file "
        $xmlLoaded = $false
    }

    ## If xml loaded, begining check and create...
    if ($xmlLoaded) {
        ## Log loop start
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> variable XmlLoaded.......: $xmlLoaded"
        
        ## Creating a variable to monitor failing tasks
        $noError = $true

        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> variable noError.........: $noError"
        
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

        if ($noError) {
            ## Getting root DNS name
            $DomainRootDN = (Get-ADDomain).DistinguishedName
     
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Parameter DomainRootDN...: $DomainRootDN"

            ## Getting specified schema
            $xmlData = $xmlSkeleton.settings.OrganizationalUnits.ouTree.OU | Where-Object { $_.class -eq $ClassName }
     
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> xml data loaded (" + $xmlData.ChildOU.count + " child's OU - class=$ClassName)"

            ## if we got data, begining creation loop
            if ($xmlData) {
                if ([adsi]::exists(("LDAP://OU=" + $xmlData.Name + "," + $DomainRootDN))) {
                    ## OU Present
                    $hrOUs = (("OU=" + $xmlData.Name + "," + $DomainRootDN) -split "," -replace "OU=", "") -replace "DC=", ""
                    for ($i = $hrOUs.count - 1 ; $i -ge 0 ; $i--) {
                        $hrOUname += " | " + $hrOUs[$i] 
                    }
                    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> === $hrOUname  already exists"

                }
                Else {
                    ## Create Root OU
                    $hrOUs = (("OU=" + $xmlData.Name + "," + $DomainRootDN) -split "," -replace "OU=", "") -replace "DC=", ""
                    for ($i = $hrOUs.count - 1 ; $i -ge 0 ; $i--) {
                        $hrOUname += " | " + $hrOUs[$i] 
                    }
                    Try {
                        New-ADOrganizationalUnit -Name $xmlData.Name -Description $xmlData.Description -Path $DomainRootDN
                        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> +++ $hrOUname created"
                    }
                    Catch {
                        # Failed at creating!
                        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> !!! $hrOUname could not be created!"
                    }
                }
                
                ## Now creating all childs OU
                foreach ($OU in $xmlData.ChildOU) {
                    $dbgMess += CreateOU $OU ("OU=" + $xmlData.Name + "," + $DomainRootDN)
                }

                $result = 0

            }
            else {
     
                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---! Warning: xmlData is empty!"
                $result = 1
            }

        }
        else {

            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---! Error: could not proceed!"
            $result = 2
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
#endregion

#region New-M365OrganizationalUnits
Function New-M365OrganizationalUnits {
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
        Version: 01.00.000 -- contact@hardenad.net 
        history: 2021/06.08 - Script creation

        this function is now deprecated.
    #>
    param(
        [Parameter(mandatory = $true, Position = 0)]
        [String]
        $OUName,

        [Parameter(mandatory = $true, Position = 1)]
        [ValidateSet("Automatic", "Manual")]
        [String]
        $CreationMode,

        [Parameter(mandatory = $False, Position = 2)]
        [String]
        $SearchBase

    )
    ## Function: SEARCH-OU
    function Search-OU ($OUPath) {
        #.Search for objects in OU
        $ObjectU = Get-ADUser     -Filter * -SearchBase $OUPath -SearchScope OneLevel
        $ObjectC = Get-ADComputer -Filter * -SearchBase $OUPath -SearchScope OneLevel
        $ObjectG = Get-ADGroup    -Filter * -SearchBase $OUPath -SearchScope OneLevel

        #.if objects found, create the m365 org. unit
        if ($ObjectU -or $ObjectC -or $ObjectG) {
            if ([adsi]::Exists(("LDAP://OU=" + $OUName + "," + $OUPath))) {
                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> [ANALYZING]: $OUPath - objects found and OU exists (skipped)"
            }
            else {
                Try {
                    if ($OUPath -notlike "OU=Domain Controllers,*") {
                        New-ADOrganizationalUnit -Name $OUName -Path $OUPath -ProtectedFromAccidentalDeletion $False | Out-Null
                        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> [ANALYZING]: $OUPath - objects found and OU created (success)"
                    }
                    else {
                        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> [ANALYZING]: $OUPath - OU Domain Controllers detected (skipped)"
                    }
                }
                Catch {
                    $result = 1
                    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> [ANALYZING]: $OUPath - objects found and OU not created (failed)"
                    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> variable result..........: $result"
                }
            }
        }
        else {
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> [ANALYZING]: $OUPath - No objects found (skipped)"
        }
        #.Looking at next child OU, if any. To be compatible with PowerShell 2.0, we need to check $childOUs also.
        $ChildOUs = Get-ADOrganizationalUnit -Filter * -SearchBase $OUPath -SearchScope OneLevel
        if ($childOUs) {
            foreach ($ChildOU in $ChildOUs) {
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
    Try { 
        $xmlSkeleton = [xml](Get-Content .\Configs\TasksSequence_HardenAD.xml -Encoding utf8 -ErrorAction Stop)
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> xml skeleton file........: loaded successfully"
        $xmlLoaded = $true
    } 
    Catch {
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---! FAILED loading xml skeleton file "
        $xmlLoaded = $false
    }

    ## When dealing with 2008R2, we need to import AD module first
    $noError = $true
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

    ## If xml loaded, build OUs
    If ($xmlLoaded -and $noError) {
        ## Success Flag
        $result = 0
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> variable result..........: $result"

        Switch ($CreationMode) {
            ## Automatic mode
            "Automatic" {
                #.Log
                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> [START]..................: automatic mode"
                #.Check prerequesite on SearchBase
                if (-not($SearchBase) -or $SearchBase -eq "") {
                    $SearchBase = (Get-ADDomain).DistinguishedName
                }
                else {
                    $SearchBase = $SearchBase -replace 'RootDN', ((Get-ADDomain).distinguishedName)
                }
                
                #.Check if the base OU exists
                if ([adsi]::exists(("LDAP://" + $SearchBase))) {
                    #.Log
                    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> [CHECK]..................: $SearchBase exists"
                    #.Parse OU tree and look for objects
                    $dbgMess += Search-OU -OUPath $SearchBase
                    #.Dealing if warning encountered while processing
                    if ($DbgFile -match 'variable result..........: 1') {
                        $result = 1
                    }
                }
                else {
                    $result = 2
                    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> [CHECK]..................: $SearchBase does not exists (error)"
                    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> variable resultCode......: $resultCode"
                }
            }
            ## Manual mode
            "Manual" {
                #.Log
                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> [START]..................: manual mode"
                
                #.Getting Targets
                $Targets = $xmlSkeleton.Settings.Microsoft365.target

                #.Looping targets
                foreach ($ztarget in $Targets) {
                    $Target = $ztarget -replace 'RootDN', ((Get-ADDomain).distinguishedName)
                    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> [ANALYZING]..................: $target"
                    if ([adsi]::Exists(("LDAP://" + $target))) {
                        if ([adsi]::Exists(("LDAP://OU=" + $OUName + "," + $target))) {
                            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> [ANALYZING]..................: $target (already exists)"
                        }
                        else {
                            try {
                                New-ADOrganizationalUnit -Name $OUName -Path $target -ProtectedFromAccidentalDeletion $false | Out-Null
                                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> [ANALYZING]..................: $target created (success)"                                              
                            }
                            catch {
                                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> [ANALYZING]..................: $target not created (failed)"
                                $Result = 1
                            }
                        }
                    }
                    else {
                        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> [ANALYZING]..................: $target does not exists (error)"
                        $Result = 2
                    }
                }
            }
        }
    }
    else {
        $result = 2
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Prerequesites............: Failed (error)"
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> variable resultCode......: $resultCode"
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
#endregion

#region Get-GroupNameFromSID
function Get-GroupNameFromSID {
    param (
        [Parameter(Mandatory = $true)]
        [string] $GroupSID
    )

    try {
        $group = New-Object System.Security.Principal.SecurityIdentifier($GroupSID)
        $groupName = $group.Translate([System.Security.Principal.NTAccount]).Value

        if ($groupName -like "*\*") {
            $groupName = $groupName -replace ".*\\", ""
        }

        if ($groupName) {
            return $groupName
        }
        else {
            return "The group with SID '$GroupSID' was not found."
        }
    }
    catch {
        Write-Host "An error occurred while searching for the group with SID '$GroupSID'."
        $inputValid = $false
        $userInput = $null
        return $userInput
    }
}
#endregion

