##################################################################
## Set-HardenACL                                                ##
## -------------                                                ##
## This function will set ACL on a target OU                    ##
##                                                              ##
## Version: 01.00.000                                           ##
##  Author: contact@hardenad.net                                ##
##################################################################
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

##################################################################
## Push-DelegationModel                                         ##
## --------------------                                         ##
## This function will push ACL on a domain                      ##
##                                                              ##
## Version: 01.00.000                                           ##
##  Author: Constantin Hager                                    ##
##################################################################
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

##################################################################
## New-ADDGuidMap                                               ##
## --------------                                               ##
## This function will return Standard Right guid map            ##
##                                                              ##
## Version: 01.00.000                                           ##
##  Author: Constantin Hager                                    ##
##################################################################
function New-ADDGuidMap {
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

##################################################################
## New-ADDExtendedRightMap                                      ##
## -----------------------                                      ##
## This function will return extendedRight guid map             ##
##                                                              ##
## Version: 01.00.000                                           ##
##  Author: contact@hardenad.net                                ##
##################################################################
function New-ADDExtendedRightMap {
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

##################################################################
## Set-HardenSDDL                                               ##
## --------------                                               ##
## This function will push custom ACL on a target               ##
##                                                              ##
## Version: 01.00.000                                           ##
##  Author: contact@hardenad.net                                ##
##################################################################
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

Export-ModuleMember -Function *