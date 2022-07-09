##################################################################
## Set-HardenACL                                                ##
## -------------                                                ##
## This function will set ACL on a target OU                    ##
##                                                              ##
## Version: 01.00.000                                           ##
##  Author: contact@hardenad.net                                ##
##################################################################
Function Set-HardenACL 
{ 
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
        [ValidateSet("group","user","computer","contact","member")]
        [string]
        $ObjectType
    )

    #.Move location to AD to simplify AD manipulation
    Push-Location AD:
    try   {
            $acl   = Get-Acl ("AD:\" + $targetDN)
            $group = Get-ADGroup $trustee
            $sid   = New-Object System.Security.Principal.SecurityIdentifier $($group.SID)
            
            if ($inheritedObjects -ne "" -and $Null -ne $inheritedObjects) 
            {
                switch ($inheritedObjects) 
                {
                    "group"    { $inheritanceguid = New-Object Guid bf967a9c-0de6-11d0-a285-00aa003049e2 }
                    "user"     { $inheritanceguid = New-Object Guid bf967aba-0de6-11d0-a285-00aa003049e2 }
                    "computer" { $inheritanceguid = New-Object Guid bf967a86-0de6-11d0-a285-00aa003049e2 }
                    "contact"  { $inheritanceguid = New-Object Guid 5cb41ed0-0e4c-11d0-a286-00aa003049e2 }
                    "member"   { $inheritanceguid = New-Object Guid bf9679c0-0de6-11d0-a285-00aa003049e2 }
                }
            } else {
                
                $inheritanceguid = New-Object Guid 00000000-0000-0000-0000-000000000000
            }

            if ($ObjectType -ne "" -and $Null -ne $ObjectType) 
            {
                switch ($ObjectType) 
                {
                    "group"    { $Objectguid = New-Object Guid bf967a9c-0de6-11d0-a285-00aa003049e2 }
                    "user"     { $Objectguid = New-Object Guid bf967aba-0de6-11d0-a285-00aa003049e2 }
                    "computer" { $Objectguid = New-Object Guid bf967a86-0de6-11d0-a285-00aa003049e2 }
                    "contact"  { $Objectguid = New-Object Guid 5cb41ed0-0e4c-11d0-a286-00aa003049e2 }
                    "member"   { $Objectguid = New-Object Guid bf9679c0-0de6-11d0-a285-00aa003049e2 }
                }
            } else {
            
                $Objectguid = New-Object Guid 00000000-0000-0000-0000-000000000000
            }

        $identity        = [System.Security.Principal.IdentityReference] $SID
        $adRights        = [System.DirectoryServices.ActiveDirectoryRights] $right
        $type            = [System.Security.AccessControl.AccessControlType] $rightType
        $inheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance] $inheritance
        $ace             = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $identity, $adRights, $type, $Objectguid, $inheritanceType, $inheritanceguid
        
        $acl.AddAccessRule($ace)

        Set-Acl -AclObject $acl -Path ("AD:\" + ($targetDN)) -ErrorAction SilentlyContinue
        
        #Write-Log -Type "ACTION" -Level "Global" -String "Giving $adRights to $trustee on $targetDN." -ModuleName $ModuleName -G_debug $G_debug
        $Result = $true
    }
    catch {
        #Write-Log -Type "ERROR" -Level "Global" -String "Error giving $adRights to $trustee on $targetDN. : $($Error[0].exception.message)" -ModuleName $ModuleName -G_debug $G_debug
        $Result = $False
    }
    #.Reset location 
    Pop-Location
    #.Return result
    Return $Result
}

Function Push-DelegationModel
{
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

        ## if Everything run smoothly, let's begin.
        if ($noError)
        {
            ## Getting root DNS name
            $DomainRootDN = (Get-ADDomain).DistinguishedName
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Parameter DomainRootDN...: $DomainRootDN"

            ## Getting specified schema
            $xmlData = $xmlSkeleton.settings.DelegationACEs.ACL
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> .........................: xml data loaded (" + $xmlData.count + " ACL(s))"
            
            ## if we got data, begining creation loop
            if ($xmlData)
            {
                #-Failing Creation index
                $ErrIdx = 0
                
                #.Begin object creation loop
                foreach ($HADacl in $xmlData)
                {
                    Switch ($HADacl.InheritedObjects)
                    {
                        ""      { $result = Set-HardenACL -TargetDN        ($HADacl.TargetDN -replace "RootDN",$DomainRootDN) `
                                                          -Trustee          $HADacl.Trustee `
                                                          -Right            $HADacl.Right`
                                                          -RightType        $HADacl.RightType`
                                                          -Inheritance      $HADacl.Inheritance`
                                                          -ObjectType       $HADacl.ObjectType
                                }
                        Default { $result = Set-HardenACL -TargetDN        ($HADacl.TargetDN -replace "RootDN",$DomainRootDN) `
                                                          -Trustee          $HADacl.Trustee `
                                                          -Right            $HADacl.Right`
                                                          -RightType        $HADacl.RightType`
                                                          -Inheritance      $HADacl.Inheritance`
                                                          -InheritedObjects $HADacl.InheritedObjects
                                }
                    }
                    if ($result)
                    {
                        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> +++ ACL added: TargetDN= " + ($HADacl.TargetDN -replace "RootDN",$DomainRootDN)
                        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--->                 Trustee= " + $HADacl.Trustee
                        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--->                   Right= " + $HADacl.Right
                        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--->               RightType= " + $HADacl.RightType
                        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--->             Inheritance= " + $HADacl.Inheritance
                        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--->        InheritedObjects= " + $HADacl.InheritedObjects
                        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--->              ObjectType= " + $HADacl.ObjectType
                    } Else {
                        $ErrIdx++
                        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---! !!! ACL ERROR: TargetDN= " + ($HADacl.TargetDN -replace "RootDN",$DomainRootDN)
                        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---!                 Trustee= " + $HADacl.Trustee
                        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---!                   Right= " + $HADacl.Right
                        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---!               RightType= " + $HADacl.RightType
                        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---!             Inheritance= " + $HADacl.Inheritance
                        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---!        InheritedObjects= " + $HADacl.InheritedObjects
                        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---!              ObjectType= " + $HADacl.ObjectType
                    }
                }

                #-Success: no issue
                if ($ErrIdx -eq 0) 
                { 
                    $result = 0 
                    $ResMess = "no error"
                }
                #-Warning: some were not created and generate an error
                if ($ErrIdx -gt 0 -and $ErrIdx -lt $xmlData.count) 
                { 
                    $result = 1
                    $ResMess = "$ErrIdx out of " + $xmlData.count + " failed"
                }
                #-Error: none were created!
                if ($ErrIdx -ge $xmlData.count) 
                { 
                    $result = 2
                    $ResMess = "error when creating ACEs!"
                }

            } else {
        
                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---! Warning: xmlData is empty!"
                $result = 1
                $ResMess = "No Data to deal with"
            }
        } else {
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---! Error: could not proceed!"
            $result = 2
            $ResMess = "prerequesite failure"
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