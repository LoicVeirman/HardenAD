##################################################################
## new-AdministrationAccounts                                   ##
## --------------------------                                   ##
## This function will create the user objects needed to use the ##
## tier model and declared in the taskSequence xml file.        ##
##                                                              ##
## Version: 01.00.000                                           ##
##  Author: loic.veirman@mssec.fr                               ##
##################################################################
Function New-AdministrationAccounts
{
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
            01.00 -- Loic.veirman@mssec.fr
         
         history: 
            01.00 -- Script creation
    #>
    param(
        [Parameter(mandatory=$false)]
        [String]
        $KeepassPwd
    )

    ## Default keepass password
    if (-not($KeepassPwd))
    {
        $KeepassPwd = 'H4rd3n@D!!'
    }

    ## Function dynamic OU path rewriting
    Function Rewrite-OUPath ([String]$OUPath)
    {
        $OUPath2 = $OUPath -replace 'RootDN',(Get-ADDomain).DistinguishedName
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
            $xmlData = $xmlSkeleton.settings.accounts.user
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> xml data loaded (" + $xmlData.count + " account(s))"

            ## if we got data, begining creation loop
            if ($xmlData)
            {
                #-Failing Creation index
                $ErrIdx = 0
            
                #-Reacling Keepass binaries to avoid issue with read-only permissions
                $path   = (Get-Location).Path + "\Tools\KeePass-2.48.1\"
                $pathdb = (Get-Location).Path + "\Outputs\"
                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> binaries path=$path"
                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> database path=$pathdb"
                $GrpName = (Get-ADGroup -filter { Sid -eq "S-1-5-32-545" }).sAMAccountname
                $AceUser = "BUILTIN\" + $GrpName
                Try 
                {
                    $acl = Get-Acl $path
                    $ArgumentsList = $AceUser,,”FullControl”,”ContainerInherit,ObjectInherit”,”None”,”Allow”
                    $AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule -ArgumentList $ArgumentsList
                    $acl.SetAccessRule($AccessRule)
                    Set-Acl $path $acl
                    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> $AceUser now has FULLCONTROL permission on $path"
                }
                Catch
                {
                    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---! ERROR! $AceUser : FULLCONTROL permission on $path failed to be applied!"
                }
                Try
                {
                    $acl = Get-Acl $pathdb
                    $acl.SetAccessRule($AccessRule)
                    Set-Acl $pathdb $acl 
                    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> $AceUser now has FULLCONTROL permission on $pathdb"
                }
                Catch
                {
                    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---! ERROR! $AceUser : FULLCONTROL permission on $pathdb failed to be applied!"
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
                    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---! keepass binaries not found!"
                }
                if ($KpsFlag)
                {
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
                        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---! keepass database not found!"
                    }
                }
                foreach ($account in $xmlData)
                {
                    #-Create a LDAP search filter
                    $Searcher = New-Object System.DirectoryServices.DirectorySearcher($DomainDN)
                    $Searcher.Filter = "(&(ObjectClass=User)(sAMAccountName=" + $account.sAMAccountName + "))"

                    if ($Searcher.FindAll() -ne $null)
                    {
                        ## Account is Present
                        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> === " + $account.DisplayName + " already exists"

                    } Else {
                        ## Create User
                        Try 
                        {
                            #-Generate a random password
                            $NewPwd = $null
                            ((48..57) + (65..90) + (97..122) + 36 + 33) | Get-Random -Count 16 | %{ $NewPwd += [char]$_ }
                            $SecPwd = ConvertTo-SecureString -AsPlainText $NewPwd -Force
                            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> +++ Password generated"

                            #-Create new user object
                            New-ADUser -Name $account.DisplayName -AccountNotDelegated $true -AccountPassword $SecPwd -Description $account.description `
                                       -DisplayName $account.displayName -Enabled $true -GivenName $account.GivenName -SamAccountName $account.sAMAccountName `
                                       -Surname $account.surname -UserPrincipalName ($account.sAMAccountName + "@" + (Get-Addomain).DNSRoot) `
                                       -Path (Rewrite-OUPath $account.Path) -ErrorAction Stop

                            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> +++ user created: " + $account.displayName
                        
                            #-Export Password
                            if ($KpsFlag)
                            {
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
                                    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---!     ERROR: password could not be stored in the keepass database!"
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
                    $ResMess = "error when creating accounts"
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

##################################################################
## new-AdministrationGroups                                     ##
## ------------------------                                     ##
## This function will create the group objects needed to use    ##
## the tier model and declared in the taskSequence xml file.    ##
##                                                              ##
## Version: 01.00.000                                           ##
##  Author: loic.veirman@mssec.fr                               ##
##################################################################
Function New-AdministrationGroups
{
    <#
        .Synopsis
         Create Tier 0 and Tier 1/2 group objects.
        
        .Description
         from the XML file, the script will look at child elements "group" and their descendant "members" from within the element "groups".
         for each of them, the object will be checked and, if needed, created or updated accordingly.
         the "Path" parameter indicate the object location: use ROOTDN to dynamically add your domain DistinguishedName (DC=...,DC=...).
        
        .Notes
         Version: 
            01.00 -- Loic.veirman@mssec.fr
         
         history: 
            01.00 -- Script creation
    #>
    param(
    )

    ## Function dynamic OU path rewriting
    Function Rewrite-OUPath ([String]$OUPath)
    {
        $OUPath2 = $OUPath -replace 'RootDN',(Get-ADDomain).DistinguishedName
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
            $xmlData = $xmlSkeleton.settings.groups.group
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> .........................: xml data loaded (" + $xmlData.count + " group(s))"

            ## if we got data, begining creation loop
            if ($xmlData)
            {
                #-Failing Creation index
                $ErrIdx = 0
                
                #.Begin object creation loop
                foreach ($account in $xmlData)
                {
                    #-Create a LDAP search filter
                    $Searcher = New-Object System.DirectoryServices.DirectorySearcher($DomainDN)
                    $Searcher.Filter = "(&(ObjectClass=Group)(sAMAccountName=" + $account.Name + "))"

                    #.Check if the object already exists
                    if ($Searcher.FindAll() -ne $null)
                    {
                        ## Account is Present
                        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> .........................: === " + $account.Name + " already exists"
                        $AddUser = $true

                    } Else {
                        ## Create Group
                        Try 
                        {
                            #-Create new group object
                            New-ADGroup -Name $account.Name -Description $account.description -Path (Rewrite-OUPath $account.Path) `
                                        -GroupCategory $account.Category -GroupScope $account.Scope -ErrorAction Stop 
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
                    if ($AddUser)
                    {
                        #.Collection members forthis specific group
                        $members = $account.Member
                        #.create a collection object with all members
                        $MbrsList = @()
                        foreach ($member in $members)
                        {
                            $MbrsList += $member.sAMAccountName
                            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> .........................: +++ adding member: " + $member.SAMAccountName
                        }
                        #.Adding members
                        Try
                        {
                            if ($members) 
                            {
                                Add-ADGroupMember -Identity $account.Name -Members $MbrsList | Out-Null
                                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> .........................: +++ all members added successfully."
                            }
                            Else
                            {
                                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> .........................: === No members to add."
                            }
                        }
                        Catch
                        {
                            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> .........................: !!! Failed to add new members!"
                            $ErrIdx++
                        }
                    }
                    Else
                    {
                        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> .........................: !!! members could not be added! (" + $account.Name + ")"
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
                    $ResMess = "error when creating accounts"
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

##################################################################
## Reset-GroupMembership                                        ##
## ---------------------                                        ##
## This function will reset group members and only keeps        ##
## mandatory objects in it                                      ##
##                                                              ##
## Version: 01.00.000                                           ##
##  Author: loic.veirman@mssec.fr                               ##
##################################################################
Function Reset-GroupMembership
{
    <#
        .Synopsis
         Reset group members to its factory default.
        
        .Description
         The TasksSequence_HardenAD.xmpl file contains the mandatory members of each groups to flush. 
        
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
                    $Result = 2
                  }
        } else {
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> is windows 2008/R2.......: False"
        }

        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> Script Starts"
        
        ## recover XML data
        [xml]$xmlSkeleton = Get-Content (".\Configs\TasksSequence_HardenAD.xml") -ErrorAction Stop
        $xmlGroups = $xmlSkeleton.Settings.DefaultMembers

        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> Found " + $xmlGroups.group.count + " group(s) to reset"
        
        ## Recover domain data
        $DomainSID = (Get-ADDomain).DomainSID

        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> Domain SID is $DomainSID"
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> Loop begins"

        ## Reset loop
        foreach ($group in $xmlGroups.group)
        {
            #.Group identity
            $GroupID = ($group.target -replace '%domainSid%',$DomainSID)
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- --- ---> Working on $GroupID"

            #.Create mandatory members list
            $mbrLists = @()
            foreach ($member in $group.Member)
            {
                ## Convert %DomainSID% if needded
                $mbrTranslated = $member -replace '%domainsid%',$DomainSID

                ## Double test to discover the object class and run the proper command
                ##This is not a clean approach but... It works :)
                $test = $false
                try {
                    $mbrObj = Get-ADUser $mbrTranslated
                    $test = $true
                } Catch {
                    $test = $false
                }
                if (-not($test))
                {
                    try {
                        $mbrObj = Get-ADGroup $mbrTranslated
                        $test = $true
                    } Catch {
                        $test = $false
                    }
                }
                ## Adding object to a table for a futur comparison with existing members
                $mbrLists += $mbrObj
            }
            ## Get the Group Object
            $groupTarget = Get-ADGroup $GroupID

            ## Get the Group members
            $MbrInIt = Get-ADGroupMember $groupTarget

            ## Cleaning group and adding missing users
            foreach ($badID in (Compare-Object $MbrInIt $mbrLists))
            {
                ## Side Indicator: should not be in
                if ($badID.SideIndicator -eq "<=")
                {
                    Remove-ADGroupMember -Identity $groupID -Members $badID.InputObject -Confirm:$false
                    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- --- ---> Remove....: " + $badID.inputObject
                }
                ## Side Indicator: should be in
                if ($badID.SideIndicator -eq "=>")
                {
                    Add-ADGroupMember -Identity $groupID -Members $badID.InputObject -Confirm:$false
                    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- --- ---> add.......: " + $badID.inputObject
                }
            }
        }
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> Loop is over"
    }
    
    $Result = 0

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