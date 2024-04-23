##################################################################
## new-AdministrationAccounts                                   ##
## --------------------------                                   ##
## This function will create the user objects needed to use the ##
## tier model and declared in the taskSequence xml file.        ##
##                                                              ##
## Version: 01.00.000                                           ##
##  Author: contact@hardenad.net                                ##
##################################################################
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
    if (-not($KeepassPwd)) 
    {
        $KeepassPwd = 'H4rd3n@D!!'
    }

    ## Function dynamic OU path rewriting
    Function Rewrite-OUPath ([String]$OUPath) 
    {
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
        if ($noError) 
        {
            ## Getting root DNS name
            $DomainRootDN = (Get-ADDomain).DistinguishedName
            $dbgMess     += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Parameter DomainRootDN...: $DomainRootDN"

            ## Getting specified schema
            $xmlData  = $xmlSkeleton.settings.accounts.user
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> xml data loaded (" + $xmlData.count + " account(s))"

            ## Getting Password Parameter Settings
            $xmlParam  = Select-Xml $xmlSkeleton -XPath "//*/Translation/wellKnownID[@objectClass='param']" | Select-Object -ExpandProperty "Node"
            $pwdLength = ($xmlParam | Where-Object { $_.translateFrom -eq '%pwdLength%' }).translateTo
            $pwdNANC   = ($xmlParam | Where-Object { $_.translateFrom -eq '%pwdNonAlphaNumChar%' }).translateTo

            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Password Length.......................: $pwdLength"
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Number of non alpha numeric characters: $pwdNANC"

            ## if we got data, begining creation loop
            if ($xmlData) 
            {
                #-Failing Creation index
                $ErrIdx = 0
            
                #-Reacling Keepass binaries to avoid issue with read-only permissions
                $path     = (Get-Location).Path + "\Tools\KeePass-2.48.1\"
                $pathdb   = (Get-Location).Path + "\Outputs\"
                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> binaries path=$path"
                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> database path=$pathdb"
                $GrpName  = (Get-ADGroup -filter { Sid -eq "S-1-5-32-545" }).sAMAccountname
                $AceUser  = "BUILTIN\" + $GrpName
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
                        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "-!!! keepass database not found!"
                    }
                }
                foreach ($account in $xmlData) 
                {
                    #-Create a LDAP search filter
                    $Searcher = New-Object System.DirectoryServices.DirectorySearcher($DomainRootDN)
                    $Searcher.Filter = "(&(ObjectClass=User)(sAMAccountName=" + $account.sAMAccountName + "))"

                    if ($Searcher.FindAll() -ne $null) 
                    {
                        ## Account is Present
                        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> === " + $account.DisplayName + " already exists"

                    }
                    Else {
                        ## Create User
                        Try {
                            #-Generate a random password
                            $NewPwd = $null
                            
                            Add-Type -AssemblyName 'System.Web'

                            $NewPwd   = [System.Web.Security.Membership]::GeneratePassword($pwdLength, $pwdNANC)
                            $SecPwd   = ConvertTo-SecureString -AsPlainText $NewPwd -Force
                            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> +++ Password generated"

                            #-Create new user object
                            New-ADUser  -Name $account.DisplayName -AccountNotDelegated $true -AccountPassword $SecPwd -Description $account.description `
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
## Version: 01.01.000                                           ##
##  Author: contact@hardenad.net                                ##
##################################################################
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
    Function Rewrite-OUPath ([String]$OUPath) 
    {
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
            $xmlData  = @()
            $xmlData += $xmlSkeleton.settings.groups.group
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> .........................: xml data loaded (" + $xmlData.count + " group(s))"

            ## if we got data, begining creation loop
            if ($xmlData) 
            {
                #-Failing Creation index
                $ErrIdx = 0
                
                #.Begin object creation loop
                foreach ($account in $xmlData) {
                    #-Ensure this is not EA in a child domain
                    if ($account.Name -eq 'Enterprise Admins' -or $account.Name -like 'Administrateurs de l*')
                    {
                        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Enterprise Admins Group: Detected."
                        if ($ForestDomain -ne ($xmlSkeleton.Settings.Translation.wellKnownID | Where-Object { $_.translateFrom -eq '%domaindns%'}).translateTo)
                        {
                            ## Do not create it, move to next group.
                            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Enterprise Admins Group: working in a child domain! Skipping."
                            continue
                        } Else {
                            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Enterprise Admins Group: root domain - will manage from here."
                        }
                    }
                    #-Create a LDAP search filter
                    $Searcher = New-Object System.DirectoryServices.DirectorySearcher($DomainRootDN)
                    $Searcher.Filter = "(&(ObjectClass=Group)(sAMAccountName=" + $account.Name + "))"

                    #.Check if the object already exists
                    if ($Searcher.FindAll() -ne $null) 
                    {
                        ## Account is Present
                        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> .........................: === " + $account.Name + " already exists"
                        $AddUser = $true
                    }
                    Else 
                    {
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
                        Try {
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
## mandatory objects in it (from section <DefaultMembers>)      ##
##                                                              ##
## Version: 03.00.000                                           ##
##  Author: contact@hardenad.net                                ##
##################################################################
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
        $xmlLoaded   = $true
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> XML Skeleton loaded successfully (TasksSequence_HardenAD.xml)"
    }
    Catch {
        $xmlLoaded = $false
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "-!!! Error: XML Skeleton could not be loaded (TasksSequence_HardenAD.xml)"
    }

    ## If xml loaded, begining check and create...
    if ($xmlLoaded) 
    {
        ## Creating a variable to monitor failing tasks
        $noError = $true
        
        ## When dealing with 2008R2, we need to import AD module first
        if ((Get-WMIObject win32_operatingsystem).name -like "*2008*") 
        {
            Try { 
                Import-Module ActiveDirectory
            } 
            Catch {
                $noError = $false
                $Result = 2
                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "-!!! Error: could not load the ActiveDirectory module on a 2k8 system"
            }
        } 
        
        if ($noError)
        {
            ## recover XML data
            $xmlGroups = $xmlSkeleton.Settings.DefaultMembers
            $Translat  = $xmlSkeleton.Settings.Translation

            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> New parameter: xmlGroups (xmlSkeleton.Settings.DefaultMembers)"
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> New parameter: Translat  (xmlSkeleton.Settings.Translation   )"

            ## Recover domain data
            $DomainSID = (Get-ADDomain).DomainSID

            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> New parameter: DomainSID=$DomainSID"

            ## Reset loop
            foreach ($group in $xmlGroups.group) 
            {
                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> WORKING ON: $($group.target)"
                #.Group identity
                $GroupID = $group.target -replace '%domainSid%', $DomainSID
                $Action  = $group.AllowedTo

                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---- --> GroupID is...: '$GroupID'"
                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---- --> AllowedTo....: $Action"

                #.Create mandatory members list
                $mbrLists = @()
                foreach ($member in $group.Member) 
                {
                    ## Convert %DomainSID% if needded
                    $mbrTranslated = $member -replace '%domainsid%', $DomainSID
                    
                    ## Dynamic replacement
                    foreach ($transID in $translat.wellKnownID) 
                    {
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
                    } Catch {
                        $test = $false
                    }
                    
                    # is group ?
                    if (-not($test)) 
                    {
                        try {
                            $mbrObj = Get-ADGroup $mbrTranslated
                            $test = $true
                        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---- --> Allowed group....: $($mbrObj.samAccountName)"
                        } Catch {
                            $test = $false
                        }
                    }

                    ## Adding object to a table for a futur comparison with existing members
                    if ($test)
                    {
                        $mbrLists += $mbrObj
                    }
                }

                ## Get the Group Object
                Try {
                    $groupTarget = Get-ADGroup $GroupID -ErrorAction SilentlyContinue
                    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---- --> Retrieved group members from $($groupTarget) and analyzing them..."
                    $isOK = $true
                } Catch {
                    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---- !!! ERROR: $groupID could not be found in the domain!"
                    $Result = 1
                    $isOK = $false
                }

                ## Get the Group members
                if ($isOK)
                {
                    $MbrInIt = @()
                    $MbrInIt += Get-ADGroupMember $groupTarget

                    ## Cleaning group and adding missing users
                    foreach ($badID in (Compare-Object $MbrInIt $mbrLists -IncludeEqual)) 
                    {
                        ## Side Indicator: should not be in
                        if ($badID.SideIndicator -eq "<=" -and $Action -eq 'Enforce') 
                        {
                            # Action allow to remove an unwanted member
                            Try {
                                Remove-ADGroupMember -Identity $groupID -Members $badID.InputObject -Confirm:$false
                                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---- <<< REMOVED: $($badID.InputObject)"
                            } Catch {
                                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---- !!! ERROR..: $($badID.InputObject) could not be removed from group!"
                                $Result = 1
                            }
                        }
                        ## Side Indicator: should be in
                        if ($badID.SideIndicator -eq "=>") 
                        {
                            # Well, dude, get in :)
                            Try {
                                Add-ADGroupMember -Identity $groupID -Members $badID.InputObject -Confirm:$false
                                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---- >>> ADDED..: $($badID.InputObject)"
                            } Catch {
                                $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---- !!! ERROR..: $($badID.InputObject) could not be added to group!"
                                $Result = 1
                            }
                        }
                        ## Side Indicator: allowed to be in
                        if ($badID.SideIndicator -eq "==")
                        {
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
## Add-SourceToDestGrps                                         ##
## ---------------------                                        ##
## This function is used to cross groups between two            ##
## domains.                                                     ##
##                                                              ##
## Version: 02.01.000                                           ##
##  Author: contact@hardenad.net                                ##
## History:                                                     ##
## 02.00.000: update thole script to use dynamic data.          ##
##                                                              ##
## 02.01.0000: fixed issue with cross domain group creation.    ##
##                                                              ##
##################################################################
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
    $xmlSkeleton    = [xml](Get-Content ".\Configs\TasksSequence_HardenAD.xml" -Encoding utf8)
    
    #.Retrieving dynamic data...
    [string]$OUadmin = ($xmlSkeleton.Settings.Translation.wellKnownID | Where-Object { $_.translateFrom -eq "%OU-Adm%" }).translateTo
    [string]$OUtier0 = ($xmlSkeleton.Settings.Translation.wellKnownID | Where-Object { $_.translateFrom -eq "%OU-Adm-Groups-T0%" }).translateTo
    [string]$OUtier1 = ($xmlSkeleton.Settings.Translation.wellKnownID | Where-Object { $_.translateFrom -eq "%OU-Adm-Groups-T1%" }).translateTo
    [string]$OUtier2 = ($xmlSkeleton.Settings.Translation.wellKnownID | Where-Object { $_.translateFrom -eq "%OU-Adm-Groups-T2%" }).translateTo
    [string]$OUt1Leg = ($xmlSkeleton.Settings.Translation.wellKnownID | Where-Object { $_.translateFrom -eq "%OU-Adm-Groups-T1L%"}).translateTo
    [string]$OUt2Leg = ($xmlSkeleton.Settings.Translation.wellKnownID | Where-Object { $_.translateFrom -eq "%OU-Adm-Groups-T2L%"}).translateTo
    [string]$GrpGlob = ($xmlSkeleton.Settings.Translation.wellKnownID | Where-Object { $_.translateFrom -eq "%prefix-global%" }).translateTo
    [string]$GrpDloc = ($xmlSkeleton.Settings.Translation.wellKnownID | Where-Object { $_.translateFrom -eq "%prefix-DomLoc%" }).translateTo
    [string]$T0      = ($xmlSkeleton.Settings.Translation.wellKnownID | Where-Object { $_.translateFrom -eq "%isT0%"    }).translateTo
    [string]$T1      = ($xmlSkeleton.Settings.Translation.wellKnownID | Where-Object { $_.translateFrom -eq "%isT1%"    }).translateTo
    [string]$T2      = ($xmlSkeleton.Settings.Translation.wellKnownID | Where-Object { $_.translateFrom -eq "%isT2%"    }).translateTo
    [string]$T1L     = ($xmlSkeleton.Settings.Translation.wellKnownID | Where-Object { $_.translateFrom -eq "%isT1Leg%" }).translateTo
    [string]$T2L     = ($xmlSkeleton.Settings.Translation.wellKnownID | Where-Object { $_.translateFrom -eq "%isT2Leg%" }).translateTo

    #.Getting domain details
    $Src_Domain  = Get-ADDomain -Server $SrcDomDns
    $Dest_Domain = Get-ADDomain -Server $DestDomDns

    #.Filtering on administration OU to avoid false positive and speed-up the script execution time
    $Src_AdministrationOU  = Get-ADOrganizationalUnit -Filter { Name -eq $OUadmin } -Server $Src_Domain.DNSRoot
    $Dest_AdministrationOU = Get-ADOrganizationalUnit -Filter { Name -eq $OUAdmin } -Server $Dest_Domain.DNSRoot

    #.Creating array for matching purpose
    $arrTier = @($t0,$T1,$T2,$T1L,$T2L)
    $arrOUph = @($OUtier0,$OUtier1,$OUtier2,$OUt1Leg,$OUt2Leg)

    #.Looping accross tiers
    #foreach ($Tier in @($T0, $T1, $T2, $T1L, $T2L)) 
    for ($i = 0 ; $i -lt $arrTier.count ; $i++)
    {
        #.Flushing groups data
        $Src_GSGroups  = $null
        $Dest_GSGroups = $null

        #.Building Lookup structure
        $LookupLSTX    = "$GrpDloc$($arrTier[$i])"
        $LookupGS      = "$GrpGlob$($arrTier[$i])*"
        $LookupGroupOU = $arrOUph[$i]

        #.Finding objects
        $Src_GroupsOU  = Get-ADOrganizationalUnit -Filter { Name -eq $LookupGroupOU } -SearchBase $Src_AdministrationOU.DistinguishedName  -Server $Src_Domain.DNSRoot
        $Dest_GroupsOU = Get-ADOrganizationalUnit -Filter { Name -eq $LookupGroupOU } -SearchBase $Dest_AdministrationOU.DistinguishedName -Server $Dest_Domain.DNSRoot
      
        #.Filling-up group membership
        if ($Src_GroupsOU -and $Dest_GroupsOU) 
        {
            #.Find source and destination domain local groups 
            $Src_LSTX  = Get-ADGroup -Filter { Name -eq $LookupLSTX } -SearchBase $Src_GroupsOU.DistinguishedName  -SearchScope OneLevel -Server $Src_Domain.DNSRoot
            $Dest_LSTX = Get-ADGroup -Filter { Name -eq $LookupLSTX } -SearchBase $Dest_GroupsOU.DistinguishedName -SearchScope OneLevel -Server $Dest_Domain.DNSRoot

            #.Find source and destination global groups
            $Src_GSGroups  = Get-ADGroup -Filter { Name -like $LookupGS } -SearchBase $Src_GroupsOU.DistinguishedName  -SearchScope OneLevel -Server $Src_Domain.DNSRoot
            $Dest_GSGroups = Get-ADGroup -Filter { Name -like $LookupGS } -SearchBase $Dest_GroupsOU.DistinguishedName -SearchScope OneLevel -Server $Dest_Domain.DNSRoot

            if ($Src_LSTX -and $Dest_GSGroups) 
            {
                $Dest_GSGroups | ForEach-Object {
                    try {
                        Add-ADGroupMember -Identity $Src_LSTX -Members $_ -Credential $Cred
                    } 
                    catch {
                        $res += "$($Src_LSTX.DistinguishedName): $($_.Exception.Message)"
                    } 
                }
            }

            if ( $Dest_LSTX -and $Src_GSGroups) 
            {
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

##################################################################
## Add-ManagerToEA                                              ##
## ---------------                                              ##
## This function is used to add T0 manager to the Enterprise    ##
## Admins group.                                                ##
##                                                              ##
## Version: 01.02.000                                           ##
##  Author: contact@hardenad.net                                ##
## History:                                                     ##
## 01.01.000: replaced the static group name for T0 Manager by  ##
##            a dynamic querie to the Translation section.      ##
##                                                              ##
## 01.02.0000: fixed issue with cross domain group creation.    ##
##                                                              ##
##################################################################
function Add-ManagerToEA {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]
        $SrcDomain,

        $Cred
    )
    #.Loading the configuration xml file
    $xmlSkeleton = [xml](Get-Content ".\Configs\TasksSequence_HardenAD.xml" -Encoding utf8)
    
    #.Retrieving Enterprise Admins group name, Tier 0 Managers group name and RootDomainDNS
    [string]$EAName        = ($xmlSkeleton.Settings.Translation.wellKnownID | Where-Object { $_.translateFrom -eq "%EnterpriseAdmins%" }).translateTo
    [string]$T0Mngr        = ($xmlSkeleton.Settings.Translation.wellKnownID | Where-Object { $_.translateFrom -eq "%t0-managers%" }).translateTo

    #.Getting domain objects to ensure that we query the Root Domain in a multi domain environment.
    $RootDomainDns  = (Get-ADForest).RootDomain
    $RootEA         = Get-ADGroup -Identity $EAName -Server $RootDomainDns -ErrorAction Stop
    $GST0Man        = Get-ADGroup -Identity $T0Mngr -Server $SrcDomain     -ErrorAction Stop

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

##################################################################
## Add-GroupsOverDomain                                         ##
## ---------------------                                        ##
## This function is used to determine which domain              ##
## will be available for cross integration.                     ##
##                                                              ##
## Version: 01.02.000                                           ##
##  Author: contact@hardenad.net                                ##
## History:                                                     ##
## 01.01.0000: replaced the static group name for T0 Manager by ##
##            a dynamic querie to the Translation section.      ##
##                                                              ##
## 01.02.0000: fixed issue with cross domain group creation.    ##
##                                                              ##
##################################################################
function Add-GroupsOverDomain {
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
    } Catch {
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
        $AllDomains   = $Forest.Domains
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

Export-ModuleMember -Function *