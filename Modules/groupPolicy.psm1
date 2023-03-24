##################################################################
## Convert-MigrationTable                                       ##
## ----------------------                                       ##
## This function will prepare the migration table file for GPO  ##
## import                                                       ##
##                                                              ##
## Version: 02.00.000                                           ##
##  Author: contact@hardenad.net                                ##
##################################################################
Function Convert-MigrationTable {
    <#
        .SYNPOSIS
            This function will replace the specified name in a .migTable file to the target one.

        .DETAILS
            GPO imported from a dev domain will contains unknown principals. To remediate this when restoring parameters,
            this function search on %objectName% and replace it with the corresponding SID in the target domain.
            The function will write the date to a new file called "translated.migtable".

            Note: when the script detects that the file "translated.migtable" is present, it will firstly delete it.

            Note: this release is no more compliant with windows server 2008 R2 and younger systems.

        .PARAMETER GpoName
            GPO to be translated.

        .NOTES
            Version: 02.01
            Author.: contact@hardenad.net  - MSSEC
            Desc...: Function rewrite. Logging are no more used to ease the script analysis.
    #>

    Param(
        [Parameter(mandatory = $true)]
        [String]
        $GpoName
    )

    #.Testing if the GPO files are reachable and if a translated file already exist and should be deleted first.
    $gpoPath = ".\Inputs\GroupPolicies\" + $GpoName

    if (Test-Path $gpoPath) {
        if (Test-Path ($gpoPath + "\translated.migtable")) {
            Remove-Item ($gpoPath + "\translated.migtable") -Force
            #.Double check for deletion
            Start-Sleep -Milliseconds 10
            if (Test-Path ($gpoPath + "\translated.migtable")) {
                #.Deletion KO
                $resultCode = $false
                $resultat = 1
            }
            Else {
                #.Deletion OK
                $resultCode = $true
                $resultat = 0
            }
        }
        Else {
            #.No prerun file
            $resultCode = $true
            $resultat = 0
        }
        #.Ensuring a migtable file is present
        if (-not(Test-Path ($gpoPath + "\hardenad.migtable"))) {
            #.Not needed.
            $resultCode = $false
            $resultat = 0
        }
    }
    else {
        #.Data missing
        $resultCode = $false
        $resultat = 2
    }

    #.Once we have checked the GPO exists and there is no leaving trace of a previous run, we can start the translation.
    #.The whole translation process will refer to the TasksSequence.xml file to match a source ID to its target: a target is refered 
    #.as a variable stored as %xxxx% - this is the value you should find in the translation.XML file. 
    if ($resultCode) {
        # Opening the migtable file to a text format - if failed, the function stop.
        $xmlData = Get-Content ($gpoPath + "\hardenad.migtable") -ErrorAction Stop

        #.Opening the xml data from the tasks sequence for translation then filtering to the needed data
        $xmlRefs = ([xml](Get-Content .\Configs\TasksSequence_HardenAD.xml -ErrorAction Stop)).Settings.Translation.wellKnownID
        
        # Opening the migtable file to a XML format - if failed, the function stop.
        $xmlObjs = ([xml](Get-Content ($gpoPath + "\hardenad.migtable") -ErrorAction Stop)).MigrationTable.mapping

        #.Translating migration
        # Update each entry of the Harden.migtable file (XML file)
        foreach ($obj in $xmlObjs) {
            $Destination = $obj.Destination
            # Replace variable by the target value defined in the configuration file TasksSequence_HardenAD.xml
            # This will replace domain and name of the group during multiple loop
            if ($Destination -match "%*%") {
                foreach ($ref in $xmlRefs) {
                    $Destination = $Destination -replace $ref.translateFrom, $ref.TranslateTo
                }
            }
            #Write-Host $Destination
            #write-host $($obj.objectClass)

            # Generate the translated.migtable file (result file) 
            switch ($obj.Type) {
                "User" { 
                    Try { 
                        $xmlData = $xmlData -replace $obj.Destination, $Destination 
                    }
                    Catch {
                        #.No replace
                    }
                }
                "Computer" { 
                    Try {
                        $xmlData = $xmlData -replace $obj.Destination, $Destination 
                    }
                    Catch {
                        #.No replace
                    }
                }
                "LocalGroup" { 
                    Try {
                        $xmlData = $xmlData -replace $obj.Destination, $Destination
                    }
                    Catch {
                        #.No replace
                    }
                }
                "GlobalGroup" { 
                    Try {
                        $xmlData = $xmlData -replace $obj.Destination, $Destination
                    }
                    Catch {
                        #.Noreplace
                    }
                }
                "UniversalGroup" { 
                    Try {
                        $xmlData = $xmlData -replace $obj.Destination, $Destination
                    }
                    Catch {
                        #.No replace
                    }
                }
                "UNCPath" { $xmlData = $xmlData -replace $obj.Destination, $Destination }
                "Unknown" { $xmlData = $xmlData -replace $obj.Destination, $Destination }
            }
        }

        #.Once all objets in XML translation are parsed, we can save the new migration file
        $null = $xmlData | Out-File ($gpoPath + "\translated.migtable") -Force 
    }

    ## Return translated xml
    return (New-Object -TypeName psobject -Property @{ ResultCode = $resultat ; ResultMesg = "" ; TaskExeLog = "" })
}

##################################################################
## Convert-GpoPreferencesXml                                    ##
## -------------------------                                    ##
## This function will prepare the preferences.xml file for GPO  ##
## import                                                       ##
##                                                              ##
## Version: 02.00.000                                           ##
##  Author: contact@hardenad.net                                ##
##################################################################
Function Convert-GpoPreferencesXml {
    <#
        .SYNPOSIS
        This function will replace the specified target in a preferences.xml file to the target one.

        .DETAILS
        GPO imported from a dev domain will contains unknown principals. To remediate this when restoring parameters,
        this function search on %objectName% and replace it with the corresponding SID in the target domain.
        The function will write the date to the same new file called and provide a backup at ir first run (preferences.xml.backup).

        Note: this release is no more compliant with windows server 2008 R2 and younger systems.

        .PARAMETER GpoName
        GPO to be translated.

        .NOTES
        Version: 02.00
        Author.: contact@hardenad.net  - MSSEC
        Desc...: Function rewrite. Logging are no more used to ease the script analysis.
    #>
    Param(
        [Parameter(mandatory = $true)]
        [String]
        $GpoName
    )

    #.Testing if the GPO files are reachable. If so, looking at preferences.xml, then checking if a backup file is present (else perform one)
    $gpoPath = ".\Inputs\GroupPolicies\" + $GpoName
    $gciPath = Get-ChildItem "$gpoPath\DomainSysvol" -Recurse | Where-Object { $_.extension -eq ".xml" }

    if ($gciPath) {
        #.Loading translation data
        $xmlRefs = ([xml](Get-Content .\Configs\TasksSequence_HardenAD.xml -ErrorAction Stop)).Settings.Translation.wellKnownID
        $xmlPref = ([xml](Get-Content ($gpoPath + "\translation.xml" ))).translation.Preferences.replace

        ForEach ($xmlObj in $gciPath) {
            $backupXml = $xmlObj.DirectoryName + "\" + $xmlObj.name + ".backup"
            if (-not(Test-Path $backupXml)) {
                Copy-Item $xmlObj.FullName $backupXml
            }

            #.From now on, we will use the backup file for modification purpose and overwrite the original file
            $xmlData = [system.io.file]::ReadAllText($backupXml)

            #.Looking for translation needs... We look at the translation.xml which in return will search for any "global translation"
            #.in the task sequences xml.
            foreach ($data in $xmlPref) {
                $findValue = $data.find
                $replValue = $data.replaceBy

                if ($replValue -match "%*%") {
                    switch -regex ($replValue) {
                        "^%SID:ID=*" {
                            $tmpDat = ($replValue -replace "%", "") -replace "SID:", ""
                            $newRep = ($xmlPref | Where-Object { $_.ID -eq ($tmpDat -split "=")[1] }).replaceBy

                            if ($newRep -match "%*%") {
                                foreach ($ref in $xmlRefs) {
                                    $newRep = $newRep -replace $ref.translateFrom, $ref.TranslateTo
                                }
                            }

                            Try {
                                $sAMAccountName = ($newRep -split "\\")[1]
                                $newRep = (Get-ADObject -filter { sAMAccountName -eq $sAMAccountName } -Properties objectSID).objectSID.Value
                            }
                            Catch {
                                #.No change
                            }
                            $xmlData = $xmlData -replace $findValue, $newRep
                            break
                        }
                        
                        Default {
                            foreach ($ref in $xmlRefs) {
                                $replValue = $replValue -replace $ref.translateFrom, $ref.TranslateTo
                            }
                            $xmlData = $xmlData -replace ($findValue -replace "\\", "\\"), $replValue
                        }
                    }
                }
            }
            [system.io.file]::WriteAllLines($xmlObj.FullName, $xmlData)
        }
    }
    ## Return translated xml
    return (New-Object -TypeName psobject -Property @{ ResultCode = 0 ; ResultMesg = "" ; TaskExeLog = "" })
}

##################################################################
## Import-WmiFilters                                            ##
## -----------------                                            ##
## This function will import wmi filters from backup files.     ##
##                                                              ##
## Version: 01.01.000                                           ##
##  Author: contact@hardenad.net                                ##
##################################################################
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
    #>

    Param(
    )

    ## When dealing with 2008R2, we need to import AD module first
    if ((Get-WMIObject win32_operatingsystem).name -like "*2008*") {
        Try { 
            Import-Module ActiveDirectory
        } 
        Catch {
            $noError = $false
        }
    }
    ## Get Current Location
    $curDir = (Get-Location).Path
    
    ## loading configuration file
    Try {
        $xmlFile = [xml](Get-Content .\Configs\TasksSequence_HardenAD.xml)
        $Resultat = 0
    }
    Catch {
        $Resultat = 2
    }

    if ($resultat -ne 2) {
        ## Begin WMI filter importation
        $WmiFilters = $xmlFile.settings.groupPolicies.wmiFilters
        $CurrWmiFtr = Get-ADObject -Filter { ObjectClass -eq 'msWMI-Som' } -Properties *

        foreach ($filterData in $WmiFilters.filter) {
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

                try {
                    $noSplash = mofcomp.exe -N:root\Policy ($mofPath + ".tmp") | Out-Null

                }
                Catch {
                    $Resultat = 1
                    $ResMess = "Some filter were not imported successfully."
                }
                
                Remove-Item ($mofPath + ".tmp") -Force

                #.Checking import status
                $CheckWmiFtr = Get-ADObject -Filter { ObjectClass -eq 'msWMI-Som' } -Properties *
                if ($CheckWmiFtr.'msWMI-Name' -match $filterData.Name) {
                    #. check OK - The wmi Filter is present.
                }
                Else {
                    $Resultat = 1
                    $ResMess = "Some filter failed to be found when checking the import result."
                }
            }
        }
    }

    ## Exit
    ## Return translated xml
    return (New-Object -TypeName psobject -Property @{ResultCode = $resultat ; ResultMesg = $ResMess ; TaskExeLog = $ResMess })
}

##################################################################
## New-GpoObject                                                ##
## -------------                                                ##
## This function will import a new gpo from a backup file.      ##
## When a GPO is added, or replaced, it will look at the        ##
## the creation of DENY Group and/or an APPLY Grou - the        ##
## attribute "<GPO Mode=...>" is used as a referal. If ommited, ##
## the script will deal a "deny and apply" mode.                ##
##                                                              ##
## Version: 02.00.000                                           ##
##  Author: contact@hardenad.net                                ##
##################################################################
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
    #>
    param(
    )

    ## When dealing with 2008R2, we need to import AD module first
    if ((Get-WMIObject win32_operatingsystem).name -like "*2008*") {
        Import-Module ActiveDirectory -ErrorAction Stop
        Import-Module GroupPolicy -ErrorAction Stop
    }
    
    ## Get Current Location
    $curDir = (Get-Location).Path

    ## loading configuration file
    Try {
        $xmlFile = [xml](Get-Content .\Configs\TasksSequence_HardenAD.xml)
        $Result = 0
    }
    Catch {
        $Result = 2
    }
    
    ## Recovering GPOs data
    $GpoData = $xmlFile.Settings.GroupPolicies.GPO

    ## Analyzing and processing
    if ($Result -ne 2) {
        foreach ($Gpo in $GpoData) {
            #.Recovering data
            #.New attribute : overwrite - this one let the script knows if an existing GPO should be replaced or not.
            $gpName = $Gpo.Name
            $gpDesc = $Gpo.Description
            $gpVali = $Gpo.Validation
            $gpBack = $Gpo.BackupID
        
            #.Check if the GPO already exists
            $gpChek = Get-GPO -Name $gpName -ErrorAction SilentlyContinue

            if ($gpChek) {
                #GPO Exists - Set flag according to the overwrite attribute.
                if ($gpVali -eq "No") {   
                    $gpFlag = $true
                }
                Else {
                    $gpFlag = $false
                    $result = 0
                }
            }
            Else {
                #.Create empty GPO
                Try {
                    $null = New-Gpo -Name $gpName -Comment $gpDesc -ErrorAction SilentlyContinue
                    $gpFlag = $true
                }
                Catch {
                    $gpFlag = $false
                    $result = 1
                }
            }

            #.If no issue, time to import data, set deny mermission and, if needed, link the GPO
            if ($gpFlag) {
                $null = Convert-MigrationTable    -GpoName "$gpName\$gpBack"
                $null = Convert-GpoPreferencesXml -GpoName "$gpName\$gpBack"

                #.Import backup
                try {
                    # Case 1 : no translated.migtable
                    $MigTableFile = "$curDir\Inputs\GroupPolicies\$gpName\$gpBack\translated.migtable"
                    if (-not(Test-Path $MigTableFile)) {
                        $null = Import-GPO -BackupId $gpBack -TargetName $gpName -Path $curDir\Inputs\GroupPolicies\$gpName -ErrorAction Stop
                        $importFlag = $true
                    }
                    # Case 2 : translated.migtable
                    else {
                        $null = Import-GPO -BackupId $gpBack -TargetName $gpName -MigrationTable $MigTableFile -Path $curDir\Inputs\GroupPolicies\$gpName -ErrorAction Stop

                        $importFlag = $true
                    }
                }
                Catch {
                    $result = 1
                    $errMess += " Failed to import at least one GPO : $Error[0]"
                    $errMess += ""
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
                        }
                        Catch {
                            $Result = 1
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

                #.Guessing 
                Switch ($Tier) {
                    "tier0" { $GrpPath = $xmlFile.Settings.GroupPolicies.GlobalGpoSettings.GpoTier0.OU }
                    "tier1" { $GrpPath = $xmlFile.Settings.GroupPolicies.GlobalGpoSettings.GpoTier0.OU }
                    "tier2" { $GrpPath = $xmlFile.Settings.GroupPolicies.GlobalGpoSettings.GpoTier0.OU }
                }
                
                #.Cheking if any translation is requiered
                foreach ($translate in $xmlFile.Settings.Translation.wellKnownID) {
                    $GrpPath = $GrpPath -replace $translate.translateFrom, $translate.TranslateTo
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
                            $null = New-ADGroup -Name $GrpName -Path $GrpPath -Description "DENY GPO: $GpName" -GroupCategory Security -GroupScope DomainLocal -ErrorAction SilentlyContinue
                        }
                        Catch {
                            #.Failed Creation, set error code to Error
                            $result = 1
                            $errMess += " Error: failed to create GPO group $grpName"
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
                    }
                    Catch {
                        $result = 1
                        $errMess += " Error: could not apply the deny permission on one or more GPO"
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
                            $null = New-ADGroup -Name $GrpName -Path $GrpPath -Description "APPLY GPO: $GpName" -GroupCategory Security -GroupScope DomainLocal -ErrorAction SilentlyContinue
                        }
                        Catch {
                            #.Failed Creation, set error code to Error
                            $result = 1
                            $errMess += " Error: failed to create GPO group $grpName"
                        }
                    }

                    #.adding new security filter permissions
                    $NtAcct = (Get-ADDomain).NetBIOSName + "\" + $GrpName
                    $NBName = [System.Security.Principal.NTAccount]$NtAcct

                    #.Applying Security Filter
                    Try {
                        #.Adding new Security Filter
                        Set-GPPermission -Name $gpName -PermissionLevel GpoApply -TargetName $NBName -TargetType Group -Confirm:$false
                    }
                    Catch {
                        $result = 1
                        $errMess += " Error: could not apply the deny permission on one or more GPO"
                    }

                    #.recover group name to adapt with AD running language
                    $AuthUsers = (Get-ADObject -LDAPFilter "(&(objectSID=S-1-5-11))" -Properties msDS-PrincipalName)."msDS-PrincipalName"

                    #.reset permission for Authenticated Users
                    Try {
                        Set-GPPermission -Name $GpName -PermissionLevel GpoRead -TargetName $AuthUsers -TargetType Group -Confirm:$false -Replace
                    }
                    Catch {
                        $result = 1
                        $errMess += " Error: failed to rewrite S-1-5-11 from security filter list"
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
                                $null = Set-GPLink -Name $gpName -Target $gpPath -LinkEnabled $gpLink.Enabled -Enforced $gpLink.enforced -ErrorAction Stop
                            }
                            Catch {
                                $result = 1
                                $errMess += " Error: could not link one or more GPO"
                            }
                        }
                        Else {
                            Try {
                                $null = New-GPLink -Name $gpName -Target $gpPath -LinkEnabled $gpLink.Enabled -Enforced $gpLink.enforced -ErrorAction Stop
                            }
                            Catch {
                                $result = 1
                                $errMess += " Error: could not link one or more GPO"
                            }
                        }
                    }
                }
            }
        }

    }
    Else {
        $errMess = "Failed to load powerShell modules - canceled."
    }

    ## Return function results
    return (New-Object -TypeName psobject -Property @{ResultCode = $result ; ResultMesg = $ErrMess ; TaskExeLog = $ErrMess })
}

Export-ModuleMember -Function * 