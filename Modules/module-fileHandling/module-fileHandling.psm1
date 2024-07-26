#region Import-ini
Function Import-Ini {
    <# 
        .Synopsis
        return ini file content to as array.

        .Description
        By parsing the ini file, will return an array letting script calls its content this way : $YourVar["Section"]["Parameter"]
        
        .Parameter FilePath
        File path to the ini file.

        .Notes
        Version 01.00: 24/08/2019. 
            History: Function creation.
    #>

    ## Parameters 
    Param (
        # Path to the ini file
        [Parameter(Mandatory = $true)]
        [string]
        $FilePath
    )

    ## Generate output variable container
    $ini = @{}
    
    ## Parse the file content and compare it with regular expression
    if (!(Test-Path $FilePath)) { 
        return $null 
        break 
    }
    
    switch -regex -file $FilePath {
        # Section
        "^\[(.+)\]" {
            $section = $matches[1]
            $ini[$section] = @{}
            $CommentCount = 0 
        }
        # Comment
        "^(;.*)$" {
            $value = $matches[1]
            $CommentCount = $CommentCount + 1
            $name = "Comment" + $CommentCount
            $ini[$section][$name] = $value 
        } 
        # Key
        "(.+?)\s*=(.*)" {
            $name, $value = $matches[1..2] 
            $ini[$section][$name] = $value 
        }
    }    
        
    ## return value
    return $ini
}
#endregion

#region set-LapsScripts
Function Set-LapsScripts {
    <#
        .Synopsis
        The deployment script needs to be update to fetch with the running domain.
        
        .Description
        The deployment script needs to be update to fetch with the running domain. 
        The script will be overwritten and replace %DN% by the domain FQDN.

        .Notes
        Version: 01.00 -- contact@hardenad.net 
        Version: 01.01 -- contact@hardenad.net 
        
        history:    21.08.06 Script creation
                    21.11.21 Added admx/adml file to CentralStore repo
    #>
    param(
        [Parameter(mandatory = $true, Position = 0)]
        [String]
        $ScriptDir
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
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Parameter ScriptDir......: $ScriptDir"
    $result = 0

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

    ## Get script local position
    Switch -Regex ($ScriptDir) {
        #.NETLOGON
        "NETLOGON" {
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> The target location path refers to..: NETLOGON"
            if (((Get-WMIObject win32_operatingsystem).name -like "*2008*")) {
                $NetLogonD = (Get-WmiObject -Class Win32_Share -Filter "Name='NETLOGON'").Path
            }
            else {
                $NetLogonD = (Get-SmbShare -Name NetLogon).Path
            }
            $ScriptDir = $ScriptDir -replace "NETLOGON", $NetLogonD 
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> the script files will be located to.: $ScriptDir"
        }
        #.SYSVOL
        "SYSVOL" {
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> The target location path refers to..: SYSVOL"
            if (((Get-WMIObject win32_operatingsystem).name -like "*2008*")) {
                $sysVolD = (Get-WmiObject -Class Win32_Share -Filter "Name='SYSVOL'").Path
            }
            else {
                $SysVolD = (Get-SmbShare -Name SYSVOL).Path
            }
            $ScriptDir = $ScriptDir -replace "SYSVOL", $SysVolD 
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> the script files will be located to.: $ScriptDir"
        }
        #.UNC Path
        Default {
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> The target location path refers to..: UNC PATH"
            $ScriptDir = $ScriptDir -replace "RootDN", (Get-ADDomain).DistinguishedName
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> the script files will be located to.: $ScriptDir"
        }
    }

    ## Create repository directory if needed
    if (-not(Test-Path $ScriptDir)) {
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> The target location path exists.....: False"
        Try {
            New-Item -Path $ScriptDir -ItemType Directory | Out-Null
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> The target location path exists.....: created successfully"
        }
        Catch {
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> The target location path exists.....: Error! could not create the directory target!"
            $result = 2
            $ResMess = "Error! could not create the directory target!"
        }
    }
    Else {
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> The target location path exists.....: True"
    }

    ## Duplicate file to the target destination
    if ($result -ne 2) {
        Robocopy.exe .\Inputs\LocalAdminPwdSolution\Binaries $ScriptDir /IS | Out-Null
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> binary files copied"
        Robocopy.exe .\Inputs\LocalAdminPwdSolution\LogonScripts $ScriptDir /IS | Out-Null
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> script files copied"
    }

    ## Rewriting script file
    foreach ($file in (Get-ChildItem -Path $ScriptDir | Where-Object { $_.Name -like "*.bat" })) {
        $newFile = @()
        Try {
            (Get-Content $file.fullName) -Replace '%DN%', (Get-ADDomain).DnsRoot | Set-Content $File.FullName 
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> rewritten file " + $file.Name + " (success)"
        }
        Catch {
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> rewritten file " + $file.Name + " (failed!)"
            $result = 1
            $ResMess += "(Failed to rewrite the file " + $file.name + ")"
        }
    }

    ## Deploying ADML and ADMX files to the Central Repository Store
    if ($result -eq 0) {
        if (((Get-WMIObject win32_operatingsystem).name -like "*2008*")) {
            Import-Module ActiveDirectory
            $sysVolBasePath = ((net share | ? { $_ -like "SYSVOL*" }) -split " " | ? { $_ -ne "" })[1]
        }
        else {
            $sysVolBasePath = (Get-SmbShare SYSVOL).path
        }

        $domName = (Get-AdDomain).DNSRoot
        
        Robocopy.exe .\Inputs\LocalAdminPwdSolution\PolicyDefinitions $sysVolBasePath\$domName\Policies\PolicyDefinitions /s | Out-Null
        
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> PolicyDefinitions files copied."
    }
    else {
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "ERR ---> PolicyDefinitions files not copied due to a previous error!"
    }

    ## Exit
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> function return RESULT: $Result"
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "=== | INIT  ROTATIVE  LOG "
    if (Test-Path .\Logs\Debug\$DbgFile) {
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Rotate log file......: 1000 last entries kept" 
        if (((Get-WMIObject win32_operatingsystem).name -notlike "*2008*")) {
            $Backup = Get-Content .\Logs\Debug\$DbgFile -Tail 1000 
            $Backup | Out-File .\Logs\Debug\$DbgFile -Force
        }
    }
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "=== | STOP  ROTATIVE  LOG "
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ****")
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T **** FUNCTION ENDS")
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ****")
    $DbgMess | Out-File .\Logs\Debug\$DbgFile -Append

    return (New-Object -TypeName psobject -Property @{ResultCode = $result ; ResultMesg = $ResMess ; TaskExeLog = $ResMess })
}
#endregion

#region Set-LocAdmTaskScripts
Function Set-LocAdmTaskScripts {
    <#
        .Synopsis
        The deployment script needs to be update to fetch with the running domain.
        
        .Description
        The deployment script needs to be update to fetch with the running domain. 
        The script will be overwritten and replace %DN% by the domain FQDN.

        .Notes
        Version: 01.00 -- contact@hardenad.net 
        Version: 01.01 -- contact@hardenad.net 
        
        history:    21.08.06 Script creation
                    21.11.21 Added admx/adml file to CentralStore repo
    #>
    param(
        [Parameter(mandatory = $true, Position = 0)]
        [String]
        $ScriptDir
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
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Parameter ScriptDir......: $ScriptDir"
    $result = 0

    ## loading configuration file
    Try {
        $xmlFile = [xml](Get-Content .\Configs\TasksSequence_HardenAD.xml -Encoding utf8)
        $Result = 0
    }
    Catch {
        $Result = 2
    }
    
    ## Recovering DomainDns Name
    $AllTranslation = $xmlFile.Settings.Translation.wellKnownID
    $DomainDns = ($AllTranslation | where-Object { $_.translateFrom -eq "%domaindns%" }).translateTo

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


    ## Get script local position
    #.SYSVOL
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> The target location path refers to..: SYSVOL"
    if (((Get-WMIObject win32_operatingsystem).name -like "*2008*")) {
        $sysVolD = (Get-WmiObject -Class Win32_Share -Filter "Name='SYSVOL'").Path
    }
    else {
        $SysVolD = (Get-SmbShare -Name SYSVOL).Path
    }
    $ScriptDir = $ScriptDir -replace "SYSVOL", $SysVolD
    $ScriptDir = $ScriptDir -replace "%domaindns%", $DomainDns 
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> the script files will be located to.: $ScriptDir"

    ## rewriting xml backup file with specific values
    $rawXml = Get-Content .\Inputs\GroupPolicies\`{88019C86-A81F-4C38-85B9-CD62970E8201`}\DomainSysvol\GPO\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml
    $rawXml = $rawXml -replace '%ScriptDir%', $ScriptDir
    $rawXml | Out-File .\Inputs\GroupPolicies\`{88019C86-A81F-4C38-85B9-CD62970E8201`}\DomainSysvol\GPO\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml-Encoding unicode -Force
    $rawXml = Get-Content .\Inputs\GroupPolicies\`{88019C86-A81F-4C38-85B9-CD62970E8201`}\DomainSysvol\GPO\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml.backup
    $rawXml = $rawXml -replace '%ScriptDir%', $ScriptDir
    $rawXml | Out-File .\Inputs\GroupPolicies\`{88019C86-A81F-4C38-85B9-CD62970E8201`}\DomainSysvol\GPO\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml.backup -Encoding unicode -Force

    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> Xml rewrited with customized value in .\Inputs\GroupPolicies\`{88019C86-A81F-4C38-85B9-CD62970E8201`}\DomainSysvol\GPO\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml"
    
    ## Create repository directory if needed
    if (-not(Test-Path $ScriptDir)) {
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> The target location path exists.....: False"
        Try {
            New-Item -Path $ScriptDir -ItemType Directory | Out-Null
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> The target location path exists.....: created successfully"
        }
        Catch {
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> The target location path exists.....: Error! could not create the directory target!"
            $result = 2
            $ResMess = "Error! could not create the directory target!"
        }
    }
    Else {
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> The target location path exists.....: True"
    }

    ## Duplicate file to the target destination
    if ($result -ne 2) {
        Robocopy.exe .\Inputs\GroupPolicies\`{88019C86-A81F-4C38-85B9-CD62970E8201`}\DomainSysvol\GPO\Machine\Scripts\ScheduledTasks $ScriptDir /IS | Out-Null
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---> Loc Adm Script files copied"
    }

    ## Exit
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> function return RESULT: $Result"
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "=== | INIT  ROTATIVE  LOG "
    if (Test-Path .\Logs\Debug\$DbgFile) {
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Rotate log file......: 1000 last entries kept" 
        if (((Get-WMIObject win32_operatingsystem).name -notlike "*2008*")) {
            $Backup = Get-Content .\Logs\Debug\$DbgFile -Tail 1000 
            $Backup | Out-File .\Logs\Debug\$DbgFile -Force
        }
    }
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "=== | STOP  ROTATIVE  LOG "
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ****")
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T **** FUNCTION ENDS")
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ****")
    $DbgMess | Out-File .\Logs\Debug\$DbgFile -Append

    return (New-Object -TypeName psobject -Property @{ResultCode = $result ; ResultMesg = $ResMess ; TaskExeLog = $ResMess })
}
#endregion

#region Format-xmlFile
function Format-XMLFile {
	<#
		.SYNOSPIS
		This script will load and rewrite an XML file to indent it with tab.
		
		.PARAMETER XmlFile
		Path to the xml file.
		
		.NOTES
		Version 02.00 by Loic VEIRMAN MSSec
	#>
	param(
			[Parameter(Mandatory = $True, Position = 0)]
			[String]
			$XMLFile
	)

	try {
		Test-Path $XMLFile -ErrorAction Stop
	}
	catch {
		Write-Host "Error: " -ForegroundColor Red -NoNewLine
		Write-Host "$XMLFile - File not found!" -ForegroundColor Yellow
		return
	}

	# Load the XML file content
	$XMLFileContent = [XML](Get-Content $XMLFile -Encoding UTF8)

	# Format the XML content
	Format-XMLData -XMLData $XMLFileContent
}
#endregion

#region Format-xmlData
Function Format-XMLData {
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $True, Position = 0)]
		[XML]
		$XMLData
	)

	# Set the indentation level
	$Indent = 1
	
	# Prepare the XML handler object
	$stringWriter = New-Object System.IO.StringWriter
	$xmlWriter = New-Object System.XMl.XmlTextWriter $stringWriter
		
	# Configure the XML handler object with our specific formatting expectation
	$xmlWriter.Formatting = 'indented'
	$xmlWriter.Indentation = $Indent
	$xmlWriter.IndentChar = "`t"
		
	# refomating the XML file
	$XMLData.WriteContentTo($xmlWriter)
	$xmlWriter.Flush()
	$stringWriter.Flush()
		
	# return the formatted XML
	return $stringWriter.ToString()
}
#endregion

#region Convert-MigrationTable
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

            Version: 02.02
            Author.: contact@hardenad.net  - MSSEC
            Desc...: Optimized translation section by removing "select object" which was useless.
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
        $xmlData = Get-Content ($gpoPath + "\hardenad.migtable") -ErrorAction Stop -Encoding utf8

        #.Opening the xml data from the tasks sequence for translation then filtering to the needed data
        $xmlRefs = ([xml](Get-Content .\Configs\TasksSequence_HardenAD.xml -ErrorAction Stop)).Settings.Translation.wellKnownID
        
        # Opening the migtable file to a XML format - if failed, the function stop.
        $xmlObjs = ([xml](Get-Content ($gpoPath + "\hardenad.migtable") -ErrorAction Stop -Encoding utf8)).MigrationTable.mapping

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

            # Generate the translated.migtable file (result file) 
            Try { 
                $xmlData = ($xmlData).replace($obj.Destination, $Destination)
            }
            Catch {
                #.No replace
            }
        }

        #.Once all objets in XML translation are parsed, we can save the new migration file
        $null = $xmlData | Out-File ($gpoPath + "\translated.migtable") -Force 
    }

    ## Return translated xml
    return (New-Object -TypeName psobject -Property @{ ResultCode = $resultat ; ResultMesg = "" ; TaskExeLog = "" })
}
#endregion

#region Convert-GpoPreferencesXml
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
        $xmlRefs = ([xml](Get-Content .\Configs\TasksSequence_HardenAD.xml -ErrorAction Stop -Encoding utf8)).Settings.Translation.wellKnownID
        $xmlPref = ([xml](Get-Content ($gpoPath + "\translation.xml" ) -Encoding utf8)).translation.Preferences.replace

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
#endregion
