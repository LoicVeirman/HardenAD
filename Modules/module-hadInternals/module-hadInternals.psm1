#region Get-PingCastle
Function Get-PingCastle {
    <#
        .Synopsis
        This function Download the latest release and execute and audit with PingCastle.
        
        .Description
        This function execute PingCastle with parameter --healthcheck --no-enum-limit  --level Full      
        
        .Notes
        Version: 01.01 -- contact@hardenad.net 
        
        history: 21.12.16 Add Download latest release form Github
        history: 21.12.15 Script creation
    #>
    param(
        [Parameter(mandatory = $false)]
        [String]
        $Arguments
    )

    ## Default keepass password
    if (-not($Arguments)) {
        $Arguments = '--healthcheck --no-enum-limit  --level Full'
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

    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Test Internet connectivity  " 

    $OriginalProgressPreference = $Global:ProgressPreference
    $Global:ProgressPreference = 'SilentlyContinue'
    $test = Test-NetConnection
    
    switch ($test.PingSucceeded) {
        'True' {
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Test Internet connectivity OK " 
           
            $repo = "vletoux/pingcastle"
            $file = "PingCastle.zip"
            
            $releases = "https://api.github.com/repos/$repo/releases"
           
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Define repository to  $releases " 

            $tag = (Invoke-WebRequest $releases | ConvertFrom-Json)[0].tag_name 
            
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Find latest  release to PingCastle to $tag " 

            $name = $file.Split(".")[0]
            $zip = "$name`_$tag.zip"
            
            $download = "https://github.com/$repo/releases/download/$tag/$zip"
            
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Downoad the file $zip " 

            Invoke-WebRequest $download -Out $zip
            
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Extract the File $Zip to the folder $name " 
            Expand-Archive $zip -DestinationPath $name -Force 
            
            Remove-Item $zip -Recurse -Force -ErrorAction SilentlyContinue 
            
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Cleaning the download file $Zip " 

            Start-Process -FilePath .\$name\PingCastle.exe -ArgumentList "$Arguments" -WindowStyle Minimized -Wait

            $result = 0

        }
        'False' {

            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Test Internet connectivity KO ; ( " 

            $result = 1

        }
        Default {}
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

#region NEw-LogEntry
Function New-LogEntry {
    <#
        .Synopsis 
        This function will format the log file output.
    #>
    Param(
        [Parameter(Mandatory, Position = 0)]
        [ValidateSet("info", "warning", "debug", "error")]
        [String]
        $LogLevel,

        [Parameter(Mandatory, Position = 1)]
        $LogText
    )
    
    # Variables
    $Result = @()
    
    # Generate timestamp
    $Timstamp = Get-Date -Format "yyyy/MM/dd HH:mm:ss"
    
    # Generate log level
    Switch ($LogLevel) {
        "info" { $Level = "INFO" }
        "warning" { $Level = "WARN" }
        "debug" { $Level = "DBUG" }
        "error" { $Level = "ERR!" }
    }

    # Format text (able to handle multiple line)
    foreach ($entry in $LogText) {
        $Result += "$Timstamp`t[$Level]`t$entry"
    }
    
    # Return result
    return $Result
}
#endregion

#region Set-Translation
function Set-Translation {
    <#
        .Synopsis
        This function will set the translation in TaskSequence.xml
    #>
    param (
        [Parameter(Position=0)]
        $TasksSeqConfig,

        [Parameter(Position=1)]
        $xmlFileFullName,

        [Parameter(Position=2)]
        $NoConfirmationForRootDomain
    )

    # Using ANSI Escape code
    $S_Orange   = "$([char]0x1b)[38;2;244;135;69m"
    $S_OrangeC  = "$([char]0x1b)[38;2;255;171;21m"
    $S_bluec    = "$([char]0x1b)[38;2;94;153;255m"
    $S_CBlue    = "$([char]0x1b)[38;2;0;175;204;24m"
    $S_Green    = "$([char]0x1b)[38;5;42;24m"
    $S_yellow   = "$([char]0x1b)[38;2;220;220;170;24m"
    $bCyan      = "$([char]0x1b)[96;24m"
    $S_brown    = "$([char]0x1b)[38;2;206;145;120m"
    $S_purple   = "$([char]0x1b)[38;2;218;101;167m"
    $S_Red      = "$([char]0x1b)[38;2;255;0;0m"
    $Cend       = "$([char]0x1b)[0m"

    # Getting running domain and forest context
    $Domain = Get-ADDomain
    
    # Grabbing required data from domain
    $DomainDNS     = $Domain.DNSRoot
    $DomainNetBios = $Domain.NetBIOSName
    $DN            = $Domain.DistinguishedName
    $DomainSID     = $Domain.DomainSID
    $ForestDNS     = $Domain.Forest

    # Prompting for running domain information.
    Write-Host "${S_Bluec}Current forest ................: ${S_yellow}$ForestDNS${Cend}"
    Write-Host "${S_Bluec}Current domain ................: ${S_yellow}$DomainDNS${Cend}"
    Write-Host "${S_Bluec}Current NetBIOS................: ${S_yellow}$DomainNetBios${Cend}"
    Write-Host "${S_Bluec}Current DistinguishedName......: ${S_yellow}$DN${Cend}"

    # If not the same as the forest, will ask for confirmation.
    if ($DomainDNS -ne $ForestDNS) {
        Write-Host ""
        Write-Host "${S_Red}Your domain is a child domain of ${S_orangeC}$($ForestDNS)${S_Red}! Is it expected?${Cend}" -NoNewline
        Write-Host " [Y/N] " -NoNewline
        
        # Waiting key input. If not Y, then leaves.
        $isChild = $null
        while ($null -eq $isChild) {
            $key = $Host.UI.RawUI.ReadKey("IncludeKeyDown,NoEcho")
            if ($key.VirtualKeyCode -eq 89 -or $key.VirtualKeyCode -eq 13) {
                Write-Host "Expected, so you say...`n" -ForegroundColor Green
                $isChild = $true
            }
            else {
                Write-Host "Unexpected? Do, or do not. But there there is no try.`n" -ForegroundColor Red
                $isChild = $false
            }
        }

        # Test if child domain or not
        if ($isChild) {
            #.This is a Child Domain. Adjusting the tasksSequence acordingly.
            # Grabbing expected values...
            $RootDomain        = Get-ADDomain -Identity $ForestDNS
            $RootDomainDNS     = $RootDomain.DNSRoot
            $RootDomainNetBios = $RootDomain.NetBIOSName
            $RootDN            = $RootDomain.DistinguishedName
            $RootDomainSID     = $RootDomain.DomainSID.value

            # Disable FFL Upgrade
            ($TasksSeqConfig.Settings.Sequence.Id | Where-Object { $_.Number -eq "006" }).TaskEnabled = "No"
            
            # Disable LAPS Schema update
            ($TasksSeqConfig.Settings.Sequence.Id | Where-Object { $_.Number -eq "134" }).TaskEnabled = "No"
        
        }
        else {
            # Not a child, setting up root domain value with current domain
            $RootDomainDNS     = $DomainDNS
            $RootDomainNetBios = $DomainNetBios
            $RootDN            = $DN
            $RootDomainSID     = $DomainSID
        }

        Write-Host "${S_Bluec}Root Domain............: ${S_yellow}$RootDomainDNS${Cend}"   
        Write-Host "${S_Bluec}Root NetBIOS...........: ${S_yellow}$RootDomainNetBios${Cend}"
        Write-Host "${S_Bluec}Root DistinguishedName.: ${S_yellow}$RootDN${Cend}"
    
        # Validate result and open for manual input if necessary.
        Write-Host "`nAre those pieces of information correct? " -ForegroundColor Yellow -NoNewline
        
        Write-Host "[Y/N] " -NoNewline
        
        # Waiting for key input and deal with Y and return.
        $isOK = $null
        while ($null -eq $isOK) {
            $key = $Host.UI.RawUI.ReadKey("IncludeKeyDown,NoEcho")
            if ($key.VirtualKeyCode -eq 89 -or $key.VirtualKeyCode -eq 13) {
                Write-Host "Glad you'll agree with it!`n" -ForegroundColor Green
                $isOK = $true
            }
            if ($key.VirtualKeyCode -eq 78) {
                Write-Host "'Kay... You're too old for this, Roger?`n" -ForegroundColor Red
                $isOK = $false
            }
        }

        # We ask for new values if nedded, else we start.
        if (-not $isOK) {
            # Ask for domain name parts
            $netbiosName = Read-Host "{$bCyan}Enter the Root NetBIOS domain name..${cend}"
            $Domaindns   = Read-Host "${bCyan}Enter the Root Domain DNS...........${cend}"

            # Checking if the domain is reachable.
            try {
                $DistinguishedName =  Get-ADDomain -Server $DomainDNS -ErrorAction Stop
                $RootDomainSID     = (Get-ADDomain -Server $DomainDNS -ErrorAction Stop).DomainSID.value
            }
            catch {
                $DistinguishedName = $null
                # Force leaving                    
                $isOK = $false
            }

            Write-Host "`nNew values:"            -ForegroundColor Magenta
            Write-Host "Root NetBIOS Name........: " -ForegroundColor Gray -NoNewline ; Write-Host $netbiosName       -ForegroundColor Yellow
            Write-Host "Root Domain DNS..........: " -ForegroundColor Gray -NoNewline ; Write-Host $Domaindns         -ForegroundColor Yellow
            Write-Host "Root Distinguished Name..: " -ForegroundColor Gray -NoNewline ; Write-Host $DistinguishedName -ForegroundColor Yellow
            Write-Host "Root Domain SID..........: " -ForegroundColor Gray -NoNewline ; Write-Host $RootDomainSID     -ForegroundColor Yellow
            Write-Host "`nAre those informations correct? " -ForegroundColor Magenta -NoNewline
            Write-Host "(Y/N) " -NoNewline
            
            $PleaseContinueItIsSoGood = $true
            While ($PleaseContinueItIsSoGood) {
                $key = $Host.UI.RawUI.ReadKey("IncludeKeyDown,NoEcho")
                if ($key.VirtualKeyCode -eq 89 -or $key.VirtualKeyCode -eq 13) {  
                    $isOK = $true 
                    $PleaseContinueItIsSoGood = $false
                }
                if ($key.VirtualKeyCode -eq 78) {
                    $isOK = $false
                    $PleaseContinueItIsSoGood = $false
                }
            }
        }

        # If no issue, then script will continue. Else it exits with code 2
        if ($isOK) { 
            Write-Host "Information validated.`n" -ForegroundColor Green 
        }
        else { 
            Write-Host "Installation canceled... Help me, Obi-Wan Kenobi. You're my only hope!`n" -ForegroundColor red
            return 2
            #exit 2
        }
    }
    else {
        # Not a child, setting up root domain value with current domain
        $RootDomainDNS     = $DomainDNS
        $RootDomainNetBios = $DomainNetBios
        $RootDN            = $DN
        $RootDomainSID     = $DomainSID

        # Prompting for confirmation, if needed (default value)
        if (-not $NoConfirmationForRootDomain) {
            Write-Host "`nDo you want to continue with those values? " -ForegroundColor Yellow -NoNewline
            Write-Host "[Y/N] " -NoNewline
            
            # Waiting key input. If not Y, then leaves.
            $dontLeaveMe = $true
            While ($dontLeaveMe)
            {
                $key = $Host.UI.RawUI.ReadKey("IncludeKeyDown,NoEcho")
                if ($key.VirtualKeyCode -eq 89 -or $key.VirtualKeyCode -eq 13) {
                    Write-Host "Y`nGoing on... Or: nearly 'Just Secured', I should say." -ForegroundColor Green
                    $dontLeaveMe = $false
                }
                elseif ($key.VirtualKeyCode -eq 78) {
                    # Just leaving
                    Write-Host "N`nOk, canceling... I find your lack of faith disturbing." -ForegroundColor Red
                    return 1
                    #exit 0
                }
            }
        }
    }

    # Compute new wellKnownSID
    $authenticatedUsers_SID = "S-1-5-11"
    $administrators_SID     = "S-1-5-32-544"
    $RDUsers_SID            = "S-1-5-32-555"
    $users_SID              = "S-1-5-32-545"
    $Guests_SID             = "S-1-5-32-546"

    # Specific admins group of a domain
    $enterpriseAdmins_SID = "$($RootDomainSID)-519"
    $domainAdmins_SID     = "$($domainSID)-512"
    $schemaAdmins_SID     = "$($RootDomainSID)-518"
    $Guest_SID            = "$($RootDomainSID)-501"

    # Get group names from SID
    $authenticatedUsers_ = Get-GroupNameFromSID -GroupSID $authenticatedUsers_SID
    $administrators_     = Get-GroupNameFromSID -GroupSID $administrators_SID
    $RDUsers_            = Get-GroupNameFromSID -GroupSID $RDUsers_SID
    $users_              = Get-GroupNameFromSID -GroupSID $users_SID
    $enterpriseAdmins_   = Get-GroupNameFromSID -GroupSID $enterpriseAdmins_SID
    $domainAdmins_       = Get-GroupNameFromSID -GroupSID $domainAdmins_SID
    $schemaAdmins_       = Get-GroupNameFromSID -GroupSID $schemaAdmins_SID
    $Guest_              = Get-GroupNameFromSID -GroupSID $Guest_SID
    $Guests_             = Get-GroupNameFromSID -GroupSID $Guests_SID

    # Exit from script if Enterprise Admins is empty
    if ($enterpriseAdmins_ -eq "" -or $isnull -eq $enterpriseAdmins_) {
        Write-host "`nInstallation cancelled! You blew-up the process: the Enterprise Admins group is unreachable...`n" -ForegroundColor red
        return 1
        exit 1
    }

    # Locate the nodes to update in taskSequence File
    $wellKnownID_AU            = $TasksSeqConfig.Settings.Translation.wellKnownID | Where-Object { $_.translateFrom -eq "%AuthenticatedUsers%" }
    $wellKnownID_Adm           = $TasksSeqConfig.Settings.Translation.wellKnownID | Where-Object { $_.translateFrom -eq "%Administrators%" }
    $wellKnownID_EA            = $TasksSeqConfig.Settings.Translation.wellKnownID | Where-Object { $_.translateFrom -eq "%EnterpriseAdmins%" }
    $wellKnownID_domainAdm     = $TasksSeqConfig.Settings.Translation.wellKnownID | Where-Object { $_.translateFrom -eq "%DomainAdmins%" }
    $wellKnownID_SchemaAdm     = $TasksSeqConfig.Settings.Translation.wellKnownID | Where-Object { $_.translateFrom -eq "%SchemaAdmins%" }
    $wellKnownID_RDP           = $TasksSeqConfig.Settings.Translation.wellKnownID | Where-Object { $_.translateFrom -eq "%RemoteDesktopUsers%" }
    $wellKnownID_Users         = $TasksSeqConfig.Settings.Translation.wellKnownID | Where-Object { $_.translateFrom -eq "%Users%" }
    $wellKnownID_Netbios       = $TasksSeqConfig.Settings.Translation.wellKnownID | Where-Object { $_.translateFrom -eq "%NetBios%" }
    $wellKnownID_Domain        = $TasksSeqConfig.Settings.Translation.wellKnownID | Where-Object { $_.translateFrom -eq "%Domain%" }
    $wellKnownID_domaindns     = $TasksSeqConfig.Settings.Translation.wellKnownID | Where-Object { $_.translateFrom -eq "%domaindns%" }
    $wellKnownID_DN            = $TasksSeqConfig.Settings.Translation.wellKnownID | Where-Object { $_.translateFrom -eq "%DN%" }
    $wellKnownID_RootNetbios   = $TasksSeqConfig.Settings.Translation.wellKnownID | Where-Object { $_.translateFrom -eq "%RootNetBios%" }
    $wellKnownID_Rootdomaindns = $TasksSeqConfig.Settings.Translation.wellKnownID | Where-Object { $_.translateFrom -eq "%Rootdomaindns%" }
    $wellKnownID_RootDN        = $TasksSeqConfig.Settings.Translation.wellKnownID | Where-Object { $_.translateFrom -eq "%RootDN%" }
    $wellKnownID_Guests        = $TasksSeqConfig.Settings.Translation.wellKnownID | Where-Object { $_.translateFrom -eq "%Guests%" }
    $wellKnownID_Guest         = $TasksSeqConfig.Settings.Translation.wellKnownID | Where-Object { $_.translateFrom -eq "%Guest%" }
    $historyScript             = $TasksSeqConfig.Settings.History.Script
    $historyLastRun            = $TasksSeqConfig.Settings.History.LastRun
    $historyDomains            = $TasksSeqConfig.Settings.History.Domains

    # Check if this is a PDC
    $isPDC = ((Get-ADDomain).PDCemulator -split '\.')[0] -eq $env:COMPUTERNAME

    # Updating Values :
    # ..Domain values
    $wellKnownID_Netbios.translateTo   = $DomainNetBios
    $wellKnownID_Domain.translateTo    = $DomainNetBios
    $wellKnownID_domaindns.translateTo = [string]$DomainDNS
    $wellKnownID_DN.translateTo        = $DN

    # ..RootDomain value
    $wellKnownID_RootNetbios.translateTo   = $RootDomainNetBios
    $wellKnownID_Rootdomaindns.translateTo = $RootDomainDNS
    $wellKnownID_RootDN.translateTo        = $RootDN
    
    # ..Group values
    $wellKnownID_AU.translateTo        = "$authenticatedUsers_"
    $wellKnownID_Adm.translateTo       = "$administrators_"
    $wellKnownID_EA.translateTo        = "$enterpriseAdmins_"
    $wellKnownID_domainAdm.translateTo = "$domainAdmins_"
    $wellKnownID_SchemaAdm.translateTo = "$schemaAdmins_"
    $wellKnownID_RDP.translateTo       = "$RDUsers_"
    $wellKnownID_Users.translateTo     = "$users_"
    $wellKnownID_Guests                = "$Guests_"
    $wellKnownID_Guest                 = "$Guest_"

    # ..History
    $historyLastRun.Date          = [string](Get-Date -Format "yyyy/MM/dd - HH:mm")
    $historyLastRun.System        = $env:COMPUTERNAME
    $historyLastRun.isPDCemulator = [string]$isPDC
    $historyDomains.Root          = $RootDomainDNS
    $historyDomains.Domain        = [string]$DomainDNS
    $historyScript.SourcePath     = [string]((Get-Location).Path)

    # Saving file and keeping formating with tab...    
    Format-XMLData -XMLData $TasksSeqConfig | Out-File $xmlFileFullName -Encoding utf8 -Force

    return 3
}
#endregion

#region Write-DebugMessage
function Write-DebugMessage {
    <#
        .Synopsis
        Format the log output for debug file.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    try {
        Add-Content -Path $DebugLogPath -Value "$(Get-Date -UFormat "%Y-%m-%d %T") $Message"
    }
    catch {
        #Write-Warning "Failed to write debug message to log file: $($_.toString())"
    }
}
#endregion

#region Rename-ThroughTranslation
Function Rename-ThroughTranslation {
    <#
        .Synopsis
        Translate an input string through the <translation> section.

        .Description
        The <translation> section contains a lot of dynamic reference to ease maintenability and accessibility of the script and modules.
        When calling this function, the string object passed as input will be compared to each possible translation. The translated object is returned to the caller.

        .Parameter ToTranslate
        String to be translated.

        .Parameter xmlTranslateTo
        xml data to be used for translation. This will avoid loading each time the xml file.

        .Notes
        Author
            Loic VEIRMAN MSSec
        
        Version history
            1.0.0   Script creation
    #>
    [CmdletBinding()]
    param (
        [Parameter(mandatory,position=0)]
        [string]
        $ToTranslate,

        [Parameter(mandatory,position=1)]
        $xmlTranslateTo
    )

    # This function will not generate any log.
    Try {
        # We use another variable to manipulate the data. This save the initial value if needed (see catch area)
        $newValue = $ToTranslate
        # Looping through translation
        foreach ($translation in $xmlTranslateTo) {
            $newValue = $newValue -replace $translation.translateFrom, $translation.translateTo
        }
        # if new value conains % then we do it a second time - this is to allow call to dynamic value in the TranslateTo value.
        if ($newValue -match '%') {
            foreach ($translation in $xmlTranslateTo) {
                $newValue = $newValue -replace $translation.translateFrom, $translation.translateTo
            }   
        }
        # send result back
        return $newValue
    }
    Catch {
        # if something goes wrong, then we return the initial value.
        return $ToTranslate
    }
}
#endregion

#region Set-GpttmplSID
Function Set-GptTmplSID {
    <#
        .Synopsis
        Replace SID value per the new in GptTmpl.inf.

        .Description
        Allow to manipulate inf file within a GPO backup repository to replace SID value. Use a fixed array.

        .Notes
        Author:
            Loic VEIRMAN Mssec
        Version:
            01.00.00    Script creation
    #>
    Param(
        [Parameter(Mandatory, Position = 0)]
        [String]
        $GpoBackupID
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

    ## Report parameters to log
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Parameter GpoBackupID....: $($GpoBackupID)"

    # - Fixed value
    $KnownSIDs = @(
        "S-1-5-21-1646015392-45128516-3240267615-3147;%T0-Operators%",
        "S-1-5-21-1646015392-45128516-3240267615-3148;%T1-Operators%",
        "S-1-5-21-1646015392-45128516-3240267615-3157;%T2-Operators%"
    )

    Try {
        # - Loading xmlRef file
        $xmlTS = [xml](Get-Content .\Configs\TasksSequence_HardenAD.xml -Encoding UTF8 -ErrorAction Stop)
        $xmlTranslation = $xmlTS.Settings.Translation.wellKnownID
        # - find Gpo path
        $gpoPath = (Get-ChildItem .\Inputs\GroupPolicies -Recurse | Where-Object { $_.Name -eq $GpoBackupID }).FullName
        # - Loading inf file
        $GptTmpl = Get-Content "$($gpoPath)\DomainSysvol\GPO\Machine\microsoft\Windows nt\SecEdit\GptTmpl.inf" -Encoding Unicode -ErrorAction Stop
    }
    Catch {
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "-!!! Error: $($_.ToString())"
    }

    # Modus Operandi...
    $newArray = @()
    foreach ($KnowSID in $KnownSIDs) {
        # what to find and sid to find
        $TranslateIt = ($KnowSID -split ";")[0]
        $findThisSID = ($KnowSID -split ";")[1]
        # Translating
        foreach ($translation in $xmlTranslation) {
            $findThisSID = $findThisSID -replace $translation.TranslateFrom, $translation.TranslateTo
        }
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Finding $($findThisSID)..."
        # finding sid (if any)
        Try {
            $newSID = (Get-ADObject -Filter { samAccountName -eq $findThisSID } -ErrorAction Stop -Properties ObjectSID).ObjectSID
        } 
        Catch {
            $newSID = $TranslateIt
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "-!!! Error: $($_.ToString())"
        }
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> New SID will be: $NewSID"
        #  adding to array
        $newArray += "$($TranslateIt);$($newSID)"
    }
    # rewrite file
    $newFile = @()
    foreach ($line in $GptTmpl) {
        $tmpLine = $line
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Working on: $line"
        foreach ($id in $newArray) {
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---- ----> Find........: $(($id -split ';')[0])"
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---- ----> Replace with: $(($id -split ';')[1])"
            $tmpLine = $tmpLine -replace ($id -split ';')[0], ($id -split ';')[1]
        }
        $newFile += $tmpLine
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---- ----> new line value: $($tmpLine)"
    }
    # outing file.
    $newFile | Out-File "$($gpoPath)\DomainSysvol\GPO\Machine\microsoft\Windows nt\SecEdit\GptTmpl.inf" -Encoding unicode -Force

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

    return (New-Object -TypeName psobject -Property @{ResultCode = 0 ; ResultMesg = $ResMess ; TaskExeLog = $ResMess })
    
}
#endregion