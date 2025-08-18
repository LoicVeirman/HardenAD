##################################################################
## Get-GroupNameFromSID                                         ##
## -------------------                                          ##
## This function will return a group name form a SID            ##
##                                                              ##
## Version: 01.00.000                                           ##
##  Author: contact@hardenad.net                                ##
##################################################################
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
        $userInput  = $null
        return $userInput
    }
}

##################################################################
## Set-Translation                                              ##
## ---------------                                              ##
## This function will set the translation in TaskSequence.xml   ##
##                                                              ##
## Version: 01.01.000                                           ##
##    Note: added XML formating function                        ##
##################################################################
function Set-TranslationOld {
    param (
        [Parameter(Mandatory = $true)]
        [string]$TasksSequence,

        [Parameter(Mandatory = $true)]
        [string]$ScriptPath,

        [Parameter(Mandatory = $false)]
        [switch]$Child
    )

    #.Function to reformat XML as we need
    function Format-XML ([xml]$xml, $indent=1)
    {
        $StringWriter = New-Object System.IO.StringWriter
        $XmlWriter = New-Object System.XMl.XmlTextWriter $StringWriter
        $xmlWriter.Formatting = “indented”
        $xmlWriter.Indentation = $Indent
        $xmlWriter.IndentChar = "`t"
        $xml.WriteContentTo($XmlWriter)
        $XmlWriter.Flush()
        $StringWriter.Flush()
        return $StringWriter.ToString()
    }

    #.Main code
    #.Gettings tasks sequence data
    $xmlFileFullName = convert-path $ScriptPath\Configs\$TasksSequence
    $TasksSeqConfig  = [xml](get-content $ScriptPath\Configs\$TasksSequence -Encoding utf8)

    # Main code
    # Getting running domain and forest context
    $Domain = Get-ADDomain
    
    # Grabbing required data from domain
    $DomainDNS     = $Domain.DNSRoot
    $DomainNetBios = $Domain.NetBIOSName
    $DN            = $Domain.DistinguishedName
    $DomainSID     = $Domain.DomainSID
    $ForestDNS     = $Domain.Forest

    # Prompting for running domain information.
    Write-Host "Current forest ................: "  -ForegroundColor Gray -NoNewline ; Write-host $ForestDNS     -ForegroundColor Yellow
    Write-Host "Current domain ................: "  -ForegroundColor Gray -NoNewline ; Write-Host $DomainDNS     -ForegroundColor Yellow
    Write-Host "Current NetBIOS................: "  -ForegroundColor Gray -NoNewline ; Write-Host $DomainNetBios -ForegroundColor Yellow
    Write-Host "Current DistinguishedName......: "  -ForegroundColor Gray -NoNewline ; Write-Host $DN            -ForegroundColor Yellow

    # If not the same as the forest, will ask for confirmation.
    if ($DomainDNS -ne $ForestDNS) 
    {
        Write-Host ""
        Write-Host "Your domain is a child domain of $($ForestDNS)! Is it expected?" -ForegroundColor White -BackgroundColor Red -NoNewline
        Write-Host " [Y/N] " -NoNewline
        
        # Waiting key input. If not Y, then leaves.
        $isChild = $null
        While ($null -eq $isChild)
        {
            $key = $Host.UI.RawUI.ReadKey("IncludeKeyDown,NoEcho")
            if ($key.VirtualKeyCode -eq 89 -or $key.VirtualKeyCode -eq 13)
            {
                Write-Host "Expected, so you say...`n" -ForegroundColor Green
                $isChild = $true
            } Elseif ($key.VirtualKeyCode -eq 78) {
                Write-Host "Unexpected? Do, or do not. But there there is no try.`n" -ForegroundColor Red
                $isChild = $false
            }
        }

        # Test if child domain or not
        if ($isChild) 
        {
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
        
        } else {
            # Not a child, setting up root domain value with current domain
            $RootDomainDNS     = $DomainDNS
            $RootDomainNetBios = $DomainNetBios
            $RootDN            = $DN
            $RootDomainSID     = $DomainSID
        }

        Write-Host "Root Domain............: " -ForegroundColor Gray -NoNewline ; Write-Host $RootDomainDNS     -ForegroundColor Yellow
        Write-Host "Root NetBIOS...........: " -ForegroundColor Gray -NoNewline ; Write-Host $RootDomainNetBios -ForegroundColor Yellow
        Write-Host "Root DistinguishedName.: " -ForegroundColor Gray -NoNewline ; Write-Host $RootDN            -ForegroundColor Yellow
    
        # Validating result and opening to a manual input if needed.
        Write-Host "`nAre those informations correct? " -ForegroundColor Yellow -NoNewline
        Write-Host "[Y/N] " -NoNewline
        
        # Waiting key input and deal with Y and return.
        $isOK = $null
        While ($null -eq $isOK)
        {
            $key = $Host.UI.RawUI.ReadKey("IncludeKeyDown,NoEcho")
            if ($key.VirtualKeyCode -eq 89 -or $key.VirtualKeyCode -eq 13)
            {
                Write-Host "Glad you'll agree with it!`n" -ForegroundColor Green
                $isOK = $true
            } Elseif ($key.VirtualKeyCode -eq 78) {
                Write-Host "'Kay... You break my heart...`n" -ForegroundColor Red
                $isOK = $false
            }
        }

        # We ask for new values if nedded, else we start.
        if (-not $isOK) 
        {
            # Ask for domain name parts
            $netbiosName = Read-Host "Enter the Root NetBIOS domain name.."
            $Domaindns   = Read-Host "Enter the Root Domain DNS..........."

            # Checking if the domain is reachable.
            Try {
                $DistinguishedName = Get-ADDomain -Server $DomainDNS -ErrorAction Stop
                $RootDomainSID     = (Get-ADDomain -Server $DomainDNS -ErrorAction Stop).DomainSID.value
            } Catch {
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
            
            $key = $Host.UI.RawUI.ReadKey("IncludeKeyDown,NoEcho")
                
            if ($key.VirtualKeyCode -eq 89 -or $key.VirtualKeyCode -eq 13) 
            {  
                $isOK = $true 
            } Else {
                $isOK = $false
            }
        }

        # If no issue, then script will continue. Else it exits with code 2
        if ($isOK) 
        { 
            Write-Host "Information validated.`n" -ForegroundColor Green 
        } else { 
            Write-Host "Installation canceled... Help me, Obi-Wan Kenobi. You're my only hope!`n" -ForegroundColor red
            Exit 2 
        }
    } else {
        # Not a child, setting up root domain value with current domain
        $RootDomainDNS     = $DomainDNS
        $RootDomainNetBios = $DomainNetBios
        $RootDN            = $DN
        $RootDomainSID     = $DomainSID

        # Prompting for confirmation, if needed (default value)
        if (-not $NoConfirmationForRootDomain)
        {
            Write-Host "`nDo you want to continue with those values? " -ForegroundColor Yellow -NoNewline
            Write-Host "[Y/N] " -NoNewline
            
            # Waiting key input. If not Y, then leaves.
            $dontLeaveMe = $true
            While ($dontLeaveMe) {
                $key = $Host.UI.RawUI.ReadKey("IncludeKeyDown,NoEcho")
                if ($key.VirtualKeyCode -eq 89 -or $key.VirtualKeyCode -eq 13)
                {
                    Write-Host "Going on... Or: nearly 'Just Secured', I should say." -ForegroundColor Green
                    $dontLeaveMe = $false
                } elseif ($key.VirtualKeyCode -eq 78) {
                    # Just leaving
                    Write-Host "Ok, canceling... I find your lack of faith disturbing." -ForegroundColor Red
                    Exit 0
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
    $DomainUsers_SID      = "$($RootDomainSID)-513"

    # Get group names from SID
    $DomainUsers_        = Get-GroupNameFromSID -GroupSID $DomainUsers_SID
    $authenticatedUsers_ = Get-GroupNameFromSID -GroupSID $authenticatedUsers_SID
    $administrators_     = Get-GroupNameFromSID -GroupSID $administrators_SID
    $RDUsers_            = Get-GroupNameFromSID -GroupSID $RDUsers_SID
    $users_              = Get-GroupNameFromSID -GroupSID $users_SID
    $Guests_             = Get-GroupNameFromSID -GroupSID $Guests_SID
    $enterpriseAdmins_   = Get-GroupNameFromSID -GroupSID $enterpriseAdmins_SID
    $domainAdmins_       = Get-GroupNameFromSID -GroupSID $domainAdmins_SID
    $schemaAdmins_       = Get-GroupNameFromSID -GroupSID $schemaAdmins_SID
    $Guest_              = Get-GroupNameFromSID -GroupSID $Guest_SID

    # Exit from script if Enterprise Admins is empty
	if ($enterpriseAdmins_ -eq "" -or $isnull -eq $enterpriseAdmins_)
	{
		Write-host "`nInstallation cancelled! You blew-up the process: the Enterprise Admins group is unreachable...`n" -ForegroundColor red
		Exit 1
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
    $wellKnownID_domaindns     = $TasksSeqConfig.Settings.Translation.wellKnownID | Where-Object { $_.translateFrom -eq "%è%" }
    $wellKnownID_DN            = $TasksSeqConfig.Settings.Translation.wellKnownID | Where-Object { $_.translateFrom -eq "%DN%" }
    $wellKnownID_RootNetbios   = $TasksSeqConfig.Settings.Translation.wellKnownID | Where-Object { $_.translateFrom -eq "%RootNetBios%" }
    $wellKnownID_Rootdomaindns = $TasksSeqConfig.Settings.Translation.wellKnownID | Where-Object { $_.translateFrom -eq "%Rootdomaindns%" }
    $wellKnownID_RootDN        = $TasksSeqConfig.Settings.Translation.wellKnownID | Where-Object { $_.translateFrom -eq "%RootDN%" }
    $wellKnownID_Guests        = $TasksSeqConfig.Settings.Translation.wellKnownID | Where-Object { $_.translateFrom -eq "%Guests%" }
    $wellKnownID_Guest         = $TasksSeqConfig.Settings.Translation.wellKnownID | Where-Object { $_.translateFrom -eq "%Guest%" }
    $historyScript             = $TasksSeqConfig.Settings.History.Script
    $historyLastRun            = $TasksSeqConfig.Settings.History.LastRun
    $historyDomains            = $TasksSeqConfig.Settings.History.Domains
    $Groups_Group_EAmember     = $TasksSeqConfig.Settings.Groups.Group | Where-Object { $_.Scope -eq "Universal" }

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
    $wellKnownID_Guests.translateTo    = "$Guests_"
    $wellKnownID_Guest.translateTo     = "$Guest_"
    $Groups_Group_EAmember.Name        = "$EnterpriseAdmins_"

    # ..History
    $historyLastRun.Date          = [string](Get-Date -Format "yyyy/MM/dd - HH:mm")
    $historyLastRun.System        = $env:COMPUTERNAME
    $historyLastRun.isPDCemulator = [string]$isPDC
    $historyDomains.Root          = $RootDomainDNS
    $historyDomains.Domain        = [string]$DomainDNS
    $historyScript.SourcePath     = [string]((Get-Location).Path)

    #.Saving file and keeping formating with tab...
    Format-XML $TasksSeqConfig | Out-File $xmlFileFullName -Encoding utf8 -Force
}

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
