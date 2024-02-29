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
        while (-not $inputValid) {
            $userInput = Read-Host "Please enter the group name manually:"
            $confirmation = Read-Host "Confirm that '$userInput' is the group name. (y/n)"
            if ($confirmation.ToLower() -eq "y") {
                $inputValid = $true
            }
        }
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
function Set-Translation {
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

    #.Getting running domain and forest context
    $Domain = Get-ADDomain
    $Forest = Get-ADForest

    #.Grabbing required data from domain
    $DomainDNS     = $Domain.DNSRoot
    $DomainNetBios = $Domain.NetBIOSName
    $DN            = $Domain.DistinguishedName
    $DomainSID     = $Domain.DomainSID
    $ForestDNS     = $Forest.RootDomain

    #.Prompting for running domain information.
    Write-Warning "Current forest root domain........: $ForestDNS"
    Write-Warning "Current domain dns name...........: $DomainDNS"
    Write-Warning "Current domain NetBIOS............: $DomainNetBios"
    Write-Warning "Current domain DistinguishedName..: $DN"

    #.If not the same as the forest, will ask for confirmation.
    if ($DomainDNS -ne $ForestDNS) 
    {
        Write-Warning "Your domain is a child domain of $($ForestDNS)!"
        Write-Warning ""
        Write-Warning "PLEASE, CONFIRM THIS IS THE RIGHT DOMAIN TO DEAL WITH BY PRESSING Y." 
        
        #.Waiting key input and deal with Y,y, ESC, return and Q.
        $isChild = $null
        While ($null -eq $isChild)
        {
            $key = $Host.UI.RawUI.ReadKey("NoEcho")
            
            Switch ($key.VirtualKeyCode)
            {
                #.Return
                13 { $isChild = $true }
                #.Escape
                27 { $isChild = $false }
                #.Q or q
                81 { $isChild = $false }
                #.Y or y
                89 { $isChild = $true }
            }
        }
        #.Test if child domain or not
        if ($isChild) 
        {
            #.Is Child Domain. Adjusting the tasksSequence acordingly.
            #.Grabbing expected values...
            $RootDomain        = Get-ADDomain -Identity $ForestDNS
            $RootDomainDNS     = $RootDomain.DNSRoot
            $RootDomainNetBios = $RootDomain.NetBIOSName
            $RootDN            = $RootDomain.DistinguishedName
            $RootDomainSID     = $RootDomain.DomainSID

            Write-Warning "Root domain DNS is................: $RootDomainDNS"
            Write-Warning "Root domain NetBIOS...............: $RootDomainNetBios"
            Write-Warning "Root domain DistinguishedName.....: $RootDN"       

            ($TasksSeqConfig.Settings.Sequence.Id | Where-Object { $_.Number -eq "006" }).TaskEnabled = "No"
            ($TasksSeqConfig.Settings.Sequence.Id | Where-Object { $_.Number -eq "134" }).TaskEnabled = "No"
        } 
        else {
            #.Not a child, setting up root domain value with current domain
            $RootDomainDNS     = $DomainDNS
            $RootDomainNetBios = $DomainNetBios
            $RootDN            = $DN
            $RootDomainSID     = $DomainSID
        }
        
        #.Validating result and opening to a manual input if needed.
        Write-Warning ""
        Write-Warning "Are those informations correct? (Y/N)"
        
        #.Waiting key input and deal with Y,y, ESC, return and Q.
        $isOK = $null
        While ($null -eq $isOK)
        {
            $key = $Host.UI.RawUI.ReadKey("NoEcho")
            
            Switch ($key.VirtualKeyCode)
            {
                #.N or n
                78 { $isOK = $false }
                #.Y or y
                89 { $isOK = $true }
            }
        }
        # .If Yes, then we continue. Else we ask for new values.
        if ($isOK) 
        {
            Write-Warning "Information validated."
        }
        else {
            $isOK = $null
            while ($null -eq $isOK) 
            {
                # If user answers "N" --> ask for domain name parts
                $netbiosName = Read-Host "Enter the NetBIOS domain name.."
                $Domaindns   = Read-Host "Enter the Domain DNS..........."
    
                #.Checking if the domain is reachable.
                Try {
                    $DistinguishedName = Get-ADDomain -Server $DomainDNS -ErrorAction Stop
                } Catch {
                    $DistinguishedName = $null
                    #.Force leaving                    
                    $isOK = $false
                }

                Write-Warning "New informations:"
                Write-Warning " NetBIOS Name........: $netbiosName"
                Write-Warning " Domain DNS..........: $Domaindns" 
                Write-Warning " Distinguished Name..: $DistinguishedName"
                Write-Warning ""
                Write-Warning "Are those informations correct? (Y/N)"                
                
                $key = $Host.UI.RawUI.ReadKey("NoEcho")
                    
                if ($key.VirtualKeyCode -eq 89) { $isOK = $true }
            }
            #.If no issue, then script will continue. Else it exits with code 2
            if ($isOK) { Write-Warning "Information validated!" } else { Exit 2 }
        }
    }
    else {
        #.Not a child, setting up root domain value with current domain
        $RootDomainDNS     = $DomainDNS
        $RootDomainNetBios = $DomainNetBios
        $RootDN            = $DN
        $RootDomainSID     = $DomainSID
    }
    #.Compute new wellKnownSID
    $authenticatedUsers_SID = "S-1-5-11"
    $administrators_SID     = "S-1-5-32-544"
    $RDUsers_SID            = "S-1-5-32-555"
    $users_SID              = "S-1-5-32-545"

    # Specific admins group of a domain
    $enterpriseAdmins_SID = $RootDomainSID + "-519"
    $domainAdmins_SID     = $domainSID     + "-512"
    $schemaAdmins_SID     = $RootDomainSID + "-518"

    # Get group names from SID
    $authenticatedUsers_ = Get-GroupNameFromSID -GroupSID $authenticatedUsers_SID
    $administrators_     = Get-GroupNameFromSID -GroupSID $administrators_SID
    $RDUsers_            = Get-GroupNameFromSID -GroupSID $RDUsers_SID
    $users_              = Get-GroupNameFromSID -GroupSID $users_SID
    $enterpriseAdmins_   = Get-GroupNameFromSID -GroupSID $enterpriseAdmins_SID
    $domainAdmins_       = Get-GroupNameFromSID -GroupSID $domainAdmins_SID
    $schemaAdmins_       = Get-GroupNameFromSID -GroupSID $schemaAdmins_SID

    # Locate the nodes to update in taskSequence File
    $wellKnownID_AU            = $TasksSeqConfig.Settings.Translation.wellKnownID | Where-Object { $_.translateFrom -eq "%AuthenticatedUsers%" }
    $wellKnownID_Adm           = $TasksSeqConfig.Settings.Translation.wellKnownID | Where-Object { $_.translateFrom -eq "%Administrators%" }
    $wellKnownID_EA            = $TasksSeqConfig.Settings.Translation.wellKnownID | Where-Object { $_.translateFrom -eq "%EnterpriseAdmins%" }
    $wellKnownID_domainAdm     = $TasksSeqConfig.Settings.Translation.wellKnownID | Where-Object { $_.translateFrom -eq "%DomainAdmins%" }
    $wellKnownID_SchemaAdm     = $TasksSeqConfig.Settings.Translation.wellKnownID | Where-Object { $_.translateFrom -eq "%SchemaAdmins%" }
    $wellKnownID_RDP           = $TasksSeqConfig.Settings.Translation.wellKnownID | Where-Object { $_.translateFrom -eq "%RemoteDesktopUsers%" }
    $wellKnownID_Users         = $TasksSeqConfig.Settings.Translation.wellKnownID | Where-Object { $_.translateFrom -eq "%Users%" }
    $wellKnownID_Netbios       = $TasksSeqConfig.Settings.Translation.wellKnownID | Where-Object { $_.translateFrom -eq "%NetBios%" }
    $wellKnownID_domaindns     = $TasksSeqConfig.Settings.Translation.wellKnownID | Where-Object { $_.translateFrom -eq "%domaindns%" }
    $wellKnownID_DN            = $TasksSeqConfig.Settings.Translation.wellKnownID | Where-Object { $_.translateFrom -eq "%DN%" }
    $wellKnownID_RootNetbios   = $TasksSeqConfig.Settings.Translation.wellKnownID | Where-Object { $_.translateFrom -eq "%RootNetBios%" }
    $wellKnownID_Rootdomaindns = $TasksSeqConfig.Settings.Translation.wellKnownID | Where-Object { $_.translateFrom -eq "%Rootdomaindns%" }
    $wellKnownID_RootDN        = $TasksSeqConfig.Settings.Translation.wellKnownID | Where-Object { $_.translateFrom -eq "%RootDN%" }

    # Updating Values :
    # ..Domain values
    $wellKnownID_Netbios.translateTo   = $DomainNetBios
    $wellKnownID_domaindns.translateTo = $DomainDNS
    $wellKnownID_DN.translateTo        = $DN

    #..RootDomain value
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

    #.Saving file and keeping formating with tab...
    Format-XML $TasksSeqConfig | Out-File $xmlFileFullName -Encoding utf8 -Force
}

