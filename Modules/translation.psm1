##################################################################
## Set-Translation                                              ##
## -------------------                                          ##
## This function will set the translation in TaskSequence.xml   ##
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

function Set-Translation {
    param (
        [Parameter(Mandatory = $true)]
        [string]$TasksSequence,

        [Parameter(Mandatory = $true)]
        [string]$ScriptPath,

        [Parameter(Mandatory = $false)]
        [switch]$Child
    )

    $TasksSeqConfig = [xml](get-content $ScriptPath\Configs\$TasksSequence)

    $Domain = Get-ADDomain
    $Forest = Get-ADForest

    $DomainDNS = $Domain.DNSRoot
    $DomainNetBios = $Domain.NetBIOSName
    [string] $DN = "DC=" + $DomainDNS.Replace(".", ",DC=")
    [string] $DomainSID = $Domain.DomainSID

    Write-Warning "This domain DNS is : $DomainDNS"
    Write-Warning "This domain NetBIOS name is : $DomainNetBios"
    Write-Warning "The distinguished name is : $DN"

    if ($DomainDNS -ne $Forest.RootDomain) {
        Write-Warning "Your domain is a child domain of $($Forest.RootDomain), is it correct? (y/n)"
        do {
            $isChild = Read-Host
        } until (
            $isChild -in @("Yes", "No", "n", "y")
        )

        if ($isChild -in ("yes", "y")) {
            $RootDomain = Get-ADDomain -Identity $Forest.RootDomain
            $RootDomainDNS = $RootDomain.DNSRoot
            $RootDomainNetBios = $RootDomain.NetBIOSName
            [string] $RootDN = "DC=" + $RootDomainDNS.Replace(".", ",DC=")
            [string] $RootDomainSID = $RootDomain.DomainSID

            Write-Warning "The root domain DNS is : $RootDomainDNS"
            Write-Warning "The root NetBIOS name is : $RootDomainNetBios"
            Write-Warning "The root distinguished name is : $RootDN"

            ($TasksSeqConfig.Settings.Sequence.Id | Where-Object {
                $_.Number -eq "006"
            }).TaskEnabled = "No"
           ( $TasksSeqConfig.Settings.Sequence.Id | Where-Object {
                $_.Number -eq "134"
            }).TaskEnabled = "No"
        }
        else {
            $RootDomainDNS = $DomainDNS
            $RootDomainNetBios = $DomainNetBios
            [string] $RootDN = $DN
            [string] $RootDomainSID = $DomainSID
        }
    }
    else {
        $RootDomainDNS = $DomainDNS
        $RootDomainNetBios = $DomainNetBios
        [string] $RootDN = $DN
        [string] $RootDomainSID = $DomainSID
    }

    $confirm_message = "Is the information correct? (Y/N)"
    $confirm_choice = Read-Host -Prompt $confirm_message
    # Validating information :
    # ..If user answers "Y"
    if ($confirm_choice.ToLower() -eq "y") {
        Write-Warning "Information validated!"
    }
    else {
        while ($true) {
            # If user answers "N" --> ask for domain name parts
            $netbiosName = Read-Host "Enter the NetBIOS domain name"
            $Domaindns = Read-Host "Enter the Domain DNS"

            $domain_parts = $Domaindns.Split('.')
            $taille = $domain_parts.Count


            $DN_1 = $domain_parts[0]
            $DN_2 = $domain_parts[1]

            if ($taille -eq 3) {
                $DN_3 = $domain_parts[2]
            }

            Write-Warning "New informations :"
            Write-Warning "NetBIOS Name : $netbiosName"
            Write-Warning "Domain DNS : $Domaindns" 
            
            $DistinguishedName = "DC=$DN_1,DC=$DN_2"
            if ($taille -eq 3) {
                $DistinguishedName = "DC=$DN_1,DC=$DN_2,DC=$DN_3"
            }
            Write-Warning "Distinguished Name : $DistinguishedName"
            $confirm_message = "Do you want to validate? (y/n)"
            $confirm_choice = Read-Host -Prompt $confirm_message
            if ($confirm_choice.ToLower() -eq "y") {
                Write-Warning "Information validated!"
                break
            }
        }
    }

    [string] $authenticatedUsers_SID = "S-1-5-11"
    [string] $administrators_SID = "S-1-5-32-544"
    [string] $RDUsers_SID = "S-1-5-32-555"
    [string] $users_SID = "S-1-5-32-545"

    # Specific admins group of a domain
    [string] $enterpriseAdmins_SID = $RootDomainSID + "-519"
    [string] $domainAdmins_SID = $domainSID + "-512"
    [string] $schemaAdmins_SID = $RootDomainSID + "-518"

    # Get group names from SID
    $authenticatedUsers_ = Get-GroupNameFromSID -GroupSID $authenticatedUsers_SID
    $administrators_ = Get-GroupNameFromSID -GroupSID $administrators_SID
    $RDUsers_ = Get-GroupNameFromSID -GroupSID $RDUsers_SID
    $users_ = Get-GroupNameFromSID -GroupSID $users_SID
    $enterpriseAdmins_ = Get-GroupNameFromSID -GroupSID $enterpriseAdmins_SID
    $domainAdmins_ = Get-GroupNameFromSID -GroupSID $domainAdmins_SID
    $schemaAdmins_ = Get-GroupNameFromSID -GroupSID $schemaAdmins_SID


    # Locate the nodes to update in taskSequence File
    $wellKnownID_AU = $TasksSeqConfig.Settings.Translation.wellKnownID | Where-Object { $_.translateFrom -eq "%AuthenticatedUsers%" }
    $wellKnownID_Adm = $TasksSeqConfig.Settings.Translation.wellKnownID | Where-Object { $_.translateFrom -eq "%Administrators%" }
    $wellKnownID_EA = $TasksSeqConfig.Settings.Translation.wellKnownID | Where-Object { $_.translateFrom -eq "%EnterpriseAdmins%" }
    $wellKnownID_domainAdm = $TasksSeqConfig.Settings.Translation.wellKnownID | Where-Object { $_.translateFrom -eq "%DomainAdmins%" }
    $wellKnownID_SchemaAdm = $TasksSeqConfig.Settings.Translation.wellKnownID | Where-Object { $_.translateFrom -eq "%SchemaAdmins%" }
    $wellKnownID_RDP = $TasksSeqConfig.Settings.Translation.wellKnownID | Where-Object { $_.translateFrom -eq "%RemoteDesktopUsers%" }
    $wellKnownID_Users = $TasksSeqConfig.Settings.Translation.wellKnownID | Where-Object { $_.translateFrom -eq "%Users%" }

    $wellKnownID_Netbios = $TasksSeqConfig.Settings.Translation.wellKnownID | Where-Object { $_.translateFrom -eq "%NetBios%" }
    $wellKnownID_domaindns = $TasksSeqConfig.Settings.Translation.wellKnownID | Where-Object { $_.translateFrom -eq "%domaindns%" }
    $wellKnownID_DN = $TasksSeqConfig.Settings.Translation.wellKnownID | Where-Object { $_.translateFrom -eq "%DN%" }
    
    $wellKnownID_RootNetbios = $TasksSeqConfig.Settings.Translation.wellKnownID | Where-Object { $_.translateFrom -eq "%RootNetBios%" }
    $wellKnownID_Rootdomaindns = $TasksSeqConfig.Settings.Translation.wellKnownID | Where-Object { $_.translateFrom -eq "%Rootdomaindns%" }
    $wellKnownID_RootDN = $TasksSeqConfig.Settings.Translation.wellKnownID | Where-Object { $_.translateFrom -eq "%RootDN%" }

    # Updating Values :
    # ..Domain values
    $wellKnownID_Netbios.translateTo = $DomainNetBios
    $wellKnownID_domaindns.translateTo = $DomainDNS
    $wellKnownID_DN.translateTo = $DN

    $wellKnownID_RootNetbios.translateTo = $RootDomainNetBios
    $wellKnownID_Rootdomaindns.translateTo = $RootDomainDNS
    $wellKnownID_RootDN.translateTo = $RootDN
    
    # ..Group values
    $wellKnownID_AU.translateTo = "$authenticatedUsers_"
    $wellKnownID_Adm.translateTo = "$administrators_"
    $wellKnownID_EA.translateTo = "$enterpriseAdmins_"
    $wellKnownID_domainAdm.translateTo = "$domainAdmins_"
    $wellKnownID_SchemaAdm.translateTo = "$schemaAdmins_"
    $wellKnownID_RDP.translateTo = "$RDUsers_"
    $wellKnownID_Users.translateTo = "$users_"


    #Saving xml Task Sequence file
    $TasksSeqConfig.Save("$ScriptPath\Configs\$TasksSequence")

}