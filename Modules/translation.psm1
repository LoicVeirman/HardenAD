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
        [string]$ScriptPath
    )

    $TasksSeqConfig = [xml](get-content $ScriptPath\Configs\$TasksSequence)

    $dc = Get-ADDomainController -Discover 
    $Domaindns = $dc.Domain
    $domain_parts = $Domaindns.Split('.')
    $taille = $domain_parts.Count

    $DN_1 = $domain_parts[0]
    $DN_2 = $domain_parts[1]

    $domainNetbios = Get-ADDomain
    $netbiosName = $domainNetbios.NetBIOSName

    # Show RootDN information with console messages
    Write-Warning "Domain DNS is : $Domaindns"
    Write-Warning "NetBIOS Name is : $netbiosName"


    $DistinguishedName = "DC=$DN_1,DC=$DN_2"
    if ($taille -eq 3) {
        $DN_3 = $domain_parts[2]
        $DistinguishedName = "DC=$DN_1,DC=$DN_2,DC=$DN_3"
    }
    Write-Warning "Distinguished Name : $DistinguishedName"
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

    # Get the domain object
    $domain = Get-ADDomain -Identity $Domaindns
    # Retrieve the SID Domain information
    $domainSID = $domain.DomainSID.Value

    $authenticatedUsers_SID = "S-1-5-11"
    $administrators_SID = "S-1-5-32-544"
    $RDUsers_SID = "S-1-5-32-555"
    $users_SID = "S-1-5-32-545"

    # Specific admins group of a domain
    $enterpriseAdmins_SID = $domainSID + "-519"
    $domainAdmins_SID = $domainSID + "-512"
    $schemaAdmins_SID = $domainSID + "-518"

    # Get group names from SID
    $authenticatedUsers_ = Get-GroupNameFromSID -GroupSID $authenticatedUsers_SID
    $administrators_ = Get-GroupNameFromSID -GroupSID $administrators_SID
    $RDUsers_ = Get-GroupNameFromSID -GroupSID $RDUsers_SID
    $users_ = Get-GroupNameFromSID -GroupSID $users_SID
    $enterpriseAdmins_ = Get-GroupNameFromSID -GroupSID $enterpriseAdmins_SID
    $domainAdmins_ = Get-GroupNameFromSID -GroupSID $domainAdmins_SID
    $schemaAdmins_ = Get-GroupNameFromSID -GroupSID $schemaAdmins_SID


    # Locate the nodes to update in taskSequence File
    $wellKnownID_domain = $TasksSeqConfig.Settings.Translation.wellKnownID | Where-Object { $_.translateFrom -eq "%domain%" }
    $wellKnownID_domaindns = $TasksSeqConfig.Settings.Translation.wellKnownID | Where-Object { $_.translateFrom -eq "%domaindns%" }
    $wellKnownID_RootDN = $TasksSeqConfig.Settings.Translation.wellKnownID | Where-Object { $_.translateFrom -eq "%RootDN%" }

    $wellKnownID_AU = $TasksSeqConfig.Settings.Translation.wellKnownID | Where-Object { $_.translateFrom -eq "%AuthenticatedUsers%" }
    $wellKnownID_Adm = $TasksSeqConfig.Settings.Translation.wellKnownID | Where-Object { $_.translateFrom -eq "%Administrators%" }
    $wellKnownID_EA = $TasksSeqConfig.Settings.Translation.wellKnownID | Where-Object { $_.translateFrom -eq "%EnterpriseAdmins%" }
    $group_EA = $TasksSeqConfig.Settings.Groups.Group | Where-Object { $_.Name -eq "Enterprise Admins" }
    $wellKnownID_domainAdm = $TasksSeqConfig.Settings.Translation.wellKnownID | Where-Object { $_.translateFrom -eq "%DomainAdmins%" }
    $wellKnownID_SchemaAdm = $TasksSeqConfig.Settings.Translation.wellKnownID | Where-Object { $_.translateFrom -eq "%SchemaAdmins%" }
    $wellKnownID_RDP = $TasksSeqConfig.Settings.Translation.wellKnownID | Where-Object { $_.translateFrom -eq "%RemoteDesktopUsers%" }
    $wellKnownID_Users = $TasksSeqConfig.Settings.Translation.wellKnownID | Where-Object { $_.translateFrom -eq "%Users%" }

    # Updating Values :
    # ..Domain values
    $wellKnownID_domain.translateTo = "$netbiosName"
    $wellKnownID_domaindns.translateTo = "$Domaindns"
    $wellKnownID_RootDN.translateTo = $DistinguishedName
    
    # ..Group values
    $wellKnownID_AU.translateTo = "$authenticatedUsers_"
    $wellKnownID_Adm.translateTo = "$administrators_"
    $wellKnownID_EA.translateTo = "$enterpriseAdmins_"
    $group_EA.Name = "$enterpriseAdmins_"
    $wellKnownID_domainAdm.translateTo = "$domainAdmins_"
    $wellKnownID_SchemaAdm.translateTo = "$schemaAdmins_"
    $wellKnownID_RDP.translateTo = "$RDUsers_"
    $wellKnownID_Users.translateTo = "$users_"


    #Saving xml Task Sequence file
    $TasksSeqConfig.Save("$ScriptPath\Configs\$TasksSequence")

}
