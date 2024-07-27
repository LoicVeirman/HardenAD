<#
    .SYNOPSIS
    Read RunSetup.xml from Hello-my-Dir and update TasksSequence_HardenAD.xml.

    .DESCRIPTION
    If the domain was built from Hello-My-Dir (up to release 1.1.2) and you have kept the installation binaries, you can use this script to adapt the tasksSequence file directly.

    .NOTES
    Version 1.0.0 
#>
Param(
    [Parameter(Mandatory,Position=0)]
    [String]
    $RunSetupXmlFilePath
)
#region INIT
# Using ANSI Escape code
$S_Orange   = "$([char]0x1b)[38;2;244;135;69m"
$S_OrangeC  = "$([char]0x1b)[38;2;255;171;21m"
$S_bluec    = "$([char]0x1b)[38;2;94;153;255m"
$S_CBlue    = "$([char]0x1b)[38;2;0;175;204;24m"
$S_Green    = "$([char]0x1b)[38;5;42;24m"
$S_yellow   = "$([char]0x1b)[38;2;220;220;170;24m"
$bCyan      = "$([char]0x1b)[96;24m"
$S_brown    = "$([char]0x1b)[38;2;206;145;120m"
$Cend       = "$([char]0x1b)[0m"

# Test if the file is present
if (Test-path $RunSetupXmlFilePath) {
    $xml_runSetup = [xml](Get-Content $RunSetupXmlFilePath -Encoding UTF8)
} Else {
    Write-Host "${S_Orange}Error: ${S_OrangeC}The file runSetup.xml was not found!${Cend}"
    Exit 1
}

# Loading Task Sequences
$xml_TasksSequence = [xml](Get-Content .\..\..\Configs\TasksSequence_HardenAD.xml -Encoding UTF8)
#endregion
#region Query new names
# Let's proceed to changes...
Write-Host "${S_BlueC}PLEASE SEIZE YOUR OU NAME, AS PER YOUR WISHES:${Cend}"
Write-Host "[$((Get-AdDomain).DistinguishedName)]"
# NewName1.: OU Administration
Write-Host "+--[_Administration]" -NoNewline
Write-Host "${bCyan} New name (default: ${S_Brown}_Administration${bCyan}): ${Cend}" -NoNewline ; $NewName1 = Read-Host  ; if ($NewName1 -eq "" -or $null -eq $NewName1) { $NewName1 = "_Administration" }
# NewName2.: OU Administration | GPO
Write-Host "|  +--[GPO]" -NoNewline
Write-Host "         ${bCyan} New name (default: ${S_Brown}GPO${bCyan})............: ${Cend}" -NoNewline ; $newName2 = Read-Host  ; if ($newName2 -eq "" -or $null -eq $newName2) { $newName2 = "GPO" }
# NewName3.: OU Administration | PAW
write-Host "|  +--[PAW]" -NoNewline
Write-Host "         ${bCyan} New name (default: ${S_Brown}PAW${bCyan})............: ${Cend}" -NoNewline ; $newName3 = Read-Host  ; if ($newName3 -eq "" -or $null -eq $newName3) { $newName3 = "PAW" }
# NewName4.: OU Administration | PAW | Stations | Access
Write-Host "|  |  +--[Stations]"
Write-Host "|  |  |  +--[Access]" -NoNewline
Write-Host "${bCyan} New name (default: ${S_Brown}Access${bCyan}).........: ${Cend}" -NoNewline ; $newName4 = Read-Host  ; if ($newName4 -eq "" -or $null -eq $newName4) { $newName4 = "Access" }
# NewName5.: OU Administration | PAW | Stations | T0
Write-Host "|  |  |  +--[T0]" -NoNewline
Write-Host "    ${bCyan} New name (default: ${S_Brown}T0${bCyan}).............: ${Cend}" -NoNewline ; $newName5 = Read-Host  ; if ($newName5 -eq "" -or $null -eq $newName5) { $newName5 = "T0" }
# NewName6.: OU Administration | PAW | Stations | T12L
Write-Host "|  |  |  +--[T12L]" -NoNewline
Write-Host "  ${bCyan} New name (default: ${S_Brown}T12L${bCyan})...........: ${Cend}" -NoNewline ; $newName6 = Read-Host  ; if ($newName5 -eq "" -or $null -eq $newName6) { $newName5 = "T12L" }
# NewName7.: OU Harden_T0
Write-Host "+--[Harden_T0]" -NoNewline
Write-Host "      ${bCyan} New name (default: ${S_Brown}Harden_T0${bCyan})......: ${Cend}" -NoNewline ; $NewName7 = Read-Host  ; if ($NewName7 -eq "" -or $null -eq $NewName7) { $NewName7 = "Harden_T0" }
# NewName8.:
Write-Host "+--[Harden_T12]" -NoNewline
Write-Host "     ${bCyan} New name (default: ${S_Brown}Harden_T12${bCyan}).....: ${Cend}" -NoNewline ; $NewName8 = Read-Host  ; if ($NewName8 -eq "" -or $null -eq $NewName8) { $NewName8 = "Harden_T12" }
# NewName10:
Write-Host "|  +--[Provisioning]" -NoNewline
Write-Host "${bCyan} New name (default: ${S_Brown}Provisioning${bCyan})...: ${Cend}" -NoNewline ; $NewName10 = Read-Host ; if ($NewName10 -eq "" -or $null -eq $NewName10) { $NewName10 = "Provisioning" }
# NewName9.:
Write-Host "+--[Harden_TL]" -NoNewline
Write-Host "      ${bCyan} New name (default: ${S_Brown}Harden_TL${bCyan})......: ${Cend}" -NoNewline ; $NewName9 = Read-Host  ; if ($NewName9 -eq "" -or $null -eq $NewName9) { $NewName9 = "Harden_TL" }
#endregion
Write-Host
Write-Host "${S_BlueC}NOW ADAPTING THE ${S_Cblue}TASKSSEQUENCE_HARDENAD.XML${S_BlueC} CONFIGURATION FILE..."
#region Renaming Administration OU
Write-Host "<    > ${bCyan}New OU Design..: ${S_Yellow}renaming ${S_Brown}_Administration ${S_Yellow}OU${Cend}" -NoNewline

$node  = $xml_TasksSequence.Settings.OrganizationalUnits.ouTree.OU                   | Where-Object { $_.Class -eq "HardenAD_ADMIN" }              ; $node.Name = "$NewName1"
$node  = $xml_TasksSequence.Settings.Translation.wellKnownID                         | Where-Object { $_.TranslateFrom -eq "%OU-ADM%" }            ; $node.translateTo = "$NewName1"
$nodes = $xml_TasksSequence.Settings.DelegationACEs.ACL                              | Where-Object { $_.TargetDN -Like "*=_Administration*" }     ; foreach ($node in $nodes) { $node.TargetDN = $node.TargetDN -replace "OU=_Administration","OU=$newName1" }
$nodes = $xml_TasksSequence.Settings.GroupPolicies.GPO                               | Where-Object { $_.GpoLink.Path -like "*=_Administration*" } ; foreach ($node in $nodes) { foreach ($tmpnode in $Node.GpoLink) { $tmpnode.Path = $tmpnode.Path -replace "OU=_Administration","OU=$newName1" } }
$nodes = $xml_TasksSequence.Settings.Accounts.User                                   | Where-Object { $_.Path -like "*=_Administration*" }         ; foreach ($node in $nodes) { $node.Path = $node.Path -replace "OU=_Administration","OU=$newName1" }
$nodes = $xml_TasksSequence.Settings.Groups.Group                                    | Where-Object { $_.Path -like "*=_Administration*" }         ; foreach ($node in $nodes) { $node.Path = $node.Path -replace "OU=_Administration","OU=$newName1" }
$nodes = $xml_TasksSequence.Settings.LocalAdminPasswordSolution.AdmPwdSelfPermission | Where-Object { $_.Target -like "*=_Administration*" }       ; foreach ($node in $nodes) { $node.Target = $node.Target -replace "OU=_Administration","OU=$newName1" }

$Host.UI.RawUI.CursorPosition = @{X=1;Y=$Host.UI.RawUI.CursorPosition.Y}
Write-Host "${s_Green}done"
#endregion
#region Renaming Administration | GPO
Write-Host "<    > ${bCyan}New OU Design..: ${S_Yellow}renaming ${S_Brown}_Administration | GPO ${S_Yellow}OU${Cend}" -NoNewline

$node  = $xml_TasksSequence.Settings.OrganizationalUnits.ouTree.OU.ChildOU | Where-Object { $_.Description -eq "Groups dedicated to OU filtering (apply and deny)" } ; $node.Name = "$newName2"
$node  = $xml_TasksSequence.Settings.Translation.wellKnownID               | Where-Object { $_.TranslateFrom -eq '%OU-ADM-GPO%' } ; $node.TranslateTo = "$newName2"

$Host.UI.RawUI.CursorPosition = @{X=1;Y=$Host.UI.RawUI.CursorPosition.Y}
Write-Host "${s_Green}done"
#endregion
#region Renaming Administration | PAW
Write-Host "<    > ${bCyan}New OU Design..: ${S_Yellow}renaming ${S_Brown}_Administration | PAW ${S_Yellow}OU${Cend}" -NoNewline

$node  = $xml_TasksSequence.Settings.OrganizationalUnits.ouTree.OU.ChildOU | Where-Object { $_.Description -eq "Privileged Admin Workstations" } ; $node.Name = "$newName3"

$Host.UI.RawUI.CursorPosition = @{X=1;Y=$Host.UI.RawUI.CursorPosition.Y}
Write-Host "${s_Green}done"
#endregion
#region Renaming Administration | PAW | Stations | Access
Write-Host "<    > ${bCyan}New OU Design..: ${S_Yellow}renaming ${S_Brown}_Administration | PAW | Stations | Access ${S_Yellow}OU${Cend}" -NoNewline

$node  = $xml_TasksSequence.Settings.OrganizationalUnits.ouTree.OU.ChildOU.ChildOU.ChildOU | Where-Object { $_.Description -eq "Physical PAW dedicated to connect to a jump server" } ; $node.Name = "$newName4"
$node  = $xml_TasksSequence.Settings.Translation.wellKnownID | Where-Object { $_.TranslateFrom -eq "%OU-ADM-PAW-STATIONS-ACCESS%" } ; $node.translateTo = "$newName4"
$nodes = $xml_TasksSequence.Settings.GroupPolicies.GPO | Where-Object { $_.GpoLink.Path -like "*=PawAccess*" } ; foreach ($node in $nodes) { foreach ($tmpnode in $Node.GpoLink) { $tmpnode.Path = $tmpnode.Path -replace "OU=PawAccess","OU=$newName4,OU=Stations,OU=$NewName3" } }
$nodes = $xml_TasksSequence.Settings.LocalAdminPasswordSolution.AdmPwdSelfPermission | Where-Object { $_.Target -like "*=PawAccess*" } ; foreach ($node in $nodes) { $node.Target = $node.Target -replace "OU=PawAccess","OU=$newName4,OU=Stations,OU=$NewName3" }

$Host.UI.RawUI.CursorPosition = @{X=1;Y=$Host.UI.RawUI.CursorPosition.Y}
Write-Host "${s_Green}done"
#endregion
#region Renaming Administration | PAW | Stations | T0
Write-Host "<    > ${bCyan}New OU Design..: ${S_Yellow}renaming ${S_Brown}_Administration | PAW | Stations | T0 ${S_Yellow}OU${Cend}" -NoNewline

$node  = $xml_TasksSequence.Settings.OrganizationalUnits.ouTree.OU.ChildOU.ChildOU.ChildOU | Where-Object { $_.Description -eq "Physical or virtual PAW dedicated to manage Tier 0 only" } ; $node.Name = "$newName5"
$node  = $xml_TasksSequence.Settings.Translation.wellKnownID                               | Where-Object { $_.TranslateFrom -eq "%OU-ADM-PAW-STATIONS-T0%" }                                           ; $node.translateTo = "$newName5"
$nodes = $xml_TasksSequence.Settings.GroupPolicies.GPO                                     | Where-Object { $_.GpoLink.Path -like "*=PawT0*" }                                             ; foreach ($node in $nodes) { foreach ($tmpnode in $Node.GpoLink) { $tmpnode.Path = $tmpnode.Path -replace "OU=PawT0","OU=$newName5,OU=Stations,OU=$NewName3" } }

$Host.UI.RawUI.CursorPosition = @{X=1;Y=$Host.UI.RawUI.CursorPosition.Y}
Write-Host "${s_Green}done"
#endregion
#region Renaming Administration | PAW | Stations | T12L
Write-Host "<    > ${bCyan}New OU Design..: ${S_Yellow}renaming ${S_Brown}_Administration | PAW | Stations | T0 ${S_Yellow}OU${Cend}" -NoNewline

$node  = $xml_TasksSequence.Settings.OrganizationalUnits.ouTree.OU.ChildOU.ChildOU.ChildOU | Where-Object { $_.Description -eq "Physical or virtual PAW dedicated to manage Tier 1, 2 or Legacy" } ; $node.Name = "$newName6"
$node  = $xml_TasksSequence.Settings.Translation.wellKnownID                               | Where-Object { $_.TranslateFrom -eq "%OU-ADM-PAW-STATIONS-T12L%" }                                                 ; $node.translateTo = "$newName6"
$nodes = $xml_TasksSequence.Settings.GroupPolicies.GPO                                     | Where-Object { $_.GpoLink.Path -like "*=PawT12L*" }                                                   ; foreach ($node in $nodes) { foreach ($tmpnode in $Node.GpoLink) { $tmpnode.Path = $tmpnode.Path -replace "OU=PawT12L","OU=$newName6,OU=Stations,OU=$NewName3" } }
$nodes = $xml_TasksSequence.Settings.LocalAdminPasswordSolution.AdmPwdSelfPermission       | Where-Object { $_.Target -like "*=PawT12L*" }                                                         ; foreach ($node in $nodes) { $node.Target = $node.Target -replace "OU=PawAccess","OU=$newName6,OU=Stations,OU=$NewName3" }

$Host.UI.RawUI.CursorPosition = @{X=1;Y=$Host.UI.RawUI.CursorPosition.Y}
Write-Host "${s_Green}done"
#endregion
#region Renaming Harden_T0
Write-Host "<    > ${bCyan}New OU Design..: ${S_Yellow}renaming ${S_Brown}Harden_T0 ${S_Yellow}OU${Cend}" -NoNewline

$node  = $xml_TasksSequence.Settings.OrganizationalUnits.ouTree.OU | Where-Object { $_.Class -eq "HardenAD_PROD-T0" }           ; $node.Name = "$NewName7"
$nodes = $xml_TasksSequence.Settings.DelegationACEs.SDDL           | Where-Object { $_.TargetDN -like "*=Harden_T0*" }          ; foreach ($node in $nodes) { $node.TargetDN = $node.TargetDN -replace 'Ou=Harden_T0',"OU=$NewName7" }
$node  = $xml_TasksSequence.Settings.Translation.wellKnownID       | Where-Object { $_.TranslateFrom -eq "%OU-PRD-T0%" } ; $node.translateTo = "$NewName7"
$nodes = $xml_TasksSequence.Settings.GroupPolicies.GPO             | Where-Object { $_.GpoLink.Path -like "*=Harden_T0*" }      ; foreach ($node in $nodes) { foreach ($tmpnode in $Node.GpoLink) { $tmpnode.Path = $tmpnode.Path -replace "OU=Harden_T0","OU=$newName7" } }

$Host.UI.RawUI.CursorPosition = @{X=1;Y=$Host.UI.RawUI.CursorPosition.Y}
Write-Host "${s_Green}done"
#endregion
#region Renaming Harden_T12
Write-Host "<    > ${bCyan}New OU Design..: ${S_Yellow}renaming ${S_Brown}Harden_T12 ${S_Yellow}OU${Cend}" -NoNewline

$node  = $xml_TasksSequence.Settings.OrganizationalUnits.ouTree.OU                   | Where-Object { $_.Class -eq "HardenAD_PROD-T1and2" }         ; $node.Name = "$NewName8"
$nodes = $xml_TasksSequence.Settings.DelegationACEs.ACL                              | Where-Object { $_.TargetDN -like "*=Harden_T12*" }           ; foreach ($node in $nodes) { $node.TargetDN = $node.TargetDN -replace 'Ou=Harden_T12',"OU=$NewName8" }
$nodes = $xml_TasksSequence.Settings.DelegationACEs.SDDL                             | Where-Object { $_.TargetDN -like "*=Harden_T12*" }           ; foreach ($node in $nodes) { $node.TargetDN = $node.TargetDN -replace 'Ou=Harden_T12',"OU=$NewName8" }
$node  = $xml_TasksSequence.Settings.Translation.wellKnownID                         | Where-Object { $_.TranslateFrom -eq "%OU-PRD-T12%" }  ; $node.translateTo = "$NewName8"
$nodes = $xml_TasksSequence.Settings.GroupPolicies.GPO                               | Where-Object { $_.GpoLink.Path -like "*=Harden_T12*" }       ; foreach ($node in $nodes) { foreach ($tmpnode in $Node.GpoLink) { $tmpnode.Path = $tmpnode.Path -replace "OU=Harden_T12","OU=$newName8" } }
$Nodes = $xml_TasksSequence.Settings.LocalAdminPasswordSolution.AdmPwdSelfPermission | Where-Object { $_.Target -like "*=Harden_T12*" }             ; foreach ($node in $nodes) { $node.Target = $node.Target -replace "OU=Harden_T12","$NewName8" }
$Nodes = $xml_TasksSequence.Settings.LocalAdminPasswordSolution.AdmPwdPasswordReader | Where-Object { $_.Target -like "*=Harden_T12*" }             ; foreach ($node in $nodes) { $node.Target = $node.Target -replace "OU=Harden_T12","$NewName8" }
$Nodes = $xml_TasksSequence.Settings.LocalAdminPasswordSolution.AdmPwdPasswordReset  | Where-Object { $_.Target -like "*=Harden_T12*" }             ; foreach ($node in $nodes) { $node.Target = $node.Target -replace "OU=Harden_T12","$NewName8" }

$Host.UI.RawUI.CursorPosition = @{X=1;Y=$Host.UI.RawUI.CursorPosition.Y}
Write-Host "${s_Green}done"
#endregion
#region Renaming Harden_TL
Write-Host "<    > ${bCyan}New OU Design..: ${S_Yellow}renaming ${S_Brown}Harden_T12 ${S_Yellow}OU${Cend}" -NoNewline

$node  = $xml_TasksSequence.Settings.OrganizationalUnits.ouTree.OU                   | Where-Object { $_.Class -eq "HardenAD_PROD-LEGACY" }         ; $node.Name = "$NewName9"
$nodes = $xml_TasksSequence.Settings.DelegationACEs.ACL                              | Where-Object { $_.TargetDN -like "*=Harden_TL*" }            ; foreach ($node in $nodes) { $node.TargetDN = $node.TargetDN -replace 'Ou=Harden_TL',"OU=$NewName9" }
$node  = $xml_TasksSequence.Settings.Translation.wellKnownID                         | Where-Object { $_.TranslateFrom -eq "%OU-PRD-TL%" }   ; $node.translateTo = "$NewName9"
$nodes = $xml_TasksSequence.Settings.GroupPolicies.GPO                               | Where-Object { $_.GpoLink.Path -like "*=Harden_TL*" }        ; foreach ($node in $nodes) { foreach ($tmpnode in $Node.GpoLink) { $tmpnode.Path = $tmpnode.Path -replace "OU=Harden_TL","OU=$newName9" } }
$Nodes = $xml_TasksSequence.Settings.LocalAdminPasswordSolution.AdmPwdSelfPermission | Where-Object { $_.Target -like "*=Harden_TL*" }              ; foreach ($node in $nodes) { $node.Target = $node.Target -replace "OU=Harden_TL","$NewName9" }
$Nodes = $xml_TasksSequence.Settings.LocalAdminPasswordSolution.AdmPwdPasswordReader | Where-Object { $_.Target -like "*=Harden_TL*" }              ; foreach ($node in $nodes) { $node.Target = $node.Target -replace "OU=Harden_TL","$NewName9" }
$Nodes = $xml_TasksSequence.Settings.LocalAdminPasswordSolution.AdmPwdPasswordReset  | Where-Object { $_.Target -like "*=Harden_TL*" }              ; foreach ($node in $nodes) { $node.Target = $node.Target -replace "OU=Harden_TL","$NewName9" }

$Host.UI.RawUI.CursorPosition = @{X=1;Y=$Host.UI.RawUI.CursorPosition.Y}
Write-Host "${s_Green}done"
#endregion
#region Renaming Provisioning
Write-Host "<    > ${bCyan}New OU Design..: ${S_Yellow}renaming ${S_Brown}Provisioning ${S_Yellow}OU${Cend}" -NoNewline

$node  = $xml_TasksSequence.Settings.OrganizationalUnits.ouTree.OU.ChildOU           | Where-Object { $_.Name -eq "Provisioning" }                  ; $node.Name = "$NewName10"
$node  = $xml_TasksSequence.Settings.OrganizationalUnits.ouTree.OU                   | Where-Object { $_.Class -eq "PROVISIONNING-EN" }             ; $node.Name = "$NewName10"
$nodes = $xml_TasksSequence.Settings.DelegationACEs.ACL                              | Where-Object { $_.TargetDN -like "*=Provisioning*" }         ; foreach ($node in $nodes) { $node.TargetDN = $node.TargetDN -replace 'Ou=Provisioning',"OU=$NewName10,OU=$newName8" }
$nodes = $xml_TasksSequence.Settings.DelegationACEs.SDDL                             | Where-Object { $_.TargetDN -like "*=Provisioning*" }         ; foreach ($node in $nodes) { $node.TargetDN = $node.TargetDN -replace 'Ou=Provisioning',"OU=$NewName10,OU=$NewName8" }
$nodes = $xml_TasksSequence.Settings.GroupPolicies.GPO                               | Where-Object { $_.GpoLink.Path -like "*=Provisioning*" }     ; foreach ($node in $nodes) { foreach ($tmpnode in $Node.GpoLink) { $tmpnode.Path = $tmpnode.Path -replace "OU=Provisioning","OU=$newName10,OU=$NewName8" } }
$Nodes = $xml.TasksSequence.Settings.Sequences.Id                                    | Where-Object { $_.UseParameters -like "*=Provisioning*" }    ; foreach ($node in $nodes) { $node.UseParameters = $_.UseParameters -replace "OU=Provisioning","$NewName10,OU=$NewName8" }

$Host.UI.RawUI.CursorPosition = @{X=1;Y=$Host.UI.RawUI.CursorPosition.Y}
Write-Host "${s_Green}done"
#endregion
#region Renaming Target DN to match the new OU design : Exchange
Write-Host "<    > ${bCyan}New OU Design..: ${S_Yellow}Replacing Target ${S_Brown}OU=Contacts ${S_Yellow} with ${S_Brown}OU=Contacts,OU=Exchange${Cend}" -NoNewline

$nodes = $xml_TasksSequence.Settings.DelegationACEs.ACL      | Where-Object { $_.TargetDN -like "*=Contacts,*" }            ; foreach ($node in $nodes) { $node.TargetDN = $node.TargetDN -replace "OU=Contacts","OU=Contacts,OU=Exchange" }

$Host.UI.RawUI.CursorPosition = @{X=1;Y=$Host.UI.RawUI.CursorPosition.Y}
Write-Host "${s_Green}done"
#Endregion
#region Renaming Target DN to match the new OU design : GroupsT1
Write-Host "<    > ${bCyan}New OU Design..: ${S_Yellow}Replacing Target ${S_Brown}OU=GroupsT1 ${S_Yellow} with ${S_Brown}OU=Groups,OU=Tier 1${Cend}" -NoNewline

$nodes = $xml_TasksSequence.Settings.DelegationACEs.ACL      | Where-Object { $_.TargetDN -like "*=GroupsT1,*" }            ; foreach ($node in $nodes) { $node.TargetDN = $node.TargetDN -replace "OU=GroupsT1","OU=Groups,OU=Tier 1" }
$Node  = $xml_TasksSequence.Settings.Translation.wellKnownID | Where-Object { $_.TranslateFrom -eq "%OU-ADM-Groups-T1%" }   ; $node.translateTo = "Groups,OU=Tier 1"
$Nodes = $xml_TasksSequence.Settings.Groups.Group            | Where-Object { $_.Path -like "*=GroupsT1,*" }                ; foreach ($node in $nodes) { $node.path = $node.Path -replace "OU=GroupsT1","OU=Groups,OU=Tier 1" }

$Host.UI.RawUI.CursorPosition = @{X=1;Y=$Host.UI.RawUI.CursorPosition.Y}
Write-Host "${s_Green}done"
#Endregion
#region Renaming Target DN to match the new OU design : GroupsT1L
Write-Host "<    > ${bCyan}New OU Design..: ${S_Yellow}Replacing Target ${S_Brown}OU=GroupsT1L ${S_Yellow} with ${S_Brown}OU=Groups,OU=Tier 1 Legacy${Cend}" -NoNewline

$nodes = $xml_TasksSequence.Settings.DelegationACEs.ACL      | Where-Object { $_.TargetDN -like "*=GroupsT1L,*" }           ; foreach ($node in $nodes) { $node.TargetDN= $node.TargetDN-replace "OU=GroupsT1L","OU=Groups,OU=Tier 1 Legacy" }
$Node  = $xml_TasksSequence.Settings.Translation.wellKnownID | Where-Object { $_.TranslateFrom -eq "%OU-ADM-Groups-L1%" }  ; $node.translateTo = "Groups,OU=Tier 1 Legacy"
$Nodes = $xml_TasksSequence.Settings.Groups.Group            | Where-Object { $_.Path -like "*=GroupsT1L,*" }               ; foreach ($node in $nodes) { $node.Path = $node.Path -replace "OU=GroupsT1L","OU=Groups,OU=Tier 1 Legacy" }

$Host.UI.RawUI.CursorPosition = @{X=1;Y=$Host.UI.RawUI.CursorPosition.Y}
Write-Host "${s_Green}done"
#Endregion
#region Renaming Target DN to match the new OU design : GroupsT2
Write-Host "<    > ${bCyan}New OU Design..: ${S_Yellow}Replacing Target ${S_Brown}OU=GroupsT2 ${S_Yellow} with ${S_Brown}OU=Groups,OU=Tier 2${Cend}" -NoNewline

$nodes = $xml_TasksSequence.Settings.DelegationACEs.ACL      | Where-Object { $_.TargetDN -like "*=GroupsT2,*" }            ; foreach ($node in $nodes) { $node.TargetDN= $node.TargetDN-replace "OU=GroupsT2","OU=Groups,OU=Tier 2" }
$Node  = $xml_TasksSequence.Settings.Translation.wellKnownID | Where-Object { $_.TranslateFrom -eq "%OU-ADM-Groups-T2%" }   ; $node.translateTo = "Groups,OU=Tier 2"
$Nodes = $xml_TasksSequence.Settings.Groups.Group            | Where-Object { $_.Path -like "*=GroupsT2,*" }                ; foreach ($node in $nodes) { $node.Path = $node.Path -replace "OU=GroupsT2","OU=Groups,OU=Tier 2" }

$Host.UI.RawUI.CursorPosition = @{X=1;Y=$Host.UI.RawUI.CursorPosition.Y}
Write-Host "${s_Green}done"
#Endregion
#region Renaming Target DN to match the new OU design : GroupsT2L
Write-Host "<    > ${bCyan}New OU Design..: ${S_Yellow}Replacing Target ${S_Brown}OU=GroupsT2L ${S_Yellow} with ${S_Brown}OU=Groups,OU=Tier 2 Legacy${Cend}" -NoNewline

$nodes = $xml_TasksSequence.Settings.DelegationACEs.ACL      | Where-Object { $_.TargetDN -like "*=GroupsT2L,*" }           ; foreach ($node in $nodes) { $node.TargetDN= $node.TargetDN-replace "OU=GroupsT2L","OU=Groups,OU=Tier 2 Legacy" }
$Node  = $xml_TasksSequence.Settings.Translation.wellKnownID | Where-Object { $_.TranslateFrom -eq "%OU-ADM-Groups-L2%" }  ; $node.translateTo = "Groups,OU=Tier 2 Legacy"
$Nodes = $xml_TasksSequence.Settings.Groups.Group            | Where-Object { $_.Path -like "*=GroupsT2L,*" }               ; foreach ($node in $nodes) { $node.Path = $node.Path -replace "OU=GroupsT2L","OU=Groups,OU=Tier 2 Legacy" }

$Host.UI.RawUI.CursorPosition = @{X=1;Y=$Host.UI.RawUI.CursorPosition.Y}
Write-Host "${s_Green}done"
#Endregion
#region Renaming Target DN to match the new OU design : UsersT1
Write-Host "<    > ${bCyan}New OU Design..: ${S_Yellow}Replacing Target ${S_Brown}OU=UsersT1 ${S_Yellow} with ${S_Brown}OU=Users,OU=Tier 1${Cend}" -NoNewline

$nodes = $xml_TasksSequence.Settings.DelegationACEs.ACL  | Where-Object { $_.TargetDN -like "*=UsersT1,*" } ; foreach ($node in $nodes) { $node.TargetDN= $node.TargetDN-replace "OU=UsersT1","OU=Users,OU=Tier 1" }
$Nodes = $xml_TasksSequence.Settings.Accounts.User       | Where-Object { $_.Path -like "*=UsersT1,*" }     ; foreach ($node in $nodes) { $node.Path = $node.Path -replace "OU=UsersT1","OU=Users,OU=Tier 1" }

$Host.UI.RawUI.CursorPosition = @{X=1;Y=$Host.UI.RawUI.CursorPosition.Y}
Write-Host "${s_Green}done"
#Endregion
#region Renaming Target DN to match the new OU design : UsersT1L
Write-Host "<    > ${bCyan}New OU Design..: ${S_Yellow}Replacing Target ${S_Brown}OU=UsersT1L ${S_Yellow} with ${S_Brown}OU=Users,OU=Tier 1 Legacy${Cend}" -NoNewline

$nodes = $xml_TasksSequence.Settings.DelegationACEs.ACL | Where-Object { $_.TargetDN -like "*=UsersT1L,*" } ; foreach ($node in $nodes) { $node.TargetDN= $node.TargetDN-replace "OU=UsersT1L","OU=Users,OU=Tier 1 Legacy" }
$Nodes = $xml_TasksSequence.Settings.Accounts.User      | Where-Object { $_.Path -like "*=UsersT1L,*" }     ; foreach ($node in $nodes) { $node.Path = $node.Path -replace "OU=UsersT1L","OU=Users,OU=Tier 1 Legacy" }

$Host.UI.RawUI.CursorPosition = @{X=1;Y=$Host.UI.RawUI.CursorPosition.Y}
Write-Host "${s_Green}done"
#Endregion
#region Renaming Target DN to match the new OU design : UsersT2
Write-Host "<    > ${bCyan}New OU Design..: ${S_Yellow}Replacing Target ${S_Brown}OU=UsersT2 ${S_Yellow} with ${S_Brown}OU=Users,OU=Tier 2${Cend}" -NoNewline

$nodes = $xml_TasksSequence.Settings.DelegationACEs.ACL | Where-Object { $_.TargetDN -like "*=UsersT2,*" }  ; foreach ($node in $nodes) { $node.TargetDN= $node.TargetDN-replace "OU=UsersT2","OU=Users,OU=Tier 2" }
$Nodes = $xml_TasksSequence.Settings.Accounts.User      | Where-Object { $_.Path -like "*=UsersT2,*" }      ; foreach ($node in $nodes) { $node.Path = $node.Path -replace "OU=UsersT2","OU=Users,OU=Tier 2" }

$Host.UI.RawUI.CursorPosition = @{X=1;Y=$Host.UI.RawUI.CursorPosition.Y}
Write-Host "${s_Green}done"
#Endregion
#region Renaming Target DN to match the new OU design : UsersT2L
Write-Host "<    > ${bCyan}New OU Design..: ${S_Yellow}Replacing Target ${S_Brown}OU=UsersT2L ${S_Yellow} with ${S_Brown}OU=Users,OU=Tier 2 Legacy${Cend}" -NoNewline

$nodes = $xml_TasksSequence.Settings.DelegationACEs.ACL | Where-Object { $_.TargetDN -like "*=UsersT2L,*" } ; foreach ($node in $nodes) { $node.TargetDN= $node.TargetDN-replace "OU=UsersT2L","OU=Users,OU=Tier 2 Legacy" }
$Nodes = $xml_TasksSequence.Settings.Accounts.User      | Where-Object { $_.Path -like "*=UsersT2L,*" }     ; foreach ($node in $nodes) { $node.Path = $node.Path -replace "OU=UsersT2L","OU=Users,OU=Tier 2 Legacy" }

$Host.UI.RawUI.CursorPosition = @{X=1;Y=$Host.UI.RawUI.CursorPosition.Y}
Write-Host "${s_Green}done"
#Endregion
#region Renaming Target DN to match the new OU design : Groups in T0
Write-Host "<    > ${bCyan}New OU Design..: ${S_Yellow}Replacing Target ${S_Brown}OU=Logon,OU=Tier 0 ${S_Yellow}with ${S_Brown}OU=Groups,OU=$($newName3)${Cend}" -NoNewline

$nodes = $xml_TasksSequence.Settings.Groups.Group | Where-Object { $_.Path -like "*=Logon*" } ; foreach ($node in $nodes) { $node.path = $node.path -replace "OU=Logon,OU=GroupsT0","OU=Groups,OU=$newName3" }

$Host.UI.RawUI.CursorPosition = @{X=1;Y=$Host.UI.RawUI.CursorPosition.Y}
Write-Host "${s_Green}done"
Write-Host "<    > ${bCyan}New OU Design..: ${S_Yellow}Replacing Target ${S_Brown}OU=GroupsT0 ${S_Yellow} with ${S_Brown}OU=Groups,OU=Tier 0${Cend}" -NoNewline

$node  = $xml_TasksSequence.Settings.translation.wellKnownID  | Where-Object { $_.TranslateFrom -eq "%OU-ADM-Groups-T0%" }  ; $node.TranslateTo = "Groups,OU=GPO"
$nodes = $xml_TasksSequence.Settings.Groups.Group             | Where-Object { $_.Path -like "*=GroupsT0*" }                ; foreach ($node in $nodes) { $node.path = $node.path -replace "OU=GroupsT0","OU=Groups,OU=Tier 0" }

$Host.UI.RawUI.CursorPosition = @{X=1;Y=$Host.UI.RawUI.CursorPosition.Y}
Write-Host "${s_Green}done"
#endregion
#region Renaming Target DN to match the new OU design : Users in T0
Write-Host "<    > ${bCyan}New OU Design..: ${S_Yellow}Replacing Target ${S_Brown}OU=UsersT0 ${S_Yellow} with ${S_Brown}OU=Users,OU=Tier 0${Cend}" -NoNewline

$nodes = $xml_TasksSequence.Settings.Accounts.User | Where-Object { $_.Path -like "*=UsersT0*" } ; foreach ($node in $nodes) { $node.path = $node.path -replace "OU=UsersT0","OU=Users,OU=Tier 0" }

$Host.UI.RawUI.CursorPosition = @{X=1;Y=$Host.UI.RawUI.CursorPosition.Y}
Write-Host "${s_Green}done"
#endregion
#region Renaming Translation to match with current domain
Write-Host "<    > ${bCyan}Domain adoption: ${S_Yellow}Updating ${S_Brown}<translation> ${S_Yellow}with value from ${S_Brown}$((Get-ADDomain).DNSRoot)${Cend}" -NoNewline

$node = $xml_TasksSequence.Settings.Translation.wellKnownID | Where-Object { $_.TranslateFrom -eq '%netBios%' }         ; $node.translateTo = (Get-ADDomain).netBIOSName
$node = $xml_TasksSequence.Settings.Translation.wellKnownID | Where-Object { $_.TranslateFrom -eq '%domaindns%' }       ; $node.translateTo = (Get-ADDomain).DNSRoot
$node = $xml_TasksSequence.Settings.Translation.wellKnownID | Where-Object { $_.TranslateFrom -eq '%DN%' }              ; $node.translateTo = (Get-ADDomain).DistinguishedName
$node = $xml_TasksSequence.Settings.Translation.wellKnownID | Where-Object { $_.TranslateFrom -eq '%RootnetBios%' }     ; $node.translateTo = (Get-ADDomain (Get-ADForest).RootDomain).netBIOSName
$node = $xml_TasksSequence.Settings.Translation.wellKnownID | Where-Object { $_.TranslateFrom -eq '%domain%' }          ; $node.translateTo = (Get-ADDomain).netBIOSName
$node = $xml_TasksSequence.Settings.Translation.wellKnownID | Where-Object { $_.TranslateFrom -eq '%rootdomaindns%' }   ; $node.translateTo = (Get-ADForest).RootDomain
$node = $xml_TasksSequence.Settings.Translation.wellKnownID | Where-Object { $_.TranslateFrom -eq '%rootDN%' }          ; $node.translateTo = (Get-ADDomain (Get-ADForest).RootDomain).DistinguishedName

$Host.UI.RawUI.CursorPosition = @{X=1;Y=$Host.UI.RawUI.CursorPosition.Y}
Write-Host "${s_Green}done"
#endregion
#region Remove those f**g underscore
Write-Host "<    > ${bCyan}Domain adoption: ${S_Yellow}Replacing ${S_Brown}_ ${S_Yellow}with ${S_Brown}- ${S_Yellow}in ${S_Brown}<translation>${Cend}" -NoNewline

$nodes = $xml_TasksSequence.Settings.Translation.wellKnownID | Where-Object { $_.translateTo -like "*T0_*" }            ; foreach ($node in $nodes) { $node.translateTo = $node.translateTo -replace 'T0_','T0-' }
$nodes = $xml_TasksSequence.Settings.Translation.wellKnownID | Where-Object { $_.translateTo -like "*T1_*" }            ; foreach ($node in $nodes) { $node.translateTo = $node.translateTo -replace 'T1_','T1-' }
$nodes = $xml_TasksSequence.Settings.Translation.wellKnownID | Where-Object { $_.translateTo -like "*T2_*" }            ; foreach ($node in $nodes) { $node.translateTo = $node.translateTo -replace 'T2_','T2-' }
$nodes = $xml_TasksSequence.Settings.Translation.wellKnownID | Where-Object { $_.translateTo -like "*T1L_*" }           ; foreach ($node in $nodes) { $node.translateTo = $node.translateTo -replace 'T1L_','T1L-' }
$nodes = $xml_TasksSequence.Settings.Translation.wellKnownID | Where-Object { $_.translateTo -like "*T2L_*" }           ; foreach ($node in $nodes) { $node.translateTo = $node.translateTo -replace 'T2L_','T2L-' }
$nodes = $xml_TasksSequence.Settings.Translation.wellKnownID | Where-Object { $_.translateTo -like "*PawAccess_*" }     ; foreach ($node in $nodes) { $node.translateTo = $node.translateTo -replace 'PawAccess_','PawAccess-' }
$nodes = $xml_TasksSequence.Settings.Translation.wellKnownID | Where-Object { $_.translateTo -like "*PawT0_*" }         ; foreach ($node in $nodes) { $node.translateTo = $node.translateTo -replace 'PawT0_','PawT0-' }
$nodes = $xml_TasksSequence.Settings.Translation.wellKnownID | Where-Object { $_.translateTo -like "*PawT12L_*" }        ; foreach ($node in $nodes) { $node.translateTo = $node.translateTo -replace 'PawT12L_','PawT12L-' }
$nodes = $xml_TasksSequence.Settings.Translation.wellKnownID | Where-Object { $_.translateTo -like "*LocalAdmins_*" }    ; foreach ($node in $nodes) { $node.translateTo = $node.translateTo -replace 'LocalAdmins_','LocalAdmins-' }
$nodes = $xml_TasksSequence.Settings.Translation.wellKnownID | Where-Object { $_.translateTo -like "*DELEG_*" }          ; foreach ($node in $nodes) { $node.translateTo = $node.translateTo -replace 'DELEG_','DELEG-' }
$nodes = $xml_TasksSequence.Settings.Translation.wellKnownID | Where-Object { $_.translateTo -like "*LAPS_*" }           ; foreach ($node in $nodes) { $node.translateTo = $node.translateTo -replace 'LAPS_','LAPS-' }

$Host.UI.RawUI.CursorPosition = @{X=1;Y=$Host.UI.RawUI.CursorPosition.Y}
Write-Host "${s_Green}done"
Write-Host "<    > ${bCyan}Domain adoption: ${S_Yellow}Replacing ${S_Brown}_ ${S_Yellow}with ${S_Brown}- ${S_Yellow}in ${S_Brown}<groups> ${S_Yellow}and ${S_Brown}<Accounts>${Cend}" -NoNewline

$nodes = $xml_TasksSequence.Settings.Groups.Group        | Where-Object { $_.Name -like "*_*" }             ; foreach ($node in $nodes) { $node.Name = $node.Name -replace '_','-' }
$nodes = $xml_TasksSequence.Settings.Groups.Group.member | Where-Object { $_.samAccountName -like "*_*" }   ; foreach ($node in $nodes) { $node.samAccountName = $node.SamAccountName -replace '_','-' }

$Host.UI.RawUI.CursorPosition = @{X=1;Y=$Host.UI.RawUI.CursorPosition.Y}
Write-Host "${s_Green}done"
Write-Host "<    > ${bCyan}Domain adoption: ${S_Yellow}Replacing ${S_Brown}DELEG_ ${S_Yellow}with ${S_Brown}DELEG- ${S_Yellow}in ${S_Brown}<DelegationACEs>${Cend}" -NoNewline

$nodes = $xml_TasksSequence.Settings.DelegationACEs.ACL  | Where-Object { $_.Trustee -like "*DELEG_*" }   ; foreach ($node in $nodes) { $node.trustee = $node.trustee -replace 'DELEG_','DELEG-' }
$nodes = $xml_TasksSequence.Settings.DelegationACEs.SDDL | Where-Object { $_.Trustee -like "*DELEG_*" }   ; foreach ($node in $nodes) { $node.trustee = $node.trustee -replace 'DELEG_','DELEG-' }

$Host.UI.RawUI.CursorPosition = @{X=1;Y=$Host.UI.RawUI.CursorPosition.Y}
Write-Host "${s_Green}done"
#endregion

# Save XML
Write-Host "`n${S_BlueC}Saving file...${Cend} " -NoNewline
$xml_TasksSequence.Save((Resolve-Path -LiteralPath ".\..\..\Configs\TasksSequence_HardenAD.xml"))
Write-Host "${S_Green}OK${Cend}"
Write-Host "`nScript's done.`n"