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
# Using ANSI Escape code
$S_blueB    = "$([char]0x1b)[48;2;142;140;216m"
$S_Orange   = "$([char]0x1b)[38;2;244;135;69m"
$S_OrangeC  = "$([char]0x1b)[38;2;255;171;21m"
$S_bluec    = "$([char]0x1b)[38;2;94;153;255m"
$SU_Blue    = "$([char]0x1b)[38;2;142;140;216;4m"
$S_CBlue    = "$([char]0x1b)[38;2;0;175;204;24m"
$S_Blue     = "$([char]0x1b)[38;2;142;140;216;24m"
$S_Green    = "$([char]0x1b)[38;5;42;24m"
$S_purple   = "$([char]0x1b)[38;2;218;101;167m"
$S_purple2  = "$([char]0x1b)[38;2;206;112;179m"
$S_yellow   = "$([char]0x1b)[38;2;220;220;170;24m"
$S_Red      = "$([char]0x1b)[38;2;255;0;0m"
$bCyan      = "$([char]0x1b)[96;24m"
$S_brown    = "$([char]0x1b)[38;2;206;145;120m"
$Cend = "$([char]0x1b)[0m"

# Test if the file is present
if (Test-path $RunSetupXmlFilePath) {
    $xml_runSetup = [xml](Get-Content $RunSetupXmlFilePath -Encoding UTF8)
} Else {
    Write-Host "${S_Orange}Error: ${S_OrangeC}The file runSetup.xml was not found!${Cend}"
    Exit 1
}

# Loading Task Sequences
$xml_TasksSequence = [xml](Get-Content .\..\..\Configs\TasksSequence_HardenAD.xml -Encoding UTF8)

# Let's proceed to changes...
#region Administration OU
Write-Host "${bCyan}Type-in the name of the ADMINISTRATION O.U. (default: ${S_Brown}_Administration${bCyan}): ${Cend}" -NoNewline
$NewName1 = Read-Host 
if ($NewName1 -eq "" -or $null -eq $NewName1) { $NewName1 = "_Administration" }
$node = $xml_TasksSequence.Settings.OrganizationalUnits.ouTree.OU | Where-Object { $_.Class -eq "HardenAD_ADMIN" } ; $node.Name = "$NewName1"
$node = $xml_TasksSequence.Settings.Translation.wellKnownID | Where-Object { $_.TranslateFrom -eq "%OU-Adm%" } ; $node.translateTo = "$NewName1"
$nodes = $xml_TasksSequence.Settings.DelegationACEs.ACL | Where-Object { $_.Trustee -eq "L-S-T1-DELEG_Group - Create and Delete (administration)" } ; foreach ($node in $nodes) { $node.TargetDN = $node.TargetDN -replace "OU=_Administration","OU=$newName1" }
$nodes = $xml_TasksSequence.Settings.DelegationACEs.ACL | Where-Object { $_.Trustee -eq "L-S-T2-DELEG_Group - Create and Delete (administration)" } ; foreach ($node in $nodes) { $node.TargetDN = $node.TargetDN -replace "OU=_Administration","OU=$newName1" }
$nodes = $xml_TasksSequence.Settings.DelegationACEs.ACL | Where-Object { $_.Trustee -eq "L-S-T1-DELEG_User - Create and Delete (administration)" } ; foreach ($node in $nodes) { $node.TargetDN = $node.TargetDN -replace "OU=_Administration","OU=$newName1" }
$nodes = $xml_TasksSequence.Settings.DelegationACEs.ACL | Where-Object { $_.Trustee -eq "L-S-T2-DELEG_User - Create and Delete (administration)" } ; foreach ($node in $nodes) { $node.TargetDN = $node.TargetDN -replace "OU=_Administration","OU=$newName1" }
$nodes = $xml_TasksSequence.Settings.GroupPolicies.GPO | Where-Object { $_.GpoLink.Path -like "*_Administration*" } ; foreach ($node in $nodes) { foreach ($tmpnode in $Node.GpoLink) { $tmpnode.Path = $tmpnode.Path -replace "OU=_Administration","OU=$newName1" } }
$nodes = $xml_TasksSequence.Settings.Accounts.User | Where-Object { $_.Path -like "*_Administration*" } ;foreach ($node in $nodes) { $node.Path = $node.Path -replace "OU=_Administration","OU=$newName1" }
$nodes = $xml_TasksSequence.Settings.Groups | Where-Object { $_.Path -like "*_Administration*" } ; foreach ($node in $nodes) { $node.Path = $node.Path -replace "OU=_Administration","OU=$newName1" }
$nodes = $xml_TasksSequence.Settings.LocalAdminPasswordSolution.AdmPwdSelfPermission | Where-Object { $_.Target -like "*_Administration*" } ; foreach ($node in $nodes) { $node.Target = $node.Target -replace "OU=_Administration","OU=$newName1" }
#endregion
#region Administration - Tier 0 - OU
# OU: GPO
Write-Host "${bCyan}Type-in the name of the Administration Group Policy O.U. (default: ${S_Brown}GPO${bCyan}): ${Cend}" -NoNewline
$newName2 = Read-Host 
if ($newName2 -eq "" -or $null -eq $newName2) { $newName2 = "GPO" }
$node = $xml_TasksSequence.Settings.OrganizationalUnits.ouTree.OU.ChildOU | Where-Object { $_.Description -eq "Groups dedicated to OU filtering (apply and deny)" } ; $node.Name = "$newName2"
$node = $xml_TasksSequence.Settings.GroupPolicies.GlobalGpoSettings.GpoTier0 ; $node.OU = $node.OU -replace "OU=GPO","OU=$newName2"
$node = $xml_TasksSequence.Settings.GroupPolicies.GlobalGpoSettings.GpoTier1 ; $node.OU = $node.OU -replace "OU=GPO","OU=$newName2"
$node = $xml_TasksSequence.Settings.GroupPolicies.GlobalGpoSettings.GpoTier2 ; $node.OU = $node.OU -replace "OU=GPO","OU=$newName2"

# OU: PAW
Write-Host "${bCyan}Type-in the name of the Administration PAW O.U. (default: ${S_Brown}PAW${bCyan}): ${Cend}" -NoNewline
$newName3 = Read-Host 
if ($newName3 -eq "" -or $null -eq $newName3) { $newName3 = "PAW" }
$node = $xml_TasksSequence.Settings.OrganizationalUnits.ouTree.OU.ChildOU | Where-Object { $_.Description -eq "Privileged Admin Workstations" } ; $node.Name = "$newName3"

# OU: PAW / Stations / Prime Access
Write-Host "${bCyan}Type-in the name of the O.U. for PAW Computer used as Primary Access (default: ${S_Brown}Access${bCyan}): ${Cend}" -NoNewline
$newName4 = Read-Host 
if ($newName4 -eq "" -or $null -eq $newName4) { $newName4 = "Access" }
$node = $xml_TasksSequence.Settings.OrganizationalUnits.ouTree.OU.ChildOU | Where-Object { $_.Description -eq "Physical PAW dedicated to connect to a jump server" } ; $node.Name = "$newName4"
$node = $xml_TasksSequence.Settings.Translation.wellKnownID | Where-Object { $_.TranslateFrom -eq "%OU-PawAcs%" } ; $node.translateTo = "$newName4"
$nodes = $xml_TasksSequence.Settings.GroupPolicies.GPO | Where-Object { $_.GpoLink.Path -like "*=PawAccess*" } ; foreach ($node in $nodes) { foreach ($tmpnode in $Node.GpoLink) { $tmpnode.Path = $tmpnode.Path -replace "OU=PawAccess","OU=$newName4,OU=Stations,OU=$NewName3" } }
$nodes = $xml_TasksSequence.Settings.LocalAdminPasswordSolution.AdmPwdSelfPermission | Where-Object { $_.Target -like "*=PawAccess*" } ; foreach ($node in $nodes) { $node.Target = $node.Target -replace "OU=PawAccess","OU=$newName4,OU=Stations,OU=$NewName3" }

# OU: PAW / Stations / Tier 0
Write-Host "${bCyan}Type-in the name of the O.U. for PAW Computer used in Tier O (default: ${S_Brown}T0${bCyan}): ${Cend}" -NoNewline
$newName5 = Read-Host 
if ($newName5 -eq "" -or $null -eq $newName5) { $newName5 = "T0" }
$node = $xml_TasksSequence.Settings.OrganizationalUnits.ouTree.OU.ChildOU | Where-Object { $_.Description -eq "Physical or virtual PAW dedicated to manage Tier 0 only" } ; $node.Name = "$newName5"
$node = $xml_TasksSequence.Settings.Translation.wellKnownID | Where-Object { $_.TranslateFrom -eq "%OU-Paw-T0%" } ; $node.translateTo = "$newName5"
$nodes = $xml_TasksSequence.Settings.GroupPolicies.GPO | Where-Object { $_.GpoLink.Path -like "*=PawT0*" } ; foreach ($node in $nodes) { foreach ($tmpnode in $Node.GpoLink) { $tmpnode.Path = $tmpnode.Path -replace "OU=PawT0","OU=$newName5,OU=Stations,OU=$NewName3" } }

# OU: PAW / Stations / Tier 12L
Write-Host "${bCyan}Type-in the name of the O.U. for PAW Computer used in Tier 1, 2 and Legacy (default: ${S_Brown}T12L${bCyan}): ${Cend}" -NoNewline
$newName6 = Read-Host 
if ($newName5 -eq "" -or $null -eq $newName6) { $newName5 = "T12L" }
$node = $xml_TasksSequence.Settings.OrganizationalUnits.ouTree.OU.ChildOU | Where-Object { $_.Description -eq "Physical or virtual PAW dedicated to manage Tier 1, 2 or Legacy" } ; $node.Name = "$newName6"
$node = $xml_TasksSequence.Settings.Translation.wellKnownID | Where-Object { $_.TranslateFrom -eq "%OU-Paw-T12L%" } ; $node.translateTo = "$newName6"
$nodes = $xml_TasksSequence.Settings.GroupPolicies.GPO | Where-Object { $_.GpoLink.Path -like "*=PawT12L*" } ; foreach ($node in $nodes) { foreach ($tmpnode in $Node.GpoLink) { $tmpnode.Path = $tmpnode.Path -replace "OU=PawT12L","OU=$newName6,OU=Stations,OU=$NewName3" } }
$nodes = $xml_TasksSequence.Settings.LocalAdminPasswordSolution.AdmPwdSelfPermission | Where-Object { $_.Target -like "*=PawT12L*" } ; foreach ($node in $nodes) { $node.Target = $node.Target -replace "OU=PawAccess","OU=$newName6,OU=Stations,OU=$NewName3" }
#endregion
#region Tier 0 OU
Write-Host "${bCyan}Type-in the name of the Tier 0 O.U. (default: ${S_Brown}Harden_T0${bCyan}): ${Cend}" -NoNewline
$NewNam7 = Read-Host 
if ($NewName7 -eq "" -or $null -eq $NewName7) { $NewName7 = "Harden_T0" }
$node = $xml_TasksSequence.Settings.OrganizationalUnits.ouTree.OU | Where-Object { $_.Class -eq "HardenAD_PROD=T0" } ; $node.Name = "$NewName7"
$node = $xml_TasksSequence.Settings.DelegationACEs.SDDL | Where-Object { $_.Trustee -eq "L-S-T0-DELEG_Computer - Join Domain" } ; $node.TargetDN = $node.TargetDN -replace "OU=Harden_T0","OU=$newName7" }
$node = $xml_TasksSequence.Settings.Translation.wellKnownID | Where-Object { $_.TranslateFrom -eq "%OU-Production-T0%" } ; $node.translateTo = "$NewName7"
$nodes = $xml_TasksSequence.Settings.GroupPolicies.GPO | Where-Object { $_.GpoLink.Path -like "*Harden_T0*" } ; foreach ($node in $nodes) { foreach ($tmpnode in $Node.GpoLink) { $tmpnode.Path = $tmpnode.Path -replace "OU=Harden_T0","OU=$newName7" } }

#endregion


# Save XML
$xml_TasksSequence.Save((Resolve-Path -LiteralPath ".\..\..\Configs\TasksSequence_HardenAD.xml"))
