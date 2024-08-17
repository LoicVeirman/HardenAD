<#
    .SYNOPSIS
    This is a caller to perform a mass check upon all existing computer objects.

    .NOTES
    Script version 01.00 by Loic VEIRMAN - MSSEC / 15th April 2024.
    Script version 01.01 by Loic VEIRMAN - MSSEC / 14th August 2024.
#>

Param()

try {
    # Loading XML settings
    $configXml = [xml](Get-Content .\configuration-custom.xml -Encoding UTF8 -ErrorAction Stop)
    $TskSeqXml = [xml](Get-Content $env:ProgramData\HardenAD\Configuration\TasksSequence_HardenAD.xml -Encoding UTF8 -ErrorAction Stop)

    # Getting data from AD
    $DCs   = (Get-ADDomainController -Filter *) | ForEach-Object { Get-ADComputer $_.Name }
    $Cptrs = Get-ADComputer -Filter * 

    # Filtering out DCs to get the real test list
    $Check = (Compare-Object $Cptrs $DCs).InputObject

    # Running the check... We hunt for missing group, and of found, we call the creation script.
    $Code = 0
    $GroupPattern = $configXml.customRuleSet.default.target.name
    # First translation: raw data
    foreach ($translation in $TskSeqXml.Settings.translation.wellKnownID) { $GroupPattern = $GroupPattern -replace $translation.TranslateFrom, $translation.TranslateTo }
    # Second translation: TranslateTo refering to TranslateFrom
    foreach ($translation in $TskSeqXml.Settings.translation.wellKnownID) { $GroupPattern = $GroupPattern -replace $translation.TranslateFrom, $translation.TranslateTo }
    # Dealing object
    foreach ($Computer in $Check)
    {
        Try {
            # Compute group name
            $GrpName = $GroupPattern -replace '%ComputerName%', $Computer.Name

            if (-not(Get-ADObject -LDAPFilter "(&(ObjectClass=Group)(sAMAccountName=$GrpName))"))
            {
                [void](.\Set-RemoteDesktopUsers -ComputerName $Computer.Name)
            }
        } 
        Catch {
            $Code++
        }
    }
    # Exit with code error equal to the amount of failure :)
    Exit $Code
}
Catch {
    # wooops
    Throw $_.ToString()
}