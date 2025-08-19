<#
    .SYNOPSIS
    Invoke the documentation builder.

    .DESCRIPTION
    Automatically generate reference documentation in markdown.

    .PARAMETER Release
    To allow the release (defaulted to 2.9.9).

    .NOTES
    Version 1.0 by Loic VEIRMAN
#>
Param(
    [String]
    $Release="2.9.9"
)
Try {
    # Load module
    Import-Module ./../../Modules/translation.psm1

    # Load XML
    $tsXML = [xml](get-content ./../../Configs/TasksSequence_HardenAD.xml -Encoding UTF8 -ErrorAction Stop)

    # List GPO name, description, Linked OU and default settings.
    $gpoDoc = @('# GPO LIST'
                "### HardenAD release $($Release)"
                '---'
                'Name|Description|Active|WMI filter'
                '---|---|---|---'
                )
    
    $lnkDoc = @('# GPO LINK LIST'
    "### HardenAD release $($Release)"
    '---'
    'Name|Linked to|Enforced|Enabled'
    '---|---|---|---'
    )

    $GpoList = select-xml -Xml $tsXML -XPath "//*/GPO" | Select-Object -ExpandProperty Node

    foreach ($GpoItem in $GpoList) {
        $GpoDesc = ($GpoItem.description).replace('--- Harden AD --- " ,"',$null)
        $GpoLink = ''
        $GpoEnfo = ''
        $GpoEnab = ''
        $firstGpLink = $true
        if ($GpoItem.GpoLink) {
            foreach ($link in $GpoItem.GpoLink) {
                if ($firstGpLink) {
                    $GpoLink += Rename-ThroughTranslation $link.Path $tsXML.Settings.Translation
                    $GpoEnfo += $link.Enforced
                    $GpoEnab += $link.Enabled
                    $firstGpLink = $false
                }
                else {
                    $GpoLink += "</BR>$(Rename-ThroughTranslation $link.Path $tsXML.Settings.Translation)"
                    $GpoEnfo += "</BR>$($link.Enforced)"
                    $GpoEnab += "</BR>$($link.Enabled)"
                }
            }
        }
        $gpoDoc += "$($GpoItem.Name)|$($GpoDesc)|$($GpoItem.Validation)|$($GpoItem.GpoFilter.Wmi)"
        $lnkDoc += "$($GpoItem.Name)|$($GpoLink)|$($GpoEnfo)|$($GpoEnab)"
    }
    $gpoDoc | Out-File ./../../Documentations/"$Release Gpo Details.md" -Encoding UTF8 -Force
    $lnkDoc | Out-File ./../../Documentations/"$Release Gpo Links Details.md" -Encoding UTF8 -Force
}
Catch {
    write-host "Fatal error: $($_)"
    exit 1
}