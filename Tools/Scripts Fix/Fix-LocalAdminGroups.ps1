<#
    .SYNOPSIS
    Fix the local Admin Group name issue in HAD-LocalAdmin GPO.

    .DESCRIPTION
    Replace the wrong value in translation.xml to match with the correct one in the following GPO folders:
    > HAD-LocalAdmins-Paw
    > HAD-LocalAdmins-PawT0
    > HAD-LocalAdmins-PawT12L
    > HAD-LocalAdmins-T0-Srv
    > HAD-LocalAdmins-T0-Wks
    > HAD-LocalAdmins-T1
    > HAD-LocalAdmins-T1L
    > HAD-LocalAdmins-T2
    > HAD-LocalAdmins-T2L

    .NOTES
    Version 1.0.0 
#>
Param()
#Region displayColor creation
# Using ANSI Escape code
$S_Orange   = "$([char]0x1b)[38;2;244;135;69m"
$S_purple   = "$([char]0x1b)[38;2;218;101;167m"
$S_purple2  = "$([char]0x1b)[38;2;206;112;179m"
$S_yellow   = "$([char]0x1b)[38;2;220;220;170;24m"
$S_Red      = "$([char]0x1b)[38;2;255;0;0m"
$S_Green    = "$([char]0x1b)[38;5;42;24m"
$Cend       = "$([char]0x1b)[0m"
#EndRegion
# Retrieve XML file
Try {
    $xmlTS = [xml](Get-Content .\..\..\Configs\TasksSequence_HardenAD.xml -Encoding UTF8 -ErrorAction Stop)
    write-host "${S_Orange}File${Cend}${S_yellow} TasksSequence_HardenAD.xml ${Cend}${S_Orange}Loaded${Cend}"
} Catch {
    Write-Host "${S_Red}Error${Cend}: ${S_Purple2}$($_.ToString())${Cend}"
    exit 1
}

# Get GPO list to work with
Try {
    $GPOList = Select-Xml $xmlTS -XPath "//GPO[starts-with(@Name,'HAD-LocalAdmins-')]" | Select-Object -ExpandProperty Node
    write-host "${S_Orange}Found${Cend}${S_yellow} $($GPOList.Count) ${Cend}${S_Orange}GPO entry to deal with${Cend}"
} Catch {
    Write-Host "${S_Red}Error${Cend}: ${S_Purple}$($_.ToString())${Cend}"
    exit 2
}

# Modifying file translation.xml
foreach ($GPO in $GPOList) {
    # Display to user
    write-host "[${S_Orange}$($GPO.Name)${Cend}] " -NoNewline
    # Looking for translation.xml
    if (Test-Path (Resolve-Path -LiteralPath ".\..\..\Inputs\GroupPolicies\$($GPO.Name)\$($GPO.BackupID)\translation.xml")) {
        # update screeen
        write-host "${S_yellow}found translation.xml${Cend} " -NoNewline
        # load and replace content
        Try {
            $string = [System.IO.File]::ReadAllText((Resolve-Path -LiteralPath ".\..\..\Inputs\GroupPolicies\$($GPO.Name)\$($GPO.BackupID)\translation.xml"))
            $string = $string.Replace('%NetBios%\%Prefix%_%Groups_Computers%', '%NetBios%\%Prefix-domLoc%%Groups_Computers%')
            [System.IO.File]::WriteAllText((Resolve-Path -LiteralPath ".\..\..\Inputs\GroupPolicies\$($GPO.Name)\$($GPO.BackupID)\translation.xml"), $string)
            Write-Host "${S_Green}File updated successfully${Cend}"
        }
        Catch {
            Write-Host "${S_Red}File failed to be updated!${Cend}"
        }
    } 
    Else {
        # Update screeen
        write-host "${S_Green} translation.xml not present"
    }
}

# End
Write-Host "`n${S_Purple}Script's done.${Cend}`n"