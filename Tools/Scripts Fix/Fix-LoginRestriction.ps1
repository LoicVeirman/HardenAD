<#
    .SYNOPSIS
    Fix the Guest account issue in Login Restirction GPO.

    .DESCRIPTION
    Replace the Guest account per the Guest Group in the following GPO:
    > HAD-LoginRestrictions-T0
    > HAD-LoginRestrictions-T1
    > HAD-LoginRestrictions-T2
    > HAD-LoginRestrictions-T1L
    > HAD-LoginRestrictions-T2L

    .NOTES
    Version 1.0.0 
#>
Param()

#Region displayColor creation
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
    $GPOList = Select-Xml $xmlTS -XPath "//GPO[starts-with(@Name,'HAD-LoginRestrictions-T')]" | Select-Object -ExpandProperty Node
    write-host "${S_Orange}Found${Cend}${S_yellow} $($GPOList.Count) ${Cend}${S_Orange}GPO entry to deal with${Cend}"
} Catch {
    Write-Host "${S_Red}Error${Cend}: ${S_Purple}$($_.ToString())${Cend}"
    exit 2
}

# Modifying GPO
foreach ($GPO in $GPOList) {
    # Loading SecPol file
    Try {
        # Get data
        $GPOBkpID = $GPO.BackupID
        $GPOPath = Resolve-Path -LiteralPath ".\..\..\Inputs\GroupPolicies\$($GPO.Name)\$GPOBkpID" -ErrorAction Stop
        $SecPolData = Get-Content "$GPOPath\DomainSysVol\GPO\Machine\microsoft\windows nt\SecEdit\GptTmpl.inf" -Encoding Unicode -ErrorAction Stop
        Write-Host "$($GPO.NAme) ${S_Green}Success${Cend}: ${S_Yellow}GptTmpl.inf loaded${Cend}"

        # Replacing value
        $SecPolData = $SecPolData.Replace('S-1-5-21-776332210-1913898547-2567112534-501','S-1-5-32-546')
        Write-Host "$($GPO.NAme) ${S_Green}Success${Cend}: ${S_Yellow}S-1-5-21-776332210-1913898547-2567112534-501' replaced by 'S-1-5-32-546'${Cend}"

        # output to file
        $SecPolData | Out-File "$GPOPath\DomainSysVol\GPO\Machine\microsoft\windows nt\SecEdit\GptTmpl.inf" -Force -ErrorAction Stop -Encoding Unicode
        Write-Host "$($GPO.NAme) ${S_Green}Success${Cend}: ${S_Yellow}file GptTmpl.inf updated${Cend}"

    } Catch {
        Write-Host "$($GPO.NAme) ${S_Red}Error${Cend}: ${S_Purple}$($_.ToString())${Cend}"
    }
}
