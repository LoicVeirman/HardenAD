<#
    .SYNOPSIS
    Script to automatically create update documentation.

    .DESCRIPTION
    Compare two editions of HardenAD and generate change log files and a resume for the github page.

    .PARAMETER PreviousSourceFolder
    Give path (relative or not) to the previous hAD binaries to be compared.

    .NOTES
    Version 1.0.0
    Author  Loic VEIRMAN - MSSEC
#>
Param(
    [Parameter(Mandatory)]
    [String]
    $PreviousVersionPath
)
Try {
    #region .. Welcome
    $Global:PreviousSourceFolder = $PreviousVersionPath -replace '\\$'
    # Import modules
    [void](Import-Module .\Modules -Force -ErrorAction Stop)
    #.Header data
    $LUpCorner    = "$([Char]0x2554)"
    $RUpCorner    = "$([Char]0x2557)" 
    $flatedLine   = "$([Char]0x2550)"
    $borderLine   = "$([Char]0x2551)"
    $LDownCorner  = "$([Char]0x255A)"
    $RDownCorner  = "$([Char]0x255D)"
    $HeaderName   = "hAD Documentator"
    $HeaderVer    = "1.0.0"
    $HeaderLic    = "$([char]0xA9) MSSEC"
    $MyFlatedLine = ""
    $myHeaderBln1 = ""
    $myHeaderBln2 = ""

    # Compute max lengthes
    $maxLength = [Math]::Max($HeaderName.Length, ($HeaderVer.length + $HeaderLic.Length + 1))
    for($i = 1 ; $i -le $maxLength + 2 ; $i++) {
        $MyFlatedLine += $flatedLine
    }
    For ($i = $HeaderName.Length ; $i -le $maxLength ; $i++) {
        $myHeaderBln1 += " "
    }
    For ($i = $HeaderVer.Length + $HeaderLic.Length  ; $i -lt $maxLength ; $i++) {
        $myHeaderBln2 += " "
    }
    $H0_1 = "$($LUpCorner)$($MyFlatedLine)$($RUpCorner)"
    $H0_2 = "$($borderLine) $($HeaderName)$($myHeaderBln1)$($borderLine)" 
    $H0_3 = "$($borderLine) $($HeaderLic)$($myHeaderBln2)$($HeaderVer) $($borderLine)"
    $H0_4 = "$($LDownCorner)$($MyFlatedLine)$($RDownCorner)"

    # Display header
    WriteScreen M1 ' '
    WriteScreen H0 @($H0_1,$H0_2,$H0_3,$H0_4)
    WriteScreen M1 ' '
    #endRegion Welcome
    
    #region .. PreFlightcheck
    # ensure the path contains expected file
    if (-not(test-path "$($PreviousSourceFolder)\Configs\TasksSequence_hardenAD.xml")) {
        Throw "The path $($PreviousSourceFolder) does not contains .\Configs\TasksSequence_HardenAD.xml"
    }
    # ensure it can load the xml file
    $oldXML = [xml](Get-content "$($PreviousSourceFolder)\Configs\TasksSequence_hardenAD.xml" -Encoding UTF8 -ErrorAction Stop)
    # ensure it can load the running xml file
    $newXML = [xml](Get-Content (Resolve-Path ..\..\Configs\TasksSequence_HardenAD.xml).Path -Encoding UTF8 -ErrorAction Stop)
    #endRegion PreFlightcheck

    #region .. Routine
    # The routine call separate function and collect output result for the final md resume file.
    $mdResume = @(
        '# HARDEN AD CHANGE LOG  '
        ' '
        "File updated on $(Get-Date -Format 'yyyy-MM-dd [HH:mm:ss]')  "
        ' '
        "---  "
        "### About this file  "
        " This file is a resume of changes operated between the version $($oldXML.Settings.Version.Release.Major).$($oldXML.Settings.Version.Release.Minor).$($oldXML.Settings.Version.Release.BugFix) and this release.  "
    )

    # Routine call function and catch result. The function are listed in an array here under (noun only).
    $routines = @(
        'OrganizationalUnits'
        'DelegationACEs'
        'Translation'
        'GroupPolicies'
        'Accounts'
        'Groups'
        'DefaultMembers'
        'LocalAdminPasswordSolution'
        'Sequence'
    )

    # Let's the party begin...
    foreach ($routine in $routines) {
        WriteScreen I0 "analyzing $($routine) section"
        if ($routine -ne 'OrganizationalUnits') {
            $mdResume += . "compare-$routine" $oldXML.Settings.$routine $newXML.Settings.$routine
        } 
        Else {
            $mdResume += . "compare-$routine" $oldXML $newXML
        }
        WriteScreen R0 "Anlyze of $($routine) section;done"
    }
    #endRegion Routine

    #region .. Byebye
    # Compute Header
    $mdResume | Out-File ..\..\Documentations\Resume-ThisEdition.md -Encoding UTF8 -Force
    $HeaderOver = "Script's done"
    $MyFlatedLine = ""
    for ($i = 1 ; $i -le $HeaderOver.Length + 2 ; $i++) {
        $MyFlatedLine += $flatedLine
    }
    $H1_1 = "$($LUpCorner)$($MyFlatedLine)$($RUpCorner)"
    $H1_2 = "$($borderLine) $($HeaderOver) $($borderLine)" 
    $H1_3 = "$($LDownCorner)$($MyFlatedLine)$($RDownCorner)"

    # Display header
    WriteScreen M1 ' '
    WriteScreen H1 @($H1_1,$H1_2,$H1_3)
    WriteScreen M1 ' '
    #endRegion ByeBye
}
Catch {
    #region .. Unexpected Error
    WriteScreen E0 @("Unexpected error - Script's leaves unexpectedly.",$_)
    Exit 1
    #endRegion Unexpected Error
}