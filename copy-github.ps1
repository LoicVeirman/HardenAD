<#
    .SYNOPSIS
    Script to duplicate the repo to a test directory.

    .DESCRIPTION
    This script copy the files in the current location to your test directory. This way, you can maintain the repo clean and test updates.

    .PARAMETER TargetDir
    Path to your destination dir.

    .NOTES
    Version 1.0.0 By Loic VEIRMAN
#>

[CmdletBinding()]
param (
    [Parameter()]
    [String]
    $TargetDir="C:\HAD"
)

if (-not (Test-Path $TargetDir)) {
    New-Item -ItemType Directory -Path $TargetDir -Force
}
Robocopy.exe (Convert-Path -LiteralPath .) (Convert-Path -LiteralPath $TargetDir) /MIR