using module BitLocker
using module ".\Classes\Logger.psm1"
using module ".\Classes\HADDrives.psm1"
using module ".\Classes\RunAsUser\runasuser.psm1"

$Public = Get-ChildItem -Path $PSScriptRoot\Public\*ps1
$Private = Get-ChildItem -Path $PSScriptRoot\Private\*ps1

foreach ($File in @($Public + $Private)) {
    try {
        . $File.FullName
    }
    catch {
        Write-Error -Message "Failed to import function $($File.FullName): $_"
    }
}