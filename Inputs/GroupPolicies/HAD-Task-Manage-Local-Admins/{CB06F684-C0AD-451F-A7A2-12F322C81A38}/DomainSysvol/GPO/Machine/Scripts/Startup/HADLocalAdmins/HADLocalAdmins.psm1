### Use custom classes as module
using module .\HardenEngine\HADObjects\HADObjects.psm1
using module .\HardenEngine\HADLogger\HADLogger.psm1

### Import every functions
$Functions = Get-ChildItem -Path "$PSScriptRoot\Functions\*" -Recurse -Include "*.ps1" 
foreach ($Function in $Functions) {
    try {
        . $Function.FullName
    }
    catch {
        Write-Error -Message ("Failed to import function {0}: {1}" -f $($Function.FullName), $_.Exception.Message)
    }
}