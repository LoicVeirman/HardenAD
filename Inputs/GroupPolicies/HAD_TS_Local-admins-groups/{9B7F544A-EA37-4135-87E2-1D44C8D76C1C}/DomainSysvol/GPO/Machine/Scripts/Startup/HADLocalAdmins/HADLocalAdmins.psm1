using module .\Class\HADLogging.psm1

$Public = @( Get-ChildItem -Path $PSScriptRoot\Public\*ps1 -Recurse -ErrorAction SilentlyContinue)
$Private = @( Get-ChildItem -Path $PSScriptRoot\Private\*ps1 -Recurse -ErrorAction SilentlyContinue)

foreach ($File in @($Private + $Public)) {
    try {
        . $File.FullName
    }
    catch {
        Write-Error -Message "Failed to import function $($File.FullName): $_"
    }
}

# Export-ModuleMember -Function $Public.BaseName