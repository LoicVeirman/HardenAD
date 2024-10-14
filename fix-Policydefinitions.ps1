<#
    .Synopsis
    Script to add missing ADML file to non en-us folder.

    .Notes
    Version 1.0.0 by Loic VEIRMAN
#>

Param()

$AdmlFiles = Get-ChildItem .\Inputs\PolicyDefinitions\en-US\
$AdmlDirs  = Get-ChildItem .\Inputs\PolicyDefinitions\ -Directory -Exclude "en-US"

ForEach ($Adml in $AdmlFiles)
{
    Write-Host "Checking $($Adml.Name):" -ForegroundColor Cyan
    foreach ($Dir in $AdmlDirs)
    {
        Write-Host "`t$($Dir.Fullname)\$($Adml.Name): " -NoNewline
        if (Test-Path "$($Dir.Fullname)\$($Adml.Name)")
        {
            Write-Host "exists" -ForegroundColor Green
        }
        else 
        {
            Try 
            {
                [void](Copy-Item -path $adml.FullName -Destination $dir.FullName -ErrorAction Stop -WarningAction SilentlyContinue)
                Write-host "copied successfully" -ForegroundColor Yellow
            }
            catch
            {
                Write-Host "copy failed!" -ForegroundColor Red
            }
        }
    }
}

Write-Host "`nScript's done`n" -ForegroundColor Magenta