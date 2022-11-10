<#
    .SYNOPSIS
    This script will search for gpReport.xml file and generate a translation file a root of .\inputs

    .NOTES
    Version 01.00
#>

Param(
)

write-host "[" -ForegroundColor Green -NoNewline
Write-host "START" -ForegroundColor Yellow -NoNewline
Write-host "]" -ForegroundColor Green -NoNewline
Write-host " Building GPO BackupID reference table" -ForegroundColor White

$BkpXmls = Get-ChildItem ..\..\Inputs\GroupPolicies -Recurse | Where-Object { $_.name -eq "gpReport.xml" }

If (Test-Path ..\..\Inputs\GroupPolicies\BackupID-Translation.csv)
{
    Remove-Item ..\..\Inputs\GroupPolicies\BackupID-Translation.csv -Force

    write-host "[" -ForegroundColor Green -NoNewline
    Write-host "CLEAR" -ForegroundColor Magenta -NoNewline
    Write-host "]" -ForegroundColor Green -NoNewline
    Write-host " Deleting preexisting file" -ForegroundColor White
}
$result = @()

foreach ($BkpXml in $BkpXmls)
{
    $xml = [xml]([system.io.file]::ReadAllText($BkpXml.fullname))
    $result += New-Object -TypeName psobject -Property @{Name=$xml.GPO.Name ; BackupId=$BkpXml.Directory.Name}

    write-host "[" -ForegroundColor Green -NoNewline
    Write-host " RUN " -ForegroundColor cyan -NoNewline
    Write-host "]" -ForegroundColor Green -NoNewline
    Write-host " Analazing" $BkpXml.Directory.Name -ForegroundColor White
}

$result | Export-Csv ..\..\Inputs\GroupPolicies\BackupID-Translation.csv -Delimiter ";" -Encoding "UTF8" -NoTypeInformation

Write-Host "[" -ForegroundColor Green -NoNewline
Write-Host "DONE!" -ForegroundColor Yellow -NoNewline
Write-Host "]" -ForegroundColor Green -NoNewline
Write-Host " Table file exported to " -ForegroundColor White -NoNewline
Write-Host "BackupID-Translation.csv" -ForegroundColor Yellow
Write-Host

Exit 0