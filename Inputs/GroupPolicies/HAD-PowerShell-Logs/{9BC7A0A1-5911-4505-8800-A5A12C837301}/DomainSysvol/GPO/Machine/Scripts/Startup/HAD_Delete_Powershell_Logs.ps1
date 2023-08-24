$dateActuelle = Get-Date

$dateLimite = $dateActuelle.AddDays(-7)

$cheminRepertoire = "C:\Windows\HardenAD\Logs\Powershell-Logs"
$dossiers = Get-ChildItem -Path $cheminRepertoire -Directory

foreach ($dossier in $dossiers) {
    try {
        $timestamp = [datetime]::ParseExact($dossier.Name, "yyyyMMdd", $null)
        
        if ($timestamp -lt $dateLimite) {
            Remove-Item -Path $dossier.FullName -Recurse -Force
        }
    }
    catch {
        continue
    }
}