<# Les informations journalisées par PowerShell devraient être considérées comme sensibles dans la 
mesure où des scripts PowerShell exécutés sur les systèmes peuvent contenir des informations 
sensibles. Il convient dans ce cas de modifier le descripteur de sécurité du journal 
Microsoft-Windows-PowerShell/Operational pour empêcher sa lecture par tout le monde.

Pour ce faire, il est recommandé d'appliquer le descripteur de sécurité (au format SDDL)
du journal de sécurité au journal Microsoft-Windows-PowerShell/Operational.
Cela peut se faire par PowerShell tel qu'illustré par ce script.
#>

# Chemin du journal Microsoft-Windows-PowerShell/Operationnal
$Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\winevt\Channels\Microsoft-Windows-PowerShell/Operational'
# Copie du SDDL du journal de sÃ©curitÃ©
$Sddl = ((wevtutil gl security) -like 'channelAccess*').Split(' ')[1]
# Application au SDDL du journal Microsoft-Windows-PowerShell/Operational
Set-ItemProperty -Path $Path -Name ChannelAccess -Value $Sddl
