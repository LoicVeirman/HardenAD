<#
.SYNOPSIS
   Reintialisation du mot de passe du compte krbtgt

.DESCRIPTION
    Ce script permet de réinitialiser le mot de passe du compte krbtgt et de le synchroniser sur tous les DCs du domaine.
    Il est exécuté tous les 30 jours sur le PDC Emulator via une Tache planifiée du même nom déployée par GPO.

.NOTES
    Auteur    : Hugo SANCHEZ
    Date      : 23/08/2023
    Version   : 1.3
    Historique:
                - 25/08/2023 : Version 1.0 (Hugo Sanchez)


#>


function Generate-RandomSecurePassword {
    param (
        [int]$Length = 30,
        [int]$SpecialCharCount = 2,
        [int]$NumberCount = 2
    )

    $SpecialChars = '!@#$%^&*()_-+=<>?'
    $Numbers = '0123456789'
    $Uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    $Lowercase = 'abcdefghijklmnopqrstuvwxyz'

    $Random = New-Object System.Random
    $PasswordChars = @()

    for ($i = 0; $i -lt $SpecialCharCount; $i++) {
        $PasswordChars += $SpecialChars[$Random.Next(0, $SpecialChars.Length)]
    }

    for ($i = 0; $i -lt $NumberCount; $i++) {
        $PasswordChars += $Numbers[$Random.Next(0, $Numbers.Length)]
    }

    for ($i = 0; $i -lt ($Length - $SpecialCharCount - $NumberCount); $i++) {
        $CharSet = $Uppercase + $Lowercase
        $PasswordChars += $CharSet[$Random.Next(0, $CharSet.Length)]
    }

    $ShuffledPassword = $PasswordChars | Get-Random -Count $PasswordChars.Length
    $GeneratedPassword = -join $ShuffledPassword

    $SecurePassword = $GeneratedPassword | ConvertTo-SecureString -AsPlainText -Force

    return $SecurePassword
}


function Remove-EmptyMessageLines {
    param (
        [string]$logFilePath
    )

    # Load the CSV data
    $csvData = Import-Csv -Path $logFilePath

    # Filter out lines with empty message
    $filteredData = $csvData | Where-Object { $_.Message -ne "" }

    # Export the filtered data back to the CSV file
    $filteredData | Export-Csv -Path $logFilePath -NoTypeInformation -Force
}




function Set-KrbtgtPassword
{
    $LogDirectory = "C:\Windows\HardenAD\Logs\KRBTGT_PasswordReset"
    $LogFilePath = Join-Path -Path $LogDirectory -ChildPath "Log.csv"

    # Check if the log directory exists, create if not
    if (-not (Test-Path -Path $LogDirectory)) {
        New-Item -Path $LogDirectory -ItemType Directory
    }

    # Get the execution date of the script
    $ExecutionDate = Get-Date

    # Check if the script is running on the PDC
    $domainController_PDC = Get-ADDomainController -Discover -Service PrimaryDC
    if ($domainController_PDC.Name -eq $env:COMPUTERNAME) {
        # Reset the krbtgt password
        $SecureGeneratedPassword = Generate-RandomSecurePassword -Length 30 -SpecialCharCount 3 -NumberCount 3
        $krbtgt = Get-ADUser krbtgt
        $krbtgt | Set-ADAccountPassword -NewPassword $SecureGeneratedPassword

        # Run repadmin command and capture its output
        $repadminOutput = Invoke-Expression "repadmin /syncall /AdeP"

        # Format repadmin output for logging
        $formattedOutput = $repadminOutput -split "`r`n" | ForEach-Object {
            [PSCustomObject]@{
                Date = $ExecutionDate
                Message = $_
            }
        }

        # Write formatted repadmin output to the log file
        $formattedOutput | Export-Csv -Path $LogFilePath -Append -NoTypeInformation

        $LogMessage = "Krbtgt account password has been reset."
        $LogEntry = [PSCustomObject]@{
            Date = $ExecutionDate
            Message = $LogMessage
        }
        $LogEntry | Export-Csv -Path $LogFilePath -Append -NoTypeInformation
        # Call the function to remove lines with empty message
        Remove-EmptyMessageLines -logFilePath $LogFilePath

        Write-Host $LogMessage
    } else {
        $LogMessage = "This DC does not have the role PDC Emulator. Please check your configuration."
        $LogEntry = [PSCustomObject]@{
            Date = $ExecutionDate
            Message = $LogMessage
        }
        $LogEntry | Export-Csv -Path $LogFilePath -Append -NoTypeInformation

        Write-Warning $LogMessage
        exit
    }
}

Set-KrbtgtPassword