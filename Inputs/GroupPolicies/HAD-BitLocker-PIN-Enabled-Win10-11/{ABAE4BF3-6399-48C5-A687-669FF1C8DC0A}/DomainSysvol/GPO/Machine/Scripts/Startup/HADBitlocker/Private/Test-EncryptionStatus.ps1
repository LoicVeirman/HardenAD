function Test-EncryptionStatus {
    [CmdletBinding()]
    param (
        [Parameter()]
        [bool]
        $PIN = $false
    )

    $Log = [LogMessage]::NewLogs()
    
    [Microsoft.BitLocker.Structures.BitLockerVolume[]] $DriveWithEncryptionNeeded = @()
    [Microsoft.BitLocker.Structures.BitLockerVolume[]] $BLVolumes = Get-BitLockerVolume

    foreach ($Volume in $BLVolumes) {

        if ($Volume.VolumeStatus -eq [Microsoft.BitLocker.Structures.BitLockerVolumeStatus]::FullyDecrypted) {
            
            $Log.Info(("Volume {0} is fully decrypted." -f $Volume.MountPoint))
            $DriveWithEncryptionNeeded += $Volume
            Continue
        }

        if ($PIN -and 
            ($Volume.VolumeStatus -eq [Microsoft.BitLocker.Structures.BitLockerVolumeStatus]::EncryptionSuspended -or 
            $Volume.VolumeStatus -eq [Microsoft.BitLocker.Structures.BitLockerVolumeStatus]::FullyEncrypted) -and 
            $Volume.KeyProtector.KeyProtectorType -notcontains "TpmPin") {
            
            $Log.Info(("Volume {0} is encrypted but doesn't have a PIN configured." -f $Volume.MountPoint))
            $DriveWithEncryptionNeeded += $Volume
            continue
            
        }

        if ($Volume.VolumeStatus -eq [Microsoft.BitLocker.Structures.BitLockerVolumeStatus]::FullyEncrypted -and
            $Volume.ProtectionStatus -eq [Microsoft.BitLocker.Structures.BitLockerVolumeProtectionStatus]::Off) {
            
            $Log.Info(("Volume {0} is encrypted but protection is off" -f $Volume.MountPoint))
            $DriveWithEncryptionNeeded += $Volume
            continue
        }        
    }

    return $DriveWithEncryptionNeeded

}