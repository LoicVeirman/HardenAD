function Start-HADEncryption {
    [CmdletBinding()]
    param (
        [Parameter(
        )]
        [switch]
        $Pin,
        [Parameter(
        )]
        [switch]
        $OS,
        [Parameter(
        )]
        [switch]
        $Fixed,
        [Parameter(
        )]
        [switch]
        $USB
    )

    [LogMessage]::Initialize("$env:SystemRoot\Logs\HardenAD\Bitlocker", "Bitlocker")
    $Log = [LogMessage]::NewLogs()

    if (!(Test-ComputerSecureChannel)) {
        $Log.Fatal("Domain is not reachable.")
    }

    $Log.Success("Domain is reachable.")

    try {
        $BLVolumes = Test-EncryptionStatus -PIN $Pin
        $Log.Success(("{0} BitLocker volume, ready for encryption, have been found." -f $BLVolumes.Count))
    }
    catch {
        $Log.Fatal(("Unable to list any BitLocker volume: {0}." -f $_.Exception.Message))
    }

    if ($BLVolumes.Count -eq 0) {
        $Log.Info("All disks are already encrypted or in the process of being encrypted.")
        exit
    }   

    Compare-DiskToLogical

    foreach ($Volume in $BLVolumes) {
        
        if ($Volume.VolumeStatus -eq [Microsoft.BitLocker.Structures.BitLockerVolumeStatus]::FullyEncrypted -and
            $Volume.ProtectionStatus -eq [Microsoft.BitLocker.Structures.BitLockerVolumeProtectionStatus]::Off) {
            
            $Log.Info(("Decryption in progress for volume {0}." -f $Volume.MountPoint))
            Disable-BitLocker -MountPoint $Volume.MountPoint -Confirm:$false

            while ((Get-BitLockerVolume -MountPoint $Volume.MountPoint).VolumeStatus -eq [Microsoft.BitLocker.Structures.BitLockerVolumeStatus]::DecryptionInProgress) {
                Start-Sleep -Seconds 10
            }
            
            $Log.Info(("Volume {0} has been fully decrypted." -f $Volume.MountPoint))
        }     

        switch (Get-DriveType $Volume) {
        ([Microsoft.BitLocker.Structures.BitLockerVolumeType]::OperatingSystem) {
                if ($OS) {
                    $Log.Info(("Starting OS encryption for {0}." -f $Volume.MountPoint))
                    if ($PIN) {
                        $ScriptBlock = {
                            . "$env:ProgramFiles\HADBitlocker\Public\Get-PIN.ps1"
                            Get-PIN
                        }
                        try {
                            $CustomPin = (Invoke-AsCurrentUser -ScriptBlock $ScriptBlock -CaptureOutput -NonElevatedSession) -match "(\d){6,}"
                            $Log.Success("The PIN as been successfully choosed.")
                        }
                        catch {
                            $Log.Fatal(("The PIN could not be defined: {0}." -f $_.Exception.Message))
                        }
                        if ($Matches[0]) {
                            $null = [HADOSDrive]::new($Volume, $Matches[0])
                        }
                        else {
                            $Log.Fatal(("No PIN detected. Exiting... {0}" -f $_.Exception.Message))
                        }
                    }
                    else {
                        $null = [HADOSDrive]::new($Volume)
                    }
                }
            }

        ([System.IO.DriveType]::Fixed) {
                if ($Fixed) {
                    $Log.Info(("Starting fixed encryption for {0}." -f $Volume.MountPoint))
                    $null = [HADFixedDrive]::new($Volume)
                }
            }

        ([System.IO.DriveType]::Removable) {
                if ($USB) {
                    $Log.Info(("Starting USB encryption for {0}." -f $Volume.MountPoint))
                    $null = [HADRemovableDrive]::new($Volume)
                }
            }
            "Unknown" {
                $Log.Info(("Do nothing."))
            }
            Default {}
        }
    }
    
    Start-Process "$env:SystemRoot\System32\fvenotify.exe"
}