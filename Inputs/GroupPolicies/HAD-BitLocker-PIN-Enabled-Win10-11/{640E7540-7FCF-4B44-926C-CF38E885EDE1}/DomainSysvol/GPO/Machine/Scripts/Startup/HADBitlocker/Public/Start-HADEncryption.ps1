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

    [LogMessage]::Initialize("$env:SystemRoot\Logs\HardenAD\Bitlocker")
    $Log = [LogMessage]::NewLogs()

    if (!(Test-ComputerSecureChannel)) {
        $Log.Fatal("Domain is not reachable.")
    }

    try {
        $BLVolumes = Get-BitLockerVolume | Where-Object { $_.VolumeStatus -eq "FullyDecrypted" }
        $Log.Success(("{0} BitLocker volume, ready for encryption, have been found." -f $BLVolumes.Count))
    }
    catch {
        $Log.Fatal(("Unable to list any BitLocker volume: {0}." -f $_.Exception.Message))
    }

    Compare-DiskToLogical

    foreach ($Volume in $BLVolumes) {
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
                            [HADOSDrive]::new($Volume, $Matches[0])
                        }
                        else {
                            $Log.Fatal(("No PIN detected. Exiting... {0}" -f $_.Exception.Message))
                        }
                    }
                    else {
                        [HADOSDrive]::new($Volume)
                    }
                }
            }
        ([System.IO.DriveType]::Fixed) {
                if ($Fixed) {
                    $Log.Info(("Starting fixed encryption for {0}." -f $Volume.MountPoint))
                    [HADFixedDrive]::new($Volume)
                }
            }
        ([System.IO.DriveType]::Removable) {
                if ($USB) {
                    $Log.Info(("Starting USB encryption for {0}." -f $Volume.MountPoint))
                    [HADRemovableDrive]::new($Volume)
                }
            }
            Default {}
        }
    }
    Start-Process "$env:SystemRoot\System32\fvenotify.exe"
}