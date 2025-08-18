function Get-DriveType {
    [CmdletBinding()]
    param (
        [Parameter(
            Mandatory = $true,
            HelpMessage = "The volume that will be bitlocked."
        )]
        [ValidateNotNullOrEmpty()]
        [Microsoft.BitLocker.Structures.BitLockerVolume]
        $Volume
    )

    if ($Volume.MountPoint -eq $env:SystemDrive -and $Volume.VolumeType -eq [Microsoft.BitLocker.Structures.BitLockerVolumeType]::OperatingSystem) {
        return [Microsoft.BitLocker.Structures.BitLockerVolumeType]::OperatingSystem
    }
    else {
        if (($Global:Array | Where-Object { $_.DriveLetter -eq $Volume.MountPoint }).BusType -in @("nvme", "sata")) {
            return [System.IO.DriveType]::Fixed
        }
        elseif (($Global:Array | Where-Object { $_.DriveLetter -eq $Volume.MountPoint }).BusType -eq "USB") {
            return [System.IO.DriveType]::Removable
        }
        else {
            return "Unknown"
        }
    }
}


