[CmdletBinding()]
param (
    [Parameter(
    )]
    [switch]
    $Pin
)

enum DiskType {
    Fixed
    OS
    Removable
}

class HADDrive {
    # [Microsoft.BitLocker.Structures.BitLockerVolume] $BLV
    [string] $MountPoint
    [bool] $TPMReady = $false
    [bool] $ValidVersion = $false
    [string] $EncryptionStatus
    [string] $DiskType
    [string] $VolumeType

    HADDrive($Volume) {
        # $this.BLV = $Volume
        $this.MountPoint = $Volume.MountPoint
        $this.EncryptionStatus = $Volume.VolumeStatus
        $this.VolumeType = $Volume.VolumeType

        $this.GetDriveType()
        $this.IsBLCompatible()

        if ($this.ValidVersion -and $this.TPMReady) {
            $this.EnableBitlocker()
        }
    }

    [void] GetDriveType() {
        if ($this.MountPoint -eq $env:SystemDrive -and $this.VolumeType -eq "OperatingSystem") {
            $this.DiskType = [DiskType]::OS
        }
        else {
            if (($Global:Array | Where-Object { $_.DriveLetter -eq $this.MountPoint }).BusType -eq "USB") {
                $this.DiskType = [DiskType]::Removable
            }
            else {
                $this.DiskType = [DiskType]::Fixed
            }
        }
    }

    [void] IsBLCompatible() {

        [bool] $isSystemSupported = ([System.Environment]::OSVersion.Version -ge ([System.Version] "6.2.9200"))
        [bool] $isSystemAWorkstation = ((Get-WmiObject -Class Win32_OperatingSystem | Where-Object { $_.PSComputerName -eq $env:COMPUTERNAME }).ProductType -eq 1)

        if ($isSystemSupported -and $isSystemAWorkstation) {
            $this.ValidVersion = $true
            if (!(Get-Tpm).TpmReady) {
                try {
                    Initialize-Tpm -AllowClear -AllowPhysicalPresence
                    $this.TPMReady = $true
                }
                catch {
                    <#Do this if a terminating exception happens#>
                }
            }
            else {
                $this.TPMReady = $true
            }
        }
    }

    [void] EnableBitlocker() {
        switch ($this.DiskType) {
            "OS" {
                write-host "Hello"
                Add-BitLockerKeyProtector -MountPoint $this.MountPoint -TpmProtector
                Enable-BitLocker -MountPoint $this.MountPoint -RecoveryPasswordProtector -SkipHardwareTest
            }
            "Fixed" { 
                if ((Get-BitLockerVolume -MountPoint $env:SystemDrive).VolumeType -eq "FullyDecripted") {
                    continue
                }
                Enable-BitLocker -MountPoint $this.MountPoint -RecoveryPasswordProtector -SkipHardwareTest
                Enable-BitLockerAutoUnlock -MountPoint $this.MountPoint
            }
            "Removable" { 
                Enable-BitLocker -MountPoint $this.MountPoint -PasswordProtector (ConvertTo-SecureString -AsPlainText "Root123/*-" -Force)
                Enable-BitLockerAutoUnlock
            }
            Default {}
        }
    }
}

function Get-DiskLetterAndType {
    $Partitions = Get-CimInstance Win32_DiskPartition
    $PhysicalDisks = Get-PhysicalDisk
    
    $Global:Array = @()
    
    foreach ($Partition in $Partitions) {
        $Corresp = Get-CimInstance -Query "ASSOCIATORS OF `
        {Win32_DiskPartition.DeviceID='$($Partition.DeviceID)'} `
        WHERE AssocClass=Win32_LogicalDiskToPartition"
        $Regex = $Partition.Name -match "(\d+)"
        $PhysicalDiskNr = $Matches[0]
    
        foreach ($C in $Corresp) {
            $Global:Array += [PSCustomObject]@{
                DriveLetter = $C.DeviceID
                BusType     = ($PhysicalDisks | Where-Object { $_.DeviceID -eq $PhysicalDiskNr }).BusType
            }
        }
    }
}

Get-DiskLetterAndType

$BLVolumes = Get-BitLockerVolume | Where-Object { $_.VolumeStatus -eq "FullyDecrypted" }

foreach ($Volume in $BLVolumes) {
    [HADDrive]::new($Volume)
}