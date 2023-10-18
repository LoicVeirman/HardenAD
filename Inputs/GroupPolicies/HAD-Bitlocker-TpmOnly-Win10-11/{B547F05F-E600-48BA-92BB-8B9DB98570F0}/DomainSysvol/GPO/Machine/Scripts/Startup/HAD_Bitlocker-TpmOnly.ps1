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

    HADDrive([Microsoft.BitLocker.Structures.BitLockerVolume] $Volume) {
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
            [uint32] $_VolumeType = (Get-WmiObject Win32_Volume | Where-Object { $_.DriveLetter -eq $this.MountPoint }).DriveType
            [System.IO.DriveType] $_DriveInfo = (([System.IO.DriveInfo]::new($this.MountPoint)).DriveType)
        
            if ($_VolumeType -eq 3 -and $_DriveInfo -eq "Fixed") {
                $this.DiskType = [DiskType]::Fixed
            }
            elseif ($_VolumeType -eq 2 -and $_DriveInfo -eq "Removable") {
                $this.DiskType = [DiskType]::Removable
            }
            else {
                Write-host "hell"
                ### BAD TYPE
                exit
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
                Add-BitLockerKeyProtector -MountPoint $this.MountPoint -TpmProtector
                Enable-BitLocker -MountPoint $this.MountPoint -RecoveryPasswordProtector -SkipHardwareTest
            }
            "Fixed" {  }
            "Removable" {  }
            Default {}
        }
    }
}

$BLVolumes = Get-BitLockerVolume | Where-Object { $_.VolumeStatus -eq "FullyDecrypted" }

foreach ($Volume in $BLVolumes) {
    [HADDrive]::new($Volume)
}