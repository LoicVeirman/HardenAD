using module .\Logger.psm1
enum DiskType {
    Fixed
    OS
    Removable
}

class HADDrive {
    [string] $MountPoint
    [bool] $TPMReady = $false
    [bool] $ValidVersion = $false
    [string] $EncryptionStatus
    [string] $VolumeType

    HADDrive($Volume) {
        $this.MountPoint = $Volume.MountPoint
        $this.EncryptionStatus = $Volume.VolumeStatus
        $this.VolumeType = $Volume.VolumeType
        $this.IsBLCompatible()
    }
    
    [void] IsBLCompatible() {

        $Log = [LogMessage]::NewLogs()
        [bool] $isSystemSupported = $false
        [bool] $isSystemAWorkstation = $false
        [bool] $isVolumeInitializedForProtection = $false

        try {
            $isSystemSupported = ([System.Environment]::OSVersion.Version -ge ([System.Version] "6.2.9200"))
            $Log.Success(("The OS version [{0}] is compatible with BitLocker encryption." -f [System.Environment]::OSVersion.Version))
        }
        catch {
            $Log.Fatal(("An error occured while collecting OS version: {0}." -f $_.Exception.Message))                
        }        
        try {
            $isSystemAWorkstation = ((Get-WmiObject -Class Win32_OperatingSystem | Where-Object { $_.PSComputerName -eq $env:COMPUTERNAME }).ProductType -eq 1)
            $Log.Success("The computer is a workstation, continue.")
        }
        catch {
            $Log.Fatal(("An error occured while collecting the computer type."))        
        }        
        try {
            $isVolumeInitializedForProtection = (Get-WmiObject -Class Win32_EncryptableVolume -Namespace 'root\cimv2\Security\MicrosoftVolumeEncryption' -Filter "DriveLetter=`"$($this.MountPoint)`"").IsVolumeInitializedForProtection
            $Log.Success(("{0} is initialized for protection" -f $this.MountPoint))
        }
        catch {
            $Log.Fatal(("An error occured while collecting informations about volume encryption status: {0}." -f $_.Exception.Message))        
        }

        if ($isSystemSupported -and $isSystemAWorkstation -and !$isVolumeInitializedForProtection) {
            $this.ValidVersion = $true
            if (!(Get-Tpm).TpmReady) {
                $Log.Info("The TPM isn't ready yet for BitLocker encryption.")
                try {
                    Initialize-Tpm -AllowClear -AllowPhysicalPresence
                    $this.TPMReady = $true
                    $Log.Success("Initialization of TPM has been successfull.")
                }
                catch {
                    $Log.Fatal(("Unable to initialize TPM: {0}." -f $_.Exception.Message))                
                }
            }
            else {
                $Log.Info("TPM is ready for BitLocker encryption.")
                $this.TPMReady = $true
            }
        }
    }

    [void] EnableBitLocker([string] $CustomPIN) {
        $Log = [LogMessage]::NewLogs()
        if ($this.ValidVersion -and $this.TPMReady) {
            switch ($this.DiskType) {
                ([DiskType]::OS) {
                    $Log.Info(("Start encryption process for the OS drive: {0}." -f $this.MountPoint))
                    if ($this.PIN) {
                        [System.Security.SecureString] $SecurePin = $null
                        try {
                            $SecurePin = ConvertTo-SecureString $CustomPIN -AsPlainText -Force
                            $Log.Success("PIN has been converted to a secure string.")
                        }
                        catch {
                            $Log.Fatal(("Unable to secure the PIN: {0}" -f $_.Exception.Message))                        
                        }
                        if ($SecurePin) {
                            try {
                                Add-BitLockerKeyProtector -MountPoint $this.MountPoint -Pin $SecurePin -TpmAndPinProtector -Verbose:$false
                                $Log.Success(("A PIN has been added for BitLocker protection."))
                            }
                            catch {
                                $Log.Fatal(("Unable to add a PIN for BitLocker encryption: {0}." -f $_.Exception.Message))
                            }                            
                        }
                        else {
                            $Log.Fatal("Secure PIN is empty.")
                        }
                    }
                    try {
                        $null = Enable-BitLocker -MountPoint $this.MountPoint -RecoveryPasswordProtector -SkipHardwareTest -Verbose:$false
                        $Log.Success(("{0} has been successfully encrypted." -f $this.MountPoint))
                    }
                    catch {
                        $Log.Error("Unable to encrypt {0}: {1}." -f $this.MountPoint, $_.Exception.Message)
                    }                
                }
                ([DiskType]::Fixed) {
                    $Log.Info(("Start encryption process for the fixed drive: {0}." -f $this.MountPoint))
                    [Microsoft.BitLocker.Structures.BitLockerVolume] $BLV = $null
                    try {
                        $BLV = Get-BitLockerVolume -MountPoint $env:SystemDrive
                    }
                    catch {
                        $Log.Error(("Unable to get a volume for {0}: {1}." -f $this.MountPoint, $_.Exception.Message))
                    }
                    [bool] $isOSEncrypted = $BLV.VolumeStatus -ne [Microsoft.BitLocker.Structures.BitLockerVolumeStatus]::FullyDecrypted
                    $Log.Info(("{0} is {1}" -f $this.MountPoint, $BLV.VolumeStatus))

                    if ($isOSEncrypted) {
                        try {
                            $null = Enable-BitLocker -MountPoint $this.MountPoint -RecoveryPasswordProtector -SkipHardwareTest -Verbose:$false
                            $Log.Success(("{0} has been encrypted successfully."))
                        }
                        catch {
                            $Log.Fatal(("An error occured while encrypting {0}: {1}." -f $this.MountPoint, $_.Exception.Message))                        
                        }                        
                        try {
                            $null = Enable-BitLockerAutoUnlock -MountPoint $this.MountPoint
                            $Log.Success(("Auto unlock has been activated on {0}." -f $this.MountPoint))
                        }
                        catch {
                            $Log.Error(("An error occured while activating auto unlock on {0}: {1}." -f $this.MountPoint, $_.Exception.Message))                        
                        }
                    }
                }
                ([DiskType]::Removable) {
                    $Log.Info(("Start encryption process for the removable drive: {0}." -f $this.MountPoint))
                    $null = Enable-BitLocker -MountPoint $this.MountPoint -RecoveryPasswordProtector -SkipHardwareTest -Verbose:$false
                }
                Default {}
            }
        }
    }

    [void] BackupBitlockerKey() {
        $Log = [LogMessage]::NewLogs()
        [Microsoft.BitLocker.Structures.BitLockerVolume] $BLV = $null
        try {
            $BLV = Get-BitLockerVolume -MountPoint $this.MountPoint
        }
        catch {
            $Log.Error(("Unable to get a volume for {0}: {1}." -f $this.MountPoint, $_.Exception.Message))
        }
        $KeyProtectorID = ($BLV.KeyProtector | Where-Object { $_.KeyProtectorType -eq [Microsoft.BitLocker.Structures.BitLockerVolumeKeyProtectorType]::RecoveryPassword }).KeyProtectorID
        if ($KeyProtectorID) {
            try {
                $null = Backup-BitLockerKeyProtector -MountPoint $this.MountPoint -KeyProtectorId $KeyProtectorID -Verbose:$false
                $Log.Success(("Recovery Key for {0} has been saved on Active Directory." -f $this.MountPoint))
            }
            catch {
                $Log.Error(("Unable to backup recovery key for {0}: {1}." -f $this.MountPoint, $_.Exception.Message))
            }        
        }
    }
}

class HADOSDrive : HADDrive {
    [DiskType] $DiskType = [DiskType]::OS
    [bool] $PIN = $false

    HADOSDrive($Volume) : base($Volume) {
        $this.EnableBitLocker($null)        
        $this.BackupBitlockerKey()
    }

    HADOSDrive($Volume, [string] $CustomPIN) : base($Volume) {
        $this.PIN = $true
        $this.EnableBitLocker($CustomPIN)
        $this.BackupBitlockerKey()
    }
}

class HADFixedDrive : HADDrive {
    [DiskType] $DiskType = [DiskType]::Fixed

    HADFixedDrive($Volume) : base($Volume) {
        $this.EnableBitLocker($null)
        $this.BackupBitlockerKey()
    }
}

class HADRemovableDrive : HADDrive {
    [DiskType] $DiskType = [DiskType]::Removable

    HADRemovableDrive($Volume) : base($Volume) {
        $this.EnableBitlocker()
        $this.BackupBitlockerKey()
    }
}