using module BitLocker

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

        [bool] $isSystemSupported = ([System.Environment]::OSVersion.Version -ge ([System.Version] "6.2.9200"))
        [bool] $isSystemAWorkstation = ((Get-WmiObject -Class Win32_OperatingSystem | Where-Object { $_.PSComputerName -eq $env:COMPUTERNAME }).ProductType -eq 1)
        [bool] $isVolumeInitializedForProtection = (Get-WmiObject -Class Win32_EncryptableVolume -Namespace 'root\cimv2\Security\MicrosoftVolumeEncryption' -Filter "DriveLetter=`"$($this.MountPoint)`"").IsVolumeInitializedForProtection

        if ($isSystemSupported -and $isSystemAWorkstation -and !$isVolumeInitializedForProtection) {
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

    [void] EnableBitLocker([string] $PIN) {
        if ($this.ValidVersion -and $this.TPMReady) {
            switch ($this.DiskType) {
                ([DiskType]::OS) {
                    Enable-BitLocker -MountPoint $this.MountPoint -RecoveryPasswordProtector -SkipHardwareTest -Verbose:$false

                    if ($this.PIN) {
                        $SecurePin = ConvertTo-SecureString -AsPlainText $PIN -Force
                        Add-BitLockerKeyProtector -MountPoint $this.MountPoint -Pin $SecurePin -TpmAndPinProtector -Verbose:$false
                    }
                }
                ([DiskType]::Fixed) {
                    Enable-BitLocker -MountPoint $this.MountPoint -RecoveryPasswordProtector -SkipHardwareTest -Verbose:$false
                    Enable-BitLockerAutoUnlock -MountPoint $this.MountPoint            
                }
                ([DiskType]::Removable) {
                    Enable-BitLocker -MountPoint $this.MountPoint -RecoveryPasswordProtector -SkipHardwareTest -Verbose:$false
                }
                Default {}
            }
            Add-BitLockerKeyProtector -MountPoint $this.MountPoint -RecoveryPasswordProtector -Verbose:$false
        }
    }

    [void] BackupBitlockerKey($Volume) {
        $RecoveryPasswordProtector = $Volume.KeyProtector | Where-Object { $_.KeyProtectorId -eq [Microsoft.BitLocker.Structures.BitLockerVolumeKeyProtectorType]::RecoveryPassword }
        Backup-BitLockerKeyProtector -MountPoint $this.MountPoint -KeyProtectorId $RecoveryPasswordProtector -Verbose:$false
    }
}

class HADOSDrive : HADDrive {
    [DiskType] $DiskType = [DiskType]::OS
    [bool] $PIN = $false

    HADOSDrive($Volume) : base($Volume) {
        $this.EnableBitLocker($null)        
        $this.BackupBitlockerKey($Volume)
    }

    HADOSDrive($Volume, [string] $PIN) : base($Volume) {
        $this.PIN = $true
        $this.EnableBitLocker($PIN)
        $this.BackupBitlockerKey($Volume)
    }
}

class HADFixedDrive : HADDrive {
    [DiskType] $DiskType = [DiskType]::Fixed

    HADFixedDrive($Volume) : base($Volume) {
        $this.EnableBitLocker($null)
        $this.BackupBitlockerKey($Volume)
    }
}

class HADRemovableDrive : HADDrive {
    [DiskType] $DiskType = [DiskType]::Removable

    HADRemovableDrive($Volume) : base($Volume) {
        $this.EnableBitlocker()
        $this.BackupBitlockerKey($Volume)
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
        if (($Global:Array | Where-Object { $_.DriveLetter -eq $this.MountPoint }).BusType -eq "USB") {
            return [System.IO.DriveType]::Removable
        }
        else {
            return [System.IO.DriveType]::Fixed
        }
    }
}

function Get-PIN {

    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    Add-Type -Name Window -Namespace Console -MemberDefinition '
    [DllImport("Kernel32.dll")]
    public static extern IntPtr GetConsoleWindow();
    
    [DllImport("user32.dll")]
    public static extern bool ShowWindow(IntPtr hWnd, Int32 nCmdShow);
    '

    $ConsolePtr = [Console.Window]::GetConsoleWindow()
    [Console.Window]::ShowWindow($ConsolePtr, 0)

    Start-Sleep 3

    $Form = [System.Windows.Forms.Form]::new()
    $Form.Text = "  Bitlocker Encryption - PIN Selection"
    $Form.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterScreen
    $Form.MaximizeBox = $false
    $Form.MinimizeBox = $false
    $Form.ControlBox = $false
    $Form.Size = [System.Drawing.Size]::new(400, 380)
    $Form.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
    $Form.TopMost = $true

    $RulesLabel = [System.Windows.Forms.Label]::new()
    $RulesLabel.Location = [System.Drawing.Point]::new(20, 20)
    $RulesLabel.Size = [System.Drawing.Size]::new(360, 100)
    $RulesLabel.Text = "In line with your company's security policy, your disk will be encrypted and protected by a PIN code.
You will be asked for this PIN code when you start up your workstation. 
    
Please choose your PIN code, which must meet the following requirements:"

    $ComplexityLabel = [System.Windows.Forms.Label]::new()
    $ComplexityLabel.Location = [System.Drawing.Point]::new(40, 120)
    $ComplexityLabel.Size = [System.Drawing.Size]::new(360, 50)
    $ComplexityLabel.Text = "- 6 digits minimum
- Do not use the same number 6 times"

    $PinLabel = [System.Windows.Forms.Label]::new()
    $PinLabel.Location = [System.Drawing.Point]::new(20, 180)
    $PinLabel.Size = [System.Drawing.Size]::new(360, 20)
    $PinLabel.Text = "PIN : "

    $PinInit = [System.Windows.Forms.MaskedTextBox]::new() 
    $PinInit.Location = [System.Drawing.Point]::new(20, 200)
    $PinInit.Size = [System.Drawing.Size]::new(360, 20)
    $PinInit.PasswordChar = "*"

    $ConfirmedPinLabel = [System.Windows.Forms.Label]::new()
    $ConfirmedPinLabel.Location = [System.Drawing.Point]::new(20, 230)
    $ConfirmedPinLabel.Size = [System.Drawing.Size]::new(360, 20)
    $ConfirmedPinLabel.Text = "Confirm PIN : "

    $PinConfirm = [System.Windows.Forms.MaskedTextBox]::new() 
    $PinConfirm.Location = [System.Drawing.Point]::new(20, 250)
    $PinConfirm.Size = [System.Drawing.Size]::new(360, 20)
    $PinConfirm.PasswordChar = "*"

    $SubmitButton = [System.Windows.Forms.Button]::new()
    $SubmitButton.Width = 80
    $SubmitButton.Height = 40
    $SubmitButton.Location = [System.Drawing.Point]::new((($Form.Width - $SubmitButton.Width) / 2), 280)
    $SubmitButton.Text = "Submit"

    $Form.AcceptButton = $SubmitButton
    
    $ConfirmationStatus = [System.Windows.Forms.StatusBar]::new()

    $Form.Controls.Add($RulesLabel)
    $Form.Controls.Add($ComplexityLabel)
    $Form.Controls.Add($PinLabel)
    $Form.Controls.Add($ConfirmedPinLabel)
    $Form.Controls.Add($PinInit)
    $Form.Controls.Add($PinConfirm)
    $Form.Controls.Add($SubmitButton)
    $Form.Controls.Add($ConfirmationStatus)

    $Form.Add_Shown({ $PinInit.Select() })
    
    $SubmitButton.Add_Click(
        {
            if ($PinInit.Text -ne $PinConfirm.Text) {
                $ConfirmationStatus.Text = "PIN mismatch."
                $PinInit.Text = ""
                $PinConfirm.Text = ""
            }
            elseif ($PinConfirm.Text -notmatch "^(\d){6,}$") {
                $ConfirmationStatus.Text = "PIN need to contains at least 6 digits."
                $PinInit.Text = ""
                $PinConfirm.Text = ""
            }
            elseif ($PinConfirm.Text -match "(\d)\1{$($PinConfirm.Text.Length -1)}$") {
                $ConfirmationStatus.Text = "PIN cannot be composed of the same 6 digits."
                $PinInit.Text = ""
                $PinConfirm.Text = ""
            }
            elseif ($PinConfirm.Text -in @("123456",
                    "1234567",
                    "12345678",
                    "123456789",
                    "1234567890",
                    "12341234")
            ) {
                $ConfirmationStatus.Text = "$($PinConfirm.Text) is not a valid PIN."
                $PinInit.Text = ""
                $PinConfirm.Text = ""
            }
            else {
                $ConfirmationStatus.Text = "Correct PIN"
                $Form.DialogResult = [System.Windows.Forms.DialogResult]::OK
                $Form.Close()
            }
        }
    )    
    if ($Form.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        return $PinConfirm.Text
    }
}

Get-DiskLetterAndType

$BLVolumes = Get-BitLockerVolume | Where-Object { $_.VolumeStatus -eq "FullyDecrypted" }

foreach ($Volume in $BLVolumes) {
    switch (Get-DriveType $Volume) {
        ([Microsoft.BitLocker.Structures.BitLockerVolumeType]::OperatingSystem) {
            if ($OS) {
                if ($PIN) {
                    $Pin = Get-PIN
                    [HADOSDrive]::new($Volume, $PinCode)
                }
                else {
                    [HADOSDrive]::new($Volume)
                }
            }
        }
        ([System.IO.DriveType]::Fixed) {
            if ($Fixed) {
                [HADFixedDrive]::new($Volume)
            }
        }
        ([System.IO.DriveType]::Removable) {
            if ($USB) {
                [HADRemovableDrive]::new($Volume)
            }
        }
        Default {}
    }
}


### TODO : launch FVENotify.exe