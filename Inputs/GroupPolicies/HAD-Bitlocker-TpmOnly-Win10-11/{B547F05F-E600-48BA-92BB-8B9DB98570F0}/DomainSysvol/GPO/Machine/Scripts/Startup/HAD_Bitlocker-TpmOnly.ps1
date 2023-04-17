################################################
# VARIABLES
################################################
$drives = Get-BitLockerVolume
$hardenad_dir = "$env:SystemDrive\Windows\HardenAD"
$log_file = "$hardenad_dir\Logs\BitLockerLogs.txt"
$active_script_name = $MyInvocation.MyCommand.Name



################################################
# INSTALLATION
################################################
# check the volume status of all the drives
"[$(Get-Date)][$($active_script_name)] START" | Out-File -Append -FilePath $log_file

foreach($drive in $drives){
    "[$(Get-Date)][$($active_script_name)][$($drive.MountPoint)] Init" | Out-File -Append -FilePath $log_file
    #Check if drive are encrypted
    if($drive.VolumeStatus -eq "FullyEncrypted" -or $drive.ProtectionStatus -eq "On"){
        "[$(Get-Date)][$($active_script_name)][$($drive.MountPoint)] State: FullyEncrypted" | Out-File -Append -FilePath $log_file
        "[$(Get-Date)][$($active_script_name)][$($drive.MountPoint)] End" | Out-File -Append -FilePath $log_file
        continue
    }
    else{
        "[$(Get-Date)][$($active_script_name)][$($drive.MountPoint)] State: $($drive.VolumeStatus)" | Out-File -Append -FilePath $log_file

        #system drive encryption state
        $systemDrive = Get-BitLockerVolume -MountPoint $env:SystemDrive

        #check disk type >> for exclude USB drive (USB drive if $type equal 2)
        $type = Get-WmiObject Win32_Volume -Filter "DriveLetter='$($drive.MountPoint)'"
        $type = $type.DriveType

        #check bitLocker prerequisites
        $TPMNotEnabled = Get-WmiObject win32_tpm -Namespace root\cimv2\security\microsofttpm | Where-Object {$_.IsEnabled_InitialValue -eq $false} -ErrorAction SilentlyContinue
        $TPMEnabled = Get-WmiObject win32_tpm -Namespace root\cimv2\security\microsofttpm | Where-Object {$_.IsEnabled_InitialValue -eq $true} -ErrorAction SilentlyContinue
        $WindowsVer = Get-WmiObject -Query 'select * from Win32_OperatingSystem where (Version like "6.2%" or Version like "6.3%" or Version like "10.0%") and ProductType = "1"' -ErrorAction SilentlyContinue
        $BitLockerReadyDrive = Get-BitLockerVolume -MountPoint $drive.MountPoint -ErrorAction SilentlyContinue
        $BitLockerDecrypted = Get-BitLockerVolume -MountPoint $drive.MountPoint | Where-Object {$_.VolumeStatus -eq "FullyDecrypted"} -ErrorAction SilentlyContinue


        if($drive.VolumeType -eq "OperatingSystem"){
            "[$(Get-Date)][$($active_script_name)][$($drive.MountPoint)] Type: $($drive.VolumeType)" | Out-File -Append -FilePath $log_file

            #Step 1 - Check if TPM is enabled and initialise if required
            if ($WindowsVer -and !$TPMNotEnabled) {
                $Error.Clear()
                try{
                    Initialize-Tpm -AllowClear -AllowPhysicalPresence -ErrorAction Stop
                    "[$(Get-Date)][$($active_script_name)][$($drive.MountPoint)] TPM not enabled and correctly initialized" | Out-File -Append -FilePath $log_file
                }catch{
                    "[$(Get-Date)][$($active_script_name)][$($drive.MountPoint)] TPM activation failed: $($Error)" | Out-File -Append -FilePath $log_file 
                    exit  
                }
            } else {
                "[$(Get-Date)][$($active_script_name)][$($drive.MountPoint)] TPM already enabled" | Out-File -Append -FilePath $log_file
            }

            #Step 2 - Check if BitLocker volume is provisioned and partition system drive for BitLocker if required
            if ($WindowsVer -and $TPMEnabled -and !$BitLockerReadyDrive) {
                $Error.Clear()
                try{
                    Get-Service -Name defragsvc -ErrorAction Stop | Set-Service -Status Running -ErrorAction SilentlyContinue
                    BdeHdCfg -target $env:SystemDrive shrink -quiet
                    "[$(Get-Date)][$($active_script_name)][$($drive.MountPoint)] BitLocker volume is provisioned" | Out-File -Append -FilePath $log_file
                }
                catch {
                    "[$(Get-Date)][$($active_script_name)][$($drive.MountPoint)] Get-service defragsvc $($Error[0].Exception.Message)" | Out-File -Append -FilePath $log_file
                    exit
                }
            } else {
                "[$(Get-Date)][$($active_script_name)][$($drive.MountPoint)] Bitlocker volume already provisionned" | Out-File -Append -FilePath $log_file
            }

            #Step 3 - Create BitLocker recory key, Backup to AD, enable BitLocker
            if ($WindowsVer -and $TPMEnabled -and $BitLockerReadyDrive -and $BitLockerDecrypted) 
            {
                $Error.Clear()
                try{
                    Add-BitLockerKeyProtector -MountPoint $env:SystemDrive -TpmProtector -ErrorAction Stop
                    "[$(Get-Date)][$($active_script_name)][$($drive.MountPoint)] Add Bitlocker Key Protector: SUCCESS" | Out-File -Append -FilePath $log_file
                } catch {
                    "[$(Get-Date)][$($active_script_name)][$($drive.MountPoint)] Add Bitlocker Key Protector: ERROR $($Error[0].Exception.Message)" | Out-File -Append -FilePath $log_file
                }

                $volumeStatus = Get-BitLockerVolume -MountPoint $drive.MountPoint
                "[$(Get-Date)][$($active_script_name)][$($drive.MountPoint)] Recheck value of Volume Status (Expected TpmPin): $($volumeStatus.VolumeStatus)" | Out-File -Append -FilePath $log_file
                "[$(Get-Date)][$($active_script_name)][$($drive.MountPoint)] Recheck value of Key Protector (Expected TpmPin): $($volumeStatus.KeyProtector)" | Out-File -Append -FilePath $log_file

                $BLVS = (Get-BitLockerVolume -MountPoint $drive.MountPoint | Where-Object {$_.KeyProtector | Where-Object {$_.KeyProtectorType -eq 'Tpm'}})     
                if ($BLVS) {
                    ForEach ($BLV in $BLVS) {
                        $Key = $BLV | Select-Object -ExpandProperty KeyProtector | Where-Object {$_.KeyProtectorType -eq 'Tpm'}
                        ForEach ($obj in $Key){ 
                            #Backup To AD
                            $Error.Clear()
                            try{
                                $obj.KeyProtectorId
                                Backup-BitLockerKeyProtector -MountPoint $BLV.MountPoint -KeyProtectorID $obj.KeyProtectorId
                                "[$(Get-Date)][$($active_script_name)][$($drive.MountPoint)] Backup BitLocker Key Protector: SUCCESS" | Out-File -Append -FilePath $log_file
                            }
                            catch {
                                "[$(Get-Date)][$($active_script_name)][$($drive.MountPoint)] Backup BitLocker Key Protector: ERROR $($Error[0].Exception.Message)" | Out-File -Append -FilePath $log_file
                            }


                            #check device is joined to AAD
                            $subKey = Get-Item "HKLM:/SYSTEM/CurrentControlSet/Control/CloudDomainJoin/JoinInfo"

                            $guids = $subKey.GetSubKeyNames()
                            foreach($guid in $guids) {
                                $guidSubKey = $subKey.OpenSubKey($guid);
                                $tenantId = $guidSubKey.GetValue("TenantId");
                                $userEmail = $guidSubKey.GetValue("UserEmail");
                            }

                            if($tenantId){
                                #Backup To AAD
                                $Error.Clear()
                                try{
                                    BackupToAAD-BitLockerKeyProtector -MountPoint $BLV.MountPoint -KeyProtectorID $obj.KeyProtectorId
                                    "[$(Get-Date)][$($active_script_name)][$($drive.MountPoint)] Backup To ADD BitLocker Key Protector: SUCCESS" | Out-File -Append -FilePath $log_file
                                }
                                catch {
                                    "[$(Get-Date)][$($active_script_name)][$($drive.MountPoint)] Backup To ADD BitLocker Key Protector: ERROR $($Error[0].Exception.Message)" | Out-File -Append -FilePath $log_file
                                } 
                            } 
                        }
                    }
                    $Error.Clear()
                    try{
                        Enable-BitLocker -MountPoint $drive.MountPoint -RecoveryPasswordProtector -ErrorAction SilentlyContinue 
                        "[$(Get-Date)][$($active_script_name)][$($drive.MountPoint)] Enable Bitlocker: SUCCESS" | Out-File -Append -FilePath $log_file
                    } catch {
                        "[$(Get-Date)][$($active_script_name)][$($drive.MountPoint)] Enable Bitlocker: ERROR $($Error[0].Exception.Message)" | Out-File -Append -FilePath $log_file
                    }
                } else {
                    "[$(Get-Date)][$($active_script_name)][$($drive.MountPoint)] Key Protector Type not contains TpmPin" | Out-File -Append -FilePath $log_file
                }
            }
        } else {
            "[$(Get-Date)][$($active_script_name)][$($drive.MountPoint)] Drive is not Operating System" | Out-File -Append -FilePath $log_file
        }
    }
}

######################
# Data drives
######################
$drives = Get-BitLockerVolume
$systemDrive = Get-BitLockerVolume -MountPoint $env:SystemDrive 
$WindowsVer = Get-WmiObject -Query 'select * from Win32_OperatingSystem where (Version like "6.2%" or Version like "6.3%" or Version like "10.0%") and ProductType = "1"' -ErrorAction SilentlyContinue
$TPMNotEnabled = Get-WmiObject win32_tpm -Namespace root\cimv2\security\microsofttpm | Where-Object {$_.IsEnabled_InitialValue -eq $false} -ErrorAction SilentlyContinue
$BitLockerReadyDrive = Get-BitLockerVolume -MountPoint $drive.MountPoint -ErrorAction SilentlyContinue
foreach($drive in $drives){
    #Check if drive are encrypted
    #$type equal 2 if drive type is Removable
    if ($drive.VolumeType -eq "Data" -and $systemDrive.VolumeStatus -eq "FullyEncrypted" -and ($type -ne "2" )){
        "[$(Get-Date)][$($active_script_name)][$($drive.MountPoint)] Drive is detected as Data but not removable" | Out-File -Append -FilePath $log_file

        #Step 1 - Check if TPM is enabled and initialise if required
        if ($WindowsVer -and !$TPMNotEnabled) 
        {
            $Error.Clear()
            try{
                Initialize-Tpm -AllowClear -AllowPhysicalPresence -ErrorAction Stop
                "[$(Get-Date)][$($active_script_name)][$($drive.MountPoint)] TPM not enabled and correctly initialized" | Out-File -Append -FilePath $log_file
            }catch{
                "[$(Get-Date)][$($active_script_name)][$($drive.MountPoint)] TPM activation failed" | Out-File -Append -FilePath $log_file 
                exit  
            }
        }
        #Step 2 - Check if BitLocker volume is provisioned and partition system drive for BitLocker if required
        if ($WindowsVer -and $TPMEnabled -and !$BitLockerReadyDrive){
            $Error.Clear()
            try{
                Get-Service -Name defragsvc -ErrorAction Stop | Set-Service -Status Running -ErrorAction SilentlyContinue
                BdeHdCfg -target $drive.MountPoint shrink -quiet
                "[$(Get-Date)][$($active_script_name)][$($drive.MountPoint)] BitLocker volume is provisioned" | Out-File -Append -FilePath $log_file
            }
            catch {
                "[$(Get-Date)][$($active_script_name)][$($drive.MountPoint)] Get-service defragsvc $($Error[0].Exception.Message)" | Out-File -Append -FilePath $log_file
            }
        }
        $Error.Clear()
        try{
            Enable-BitLocker -MountPoint $drive.MountPoint -RecoveryPasswordProtector -ErrorAction Stop
            Enable-BitLockerAutoUnlock -MountPoint $drive.MountPoint
            "[$(Get-Date)][$($active_script_name)][$($drive.MountPoint)] Enable Bitlocker for fixed data drives: SUCCESS" | Out-File -Append -FilePath $log_file
        }catch{
            "[$(Get-Date)][$($active_script_name)][$($drive.MountPoint)] Enable Bitlocker for fixed data drives: ERROR $($Error[0].Exception.Message)" | Out-File -Append -FilePath $log_file
        }
    }
}

"[$(Get-Date)][$($active_script_name)] END" | Out-File -Append -FilePath $log_file