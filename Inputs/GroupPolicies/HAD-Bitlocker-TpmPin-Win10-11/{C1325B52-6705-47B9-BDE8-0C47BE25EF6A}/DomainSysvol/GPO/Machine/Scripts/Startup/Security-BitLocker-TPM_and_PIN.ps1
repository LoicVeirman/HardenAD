################################################
# VARIABLES
################################################
$drives = Get-BitLockerVolume
$reg_hadbitlocker = "HKLM:\SOFTWARE\HADBitLocker"
$req_habitlocker_valuepin = "$reg_hadbitlocker\ValuePIN"
$req_habitlocker_status = "$reg_hadbitlocker\Status"
$hardenad_dir = "$env:SystemDrive\Windows\HardenAD"
$log_file = "$hardenad_dir\Logs\BitLockerLogs_Activation.txt"
$active_script_name = $MyInvocation.MyCommand.Name
$s_name = "HADBitlocker"
$s_bitlocker = Get-Service -Name $s_name -ErrorAction SilentlyContinue


################################################
# PRE-INSTALLATION
################################################
"[$(Get-Date)][$($active_script_name)] Start" | Out-File -Append -FilePath $log_file

if(!(Test-Path "$env:SystemDrive\Windows\Logs\BitLocker")){
    New-Item -Name "BitLocker" -Path "$env:SystemDrive\Windows\Logs" -itemType directory
}

if(!(Test-Path $reg_hadbitlocker)){
    New-Item -Path "HKLM:\SOFTWARE" -Name "HADBitLocker"
    New-Item -Path $reg_hadbitlocker -Name "ValuePIN"
    New-Item -Path $reg_hadbitlocker -Name "Status"

    $acl = Get-Acl $req_habitlocker_valuepin

    $authusers = $([System.Security.Principal.IdentityReference] $(New-Object System.Security.Principal.SecurityIdentifier S-1-5-11))
    $ace = New-Object System.Security.AccessControl.RegistryAccessRule($authusers,"FullControl","ContainerInherit","None","Allow")
    $acl.AddAccessRule($ace)
    $acl | Set-Acl -Path $req_habitlocker_valuepin
}

if($(Get-ItemProperty -Path $req_habitlocker_valuepin | Select-Object -ExpandProperty 'ValuePIN') -eq $null){
    New-ItemProperty -Path $req_habitlocker_valuepin -Name "ValuePIN" -Value "0000" -PropertyType ExpandString
    "[$(Get-Date)][$($active_script_name)] ValuePIN regedit creation" | Out-File -Append -FilePath $log_file
}

if($(Get-ItemProperty -Path $req_habitlocker_status | Select-Object -ExpandProperty 'Status') -eq $null){
    New-ItemProperty -Path $req_habitlocker_status -Name "Status" -Value "Initialized" -PropertyType ExpandString
    "[$(Get-Date)][$($active_script_name)] Status regedit creation" | Out-File -Append -FilePath $log_file
}elseif($(Get-ItemProperty -Path HKLM:\SOFTWARE\HADBitLocker\Status | Select-Object -ExpandProperty 'Status') -eq "FullyDecrypted" -and $(Get-ItemProperty -Path "HKLM:\SOFTWARE\HADBitLocker\ValuePIN" | Select-Object -ExpandProperty 'ValuePIN') -eq "9999"){
    Set-ItemProperty -Path HKLM:\SOFTWARE\HADBitLocker\Status -Name "Status" -Value "Initialized"
    Set-ItemProperty -Path HKLM:\SOFTWARE\HADBitLocker\ValuePIN -Name "ValuePIN" -Value "0000"
    "[$(Get-Date)][$($active_script_name)] Regedit keys initialized" | Out-File -Append -FilePath $log_file
}elseif($(Get-ItemProperty -Path $req_habitlocker_status | Select-Object -ExpandProperty 'Status') -eq "BitlockerActivated" -and $(Get-ItemProperty -Path $req_habitlocker_valuepin | Select-Object -ExpandProperty 'ValuePIN') -ne $null -and $(Get-ItemProperty -Path $req_habitlocker_valuepin | Select-Object -ExpandProperty 'ValuePIN') -ne "0000"){
    $status_bitlocker = (Get-BitLockerVolume -MountPoint "C:").VolumeStatus
    Set-ItemProperty -Path $req_habitlocker_status -Name "Status" -Value $status_bitlocker
    Set-ItemProperty -Path $req_habitlocker_valuepin -Name "ValuePIN" -Value "9999"
    "[$(Get-Date)][$($active_script_name)] Regedit keys updated" | Out-File -Append -FilePath $log_file
}elseif(($(Get-ItemProperty -Path $req_habitlocker_status | Select-Object -ExpandProperty 'Status') -eq "Initialized") -and ($(Get-ItemProperty -Path $req_habitlocker_valuepin | Select-Object -ExpandProperty 'ValuePIN') -ne "0000") -and ($(Get-ItemProperty -Path $req_habitlocker_valuepin | Select-Object -ExpandProperty 'ValuePIN') -ne "9999")){
    Set-ItemProperty -Path $req_habitlocker_status -Name "Status" -Value "PinCodeSetted"
    "[$(Get-Date)][$($active_script_name)] Status regedit updated to PinCodeSetted" | Out-File -Append -FilePath $log_file
}elseif(($(Get-ItemProperty -Path $req_habitlocker_status | Select-Object -ExpandProperty 'Status') -eq "Initialized") -or ($(Get-ItemProperty -Path $req_habitlocker_status | Select-Object -ExpandProperty 'Status') -eq "PinCodeSetted")){
    "[$(Get-Date)][$($active_script_name)] Regedit keys no changed" | Out-File -Append -FilePath $log_file
}else{
    $status_bitlocker = (Get-BitLockerVolume -MountPoint "$env:SystemDrive").VolumeStatus
    Set-ItemProperty -Path $req_habitlocker_status -Name "Status" -Value $status_bitlocker
    "[$(Get-Date)][$($active_script_name)] Status regedit updated " | Out-File -Append -FilePath $log_file
}

#Cr�ation du service
if ($service_bitlocker.Length -ieq 0) {
	$Error.Clear()
	try{
		sc.exe create $s_name start=auto binpath="$($hardenad_dir)\BitLocker-TPMandPIN\$($s_name).exe"
        Start-Sleep 2
        sc.exe start $s_name
        "[$(Get-Date)][$($active_script_name)] Service creation $($s_name): SUCCESS" | Out-File -Append -FilePath $log_file
	}
	catch{
		"[$(Get-Date)][$($active_script_name)] Get-service $($s_name): $($Error[0].Exception.Message)" | Out-File -Append -FilePath $log_file
	}
}else{
    $Error.Clear()
	try{
        sc.exe start $s_name
	    "[$(Get-Date)][$($active_script_name)] Start-service $($s_name): SUCCESS" | Out-File -Append -FilePath $log_file
    }catch{
        "[$(Get-Date)][$($active_script_name)] Start-service $($s_name): FAILED $($Error[0].Exception.Message)" | Out-File -Append -FilePath $log_file
    }

}


################################################
# INSTALLATION
################################################


    ######################
    # OS drive
    ######################
    $pincode = (Get-ItemProperty -Path $req_habitlocker_valuepin -Name "ValuePIN").ValuePIN
    $status = (Get-ItemProperty -Path $req_habitlocker_status -Name "Status").Status

    
    # check the volume status of all the drives
    if($pincode -ne "" -and $pincode -ne "9999" -and $pincode -ne "0000" -and $pincode.Length -ge 6 -and $pincode -match "^\d+$" -and $status -eq "PinCodeSetted"){
        "[$(Get-Date)][$($active_script_name)] Valid code PIN and status" | Out-File -Append -FilePath $log_file
        foreach($drive in $drives){
            #Check if drive are encrypted
            if($drive.VolumeStatus -eq "FullyEncrypted" -or $drive.ProtectionStatus -eq "On"){
                "[$(Get-Date)][$($active_script_name)] [$($drive.MountPoint)] Bitlocker already enabled on drive" | Out-File -Append -FilePath $log_file
                continue
            }
            else{
                "[$(Get-Date)][$($active_script_name)] [$($drive.MountPoint)] Bitlocker not enabled on drive" | Out-File -Append -FilePath $log_file

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
        
                #check if the drive is the operating system drive or a fixed data drive
                if ($drive.VolumeType -eq "OperatingSystem"){

                    "[$(Get-Date)][$($active_script_name)] [$($drive.MountPoint)] Drive is detected as the OperatingSystem" | Out-File -Append -FilePath $log_file

                    #Step 1 - Check if TPM is enabled and initialise if required
                    if ($WindowsVer -and !$TPMNotEnabled) 
                    {
                        try{
                            Initialize-Tpm -AllowClear -AllowPhysicalPresence -ErrorAction SilentlyContinue
                            "[$(Get-Date)][$($active_script_name)] [$($drive.MountPoint)] TPM not enabled and correctly initialized" | Out-File -Append -FilePath $log_file
                        }catch{
                            "[$(Get-Date)][$($active_script_name)] [$($drive.MountPoint)] Initialize TPM failed" | Out-File -Append -FilePath $log_file 
                            exit  
                        }
                    } else {
                        "[$(Get-Date)][$($active_script_name)] [$($drive.MountPoint)] TPM already enabled" | Out-File -Append -FilePath $log_file
                    }

                    #Step 2 - Check if BitLocker volume is provisioned and partition system drive for BitLocker if required
                    if ($WindowsVer -and $TPMEnabled -and !$BitLockerReadyDrive) 
                    {
                        $Error.Clear()
                        try{
                            Get-Service -Name defragsvc -ErrorAction Stop | Set-Service -Status Running -ErrorAction SilentlyContinue
                            BdeHdCfg -target $env:SystemDrive shrink -quiet
                            "[$(Get-Date)][$($active_script_name)] [$($drive.MountPoint)] BitLocker volume is provisioned" | Out-File -Append -FilePath $log_file
                        }
                        catch {
                            "[$(Get-Date)][$($active_script_name)] [$($drive.MountPoint)] Get-service defragsvc $($Error[0].Exception.Message)" | Out-File -Append -FilePath $log_file
                            exit
                        }
                    }
                    #Step 3 - init PIN
                    $PIN = ConvertTo-SecureString $pincode -AsPlainText -Force

                    #Step 4 - Create BitLocker recory key, Backup to AD, enable BitLocker
                    if ($WindowsVer -and $TPMEnabled -and $BitLockerReadyDrive -and $BitLockerDecrypted) {
                        $Error.Clear()
                        try{
                            Add-BitLockerKeyProtector -MountPoint $env:SystemDrive -Pin $PIN -TpmAndPinProtector -ErrorAction Stop
                            "[$(Get-Date)][$($active_script_name)] [$($drive.MountPoint)] Add Bitlocker Key Protector: SUCCESS" | Out-File -Append -FilePath $log_file
                        } catch {
                            "[$(Get-Date)][$($active_script_name)] [$($drive.MountPoint)] Add Bitlocker Key Protector: ERROR $($Error[0].Exception.Message)" | Out-File -Append -FilePath $log_file
                        }
                        $volumeStatus = Get-BitLockerVolume -MountPoint $drive.MountPoint
                        "[$(Get-Date)][$($active_script_name)] [$($drive.MountPoint)] Recheck value of Volume Status (Expected TpmPin): $($volumeStatus.VolumeStatus)" | Out-File -Append -FilePath $log_file
                        "[$(Get-Date)][$($active_script_name)] [$($drive.MountPoint)] Recheck value of Key Protector (Expected TpmPin): $($volumeStatus.KeyProtector)" | Out-File -Append -FilePath $log_file
        
                        $BLVS = (Get-BitLockerVolume -MountPoint $drive.MountPoint | Where-Object {$_.KeyProtector | Where-Object {$_.KeyProtectorType -eq 'TpmPin'}})
                        if ($BLVS) {
                            ForEach ($BLV in $BLVS) {
                                $Key = $BLV | Select-Object -ExpandProperty KeyProtector | Where-Object {$_.KeyProtectorType -eq 'TpmPin'}
                                ForEach ($obj in $Key){ 
                                    #Backup To AD
                                    $Error.Clear()
                                    try{
                                        Backup-BitLockerKeyProtector -MountPoint $BLV.MountPoint -KeyProtectorID $obj.KeyProtectorId
                                        "[$(Get-Date)][$($active_script_name)] [$($drive.MountPoint)] Backup BitLocker Key Protector: SUCCESS" | Out-File -Append -FilePath $log_file
                                    }
                                    catch {
                                        "[$(Get-Date)][$($active_script_name)] [$($drive.MountPoint)] Backup BitLocker Key Protector: ERROR $($Error[0].Exception.Message)" | Out-File -Append -FilePath $log_file
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
                                            "[$(Get-Date)][$($active_script_name)] [$($drive.MountPoint)] Backup To ADD BitLocker Key Protector: SUCCESS" | Out-File -Append -FilePath $log_file
                                        }
                                        catch {
                                            "[$(Get-Date)][$($active_script_name)] [$($drive.MountPoint)] Backup To ADD BitLocker Key Protector: ERROR $($Error[0].Exception.Message)" | Out-File -Append -FilePath $log_file
                                        } 
                                    } 
                                }
                            }
                            $Error.Clear()
                            try{
                                Enable-BitLocker -MountPoint $drive.MountPoint -RecoveryPasswordProtector -ErrorAction SilentlyContinue
                                Set-ItemProperty -Path $req_habitlocker_valuepin -Name "ValuePIN" -Value "9999"
                                Set-ItemProperty -Path $req_habitlocker_status -Name "Status" -Value BitlockerActivated
                                "[$(Get-Date)][$($active_script_name)] [$($drive.MountPoint)] Enable Bitlocker: SUCCESS" | Out-File -Append -FilePath $log_file
                            } catch {
                                "[$(Get-Date)][$($active_script_name)] [$($drive.MountPoint)] Enable Bitlocker: ERROR $($Error[0].Exception.Message)" | Out-File -Append -FilePath $log_file
                            }

                        } else {
                            "[$(Get-Date)][$($active_script_name)] [$($drive.MountPoint)] Key Protector Type not contains TpmPin" | Out-File -Append -FilePath $log_file
                        }
                    }
                }
                else {
                    "[$(Get-Date)][$($active_script_name)] [$($drive.MountPoint)] Drive is not Operating System" | Out-File -Append -FilePath $log_file
                }
            }
        }
    } else {
        "[$(Get-Date)][$($active_script_name)] Invalid code PIN and status. " | Out-File -Append -FilePath $log_file
    }


    ######################
    # Data drives
    ######################
    $systemDrive = Get-BitLockerVolume -MountPoint $env:SystemDrive 
    $WindowsVer = Get-WmiObject -Query 'select * from Win32_OperatingSystem where (Version like "6.2%" or Version like "6.3%" or Version like "10.0%") and ProductType = "1"' -ErrorAction SilentlyContinue
    $TPMNotEnabled = Get-WmiObject win32_tpm -Namespace root\cimv2\security\microsofttpm | Where-Object {$_.IsEnabled_InitialValue -eq $false} -ErrorAction SilentlyContinue
    $BitLockerReadyDrive = Get-BitLockerVolume -MountPoint $drive.MountPoint -ErrorAction SilentlyContinue
    foreach($drive in $drives){
        #Check if drive are encrypted
        #$type equal 2 if drive type is Removable
        if ($drive.VolumeType -eq "Data" -and $systemDrive.VolumeStatus -eq "FullyEncrypted" -and ($type -ne "2" )){
            "[$(Get-Date)][$($active_script_name)] [$($drive.MountPoint)] Drive is detected as Data but not removable" | Out-File -Append -FilePath $log_file

            #Step 1 - Check if TPM is enabled and initialise if required
            if ($WindowsVer -and !$TPMNotEnabled) 
            {
                Initialize-Tpm -AllowClear -AllowPhysicalPresence -ErrorAction SilentlyContinue
            }
            #Step 2 - Check if BitLocker volume is provisioned and partition system drive for BitLocker if required
            if ($WindowsVer -and $TPMEnabled -and !$BitLockerReadyDrive){
                $Error.Clear()
                try{
                    Get-Service -Name defragsvc -ErrorAction Stop | Set-Service -Status Running -ErrorAction SilentlyContinue
                    BdeHdCfg -target $drive.MountPoint shrink -quiet
                    "[$(Get-Date)][$($active_script_name)] [$($drive.MountPoint)] BitLocker volume is provisioned" | Out-File -Append -FilePath $log_file
                }
                catch {
                    "[$(Get-Date)][$($active_script_name)] [$($drive.MountPoint)] Get-service defragsvc $($Error[0].Exception.Message)" | Out-File -Append -FilePath $log_file
                }
            }
            $Error.Clear()
            try{
                Enable-BitLocker -MountPoint $drive.MountPoint -RecoveryPasswordProtector -ErrorAction SilentlyContinue
                Enable-BitLockerAutoUnlock -MountPoint $drive.MountPoint
                $f_del_reg_valuepin = $true
                "[$(Get-Date)][$($active_script_name)] [$($drive.MountPoint)] Enable Bitlocker for fixed data drives: SUCCESS" | Out-File -Append -FilePath $log_file
            }catch{
                "[$(Get-Date)][$($active_script_name)] [$($drive.MountPoint)] Enable Bitlocker for fixed data drives: ERROR $($Error[0].Exception.Message)" | Out-File -Append -FilePath $log_file
            }
        }
    }



"[$(Get-Date)][$($active_script_name)] End" | Out-File -Append -FilePath $log_file

