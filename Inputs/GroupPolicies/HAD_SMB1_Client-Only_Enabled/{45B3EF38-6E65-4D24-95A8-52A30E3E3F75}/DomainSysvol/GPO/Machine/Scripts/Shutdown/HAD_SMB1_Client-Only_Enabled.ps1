################################################
# FONCTIONS
################################################
function Check-HardenAD_directory(){
    if(!(Test-Path "$env:SystemDrive\Windows\HardenAD")){
        New-Item -Name "HardenAD" -Path "$env:SystemDrive\Windows\" -itemType directory

	    # Generate permissions
        $ace = ""
        $acl = ""
        $acl = New-Object System.Security.AccessControl.DirectorySecurity

        $localsystem = $([System.Security.Principal.IdentityReference] $(New-Object System.Security.Principal.SecurityIdentifier S-1-5-18))
        $ace = New-Object System.Security.AccessControl.FileSystemAccessRule($localsystem,"FullControl","ContainerInherit,ObjectInherit", "None","Allow")
        $acl.AddAccessRule($ace)

        $localadmin = $([System.Security.Principal.IdentityReference] $(New-Object System.Security.Principal.SecurityIdentifier S-1-5-32-544))
        $ace = ""
        $ace = New-Object System.Security.AccessControl.FileSystemAccessRule($localadmin,"FullControl","ContainerInherit,ObjectInherit", "None","Allow")
        $acl.AddAccessRule($ace)

        $authusers = $([System.Security.Principal.IdentityReference] $(New-Object System.Security.Principal.SecurityIdentifier S-1-5-11))
        $ace = New-Object System.Security.AccessControl.FileSystemAccessRule($authusers,"ReadAndExecute","ContainerInherit,ObjectInherit", "None","Allow")
        $acl.AddAccessRule($ace)

	    # Assign permissions
        $acl | Set-Acl "$env:SystemDrive\windows\HardenAD"

        #remove the default ace
        $ace = ""
        $ace = (get-acl "$env:SystemDrive\windows\HardenAD")
        $ace.SetAccessRuleProtection($true,$false)
        $ace.SetOwner($localadmin)
        $ace | Set-Acl -Path "$env:SystemDrive\Windows\HardenAD"

        if(!(Test-Path "$env:SystemDrive\Windows\HardenAD\Logs")){
            New-Item -Name "Logs" -Path "$env:SystemDrive\Windows\HardenAD\" -itemType directory
        }
    }
}

################################################
# VARIABLES
################################################
$hardenAD_path = "$env:SystemDrive\Windows\HardenAD"
$active_script_name = $MyInvocation.MyCommand.Name
$os = ((Get-WMIObject win32_operatingsystem) | Select Version).Version
$hardenAD_logs_path = "$env:SystemDrive\Windows\HardenAD\Logs\$($active_script_name).logs"

################################################
# PRE-INSTALLATION
################################################
Check-HardenAD_directory

################################################
# INSTALLATION
################################################
"[$(Get-Date)][$($active_script_name)] START" | Out-File -Append -FilePath $hardenAD_logs_path
    
#if os > windows 10 or windows 2012
if($os -ge "6.2"){
    #Activation SMB1 Windows Feature
    $smb1 = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol
    if($smb1.State -eq "Disabled"){
        $Error.Clear()
        try{
            Enable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -all
            "[$(Get-Date)][$($active_script_name)] SMB1 protocol not installed. Enable SMB1 protocol" | Out-File -Append -FilePath $hardenAD_logs_path
        }catch{
            "[$(Get-Date)][$($active_script_name)] SMB1 protocol not installed. Enable SMB1 protocol failed: $($Error[0])" | Out-File -Append -FilePath $hardenAD_logs_path
        }
    }elseif($smb1.State -eq "Enabled"){
        "[$(Get-Date)][$($active_script_name)] SMB1 protocol is already activated" | Out-File -Append -FilePath $hardenAD_logs_path
    }else{
        "[$(Get-Date)][$($active_script_name)] SMB1 protocol status is not expected" | Out-File -Append -FilePath $hardenAD_logs_path
    }

    #Desactivation SMB1 Server
    if ((Get-SmbServerConfiguration).EnableSMB1Protocol -ieq $true){
        $Error.Clear()
        try{
            Set-SmbServerConfiguration -EnableSMB1Protocol $false -Confirm:$false
            Set-SmbServerConfiguration -EnableSMB2Protocol $true -Confirm:$false
            "[$(Get-Date)][$($active_script_name)] Disable SMB1 server success" | Out-File -Append -FilePath $hardenAD_logs_path
        }catch{
            "[$(Get-Date)][$($active_script_name)] Disable SMB1 server failed: $($Error[0])" | Out-File -Append -FilePath $hardenAD_logs_path
        }
    }else{
        "[$(Get-Date)][$($active_script_name)] SMB1 server already disabled" | Out-File -Append -FilePath $hardenAD_logs_path
    }
} elseif($os -lt "6.2") {
    "[$(Get-Date)][$($active_script_name)] -lt 6.2 " | Out-File -Append -FilePath $hardenAD_logs_path
    $Error.Clear()
    try{
        Set-ItemProperty -Name SMB1 -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Type DWORD -Value 0 -Force
        Set-ItemProperty -Name SMB2 -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Type DWORD -Value 1 -Force
        "[$(Get-Date)][$($active_script_name)] Disable SMB1 server protocol: SUCCESS " | Out-File -Append -FilePath $hardenAD_logs_path
    }catch{
        "[$(Get-Date)][$($active_script_name)] Disable SMB1 server protocol: FAILED $($Error[0])" | Out-File -Append -FilePath $hardenAD_logs_path
    }
}else{
    "[$(Get-Date)][$($active_script_name)] OS not expected" | Out-File -Append -FilePath $hardenAD_logs_path
}

$Error.Clear()
try{
    sc.exe config lanmanworkstation depend= bowser/mrxsmb10/mrxsmb20/nsi
    sc.exe config mrxsmb10 start= auto
    sc.exe config mrxsmb20 start= auto
    if($LastExitCode -eq 0){
        "[$(Get-Date)][$($active_script_name)] SMB1 client activated" | Out-File -Append -FilePath $hardenAD_logs_path
    }else{
        "[$(Get-Date)][$($active_script_name)] Enable SMB1 client failed with exitcode $($LastExitCode): $($Error[0])" | Out-File -Append -FilePath $hardenAD_logs_path
    }    
}catch{
    "[$(Get-Date)][$($active_script_name)] Enable SMB1 client failed: $($Error[0])" | Out-File -Append -FilePath $hardenAD_logs_path
}


"[$(Get-Date)][$($active_script_name)] END" | Out-File -Append -FilePath $hardenAD_logs_path
