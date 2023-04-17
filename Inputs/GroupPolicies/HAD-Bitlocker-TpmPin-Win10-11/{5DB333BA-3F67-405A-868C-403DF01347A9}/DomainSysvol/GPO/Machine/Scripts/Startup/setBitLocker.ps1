################################################
# FONCTIONS
################################################
function Get-Connectivity{
    $res = $false
    $domain_fqdn = (Get-WmiObject -Namespace root\cimv2 -Class Win32_ComputerSystem).Domain
    try{
        $res = Test-ComputerSecureChannel -Server $domain_fqdn
    }
    catch{
        $res = $false
    }
    return $res
}

################################################
# VARIABLES
################################################
$ErrorActionPreference = ‘Continue’
$reg_hadbitlocker = "HKLM:\SOFTWARE\HADBitLocker"
$req_habitlocker_valuepin = "$reg_hadbitlocker\ValuePIN"
$req_habitlocker_status = "$reg_hadbitlocker\Status"
$log_file = "$env:USERPROFILE\AppData\Local\Temp\HadBitLockerLogs.txt"
$status = (Get-ItemProperty -Path $req_habitlocker_status -Name "Status").status
$pincode = (Get-ItemProperty -Path $req_habitlocker_valuepin -Name "ValuePIN").ValuePIN
$hardenad_dir = "$env:SystemDrive\Windows\HardenAD"
$active_script_name = $MyInvocation.MyCommand.Name
$s_name = "HADBitlocker"
$s_status = (Get-Service -Name $s_name).Status

################################################
# INSTALLATION
################################################

if($status -eq "Initialized" -and $pincode -eq "0000" -and $s_status -eq "Running"){

    "[$(Get-Date)][$($active_script_name)] START" | Out-File -Append -FilePath $log_file
    while($status -eq "Initialized"){
        
        Add-Type -AssemblyName System.Windows.Forms
        Add-Type -AssemblyName System.Drawing
    
        $form = ""
        $form = New-Object System.Windows.Forms.Form
        $form.Text = 'Chiffrement de votre poste'
        $form.Size = New-Object System.Drawing.Size(400,350)
        $form.StartPosition = 'CenterScreen'

        $okButton = ""
        $okButton = New-Object System.Windows.Forms.Button
        $okButton.Location = New-Object System.Drawing.Point(110,250)
        $okButton.Size = New-Object System.Drawing.Size(75,23)
        $okButton.Text = 'OK'
        $okButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
        $form.AcceptButton = $okButton
        $form.Controls.Add($okButton)

        $cancelButton = ""
        $cancelButton = New-Object System.Windows.Forms.Button
        $cancelButton.Location = New-Object System.Drawing.Point(190,250)
        $cancelButton.Size = New-Object System.Drawing.Size(75,23)
        $cancelButton.Text = 'Cancel'
        $cancelButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
        $form.CancelButton = $cancelButton
        $form.Controls.Add($cancelButton)

        $label = ""
        $label = New-Object System.Windows.Forms.Label
        $label.Location = New-Object System.Drawing.Point(10,20)
        $label.Size = New-Object System.Drawing.Size(380,100)
        $label.Text = "Pour des raisons de sécurité, votre poste de travail va être chiffré.`nDe ce fait, vous allez devoir choisir un code PIN d'au moins 6 caractères.`nCe code PIN vous sera demandé (après plusieurs redémarrages) à l'allumage de votre poste.`nVotre code PIN ne peut contenir que les chiffres de 0 à 9.`nVotre poste redémarrera automatiquement après le renseignement du code PIN, veuillez sauvegarder vos données avant de confirmer votre code PIN."
        $form.Controls.Add($label)

        $label = ""
        $label = New-Object System.Windows.Forms.Label
        $label.Location = New-Object System.Drawing.Point(10,130)
        $label.Size = New-Object System.Drawing.Size(380,20)
        $label.Text = 'Code PIN:'
        $form.Controls.Add($label)

        $textBox_init = ""
        $textBox_init = New-Object System.Windows.Forms.MaskedTextBox
        $textBox_init.Location = New-Object System.Drawing.Point(10,150)
        $textBox_init.Size = New-Object System.Drawing.Size(360,20)
        $textBox_init.PasswordChar = '*'
        $form.Controls.Add($textBox_init)

        $label = ""
        $label = New-Object System.Windows.Forms.Label
        $label.Location = New-Object System.Drawing.Point(10,180)
        $label.Size = New-Object System.Drawing.Size(380,20)
        $label.Text = 'Confirmation code PIN:'
        $form.Controls.Add($label)

        $textBox_confirm =""
        $textBox_confirm = New-Object System.Windows.Forms.MaskedTextBox
        $textBox_confirm.Location = New-Object System.Drawing.Point(10,200)
        $textBox_confirm.Size = New-Object System.Drawing.Size(360,20)
        $textBox_confirm.PasswordChar = '*'
        $form.Controls.Add($textBox_confirm)

        $form.Topmost = $true

        $form.Add_Shown({$textBox_init.Select()})
        $form.Add_Shown({$textBox_confirm.Select()})
        $result = $form.ShowDialog()
        $s_status = (Get-Service -Name $s_name).Status

        if($result -eq [System.Windows.Forms.DialogResult]::OK)
        {
            $codepin1 = ""
            $codepin2 = ""
            $codepin1 = $textBox_init.Text
            $codepin2 = $textBox_confirm.Text

            if($codepin1 -eq $codepin2 -and $codepin1 -ne "" -and $codepin1 -ne "9999" -and $codepin1 -ne "0000" -and $codepin1.Length -ge 6 -and $codepin1 -match "^\d+$" -and $(Get-Connectivity) -and $s_status -eq "Running"){
                Set-ItemProperty -Path $req_habitlocker_valuepin -Name "ValuePIN" -Value $codepin1

                $valuePIN = (Get-ItemProperty -Path $req_habitlocker_valuepin -Name "ValuePIN").ValuePIN
                if($valuePIN -eq $codepin1){
                    "[$(Get-Date)][$($active_script_name)] Code PIN setted valid" | Out-File -Append -FilePath $log_file
                    "[$(Get-Date)][$($active_script_name)] END" | Out-File -Append -FilePath $log_file
                    exit
                    <#try{
                        "[$(Get-Date)][$($active_script_name)] Restarting computer" | Out-File -Append -FilePath $log_file
                        Restart-Computer
                    }catch{
                        "[$(Get-Date)][$($active_script_name)] Restarting computer failed" | Out-File -Append -FilePath $log_file
                    }#>
                }else{
                    "[$(Get-Date)][$($active_script_name)] Code PIN setted but not conform" | Out-File -Append -FilePath $log_file
                    Add-Type -AssemblyName PresentationFramework
                    $msgBoxInput = [System.Windows.MessageBox]::Show("Votre code PIN est inférieur à 6 caractères ou votre code PIN ne contient pas uniquement des chiffres entre 0 et 9.`nVeuillez renseigner un code PIN valide.","Attention !",'OK','Error')
                }
            }elseif($s_status -ne "Running"){
                "[$(Get-Date)][$($active_script_name)] Le service HADBLO02 n'est pas démarré" | Out-File -Append -FilePath $log_file
                Add-Type -AssemblyName PresentationFramework
                $msgBoxInput = [System.Windows.MessageBox]::Show("Une erreur est survenue.`nLe service HADBLO02 n'est pas démarré.`nVeuillez redémarrer votre poste pour réessayer.","Attention !",'OK','Error')
                "[$(Get-Date)][$($active_script_name)] END" | Out-File -Append -FilePath $log_file
                exit
            }elseif(!$(Get-Connectivity)){
                "[$(Get-Date)][$($active_script_name)] Le poste n'est pas connecté au domaine. Veuillez le reconnecter et reessayer." | Out-File -Append -FilePath $log_file
                Add-Type -AssemblyName PresentationFramework
                $msgBoxInput = [System.Windows.MessageBox]::Show("Le poste de travail n'est pas connecté au domaine`nVeuillez vérifier votre connexion VPN si vous êtes à distance.","Attention !",'OK','Error')
            }else{
                "[$(Get-Date)][$($active_script_name)] Votre code PIN ne correspond pas ou est nul. Veuillez renseigner un code PIN valide." | Out-File -Append -FilePath $log_file
                Add-Type -AssemblyName PresentationFramework
                $msgBoxInput = [System.Windows.MessageBox]::Show("Les code PIN renseignés ne sont pas identiques ou sont nuls`nVeuillez renseigner un code PIN valide.","Attention !",'OK','Error')
            }

        }elseif($result -eq [System.Windows.Forms.DialogResult]::Cancel){
            Add-Type -AssemblyName PresentationFramework
            $msgBoxInput = [System.Windows.MessageBox]::Show("Vous ne pouvez pas annuler le chiffrement du poste.`nVeuillez renseigner un code PIN afin d'activer le chiffrement du poste,","Attention !")
        }
        $status = (Get-ItemProperty -Path $req_habitlocker_status -Name "Status").status
    }

    #Enable X Button
    [Win32.NativeMethods]::EnableMenuItem($hMenu, $SC_CLOSE, $MF_ENABLED) | Out-Null
    [Win32.NativeMethods]::EnableWindow($hwnd, 1) | Out-Null
 
    "[$(Get-Date)][$($active_script_name)] END" | Out-File -Append -FilePath $log_file

}