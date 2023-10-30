using module ..\Classes\Logger.psm1
function Get-PIN {

    [LogMessage]::Initialize("$env:SystemRoot\Logs\HardenAD\Bitlocker")
    $Log = [LogMessage]::NewLogs()

    try {
        Add-Type -AssemblyName System.Windows.Forms
        Add-Type -AssemblyName System.Drawing
        Add-Type -Name Window -Namespace Console -MemberDefinition '
    [DllImport("Kernel32.dll")]
    public static extern IntPtr GetConsoleWindow();
        
    [DllImport("user32.dll")]
    public static extern bool ShowWindow(IntPtr hWnd, Int32 nCmdShow);
    '
        $Log.Success("All assemblies have been added.")
    }
    catch {
        $Log.Fatal(("At least one assembly could not be loaded: {0}." -f $_.Exception.Message))
    }

    try {
        $Log.Info("Starting the popup insterface.")
        $ConsolePtr = [Console.Window]::GetConsoleWindow()
        $null = [Console.Window]::ShowWindow($ConsolePtr, 0)
    
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
        $PinLabel.Size = [System.Drawing.Size]::new(340, 20)
        $PinLabel.Text = "PIN : "
    
        $PinInit = [System.Windows.Forms.MaskedTextBox]::new() 
        $PinInit.Location = [System.Drawing.Point]::new(20, 200)
        $PinInit.Size = [System.Drawing.Size]::new(340, 20)
        $PinInit.PasswordChar = "*"
    
        $ConfirmedPinLabel = [System.Windows.Forms.Label]::new()
        $ConfirmedPinLabel.Location = [System.Drawing.Point]::new(20, 230)
        $ConfirmedPinLabel.Size = [System.Drawing.Size]::new(340, 20)
        $ConfirmedPinLabel.Text = "Confirm PIN : "
    
        $PinConfirm = [System.Windows.Forms.MaskedTextBox]::new() 
        $PinConfirm.Location = [System.Drawing.Point]::new(20, 250)
        $PinConfirm.Size = [System.Drawing.Size]::new(340, 20)
        $PinConfirm.PasswordChar = "*"
    
        $SubmitButton = [System.Windows.Forms.Button]::new()
        $SubmitButton.Width = 80
        $SubmitButton.Height = 40
        $SubmitButton.Location = [System.Drawing.Point]::new((($Form.Width - $SubmitButton.Width) / 2), 280)
        $SubmitButton.Text = "Submit"
        $Form.AcceptButton = $SubmitButton
    
        $ConfirmationStatus = [System.Windows.Forms.StatusBar]::new()
    
        if (!([System.Windows.Forms.Control]::IsKeyLocked("NumLock"))) {
            $ConfirmationStatus.Text = "Warning : Num. Lock isn't activated."
        }
        else {
            $ConfirmationStatus.Text = ""
        }
    
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
                elseif ($PinConfirm.Text -match "(\d)\1{$($PinConfirm.Text.Length - 1)}$") {
                    $ConfirmationStatus.Text = "PIN cannot be composed of the same $($PinConfirm.Text.Length) digits."
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
    catch {
        $Log.Fatal(("An error occurred when displaying the user interface to change the PIN: {0}." -f $_.Exception.Message))
    }
}
