<#
    .SYNOPSIS
    Simplify lab setup for testing purpose.

    .DESCRIPTION
    Simplify the lab setup for test purpose: enable all GPO, reset all admin password to the same, ...

    .NOTES
    Version 1.0 by Loïc VEIRMAN
#>

Try {
    # Say hello
    Write-host "************************" -ForegroundColor Blue
    Write-Host "* " -ForegroundColor Blue -NoNewline
    Write-Host "Labator Space Pirate" -ForegroundColor Cyan -NoNewline
    Write-Host " *" -ForegroundColor Blue
    Write-host "************************" -ForegroundColor Blue
    # display menu
    Write-Host "`nPlease, select an action:" -ForegroundColor Yellow
    write-host "[1] Set all admins password" -ForegroundColor Cyan
    write-host "[2] Enable all GPO" -ForegroundColor Cyan
    Write-Host "[0] Exit" -ForegroundColor Cyan
    Write-host "`nYour choice? " -ForegroundColor Yellow
    # Ask choice
    $noChoice = $true
    While ($noChoice) {
        $userChoice = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
        # lesss or equal 96 + max choice value
        if ($userChoice.VirtualKeyCode -le 98) {
            $noChoice = $false
        }
    }
    # Deal Choice
    Switch ($userChoice.VirtualKeyCode) {
        # Pressed 0
        96 {
            Write-Host "Leaving..." -ForegroundColor Magenta
        }
        # Pressed 1
        97 {
            $newPassword = Read-Host -Prompt "Enter new password" -AsSecureString
            $myXML = [XML](Get-Content ./../../Configs/TasksSequence_HardenAD.xml -Encoding UTF8 -ErrorAction Stop)
            foreach ($account in $myXML.Settings.Accounts.User) {
                Write-Host "> $($account.SAMAccountName)`t" -ForegroundColor Gray -NoNewline
                Try {
                    [void](Set-ADAccountPassword -Identity $Account.samAccountName -NewPassword $newPassword)
                    Write-Host "Success" -ForegroundColor Green
                }
                Catch {
                    Write-Host "Failed: " -ForegroundColor Red -NoNewline
                    Write-Host $_
                }
            }
        }
        # Pressed 2
        98 {
            $myXML = [XML](Get-Content ./../../Configs/TasksSequence_HardenAD.xml -Encoding UTF8 -ErrorAction Stop)
            foreach ($GPO in $myXML.Settings.GroupPolicies.GPO) {
                Write-Host "> $($GPO.Name): " -NoNewline -ForegroundColor Gray
                Try {
                    if ($GPO.GpoMode -notlike "den*") {
                        [void](Set-GPPermission -Name $GPO.Name -PermissionLevel GpoApply -TargetType Group -TargetName (New-Object -TypeName System.Security.Principal.SecurityIdentifier -ArgumentList (Get-ADObject -LDAPFilter "(objectSID=S-1-5-11)").Name).Translate([System.Security.Principal.NTAccount]).Value -ErrorAction Stop)
                        write-host "success" -ForegroundColor Green
                    }
                    Else {
                        Write-Host "Already enabled" -ForegroundColor cyan
                    }
                }
                Catch {
                    write-Host "failed! " -ForegroundColor Red -NoNewline
                    write-host $_ -ForegroundColor magenta
                }
            }
        }
    }
    Write-Host "`nGoodbye!`n" -ForegroundColor Yellow
}
Catch {
    Write-host "fatal error" -ForegroundColor Yellow -BackgroundColor Red
    write-host $_ -ForegroundColor yellow
}