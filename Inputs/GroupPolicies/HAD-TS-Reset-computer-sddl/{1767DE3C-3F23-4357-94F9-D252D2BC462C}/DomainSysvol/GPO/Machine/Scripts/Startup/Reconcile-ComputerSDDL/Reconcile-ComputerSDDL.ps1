<#
    .SYNOPSIS
    This script reset the owner and ACL of any uncomformed computer object.
    
    .DESCRIPTION
    When a computer account is created through a delegation, the owner of the object will be the account that have created it and add rights specifically to this acocunt.
    The attribute mS-DS-CreatorSid is also filled with user Sid when the attribute mS-DS-MachineAccountQuota is not equal to 0.

    this script is tailored to reset authorization upon a one-time call (mainly to run through a schedule task).
    
    EventID code:
        100 - Script Start or End
        110 - Owner reset successful
        120 - SDDL reset successful
        210 - Owner reset fail
        220 - SDDL reset fail
        300 - Failed to retrieve nTSecurityDescriptor

    .NOTES
    Credits: 
    > https://blog.piservices.fr/post/2021/03/29/powershell-who-s-owner-of-my-ad-object
    > https://blog.piservices.fr/post/2021/04/12/powershell-change-the-owner-of-my-ad-objects
#>

Param()

# Exception to not handle in manual reset
$NotThoseOnes = Import-Csv .\Exceptions.csv -Delimiter ';' -Encoding utf8

# Exit Code
$Code = 0

# Event Log update
try { New-EventLog -LogName Application -Source "HAD_TS_Reset-Computer-SDDL" -ErrorAction SilentlyContinue } Catch { }

# Log schedule start
$StartMsg = "The reconcile process has started (computer owner and ACL).`n`nThe following objects will be discarded if met:`n"
foreach ($avoidThis in $NotThoseOnes) { $StartMsg += "> Exception: $($avoidThis.SamAccountName)`n" }

Write-EventLog -LogName Application -Source "HAD_TS_Reset-Computer-SDDL" -EntryType SuccessAudit -EventId 100 -Category 0 -Message $StartMsg

# Computer Domain NetBIOS name
$DomNbios = [String](Get-ADDomain).NetBIOSName

# Compute Domain Admins
$DAsid  = [String](Get-ADDomain).DomainSID.Value + "-512"
$DAName = (Get-ADGroup $DAsid).Name
$DAPreW = "$($domNbios)\$((Get-ADGroup $DAsid).Name)"

# Find computer object with an abnormal owner
$Computers = Get-AdComputer -Filter { enabled -eq $true } -Properties ObjectClass,nTSecurityDescriptor | Where-Object { $_.nTSecurityDescriptor.Owner -ne $DAPreW -and $NotThoseOnes.SamAccountName -notcontains $_.SamAccountName }

# Store Info
$Computers | ForEach-Object {
    # Current  Computer
    $SamAccountName = $_.SamAccountName
    
    # Change Owner
    Try {
        # Define Target
        $TargetObject = Get-ADComputer $SamAccountName 
        $AdsiTarget   = [adsi]"LDAP://$($TargetObject.DistinguishedName)"

        # Set new Owner
        $NewOwner = New-Object System.Security.Principal.NTAccount($DAName)
        $AdsiTarget.PSBase.ObjectSecurity.SetOwner($NewOwner)
        $AdsiTarget.PSBase.CommitChanges()

        # Write to event log
        Write-EventLog -LogName Application -Source "HAD_TS_Reset-Computer-SDDL" -EntryType SuccessAudit -EventId 110 -Category 0 -Message "The computer '$SamaccountName' owner has been refreshed to $DAName"
    }
    Catch {
        # Failed.
        Write-EventLog -LogName Application -Source "HAD_TS_Reset-Computer-SDDL" -EntryType  FailureAudit -EventId 210 -Category 0 -Message "The computer '$SamaccountName' owner Failed to be updted! Error: $($_.ToString())"
        $Code += 1
        }

    # Reset ACL
    # Get computer default ACL
    $SchemaNamingContext       = (Get-ADRootDSE).schemaNamingContext
    $DefaultSecurityDescriptor = Get-ADObject -Identity "CN=Computer,$SchemaNamingContext" -Properties defaultSecurityDescriptor | Select-Object -ExpandProperty defaultSecurityDescriptor

    $ADObj = Get-ADComputer -Identity $SamAccountName -Properties nTSecurityDescriptor -ErrorVariable GetADObjError

    if ($GetADobjError) { 
        # Failed
        $Code += 10

        # Write to event log
        Write-EventLog -LogName Application -Source "HAD_TS_Reset-Computer-SDDL" -EntryType FailureAudit -EventId 300 -Category 0 -Message "The computer '$SamaccountName' ntSecurityDescriptor could not be retrieved! Error: $($_.ToString())"
    }
    Else {
        Try {
            $ADObj.nTSecurityDescriptor.SetSecurityDescriptorSddlForm( $DefaultSecurityDescriptor )
            Set-ADObject -Identity $ADObj.DistinguishedName -Replace @{ nTSecurityDescriptor = $ADObj.nTSecurityDescriptor } -Confirm:$false
            
            # Write to event log
            Write-EventLog -LogName Application -Source "HAD_TS_Reset-Computer-SDDL" -EntryType SuccessAudit -EventId 120 -Category 0 -Message "The computer '$SamaccountName' SDDL has been recycled to its default value."

        } 
        Catch {
            #.Failed
            $Code += 100

            # Write to event log
            Write-EventLog -LogName Application -Source "HAD_TS_Reset-Computer-SDDL" -EntryType FailureAudit -EventId 200 -Category 0 -Message "The computer '$SamaccountName' SDDL could not be refreshed! Error: $($_.ToString())"
        }
    }
    # Release variable
    $SamAccountName = $null
}

# Log schedule end
Write-EventLog -LogName Application -Source "HAD_TS_Reset-Computer-SDDL" -EntryType SuccessAudit -EventId 100 -Category 0 -Message "The reconcile process has ended (computer owner and ACL)."

Exit 0
