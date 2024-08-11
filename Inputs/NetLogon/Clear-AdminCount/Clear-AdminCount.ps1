<# 
    .SYNOPSIS
    Cleat the AdminCount attribute on non-admin accounts and generate an alert in the Security Event Log for tracability. 

    .DESCRIPTION
    An account with the adminCount set to 1 is being protected with different ACL than other objects and is only intended for Admin Accounts (DA, EA, A, SA).
    When an account is not member of one of those protected groups, the flag must be cleared-out and the ACLs reseted.

    Warning: 
    This implies a lack of information when hunting for rogue admin accounts or bad usage by the IT team. 
    To avoid a complete loss of information, the script will push an alert in the security event log.

    .NOTES
    Version 2.0.0 by L.Veirman.
#>
Param(
    [Parameter(Position = 0)]
    [String]
    $TargetDomain,

    [Parameter(Position = 1)]
    [ValidateSet("EnterpriseAdmins", "DomainAdmins", "BuiltinAdminstrators")]
    [String]
    $NewOwner
)

# Default behavior when an error is met.
# Can be overwritten in function by using -ErrorAction.
$ErrorActionPreference = 'Stop'

## Function Log Debug File
$DbgFile = 'Debug_{0}.log' -f $MyInvocation.MyCommand
$dbgMess = @()

## Start Debug Trace
$dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "****"
$dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "**** FUNCTION STARTS"
$dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "****"

## Indicates caller and options used
$dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Function caller..........: " + (Get-PSCallStack)[1].Command

# Preparing Event Log
Try {
    [Void](New-EventLog -LogName Application -Source "HardenAD_Clear-AdminCount" -ErrorAction Stop)
    $debugMessage += Write-DebugLog inf "EVENT VIEWER: the eventlog name '$eventLogName' has been updated with the source '$eventLogSource'."
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Event logging............: Application / HardenAD_Clear-AdminCount (successfully created)"
} 
Catch {
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Event logging............: Application / HardenAD_Clear-AdminCount (already declared)"
}

Try {
    # If no TargetDomain...
    if (-not($TargetDomain)) 
    { 
        $TargetDomain = (Get-ADDomain).DNSroot 
    }

    # Create Array
    $Array = @()

    # Compute Admin Groups (universal language compatible)
    $DAsid  = [String](Get-ADDomain -Server $TargetDomain).DomainSID.Value + "-512"
    $DAName = (Get-ADGroup $DAsid).Name

    $EAsid  = [String](Get-ADDomain (Get-ADDomain -Server $TargetDomain).Forest).DomainSID.Value + "-519" 
    $EAName = (Get-ADGroup $EAsid -Server (Get-ADDomain -Server $TargetDomain).Forest).Name

    $ASsid  = "S-1-5-32-544"
    $ASName = (Get-ADGroup $ASsid -Server $TargetDomain).Name

    # Echo value to log for debug puppose
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Function caller..........:"
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Group Enterprise Admins..: $($EAName)"
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Group Domain Admins......: $($DAName)"
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Group Builtin Admins.....: $($ASName)"

    # if NewOwner...
    switch ($NewOwner) 
    {
        'EnterpriseAdmins'      { $OwName = $EAName }
        'DomainAdmins'          { $OwName = $DAName }
        'BuiltinAdministrators' { $OwName = $ASName }
        Default                 { $OwName = $DAName }
    }
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---"
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> New owner will be........: $($OwName)"
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---"

    # Collect AD infos
    $DomainNetBIOS  = Get-ADDomain -Server $TargetDomain | Select-Object -ExpandProperty NetBIOSName
    $accountsList   = Get-ADObject -filter 'AdminCount -eq 1 -and isCriticalsystemObject -notlike "*"' -Server $TargetDomain -properties *
    $adminGroupList = get-adgroup  -filter 'admincount -eq 1 -and iscriticalsystemobject -like "*"'    -Server $TargetDomain | Select-Object -ExpandProperty distinguishedName
    
    # Store Info (I wonder myself why the hell I'm doing this...)
    foreach ($Account in $AccountsList ) 
    {
        $Array += New-Object psobject -Property @{
            DistinguishedName = $Account.DistinguishedName
            Name              = $Account.Name
            ObjectClass       = $Account.ObjectClass
            ObjectGUID        = $Account.ObjectGUID
            SamAccountName    = $Account.SamAccountName
            SID               = $Account.ObjectSID
            Owner             = $Account.nTSecurityDescriptor.owner
        }
    }
    
    # How many Accounts were returns ?
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Found $(($Array | Where-Object { $_.ObjectClass -eq 'user' }).Count) User(s) and $(($Array | Where-Object { $_.ObjectClass -eq 'group' }).Count) Group(s)"

    # How many Accounts need to be reviewed ?
    $NoGood = @()

    foreach ($account in $accountsList) 
    {
        $dn         = $account.DistinguishedName
        $isMemberOf = Get-ADGroup -Filter { member -recursiveMatch $dn }
        $isAdmin    = $false
        
        foreach ($Grp in $isMemberOf) 
        {
            if ($adminGroupList.Contains($Grp.distinguishedName)) 
            {
                $isAdmin = $true
                break
            }
        }

        if (-not($isAdmin)) 
        {
            $NoGood  += $account
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---- >>>> Found non-compliant user: $($Account.samAccountName)" 
        }
    }

    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---"
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> About $($NoGood.count) User(s) and/or Group(s) needs to be fixed." 
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---"

    # get default ACL
    $SchemaNamingContext       = (Get-ADRootDSE -Server $TargetDomain).schemaNamingContext
    $GrpDfltSecurityDescriptor = Get-ADObject -Identity "CN=Group,$SchemaNamingContext" -Properties defaultSecurityDescriptor -Server $TargetDomain | Select-Object -ExpandProperty defaultSecurityDescriptor
    $UsrDfltSecurityDescriptor = Get-ADObject -Identity "CN=User,$SchemaNamingContext"  -Properties defaultSecurityDescriptor -Server $TargetDomain | Select-Object -ExpandProperty defaultSecurityDescriptor

    # Fixing
    $resultA = $false
    $resultB = $resultA
    $resultC = $resultB

    foreach ($Account in $NoGood) 
    {
        # Prepare for result collection
        $changeResult = @{AdmCnt = " " ; Owner = " " ; ntSD = " "}
        # Current  Account
        $SamAccountName = $Account.SamAccountName

        # Tracking to security event log
        $message  = "Action Taken:`nCleared-out AdminCount, Changed owner to $($NewOwner) and reset ACL to default for class $($Account.ObjectClass)`n`n"
        $message += "Name:`t`t`t$($Account.Name)`n" 
        $message += "DistinguishedName:`t$($Account.DistinguishedName)`n" 
        $message += "ObjectClass:`t`t$($Account.ObjectClass)`n" 
        $message += "ObjectGUID:`t`t$($Account.ObjectGUID)`n" 
        $message += "SamAccountName:`t$($Account.SamAccountName)`n" 
        $message += "SID:`t`t`t$($Account.ObjectSID)`n" 
        $message += "Owner:`t`t`t$($Account.ntSecurityDescriptor.owner)`n" 
        $message += "AdminCount:`t`t1`n" 
        $message += "RogueAdminAccount:`tTrue`n" 
        $message += "`nCurrent ACCESS LIST:`n`n"

        foreach($ACL in $Account.ntSecurityDescriptor.Access)
        {
            $message += "IdentityReference:`t`t$($ACL.IdentityReference)`n"
            $message += "ActiveDirectoryRights:`t$($ACL.ActiveDirectoryRights)`n"
            $message += "InheritanceType:`t`t$($ACL.InheritanceType)`n"
            $message += "ObjectType:`t`t$($ACL.ObjectType)`n"
            $message += "InheritedObjectType:`t$($ACL.InheritedObjectType)`n"
            $message += "ObjectFlags:`t`t$($ACL.ObjectFlags)`n"
            $message += "AccessControlType:`t$($ACL.AccessControlType)`n"
            $message += "IsInherited:`t`t$($ACL.IsInherited)`n"
            $message += "InheritanceFlags:`t`t$($ACL.InheritanceFlags)`n"
            $message += "PropagationFlag:`t`t$($ACL.PropagationFlags)`n`n"         
        }

        # Reset AdminCount                   
        Try {
            Get-ADObject $Account.DistinguishedName | Set-ADObject -Remove @{AdminCount = 1 } -ErrorAction Stop
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---- <<<< $($Account.SamAccountName): AdminCount attribute cleared-out."
            $resultA = $false
            $changeResult.AdmCnt = "Success"
        }
        Catch {
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---- !!!! $($Account.SamAccountName): Error - Failed to clear-out the AdminCount attribute."
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---- !!!! $($Account.SamAccountName): Error message: $($_.ToString())"
            $changeResult.AdmCnt = "Error"
        }

        # Change Owner
        Try {
            # Define Target
            $AdsiTarget = [adsi]"LDAP://$($Account.DistinguishedName)"
            # Set new Owner
            $NewOwn = New-Object System.Security.Principal.NTAccount($DomainNetBIOS,$OwName)
            $AdsiTarget.PSBase.ObjectSecurity.SetOwner($NewOwn)
            $AdsiTarget.PSBase.CommitChanges()
            $changeResult.Owner = "Success"
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---- <<<< $($Account.SamAccountName): Owner reset to $($NewOwn)."
        }
        Catch {
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---- !!!! $($Account.SamAccountName): Error - Failed to reset the Owner to $($OwName)."
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---- !!!! $($Account.SamAccountName): Error message: $($_.ToString())"
            $resultB = $true
            $changeResult.Owner = "Error"
        }
    
        # Reset ACL
        # Wrapup existing ACL to log (in case eventlog application got cleared of faulty)
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---- **** EXISTING ACL:"
        foreach($ACL in $Account.ntSecurityDescriptor.Access)
        {
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---- ----"
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---- >>>> IdentityReference     : $($ACL.IdentityReference)"
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---- >>>> ActiveDirectoryRights : $($ACL.ActiveDirectoryRights)"
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---- >>>> InheritanceType       : $($ACL.InheritanceType)"
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---- >>>> ObjectType            : $($ACL.ObjectType)"
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---- >>>> InheritedObjectType   : $($ACL.InheritedObjectType)"
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---- >>>> ObjectFlags           : $($ACL.ObjectFlags)"
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---- >>>> AccessControlType     : $($ACL.AccessControlType)"
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---- >>>> IsInherited           : $($ACL.IsInherited)"
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---- >>>> InheritanceFlags      : $($ACL.InheritanceFlags)"
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---- >>>> PropagationFlags      : $($ACL.PropagationFlags)"
        }
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---- ----"

        Try {
            switch ($Account.ObjectClass) 
            {
                'user'  { $ADObj = Get-ADUser  -Identity $SamAccountName -Properties nTSecurityDescriptor -ErrorVariable GetADObjError -Server $TargetDomain }
                'group' { $ADObj = Get-ADGroup -Identity $SamAccountName -Properties nTSecurityDescriptor -ErrorVariable GetADObjError -Server $TargetDomain }
            }
        
            switch ($Account.ObjectClass) 
            {
                'user'  { $ADObj.nTSecurityDescriptor.SetSecurityDescriptorSddlForm( $UsrDfltSecurityDescriptor ) }
                'group' { $ADObj.nTSecurityDescriptor.SetSecurityDescriptorSddlForm( $GrpDfltSecurityDescriptor ) }
            }
            
            Set-ADObject -Identity $ADObj.DistinguishedName -Replace @{ nTSecurityDescriptor = $ADObj.nTSecurityDescriptor } -Confirm:$false -Server $TargetDomain
            $changeResult.ntSD = "Success"
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---- <<<< $($Account.SamAccountName): ntSecurityDescriptor reset to default from class $($Account.ObjectClass)."
        } 
        Catch {
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---- !!!! $($Account.SamAccountName): Error - Failed to reset ntSecurityDescriptor."
            $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---- !!!! $($Account.SamAccountName): Error message: $($_.ToString())"
            $resultC = $true
            $changeResult.ntSD = "Error"
        }
        # Write to event log 
        $message += "`nOperation result:`nClear adminCount:`t$($changeResult.AdmCnt)`nChange Owner:`t`t$($changeResult.Owner)`nReset ACL:`t`t$($changeResult.ntSD)"

        if ($changeResult.AdmCnt -eq "Error" -or $changeResult.Owner -eq "Error" -or $changeResult.ntSD -eq "Error")
        {
            $EventType = "Error"
            $EventId   = 65535
        }
        Else {
            $EventType = "Warning"
            $EventId   = 1024 
        }
        write-EventLog -LogName Application -Source "HardenAD_Clear-AdminCount" -EntryType $EventType -EventId $EventId -Message $message

        # Release variable
        $SamAccountName = $null
    }
    # Computing final result for the sake of the goodness when analyzing
    if ($resultA)           { $Synthetisis = "Failed to reset some admin accounts" }
    if ($resultB)           { if ($Synthetisis) { $Synthetisis += ", failed to set some owners"} else { $Synthetisis = "Failed to set some owners"} }
    if ($resultC)           { if ($Synthetisis) { $Synthetisis += ", failed to set some ntSecurityDescriptors"} else { $Synthetisis = "Failed to set some ntSecurityDescriptors"} }
    if (-not($Synthetisis)) { $Synthetisis = "Everything was fixed smoothly." ; $result = 0 ; $ResMess = "Success" } else { $result = 1 ; $ResMess = $Synthetisis }

    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---"
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> $($Synthetisis)." 
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---"
}
Catch {
    # Manage error.
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "!!!! FATAL ERROR: The script break before processing all commands!"
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "!!!! FATAL ERROR: $($_.ToString())"
    $result = 2
    $ResMess = $_.ToString()
}
Finally {
    ## Exit log to file
    if (-not(test-path "$($env:ProgramData)\HardenAD\Logs\"))
    {
        [void](New-Item -Name "Logs" -ItemType Directory -Path "$($env:ProgramData)\HardenAD" -force)
    }
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Script return RESULT.: $($Result)"
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Script return MESSAGE: $($ResMess)"
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "=== | INIT  ROTATIVE  LOG "
    if (Test-Path "$($env:ProgramData)\HardenAD\Logs\$DbgFile") 
    {
        $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "---> Rotate log file......: 1000 last entries kept" 
        $Backup = Get-Content "$($env:ProgramData)\HardenAD\Logs\$DbgFile" -Tail 1000 
        $Backup | Out-File "$($env:ProgramData)\HardenAD\Logs\$DbgFile" -Force
    }
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ") + "=== | STOP  ROTATIVE  LOG "
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ****")
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T **** FUNCTION ENDS")
    $dbgMess += (Get-Date -UFormat "%Y-%m-%d %T ****")
    $DbgMess | Out-File "$($env:ProgramData)\HardenAD\Logs\$DbgFile" -Append

    # return result to caller
    exit $result
}