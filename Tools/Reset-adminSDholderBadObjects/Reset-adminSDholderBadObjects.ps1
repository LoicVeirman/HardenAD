<#
    .SYNOPSIS
    This script reset the admincount attribute, the owner and the ACL of a user or group object if the account is not really protected by AdminSDholder.
    
    .DETAILS
    When a user or a group object is moved to an adminSDHolder protected group, the admincount of the object is set to 1 and will not be removed even if this one is moved away from those groups.
    When adminCount is set to 1, the ACL inheritance for this object is broken and its ACL are replaced by the one from the adminSDholder - this could lead to a security risks if not remediate.
    The script seek for objects with the adminCount equal to 1 and not member of a protect adminSDholder group, then clear the attribute, reset the ACL and change the object owner accordingly.

    this script is tailored to reset authorization upon a one-time call (mainly to run through a schedule task).

    .PARAMETER TargetDomain
    The domain to be analyzed. If not set, the script will run in the system domain.

    .PARAMETER Owner
    Specify which group should be owner of the objects (Enterprise Admins, domain Admins, Builtin Administrator). Default is Domain Admins.
    .NOTES
    Credits: 
        > https://blog.piservices.fr/post/2021/03/29/powershell-who-s-owner-of-my-ad-object
        > https://blog.piservices.fr/post/2021/04/12/powershell-change-the-owner-of-my-ad-objects
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

# If no TargetDomain...
if (-not($TargetDomain)) { $TargetDomain = (Get-ADDomain).DNSroot }

# Create Array
$Array = @()

# Compute Admin Groups (universal language compatible)
$DAsid = [String](Get-ADDomain -Server $TargetDomain).DomainSID.Value + "-512"
$DAName = (Get-ADGroup $DAsid).Name

$EAsid = [String](Get-ADDomain (Get-ADDomain -Server $TargetDomain).Forest).DomainSID.Value + "-519" 
$EAName = (Get-ADGroup $EAsid -Server (Get-ADDomain -Server $TargetDomain).Forest).Name

$ASsid = "S-1-5-32-544"
$ASName = (Get-ADGroup $ASsid -Server $TargetDomain).Name

# if NewOwner...
switch ($NewOwner) {
    'EnterpriseAdmins' { $OwName = $EAName }
    'DomainAdmins' { $OwName = $DAName }
    'BuiltinAdministrators' { $OwName = $ASName }
    Default { $OwName = $DAName }
}

# Collect AD infos
$Domain = Get-ADDomain -Server $TargetDomain | select -ExpandProperty NetBIOSName
$accountsList = Get-ADObject -filter 'AdminCount -eq 1 -and isCriticalsystemObject -notlike "*"' -Server $TargetDomain -properties *
$adminGroupList = get-adgroup  -filter 'admincount -eq 1 -and iscriticalsystemobject -like "*"'    -Server $TargetDomain | select -ExpandProperty distinguishedName
 
# Store Info
$AccountsList | foreach {
    $DistinguishedName = $_.DistinguishedName
    $Name = $_.Name
    $ObjectClass = $_.ObjectClass
    $ObjectGUID = $_.ObjectGUID
    $SamAccountName = $_.SamAccountName
    $SID = $_.SID
    $nTSecurityDescriptor = $_.nTSecurityDescriptor


    $Array += New-Object psobject -Property @{
        DistinguishedName = $DistinguishedName
        Name              = $Name
        ObjectClass       = $ObjectClass
        ObjectGUID        = $ObjectGUID
        SamAccountName    = $SamAccountName
        SID               = $SID
        Owner             = $nTSecurityDescriptor.owner
    }
     
    $DistinguishedName = $null
    $Name = $null
    $ObjectClass = $null
    $ObjectGUID = $null
    $SamAccountName = $null
    $SID = $null
    $nTSecurityDescriptor = $null
}
 
# How many Accounts were returns ?
Write-Host "Found " -NoNewline -ForegroundColor Gray
Write-Host ($Array | Where-Object { $_.ObjectClass -eq 'user' }).Count -ForegroundColor Yellow -NoNewline
Write-Host " users and " -ForegroundColor Gray -NoNewline
Write-Host ($Array | Where-Object { $_.ObjectClass -eq 'group' }).Count -ForegroundColor Yellow -NoNewline
Write-Host " groups" -ForegroundColor Gray

# How many Accounts need to be reviewed ?
$NoGood = @()

foreach ($account in $accountsList) {
    $dn = $account.DistinguishedName
    $isMemberOf = Get-ADGroup -Filter { member -recursiveMatch $dn }
    $isAdmin = $false
    
    foreach ($Grp in $isMemberOf) {
        if ($adminGroupList.Contains($Grp.distinguishedName)) {
            $isAdmin = $true
            break
        }
    }

    if (-not($isAdmin)) {
        $NoGood += $account
    }
}

Write-Host "About " -NoNewline -ForegroundColor Gray
Write-Host $NoGood.count -ForegroundColor Cyan -NoNewline
Write-Host " Users/Groups needs to be fixed." -ForegroundColor Gray

$color = "white"

# get default ACL
$SchemaNamingContext = (Get-ADRootDSE -Server $TargetDomain).schemaNamingContext
$GrpDfltSecurityDescriptor = Get-ADObject -Identity "CN=Group,$SchemaNamingContext" -Properties defaultSecurityDescriptor -Server $TargetDomain | Select-Object -ExpandProperty defaultSecurityDescriptor
$UsrDfltSecurityDescriptor = Get-ADObject -Identity "CN=User,$SchemaNamingContext"  -Properties defaultSecurityDescriptor -Server $TargetDomain | Select-Object -ExpandProperty defaultSecurityDescriptor

# Fixing
$NoGood | foreach {

    # switching color
    if ($color -eq "darkgray") { $color = "gray" ; $succol = "green" } else { $color = "darkgray" ; $succol = "green" }    
    
    # Current  Account
    $SamAccountName = $_.SamAccountName

    # Reset AdminCount                   
    Write-Host $SamAccountName                   -NoNewline -ForegroundColor $Color
    Write-Host "`tClearing AdminCount attribute" -NoNewline -ForegroundColor $Color

    Try {
        Get-ADObject $_.DistinguishedName | Set-ADObject -Remove @{AdminCount = 1 }
        Write-Host "        `tSuccess" -ForegroundColor $succol
    }
    Catch {
        Write-Warning $($_)
        Write-Host "        `tfailed!" -ForegroundColor red
    }

    # Change Owner
    Write-Host $SamAccountName                -NoNewline -ForegroundColor $color
    write-host "`tchanging owner to $OwName " -NoNewline -ForegroundColor $color

    Try {
        # Define Target
        $AdsiTarget = [adsi]"LDAP://$($_.DistinguishedName)"
 
        # Set new Owner
        $NewOwner = New-Object System.Security.Principal.NTAccount($OwName)
        $AdsiTarget.PSBase.ObjectSecurity.SetOwner($NewOwner)
        $AdsiTarget.PSBase.CommitChanges()

        Write-Host "`tSuccess" -ForegroundColor $succol
    }
    Catch {
        Write-Warning $($_)
        Write-Host "`tfailed!" -ForegroundColor red
    }
 
    # Reset ACL
    $DescriptionMessage = "Resetting SDDL for computer $SamAccountName"

    Write-Host $SamAccountName                       -NoNewline -ForegroundColor $color
    Write-Host "`tResetting SDDL to schema default " -NoNewline -ForegroundColor $color
        
    switch ($_.ObjectClass) {
        'user' { $ADObj = Get-ADUser  -Identity $SamAccountName -Properties nTSecurityDescriptor -ErrorVariable GetADObjError -Server $TargetDomain }
        'group' { $ADObj = Get-ADGroup -Identity $SamAccountName -Properties nTSecurityDescriptor -ErrorVariable GetADObjError -Server $TargetDomain }
    }
    
    if ($GetADobjError) { 
        Write-Host "`tFailed!" -ForegroundColor Red 
    }
    Else {
        Try {
            switch ($_.ObjectClass) {
                'user' { $ADObj.nTSecurityDescriptor.SetSecurityDescriptorSddlForm( $UsrDfltSecurityDescriptor ) }
                'group' { $ADObj.nTSecurityDescriptor.SetSecurityDescriptorSddlForm( $GrpDfltSecurityDescriptor ) }
            }
                
            Set-ADObject -Identity $ADObj.DistinguishedName -Replace @{ nTSecurityDescriptor = $ADObj.nTSecurityDescriptor } -Confirm:$false -Server $TargetDomain
            Write-Host "`tSuccess" -ForegroundColor $succol
        } 
        Catch {
            Write-Host "`tFailed" -ForegroundColor red
        }
    }
    
    # Release variable
    $SamAccountName = $null
    Write-Host
}