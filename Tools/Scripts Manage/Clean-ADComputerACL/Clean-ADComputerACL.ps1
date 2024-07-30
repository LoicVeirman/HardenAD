

# Get Computer Owner
# Sources : 
#   - https://blog.piservices.fr/post/2021/03/29/powershell-who-s-owner-of-my-ad-object
#   - https://blog.piservices.fr/post/2021/04/12/powershell-change-the-owner-of-my-ad-objects
#
#   /!\ You must adapt the name of the groups to the installation language of your domain controller /!\
#
#   Dans le cas d'utilisation de ORADAD de ANSSI, le script permet de corriger le probleme : vuln3_owner
#   https://www.cert.ssi.gouv.fr/uploads/guide-ad.html#owner
#
#   Revision du 23/2/2024 - Script rendu agnostique de la langue et dynamique.
Param(
    [Parameter(mandatory)]
    [String]
    $TargetDomain
)

# Create Array
$Array = @()

# Compute Domain Admins
$DAsid = [String](Get-ADDomain).DomainSID.Value + "-512"
$DAName = (Get-ADGroup $DAsid).Name

$EAsid = [String](Get-ADDomain).DomainSID.Value + "-519"
$EAName = (Get-ADGroup $EAsid).Name

$ASsid = "S-1-5-32-544"
$ASName = (Get-ADGroup $ASsid).Name


# Collect AD infos
$Domain       = Get-ADDomain   -Server $TargetDomain | Select-Object -ExpandProperty NetBIOSName
$AllComputers = Get-ADComputer -Server $TargetDomain -Filter * -Properties nTSecurityDescriptor
 
# Store Info
$AllComputers | ForEach-Object {
    $Array += New-Object psobject -Property @{
        DistinguishedName = $_.DistinguishedName
        DNSHostName       = $_.DNSHostName
        Enabled           = $_.Enabled
        Name              = $_.Name
        ObjectClass       = $_.ObjectClass
        ObjectGUID        = $_.ObjectGUID
        SamAccountName    = $_.SamAccountName
        SID               = $_.SID
        Owner             = $_.nTSecurityDescriptor.owner
    }
}

# How many Accounts were returns ?
Write-Host "Found " -NoNewline -ForegroundColor Gray
Write-Host $Array.Count -ForegroundColor Yellow -NoNewline
Write-Host " computers" -ForegroundColor Gray

# How many Accounts need to be reviewed ?
$NoGood = $Array.Where({ (($_.Owner -ne "$domain\$DAName") -and ($_.Owner -ne "$domain\$EAName") -and ($_.Owner -ne "$domain\$ASName")) })

Write-Host "About " -NoNewline -ForegroundColor Gray
Write-Host $NoGood.count -ForegroundColor Cyan -NoNewline
Write-Host " needs to be fixed." -ForegroundColor Gray

$color = "white"

# Computers
$NoGood | foreach {
    # switching color
    if ($color -eq "darkgray") { $color = "gray" ; $succol = "green" } else { $color = "darkgray" ; $succol = "green" }    
    # Current  Computer
    $SamAccountName = $_.SamAccountName

    Write-Host $SamAccountName        -NoNewline -ForegroundColor $color
    write-host "`tchanging owner of " -NoNewline -ForegroundColor $color

    # Change Owner
    Try {
        # Define Target
        $TargetObject = Get-ADComputer $SamAccountName -Server $TargetDomain
        $AdsiTarget = [adsi]"LDAP://$($TargetObject.DistinguishedName)"

        # Set new Owner
        $NewOwner = New-Object System.Security.Principal.NTAccount($DAName)
        $AdsiTarget.PSBase.ObjectSecurity.SetOwner($NewOwner)
        $AdsiTarget.PSBase.CommitChanges()

        Write-Host "`tSuccess" -ForegroundColor $succol
    }
    Catch {
        Write-Warning $($_)
        #$SamAccountName
        Write-Host "`tfailed!" -ForegroundColor red
    }

    # Reset ACL
    # get computer default ACL
    $SchemaNamingContext = (Get-ADRootDSE -Server $TargetDomain).schemaNamingContext
    $DefaultSecurityDescriptor = Get-ADObject -Identity "CN=Computer,$SchemaNamingContext" -Properties defaultSecurityDescriptor -Server $TargetDomain | Select-Object -ExpandProperty defaultSecurityDescriptor

    $DescriptionMessage = "Resetting SDDL for computer $SamAccountName"

    Write-Host $SamAccountName        -NoNewline -ForegroundColor $color
    Write-Host "`tResetting SDDL of " -NoNewline -ForegroundColor $color
        
    $ADObj = Get-ADComputer -Identity $SamAccountName -Properties nTSecurityDescriptor -ErrorVariable GetADObjError -Server $TargetDomain

    if ($GetADobjError) { 
        Write-Host "`tFailed!" -ForegroundColor Red 
    }
    Else {
        Try {
            $ADObj.nTSecurityDescriptor.SetSecurityDescriptorSddlForm( $DefaultSecurityDescriptor )
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

