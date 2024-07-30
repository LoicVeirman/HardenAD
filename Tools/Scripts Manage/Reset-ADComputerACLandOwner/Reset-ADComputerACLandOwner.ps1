<#
    .SYNOPSIS
    This script reset the owner and ACL of a newly created computer.
    
    .DETAILS
    When a computer account is created through a delegation, the owner of the object will be the account that have created it and add rights specifically to this acocunt.
    The attribute mS-DS-CreatorSid is also filled with user Sid when the attribute mS-DS-MachineAccountQuota is not equal to 0.

    this script is tailored to reset authorization upon a one-time call (mainly to run through a schedule task).

    .PARAMETER ComputerName
    The computer object name to clean-up.

    .NOTES
    Credits: 
        > https://blog.piservices.fr/post/2021/03/29/powershell-who-s-owner-of-my-ad-object
        > https://blog.piservices.fr/post/2021/04/12/powershell-change-the-owner-of-my-ad-objects
#>

Param(
    [Parameter(mandatory)]
    [String]
    $Computer
)
# Exit Code
$Code = 0

# Event Log update
try { New-EventLog -LogName Application -Source "HardenAD" } Catch { }

# Compute Domain Admins
$DAsid  = [String](Get-ADDomain).DomainSID.Value + "-512"
$DAName = (Get-ADGroup $DAsid).Name

$EAsid  = [String](Get-ADDomain).DomainSID.Value + "-519"
$EAName = (Get-ADGroup $EAsid).Name

$ASsid  = "S-1-5-32-544"
$ASName = (Get-ADGroup $ASsid).Name


# Collect AD infos
$Domain   = Get-ADDomain | select -ExpandProperty NetBIOSName
$Computer = Get-ADComputer $Computer -Properties nTSecurityDescriptor
 
# Store Info
$Computer | foreach {
    $DistinguishedName    = $_.DistinguishedName
    $GroupCategory        = $_.GroupCategory
    $GroupScope           = $_.GroupScope
    $Name                 = $_.Name
    $ObjectClass          = $_.ObjectClass
    $ObjectGUID           = $_.ObjectGUID
    $SamAccountName       = $_.SamAccountName
    $SID                  = $_.SID
    $nTSecurityDescriptor = $_.nTSecurityDescriptor


    $Array = New-Object psobject -Property @{
        DistinguishedName = $DistinguishedName
        DNSHostName       = $DNSHostName
        Enabled           = $Enabled
        Name              = $Name
        ObjectClass       = $ObjectClass
        ObjectGUID        = $ObjectGUID
        SamAccountName    = $SamAccountName
        SID               = $SID
        Owner             = $nTSecurityDescriptor.owner
        }
}

# Computers
$Array | foreach {
    
    # Current  Computer
    $SamAccountName = $_.SamAccountName
               
    # Change Owner
    Try   {
            # Define Target
            $TargetObject = Get-ADComputer $SamAccountName 
            $AdsiTarget   = [adsi]"LDAP://$($TargetObject.DistinguishedName)"
 
            # Set new Owner
            $NewOwner = New-Object System.Security.Principal.NTAccount($DAName)
            $AdsiTarget.PSBase.ObjectSecurity.SetOwner($NewOwner)
            $AdsiTarget.PSBase.CommitChanges()

            # Write to event log
            Write-EventLog -LogName Application -Source "HardenAD" -EntryType SuccessAudit -EventId 0 -Category 0 -Message "The computer '$Computer' owner has been refreshed to $DAName"
          }
    Catch {
            # Failed.
            $Code += 1

            # Write to event log
            Write-EventLog -LogName Application -Source "HardenAD" -EntryType FailureAudit -EventId $Code -Category 0 -Message "The computer '$Computer' owner could not be modified to $DAName!"
          }
 
    # Reset ACL
    # Get computer default ACL
    $SchemaNamingContext       = (Get-ADRootDSE).schemaNamingContext
    $DefaultSecurityDescriptor = Get-ADObject -Identity "CN=Computer,$SchemaNamingContext" -Properties defaultSecurityDescriptor | Select-Object -ExpandProperty defaultSecurityDescriptor

    $DescriptionMessage = "Resetting SDDL for computer $SamAccountName"

    $ADObj = Get-ADComputer -Identity $SamAccountName -Properties nTSecurityDescriptor -ErrorVariable GetADObjError

    if ($GetADobjError) 
    { 
        # Failed
        $Code += 10

        # Write to event log
        Write-EventLog -LogName Application -Source "HardenAD" -EntryType FailureAudit -EventId $Code -Category 0 -Message "The computer '$Computer' ntSecurityDescriptor could not be retrieved!"

    }
    Else 
    {
        Try   {
                $ADObj.nTSecurityDescriptor.SetSecurityDescriptorSddlForm( $DefaultSecurityDescriptor )
                Set-ADObject -Identity $ADObj.DistinguishedName -Replace @{ nTSecurityDescriptor = $ADObj.nTSecurityDescriptor } -Confirm:$false
                
                # Write to event log
                Write-EventLog -LogName Application -Source "HardenAD" -EntryType SuccessAudit -EventId 0 -Category 0 -Message "The computer '$Computer' SDDL has been recycled to its default value."

              } 
        Catch {
                #.Failed
                $Code += 100

                # Write to event log
                Write-EventLog -LogName Application -Source "HardenAD" -EntryType FailureAudit -EventId $Code -Category 0 -Message "The computer '$Computer' SDDL could not be refreshed!"

              }
    }
    # Release variable
    $SamAccountName = $null
}

Exit $Code
