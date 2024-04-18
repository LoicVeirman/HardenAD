<#
    .SYNOPSIS
    This is a caller to perform a mass check upon all existing computer objects.

    .NOTES
    Script version 01.00 by Loic VEIRMAN - MSSEC / 15th April 2024.
#>

Param()

# Getting data from AD
$DCs   = (Get-ADDomainController -Filter * -Server $ENV:COMPUTERNAME) | ForEach-Object { Get-ADComputer $_.Name }
$Cptrs = Get-ADComputer -Filter * -Server $ENV:COMPUTERNAME 

# Filtering out DCs to get the real test list
$Check = (Compare-Object $Cptrs $DCs).InputObject

# Running the check...
$Code = 0
foreach ($Computer in $Check)
{
    Try {
        $null = .\Set-LocalAdminGroups -ComputerName $Computer.Name
    } Catch {
        $Code++
    }
}
# Exit with code error equal to the amount of failure :)
Exit $Code