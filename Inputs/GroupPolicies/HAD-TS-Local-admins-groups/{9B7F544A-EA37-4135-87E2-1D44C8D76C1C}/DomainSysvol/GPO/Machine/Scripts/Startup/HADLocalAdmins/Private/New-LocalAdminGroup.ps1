function New-LocalAdminGroup {
    <#
        .SYNOPSIS
         The <New-LocalAdminGroup> function updates the existing groups (in case a T0 becomes a T2 for example).
         Then it creates the missing groups.
        .DESCRIPTION
         The function scans all the computers in the domain, and checks:
            - A group exists for this computer :
                - If yes, the script checks that it is in the right tier.
                - If not, the script creates the group in the right tier.
         If a group is not in the right tier, it is moved to the inactive OU corresponding to its tier and 
         a new group is created, this time in the correct tier.
        .NOTES
         This script is private and cannot be used outside the module.
    #>
    
    [CmdletBinding()]
    param (
        [Parameter(
            Mandatory
        )]
        [System.Collections.Hashtable] $Config
    )

    $Log = [LoggerFactory]::CreateLogger()
    
    $Computers = $Config["COMPUTERS"]

    foreach ($Computer in $Computers) {
        
        $Tier = Get-Tiers $Config $Computer

        $GroupName = $Config["NAMING"] -replace "%ComputerName%", $Computer.Name
        $Description = "Members of this group will become part of the builtin administrators group of {0}." -f $Computer.Name
        $Path = $Config["LA_$Tier"].DistinguishedName

        if ($Tier -eq "Tbc") {
            $Path = $Config["TBC_T0"].DistinguishedName
        }
        <#
        elseif ($Tier -eq "Tbc_Svr") {
            $Path = $Config["TBC_T0_SRV"].DistinguishedName
        }
        elseif ($Tier -eq "Tbc_Wks") {
            $Path = $Config["TBC_T0_WKS"].DistinguishedName
        }
        #>
        
        try {
            New-ADGroup -Name $GroupName -Path $Path -GroupCategory Security -GroupScope DomainLocal -Description $Description
            $Log.Success(("{0} has been created in {1}." -f $GroupName, $Path))
        }
        catch [Microsoft.ActiveDirectory.Management.ADException] {
        }
        catch {
            $Log.Error(("An error occurred when creating the {0} group: {1}" -f $GroupName, $_.Exception.Message))
        }
    }
}