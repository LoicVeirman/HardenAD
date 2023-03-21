function Remove-LocalAdminGroup {
    <#
        .SYNOPSIS
         The <Remove-LocalAdminGroup> function is used to move "CGLA" groups that are no longer associated with an enabled or existing computer in the domain.
        .DESCRIPTION
         This function first searches for all "CGLA" groups in the domain and then compares them to existing systems in the same domain.
         If the comparison returns nothing, it means that the computer is disabled or no longer exists. The group is then moved to an "Inactive" OU.
        .NOTES
         This script is private and cannot be used outside the module.
    #>
    
    [CmdletBinding()]
    param (
        [Parameter(
            Mandatory
        )]
        [System.Collections.Hashtable] $Config,
        [Parameter(
            Mandatory = $false
        )]
        [string] $ComputerNameFormatted
    )

    $Log = [LoggerFactory]::CreateLogger()

    if ($ComputerNameFormatted) {
        $GroupName = "$($Config["NAMING"])" -replace "%ComputerName%", $ComputerNameFormatted
        try {
            Get-ADGroup -Identity $GroupName | Remove-ADGroup -Confirm:$false
            $Log.Success(("{0} has been deleted." -f $GroupName))
        }
        catch {
            $Log.Error(("{0} can't be deleted: {1}." -f $GroupName, $_.Exception.Message))
        }
    }
    else {
        $Tiers = @("T0", "T1", "T2", "TLegacy")

        foreach ($Tier in $Tiers) {

            $Computers = $Config["COMPUTERS"] | Where-Object { $_.Enabled }
            $SearchName = $Config["NAMING"] -replace "_%ComputerName", ""
            $ApplicableLocalAdminGroups = Get-ADGroup -Filter { Name -like $SearchName } -SearchBase $Config["LA_$Tier"]
            
            foreach ($Group in $ApplicableLocalAdminGroups) {
        
                $GroupComputerName = ($Group.Name -split "$($SearchName)_")[1]
    
                if ($GroupComputerName -notin $Computers.Name) {
                    try {
                        Remove-ADGroup -Identity $Group -Confirm:$false
                        $Log.Success(("{0} has been successfully deleted." -f $Group.Name))    
                    }
                    catch {
                        $Log.Error(("An error occurred while deleting the object {0}: {1}" -f $Group.Name, $_.Exception.Message))
                    }
                }
            }    
        }    
    }
}