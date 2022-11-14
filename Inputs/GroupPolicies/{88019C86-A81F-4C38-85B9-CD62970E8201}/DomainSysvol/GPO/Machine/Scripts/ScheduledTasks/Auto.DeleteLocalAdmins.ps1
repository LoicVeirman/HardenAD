using module .\Test.HardenTiers.psm1

function Remove-OldGroups {
    param (
        [Parameter(Mandatory = $true)]
        $Config
    )

    $Log = [LoggerFactory]::CreateLogger()

    $ApplicableLocalAdminGroups = Get-ADGroup -Filter { Name -like "*Local-Admins*" } | Where-Object { `
            $_.Name -ne "S_Local-Admins_Servers_T0" -and `
            $_.Name -ne "S_Local-Admins_Workstations" -and `
            $_.Name -ne "S_Local-Admins_Servers_T1" -and `
            $_.Name -ne "S_Local-Admins_Servers_TLegacy" }

    $Computers = $Config["Computers"] | Where-Object { $_.Enabled }
    
    foreach ($LocalAdminGroups in $ApplicableLocalAdminGroups) {
        $FormattedComputerName = ""
        $SplittedGroupName = $LocalAdminGroups.Name.Split("_")
        for ($i = 2; $i -lt $SplittedGroupName.Length; $i++) {
            if ($SplittedGroupName[$i]) {
                $FormattedComputerName += $SplittedGroupName[$i] + "_"
            }
        }
        if ($FormattedComputerName.Substring(0, $FormattedComputerName.Length - 1) -notin $Computers.Name) {
            try {
                Remove-ADGroup -Identity $LocalAdminGroups -Confirm:$false
                $Log.Info(("{0} has been removed" -f $LocalAdminGroups.Name))
            }
            catch {
                $Log.Error(("Error while removing : {0} ({1})" -f $LocalAdminGroups.Name, $_.Exception.Message))
            }
        }
    }
}


[LoggerFactory]::Initialize("C:\_hardenLogs")
$ErrorActionPreference = "Continue"

$Config = @{}

Get-Information $Config
Remove-OldGroups $Config