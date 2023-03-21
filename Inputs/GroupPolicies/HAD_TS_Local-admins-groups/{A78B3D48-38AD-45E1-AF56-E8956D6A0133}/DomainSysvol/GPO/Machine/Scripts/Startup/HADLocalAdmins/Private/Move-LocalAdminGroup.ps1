function Move-LocalAdminGroup {
    [CmdletBinding()]
    param (
        [Parameter(
            Mandatory
        )]
        [System.Collections.Hashtable] $Config,
        [Parameter(
            Mandatory
        )]
        [System.Array] $OldDN,
        [Parameter(
            Mandatory
        )]
        [System.Array] $NewDN
    )

    $Log = [LoggerFactory]::CreateLogger()
    
    $Tiers = @(
        "T0"
        "T1"
        "T2"
        "TLegacy"
    )

    $ComputerName = ($OldDN.Split(",")[0]).Substring(($OldDN.Split(",")[0]).IndexOf("=") + 1)

    try {
        $Computer = Get-ADComputer -Identity $ComputerName -Properties *
        $Log.Success(("{0} has been found." -f $ComputerName))
    }
    catch {
        $Log.Fatal(("{0} could not be found in {1}: {2}." -f $ComputerName, $Config["DOMAIN"].DNSRoot, $_.Exception.Message))
    }

    $ComputerTier = Get-Tiers $Config $Computer
    $NewGroupLocation = $Config["LA_$ComputerTier"]

    $OldDN = $OldDN.Substring($OldDN.IndexOf(",") + 1)
    $NewDN = $NewDN.Substring($NewDN.IndexOf(",") + 1)

    if ($OldDN -ne $NewDN) {
        foreach ($Tier in $Tiers) {
            if ($OldDN -like "*$($Config["PROD_$Tier"])") {
                $OldGroup = Get-ADGroup -Identity ("$($Config["NAMING"])" -replace "%ComputerName%", $ComputerName)
            }
        } 
        try {
            Move-ADObject -Identity $OldGroup.DistinguishedName -TargetPath $NewGroupLocation.DistinguishedName
            $Log.Success(("{0} has been moved to {1}." -f $OldGroup.Name, $NewGroupLocation.DistinguishedName))
        }
        catch {
            $Log.Error(("Error encountered while moving {0} into {1}: {2}." -f $OldGroup.DistinguishedName, $NewGroupLocation.DistinguishedName, $_.Exception.Message))
        }
    }   
}