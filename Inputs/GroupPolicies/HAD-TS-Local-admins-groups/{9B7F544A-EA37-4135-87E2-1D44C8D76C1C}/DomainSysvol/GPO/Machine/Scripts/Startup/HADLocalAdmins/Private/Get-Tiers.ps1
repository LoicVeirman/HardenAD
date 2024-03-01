function Get-Tiers {
    <#
        .SYNOPSIS
         The <Get-Tiers> function is used to determine the tier of each machine in the domain. This tier is then used to create the "CGLA" groups in the right location.        .DESCRIPTION
        .DESCRIPTION
         The order of checking is as follows:
            - Is the system disabled?                                   --> N/A
            - Is the system a DC?                                       --> N/A
            - Is the system supported?                                  
                - Yes, it is supported:                                 --> T0/T1/T2
                    - Is it a tier-0 (Belongs to OU T0)                 --> T0
                    - Is it a tier-1? (Belongs to the T1 OU)            --> T1
                    - Is it a tier-2? (Belongs to the T2 OU)            --> T2
                    - Is it a server?                                   --> T1
                    - Is it a workstation?                              --> T2
                - No, it is not supported.                              --> TLegacy        
        .OUTPUTS
         This function returns a string which is used to define the type and the actions to perform.
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
            Mandatory
        )]
        [Microsoft.ActiveDirectory.Management.ADAccount] $Computer
    )
    
    $Log = [LoggerFactory]::CreateLogger()

    $Path = ($Computer.DistinguishedName).Substring(($Computer.DistinguishedName).IndexOf(",") + 1)

    if ($Computer.Enabled -eq $false) {
        $Log.Info("{0} is disabled." -f $Computer.Name)
        continue
    }
    if ($Config["DC"].Name -contains $Computer.Name) {
        $Log.Info("{0} is a Domain Controller." -f $Computer.Name)
        continue
    }


    #On check l'ou en P0
    if ($Path -like "*$($Config["PROD_T2L"].DistinguishedName)") {
        $Log.Info("{0} is a T1-Legacy system." -f $Computer.Name)
        return "T2L"
    }
    elseif ($Path -like "*$($Config["PROD_T1L"].DistinguishedName)") {
        $Log.Info("{0} is T1-Legacy system." -f $Computer.Name)
        return "T1L"
    }
    elseif ($Path -like "*$($Config["PROD_T1"].DistinguishedName)") {
        $Log.Info("{0} is Tier-1 server." -f $Computer.Name)
        return "T1"
    }
    elseif ($Path -like "*$($Config["PROD_T2"].DistinguishedName)") {
        $Log.Info("{0} is Tier-2 Workstation." -f $Computer.Name)
        return "T2"    
    }
    else {
        #.Default value is T0.
        $Log.Info("{0} is T2-Legacy system." -f $Computer.Name)
        return "T0"
    }   

    # On check l'OS en P1 si rien n'a été trouvé précédemment

    if (($Computer.OperatingSystem -like "*Windows 10*") `
            -or ($Computer.OperatingSystem -like "*Windows 11*") `
            -or ($Computer.OperatingSystem -like "*2012*") `
            -or ($Computer.OperatingSystem -like "*2016*") `
            -or ($Computer.OperatingSystem -like "*2019*") `
            -or ($Computer.OperatingSystem -like "*2022*")) {

                if ($Computer.OperatingSystem -like "*Server*") {
                    $Log.Info("{0} is T1-Server." -f $Computer.Name)
                    return "T1"
                }
                else{
                    $Log.Info("{0} is T2-Workstation." -f $Computer.Name)
                    return "T2"
                }

    }
    else {
        if ($Computer.OperatingSystem -like "*Server*") {
            $Log.Info("{0} is T1-Legacy system." -f $Computer.Name)
            return "T1L"
        }
        else {
            $Log.Info("{0} is T2-Legacy system." -f $Computer.Name)
            return "T2L"
        }   
        
    }
    $Log.Error("{0}'s tier could not be determined" -f $Computer.Name)
    return "Tbc"
}