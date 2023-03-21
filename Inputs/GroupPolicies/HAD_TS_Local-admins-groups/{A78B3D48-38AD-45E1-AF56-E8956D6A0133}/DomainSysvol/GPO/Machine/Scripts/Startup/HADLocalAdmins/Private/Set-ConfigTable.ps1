function Set-ConfigTable {
    <#
        .SYNOPSIS
         The <Set-ConfigTable> function is used to configure the table used throughout the module once.
        .DESCRIPTION
         This function fills a "Hashtable" defined in the <Start-HardenADLocalGroups> script.
         This Hashtable is called regularly to retrieve configuration items variabilized in the script <Start-HardenADLocalGroups> (CustomParameters for example) 
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
        [System.Collections.Hashtable] $CustomParameters
    )

    $Log = [LoggerFactory]::CreateLogger()

    $Config["NAMING"] = $CustomParameters["Nomenclature for Local Admin groups"]

    try {
        $Config["DOMAIN"] = Get-ADDomain
        $Config["DC"] = Get-ADDomainController -Filter *
        $Log.Success("The domain-specific elements have been loaded correctly.")
    }
    catch {
        $Log.Fatal(("An error occurred while querying the domain.`{0}" -f $_.Exception.Message))
    }

    try {
        $Config["LA_T0"] = Get-ADOrganizationalUnit $CustomParameters["Local Admin's OU for T0 members"]
        $Config["LA_T1"] = Get-ADOrganizationalUnit $CustomParameters["Local Admin's OU for T1 members"]
        $Config["LA_T2"] = Get-ADOrganizationalUnit $CustomParameters["Local Admin's OU for T2 members"]
        $Config["LA_T1L"] = Get-ADOrganizationalUnit $CustomParameters["Local Admin's OU for Legacies servers"]
        $Config["LA_T2L"] = Get-ADOrganizationalUnit $CustomParameters["Local Admin's OU for Legacies Workstations"]

        $Config["PROD_T0"] = Get-ADOrganizationalUnit $CustomParameters["Production OU for T0 members"]
        $Config["PROD_T1"] = Get-ADOrganizationalUnit $CustomParameters["Production OU for T1 members"]
        $Config["PROD_T2"] = Get-ADOrganizationalUnit $CustomParameters["Production OU for T2 members"]
        $Config["PROD_TLegacy"] = Get-ADOrganizationalUnit $CustomParameters["Production OU for TLegacy members"]

       
        $Config["PAW"] = Get-ADOrganizationalUnit $CustomParameters["PAW OU"]
        $Config["PAW_T0"] = Get-ADOrganizationalUnit $CustomParameters["PAW OU for T0"]
        $Config["PAW_T12L"] = Get-ADOrganizationalUnit $CustomParameters["PAW OU for T12L"]

        $Log.Success("All information related to the OUs has been loaded")
    }
    catch {
        $Log.Fatal(("An error occurred while loading the OUs.`{0}" -f $_.Exception.Message))
    }
}