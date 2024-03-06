function Set-HADGroupsTTL {
    # TODO : Add descriptions for each parameter
    [CmdletBinding()]
    param (
        [Parameter()]
        [int] $TTL #,
        # [Parameter()]
        # [switch] $WorkstationOnly,
        # [Parameter()]
        # [switch] $ServerOnly
    )

    [HADGroup]::TTLCompatible = [HADGroup]::CheckTTLPrerequisites()
    
    if (!([HADGroup]::TTLCompatible)) {
        return $false
    }

    [xml] $XML = (Get-Content -Path $PSScriptRoot\..\Configuration.xml)
    [string] $Naming = (($XML.Config.DefaultParameters.Naming) -replace "%ComputerName%", "") + "*"
    [timespan] $DefaultTTL = New-TimeSpan -Days $TTL


    [System.Array] $Groups = Get-ADGroup -Filter { Name -like $Naming } -Properties *
    
    foreach ($Group in $Groups) {
        $GroupObj = [HADGroup]::new($Group)
        $GroupObj.AddTTLToExistingMembers($DefaultTTL)    
    }
    
    
}