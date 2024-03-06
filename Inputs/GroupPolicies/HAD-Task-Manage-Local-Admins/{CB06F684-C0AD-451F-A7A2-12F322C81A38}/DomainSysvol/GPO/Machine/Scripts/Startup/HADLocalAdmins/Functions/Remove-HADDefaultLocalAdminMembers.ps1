function Remove-HADDefaultLocalAdminMembers {
    [xml] $XML = (Get-Content $PSScriptRoot\..\Configuration.xml)
    [System.Array] $DefaultGroups = $XML.Config.DefaultParameters.DefaultGroups.DefaultGroup

    foreach ($DefaultGroup in $DefaultGroups) {
        $DefaultGroupObj = [HADGroup]::new($DefaultGroup.Name)
        if ($DefaultGroup.Flush -eq "True") {
            $DefaultGroupObj.Flush()
        }
    }
    
}