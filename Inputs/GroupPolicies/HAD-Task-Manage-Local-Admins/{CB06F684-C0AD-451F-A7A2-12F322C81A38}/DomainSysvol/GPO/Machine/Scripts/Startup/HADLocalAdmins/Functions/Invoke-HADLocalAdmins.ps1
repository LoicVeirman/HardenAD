function Invoke-HADLocalAdmins {
    # [Alias("Ik-HADLA")]
    [CmdletBinding()]
    param (
        [Parameter(
            Mandatory = $false
        )]
        [string] $ComputerName,
        [Parameter(
            Mandatory = $false
        )]
        [switch] $Create,
        [Parameter(
            Mandatory = $false
        )]
        [switch] $Delete,
        [Parameter(
            Mandatory = $false
        )]
        [int] $EventID
    )

    [bool] $Debug = $false
    [bool] $Warnings = $false
    [bool] $Success = $false
    [bool] $Errors = $false

    if ($VerbosePreference -eq "Continue" -or $DebugPreference -eq "Inquire") {
        $Debug = $true
    }

    # TODO: Display parameters in 1st log
    # [string] $Parameters += foreach ($Parameter in $MyInvocation.BoundParameters) {
    #     "$($Parameter.Key): $($Parameter.Item)"
    # }

    # Initiate logs
    $Log = ([HADLogger]::new($Debug, "$PSScriptRoot\..\HardenEngine\HADLogger\LogTable.jsonc")).InitEventViewer("HardenAD", "LocalAdmins").InitHost().InitLogFile("$PSScriptRoot\..\LocalAdmins.log")
    [Harden]::InitializeLog($Log)
    [ADConfig]::Build()

    $Log.NewLog("1", "Local Admins with: EventID: $EventID -- ComputerName: $ComputerName")

    # Write-Host ($MyInvocation.BoundParameters).GetType()

    # Init Config
    [string] $ConfigPath = "$PSScriptRoot\..\Configs\Configuration.xml"
    
    if (Test-Path $ConfigPath) {
        try {
            $ConfigObj = Get-Item $ConfigPath
            [Harden]::InitializeConfiguration($ConfigObj.FullName)
            $Log.NewLog("100", $ConfigObj.BaseName)
        }
        catch {
            $Log.NewLog("101", $ConfigPath)
        }
    }
    else {
        $Log.NewLog("102", $ConfigPath)
        exit
    }

    [System.Array] $Computers = $null
    
    if ($PSBoundParameters.ContainsKey("ComputerName")) {
        $Log.NewLog(10001)
        if ($EventID -eq 5139) {
            $ComputerName = $($ComputerName.Substring(0, $ComputerName.IndexOf(","))).Substring($ComputerName.IndexOf("=") + 1)
        }
        $ComputerName = $ComputerName.Replace("$", "")

        try {
            $Computers = Get-ADComputer -Identity $ComputerName -Properties OperatingSystem
            $Log.NewLog(1020, @($ComputerName, $Computers.DistinguishedName))
        }
        catch {
            $Log.NewLog(1021, $ComputerName)            
        }
    }

    if ($Create -or $EventID -in @(4741, 5139)) {
        
        if (!$Computers) {
            $Log.NewLog(10002)
            # TODO : revoir la séparation Wks/Srv
            # if ($ServerOnly) {
            #     [HADComputer]::ServerOnly = $true
            # }
            # elseif ($WorkstationOnly) {
            #     [HADComputer]::WorkstationOnly = $true
            # }
            try {
                $Computers = Get-ADComputer -Filter * -Properties OperatingSystem
            }
            catch {
                $Log.NewLog(1024)
                exit
            }
        }   

        foreach ($Computer in $Computers) {
            $tmpComputer = [HADComputer]::new($Computer)
            $tmpComputer.UpdateLocalAdminGroup()
        }
    }

    if ($Delete -or $EventID -eq 4743) {
        Write-Host "Enter delete mode"
        if ($ComputerName) {
            Write-Host "with computername : $ComputerName"
            [HADLocalAdminGroup]::RemoveNotMatchingGroups($ComputerName)
        }
        else {
            Write-Host "Without ComputerName"
            [HADLocalAdminGroup]::RemoveNotMatchingGroups()
        }
    }

    if ($Warnings) {
        $Log.NewLog("3", "Local Admins")
    }

    if ($Errors) {
        $Log.NewLog("4", "Local Admins")
    }

    if ($Success) {
        $Log.NewLog("2", "Local Admins")
    }
}