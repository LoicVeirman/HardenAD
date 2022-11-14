using module .\Test.HardenTiers.psm1

function New-LocalAdminsGroups {
    param(
        [Parameter(Mandatory = $true)]
        $Config
    )

    $Log = [LoggerFactory]::CreateLogger()
    $Computers = $Config["Computers"]

    foreach ($Computer in $Computers) {
        $Tier = Get-Tier $Computer $Config
        $GroupName = "L-S-" + $Tier + "_LocalAdmins_Groups_" + $Computer.Name
        switch ($Tier) {
            "DC" {
                Continue
            }
            "Disabled" {
                Continue
            }
            "T0" {
                try {
                    New-ADGroup -Name $GroupName -Path $Config["LocalAdminOU_T0"].DistinguishedName -GroupCategory Security -GroupScope DomainLocal
                    $Log.Info(("{0} has been successfully created" -f $GroupName))
                }
                catch {
                    $Log.Error(("Error while creating {0} ({1})" -f $GroupName, $_.Exception.Message))
                }
            }
            "T1" {
                try {
                    New-ADGroup -Name $GroupName -Path $Config["LocalAdminOU_T1"].DistinguishedName -GroupCategory Security -GroupScope DomainLocal
                    $Log.Info(("{0} has been successfully created" -f $GroupName))
                }
                catch {
                    $Log.Error(("Error while creating {0} ({1})" -f $GroupName, $_.Exception.Message))
                }
            }
            "T2" {
                try {
                    New-ADGroup -Name $GroupName -Path $Config["LocalAdminOU_T2"].DistinguishedName -GroupCategory Security -GroupScope DomainLocal
                    $Log.Info(("{0} has been successfully created" -f $GroupName))
                }
                catch {
                    $Log.Error(("Error while creating {0} ({1})" -f $GroupName, $_.Exception.Message))
                }
            }
            "TLegacy" {
                try {
                    New-ADGroup -Name $GroupName -Path $Config["LocalAdminOU_TLegacy"].DistinguishedName -GroupCategory Security -GroupScope DomainLocal
                    $Log.Info(("{0} has been successfully created" -f $GroupName))
                }
                catch {
                    $Log.Error(("Error while creating {0} ({1})" -f $GroupName, $_.Exception.Message))
                }
            }
        }

    }
}

[LoggerFactory]::Initialize("C:\_hardenLogs")
$ErrorActionPreference = "Continue"

$Config = @{}

Get-Information $Config
New-LocalAdminsGroups $Config
