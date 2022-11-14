enum LogLevel {
    Debug = 0;
    Info = 1;
    Error = 2;
    Fatal = 3
}

Class LoggerFactory {
    static [int] $Count
    static [String] $LogFolder
    static $Loggers = @{}
    static [LogLevel] $LogLevel = [LogLevel]::Error
    static [string] $Global

    static [Void] Initialize ([String] $LogFolder, [LogLevel] $LogLevel) {
        if (!(Test-Path $LogFolder)) {
            try {
                mkdir $LogFolder
            }
            catch {
                Write-Error "Could not create $LogFolder : " + $_.Exception.Message + ", Exiting"
                exit
            }
        }

        [LoggerFactory]::LogFolder = $LogFolder
        [LoggerFactory]::Global = $LogFolder + "\Global.log"
        [LoggerFactory]::LogLevel = $LogLevel
    }

    static [Void] Initialize ([String] $LogFolder) {
        if (!(Test-Path $LogFolder)) {
            try {
                mkdir $LogFolder
            }
            catch {
                Write-Error "Could not create $LogFolder : " + $_.Exception.Message + ", Exiting"
                exit
            }
        }

        [LoggerFactory]::LogFolder = $LogFolder
        [LoggerFactory]::Global = $LogFolder + "\Global.log"
    }


    static [Logger] CreateLogger() {

        $Caller = (Get-PSCallStack)[1]
        $Path = $Caller.ScriptName.Split("\")
        $Name = $Path[$Path.Count - 1] + "." + $Caller.FunctionName + ":(" + $Caller.ScriptLineNumber + ")"

        if ([LoggerFactory]::Loggers.Contains("$Name")) {
            return [LoggerFactory]::Loggers["$Name"]
        }

        $LogPath = ([LoggerFactory]::LogFolder + "\" + $Caller.FunctionName + ".log")
        [LogLevel]$CurrentLogLevel = [LoggerFactory]::LogLevel
        $GlobalString = [LoggerFactory]::Global

        $res = New-Object Logger $LogPath, $GlobalString, $CurrentLogLevel
        return $res
    }
}

Class Logger {
    [String] $LogFile
    [LogLevel] $LogLevel
    [String] $Global

    Logger ([String]$LogFile, [String]$Global, [LogLevel]$LogLevel) {
        $this.LogFile = $LogFile
        $this.Global = $Global
        $this.LogLevel = $LogLevel
    }

    LogInternal ([String] $Message, [LogLevel] $Level) {

        $Caller = (Get-PSCallStack)[2]
        $Path = $Caller.ScriptName.Split("\")
        $LogName = $Path[$Path.Count - 1] + ":" + $Caller.FunctionName + ":(" + $Caller.ScriptLineNumber + ")"

        $FormattedMessage = $Level.ToString().ToUpper() + ": " + $(Get-Date -UFormat "%m-%d-%Y %T ") + $LogName + " - " + $Message

        Out-File -FilePath $this.LogFile -Append -InputObject $FormattedMessage
        Out-File -FilePath $this.Global -Append -InputObject $FormattedMessage
    }

    Debug([String] $Message) {
        $this.LogInternal($Message, [LogLevel]::Debug)
    }
    Info([String] $Message) {
        $this.LogInternal($Message, [LogLevel]::Info)
    }
    Error([String] $Message) {
        $this.LogInternal($Message, [LogLevel]::Error)
    }
    Fatal([String] $Message) {
        $this.LogInternal($Message + ", Exiting", [LogLevel]::Fatal)
        exit
    }

}

function Get-Information {
    param (
        [Parameter(Mandatory = $true)]
        $Config
    )

    $Config["Prefix"] = "L-S-"
    $Config["Domain"] = Get-ADDomain
    $Config["DCs"] = Get-ADDomainController
    $Config["Computers"] = Get-ADComputer -Filter * -Properties Name, OperatingSystem, DistinguishedName

    
    $Config["OU_T0"] = Get-ADOrganizationalUnit -filter { Name -like "*- Tier 0*" -and Name -notlike "*Administration*" } -SearchBase $Config["Domain"].DistinguishedName -SearchScope OneLevel
    $Config["OU_T12"] = Get-ADOrganizationalUnit -filter { Name -like "*- Tier 1 and 2*" -and Name -notlike "*Administration*" } -SearchBase $Config["Domain"].DistinguishedName -SearchScope OneLevel
    $Config["OU_TLegacy"] = Get-ADOrganizationalUnit -filter { Name -like "*- Tier Legacy*" -and Name -notlike "*Administration*" } -SearchBase $Config["Domain"].DistinguishedName -SearchScope OneLevel
    #$Config["LocalAdminOU"] = Get-ADOrganizationalUnit -Filter { Name -eq "Local-Admins" }

    $Config["LocalAdminOU_T0"] = Get-ADOrganizationalUnit -Filter * -Properties * | Where-Object { $_.DistinguishedName -like "*Local Admins*" -and $_.DistinguishedName -like "*Tier 0*" }
    $Config["LocalAdminOU_T1"] = Get-ADOrganizationalUnit -Filter * -Properties * | Where-Object { $_.DistinguishedName -like "*Local Admins*" -and $_.DistinguishedName -like "*Tier 1*" }
    $Config["LocalAdminOU_T2"] = Get-ADOrganizationalUnit -Filter * -Properties * | Where-Object { $_.DistinguishedName -like "*Local Admins*" -and $_.DistinguishedName -like "*Tier 2*" }
    $Config["LocalAdminOU_TLegacy"] = Get-ADOrganizationalUnit -Filter * -Properties * | Where-Object { $_.DistinguishedName -like "*Local Admins*" -and $_.DistinguishedName -like "*Tier Legacy*" }
}

function Test-Tier0 {
    param(
        [Parameter(Mandatory = $true)]
        $Computer,
        $Config
    )

    $DN = $Computer.DistinguishedName

    if ($DN -like "*$($Config['OU_T0'].DistinguishedName)*") {
        return $true
    }

    return $false
}

function Test-Tier1 {
    param(
        [Parameter(Mandatory = $true)]
        $Computer,
        $Config
    )

    $DN = $Computer.DistinguishedName
    $OS = $Computer.OperatingSystem

    if ($OS -like "*Server*") {
        return $true
    }

    if ($DN -like "*$($Config['OU_T12'].DistinguishedName)*" -and $DN -like "*Servers*") {
        return $true
    }
    return $false
}

function Test-Tier2 {
    param(
        [Parameter(Mandatory = $true)]
        $Computer,
        $Config
    )

    $DN = $Computer.DistinguishedName
    $OS = $Computer.OperatingSystem

    if (($OS -like "*Windows 10*") -or ($OS -like "*Windows 11*") -or ($OS -like "*Windows 8*") -or ($OS -like "*Windows Embedded 8*")) {
        return $True
    }
    if ($DN -like "*$($Config['OU_T12'].DistinguishedName)*" -and $DN -like "*Workstations*") {
        return $True
    }
    return $false
}

function Test-TierLegacy {
    param(
        [Parameter(Mandatory = $true)]
        $Computer,
        $Config
    )

    $Log = [LoggerFactory]::CreateLogger()
    $DN = $Computer.DistinguishedName
    $OS = $Computer.OperatingSystem

    if ($DN -like "*$($Config['OU_TLegacy'].DistinguishedName)*") {
        $Log.Info("$($Config['OU_TLegacy'].DistinguishedName)")
        $Log.Info("Computer is in OU Tlegacy")
        return $True
    }

    if (($OS -like "*2003*") -or ($OS -like "*2008*") -or ($OS -like "*2003*") -or ($OS -like "*2000*") -or ($OS -like "*XP*") -or ($OS -like "*Vista*") -or ($OS -like "*Windows 7*")) {
        $Log.Info("Computer has an old OS")
        return $True
    }
    return $false
}

function Get-Tier {
    param(
        [Parameter(Mandatory = $true)]
        $Computer,
        $Config
    )
    $Log = [LoggerFactory]::CreateLogger()
    if ($Computer.Enabled -eq $false) {
        return "Disabled"
    }
    if ($Computer.DistinguishedName -like "*Domain Controllers*") {
        return "DC"
    }
    if (Test-TierLegacy $Computer $Config) {
        $Log.Info(("{0} is tier Legacy" -f $Computer.Name))
        return "TLegacy"
    }
    if (Test-Tier2 $Computer $Config) {
        $Log.Info(("{0} is tier 2" -f $Computer.Name))
        return "T2"
    }
    if (Test-Tier1 $Computer $Config) {
        $Log.Info(("{0} is tier 1" -f $Computer.Name))
        return "T1"
    }
    if (Test-Tier0 $Computer $Config) {
        $Log.Info(("{0} is tier 0" -f $Computer.Name))
        return "T0"
    }

    return $null
}