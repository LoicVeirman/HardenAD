<#
.SYNOPSIS
    This script manages the SMBv1 protocol on Windows systems, allowing granular control over the SMB client and server settings.
.DESCRIPTION
    This script allows granular management of SMBv1. It supports OS starting from Windows Vista / Server 2008.
    It is crucial to test this script in a non-production environment before deploying it.
    A reboot may be required for all changes to take effect.

.PARAMETER Mode
    This setting selects the mode of operation for the script. Possible values are:
    - 'enable': Enables both SMBv1 client and server.
    - 'disable': Disables both SMBv1 client and server. (Recommended for security)
    - 'client': Enables SMBv1 client only and disables SMBv1 server.
    - 'server': Enables SMBv1 server only and disables SMBv1 client.
    - 'audit': Audits current SMBv1 settings without making changes.

.PARAMETER DebugVerbose
    This switch enables verbose logging even if no changes are made. Useful for debugging and auditing purposes.

.EXAMPLE
    .\Manage-SMBv1.ps1 -Mode "disable"
    Disable SMBv1 client and server on the local machine.

.EXAMPLE
    .\Manage-SMBv1.ps1 -Mode "disable" -DebugVerbose
    Disable SMBv1 client and server on the local machine. Verbose logging will be enabled even if no changes are made.

.EXAMPLE
    .\Manage-SMBv1.ps1 -Mode "audit"
    Audit current SMBv1 settings without making any changes. All changes will be logged.


.NOTES
    Author: Hugo Sanchez
    Date: 08/22/2025
    Version: 2.3

    History of changes:
    - 2.3 (08/22/2025): Added DISM fallback feature for Get-WindowsOptionalFeature cmdLet.
    - 2.2 (06/06/2025): Added log rotation and error handling.
    - 2.1 (05/16/2025): Added rollback logic for Set-LanmanWorkstationSMB1ClientState and stopping MrxSmb10.
    - 2.0 (05/23/2025): Major overhaul for clarity, robustness, OS handling, and extended modes.
    - 1.0 (05/02/2025): Initial version.

#>


[CmdletBinding(SupportsShouldProcess=$true)]
param (
    [Parameter(Mandatory=$true, HelpMessage="Operation mode: 'enable', 'disable', 'client', 'server', 'audit'")]
    [ValidateSet('enable', 'disable', 'client', 'server', 'audit')]
    [string]$Mode,


    [Parameter(Mandatory=$false, HelpMessage="Enable verbose file logging even if no changes are made.")]
    [switch]$DebugVerbose
)



################################################
# UTILITY FUNCTIONS
################################################

<#
.SYNOPSIS
    This function writes log entries to a specified log file and optionally to the console.
.DESCRIPTION
    It supports error handling and can write to a specific log path if provided.
.PARAMETER Message
    The message to log.
.PARAMETER IsError
    A switch indicating if the message is an error. If set, the message will be written as a warning.
.PARAMETER SpecificLogPath
    A specific log path to write the message to. If not provided, the default log file path will be used.
.EXAMPLE
    Write-Log -Message "This is a log message." -IsError:$false
    Writes a log message to the default log file and console.
#>
function Write-Log {
    param (
        [string]$Message,
        [switch]$IsError,
        [string]$SpecificLogPath 
    )
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $currentScriptName = if ($Script:ActiveScriptName) { $Script:ActiveScriptName } else { $MyInvocation.MyCommand.Name }
    $logEntry = "[$timestamp][$($currentScriptName)] $Message"
    
    $targetLogPath = $Script:LogFilePath 
    if ($SpecificLogPath -ne $null -and $SpecificLogPath.Trim() -ne "") {
        $targetLogPath = $SpecificLogPath
    }

    if ($IsError) {
        Write-Warning $logEntry
    } else {
        # Only write to console if the log path is not specified or if the message is not a summary of modified settings
        if (($SpecificLogPath -eq $null -or $SpecificLogPath.Trim() -eq "") -and ($targetLogPath -ne $Script:LogFilePath -or $Message -notmatch "SUMMARY OF MODIFIED SETTINGS|Before: .* --> After: ")) { 
            Write-Host $logEntry
        }
    }

    try {
        $logDir = Split-Path -Path $targetLogPath -ErrorAction SilentlyContinue
        if ($logDir -and (-not (Test-Path -Path $logDir))) {
            New-Item -ItemType Directory -Path $logDir -Force -ErrorAction SilentlyContinue | Out-Null
        }
        Add-Content -Path $targetLogPath -Value $logEntry -ErrorAction Stop
    } catch {
        Write-Error "CRITICAL: Could not write to log file '$targetLogPath'. Error: $($_.Exception.Message)"
    }
}



<#
.SYNOPSIS
    This function checks and creates the HardenAD directory with appropriate permissions.
.DESCRIPTION
    This function checks if the HardenAD directory exists and creates it if it does not.
    It also sets the appropriate permissions for the directory to ensure security.
.EXAMPLE
    Check-HardenAD_directory
    Checks if the HardenAD directory exists and creates it if it does not, setting the appropriate permissions.
#>
function Check-HardenAD_directory {
    Write-Log -Message "Verifying/Creating HardenAD directory and permissions..."
    if ($PSCmdlet.ShouldProcess($Script:HardenADPath, "Verify/Create directory and ACLs")) {
        try {
            if (-not (Test-Path $Script:HardenADPath)) {
                Write-Log -Message "Creating directory: $($Script:HardenADPath)"
                New-Item -Name "HardenAD" -Path (Split-Path $Script:HardenADPath) -ItemType Directory -Force -ErrorAction Stop | Out-Null
            }

            $localSystemSid = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-18")
            $administratorsSid = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")
            $authenticatedUsersSid = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-11")

            $acl = Get-Acl $Script:HardenADPath -ErrorAction Stop
            $aceSystem = New-Object System.Security.AccessControl.FileSystemAccessRule($localSystemSid, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
            $aceAdmins = New-Object System.Security.AccessControl.FileSystemAccessRule($administratorsSid, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
            $aceAuthUsers = New-Object System.Security.AccessControl.FileSystemAccessRule($authenticatedUsersSid, "ReadAndExecute", "ContainerInherit,ObjectInherit", "None", "Allow")

            $acl.SetAccessRuleProtection($true, $false)
            $acl.SetOwner($administratorsSid)
            
            $currentRules = $acl.GetAccessRules($true, $true, [System.Security.Principal.NTAccount])
            foreach ($rule in $currentRules) { $acl.RemoveAccessRule($rule) | Out-Null }
            
            $acl.AddAccessRule($aceSystem)
            $acl.AddAccessRule($aceAdmins)
            $acl.AddAccessRule($aceAuthUsers)
            Set-Acl -Path $Script:HardenADPath -AclObject $acl -ErrorAction Stop
            Write-Log -Message "Permissions configured for $($Script:HardenADPath)."

            $logsDir = Join-Path -Path $Script:HardenADPath -ChildPath "Logs"
            if (-not (Test-Path $logsDir)) {
                Write-Log -Message "Creating logs directory: $logsDir"
                New-Item -Name "Logs" -Path $Script:HardenADPath -ItemType Directory -Force -ErrorAction Stop | Out-Null
            }
            Write-Log -Message "HardenAD directory and Logs verified/created successfully."
        } catch {
            Write-Log -Message "Error during HardenAD directory creation/configuration: $($_.Exception.Message)" -IsError
        }
    }
}

################################################
# SMB CONFIGURATION FUNCTIONS
################################################

<#
.SYNOPSIS
    Retrieves the start type of a service or driver from the registry.
.DESCRIPTION
    This function checks the registry for the start type of a specified service or driver.
    It returns a string indicating the start type or "Not Found" if the service does not exist.
.PARAMETER ServiceName
    The name of the service or driver to check.
.EXAMPLE
    Get-ServiceOrDriverStartTypeFromRegistry -ServiceName "LanmanWorkstation"
    Retrieves the start type of the LanmanWorkstation service from the registry.
.EXAMPLE
    Get-ServiceOrDriverStartTypeFromRegistry -ServiceName "MrxSmb10"
    Retrieves the start type of the MrxSmb10 driver from the registry.
#>
function Get-ServiceOrDriverStartTypeFromRegistry {
    param ([string]$ServiceName)
    
    $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"
    if (-not (Test-Path $registryPath)) {
        return "Not Found"
    }
    $startValue = (Get-ItemProperty -Path $registryPath -Name Start -ErrorAction SilentlyContinue).Start
    
    if ($null -ne $startValue) {
        switch ($startValue) {
            0 { return "boot" }     
            1 { return "system" }   
            2 { return "auto" }     
            3 { return "demand" }   
            4 { return "disabled" } 
            default { 
                return "Unknown ($startValue)" 
            }
        }
    } else {
        return "Not Found" 
    }
}

<#
.SYNOPSIS
    Sets the SMB1 client state for LanmanWorkstation and MrxSmb10 service/driver.
.DESCRIPTION
    This function configures the SMB1 client state by modifying the dependencies of the LanmanWorkstation service and the start type of the MrxSmb10 service/driver.
    It can enable or disable SMB1 client functionality based on the provided parameter.
.PARAMETER EnableSMB1Client
    A boolean value indicating whether to enable (true) or disable (false) the SMB1 client.
.EXAMPLE
    Set-LanmanWorkstationSMB1ClientState -EnableSMB1Client $true
    Enables the SMB1 client by configuring LanmanWorkstation and MrxSmb10 service/driver dependencies.
.EXAMPLE
    Set-LanmanWorkstationSMB1ClientState -EnableSMB1Client $false
    Disables the SMB1 client by removing MrxSmb10 from LanmanWorkstation dependencies and setting its start type to disabled.
#>
function Set-LanmanWorkstationSMB1ClientState {
    param (
        [Parameter(Mandatory=$true)]
        [bool]$EnableSMB1Client
    )

    $actionDescription = if ($EnableSMB1Client) { "Enabling" } else { "Disabling" }
    Write-Log -Message "$actionDescription SMB1 client dependencies for LanmanWorkstation and MrxSmb10 service/driver..."
    # Check if the script is running in a ShouldProcess context (e.g., when -WhatIf or -Confirm is used)
    if ($PSCmdlet.ShouldProcess("LanmanWorkstation and MrxSmb10", "Configure SMB1 Client State ($actionDescription)")) {
        # Initialize variable to store original dependencies
        [string[]]$originalLanmanWorkstationDepsArray = @() 
        
        $mrxsmb10ServiceName = "MrxSmb10"
        $mrxsmb20ServiceName = "MRxSmb20"
        
        $dependenciesRestored = $true 
        $startTypeRestored = $true
        # Retrieve the original start type of MrxSmb10 and MrxSmb20 from the registry
        $originalMrxSmb10ScStartType = $Script:BeforeStates["MrxSmb10_StartType"]
        $currentMrxSmb20StartType = $Script:BeforeStates["MrxSmb20_StartType"]

        try {
            # Read the original LanmanWorkstation dependencies from the script's before states
            $originalLanmanWorkstationDepsString = $Script:BeforeStates["LanmanWorkstation_Dependencies"]
            if ($originalLanmanWorkstationDepsString -ne "Not Found/Error" -and $originalLanmanWorkstationDepsString -ne $null -and $originalLanmanWorkstationDepsString.Trim() -ne "") {
                 $tempSplitArray = $originalLanmanWorkstationDepsString.Split(',')
                 foreach ($item_dep in $tempSplitArray) {
                     $trimmed_item_dep = $item_dep.Trim()
                     if ($trimmed_item_dep) { 
                         $originalLanmanWorkstationDepsArray += $trimmed_item_dep
                     }
                 }
            }
            # If the original dependencies are not found, initialize to an empty array
            [string[]]$newLanmanWorkstationDepsArray = @("Bowser", "NSI") 
            # Add mrxsmb20 to the new dependencies array if it exists
            if ($currentMrxSmb20StartType -and $currentMrxSmb20StartType -ne "Not Found") { 
                $newLanmanWorkstationDepsArray += "MRxSmb20"
            } else {
                Write-Log -Message "Warning: $mrxsmb20ServiceName service/driver not found (based on initial StartType read). It will not be added as a dependency for LanmanWorkstation." -IsError
            }
            [string]$newMrxSmb10ScStartTypeTarget = "disabled" 
            # If enabling SMB1 client, check if the OS version supports it and if the service exists. 
            # If so, add it to the dependencies and set the start type to auto.
            if ($EnableSMB1Client) {
                # Check if the OS version is compatible with SMB1 client and if the service exists
                if (($Script:OSMajor -eq 6 -and $Script:OSMinor -le 1)) { 
                    if ($originalMrxSmb10ScStartType -and $originalMrxSmb10ScStartType -ne "Not Found") { 
                        $newLanmanWorkstationDepsArray += "MRxSmb10"
                        Write-Log -Message "Info: Adding $mrxsmb10ServiceName to LanmanWorkstation dependencies for this OS version (OS: $($Script:OSMajor).$($Script:OSMinor))."
                    } else {
                        Write-Log -Message "Warning: $mrxsmb10ServiceName service/driver not found (based on initial StartType read). Cannot add as dependency." -IsError
                    }
                } else { 
                     Write-Log -Message "Info: Not adding $mrxsmb10ServiceName to LanmanWorkstation dependencies for this OS version (OS: $($Script:OSMajor).$($Script:OSMinor)) as per observed behavior."
                }
                $newMrxSmb10ScStartTypeTarget = "auto" 
            }
            $newLanmanWorkstationDepsString = ($newLanmanWorkstationDepsArray | Where-Object { $_ } | Sort-Object -Unique) -join '/' 
            if ($newLanmanWorkstationDepsString -eq $null -or $newLanmanWorkstationDepsString.Trim() -eq "") { 
                $newLanmanWorkstationDepsString = '""' 
            }
            # Check if the original dependencies are already configured as targeted
            $skipLanmanWorkstationDepChange = $false
            $sortedOriginalDeps = $originalLanmanWorkstationDepsArray | Sort-Object -Unique
            $sortedNewDeps = $newLanmanWorkstationDepsArray | Sort-Object -Unique 
            
            $comparisonOutput = Compare-Object -ReferenceObject $sortedOriginalDeps -DifferenceObject $sortedNewDeps -PassThru -SyncWindow 0
            if (-not $comparisonOutput) {
                 Write-Log -Message "LanmanWorkstation dependencies are already configured as targeted ($($newLanmanWorkstationDepsString)). Skipping dependency reconfiguration."
                 $skipLanmanWorkstationDepChange = $true
            } elseif (-not $EnableSMB1Client -and (-not ($originalLanmanWorkstationDepsArray | Where-Object {$_.ToLowerInvariant() -eq "mrxsmb10"}))) {
                 Write-Log -Message "$mrxsmb10ServiceName is already absent from LanmanWorkstation dependencies. Skipping dependency reconfiguration for removal."
                 $skipLanmanWorkstationDepChange = $true
            }
            # If the dependencies are not as targeted, configure them
            if (-not $skipLanmanWorkstationDepChange) {
                Write-Log -Message "Configuring LanmanWorkstation dependencies to: $newLanmanWorkstationDepsString"
                sc.exe config lanmanworkstation depend= $newLanmanWorkstationDepsString 2>&1 | Out-Null
                if ($LASTEXITCODE -ne 0) { throw "sc.exe config lanmanworkstation failed with exit code $LASTEXITCODE." }
            }
            # Configure the start type of MrxSmb10 service/driver based on the EnableSMB1Client parameter
            if ($originalMrxSmb10ScStartType -and $originalMrxSmb10ScStartType -ne "Not Found") { 
                if ($originalMrxSmb10ScStartType -ne $newMrxSmb10ScStartTypeTarget) {
                     Write-Log -Message "Configuring $mrxsmb10ServiceName start type from '$originalMrxSmb10ScStartType' to: $newMrxSmb10ScStartTypeTarget"
                     sc.exe config $mrxsmb10ServiceName start= $newMrxSmb10ScStartTypeTarget 2>&1 | Out-Null
                     if ($LASTEXITCODE -ne 0) { throw "sc.exe config $mrxsmb10ServiceName start= $newMrxSmb10ScStartTypeTarget failed with exit code $LASTEXITCODE." }
                } else {
                    Write-Log -Message "$mrxsmb10ServiceName start type is already $newMrxSmb10ScStartTypeTarget."
                }
            } else {
                 Write-Log -Message "$mrxsmb10ServiceName service/driver not found (based on initial StartType read), no start type configuration applied for it."
            }
            # Check if the MrxSmb20 service/driver exists and configure its start type to auto if it is not already set
            if ($currentMrxSmb20StartType -and $currentMrxSmb20StartType -ne "Not Found") { 
                if ($currentMrxSmb20StartType -ne "auto") {
                    Write-Log -Message "Configuring $mrxsmb20ServiceName start type from '$currentMrxSmb20StartType' to: auto"
                    sc.exe config $mrxsmb20ServiceName start= auto 2>&1 | Out-Null
                    if ($LASTEXITCODE -ne 0) { Write-Log -Message "Warning: sc.exe config $mrxsmb20ServiceName start= auto failed. Code: $LASTEXITCODE." -IsError }
                } else { Write-Log -Message "$mrxsmb20ServiceName is already configured for automatic start." }
            } else {
                 Write-Log -Message "Warning: $mrxsmb20ServiceName service/driver not found (based on initial StartType read). Cannot verify/set to auto." -IsError
            }
            # If disabling SMB1 client, stop the MrxSmb10 service if it is running
            if (-not $EnableSMB1Client) {
                $mrxSmb10ServiceObj = Get-Service $mrxsmb10ServiceName -ErrorAction SilentlyContinue 
                if ($mrxSmb10ServiceObj -and $mrxSmb10ServiceObj.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running) {
                    Write-Log -Message "Stopping $mrxsmb10ServiceName service..."
                    Stop-Service -Name $mrxsmb10ServiceName -Force -ErrorAction SilentlyContinue
                    # Allow a moment for the service to fully stop before re-checking its status
                    Start-Sleep -Seconds 2 
                    $mrxSmb10ServiceObj = Get-Service $mrxsmb10ServiceName -ErrorAction SilentlyContinue
                    if ($mrxSmb10ServiceObj -and $mrxSmb10ServiceObj.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Stopped){
                        Write-Log -Message "$mrxsmb10ServiceName service stopped successfully."
                    } elseif($mrxSmb10ServiceObj) {
                        Write-Log -Message "Failed to stop $mrxsmb10ServiceName service. Current state: $($mrxSmb10ServiceObj.Status). Check status after Reboot" -IsError
                    } else {
                        Write-Log -Message "$mrxsmb10ServiceName service could not be queried by Get-Service after stop attempt (may be a driver not listed by Get-Service)."
                    }
                } elseif ($mrxSmb10ServiceObj) { 
                    Write-Log -Message "$mrxsmb10ServiceName service (from Get-Service) is not running (State: $($mrxSmb10ServiceObj.Status))."
                } elseif ($originalMrxSmb10ScStartType -and $originalMrxSmb10ScStartType -ne "Not Found") { 
                     Write-Log -Message "$mrxsmb10ServiceName (driver) is not running or not manageable by Get-Service. Assuming sc.exe config disabled it."
                }
            }
            Write-Log -Message "LanmanWorkstation/$mrxsmb10ServiceName configuration for SMB1 client ($actionDescription) completed successfully."

        } catch { 
            Write-Log -Message "CRITICAL error during LanmanWorkstation/$mrxsmb10ServiceName configuration: $($_.Exception.Message)" -IsError
            Write-Log -Message "Attempting to restore original configurations..."
            # Restore original configurations if possible
            if ($originalMrxSmb10ScStartType -and $originalMrxSmb10ScStartType -ne "Not Found") { 
                if ((Get-ServiceOrDriverStartTypeFromRegistry -ServiceName $mrxsmb10ServiceName) -ne "Not Found"){ 
                    try {
                        Write-Log -Message "Restoring $mrxsmb10ServiceName start type to: $originalMrxSmb10ScStartType"
                        sc.exe config $mrxsmb10ServiceName start= $originalMrxSmb10ScStartType 2>&1 | Out-Null
                        if ($LASTEXITCODE -ne 0) { Write-Log -Message "FAILED to restore $mrxsmb10ServiceName start type. Code: $LASTEXITCODE" -IsError; $startTypeRestored = $false }
                        else { Write-Log -Message "$mrxsmb10ServiceName start type restored."}
                    } catch { Write-Log -Message "Exception during $mrxsmb10ServiceName start type restoration: $($_.Exception.Message)" -IsError; $startTypeRestored = $false }
                }
            }
            # Restore original LanmanWorkstation dependencies if possible
            $originalDepsStringToRestore = ($originalLanmanWorkstationDepsArray | Where-Object { $_ } | Sort-Object -Unique) -join '/'
            if ($originalDepsStringToRestore -eq $null -or $originalDepsStringToRestore.Trim() -eq "") { 
                 $originalDepsStringToRestore = '""' 
            }
            if ($originalLanmanWorkstationDepsArray.Count -gt 0 -or ($originalLanmanWorkstationDepsArray.Count -eq 0 -and $Script:BeforeStates["LanmanWorkstation_Dependencies"] -ne "Not Found/Error" -and $Script:BeforeStates["LanmanWorkstation_Dependencies"] -ne $null)) {
                try {
                    Write-Log -Message "Restoring LanmanWorkstation dependencies to: $originalDepsStringToRestore"
                    sc.exe config lanmanworkstation depend= $originalDepsStringToRestore 2>&1 | Out-Null
                    if ($LASTEXITCODE -ne 0) { Write-Log -Message "FAILED to restore LanmanWorkstation dependencies. Code: $LASTEXITCODE" -IsError; $dependenciesRestored = $false }
                    else { Write-Log -Message "LanmanWorkstation dependencies restored."}
                } catch { Write-Log -Message "Exception during LanmanWorkstation dependency restoration: $($_.Exception.Message)" -IsError; $dependenciesRestored = $false }
            }

            if ($dependenciesRestored -and $startTypeRestored) { Write-Log -Message "Original configurations (if possible) restored." }
            else { Write-Log -Message "PARTIAL OR TOTAL RESTORATION FAILURE. Manual check required for LanmanWorkstation and $mrxsmb10ServiceName." -IsError }
        } 
    } 
}

<#
.SYNOPSIS
    Configures the SMB server state by modifying the registry or using cmdlets.
.DESCRIPTION
    This function configures the SMB server state by either modifying the registry or using the Set-SmbServerConfiguration cmdlet.
    It can enable or disable SMB1 server functionality based on the provided parameter.
.PARAMETER EnableSMB1Server
    A boolean value indicating whether to enable (true) or disable (false) the SMB1 server.
.EXAMPLE
    Configure-SMBServerStateByRegistry -EnableSMB1Server $true
    Enables the SMB1 server by modifying the registry.
#>
function Configure-SMBServerStateByRegistry {
    param (
        [Parameter(Mandatory=$true)]
        [bool]$EnableSMB1Server
    )
    $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
    $smb1Value = if ($EnableSMB1Server) { 1 } else { 0 }
    $actionDescription = if ($EnableSMB1Server) { "Enabling" } else { "Disabling" }

    Write-Log -Message "$actionDescription SMB1 server via registry..."
    if ($PSCmdlet.ShouldProcess($registryPath, "Configure SMB1 Server ($actionDescription) via registry")) {
        try {
            if (-not (Test-Path $registryPath)) {
                Write-Log -Message "Registry key $registryPath not found. Creating..."
                New-Item -Path $registryPath -Force -ErrorAction Stop | Out-Null
            }
            
            $regItem = Get-ItemProperty -Path $registryPath -ErrorAction SilentlyContinue
            $currentSMB1Value = if ($regItem -and $regItem.PSObject.Properties["SMB1"]) { $regItem.SMB1 } else { $null }
            # Check if the current SMB1 value is different from the desired value
            if ($currentSMB1Value -ne $smb1Value) {
                # Set the SMB1 value in the registry
                Write-Log -Message "Setting $registryPath\SMB1 to $smb1Value."
                Set-ItemProperty -Path $registryPath -Name SMB1 -Type DWORD -Value $smb1Value -Force -ErrorAction Stop
                Write-Log -Message "SMB1 server ($actionDescription) configured via registry."
            } else {
                Write-Log -Message "SMB1 server registry key ($registryPath\SMB1) is already set to $smb1Value."
            }
            # Check and ensure SMB2 is enabled
            $currentSMB2Value = if ($regItem -and $regItem.PSObject.Properties["SMB2"]) { $regItem.SMB2 } else { $null }
            if ($currentSMB2Value -ne 1) {
                Write-Log -Message "Ensuring SMB2 server is enabled via registry ($registryPath\SMB2 = 1)."
                Set-ItemProperty -Path $registryPath -Name SMB2 -Type DWORD -Value 1 -Force -ErrorAction Stop
                Write-Log -Message "SMB2 server verified/enabled via registry."
            } else {
                 Write-Log -Message "SMB2 server registry key ($registryPath\SMB2) is already enabled (1)."
            }
        } catch {
            Write-Log -Message "Error configuring SMB server via registry: $($_.Exception.Message)" -IsError
        }
    }
}

<#
.SYNOPSIS
    Configures the SMB server state using the Set-SmbServerConfiguration cmdlet.
.DESCRIPTION
    This function configures the SMB server state by using the Set-SmbServerConfiguration cmdlet.
    It can enable or disable SMB1 server functionality based on the provided parameter.
.PARAMETER EnableSMB1Server
    A boolean value indicating whether to enable (true) or disable (false) the SMB1 server.
.EXAMPLE
    Configure-SMBServerStateByCmdlet -EnableSMB1Server $true
    Enables the SMB1 server using the Set-SmbServerConfiguration cmdlet.
#>
function Configure-SMBServerStateByCmdlet {
    param (
        [Parameter(Mandatory=$true)]
        [bool]$EnableSMB1Server
    )
    $actionDescription = if ($EnableSMB1Server) { "Enabling" } else { "Disabling" }
    Write-Log -Message "$actionDescription SMB1 server via Set-SmbServerConfiguration cmdlet..."
    
    if ($PSCmdlet.ShouldProcess("SMB Server Configuration", "Configure SMB1 Server ($actionDescription) via cmdlet")) {
        # Check if the cmdlet exists and is available
        try {
            $cmdletExists = Get-Command Set-SmbServerConfiguration -ErrorAction SilentlyContinue
            if (-not $cmdletExists) {
                Write-Log -Message "Cmdlet Set-SmbServerConfiguration not found. This method is not applicable on this OS version." 
                return
            }
            # Retrieve the current SMB server configuration
            $currentConfig = Get-SmbServerConfiguration -ErrorAction SilentlyContinue
            if ($null -eq $currentConfig) {
                Write-Log -Message "Could not retrieve SMB server configuration. The SMBShare module might not be available or an error occurred." -IsError
                return
            }

            if ($currentConfig.EnableSMB1Protocol -ne $EnableSMB1Server) {
                Write-Log -Message "Setting EnableSMB1Protocol to `$($EnableSMB1Server)."
                Set-SmbServerConfiguration -EnableSMB1Protocol $EnableSMB1Server -Confirm:$false -Force -ErrorAction Stop
                Write-Log -Message "SMB1 server ($actionDescription) configured via cmdlet."
            } else {
                Write-Log -Message "SMB1 server is already in the desired state (`$($EnableSMB1Server)) via cmdlet."
            }

            if (-not $currentConfig.EnableSMB2Protocol) {
                Write-Log -Message "Enabling EnableSMB2Protocol (SMB2/3) via cmdlet."
                Set-SmbServerConfiguration -EnableSMB2Protocol $true -Confirm:$false -Force -ErrorAction Stop
                Write-Log -Message "SMB2/3 server enabled via cmdlet."
            }
        } catch {
            Write-Log -Message "Error configuring SMB server via cmdlet: $($_.Exception.Message)" -IsError
        }
    }
}

<#
.SYNOPSIS
    Configures the SMB1 feature on Windows.
.DESCRIPTION

    This function configures the SMB1 feature by enabling or disabling it based on the provided parameters.
    It can also remove the feature if specified when disabling.
.PARAMETER FeatureName
    The name of the Windows feature to configure (e.g., "FS-SMB1").
.PARAMETER EnableFeature
    A boolean value indicating whether to enable (true) or disable (false) the feature.
.PARAMETER RemoveFeatureOnDisable
    A boolean value indicating whether to remove the feature when disabling it. Default is false.
    If set to true, the feature will be completely removed when disabled and installatuin will be impossible without reinstalling the features source.

.EXAMPLE
    Configure-SMB1Feature -FeatureName "FS-SMB1" -EnableFeature $true
    Enables the SMB1 feature on Windows.
.EXAMPLE
    Configure-SMB1Feature -FeatureName "FS-SMB1" -EnableFeature $false -RemoveFeatureOnDisable $true
    Disables and removes the SMB1 feature on Windows.
#>
function Configure-SMB1Feature {
    param (
        [Parameter(Mandatory=$true)]
        [string]$FeatureName, 
        [Parameter(Mandatory=$true)]
        [bool]$EnableFeature,
        [bool]$RemoveFeatureOnDisable = $false 
    )
    $actionDescription = if ($EnableFeature) { "Enabling" } else { "Disabling" }
    $fullAction = if ($EnableFeature) { $actionDescription } else {
        if ($RemoveFeatureOnDisable) { "$actionDescription and Removing" } else { $actionDescription }
    }

    Write-Log -Message "$fullAction Windows feature '$FeatureName'..."
    if ($PSCmdlet.ShouldProcess($FeatureName, "$fullAction Windows feature")) {
        try {
            try {
                # --- ATTEMPT 1: Use PowerShell Cmdlets (Preferred) ---
                $cmdletExists = Get-Command Get-WindowsOptionalFeature -ErrorAction SilentlyContinue
                if (-not $cmdletExists -and ($Script:OSCaption -match "Server")) {
                    Import-Module ServerManager -ErrorAction SilentlyContinue
                    $cmdletExists = Get-Command Get-WindowsOptionalFeature -ErrorAction SilentlyContinue
                }
                if (-not $cmdletExists) { throw "Cmdlet Get/Enable/Disable-WindowsOptionalFeature not found. Cannot proceed with this method." }

                $feature = Get-WindowsOptionalFeature -Online -FeatureName $FeatureName -ErrorAction Stop # Use Stop to trigger catch
                if ($null -eq $feature) {
                    Write-Log -Message "Feature '$FeatureName' not found. It may not be applicable or was already removed."
                    return 
                }

                $isCurrentlyEnabled = ($feature.State -eq "Enabled")
                
                if ($EnableFeature) {
                    if (-not $isCurrentlyEnabled) {
                        Write-Log -Message "Enabling '$FeatureName' via PowerShell cmdlet..."
                        Enable-WindowsOptionalFeature -Online -FeatureName $FeatureName -NoRestart -All -ErrorAction Stop 
                        Write-Log -Message "--> Feature '$FeatureName' enabled. A reboot may be required."
                    } else {
                        Write-Log -Message "--> Feature '$FeatureName' is already enabled."
                    }
                } else { # Disabling feature
                    if ($isCurrentlyEnabled) {
                        Write-Log -Message "Disabling '$FeatureName' via PowerShell cmdlet..."
                        $disableParams = @{ Online = $true; FeatureName = $FeatureName; NoRestart = $true; ErrorAction = 'Stop' }
                        if ($RemoveFeatureOnDisable) {
                             Write-Log -Message "Attempting to completely remove feature '$FeatureName'."
                             $disableParams.Add("Remove", $true)
                        }
                        Disable-WindowsOptionalFeature @disableParams
                        Write-Log -Message "--> Feature '$FeatureName' disabled. A reboot may be required."
                    } else {
                        Write-Log -Message "--> Feature '$FeatureName' is already disabled or in a non-enabled state (e.g., DisablePending, Removed)."
                    }
                }
            }
            catch [System.Runtime.InteropServices.COMException] {
                Write-Log -Message "Warning: PowerShell cmdlet failed with COMException. Falling back to dism.exe for '$FeatureName'." -IsError
                
                # --- ATTEMPT 2: Fallback to dism.exe ---
                $dismOutput = dism.exe /Online /Get-FeatureInfo /FeatureName:$FeatureName
                $stateLine = $dismOutput | Select-String -Pattern "State :"
                $currentState = if ($stateLine) { ($stateLine -split ":")[1].Trim() } else { "Not Found" }
                
                if ($EnableFeature) {
                    if ($currentState -ne "Enabled") {
                        Write-Log -Message "Enabling '$FeatureName' via dism.exe..."
                        $dismArgs = "/Online /Enable-Feature /FeatureName:$FeatureName /All /NoRestart"
                        $process = Start-Process dism.exe -ArgumentList $dismArgs -Wait -NoNewWindow -PassThru
                        if ($process.ExitCode -ne 0 -and $process.ExitCode -ne 3010) { throw "dism.exe failed to enable feature '$FeatureName' with exit code $($process.ExitCode)." }
                        Write-Log -Message "--> Feature '$FeatureName' enabled via dism.exe. A reboot may be required."
                    } else {
                        Write-Log -Message "--> Feature '$FeatureName' is already enabled (checked via dism.exe)."
                    }
                } else { # Disabling feature
                    if ($currentState -eq "Enabled") {
                        Write-Log -Message "Disabling '$FeatureName' via dism.exe..."
                        $dismArgs = "/Online /Disable-Feature /FeatureName:$FeatureName /NoRestart"
                        if ($RemoveFeatureOnDisable) {
                            $dismArgs += " /Remove"
                            Write-Log -Message "Attempting to completely remove feature '$FeatureName' via dism.exe."
                        }
                        $process = Start-Process dism.exe -ArgumentList $dismArgs -Wait -NoNewWindow -PassThru
                        if ($process.ExitCode -ne 0 -and $process.ExitCode -ne 3010) { throw "dism.exe failed to disable feature '$FeatureName' with exit code $($process.ExitCode)." }
                        Write-Log -Message "--> Feature '$FeatureName' disabled via dism.exe. A reboot may be required."
                    } else {
                        Write-Log -Message "--> Feature '$FeatureName' is already disabled or in a non-enabled state (checked via dism.exe)."
                    }
                }
            }
            # Handles other errors from the primary try, or errors from the dism.exe fallback
        } catch {
            $errorMessage = $_.Exception.Message
            $isSourceMissingError = $false
            if ($errorMessage -match "The source files could not be found" -or $errorMessage -match "0x800f081f" -or $errorMessage -match "0x800F0906") { 
                $isSourceMissingError = $true
            }

            if ($isSourceMissingError) {
                Write-Log -Message "--! Error enabling feature '$FeatureName': Installation files are missing. Windows could not find the files needed to complete the requested changes. This often happens if the feature was uninstalled with the '-Remove' option or if the installation source (Windows Update, WSUS, local path) is not accessible or configured. Error details: $errorMessage. Consider using the '-Source' parameter with Enable-WindowsOptionalFeature/DISM if you have a local installation media/image, or ensure your update source can provide these files." -IsError
            } else {
                Write-Log -Message "--! Error configuring feature '$FeatureName': $errorMessage" -IsError
            }
        }
    }
}

<#
.SYNOPSIS
    Captures the current SMB states and configurations.
.DESCRIPTION
    This function captures the current SMB states and configurations, including registry settings, service start types, and feature states.
    It stores the results in a hashtable for further processing or reporting.
.PARAMETER StateContainer
    A hashtable to store the captured SMB states and configurations.
.EXAMPLE
    $smbStates = @{}
    Capture-CurrentSMBStates -StateContainer $smbStates
    This captures the current SMB states and stores them in the $smbStates hashtable.
#>
function Capture-CurrentSMBStates {
    param ([hashtable]$StateContainer)

    $StateContainer.Clear() 
    # --- Section 1 : Common configurations for all OS versions ---
    $lanmanServerParamsPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
    if (Test-Path $lanmanServerParamsPath) {
        $regItem = Get-ItemProperty -Path $lanmanServerParamsPath -ErrorAction SilentlyContinue
        $StateContainer["LanmanServer_SMB1_Registry"] = if ($regItem -and $regItem.PSObject.Properties["SMB1"]) { $regItem.SMB1 } else { "Not Found" }
        $StateContainer["LanmanServer_SMB2_Registry"] = if ($regItem -and $regItem.PSObject.Properties["SMB2"]) { $regItem.SMB2 } else { "Not Found" }
    } else {
        $StateContainer["LanmanServer_SMB1_Registry"] = "Path Not Found"
        $StateContainer["LanmanServer_SMB2_Registry"] = "Path Not Found"
    }

    $lanmanWksPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation"
    $regItemWks = Get-ItemProperty -Path $lanmanWksPath -ErrorAction SilentlyContinue
    $lanmanWksDepsValue = if ($regItemWks -and $regItemWks.PSObject.Properties["DependOnService"]) { $regItemWks.DependOnService } else { $null }
    $StateContainer["LanmanWorkstation_Dependencies"] = if ($lanmanWksDepsValue -ne $null) { ($lanmanWksDepsValue | Sort-Object -Unique) -join ', ' } else { "Not Found or Empty" }

    $StateContainer["MrxSmb10_StartType"] = Get-ServiceOrDriverStartTypeFromRegistry -ServiceName "MrxSmb10"
    $StateContainer["MrxSmb20_StartType"] = Get-ServiceOrDriverStartTypeFromRegistry -ServiceName "MRxSmb20"
    $StateContainer["LanmanServer_StartType"] = Get-ServiceOrDriverStartTypeFromRegistry -ServiceName "LanmanServer"
    $StateContainer["LanmanWorkstation_StartType"] = Get-ServiceOrDriverStartTypeFromRegistry -ServiceName "LanmanWorkstation"


    # --- Section 2: Specific configurations based on OS version ---
    if (($Script:OSMajor -eq 6 -and $Script:OSMinor -ge 2) -or $Script:OSMajor -gt 6) { # Win 8/2012 and newer
        
        # Check for feature cmdlets availability
        $cmdletGetFeaturesExists = $false
        if (Get-Command Get-WindowsOptionalFeature -ErrorAction SilentlyContinue) { $cmdletGetFeaturesExists = $true }
        elseif ($Script:OSCaption -match "Server") { 
            Import-Module ServerManager -ErrorAction SilentlyContinue
            if (Get-Command Get-WindowsOptionalFeature -ErrorAction SilentlyContinue) { $cmdletGetFeaturesExists = $true }
        }

        foreach ($featureNameInLoop in @("SMB1Protocol", "SMB1Protocol-Client", "SMB1Protocol-Server")) {
            $featureState = "Cmdlet Not Available" # Default value
            if ($cmdletGetFeaturesExists) {
                try {
                    # Try preferred method (Get-WindowsOptionalFeature cmdlet)
                    $feature = Get-WindowsOptionalFeature -Online -FeatureName $featureNameInLoop -ErrorAction Stop
                    $featureState = if ($feature) { $feature.State.ToString() } else { "Not Found/Applicable" }
                } 
                catch [System.Runtime.InteropServices.COMException] {
                    Write-Log -Message "Warning: Get-WindowsOptionalFeature failed with COMException for '$featureNameInLoop'. Falling back to dism.exe." -IsError
                    try {
                        $dismOutput = dism.exe /Online /Get-FeatureInfo /FeatureName:$featureNameInLoop
                        $stateLine = $dismOutput | Select-String -Pattern "State :"
                        if ($stateLine) {
                            $featureState = ($stateLine -split ":")[1].Trim() + " (via dism.exe)"
                        } else {
                            $featureState = "Not Found (dism.exe)"
                        }
                    } catch {
                        $featureState = "Error checking with DISM.exe after cmdlet failure."
                        Write-Log -Message "Fallback to dism.exe for '$featureNameInLoop' also failed: $($_.Exception.Message)" -IsError
                    }
                }
                catch {
                    # Catch other non-COM errors
                    $featureState = "Error retrieving state: $($_.Exception.Message)"
                    Write-Log -Message "Failed to get state for feature '$featureNameInLoop': $($_.Exception.Message)" -IsError
                }
            }
            $StateContainer["Feature_$($featureNameInLoop)_State"] = $featureState
        }

        if (Get-Command Get-SmbServerConfiguration -ErrorAction SilentlyContinue) {
            $smbServerConfig = Get-SmbServerConfiguration -ErrorAction SilentlyContinue
            if ($smbServerConfig) {
                $StateContainer["Cmdlet_EnableSMB1Protocol"] = $smbServerConfig.EnableSMB1Protocol.ToString()
                $StateContainer["Cmdlet_EnableSMB2Protocol"] = $smbServerConfig.EnableSMB2Protocol.ToString()
            } else {
                $StateContainer["Cmdlet_EnableSMB1Protocol"] = "Error Retrieving"
                $StateContainer["Cmdlet_EnableSMB2Protocol"] = "Error Retrieving"
            }
        } else {
            $StateContainer["Cmdlet_EnableSMB1Protocol"] = "Cmdlet Not Available"
            $StateContainer["Cmdlet_EnableSMB2Protocol"] = "Cmdlet Not Available"
        }
    } else { # For older OS versions (Win 7/2008 R2 and earlier)
        $StateContainer["Feature_SMB1Protocol_State"] = "N/A (Older OS)"
        $StateContainer["Feature_SMB1Protocol-Client_State"] = "N/A (Older OS)"
        $StateContainer["Feature_SMB1Protocol-Server_State"] = "N/A (Older OS)"
        $StateContainer["Cmdlet_EnableSMB1Protocol"] = "N/A (Older OS)"
        $StateContainer["Cmdlet_EnableSMB2Protocol"] = "N/A (Older OS)"
    }
}


<#
.SYNOPSIS
    Writes a summary of changes made to SMB settings.
.DESCRIPTION
    This function writes a summary of changes made to SMB settings, comparing the before and after states.
    Variables can be set manually or captured using the Capture-CurrentSMBStates function.
    It logs the changes and can export the summary to a CSV file if specified.
.PARAMETER Before
    A hashtable containing the initial state of SMB settings before changes.
.PARAMETER After
    A hashtable containing the final state of SMB settings after changes.
.PARAMETER CsvExportPath
    The path to export the change summary to a CSV file. If not specified, no export will be performed.
.EXAMPLE
    $beforeStates = @{ "LanmanServer_SMB1_Registry" = 0; "LanmanServer_SMB2_Registry" = 1; "Feature_SMB1Protocol_State" = "Disabled" }
    $afterStates = @{ "LanmanServer_SMB1_Registry" = 1; "LanmanServer_SMB2_Registry" = 1; "Feature_SMB1Protocol_State" = "Enabled" }
    Write-ChangeSummary -Before $beforeStates -After $afterStates -CsvExportPath "C:\SMBChangeSummary.csv"
    This writes a summary of changes made to SMB settings and exports it to a CSV file.
#>
function Write-ChangeSummary {
    param(
        [hashtable]$Before,
        [hashtable]$After,
        [string]$CsvExportPath 
    )

    Write-Log -Message "--------------------------------------------------------------------"
    Write-Log -Message "SUMMARY OF MODIFIED SETTINGS"
    Write-Log -Message "--------------------------------------------------------------------"

    $settingsToReport = @(
        @{ Name = "LanmanServer SMB1 Registry (HKLM:\...\Parameters\SMB1)"; Key = "LanmanServer_SMB1_Registry" },
        @{ Name = "LanmanServer SMB2 Registry (HKLM:\...\Parameters\SMB2)"; Key = "LanmanServer_SMB2_Registry" },
        @{ Name = "MrxSmb10 StartType (Registry)"; Key = "MrxSmb10_StartType" },
        @{ Name = "MrxSmb20 StartType (Registry)"; Key = "MrxSmb20_StartType" },
        @{ Name = "LanmanWorkstation Dependencies (Registry)"; Key = "LanmanWorkstation_Dependencies" },
        @{ Name = "Feature 'SMB1Protocol' State"; Key = "Feature_SMB1Protocol_State" },
        @{ Name = "Feature 'SMB1Protocol-Client' State"; Key = "Feature_SMB1Protocol-Client_State" },
        @{ Name = "Feature 'SMB1Protocol-Server' State"; Key = "Feature_SMB1Protocol-Server_State" },
        @{ Name = "Cmdlet 'EnableSMB1Protocol' (SmbServerConfiguration)"; Key = "Cmdlet_EnableSMB1Protocol" },
        @{ Name = "Cmdlet 'EnableSMB2Protocol' (SmbServerConfiguration)"; Key = "Cmdlet_EnableSMB2Protocol" }
    )

    $changedSettingsData = @() 

    $settingColWidth = 60
    $beforeColWidth = 30
    $afterColWidth = 30
    
    $headerLine = "Setting".PadRight($settingColWidth) + " | " + "Before".PadRight($beforeColWidth) + " | " + "After".PadRight($afterColWidth)
    $separatorLine = "-" * $settingColWidth + "-+-" + "-" * $beforeColWidth + "-+-" + "-" * $afterColWidth
    
    Write-Log -Message $headerLine
    Write-Log -Message $separatorLine

    $changesMade = $false # Initialisation
    foreach ($setting in $settingsToReport) {
        $beforeValue = $Before[$setting.Key]
        $afterValue = $After[$setting.Key]
        
        $beforeValueComparable = if ($null -ne $beforeValue) { "$beforeValue" } else { "[null]" }
        $afterValueComparable  = if ($null -ne $afterValue)  { "$afterValue"  } else { "[null]" }

        if ($beforeValueComparable -ne $afterValueComparable) {
            $changesMade = $true # Indicate that at least one change was made
            
            $settingNameDisplay = $setting.Name
            $beforeDisplay = $beforeValueComparable
            $afterDisplay = $afterValueComparable

            if ($settingNameDisplay.Length -gt $settingColWidth) { $settingNameDisplay = $settingNameDisplay.Substring(0, $settingColWidth - 3) + "..." }
            if ($beforeDisplay.Length -gt $beforeColWidth) { $beforeDisplay = $beforeDisplay.Substring(0, $beforeColWidth - 3) + "..." }
            if ($afterDisplay.Length -gt $afterColWidth) { $afterDisplay = $afterDisplay.Substring(0, $afterColWidth - 3) + "..." }

            $logLine = $settingNameDisplay.PadRight($settingColWidth) + " | " + $beforeDisplay.PadRight($beforeColWidth) + " | " + $afterDisplay.PadRight($afterColWidth)
            Write-Log -Message $logLine

            $csvObject = New-Object -TypeName PSObject
            $csvObject | Add-Member -MemberType NoteProperty -Name "Setting" -Value $setting.Name 
            $csvObject | Add-Member -MemberType NoteProperty -Name "Before"  -Value $beforeValueComparable
            $csvObject | Add-Member -MemberType NoteProperty -Name "After"   -Value $afterValueComparable
            $changedSettingsData += $csvObject
        }
    }

    if (-not $changesMade) {
        Write-Log -Message "No tracked settings were modified by the script for the current mode and OS."
    }
    Write-Log -Message $separatorLine 
    Write-Log -Message "--------------------------------------------------------------------"

    # Export to CSV if changes were made and path is provided
    if ($changesMade -and $CsvExportPath -ne $null -and $CsvExportPath.Trim() -ne "") {
        try {
            Write-Log -Message "Exporting change summary to CSV: $CsvExportPath"
            $changedSettingsData | Export-Csv -Path $CsvExportPath -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
            Write-Log -Message "Change summary successfully exported to CSV."
        } catch {
            Write-Log -Message "Error exporting change summary to CSV '$CsvExportPath': $($_.Exception.Message)" -IsError
        }
    } elseif ($changesMade) {
        Write-Log -Message "CSV export path not provided or empty; skipping CSV export of summary."
    }

    # Return whether changes were made
    return $changesMade
}

<#
.SYNOPSIS
    Invokes the SMB configuration audit using pre-captured states.
.DESCRIPTION
    This function performs an audit of the SMB configuration using pre-captured states stored in a hashtable.
    It logs the audit results and displays them on the console.
.PARAMETER CapturedStates
    A hashtable containing the pre-captured states of SMB configurations, including registry settings, service statuses, and feature states.
.EXAMPLE
    $capturedStates = @{
        "LanmanServer_SMB1_Registry" = 0
        "LanmanServer_SMB2_Registry" = 1
        "LanmanWorkstation_Dependencies" = "MRxSmb20"
        "MrxSmb10_StartType" = "Manual"
        "MrxSmb20_StartType" = "Auto"
        "LanmanServer_StartType" = "Auto"
        "LanmanWorkstation_StartType" = "Auto"
    }
    Invoke-SMBConfigurationAudit -CapturedStates $capturedStates
    This performs an audit of the SMB configuration using the provided captured states.
#>
function Invoke-SMBConfigurationAudit {
    param([hashtable]$CapturedStates) 

    Write-Log -Message "Starting SMB Configuration Audit (using pre-captured states)..." -SpecificLogPath $Script:AuditLogFilePath
    Write-Host "`n--- SMB Configuration Audit ---"

    function Audit-Entry { 
        param ([string]$Category, [string]$Detail)
        Write-Log -Message "AUDIT | $Category | $Detail" -SpecificLogPath $Script:AuditLogFilePath
        Write-Host "  $Category : $Detail"
    }

    Audit-Entry "Date" (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
    Audit-Entry "Hostname" $env:COMPUTERNAME
    Audit-Entry "OS Version" $Script:OSCaption
    Audit-Entry "OS Build" $Script:OSVersionObj.ToString()
    Audit-Entry "PowerShell Version" $Script:PSVersionInfo.ToString()

    # --- LanmanServer ---
    $serviceAuditName = "LanmanServer"
    Write-Host "`n[$serviceAuditName (Server Service)]"
    Write-Log -Message "AUDIT | --- $serviceAuditName Configuration ---" -SpecificLogPath $Script:AuditLogFilePath
    Audit-Entry "Registry SMB1 ($serviceAuditName)" ($CapturedStates["LanmanServer_SMB1_Registry"] | Out-String).Trim()
    Audit-Entry "Registry SMB2 ($serviceAuditName)" ($CapturedStates["LanmanServer_SMB2_Registry"] | Out-String).Trim()
    
    $serviceObj = Get-Service $serviceAuditName -ErrorAction SilentlyContinue 
    if($serviceObj){ Audit-Entry "Service Status ($serviceAuditName)" ($serviceObj.Status | Out-String).Trim() } 
    else { Audit-Entry "Service Status ($serviceAuditName)" "Not Found (Get-Service)." }
    Audit-Entry "Service StartType ($serviceAuditName)" ($CapturedStates["LanmanServer_StartType"] | Out-String).Trim()


    # --- LanmanWorkstation ---
    $serviceAuditName = "LanmanWorkstation"
    Write-Host "`n[$serviceAuditName (Workstation Service)]"
    Write-Log -Message "AUDIT | --- $serviceAuditName Configuration ---" -SpecificLogPath $Script:AuditLogFilePath
    Audit-Entry "Dependencies ($serviceAuditName)" ($CapturedStates["LanmanWorkstation_Dependencies"] | Out-String).Trim()
    $serviceObj = Get-Service $serviceAuditName -ErrorAction SilentlyContinue
    if($serviceObj){ Audit-Entry "Service Status ($serviceAuditName)" ($serviceObj.Status | Out-String).Trim() }
    else { Audit-Entry "Service Status ($serviceAuditName)" "Not Found (Get-Service)." }
    Audit-Entry "Service StartType ($serviceAuditName)" ($CapturedStates["LanmanWorkstation_StartType"] | Out-String).Trim()


    # --- MrxSmb10 ---
    $serviceAuditName = "MrxSmb10"
    Write-Host "`n[$serviceAuditName (SMB1 Client Driver)]"
    Write-Log -Message "AUDIT | --- $serviceAuditName Configuration ---" -SpecificLogPath $Script:AuditLogFilePath
    $serviceObj = Get-Service $serviceAuditName -ErrorAction SilentlyContinue 
    $serviceStartType = $CapturedStates["MrxSmb10_StartType"]
    if($serviceStartType -and $serviceStartType -ne "Not Found"){ 
        Audit-Entry "Driver Exists ($serviceAuditName)" "Yes (Registry Key Found)"
        Audit-Entry "Driver StartType ($serviceAuditName)" ($serviceStartType | Out-String).Trim()
        if($serviceObj){ Audit-Entry "Service Status ($serviceAuditName)" ($serviceObj.Status | Out-String).Trim() }
        else { Audit-Entry "Service Status ($serviceAuditName)" "Not listed by Get-Service (typical for drivers)." }
    } else {
        Audit-Entry "Driver Exists ($serviceAuditName)" "No (Registry Key for StartType not found or error)"
    }

    # --- MrxSmb20 ---
    $serviceAuditName = "MRxSmb20" 
    Write-Host "`n[$serviceAuditName (SMB2/3 Client Driver)]"
    Write-Log -Message "AUDIT | --- $serviceAuditName Configuration ---" -SpecificLogPath $Script:AuditLogFilePath
    $serviceObj = Get-Service $serviceAuditName -ErrorAction SilentlyContinue
    $serviceStartType = $CapturedStates["MrxSmb20_StartType"]
     if ($serviceStartType -and $serviceStartType -ne "Not Found") {
        Audit-Entry "Driver Exists ($serviceAuditName)" "Yes (Registry Key Found)"
        Audit-Entry "Driver StartType ($serviceAuditName)" ($serviceStartType | Out-String).Trim()
        if($serviceObj){ Audit-Entry "Service Status ($serviceAuditName)" ($serviceObj.Status | Out-String).Trim() }
        else { Audit-Entry "Service Status ($serviceAuditName)" "Not listed by Get-Service (typical for drivers)." }
    } else {
        Audit-Entry "Driver Exists ($serviceAuditName)" "No (Registry Key for StartType not found or error)"
    }

    if (($Script:OSMajor -eq 6 -and $Script:OSMinor -ge 2) -or $Script:OSMajor -gt 6) { 
        Write-Host "`n[Windows Optional Features (SMB1) - Modern OS]"
        Write-Log -Message "AUDIT | --- Windows Optional Features (SMB1) - Modern OS ---" -SpecificLogPath $Script:AuditLogFilePath
        Audit-Entry "Feature 'SMB1Protocol' State" ($CapturedStates["Feature_SMB1Protocol_State"] | Out-String).Trim()
        Audit-Entry "Feature 'SMB1Protocol-Client' State" ($CapturedStates["Feature_SMB1Protocol-Client_State"] | Out-String).Trim()
        Audit-Entry "Feature 'SMB1Protocol-Server' State" ($CapturedStates["Feature_SMB1Protocol-Server_State"] | Out-String).Trim()

        Write-Host "`n[SMB Server Configuration (Cmdlet) - Modern OS]"
        Write-Log -Message "AUDIT | --- SMB Server Configuration (Cmdlet) - Modern OS ---" -SpecificLogPath $Script:AuditLogFilePath
        Audit-Entry "Cmdlet EnableSMB1Protocol" ($CapturedStates["Cmdlet_EnableSMB1Protocol"] | Out-String).Trim()
        Audit-Entry "Cmdlet EnableSMB2Protocol" ($CapturedStates["Cmdlet_EnableSMB2Protocol"] | Out-String).Trim()
    }
    Write-Host "--- End of Audit ---`n"
    Write-Log -Message "SMB Configuration Audit Completed." -SpecificLogPath $Script:AuditLogFilePath
}



# Main try-catch block to handle script execution and logging
try {
    ################################################
    # GLOBAL VARIABLES
    ################################################
    $Script:HardenADPath = Join-Path -Path $env:SystemDrive -ChildPath "Windows\HardenAD"
    $Script:ActiveScriptName = $MyInvocation.MyCommand.Name
    $Script:LogFilePath = Join-Path -Path $Script:HardenADPath -ChildPath "Logs\$($Script:ActiveScriptName).log"
    $Script:AuditLogFilePath = Join-Path -Path $Script:HardenADPath -ChildPath "Logs\SMB_Audit_$($env:COMPUTERNAME)_$(Get-Date -Format 'yyyyMMddHHmmss').log"
    $Script:TranscriptFilePath = Join-Path -Path $Script:HardenADPath -ChildPath "Logs\Transcript_SMB_Audit_$($env:COMPUTERNAME)_$(Get-Date -Format 'yyyyMMddHHmmss').log"
    $Script:SummaryCsvFilePath = Join-Path -Path $Script:HardenADPath -ChildPath "Logs\SMB_Change_Summary_$($env:COMPUTERNAME)_$(Get-Date -Format 'yyyyMMddHHmmss').csv"


    # Variables to store Before and After states for summary change
    $Script:BeforeStates = @{}
    $Script:AfterStates = @{}
    $Script:TranscriptStartedByThisScript = $false



    # Starting Transcript in case of crash during logging.
    try {
        Start-Transcript -Path $Script:TranscriptFilePath -ErrorAction Stop 
        $Script:TranscriptStartedByThisScript = $true
    } catch {
        if ($_.Exception.Message -match "Transcription has already been started") {
            Write-Warning "Transcript was already running. This script instance will not attempt to stop it. Output may be appended or to a different file if path differs."
        } else {
            Write-Warning "Could not start transcript at '$($Script:TranscriptFilePath)'. Error: $($_.Exception.Message)"
        }
    }


    # OS Information
    try {
        $Script:OSInfo = Get-WmiObject Win32_OperatingSystem -ErrorAction Stop
        $Script:OSVersionObj = [version]$Script:OSInfo.Version
        $Script:OSMajor = $Script:OSVersionObj.Major
        $Script:OSMinor = $Script:OSVersionObj.Minor
        $Script:OSCaption = $Script:OSInfo.Caption
        $Script:PSVersionInfo = $PSVersionTable.PSVersion
    } catch {
        Write-Error "FATAL: Could not retrieve OS or PowerShell version information. Error: $($_.Exception.Message)"
        if ($Script:TranscriptStartedByThisScript) { Stop-Transcript -ErrorAction SilentlyContinue }
        exit 1
    }

    ################################################
    # PREPARATION & INITIAL LOGGING
    ################################################
    Check-HardenAD_directory 

    # --- Log Rotation Check at Startup ---
    try {
        if (Test-Path $Script:LogFilePath) {
            $lineCount = (Get-Content $Script:LogFilePath).Length
            if ($lineCount -gt 10000) {
                # Prepare rotation message before clearing the file
                $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
                $rotationMessage = "[$timestamp][$($Script:ActiveScriptName)] --- LOG ROTATION: Main log file has $lineCount lines (limit is 10000), clearing it before writing new logs. ---"
                
                # Clear the file
                Clear-Content -Path $Script:LogFilePath -ErrorAction Stop
                Add-Content -Path $Script:LogFilePath -Value $rotationMessage
            }
        }
    } catch {
        # If something goes wrong (e.g., permissions), just warn and continue. Don't let log rotation stop the script.
        Write-Warning "Could not perform log rotation check on '$($Script:LogFilePath)'. Error: $($_.Exception.Message)"
    }
    # --- End Log Rotation Check ---


    Write-Log -Message "--------------------------------------------------------------------"
    Write-Log -Message "SCRIPT START - Mode: '$($Mode)' - OS: $($OSCaption) (Version: $($OSVersionObj))"
    Write-Log -Message "Executed as: $(whoami)"
    if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Log -Message "WARNING: Script is not running with Administrator privileges. Exiting..." -IsError
        if ($Script:TranscriptStartedByThisScript) { Stop-Transcript -ErrorAction SilentlyContinue }
        exit 1 
    }

    # Capture initial state ONCE
    Write-Log -Message "Capturing initial SMB configuration state for audit and 'before' snapshot..."
    Capture-CurrentSMBStates -StateContainer $Script:BeforeStates

    # Perform audit using the captured 'BeforeStates'
    Invoke-SMBConfigurationAudit -CapturedStates $Script:BeforeStates


    ################################################
    # MAIN LOGIC BY MODE
    ################################################

    if ($Mode -eq "audit") {
        Write-Log -Message "Mode: AUDIT - Audit already performed. No changes will be made."
    } else { 
        Write-Log -Message "Information : Mode = '$($Mode)' - Starting operations..."
        switch ($Mode) {
            "enable" { 
                # Enable SMB1 based on OS version (Windows 10/Server 2016 and later)
                if ($OSMajor -ge 10) { 
                    Configure-SMB1Feature -FeatureName "SMB1Protocol" -EnableFeature $true
                    Configure-SMB1Feature -FeatureName "SMB1Protocol-Client" -EnableFeature $true
                    Configure-SMB1Feature -FeatureName "SMB1Protocol-Server" -EnableFeature $true
                    Configure-SMBServerStateByCmdlet -EnableSMB1Server $true 
                    Configure-SMBServerStateByRegistry -EnableSMB1Server $true 
                    Set-LanmanWorkstationSMB1ClientState -EnableSMB1Client $true 
                }
                # Enable SMB1 for Windows 8/Server 2012 and later 
                elseif (($OSMajor -eq 6 -and $OSMinor -ge 1) ) { 
                    # For Windows 8/Server 2012 and later, use the feature cmdlet
                    if ($OSMinor -ge 2) { 
                        Configure-SMB1Feature -FeatureName "SMB1Protocol" -EnableFeature $true
                        Configure-SMBServerStateByCmdlet -EnableSMB1Server $true
                        Configure-SMBServerStateByRegistry -EnableSMB1Server $true 
                    } else { 
                        # For Windows 7/Server 2008 R2, use the registry method
                        Configure-SMBServerStateByRegistry -EnableSMB1Server $true 
                    }
                    # Enable SMB1 client state
                    Set-LanmanWorkstationSMB1ClientState -EnableSMB1Client $true
                } elseif ($OSMajor -eq 5) { 
                    # Windows XP/Server 2003
                    Write-Log -Message "Windows XP/Server 2003: SMB1 is enabled by default. No specific enabling action taken by this script."
                } else { 
                    Write-Log -Message "OS Version ($($OSCaption)) not explicitly targeted for full SMB1 enablement by this script logic path. Check OS specific functions." -IsError
                }
            }
            "disable" { 
                # Disable SMB1 based on OS version (Windows 10/Server 2016 and later)
                if ($OSMajor -ge 10) { 
                    Configure-SMBServerStateByRegistry -EnableSMB1Server $false 
                    Configure-SMBServerStateByCmdlet -EnableSMB1Server $false
                    # Disable the feature but do not remove source files (-RemoveFeatureOnDisable $false)
                    # This allows for easier re-enabling later without needing external installation media.   
                    Configure-SMB1Feature -FeatureName "SMB1Protocol" -EnableFeature $false -RemoveFeatureOnDisable $false
                    Set-LanmanWorkstationSMB1ClientState -EnableSMB1Client $false 
                } elseif (($OSMajor -eq 6 -and $OSMinor -ge 1)) { 
                    # For Windows 8/Server 2012 and later, use the feature cmdlet
                    if ($OSMinor -ge 2) { 
                        Configure-SMBServerStateByRegistry -EnableSMB1Server $false 
                        Configure-SMBServerStateByCmdlet -EnableSMB1Server $false   
                        Configure-SMB1Feature -FeatureName "SMB1Protocol" -EnableFeature $false 
                    } else { 
                        # For Windows 7/Server 2008 R2, use the registry method
                        Configure-SMBServerStateByRegistry -EnableSMB1Server $false 
                    }
                    # Disable SMB1 client state
                    Set-LanmanWorkstationSMB1ClientState -EnableSMB1Client $false
                } elseif ($OSMajor -eq 5) { 
                    Write-Log -Message "Windows XP/Server 2003: Disabling SMB1 is not recommended as SMB2 is not natively supported. No action taken." -IsError
                } else {
                    Write-Log -Message "OS Version ($($OSCaption)) not explicitly targeted for SMB1 disablement. Check OS specific functions." -IsError
                }
            }
            "client" { 
                # Configure SMB1 client-only mode based on OS version (Windows 10/Server 2016 and later)
                if ($OSMajor -ge 10) { 
                    Configure-SMBServerStateByRegistry -EnableSMB1Server $false 
                    Configure-SMBServerStateByCmdlet -EnableSMB1Server $false   
                    Configure-SMB1Feature -FeatureName "SMB1Protocol" -EnableFeature $true 
                    Configure-SMB1Feature -FeatureName "SMB1Protocol-Client" -EnableFeature $true
                    Configure-SMB1Feature -FeatureName "SMB1Protocol-Server" -EnableFeature $false 
                    Set-LanmanWorkstationSMB1ClientState -EnableSMB1Client $true
                } elseif (($OSMajor -eq 6 -and $OSMinor -ge 1)) {
                    # For Windows 8/Server 2012 and later, use the feature cmdlet 
                    if ($OSMinor -ge 2) { 
                        Configure-SMBServerStateByRegistry -EnableSMB1Server $false 
                        Configure-SMBServerStateByCmdlet -EnableSMB1Server $false   
                        Configure-SMB1Feature -FeatureName "SMB1Protocol" -EnableFeature $true 
                    } else {
                        # For Windows 7/Server 2008 R2, use the registry method
                        Configure-SMBServerStateByRegistry -EnableSMB1Server $false 
                    }
                    Set-LanmanWorkstationSMB1ClientState -EnableSMB1Client $true
                } elseif ($OSMajor -eq 5) { 
                    # Windows XP/Server 2003
                    Write-Log -Message "Windows XP/Server 2003: SMB1 client-only configuration not applicable via this script." -IsError
                } else {
                    Write-Log -Message "OS Version ($($OSCaption)) not explicitly targeted for this SMB1 client-only mode. Check OS specific functions." -IsError
                }
            }
            "server" { 
                if ($OSMajor -ge 10) { 
                    # For Windows 10/Server 2016 and later, enable SMB1 server-only mode
                    Configure-SMB1Feature -FeatureName "SMB1Protocol" -EnableFeature $true 
                    Configure-SMB1Feature -FeatureName "SMB1Protocol-Server" -EnableFeature $true
                    Configure-SMB1Feature -FeatureName "SMB1Protocol-Client" -EnableFeature $false 
                    Configure-SMBServerStateByCmdlet -EnableSMB1Server $true   
                    Configure-SMBServerStateByRegistry -EnableSMB1Server $true 
                    Set-LanmanWorkstationSMB1ClientState -EnableSMB1Client $false
                } elseif (($OSMajor -eq 6 -and $OSMinor -ge 1)) { 
                    # For Windows 8/Server 2012 and later, use the feature cmdlet
                    if ($OSMinor -ge 2) { 
                        Configure-SMB1Feature -FeatureName "SMB1Protocol" -EnableFeature $true 
                        Configure-SMBServerStateByCmdlet -EnableSMB1Server $true
                        Configure-SMBServerStateByRegistry -EnableSMB1Server $true 
                    } else { 
                        # For Windows 7/Server 2008 R2, use the registry method
                        Configure-SMBServerStateByRegistry -EnableSMB1Server $true 
                    }
                    Set-LanmanWorkstationSMB1ClientState -EnableSMB1Client $false 
                } elseif ($OSMajor -eq 5) { 
                    # Windows XP/Server 2003
                    Write-Log -Message "Windows XP/Server 2003: SMB1 server-only configuration not applicable via this script." -IsError
                } else {
                    Write-Log -Message "OS Version ($($OSCaption)) not explicitly targeted for this SMB1 server-only mode. Check OS specific functions." -IsError
                }
            }
            default { 
                # Unrecognized mode, log an error and exit²
                Write-Log -Message "Unrecognized Mode '$Mode'. Please use 'enable', 'disable', 'client', 'server', or 'audit'." -IsError
                if ($Script:TranscriptStartedByThisScript) { Stop-Transcript -ErrorAction SilentlyContinue }
                exit 1
            }
        }
    }
}
# --- GLOBAL CATCH  ---
catch {
    Write-Log -Message "A TERMINATING ERROR OCCURRED: $($_.Exception.Message)" -IsError
    Write-Log -Message "Script execution halted unexpectedly. Check the transcript for details: $($Script:TranscriptFilePath)" -IsError
}

# --- GLOBAL FINALLY  ---
finally {
    # --- FINALIZATION AND LOG CLEANUP ---
    # Variable to track if any changes were actually made by the script.
    $changesWereFound = $false

    if ($Mode -ne "audit") {
        Write-Log -Message "Capturing SMB configuration state AFTER modifications to generate summary..."
        Capture-CurrentSMBStates -StateContainer $Script:AfterStates
        $changesWereFound = Write-ChangeSummary -Before $Script:BeforeStates -After $Script:AfterStates -CsvExportPath $Script:SummaryCsvFilePath
    }

    Write-Log -Message "SCRIPT END. A system reboot may be required for all changes to take full effect."
    Write-Log -Message "--------------------------------------------------------------------"

    # Stop the transcript before potentially deleting it
    if ($Script:TranscriptStartedByThisScript) {
        Stop-Transcript -ErrorAction SilentlyContinue
    }

    $keepLogFiles = $DebugVerbose.IsPresent -or $changesWereFound -or ($Mode -eq 'audit')
    if (-not $keepLogFiles) {
        Write-Host "No changes were made and -DebugVerbose was not specified. Removing non-essential log files."
        
        if ($Script:TranscriptStartedByThisScript -and (Test-Path $Script:TranscriptFilePath)) {
            try {
                Remove-Item -Path $Script:TranscriptFilePath -Force -ErrorAction Stop
                Write-Host "Removed transcript file: $Script:TranscriptFilePath"
            } catch {
                Write-Warning "Could not remove transcript file: $($_.Exception.Message)"
            }
        }

        # Delete the audit log
        if (Test-Path $Script:AuditLogFilePath) {
            try {
                Remove-Item -Path $Script:AuditLogFilePath -Force -ErrorAction Stop
                Write-Host "Removed audit log file: $Script:AuditLogFilePath"
            } catch {
                Write-Warning "Could not remove audit log file: $($_.Exception.Message)"
            }
        }
    } else {
        Write-Host "Log files are preserved (Verbose mode, changes were made, or audit mode)."
    }
}