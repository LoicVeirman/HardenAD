<#
    .SYNOPSIS
    This is a caller to perform a mass check upon all existing computer objects.

    .NOTES
    Script version 01.00 by Loic VEIRMAN - MSSEC / 15th April 2024.
#>

Param()


# FUNCTION: WRITE-DEBUGLOG
# This function will add log information to the debug file. It ensure a proper formating.
Function Write-DebugLog
{
    Param(
        [Parameter(mandatory,Position=0)]
        [ValidateSet("inf","warn","error")]
        [String]
        $EventType,

        [Parameter(mandatory,Position=1)]
        [String]
        $EventMsg
        )

    # Formating Event Type Log
    Switch ($EventType)
    {
        "inf"   { $EventIs = "[INFORMATION]" }
        "warn"  { $EventIs = "[  WARNING  ]" }
        "error" { $EventIs = "[  !ERROR!  ]" }
    }

    # Adding log to array
    $toAppend = @()
    foreach ($line in ($EventMsg -split "`n"))
    {
        $toAppend += "$(Get-Date -Format "yyyy/MM/dd hh:mm:ss")`t$EventIs`t$line"
    }

    Return $toAppend
}

# FUNCTION: EXPORT-DEBUGLOG
# This function ends the log stack and output it to a file.
Function Export-DebugLog
{
    Param(
        [Parameter(mandatory,position=0)]
        [array]
        $MsgArray,

        [Parameter(mandatory,Position=1)]
        [String]
        $LogFilePath
    )

    $MsgArray += Write-DebugLog inf "--------------------`n###  SCRIPT END  ###`n--------------------"
    $MsgArray | Out-File $LogFilePath -Encoding utf8 -Append

    if (-not((Get-WMIObject win32_operatingsystem).name -like "*2008*")) 
    {
        $Backup = Get-Content $LogFilePath -Tail 10000 
        $Backup | Out-File $LogFilePath -Force -Encoding utf8
    }
}

# STATIC PARTS 
$CurrentDir     = Split-Path -Parent $MyInvocation.MyCommand.Definition
$EventLogName   = "Application"
$EventLogSource = 'HardenAD_{0}' -f $MyInvocation.MyCommand
$DebugFileName  = 'Debug_{0}.log' -f $MyInvocation.MyCommand
$DebugFile      = "$($CurrentDir)\$($DebugFileName)"
$Code = 4

# PREPARE FOR LOGGING: EVENTVWR IS USED FOR TRACKING ACTIVITIES, WHEREAS DEBUGFILE IS USED FOR SCRIPT MAINTENANCE.
# First, we initiate the debug array. This one will be output to the file once the script is over.
$debugMessage  = @()
$debugMessage += Write-DebugLog inf "--------------------`n### SCRIPT START ###`n--------------------"

# Secondly, ensure we are running as administrator
if ((New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
{
    $debugMessage += Write-DebugLog inf "RUN AS ADMINISTRATOR: True"
} Else {
    $debugMessage += Write-DebugLog inf "RUN AS ADMINISTRATOR: false"
    Write-Error "The script should be ran in the administrator context."
    Export-DebugLog $debugMessage $DebugFile
    Exit $Code++
}


# Thirdly, we ensure that the event log is ready to catch our event. To do so, we forcefully recreate the event source and trap the error if already existing.
Try {
    $null = New-EventLog -LogName $EventLogName -Source $EventLogSource -ErrorAction Stop
    $debugMessage += Write-DebugLog inf "EVENT VIEWER: the eventlog name '$eventLogName' has been updated with the source '$eventLogSource'."
} Catch {
    $debugMessage += Write-DebugLog inf "EVENT VIEWER: the eventlog name '$EventLogName' has already been set with the source '$EventLogSource'."
}

# Load the xml conf file to retrieve datas
try {
    $domainName = (Get-ADDomain).DNSRoot
    $hardenNetlogonPath = Join-Path -Path "\\$domainName" -ChildPath "SYSVOL\$domainName\scripts\HardenAD\HAD-TS-Local-admins-groups\Set-LocalAdminGroups"
    $debugMessage += Write-DebugLog inf "[NETLOGON HARDEN PATH : $hardenNetlogonPath]"
}
catch {
    $debugMessage += Write-DebugLog error "Could not Find NETLOGON FOLDER : $hardenNetlogonPath"
    $debugMessage += Write-DebugLog error "-- > Error detailled: $($Error[0].Exception.Message)"
    Exit $Code++
}
Try {
    $myConfig = [xml](Get-Content "$hardenNetlogonPath\configuration-custom.xml" -Encoding UTF8 -ErrorAction SilentlyContinue)
    $debugMessage += Write-DebugLog inf "File 'configuration-custom.xml' loaded"
} Catch {
    $debugMessage += Write-DebugLog error "File 'configuration-custom.xml' is not accessible!"
    $debugMessage += Write-DebugLog error "-- > Error detailled: $($Error[0].Exception.Message)"  
    Write-EventLog -LogName $EventLogName -Source $EventLogSource -EntryType FailureAudit -EventId 22 -Category 0 -Message "File 'configuration-custom.xml' is not accessible"
    Export-DebugLog $debugMessage $DebugFile
    Exit $Code++
}


# Getting datas from XML conf file
try {
    $prefix = $myConfig.customRuleSet.config.PrefixDomLoc
    $groupNameLA = $prefix + $myConfig.customRuleSet.config.settings.LOCALADMIN.GroupName
    $groupNameRDU = $prefix + $myConfig.customRuleSet.config.settings.RDU.GroupName
    
    $debugMessage += Write-DebugLog inf "Pattern for LocalAdmin group : $groupNameLA*"
    $debugMessage += Write-DebugLog inf "Pattern for LocalRDU group : $groupNameRDU*"
}
catch {
    $debugMessage += Write-DebugLog error "Error when fetching variables from `$myConfig!"
    $debugMessage += Write-DebugLog error "-- > Error detailled: $($Error[0].Exception.Message)"  
    Exit $Code++
}



$DCNames = @()
try {
    $DCComputerObjects = (Get-ADDomainController -Filter * -Server $ENV:COMPUTERNAME -ErrorAction Stop) | ForEach-Object { Get-ADComputer $_.Name -ErrorAction Stop }
    if ($DCComputerObjects) {
        $DCNames = $DCComputerObjects | Select-Object -ExpandProperty Name
    } 
} catch {
    $debugMessage += Write-DebugLog error "Could not retrieve DC"
    $debugMessage += Write-DebugLog error "-- > Error detailled: $($Error[0].Exception.Message)"
    Exit $Code++
}

if ($DCNames.Count -eq 0) {
    $debugMessage += Write-DebugLog error "0 DC found. Stopping"
    Exit $Code++
}


$debugMessage += Write-DebugLog inf "Searching security groups with pattern '$groupNameLA' or '$groupNameRDU' to check if there is a group for a DC"
$groupFilter = "((Name -like '$groupNameLA*') -or (Name -like '$groupNameRDU*')) -and (GroupCategory -eq 'Security')"

try {
    $targetGroups = Get-ADGroup -Filter $groupFilter -Properties Name, DistinguishedName
    if ($targetGroups) {
        $debugMessage += Write-DebugLog inf "$($targetGroups.Count) groups found matching with the pattern"

        foreach ($group in $targetGroups) {
            $currentGroupName = $group.Name
            $groupMatchedForDeletion = $false
            $matchedDcName = $null
            $matchedPattern = $null

            foreach ($dcName in $DCNames) {
                $expectedNameLA = $groupNameLA + $dcName
                $expectedNameRDU = $groupNameRDU + $dcName

                if ($currentGroupName -eq $expectedNameLA) {
                    $groupMatchedForDeletion = $true; $matchedDcName = $dcName; $matchedPattern = $expectedNameLA; break
                }
                if ($currentGroupName -eq $expectedNameRDU) {
                    $groupMatchedForDeletion = $true; $matchedDcName = $dcName; $matchedPattern = $expectedNameRDU; break
                }
            }

            if ($groupMatchedForDeletion) {
                 $debugMessage += Write-DebugLog inf "Group '$currentGroupName' corresponding to the pattern'$matchedPattern' (DC '$matchedDcName')."
                 $debugMessage += Write-DebugLog inf "Trying to delete group $currentGroupName' ($($group.DistinguishedName))"
                try {
                    Remove-ADGroup -Identity $group.DistinguishedName -Confirm:$false
                    if($?) {
                        $debugMessage += Write-DebugLog inf "ACTION : Group '$currentGroupName' has been deleted"
                    } else {
                        $debugMessage += Write-DebugLog error "The attempt to delete '$currentGroupName' appears to have failed after execution (check permissions or AD logs)."
                    }
                } catch {
                    $debugMessage += Write-DebugLog error "Error when deleting Group : $currentGroupName"
                    $debugMessage += Write-DebugLog error "-- > Error detailled: $($Error[0].Exception.Message)"
                }
            }
        } 

    } else {
        $debugMessage += Write-DebugLog inf "No groups found starting with '$groupNameLA' ou '$groupNameRDU'."
    }
} catch {
    $debugMessage += Write-DebugLog error "Error when processing groups."
    $debugMessage += Write-DebugLog error "-- > Error detailled: $($Error[0].Exception.Message)"
    Exit $Code++
}









# Getting data from AD
$Cptrs = Get-ADComputer -Filter * -Server $ENV:COMPUTERNAME


# Filtering out DCs to get the real test list
$Check = (Compare-Object $Cptrs $DCComputerObjects).InputObject
# Running the check...
$debugMessage += Write-DebugLog inf "--------------------`n### Starting Set-LocalAdmins script ###`n--------------------"
foreach ($Computer in $Check)
{
    Try {
        $null = .\Set-LocalAdminGroups -ComputerName $Computer.Name
    } Catch {
        $Code++
    }
}
# Exit with code error equal to the amount of failure :)
Export-DebugLog $debugMessage $DebugFile
Exit $Code