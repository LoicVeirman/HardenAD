<#
    .SYNOPSIS
    This script hunt for local admins group which are no more used as the computer objet is inexistant.

    .DESCRIPTION
    On a periodic basis, the script set-lacolAdminsGroups.ps1 create new groups to handles builtin administrators delagation upon systems. This script will ensure that all of those groups are still needed.

    **How does it proceed?
    The script use the configuration.xml file to compute the base name of those group. 
    Then, the script collect all of them through a search, perform a compute of the computer and try to locate it. If the object is not found, the group is deleted.

    **How to use it?
    Just schedule it on one DC at a frequency that best feet your need (every hour is enough).

    .NOTES
    Version 01.00 by Loic VEIRMAN on 2024/04.09.
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
$EventLogSource = "HardenAD_$(($MyInvocation.MyCommand) -replace '.PS1',$Null)"
$DebugFileName  = "Debug_{0}_$(Get-Date -Format yyyyMMddhhmmss).log" -f $MyInvocation.MyCommand
$DebugFile      = "$($env:ProgramData)\HardenAD\Logs\$($DebugFileName)"

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
    Exit 1
}

# Thirdly, we ensure that the event log is ready to catch our event. To do so, we forcefully recreate the event source and trap the error if already existing.
Try {
    $null = New-EventLog -LogName $EventLogName -Source $EventLogSource -ErrorAction Stop
    $debugMessage += Write-DebugLog inf "EVENT VIEWER: the eventlog name '$eventLogName' has been updated with the source '$eventLogSource'."
} Catch {
    $debugMessage += Write-DebugLog inf "EVENT VIEWER: the eventlog name '$EventLogName' has already been set with the source '$EventLogSource'."
}

# Loading XML configuration
$myConfig = [xml](Get-Content .\configuration-custom.xml -Encoding utf8)
$TasksXml = [xml](Get-Content "$($env:ProgramData)\HardenAD\Configuration\TasksSequence_HardenAD.xml" -Encoding utf8)

# Ensure the file is readable
if ($myConfig.customRuleSet)
{
    $debugMessage += Write-DebugLog inf "SUCCESS: the file configuration.xml has been loaded"
} Else {
    $debugMessage += Write-DebugLog error "ERROR: the configuration.xml file is not as expected."
    Write-EventLog -LogName $EventLogName -Source $EventLogSource -EntryType FailureAudit -EventId 2 -Category 0 -Message "ERROR: the configuration.xml file is not as expected. The schedule failed to run."
    Export-DebugLog $debugMessage $DebugFile
    Exit 2
}

# Computing group name filter
$GroupNameFilter = $($myConfig.customRuleSet.default.Target.Name)
# translate raw data
foreach ($translation in $TasksXml.Settings.Translation.wellKnownID) { $GroupNameFilter = $GroupNameFilter -replace $translation.TranslateFrom, $translation.TranslateTo }
# translate TranslateTo when refering to TranslateFrom
foreach ($translation in $TasksXml.Settings.Translation.wellKnownID) { $GroupNameFilter = $GroupNameFilter -replace $translation.TranslateFrom, $translation.TranslateTo }

$GroupNameFilter = $GroupNameFilter -REPLACE '%ComputerName%',$null
$debugMessage += Write-DebugLog INF "GROUP FILTER: $GroupNameFilter"

# Finding groups
$Groups = @()
$TampusFilterus = "$($GroupNameFilter)*"
$Groups += Get-ADGroup -Filter { name -like $TampusFilterus } 
$debugMessage += Write-DebugLog inf "Found $($Groups.Count) groups to control"

# Checking groups Vs computers....
foreach ($group in $Groups)
{
    $debugMessage += Write-DebugLog INF "Working on: $($group.name)"
    $CptrName = ($group.Name).Replace($GroupNameFilter,'')
    $CptrChck = Get-ADObject -Filter { Name -eq $CptrName -and ObjectClass -eq 'computer' }
    
    if ( -not ($CptrChck))
    {
        Try {
            [void](Remove-ADGroup -Identity $group.NAME -Confirm:$false)
            $debugMessage += Write-DebugLog inf "   SUCCESS: the group $($group.name) has been deleted."
            Write-EventLog -LogName $EventLogName -Source $EventLogSource -EntryType SuccessAudit -EventId 0 -Category 0 -Message "SUCCESS: the group $($group.name) has been deleted."
        } Catch {
            $debugMessage += Write-DebugLog error "   FAILED: could not delete the group $($group.name)"
            Write-EventLog -LogName $EventLogName -Source $EventLogSource -EntryType FailureAudit -EventId 11 -Category 0 -Message "FAILED: could not delete the group $($group.name)."
        }
    }
}

## Exit
Export-DebugLog $debugMessage $DebugFile
Exit 0