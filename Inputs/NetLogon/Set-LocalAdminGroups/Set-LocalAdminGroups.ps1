<#
    .SYNOPSIS
    This script is intended to manage system's local administrator group membership.

    .DESCRIPTION
    When a windows computer object is joined to the domain, a GPO will apply to fillup the builtin\administrator group with a dedicated domainLocal group (L-S-LocalAdmins-%ComputerName%).
    If the group does not exists, then an attackant with a right to create a group in AD will be able to sneak into the system by granting himself the local admin rights (and even move to another system in another tier). To circumvent this risk, this script is ran through a Task Schedule that will operate each time a computer object is created, modified or deleted - the schedule runs on every DC.

    ** How does the script works?
    The script receive from the event triggered the computer name to deal with:
    > First of all, the script will ensure if this is a Windows System or not. 
    > Secondly, the script will look for the group object and define if it will have to be created or not.
    > Thirdly, the script identify the computer as server or a station (only for Windows OS) OR protect it by adding it to the Tier 0 (Unknown OS).
    > Fourth, the script check if the systems belong to PAW or TIER 0 (special use case)
    > Fifth,  the script create or move the group to the correct location.

    ** How PAW is identified?
    A PAW is identified by the distinguished name (DN) of the computer object.
    To detect if the is the DN match the PAW main OU, the script use an XML file containing relevant information from the TasksSequence_HardenAD.xml file - created on script deployment. The group is then stored as a TIER 0 Protected group. 
    
    XML Reference: Settings/Translation/WellKnownID --> %OU-PAW-Acs%, %OU-ADM-PAW-STATIONS-T0%, %OU-ADM-PAW-STATIONS-T12L%


    ** How TIER 0 is identified?
    A TIER 0 is identified by the distinguished name (DN) of the computer object.
    To detect if the is the DN match the TIER 0 main OU, the script use an XML file containing relevant information from the TasksSequence_HardenAD.xml file - created on script deployment. The group is then stored as a TIER 0 Protected group.
    
    XML Reference: Settings/Translation/WellKnownID --> %OU-PRD-T0%
    

    ** How TIER 1 is identified?
    A TIER 1 is identified when the combination of "OS is server" and "OS is not legacy" are filled. The group is then stored as a TIER 1 Protected group.

    ** How TIER 2 is identified?
    A TIER 2 is identified when the combination of "OS is not a server" and "OS is not legacy" are filled. The group is then stored as a TIER 2 Protected group.

    ** How TIER 1 LEGACY is identified?
    A TIER 1 LEGACY is identified when the combination of "OS is server" and "OS is legacy" are filled. The group is then stored as a TIER 1 LEGACY Protected group.

    ** How TIER 2 LEGACY is identified?
    A TIER 2 LEGACY is identified when the combination of "OS is not a server" and "OS is legacy" are filled. The group is then stored as a TIER 2 LEGACY Protected group.

    ** What about NON-WINDOWS systems?
    A NON-WINDOWS system is define when, either:
    > The OperatingSystem attributes is empty or null;
    > The OperatingSystem attributes dos not contains Windows as keyword.
    When such a condition is met, the group will be created to protect a possible system abuse (futur computer to be joined, linux systems using kerberos for authentication, ...). The group is then stored as a TIER 0 Protected group.

    ** How is determined the target path for the group (move/create)?
    The script will compute the target path from the XML file. There is two parts for the computation:
    > First of all, the script computing the common static part of the path: OU=%OU-ADM-LOCALADMINS%,OU=?,OU=%OU-ADM%,%DN%
    > Secondly, the script will replace the question mark (?) by the tier specific group OU: 
      - Tier 0.......: %OU-ADM-Groups-T0%
      - Tier 1.......: %OU-ADM-Groups-T1%
      - Tier 2.......: %OU-ADM-Groups-T2%
      - Tier 1 Legacy: %OU-ADM-Groups-L1%
      - Tier 2 Legacy: %OU-ADM-Groups-L2%

    ** What if I modify my OU structure?
    If you modify your OU structure AFTER the GPO has been deployed (and thus the configuration.xml generated from the TasksSequence_HardenAD.xml file), you'll need to reflect this change to the configuration.xml file.
    The script is able to regenerate the configuration.xml file through a parameter call (see parameters).

    ** Special use-case
    Some of you may not match those default rules that were built for our security model. Hence, we have added a special option to enforce source and target path. 
    I Should tell you more about this but I screwed my nerves last night... So just let me come back later on this ;)

    .PARAMETER ComputerName
    The name of the computer object to deal with.

    .PARAMETER UpdateConfig
    When used, the script will generate the configuration.xml file from the TasksSequence_HardenAD.xml.

    .PARAMETER xmlSourcePath
    Teach the UpdateConfig parameter upon the location of the TasksSequence_HardenAD.xml.

    .PARAMETER CustomRules
    Teach the script to not use the configuration.xml file but configuration-custom.xml. Beware, its content is hand made, hence we can not guarantee this will works as you expect...

    .EXAMPLE
    PS> Set-LocalAdminGroups.ps1 -ComputerName MyComputer

    The script will create or move the group L-S-LocalAdmins_MyComputer to the correct OU. In the case of a move, the group will cleared off all its members.

    .EXAMPLE
    PS> Set-LocalAdminGroups.ps1 -UpdateConfig

    The script will create the configuration.xml file. The source path will be set as ..\..\Configs\TasksSequence_HardenAD.xml.

    .EXAMPLE
    PS> Set-LocalAdminGroups.ps1 -UpdateConfig -xmlSourcePath c:\HAD\Config\TasksSequence_HardenAD.xml

    The script will create the configuration.xml file. The source path will be set as c:\HAD\Configs\TasksSequence_HardenAD.xml.

    .NOTES
    Script version 01.00 by Loic VEIRMAN - MSSEC / 9th April 2024.
    Script version 01.01 by Loic VEIRMAN - MSSEC / 14th August 2024.
#>

Param(
    # Catch Computer name to works on
    [Parameter(Mandatory)]
    [String]
    $ComputerName
)

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
        $toAppend += "$(Get-Date -Format "yyyy/MM/dd HH:mm:ss")`t$EventIs`t$line"
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
$EventLogName   = "Application"
$EventLogSource = 'HardenAD_{0}' -f $MyInvocation.MyCommand
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
} 
Else 
{
    $debugMessage += Write-DebugLog inf "RUN AS ADMINISTRATOR: false"
    Write-Error "The script should be ran in the administrator context."
    Export-DebugLog $debugMessage $DebugFile
    Exit 1
}

# Thirdly, we ensure that the event log is ready to catch our event. To do so, we forcefully recreate the event source and trap the error if already existing.
Try {
    $null = New-EventLog -LogName $EventLogName -Source $EventLogSource -ErrorAction Stop
    $debugMessage += Write-DebugLog inf "EVENT VIEWER: the eventlog name '$eventLogName' has been updated with the source '$eventLogSource'."

} 
Catch {
    $debugMessage += Write-DebugLog inf "EVENT VIEWER: the eventlog name '$EventLogName' has already been set with the source '$EventLogSource'."
}


# RUN THE SCRIPT
$debugMessage += Write-DebugLog inf "ComputerName: '$computerName'."
$debugMessage += Write-DebugLog inf "[CustomRules] called"

# Get Computer AD information
Try {
    $myComputer = Get-ADComputer $ComputerName -Properties OperatingSystem -ErrorAction Stop
    $debugMessage += Write-DebugLog inf "[WORKING ON $($myComputer.Name)]"
} 
Catch {
    $debugMessage += Write-DebugLog error "Could not retrieve computer object $ComputerName"
    Export-DebugLog $debugMessage $DebugFile
    Write-EventLog -LogName $EventLogName -Source $EventLogSource -EntryType FailureAudit -EventId 21 -Category 0 -Message "Could not retrieve computer object $ComputerName. No group created."
    Export-DebugLog $debugMessage $DebugFile
    exit 21
}

# Loading XML configuration
Try {
	$xmlFileName = "configuration-custom.xml"
    $myConfig = [xml](Get-Content .\$xmlFileName -Encoding UTF8 -ErrorAction Stop)
    $debugMessage += Write-DebugLog inf "File 'configuration-custom.xml' loaded"
	
	$xmlFileName = "TasksSequence_HardenAD.xml"
    $TskSqXml = [xml](Get-Content $env:ProgramData\HardenAD\Configuration\$xmlFileName -Encoding UTF8 -ErrorAction Stop)
    $debugMessage += Write-DebugLog inf "File 'tasksSequence_HardenAD.xml' loaded"
} 
Catch {
    $debugMessage += Write-DebugLog error "File '$xmlFileName' is not accessible!"
    Write-EventLog -LogName $EventLogName -Source $EventLogSource -EntryType FailureAudit -EventId 22 -Category 0 -Message "One or More configuration File is not readable`n`n$($_.ToString())"
    Export-DebugLog $debugMessage $DebugFile
    Exit 22
}

# Build Sources Pattern...
$Sources = Select-Xml $myConfig -XPath "//sources/source" | Select-Object -ExpandProperty "Node"
$debugMessage += Write-DebugLog inf "Found $($Sources.count) Source as source identity."

# Checking to which tier the computer belong...
$debugMessage += Write-DebugLog inf "Analyzing: $($myComputer.DistinguishedName)"

# Check for a match...
$srcFound = $false
foreach ($Source in $Sources)
{
    $SourcednPattern = $Source.dnPattern
    # Translating Raw data
    foreach ($Translation in $TskSqXml.Settings.Translation.wellKnownID) { $SourcednPattern = $SourcednPattern.replace($Translation.TranslateFrom,$Translation.TranslateTo) }
    # translating TranslateTo to match ref. to TranslateFrom.
    foreach ($Translation in $TskSqXml.Settings.Translation.wellKnownID) { $SourcednPattern = $SourcednPattern.replace($Translation.TranslateFrom,$Translation.TranslateTo) }

    # Compare dnPattern to Computer DN. If match, exit.
    if ($myComputer.DistinguishedName -match $SourcednPattern)
    {
        $debugMessage += Write-DebugLog inf "DN PATTERN: matching with $($SourcednPattern)"
        # Second level of check: osPattern (if any)
        if ($myComputer.OperatingSystem -match $Source.osPattern)
        {
            $debugMessage += Write-DebugLog inf "OS PATTERN: matching with $($Source.osPattern)"
            # Third level: is it a legacy OS?
            if ($myComputer.OperatingSystem -match "Windows")
            {
                $debugMessage += Write-DebugLog inf "OS PATTERN: detected as a Windows system"
                # Legacy is different for servers and clients. We use the common base "serv" (from servers and serveurs) to identify a server OS.
                switch ($myComputer.OperatingSystem -match 'serv')
                {
                    $true {
                        $debugMessage += Write-DebugLog inf "OS PATTERN: detected as a Windows server (OperatingSystem matching 'serv')"
                        $osMaj = [int]$myConfig.customRuleSet.default.operatingSystems.supported.server.MajorVersion
                        $osMin = [int]$myConfig.customRuleSet.default.operatingSystems.supported.server.MinorVersion
                    }
                    $false {
                        $debugMessage += Write-DebugLog inf "OS PATTERN: detected as a Windows client (OperatingSystem not matching 'serv'.)"
                        $osMaj = [int]$myConfig.customRuleSet.default.operatingSystems.supported.client.MajorVersion
                        $osMin = [int]$myConfig.customRuleSet.default.operatingSystems.supported.client.MinorVersion
                    }
                }
                # Comparing existing value...
                $CptrOSver = ($myComputer.OperatingSystemVersion -split ' ')[0] -split '\.'
                if ([int]$CptrOSver[0] -lt $osMaj -or ([int]$CptrOSver[0] -eq $osMaj -and [int]$CptrOSver[1] -lt $osMin))
                {
                    # is Legacy
                    $debugMessage += Write-DebugLog warn "OS VERSION: legacy OS detected (MajorVersion=$($CptrOSver[0]) vs $osMaj, MinorVersion=$($CptrOSver[1]) vs $osMin)"
                    $debugMessage += Write-DebugLog warn "OS VERSION: [debug: <target='$($Source.target)' targetLegacy='$($Source.Legacytarget)'>]"
                    if ($Source.LegacyTarget -ne "" -and $Source.LegacyTarget -ne $null)
                    {
                        $myTarget = $Source.LegacyTarget
                    } Else {
                        $myTarget = $Source.Target
                    }
                } Else {
                    $debugMessage += Write-DebugLog inf "OS VERSION: modern OS detected (MajorVersion=$($CptrOSver[0]) vs $osMaj, MinorVersion=$($CptrOSver[1]) vs $osMin)"
                    $myTarget = $Source.target
                }
            } Else {
                # Not a windows, we don't manage legacy use case here.
                $debugMessage += Write-DebugLog inf "OS VERSION: unknown OS or unjoined Windows computer detect"
                $myTarget = $Source.target
            }
            $srcFound = $true
            $debugMessage += Write-DebugLog inf "TARGET....: <$myTarget>"
            break
        }
    }
}
# A target is maybe found, but does it means that the <targets><myTarget> section exists? 
if ($srcFound)
{
    Try {
        $xmlTarget = Select-Xml $myConfig -XPath "//targets/$($myTarget)" -ErrorAction Stop | Select-Object -ExpandProperty "Node"
        $debugMessage += Write-DebugLog inf "TARGET....: xml data catche successfully"
    } 
    Catch {
        $debugMessage += Write-DebugLog error "TARGET....: ERROR! Could not grab the xml data!"
        Export-DebugLog $debugMessage $DebugFile
        Write-EventLog -LogName $EventLogName -Source $EventLogSource -EntryType FailureAudit -EventId 99 -Category 0 -Message "TARGET....: ERROR! Could not grab the xml data!"   
        Exit 99
    }
    if ($xmlTarget.count -eq 0) 
    {
        # Not found!
        $debugMessage += Write-DebugLog error "TARGET....: <$myTarget> exists? FALSE! the default target will be use. Note: the target detection is case sensitive."
        $myTarget = $null
    } Else {
        $debugMessage += Write-DebugLog inf "TARGET....: <$myTarget> exists? True."
    }
}
# Loop is done. Do we have found a target, or do we have to use the default one?
if ($srcFound)
{
    # Reading data from expected target.
    $GroupName = $xmlTarget.name
    $GroupDesc = $xmlTarget.description
    $GroupPath = $xmlTarget.path
    $GroupCate = $xmlTarget.category
    $GroupScop = $xmlTarget.scope
} Else {
    # Reading data from default target.
    $xmlTarget = Select-Xml $myConfig -XPath "//default/target" | Select-Object -ExpandProperty "Node"
    $GroupName = $xmlTarget.name
    $GroupDesc = $xmlTarget.description
    $GroupPath = $xmlTarget.path
    $GroupCate = $xmlTarget.category
    $GroupScop = $xmlTarget.scope
}
# Translating... 2 times (RAWX the TranslateTo with ref. to TranslateFrom)
foreach  ($translation in $TskSqXml.settings.Translation.wellKnownID)
{
    $GroupName = $GroupName -replace $translation.TranslateFrom, $translation.TranslateTo
    $GroupDesc = $GroupDesc -replace $translation.TranslateFrom, $translation.TranslateTo
    $GroupPath = $GroupPath -replace $Translation.TranslateFrom, $translation.TranslateTo
}
foreach  ($translation in $TskSqXml.settings.Translation.wellKnownID)
{
    $GroupName = $GroupName -replace $translation.TranslateFrom, $translation.TranslateTo
    $GroupDesc = $GroupDesc -replace $translation.TranslateFrom, $translation.TranslateTo
    $GroupPath = $GroupPath -replace $translation.TranslateFrom, $translation.TranslateTo
}
# Updating with computer name
$GroupName = $GroupName.replace('%ComputerName%',$myComputer.Name)
$GroupDesc = $GroupDesc.replace('%ComputerName%',$myComputer.Name)
# Debug log and clearing xmlTarget
$xmlTarget = $void
$debugMessage += Write-DebugLog inf ">> TARGET DATA:`n>> Group Name......: $GroupName`n>> Description.....: $GroupDesc`n>> Group Category..: $GroupCate`n>> Group Scope.....: $GroupScop`n>> Path............: $GroupPath"

# Time to deal with the group object. 
# First: does the group already exists?
Try {
    $myGroup = Get-ADGroup $GroupName -ErrorAction SilentlyContinue
    $debugMessage += Write-DebugLog inf "Group object exists. the group will be checked."
    $CreateGrp = $false
} 
Catch {
    $debugMessage += Write-DebugLog warn "Group object does not exists. the group will be created."
    $CreateGrp = $true
}
# Dealing the group creation
if ($CreateGrp)
{
    try {
        $void = New-ADGroup -Name $GroupName -SamAccountName $GroupName -DisplayName $GroupName -Description $GroupDesc -GroupCategory $GroupCate -GroupScope $GroupScop -Path $GroupPath
        $debugMessage += Write-DebugLog inf "SUCCESS: the group '$GroupName' has been created in $GroupPath"
        Write-EventLog -LogName $EventLogName -Source $EventLogSource -EntryType SuccessAudit -EventId 0 -Category 0 -Message "SUCCESS: the group '$GroupName' has been created in $GroupPath"
    
    } 
    Catch {
        $debugMessage += Write-DebugLog error "FAILED: the group '$GroupName' could not be created in $GroupePath"
        Write-EventLog -LogName $EventLogName -Source $EventLogSource -EntryType FailureAudit -EventId 23 -Category 0 -Message "Could not create group object '$GroupName' in $GroupPath."   
    }

} Else {
    # Checking if the group is localized at the right place. If not, the group will be moved and flushed of its members.
    $debugMessage += Write-DebugLog inf "Debug: [CurrentPath=$(($myGroup.DistinguishedName).Replace("CN=$($myGroup.Name),",''))]`nDebug: [  GroupPath=$GroupPath]"

    if (($myGroup.DistinguishedName).Replace("CN=$($myGroup.Name),",'') -eq $GroupPath)
    {
        # Nothing to do, the  group object is properly localized.
        $debugMessage += Write-DebugLog inf "NO CHANGE: the group '$GroupName' is already presents in $GroupPath"
        Write-EventLog -LogName $EventLogName -Source $EventLogSource -EntryType SuccessAudit -EventId 0 -Category 0 -Message "NO CHANGE: the group '$GroupName' is already presents in $GroupPath"

    } Else {
        # The group is not present in the right OU. The group will be purged of its members and moved.
        $debugMessage += Write-DebugLog warn "CHANGE DETECTED: the group is not present in the right OU"

        # Clearing membership
        Try {
            $void = $myGroup | Set-ADGroup -Clear member
            $debugMessage += Write-DebugLog inf "The group $GroupName has been cleared from its members."
            Write-EventLog -LogName $EventLogName -Source $EventLogSource -EntryType SuccessAudit -EventId 0 -Category 0 -Message "SUCCESS: the group '$GroupName' has been flushed from its members."
        } 
        Catch {
            $debugMessage += Write-DebugLog error "The group $GroupName has NOT been cleared from its members."
            Write-EventLog -LogName $EventLogName -Source $EventLogSource -EntryType FailureAudit -EventId 24 -Category 0 -Message "ERROR: the group '$GroupName' was not flushed from its members."
        }

        # Moving group to the new OU
        Try {
            $void = Move-ADObject -Identity $myGroup.ObjectGUID -TargetPath $GroupPath
            $debugMessage += Write-DebugLog inf "The group $GroupName has been relocated to $GroupPath."
            Write-EventLog -LogName $EventLogName -Source $EventLogSource -EntryType SuccessAudit -EventId 0 -Category 0 -Message "SUCCESS: the group '$GroupName' has been relocated to $GroupPath."
        } 
        Catch {
            $debugMessage += Write-DebugLog error "The group $GroupName has NOT been relocated to $GroupPath."
            Write-EventLog -LogName $EventLogName -Source $EventLogSource -EntryType FailureAudit -EventId 25 -Category 0 -Message "ERROR: the group '$GroupName' has NOT been relocated to $GroupPath."
        }
    }
}
## Exit
Export-DebugLog $debugMessage $DebugFile
Exit 0
