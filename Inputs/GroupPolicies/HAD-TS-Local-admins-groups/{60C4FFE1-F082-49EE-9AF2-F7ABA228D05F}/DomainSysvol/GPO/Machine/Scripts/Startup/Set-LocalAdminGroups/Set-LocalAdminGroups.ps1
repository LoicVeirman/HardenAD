<#
    .SYNOPSIS
    This script is intended to manage system's local administrator group membership.

    .DESCRIPTION
    When a windows computer object is joined to the domain, a GPO will apply to fillup the builtin\administrator group with a dedicated domainLocal group (L-S-LocalAdmins_%computername%).
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
    
    XML Reference: Settings/Translation/WellKnownID --> %OU-PAW-Acs%, %OU-PAW-T0%, %OU-PAW-T12L%


    ** How TIER 0 is identified?
    A TIER 0 is identified by the distinguished name (DN) of the computer object.
    To detect if the is the DN match the TIER 0 main OU, the script use an XML file containing relevant information from the TasksSequence_HardenAD.xml file - created on script deployment. The group is then stored as a TIER 0 Protected group.
    
    XML Reference: Settings/Translation/WellKnownID --> %OU-Production-T0%
    

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
    > First of all, the script computing the common static part of the path: OU=%OU-LocalAdmins%,OU=?,OU=%OU-ADM%,%DN%
    > Secondly, the script will replace the question mark (?) by the tier specific group OU: 
      - Tier 0.......: %OU-ADM-Groups-T0%
      - Tier 1.......: %OU-ADM-Groups-T1%
      - Tier 2.......: %OU-ADM-Groups-T2%
      - Tier 1 Legacy: %OU-ADM-Groups-T1L%
      - Tier 2 Legacy: %OU-ADM-Groups-T2L%

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
#>

[CmdletBinding(DefaultParameterSetName = 'RUN')]
Param(
    # Catch Computer name to works on
    [Parameter(ParameterSetName = 'RUN',   Position = 0)]
    [Parameter(ParameterSetName = 'CUSTO', Position = 1)]
    [String]
    $ComputerName,

    # Instrcut to generate the configuration.xml file
    [Parameter(ParameterSetName = 'BUILD', Position = 0)]
    [Switch]
    $UpdateConfig,

    # Indicate where to find the source xml file. If not specified, will consider as ran from the /tools folder.
    [Parameter(ParameterSetName = 'BUILD', Position = 1)]
    [String]
    $xmlSourcePath,

    # Instruct to use configuration-custom.xml instead of configuration.xml.
    [Parameter(ParameterSetName = 'CUSTO', Position = 0)]
    [Switch]
    $CustomRules
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

# FUNCTION: FORMAT-XML
# This function ensure the file is written nicely with tab indentation.
Function Format-XML ([xml]$xml, $indent=1)
{
    $StringWriter = New-Object System.IO.StringWriter
    $XmlWriter = New-Object System.XMl.XmlTextWriter $StringWriter
    $xmlWriter.Formatting = “indented”
    $xmlWriter.Indentation = $Indent
    $xmlWriter.IndentChar = "`t"
    $xml.WriteContentTo($XmlWriter)
    $XmlWriter.Flush()
    $StringWriter.Flush()
    return $StringWriter.ToString()
}

# STATIC PARTS 
$CurrentDir     = Split-Path -Parent $MyInvocation.MyCommand.Definition
$EventLogName   = "Application"
$EventLogSource = 'HardenAD_{0}' -f $MyInvocation.MyCommand
$DebugFileName  = 'Debug_{0}.log' -f $MyInvocation.MyCommand
$DebugFile      = "$($CurrentDir)\$($DebugFileName)"
$myPDC          = (Get-ADDomain).PDCEmulator

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
$debugMessage += Write-DebugLog inf "ComputerName: '$computerName'."

# Debug: is paramater computerName set?

# FIRST CASE: BUILD THE CONFIGURATION FILE
if ($UpdateConfig)
{
    $debugMessage += Write-DebugLog inf "[UpdateConfig] called"
    # Checking if a xml file has been specified.
    if ($xmlSourcePath) 
    {
        $debugMessage += Write-DebugLog inf "The xmlSourcePath has been specified. the script will use the following value: $xmlSourcePath"
     } Else {
        $xmlSourcePath = Convert-Path -LiteralPath "..\..\Configs\TasksSequence_HardenAD.xml"
        $debugMessage += Write-DebugLog warn "NO xmlSourcePath has been specified. the script will use the following value: $xmlSourcePath"
    }
    
    # Checking if the file exist, and if so will ensure this is the one expected.
    if (Test-Path $xmlSourcePath)
    {
        $debugMessage += Write-DebugLog inf "$xmlSourcePath is present"
        # Load file as XML
        Try {
            $SourceXml = [xml](Get-Content $xmlSourcePath -Encoding utf8 -ErrorAction Stop)
        } Catch {
            $debugMessage += Write-DebugLog error "Failed to get content of $xmlSourcePath"
            Write-Error "Failed to get content of $xmlSourcePath"
            Export-DebugLog $debugMessage $DebugFile
            Write-EventLog -LogName $EventLogName -Source $EventLogSource -EntryType FailureAudit -EventId 3 -Category 0 -Message "Could not update configuration.xml: failed to get content of $xmlSourcePath"
            exit 3
        }
        # Ensure this is the expected xml format...
        $CheckXml = $SourceXml.Settings.Translation.WellKnownID

        if ($CheckXml.count -gt 1)
        {
            $debugMessage += Write-DebugLog inf "successfully loaded the source xml file. Retrieving values..."
            
            # Creating the XML file
            Try {
                $XmlWriter = New-Object System.XMl.XmlTextWriter("$CurrentDir\configuration.xml",$null)
                $xmlWriter.Formatting = "indented"
                $xmlWriter.Indentation = 1
                $xmlWriter.IndentChar = "`t"
                $debugMessage += Write-DebugLog inf "new configuration.xml array object created"
            } Catch {
                $debugMessage += Write-DebugLog error "Failed to create the configuration.xml variable"
                Write-Error "Failed to create the configuration.xml variable"
                Export-DebugLog $debugMessage $DebugFile
                Write-EventLog -LogName $EventLogName -Source $EventLogSource -EntryType FailureAudit -EventId 5 -Category 0 -Message "Could not update configuration.xml: Failed to create the configuration.xml variable"
                exit 5
            }
            # Getting value from file...
            $XmlWriter.WriteStartDocument()
            $XmlWriter.WriteComment("Creation timestamp: $(Get-Date -Format 'yyyy/MM/dd at hh:mm:ss')")
            $XmlWriter.WriteStartElement('translation')
            
            # Settings/Translation/WellKnownID --> %OU-PAWAcs%
            $Data = ($SourceXml.Settings.Translation.WellKnownID | Where-Object { $_.TranslateFrom -eq '%OU-PAWAcs%' }).TranslateTo
            $XmlWriter.WriteComment('OU PAW ACCESS')
            $XmlWriter.WriteElementString('OU-PAW-ACCESS',$Data)
            $debugMessage += Write-DebugLog inf "Added to xml: OU-PAW-ACCESS ($data)"
            
            # Settings/Translation/WellKnownID --> %OU-PAW-T0%
            $Data = ($SourceXml.Settings.Translation.WellKnownID | Where-Object { $_.TranslateFrom -eq '%OU-PAW-T0%' }).TranslateTo
            $XmlWriter.WriteComment('OU PAW T0')
            $XmlWriter.WriteElementString('OU-PAW-T0',$Data)
            $debugMessage += Write-DebugLog inf "Added to xml: OU-PAW-T0 ($data)"
            
            # Settings/Translation/WellKnownID --> %OU-PAW-T12L%
            $data = ($SourceXml.Settings.Translation.WellKnownID | Where-Object { $_.TranslateFrom -eq '%OU-PAW-T12L%' }).TranslateTo
            $XmlWriter.WriteComment('OU PAW T12L')
            $XmlWriter.WriteElementString('OU-PAW-T12L',$Data)
            $debugMessage += Write-DebugLog inf "Added to xml: OU-PAW-T12L ($data)"

            # Settings/Translation/WellKnownID --> %OU-Production-T0%
            $Data = ($SourceXml.Settings.Translation.WellKnownID | Where-Object { $_.TranslateFrom -eq '%OU-Production-T0%' }).TranslateTo
            $XmlWriter.WriteComment('OU TIER 0')
            $XmlWriter.WriteElementString('OU-PRD-T0',$Data)
            $debugMessage += Write-DebugLog inf "Added to xml: OU-PRD-T0 ($data)"

            # Settings/Translation/WellKnownID --> %OU-LocalAdmins%
            $Data = ($SourceXml.Settings.Translation.WellKnownID | Where-Object { $_.TranslateFrom -eq '%OU-LocalAdmins%' }).TranslateTo
            $XmlWriter.WriteComment('OU Local Admins Group')
            $XmlWriter.WriteElementString('OU-LOCALADMINS',$Data)
            $debugMessage += Write-DebugLog inf "Added to xml: OU-LOCALADMINS ($data)"

            # Settings/Translation/WellKnownID --> %OU-ADM%
            $Data = ($SourceXml.Settings.Translation.WellKnownID | Where-Object { $_.TranslateFrom -eq '%OU-ADM%' }).TranslateTo
            $XmlWriter.WriteComment('OU ADMINISTRATION')
            $XmlWriter.WriteElementString('OU-ADM',$Data)
            $debugMessage += Write-DebugLog inf "Added to xml: OU-ADM ($data)"

            # Settings/Translation/WellKnownID --> %DN%
            $Data = ($SourceXml.Settings.Translation.WellKnownID | Where-Object { $_.TranslateFrom -eq '%DN%' }).TranslateTo
            $XmlWriter.WriteComment('DN OF THE DOMAIN')
            $XmlWriter.WriteElementString('DN',$Data)
            $debugMessage += Write-DebugLog inf "Added to xml: DN ($data)"

            # Settings/Translation/WellKnownID --> %OU-ADM-Groups-T0%
            $Data = ($SourceXml.Settings.Translation.WellKnownID | Where-Object { $_.TranslateFrom -eq '%OU-ADM-Groups-T0%' }).TranslateTo
            $XmlWriter.WriteComment('OU TIER 0 GROUP')
            $XmlWriter.WriteElementString('OU-ADM-GRP-T0',$Data)
            $debugMessage += Write-DebugLog inf "Added to xml: OU-ADM-GRP-T0 ($data)"

            # Settings/Translation/WellKnownID --> %OU-ADM-Groups-T1%
            $Data = ($SourceXml.Settings.Translation.WellKnownID | Where-Object { $_.TranslateFrom -eq '%OU-ADM-Groups-T1%' }).TranslateTo
            $XmlWriter.WriteComment('OU TIER 1 GROUP')
            $XmlWriter.WriteElementString('OU-ADM-GRP-T1',$Data)
            $debugMessage += Write-DebugLog inf "Added to xml: OU-ADM-GRP-T1 ($data)"

            # Settings/Translation/WellKnownID --> %OU-ADM-Groups-T2%
            $Data = ($SourceXml.Settings.Translation.WellKnownID | Where-Object { $_.TranslateFrom -eq '%OU-ADM-Groups-T2%' }).TranslateTo
            $XmlWriter.WriteComment('OU TIER 2 GROUP')
            $XmlWriter.WriteElementString('OU-ADM-GRP-T2',$Data)
            $debugMessage += Write-DebugLog inf "Added to xml: OU-ADM-GRP-T2 ($data)"

            # Settings/Translation/WellKnownID --> %OU-ADM-Groups-T1L%
            $Data = ($SourceXml.Settings.Translation.WellKnownID | Where-Object { $_.TranslateFrom -eq '%OU-ADM-Groups-T1L%' }).TranslateTo
            $XmlWriter.WriteComment('OU TIER 1 LEGACY GROUP')
            $XmlWriter.WriteElementString('OU-ADM-GRP-L1',$Data)
            $debugMessage += Write-DebugLog inf "Added to xml: OU-ADM-GRP-L1 ($data)"

            # Settings/Translation/WellKnownID --> %OU-ADM-Groups-T2L%
            $Data = ($SourceXml.Settings.Translation.WellKnownID | Where-Object { $_.TranslateFrom -eq '%OU-ADM-Groups-T2L%' }).TranslateTo
            $XmlWriter.WriteComment('OU TIER 2 LEGACY GROUP')
            $XmlWriter.WriteElementString('OU-ADM-GRP-L2',$Data)
            $debugMessage += Write-DebugLog inf "Added to xml: OU-ADM-GRP-L2 ($data)"

            # Settings/Translation/WellKnownID --> %Prefix-domLoc%
            $Data = ($SourceXml.Settings.Translation.WellKnownID | Where-Object { $_.TranslateFrom -eq '%PREFIX-DOMLOC%' }).TranslateTo
            $XmlWriter.WriteComment('PREFIX DOMAINLOCAL GROUP')
            $XmlWriter.WriteElementString('PREFIX-DOMLOC',$Data)
            $debugMessage += Write-DebugLog inf "Added to xml: PREFIX-DOMLOC ($data)"

            # Settings/Translation/WellKnownID --> %Groups_Computers%
            $Data = ($SourceXml.Settings.Translation.WellKnownID | Where-Object { $_.TranslateFrom -eq '%Groups_Computers%' }).TranslateTo
            $XmlWriter.WriteComment('GROUP COMPUTER NAME')
            $XmlWriter.WriteElementString('GRP-NAME',$Data)
            $debugMessage += Write-DebugLog inf "Added to xml: GRP-NAME ($data)"

            # Closing XML
            $XmlWriter.WriteEndElement()
            $XmlWriter.WriteEndDocument()
            $debugMessage += Write-DebugLog inf "File configuration.xml ready to be created"

            # Saving to file
            $XmlWriter.Flush()
            $XmlWriter.close()
            $debugMessage += Write-DebugLog inf "File configuration.xml generated."
            Write-EventLog -LogName $EventLogName -Source $EventLogSource -EntryType SuccessAudit -EventId 0 -Category 0 -Message "configuration.xml: successfully updated."

            # If a backup file exists, then we need to overwrite it with the new file.
            if (Test-Path $CurrentDir\configuration.xml.backup)
            {
                $debugMessage += Write-DebugLog warn "File configuration.xml.backup is present!"
                Try {
                    Copy-Item -Path $CurrentDir\configuration.xml -Destination $CurrentDir\configuration.xml.backup -Force | Out-Null
                    $debugMessage += Write-DebugLog inf "File configuration.xml copied to configuration.xml.backup (overwrite)."
                } Catch {
                    $debugMessage += Write-DebugLog error "failed to copy the file configuration.xml to configuration.xml.backup (overwrite)!"
                }
            } Else {
                $debugMessage += Write-DebugLog inf "File configuration.xml.backup is not present: no action taken."
            }


        } Else {
            $debugMessage += Write-DebugLog error "$xmlSourcePath is not a correct XML!"
            Write-Error "$xmlSourcePath is not a correct XML!"
            Export-DebugLog $debugMessage $DebugFile
            Write-EventLog -LogName $EventLogName -Source $EventLogSource -EntryType FailureAudit -EventId 4 -Category 0 -Message "Could not update configuration.xml: $xmlSourcePath is not a correct XML!"
            exit 4
        }
    } Else {
        $debugMessage += Write-DebugLog error "$xmlSourcePath not found!"
        Write-Error "$xmlSourcePath not found!"
        Export-DebugLog $debugMessage $DebugFile
        Write-EventLog -LogName $EventLogName -Source $EventLogSource -EntryType FailureAudit -EventId 2 -Category 0 -Message "Could not update configuration.xml: $xmlSourcePath not found!"
        exit 2
    }
}

# SECOND CASE: RUN THE SCRIPT (STANDARD USE CASE)
if ($ComputerName -and -not($UpdateConfig) -and -not($CustomRules))
{
    $debugMessage += Write-DebugLog inf "[ComputerName] called"

    # Get Computer AD information
    Try {
        $myComputer = Get-ADComputer $ComputerName -Server $myPDC -Properties * -ErrorAction Stop
        $debugMessage += Write-DebugLog inf "[WORKING ON $myComputer]"
    } Catch {
        $debugMessage += Write-DebugLog error "Could not retrieve computer object $ComputerName"
        Export-DebugLog $debugMessage $DebugFile
        Write-EventLog -LogName $EventLogName -Source $EventLogSource -EntryType FailureAudit -EventId 11 -Category 0 -Message "Could not retrieve computer object $ComputerName. No group created."
        exit 11
    }

    # Loading XML configuration
    $myConfig = [xml](Get-Content .\configuration.xml -Encoding UTF8)

    # Checking to which tier the computer belong...
    $isMsftOS  = $false
    $isServer  = $false
    $isLegacy  = $false
    $isPawOrT0 = $false
    $DoMoreChk = $true
    
    if ($myComputer.OperatingSystem -eq "" -or $myComputer.OperatingSystem -eq $null)
    {
        # This is an unknown OS or a computer not yet joined to the domain
        # In such case, the group is protected as if it was a Paw or a Tier 0 one.
        $isPawOrT0 = $true
        $DoMoreChk = $false

        $debugMessage += Write-DebugLog inf "Found an unkown OS, or a not yet joined windows system."
    }

    if ($DoMoreChk)
    {
        # Let's see if this a PAW or Tier 0 object...
        $PawAccs = $myComputer.DistinguishedName -match $myConfig.translation.'OU-PAW-ACCESS'
        $pawT0   = $myComputer.DistinguishedName -match $myConfig.translation.'OU-PAW-T0'
        $pawT12L = $myComputer.DistinguishedName -match $myConfig.translation.'OU-PAW-T12L'
        $Tier0   = $myComputer.DistinguishedName -match $myConfig.translation.'OU-PRD-T0'

        if ($PawAccs -or $pawT0 -or $pawT12L -or $Tier0)
        {
            # Found a Tier 0 Protected group, no more check to do.
            $isPawOrT0 = $true
            $DoMoreChk = $false

            $debugMessage += Write-DebugLog inf "Found an object belonging to a tier 0 protected area."
        }
    }

    if ($DoMoreChk -and $myComputer.OperatingSystem -like "Windows*")
    {
        # We are dealing a windows system.
        $isMsftOS = $true

        $debugMessage += Write-DebugLog inf "Found a windows system."

        # Because this is a windows system, let see if it is a server or a client OS
        if ($myComputer.OperatingSystem -like "*serv*")
        {
            # This is a server
            $isServer = $true
            $debugMessage += Write-DebugLog inf "The system is a server."
        }  Else {
            $debugMessage += Write-DebugLog inf "The system is a client."
        }

        # Let's see if this is a legacy OS or not.
        Switch ($isServer)
        {
            $true {
                # The Major OS version is 6 and the minor is greater than 2.
                $OSversion = ($myComputer.OperatingSystemVersion -split " ")[0] -split "\."
                $MajorVer  = [int]$OSversion[0]
                $MinorVer  = [int]$OSversion[1]

                if ($MajorVer -lt 6 -or ($MajorVer -eq 6 -and $MinorVer -le 2))
                {
                    $isLegacy = $true
                    $debugMessage += Write-DebugLog inf "The system is a legacy one."
                } Else {
                    $debugMessage += Write-DebugLog inf "The system is supported."
                }
            }
            $false {
                # The major 0S version is 10.
                $OSversion = ($myComputer.OperatingSystemVersion -split " ")[0] -split "\."
                $MajorVer  = [int]$OSversion[0]
                $MinorVer  = [int]$OSversion[1]

                if ($MajorVer -lt 10)
                {
                    $isLegacy = $true
                    $debugMessage += Write-DebugLog inf "The system is a legacy one."
                } Else {
                    $debugMessage += Write-DebugLog inf "The system is supported."
                }
            }
        }
    }

    # Define group target
    $myBaseDN = "OU=$($myConfig.translation.'OU-LOCALADMINS'),OU=?,OU=$($myConfig.translation.'OU-ADM'),$($myConfig.translation.DN)"

    # replacing ? per appropriate value for the tier
    if ($isPawOrT0)
    {
        $myBaseDN = ($myBaseDN).Replace('?',$myConfig.translation.'OU-ADM-GRP-T0')
    } elseif ($isServer) {
        switch ($isLegacy)
        {
            $true  { $myBaseDN = ($myBaseDN).Replace('?',$myConfig.translation.'OU-ADM-GRP-L1') }
            $false { $myBaseDN = ($myBaseDN).Replace('?',$myConfig.translation.'OU-ADM-GRP-T1') }
        }
    } Else {
        switch ($isLegacy)
        {
            $true  { $myBaseDN = ($myBaseDN).Replace('?',$myConfig.translation.'OU-ADM-GRP-L2') }
            $false { $myBaseDN = ($myBaseDN).Replace('?',$myConfig.translation.'OU-ADM-GRP-T2') }
        }
    }

    $debugMessage += Write-DebugLog inf "The group will be moved/created in $myBaseDN"

    # Time to go with the group itself
    $myGrpName = "$($myConfig.translation.'PREFIX-DOMLOC')$(($myConfig.translation.'GRP-NAME').Replace('%ComputerName%',$myComputer.name))"
    $debugMessage += Write-DebugLog inf "[TARGET GROUP: $myGrpName]"

    # Check if the group exists or not
    $isCreated = Get-ADObject -Filter { Name -eq $myGrpName -and ObjectClass -eq 'group' }

    if ($isCreated)
    {
        $debugMessage += Write-DebugLog warn "The group already exists ($($isCreated.DistinguishedName))"

        # Checking if the group has to be moved or not
        $CurrentPath = ($isCreated.DistinguishedName).replace("CN=$($isCreated.Name),",'')
        if ($myBaseDN -eq $CurrentPath)
        {
            # The object belong to the appropriate Tier, nothing to do.
            $debugMessage += Write-DebugLog inf "The group is already in the right OU. Nothing to do."
            Write-EventLog -LogName $EventLogName -Source $EventLogSource -EntryType SuccessAudit -EventId 0 -Category 0 -Message "SUCCESS: the group '$myGrpName' is already in the correct OU ($myBaseDN)."
        
        } Else {
            # The group has to be moved away and cleaned.
            $debugMessage += Write-DebugLog warn "The group is not localized in the appropriate OU. The group will be moved to a new location and its membership cleared."

            # Clearing membership
            Try {
                $myGroup = Get-ADGroup $myGrpName -Server $myPDC
                $void = $myGroup | Set-ADGroup -Clear member
                $debugMessage += Write-DebugLog inf "The group $myGrpName has been cleared from its members."
                Write-EventLog -LogName $EventLogName -Source $EventLogSource -EntryType SuccessAudit -EventId 0 -Category 0 -Message "SUCCESS: the group '$myGrpName' has been flushed from its members."
            } Catch {
                $debugMessage += Write-DebugLog error "The group $myGrpName has NOT been cleared from its members."
                Write-EventLog -LogName $EventLogName -Source $EventLogSource -EntryType FailureAudit -EventId 13 -Category 0 -Message "ERROR: the group '$myGrpName' was not flushed from its members."
            }

            # Moving group to the nnew OU
            Try {
                $void = Move-ADObject -Identity $myGroup.ObjectGUID -TargetPath $myBaseDN
                $debugMessage += Write-DebugLog inf "The group $myGrpName has been relocated to $myBaseDN."
                Write-EventLog -LogName $EventLogName -Source $EventLogSource -EntryType SuccessAudit -EventId 0 -Category 0 -Message "SUCCESS: the group '$myGrpName' has been relocated to $myBaseDN."
            } Catch {
                $debugMessage += Write-DebugLog error "The group $myGrpName has NOT been relocated to $myBaseDN."
                Write-EventLog -LogName $EventLogName -Source $EventLogSource -EntryType FailureAudit -EventId 14 -Category 0 -Message "ERROR: the group '$myGrpName' has NOT been relocated to $myBaseDN."
            }
        }
    } Else {
        # The group does not exist, then we simply create it.
        try {
            $void = New-ADGroup -Name $myGrpName -SamAccountName $myGrpName -DisplayName $myGrpName -Description "This group manage members of builtin administrators group for $($myComputer.Name)" -GroupCategory Security -GroupScope DomainLocal -Server $myPDC -Path $myBaseDN
            $debugMessage += Write-DebugLog inf "SUCCESS: the group '$myGrpName' has been created in $myBaseDN"
            Write-EventLog -LogName $EventLogName -Source $EventLogSource -EntryType SuccessAudit -EventId 0 -Category 0 -Message "SUCCESS: the group '$myGrpName' has been created in $myBaseDN."
        } Catch {
            $debugMessage += Write-DebugLog error "FAILED: the group '$myGrpName' could not be created in $myBaseDN"
            Write-EventLog -LogName $EventLogName -Source $EventLogSource -EntryType FailureAudit -EventId 12 -Category 0 -Message "Could not create group object '$myGrpName' in $myBaseDN."   
        }
    }
}

# THIRD CASE: RUN THE SCRIPT (CUSTOM RULES USE CASE)
if ($ComputerName -and -not($UpdateConfig) -and $CustomRules)
{
    $debugMessage += Write-DebugLog inf "[CustomRules] called"

    # Get Computer AD information
    Try {
        $myComputer = Get-ADComputer $ComputerName -Server $myPDC -Properties * -ErrorAction SilentlyContinue
        $debugMessage += Write-DebugLog inf "[WORKING ON $myComputer]"
    } Catch {
        $debugMessage += Write-DebugLog error "Could not retrieve computer object $ComputerName"
        Export-DebugLog $debugMessage $DebugFile
        Write-EventLog -LogName $EventLogName -Source $EventLogSource -EntryType FailureAudit -EventId 21 -Category 0 -Message "Could not retrieve computer object $ComputerName. No group created."
        Export-DebugLog $debugMessage $DebugFile
        exit 21
    }

    # Loading XML configuration
    Try {
        $myConfig = [xml](Get-Content .\configuration-custom.xml -Encoding UTF8 -ErrorAction SilentlyContinue)
        $debugMessage += Write-DebugLog inf "File 'configuration-custom.xml' loaded"
    } Catch {
        $debugMessage += Write-DebugLog error "File 'configuration-custom.xml' is not accessible!"
        Write-EventLog -LogName $EventLogName -Source $EventLogSource -EntryType FailureAudit -EventId 22 -Category 0 -Message "File 'configuration-custom.xml' is not accessible"
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
        # Compare dnPattern to Computer DN. If match, exit.
        if ($myComputer.DistinguishedName -match $Source.dnPattern)
        {
            $debugMessage += Write-DebugLog inf "DN PATTERN: matching with $($Source.dnPattern)"
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
        } Catch {
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
        $GroupName = ($xmlTarget.name).replace('%ComputerName%',$myComputer.Name)
        $GroupDesc = ($xmlTarget.description).replace('%ComputerName%',$myComputer.Name)
        $GroupPath = $xmlTarget.path
        $GroupCate = $xmlTarget.category
        $GroupScop = $xmlTarget.scope
    } Else {
        # Reading data from default target.
        $xmlTarget = Select-Xml $myConfig -XPath "//default/target" | Select-Object -ExpandProperty "Node"
        $GroupName = ($xmlTarget.name).replace( '%ComputerName',$myComputer.Name)
        $GroupDesc = ($xmlTarget.description).replace( '%ComputerName',$myComputer.Name)
        $GroupPath = $xmlTarget.path
        $GroupCate = $xmlTarget.category
        $GroupScop = $xmlTarget.scope
    }
    # Debug log and clearing xmlTarget
    $xmlTarget = $void
    $debugMessage += Write-DebugLog inf ">> TARGET DATA:`n>> Group Name......: $GroupName`n>> Description.....: $GroupDesc`n>> Group Category..: $GroupCate`n>> Group Scope.....: $GroupScop`n>> Path............: $GroupPath"

    # Time to deal with the group object. 
    # First: does the group already exists?
    Try {
        $myGroup = Get-ADGroup $GroupName -ErrorAction SilentlyContinue
        $debugMessage += Write-DebugLog inf "Group object exists. the group will be checked."
        $CreateGrp = $false
    } Catch {
        $debugMessage += Write-DebugLog warn "Group object does not exists. the group will be created."
        $CreateGrp = $true
    }
    # Dealing the group creation
    if ($CreateGrp)
    {
        try {
            $void = New-ADGroup -Name $GroupName -SamAccountName $GroupName -DisplayName $GroupName -Description $GroupDesc -GroupCategory $GroupCate -GroupScope $GroupScop -Server $myPDC -Path $GroupPath
            $debugMessage += Write-DebugLog inf "SUCCESS: the group '$GroupName' has been created in $GroupPath"
            Write-EventLog -LogName $EventLogName -Source $EventLogSource -EntryType SuccessAudit -EventId 0 -Category 0 -Message "SUCCESS: the group '$GroupName' has been created in $GroupPath"
        
        } Catch {
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
            } Catch {
                $debugMessage += Write-DebugLog error "The group $GroupName has NOT been cleared from its members."
                Write-EventLog -LogName $EventLogName -Source $EventLogSource -EntryType FailureAudit -EventId 24 -Category 0 -Message "ERROR: the group '$GroupName' was not flushed from its members."
            }

            # Moving group to the new OU
            Try {
                $void = Move-ADObject -Identity $myGroup.ObjectGUID -TargetPath $GroupPath
                $debugMessage += Write-DebugLog inf "The group $GroupName has been relocated to $GroupPath."
                Write-EventLog -LogName $EventLogName -Source $EventLogSource -EntryType SuccessAudit -EventId 0 -Category 0 -Message "SUCCESS: the group '$GroupName' has been relocated to $GroupPath."
            } Catch {
                $debugMessage += Write-DebugLog error "The group $GroupName has NOT been relocated to $GroupPath."
                Write-EventLog -LogName $EventLogName -Source $EventLogSource -EntryType FailureAudit -EventId 25 -Category 0 -Message "ERROR: the group '$GroupName' has NOT been relocated to $GroupPath."
            }
        }
    }
}

## Exit
Export-DebugLog $debugMessage $DebugFile
Exit 0
