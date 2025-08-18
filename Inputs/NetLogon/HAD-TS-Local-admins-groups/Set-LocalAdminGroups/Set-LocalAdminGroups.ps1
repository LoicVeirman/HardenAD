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
    $xmlSourcePath
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
$hostname          = hostname

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
            
            Try {
                
                $CustomConfXml = [xml](Get-Content -Path "$CurrentDir\configuration-custom.xml" -Encoding utf8 -ErrorAction Stop)
                $debugMessage += Write-DebugLog inf "configuration-custom.xml array object loaded"
            } Catch {
                $debugMessage += Write-DebugLog error "Failed to load the configuration-custom.xml variable"
                Export-DebugLog $debugMessage $DebugFile
                Write-EventLog -LogName $EventLogName -Source $EventLogSource -EntryType FailureAudit -EventId 5 -Category 0 -Message "Could not update configuration.xml: Failed to create the configuration.xml variable"
                exit 5
            }
            
            $debugMessage += Write-DebugLog inf "Values from configuration-custom.xml file loaded."

            # Update mode from TaskSequence file
            $Data = ($SourceXml.Settings.Translation.WellKnownID | Where-Object { $_.TranslateFrom -eq '%LOCAL-ADMINS-RDU-MODE%' }).TranslateTo
            $CustomConfXml.customRuleSet.config.mode = $Data
            $debugMessage += Write-DebugLog inf "Added to xml: mode ($data)"
            
            # Update OU LocalAdmins from TaskSequence file
            $Data = ($SourceXml.Settings.Translation.WellKnownID | Where-Object { $_.TranslateFrom -eq '%OU-LocalAdmins%' }).TranslateTo
            $CustomConfXml.customRuleSet.config.settings.LOCALADMIN.OU = $Data
            $debugMessage += Write-DebugLog inf "Added to xml: OU-LocalAdmins ($data)"

            # Update OU RDU from TaskSequence file
            $Data = ($SourceXml.Settings.Translation.WellKnownID | Where-Object { $_.TranslateFrom -eq '%OU-LocalRDU%' }).TranslateTo
            $CustomConfXml.customRuleSet.config.settings.RDU.OU = $Data
            $debugMessage += Write-DebugLog inf "Added to xml: OU-LocalRDU ($data)"

            # Update GroupName for LocalAdmins from TaskSequence file
            $Data = ($SourceXml.Settings.Translation.WellKnownID | Where-Object { $_.TranslateFrom -eq '%Groups_Computers_LA%' }).TranslateTo
            $Data = $Data -replace '%ComputerName%', '' # Remove the %ComputerName% placeholder
            $CustomConfXml.customRuleSet.config.settings.LOCALADMIN.GroupName = $Data
            $debugMessage += Write-DebugLog inf "Added to xml: GroupName for Local admin ($data)"

            # Update GroupName for LocalRDU from TaskSequence file
            $Data = ($SourceXml.Settings.Translation.WellKnownID | Where-Object { $_.TranslateFrom -eq '%Groups_Computers_RDU%' }).TranslateTo
            $Data = $Data -replace '%ComputerName%', '' # Remove the %ComputerName% placeholder
            $CustomConfXml.customRuleSet.config.settings.RDU.GroupName = $Data
            $debugMessage += Write-DebugLog inf "Added to xml: GroupName for Local RDU ($data)"


            # Settings/Translation/WellKnownID --> %OS-SRV-MAJOR-VERSION%
            $Data = ($SourceXml.Settings.Translation.WellKnownID | Where-Object { $_.TranslateFrom -eq '%OS-SRV-MAJOR-VERSION%' }).TranslateTo
            $CustomConfXml.customRuleSet.config.operatingSystems.supported.server.MajorVersion = $Data
            $debugMessage += Write-DebugLog inf "Added to xml: OS-SRV-MAJOR-VERSION ($data)"


            # Settings/Translation/WellKnownID --> %OS-SRV-MINOR-VERSION%
            $Data = ($SourceXml.Settings.Translation.WellKnownID | Where-Object { $_.TranslateFrom -eq '%OS-SRV-MINOR-VERSION%' }).TranslateTo
            $CustomConfXml.customRuleSet.config.operatingSystems.supported.server.MinorVersion = $Data
            $debugMessage += Write-DebugLog inf "Added to xml: OS-SRV-MINOR-VERSION ($data)"

            # Settings/Translation/WellKnownID --> %OS-SRV-MAJOR-VERSION%
            $Data = ($SourceXml.Settings.Translation.WellKnownID | Where-Object { $_.TranslateFrom -eq '%OS-CLIENT-MAJOR-VERSION%' }).TranslateTo
            $CustomConfXml.customRuleSet.config.operatingSystems.supported.client.MajorVersion = $Data
            $debugMessage += Write-DebugLog inf "Added to xml: OS-CLIENT-MAJOR-VERSION ($data)"

            # Settings/Translation/WellKnownID --> %OS-SRV-MINOR-VERSION%
            $Data = ($SourceXml.Settings.Translation.WellKnownID | Where-Object { $_.TranslateFrom -eq '%OS-CLIENT-MINOR-VERSION%' }).TranslateTo
            $CustomConfXml.customRuleSet.config.operatingSystems.supported.client.MinorVersion = $Data
            $debugMessage += Write-DebugLog inf "Added to xml: OS-CLIENT-MINOR-VERSION ($data)"

            # Settings/Translation/WellKnownID --> PREFIX DOMLOC
            $Data = ($SourceXml.Settings.Translation.WellKnownID | Where-Object { $_.TranslateFrom -eq '%Prefix-domLoc%' }).TranslateTo
            $CustomConfXml.customRuleSet.config.PrefixDomLoc = $Data
            $debugMessage += Write-DebugLog inf "Added to xml: PrefixDomLoc ($data)"
            

            # Edit data path for default target in configuration-custom.xml
            $Data_DOMAIN = ($SourceXml.Settings.Translation.WellKnownID | Where-Object { $_.TranslateFrom -eq '%RootDN%' }).TranslateTo
            $Data_ADMIN_OU = ($SourceXml.Settings.Translation.WellKnownID | Where-Object { $_.TranslateFrom -eq '%OU-Adm%' }).TranslateTo
            $Data = "OU=$Data_ADMIN_OU,$Data_DOMAIN"
            $CustomConfXml.customRuleSet.default.target.path = $CustomConfXml.customRuleSet.default.target.path -replace "OU=_Administration,DC=HARDEN,DC=AD", $Data

            # Edit data path for each target in configuration-custom.xml
            foreach ($node in $CustomConfXml.customRuleSet.targets.ChildNodes) {
                if ($node.path) {
                    $node.path = $node.path -replace "OU=_Administration,DC=HARDEN,DC=AD", $Data
                }
            }


            
            # Edit Sources data in config-custom file
            $sourcesNode = $CustomConfXml.customRuleSet.sources
            $sourcesNode.RemoveAll()
            $debugMessage += Write-DebugLog inf "Node <sources> has been removed from configuration-custom.xml."
            $ouTranslationsNode = $SourceXml.Settings.Translation

            # Tableau pour stocker les dnPatterns et leurs attributs
            $sourcesData = @()

            # Translations OU à rechercher (Correspondent aux TranslateFrom)
            $ouTranslations = @(
                "%OU-Production-T0%",
                "%OU-Production-T1%",
                "%OU-Production-T2%",
                "%OU-Adm%",
                "%OU-Provisionning%"
            )


            # Parcourir les translation OU
            foreach ($ouTranslation in $ouTranslations) {
                try {
                    $ouValue = ($ouTranslationsNode.wellKnownID | Where-Object { $_.TranslateFrom -eq $ouTranslation }).TranslateTo | Select-Object -First 1 -ErrorAction Stop
                    $dnPattern = "OU=$ouValue"

                    $debugMessage += Write-DebugLog inf "Translation '$ouTranslation' trouvée. dnPattern = '$dnPattern'."

                    # Ajouter les dnPatterns et leurs attributs au tableau
                    switch ($ouTranslation) {
                        "%OU-Production-T0%" {
                            $sourcesData += @{ dnPattern = $dnPattern; osPattern = "serve"; target = "tier0server"; LegacyTarget = "" }
                            $sourcesData += @{ dnPattern = $dnPattern; osPattern = "Windo"; target = "tier0client"; LegacyTarget = "" }
                            $sourcesData += @{ dnPattern = $dnPattern; osPattern = ".*"; target = "tier0server"; LegacyTarget = "" }
                        }
                        "%OU-Production-T1%" {
                            $sourcesData += @{ dnPattern = $dnPattern; osPattern = "serve"; target = "tier1"; LegacyTarget = "tier1leg" }
                            if ($ouValue -ne ($ouTranslationsNode.wellKnownID | Where-Object { $_.TranslateFrom -eq "%OU-Production-T2%" }).TranslateTo) {
                                $sourcesData += @{ dnPattern = $dnPattern; osPattern = ".*"; target = "tier0server"; LegacyTarget = "" }
                            }
                        }
                        "%OU-Production-T2%" {
                            $sourcesData += @{ dnPattern = $dnPattern; osPattern = "Windo"; target = "tier2"; LegacyTarget = "tier2leg" }
                            $sourcesData += @{ dnPattern = $dnPattern; osPattern = ".*"; target = "tier0server"; LegacyTarget = "" }
                        }
                        "%OU-Provisionning%" {
                            $sourcesData += @{ dnPattern = $dnPattern; osPattern = "serve"; target = "provisioningtier1"; LegacyTarget = "" }
                            $sourcesData += @{ dnPattern = $dnPattern; osPattern = "Windo"; target = "provisioningtier2"; LegacyTarget = "" }
                            $sourcesData += @{ dnPattern = $dnPattern; osPattern = ".*"; target = "provisioningtier0"; LegacyTarget = "" }
                        }
                        "%OU-Adm%" {
                            $admOU = ($ouTranslationsNode.wellKnownID | Where-Object { $_.TranslateFrom -eq "%OU-Adm%" }).TranslateTo
                            $pawAccessOU = ($ouTranslationsNode.wellKnownID | Where-Object { $_.TranslateFrom -eq "%OU-PawAcs%" }).TranslateTo
                            $pawT0OU = ($ouTranslationsNode.wellKnownID | Where-Object { $_.TranslateFrom -eq "%OU-PAW-T0%" }).TranslateTo
                            $pawT12LOU = ($ouTranslationsNode.wellKnownID | Where-Object { $_.TranslateFrom -eq "%OU-PAW-T12L%" }).TranslateTo

                            if ($pawAccessOU) {
                                $sourcesData += @{ dnPattern = "OU=$pawAccessOU,OU=$admOU"; osPattern = ".*"; target = "pawtier0"; LegacyTarget = "" }
                            }
                            if ($pawT0OU) {
                                $sourcesData += @{ dnPattern = "OU=$pawT0OU,OU=$admOU"; osPattern = ".*"; target = "pawtier0"; LegacyTarget = "" }
                            }
                            if ($pawT12LOU) {
                                $sourcesData += @{ dnPattern = "OU=$pawT12LOU,OU=$admOU"; osPattern = ".*"; target = "pawprod"; LegacyTarget = "" }
                            }
                        }
                    }
                }
                catch {
                    Write-Warning "Translation '$ouTranslation' non trouvée. Données ignorées."
                }
            }

            # Ajouter les sources au nœud <sources>
            foreach ($source in $sourcesData) {
                $sourceElement = $CustomConfXml.CreateElement("source")
                foreach ($key in $source.Keys) {
                    $sourceElement.SetAttribute($key, $source.$key)
                }
                $sourcesNode.AppendChild($sourceElement) | Out-Null
            }

            # Ajouter la source par défaut
            $defaultSourceElement = $CustomConfXml.CreateElement("source")
            $defaultSourceElement.SetAttribute("dnPattern", ".*")
            $defaultSourceElement.SetAttribute("osPattern", ".*")
            $defaultSourceElement.SetAttribute("target", "")
            $defaultSourceElement.SetAttribute("LegacyTarget", "")
            $sourcesNode.AppendChild($defaultSourceElement) | Out-Null

            $CustomConfXml.Save("$CurrentDir\configuration-custom.xml")

            $debugMessage += Write-DebugLog inf "File configuration.xml and configuration-custom.xml generated."
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



# SECOND CASE: RUN THE SCRIPT (CUSTOM RULES USE CASE)
if ($ComputerName -and -not($UpdateConfig))
{
    $debugMessage += Write-DebugLog inf "Sarting the script"

    # Get Computer AD information
    $Error.Clear()
    Try {
        $myComputer = Get-ADComputer $ComputerName -Server $hostname -Properties * -ErrorAction SilentlyContinue

        $domainName = (Get-ADDomain).DNSRoot
        $hardenNetlogonPath = Join-Path -Path "\\$domainName" -ChildPath "SYSVOL\$domainName\scripts\HardenAD\HAD-TS-Local-admins-groups\Set-LocalAdminGroups"

        $debugMessage += Write-DebugLog inf "[WORKING ON $myComputer]"
        $debugMessage += Write-DebugLog inf "[NETLOGON HARDEN PATH : $hardenNetlogonPath]"
    } Catch {
        $debugMessage += Write-DebugLog error "Could not retrieve computer object $ComputerName"
        $debugMessage += Write-DebugLog error "-- > Error detailled: $($Error[0].Exception.Message)"  
        Export-DebugLog $debugMessage $DebugFile
        Write-EventLog -LogName $EventLogName -Source $EventLogSource -EntryType FailureAudit -EventId 21 -Category 0 -Message "Could not retrieve computer object $ComputerName. No group created."
        Export-DebugLog $debugMessage $DebugFile
        exit 21
    }

    # Loading XML configuration
    $Error.Clear()
    Try {
        $myConfig = [xml](Get-Content "$hardenNetlogonPath\configuration-custom.xml" -Encoding UTF8 -ErrorAction SilentlyContinue)
        $debugMessage += Write-DebugLog inf "File 'configuration-custom.xml' loaded"
    } Catch {
        $debugMessage += Write-DebugLog error "File 'configuration-custom.xml' is not accessible!"
        $debugMessage += Write-DebugLog error "-- > Error detailled: $($Error[0].Exception.Message)"  
        Write-EventLog -LogName $EventLogName -Source $EventLogSource -EntryType FailureAudit -EventId 22 -Category 0 -Message "File 'configuration-custom.xml' is not accessible"
        Export-DebugLog $debugMessage $DebugFile
        Exit 22
    }

    # Build Sources Pattern...
    $Sources = Select-Xml $myConfig -XPath "//sources/source" | Select-Object -ExpandProperty "Node"
    $debugMessage += Write-DebugLog inf "Found $($Sources.count) Source as source identity."
    
    # Checking to which tier the computer belong...
    $debugMessage += Write-DebugLog inf "Analyzing: $($myComputer.DistinguishedName)"

    # Load the prefix value from the configuration file
    $prefixDomLoc = $myConfig.customRuleSet.config.PrefixDomLoc

    # Load the custom mode to define which group to create (LOCALADMIN, RDU, BOTH)
    $mode = $myConfig.customRuleSet.config.mode
    $LA_OU = $myConfig.customRuleSet.config.settings.LOCALADMIN.OU
    $RDU_OU = $myConfig.customRuleSet.config.settings.RDU.OU
    $LA_OU = "OU=$LA_OU,"
    $RDU_OU = "OU=$RDU_OU,"
    $LA_GroupName = $myConfig.customRuleSet.config.settings.LOCALADMIN.GroupName
    $RDU_GroupName = $myConfig.customRuleSet.config.settings.RDU.GroupName

    $debugMessage += Write-DebugLog inf "Script mode : $mode"
    $debugMessage += Write-DebugLog inf "LOCALADMIN OU: $LA_OU"
    $debugMessage += Write-DebugLog inf "LOCALADMIN GroupName: $LA_GroupName"
    $debugMessage += Write-DebugLog inf "RDU OU: $RDU_OU"
    $debugMessage += Write-DebugLog inf "RDU GroupName: $RDU_GroupName"




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
                            $osMaj = [int]$myConfig.customRuleSet.config.operatingSystems.supported.server.MajorVersion
                            $osMin = [int]$myConfig.customRuleSet.config.operatingSystems.supported.server.MinorVersion
                        }
                        $false {
                            $debugMessage += Write-DebugLog inf "OS PATTERN: detected as a Windows client (OperatingSystem not matching 'serv'.)"
                            $osMaj = [int]$myConfig.customRuleSet.config.operatingSystems.supported.client.MajorVersion
                            $osMin = [int]$myConfig.customRuleSet.config.operatingSystems.supported.client.MinorVersion
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
        $Error.Clear()
        Try {
            $xmlTarget = Select-Xml $myConfig -XPath "//targets/$($myTarget)" -ErrorAction Stop | Select-Object -ExpandProperty "Node"
            $debugMessage += Write-DebugLog inf "TARGET....: xml data catche successfully"
        } Catch {
            $debugMessage += Write-DebugLog error "TARGET....: ERROR! Could not grab the xml data!"
            $debugMessage += Write-DebugLog error "-- > Error detailled: $($Error[0].Exception.Message)"  
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

    # Manage the group to create depending on the mode selected.
    if ($mode -eq "LOCALADMIN" -or $mode -eq "BOTH")
    {
        $debugMessage += Write-DebugLog inf "STARTING group creation in mode : $mode"
        # Loop is done. Do we have found a target, or do we have to use the default one?
        if ($srcFound)
        {
            # Reading data from expected target.
            $GroupName = $prefixDomLoc + $LA_GroupName + $myComputer.Name
            $GroupDesc = ($xmlTarget.description).replace('%ComputerName%',$myComputer.Name)
            $GroupPath = $LA_OU + $xmlTarget.path
            $GroupCate = $xmlTarget.category
            $GroupScop = $xmlTarget.scope
        } Else {
            # Reading data from default target.
            $xmlTarget = Select-Xml $myConfig -XPath "//default/target" | Select-Object -ExpandProperty "Node"
            $GroupName = $prefixDomLoc + $LA_GroupName + $myComputer.Name
            #$GroupName = ($xmlTarget.name).replace('%ComputerName%',$myComputer.Name)
            $GroupDesc = ($xmlTarget.description).replace( '%ComputerName',$myComputer.Name)
            $GroupPath = $LA_OU + $xmlTarget.path
            $GroupCate = $xmlTarget.category
            $GroupScop = $xmlTarget.scope
        }
        # Debug log
        $debugMessage += Write-DebugLog inf ">> TARGET DATA (LOCALADMIN):`n>> Group Name......: $GroupName`n>> Description.....: $GroupDesc`n>> Group Category..: $GroupCate`n>> Group Scope.....: $GroupScop`n>> Path............: $GroupPath"

        # Time to deal with the group object. 
        # First: does the group already exists?
        $Error.clear()
        Try {
            $myGroup = Get-ADGroup $GroupName -Server $hostname -ErrorAction SilentlyContinue
            $debugMessage += Write-DebugLog inf "Group object exists. the group will be checked."
            $CreateGrp = $false
        } Catch {
            $debugMessage += Write-DebugLog warn "Group object does not exists. the group will be created."
            $debugMessage += Write-DebugLog warn "-- > Error detailled: $($Error[0].Exception.Message)"
            $CreateGrp = $true
        }
        # Dealing the group creation
        if ($CreateGrp)
        {
            $Error.clear()
            try {
                $void = New-ADGroup -Name $GroupName -SamAccountName $GroupName -DisplayName $GroupName -Description $GroupDesc -GroupCategory $GroupCate -GroupScope $GroupScop -Server $hostname -Path $GroupPath
                $debugMessage += Write-DebugLog inf "SUCCESS: the group '$GroupName' has been created in $GroupPath"
                Write-EventLog -LogName $EventLogName -Source $EventLogSource -EntryType SuccessAudit -EventId 0 -Category 0 -Message "SUCCESS: the group '$GroupName' has been created in $GroupPath"
            
            } Catch {
                $debugMessage += Write-DebugLog error "FAILED: the group '$GroupName' could not be created in $GroupePath"
                $debugMessage += Write-DebugLog error "-- > Error detailled: $($Error[0].Exception.Message)"  
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
                $Error.clear()
                Try {
                    $void = $myGroup | Set-ADGroup -Clear member
                    $debugMessage += Write-DebugLog inf "The group $GroupName has been cleared from its members."
                    Write-EventLog -LogName $EventLogName -Source $EventLogSource -EntryType SuccessAudit -EventId 0 -Category 0 -Message "SUCCESS: the group '$GroupName' has been flushed from its members."
                } Catch {
                    $debugMessage += Write-DebugLog error "The group $GroupName has NOT been cleared from its members."
                    $debugMessage += Write-DebugLog error "-- > Error detailled: $($Error[0].Exception.Message)"  
                    Write-EventLog -LogName $EventLogName -Source $EventLogSource -EntryType FailureAudit -EventId 24 -Category 0 -Message "ERROR: the group '$GroupName' was not flushed from its members."
                }

                # Moving group to the new OU
                $Error.clear()
                Try {
                    $void = Move-ADObject -Identity $myGroup.ObjectGUID -TargetPath $GroupPath
                    $debugMessage += Write-DebugLog inf "The group $GroupName has been relocated to $GroupPath."
                    Write-EventLog -LogName $EventLogName -Source $EventLogSource -EntryType SuccessAudit -EventId 0 -Category 0 -Message "SUCCESS: the group '$GroupName' has been relocated to $GroupPath."
                } Catch {
                    $debugMessage += Write-DebugLog error "The group $GroupName has NOT been relocated to $GroupPath."
                    $debugMessage += Write-DebugLog error "-- > Error detailled: $($Error[0].Exception.Message)"  
                    Write-EventLog -LogName $EventLogName -Source $EventLogSource -EntryType FailureAudit -EventId 25 -Category 0 -Message "ERROR: the group '$GroupName' has NOT been relocated to $GroupPath."
                }
            }
        }
    }

    if ($mode -eq "RDU" -or $mode -eq "BOTH")
    {
        # Loop is done. Do we have found a target, or do we have to use the default one?
        $debugMessage += Write-DebugLog inf "STARTING group creation in mode : $mode"
        if ($srcFound)
        {
            # Reading data from expected target.
            $GroupName = $prefixDomLoc + $RDU_GroupName  + $myComputer.Name

            $GroupDesc = ($xmlTarget.description).replace('%ComputerName%',$myComputer.Name)
            $GroupPath = $RDU_OU + $xmlTarget.path
            $GroupCate = $xmlTarget.category
            $GroupScop = $xmlTarget.scope
        } Else {
            # Reading data from default target.
            $xmlTarget = Select-Xml $myConfig -XPath "//default/target" | Select-Object -ExpandProperty "Node"
            $GroupName = $prefixDomLoc + $RDU_GroupName  + $myComputer.Name
            $GroupDesc = ($xmlTarget.description).replace( '%ComputerName',$myComputer.Name)
            $GroupPath = $RDU_OU + $xmlTarget.path
            $GroupCate = $xmlTarget.category
            $GroupScop = $xmlTarget.scope
        }
        
        $debugMessage += Write-DebugLog inf ">> TARGET DATA (RDU):`n>> Group Name......: $GroupName`n>> Description.....: $GroupDesc`n>> Group Category..: $GroupCate`n>> Group Scope.....: $GroupScop`n>> Path............: $GroupPath"

        # Time to deal with the group object. 
        # First: does the group already exists?
        $Error.clear()
        Try {
            $myGroup = Get-ADGroup $GroupName -Server $hostname -ErrorAction SilentlyContinue
            $debugMessage += Write-DebugLog inf "Group object exists. the group will be checked."
            $CreateGrp = $false
        } Catch {
            $debugMessage += Write-DebugLog warn "Group object does not exists. the group will be created."
            $debugMessage += Write-DebugLog warn "-- > Error detailled: $($Error[0].Exception.Message)"
            $CreateGrp = $true
        }
        # Dealing the group creation
        if ($CreateGrp)
        {
            $Error.clear()
            try {
                $void = New-ADGroup -Name $GroupName -SamAccountName $GroupName -DisplayName $GroupName -Description $GroupDesc -GroupCategory $GroupCate -GroupScope $GroupScop -Server $hostname -Path $GroupPath
                $debugMessage += Write-DebugLog inf "SUCCESS: the group '$GroupName' has been created in $GroupPath"
                Write-EventLog -LogName $EventLogName -Source $EventLogSource -EntryType SuccessAudit -EventId 0 -Category 0 -Message "SUCCESS: the group '$GroupName' has been created in $GroupPath"
            
            } Catch {
                $debugMessage += Write-DebugLog error "FAILED: the group '$GroupName' could not be created in $GroupePath"
                $debugMessage += Write-DebugLog error "-- > Error detailled: $($Error[0].Exception.Message)"  
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
                $Error.clear()
                Try {
                    $void = $myGroup | Set-ADGroup -Clear member
                    $debugMessage += Write-DebugLog inf "The group $GroupName has been cleared from its members."
                    Write-EventLog -LogName $EventLogName -Source $EventLogSource -EntryType SuccessAudit -EventId 0 -Category 0 -Message "SUCCESS: the group '$GroupName' has been flushed from its members."
                } Catch {
                    $debugMessage += Write-DebugLog error "The group $GroupName has NOT been cleared from its members."
                    $debugMessage += Write-DebugLog error "-- > Error detailled: $($Error[0].Exception.Message)"  
                    Write-EventLog -LogName $EventLogName -Source $EventLogSource -EntryType FailureAudit -EventId 24 -Category 0 -Message "ERROR: the group '$GroupName' was not flushed from its members."
                }

                # Moving group to the new OU
                $Error.clear()
                Try {
                    $void = Move-ADObject -Identity $myGroup.ObjectGUID -TargetPath $GroupPath
                    $debugMessage += Write-DebugLog inf "The group $GroupName has been relocated to $GroupPath."
                    Write-EventLog -LogName $EventLogName -Source $EventLogSource -EntryType SuccessAudit -EventId 0 -Category 0 -Message "SUCCESS: the group '$GroupName' has been relocated to $GroupPath."
                } Catch {
                    $debugMessage += Write-DebugLog error "The group $GroupName has NOT been relocated to $GroupPath."
                    $debugMessage += Write-DebugLog error "-- > Error detailled: $($Error[0].Exception.Message)"  
                    Write-EventLog -LogName $EventLogName -Source $EventLogSource -EntryType FailureAudit -EventId 25 -Category 0 -Message "ERROR: the group '$GroupName' has NOT been relocated to $GroupPath."
                }
            }
        }
    }
    # Cleaning up
    $xmlTarget = $void
}

## Exit
Export-DebugLog $debugMessage $DebugFile
Exit 0
