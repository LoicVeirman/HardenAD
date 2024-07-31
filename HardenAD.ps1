<#
    .SYNOPSIS
    This script and all its dependencies will assist you in hardening an Active Directory domain.

    .DESCRIPTION
    Welcome to the Harden AD Community Edition! 
    We are really happy to offers to the comunity this free edition of Harden AD, a fully designed hardening model based on best practices and recommendation from the AD Security experts.
    We strongly encourage that you firstly read our documentation and review, at least, the TasksSequences_HardenAD.xml file. you should also give a try to our website to hunt for videos or blog articles.
    
    If you need support, please use contact@hardenad.net to reach us.

    Remember: this tool is free and you are not allowed to resell it to customers. 

    .PARAMETER NoConfirmationForRootDomain
    This parameter teach the script to automatically validate a confirmation request. Only used when working in a root domain of a forest.

    .PARAMETER EnableTask
    This parameter will modify the script and enable all or specific task on demand. You can use it in combination with -DisableTask.
    Note: this parameter will force the script to exit once the modification is done.

    .PARAMETER DisableTask
    This parameter will modify the script and disable all or specific task on demand. You can use it in combination with -EnableTask.
    Note: This parameter superseed -EnableTask.
    Note: this parameter will force the script to exit once the modification is done.

    .EXAMPLE
    HardenAD.ps1
    
    Runs the script in interactive mode.

    .EXAMPLE
    HardenAD.ps1 -NoConfirmationForSingleDomain
    
    Runs the script in non-interactive mode in the root forest domain only.

    .EXAMPLE
    HardenAD.ps1 -EnableTask All
    
    Enable all tasks in the file TasksSequence_HardenAD.xml.

    .EXAMPLE
    HardenAD.ps1 -disableTask All
    
    Disable all tasks in the file TasksSequence_HardenAD.xml.

    .EXAMPLE
    HardenAD.ps1 -EnableTask All -Disable 'Activate Active Directory Recycle Bin','Create administration accounts'
    
    Enable all tasks by default, then disable 'Activate Active Directory Recycle Bin' and 'Create administration accounts' in the file TasksSequence_HardenAD.xml.

    .EXAMPLE
    HardenAD.ps1 -EnableTask 'Activate Active Directory Recycle Bin','Create administration accounts'
    
    Enable 'Activate Active Directory Recycle Bin' and 'Create administration accounts' in the file TasksSequence_HardenAD.xml.

    .EXAMPLE
    HardenAD.ps1 -DisableTask 'Activate Active Directory Recycle Bin','Create administration accounts'
    
    Disable 'Activate Active Directory Recycle Bin' and 'Create administration accounts' in the file TasksSequence_HardenAD.xml.

    .NOTES
    Version 01.00.000 - Script creation.

    Version 02.00.000 - Script rewritten.
    Version 02.00.001 - Fixed a display issue with progress status when pShell version minor to 5.0.
    Version 02.00.002 - Updated script to match with the XML file.
    Version 02.00.003 - Added a test condition to ensure that the script was not previously ran in another domain.
    Version 02.00.004 - Updated to reflect new requierement from release 2.9.0.
    Version 02.01.000 - Added the function Format-XML to maintain the xml file in a readable format when this one is modified.
    Version 02.02.000 - Fixed some minor issues with display screen and the checking section.

    Version 03.00.000 - Script sanitization. The parameter TasksSequence has been removed. 
                        The Help section has been completed. Version are now embedded within the configuration_HardenAD.xml file.
                        The script as some easter eggs when interacting with you, that's just to make you smiling once at least ;)
                        A new parameter to bypass the validation step when running in a single forest/domain: -NoConfirmationForRootDomain.
                        Two new parameters have been added to manage the task sequence from the script: -TaskEnable and -TaskDisable (combinable).
#>
[CmdletBinding(DefaultParameterSetName = 'RUN')]
Param(
    [Parameter(ParameterSetName = 'RUN')]
    [Parameter(Position=0)]
    [switch]
    $NoConfirmationForRootDomain,

    [Parameter(ParameterSetName = 'TASK')]
    [ValidateSet('All','Activate Active Directory Recycle Bin','Create administration accounts','Create administration groups','Default computer location on creation','Default user location on creation','Enforce delegation model through ACEs','Import additional WMI Filters','Import new GPO or update existing ones','Prepare GPO files before GPO import','Restrict computer junction to the domain','Reset HAD Protected Groups Memberships','Set Administration Organizational Unit','Set GPO Central Store','Set Legacy Organizational Unit','Set Notify on every Site Links','Set Provisioning Organizational Unit','Set Tier 0 Organizational Unit','Set Tier 1 and Tier 2 Organizational Unit','Setup LAPS permissions over the domain','Update Ad schema for LAPS and deploy PShell tools','Update LAPS deployment scripts','Upgrade Domain Functional Level','Upgrade Forest Functional Level')]
    [Array]
    $EnableTask,

    [Parameter(ParameterSetName = 'TASK')]
    [ValidateSet('All','Activate Active Directory Recycle Bin','Create administration accounts','Create administration groups','Default computer location on creation','Default user location on creation','Enforce delegation model through ACEs','Import additional WMI Filters','Import new GPO or update existing ones','Prepare GPO files before GPO import','Reset HAD Protected Groups Memberships','Restrict computer junction to the domain','Set Administration Organizational Unit','Set GPO Central Store','Set Legacy Organizational Unit','Set Notify on every Site Links','Set Provisioning Organizational Unit','Set Tier 0 Organizational Unit','Set Tier 1 and Tier 2 Organizational Unit','Setup LAPS permissions over the domain','Update Ad schema for LAPS and deploy PShell tools','Update LAPS deployment scripts','Upgrade Domain Functional Level','Upgrade Forest Functional Level')]
    [Array]
    $DisableTask
)

<#
    FUNCTION: FORMAT-XML
    This function out an XML with a TAB indentation - requiered when you modify an XML.
#>
Function Format-XML
{
    Param(
        # The XML data to be formatted
        [Parameter(mandatory,Position=0)]
        [XML]
        $XML
    )  
    # Prepare the XML handler object
    $StringWriter = New-Object System.IO.StringWriter
    $XmlWriter    = New-Object System.XMl.XmlTextWriter $StringWriter

    # Configure the XML handler with our specific formatting expectation
    $xmlWriter.Formatting  = 'indented'
    $xmlWriter.Indentation = 1
    $xmlWriter.IndentChar  = "`t"

    # Reformatting the XML...
    $xml.WriteContentTo($XmlWriter)
    $XmlWriter.Flush()
    $StringWriter.Flush()

    # Returning result.
    return $StringWriter.ToString()
}

<#
    FUNCTION: NEW-LOGENTRY
    This function will format the log file output.
#>
Function New-LogEntry 
{
    Param(
        [Parameter(Mandatory, Position = 0)]
        [ValidateSet("info", "warning", "debug", "error")]
        [String]
        $LogLevel,

        [Parameter(Mandatory, Position = 1)]
        $LogText
    )
    
    # Variables
    $Result = @()
    
    # Generate timestamp
    $Timstamp = Get-Date -Format "yyyy/MM/dd HH:mm:ss"
    
    # Generate log level
    Switch ($LogLevel) 
    {
        "info"    { $Level = "INFO" }
        "warning" { $Level = "WARN" }
        "debug"   { $Level = "DBUG" }
        "error"   { $Level = "ERR!" }
    }

    # Format text (able to handle multiple line)
    foreach ($entry in $LogText) 
    {
        $Result += "$Timstamp`t[$Level]`t$entry"
    }
    
    # Return result
    return $Result
}

<#
    FUNCTION: SET-TRANSLATION
    This function will set the translation in TaskSequence.xml
#>
function Set-Translation 
{
    param (
    )

    # Loading requiered module
    Import-Module .\Modules\translation.psm1

    # Main code
    # Getting running domain and forest context
    $Domain = Get-ADDomain
    
    # Grabbing required data from domain
    $DomainDNS     = $Domain.DNSRoot
    $DomainNetBios = $Domain.NetBIOSName
    $DN            = $Domain.DistinguishedName
    $DomainSID     = $Domain.DomainSID
    $ForestDNS     = $Domain.Forest

    # Prompting for running domain information.
    Write-Host "Current forest ................: "  -ForegroundColor Gray -NoNewline ; Write-host $ForestDNS     -ForegroundColor Yellow
    Write-Host "Current domain ................: "  -ForegroundColor Gray -NoNewline ; Write-Host $DomainDNS     -ForegroundColor Yellow
    Write-Host "Current NetBIOS................: "  -ForegroundColor Gray -NoNewline ; Write-Host $DomainNetBios -ForegroundColor Yellow
    Write-Host "Current DistinguishedName......: "  -ForegroundColor Gray -NoNewline ; Write-Host $DN            -ForegroundColor Yellow

    # If not the same as the forest, will ask for confirmation.
    if ($DomainDNS -ne $ForestDNS) 
    {
        Write-Host ""
        Write-Host "Your domain is a child domain of $($ForestDNS)! Is it expected?" -ForegroundColor White -BackgroundColor Red -NoNewline
        Write-Host " [Y/N] " -NoNewline
        
        # Waiting key input. If not Y, then leaves.
        $isChild = $null
        While ($null -eq $isChild)
        {
            $key = $Host.UI.RawUI.ReadKey("IncludeKeyDown,NoEcho")
            if ($key.VirtualKeyCode -eq 89 -or $key.VirtualKeyCode -eq 13)
            {
                Write-Host "Expected, so you say...`n" -ForegroundColor Green
                $isChild = $true
            } Elseif ($key.VirtualKeyCode -eq 78) {
                Write-Host "Unexpected? Do, or do not. But there there is no try.`n" -ForegroundColor Red
                $isChild = $false
            }
        }

        # Test if child domain or not
        if ($isChild) 
        {
            #.This is a Child Domain. Adjusting the tasksSequence acordingly.
            # Grabbing expected values...
            $RootDomain        = Get-ADDomain -Identity $ForestDNS
            $RootDomainDNS     = $RootDomain.DNSRoot
            $RootDomainNetBios = $RootDomain.NetBIOSName
            $RootDN            = $RootDomain.DistinguishedName
            $RootDomainSID     = $RootDomain.DomainSID.value

            # Disable FFL Upgrade
            ($TasksSeqConfig.Settings.Sequence.Id | Where-Object { $_.Number -eq "006" }).TaskEnabled = "No"
            
            # Disable LAPS Schema update
            ($TasksSeqConfig.Settings.Sequence.Id | Where-Object { $_.Number -eq "134" }).TaskEnabled = "No"
        
        } else {
            # Not a child, setting up root domain value with current domain
            $RootDomainDNS     = $DomainDNS
            $RootDomainNetBios = $DomainNetBios
            $RootDN            = $DN
            $RootDomainSID     = $DomainSID
        }

        Write-Host "Root Domain............: " -ForegroundColor Gray -NoNewline ; Write-Host $RootDomainDNS     -ForegroundColor Yellow
        Write-Host "Root NetBIOS...........: " -ForegroundColor Gray -NoNewline ; Write-Host $RootDomainNetBios -ForegroundColor Yellow
        Write-Host "Root DistinguishedName.: " -ForegroundColor Gray -NoNewline ; Write-Host $RootDN            -ForegroundColor Yellow
    
        # Validating result and opening to a manual input if needed.
        Write-Host "`nAre those informations correct? " -ForegroundColor Yellow -NoNewline
        Write-Host "[Y/N] " -NoNewline
        
        # Waiting key input and deal with Y and return.
        $isOK = $null
        While ($null -eq $isOK)
        {
            $key = $Host.UI.RawUI.ReadKey("IncludeKeyDown,NoEcho")
            if ($key.VirtualKeyCode -eq 89 -or $key.VirtualKeyCode -eq 13)
            {
                Write-Host "Glad you'll agree with it!`n" -ForegroundColor Green
                $isOK = $true
            } Elseif ($key.VirtualKeyCode -eq 78) {
                Write-Host "'Kay... You break my heart...`n" -ForegroundColor Red
                $isOK = $false
            }
        }

        # We ask for new values if nedded, else we start.
        if (-not $isOK) 
        {
            # Ask for domain name parts
            $netbiosName = Read-Host "Enter the Root NetBIOS domain name.."
            $Domaindns   = Read-Host "Enter the Root Domain DNS..........."

            # Checking if the domain is reachable.
            Try {
                $DistinguishedName = Get-ADDomain -Server $DomainDNS -ErrorAction Stop
                $RootDomainSID     = (Get-ADDomain -Server $DomainDNS -ErrorAction Stop).DomainSID.value
            } Catch {
                $DistinguishedName = $null
                # Force leaving                    
                $isOK = $false
            }

            Write-Host "`nNew values:"            -ForegroundColor Magenta
            Write-Host "Root NetBIOS Name........: " -ForegroundColor Gray -NoNewline ; Write-Host $netbiosName       -ForegroundColor Yellow
            Write-Host "Root Domain DNS..........: " -ForegroundColor Gray -NoNewline ; Write-Host $Domaindns         -ForegroundColor Yellow
            Write-Host "Root Distinguished Name..: " -ForegroundColor Gray -NoNewline ; Write-Host $DistinguishedName -ForegroundColor Yellow
            Write-Host "Root Domain SID..........: " -ForegroundColor Gray -NoNewline ; Write-Host $RootDomainSID     -ForegroundColor Yellow
            Write-Host "`nAre those informations correct? " -ForegroundColor Magenta -NoNewline
            Write-Host "(Y/N) " -NoNewline
            
            $key = $Host.UI.RawUI.ReadKey("IncludeKeyDown,NoEcho")
                
            if ($key.VirtualKeyCode -eq 89 -or $key.VirtualKeyCode -eq 13) 
            {  
                $isOK = $true 
            } Else {
                $isOK = $false
            }
        }

        # If no issue, then script will continue. Else it exits with code 2
        if ($isOK) 
        { 
            Write-Host "Information validated.`n" -ForegroundColor Green 
        } else { 
            Write-Host "Installation canceled... Help me, Obi-Wan Kenobi. You're my only hope!`n" -ForegroundColor red
            Exit 2 
        }
    } else {
        # Not a child, setting up root domain value with current domain
        $RootDomainDNS     = $DomainDNS
        $RootDomainNetBios = $DomainNetBios
        $RootDN            = $DN
        $RootDomainSID     = $DomainSID

        # Prompting for confirmation, if needed (default value)
        if (-not $NoConfirmationForRootDomain)
        {
            Write-Host "`nDo you want to continue with those values? " -ForegroundColor Yellow -NoNewline
            Write-Host "[Y/N] " -NoNewline
            
            # Waiting key input. If not Y, then leaves.
            $dontLeaveMe = $true
            While ($dontLeaveMe) {
                $key = $Host.UI.RawUI.ReadKey("IncludeKeyDown,NoEcho")
                if ($key.VirtualKeyCode -eq 89 -or $key.VirtualKeyCode -eq 13)
                {
                    Write-Host "Going on... Or: nearly 'Just Secured', I should say." -ForegroundColor Green
                    $dontLeaveMe = $false
                } elseif ($key.VirtualKeyCode -eq 78) {
                    # Just leaving
                    Write-Host "Ok, canceling... I find your lack of faith disturbing." -ForegroundColor Red
                    Exit 0
                }
            }
        }
    }

    # Compute new wellKnownSID
    $authenticatedUsers_SID = "S-1-5-11"
    $administrators_SID     = "S-1-5-32-544"
    $RDUsers_SID            = "S-1-5-32-555"
    $users_SID              = "S-1-5-32-545"
    $Guests_SID             = "S-1-5-32-546"

    # Specific admins group of a domain
    $enterpriseAdmins_SID = "$($RootDomainSID)-519"
    $domainAdmins_SID     = "$($domainSID)-512"
    $schemaAdmins_SID     = "$($RootDomainSID)-518"
    $Guest_SID            = "$($RootDomainSID)-501"
    $DomainUsers_SID      = "$($RootDomainSID)-513"

    # Get group names from SID
    $DomainUsers_        = Get-GroupNameFromSID -GroupSID $DomainUsers_SID
    $authenticatedUsers_ = Get-GroupNameFromSID -GroupSID $authenticatedUsers_SID
    $administrators_     = Get-GroupNameFromSID -GroupSID $administrators_SID
    $RDUsers_            = Get-GroupNameFromSID -GroupSID $RDUsers_SID
    $users_              = Get-GroupNameFromSID -GroupSID $users_SID
    $Guests_             = Get-GroupNameFromSID -GroupSID $Guests_SID
    $enterpriseAdmins_   = Get-GroupNameFromSID -GroupSID $enterpriseAdmins_SID
    $domainAdmins_       = Get-GroupNameFromSID -GroupSID $domainAdmins_SID
    $schemaAdmins_       = Get-GroupNameFromSID -GroupSID $schemaAdmins_SID
    $Guest_              = Get-GroupNameFromSID -GroupSID $Guest_SID

    # Exit from script if Enterprise Admins is empty
	if ($enterpriseAdmins_ -eq "" -or $isnull -eq $enterpriseAdmins_)
	{
		Write-host "`nInstallation cancelled! You blew-up the process: the Enterprise Admins group is unreachable...`n" -ForegroundColor red
		Exit 1
	}

    # Locate the nodes to update in taskSequence File
    $wellKnownID_AU            = $TasksSeqConfig.Settings.Translation.wellKnownID | Where-Object { $_.translateFrom -eq "%AuthenticatedUsers%" }
    $wellKnownID_Adm           = $TasksSeqConfig.Settings.Translation.wellKnownID | Where-Object { $_.translateFrom -eq "%Administrators%" }
    $wellKnownID_EA            = $TasksSeqConfig.Settings.Translation.wellKnownID | Where-Object { $_.translateFrom -eq "%EnterpriseAdmins%" }
    $wellKnownID_domainAdm     = $TasksSeqConfig.Settings.Translation.wellKnownID | Where-Object { $_.translateFrom -eq "%DomainAdmins%" }
    $wellKnownID_SchemaAdm     = $TasksSeqConfig.Settings.Translation.wellKnownID | Where-Object { $_.translateFrom -eq "%SchemaAdmins%" }
    $wellKnownID_RDP           = $TasksSeqConfig.Settings.Translation.wellKnownID | Where-Object { $_.translateFrom -eq "%RemoteDesktopUsers%" }
    $wellKnownID_Users         = $TasksSeqConfig.Settings.Translation.wellKnownID | Where-Object { $_.translateFrom -eq "%Users%" }
    $wellKnownID_Netbios       = $TasksSeqConfig.Settings.Translation.wellKnownID | Where-Object { $_.translateFrom -eq "%NetBios%" }
    $wellKnownID_Domain        = $TasksSeqConfig.Settings.Translation.wellKnownID | Where-Object { $_.translateFrom -eq "%Domain%" }
    $wellKnownID_domaindns     = $TasksSeqConfig.Settings.Translation.wellKnownID | Where-Object { $_.translateFrom -eq "%domaindns%" }
    $wellKnownID_DN            = $TasksSeqConfig.Settings.Translation.wellKnownID | Where-Object { $_.translateFrom -eq "%DN%" }
    $wellKnownID_RootNetbios   = $TasksSeqConfig.Settings.Translation.wellKnownID | Where-Object { $_.translateFrom -eq "%RootNetBios%" }
    $wellKnownID_Rootdomaindns = $TasksSeqConfig.Settings.Translation.wellKnownID | Where-Object { $_.translateFrom -eq "%Rootdomaindns%" }
    $wellKnownID_RootDN        = $TasksSeqConfig.Settings.Translation.wellKnownID | Where-Object { $_.translateFrom -eq "%RootDN%" }
    $wellKnownID_Guests        = $TasksSeqConfig.Settings.Translation.wellKnownID | Where-Object { $_.translateFrom -eq "%Guests%" }
    $wellKnownID_Guest         = $TasksSeqConfig.Settings.Translation.wellKnownID | Where-Object { $_.translateFrom -eq "%Guest%" }
    $historyScript             = $TasksSeqConfig.Settings.History.Script
    $historyLastRun            = $TasksSeqConfig.Settings.History.LastRun
    $historyDomains            = $TasksSeqConfig.Settings.History.Domains
    $Groups_Group_EAmember     = $TasksSeqConfig.Settings.Groups.Group | Where-Object { $_.Name -eq "Enterprise Admins" }
    $DlgAces_ACL_Audit         = $TasksSeqConfig.Settings.DelegationACEs.ACL | Where-Object { $_.Audit -eq "True" }

    # Check if this is a PDC
    $isPDC = ((Get-ADDomain).PDCemulator -split '\.')[0] -eq $env:COMPUTERNAME

    # Updating Values :
    # ..Domain values
    $wellKnownID_Netbios.translateTo   = $DomainNetBios
    $wellKnownID_Domain.translateTo    = $DomainNetBios
    $wellKnownID_domaindns.translateTo = [string]$DomainDNS
    $wellKnownID_DN.translateTo        = $DN

    # ..RootDomain value
    $wellKnownID_RootNetbios.translateTo   = $RootDomainNetBios
    $wellKnownID_Rootdomaindns.translateTo = $RootDomainDNS
    $wellKnownID_RootDN.translateTo        = $RootDN
    
    # ..Group values
    $wellKnownID_AU.translateTo        = "$authenticatedUsers_"
    $wellKnownID_Adm.translateTo       = "$administrators_"
    $wellKnownID_EA.translateTo        = "$enterpriseAdmins_"
    $wellKnownID_domainAdm.translateTo = "$domainAdmins_"
    $wellKnownID_SchemaAdm.translateTo = "$schemaAdmins_"
    $wellKnownID_RDP.translateTo       = "$RDUsers_"
    $wellKnownID_Users.translateTo     = "$users_"
    $wellKnownID_Guests.translateTo    = "$Guests_"
    $wellKnownID_Guest.translateTo     = "$Guest_"
    $Groups_Group_EAmember.Name        = "$EnterpriseAdmins_"
    $DlgAces_ACL_Audit.Trustee         = "$DomainUsers_"

    # ..History
    $historyLastRun.Date          = [string](Get-Date -Format "yyyy/MM/dd - HH:mm")
    $historyLastRun.System        = $env:COMPUTERNAME
    $historyLastRun.isPDCemulator = [string]$isPDC
    $historyDomains.Root          = $RootDomainDNS
    $historyDomains.Domain        = [string]$DomainDNS
    $historyScript.SourcePath     = [string]((Get-Location).Path)

    # Saving file and keeping formating with tab...    
    Format-XML $TasksSeqConfig | Out-File $xmlFileFullName -Encoding utf8 -Force
}


<#
    SCRIPT BLOCK FOR RUN-JOB
    ------------------------
    Function called by the script block should return a psObject:
    > ResultCode: 0 (success), 1 (warning), 2 (error), 3 (ignore)
    > ResultMesg: Message to be displayed on screen.
    > TaskExeLog: Message to be added at global log.

    When calling the block, parameters should be passed through an array (@()); the function will then deal the parameter by itself.
#>
$Block = { 
        param(   
            # Name of the function to be executed
            [Parameter(Mandatory, Position = 0)]
            [String]
            $Command,
            
            # Parameter set to be passed as argument to $command
            [Parameter(Mandatory, Position = 1)]
            $Parameters,
            # Set the execution context in a specific path. 
            
            # Needed to relocate the new pShell process at the same calling space to find modules, etc.
            [Parameter(Mandatory, Position = 2)]
            [String]
            $Location,
            
            # Array of modules to be loaded for this function to run.
            [Parameter(Position = 3)]
            $mods
        )
    
        # Relocating the new pShell session to the same location as the calling script.
        Push-Location $Location

        # Checking OS to handle pShell 2.0
        $is2k8r2 = (Get-WMIObject win32_operatingsystem).name -like "*2008*"

        # Loading modules, if needed.
        Try { 
            # Module loading...
            Switch ($is2k8r2)
            {
                $true  { $null = $mods | ForEach-Object { Import-Module $_.fullName } }
                $false { $null = $mods | ForEach-Object { Import-Module $_ }          }
            }
        } Catch { 
            # The script block failed to load prerequiered module(s). Exiting.
            $RunData = New-Object -TypeName psobject -Property @{ResultCode = 9 ; ResultMesg = "Error loading one or more module" ; TaskExeLog = "Error" }
        }

        # Run the expected function
        Try {
            # Checking for multiple parameters and OS: more than 1 parameter but greater than 2008 R2
            if ($Parameters.count -gt 1 -and -not ($is2k8r2)) 
            {
                $RunData = . $Command @Parameters | Select-Object -ExcludeProperty PSComputerName, RunspaceId, PSShowComputerName
            } 
                        
            # Checking for multiple parameters and OS: more than 1 parameter and is 2008 R2
            if ($Parameters.count -gt 1 -and $is2k8r2) 
            {
                #-pShell 2.0 is not able to translate the multiple useParameters inputs from the xml file. We rewrite the parameters in a more compliant way.
                $tmpParam = @() ; for ($i = 0 ; $i -lt $Parameters.count ; $i++) { $tmpParam += $Parameters[$i] }
                
                $RunData = . $Command @TmpParam | Select-Object -ExcludeProperty PSComputerName, RunspaceId, PSShowComputerName
            }
                        
            # Checking for multiple parameters and OS: 1 parameter or none
            if ($Parameters.count -le 1) 
            {
                $RunData = . $Command $Parameters | Select-Object -ExcludeProperty PSComputerName, RunspaceId, PSShowComputerName
            }
        } Catch {
            $RunData = New-Object -TypeName psobject -Property @{ResultCode = 9 ; ResultMesg = "Error launching the function $command" ; TaskExeLog = "Error" }
        }
        
        # Return the result
        $RunData
}

<#
    MANAGE TASKS SEQUENCE
    ---------------------
    Script routing to update the tasks sequence before runing the main script.
    The script will forcefully exit at the end of this section to let you review the modification (or bring manually some)
    Denying a task will overide enabling it...
#>
# Loading xml and readiness for backup...
if ($EnableTask -or $DisableTask)
{
    $TasksSeqConfig  = [xml](get-content .\Configs\TasksSequence_HardenAD.xml -Encoding utf8)
    $xmlFileFullName = (resolve-path .\Configs\TasksSequence_HardenAD.xml).Path
}

# When someone wan't me to perform...
if ($EnableTask)
{
    # Dealing with the "all" case: we build the array list
    if ($EnableTask -eq 'All')
    {
        $tmpArray = Select-Xml $TasksSeqConfig -XPath "//Sequence/Id" | Select-Object -ExpandProperty "Node"
        $outArray = @() 
        $tmpArray.Name | ForEach-Object { $outArray += $_ }
    } Else {
        $outArray = $EnableTask | Where-Object { $_ -ne 'All' }
    }

    # Array is ready, let's go to modify...
    ForEach ($Task in $outArray)
    {
        $taskNode = Select-Xml $TasksSeqConfig -XPath "//Sequence/Id[@Name='$Task']" | Select-Object -ExpandProperty "Node"
        $taskNode.TaskEnabled = "Yes"
    }

    # Saving file...
    Format-XML $TasksSeqConfig | Out-File $xmlFileFullName -Encoding utf8 -Force

    # Prepare output
    $ActionMade = "enable"
}

# When someone don't wan't me to perform...
if ($DisableTask)
{
    # Dealing with the "all" case: we build the array list
    if ($DisableTask -eq 'All')
    {
        $tmpArray = Select-Xml $TasksSeqConfig -XPath "//Sequence/Id" | Select-Object -ExpandProperty "Node"
        $outArray = @()
        $tmpArray.Name | ForEach-Object { $outArray += $_ }
    } Else {
        $outArray = $DisableTask | Where-Object { $_ -ne 'All' }
    }

    # Array is ready, let's go to modify...
    ForEach ($Task in $outArray)
    {
        $taskNode = Select-Xml $TasksSeqConfig -XPath "//Sequence/Id[@Name='$Task']" | Select-Object -ExpandProperty "Node"
        $taskNode.TaskEnabled = "No"
    }

    # Saving file...
    Format-XML $TasksSeqConfig | Out-File $xmlFileFullName -Encoding utf8 -Force

    # Prepare output
    $ActionMade = "disable"
}

# Exiting if modification were made for review.
if ($EnableTask -or $DisableTask)
{
    Write-Host "The script have " -ForegroundColor Yellow -NoNewline
    Write-Host $ActionMade        -ForegroundColor Cyan   -NoNewline
    Write-Host " the selected task(s). Please find below a quick resume of the new values:" -ForegroundColor Yellow

    # Reload file to ensure that we display the real file value, not the momory ones.
    $TasksSeqConfig  = [xml](get-content .\Configs\TasksSequence_HardenAD.xml -Encoding utf8)

    # Display
    $tasks = Select-Xml $TasksSeqConfig -XPath "//Sequence/Id" | Select-Object -ExpandProperty "Node"
    $tasks | Select-Object Number, Name, TaskEnabled | Sort-Object Number | Format-Table Number,Name,TaskEnabled -AutoSize

    # Exist
    Write-Host "`nScript's done.`n" -ForegroundColor Green
    Exit 0
}

<#
    MAIN SCRIPT
    -----------
    Script routing which will drive the hardening of Active Dir.
#>

# Setting backgroundColor and foregroundColor, Then freshup display
$Host.UI.RawUI.BackgroundColor = 'black'
$Host.UI.RawUI.ForegroundColor = 'white'
Clear-Host

# Loading modules
# When dealing with 2008R2, we need to import AD module first
Switch ((Get-WMIObject win32_operatingsystem).name -like "*2008*")
{
    $True  { $scriptModules = (Get-ChildItem .\Modules -Filter "*.psm1") | Select-Object FullName }
    $false { $scriptModules = (Get-ChildItem .\Modules -Filter "*.psm1").FullName }
}

# Setting-up usefull variables
$SchedulrConfig  = [xml](get-content .\Configs\Configuration_HardenAD.xml -Encoding utf8)
$SchedulrLoging  = @()
$TasksSeqConfig  = [xml](get-content .\Configs\TasksSequence_HardenAD.xml -Encoding utf8)
$ScriptLocation  = Get-Location
$pShellMajorVer  = ((Get-Host).version -split '\.')[0]
$xmlFileFullName = (resolve-path .\Configs\TasksSequence_HardenAD.xml).Path

<# 
    Setting up colors and texts scheme. 
    To deal with highlight color in display, use the ` to initiate (or end) a color change in your string, then use ont of the three characters specified in value AltBaseHTxt(A,B, or C) to select your color.
    The color will switch back to normal at the next `. Example : "This is a `[marvelous` text!"
#>
$ColorsAndTexts = New-Object -TypeName psobject -Property @{    PendingColor = "DarkGray"
                                                                RunningColor = "Cyan"
                                                                WarningColor = "Yellow"
                                                                FailureColor = "Red"
                                                                IgnoredColor = "cyan"
                                                                SuccessColor = "green"
                                                                DisabledColor= "gray"
                                                                BaseTxtColor = "white"
                                                                AltBaseHColA = "magenta"
                                                                AltBaseHColB = "darkgray"
                                                                AltBaseHColC = "gray"
                                                                PendingText  = "pending"
                                                                RunningText  = "running"
                                                                WarningText  = "warning"
                                                                FailureText  = "failure"
                                                                SuccessText  = "success"
                                                                ignoredText  = "ignored"
                                                                FuncErrText  = "!ERROR!"
                                                                DisabledText = "disable"
                                                                AltBaseHTxtA = "["
                                                                AltBaseHTxtB = "("
                                                                AltBaseHTxtC = "{" }

# Loading Header (yes, a bit of fun)
$LogoData  = Get-Content (".\Configs\" + $SchedulrConfig.SchedulerSettings.ScriptHeader.Logo.file)
$PriTxCol  = $SchedulrConfig.SchedulerSettings.ScriptHeader.Logo.DefltColor
$MaxLength = 0

foreach ($line in $LogoData) 
{
    Write-Host $line -ForegroundColor $PriTxCol
    if ($line.length -gt $MaxLength) 
    { 
        $MaxLength = $line.Length 
    }
}

# New in version 3.0.0: the cartridge will now dynamically display information about xml files used.
# Loading Cartridge: separation line (we build a separator with a custom character and a max length previsously computed)
$SeparationLine = ""
For ($i = 1 ; $i -le $MaxLength ; $i++) 
{ 
    $SeparationLine += $SchedulrConfig.SchedulerSettings.ScriptHeader.Cartridge.BorderChar 
}

# Loading Cartridge: script title from configuration
$ApTitle = $SchedulrConfig.SchedulerSettings.ScriptHeader.Cartridge.Name

# Loading Cartridge: HAD version from tasksSequence
$Version = "$($TasksSeqConfig.Settings.Version.Release.Major).$($TasksSeqConfig.Settings.Version.Release.Minor).$($TasksSeqConfig.Settings.Version.Release.BugFix)"

# Loading Cartridge: Edition
$Edition = $TasksSeqConfig.Settings.Version.Edition.Name

# Loading Cartridge: contributor
$Contact = $SchedulrConfig.SchedulerSettings.ScriptHeader.Cartridge.Contact

# Loading Cartridge: description
$PunchLi = $SchedulrConfig.SchedulerSettings.ScriptHeader.Cartridge.Description

# Display cartridge
Write-Host $SeparationLine -ForegroundColor DarkGray
Write-Host "Script.....: " -ForegroundColor Gray -NoNewline ; Write-Host $ApTitle -ForegroundColor Green
Write-Host "Edition....: " -ForegroundColor Gray -NoNewline ; Write-Host $Edition -ForegroundColor Yellow
Write-Host "Version....: " -ForegroundColor Gray -NoNewline ; Write-Host $Version -ForegroundColor DarkGreen
Write-Host "Contact....: " -ForegroundColor Gray -NoNewline ; Write-Host $Contact -ForegroundColor DarkGray
Write-Host "Our words..: " -ForegroundColor Gray -NoNewline ; Write-Host $PunchLi -ForegroundColor Cyan
Write-Host $SeparationLine -ForegroundColor DarkGray

# Show me how nice you are ;)
Start-Sleep -Seconds 2

# Checking if all prerequesite are met.
# Version 3.0.0: there no real usage in displaying all checks... We will just focus on highlighting the failling ones.
$InitialPosition = $host.UI.RawUI.CursorPosition
$FlagPreReq      = $true

$Prerequesites = $SchedulrConfig.SchedulerSettings.Prerequesites
$NoRunDetails  = @()

foreach ($Prerequesite in $Prerequesites.Directory) 
{
    # Checking Folder
    if (-not(Test-Path (".\" + $Prerequesite.Name))) 
    { 
        $NoRunDetails += "Folder $($Prerequesite.Name) is missing" 
        $FlagPreReq    = $false 
    }
    
    # Checking files, if any.
    if ($Prerequesite.File) 
    {
        foreach ($file in $Prerequesite.File) 
        {
            if (-not (Test-Path (".\" + $Prerequesite.Name + "\" + $file)))
            { 
                $NoRunDetails += "File .\$($Prerequesite.Name)\$File is missing" 
                $FlagPreReq    = $false 
            }
        }
    }
}

# New in version 3.0.0: The script will now update the tasksSequence to teach that it has already been ran and add forest/domain information.
$TShistoryLastRun   = $TasksSeqConfig.Settings.History.LastRun.Date
$TShistoryRootDns   = $TasksSeqConfig.Settings.History.Domains.Root
$TShistoryDomainDns = $TasksSeqConfig.Settings.History.Domains.Domain

if ($TShistoryLastRun -eq "" -and $TShistoryRootDns -eq "" -and $TShistoryDomainDns -eq "")
{
    # Script has never run.
    $allowedRun = $True
} Else {
    # The script has already been ran. We need to ensure this is not a "copy/paste" in another domain/forest.
    # First: is it the same system? If so, this is ok.
    if (($env:COMPUTERNAME) -eq $TasksSeqConfig.Settings.History.LastRun.System)
    {
        $allowedRun = $true
    } Else {
        # This is not the same system, but if the domain and forest are the same, then it's ok.
        if ((Get-ADDomain).Forest -eq $TShistoryRootDns -and (Get-ADDomain).DNSRoot -eq $TShistoryDomainDns)
        {
            $allowedRun = $True
        } Else {
            # This is a problem: we need to ensure that the sources are fresh.
            # To achieve this goal, we simply hunt for any translated.migtable file in the GroupPolicy folder (those file are generated by the script on its first run).
            $TranslatedMigTable = Get-ChildItem C:\HardenAD\Inputs\GroupPolicies\ -Recurse -File -Filter "translated.migtable"
            switch ($TranslatedMigTable.count) 
            {
                0       { $allowedRun = $True  }
                Default { 
                    $NoRunDetails += "This repository seems to have already been ran on the $TShistoryLastRun, on the system $($TasksSeqConfig.Settings.History.LastRun.System)."
                    $NoRunDetails += "This repository seems to have already been ran in the forest $TShistoryRootDns for the domain $TShistoryDomainDns."
                    $NoRunDetails += "Such conditions requires to use a fresh repository, even if the TasksSequence_HardenAD.xml file remains common to both environment."
                    $allowedRun    = $false 
                }
            }
        }
    }
}

# If not allowed to run, we leave the script.
if (-not ($FlagPreReq) -or -not($allowedRun))
{
    Write-Host "`nTHE SCRIPT COULD NOT RUN:" -ForegroundColor Red
    foreach ($line in $NoRunDetails)
    {
        Write-Host "> "  -ForegroundColor Red -NoNewline
        Write-Host $Line -ForegroundColor Yellow
    }
    Write-Host "`nFix the issue(s) and retry.`n" -ForegroundColor Magenta
    Exit 1
}

# Updating the TasksSequence file to reflect the new data.
Set-Translation

if ($FlagPreReq) 
{
    Write-Host "All prerequesites are OK.`n" -ForegroundColor Green

    # Reload the config file
    $TasksSeqConfig = [xml](get-content .\Configs\TasksSequence_HardenAD.xml -Encoding utf8)

} Else {
    Write-Host "Some check have failed!" -ForegroundColor Red
    exit 1
}

# Catch initial cursor position
$InitialPosition = $host.UI.RawUI.CursorPosition
                                                     
#-Using XML
$Resume = @()

$Tasks = $TasksSeqConfig.Settings.Sequence.ID | Sort-Object Number

foreach ($task in $Tasks) 
{
    # Update log
    $SchedulrLoging += New-LogEntry "Info" ("NEW TASK: " + $task.Name)

    # Checking if a DSIagreement exists
    switch ($task.TaskEnabled)
    {
        'Yes'   { $doNotRun = $false }
        Default { $doNotRun = $True  }
    }

    # Get current cusror position on screen
    $InitialPosition = $host.UI.RawUI.CursorPosition

    # Write the newline to initiate the progress bar
    Write-Host $ColorsAndTexts.PendingText -ForegroundColor $ColorsAndTexts.PendingColor -NoNewline
    Write-Host ": " -ForegroundColor $ColorsAndTexts.BaseTxtColor -NoNewline

    #-Display the task description and managing color output
    $TextToDisplay = $task.TaskDescription -split '`'

    foreach ($Section in $TextToDisplay) 
    {
        # Looking at the first character: if this one is one of the AltBaseHTxt, the applying special color scheme.
        $color = $ColorsAndTexts.BaseTxtColor
        if ($Section[0] -eq $ColorsAndTexts.AltBaseHTxtA) { $color = $ColorsAndTexts.AltBaseHColA }
        if ($Section[0] -eq $ColorsAndTexts.AltBaseHTxtB) { $color = $ColorsAndTexts.AltBaseHColB }
        if ($Section[0] -eq $ColorsAndTexts.AltBaseHTxtC) { $color = $ColorsAndTexts.AltBaseHColC }
        
        # Output text. We use a regex expression to remove the highlightCar
        # WARNING: the regex is built fitst to fetch with $ColorsAndTexts.
        [regex]$myRegex = "\" + $ColorsAndTexts.AltBaseHTxtA + "|\" + $ColorsAndTexts.AltBaseHTxtB + "|\" + $ColorsAndTexts.AltBaseHTxtC
        Write-Host ($Section -replace $myRegex, "") -ForegroundColor $Color -NoNewline
    }

    # Initiate waiting loop: isRunning will be the flag to keep the loop in a pending state, while charIndex will handle the new text to display.
    $isRunning = $true
    $CharIndex = -1
    
    # Cursor management
    # Update for bug #6: if not pShell 5 or greater, the escape char will be ignored. Time for flashy Dance... That's backward compatibility :)
    if ($pShellMajorVer -ge 5) 
    {
        $esc = [char]27
        $hideCursor = "$esc[?25l"
        $showCursor = "$esc[?25h"
        $resetAll = "$esc[0m" 
    } else {
        $esc = $null
        $hideCursor = $null
        $showCursor = $null
        $resetAll = $null 
    }

    # Logging
    $SchedulrLoging += New-LogEntry "debug" ("--- ----: Calling function " + [string]($task.CallingFunction) + " with parameters " + [string]($task.UseParameters))
    
    # Run the job
    if (-not ($doNotRun)) 
    { 
        $job = Start-Job -ScriptBlock $Block -Name CurrentJob -ArgumentList $task.CallingFunction, $task.UseParameters, $ScriptLocation, $scriptModules
    } else {
        $isRunning = $false
    }
        
    # Looping around while the jos is still performing its task
    while ($isRunning) 
    { 
        # Checking the current job status.
        if ((Get-Job $job.Id).State -ne "Running") 
        { 
            #-Flag down: exiting the loop.
            $isRunning = $false 
        } 
        
        # Text animation to show the running status
        # First, moving to the next highlighted character
        $CharIndex++
        # Second, managing the case when we face the end of the string
        if ($CharIndex -ge [String]($ColorsAndTexts.RunningText).length) 
        {
            #-Reinit the index to 0 (aka first character). 
            $CharIndex = 0
        }
        
        # Managing the output
        # First, lets relocate the cursor position to the line beginning
        $Host.UI.RawUI.CursorPosition = New-Object System.Management.Automation.Host.Coordinates $InitialPosition.X, $InitialPosition.Y
        
        # Second, using a loop condition, let's rewrite
        for ($ptr = 0 ; $ptr -lt ($ColorsAndTexts.RunningText).length ; $ptr++) 
        { 
            if ($CharIndex -eq $ptr) 
            { 
                #-This character will be highlighted
                Write-Host (${hideCursor} + ([string]($ColorsAndTexts.RunningText)[$ptr]).toUpper()) -ForegroundColor $ColorsAndTexts.RunningColor -NoNewline 
            } else { 
                # This character is written as usual
                Write-Host (${hideCursor} + ([string]($ColorsAndTexts.RunningText)[$ptr]).toLower()) -ForegroundColor $ColorsAndTexts.PendingColor -NoNewline 
            } 
        }

        # Waiting a little time. This is the speeding for animation.
        Start-Sleep -Milliseconds 175
    }
    
    # Logging
    $SchedulrLoging += New-LogEntry "debug" ("--- ----: function's ended")

    # Grab the job result.
    if (-not ($doNotRun)) 
    { 
        $result = Receive-Job $job.Id
    } else {
        $result = New-Object -TypeName psobject -Property @{Resultcode = 4 }
    }

    # Special use case: some function ask for credential and this report badly the result - We will taks this into account.
    if ($task.CallingFunction -eq "Add-GroupsOverDomain")
    {
        $result = New-Object -TypeName psobject -Property @{Resultcode = 0}
    }

    # Display result on screen
    Switch ($result.ResultCode) 
    {
        0       { $zText = $ColorsAndTexts.SuccessText  ; $zColor = $ColorsAndTexts.SuccessColor  }
        1       { $zText = $ColorsAndTexts.WarningText  ; $zColor = $ColorsAndTexts.WarningColor  }
        2       { $zText = $ColorsAndTexts.FailureText  ; $zColor = $ColorsAndTexts.FailureColor  }
        3       { $zText = $ColorsAndTexts.IgnoredText  ; $zColor = $ColorsAndTexts.IgnoredColor  }
        4       { $zText = $ColorsAndTexts.DisabledText ; $zColor = $ColorsAndTexts.DisabledColor }
        default { $zText = $ColorsAndTexts.FuncErrText  ; $zColor = $ColorsAndTexts.FailureColor  }
    }

    $Host.UI.RawUI.CursorPosition = New-Object System.Management.Automation.Host.Coordinates $InitialPosition.X, $InitialPosition.Y
    Write-Host (${hideCursor} + [string]$zText) -ForegroundColor $zColor -NoNewline
    
    # Remove the job from the queue
    if (-not ($doNotRun)) 
    {   
        Try { Remove-Job $job.ID -ErrorAction Stop } Catch { }
    }
    # Next line ;)
    write-host $resetAll$showCursor
    
    # Keeping a resume to be displayed at the end and exported to the output folder
    $Resume += New-Object -TypeName psobject -Property @{ TaskID = $Task.Number ; TaskName = $task.Name ; TaskResult = $zText }
    
    # Logging
    $SchedulrLoging += New-LogEntry "debug" @(("--- ----: TaskID     = " + $Task.Number), ("--- ----: TaskName   = " + $task.Name), "--- ----: TaskResult = $zText", ("--- ----: Message    = " + $result.ResultMesg))
    
    # Extra logging when an error was faced.
    if ($zText -eq $ColorsAndTexts.FuncErrText) 
    {
        $SchedulrLoging += New-LogEntry "error" "ERR FUNC: it seems that the called function is missing or is not properly returning its result!" 
        $SchedulrLoging += New-LogEntry "error" ("ERR FUNC: received result code: " + $result.ResultCode)
    }
}

#-Script over. exporting run log.
$csvName = (Get-Date -Format "yyyy-MM-dd_hhmmss_") + "HardenAD-Results.csv"
$logName = (Get-Date -Format "yyyy-MM-dd_hhmmss_") + "HardenAD-Results.log"

Write-Host ""
Write-Host "Exporting results to .\Logs\" -ForegroundColor Gray     -NoNewline
Write-Host $csvName                       -ForegroundColor DarkGray -NoNewline
Write-Host "..."                          -ForegroundColor Gray     -NoNewline

Try { 
    $Resume | Select-Object TaskId, TaskResult, TaskName | Sort-Object TaskID | Export-Csv .\Logs\$CsvName -Delimiter "`t" -Encoding utf8 -NoTypeInformation
    Write-Host "success" -ForegroundColor Green
} Catch {
    Write-Host "failure" -ForegroundColor red
}

Write-Host "Exporting logging to .\Logs\" -ForegroundColor Gray     -NoNewline
Write-Host $logName                       -ForegroundColor DarkGray -NoNewline
Write-Host "..."                          -ForegroundColor Gray     -NoNewline

Try { 
    $SchedulrLoging | Out-File .\Logs\$LogName -Encoding utf8
    Write-Host "success`n" -ForegroundColor Green
} Catch {
    Write-Host "failure`n" -ForegroundColor red
}

Write-Host "`nScript's done.`n" -ForegroundColor Yellow
