# Script requirement
#Requires -RunAsAdministrator
#Requires -Version 5.0
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

    .PARAMETER EditTasksSequence
    Run the GUI to edit which tasksSequence should be performed.

    .PARAMETER EditGpoActivation
    Run the GUI to edit which GPO should be imported.

    .PARAMETER EnableTask
    This parameter will modify the script and enable all or specific task on demand. You can use it in combination with -DisableTask.
    Note: this parameter will force the script to exit once the modification is done.

    .PARAMETER DisableTask
    This parameter will modify the script and disable all or specific task on demand. You can use it in combination with -EnableTask.
    Note: This parameter superseed -EnableTask.
    Note: this parameter will force the script to exit once the modification is done.

    .EXAMPLE
    HardenAD.ps1
    
    Runs the script.

    .EXAMPLE
    HardenAD.ps1 -NoConfirmationForSingleDomain
    
    Runs the script in non-interactive mode in the root forest domain only.

    .EXAMPLE
    HardenAD.ps1 -EditTasksSequence

    Launches the GUI to enable or disable task in the sequence.

    .EXAMPLE
    HArdenAD.ps1 -EditGpoActivation

    Launches the GUI to enable or disable a GPO import.

    .EXAMPLE
    HardenAD.ps1 -EnableTask All
    
    Enable all tasks in the file TasksSequence_HardenAD.xml.

    .EXAMPLE
    HardenAD.ps1 -DisableTask All
    
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
    Version 03.01.000 - Script rewrite to handle move of some function that was part of the main code.
    Version 03.01.001 - Integration of 2 GUI (GPO and TASKS management).
#>
[CmdletBinding(DefaultParameterSetName = 'RUN')]
Param(
    [Parameter(ParameterSetName = 'RUN')]
    [Parameter(Position = 0)]
    [switch]
    $NoConfirmationForRootDomain,

    [Parameter(ParameterSetName = 'CONFIGTASK')]
    [Parameter(Position = 0)]
    [switch]
    $EditTasksSequence,

    [Parameter(ParameterSetName = 'CONFIGGPO')]
    [Parameter(Position = 0)]
    [switch]
    $EditGpoActivation,

    [Parameter(ParameterSetName = 'TASK')]
    [ValidateSet('All', 'Activate Active Directory Recycle Bin', 'Create administration accounts', 'Create administration groups', 'Default computer location on creation', 'Default user location on creation', 'Enforce delegation model through ACEs', 'Import additional WMI Filters', 'Import new GPO or update existing ones', 'Prepare GPO files before GPO import', 'Restrict computer junction to the domain', 'Reset HAD Protected Groups Memberships', 'Set Administration Organizational Unit', 'Set GPO Central Store', 'Set Legacy Organizational Unit', 'Set Notify on every Site Links', 'Set Provisioning Organizational Unit', 'Set Tier 0 Organizational Unit', 'Set Tier 1 and Tier 2 Organizational Unit', 'Setup LAPS permissions over the domain', 'Update Ad schema for LAPS and deploy PShell tools', 'Update LAPS deployment scripts', 'Upgrade Domain Functional Level', 'Upgrade Forest Functional Level')]
    [Array]
    $EnableTask,

    [Parameter(ParameterSetName = 'TASK')]
    [ValidateSet('All', 'Activate Active Directory Recycle Bin', 'Create administration accounts', 'Create administration groups', 'Default computer location on creation', 'Default user location on creation', 'Enforce delegation model through ACEs', 'Import additional WMI Filters', 'Import new GPO or update existing ones', 'Prepare GPO files before GPO import', 'Reset HAD Protected Groups Memberships', 'Restrict computer junction to the domain', 'Set Administration Organizational Unit', 'Set GPO Central Store', 'Set Legacy Organizational Unit', 'Set Notify on every Site Links', 'Set Provisioning Organizational Unit', 'Set Tier 0 Organizational Unit', 'Set Tier 1 and Tier 2 Organizational Unit', 'Setup LAPS permissions over the domain', 'Update Ad schema for LAPS and deploy PShell tools', 'Update LAPS deployment scripts', 'Upgrade Domain Functional Level', 'Upgrade Forest Functional Level')]
    [Array]
    $DisableTask
)
#region Initialize and functions

# Using ANSI Escape code
$FG_Purple      = "$([char]0x1b)[38;2;142;140;216;24m"                  # 38:Foreground, 2:RGB, Red:142, Green:140, Blue:216, 24: not underlined
$BG_Purple      = "$([char]0x1b)[48;2;142;140;216m"                     # 48:background, 2:RGB, Red:142, Green:140, Blue:216
$FG_Purple_U    = "$([char]0x1b)[38;2;142;140;216;4m"                   # 38:Foreground, 2:RGB, Red:142, Green:140, Blue:216, 4: underlined
$FG_Blue        = "$([char]0x1b)[38;2;94;153;255m"                      # 38:Foreground, 2:RGB, Red:94 , Green:153, Blue:255 
$FG_Turquoise   = "$([char]0x1b)[38;2;0;175;204;24m"                    # 38:Foreground, 2:RGB, Red:0  , Green:175, Blue:204, 24: not underlined
$FG_RedLight    = "$([char]0x1b)[38;2;244;135;69m"                      # 38:Foreground, 2:RGB, Red:244, Green:135, Blue:69
$FG_Orange      = "$([char]0x1b)[38;2;255;171;21m"                      # 38:Foreground, 2:RGB, Red:255, Green:171, Blue:21
$FG_GreenLight  = "$([char]0x1b)[38;5;42;24m"                           # 38:Foreground, 5:Indexed Color, 42: Green, 24: not underlined
$FG_PinkDark    = "$([char]0x1b)[38;2;218;101;167m"                     # 38:Foreground, 2:RGB, Red:218, Green:101, Blue:167
$FG_yellowLight = "$([char]0x1b)[38;2;220;220;170;24m"                  # 38:Foreground, 2:RGB, Red:22°, Green:220, Blue:170, 24: not underlined
$FG_Red         = "$([char]0x1b)[38;2;255;0;0m"                         # 38:Foreground, 2:RGB, Red:255, Green:0  , Blue:0
$FG_BrightCyan  = "$([char]0x1b)[96;24m"                                # 96:24 bits color code from standard VGA, 24: not underlined
$FG_brown       = "$([char]0x1b)[38;2;206;145;120m"                     # 38:Foreground, 2:RGB, Red:206, Green:146, Blue:120
$SelectedChoice = "$([char]0x1b)[38;2;255;210;0;48;2;0;175;204;24m"     # 38:Foreground, 2:RGB, Red:255, Green:210, Blue:0  , 48:Background, 2:RGB, Red:0  ,Green:175, Blue:204, 24: not underlined
$ANSI_End       = "$([char]0x1b)[0m"                                    # 0: end of ANSI, reset to default. 

# Load modules
try {
    $modules = (Get-ChildItem .\modules).FullName
    [void](Import-Module $modules -ErrorAction Stop)
} Catch {
    Write-Host "Error: $($_.ToString())" -ForegroundColor Red
    exit 999
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

    # Loading modules, if needed.
    try { 
        # Module loading...
        #write-host (resolve-path .\modules) -backgroundcolor red -ForegroundColor white
        $modules = (Get-ChildItem .\modules).FullName
        [void](Import-Module $modules -ErrorAction Stop)
    }
    catch { 
        # The script block failed to load prerequiered module(s). Exiting.
        $RunData = New-Object -TypeName psobject -Property @{ResultCode = 9 ; ResultMesg = "Error:$($_.ToString())" ; TaskExeLog = "Error" }
    }

    # Run the expected function
    try {
        # Checking for multiple parameters and OS: more than 1 parameter but greater than 2008 R2
        if ($Parameters.count -gt 1 -and -not ($is2k8r2)) {
            $RunData = . $Command @Parameters | Select-Object -ExcludeProperty PSComputerName, RunspaceId, PSShowComputerName
        } 
                        
        # Checking for multiple parameters and OS: more than 1 parameter and is 2008 R2
        if ($Parameters.count -gt 1 -and $is2k8r2) {
            #-pShell 2.0 is not able to translate the multiple useParameters inputs from the xml file. We rewrite the parameters in a more compliant way.
            $tmpParam = @() ; for ($i = 0 ; $i -lt $Parameters.count ; $i++) { $tmpParam += $Parameters[$i] }
                
            $RunData = . $Command @TmpParam | Select-Object -ExcludeProperty PSComputerName, RunspaceId, PSShowComputerName
        }
                        
        # Checking for multiple parameters and OS: 1 parameter or none
        if ($Parameters.count -le 1) {
            $RunData = . $Command $Parameters | Select-Object -ExcludeProperty PSComputerName, RunspaceId, PSShowComputerName
        }
    }
    catch {
        $RunData = New-Object -TypeName psobject -Property @{ResultCode = 9 ; ResultMesg = "Error launching the function $command" ; TaskExeLog = "Error" }
    }
        
    # Return the result
    $RunData
}
#endregion

#region Tasks Sequence Management
<#
    MANAGE TASKS SEQUENCE
    ---------------------
    Script routing to update the tasks sequence before runing the main script.
    The script will forcefully exit at the end of this section to let you review the modification (or bring manually some)
    Denying a task will overide enabling it...
#>
# Loading xml and readiness for backup...

if ($EditTasksSequence) {
    # Launching GUI
    & "$PSSCRIPTROOT\Tools\Invoke-HardenADTask\Invoke-HardenADTask.ps1"
    return "${FG_yellowLight}Please, rerun ${FG_Purple_U}HardenAD.ps1${ANSI_End}${FG_yellowLight} to continue your hardening journey.${ANSI_End}"
}

if ($EditGpoActivation) {
    # Launching GUI
    & "$PSSCRIPTROOT\Tools\Invoke-HardenADGpo\Invoke-HardenADGpo.ps1"
    return "${FG_yellowLight}Please, rerun ${FG_Purple_U}HardenAD.ps1${ANSI_End}${FG_yellowLight} to continue your hardening journey.${ANSI_End}"
}

if ($EnableTask -or $DisableTask) {
    $TasksSeqConfig = [xml](Get-Content .\Configs\TasksSequence_HardenAD.xml -Encoding utf8)
    $xmlFileFullName = (Resolve-Path .\Configs\TasksSequence_HardenAD.xml).Path
}

# When someone wan't me to perform...
if ($EnableTask) {
    # Dealing with the "all" case: we build the array list
    if ($EnableTask -eq 'All') {
        $tmpArray = Select-Xml $TasksSeqConfig -XPath "//Sequence/Id" | Select-Object -ExpandProperty "Node"
        $outArray = @() 
        $tmpArray.Name | ForEach-Object { $outArray += $_ }
    }
    else {
        $outArray = $EnableTask | Where-Object { $_ -ne 'All' }
    }

    # Array is ready, let's go to modify...
    ForEach ($Task in $outArray) {
        $taskNode = Select-Xml $TasksSeqConfig -XPath "//Sequence/Id[@Name='$Task']" | Select-Object -ExpandProperty "Node"
        $taskNode.TaskEnabled = "Yes"
    }

    # Saving file...
    Format-XMLData -XMLData $TasksSeqConfig | Out-File $xmlFileFullName -Encoding utf8 -Force

    # Prepare output
    $ActionMade = "enable"
}

# When someone don't wan't me to perform...
if ($DisableTask) {
    # Dealing with the "all" case: we build the array list
    if ($DisableTask -eq 'All') {
        $tmpArray = Select-Xml $TasksSeqConfig -XPath "//Sequence/Id" | Select-Object -ExpandProperty "Node"
        $outArray = @()
        $tmpArray.Name | ForEach-Object { $outArray += $_ }
    }
    else {
        $outArray = $DisableTask | Where-Object { $_ -ne 'All' }
    }

    # Array is ready, let's go to modify...
    ForEach ($Task in $outArray) {
        $taskNode = Select-Xml $TasksSeqConfig -XPath "//Sequence/Id[@Name='$Task']" | Select-Object -ExpandProperty "Node"
        $taskNode.TaskEnabled = "No"
    }

    # Saving file...
    Format-XMLData -XMLData $TasksSeqConfig | Out-File $xmlFileFullName -Encoding utf8 -Force

    # Prepare output
    $ActionMade = "disable"
}

# Exiting if modification were made for review.
if ($EnableTask -or $DisableTask) {
    Write-Host "The script have " -ForegroundColor Yellow -NoNewline
    Write-Host $ActionMade        -ForegroundColor Cyan   -NoNewline
    Write-Host " the selected task(s). Please find below a quick resume of the new values:" -ForegroundColor Yellow

    # Reload file to ensure that we display the real file values, not the memory ones.
    $TasksSeqConfig = [xml](Get-Content .\Configs\TasksSequence_HardenAD.xml -Encoding utf8)

    # Display
    $tasks = Select-Xml $TasksSeqConfig -XPath "//Sequence/Id" | Select-Object -ExpandProperty "Node"
    $tasks | Select-Object Number, Name, TaskEnabled | Sort-Object Number | Format-Table Number, Name, TaskEnabled -AutoSize

    # Exist
    Write-Host "`nScript's done.`n" -ForegroundColor Green
    exit 0
}
#endregion

#region Script
<#
    MAIN SCRIPT
    -----------
    Script routing which will drive the hardening of Active Dir.
#>

# Setting backgroundColor and foregroundColor, Then freshup display
$Host.UI.RawUI.BackgroundColor = 'black'
$Host.UI.RawUI.ForegroundColor = 'white'
Clear-Host

# Setting-up usefull variables
$SchedulrConfig = [xml](get-content .\Configs\Configuration_HardenAD.xml -Encoding utf8)
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
$ColorsAndTexts = New-Object -TypeName psobject -Property @{    
    PendingColor = "DarkGray"
    RunningColor = "Cyan"
    WarningColor = "Yellow"
    FailureColor = "Red"
    IgnoredColor = "cyan"
    SuccessColor = "green"
    DisabledColor= "gray"
    CanceledColor= "Magenta"
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
    CanceledText = "cancel!"
    FuncErrText  = "!ERROR!"
    DisabledText = "disable"
    AltBaseHTxtA = "["
    AltBaseHTxtB = "("
    AltBaseHTxtC = "{" 
}

# Loading Header (yes, a bit of fun)
$S_blueHarden = "$([char]0x1b)[38;2;43;200;255m"
$Cend         = "$([char]0x1b)[0m"

$LogoData = Get-Content (".\Configs\" + $SchedulrConfig.SchedulerSettings.ScriptHeader.Logo.file)
$MaxLength = 0

foreach ($line in $LogoData) {
    Write-Host "${S_BlueHarden}$line${Cend}" #-ForegroundColor $PriTxCol
    if ($line.length -gt $MaxLength) { 
        $MaxLength = $line.Length 
    }
}

# New in version 3.0.0: the cartridge will now dynamically display information about xml files used.
# Loading Cartridge: separation line (we build a separator with a custom character and a max length previsously computed)
$SeparationLine = ""
for ($i = 1 ; $i -le $MaxLength ; $i++) { 
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
$FlagPreReq = $true

$Prerequesites = $SchedulrConfig.SchedulerSettings.Prerequesites
$NoRunDetails = @()

foreach ($Prerequesite in $Prerequesites.Directory) {
    # Checking Folder
    if (-not(Test-Path (".\" + $Prerequesite.Name))) { 
        $NoRunDetails += "Folder $($Prerequesite.Name) is missing" 
        $FlagPreReq = $false 
    }
    
    # Checking files, if any.
    if ($Prerequesite.File) {
        foreach ($file in $Prerequesite.File) {
            if (-not (Test-Path (".\" + $Prerequesite.Name + "\" + $file))) { 
                $NoRunDetails += "File .\$($Prerequesite.Name)\$File is missing" 
                $FlagPreReq = $false 
            }
        }
    }
}

# New in version 3.0.0: The script will now update the tasksSequence to teach that it has already been ran and add forest/domain information.
$TShistoryLastRun   = $TasksSeqConfig.Settings.History.LastRun.Date
$TShistoryRootDns   = $TasksSeqConfig.Settings.History.Domains.Root
$TShistoryDomainDns = $TasksSeqConfig.Settings.History.Domains.Domain

if ($TShistoryLastRun -eq "" -and $TShistoryRootDns -eq "" -and $TShistoryDomainDns -eq "") {
    # Script has never run.
    $allowedRun = $True
}
else {
    # The script has already been ran. We need to ensure this is not a "copy/paste" in another domain/forest.
    # First: is it the same system? If so, this is ok.
    if (($env:COMPUTERNAME) -eq $TasksSeqConfig.Settings.History.LastRun.System) {
        $allowedRun = $true
    }
    else {
        # This is not the same system, but if the domain and forest are the same, then it's ok.
        if ((Get-ADDomain).Forest -eq $TShistoryRootDns -and (Get-ADDomain).DNSRoot -eq $TShistoryDomainDns) {
            $allowedRun = $True
        }
        else {
            # This is a problem: we need to ensure that the sources are fresh.
            # To achieve this goal, we simply hunt for any translated.migtable file in the GroupPolicy folder (those file are generated by the script on its first run).
            $TranslatedMigTable = Get-ChildItem C:\HardenAD\Inputs\GroupPolicies\ -Recurse -File -Filter "translated.migtable"
            switch ($TranslatedMigTable.count) {
                0 { $allowedRun = $True }
                Default { 
                    $NoRunDetails += "This repository seems to have already been ran on the $TShistoryLastRun, on the system $($TasksSeqConfig.Settings.History.LastRun.System)."
                    $NoRunDetails += "This repository seems to have already been ran in the forest $TShistoryRootDns for the domain $TShistoryDomainDns."
                    $NoRunDetails += "Such conditions requires to use a fresh repository, even if the TasksSequence_HardenAD.xml file remains common to both environment."
                    $allowedRun = $false 
                }
            }
        }
    }
}

# If not allowed to run, we leave the script.
if (-not ($FlagPreReq) -or -not($allowedRun)) {
    Write-Host "`nTHE SCRIPT COULD NOT RUN:" -ForegroundColor Red
    foreach ($line in $NoRunDetails) {
        Write-Host "> "  -ForegroundColor Red -NoNewline
        Write-Host $Line -ForegroundColor Yellow
    }
    Write-Host "`nFix the issue(s) and retry.`n" -ForegroundColor Magenta
    exit 1
}

# Updating the TasksSequence file to reflect the new data.
$control = Set-Translation -tasksSeqConfig $TasksSeqConfig -xmlFileFullName $xmlFileFullName $NoConfirmationForRootDomain
switch -regex ($control) {
    [0-2] { Exit $control }
}
if ($FlagPreReq) {
    Write-Host "All prerequesites are OK.`n" -ForegroundColor Green

    # Reload the config file
    $TasksSeqConfig = [xml](get-content .\Configs\TasksSequence_HardenAD.xml -Encoding utf8)
}
else {
    Write-Host "Some check have failed!" -ForegroundColor Red
    exit 1
}

# Catch initial cursor position
$InitialPosition = $host.UI.RawUI.CursorPosition

#-Using XML
$Resume = @()

$Tasks = $TasksSeqConfig.Settings.Sequence.ID | Sort-Object Number

foreach ($task in $Tasks) {
    # Update log
    $SchedulrLoging += New-LogEntry "Info" ("NEW TASK: " + $task.Name)

    # Checking if a DSIagreement exists
    switch ($task.TaskEnabled) {
        'Yes' { $doNotRun = $false }
        Default { $doNotRun = $True }
    }

    # Get current cusror position on screen
    $InitialPosition = $host.UI.RawUI.CursorPosition

    # Write the newline to initiate the progress bar
    Write-Host $ColorsAndTexts.PendingText -ForegroundColor $ColorsAndTexts.PendingColor -NoNewline
    Write-Host ": " -ForegroundColor $ColorsAndTexts.BaseTxtColor -NoNewline

    #-Display the task description and managing color output
    $TextToDisplay = $task.TaskDescription -split '`'

    foreach ($Section in $TextToDisplay) {
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
    if ($pShellMajorVer -ge 5) {
        $esc = [char]27
        $hideCursor = "$esc[?25l"
        $showCursor = "$esc[?25h"
        $resetAll = "$esc[0m" 
    }
    else {
        $esc = $null
        $hideCursor = $null
        $showCursor = $null
        $resetAll = $null 
    }

    # Logging
    $SchedulrLoging += New-LogEntry "debug" ("--- ----: Calling function " + [string]($task.CallingFunction) + " with parameters " + [string]($task.UseParameters))
    
    # Run the job
    if (-not ($doNotRun)) { 
        $job = Start-Job -ScriptBlock $Block -Name CurrentJob -ArgumentList $task.CallingFunction, $task.UseParameters, $ScriptLocation, $scriptModules
    }
    else {
        $isRunning = $false
    }
        
    # Looping around while the jos is still performing its task
    while ($isRunning) { 
        # Checking the current job status.
        if ((Get-Job $job.Id).State -ne "Running") { 
            #-Flag down: exiting the loop.
            $isRunning = $false 
        } 
        
        # Text animation to show the running status
        # First, moving to the next highlighted character
        $CharIndex++
        # Second, managing the case when we face the end of the string
        if ($CharIndex -ge [String]($ColorsAndTexts.RunningText).length) {
            #-Reinit the index to 0 (aka first character). 
            $CharIndex = 0
        }
        
        # Managing the output
        # First, lets relocate the cursor position to the line beginning
        $Host.UI.RawUI.CursorPosition = New-Object System.Management.Automation.Host.Coordinates $InitialPosition.X, $InitialPosition.Y
        
        # Second, using a loop condition, let's rewrite
        for ($ptr = 0 ; $ptr -lt ($ColorsAndTexts.RunningText).length ; $ptr++) { 
            if ($CharIndex -eq $ptr) { 
                #-This character will be highlighted
                Write-Host (${hideCursor} + ([string]($ColorsAndTexts.RunningText)[$ptr]).toUpper()) -ForegroundColor $ColorsAndTexts.RunningColor -NoNewline 
            }
            else { 
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
    if (-not ($doNotRun)) { 
        $result = Receive-Job $job.Id
    }
    else {
        $result = New-Object -TypeName psobject -Property @{Resultcode = 4 }
    }

    # Special use case: some function ask for credential and this report badly the result - We will taks this into account.
    if ($task.CallingFunction -eq "Add-GroupsOverDomain") {
        $result = New-Object -TypeName psobject -Property @{Resultcode = 0 }
    }

    # Display result on screen
    Switch ($result.ResultCode) {
        0 { $zText = $ColorsAndTexts.SuccessText  ; $zColor = $ColorsAndTexts.SuccessColor }
        1 { $zText = $ColorsAndTexts.WarningText  ; $zColor = $ColorsAndTexts.WarningColor }
        2 { $zText = $ColorsAndTexts.FailureText  ; $zColor = $ColorsAndTexts.FailureColor }
        3 { $zText = $ColorsAndTexts.IgnoredText  ; $zColor = $ColorsAndTexts.IgnoredColor }
        4 { $zText = $ColorsAndTexts.DisabledText ; $zColor = $ColorsAndTexts.DisabledColor }
        5 { $zText = $ColorsAndTexts.CanceledText ; $zColor = $ColorsAndTexts.CanceledColor }
        default { $zText = $ColorsAndTexts.FuncErrText  ; $zColor = $ColorsAndTexts.FailureColor }
    }

    $Host.UI.RawUI.CursorPosition = New-Object System.Management.Automation.Host.Coordinates $InitialPosition.X, $InitialPosition.Y
    Write-Host (${hideCursor} + [string]$zText) -ForegroundColor $zColor -NoNewline
    
    # Remove the job from the queue
    if (-not ($doNotRun)) {   
        try { Remove-Job $job.ID -ErrorAction Stop } catch { }
    }
    # Next line ;)
    write-host $resetAll$showCursor
    
    # Keeping a resume to be displayed at the end and exported to the output folder
    $Resume += New-Object -TypeName psobject -Property @{ TaskID = $Task.Number ; TaskName = $task.Name ; TaskResult = $zText }
    
    # Logging
    $SchedulrLoging += New-LogEntry "debug" @(("--- ----: TaskID     = " + $Task.Number), ("--- ----: TaskName   = " + $task.Name), "--- ----: TaskResult = $zText", ("--- ----: Message    = " + $result.ResultMesg))
    
    # Extra logging when an error was faced.
    if ($zText -eq $ColorsAndTexts.FuncErrText) {
        $SchedulrLoging += New-LogEntry "error" "ERR FUNC: it seems that the called function is missing or is not properly returning its result!" 
        $SchedulrLoging += New-LogEntry "error" ("ERR FUNC: received result code: " + $result.ResultCode)
    }
}
#endregion

#region finalization
#-Script over. exporting run log.
$csvName = (Get-Date -Format "yyyy-MM-dd_hhmmss_") + "HardenAD-Results.csv"
$logName = (Get-Date -Format "yyyy-MM-dd_hhmmss_") + "HardenAD-Results.log"

Write-Host ""
Write-Host "Exporting results to .\Logs\" -ForegroundColor Gray     -NoNewline
Write-Host $csvName                       -ForegroundColor DarkGray -NoNewline
Write-Host "..."                          -ForegroundColor Gray     -NoNewline

try { 
    $Resume | Select-Object TaskId, TaskResult, TaskName | Sort-Object TaskID | Export-Csv .\Logs\$CsvName -Delimiter "`t" -Encoding utf8 -NoTypeInformation
    Write-Host "success" -ForegroundColor Green
}
catch {
    Write-Host "failure" -ForegroundColor red
}

Write-Host "Exporting logging to .\Logs\" -ForegroundColor Gray     -NoNewline
Write-Host $logName                       -ForegroundColor DarkGray -NoNewline
Write-Host "..."                          -ForegroundColor Gray     -NoNewline

try { 
    $SchedulrLoging | Out-File .\Logs\$LogName -Encoding utf8
    Write-Host "success`n" -ForegroundColor Green
}
catch {
    Write-Host "failure`n" -ForegroundColor red
}

Write-Host "`nScript's done.`n" -ForegroundColor Yellow
#endregion