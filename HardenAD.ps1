<###################################################################
 .Synopsys

 .Detail

 .Parameter TasksSequence
  USe this parameter to specify a custom XML rile in replacement of TasksSequence_HardenAD.xml.

 .Note
 +--------+---------+---------------+-----------------------------+
 | Date   | Version | Author        | Description                 |
 +--------+---------+---------------+-----------------------------+
 |21/05/21|02.00.000| Loic.Veirman  | #1 - Script Creation        |
 +--------+---------+---------------+-----------------------------+
 |05/06/21|02.00.001| Loic.Veirman  | #2 - Display issue with the |
 |        |         |               |      progress status when   |
 |        |         |               |      pShell is minor to 5.0 |
 +--------+---------+---------------+-----------------------------+
 |22/08/21|02.00.002| Loic.Veirman  | #3 - Adapted script to use  |
 |        |         |               |      new xml file with a    |
 |        |         |               |      more understandable    |
 |        |         |               |      name.                  |
 +--------+---------+---------------+-----------------------------+
 |09/04/22|02.00.003| Loic.Veirman  | #4 - Added a test condition |
 |        |         |               |      to ensure that the     |
 |        |         |               |      script is not rerun in |
 |        |         |               |      a different domain.    |
 +--------+---------+---------------+-----------------------------+
 |07/07/22|02.00.004| Loic.Veirman  | #5 - Update to reflect new  |
 |        |         |               |      release 2.9.0.          |
 +--------+---------+---------------+-----------------------------+

###################################################################>

###################################################################
## Script input Parameters                                       ##
###################################################################
Param(
    #-Provide the tasks sequence file name (xml).
    [Parameter(mandatory = $false, Position = 0)]
    [String]
    $TasksSequence = "TasksSequence_HardenAD.xml"
)

###################################################################
## Functions                                                     ##
## ---------                                                     ##
## This part holds local function used by the sequencer only.    ##
###################################################################
Function New-LogEntry {
    Param(
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateSet("info", "warning", "debug", "error")]
        [String]
        $LogLevel,

        [Parameter(Mandatory = $true, Position = 1)]
        $LogText
    )
    #-Variables
    $Result = @()
    #-Generate timestamp
    $Timstamp = Get-Date -Format "yyyy/MM/dd hh:mm:ss"
    #-Generate log level
    Switch ($LogLevel) {
        "info" { $Level = "INFO" }
        "warning" { $Level = "WARN" }
        "debug" { $Level = "DBUG" }
        "error" { $Level = "ERR!" }
    }
    #-Format text (able to handle multiple line)
    foreach ($entry in $LogText) {
        $Result += "$Timstamp`t[$Level]`t$entry"
    }
    #-Return result
    return $Result
}

###################################################################
## Script Block                                                  ##
## ------------                                                  ##
## Function called by the script block should return a psObject: ##
## ResultCode: 0 (success), 1 (warning), 2 (error), 3 (ignore)   ##
## ResultMesg: Message to be displayed on screen.                ##
## TaskExeLog: Message to be added at global log.                ##
##                                                               ##
## When calling the block, parameters should be passed through   ##
## an array (@()); the function will then deal the parameter by  ##
## itself.                                                       ##
###################################################################
$Block = { param(   #-Name of the function to be executed
        [Parameter(Mandatory = $true, Position = 0)]
        [String]
        $Command,
        #-Parameter set to be passed as argument to $command
        [Parameter(Mandatory = $true, Position = 1)]
        $Parameters,
        #-Set the execution context in a specific path. 
        #-Needed to relocate the new pShell process at the same calling space to find modules, etc.
        [Parameter(Mandatory = $true, Position = 2)]
        [String]
        $Location,
        #-Array of modules to be loaded for this function to run.
        [Parameter(Mandatory = $false, Position = 3)]
        $mods
    )
    
    #-Relocating the new pShell session to the same location as the calling script.
    Push-Location $Location

    #-Checking OS to handle pShell 2.0
    if ((Get-WMIObject win32_operatingsystem).name -like "*2008*") {
        $is2k8r2 = $true
    }
    else {
        $is2k8r2 = $false
    }

    #-Loading modules, if needed.
    Try { 
        #-Module loading...
        if ($is2k8r2) {
            $null = $mods | foreach { Import-Module $_.fullName }
        }
        else {
            $null = $mods | foreach { Import-Module $_ }
        }
    }
    Catch { 
        #-No module to be loaded.
    }

    #-Run the function
    Try {
        #-Checking for multiple parameters and OS...
        #-More than 1 parameter but greater than 2008 R2
        if ($Parameters.count -gt 1 -and -not ($is2k8r2)) {
            $RunData = . $Command @Parameters | Select -ExcludeProperty PSComputerName, RunspaceId, PSShowComputerName
        } 
                    
        #-More than 1 parameter and is 2008 R2
        if ($Parameters.count -gt 1 -and $is2k8r2) {
            #-pShell 2.0 is not able to translate the multiple useParameters inputs from the xml file.
            # We rewrite the parmaters in a more compliant way.
            $tmpParam = @()
            for ($i = 0 ; $i -lt $Parameters.count ; $i++) {
                $tmpParam += $Parameters[$i]
            }
            $RunData = . $Command @TmpParam | Select -ExcludeProperty PSComputerName, RunspaceId, PSShowComputerName
        }
                    
        #-1 parameter or less
        if ($Parameters.count -le 1) {
            $RunData = . $Command $Parameters | Select -ExcludeProperty PSComputerName, RunspaceId, PSShowComputerName
        }
    }
    Catch {
        $RunData = New-Object -TypeName psobject -Property @{ResultCode = 9 ; ResultMesg = "Error launching the function $command" ; TaskExeLog = "Error" }
    }
            
    #.Return the result
    $RunData

}#.End ScriptBlock.

###################################################################
## Script                                                        ##
## ------                                                        ##
## Script routing which will drive the hardening of Active Dir.  ##
##                                                               ##
## Version 01.00.000 - Date 2021.05.29                           ##
###################################################################

#-Setting backgroundcolor
$Host.UI.RawUI.BackgroundColor = 'black'

#-Loading modules
# When dealing with 2008R2, we need to import AD module first
if ((Get-WMIObject win32_operatingsystem).name -like "*2008*") {
    $scriptModules = (Get-ChildItem .\Modules -Filter "*.psm1") | Select FullName
}
else {
    $scriptModules = (Get-ChildItem .\Modules -Filter "*.psm1").FullName
}


#-Setting-up usefull variables
$SchedulrConfig = [xml](get-content .\Configs\Configuration_HardenAD.xml)
$SchedulrLoging = @()
$TasksSeqConfig = [xml](get-content .\Configs\$TasksSequence)
$ScriptLocation = Get-Location                                     
$pShellMajorVer = ((Get-Host).version -split '\.')[0]

#-Setting up colors and texts scheme. 
# To deal with highlight color in display, use the ` to initiate (or end) a color change in your string,
#    then use ont of the three characters specified in value AltBaseHTxt(A,B, or C) to select your color.
#    the color will switch back to normal at the next `.
#
# Example : "This is a `[marvelous` text!"
$ColorsAndTexts = New-Object -TypeName psobject `
    -Property @{       PendingColor = "DarkGray"
    RunningColor                    = "Cyan"
    WarningColor                    = "Yellow"
    FailureColor                    = "Red"
    IgnoredColor                    = "cyan"
    SuccessColor                    = "green"
    BaseTxtColor                    = "white"
    AltBaseHColA                    = "magenta"
    AltBaseHColB                    = "yellow"
    AltBaseHColC                    = "gray"
    PendingText                     = "pending"
    RunningText                     = "running"
    WarningText                     = "warning"
    FailureText                     = "failure"
    SuccessText                     = "success"
    ignoredText                     = "ignored"
    FuncErrText                     = "!ERROR!"
    AltBaseHTxtA                    = "["
    AltBaseHTxtB                    = "("
    AltBaseHTxtC                    = "{"
}
       

#-Loading Header (yes, a bit of fun)
#Clear-Host
$LogoData = Get-Content (".\Configs\" + $SchedulrConfig.SchedulerSettings.ScriptHeader.Logo.file)
$PriTxCol = $SchedulrConfig.SchedulerSettings.ScriptHeader.Logo.DefltColor

$MaxLength = 0

foreach ($line in $LogoData) {
    Write-Host $line -ForegroundColor $PriTxCol
    if ($line.length -gt $MaxLength) { $MaxLength = $line.Length }
}

#-Loading Cartridge
# Separation
$SeparationLine = ""
For ($i = 1 ; $i -le $MaxLength ; $i++) { $SeparationLine += $SchedulrConfig.SchedulerSettings.ScriptHeader.Cartridge.BorderChar }
# Title
$ApTitle = $SchedulrConfig.SchedulerSettings.ScriptHeader.Cartridge.Name
# Version
$Version = $SchedulrConfig.SchedulerSettings.ScriptHeader.Cartridge.Version
for ($i = 1 ; $i -le $idxVers ; $i++) { $Version = " " + $Version }
# Author
$Authors = $SchedulrConfig.SchedulerSettings.ScriptHeader.Cartridge.Author
# Contributor
$apContr = $SchedulrConfig.SchedulerSettings.ScriptHeader.Cartridge.Contributor
# Description
$ApDescr = $SchedulrConfig.SchedulerSettings.ScriptHeader.Cartridge.Description
# Display
Write-Host "$SeparationLine" -ForegroundColor DarkGray
Write-Host "Script Name: " -ForegroundColor Gray -NoNewline ; Write-Host $ApTitle -ForegroundColor Green
Write-Host "Release Nbr: " -ForegroundColor Gray -NoNewline ; Write-Host $Version -ForegroundColor Yellow
Write-Host "Written by : " -ForegroundColor Gray -NoNewline ; Write-Host $Authors -ForegroundColor DarkGreen
Write-Host "             " -ForegroundColor Gray -NoNewline ; Write-Host $apContr -ForegroundColor DarkGreen
Write-Host "Description: " -ForegroundColor Gray -NoNewline ; Write-Host $ApDescr -ForegroundColor Cyan
Write-Host "$SeparationLine" -ForegroundColor DarkGray
#-Show me how nice you are ;)
Start-Sleep -Seconds 2 
#-Checking if all prerequesite are met
$InitialPosition = $host.UI.RawUI.CursorPosition
$FlagPreReq = $true
Write-Host "-------------------------"
Write-Host "Checking prerequesite:"
$Linecount = 2
$Prerequesites = $SchedulrConfig.SchedulerSettings.Prerequesites
foreach ($Prerequesite in $Prerequesites.Directory) {
    $Linecount++
    #-Checking Folder
    Write-Host "Folder " -NoNewline -ForegroundColor DarkGray
    Write-Host $Prerequesite.Name -NoNewline -ForegroundColor Gray
    if (Test-Path (".\" + $Prerequesite.Name)) { Write-Host " is present" -ForegroundColor DarkGreen }
    Else { Write-Host " is missing" -ForegroundColor DarkRed ; $FlagPreReq = $false }
    #-Checking files, if any.
    if ($Prerequesite.File) {
        foreach ($file in $Prerequesite.File) {
            $Linecount++
            Write-Host "+ File " -NoNewline -ForegroundColor DarkGray
            Write-Host $File -NoNewline -ForegroundColor Gray
            if (Test-Path (".\" + $Prerequesite.Name + "\" + $file)) { Write-Host " is present" -ForegroundColor DarkGreen }
            Else { Write-Host " is missing" -ForegroundColor DarkRed ; $FlagPreReq = $false }
        }
    }
}

#4-New test: should not contains customized GPO transcription files. 
#            If it does, then the translation should be the same as the current domain name.
Write-Host "Sanity Check: " -NoNewline -ForegroundColor DarkGray
Write-Host "Has the script already been ran? " -ForegroundColor Gray -NoNewline

if (test-path .\Inputs\GroupPolicies\translated.migtable) {
    #.We found a translated migtable. We open it as an xml file and then check if the destination is set to our domain.
    $sanityXml = [xml](Get-Content .\Inputs\GroupPolicies\translated.migtable)
    $isCurrDom = $sanityXml.MigrationTable.Mapping[0].Destination -match (Get-ADDomain).NetBIOSName
    # - popping-up the result
    Switch ($isCurrDom) {
        $true {
            Write-Host "Yes" -ForegroundColor magenta
            Write-Host "Sanity Check: " -NoNewline -ForegroundColor DarkGray
            Write-Host "is it the same netbios dom name? " -ForegroundColor Gray -NoNewline
            Write-Host "Yes" -ForegroundColor Green
        }
        
        $false {
            Write-Host "Yes" -ForegroundColor Yellow
            Write-Host "Sanity Check: " -NoNewline -ForegroundColor DarkGray
            Write-Host "is it the same netbios dom name? " -ForegroundColor Gray -NoNewline
            Write-Host "No" -ForegroundColor Red
            #.Force leaving as test failed    
            $FlagPreReq = $false 
        }
    }
}
Else {
    #.Script never run
    Write-Host "No" -ForegroundColor Green
}



#--- Updating Translations of Task Sequence file
# Check if the domain information is correct
Write-Host "-------------------------"
# Check if the domain controller is the PDC emulator (Otherwise, the script will fail to import GPOs)
$domainController_PDC = Get-ADDomainController -Discover -Service PrimaryDC
if ($domainController_PDC.Name -eq $env:COMPUTERNAME) {
    Import-Module -Name "$PSScriptRoot\Modules\translation.psm1"
    $TasksSeqConfigLocation = Split-Path -Parent $MyInvocation.MyCommand.Path
    Set-Translation -TasksSequence $TasksSequence -ScriptPath $TasksSeqConfigLocation
} else {
    Write-Warning "This domain controller is not the PDC emulator."
    Write-Warning "You need tu update manually the values in the node 'translation' of the Task_sequence file."
}
#--- EXIT









if ($FlagPreReq) {
    Write-Host "All prerequesites are OK."    
    Write-Host "-------------------------"
}
Else {
    Write-Host "Some check have failed!" -ForegroundColor Red
    Write-Host "-------------------------"
    exit 1
}
#-Clearing prerequesites data 
Start-Sleep -Seconds 2
$Host.UI.RawUI.CursorPosition = New-Object System.Management.Automation.Host.Coordinates $InitialPosition.X, $InitialPosition.Y
For ($i = 1 ; $i -le ($Linecount + 2 + 14) ; $i++) { Write-Host "                                                                       " }
$Host.UI.RawUI.CursorPosition = New-Object System.Management.Automation.Host.Coordinates $InitialPosition.X, $InitialPosition.Y
                                                     
#-Loop begins!
Start-Sleep -Seconds 2

#-Using XML
$Resume = @()




$Tasks = $TasksSeqConfig.Settings.Sequence.ID | Sort-Object number
foreach ($task in $Tasks) {
    #-Update log
    $SchedulrLoging += New-LogEntry "Info" ("NEW TASK: " + $task.Name)

    #-Checking if a DSIagreement exists
    if ($task.TaskEnabled -eq 'Yes') { 
        $doNotRun = $false 
    }
    else { 
        $doNotRun = $true 
    }

    #-Get current cusror position on screen
    $InitialPosition = $host.UI.RawUI.CursorPosition

    #-Write the newline to initiate the progress bar
    Write-Host $ColorsAndTexts.PendingText -ForegroundColor $ColorsAndTexts.PendingColor -NoNewline
    Write-Host ": " -ForegroundColor $ColorsAndTexts.BaseTxtColor -NoNewline

    #-Display the task description and managing color output
    $TextToDisplay = $task.TaskDescription -split '`'

    foreach ($Section in $TextToDisplay) {
        #-Looking at the first character: if this one is one of the AltBaseHTxt, the applying special color scheme.
        $color = $ColorsAndTexts.BaseTxtColor
        if ($Section[0] -eq $ColorsAndTexts.AltBaseHTxtA) { $color = $ColorsAndTexts.AltBaseHColA }
        if ($Section[0] -eq $ColorsAndTexts.AltBaseHTxtB) { $color = $ColorsAndTexts.AltBaseHColB }
        if ($Section[0] -eq $ColorsAndTexts.AltBaseHTxtC) { $color = $ColorsAndTexts.AltBaseHColC }
        
        #-Output text. We use a regex expression to remove the highlightCar
        #-WARNING: the regex is built fitst to fetch with $ColorsAndTexts.
        [regex]$myRegex = "\" + $ColorsAndTexts.AltBaseHTxtA + "|\" + $ColorsAndTexts.AltBaseHTxtB + "|\" + $ColorsAndTexts.AltBaseHTxtC
        Write-Host ($Section -replace $myRegex, "") -ForegroundColor $Color -NoNewline
    }

    #-Initiate waiting loop: isRunning will be the flag to keep the loop in a pending state, while charIndex will handle the new text to display.
    $isRunning = $true
    $CharIndex = -1
    
    #-Cursor management
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
    
    #-Run the job
    if (-not ($doNotRun)) { 
        $job = Start-Job -ScriptBlock $Block -Name CurrentJob -ArgumentList $task.CallingFunction, $task.UseParameters, $ScriptLocation, $scriptModules
    }
    else {
        $isRunning = $false
    }
        
    #-Looping around while the jos is still performing its task
    while ($isRunning) { 
        #-Checking the current job status.
        if ((Get-Job $job.Id).State -ne "Running") { 
            #-Flag down: exiting the loop.
            $isRunning = $false 
        } 
        #-Text animation to show the running status
        #-First, moving to the next highlighted character
        $CharIndex++
        #-Second, managing the case when we face the end of the string
        if ($CharIndex -ge [String]($ColorsAndTexts.RunningText).length) {
            #-Reinit the index to 0 (aka first character). 
            $CharIndex = 0
        }
        
        #-Managing the output
        #-First, lets relocate the cursor position to the line beginning
        $Host.UI.RawUI.CursorPosition = New-Object System.Management.Automation.Host.Coordinates $InitialPosition.X, $InitialPosition.Y
        

        #-Second, using a loop condition, let's rewrite
        for ($ptr = 0 ; $ptr -lt ($ColorsAndTexts.RunningText).length ; $ptr++) { 
            if ($CharIndex -eq $ptr) { 
                #-This character will be highlighted
                Write-Host (${hideCursor} + ([string]($ColorsAndTexts.RunningText)[$ptr]).toUpper()) -ForegroundColor $ColorsAndTexts.RunningColor -NoNewline 
            }
            else { 
                #-This character is written as usual
                Write-Host (${hideCursor} + ([string]($ColorsAndTexts.RunningText)[$ptr]).toLower()) -ForegroundColor $ColorsAndTexts.PendingColor -NoNewline 
            } 
        }
        Start-Sleep -Milliseconds 175
    }
    #-Logging
    $SchedulrLoging += New-LogEntry "debug" ("--- ----: function's ended")

    #-Grab the job result.
    if (-not ($doNotRun)) { 
        $result = Receive-Job $job.Id
    }
    else {
        $result = New-Object -TypeName psobject -Property @{Resultcode = 3 }
    }

    #-Display result on screen
    Switch ($result.ResultCode) {
        0 { $zText = $ColorsAndTexts.SuccessText ; $zColor = $ColorsAndTexts.SuccessColor }
        1 { $zText = $ColorsAndTexts.WarningText ; $zColor = $ColorsAndTexts.WarningColor }
        2 { $zText = $ColorsAndTexts.FailureText ; $zColor = $ColorsAndTexts.FailureColor }
        3 { $zText = $ColorsAndTexts.IgnoredText ; $zColor = $ColorsAndTexts.IgnoredColor }
        default { $zText = $ColorsAndTexts.FuncErrText ; $zColor = $ColorsAndTexts.FailureColor }
    }
    $Host.UI.RawUI.CursorPosition = New-Object System.Management.Automation.Host.Coordinates $InitialPosition.X, $InitialPosition.Y
    Write-Host (${hideCursor} + [string]$zText) -ForegroundColor $zColor -NoNewline
    #-Remove the job from the queue
    if (-not ($doNotRun)) { 
        Remove-Job $job.ID
    }
    #-Next line ;)
    write-host $resetAll$showCursor
    #-Keeping a resume to be displayed at the end and exported to the output folder
    $Resume += New-Object -TypeName psobject -Property @{ TaskID = $Task.Number ; TaskName = $task.Name ; TaskResult = $zText }
    #-Logging
    $SchedulrLoging += New-LogEntry "debug" @(("--- ----: TaskID     = " + $Task.Number), ("--- ----: TaskName   = " + $task.Name), "--- ----: TaskResult = $zText", ("--- ----: Message    = " + $result.ResultMesg))
    #-Extra logging when an error was faced.
    if ($zText -eq $ColorsAndTexts.FuncErrText) {
        $SchedulrLoging += New-LogEntry "error" "ERR FUNC: it seems that the called function is missing or is not properly returning its result!" 
        $SchedulrLoging += New-LogEntry "error" ("ERR FUNC: received result code: " + $result.ResultCode)
    }
}

#-Script over. exporting run log.
$csvName = (Get-Date -Format "yyyy-MM-dd_hhmmss_") + "HardenAD-Results.csv"
$logName = (Get-Date -Format "yyyy-MM-dd_hhmmss_") + "HardenAD-Results.log"

Write-Host "-------------------------"
Write-Host "Exporting results to .\Logs\" -ForegroundColor Gray -NoNewline
Write-Host $csvName -ForegroundColor DarkGray -NoNewline
Write-Host "..." -ForegroundColor Gray -NoNewline

Try { 
    $Resume | Select TaskId, TaskResult, TaskName | Sort-Object TaskID | Export-Csv .\Logs\$CsvName -Delimiter "`t" -Encoding Unicode -NoTypeInformation
    Write-Host "success" -ForegroundColor Green
}
Catch {
    Write-Host "failure" -ForegroundColor red
}

Write-Host "Exporting logging to .\Logs\" -ForegroundColor Gray -NoNewline
Write-Host $logName -ForegroundColor DarkGray -NoNewline
Write-Host "..." -ForegroundColor Gray -NoNewline

Try { 
    $SchedulrLoging | Out-File .\Logs\$LogName 
    Write-Host "success`n" -ForegroundColor Green
}
Catch {
    Write-Host "failure`n" -ForegroundColor red
}

$Resume | Select TaskId, TaskResult, TaskName | Sort-Object TaskID | Format-Table -AutoSize 
