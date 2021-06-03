<###################################################################
 .Synopsys

 .Detail

 .Parameter

 .Note
 +--------+---------+---------------+-----------------------------+
 | Date   | Version | Author        | Description                 |
 +--------+---------+---------------+-----------------------------+
 |21/05/31|02.00.000| Loic.Veirman  | Script Creation             |
 +--------+---------+---------------+-----------------------------+

###################################################################>

###################################################################
## Script input Parameters                                       ##
###################################################################
Param(
    #-Provide the tasks sequence file name (xml).
    [Parameter(mandatory=$false,Position=0)]
    [String]
    $TasksSequence="TasksSequence_HardenAD.xml"
)

###################################################################
## Script Block                                                  ##
## ------------                                                  ##
## Function called by the script block should return a psObject: ##
## ResultCode: 0 (success), 1 (warning) or 2 (error)             ##
## ResultMesg: Message to be displayed on screen.                ##
## TaskExeLog: Message to be added at global log.                ##
##                                                               ##
## When calling the block, parameters should be passed through   ##
## an array (@()); the function will then deal the parameter by  ##
## itself.                                                       ##
###################################################################
$Block = {  param(   #-Name of the function to be executed
                    [Parameter(Mandatory=$true,Position=0)]
                    [String]
                    $Command,
                    #-Parameter set to be passed as argument to $command
                    [Parameter(Mandatory=$true,Position=1)]
                    $Parameters,
                    #-Set the execution context in a specific path. 
                    #-Needed to relocate the new pShell process at the same calling space to find modules, etc.
                    [Parameter(Mandatory=$true,Position=2)]
                    [String]
                    $Location,
                    #-Array of modules to be loaded for this function to run.
                    [Parameter(Mandatory=$false,Position=3)]
                    $mods
                )
    
            #-Relocating the new pShell session to the same location as the calling script.
            Push-Location $Location

            #-Loading modules, if needed.
            Try   { 
                    #-Module loading...
                    $mods | foreach { Import-Module $_ }
                  }
            Catch { 
                    #-No module to be loaded.
                  }

            #-Run the function 
            $RunData = . $Command $Parameters | Select -ExcludeProperty PSComputerName,RunspaceId,PSShowComputerName
            
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
$scriptModules  = (Get-ChildItem .\Modules -Filter "*.psm1").FullName

#-Setting-up usefull variables
$SchedulrConfig = [xml](get-content .\Configs\Configuration_Scheduler.xml)
$TasksSeqConfig = [xml](get-content .\Configs\$TasksSequence)
$ScriptLocation = Get-Location                                     

#-Setting uip colors and texts scheme. 
# To deal with highlight color in display, use the ` to initiate (or end) a color change in your string,
#    then use ont of the three characters specified in value AltBaseHTxt(A,B, or C) to select your color.
#    the color will switch back to normal at the next `.
#
# Example : "This is a `[marvelous` text!"
$ColorsAndTexts = New-Object -TypeName psobject `
                             -Property @{       PendingColor = "DarkGray"
                                                RunningColor = "Cyan"
                                                WarningColor = "Yellow"
                                                FailureColor = "Red"
                                                IgnoredColor = "gray"
                                                SuccessColor = "green"
                                                BaseTxtColor = "white"
                                                AltBaseHColA = "magenta"
                                                AltBaseHColB = "yellow"
                                                AltBaseHColC = "gray"
                                                PendingText  = "pending"
                                                RunningText  = "running"
                                                WarningText  = "warning"
                                                FailureText  = "failure"
                                                SuccessText  = "success"
                                                ignoredText  = "ignored"
                                                AltBaseHTxtA = "["
                                                AltBaseHTxtB = "("
                                                AltBaseHTxtC = "{"
                                         }
       

#-Loading Header (yes, a bit of fun)
Clear-Host
$LogoData = Get-Content (".\Configs\" + $SchedulrConfig.SchedulerSettings.ScriptHeader.Logo.file)
$PriTxCol = $SchedulrConfig.SchedulerSettings.ScriptHeader.Logo.DefltColor

$MaxLength = 0

foreach ($line in $LogoData)
{
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

#-Checking if all prerequesite are met
$InitialPosition = $host.UI.RawUI.CursorPosition
$FlagPreReq = $true
Write-Host "-------------------------"
Write-Host "Checking prerequesite:"
$Linecount = 2
$Prerequesites = $SchedulrConfig.SchedulerSettings.Prerequesites
foreach ($Prerequesite in $Prerequesites.Directory)
{
    $Linecount++
    #-Checking Folder
    Write-Host "Folder " -NoNewline -ForegroundColor DarkGray
    Write-Host $Prerequesite.Name -NoNewline -ForegroundColor Gray
    if (Test-Path (".\" + $Prerequesite.Name)) { Write-Host " is present" -ForegroundColor DarkGreen }
    Else { Write-Host " is missing" -ForegroundColor DarkRed ; $FlagPreReq = $false }
    #-Checking files, if any.
    if ($Prerequesite.File)
    {
        foreach ($file in $Prerequesite.File)
        {
            $Linecount++
            Write-Host "+ File " -NoNewline -ForegroundColor DarkGray
            Write-Host $File -NoNewline -ForegroundColor Gray
            if (Test-Path (".\" + $Prerequesite.Name + "\" + $file)) { Write-Host " is present" -ForegroundColor DarkGreen }
            Else { Write-Host " is missing" -ForegroundColor DarkRed ; $FlagPreReq = $false }
        }
    }
}
if ($FlagPreReq)
{
    Write-Host "All prerequesites are OK."    
    Write-Host "-------------------------"
}
Else 
{
    Write-Host "Some check have failed!" -ForegroundColor Red
    Write-Host "-------------------------"
    exit 1
}
#-Clearing prerequesites data 
Start-Sleep -Seconds 2
$Host.UI.RawUI.CursorPosition = New-Object System.Management.Automation.Host.Coordinates $InitialPosition.X,$InitialPosition.Y
For ($i = 1 ; $i -le ($Linecount + 2) ; $i++) { Write-Host "                                                                       " }
$Host.UI.RawUI.CursorPosition = New-Object System.Management.Automation.Host.Coordinates $InitialPosition.X,$InitialPosition.Y
                                                     
#-Loop begins!
Start-Sleep -Seconds 2

#-Using XML
$Resume = @()
$Tasks  = $TasksSeqConfig.Settings.Sequence.ID | Sort-Object number
foreach ($task in $Tasks)
{
    #-Get current cusror position on screen
    $InitialPosition = $host.UI.RawUI.CursorPosition

    #-Write the newline to initiate the progress bar
    Write-Host $ColorsAndTexts.PendingText -ForegroundColor $ColorsAndTexts.PendingColor -NoNewline
    Write-Host ": " -ForegroundColor $ColorsAndTexts.BaseTxtColor -NoNewline

    #-Display the task description and managing color output
    $TextToDisplay = $task.TaskDescription -split '`'

    foreach ($Section in $TextToDisplay)
    {
        #-Looking at the first character: if this one is one of the AltBaseHTxt, the applying special color scheme.
        $color = $ColorsAndTexts.BaseTxtColor
        if ($Section[0] -eq $ColorsAndTexts.AltBaseHTxtA) { $color = $ColorsAndTexts.AltBaseHColA }
        if ($Section[0] -eq $ColorsAndTexts.AltBaseHTxtB) { $color = $ColorsAndTexts.AltBaseHColB }
        if ($Section[0] -eq $ColorsAndTexts.AltBaseHTxtC) { $color = $ColorsAndTexts.AltBaseHColC }
        
        #-Output text. We use a regex expression to remove the highlightCar
        #-WARNING: the regex is built fitst to fetch with $ColorsAndTexts.
        [regex]$myRegex = "\" + $ColorsAndTexts.AltBaseHTxtA + "|\" + $ColorsAndTexts.AltBaseHTxtB + "|\" + $ColorsAndTexts.AltBaseHTxtC
        Write-Host ($Section -replace $myRegex,"") -ForegroundColor $Color -NoNewline
    }

    #-Initiate waiting loop: isRunning will be the flag to keep the loop in a pending state, while charIndex will handle the new text to display.
    $isRunning = $true
    $CharIndex = -1
    
    #-Cursor management
    $esc        = [char]27
    $hideCursor = "$esc[?25l"
    $showCursor = "$esc[?25h"
    $resetAll   = "$esc[0m" 
    
    #-Run the job
    $job = Start-Job -ScriptBlock $Block -Name CurrentJob -ArgumentList $task.CallingFunction,$task.UseParameters,$ScriptLocation,$scriptModules
    
    #-Looping around while the jos is still performing its task
    while ($isRunning) 
    { 
        #-Checking the current job status.
        if ((Get-Job $job.Id).State -ne "Running")
        { 
            #-Flag down: exiting the loop.
            $isRunning = $false 
        } 
        #-Text animation to show the running status
        #-First, moving to the next highlighted character
        $CharIndex++
        #-Second, managing the case when we face the end of the string
        if ($CharIndex -ge [String]($ColorsAndTexts.RunningText).length) 
        {
            #-Reinit the index to 0 (aka first character). 
            $CharIndex = 0
        }
        
        #-Managing the output
        #-First, lets relocate the cursor position to the line beginning
        $Host.UI.RawUI.CursorPosition = New-Object System.Management.Automation.Host.Coordinates $InitialPosition.X,$InitialPosition.Y
        

        #-Second, using a loop condition, let's rewrite
        for ($ptr = 0 ; $ptr -lt ($ColorsAndTexts.RunningText).length ; $ptr++) 
        { 
            if ($CharIndex -eq $ptr) 
            { 
                #-This character will be highlighted
                Write-Host (${hideCursor} + ([string]($ColorsAndTexts.RunningText)[$ptr]).toUpper()) -ForegroundColor $ColorsAndTexts.RunningColor -NoNewline 
            } else { 
                #-This character is written as usual
                Write-Host (${hideCursor} + ([string]($ColorsAndTexts.RunningText)[$ptr]).toLower()) -ForegroundColor $ColorsAndTexts.PendingColor -NoNewline 
            } 
        }
        Start-Sleep -Milliseconds 175
    }

    #-Grab the job result.
    $result = Receive-Job $job.Id
    #-Display result on screen
    Switch ($result.ResultCode)
    {
        0 { $zText = $ColorsAndTexts.SuccessText ; $zColor = $ColorsAndTexts.SuccessColor }
        1 { $zText = $ColorsAndTexts.WarningText ; $zColor = $ColorsAndTexts.WarningColor }
        2 { $zText = $ColorsAndTexts.FailureText ; $zColor = $ColorsAndTexts.FailureColor }
    }
    $Host.UI.RawUI.CursorPosition = New-Object System.Management.Automation.Host.Coordinates $InitialPosition.X,$InitialPosition.Y
    Write-Host (${hideCursor} + [string]$zText) -ForegroundColor $zColor -NoNewline
    #-Remove the job from the queue
    Remove-Job $job.Id
    #-Next line ;)
    write-host $resetAll$showCursor
    #-Keeping a resume to be displayed at the end and exported to the output folder
    $Resume += New-Object -TypeName psobject -Property @{ TaskID = $Task.Number ; TaskName = $task.Name ; TaskResult = $zText }
}

#-Script over. exporting run log.
$LogName = (Get-Date -Format "yyyy-MM-dd_hhmmss_") + "HardenAD-Results.log"

Write-Host "-------------------------"
Write-Host "Exporting results to .\Logs\" -ForegroundColor Cyan -NoNewline
Write-Host $LogName -ForegroundColor Yellow -NoNewline
Write-Host "..." -ForegroundColor Cyan -NoNewline

Try { 
    $Resume | Select TaskId,TaskResult,TaskName | Sort-Object TaskID | Export-Csv .\Logs\$LogName -Delimiter "`t" -Encoding Unicode -NoTypeInformation
    Write-Host "success`n" -ForegroundColor Green
    }
Catch {
    Write-Host "failure`n" -ForegroundColor red
    }

$Resume | Select TaskId,TaskResult,TaskName | Sort-Object TaskID | Format-Table -AutoSize 
