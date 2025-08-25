<#
    .SYNOPSIS
    This module contains only display functions.

    .DESCRIPTION
    This module contains functions used to display data on screen.

    .NOTES
    Version 01.00.00
    Author  Loïc VEIRMAN
#>

Function WriteScreen {
    <#
        .SYNOPSIS
        Echo a formated text on screen.

        .DESCRIPTION
        Based on the type of message to be displayed, the script colorized and format the output.

        .PARAMETER Format
        Type of accepted formating. 

        .PARAMETER Message
        Type of message to be displayed. Always dealed as an array of string.

        .NOTES
        ======= =================== ===================
        Version Author              Descirption
        ======= =================== ===================
        1.0.0   Loic VEIRMAN MSSec  Script creation    
        ------- ------------------- -------------------
    #>

    Param(
        [Parameter(Mandatory,Position=0)]
        [ValidateSet('E0','M0','M1','M2','Q1','V1','V2','P1','H0','H1','R0','R1','R2','I0')]
        [String]
        $Format,

        [Parameter(Mandatory,Position=1)]
        [Array]
        $Message
    )
    #region FUNCTIONS
    Function WriteColA {
        <#
            Arrange display on Col A. DfltColor will be used when ANSI color are ineficient.
        #>
        Param()

        Write-host "$($AnsiGlobal['Normal'])$($arrayCus[0])$($AnsiGlobal['end'])" -ForegroundColor White -NoNewLine
        Write-host "$($AnsiColA[$format])$($TxtColA[$Format])$($AnsiGlobal['end'])" -ForegroundColor $DfltColA[$format] -NoNewline
        Write-host "$($AnsiGlobal['Normal'])$($arrayCus[1])$($AnsiGlobal['end'])" -ForegroundColor White -NoNewLine
        Write-host "  " -ForegroundColor White -NoNewLine
    }

    Function WriteColB {
        <#
            Arrange dissplay on col B. truncate to not exceed the max width of the window.
            Split Message to B1 and B2 if nedded.
        #>
        param(
            [parameter(Mandatory,position=0)]
            [String]
            $Line
        )

        # Split message
        $splittedMsg = $Line -split ';'

        # Write line. If not splitted, use ColB1 color.
        Write-Host "$($AnsiColB1[$format])$($splittedMsg[0])$($AnsiGlobal['End'])" -ForegroundColor $DfltColB1[$format] -NoNewline
        if ($splittedMsg[1]) {
            Write-Host "$($AnsiGlobal['normal'])$($arrayCus[2]) $($AnsiGlobal['end'])" -ForegroundColor $DfltColB2[$format] -NoNewline
            Write-Host "$($AnsiColB2[$format])$($splittedMsg[1])$($AnsiGlobal['end'])" -ForegroundColor $DfltColB2[$format] -NoNewline
        }
        if ($format -in $arrayPause) {
            # Wait user input. Don't care about value
            $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | Out-Null
            write-host ''
            return $null
        }
        if ($format -in $arrayValid) {
            Switch ($format) {
                # use case : y/N
                "V2" {
                    write-host " (y/N) " -NoNewline
                    $ChoiceNotDone = $true
                    While ($ChoiceNotDone) {
                        $userInput =  $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
                        if ($userInput.VirtualKeyCode -in @(89)) {
                            Write-Host "$($AnsiGlobal['Yes'])Yes$($AnsiGlobal['End'])" -ForegroundColor Red
                            $userChoice = "Y"
                            $ChoiceNotDone = $false
                        }
                        if ($userInput.VirtualKeyCode -in @(78,13,27)) {
                            Write-Host "$($AnsiGlobal['No'])No$($AnsiGlobal['End'])" -ForegroundColor Red
                            $userChoice = "N"
                            $ChoiceNotDone = $false
                        }
                    }
                    Break
                }
                # default use case: Y/n
                Default {
                    write-host " (Y/n) " -NoNewline
                    $ChoiceNotDone = $true
                    While ($ChoiceNotDone) {
                        $userInput =  $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
                        if ($userInput.VirtualKeyCode -in @(89,13)) {
                            Write-Host "$($AnsiGlobal['Yes'])Yes$($AnsiGlobal['End'])" -ForegroundColor Red
                            $userChoice = "Y"
                            $ChoiceNotDone = $false
                        }
                        if ($userInput.VirtualKeyCode -in @(78,27)) {
                            Write-Host "$($AnsiGlobal['No'])No$($AnsiGlobal['End'])" -ForegroundColor Red
                            $userChoice = "N"
                            $ChoiceNotDone = $false
                        }
                    }
                }
            }
            return $userChoice
        }
        if ($format -in $arrayQuery) {
            # ask for a user input
            write-host ' ' -NoNewline
            $UserChoice = Read-Host
            return $userChoice
        }
        Write-host ''
        return $null
    }
    #endRegion FUNCTIONS
    #region MAINSCRIPT
    Try {
        #region defineValues
        # Defaulting return value to null
        $returnValue = $null

        # Color set for ANSI display
        $AnsiGlobal = @{
            Normal = "$([char]0x1B)[0;37m"
            End    = "$([char]0x1B)[0m"
            Yes    = "$([char]0x1B)[1;92m"
            no     = "$([char]0x1B)[1;91m"
        }

        $AnsiColA = @{
            E0 = "$([char]0x1B)[0;91m"
            M0 = "$([char]0x1B)[1;35m"
            M1 = "$([char]0x1B)[0;96m"
            M2 = "$([char]0x1B)[0;96m"
            Q1 = "$([char]0x1B)[1;96m"
            V1 = "$([char]0x1B)[0;92m"
            V2 = "$([char]0x1B)[1;91m"
            P1 = "$([char]0x1B)[1;33m"
            H0 = "$([char]0x1B)[90m"
            H1 = "$([char]0x1B)[90m"
            R0 = "$([char]0x1B)[1;32m"
            R1 = "$([char]0x1B)[1;33m"
            R2 = "$([char]0x1B)[1;31m"
            I0 = "$([char]0x1B)[0;90m"
        }

        $AnsiColB1 = @{
            E0 = "$([char]0x1B)[0;91m"
            M0 = "$([char]0x1B)[4;35m"
            M1 = "$([char]0x1B)[0;95m"
            M2 = "$([char]0x1B)[1;33m"
            Q1 = "$([char]0x1B)[1;36m"
            V1 = "$([char]0x1B)[0;37m"
            V2 = "$([char]0x1B)[0;37m"
            P1 = "$([char]0x1B)[0;93m"
            H0 = "$([char]0x1B)[0;100m"
            H1 = "$([char]0x1B)[0;100m"
            R0 = "$([char]0x1B)[0;37m"
            R1 = "$([char]0x1B)[0;37m"
            R2 = "$([char]0x1B)[0;37m"
            I0 = "$([char]0x1B)[0;37m"
        }

        $AnsiColB2 = @{
            E0 = "$([char]0x1B)[0;93m"
            M0 = "$([char]0x1B)[4;35m"
            M1 = "$([char]0x1B)[0;37m"
            M2 = "$([char]0x1B)[0;37m"
            Q1 = "$([char]0x1B)[0;96m"
            V1 = "$([char]0x1B)[1;92m"
            V2 = "$([char]0x1B)[0;91m"
            P1 = "$([char]0x1B)[0;93m"
            H0 = "$([char]0x1B)[0;100m"
            H1 = "$([char]0x1B)[0;100m"
            R0 = "$([char]0x1B)[0;32m"
            R1 = "$([char]0x1B)[0;33m"
            R2 = "$([char]0x1B)[0;31m"
            I0 = "$([char]0x1B)[0;37m"
        }

        # Color set for default view (used when ANSI is not working)
        $DfltColA = @{
            E0 = "Red"
            M0 = "Magenta"
            M1 = "Cyan"
            M2 = "Cyan"
            Q1 = "Cyan"
            V1 = "DarkGreen"
            V2 = "DarkRed"
            P1 = "Yellow"
            H0 = "Magenta"
            H1 = "Magenta"
            R0 = "Green"
            R1 = "Yellow"
            R2 = "Red"
            I0 = "Gray"
        }

        $DfltColB1 = @{
            E0 = "Red"
            M0 = "Magenta"
            M1 = "Cyan"
            M2 = "Yellow"
            Q1 = "White"
            V1 = "White"
            V2 = "White"
            P1 = "Yellow"
            H0 = "Magenta"
            H1 = "Magenta"
            R0 = "White"
            R1 = "White"
            R2 = "White"
            I0 = "white"
        }

        $DfltColB2 = @{
            E0 = "Yellow"
            M0 = "Magenta"
            M1 = "White"
            M2 = "White"
            Q1 = "Cyan"
            V1 = "darkgreen"
            V2 = "darkred"
            P1 = "Yellow"
            H0 = "Magenta"
            H1 = "Magenta"
            R0 = "Green"
            R1 = "Yellow"
            R2 = "Red"
            I0 = "White"
        }

        # Standardized text array
        $ArrayTxt = @('INF.','SUC.','WAR.','ERR.',' >> ',' -- ',' ?? ','BGIN','OVER','WAIT',' Y? ',' N? ')

        # Customized display 
        $arrayCus = @('[',']',':')
            
        # ColA value per code
        $TxtColA = @{
            'E0' = $ArrayTxt[3]
            'M0' = $ArrayTxt[4]
            'M1' = $ArrayTxt[5]
            'M2' = $ArrayTxt[5]
            'Q1' = $ArrayTxt[6]
            'V1' = $ArrayTxt[10]
            'V2' = $ArrayTxt[11]
            'P1' = $ArrayTxt[9]
            'H0' = $ArrayTxt[7]
            'H1' = $ArrayTxt[8]
            'R0' = $ArrayTxt[1]
            'R1' = $ArrayTxt[2]
            'R2' = $ArrayTxt[3]
            'I0' = $ArrayTxt[0]
        }
        # Wait for something at this line
        $arrayPause = @('P1')
        $arrayValid = @('V1','V2')
        $arrayQuery = @('Q1')
        #endRegion defineValues
        
        #region displayUseCase
        foreach ($object in $Message) {
            WriteColA
            $result = WriteColB $object
        }
        if ($result) {
            return $result
        }
        #endRegion displayUseCase
    }
    Catch {
        # Something went wrong
        write-host ""
    }
    Finally {
    }
    #endRegion MAINSCRIPT
}