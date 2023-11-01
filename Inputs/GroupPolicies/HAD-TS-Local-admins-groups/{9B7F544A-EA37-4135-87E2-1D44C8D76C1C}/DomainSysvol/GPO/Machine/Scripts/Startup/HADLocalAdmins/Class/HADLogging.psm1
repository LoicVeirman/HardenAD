enum LogLevel {
    Debug = 0;
    Info = 1;
    Success = 2;
    Warning = 3;
    Error = 4;
    Fatal = 5
}


Class LoggerFactory {
    static [int] $Count
    static [String] $LogFolder
    static $Loggers = @{}
    static [LogLevel] $LogLevel = [LogLevel]::Error
    static [string] $Global

    static [Void] Initialize ([String] $LogFolder, [LogLevel] $LogLevel) {
        if (!(Test-Path $LogFolder)) {
            try {
                mkdir $LogFolder
            }
            catch {
                Write-Error "Could not create $LogFolder : " + $_.Exception.Message + ", Exiting"
                exit
            }
        }

        [LoggerFactory]::LogFolder = $LogFolder
        [LoggerFactory]::Global = $LogFolder + "\" + ((Get-PSCallStack)[1]).FunctionName + ".log"
        [LoggerFactory]::LogLevel = $LogLevel
    }

    static [Void] Initialize ([String] $LogFolder) {
        if (!(Test-Path $LogFolder)) {
            try {
                mkdir $LogFolder
            }
            catch {
                Write-Error "Could not create $LogFolder : " + $_.Exception.Message + ", Exiting"
                exit
            }
        }

        [LoggerFactory]::LogFolder = $LogFolder
        [LoggerFactory]::Global = $LogFolder + "\" + ((Get-PSCallStack)[1]).FunctionName + ".log"
    }


    static [Logger] CreateLogger () {
        $Caller = (Get-PSCallStack)[1]
        $Path = $Caller.ScriptName.Split("\")
        $Name = $Path[$Path.Count - 1] + "." + $Caller.FunctionName + " : " + $Caller.ScriptLineNumber

        if ([LoggerFactory]::Loggers.Contains("$Name")) {
            return [LoggerFactory]::Loggers["$Name"]
        }
    
        $LogPath = ([LoggerFactory]::LogFolder + "\" + $Caller.FunctionName + ".log")
        [LogLevel]$CurrentLogLevel = [LoggerFactory]::LogLevel
        $GlobalString = [LoggerFactory]::Global
        $res = New-Object Logger $LogPath, $GlobalString, $CurrentLogLevel

        [LoggerFactory]::Loggers["$Name"] = $res
        return $res
    }
}

Class Logger {
    [String] $LogFile
    [LogLevel] $LogLevel
    [String] $Global

    Logger ([String]$LogFile, [String]$Global, [LogLevel]$LogLevel) {
        $this.LogFile = $LogFile
        $this.Global = $Global
        $this.LogLevel = $LogLevel
    }


    LogInternal ([String] $Message, [LogLevel] $Level) {
        $Caller = (Get-PSCallStack)[2]
        $Path = $Caller.ScriptName.Split("\")
        $LogName = $Path[$Path.Count - 1] + ":" + $Caller.FunctionName + ":(" + $Caller.ScriptLineNumber + ")"

        $FormattedMessage = $Level.ToString().ToUpper() + ": " + $(Get-Date -UFormat "%m-%d-%Y %T ") + $LogName + " - " + $Message
        $DisplayMessage = "[" + $(Get-Date -UFormat "%D %T") + "] : " + $Message

        switch ($Level) {
            Debug {}
            Info {
                Write-Host $DisplayMessage -ForegroundColor Gray
            }
            Success {
                Write-Host $DisplayMessage -ForegroundColor Green
            }
            Warning {
                Write-Host $DisplayMessage -ForegroundColor Yellow
            }
            Error {
                Write-Host $DisplayMessage -ForegroundColor Red
            }
            Fatal {
                Write-Host $DisplayMessage -ForegroundColor Red
            }
        }
        Out-File -FilePath $this.Global -Append -InputObject $FormattedMessage
    }

    Debug([String] $Message) {
        $this.LogInternal($Message, [LogLevel]::Debug)
    }
    Info([String] $Message) {
        $this.LogInternal($Message, [LogLevel]::Info)
    }
    Success([String] $Message) {
        $this.LogInternal($Message, [LogLevel]::Success)
    }
    Warning([String] $Message) {
        $this.LogInternal($Message, [LogLevel]::Warning)
    }
    Error([String] $Message) {
        $this.LogInternal($Message, [LogLevel]::Error)
    }
    Fatal([String] $Message) {
        $this.LogInternal($Message + "`nExiting...", [LogLevel]::Fatal)
        exit
    }
}