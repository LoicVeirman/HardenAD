enum LogSeverity {
    Fatal
    Error
    Warning
    Informative
    Success
}

class LogMessage {
    static [string] $Severity = [LogSeverity]::Informative
    static [string] $LogDirectory
    static $Logs = @{}
    static [string] $Global
    static [string] $Name

    static [void] Initialize([string] $LogDirectory, [string] $LogName) {
        if (!(Test-Path $LogDirectory)) {
            try {
                New-Item -Path $LogDirectory -ItemType Directory -Force -Confirm:$false
            }
            catch {
                Write-Error ("Could not create {0}: {1}.`nExiting..." -f $LogDirectory, $_.Exception.Message)
                exit
            }
        }

        [LogMessage]::LogDirectory = $LogDirectory
        [LogMessage]::Name = $LogName
        [LogMessage]::Global = $LogDirectory + "\Global.log"
    }

    static [Log] NewLogs () {
        $Caller = (Get-PSCallStack)[1]
        $Path = $Caller.ScriptName.Split("\")
        $ScriptName = $Path[$Path.Count - 1] + "." + $Caller.FunctionName + " : " + $Caller.ScriptLineNumber

        if ([LogMessage]::Logs.Contains("$ScriptName")) {
            return [LogMessage]::Logs["$ScriptName"]
        }

        $LogPath = ([LogMessage]::LogDirectory + "\" + $Caller.FunctionName + ".log")
        $GlobalPath = [LogMessage]::Global

        $Log = [Log]::new($LogPath, $GlobalPath, [LogMessage]::Severity)
        [LogMessage]::Logs["$ScriptName"] = $Log
        return $Log
    }
}

class Log {
    [string] $LogPath
    [string] $GlobalPath
    [LogSeverity] $LogSeverity

    Log ([string] $LogPath, [string] $GlobalPath, [LogSeverity] $LogSeverity) {
        $this.LogPath = $LogPath
        $this.GlobalPath = $GlobalPath
        $this.LogSeverity = $LogSeverity
    }

    LogInternal ([string] $Message, [LogSeverity] $LogSeverity) {
        $Caller = (Get-PSCallStack)[2]
        $Path = $Caller.ScriptName.Split("\")
        $DisplayedMessage = "[" + $LogSeverity.ToString().ToUpper() + "] " + $Message
        $FormattedLog = (Get-Date -Format "yyyy-MM-ddThh:mm:ss") + " | " + $Path[$Path.Count - 1] + ":" + $Caller.ScriptLineNumber + " | [" + $LogSeverity.ToString().ToUpper() + "] | " + $Message
        
        Out-File -FilePath $this.Globalpath -Append -InputObject $FormattedLog

        switch ($LogSeverity) {
            Informative { 
                Write-Host $DisplayedMessage -ForegroundColor White
            }
            Success { 
                Write-Host $DisplayedMessage -ForegroundColor Green
            }
            Warning { 
                Write-Host $DisplayedMessage -ForegroundColor Yellow
            }
            Error { 
                Write-Host $DisplayedMessage -ForegroundColor Red
            }
            Fatal { 
                Write-Host $DisplayedMessage -ForegroundColor DarkRed
                exit
            }
            Default { throw "Invalid log level: $_" }
        }
        # Out-File -FilePath $this.LogPath -Append -InputObject $FormattedLog
    }

    Info([string] $Message) {
        $this.LogInternal($Message, [LogSeverity]::Informative)
    }
    Success([string] $Message) {
        $this.LogInternal($Message, [LogSeverity]::Success)
    }
    Warning([string] $Message) {
        $this.LogInternal($Message, [LogSeverity]::Warning)
    }
    Error([string] $Message) {
        $this.LogInternal($Message, [LogSeverity]::Error)
    }
    Fatal([string] $Message) {
        $this.LogInternal($Message, [LogSeverity]::Fatal)
    }
}