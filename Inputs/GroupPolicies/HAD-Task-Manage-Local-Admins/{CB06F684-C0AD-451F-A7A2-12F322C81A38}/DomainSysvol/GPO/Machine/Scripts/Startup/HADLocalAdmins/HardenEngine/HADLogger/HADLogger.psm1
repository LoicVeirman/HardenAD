enum LogType {
    Error = 1
    Warning = 2
    Information = 4
}

enum LogLevel {
    INFO
    SUCCESS
    DEBUG
    WARNING
    ERROR
}

class HADLogger {
    # Bool to enable logs
    [bool] $LogToHost = $false
    [bool] $LogToFile = $false
    [bool] $LogToEventViewer = $false

    [bool] $Debug = $false

    static [System.Object] $LogTable
    [LogLevel] $LogLevel 

    # Default colors
    [string] $InfoColor = "Cyan"
    [string] $ErrorColor = "Red"
    [string] $SuccessColor = "Green"
    [string] $WarningColor = "Yellow"
    [string] $DebugColor = "DarkYellow"

    # Default LogFile
    [string] $LogFile = "$($ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath(".\"))" + "\log.log"

    # Default EventVwr
    [string[]] $ComputerName
    [string] $EventID
    [string] $EventFolder
    [string] $EventSource    
    [LogType] $LogType = [LogType]::Information

    HADLogger([bool] $Debug, [string] $JsonPath) {
        $this.Debug = $Debug
        [HADLogger]::InitLogTable($JsonPath)
    }

    static [void] InitLogTable([string] $JsonPath) {
        $JsonObj = (Get-Content -Path $JsonPath) | ConvertFrom-Json

        [HADLogger]::LogTable = $JsonObj
    }
    
    [HADLogger] InitLogFile([string] $LogFile) {
        $this.LogToFile = $true

        if (!(Get-ChildItem -Path $LogFile -ErrorAction SilentlyContinue)) { 
            try {
                New-Item -Path $LogFile -ItemType File -Force -Confirm:$false
            }
            catch {
                Write-Error -ErrorRecord $Error[0] 
                -RecommendedAction "Unable to create log file.`n
                                                Please ensure you have access to create a log file in the provided location"
            }
        }
        $this.LogFile = $LogFile

        return $this
    }

    [HADLogger] InitHost() {
        $this.LogToHost = $true
        return $this
    }

    [HADLogger] InitEventViewer([string] $EventFolder, [string] $EventSource) {
        $this.LogToEventViewer = $true

        $this.EventFolder = $EventFolder
        $this.EventSource = $EventSource

        if (!([System.Diagnostics.EventLog]::SourceExists($EventSource))) {
            $Params = @{
                LogName = $this.EventFolder
                Source  = $this.EventSource
            }

            New-EventLog @Params
        }
        else {
            Write-Warning -Message "The LogSource of $EventSource already exists"
        }

        return $this

    }

    [HADLogger] InitEventViewer([string] $EventFolder, [string] $EventSource, [string[]] $ComputerName) {
        $this.LogToEventViewer = $true

        $this.EventFolder = $EventFolder
        $this.EventSource = $EventSource

        if (!([System.Diagnostics.EventLog]::SourceExists($EventSource))) {
            $Params = @{
                LogName      = $this.EventFolder
                Source       = $this.EventSource
                ComputerName = $ComputerName
            }

            New-EventLog @Params
        }
        else {
            Write-Warning -Message "The LogSource of $EventSource already exists"
        }

        return $this
    }

    hidden [void] LogInternal([LogLevel] $LogLevel, [string] $Message) {
        $FormattedMessage = "{0} [{1}][{2}]: {3}" -f (Get-Date -Format "yyyy-MM-ddTHH:mm:ss").ToString(), $LogLevel.ToString().ToUpper(), $this.EventID , $Message

        if ($this.LogToFile) {
            $this.AddContentToLogFile($FormattedMessage)
        }

        if ($this.LogToEventViewer) {
            $this.AddContentToEventViewver($FormattedMessage)
        }

        if ($this.LogToHost) {
            $this.AddContentToHost($LogLevel, $FormattedMessage)
        }
    }

    hidden [void] AddContentToLogFile([string] $Message) {
        $Mutex = $this.Mutex()
        $Mutex.WaitOne() | Out-Null

        Add-Content -Path $this.LogFile -Value $Message

        $Mutex.ReleaseMutex() | Out-Null
    }

    hidden [void] AddContentToHost([LogLevel] $LogLevel, [string] $Message) {
        if ($LogLevel -eq "Debug" -and !$this.Debug) {
        }
        else {
            Write-Host $Message -ForegroundColor $this."$($LogLevel)Color"
        }
    }

    hidden [void] AddContentToEventViewver([string] $Message) {
        $Params = @{
            LogName   = $this.EventFolder
            Source    = $this.EventSource
            Message   = $Message
            EventId   = $this.EventID
            EntryType = $this.LogType
        }

        Write-EventLog @Params
    }

    [System.Threading.Mutex] Mutex() {
        return $(New-Object -TypeName "Threading.Mutex" -ArgumentList $false, "MyInterprocMutex")
    }

    [void] NewLog([int] $ID) {
        $Message = "$(([HADLogger]::LogTable | Where-Object {$_.ID -eq $ID}).Message)"
        $this.LogLevel = [LogLevel]::(([HADLogger]::LogTable | Where-Object { $_.ID -eq $ID }).LogLevel)
        $this.EventID = $ID

        if ($this.LogLevel -eq "Error") {
            $this.LogType = [LogType]::Error
        }
        elseif ($this.LogLevel -eq "Warning") {
            $this.LogType = [LogType]::Warning
        }
        else {
            $this.LogType = [LogType]::Information
        }
        
        $this.LogInternal($this.LogLevel, $Message)
    }

    [void] NewLog([int] $ID, $Params) {
        $Message = ("$(([HADLogger]::LogTable | Where-Object {$_.ID -eq $ID}).Message)" -f $Params)
        $this.LogLevel = [LogLevel]::(([HADLogger]::LogTable | Where-Object { $_.ID -eq $ID }).LogLevel)
        $this.EventID = $ID

        if ($this.LogLevel -eq "Error") {
            $this.LogType = [LogType]::Error
        }
        elseif ($this.LogLevel -eq "Warning") {
            $this.LogType = [LogType]::Warning
        }
        else {
            $this.LogType = [LogType]::Information
        }
        
        $this.LogInternal($this.LogLevel, $Message)
    }

    # [void] Error([System.Management.Automation.ErrorRecord] $ErrorRecord) {
    #     $this.LogType = [LogType]::Error
    #     # $this.EventID = [EventID]::Error

    #     $ErrorMessage = "{0} ({1}: {2}:{3} char:{4})" -f $ErrorRecord.Exception.Message,
    #     $ErrorRecord.FullyQualifiedErrorId,
    #     $ErrorRecord.InvocationInfo.ScriptName,
    #     $ErrorRecord.InvocationInfo.ScriptLineNumber,
    #     $ErrorRecord.InvocationInfo.OffsetInLine

    #     $this.LogInternal([LogLevel]::ERROR, $ErrorMessage)
    # }
    # [void] Error([string] $Message, [System.Management.Automation.ErrorRecord] $ErrorRecord) {
    #     $this.LogType = [LogType]::Error
    #     # $this.EventID = [EventID]::Error

    #     $ErrMessage = ("{0}`r{1}" -f $Message, $ErrorRecord)
    #     $this.LogInternal([LogLevel]::ERROR, $ErrMessage)
    # }
}