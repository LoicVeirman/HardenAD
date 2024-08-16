<# .Synopsis
	This script flush all members of the specified group present in the csv file.

   .Details
    This script flush all members of the specified group present in MCS-GroupsFlushing.csv file.

   .Note
    Version 01.00   Simply read and flush process
    Version 02.00   Enhanced config.xml (see xml comment for details)
                    The script now check only groups that are enabled in the xml. 
                    Plus, the xml contains a whitelist that allow account or groups to stay in.
                    The Windows Event Log will only contains event when a user is removed from a group.
                    Note: the script is able to use dynamic reference from TasksSequence_HardenAD.xml

#>

Param()
# function Get-TranslationfromHaDTS
Function Get-TranslationfromHaDTS 
{
    <#
        .SYNOPSIS
        Translate a text with the <translation> data from TasksSequence_HardenAD.xml.

        .DESCRIPTION
        Translate a text with the <translation> data from TasksSequence_HardenAD.xml.
        Two run: first to get data from source text, second to translate a reference to TranslateTo present in TranslateFrom.
    #>
    Param(
        [Parameter(mandatory,Position=0)]
        [String]
        $myText,

        [Parameter(mandatory,Position=1)]
        $xmlTranslation
    )
    foreach ($translation in $xmlTranslation)
    {
        $myText = $myText -replace $translation.TranslateFrom,$translation.TranslateTo
    }
    foreach ($translation in $xmlTranslation)
    {
        $myText = $myText -replace $translation.TranslateFrom,$translation.TranslateTo
    }
    return $myText
}
# init script
$DbgFile = "Debug_$(($MyInvocation.MyCommand) -replace '.PS1',$Null).log"
$Log = @()
$Log += (Get-Date -UFormat "%Y-%m-%d %T ") + "***"
$Log += (Get-Date -UFormat "%Y-%m-%d %T ") + "*** SCRIPT STARTS"
$Log += (Get-Date -UFormat "%Y-%m-%d %T ") + "***"

# Logging to Windows Event Log
$EventLogName   = "Application"
$EventLogSource = "HardenAD_$(($MyInvocation.MyCommand) -replace '.PS1',$Null)"
# We ensure that the event log is ready to catch our event. To do so, we forcefully recreate the event source and trap the error if already existing.
Try {
    [void](New-EventLog -LogName $EventLogName -Source $EventLogSource -ErrorAction Stop)
    $log += (Get-Date -UFormat "%Y-%m-%d %T ") + "--> EVENT VIEWER: the eventlog name '$eventLogName' has been updated with the source '$eventLogSource'."

} 
Catch {
    $log += (Get-Date -UFormat "%Y-%m-%d %T ") + "--> EVENT VIEWER: the eventlog name '$EventLogName' is already set with the source '$EventLogSource'."
}
# Main run
Try {
    # loading xml config file
    $xmlConfig = [xml](Get-Content .\Configuration.xml -Encoding UTF8 -ErrorAction Stop)
    $Log += (Get-Date -UFormat "%Y-%m-%d %T ") + "--> configuration.xml loaded"
    # loading xml tasksSequence file
    $xmlHADcfg = [xml](Get-Content "$($env:ProgramData)\HardenAD\Configuration\TasksSequence_HardenAD.xml" -ErrorAction Stop)
    $Log += (Get-Date -UFormat "%Y-%m-%d %T ") + "--> tasksSequence_HardenAD.xml loaded"
    # Working on allowed groups
    foreach ($Group in (Select-Xml $xmlConfig -XPath "//Group[@Enabled='Yes']" | Select-Object -ExpandProperty Node))
    {
        # Convert Dynamic Group Name (if any)
        $GroupSam = Get-TranslationfromHaDTS $Group.Name $xmlHADcfg.Settings.translation.WellKnownID
        $Log += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- --> WORKING ON: $GroupSam"
        # Convert Dynamic Whitelisted dudes (if any)
        [System.Collections.Generic.List[PSObject]]$Array = @()
        foreach ($AllowedDude in $Group.Whitelisted)
        {
            $samDude = Get-TranslationfromHaDTS $AllowedDude.sAMAccountName $xmlHADcfg.Settings.translation.WellKnownID
            $dudeObject = Get-ADObject -LDAPFilter "(sAMAccountName=$samDude)" -Properties sAMAccountName
            if ($dudeObject)
            {
                $Array.add($dudeObject)
                $Log += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- --- --> Allowed sAMAccountName: $samDude"
            }
            else 
            {
                $Log += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- --- !!! Allowed sAMAccountName: $samDude (not found in AD)"
                $eventMsg =  "Group:`t`t$GroupSam`nMember:`t$samDude`n"
                $eventMsg += "Warning:`tThe sAMAccountName should be member of this group but does not exists in AD.`n`n"
                $eventMsg += "Security risk:`t"
                $eventMsg += "An attackant with the ablity to create an object with $samDude as sAMAccountName may sneak himself to the protected group without being detected.`n`n"
                $eventMsg += "Mitigation:`t"
                $eventMsg += "Edit $($env:ProgramData)\HardenAD\Clear-ProtectedGroups\configuration.xml and remove it from the list."
                Write-EventLog -LogName $EventLogName -Source $EventLogSource -EntryType Error -EventId 2048 -Category 0 -Message $eventMsg
            }
        }
        $Log += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- --- -->"
        # recovering exisiting group members 
        $curGrpMbrs = Get-ADGroupMember -Identity $GroupSam
        $Log += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- --- --> Retrieved current groupe membership. Comparing..."
        # removing unxanted users
        if ($curGrpMbrs)
        { 
            if ($Array)
            {
                $mismatch = Compare-Object $curGrpMbrs.sAMAccountName $Array.sAMAccountName
                [System.Collections.Generic.List[PSObject]]$mismatchArray = @()
                foreach ($rogueSam in $mismatch)
                {
                    Switch ($rogueSam.SideIndicator)
                    {
                        "<=" {
                            $mismatchArray.add($rogueSam.InputObject)
                            $Log += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- --- <<< Will be removed: $($rogueSam.InputObject)"
                            Write-EventLog -LogName $EventLogName -Source $EventLogSource -EntryType Information -EventId 0 -Category 0 -Message "Group: $GroupSam`nMember: $($rogueSam.InputObject)`n`nUser has been removed from the group (not whitelisted)."
                        }
                        "=>" {
                            $Log += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- --- >>> Should be added: $($rogueSam.InputObject) (no action performed)"
                            $eventMsg =  "Group:`t`t$GroupSam`nMember:`t$($rogueSam.InputObject)`n"
                            $eventMsg += "Warning:`tThis sAMAccountName should be member of this group but is not present.`n`n"
                            $eventMsg += "Security risk:`t"
                            $eventMsg += "The group is deviant. It may indicates a misconfiguration or could potentially bring unwanted permission to a rogue group.`n`n"
                            $eventMsg += "Mitigation:`t"
                            $eventMsg += "Edit $($env:ProgramData)\HardenAD\Clear-ProtectedGroups\configuration.xml and remove it from the list or add $($rogueSam.InputObject) back to $GroupSam."
                            Write-EventLog -LogName $EventLogName -Source $EventLogSource -EntryType Warning -EventId 1024 -Category 0 -Message $eventMsg    
                        }
                    }
                }
                if ($mismatchArray)
                {
                    Remove-ADGroupMember -Identity $GroupSam -Members $mismatchArray -Confirm:$false
                    $Log += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- --- --> All identified members have been removed."
                }
                else
                {
                    $Log += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- --- === No unallowed members identified."
                }
            }
            else 
            {
                Remove-ADGroupMember -Identity $GroupSam -Members $curGrpMbrs.SamAccountName -Confirm:$False
                $Log += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- --- <<< All members have been removed."
            }
        }
        else 
        {
            $Log += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- --- === No membership to compare! Noting changed."
        }
        $Log += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- ---"
    }
    $ResultCode = 0
    $ResultMsg  = "Success"
}
# Unexpected error: catching it.
Catch {
    $ResultCode = 2
    $ResultMsg  = $_.toString()
    Write-EventLog -LogName $EventLogName -Source $EventLogSource -EntryType Error -EventId 2048 -Category 0 -Message "Unexpected Error encounter by the script!`n`n$($_.ToString())"
}

# Exit script
if (-not(test-path "$($env:ProgramData)\HardenAD\Logs\"))
{
	[void](New-Item -Name "Logs" -ItemType Directory -Path "$($env:ProgramData)\HardenAD" -force)
}

$log += (Get-Date -UFormat "%Y-%m-%d %T ") + "-->"
$log += (Get-Date -UFormat "%Y-%m-%d %T ") + "--> RESULT CODE...: $Resultcode"
$log += (Get-Date -UFormat "%Y-%m-%d %T ") + "--> RESULT MESSAGE: $ResultMsg"
$log += (Get-Date -UFormat "%Y-%m-%d %T ") + "-->"
$log += (Get-Date -UFormat "%Y-%m-%d %T ") + "=== | INIT  ROTATIVE  LOG "
if (Test-Path "$($env:ProgramData)\HardenAD\Logs\$DbgFile") 
{
    $log += (Get-Date -UFormat "%Y-%m-%d %T ") + "--- --> Rotate log file......: 1000 last entries kept" 
    $Backup = Get-Content "$($env:ProgramData)\HardenAD\Logs\$DbgFile" -Tail 1000 
    $Backup | Out-File "$($env:ProgramData)\HardenAD\Logs\$DbgFile" -Force
}
$log += (Get-Date -UFormat "%Y-%m-%d %T ") + "=== | STOP  ROTATIVE  LOG "
$Log += (Get-Date -UFormat "%Y-%m-%d %T ") + "--> Group(s) flushing is over"
$Log += (Get-Date -UFormat "%Y-%m-%d %T ") + "***"
$Log += (Get-Date -UFormat "%Y-%m-%d %T ") + "*** SCRIPT FINISH"
$Log += (Get-Date -UFormat "%Y-%m-%d %T ") + "***"
$log | out-file "$($env:ProgramData)\HardenAD\Logs\$DbgFile" -append

Exit $ResultCode