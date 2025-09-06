Function compare-GroupPolicies {
    <#
        .SYNOPSIS
        Compare two edition of had, section GroupPolicies

        .PARAMETER OldData
        The xml data to compare with.

        .PARAMETER NewData
        The xml data from the new release.

        .NOTES 
        Version 1.0.0
        Author  Loic VEIRMAN MSSEC
    #>

    Param(
        [parameter(Mandatory,Position=0)]
        $OldData,

        [parameter(Mandatory,Position=1)]
        $NewData
    )

    #region .. init
    $oldWMI = $OldData.WmiFilters.Filter
    $newWMI = $newData.WmiFilters.Filter
    $oldGPO = $OldData.GPO
    $newGPO = $NewData.GPO
    # Prepare collect data (md form)
    $ChangeLog = @(
        "# CHANGE LOG: GroupPolicies  "
        "Below information details all changes in TasksSequence_HardenAD.xml/GroupPolicies done in this edition.  "
        " "
        "---  "
    )
    $ResumeLog = @(
        "### GroupPolicies "
        ' '
    )
    #endRegion init

    #region .. Wmifilters
    $ChangeLog += @('### WMI Filters',' ','Status|Name|Source','---|---|---  ')
    $sameWMI   = 0
    $UpdateWMI = 0
    $RemoveWMI = 0
    $AddWMI    = 0
    $TotalWMI  = 0

    foreach ($Object in (Compare-Object $oldWMI.Name $newWMI.Name -IncludeEqual)) {
        Switch ($Object.SideIndicator) {
            "==" {
                # Present in both file
                $TotalWMI++
                if ( ($oldWMI | Where-Object { $_.Name -eq $Object.InputObject }).Source -eq ($newWMI | Where-Object { $_.Name -eq $Object.InputObject }).Source) {
                    $ChangeLog += "No change|$($Object.InputObject)|$(($newWMI | Where-Object { $_.Name -eq $Object.InputObject }).Source)"
                    $sameWMI++
                }
                else {
                    $ChangeLog += "Source updated|$($Object.InputObject)|$($newWMI | Where-Object { $_.Name -eq $Object.InputObject }).Source)"
                    $UpdateWMI++
                }
            }
            "=>" {
                # Present in new file
                $ChangeLog += "Added|$($Object.InputObject)|$(($newWMI | Where-Object { $_.Name -eq $Object.InputObject }).Source)"
                $AddWMI++
                $TotalWMI++
            }
            "<=" {
                # Present in old file
                $ChangeLog += "Removed|$($Object.InputObject)|$(($oldWMI | Where-Object { $_.Name -eq $Object.InputObject }).Source)"
                $RemoveWMI++
            }
        }
    }
    $ChangeLog += "  "
    $resumeTxt = "There are $($TotalWMI) WMI filter present in this edition:"
    Switch ($sameWMI) {
        { $_ -eq 0 } { $resumeTxt += " none were kept from the previous edition"  }
        { $_ -eq 1 } { $resumeTxt += " $($sameWMI) was kept from the previous edition"  }
        { $_ -gt 1 } { $resumeTxt += " $($sameWMI) were kept from the previous edition"  }
    }
    if ($UpdateWMI -gt 0) {
        $resumeTxt += ", $($UpdateWMI) have been updated"
    }
    if ($AddWMI -gt 0) {
        $resumeTxt += ", $($AddWMI) have been added"
    }
    Switch ($removeWMI) {
        { $_ -eq 0 } { $resumeTxt += " and none were removed from the previous edition.  "  }
        { $_ -eq 1 } { $resumeTxt += " and $($sameWMI) was removed from the previous edition.  "  }
        { $_ -gt 1 } { $resumeTxt += " and $($sameWMI) were removed from the previous edition.  "  }
    }
    $ResumeLog += @($resumeTxt,'  ')
    #endRegion WmiFilters

    #region .. GPO
    $addGPO    = 0
    $sameGPO   = 0
    $totalGPO  = 0
    $removeGPO = 0
    $updateGPO = 0
    $GpoDetail = @()

    $ChangeLog += @('### GPO',' ','GPO|Status  ','---|---  ')

    foreach ($Object in (Compare-Object $oldGPO.Name $newGPO.Name -IncludeEqual)) {
        Switch ($Object.SideIndicator) {
            "==" {
                # Flag for modification present
                $gpoModified = $false
                $FirstMatch  = $true
                # Present in both
                $totalGPO++
                
                # Ensure backupID are the same
                $oldBkpID = ($oldGPO | Where-Object { $_.Name -eq $Object.InputObject }).BackupID
                $newBkpID = ($newGPO | Where-Object { $_.Name -eq $Object.InputObject }).BackupID
                
                if ($oldBkpID -eq $newBkpID) {
                    # Compute common path to the main folder
                    $gpoFolder = "Inputs\GroupPolicies\$($Object.InputObject)\$($newBkpID)"
                    
                    # Get file and hashes to ensure both match and there is no hidden change...
                    $oldFiles = @()
                    $newFiles = @()
                    Get-ChildItem -Path "$($PreviousSourceFolder)\$($gpoFolder)" -Recurse -File | ForEach-Object { $oldFiles += New-Object -TypeName psobject -Property @{File = $_.Name ; Hash = (Get-FileHash $_.Fullname).Hash } }
                    Get-ChildItem -Path "$(Resolve-Path ..\..)\$($gpoFolder)" -Recurse -File | ForEach-Object { $newFiles += New-Object -TypeName psobject -Property @{File = $_.Name ; Hash = (Get-FileHash $_.Fullname).Hash } }
                    
                    # Any removed or added file? We discard equal files
                    foreach ($file in (Compare-Object $oldFiles.File $newFiles.file)) {
                        # Tag for modification
                        $gpoModified = $true
                        # Check if Gpo Details header needed
                        if ($FirstMatch) {
                            $FirstMatch = $false
                            $updateGPO++
                            $GpoDetail += "**$($Object.InputObject):**  "
                        }
                        # Define if added or removed
                        if ($file.SideIndicator -eq "<=") {
                            $gpoDetail += "> File removed: $($file.InputObject)  "
                        }
                        Else {
                            $gpoDetail += "> File added: $($file.InputObject)  "
                        }
                    }
                    # Any modified file? Discard equals.
                    foreach ($file in (Compare-Object $oldFiles.hash $newFiles.hash)) {
                        # Tag for modification
                        $gpoModified = $true
                        # Check if Gpo Details header needed
                        if ($FirstMatch) {
                            $FirstMatch = $false
                            $updateGPO++
                            $GpoDetail += "**$($Object.InputObject):**  "
                        }
                        # We only care about file modified in the new release
                        if ($file.SideIndicator -eq "=>") {
                            $gpoDetail += "> File modified: $(($newfiles | Where-Object { $_.Hash -eq $file.InputObject}).file)  "
                        }
                    }
                }
                # New backup files
                Else {
                    # Mismatch, hence its a new GPO
                    $gpoModified = $True
                    $updateGPO++
                    $GpoDetail += @("**$($Object.InputObject):**  ",'> New backup ID that indicates potential changes.  ','  ')
                }

                # Ensure no modification on WmiFilter applied to the Gpo
                $oldGpoFilter = ($oldGPO | Where-Object { $_.Name -eq $Object.InputObject }).GpoFilter
                $newGpoFilter = ($oldGPO | Where-Object { $_.Name -eq $Object.InputObject }).GpoFilter

                # mismatch between new and old and old have a value?
                Switch ($oldGpoFilter) {
                    # No old gpo filter
                    { $_ -eq $null } {
                        Switch ($newGpoFilter) {
                            # no new too - nothing to do here.
                            { $_ -eq $null } { }
                            # this is a change: a filter is now present.
                            { $_ -ne $null } {
                                # Gpo is modified
                                $gpoModified = $true
                                # First match?
                                if ($FirstMatch) {
                                    $FirstMatch = $false
                                    $updateGPO++
                                    $GpoDetail += "**$($Object.InputObject):**  "
                                }
                                # Append detail
                                $GpoDetail += "> WMI Filter has been set to $($newGpoFilter.wmi) while there was none before  "
                            }
                        }
                    }
                    # old gpo filter present
                    { $_ -ne $null } {
                        Switch ($newGpoFilter) {
                            { $_ -eq $null } { 
                                # Gpo is modified
                                $gpoModified = $true
                                # First match?
                                if ($FirstMatch) {
                                    $FirstMatch = $false
                                    $updateGPO++
                                    $GpoDetail += "**$($Object.InputObject):**  "
                                }
                                # Append detail
                                $GpoDetail += "> WMI Filter has been removed  "
                            }
                            { $_ -ne $null } {
                                # Check if value has changed
                                if ($oldGpoFilter.WMI -ne $newGpoFilter.WMI) {
                                    # Gpo is modified
                                    $gpoModified = $true
                                    # First match?
                                    if ($FirstMatch) {
                                        $FirstMatch = $false
                                        $updateGPO++
                                        $GpoDetail += "**$($Object.InputObject):**  "
                                    }
                                    # Append detail
                                    $GpoDetail += "> WMI Filter has been changed to $($newGpoFilter.wmi)  "
                                }
                            }
                        }
                    }
                }

                # Ensure no modification were done on gpLinks
                $oldGpoLinks =  ($oldGPO | Where-Object { $_.Name -eq $Object.InputObject }).GpoLink
                $newGpoLinks =  ($oldGPO | Where-Object { $_.Name -eq $Object.InputObject }).GpoLink

                if ($oldGpoLinks -and $newGpoLinks) {
                    foreach ($gpoLink in (Compare-Object $oldGpoLinks.path $newGpoLinks.Path)) {
                        # We do not care about the sideIdicator "==" which indicates no change
                        switch ($gpoLink.SideIndicator) {
                            "=>" {
                                # New settings applied
                                $gpoModified = $true

                                if ($FirstMatch) {
                                    $FirstMatch = $false
                                    $updateGPO++
                                    $GpoDetail += "**$($Object.InputObject):**  "
                                }
                                $GpoDetail += "> GPLink has been set to $($gpoLink.InputObject)"
                            }
                            "<=" {
                                # New settings applied
                                $gpoModified = $true

                                if ($FirstMatch) {
                                    $FirstMatch = $false
                                    $updateGPO++
                                    $GpoDetail += "**$($Object.InputObject):**  "
                                }
                                $GpoDetail += "> GPLink has been removed from $($gpoLink.InputObject)"
                            }
                        }
                    }
                }
                Elseif ($newGpoLinks) {
                    # Has only new links
                    $gpoModified = $true
                    foreach ($gpoLink in $newGpoLinks) {
                        if ($FirstMatch) {
                            $FirstMatch = $false
                            $updateGPO++
                            $GpoDetail += "**$($Object.InputObject):**  "
                        }
                        $GpoDetail += "> GPLink has been set to $($gpoLink.InputObject)"
                    }
                }
                # Finally update that...
                if ($gpoModified) {
                    $ChangeLog += "$($Object.InputObject)|GPO updated"
                }
                else {
                    $sameGPO++
                    $ChangeLog += "$($Object.InputObject)|GPO unmodified"
                }

            }
            "=>" {
                # Present in new
                $totalGPO++
                $addGPO++
                $ChangeLog += "$($Object.InputObject)|GPO added"
            }
            "<=" {
                # Present in old
                $removeGPO++
                $ChangeLog += "$($Object.InputObject)|GPO removed"
            }
        }
        $GpoDetail += '  '
    }
    $ChangeLog += @('  ',$GpoDetail,'  ')
    $resumeTxt = "There are $($totalGPO) GPO present in this edition:"
    Switch ($sameGPO) {
        { $_ -eq 0 } { $resumeTxt += " none were kept from the previous edition"  }
        { $_ -eq 1 } { $resumeTxt += " $($sameGPO) was kept from the previous edition"  }
        { $_ -gt 1 } { $resumeTxt += " $($sameGPO) were kept from the previous edition"  }
    }
    if ($UpdateGPO -gt 0) {
        $resumeTxt += ", $($UpdateGPO) have been updated"
    }
    if ($addGPO -gt 0) {
        $resumeTxt += ", $($AddGPO) have been added"
    }
    Switch ($removeGPO) {
        { $_ -eq 0 } { $resumeTxt += " and none were removed from the previous edition.  "  }
        { $_ -eq 1 } { $resumeTxt += " and $($removeGPO) was removed from the previous edition.  "  }
        { $_ -gt 1 } { $resumeTxt += " and $($removeGPO) were removed from the previous edition.  "  }
    }
    $ResumeLog += @($ResumeTxt,'  ','Details can be reviewed in [_Detail-GroupPolicies.md_](/Documentations/Changelog/Detail-GroupPolicies.md).')
    #endRegion GPO

    #region .. Finally
    if (Test-Path ..\..\Documentations\Changelog\Detail-GroupPolicies.md) {
        [void](Remove-Item ..\..\Documentations\Changelog\Detail-GroupPolicies.md -Force)
    }
    $ChangeLog | out-file ..\..\Documentations\Changelog\Detail-GroupPolicies.md -Encoding UTF8 -Force
    return $ResumeLog
    #endRegion Finally
}
