Function compare-Sequence {
    <#
        .SYNOPSIS
        Compare two edition of had, section Sequence

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
    # Prepare collect data (md form)
    $ChangeLog = @(
        "# CHANGE LOG: Sequence  "
        "Below information details all changes in TasksSequence_HardenAD.xml/Sequence done in this edition.  "
        " "
        "---  "
    )
    $ResumeLog = @(
        "### Sequence "
        ' '
    )
    #endRegion init

    #region .. Sequence 
    # Beware: ordering of compare-object reversed compare to other compare-...
    $ChangeDetails += @()
    $ChangeLog += @('  ',"Number|Name|Status  ",'---|---|---  ')
    foreach ($object in (Compare-Object $NewData.Id $OldData.ID -IncludeEqual -Property Name -PassThru | Sort-Object Number)) {
        $zTotal++
        $firstMatch = $true
        $oldID = ($OldData.ID | Where-Object { $_.Name -eq $object.Name }).Number
        $newID = ($NewData.ID | Where-Object { $_.Name -eq $object.Name }).Number
        Switch ($object.sideIndicator) {
            "==" {
                # present in both - everything to be checked...
                # IS the Id Number the same?
                if ($oldID -ne $newID) {
                    if ($firstMatch) {
                        $firstMatch = $false
                        $zModified++
                        $ChangeDetails += @('  ',"**$($object.Name):**  ")
                        $ChangeLog += "$($newID)|$($object.Name)|Modified  "
                    }
                    $ChangeDetails += "> Task relocated at position $($newID)  "
                }
                # Is the caller the same?
                $oldCall = ($OldData.ID | Where-Object { $_.Name -eq $object.Name }).CallingFunction
                $newCall = ($NewData.ID | Where-Object { $_.Name -eq $object.Name }).CallingFunction
                if ($oldCall -ne $newCall) {
                    if ($firstMatch) {
                        $firstMatch = $false
                        $zModified++
                        $ChangeDetails += @('  ',"**$($object.Name):**  ")
                        $ChangeLog += "$($newID)|$($object.Name)|Modified  "
                    }
                    $ChangeDetails += "> Called function modified to: $($newCall)  "
                }
                # Is thask enabled/disable the same?
                $oldEnable = ($OldData.ID | Where-Object { $_.Name -eq $object.Name }).TaskEnabled
                $newEnable = ($NewData.ID | Where-Object { $_.Name -eq $object.Name }).TaskEnabled
                if ($oldEnable -ne $newEnable) {
                    if ($firstMatch) {
                        $firstMatch = $false
                        $zModified++
                        $ChangeDetails += @('  ',"**$($object.Name):**  ")
                        $ChangeLog += "$($newID)|$($object.Name)|Modified  "
                    }
                    $ChangeDetails += "> Task is now $(if ($newEnable -eq "No") {'disabled'} else {'enabled' }) by default  "
                }
                # Is the description the same?
                $oldDesc = ($OldData.ID | Where-Object { $_.Name -eq $object.Name }).TaskDescription
                $newDesc = ($NewData.ID | Where-Object { $_.Name -eq $object.Name }).TaskDescription
                if ($oldDesc -ne $newDesc) {
                    if ($firstMatch) {
                        $firstMatch = $false
                        $zModified++
                        $ChangeDetails += @('  ',"**$($object.Name):**  ")
                        $ChangeLog += "$($newID)|$($object.Name)|Modified  "
                    }
                    $ChangeDetails += "> The descrition has been updated to **$($newDesc)**  "
                }
                # Are we using the same parameter set?
                $oldParam = ($OldData.ID | Where-Object { $_.Name -eq $object.Name }).UeParameters
                $newParam = ($NewData.ID | Where-Object { $_.Name -eq $object.Name }).UeParameters
                if ($null -ne $oldParam -and $null -ne $newParam) {
                    foreach ($usedParam in (Compare-Object $oldParam $newParam)) {
                        Switch ($usedParam.sideIndicator) {
                            "<=" {
                                # Missing in new
                                if ($firstMatch) {
                                    $firstMatch = $false
                                    $zModified++
                                    $ChangeDetails += @('  ',"**$($object.Name):**  ")
                                    $ChangeLog += "$($newID)|$($object.Name)|Modified  "
                                }
                                $ChangeDetails += "> Removed **$($usedParam.InputObject)** from parameter list  "
                            }
                            "=>" {
                                # Missing in old
                                if ($firstMatch) {
                                    $firstMatch = $false
                                    $zModified++
                                    $ChangeDetails += @('  ',"**$($object.Name):**  ")
                                    $ChangeLog += "$($newID)|$($object.Name)|Modified  "
                                }
                                $ChangeDetails += "> Added **$($usedParam.InputObject)** to parameter list  "
                            }
                        }
                    }
                }
                Elseif ($null -eq $oldParam -and $null -ne $newParam) {
                    foreach ($value in $newParam) {
                        if ($firstMatch) {
                            $firstMatch = $false
                            $zModified++
                            $ChangeDetails += @('  ',"**$($object.Name):**  ")
                            $ChangeLog += "$($newID)|$($object.Name)|Modified  "
                        }
                        $ChangeDetails += "> Added **$($value)** to parameter list  "
                    }
                }
                Elseif ($null -ne $oldParam -and $null -eq $newParam) {
                    foreach ($value in $newParam) {
                        if ($firstMatch) {
                            $firstMatch = $false
                            $zModified++
                            $ChangeDetails += @('  ',"**$($object.Name):**  ")
                            $ChangeLog += "$($newID)|$($object.Name)|Modified  "
                        }
                        $ChangeDetails += "> Removed **$($value)** from parameter list  "
                    }
                }

                # finally, any change detected?
                if ($firstMatch) {
                    $ChangeLog += "$($newID)|$($object.Name)|No change  "
                }
            }
            "=>" {
                # Only present in old
                $zRemoved++
                $ChangeLog += "$($oldID)|$($object.Name)|Removed  "
            }
            "<=" {
                # Only present in new
                $zAdded++
                $ChangeLog += "$($newID)|$($object.Name)|Added  "
                
            }
        }
    } 
    #endRegion Sequence 

    # Generate output data
    $ChangeLog += @('  ',$ChangeDetails,'  ')
    $ResumeTxt = "There are $($zTotal) actions present in this edition:"
    switch ($zIdentical) {
        { $_ -eq 0 } { $resumeTxt += " none were kept from the previous edition" }
        { $_ -eq 1 } { $resumeTxt += " $($zIdentical) was kept from the previous edition" }
        { $_ -gt 1 } { $resumeTxt += " $($zIdentical) were kept from the previous edition" }
    }
    if ($zModified -gt 0) {
        $ResumeTxt += ", $($zModified) have been updated"
    }
    if ($zAdded -gt 0) {
        $ResumeTxt += ", $($zAdded) have been added"
    }
    switch ($zRemoved) {
        { $_ -eq 0 } { $resumeTxt += " and none were removed from the previous edition.  " }
        { $_ -eq 1 } { $resumeTxt += " and $($zRemoved) was removed from the previous edition.  " }
        { $_ -gt 1 } { $resumeTxt += " and $($zRemoved) were removed from the previous edition.  " }
    }
    $ResumeLog += @($ResumeTxt,'  ','Details can be reviewed in [_Detail-Sequence.md_](/Documentations/Changelog/Detail-Sequence.md).  ')
    #endRegion LAPS

    #region .. Finally
    $ChangeLog | out-file ..\..\Documentations\Changelog\Detail-Sequence.md -Encoding UTF8 -Force
    return $ResumeLog
    #endRegion Finally
}