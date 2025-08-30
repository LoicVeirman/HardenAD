Function compare-DefaultMembers {
    <#
        .SYNOPSIS
        Compare two edition of had, section DefaultMembers

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
    $oldDfltMbrs = $OldData.Group
    $newDfltMbrs = $newData.Group
    # Prepare collect data (md form)
    $ChangeLog = @(
        "# CHANGE LOG: DefaultMembers  "
        "Below information details all changes in TasksSequence_HardenAD.xml/DefaultMembers done in this edition.  "
        " "
        "---  "
    )
    $ResumeLog = @(
        "### DefaultMembers "
        ' '
    )
    #endRegion init

    #region .. DefaultMembers
    $DfltAdded     = 0
    $DfltRemoved   = 0
    $DfltModified  = 0
    $DfltIdentical = 0
    $DfltTotal     = 0
    $ChangeDetails = @()
    $ChangeLog += @("### DefaultMembers  ", " ", "Target|Status  ","---|---  ")
    foreach ($object in (Compare-Object $oldDfltMbrs.Target $newDfltMbrs.Target -IncludeEqual)) {
        $FirstMatch = $true
        $DfltTotal++
        Switch ($object.sideIndicator) {
            "==" {
                # Present in old and new
                $oldTruc = $oldDfltMbrs | Where-Object { $_.Target -eq $object.InputObject }
                $newTruc = $newDfltMbrs | Where-Object { $_.Target -eq $object.InputObject }
                if ($oldTruc.AllowedTo -ne $newTruc.AllowedTo) {
                    if ($FirstMatch) {
                        $FirstMatch = $false
                        $DfltModified++
                        $ChangeDetails += "**$($object.InputObject):**  "
                    }
                    $ChangeDetails += "> AllowedTo modified to: *$($newTruc.AllowedTo)*  "
                }
                if ($oldTruc.Member -and $newTruc.Member) {
                    # comparing
                    foreach ($member in (Compare-Object $oldTruc.Member $newTruc.Member)) {
                        Switch ($member.sideIndicator) {
                            "<=" {
                                # Present in old
                                if ($FirstMatch) {
                                    $FirstMatch = $false
                                    $DfltModified++
                                    $ChangeDetails += "**$($object.InputObject):**  "
                                }
                                $ChangeDetails += "> Removed member: *$($member.InputObject)*  "
                            }
                            "=>" {
                                # Present in new
                                if ($FirstMatch) {
                                    $FirstMatch = $false
                                    $DfltModified++
                                    $ChangeDetails += "**$($object.InputObject):**  "
                                }
                                $ChangeDetails += "> Added member: *$($member.InputObject)*  "
                            }
                        }
                    }
                }
                if ($oldTruc.Member -and -not($newTruc.Member)) {
                    # removed members....
                    foreach ($member in $oldTruc.Member) {
                        if ($FirstMatch) {
                            $FirstMatch = $false
                            $DfltModified++
                            $ChangeDetails += "**$($object.InputObject):**  "
                        }
                        $ChangeDetails += "> Removed member: *$($member.InputObject)*  "
                    }
                }
                if ($newTruc.Member -and -not($oldTruc.Member)) {
                    # added members....
                    foreach ($member in $newTruc.Member) {
                        if ($FirstMatch) {
                            $FirstMatch = $false
                            $DfltModified++
                            $ChangeDetails += "**$($object.InputObject):**  "
                        }
                        $ChangeDetails += "> Added member: *$($member.InputObject)*  "
                    }
                }
            }
            "<=" {
                # Present in old only
                $DfltRemoved++
                $ChangeLog += "$($object.InputObject)|Removed"
            }
            "=>" {
                # Present in new only
                $DfltAdded++
                $ChangeLog += "$($object.InputObject)|Added"
                $ChangeDetails += "**$($Object.InputObject):**  "
                $ChangeDetails += ">  Allowed to: *$(($oldDfltMbrs | Where-Object { $_.Traget -eq $object.InputObject}).AllowedTo)*  "
                foreach ($member in (($oldDfltMbrs | Where-Object { $_.Traget -eq $object.InputObject}).Member)) {
                    $ChangeDetails += ">  Added Member: *$($member)*  "
                }
            }
        }
        if ($FirstMatch) {
            $DfltIdentical++
            $ChangeLog += "$($object.InputObject)|No change"
        }
        $ChangeDetails += '  '
    }
    # Generate output data
    $ChangeLog += @('  ',$ChangeDetails,'  ')
    $ResumeTxt = "There are $($DfltTotal) DefaultMembers targets present in this edition:"
    switch ($DfltIdentical) {
        { $_ -eq 0 } { $resumeTxt += " none were kept from the previous edition" }
        { $_ -eq 1 } { $resumeTxt += " $($DfltIdentical) was kept from the previous edition" }
        { $_ -gt 1 } { $resumeTxt += " $($DfltIdentical) were kept from the previous edition" }
    }
    if ($DfltModified -gt 0) {
        $ResumeTxt += ", $($DfltModified) have been updated"
    }
    if ($DfltAdded -gt 0) {
        $ResumeTxt += ", $($DfltAdded) have been added"
    }
    switch ($DfltRemoved) {
        { $_ -eq 0 } { $resumeTxt += " and none were removed from the previous edition.  " }
        { $_ -eq 1 } { $resumeTxt += " and $($DfltRemoved) was removed from the previous edition.  " }
        { $_ -gt 1 } { $resumeTxt += " and $($DfltRemoved) were removed from the previous edition.  " }
    }
    $ResumeLog += @($ResumeTxt,'  ','Details can be reviewed in [_Detail-DefaultMembers.md_](/documentations/Changelog/Detail-DefaultMembers.md).  ')
    #endRegion DefaultMembers

    #region .. Finally
    $ChangeLog | out-file ..\..\Documentations\Changelog\Detail-DefaultMembers.md -Encoding UTF8 -Force
    return $ResumeLog
    #endRegion Finally
}