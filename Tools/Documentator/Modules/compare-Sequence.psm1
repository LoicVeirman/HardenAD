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
    foreach ($object in Compare-Object $OldData.ID.Number $NewData.Id.Number -IncludeEqual) {
        $zTotal++
        Switch ($object.sideIndicator) {
            "==" {
                # present in both - everything to be checked...
            }
            "<=" {
                # Only present in old
                $zRemoved
            }
            "=>" {
                # Only present in new
                $zAdded++
                
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
    $ResumeLog += @($ResumeTxt,'  ','Details can be reviewed in [_Detail-LocalAdminPasswordSolution.md_](/Documentations/Changelog/Detail-LocalAdminPasswordSolution.md).  ')
    #endRegion LAPS

    #region .. Finally
    $ChangeLog | out-file ..\..\Documentations\Changelog\Detail-LocalAdminPasswordSolution.md -Encoding UTF8 -Force
    return $ResumeLog
    #endRegion Finally
}