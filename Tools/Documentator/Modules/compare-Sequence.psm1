Function compare-Sequence {
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
    $OldSelf = $OldData.AdmPwdSelfPermission
    $OldPwdR = $OldData.AdmPwdPasswordReader
    $OldPwdW = $OldData.AdmPwdPasswordReset
    $newSelf = $newData.AdmPwdSelfPermission
    $newPwdR = $newData.AdmPwdPasswordReader
    $newPwdW = $newData.AdmPwdPasswordReset
    # Prepare collect data (md form)
    $ChangeLog = @(
        "# CHANGE LOG: LocalAdminPasswordSolution  "
        "Below information details all changes in TasksSequence_HardenAD.xml/LocalAdminPasswordSolution done in this edition.  "
        " "
        "---  "
    )
    $ResumeLog = @(
        "### LocalAdminPasswordSolution "
        ' '
    )
    #endRegion init


    # Generate output data
    $ChangeLog += @('  ',$ChangeDetails,'  ')
    $ResumeTxt = "There are $($zTotal) permissions present in this edition:"
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