Function compare-LocalAdminPasswordSolution {
    <#
        .SYNOPSIS
        Compare two edition of had, section LocalAdminPasswordSolutions

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

    #region .. LAPS
    $ztotal     = 0
    $zModified  = 0
    $zRemoved   = 0
    $zAdded     = 0
    $zIdentical = 0
    $ChangeDetails = @()
    $ChangeLog += @("### LocalAdminPasswordSolution  ", " ", "Permission|Target|Status  ","---|---|---  ")
    
    # SelfPerm
    foreach ($object in (Compare-Object $OldSelf.Target $newSelf.target -IncludeEqual)) {
        $ztotal++
        Switch ($object.sideIndicator) {
            "==" {
                # Same 
                $zIdentical++
                $ChangeLog += "Self|$($object.InputObject)|No change  "
            }
            "<=" {
                # Only in Old
                $zRemoved++
                $ChangeLog += "Self|$($object.InputObject)|Removed  "
            }
            "=>" {
                # Only in New
                $zAdded++
                $ChangeLog += "Self|$($object.InputObject)|Added  "
            }
        }
    }

    #PasswordRead
    foreach ($object in (Compare-Object $OldPwdR.Target $newPwdR.target -IncludeEqual)) {
        $ztotal++
        Switch ($object.sideIndicator) {
            "==" {
                # Same, need to ensure this is also the same Id
                $OldID = ($OldPwdR | Where-Object { $_.Target -eq ($object.InputObject) }).Id
                $NewID = ($NewPwdR | Where-Object { $_.Target -eq ($object.InputObject) }).Id
                
                if ($OldID -eq $NewID) {
                    $zIdentical++
                    $ChangeLog += "Read Password|$($object.InputObject)|No change  "
                }
                Else {
                    $zModified++
                    $ChangeLog += "Read Password|$($object.InputObject)|New ID:</BR>$($NewID)  "
                }
            }
            "<=" {
                # Only in Old
                $zRemoved++
                $OldID = ($OldPwdR | Where-Object { $_.Target -eq ($object.InputObject) }).Id
                $ChangeLog += "Read PAssword|$($object.InputObject)|Removed:</BR>$($OldID)  "
            }
            "=>" {
                # Only in New
                $zAdded++
                $NewID = ($NewPwdR | Where-Object { $_.Target -eq ($object.InputObject) }).Id
                $ChangeLog += "Read Password|$($object.InputObject)|Added:</BR>$($NewID)  "
            }
        }
    }
    
    #PasswordReset
    foreach ($object in (Compare-Object $OldPwdW.Target $newPwdW.target -IncludeEqual)) {
        $ztotal++
        Switch ($object.sideIndicator) {
            "==" {
                # Same, need to ensure this is also the same Id
                $OldID = ($OldPwdW | Where-Object { $_.Target -eq ($object.InputObject) }).Id
                $NewID = ($NewPwdW | Where-Object { $_.Target -eq ($object.InputObject) }).Id
                
                if ($OldID -eq $NewID) {
                    $zIdentical++
                    $ChangeLog += "Reset Password|$($object.InputObject)|No change  "
                }
                Else {
                    $zModified++
                    $ChangeLog += "Reset Password|$($object.InputObject)|New ID:</BR>$($NewID)  "
                }
            }
            "<=" {
                # Only in Old
                $zRemoved++
                $OldID = ($OldPwdW | Where-Object { $_.Target -eq ($object.InputObject) }).Id
                $ChangeLog += "Reset PAssword|$($object.InputObject)|Removed:</BR>$($OldID)  "
            }
            "=>" {
                # Only in New
                $zAdded++
                $NewID = ($NewPwdW | Where-Object { $_.Target -eq ($object.InputObject) }).Id
                $ChangeLog += "Reset Password|$($object.InputObject)|Added:</BR>$($NewID)  "
            }
        }
    }
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