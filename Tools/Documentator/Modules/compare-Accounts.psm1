Function compare-Accounts {
    <#
        .SYNOPSIS
        Compare two edition of had, section Accounts

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
    $oldAccounts = $OldData.User
    $newAccounts = $newData.User
    # Prepare collect data (md form)
    $ChangeLog = @(
        "# CHANGE LOG: Accounts  "
        "Below information details all changes in TasksSequence_HardenAD.xml/Accounts done in this edition.  "
        " "
        "---  "
    )
    $ResumeLog = @(
        "### Accounts "
        ' '
    )
    #endRegion init

    #region .. Check Users
    $UserUpdated   = 0
    $UserAdded     = 0
    $UserRemoved   = 0
    $UserIdentical = 0
    $UserTotal     = 0
    $ChangeDetails = @()
    $ChangeLog += @("### Users  ", " ", "sAMAccountName|DisplayName|Status  ","---|---|---  " ) 
    foreach ($object in (compare-object $oldAccounts.sAMAccountName $newAccounts.sAMAccountName -IncludeEqual)) { 
        $UserTotal++
        Switch ($object.sideIndicator) {
            "==" {
                # Exists in both
                $oldDisp = ($oldAccounts | Where-Object { $_.sAMAccountName -eq $Object.InputObject}).DisplayName
                $oldSuNa = ($oldAccounts | Where-Object { $_.sAMAccountName -eq $Object.InputObject}).Surname
                $oldGiNa = ($oldAccounts | Where-Object { $_.sAMAccountName -eq $Object.InputObject}).GivenName
                $oldDesc = ($oldAccounts | Where-Object { $_.sAMAccountName -eq $Object.InputObject}).Description
                $oldPath = ($oldAccounts | Where-Object { $_.sAMAccountName -eq $Object.InputObject}).Path
                $newDisp = ($newAccounts | Where-Object { $_.sAMAccountName -eq $Object.InputObject}).DisplayName
                $newSuNa = ($newAccounts | Where-Object { $_.sAMAccountName -eq $Object.InputObject}).Surname
                $newGiNa = ($newAccounts | Where-Object { $_.sAMAccountName -eq $Object.InputObject}).GivenName
                $newDesc = ($newAccounts | Where-Object { $_.sAMAccountName -eq $Object.InputObject}).Description
                $newPath = ($newAccounts | Where-Object { $_.sAMAccountName -eq $Object.InputObject}).Path
                # Prepare for resume details and final check
                $FirstMatch = $true
                # Compare data
                if ($oldDisp -ne $newDisp) {
                    if ($FirstMatch) {
                        $FirstMatch = $False
                        $UserUpdated++
                        $ChangeDetails += "**$($Object.InputObject):**  "
                    }
                    $ChangeDetails += "> DisplayName has been updated to: $($newDisp)"
                }
                if ($oldSuNa -ne $newSuNa) {
                    if ($FirstMatch) {
                        $FirstMatch = $False
                        $UserUpdated++
                        $ChangeDetails += "**$($Object.InputObject):**  "
                    }
                    $ChangeDetails += "> Surname has been updated to: $($newSuNa)"
                }
                if ($oldGiNa -ne $newGiNa) {
                    if ($FirstMatch) {
                        $FirstMatch = $False
                        $UserUpdated++
                        $ChangeDetails += "**$($Object.InputObject):**  "
                    }
                    $ChangeDetails += "> GivenName has been updated to: $($newGiNa)"
                }
                if ($oldDesc -ne $newDesc) {
                    if ($FirstMatch) {
                        $FirstMatch = $False
                        $UserUpdated++
                        $ChangeDetails += "**$($Object.InputObject):**  "
                    }
                    $ChangeDetails += "> Description has been updated to: $($newDesc)"
                }
                if ($oldPath -ne $newPath) {
                    if ($FirstMatch) {
                        $FirstMatch = $False
                        $UserUpdated++
                        $ChangeDetails += "**$($Object.InputObject):**  "
                    }
                    $ChangeDetails += "> Path has been updated to: $($newPath)"
                }
                # Add final result 
                if ($FirstMatch) {
                    # No differences
                    $UserIdentical++
                    $ChangeLog += "$($object.InputObject)|$(($newAccounts | Where-Object { $_.sAMAccountName -eq $Object.InputObject}).DisplayName)|No change"
                }
                Else {
                    # Object updated
                    $ChangeLog += "$($object.InputObject)|$(($newAccounts | Where-Object { $_.sAMAccountName -eq $Object.InputObject}).DisplayName)|Updated"
                }

            }
            "<=" {
                # Exists only in old
                $UserRemoved++
                $ChangeLog += "$($object.InputObject)|$(($oldAccounts | Where-Object { $_.sAMAccountName -eq $Object.InputObject}).DisplayName)|Removed"
            }
            "=>" {
                # Exists only in new
                $UserAdded++
                $ChangeLog += "$($object.InputObject)|$(($newAccounts | Where-Object { $_.sAMAccountName -eq $Object.InputObject}).DisplayName)|Added"
            }
        }
    }
    # Generate output data
    $ChangeLog += @('  ',$ChangeDetails,'  ')
    $ResumeTxt = "There are $($UserTotal) accounts present in this edition:"
    switch ($UserIdentical) {
        { $_ -eq 0 } { $resumeTxt += " none were kept from the previous edition" }
        { $_ -eq 1 } { $resumeTxt += " $($UserIdentical) was kept from the previous edition" }
        { $_ -gt 1 } { $resumeTxt += " $($UserIdentical) were kept from the previous edition" }
    }
    if ($UserUpdated -gt 0) {
        $ResumeTxt += ", $($UserUpdated) have been updated"
    }
    if ($UserAdded -gt 0) {
        $ResumeTxt += ", $($UserAdded) have been added"
    }
    switch ($UserRemoved) {
        { $_ -eq 0 } { $resumeTxt += " and none were removed from the previous edition.  " }
        { $_ -eq 1 } { $resumeTxt += " and $($UserRemoved) was removed from the previous edition.  " }
        { $_ -gt 1 } { $resumeTxt += " and $($UserRemoved) were removed from the previous edition.  " }
    }
    $ResumeLog += @($ResumeTxt,'  ','Details can be reviewed in [_Detail-Accounts.md_](/Documentations/Changelog/Detail-Accounts.md).')
    #endRegion Check Users

    #region .. Finally
    $ChangeLog | out-file ..\..\Documentations\Changelog\Detail-Accounts.md -Encoding UTF8 -Force
    return $ResumeLog
    #endRegion Finally
}