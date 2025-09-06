Function compare-Groups {
    <#
        .SYNOPSIS
        Compare two edition of had, section Groups

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
    $oldGroups = $OldData.Group
    $newGroups = $newData.Group
    # Prepare collect data (md form)
    $ChangeLog = @(
        "# CHANGE LOG: Groups  "
        "Below information details all changes in TasksSequence_HardenAD.xml/Groups done in this edition.  "
        " "
        "---  "
    )
    $ResumeLog = @(
        "### Groups "
        ' '
    )
    #endRegion init

    #region .. Compare groups
    $GroupAdded     = 0
    $GroupModified  = 0
    $GroupIdentical = 0
    $GroupRemoved   = 0
    $GroupTotal     = 0
    $ChangeDetails  = @()
    $ChangeLog += @("### Groups  ", " ", "Group|Status  ","---|---  " ) 
    foreach ($Object in (Compare-Object $oldGroups.Name $NewGroups.Name -IncludeEqual)) {
        # init
        $FirstMatch = $true
        $GroupTotal++
        $ChangeDetails += '  '
        # Check which kind of match on comparison
        Switch ($Object.sideIndicator) {
            "==" {
                # Exists in both
                $oldGroup = $oldGroups | Where-Object { $_.Name -eq $Object.InputObject }
                $newGroup = $newGroups | Where-Object { $_.Name -eq $Object.InputObject }
                # Compare Category
                if ($oldGroup.Category -ne $newGroup.Category) {
                    if ($FirstMatch) {
                        $GroupModified++
                        $FirstMatch = $false
                        $ChangeDetails += "**$($Object.InputObject):**  "
                    }
                    $ChangeDetails += "> Group category changed to *$($newGroup.Category)*  "
                }
                # Compare Scope
                if ($oldGroup.Scope -ne $newGroup.Scope) {
                    if ($FirstMatch) {
                        $GroupModified++
                        $FirstMatch = $false
                        $ChangeDetails += "**$($Object.InputObject):**  "
                    }
                    $ChangeDetails += "> Group scope changed to *$($newGroup.Scope)*  "
                }
                # Compare Description
                if ($oldGroup.Description -ne $newGroup.Description) {
                    if ($FirstMatch) {
                        $GroupModified++
                        $FirstMatch = $false
                        $ChangeDetails += "**$($Object.InputObject):**  "
                    }
                    $ChangeDetails += "> Group description changed to *$($newGroup.Description)*  "
                }
                # Compare Path
                if ($oldGroup.Path-ne $newGroup.Path) {
                    if ($FirstMatch) {
                        $GroupModified++
                        $FirstMatch = $false
                        $ChangeDetails += "**$($Object.InputObject):**  "
                    }
                    $ChangeDetails += "> Group path changed to *$($newGroup.Path)*  "
                }
                # Compare members
                if ($oldGroup.Member.sAMAccountName -and $newGroup.Member.sAMAccountName) {
                    foreach ($member in (Compare-Object $oldGroup.Member.sAMAccountName $newGroup.Member.sAMAccountName)) {
                        Switch ($member.sideIndicator) {
                            "<=" {
                                # missing in new
                                if ($FirstMatch) {
                                    $GroupModified++
                                    $FirstMatch = $false
                                    $ChangeDetails += "**$($Object.InputObject):**  "
                                }
                                $ChangeDetails += "> Removed member: *$($member.InputObject)*  "                            
                            }
                            "=>" {
                                # missing in old
                                if ($FirstMatch) {
                                    $GroupModified++
                                    $FirstMatch = $false
                                    $ChangeDetails += "**$($Object.InputObject):**  "
                                }
                                $ChangeDetails += "> Added member: *$($member.InputObject)*  "
                            }
                        }
                    }
                }
                if ($oldGroup.Member.sAMAccountName -and -not($newGroup.Member.sAMAccountName)) {
                    foreach ($member in $oldGroup.Member.sAMAccountName) {
                        # missing in new
                        if ($FirstMatch) {
                            $GroupModified++
                            $FirstMatch = $false
                            $ChangeDetails += "**$($Object.InputObject):**  "
                        }
                        $ChangeDetails += "> Removed member: *$($member)*  "                            
                    }
                }
                if ($newGroup.Member.sAMAccountName -and -not($oldGroup.Member.sAMAccountName)) {
                    foreach ($member in $newGroup.Member.sAMAccountName) {
                        # missing in new
                        if ($FirstMatch) {
                            $GroupModified++
                            $FirstMatch = $false
                            $ChangeDetails += "**$($Object.InputObject):**  "
                        }
                        $ChangeDetails += "> Added member: *$($member)*  "                            
                    }
                }
                if ($FirstMatch) {
                    $GroupIdentical++
                    $ChangeLog += "$($Object.InputObject)|No change  "
                }
                Else {
                    $ChangeLog += "$($Object.InputObject)|Modified  "
                }
            }
            "=>" {
                # missing in old
                $GroupTotal++
                $GroupAdded++
                $ChangeLog += "$($Object.InputObject)|Added"
                # Adding details about members
                if (($newGroups | Where-Object { $_.Name -eq $Object.InputObject }).Member) {
                    $ChangeDetails += "**$($Object.InputObject):**  "
                    foreach ($Member in ($newGroups | Where-Object { $_.Name -eq $Object.InputObject }).Member) {
                        $ChangeDetails += "> Added member: $($Member.sAMAccountName)  "
                    }
                }
            }
            "<=" {
                # missing in new
                $GroupTotal++
                $GroupRemoved++
                $ChangeLog += "$($Object.InputObject)|Removed"
            }
        }
    }
    $ChangeLog += @('  ',$ChangeDetails,'  ')
    $ResumeTxt = "There are $($GroupTotal) accounts present in this edition:"
    switch ($GroupIdentical) {
        { $_ -eq 0 } { $resumeTxt += " none were kept from the previous edition" }
        { $_ -eq 1 } { $resumeTxt += " $($GroupIdentical) was kept from the previous edition" }
        { $_ -gt 1 } { $resumeTxt += " $($GroupIdentical) were kept from the previous edition" }
    }
    if ($GroupModified -gt 0) {
        $ResumeTxt += ", $($GroupModified) have been modified"
    }
    if ($GroupAdded -gt 0) {
        $ResumeTxt += ", $($GroupAdded) have been added"
    }
    switch ($GroupRemoved) {
        { $_ -eq 0 } { $resumeTxt += " and none were removed from the previous edition.  " }
        { $_ -eq 1 } { $resumeTxt += " and $($groupRemoved) was removed from the previous edition.  " }
        { $_ -gt 1 } { $resumeTxt += " and $($groupRemoved) were removed from the previous edition.  " }
    }
    $ResumeLog += @($ResumeTxt,'  ','Details can be reviewed in [_Detail-Groups.md_](/Documentations/Changelog/Detail-Groups.md).')
    #endRegion Compare groups

    #region .. Finally
    $ChangeLog | out-file ..\..\Documentations\Changelog\Detail-Groups.md -Encoding UTF8 -Force
    return $ResumeLog
    #endRegion Finally
}
