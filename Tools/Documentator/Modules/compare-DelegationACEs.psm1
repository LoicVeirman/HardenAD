Function compare-DelegationACEs {
    <#
        .SYNOPSIS
        Compare two edition of had, section delegationACEs

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
    $oldACLs = $OldData.ACL
    $newACLs = $newData.ACL
    $OldSDDL = $OldData.SDDL
    $newSDDL = $newData.SDDL

    # Prepare collect data (md form)
    $ChangeLog = @(
        "# CHANGE LOG: DelegationACEs  "
        "Below information details all changes in TasksSequence_HardenAD.xml/DelegationACEs done in this edition.  "
        " "
        "---  "
    )
    $ResumeLog = @(
        "### DelegationACEs "
        ' '
    )
    #endRegion init

    #region .. Compare ACL
    $ACLPresent = 0
    $ACLremoved = 0
    $ACLAdded   = 0
    $totalACL   = 0
    $ChangeLog += @("### ACL  ", " ", "Status|Trustee|Right|RightType|Inheritance|InheritedObjects|ObjectType|TargetDN","---|---|---|---|---|---|---|---" ) 
    foreach ($ACL in $oldACLs) {
        $ExistInNew = $null
        # increment counter
        $totalACL++
        # check if still present in newACL
        $ExistInNew = $newACLs | Where-Object {
            $_.Trustee -eq "$($aCL.Trustee)" `
            -and $_.Right -eq "$($ACL.Right)" `
            -and $_.RightType -eq "$($ACL.RightType)" `
            -and $_.Inheritance -eq "$($ACL.Inheritance)" `
            -and $_.InheritedObjects -eq "$($ACL.InheritedObjects)" `
            -and $_.ObjectType -eq "$($ACL.ObjectType)" `
            -and $_.TargetDN -eq "$($ACL.TargetDN)"
        }
        # if exists...
        if ($ExistInNew) {
            $ACLPresent++
            $ChangeLog += "No change|$($ACL.Trustee)|$($ACL.Right)|$($ACL.RightType)|$($ACL.Inheritance)|$($ACL.InheritedObjects)|$($ACL.ObjectType)|$($ACL.TargetDN)"
        }
        Else {
            $ACLremoved++
            $ChangeLog += "Removed|$($ACL.Trustee)|$($ACL.Right)|$($ACL.RightType)|$($ACL.Inheritance)|$($ACL.InheritedObjects)|$($ACL.ObjectType)|$($ACL.TargetDN)"
        }
    }
    # Now looking for new ACL
    foreach ($ACL in $newACLs) {
        # increment counter
        $ExistInOld = $null
        # check if still present in newACL
        $ExistInOld = $oldACLs | Where-Object {
            $_.Trustee -eq "$($aCL.Trustee)" `
            -and $_.Right -eq "$($ACL.Right)" `
            -and $_.RightType -eq "$($ACL.RightType)" `
            -and $_.Inheritance -eq "$($ACL.Inheritance)" `
            -and $_.InheritedObjects -eq "$($ACL.InheritedObjects)" `
            -and $_.ObjectType -eq "$($ACL.ObjectType)" `
            -and $_.TargetDN -eq "$($ACL.TargetDN)"
        }
        # if exists...
        if ($ExistInOld) {
            # don't give a ...
        }
        Else {
            $totalACL++
            $ACLAdded++
            $ChangeLog += "Added|$($ACL.Trustee)|$($ACL.Right)|$($ACL.RightType)|$($ACL.Inheritance)|$($ACL.InheritedObjects)|$($ACL.ObjectType)|$($ACL.TargetDN)"
        }
    }
    $resumTxt = "There is a total of $totalACL ACL present in the new edition. $($ACLPresent) were not modified from the previous release" 
    if ($ACLremoved -eq 1) {
        $resumTxt += ", $($ACLremoved) was removed from the previous edition"
    }
    elseif ($ACLremoved -gt 1) {
        $resumTxt += ", $($ACLremoved) were removed from the previous edition"
    }
    if ($ACLAdded -eq 1) {
        $resumTxt += " and $($ACLadded) was added from the previous edition"
    }
    elseif ($ACLAdded -gt 1) {
        $resumTxt += " and $($ACLAdded) were added from the previous edition"
    }
    $resumTxt += "."
    $ResumeLog += $resumTxt
    #endRegion Compare ACL

    #region .. Compare SDDL
    $SDDLPresent = 0
    $SDDLremoved = 0
    $SDDLAdded   = 0
    $totalSDDL   = 0
    $ChangeLog += @("  ","### SDDL  ", " ", "Status|Trustee|CustomAccessRule|TargetDN","---|---|---|---" ) 
    foreach ($SDDL in $oldSDDL) {
        # increment counter
        $ExistInNew = $null
        $totalSDDL++
        # check if still present in newACL
        $ExistInNew = $newSDDL | Where-Object {
            $_.Trustee -eq "$($SDDL.Trustee)" `
            -and $_.CustomAccessRule -eq "$($SDDL.CustomAccessRule)" `
            -and $_.TargetDN -eq "$($SDDL.TargetDN)"
        }
        # if exists...
        if ($ExistInNew) {
            $SDDLPresent++
            $ChangeLog += "No change|$($SDDL.Trustee)|$($SDDL.CustomAccessRule)|$($SDDL.TargetDN)"
        }
        Else {
            $SDDLremoved++
            $ChangeLog += "Removed|$($SDDL.Trustee)|$($SDDL.CustomAccessRule)|$($SDDL.TargetDN)"
        }
    }
    # Now looking for new ACL
    foreach ($SDDL in $newSDDL) {
        $ExistInOld = $null
        # check if still present in newACL
        $ExistInOld = $oldSDDL | Where-Object {
            $_.Trustee -eq "$($SDDL.Trustee)" `
            -and $_.CustomAccessRule -eq "$($SDDL.CustomAccessRule)" `
            -and $_.TargetDN -eq "$($SDDL.TargetDN)"
        }
        # if exists...
        if ($ExistInOld) {
            # don't give a ...
        }
        Else {
            $totalSDDL++
            $SDDLAdded++
            $ChangeLog += "Added|$($SDDL.Trustee)|$($SDDL.CustomAccessRule)|$($SDDL.TargetDN)"
        }
    }
    $resumTxt = "There is a total of $totalSDDL SDDL present in the previous edition. $($SDDLPresent) were not modified" 
    if ($SDDLremoved -eq 1) {
        $resumTxt += ", $($SDDLremoved) was removed from the previous edition"
    }
    elseif ($SDDLremoved -gt 1) {
        $resumTxt += ", $($SDDLremoved) were removed from the previous edition"
    }
    if ($SDDLAdded -eq 1) {
        $resumTxt += " and $($SDDLadded) was added from the previous edition"
    }
    elseif ($SDDLAdded -gt 1) {
        $resumTxt += " and $($SDDLAdded) were added from the previous edition"
    }
    $resumTxt += "."
    $ResumeLog += @($ResumeTxt,'  ','Details can be reviewed in [_Detail-DelegationACEs.md_](/Documentations/Changelog/Detail-DelegationACEs.md).')
    #endRegion Compare SDDL

    #region .. Finally
    $ChangeLog | out-file ..\..\Documentations\Changelog\Detail-DelegationACEs.md -Encoding UTF8 -Force
    return $ResumeLog
    #endREgion Finally
}