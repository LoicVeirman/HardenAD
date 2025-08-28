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
    $oldGroups = $OldData.Groups
    $newGroups = $newData.Groups
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
    #region .. Finally
    $ChangeLog | out-file ..\..\Documentations\Changelog\Detail-Groups.md -Encoding UTF8 -Force
    return $ResumeLog
    #endRegion Finally
}