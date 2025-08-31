Function compare-Translation {
    <#
        .SYNOPSIS
        Compare two edition of had, section Translation

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
    $oldWK = $OldData.WellKnownID
    $newWK = $newData.WellKnownID
    $OldKW = $OldData.Keyword
    $newKW = $newData.Keyword

    # Prepare collect data (md form)
    $ChangeLog = @(
        "# CHANGE LOG: Translation  "
        "Below information details all changes in TasksSequence_HardenAD.xml/Translation done in this edition.  "
        " "
        "---  "
    )
    $ResumeLog = @(
        "### Translation "
        ' '
    )
    #endRegion init

    #region .. WellKnownID
    $ChangeLog += @("### WellKnonwnID  ", " ","Status|TranslateFrom|TranslateTo  ","---|---|---  ")

    $WKnew     = 0
    $WKsame    = 0
    $WKupdate  = 0
    $WKold     = 0
    $WKtotal   = 0

    foreach ($inputFrom in (compare-object $oldWK.TranslateFrom $newWK.TranslateFrom -IncludeEqual)) {
        # Check if exist in both file or in a specific one
        Switch ($inputFrom.SideIndicator) {
            "==" {
                # Present in both
                $WKtotal++
                # Is the translation the same?
                if (($oldWK | Where-Object { $_.TranslateFrom -eq $inputFrom.InputObject}).TranslateTo -eq ($newWK | Where-Object { $_.TranslateFrom -eq $inputFrom.InputObject}).TranslateTo) {
                    $ChangeLog += "No change|$($inputFrom.InputObject)|$(($newWK | Where-Object { $_.TranslateFrom -eq $inputFrom.InputObject }).TranslateTo)"
                    $WKsame++
                }
                Else {
                    $ChangeLog += "Translation updated|$($inputFrom.InputObject)|$(($newWK | Where-Object { $_.TranslateFrom -eq $inputFrom.InputObject }).TranslateTo)"
                    $WKupdate++
                }
            }

            "=>" {
                #Present in new only
                $ChangeLog += "Added|$($inputFrom.InputObject)|$(($newWK | Where-Object { $_.TranslateFrom -eq $inputFrom.InputObject }).TranslateTo)"
                $WKnew++
                $WKtotal++
            }

            "<=" {
                # Present in old only
                $ChangeLog += "Removed|$($inputFrom.InputObject)|$(($oldWK | Where-Object { $_.TranslateFrom -eq $inputFrom.InputObject }).TranslateTo)"
                $WKold++
            }
        }
    }
    $ChangeLog += '  '    
    #endRegion WellKnonwnID

    #region .. Keyword
    $ChangeLog += @("### Keyword  ", " ","Status|LongName|ShortenName  ","---|---|---  ")

    $KWnew     = 0
    $KWsame    = 0
    $KWupdate  = 0
    $KWold     = 0
    $KWtotal   = 0

    foreach ($inputFrom in (compare-object $oldKW.LongName $newKW.LongName -IncludeEqual)) {
        # Check if exist in both file or in a specific one
        Switch ($inputFrom.SideIndicator) {
            "==" {
                # Present in both
                $KWtotal++
                # Is the translation the same?
                if (($oldKW | Where-Object { $_.LongName -eq $inputFrom.InputObject}).ShortenName -eq ($newKW | Where-Object { $_.LongName -eq $inputFrom.InputObject}).ShortenName) {
                    $ChangeLog += "No change|$($inputFrom.InputObject)|$(($newKW | Where-Object { $_.LongName -eq $inputFrom.InputObject }).ShortenName)"
                    $KWsame++
                }
                Else {
                    $ChangeLog += "Translation updated|$($inputFrom.InputObject)|$(($newKW | Where-Object { $_.LongName -eq $inputFrom.InputObject }).ShortenName)"
                    $KWupdate++
                }
            }

            "=>" {
                #Present in new only
                $ChangeLog += "Added|$($inputFrom.InputObject)|$(($newKW | Where-Object { $_.LongName -eq $inputFrom.InputObject }).ShortenName)"
                $KWnew++
                $KWtotal++
            }

            "<=" {
                # Present in old only
                $ChangeLog += "Removed|$($inputFrom.InputObject)|$(($oldWK | Where-Object { $_.LongName -eq $inputFrom.InputObject }).ShortenName)"
                $KWold++
            }
        }
    }
    $ChangeLog += '  '
    #endRegion Keyword

    #region .. Finally
    $ChangeLog | out-file ..\..\Documentations\Changelog\Detail-translation.md -Encoding UTF8 -Force
    $ResumeTxt = "There is a total of $($WKtotal) WellKnownID in this new edition. In this update"
    Switch ($WKsame) {
        { $_ -eq 0 } { $ResumeTxt += " none from the previous edition were kept" }
        { $_ -eq 1 } { $ResumeTxt += " $($WKsame) is unchanged" }
        { $_ -gt 1 } { $ResumeTxt += " $($WKsame) are unchanged" }
    }
    if ($WKupdate -ge 1) {
        $ResumeTxt += ", $($WKupdate) have its translation changed"
    }
    if ($WKnew -ge 1) {
        $ResumeTxt += ", $($WKnew) have been added"
    }
    Switch ($WKold) {
        { $_ -eq 0 } { $ResumeTxt += " and none were removed." }
        { $_ -eq 1 } { $ResumeTxt += " and $($WKold) was removed." }
        { $_ -gt 1 } { $ResumeTxt += " and $($WKold) were removed." }
    }
    $ResumeTxt += " There is also a total of $($KWtotal) Keywords in this new edition:"
    Switch ($KWsame) {
        { $_ -eq 0 } { $ResumeTxt += " none from the previous edition were kept" }
        { $_ -eq 1 } { $ResumeTxt += " $($KWsame) is unchanged" }
        { $_ -gt 1 } { $ResumeTxt += " $($KWsame) are unchanged" }
    }
    if ($KWupdate -ge 1) {
        $ResumeTxt += ", $($KWupdate) have its translation changed"
    }
    if ($KWnew -ge 1) {
        $ResumeTxt += ", $($KWnew) have been added"
    }
    Switch ($KWold) {
        { $_ -eq 0 } { $ResumeTxt += " and none were removed.  " }
        { $_ -eq 1 } { $ResumeTxt += " and $($KWold) was removed.  " }
        { $_ -gt 1 } { $ResumeTxt += " and $($KWold) were removed.  " }
    }
    $ResumeLog += @($ResumeTxt,'  ','Details can be reviewed in [_Detail-Translation.md_](/Documentations/Changelog/Detail-translation.md).')
    return $ResumeLog
    #endRegion Finally
}
