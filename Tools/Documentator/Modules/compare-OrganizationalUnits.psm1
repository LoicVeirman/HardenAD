Function compare-OrganizationalUnits {
    <#
        .SYNOPSIS
        Compare two edition of had, section organizational unit

        .PARAMETER OldXml
        The xml data to compare with.

        .PARAMETER NewXml
        The xml data from the new release.

        .NOTES 
        Version 1.0.0
        Author  Loic VEIRMAN MSSEC
    #>
    Param(
        [parameter(Mandatory,Position=0)]
        $OldXml,

        [parameter(Mandatory,Position=1)]
        $NewXml
    )
    #region .. Functions
    function ouTreechecker {
        Param ($Parent, $rawData, $type, $extraData)
        # Log collector
        $myChange = @()
        # Use Case manager
        Switch ($type) {
            "both" {            
                # if equal, we need to check if description is the same
                if ($rawData.description -eq $extraData.Description) {
                    $myChange += "$($parent) ; $($rawData.Name)|No Change  "
                }
                Else {
                    $Global:OUchanged = $true
                    $myChange += "$($parent) ; $($rawData.Name)|New description: $($extraData.Description)  "
                }
                # checking for childs
                if ($rawData.ChildOU) {
                    foreach ($subnode in (Compare-Object $rawData.ChildOU.Name $extraData.ChildOU.Name -IncludeEqual)) {
                        Switch ($subnode.sideIndicator) {
                            "==" {
                                $myChange += ouTreechecker "$($parent) ; $($rawData.Name)" ($rawData.ChildOU | Where-Object { $_.Name -eq $subnode.InputObject }) both ($extraData.ChildOU | Where-Object { $_.Name -eq $subnode.InputObject })
                            }

                            "<=" {
                                $Global:OUchanged = $true
                                $myChange += ouTreechecker "$($parent) ; $($rawData.Name)" ($rawData.ChildOU | Where-Object { $_.Name -eq $subnode.InputObject }) oldOnly
                            }

                            "=>" {
                                $Global:OUchanged = $true
                                $myChange += ouTreechecker "$($parent) ; $($rawData.Name)" ($extraData.ChildOU | Where-Object { $_.Name -eq $subnode.InputObject }) newOnly
                            }
                        }
                    }
                }
            }

            "oldOnly" {
                $Global:OUchanged = $true
                $myChange += "$($parent) ; $($rawData.Name)|OU removed  "
                foreach ($subnode in $rawData.ChildOU) {
                    $myChange += ouTreechecker "$($parent) ; $($rawData.Name)" ($rawData.ChildOU | Where-Object { $_.Name -eq $subnode.Name}) oldOnly
                }
            }

            "NewOnly" {
                $Global:OUchanged = $true
                $myChange += "$($parent) ; $($rawData.Name)|OU added  "
                foreach ($subnode in $rawData.ChildOU) {
                    $myChange += ouTreechecker "$($parent) ; $($rawData.Name)" ($rawData.ChildOU | Where-Object { $_.Name -eq $subnode.Name}) newOnly
                }
            }
        }
        return $myChange
    }
    #endRegion Functions

    #region .. Welcome
    # A tag
    $Global:OUchanged = $flase
    # Prepare collect data (md form)
    $ChangeLog = @(
        "# CHANGE LOG: OrganizationalUnits  "
        "Below information details all changes in TasksSequence_HardenAD.xml/OrganizationalUnits done in this edition.  "
        " "
        "---  "
    )
    $ResumeLog = @(
        "### OrganizationalUnits  "
        ' '
    )
    #endRegion Welcome

    #region .. OU Class
    # Checking OU class 
    $oldOUclass = Select-Xml $oldXML -XPath "//Settings/OrganizationalUnits/ouTree/OU" | Select-Object -ExpandProperty Node
    $newOUClass = Select-Xml $newXML -XPath "//*/OU" | Select-Object -ExpandProperty Node

    # 0. Update Change log heading
    $ChangeLog += "### Class List "
    $ChangeLog += "Class|Status  "
    $ChangeLog += "---|---  "
    $flagNoChange = 0
    $flagAddition = 0
    $flagIsRemove = 0

    # 1. Any new, removed or same classes?
    $comparison = Compare-Object $oldOUclass.Class $newOUClass.Class -IncludeEqual
    foreach ($class in $Comparison) {
        # Checking indicator sign
        Switch ($class.SideIndicator) {
            "==" {
                $ChangeLog += "$($class.InputObject)|remains present  "
                $flagNoChange++
            }
            "<=" {
                $ChangeLog += "$($class.InputObject)|added to this edition  "
                $flagAddition++
            }
            "=>" {
                $ChangeLog += "$($class.InputObject)|removed from this edition  "
                $flagIsRemove++
            }
        }
    }
    $ResumeLog += "The previous edition contained $($comparison.count) Class: $($flagNoChange) were kept, $($flagIsRemove) $(if ($flagIsRemove -eq 1) { "was"} else { "were"}) removed and $($flagAddition) $(if ($flagAddition -eq 1) { "was"} else { "were"}) added."

    # 2. Checking if each unchanged class have the same name and description
    $ChangeLog += @(
        "### Class details  "
        "Prexisting Class|Name as changed?|Description as changed?  "
        "---|---|---  "
    )
    $flagNewName = 0
    $flagNewDesc = 0
    foreach ($class in ($comparison | Where-Object { $_.SideIndicator -eq '=='})) {
        $ClassID = $class.InputObject
        $OldData = $oldXML.Settings.OrganizationalUnits.ouTree.OU | Where-Object { $_.Class -eq $ClassID }
        $NewData = $newXML.Settings.OrganizationalUnits.ouTree.OU | Where-Object { $_.Class -eq $ClassID }
        if ($OldData.Name -eq $NewData.Name) {
            $NameTxt = "No."
        } 
        Else {
            $NameTxt = "New name:</BR>*$($NewData.Name)*"
            $flagNewName++
        }
        if ($OldData.Description -eq $NewData.Description) {
            $DescTxt = "No."
        } 
        Elseif ($OldData.Name -eq $NewData.Name) {
            $DescTxt = "new Description:</BR>*$($NewData.Description)*"
            $flagNewDesc++
        }
        Else {
            $DescTxt = "N/A"
        }
        $ChangeLog += "$($ClassID)|$($NameTxt)|$($DescTxt)"
    }
    $ResumeLog += "There were $($flagNewName) Class renamed and $($flagNewDesc) Class with an updated description."
    #endRegion OU Class

    #region .. OU Tree
    # 3. Comparing OU tree with child nodes...
    $ChangeLog += @(
        "### OU Tree details   "
        "This section list each OU content with OU change.  "
        " "
    )
    foreach ($class in $comparison) {
        $ChangeLog += @(
            "**#$($Class.InputObject)**"
            "OU Path|Status"
            "---|---"
        )
        $oldOUclassFilter = $oldXML.Settings.OrganizationalUnits.ouTree.OU | Where-Object { $_.Class -eq $class.InputObject }
        $newOUclassFilter = $newXML.Settings.OrganizationalUnits.ouTree.OU | Where-Object { $_.Class -eq $class.InputObject }
        if ($class.SideIndicator -eq "==") {
            # The class is present on both side
            foreach ($subnode in (Compare-Object $oldOUclassFilter.ChildOU.Name $newOUclassFilter.ChildOU.Name -IncludeEqual)) {
                Switch ($subnode.sideIndicator) {
                    "==" {
                        $ChangeLog += ouTreechecker $class.InputObject ($oldOUclassFilter.ChildOU | Where-Object { $_.Name -eq $subnode.InputObject }) both ($newOUclassFilter.ChildOU | Where-Object { $_.Name -eq $subnode.InputObject })
                    }

                    "<=" {
                        $ChangeLog += ouTreechecker $class.InputObject ($oldOUclassFilter.ChildOU | Where-Object { $_.Name -eq $subnode.InputObject }) oldOnly
                    }

                    "=>" {
                        $ChangeLog += ouTreechecker $class.InputObject ($newOUclassFilter.ChildOU | Where-Object { $_.Name -eq $subnode.InputObject }) newOnly
                    }
                }
            }
        }
        if ($class.SideIndicator -eq "<=") {
            # The class is present on old side only
            foreach ($subnode in $oldOUclassFilter.ChildOU.Name) {
                $ChangeLog += ouTreechecker $class.InputObject ($oldOUclassFilter.ChildOU | Where-Object { $_.Name -eq $subnode.InputObject }) oldOnly
            }
        }
        if ($class.SideIndicator -eq "=>") {
            # The class is present on new side only
            foreach ($subnode in $newOUclassFilter.ChildOU.Name) {
                $ChangeLog += ouTreechecker $class.InputObject ($newOUclassFilter.ChildOU | Where-Object { $_.Name -eq $subnode.InputObject }) newOnly          
            }
        }
        $ChangeLog += "  "
    }
    if ($Global:OUchanged) {
        $ResumeLog += "The architecture of the organizational units contains some change.  "
    }
    Else {
        $ResumeLog += "There was no change to the default OU tree design."
    }
    $ResumeLog += @('  ','Details can be reviewed in [*Details-OrganizationalUnits.md*](/Documentations/Changelog/Detail-OrganizationalUnits.md).')
    #endRegion OU Tree
    
    # outing log details
    $ChangeLog | out-file ..\..\Documentations\ChangeLog\Detail-OrganizationalUnits.md -Encoding UTF8 -Force
    
    return $ResumeLog
}
