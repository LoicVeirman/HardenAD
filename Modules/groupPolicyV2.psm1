##################################################################
## Convert-MigrationTable                                       ##
## ----------------------                                       ##
## This function will prepare the migration table file for GPO  ##
## import                                                       ##
##                                                              ##
## Version: 02.00.000                                           ##
##  Author: contact@hardenad.net                                ##
##################################################################
Function Convert-MigrationTable
{
    <#
        .SYNPOSIS
            This function will replace the specified name in a .migTable file to the target one.

        .DETAILS
            GPO imported from a dev domain will contains unknown principals. To remediate this when restoring parameters,
            this function search on %objectName% and replace it with the corresponding SID in the target domain.
            The function will write the date to a new file called "translated.migtable".

            Note: when the script detects that the file "translated.migtable" is present, it will firstly delete it.

            Note: this release is no more compliant with windows server 2008 R2 and younger systems.

        .PARAMETER GpoName
            GPO to be translated.

        .NOTES
            Version: 02.00
            Author.: contact@hardenad.net  - MSSEC
            Desc...: Function rewrite. Logging are no more used to ease the script analysis.
    #>

    Param(
        [Parameter(mandatory=$true)]
        [String]
        $GpoName
    )

    #.Testing if the GPO files are reachable and if a translated file already exist and should be deleted first.
    $gpoPath = ".\Inputs\GroupPolicies\" + $GpoName

    if (Test-Path $gpoPath)
    {
        if (Test-Path ($gpoPath + "\translated.migtable"))
        {
            Remove-Item ($gpoPath + "\translated.migtable") -Force
            #.Double check for deletion
            Start-Sleep -Milliseconds 10
            if (Test-Path ($gpoPath + "\translated.migtable"))
            {
                #.Deletion KO
                $resultCode = $false
                $resultat = 1
            } Else {
                #.Deletion OK
                $resultCode = $true
                $resultat = 0
            }
        } Else {
            #.No prerun file
            $resultCode = $true
            $resultat = 0
        }
        #.Ensuring a migtable file is present
        if (-not(Test-Path ($gpoPath + "\hardenad.migtable")))
        {
            #.Not needed.
            $resultCode = $false
            $resultat = 0
        }
    } else {
        #.Data missing
        $resultCode = $false
        $resultat = 2
    }

    #.Once we have checked the GPO exists and there is no leaving trace of a previous run, we can start the translation.
    #.The whole translation process will refer to the TasksSequence.xml file to match a source ID to its target: a target is refered 
    #.as a variable stored as %xxxx% - this is the value you should find in the translation.XML file. 
    if ($resultCode)
    {
        #.Opening the migtable file to a XML variable - if failed, the function stop.
        $xmlData = Get-Content ($gpoPath + "\hardenad.migtable") -ErrorAction Stop

        #.Opening the xml data from the tasks sequence for translation then filtering to the needed data
        $xmlRefs = ([xml](Get-Content .\Configs\TasksSequence_HardenAD.xml -ErrorAction Stop)).Settings.Translation.wellKnownID
        $xmlObjs = ([xml](Get-Content $gpoPath\translation.xml -ErrorAction Stop)).translation.migTable.replace

        #.Translating migration table
        foreach ($obj in $xmlObjs) {
            $newDestination = $obj.NewDestination
            #.Checking if referal is requiered
            if ($NewDestination -match "%*%")
            {
                #. Referal requested, we will replace every occurence to its new value.
                foreach ($ref in $xmlRefs)
                {
                    $newDestination = $newDestination -replace $ref.translateFrom,$ref.TranslateTo
                }
            }

            #.Translating
            switch ($obj.Type)
            {
                "User"           { 
                                    Try { 
                                            $xmlData = $xmlData -replace $obj.Destination,(Get-AdUser $NewDestination -ErrorAction stop).SID 
                                    } Catch {
                                        #.No replace
                                    }
                                 }
                "Computer"       { 
                                    Try {
                                            $xmlData = $xmlData -replace $obj.Destination,(Get-AdComputer $NewDestination -ErrorAction stop).SID 
                                    } Catch {
                                        #.No replace
                                    }
                                 }
                "LocalGroup"     { 
                                    Try {
                                            $xmlData = $xmlData -replace $obj.Destination,(Get-AdGroup $NewDestination -ErrorAction stop).SID 
                                    } Catch {
                                        #.No replace
                                    }
                                 }
                "GlobalGroup"    { 
                                    Try {
                                            $xmlData = $xmlData -replace $obj.Destination,(Get-AdGroup $NewDestination -ErrorAction stop).SID 
                                    } Catch {
                                        #.Noreplace
                                    }
                                 }
                "UniversalGroup" { 
                                    Try {
                                            $xmlData = $xmlData -replace $obj.Destination,(Get-AdGroup $NewDestination).SID 
                                    } Catch {
                                        #.No replace
                                    }
                                 }
                "UNCPath"        { $xmlData = $xmlData -replace $obj.Destination,$newDestination }
                "Unknown"        { $xmlData = $xmlData -replace $obj.Destination,$NewDestination }
            }
        }

        #.Once all objets in XML translation are parsed, we can save the new migration file
        $null = $xmlData | Out-File ($gpoPath + "\translated.migtable") -Force 
    }

    ## Return translated xml
    return (New-Object -TypeName psobject -Property @{ ResultCode = $resultat ; ResultMesg = "" ; TaskExeLog = "" })
}

##################################################################
## Convert-GpoPreferencesXml                                    ##
## -------------------------                                    ##
## This function will prepare the preferences.xml file for GPO  ##
## import                                                       ##
##                                                              ##
## Version: 02.00.000                                           ##
##  Author: contact@hardenad.net                                ##
##################################################################
Function Convert-GpoPreferencesXml
{
    <#
        .SYNPOSIS
        This function will replace the specified target in a preferences.xml file to the target one.

        .DETAILS
        GPO imported from a dev domain will contains unknown principals. To remediate this when restoring parameters,
        this function search on %objectName% and replace it with the corresponding SID in the target domain.
        The function will write the date to the same new file called and provide a backup at ir first run (preferences.xml.backup).

        Note: this release is no more compliant with windows server 2008 R2 and younger systems.

        .PARAMETER GpoName
        GPO to be translated.

        .NOTES
        Version: 02.00
        Author.: contact@hardenad.net  - MSSEC
        Desc...: Function rewrite. Logging are no more used to ease the script analysis.
    #>
    Param(
        [Parameter(mandatory=$true)]
        [String]
        $GpoName
    )
}

Export-ModuleMember -Function * 