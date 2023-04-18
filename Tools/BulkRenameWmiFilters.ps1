$WmiCsv = Import-Csv "C:\Users\quentin.mallet\Documents\_MyRessources\_Temp\WmiCsv.csv" -Delimiter ";"
$TaskSequence = Get-Content 'C:\Users\quentin.mallet\Documents\_MyRessources\00 - Repos\SecureAD\Configs\TasksSequence_HardenAD.xml'

$WmiFolder = 'C:\Users\quentin.mallet\Documents\_MyRessources\00 - Repos\SecureAD\Inputs\GroupPolicies\WmiFilters'

foreach($line in $WmiCsv) {
    $OldName = $Line.Name
    $NewName = $line.'Concat(Name)'

    $FilterPath = Join-Path $WmiFolder "$($OldName).mof"
    $WmiFilter = Get-Item $FilterPath

    # Change every .mof file's content with the new name
    $MOFFile = Get-Content $WmiFilter.FullName
    $NewMofFile = $MOFFile -replace $WmiFilter.BaseName, $NewName

    $NewMofFile | Out-File $WmiFilter.FullName -Force

    # Change all old name's iterations in tasksequence file
    $TaskSequence = $TaskSequence -replace $WmiFilter.BaseName, $NewName
    # Rename all .mof file

    Rename-Item $WmiFilter.FullName -NewName $NewName
}

$TaskSequence | Out-File 'C:\Users\quentin.mallet\Documents\_MyRessources\00 - Repos\SecureAD\Configs\TasksSequence_HardenAD.xml' -Encoding utf8 -Force