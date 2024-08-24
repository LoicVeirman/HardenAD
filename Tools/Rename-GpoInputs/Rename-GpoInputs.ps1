Param(
    [Parameter(Mandatory)]
    [Object[]]
    $GpoOldName,

    [Parameter(Mandatory)]
    [Object[]]
    $GpoNewName
)

$xmlConfig = [xml](Get-content ../../Configs/TasksSequence_HardenAD.xml -Encoding utf8)
$dirConfig = Get-ChildItem ../../INputs/GroupPolicies -Directory -Filter "HAD-*"

if ($GpoOldName.count -eq $GpoNewName.Count)
{
    for ($index = 0 ; $index -lt $GpoOldName.count ; $index++) 
    {    
        Write-Host "`n-= $($GpoOldName[$index]) =-" -ForegroundColor Cyan
        try {
            $xmlData = Select-Xml $xmlConfig -XPath "//GPO[@Name='$($GpoOldName[$index])']" | Select-Object -ExpandProperty Node
            $xmlData.Name = $GpoNewName[$index]
            $xmlConfig.Save($(Convert-Path ../../Configs/TasksSequence_HardenAD.xml))

            Write-Host "   [SUCCESS] " -NoNewline -ForegroundColor Green
            Write-Host "XML updated from '$($GpoOldName[$index])' to '$($GpoNewName[$index])" -ForegroundColor Gray
            
            $dirData = $dirConfig | Where-Object { $_.Name -eq $GpoOldName[$index] }
            Rename-Item -Path $dirData.FullName -NewName $GpoNewName[$index]                
            
            Write-Host "   [SUCCESS] " -NoNewline -ForegroundColor Green
            Write-Host "DIR updated from '$($GpoOldName[$index])' to '$($GpoNewName[$index])" -ForegroundColor Gray
        }
        catch {
            Write-Host "   [ Error ] " -NoNewline -ForegroundColor Red
            Write-Host $_.ToString() -ForegroundColor Yellow 
        }
    }
} 
Else 
{
    write-host 'Error: count differs between old and new names.' -ForegroundColor Red
}
