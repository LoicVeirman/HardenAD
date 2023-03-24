<# .Synopsis
	This script flush all members of the specified group present in the csv file.

   .Details
    This script flush all members of the specified group present in MCS-GroupsFlushing.csv file.

   .Note
    Version 01.00
	Author  contact@hardenad.net 
#>

Param()

$Log = @()

$Log += (Get-Date -UFormat "%Y-%m-%d %T ") + "****"
$Log += (Get-Date -UFormat "%Y-%m-%d %T ") + "**** SCRIPT STARTS"
$Log += (Get-Date -UFormat "%Y-%m-%d %T ") + "****"

$errCde = 0

try {
    $xmlConfig = ([xml](Get-Content "$PSScriptRoot\Config\Config.xml")).Config.Group
}
catch {
    $errCde++
}

$Log += (Get-Date -UFormat "%Y-%m-%d %T ") + "Import groups data: found " + $xmlConfig + " group(s) to flush"

foreach ($Group in $xmlConfig) {
    $Log += (Get-Date -UFormat "%Y-%m-%d %T ") + "Flushing group " + $Group.Name + ": begin"

    try {
        $VerifiedGroup = Get-ADGroup -Identity $Group.Name
    }
    catch {
        $errCde++
    }
    try {
        Set-ADGroup -Identity $VerifiedGroup.DistinguishedName -Clear member
        $Log += (Get-Date -UFormat "%Y-%m-%d %T ") + "Flushing group " + $Group.Name + ": success"
    }
    catch {
        $Log += (Get-Date -UFormat "%Y-%m-%d %T ") + "Flushing group " + $Group.Name + ": failed!"
        $errCde++
    }
}


$Log += (Get-Date -UFormat "%Y-%m-%d %T ") + "--> Group(s) flushing is over"
$Log += (Get-Date -UFormat "%Y-%m-%d %T ") + "--> The process has failed for $errCde over " + $xmlConfig
$Log += (Get-Date -UFormat "%Y-%m-%d %T ") + "--> exporting log file to MCS-GroupsFlushing.log"
$Log += (Get-Date -UFormat "%Y-%m-%d %T ") + "*** SCRIPT FINISH"
$Log += (Get-Date -UFormat "%Y-%m-%d %T ") + "***"
$Log | Out-File $PSScriptRoot\Logs\MCS-GroupsFlushing.log -append