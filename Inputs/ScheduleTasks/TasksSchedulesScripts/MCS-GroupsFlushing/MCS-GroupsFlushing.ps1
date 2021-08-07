<# .Synopsis
	This script flush all members of the specified group present in the csv file.

   .Details
    This script flush all members of the specified group present in MCS-GroupsFlushing.csv file.

   .Note
    Version 01.00
	Author  loic.veirman@mssec.fr
#>

Param()

$Log = @()

$Log += (Get-Date -UFormat "%Y-%m-%d %T ") + "****"
$Log += (Get-Date -UFormat "%Y-%m-%d %T ") + "**** SCRIPT STARTS"
$Log += (Get-Date -UFormat "%Y-%m-%d %T ") + "****"

$groups = import-csv .\MCS-GroupsFlushing.csv
$errCde = 0

$Log += (Get-Date -UFormat "%Y-%m-%d %T ") + "Import groups data: found " + $groups.count + " group(s) to flush"

foreach ($group in $groups)
{
	$Log += (Get-Date -UFormat "%Y-%m-%d %T ") + "Flushing group " + $group.sAMAccountName + ": begin"
	
	Try { 
		Set-ADGroup -Identity $group.sAMAccountName	-clear member
		$Log += (Get-Date -UFormat "%Y-%m-%d %T ") + "Flushing group " + $group.sAMAccountName + ": success"
	} 
	Catch {
		$Log += (Get-Date -UFormat "%Y-%m-%d %T ") + "Flushing group " + $group.sAMAccountName + ": failed!"
		$errCde++
	}
}

$Log += (Get-Date -UFormat "%Y-%m-%d %T ") + "--> Group(s) flushing is over"
$Log += (Get-Date -UFormat "%Y-%m-%d %T ") + "--> The process has failed for $errCde over " + $groups.count
$Log += (Get-Date -UFormat "%Y-%m-%d %T ") + "--> exporting log file to MCS-GroupsFlushing.log"
$Log += (Get-Date -UFormat "%Y-%m-%d %T ") + "*** SCRIPT FINISH"
$Log += (Get-Date -UFormat "%Y-%m-%d %T ") + "***"
$log | out-file .\MCS-GroupsFlushing.log -append