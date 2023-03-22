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
	$xmlRefs = ([xml](Get-Content .\Configs\TasksSequence_HardenAD.xml -ErrorAction Stop)).Settings.Translation.wellKnownID | Where-Object { $_.ObjectClass -eq "group" }
}
catch {
	$errCde++
}
$GroupsToFlush = @(
	"%t0-localAdmin-servers%"
	"%t1-localAdmin-servers%"
	"%t1l-localAdmin-servers%"
	"%t0-localAdmin-workstations%"
	"%t2-localAdmin-workstations%"
	"%t2l-localAdmin-workstations%"
)

$Log += (Get-Date -UFormat "%Y-%m-%d %T ") + "Import groups data: found " + $GroupsToFlush.count + " group(s) to flush"

foreach ($refs in $xmlRefs) {
	if ($refs.translateFrom -in $GroupsToFlush) {

		$Log += (Get-Date -UFormat "%Y-%m-%d %T ") + "Flushing group " + $refs.translateTo + ": begin"

		try {
			Set-ADGroup -Identity $refs.translateTo	-Clear member
			$Log += (Get-Date -UFormat "%Y-%m-%d %T ") + "Flushing group " + $refs.translateTo + ": success"
		}
		catch {
			$Log += (Get-Date -UFormat "%Y-%m-%d %T ") + "Flushing group " + $refs.translateTo + ": failed!"
			$errCde++
		}

		$GroupsToFlushTranslated += $refs.translateTo
	}
}

$Log += (Get-Date -UFormat "%Y-%m-%d %T ") + "--> Group(s) flushing is over"
$Log += (Get-Date -UFormat "%Y-%m-%d %T ") + "--> The process has failed for $errCde over " + $GroupsToFlush.count
$Log += (Get-Date -UFormat "%Y-%m-%d %T ") + "--> exporting log file to MCS-GroupsFlushing.log"
$Log += (Get-Date -UFormat "%Y-%m-%d %T ") + "*** SCRIPT FINISH"
$Log += (Get-Date -UFormat "%Y-%m-%d %T ") + "***"
$log | out-file .\MCS-GroupsFlushing.log -append