# This module file merge all functions required by the script at any stage.

Function Test-Script ($message1,$message2)
{
	#.Simulate code exec
	Start-Sleep -Seconds 1

	#.Simulate a return code
	$result = Get-Random -Minimum 0 -Maximum 101

	#.Simulate a return message
	if ($result -le 33)        { $msg = "It's a success!" ; $resultCode = 0 }
	if ($result -gt 33 -le 66) { $msg = "Warning: woops?" ; $resultCode = 1 }
	if ($result -gt 66)        { $msg = "It's a Failure!" ; $resultCode = 2 }

	#.Return data
	return (New-Object -TypeName psobject -Property @{ResultCode = $resultCode ; ResultMesg = $msg ; TaskExeLog = "test A"})
}

Export-ModuleMember -Function *