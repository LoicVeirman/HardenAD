# This module file merge all functions linked.

Function Test-Script2 ($params)
{
    #.Simulate parameters translation
	$message1=$params[0]
	$message2=$params[1]

	#.Simulate code exec
	Start-Sleep -Seconds 2

	#.Simulate a return code
	$result = Get-Random -Minimum 0 -Maximum 101

	#.Simulate a return message
	if ($result -le 33)        { $msg = "It's a success! - $message1 - $message2" ; $resultCode = 0 }
	if ($result -gt 33 -le 66) { $msg = "Warning: woops? - $message1 - $message2" ; $resultCode = 1 }
	if ($result -gt 67)        { $msg = "It's a Failure! - $message1 - $message2" ; $resultCode = 2 }

	#.Return data
	return (New-Object -TypeName psobject -Property @{ResultCode = $resultCode ; ResultMesg = $msg ; TaskExeLog = "test B"})
}

Export-ModuleMember -Function *