$host.ui.RawUI.WindowTitle = “AuditSmbSession”
$data = @([pscustomobject]@{ID=$Null;ClientComputerName=$Null;ClientUserName=$Null;Dialect=$Null})
$hostname = hostname
$path_file = $($($myInvocation.InvocationName).Replace($($myInvocation.MyCommand),''))
$datafile_session = "$path_file$($hostname)_Get-SmbSession.csv"
$datafile_connection = "$path_file$($hostname)_Get-SmbConnection.csv"
$logfile = "$path_file$($hostname)_Get-SmbSession.log"

#Initiate titles in $datafile
"Server;ID;ClientComputerName;ClientUserName;Dialect" | Out-File -FilePath $datafile_session -Append -Encoding UTF8
"ServerName;ID;ShareName;UserName;Credential;Dialect" | Out-File -FilePath $datafile_connection -Append -Encoding UTF8

while(1){
    $Error.Clear()
    try{
    	$sessions = Get-SmbSession | Select-Object -Property ClientComputerName, ClientUserName, Dialect | Where-Object {$_.Dialect -like "1.*"}
    }catch{
	    "Failed to execute Get-SmbSession : $($Error[0].Exception.Message)" | Out-File -FilePath $logfile -Append -Encoding UTF8
    }
    foreach($session in $sessions){
        $d = Get-Date -Format "MM/dd/yyyy-HH:mm"
        $id = "$($session.ClientComputerName),$($session.ClientUserName)"
        if($data.ID -notcontains $id){
            $data += @([pscustomobject]@{ID=$id;ClientComputerName=$($session.ClientComputerName);ClientUserName=$($session.ClientUserName);Dialect=$($session.Dialect)})
            "$($hostname);$($id);$($session.ClientComputerName);$($session.ClientUserName);$($session.Dialect)" | Out-File -FilePath $datafile_session -Append -Encoding UTF8
        }
    }
    $Error.Clear()
    try{
    	$conns = Get-SmbConnection | Where-Object {$_.Dialect -like "1.*"}
    }catch{
	    "Failed to execute Get-SmbConnection : $($Error[0].Exception.Message)" | Out-File -FilePath $logfile -Append -Encoding UTF8
    }
    foreach($conn in $conns){
        $d = Get-Date -Format "MM/dd/yyyy-HH:mm"
        $id = "$($conn.ServerName),$($conn.ShareName),$($conn.UserName),$($conn.Credential)"
        if($data.ID -notcontains $id){
            $data += @([pscustomobject]@{ID=$id;ClientComputerName=$($conn.ClientComputerName);ClientUserName=$($conn.ClientUserName);Dialect=$($conn.Dialect)})
            "$($conn.ServerName);$($id);$($conn.ShareName),$($conn.UserName),$($conn.Credential);$($conn.Dialect)" | Out-File -FilePath $datafile_connection -Append -Encoding UTF8
        }
    }
    sleep 1
}