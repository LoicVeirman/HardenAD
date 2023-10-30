function Compare-DiskToLogical {

    $Log = [LogMessage]::NewLogs()

    try {
        $Partitions = Get-CimInstance Win32_DiskPartition
        $Log.Success("All Partition have been collected.")
    }
    catch {
        $Log.Fatal(("An error occured while collecting partitions: {0}." -f $_.Exception.Message))
    }    
    try {
        $PhysicalDisks = Get-PhysicalDisk
        $Log.Success("All physical disks have been collected.")
    }
    catch {
        $Log.Fatal(("An error occured while collecting physical disks: {0}." -f $_.Exception.Message))
    }
    
    $Global:Array = @()
    
    foreach ($Partition in $Partitions) {
        try {
            $Corresp = Get-CimInstance -Query "ASSOCIATORS OF `
            {Win32_DiskPartition.DeviceID='$($Partition.DeviceID)'} `
            WHERE AssocClass=Win32_LogicalDiskToPartition"
            $Log.Success(("{0} has been associated to a physical disk." -f $Partition.DeviceID))
        }
        catch {
            $Log.Fatal(("Unable to associate partition {0} to a physical disk: {1}." -f $Partition.DeviceID, $_.Exception.Message))
        }
        $Regex = $Partition.Name -match "(\d+)"
        $PhysicalDiskNr = $Matches[0]
    
        foreach ($C in $Corresp) {
            $Type = ($PhysicalDisks | Where-Object { $_.DeviceID -eq $PhysicalDiskNr }).BusType
            $Global:Array += [PSCustomObject]@{
                DriveLetter = $C.DeviceID
                BusType     = $Type
            }

            $Log.Info(("{0} is detected as {1} device." -f $C.DeviceID, $Type))
        }
    }
}
