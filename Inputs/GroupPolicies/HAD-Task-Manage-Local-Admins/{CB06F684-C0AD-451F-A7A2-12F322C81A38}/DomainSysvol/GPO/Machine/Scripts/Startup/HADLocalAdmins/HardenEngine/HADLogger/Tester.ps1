using module ".\HADLogger.psm1"
using module ".\HADEventViewer.psm1"
using module ".\HADWriteHost.psm1"
using module ".\HADLogFile.psm1"


$log = [HADWriteHost]::new()

$log.Info("Hello world")
$log.Success("Hello world")
$log.Warning("Hello world")
$log.Debug("Hello world")
$log.Error("Hello world")

$LogFile = [HADLogFile]::new("C:\Users\qmallet_T0.OZ\Documents\HADLogger\Tester.log")

$LogFile.Info("Hello world")
$LogFile.Success("Hello world")
$LogFile.Warning("Hello world")
$LogFile.Debug("Hello world")
$LogFile.Error("Hello world")

$EventVwr = [HADEventViewer]::new("Test", "HADTester")

$EventVwr.Info("Hello world")
$EventVwr.Success("Hello world")
$EventVwr.Warning("Hello world")
$EventVwr.Debug("Hello world")
$EventVwr.Error("Hello world")