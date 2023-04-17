@echo off
timeout /t 30
powershell.exe -File "C:\Windows\HardenAD\Bitlocker\setBitLocker.ps1" -ExecutionPolicy Bypass -WindowStyle Hidden
