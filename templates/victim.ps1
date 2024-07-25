Copy-Item C:\vagrant\data\$beacon_file ~\Documents\
Start-Process ~\Documents\$beacon_file -WindowStyle Hidden
Write-Output "Beacon started!"
