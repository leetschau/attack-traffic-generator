$beacon_file = $args[0]
Copy-Item C:\vagrant\$beacon_file ~\Documents\
Start-Process ~\Documents\$beacon_file -WindowStyle Hidden
Write-Output "$beacon_file started!"
