# Cloud-VM-Tool
Cloud VM initialising tool.



START HERE:
```
[Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls" 
$ScriptWebArchive = "https://github.com/theo-technologies/cloud-vm-tool/archive/master.zip"  
$LocalArchivePath = "$ENV:UserProfile\Downloads\Cloud-Vm-Tool"  
(New-Object System.Net.WebClient).DownloadFile($ScriptWebArchive, "$LocalArchivePath.zip")  
Expand-Archive "$LocalArchivePath.zip" -DestinationPath $LocalArchivePath -Force  
CD $LocalArchivePath\Cloud-VM-Tool-master\ | powershell.exe .\Loader.ps1
```

