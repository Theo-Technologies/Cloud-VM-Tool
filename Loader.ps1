cls
 Write-Host -foregroundcolor red "

                                                          :7777777777777777777777777777777~                                                              
                                                         .B@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@~                                                              
                                                        P@&&&@@@@@@@@@@@@@@@@@@@@@@@@@@@!                                                               
                           ~GGGGGGGGGGGGGGGGGGGGGGGGGGGG###5B@@@@@@@@@@@@@@@@@@@@@@@@@@7                                                                
                          :#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@BG@@@@@@@@@@@@@@@@@@@@@@@@@@J                                                                 
                         .B@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@BP@@@@@@@@@@@@@@@@@@@@@@@@@@Y                                                                  
                        .G@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@#P@@@@@@@@GPGGGGGGGGGGGGGGGGY                                                                   
                       P@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@#5@@@@@@@@J                                                                                      
                      Y@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@&5&@@@@@@@Y                                                                                       
                     .!!!!!!!!777777777P@@@@@@@@@@@@&5&@@@@@@@5                                                                                        
                                      ^&@@@@@@@@@@@@5#@@@@@@@P                                                                                         
                                     :#@@@@@@@@@@@@P#@@@@@@@B.                                                                                         
                                    .B@@@@@@@@@@@@PB@@@@@@@#:                                                                                          
                                   P@@@@@@@@@@@@GG@@@@@@@#^                                                                                           
                                  5@@@@@@@@@@@@GG@@@@@@@&~                                                                                            
                                 J@@@@@@@@@@@@BP@@@@@@@@!                                                                                             
                                7@@@@@@@@@@@@#P@@@@@@@@7                                                                                              
                               ~@@@@@@@@@@@@#5@@@@@@@@J                                                                                               
                              ^&@@@@@@@@@@@&5&@@@@@@@Y                                                                                                
                             :#@@@@@@@@@@@&5&@@@@@@@5                                                                                                 
                            .G@@@@@@@@@@@@P#@@@@@@@G                                                                                                  
                           P@@@@@@@@@@@@PB@&&&&&@G.                                                                                                  
                          Y@@@@@@@@@@@@5.::::::::.                                                                                                   
                         J@@@@@@@@@@@@P                                                                                                              
                        :555555555555Y.                                                                                                              
                    ~Theo Tech Cloud Creation Script~

                    This script sets up your cloud computer
                    with a bunch of settings and drivers
                    to make your life easier.  
                    
                    It's provided with no warranty, 
                    so use it at your own risk.
                    
                    Check out the Readme.txt for more
                    information.

                    This tool supports:

                    OS:
                    Server 2022
                    Windows 10 Pro
                    
                    CLOUD SKU:
                    Paperspace A4000  (Ampere A4000)
                    Paperspace P4000  (Quadro P4000)
                    Paperspace P5000  (Quadro P5000)
                    
    
"                                         
Write-Output "Setting up Environment"
$path = [Environment]::GetFolderPath("Desktop")
if((Test-Path -Path $path\THEOTemp ) -eq $true){
    } 
Else {
    New-Item -Path $path\THEOTemp -ItemType directory| Out-Null
    }

Unblock-File -Path .\*
copy-Item .\* -Destination $path\THEOTemp\ -Force -Recurse | Out-Null
#lil nap innit
Start-Sleep -s 1
#Unblocking all script files
Write-Output "Unblocking files just in case"
Get-ChildItem -Path $path\THEOTemp -Recurse | Unblock-File
Write-Output "Starting main script"
start-process powershell.exe -verb RunAS -argument "-file $path\theotemp\PostInstall\PostInstall.ps1"
Write-Host "You can close this window now...progress will happen on the Powershell Window that just opened" -backgroundcolor red
stop-process -Id $PID
