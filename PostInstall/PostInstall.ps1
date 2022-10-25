param (
    [switch]$DontPromptPasswordUpdateGPU
    )
    

$host.ui.RawUI.WindowTitle = "Theo Tech Cloud Preparation Tool"

[Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls" 

Function ProgressWriter {
    param (
    [int]$percentcomplete,
    [string]$status
    )
    Write-Progress -Activity "Setting Up Your Machine" -Status $status -PercentComplete $PercentComplete
    }

$path = [Environment]::GetFolderPath("Desktop")
$currentusersid = Get-LocalUser "$env:USERNAME" | Select-Object SID | ft -HideTableHeaders | Out-String | ForEach-Object { $_.Trim() }

#Creating Folders and moving script files into System directories
function setupEnvironment {
    ProgressWriter -Status "Moving files and folders into place" -PercentComplete $PercentComplete
    if((Test-Path -Path C:\Windows\system32\GroupPolicy\Machine\Scripts\Startup) -eq $true) {} Else {New-Item -Path C:\Windows\system32\GroupPolicy\Machine\Scripts\Startup -ItemType directory | Out-Null}
    if((Test-Path -Path C:\Windows\system32\GroupPolicy\Machine\Scripts\Shutdown) -eq $true) {} Else {New-Item -Path C:\Windows\system32\GroupPolicy\Machine\Scripts\Shutdown -ItemType directory | Out-Null}
    if((Test-Path -Path $env:ProgramData\ParsecLoader) -eq $true) {} Else {New-Item -Path $env:ProgramData\ParsecLoader -ItemType directory | Out-Null}
    if((Test-Path C:\Windows\system32\GroupPolicy\Machine\Scripts\psscripts.ini) -eq $true) {} Else {Move-Item -Path $path\TheoTemp\PreInstall\psscripts.ini -Destination C:\Windows\system32\GroupPolicy\Machine\Scripts}
    if((Test-Path C:\Windows\system32\GroupPolicy\Machine\Scripts\Shutdown\NetworkRestore.ps1) -eq $true) {} Else {Move-Item -Path $path\TheoTemp\PreInstall\NetworkRestore.ps1 -Destination C:\Windows\system32\GroupPolicy\Machine\Scripts\Shutdown} 
    if((Test-Path $env:ProgramData\ParsecLoader\clear-proxy.ps1) -eq $true) {} Else {Move-Item -Path $path\TheoTemp\PreInstall\clear-proxy.ps1 -Destination $env:ProgramData\ParsecLoader}
    if((Test-Path $env:ProgramData\ParsecLoader\CreateClearProxyScheduledTask.ps1) -eq $true) {} Else {Move-Item -Path $path\TheoTemp\PreInstall\CreateClearProxyScheduledTask.ps1 -Destination $env:ProgramData\ParsecLoader}
    if((Test-Path $env:ProgramData\ParsecLoader\Automatic-Shutdown.ps1) -eq $true) {} Else {Move-Item -Path $path\TheoTemp\PreInstall\Automatic-Shutdown.ps1 -Destination $env:ProgramData\ParsecLoader}
    if((Test-Path $env:ProgramData\ParsecLoader\CreateAutomaticShutdownScheduledTask.ps1) -eq $true) {} Else {Move-Item -Path $path\TheoTemp\PreInstall\CreateAutomaticShutdownScheduledTask.ps1 -Destination $env:ProgramData\ParsecLoader}
    if((Test-Path $env:ProgramData\ParsecLoader\GPU-Update.ico) -eq $true) {} Else {Move-Item -Path $path\TheoTemp\PreInstall\GPU-Update.ico -Destination $env:ProgramData\ParsecLoader}
    if((Test-Path $env:ProgramData\ParsecLoader\CreateOneHourWarningScheduledTask.ps1) -eq $true) {} Else {Move-Item -Path $path\TheoTemp\PreInstall\CreateOneHourWarningScheduledTask.ps1 -Destination $env:ProgramData\ParsecLoader}
    if((Test-Path $env:ProgramData\ParsecLoader\WarningMessage.ps1) -eq $true) {} Else {Move-Item -Path $path\TheoTemp\PreInstall\WarningMessage.ps1 -Destination $env:ProgramData\ParsecLoader}
    if((Test-Path $env:ProgramData\ParsecLoader\Parsec.png) -eq $true) {} Else {Move-Item -Path $path\TheoTemp\PreInstall\Parsec.png -Destination $env:ProgramData\ParsecLoader}
    if((Test-Path $env:ProgramData\ParsecLoader\ShowDialog.ps1) -eq $true) {} Else {Move-Item -Path $path\TheoTemp\PreInstall\ShowDialog.ps1 -Destination $env:ProgramData\ParsecLoader}
    if((Test-Path $env:ProgramData\ParsecLoader\OneHour.ps1) -eq $true) {} Else {Move-Item -Path $path\TheoTemp\PreInstall\OneHour.ps1 -Destination $env:ProgramData\ParsecLoader}
    if((Test-Path $env:ProgramData\ParsecLoader\TeamMachineSetup.ps1) -eq $true) {} Else {Move-Item -Path $path\TheoTemp\PreInstall\TeamMachineSetup.ps1 -Destination $env:ProgramData\ParsecLoader}
    if((Test-Path $env:ProgramData\ParsecLoader\parsecpublic.cer) -eq $true) {} Else {Move-Item -Path $path\TheoTemp\PreInstall\parsecpublic.cer -Destination $env:ProgramData\ParsecLoader}
    }

function cloudprovider { 
    #finds the cloud provider that this VM is hosted by
    $gcp = $(
                try {
                    (Invoke-WebRequest -uri http://metadata.google.internal/computeMetadata/v1/ -Method GET -header @{'metadata-flavor'='Google'} -TimeoutSec 5)
                    }
                catch {
                    }
             )

    $aws = $(
                Try {
                    (Invoke-WebRequest -uri http://169.254.169.254/latest/meta-data/ -TimeoutSec 5)
                    }
                catch {
                    }
             )

    $paperspace = $(
                        Try {
                            (Invoke-WebRequest -uri http://metadata.paperspace.com/meta-data/machine -TimeoutSec 5)
                            }
                        catch {
                            }
                    )

    $azure = $(
                  Try {(Invoke-Webrequest -Headers @{"Metadata"="true"} -Uri "http://169.254.169.254/metadata/instance/compute/userData?api-version=2021-01-01&format=text" -TimeoutSec 5)}
                  catch {}              
               )


    if ($GCP.StatusCode -eq 200) {
        "Google Cloud Instance"
        } 
    Elseif ($AWS.StatusCode -eq 200) {
        "Amazon AWS Instance"
        } 
    Elseif ($paperspace.StatusCode -eq 200) {
        "Paperspace Instance"
        }
    Elseif ($azure.StatusCode -eq 200) {
        "Microsoft Azure Instance"
        }
    Else {
        "Generic Instance"
        }
}


add-type  @"
        using System;
        using System.Collections.Generic;
        using System.Text;
        using System.Runtime.InteropServices;
 
        namespace ComputerSystem
        {
            public class LSAutil
            {
                [StructLayout(LayoutKind.Sequential)]
                private struct LSA_UNICODE_STRING
                {
                    public UInt16 Length;
                    public UInt16 MaximumLength;
                    public IntPtr Buffer;
                }
 
                [StructLayout(LayoutKind.Sequential)]
                private struct LSA_OBJECT_ATTRIBUTES
                {
                    public int Length;
                    public IntPtr RootDirectory;
                    public LSA_UNICODE_STRING ObjectName;
                    public uint Attributes;
                    public IntPtr SecurityDescriptor;
                    public IntPtr SecurityQualityOfService;
                }
 
                private enum LSA_AccessPolicy : long
                {
                    POLICY_VIEW_LOCAL_INFORMATION = 0x00000001L,
                    POLICY_VIEW_AUDIT_INFORMATION = 0x00000002L,
                    POLICY_GET_PRIVATE_INFORMATION = 0x00000004L,
                    POLICY_TRUST_ADMIN = 0x00000008L,
                    POLICY_CREATE_ACCOUNT = 0x00000010L,
                    POLICY_CREATE_SECRET = 0x00000020L,
                    POLICY_CREATE_PRIVILEGE = 0x00000040L,
                    POLICY_SET_DEFAULT_QUOTA_LIMITS = 0x00000080L,
                    POLICY_SET_AUDIT_REQUIREMENTS = 0x00000100L,
                    POLICY_AUDIT_LOG_ADMIN = 0x00000200L,
                    POLICY_SERVER_ADMIN = 0x00000400L,
                    POLICY_LOOKUP_NAMES = 0x00000800L,
                    POLICY_NOTIFICATION = 0x00001000L
                }
 
                [DllImport("advapi32.dll", SetLastError = true, PreserveSig = true)]
                private static extern uint LsaRetrievePrivateData(
                            IntPtr PolicyHandle,
                            ref LSA_UNICODE_STRING KeyName,
                            out IntPtr PrivateData
                );
 
                [DllImport("advapi32.dll", SetLastError = true, PreserveSig = true)]
                private static extern uint LsaStorePrivateData(
                        IntPtr policyHandle,
                        ref LSA_UNICODE_STRING KeyName,
                        ref LSA_UNICODE_STRING PrivateData
                );
 
                [DllImport("advapi32.dll", SetLastError = true, PreserveSig = true)]
                private static extern uint LsaOpenPolicy(
                    ref LSA_UNICODE_STRING SystemName,
                    ref LSA_OBJECT_ATTRIBUTES ObjectAttributes,
                    uint DesiredAccess,
                    out IntPtr PolicyHandle
                );
 
                [DllImport("advapi32.dll", SetLastError = true, PreserveSig = true)]
                private static extern uint LsaNtStatusToWinError(
                    uint status
                );
 
                [DllImport("advapi32.dll", SetLastError = true, PreserveSig = true)]
                private static extern uint LsaClose(
                    IntPtr policyHandle
                );
 
                [DllImport("advapi32.dll", SetLastError = true, PreserveSig = true)]
                private static extern uint LsaFreeMemory(
                    IntPtr buffer
                );
 
                private LSA_OBJECT_ATTRIBUTES objectAttributes;
                private LSA_UNICODE_STRING localsystem;
                private LSA_UNICODE_STRING secretName;
 
                public LSAutil(string key)
                {
                    if (key.Length == 0)
                    {
                        throw new Exception("Key lenght zero");
                    }
 
                    objectAttributes = new LSA_OBJECT_ATTRIBUTES();
                    objectAttributes.Length = 0;
                    objectAttributes.RootDirectory = IntPtr.Zero;
                    objectAttributes.Attributes = 0;
                    objectAttributes.SecurityDescriptor = IntPtr.Zero;
                    objectAttributes.SecurityQualityOfService = IntPtr.Zero;
 
                    localsystem = new LSA_UNICODE_STRING();
                    localsystem.Buffer = IntPtr.Zero;
                    localsystem.Length = 0;
                    localsystem.MaximumLength = 0;
 
                    secretName = new LSA_UNICODE_STRING();
                    secretName.Buffer = Marshal.StringToHGlobalUni(key);
                    secretName.Length = (UInt16)(key.Length * UnicodeEncoding.CharSize);
                    secretName.MaximumLength = (UInt16)((key.Length + 1) * UnicodeEncoding.CharSize);
                }
 
                private IntPtr GetLsaPolicy(LSA_AccessPolicy access)
                {
                    IntPtr LsaPolicyHandle;
 
                    uint ntsResult = LsaOpenPolicy(ref this.localsystem, ref this.objectAttributes, (uint)access, out LsaPolicyHandle);
 
                    uint winErrorCode = LsaNtStatusToWinError(ntsResult);
                    if (winErrorCode != 0)
                    {
                        throw new Exception("LsaOpenPolicy failed: " + winErrorCode);
                    }
 
                    return LsaPolicyHandle;
                }
 
                private static void ReleaseLsaPolicy(IntPtr LsaPolicyHandle)
                {
                    uint ntsResult = LsaClose(LsaPolicyHandle);
                    uint winErrorCode = LsaNtStatusToWinError(ntsResult);
                    if (winErrorCode != 0)
                    {
                        throw new Exception("LsaClose failed: " + winErrorCode);
                    }
                }
 
                public void SetSecret(string value)
                {
                    LSA_UNICODE_STRING lusSecretData = new LSA_UNICODE_STRING();
 
                    if (value.Length > 0)
                    {
                        //Create data and key
                        lusSecretData.Buffer = Marshal.StringToHGlobalUni(value);
                        lusSecretData.Length = (UInt16)(value.Length * UnicodeEncoding.CharSize);
                        lusSecretData.MaximumLength = (UInt16)((value.Length + 1) * UnicodeEncoding.CharSize);
                    }
                    else
                    {
                        //Delete data and key
                        lusSecretData.Buffer = IntPtr.Zero;
                        lusSecretData.Length = 0;
                        lusSecretData.MaximumLength = 0;
                    }
 
                    IntPtr LsaPolicyHandle = GetLsaPolicy(LSA_AccessPolicy.POLICY_CREATE_SECRET);
                    uint result = LsaStorePrivateData(LsaPolicyHandle, ref secretName, ref lusSecretData);
                    ReleaseLsaPolicy(LsaPolicyHandle);
 
                    uint winErrorCode = LsaNtStatusToWinError(result);
                    if (winErrorCode != 0)
                    {
                        throw new Exception("StorePrivateData failed: " + winErrorCode);
                    }
                }
            }
        }
"@

Function TestCredential {
    param
    (
        [PSCredential]$Credential
    )
    try {
        Start-Process -FilePath cmd.exe /c -Credential ($Credential)
        }
    Catch {
        If ($Error[0].Exception.Message) {
        $Error[0].Exception.Message
        Throw
        }
        }
    }

function Set-AutoLogon {
    [CmdletBinding(SupportsShouldProcess)]
    param
    (
        [PSCredential]$Credential
    )
    Try {
        if ($Credential.GetNetworkCredential().Domain) {
            $DefaultDomainName = $Credential.GetNetworkCredential().Domain
            }
        elseif ((Get-WMIObject Win32_ComputerSystem).PartOfDomain) {
            $DefaultDomainName = "."
            }
        else {
            $DefaultDomainName = ""
            }

        if ($PSCmdlet.ShouldProcess(('User "{0}\{1}"' -f $DefaultDomainName, $Credential.GetNetworkCredential().Username), "Set Auto logon")) {
            Write-Verbose ('DomainName: {0} / UserName: {1}' -f $DefaultDomainName, $Credential.GetNetworkCredential().Username)
            Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "AutoAdminLogon" -Value 1
            Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "DefaultDomainName" -Value ""
            Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "DefaultUserName" -Value $Credential.UserName
            Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "AutoLogonCount" -ErrorAction SilentlyContinue
            Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "DefaultPassword" -ErrorAction SilentlyContinue
            $private:LsaUtil = New-Object ComputerSystem.LSAutil -ArgumentList "DefaultPassword"
            $LsaUtil.SetSecret($Credential.GetNetworkCredential().Password)
            "Auto Logon Configured"
            Remove-Variable Credential
            }
    }
    Catch {
        $Error[0].Exception.Message
        Throw
        }
}


Function GetInstanceCredential {
    Try {
        $Credential = Get-Credential -Credential $null
        Try {
            TestCredential -Credential $Credential 
            }
        Catch {
                Remove-Variable Credential
                #$Error[0].Exception.Message
                "Retry?"
                $Retry = Read-Host "(Y/N)"
                Switch ($Retry){
                   Y {
                      GetInstanceCredential 
                       }
                   N {
                      Return
                       }
                    }
            }
        }
    Catch {
        if ($Credential) {Remove-Variable Credential}
        "You pressed cancel, retry?"
        $Cancel = Read-Host "(Y/N)"
        Switch ($Cancel){
            Y {
                GetInstanceCredential
                }
            N {
                Return
                }
            }
        }
    if($credential) {Set-AutoLogon -Credential $Credential}
    }
    
Function PromptUserAutoLogon {
param (
[switch]$DontPromptPasswordUpdateGPU
)
$CloudProvider = CloudProvider
    If ($DontPromptPasswordUpdateGPU) {
        }
    ElseIf ($CloudProvider -eq "Paperspace") {
    }
    Else {
        "Detected $CloudProvider"
        Write-Host @"
Do you want this computer to log on to Windows automatically? 
(Y): This is good when you want the cloud computer to boot straight to Parsec but is less secure as the computer will not be protected by a password at start up
(N): If you plan to log into Windows with RDP then connect via Parsec, or have been told you don't need to set this up
"@ -ForegroundColor Black -BackgroundColor Red
        $ReadHost = Read-Host "(Y/N)" 
        Switch ($ReadHost) 
            {
            Y {
                GetInstanceCredential
                }
            N {
                }
            }
        }
    }





#Modifies Local Group Policy to enable Shutdown scrips items
function add-gpo-modifications {
    $querygpt = Get-content C:\Windows\System32\GroupPolicy\gpt.ini
    $matchgpt = $querygpt -match '{42B5FAAE-6536-11D2-AE5A-0000F87571E3}{40B6664F-4972-11D1-A7CA-0000F87571E3}'
    if ($matchgpt -contains "*0000F87571E3*" -eq $false) {
        $gptstring = get-content C:\Windows\System32\GroupPolicy\gpt.ini
        $gpoversion = $gptstring -match "Version"
        $GPO = $gptstring -match "gPCMachineExtensionNames"
        $add = '[{42B5FAAE-6536-11D2-AE5A-0000F87571E3}{40B6664F-4972-11D1-A7CA-0000F87571E3}]'
        $replace = "$GPO" + "$add"
        (Get-Content "C:\Windows\System32\GroupPolicy\gpt.ini").Replace("$GPO","$replace") | Set-Content "C:\Windows\System32\GroupPolicy\gpt.ini"
        [int]$i = $gpoversion.trim("Version=") 
        [int]$n = $gpoversion.trim("Version=")
        $n +=2
        (Get-Content C:\Windows\System32\GroupPolicy\gpt.ini) -replace "Version=$i", "Version=$n" | Set-Content C:\Windows\System32\GroupPolicy\gpt.ini
        }
    else{
        write-output "Not Required"
        }
    }

#Adds Premade Group Policu Item if existing configuration doesn't exist
function addRegItems{
    ProgressWriter -Status "Adding Registry Items and Group Policy" -PercentComplete $PercentComplete
    if (Test-Path ("C:\Windows\system32\GroupPolicy" + "\gpt.ini")) {
        add-gpo-modifications
        }
    Else {
        Move-Item -Path $path\TheoTemp\PreInstall\gpt.ini -Destination C:\Windows\system32\GroupPolicy -Force | Out-Null
        }
    regedit /s $path\TheoTemp\PreInstall\NetworkRestore.reg
    regedit /s $path\TheoTemp\PreInstall\ForceCloseShutDown.reg
    New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS -ErrorAction SilentlyContinue | Out-Null
    }

function Test-RegistryValue {
    # https://www.jonathanmedd.net/2014/02/testing-for-the-presence-of-a-registry-key-and-value.html
    param (

     [parameter(Mandatory=$true)]
     [ValidateNotNullOrEmpty()]$Path,

    [parameter(Mandatory=$true)]
     [ValidateNotNullOrEmpty()]$Value
    )

    try {
        Get-ItemProperty -Path $Path | Select-Object -ExpandProperty $Value -ErrorAction Stop | Out-Null
        return $true
        }
    catch {
        return $false
        }

}


#Create TheoTemp folder in C Drive
function create-directories {
    ProgressWriter -Status "Creating Directories (C:\TheoTemp)" -PercentComplete $PercentComplete
    if((Test-Path -Path C:\TheoTemp) -eq $true) {} Else {New-Item -Path C:\TheoTemp -ItemType directory | Out-Null}
    if((Test-Path -Path C:\TheoTemp\Apps) -eq $true) {} Else {New-Item -Path C:\TheoTemp\Apps -ItemType directory | Out-Null}
    if((Test-Path -Path C:\TheoTemp\DirectX) -eq $true) {} Else {New-Item -Path C:\TheoTemp\DirectX -ItemType directory | Out-Null}
    if((Test-Path -Path C:\TheoTemp\Drivers) -eq $true) {} Else {New-Item -Path C:\TheoTemp\Drivers -ItemType Directory | Out-Null}
    }

#disable IE security
function disable-iesecurity {
    ProgressWriter -Status "Disabling Internet Explorer security to enable web browsing" -PercentComplete $PercentComplete
    Set-Itemproperty "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}" -name IsInstalled -value 0 -force | Out-Null
    Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}" -Name IsInstalled -Value 0 -Force | Out-Null
    Stop-Process -Name Explorer -Force
    }

#download-files-S3
function download-resources {
    ProgressWriter -Status "Downloading DirectX June 2010 Redist" -PercentComplete $PercentComplete
    (New-Object System.Net.WebClient).DownloadFile("https://download.microsoft.com/download/8/4/A/84A35BF1-DAFE-4AE8-82AF-AD2AE20B6B14/directx_Jun2010_redist.exe", "C:\TheoTemp\Apps\directx_Jun2010_redist.exe") 
    ProgressWriter -Status "Downloading Parsec Virtual Display Driver" -percentcomplete $PercentComplete
    (New-Object System.Net.WebClient).DownloadFile("https://builds.parsec.app/vdd/parsec-vdd-0.37.0.0.exe", "C:\TheoTemp\Apps\parsec-vdd.exe")
    # (New-Object System.Net.WebClient).DownloadFile("https://s3.amazonaws.com/parseccloud/image/parsec+desktop.png", "C:\TheoTemp\parsec+desktop.png")
    ProgressWriter -Status "Downloading Google Chrome" -PercentComplete $PercentComplete
    (New-Object System.Net.WebClient).DownloadFile("https://dl.google.com/tag/s/dl/chrome/install/googlechromestandaloneenterprise64.msi", "C:\TheoTemp\Apps\googlechromestandaloneenterprise64.msi")
    }

#install-base-files-silently
function install-windows-features {
    ProgressWriter -Status "Installing Chrome" -PercentComplete $PercentComplete
    start-process -filepath "C:\Windows\System32\msiexec.exe" -ArgumentList '/qn /i "C:\TheoTemp\Apps\googlechromestandaloneenterprise64.msi"' -Wait
    ProgressWriter -Status "Installing DirectX June 2010 Redist" -PercentComplete $PercentComplete
    Start-Process -FilePath "C:\TheoTemp\Apps\directx_jun2010_redist.exe" -ArgumentList '/T:C:\TheoTemp\DirectX /Q'-wait
    Start-Process -FilePath "C:\TheoTemp\DirectX\DXSETUP.EXE" -ArgumentList '/silent' -wait
    ProgressWriter -Status "Installing Direct Play" -PercentComplete $PercentComplete
    Install-WindowsFeature Direct-Play | Out-Null
    ProgressWriter -Status "Installing .net 3.5" -PercentComplete $PercentComplete
    Install-WindowsFeature Net-Framework-Core | Out-Null
    ProgressWriter -Status "Cleaning up" -PercentComplete $PercentComplete
    Remove-Item -Path C:\TheoTemp\DirectX -force -Recurse 
    }





#disable new network window
function disable-network-window {
    ProgressWriter -Status "Disabling New Network Window" -PercentComplete $PercentComplete
    if((Test-RegistryValue -path HKLM:\SYSTEM\CurrentControlSet\Control\Network -Value NewNetworkWindowOff)-eq $true) {} Else {new-itemproperty -path HKLM:\SYSTEM\CurrentControlSet\Control\Network -name "NewNetworkWindowOff" | Out-Null}
    }

#Enable Pointer Precision 
function enhance-pointer-precision {
    ProgressWriter -Status "Enabling enchanced pointer precision" -PercentComplete $PercentComplete
    Set-Itemproperty -Path 'HKCU:\Control Panel\Mouse' -Name MouseSpeed -Value 1 | Out-Null
    }

#enable Mouse Keys
function enable-mousekeys {
    ProgressWriter -Status "Enabling mouse keys to assist with mouse cursor" -PercentComplete $PercentComplete
    set-Itemproperty -Path 'HKCU:\Control Panel\Accessibility\MouseKeys' -Name Flags -Value 63 | Out-Null
    }

#disable shutdown start menu

#Sets all applications to force close on shutdown
function force-close-apps {
    ProgressWriter -Status "Setting Windows not to stop shutdown if there are unsaved apps" -PercentComplete $PercentComplete
    if (((Get-Item -Path "HKCU:\Control Panel\Desktop").GetValue("AutoEndTasks") -ne $null) -eq $true) {
        Set-ItemProperty -path "HKCU:\Control Panel\Desktop" -Name "AutoEndTasks" -Value "1"
        }
    Else {
        New-ItemProperty -path "HKCU:\Control Panel\Desktop" -Name "AutoEndTasks" -Value "1"
        }
    }



# #set wallpaper
# function set-wallpaper {
#     ProgressWriter -Status "Setting the Parsec logo ass the computer wallpaper" -PercentComplete $PercentComplete
#     if((Test-Path -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System) -eq $true) {} Else {New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies" -Name "System" | Out-Null}
#     if((Test-RegistryValue -path HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System -value Wallpaper) -eq $true) {Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System -Name Wallpaper -value "C:\TheoTemp\parsec+desktop.png" | Out-Null} Else {New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System -Name Wallpaper -PropertyType String -value "C:\TheoTemp\parsec+desktop.png" | Out-Null}
#     if((Test-RegistryValue -path HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System -value WallpaperStyle) -eq $true) {Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System -Name WallpaperStyle -value 2 | Out-Null} Else {New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System -Name WallpaperStyle -PropertyType String -value 2 | Out-Null}
#     Stop-Process -ProcessName explorer
#     }

#disable recent start menu items
function disable-recent-start-menu {
    New-Item -path HKLM:\SOFTWARE\Policies\Microsoft\Windows -name Explorer
    New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer -PropertyType DWORD -Name HideRecentlyAddedApps -Value 1
    }



#Move extracts Razer Surround Files into correct location
Function ExtractRazerAudio {
    cmd.exe /c '"C:\Program Files\7-Zip\7z.exe" x C:\TheoTemp\Apps\razer-surround-driver.exe -oC:\TheoTemp\Apps\razer-surround-driver -y' | Out-Null
    }

#modifys the installer manifest to run without interraction
Function ModidifyManifest {
    $InstallerManifest = 'C:\TheoTemp\Apps\razer-surround-driver\$TEMP\RazerSurroundInstaller\InstallerManifest.xml'
    $regex = '(?<=<SilentMode>)[^<]*'
    (Get-Content $InstallerManifest) -replace $regex, 'true' | Set-Content $InstallerManifest -Encoding UTF8
#>

 #Audio Driver Install
function AudioInstall {
<#
    (New-Object System.Net.WebClient).DownloadFile("http://rzr.to/surround-pc-download", "C:\TheoTemp\Apps\razer-surround-driver.exe")
    ExtractRazerAudio
    ModidifyManifest
    $OriginalLocation = Get-Location
    Set-Location -Path 'C:\TheoTemp\Apps\razer-surround-driver\$TEMP\RazerSurroundInstaller\'
    Start-Process RzUpdateManager.exe
    Set-Location $OriginalLocation
    Set-Service -Name audiosrv -StartupType Automatic
    #>
    (New-Object System.Net.WebClient).DownloadFile("https://download.vb-audio.com/Download_CABLE/VBCABLE_Driver_Pack43.zip", "C:\TheoTemp\Apps\VBCable.zip")
    New-Item -Path "C:\TheoTemp\Apps\VBCable" -ItemType Directory| Out-Null
    Expand-Archive -Path "C:\TheoTemp\Apps\VBCable.zip" -DestinationPath "C:\TheoTemp\Apps\VBCable"
    $pathToCatFile = "C:\TheoTemp\Apps\VBCable\vbaudio_cable64_win7.cat"
    $FullCertificateExportPath = "C:\TheoTemp\Apps\VBCable\VBCert.cer"
    $VB = @{}
    $VB.DriverFile = $pathToCatFile;
    $VB.CertName = $FullCertificateExportPath;
    $VB.ExportType = [System.Security.Cryptography.X509Certificates.X509ContentType]::Cert;
    $VB.Cert = (Get-AuthenticodeSignature -filepath $VB.DriverFile).SignerCertificate;
    [System.IO.File]::WriteAllBytes($VB.CertName, $VB.Cert.Export($VB.ExportType))
    Import-Certificate -CertStoreLocation Cert:\LocalMachine\TrustedPublisher -FilePath $VB.CertName | Out-Null
    Start-Process -FilePath "C:\TheoTemp\Apps\VBCable\VBCABLE_Setup_x64.exe" -ArgumentList '-i','-h'
    Set-Service -Name audiosrv -StartupType Automatic
    Start-Service -Name audiosrv
    }


#Provider specific driver install and setup
Function provider-specific {
    ProgressWriter -Status "Installing VB CAble Audio Driver if required and removing system information from appearing on Google Cloud Desktops" -PercentComplete $PercentComplete
    #Device ID Query 
    $gputype = Get-PnpDevice | Where-Object {($_.DeviceID -like 'PCI\VEN_10DE*' -or $_.DeviceID -like '*PCI\VEN_1002*') -and ($_.PNPClass -eq 'Display' -or $_.Name -like '*Video Controller')} | Select-Object InstanceID -ExpandProperty InstanceID
    if ($gputype -eq $null) {
        }
    Else {
            if($gputype.substring(13,8) -eq "DEV_13F2") {
            #AWS G3.4xLarge M60
            AudioInstall
            }
        ElseIF($gputype.Substring(13,8) -eq "DEV_118A"){
            #AWS G2.2xLarge K520
            AudioInstall
            }
        ElseIF($gputype.Substring(13,8) -eq "DEV_1BB1") {
            #Paperspace P4000
            } 
        Elseif($gputype.Substring(13,8) -eq "DEV_1BB0") {
            #Paperspace P5000
            }
        Elseif($gputype.substring(13,8) -eq "DEV_15F8") {
            #Tesla P100
            if((Test-Path "C:\Program Files\Google\Compute Engine\tools\BGInfo.exe") -eq $true) {remove-item -path "C:\Program Files\Google\Compute Engine\tools\BGInfo.exe"} Else {}
            if((Test-Path "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\BGinfo.lnk") -eq $true) {Remove-Item -path "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\BGinfo.lnk"} Else {}
            AudioInstall
            }
        Elseif($gputype.substring(13,8) -eq "DEV_1BB3") {
            #Tesla P4
            if((Test-Path "C:\Program Files\Google\Compute Engine\tools\BGInfo.exe") -eq $true) {remove-item -path "C:\Program Files\Google\Compute Engine\tools\BGInfo.exe"} Else {}
            if((Test-Path "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\BGinfo.lnk") -eq $true) {Remove-Item -path "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\BGinfo.lnk"} Else {}
            AudioInstall
            }
        Elseif($gputype.substring(13,8) -eq "DEV_1EB8") {
            #Tesla T4
            if((Test-Path "C:\Program Files\Google\Compute Engine\tools\BGInfo.exe") -eq $true) {remove-item -path "C:\Program Files\Google\Compute Engine\tools\BGInfo.exe"} Else {}
            if((Test-Path "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\BGinfo.lnk") -eq $true) {Remove-Item -path "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\BGinfo.lnk"} Else {}
            AudioInstall
            }
        Elseif($gputype.substring(13,8) -eq "DEV_1430") {
            #Quadro M2000
            AudioInstall
            }
        Elseif($gputype.substring(13,8) -eq "DEV_7362") {
            #AMD V520
            AudioInstall
        }
        Else {
            }
        }
    }

#7Zip is required to extract the Parsec-Windows.exe File
function Install7Zip {
    $url = Invoke-WebRequest -Uri https://www.7-zip.org/download.html
    (New-Object System.Net.WebClient).DownloadFile("https://www.7-zip.org/$($($($url.Links | Where-Object outertext -Like "Download")[1]).OuterHTML.split('"')[1])" ,"C:\TheoTemp\Apps\7zip.exe")
    Start-Process C:\TheoTemp\Apps\7zip.exe -ArgumentList '/S /D="C:\Program Files\7-Zip"' -Wait
    }

Function Server2019Controller {
    ProgressWriter -Status "Adding Xbox 360 Controller driver to Windows Server 2019" -PercentComplete $PercentComplete
    if ((gwmi win32_operatingsystem | % caption) -like '*Windows Server 2019*') {
        (New-Object System.Net.WebClient).DownloadFile("http://www.download.windowsupdate.com/msdownload/update/v3-19990518/cabpool/2060_8edb3031ef495d4e4247e51dcb11bef24d2c4da7.cab", "C:\TheoTemp\Drivers\Xbox360_64Eng.cab")
        if((Test-Path -Path C:\TheoTemp\Drivers\Xbox360_64Eng) -eq $true) {} Else {New-Item -Path C:\TheoTemp\Drivers\Xbox360_64Eng -ItemType directory | Out-Null}
        cmd.exe /c "C:\Windows\System32\expand.exe C:\TheoTemp\Drivers\Xbox360_64Eng.cab -F:* C:\TheoTemp\Drivers\Xbox360_64Eng" | Out-Null
        cmd.exe /c '"C:\Program Files\Parsec\vigem\10\x64\devcon.exe" dp_add "C:\TheoTemp\Drivers\Xbox360_64Eng\xusb21.inf"' | Out-Null
        }
    }



Function InstallParsecVDD {
    ProgressWriter -Status "Installing Parsec Virtual Display Driver" -PercentComplete $PercentComplete
    Import-Certificate -CertStoreLocation "Cert:\LocalMachine\TrustedPublisher" -FilePath "$env:ProgramData\ParsecLoader\parsecpublic.cer" | Out-Null
    Start-Process "C:\TheoTemp\Apps\parsec-vdd.exe" -ArgumentList "/silent" 
    $iterator = 0    
    do {
        Start-Sleep -s 2
        $iterator++
        }
    Until (($null -ne ((Get-PnpDevice | Where-Object {$_.Name -eq "Parsec Virtual Display Adapter"}).DeviceID)) -or ($iterator -gt 7))
    if (Get-process -name parsec-vdd -ErrorAction SilentlyContinue) {
        Stop-Process -name parsec-vdd -Force
        }
    $configfile = Get-Content C:\ProgramData\Parsec\config.txt
    $configfile += "host_virtual_monitors = 1"
    $configfile += "host_privacy_mode = 1"
    $configfile | Out-File C:\ProgramData\Parsec\config.txt -Encoding ascii
}

#Apps that require human intervention
function Install-Gaming-Apps {
    ProgressWriter -Status "Installing Parsec, ViGEm https://github.com/ViGEm/ViGEmBus and 7Zip" -PercentComplete $PercentComplete
    Install7Zip
    InstallParsec
    #if((Test-RegistryValue -path HKCU:\Software\Microsoft\Windows\CurrentVersion\Run -value "Parsec.App.0") -eq $true) {Set-ItemProperty -path HKCU:\Software\Microsoft\Windows\CurrentVersion\Run -Name "Parsec.App.0" -Value "C:\Program Files\Parsec\parsecd.exe" | Out-Null} Else {New-ItemProperty -path HKCU:\Software\Microsoft\Windows\CurrentVersion\Run -Name "Parsec.App.0" -Value "C:\Program Files\Parsec\parsecd.exe" | Out-Null}
    Start-Process -FilePath "C:\Program Files\Parsec\parsecd.exe"
    Start-Sleep -s 1
    }

#Disable Devices
function disable-devices {
    ProgressWriter -Status "Disabling Microsoft Basic Display Adapter, Generic Non PNP Monitor and other devices" -PercentComplete $PercentComplete
    Start-Process -FilePath "C:\Program Files\Parsec\vigem\10\x64\devcon.exe" -ArgumentList '/r disable "HDAUDIO\FUNC_01&VEN_10DE&DEV_0083&SUBSYS_10DE11A3*"'
    Get-PnpDevice | where {$_.friendlyname -like "Generic Non-PNP Monitor" -and $_.status -eq "OK"} | Disable-PnpDevice -confirm:$false
    Get-PnpDevice | where {$_.friendlyname -like "Microsoft Basic Display Adapter" -and $_.status -eq "OK"} | Disable-PnpDevice -confirm:$false
    Get-PnpDevice | where {$_.friendlyname -like "Google Graphics Array (GGA)" -and $_.status -eq "OK"} | Disable-PnpDevice -confirm:$false
    Get-PnpDevice | where {$_.friendlyname -like "Microsoft Hyper-V Video" -and $_.status -eq "OK"} | Disable-PnpDevice -confirm:$false
    }

#Cleanup
function clean-up {
    ProgressWriter -Status "Deleting temporary files from C:\TheoTemp" -PercentComplete $PercentComplete
    Remove-Item -Path C:\TheoTemp\Drivers -force -Recurse
    Remove-Item -Path $path\TheoTemp -force -Recurse
    }

#cleanup recent files
function clean-up-recent {
    ProgressWriter -Status "Delete recently accessed files list from Windows Explorer" -PercentComplete $PercentComplete
    remove-item "$env:AppData\Microsoft\Windows\Recent\*" -Recurse -Force | Out-Null
    }


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
#PromptUserAutoLogon -DontPromptPasswordUpdateGPU:$DontPromptPasswordUpdateGPU
$ScripttaskList = @(
"setupEnvironment";
"addRegItems";
"create-directories";
"disable-iesecurity";
"download-resources";
"install-windows-features";
#"force-close-apps";
"disable-network-window";
#"disable-logout";
#"disable-lock";
#"show-hidden-items";
#"show-file-extensions";
"enhance-pointer-precision";
"enable-mousekeys";
#"set-time";
#"set-wallpaper";
#"Create-AutoShutdown-Shortcut";
#"Create-One-Hour-Warning-Shortcut";
#"disable-server-manager";
"Install-Gaming-Apps";
"disable-devices";
"InstallParsecVDD";
"Server2019Controller";
#"gpu-update-shortcut";
"clean-up";
"clean-up-recent";
"provider-specific";
"TeamMachineSetupScheduledTask"
)

foreach ($func in $ScripttaskList) {
    $PercentComplete =$($ScriptTaskList.IndexOf($func) / $ScripttaskList.Count * 100)
    & $func $PercentComplete
    }

Write-host "DONE!" -ForegroundColor black -BackgroundColor Green
if ($DontPromptPasswordUpdateGPU) {} 
Else {pause}


