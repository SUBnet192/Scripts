# Call this script from a powershell command prompt using this command:
# Invoke-WebRequest -uri "https://raw.githubusercontent.com/SUBnet192/Scripts/master/Build-AdminJumpPoint.ps1" -UseBasicParsing | Invoke-Expression

# Force TLS 1.2 (Required by PowerShell Gallery and Chocolatey)
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Preparation
Set-PSRepository PSGallery -InstallationPolicy Trusted
Set-ExecutionPolicy RemoteSigned -Force
New-Item -Path C:\ -Name Scripts -ItemType Directory -Force
New-Item -Path C:\ -Name Sources -ItemType Directory -Force

# Install RSAT
Install-WindowsFeature -IncludeAllSubFeature RSAT

# Install WAC
$dlPath = 'C:\Sources\WAC.msi'
Invoke-WebRequest 'http://aka.ms/WACDownload' -OutFile $dlPath
$port = 443
msiexec /i $dlPath /qn /L*v log.txt SME_PORT=$port SSL_CERTIFICATE_OPTION=generate

# Install Microsoft Cloud Services Powershell modules
Install-Module -Name Az
Install-Module -Name AzureAD
Install-Module -Name MSOnline
Install-Module -Name Microsoft.Online.SharePoint.PowerShell
Install-Module -Name ExchangeOnlineManagement
Install-Module -Name MicrosoftTeams

# Install VMware PowerCLI
Install-Module -Name VMware.PowerCLI -AllowClobber
Set-PowerCLIConfiguration -Scope AllUsers -ParticipateInCEIP $false -InvalidCertificateAction Ignore -confirm:$false 

#Miscellaneous Powershell Modules - Ignore missing modules warnings, a reboot is required.
Install-Module -Name Testimo
Install-Module -Name DSInternals
Install-Module -Name PSPKI
Install-Module -Name dbatools
Find-Module -Name SUBNET192* | Install-Module

# Winget tools
$dlPath = 'C:\Sources\WinGet.appxbundle'
Invoke-WebRequest 'https://aka.ms/getwinget' -OutFile $dlPath
Add-AppxPackage $dlPath
winget install -h -e --id 7zip.7zip
winget install -h -e --id Adobe.AdobeAcrobatReaderDC
winget install -h -e --id Git.Git
winget install -h -e --id Google.Chrome
winget install -h -e --id Microsoft.AzureCLI
winget install -h -e --id Microsoft.SQLServerManagementStudio
winget install -h -e --id Microsoft.VisualStudioCode
winget install -h -e --id Notepad++.Notepad++
winget install -h -e --id TimKosse.FileZillaClient
winget install -h -e --id WinSCP.WinSCP

# SpecOps GPUpdate
Invoke-WebRequest -Uri "https://download.specopssoft.com/Release/gpupdate/specopsgpupdatesetup.exe" -OutFile C:\Sources\specops.exe
7z x C:\Sources\specops.exe -oC:\Temp\
Start-Process -FilePath "$env:systemroot\system32\msiexec.exe" -ArgumentList '/i "C:\Temp\Products\SpecOpsGPUpdate\SpecopsGpupdate-x64.msi"' -Wait
Remove-Item -Path C:\Temp -Recurse -Force

# Create default powershell profile for All Users / All Hosts
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SUBnet192/Scripts/master/psprofile.ps1" -Outfile $PROFILE.AllusersAllHosts

# Reboot to complete installation
Restart-Computer
