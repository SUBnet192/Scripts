# Call this script from a powershell command prompt using this command:
# Invoke-WebRequest -uri "https://raw.githubusercontent.com/SUBnet192/Scripts/master/Build-SAW.ps1"

# Preparation
Set-PSRepository PSGallery -InstallationPolicy Trusted
Set-ExecutionPolicy RemoteSigned -Force
Mkdir C:\Scripts

# Install RSAT
Install-WindowsFeature -IncludeAllSubFeature RSAT

# Install Powershell modules
Install-Module testimo
Find-Module SUBNET192* | Install-Module

Set-ExecutionPolicy Bypass -Scope Process -Force; iwr https://chocolatey.org/install.ps1 -UseBasicParsing | iex
# Chocolatey tools
Choco install chocolatey-gui -y

# Essential tools
Choco install notepadplusplus -y
Choco install googlechrome -y
Choco install adobereader -y
Choco install 7zip -y
Choco install winscp -y
Choco install filezilla -y
Choco install openssh -y
Choco install git -y

# Microsoft Tools
Choco install sysinternals -y
Choco install vscode -y
Choco install vscode-powershell -y

# SQL Related
Choco install sql-server-management-studio -y
Choco install dbatools -y

# Cloud - Azure / Office365
Choco install azure-cli -y
Choco install azcopy -y
Choco install msoid-cli -y

# Vmware related
Choco install vmware-powercli-psmodule -y
Choco install rvtools -y
Choco install vmware-tools -y
Set-PowerCLIConfiguration -Scope AllUsers -ParticipateInCEIP $false -confirm:$false

# SpecOps
Invoke-WebRequest -Uri "https://download.specopssoft.com/Release/gpupdate/specopsgpupdatesetup.exe" -OutFile C:\Scripts\specops.exe
7z x C:\Scripts\specops.exe -oC:\Temp\
Start-Process -FilePath "$env:systemroot\system32\msiexec.exe" -ArgumentList '/i "C:\Temp\Products\SpecOpsGPUpdate\SpecopsGpupdate-x64.msi" /qb' -Wait
rd C:\Temp -Recurse -Force
del C:\Scripts\specops.exe

# Create default powershell profile for All Users / All Hosts
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SUBnet192/Scripts/master/profile.ps1" -Outfile $PROFILE.AllusersAllHosts

# Reboot to complete installation
shutdown -t -0 -r
