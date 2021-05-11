# Call this script from a powershell command prompt using this command:
# Invoke-WebRequest -usebasicparsing -uri "https://raw.githubusercontent.com/SUBnet192/Scripts/master/Setup-CoreBasics.ps1" | Invoke-Expression

# Set Powershell as default shell
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\' -Name Shell -Value 'powershell.exe' | Out-Null

# Trust PowerShell Gallery
Set-PSRepository PSGallery -InstallationPolicy Trusted | Out-Null

# Install Default Modules
Install-Module -Name PSWindowsUpdate | Out-Null

# Set Execution Policy
Set-ExecutionPolicy RemoteSigned -Force | Out-Null

# Create Default Script Path
New-Item -Path C:\ -Name Scripts -ItemType Directory -Force | Out-Null

# Set Timezone
Set-Timezone "Eastern Standard Time"

# Install latest VMware Tools
# https://raw.githubusercontent.com/haavarstein/Applications/master/VMware/Tools/Install.ps1
Invoke-WebRequest -usebasicparsing -uri "https://raw.githubusercontent.com/haavarstein/Applications/master/VMware/Tools/Install.ps1" | Invoke-Expression

# Create default powershell profile for All Users / All Hosts
Invoke-WebRequest -usebasicparsing -Uri "https://raw.githubusercontent.com/SUBnet192/Scripts/master/psprofile.ps1" -Outfile $PROFILE.AllusersAllHosts

# Execute Windows Update
Install-WindowsUpdate -Confirm: $False

# Reboot to complete installation
Restart-Computer
