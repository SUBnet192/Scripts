# Call this script from a powershell command prompt using this command:
# Invoke-WebRequest -usebasicparsing -uri "https://raw.githubusercontent.com/SUBnet192/Scripts/master/Setup-GUIBasics.ps1" | Invoke-Expression

# Trust PowerShell Gallery
Set-PSRepository PSGallery -InstallationPolicy Trusted

# Set Execution Policy
Set-ExecutionPolicy RemoteSigned -Force

# Create Default Script Path
New-Item -Path C:\ -Name Scripts -ItemType Directory

# Set Timezone
Set-Timezone "Eastern Standard Time"

# Install latest VMware Tools
# https://raw.githubusercontent.com/haavarstein/Applications/master/VMware/Tools/Install.ps1
Invoke-WebRequest -usebasicparsing -uri "https://raw.githubusercontent.com/haavarstein/Applications/master/VMware/Tools/Install.ps1" | Invoke-Expression

# Create default powershell profile for All Users / All Hosts
Invoke-WebRequest -usebasicparsing -Uri "https://raw.githubusercontent.com/SUBnet192/Scripts/master/psprofile.ps1" -Outfile $PROFILE.AllusersAllHosts

# Reboot to complete installation
Restart-Computer
