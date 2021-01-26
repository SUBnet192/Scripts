# Call this script from a powershell command prompt using this command:
# Invoke-WebRequest -usebasicparsing -uri "https://raw.githubusercontent.com/SUBnet192/Scripts/master/Setup-CoreBasics.ps1" | Invoke-Expression

# Set Powershell as default shell
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\' -Name Shell -Value 'powershell.exe'

# Install latest VMware Tools
# https://raw.githubusercontent.com/haavarstein/Applications/master/VMware/Tools/Install.ps1
Invoke-WebRequest -usebasicparsing -uri "https://raw.githubusercontent.com/haavarstein/Applications/master/VMware/Tools/Install.ps1" | Invoke-Expression
