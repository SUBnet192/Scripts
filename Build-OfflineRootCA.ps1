# Call this script from a powershell command prompt using this command:
# Invoke-WebRequest -usebasicparsing -uri "https://raw.githubusercontent.com/SUBnet192/Scripts/master/Build-OfflineRootCA.ps1" | Invoke-Expression
Cls
Write-Host "Building Offline Root CA"
# Set default shell to Powershell
Set-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\WinLogon' -Name Shell -Value 'PowerShell.exe'

# Preparation
Set-ExecutionPolicy RemoteSigned -Force
New-Item -Path C:\ -Name Scripts -ItemType Directory -Force

# Download CAPolicy.inf for Offline Root CA
Invoke-WebRequest -Uri "hhttps://raw.githubusercontent.com/SUBnet192/inf/main/CAPolicy.inf.offlineroot" -Outfile "C:\Windows\CAPolicy.inf"

$msg = 'Do you need to edit CAPolicy.inf?'
do {
    $response = Read-Host -Prompt $msg
    if ($response -eq 'y') {
       Start-Process -Wait -FilePath "notepad.exe" -ArgumentList "c:\windows\capolicy.inf"
    }
} until ($response -eq 'n')

# Install AD Certificate Services
Add-WindowsFeature -Name ADCS-Cert-Authority -IncludeManagementTools

# Configure AD Certificate Services
$OfflineCAName = "Corp-Root-CA"
Install-AdcsCertificationAuthority -CAType EnterpriseRootCa -CryptoProviderName "RSA#Microsoft Software Key Storage Provider" -KeyLength 4096 -HashAlgorithmName SHA256 -ValidityPeriod Years -ValidityPeriodUnits 5 -CACommonName $OfflineCAName

# Reboot to complete installation
Restart-Computer
