# Call this script from a powershell command prompt using this command:
# Invoke-WebRequest -usebasicparsing -uri "https://raw.githubusercontent.com/SUBnet192/Scripts/master/Build-OfflineRootCA.ps1" | Invoke-Expression

Clear-Host
Write-Host "Building Offline Root CA" -ForegroundColor Green
Write-Host ""

Write-Host ""... Setting default shell to Powershell"
Set-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\WinLogon' -Name Shell -Value 'PowerShell.exe' | Out-null

Write-Host ""... Creating C:\Scripts folder"
New-Item -Path C:\ -Name Scripts -ItemType Directory -Force | Out-Null

Write-Host ""... Retrieving CAPolicy.inf from Github"
Invoke-WebRequest -usebasicparsing -Uri "https://raw.githubusercontent.com/SUBnet192/inf/main/CAPolicy.inf.offlineroot" -Outfile "C:\Windows\CAPolicy.inf"

Write-Host ""... Editing CAPolicy.inf"
$tart-Process -Wait -FilePath "notepad.exe" -ArgumentList "c:\windows\capolicy.inf"
Write-Host ""
Get-Content C:\Windows\CAPolicy.inf"
Write-Host ""

$msg = "Are you satisfied with the contents of CAPolicy.inf?"
do {
    $response = Read-Host -Prompt $msg -ForegroundColor White
    if ($response -eq 'n') {
       Start-Process -Wait -FilePath "notepad.exe" -ArgumentList "c:\windows\capolicy.inf"
       Write-Host ""
       Get-Content C:\Windows\CAPolicy.inf"
       Write-Host ""
    }
} until ($response -eq 'y')

# Install AD Certificate Services
Add-WindowsFeature -Name ADCS-Cert-Authority -IncludeManagementTools

# Configure AD Certificate Services
$OfflineCAName = "Corp-Root-CA"
Install-AdcsCertificationAuthority -CAType EnterpriseRootCa -CryptoProviderName "RSA#Microsoft Software Key Storage Provider" -KeyLength 4096 -HashAlgorithmName SHA256 -ValidityPeriod Years -ValidityPeriodUnits 5 -CACommonName $OfflineCAName
