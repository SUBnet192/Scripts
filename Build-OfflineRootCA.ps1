# Call this script from a powershell command prompt using this command:
# Invoke-WebRequest -usebasicparsing -uri "https://raw.githubusercontent.com/SUBnet192/Scripts/master/Build-OfflineRootCA.ps1" | Invoke-Expression

Clear-Host
Write-Host "Building Offline Root CA" -ForegroundColor Green
write-host "`n"

Write-Host "... Setting default shell to Powershell" -ForegroundColor Green
Set-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\WinLogon' -Name Shell -Value 'PowerShell.exe' | Out-null

Write-Host "... Creating C:\Scripts folder" -ForegroundColor Green
New-Item -Path C:\ -Name Scripts -ItemType Directory -Force | Out-Null

Write-Host "... Retrieving CAPolicy.inf from Github" -ForegroundColor Green
Invoke-WebRequest -usebasicparsing -Uri "https://raw.githubusercontent.com/SUBnet192/inf/main/CAPolicy.inf.offlineroot" -Outfile "C:\Windows\CAPolicy.inf"

do {
    Write-Host "... Editing CAPolicy.inf" -ForegroundColor Green
    Start-Process -Wait -FilePath "notepad.exe" -ArgumentList "c:\windows\capolicy.inf"
    write-host "`n"
    Get-Content C:\Windows\CAPolicy.inf
    write-host "`n"
    Write-Host 'Are you satisfied with the contents of CAPolicy.inf? (y/n)' -NoNewline -ForegroundColor Yellow
    $response = Read-Host
} until ($response -eq 'y')

$response = $null

Write-Host "... Install AD Certificate Services" -ForegroundColor Green
Add-WindowsFeature -Name ADCS-Cert-Authority -IncludeManagementTools

Write-Host "... Configure AD Certificate Services" -ForegroundColor Green
do {
    Write-Host 'Enter the Common Name for the Offline root CA (ex: Corp-Root-CA):' -NoNewline -ForegroundColor Yellow
    $OfflineCAName = Read-Host
    Write-Host "Are you satisfied with the CA Name '$OfflineCAName'?" -NoNewline -ForegroundColor Yellow
    $response = Read-Host
} until ($response -eq 'y')

$response = $null
Install-AdcsCertificationAuthority -CAType EnterpriseRootCa -CryptoProviderName 'RSA#Microsoft Software Key Storage Provider' -KeyLength 4096 -HashAlgorithmName SHA256 -ValidityPeriod Years -ValidityPeriodUnits 5 -CACommonName $OfflineCAName
