# Call this script from a powershell command prompt using this command:
# Invoke-WebRequest -usebasicparsing -uri "https://raw.githubusercontent.com/SUBnet192/Scripts/master/Build-SubCA.ps1" | Invoke-Expression
$response = $null
$IssuingCAName = $null
$URL = $null
$Revision = "0.0.10"
Clear-Host
Write-Host "Building Issuing CA - Script version $Revision" -ForegroundColor Green
Write-host "`n"

Write-Host "... Configure WinRM" -ForegroundColor Green
Set-Item WSMan:\localhost\Client\TrustedHosts -Value "*" -Force

Write-Host "... Setting default shell to Powershell" -ForegroundColor Green
Set-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\WinLogon' -Name Shell -Value 'PowerShell.exe' | Out-null

Write-Host "... Creating C:\Scripts folder" -ForegroundColor Green
New-Item -Path C:\ -Name Scripts -ItemType Directory -Force | Out-Null

Write-Host "... Retrieving CAPolicy.inf from Github" -ForegroundColor Green
Invoke-WebRequest -usebasicparsing -Uri "https://raw.githubusercontent.com/SUBnet192/inf/main/CAPolicy.inf.issuing" -Outfile "C:\Windows\CAPolicy.inf"

do {
    Write-Host "... Editing CAPolicy.inf" -ForegroundColor Green
    Start-Process -Wait -FilePath "notepad.exe" -ArgumentList "c:\windows\capolicy.inf"
    write-host "`n"
    Get-Content C:\Windows\CAPolicy.inf
    write-host "`n"
    Write-Host 'Are you satisfied with the contents of CAPolicy.inf? [y/n] ' -NoNewline -ForegroundColor Yellow
    $response = Read-Host
} until ($response -eq 'y')

$response = $null

Write-Host "... Install Windows Feature: AD Certificate Services" -ForegroundColor Green
Add-WindowsFeature -Name ADCS-Cert-Authority Adcs-Enroll-Web-Svc -IncludeManagementTools

Write-Host "... Install and configure AD Certificate Services" -ForegroundColor Green
do {
    Write-Host 'Enter the Common Name for the Issuing CA (ex: Corp-Issuing-CA): ' -NoNewline -ForegroundColor Yellow
    $IssuingCAName = Read-Host
    Write-Host "Are you satisfied with the CA Name '$IssuingCAName'? [y/n] " -NoNewline -ForegroundColor Yellow
    $response = Read-Host
} until ($response -eq 'y')

$response = $null
Install-AdcsCertificationAuthority -CAType EnterpriseSubordinate -CACommonName $IssuingCAName -KeyLength 4096 -HashAlgorithm SHA256 -CryptoProviderName "RSA#Microsoft Software Key Storage Provider" -Force

Write-Host "... Manual intervention required before proceeding further." -ForegroundColor Cyan
