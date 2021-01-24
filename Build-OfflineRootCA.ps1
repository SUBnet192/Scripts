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
    Write-Host 'Are you satisfied with the contents of CAPolicy.inf? [y/n] ' -NoNewline -ForegroundColor Yellow
    $response = Read-Host
} until ($response -eq 'y')

$response = $null

Write-Host "... Install Windows Feature: AD Certificate Services" -ForegroundColor Green
Add-WindowsFeature -Name ADCS-Cert-Authority -IncludeManagementTools

Write-Host "... Install and configure AD Certificate Services" -ForegroundColor Green
do {
    Write-Host 'Enter the Common Name for the Offline root CA (ex: Corp-Root-CA): ' -NoNewline -ForegroundColor Yellow
    $OfflineCAName = Read-Host
    Write-Host "Are you satisfied with the CA Name '$OfflineCAName'? [y/n] " -NoNewline -ForegroundColor Yellow
    $response = Read-Host
} until ($response -eq 'y')

$response = $null
Install-AdcsCertificationAuthority -CAType StandaloneRootCA -CACommonName $OfflineCAName -KeyLength 4096 -HashAlgorithm SHA256 -CryptoProviderName "RSA#Microsoft Software Key Storage Provider" -ValidityPeriod Years -ValidityPeriodUnits 5 -Force

Write-Host "... Customizing AD Certificate Services" -ForegroundColor Green

do {
    Write-Host 'Enter the URL where the CRL files will be located (ex: pki.mycompany.com): ' -NoNewline -ForegroundColor Yellow
    $URL = Read-Host
    Write-Host "Are you satisfied with the URL '$URL'? [y/n] " -NoNewline -ForegroundColor Yellow
    $response = Read-Host
} until ($response -eq 'y')

$response = $null

$crllist = Get-CACrlDistributionPoint; foreach ($crl in $crllist) {Remove-CACrlDistributionPoint $crl.uri -Force};

Add-CACRLDistributionPoint -Uri "$env:windir\system32\CertSrv\CertEnroll\<CaName><CRLNameSuffix><DeltaCRLAllowed>.crl" -PublishToServer -PublishDeltaToServer -Force
Add-CACRLDistributionPoint -Uri "http://$URL/certenroll/<CAName><CRLNameSuffix><DeltaCRLAllowed>.crl" -AddToCertificateCDP -AddToFreshestCrl -Force

Get-CAAuthorityInformationAccess | where {$_.Uri -like '*ldap*' -or $_.Uri -like '*http*' -or $_.Uri -like '*file*'} | Remove-CAAuthorityInformationAccess -Force
Add-CAAuthorityInformationAccess -AddToCertificateAia "http://$URL/certenroll/<CAName><CertificateName>.crt" -Force 

certutil.exe -setreg CA\CRLOverlapPeriodUnits 3
certutil.exe -setreg CA\CRLOverlapPeriod "Weeks"
certutil.exe -setreg CA\AuditFilter 127
Write-Host "... Restarting AD Certificate Services" -ForegroundColor Green
Restart-Service certsvc
Start-Sleep 5
Write-Host "... Publishing CRL" -ForegroundColor Green
certutil -crl
