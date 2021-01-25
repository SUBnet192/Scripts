
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
Add-CAAuthorityInformationAccess -Uri "http://$URL/certenroll/<CAName><CertificateName>.crt" -AddToCertificateAia -Force 

certutil.exe -setreg CA\CRLPeriodUnits 2 
certutil.exe -setreg CA\CRLPeriod "Weeks" 
certutil.exe -setreg CA\CRLDeltaPeriodUnits 1 
certutil.exe -setreg CA\CRLDeltaPeriod "Days" 
certutil.exe -setreg CA\CRLOverlapPeriodUnits 12 
certutil.exe -setreg CA\CRLOverlapPeriod "Hours" 
certutil.exe -setreg CA\ValidityPeriodUnits 1
certutil.exe -setreg CA\ValidityPeriod "Years" 
certutil.exe -setreg CA\AuditFilter 127 
Write-Host "... Restarting AD Certificate Services" -ForegroundColor Green
Restart-Service certsvc
Start-Sleep 5
Write-Host "... Publishing CRL" -ForegroundColor Green
certutil -crl
