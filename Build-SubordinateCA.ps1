# Call this script from a powershell command prompt using this command:
# Invoke-WebRequest -usebasicparsing -uri "https://raw.githubusercontent.com/SUBnet192/Scripts/master/Build-SubordinateCA.ps1" | Invoke-Expression

Clear-Host
Write-Host "Building Subordinate CA" -ForegroundColor Green
Write-host "`n"

Write-Host "... Configure WinRM" -ForegroundColor Green
Set-Item WSMan:\localhost\Client\TrustedHosts -Value "*" -Force

Write-Host "... Setting default shell to Powershell" -ForegroundColor Green
Set-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\WinLogon' -Name Shell -Value 'PowerShell.exe' | Out-null

Write-Host "... Creating C:\Scripts folder" -ForegroundColor Green
New-Item -Path C:\ -Name Scripts -ItemType Directory -Force | Out-Null

Write-Host "... Retrieving CAPolicy.inf from Github" -ForegroundColor Green
Invoke-WebRequest -usebasicparsing -Uri "https://raw.githubusercontent.com/SUBnet192/inf/main/CAPolicy.inf.subordinate" -Outfile "C:\Windows\CAPolicy.inf"

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
    Write-Host 'Enter the Common Name for the Subordinate CA (ex: Corp-Subordinate-CA): ' -NoNewline -ForegroundColor Yellow
    $SubordinateCAName = Read-Host
    Write-Host "Are you satisfied with the CA Name '$SubordinateCAName'? [y/n] " -NoNewline -ForegroundColor Yellow
    $response = Read-Host
} until ($response -eq 'y')

$response = $null
Install-AdcsCertificationAuthority -CAType EnterpriseSubordinate -CACommonName $SubordinateCAName -KeyLength 4096 -HashAlgorithm SHA256 -CryptoProviderName "RSA#Microsoft Software Key Storage Provider" -Force

Write-Host "... Connecting to Offline Root CA" -ForegroundColor Cyan
write-host "`n"
do {
    # Get Offline Root CA (ORCA) server name
    Write-Host 'Enter the Name for the Root CA server: ' -NoNewline -ForegroundColor Yellow
    $ORCAServer = Read-Host
    Write-Host "Are you satisfied with this server name: '$ORCAServer'? [y/n] " -NoNewline -ForegroundColor Yellow
    $response = Read-Host
} until ($response -eq 'y')

$ORCACreds = Get-Credential -Message "Please provide Offline Root CA credentials."
New-PSDrive -Name "X" -Root "\\$ORCAServer\CertConfig" -PSProvider "FileSystem" -Credential $ORCACreds

# Copy request from Subordinate CA to Root CA
Copy-Item C:\*.REQ -Destination X:\

# Get Offline Root CA (ORCA) name

Invoke-Command $ORCAServer -credential $ORCACreds -scriptblock {
    Write-Host "... Executing commands on Root CA"
    $ORCAName = (get-itemproperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration).Active
    $ORCAServer = hostname
    $SubordinateCAReq = Get-ChildItem "C:\CAConfig\*.req"
    # Submit CSR from Subordinate CA to the Root CA
    Write-Host "[DEBUG] ORCAServer:$ORCAServer" -ForegroundColor Yellow
    Write-Host "[DEBUG] ORCAName:$ORCAName" -ForegroundColor Yellow
    Write-Host "[DEBUG] SubordinateCAReq:$SubordinateCAReq" -ForegroundColor Yellow
    Write-Host "... Submitting Subordinate certificate to Root CA"
    certreq -config $ORCAServer\$ORCAName -submit -attrib "CertificateTemplate:SubCA" $($SubordinateCAReq).Fullname
    # Authorize Certificate Request
    Write-Host "... Issuing Subordinate certificate"
    certutil -resubmit 2
    # Retrieve Subordinate CA certificate
    Write-Host "... Retrieving Subordinate certificate"
    certreq -config $ORCAServer\$ORCAName -retrieve 2 "C:\CAConfig\SubordinateCA.crt"
    # Rename Root CA certificate (remove server name)

Rename-Item $ORCAServer_$ORCAName.crt $ORCAName.crt
    Remove-Item C:\CAConfig\*.REQ
}

# Copy certificate/CRL from Root CA to Subordinate CA
Copy-Item X:\*.CRT -Destination C:\Windows\system32\CertSrv\CertEnroll
Copy-Item X:\*.CRL -Destination C:\Windows\system32\CertSrv\CertEnroll

$RootCACert = Get-ChildItem "C:\Windows\system32\CertSrv\CertEnroll\*.crt" -exclude "SubordinateCA.crt"
$RootCACRL = Get-ChildItem "C:\Windows\system32\CertSrv\CertEnroll\*.crl"

# Publish Root CA certificate to AD
certutil.exe –dsPublish –f  $($RootCACert).FullName RootCA

# Publish Root CA certificates to Subordinate server
certutil.exe –addstore –f root $($RootCACert).FullName
certutil.exe –addstore –f root $($RootCACRL).FullName

certutil.exe -installcert C:\Windows\System32\CertSrv\CertEnroll\SubordinateCA.crt

Write-Host "... Customizing AD Certificate Services" -ForegroundColor Green

do {
    Write-Host 'Enter the URL where the CRL files will be located (ex: pki.mycompany.com): ' -NoNewline -ForegroundColor Yellow
    $URL = Read-Host
    Write-Host "Are you satisfied with the URL '$URL'? [y/n] " -NoNewline -ForegroundColor Yellow
    $response = Read-Host
} until ($response -eq 'y')

$response = $null

$crllist = Get-CACrlDistributionPoint; foreach ($crl in $crllist) {Remove-CACrlDistributionPoint $crl.uri -Force};

Add-CACRLDistributionPoint -Uri "C:\Windows\system32\CertSrv\CertEnroll\<CaName><CRLNameSuffix><DeltaCRLAllowed>.crl" -PublishToServer -PublishDeltaToServer -Force
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

# Delete REQ at root and cleanup certenroll (subordinate)

#>
