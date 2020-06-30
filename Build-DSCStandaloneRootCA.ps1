<#
.SYNOPSIS
   DSC Configuration for Standalone Root CA on Windows Server 2019

.DESCRIPTION
   DSC configuration script to apply necessary configurations to build an Offline Root CA
   - Prepare hard disks
      C: OS
      P: Pagefile (Recommend a 10GB virtual disk, thin provisioned)
      R: CDROM
   - Install and configure Active Directory Certificate Services

   *-* Adapted for my personal use from https://github.com/PlagueHO/LabBuilder
   
.NOTES
   ####################################################################################
   # Pre-requisites
   ####################################################################################

   Set-ExecutionPolicy RemoteSigned -Force
   Set-PSRepository PSGallery -InstallationPolicy Trusted
   Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force

   Install-Module -Name xComputerManagement
   Install-Module -Name ActiveDirectoryCSDsc
   Install-Module -Name xStorage

   New-Item -Path C:\ -Name DSC -ItemType Directory

   ####################################################################################
#>

#####################################################################################################################################################
# Desired State Configuration : Standalone Root CA
#####################################################################################################################################################

Configuration BuildRootCA
{
   Import-DscResource -ModuleName PSDesiredStateConfiguration
   Import-DscResource -ModuleName ActiveDirectoryCSDsc
   Import-DscResource -ModuleName xComputerManagement
   Import-DscResource -ModuleName xStorage

   Node localhost
   {
      LocalConfigurationManager {
         ActionAfterReboot  = "ContinueConfiguration"
         ConfigurationMode  = "ApplyOnly"
         RebootNodeIfNeeded = $true
      }

      ###############################################################################################################################################
      # Change CDROM Drive Letter
      ###############################################################################################################################################

      Script ChangeCDROMDriveLetter {
         GetScript  = {
            @{
               GetScript  = $GetScript
               SetScript  = $SetScript
               TestScript = $TestScript
               Result     = (Get-CimInstance -ClassName Win32_Volume -Filter "DriveLetter = 'D:'").DriveType -ne 5
            }
         }

         SetScript  = {
            Get-CimInstance -ClassName Win32_Volume -Filter "DriveLetter = 'D:'" | Set-CimInstance -Property @{ DriveLetter = "R:" }
         }

         TestScript = {
            $Status = (Get-CimInstance -ClassName Win32_Volume -Filter "DriveLetter = 'D:'").DriveType -ne 5
            $Status -eq $True
         }
      }

      ###############################################################################################################################################
      # Required Folders
      ###############################################################################################################################################

      File Scripts {
         Type            = "Directory"
         Ensure          = "Present"
         DestinationPath = "C:\Scripts"
      }

      ###############################################################################################################################################
      # Prepare new disks
      ###############################################################################################################################################

      xDisk CVolume
      {
         DiskID      = 0
         DriveLetter = 'C'			
         FSLabel     = 'OS'
      }		

      xWaitforDisk Disk1
      {
         DiskId           = 1
         RetryIntervalSec = 30
         RetryCount       = 30
      }

      xDisk PVolume
      {
         DiskId      = 1
         DriveLetter = 'P'
         FSLabel     = 'Pagefile'
         DependsOn   = '[xWaitforDisk]Disk1'
      }

      ###############################################################################################################################################
      # Set Pagefile
      ###############################################################################################################################################

      xVirtualMemory OSDisk {
         Drive = 'C'
         type  = 'NoPagingFile'
      }

      xVirtualMemory PageFileDisk {
         Drive       = 'P'
         InitialSize = 8192
         MaximumSize = 8192
         type        = 'CustomSize'
         DependsOn   = "[xDisk]PVolume"
      }

      ###############################################################################################################################################
      # Assemble the Local Admin Credentials
      ###############################################################################################################################################

      if ($Node.LocalAdminPassword) {
         $LocalAdminCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ('Administrator', (ConvertTo-SecureString $Node.LocalAdminPassword -AsPlainText -Force))
      }

      ###############################################################################################################################################
      # Install the CA Service
      ###############################################################################################################################################

      WindowsFeature ADCSCA {
         Name   = 'ADCS-Cert-Authority'
         Ensure = 'Present'
      }

      if ($InstallRSATTools) {
         WindowsFeature RSAT-ManagementTools {
            Ensure    = 'Present'
            Name      = 'RSAT-AD-Tools'
            DependsOn = '[WindowsFeature]ADCSCA'
         }
      }

      ###############################################################################################################################################
      # Create the CAPolicy.inf file that sets basic parameters for certificate issuance for this CA.
      ###############################################################################################################################################

      File CAPolicy {
         Ensure          = 'Present'
         DestinationPath = 'C:\Windows\CAPolicy.inf'
         Contents        = "[Version]`r`n Signature=`"`$Windows NT$`"`r`n[PolicyStatementExtension]`r`n Policies=InternalPolicy`r`n[InternalPolicy]`r`n OID=$($Node.OID)`r`n URL=$($Node.PolicyURL)`r`n[Certsrv_Server]`r`n RenewalKeyLength=4096`r`n RenewalValidityPeriod=Years`r`n RenewalValidityPeriodUnits=20`r`n HashAlgorithm=RSASHA256`r`n CRLPeriod=Years`r`n CRLPeriodUnits=20`r`n CRLDeltaPeriod=Days`r`n CRLDeltaPeriodUnits=0`r`n LoadDefaultTemplates=0`r`n[CRLDistributionPoint]`r`n[AuthorityInformationAccess]`r`n"


         Type            = 'File'
      }

      ###############################################################################################################################################
      # Make a CertEnroll folder to put the Root CA certificate into.
      ###############################################################################################################################################

      File CertEnrollFolder {
         Ensure          = 'Present'
         DestinationPath = 'C:\Windows\System32\CertSrv\CertEnroll'
         Type            = 'Directory'
         DependsOn       = '[File]CAPolicy'
      }

      ###############################################################################################################################################
      # Configure the Root CA which will create the Certificate REQ file that Root CA will use to issue a certificate for this Sub CA.
      ###############################################################################################################################################

      ADCSCertificationAuthority ConfigCA
      {
         Ensure                    = 'Present'
         IsSingleInstance          = 'Yes'
         CAType                    = 'StandaloneRootCA'
         Credential                = $LocalAdminCredential
         CACommonName              = $Node.CACommonName
         CADistinguishedNameSuffix = $Node.CADistinguishedNameSuffix
         OverwriteExistingCAinDS   = $true
         CryptoProviderName        = 'RSA#Microsoft Software Key Storage Provider'
         HashAlgorithmName         = 'SHA256'
         KeyLength                 = 4096
         DependsOn                 = '[File]CertEnrollFolder'
      }

      ###############################################################################################################################################
      # Perform final configuration of the CA which will cause the CA service to startupand set the advanced CA properties
      ###############################################################################################################################################

      Script ADCSAdvConfig {
         SetScript  = {
            if ($Using:Node.CADistinguishedNameSuffix) {
               & "$($ENV:SystemRoot)\system32\certutil.exe" -setreg CA\DSConfigDN "CN=Configuration,$($Using:Node.CADistinguishedNameSuffix)"
               & "$($ENV:SystemRoot)\system32\certutil.exe" -setreg CA\DSDomainDN "$($Using:Node.CADistinguishedNameSuffix)"
            }
            if ($Using:Node.CRLPublicationURLs) {
               & "$($ENV:SystemRoot)\System32\certutil.exe" -setreg CA\CRLPublicationURLs $($Using:Node.CRLPublicationURLs)
            }
            if ($Using:Node.CACertPublicationURLs) {
               & "$($ENV:SystemRoot)\System32\certutil.exe" -setreg CA\CACertPublicationURLs $($Using:Node.CACertPublicationURLs)
            }
            if ($Using:Node.CRLPeriodUnits) {
               & "$($ENV:SystemRoot)\System32\certutil.exe" -setreg CA\CRLPeriodUnits $($Using:Node.CRLPeriodUnits)
               & "$($ENV:SystemRoot)\System32\certutil.exe" -setreg CA\CRLPeriod "$($Using:Node.CRLPeriod)"
            }
            if ($Using:Node.CRLOverlapUnits) {
               & "$($ENV:SystemRoot)\System32\certutil.exe" -setreg CA\CRLOverlapUnits $($Using:Node.CRLOverlapUnits)
               & "$($ENV:SystemRoot)\System32\certutil.exe" -setreg CA\CRLOverlapPeriod "$($Using:Node.CRLOverlapPeriod)"
            }
            if ($Using:Node.ValidityPeriodUnits) {
               & "$($ENV:SystemRoot)\System32\certutil.exe" -setreg CA\ValidityPeriodUnits $($Using:Node.ValidityPeriodUnits)
               & "$($ENV:SystemRoot)\System32\certutil.exe" -setreg CA\ValidityPeriod "$($Using:Node.ValidityPeriod)"
            }
            if ($Using:Node.AuditFilter) {
               & "$($ENV:SystemRoot)\System32\certutil.exe" -setreg CA\AuditFilter $($Using:Node.AuditFilter)
            }
            Restart-Service -Name CertSvc
            New-Item -Path 'c:\windows\setup\scripts\' -ItemType Directory -ErrorAction SilentlyContinue
            Add-Content -Path 'c:\windows\setup\scripts\certutil.log' -Value 'Certificate Service Restarted ...'
         }

         GetScript  = {
            return @{
               'DSConfigDN'            = (Get-ChildItem 'HKLM:\System\CurrentControlSet\Services\CertSvc\Configuration').GetValue('DSConfigDN');
               'DSDomainDN'            = (Get-ChildItem 'HKLM:\System\CurrentControlSet\Services\CertSvc\Configuration').GetValue('DSDomainDN');
               'CRLPublicationURLs'    = (Get-ChildItem 'HKLM:\System\CurrentControlSet\Services\CertSvc\Configuration').GetValue('CRLPublicationURLs');
               'CACertPublicationURLs' = (Get-ChildItem 'HKLM:\System\CurrentControlSet\Services\CertSvc\Configuration').GetValue('CACertPublicationURLs')
               'CRLPeriodUnits'        = (Get-ChildItem 'HKLM:\System\CurrentControlSet\Services\CertSvc\Configuration').GetValue('CRLPeriodUnits')
               'CRLPeriod'             = (Get-ChildItem 'HKLM:\System\CurrentControlSet\Services\CertSvc\Configuration').GetValue('CRLPeriod')
               'CRLOverlapUnits'       = (Get-ChildItem 'HKLM:\System\CurrentControlSet\Services\CertSvc\Configuration').GetValue('CRLOverlapUnits')
               'CRLOverlapPeriod'      = (Get-ChildItem 'HKLM:\System\CurrentControlSet\Services\CertSvc\Configuration').GetValue('CRLOverlapPeriod')
               'ValidityPeriodUnits'   = (Get-ChildItem 'HKLM:\System\CurrentControlSet\Services\CertSvc\Configuration').GetValue('ValidityPeriodUnits')
               'ValidityPeriod'        = (Get-ChildItem 'HKLM:\System\CurrentControlSet\Services\CertSvc\Configuration').GetValue('ValidityPeriod')
               'AuditFilter'           = (Get-ChildItem 'HKLM:\System\CurrentControlSet\Services\CertSvc\Configuration').GetValue('AuditFilter')
            }
         }

         TestScript = {
            if (((Get-ChildItem 'HKLM:\System\CurrentControlSet\Services\CertSvc\Configuration').GetValue('DSConfigDN') -ne "CN=Configuration,$($Using:Node.CADistinguishedNameSuffix)")) {
               return $false
            }
            if (((Get-ChildItem 'HKLM:\System\CurrentControlSet\Services\CertSvc\Configuration').GetValue('DSDomainDN') -ne "$($Using:Node.CADistinguishedNameSuffix)")) {
               return $false
            }
            if (($Using:Node.CRLPublicationURLs) -and ((Get-ChildItem 'HKLM:\System\CurrentControlSet\Services\CertSvc\Configuration').GetValue('CRLPublicationURLs') -ne $Using:Node.CRLPublicationURLs)) {
               return $false
            }
            if (($Using:Node.CACertPublicationURLs) -and ((Get-ChildItem 'HKLM:\System\CurrentControlSet\Services\CertSvc\Configuration').GetValue('CACertPublicationURLs') -ne $Using:Node.CACertPublicationURLs)) {
               return $false
            }
            if (($Using:Node.CRLPeriodUnits) -and ((Get-ChildItem 'HKLM:\System\CurrentControlSet\Services\CertSvc\Configuration').GetValue('CRLPeriodUnits') -ne $Using:Node.CRLPeriodUnits)) {
               return $false
            }
            if (($Using:Node.CRLPeriod) -and ((Get-ChildItem 'HKLM:\System\CurrentControlSet\Services\CertSvc\Configuration').GetValue('CRLPeriod') -ne $Using:Node.CRLPeriod)) {
               return $false
            }
            if (($Using:Node.CRLOverlapUnits) -and ((Get-ChildItem 'HKLM:\System\CurrentControlSet\Services\CertSvc\Configuration').GetValue('CRLOverlapUnits') -ne $Using:Node.CRLOverlapUnits)) {
               return $false
            }
            if (($Using:Node.CRLOverlapPeriod) -and ((Get-ChildItem 'HKLM:\System\CurrentControlSet\Services\CertSvc\Configuration').GetValue('CRLOverlapPeriod') -ne $Using:Node.CRLOverlapPeriod)) {
               return $false
            }
            if (($Using:Node.ValidityPeriodUnits) -and ((Get-ChildItem 'HKLM:\System\CurrentControlSet\Services\CertSvc\Configuration').GetValue('ValidityPeriodUnits') -ne $Using:Node.ValidityPeriodUnits)) {
               return $false
            }
            if (($Using:Node.ValidityPeriod) -and ((Get-ChildItem 'HKLM:\System\CurrentControlSet\Services\CertSvc\Configuration').GetValue('ValidityPeriod') -ne $Using:Node.ValidityPeriod)) {
               return $false
            }
            if (($Using:Node.AuditFilter) -and ((Get-ChildItem 'HKLM:\System\CurrentControlSet\Services\CertSvc\Configuration').GetValue('AuditFilter') -ne $Using:Node.AuditFilter)) {
               return $false
            }
            return $true
         }
      }

   }
}

#####################################################################################################################################################
# Define installation customization
#####################################################################################################################################################

$ConfigData = @{
   AllNodes = @(
      @{
         PSDscAllowPlainTextPassword = $true
         Nodename                    = "localhost"
         LocalAdminPassword          = "TemporaryPassword!"
         InstallRSATTools            = $true
         CACommonName                = 'CompanyName Root CA'
         CADistinguishedNameSuffix   = 'DC=DOMAINNAME,DC=LOCAL'
         CRLPublicationURLs          = '65:C:\Windows\system32\CertSrv\CertEnroll\%3%8%9.crl\n79:ldap:///CN=%7%8,CN=%2,CN=CDP,CN=Public Key Services,CN=Services,%6%10\n6:http://pki.domainname.local/CertEnroll/%3%8%9.crl'
         CACertPublicationURLs       = '1:C:\Windows\system32\CertSrv\CertEnroll\%1_%3%4.crt\n2:ldap:///CN=%7,CN=AIA,CN=Public Key Services,CN=Services,%6%11\n2:http://pki.domainname.local/CertEnroll/%1_%3%4.crt'
         OID                         = "TO BE DETERMINED" # Request OID at https://pen.iana.org/pen/PenApplication.page
         PolicyURL                   = "http://pki.domainname.local/pki/cps.html"
         CRLPeriodUnits              = 20
         CRLPeriod                   = 'Years'
         CRLOverlapUnits             = 3
         CRLOverlapPeriod            = 'Weeks'
         ValidityPeriodUnits         = 10
         ValidityPeriod              = 'Years'
         AuditFilter                 = 127
      }
   )
}

#####################################################################################################################################################
# Initialize and Run
#####################################################################################################################################################
Start-Transcript 
BuildRootCA -ConfigurationData $ConfigData -OutputPath "C:\DSC\BuildRootCA"

# Make sure that LCM is set to continue configuration after reboot
Set-DscLocalConfigurationManager -Path "C:\DSC\BuildRootCA" -Verbose -ComputerName localhost

# Build the domain            
Start-DscConfiguration -Wait -Force -Path "C:\DSC\BuildRootCA" -Verbose -ComputerName localhost
