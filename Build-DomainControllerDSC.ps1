<#

DSC Configuration for new Domain Controllers on Server Core

- Prepare hard disks
	C: OS
	D: Active Directory Data
	P: Pagefile
	R: CDROM

- Install ADDS services
- Install DNS services
- Install DHCP services
- Enable AD RecycleBin

####################################################################################
# Pre-requisites
####################################################################################

Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name Shell -Value 'PowerShell.exe -NoExit'
Set-PSRepository PSGallery -InstallationPolicy Trusted
Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
Install-Module -Name xActiveDirectory -Force
Install-Module -Name xComputerManagement -Force
Install-Module -Name xNetworking -Force
Install-Module -Name xStorage -Force
Install-Module -Name xDNSServer -Force
Install-Module -Name ActiveDirectoryDsc -Force

####################################################################################

#>

#####################################################################################################################################################
#
#####################################################################################################################################################

configuration BuildFirstDC
{
    Import-DscResource -ModuleName PSDesiredStateConfiguration
    Import-DscResource -ModuleName ActiveDirectoryDsc
    Import-DscResource -ModuleName xActiveDirectory
    Import-DscResource -ModuleName xComputerManagement
    Import-DscResource -ModuleName xNetworking
    Import-DscResource -ModuleName xDnsServer
    Import-DscResource -ModuleName xStorage

    Node localhost
    {
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

        LocalConfigurationManager {
            ActionAfterReboot  = "ContinueConfiguration"
            ConfigurationMode  = "ApplyOnly"
            RebootNodeIfNeeded = $true
        }

        ###############################################################################################################################################
        # Required Folders
        ###############################################################################################################################################

        File Scripts {
            Type            = "Directory"
            Ensure          = "Present"
            DestinationPath = "C:\Scripts"
        }
		
        File ADFiles {
            DestinationPath = $Node.DCDatabasePath
            Type            = 'Directory'
            Ensure          = 'Present'
        }

        File SysVolFiles {
            DestinationPath = $Node.SysvolPath
            Type            = 'Directory'
            Ensure          = 'Present'
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

        xDisk DVolume
        {
            DiskId      = 1
            DriveLetter = 'D'
            FSLabel     = 'AD_Data'
            DependsOn   = '[xWaitforDisk]Disk1'
        }

        xWaitforDisk Disk2
        {
            DiskId           = 2
            RetryIntervalSec = 30
            RetryCount       = 30
        }

        xDisk PVolume
        {
            DiskId      = 2
            DriveLetter = 'P'
            FSLabel     = 'Pagefile'
            DependsOn   = '[xWaitforDisk]Disk2'
        }


        ###############################################################################################################################################
        # 
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
        # Setup IP Address
        ###############################################################################################################################################

        xIPAddress NewIPAddress {
            IPAddress      = $Node.IPAddressCIDR
            InterfaceAlias = $Node.InterfaceAlias
            AddressFamily  = "IPV4"
        }

        xDefaultGatewayAddress NewIPGateway {
            Address        = $Node.GatewayAddress
            InterfaceAlias = $Node.InterfaceAlias
            AddressFamily  = "IPV4"
            DependsOn      = "[xIPAddress]NewIPAddress"
        }

        xDnsServerAddress PrimaryDNSClient {
            Address        = $Node.DNSAddress
            InterfaceAlias = $Node.InterfaceAlias
            AddressFamily  = "IPV4"
            DependsOn      = "[xDefaultGatewayAddress]NewIPGateway"
        }
		
        ###############################################################################################################################################
        # Set Computer Name
        ###############################################################################################################################################

        xComputer NewComputerName {
            Name = $Node.ThisComputerName
        }

        ###############################################################################################################################################
        # Install DNS service
        ###############################################################################################################################################

        WindowsFeature DNSInstall {
            Ensure    = "Present"
            Name      = "DNS"
            DependsOn = "[xComputer]NewComputerName"
        }

        ###############################################################################################################################################
        # Configure DNS Primary Zone
        ###############################################################################################################################################

        xDnsServerPrimaryZone addForwardADZone {
            Ensure        = "Present"
            Name          = $Node.DomainName
            DynamicUpdate = "NonSecureAndSecure"
            DependsOn     = "[WindowsFeature]DNSInstall"
        }

        xDnsServerPrimaryZone addReverseADZone3Net {
            Ensure        = "Present"
            Name          = $Node.ReverseDNZZone
            DynamicUpdate = "NonSecureAndSecure"
            DependsOn     = "[WindowsFeature]DNSInstall"
        }
		
        ###############################################################################################################################################
        # Configure AD Directory Service
        ###############################################################################################################################################

        WindowsFeature ADDSInstall {
            Ensure    = "Present"
            Name      = "AD-Domain-Services"
            DependsOn = "[xDnsServerPrimaryZone]addForwardADZone"
        }
		
        ###############################################################################################################################################
        # Configure DHCP
        ###############################################################################################################################################

        WindowsFeature DHCPInstall {             
            Ensure = "Present"             
            Name   = "DHCP"             
        }

        ###############################################################################################################################################
        # Domain Configuration
        ###############################################################################################################################################

        if ($Node.DSRMPassword) {
            $LocalAdminCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ('Administrator', (ConvertTo-SecureString $Node.DSRMPassword -AsPlainText -Force))
        }

        if ($Node.DomainAdminPassword) {
            $DomainAdminCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ('Administrator', (ConvertTo-SecureString $Node.DomainAdminPassword -AsPlainText -Force))
        }

        xADDomain FirstDC {
            DomainName                    = $Node.DomainName
            DomainAdministratorCredential = $DomainAdminCredential
            SafemodeAdministratorPassword = $LocalAdminCredential
            DatabasePath                  = $Node.DCDatabasePath
            LogPath                       = $Node.DCLogPath
            SysvolPath                    = $Node.SysvolPath
            DependsOn                     = "[WindowsFeature]ADDSInstall", "[File]ADFiles"
        }

        ADDomain PrimaryDC {
            DomainName                    = $Node.DomainName
            Credential                    = $DomainAdminCredential
            SafemodeAdministratorPassword = $LocalAdminCredential
            DependsOn                     = '[WindowsFeature]ADDSInstall'
        }
		
        WaitForADDomain DscDomainWait
        {
            DomainName              = $Node.DomainName
            Credential              = $DomainAdminCredential
            WaitForValidCredentials = $True
            WaitTimeout             = 300
            RestartCount            = 5
            DependsOn               = '[ADDomain]PrimaryDC'
        }

        ###############################################################################################################################################
        # Enable AD Recycle bin
        ###############################################################################################################################################

        ADOptionalFeature RecycleBin
        {
            FeatureName                       = 'Recycle Bin Feature'
            EnterpriseAdministratorCredential = $DomainAdminCredential
            ForestFQDN                        = $Node.DomainName
            DependsOn                         = '[WaitForADDomain]DscDomainWait'
        }

        ###############################################################################################################################################
        # Configure DNS Forwarders
        ###############################################################################################################################################

        if ($Node.Forwarders) {
            xDnsServerForwarder DNSForwarders
            {
                IsSingleInstance = 'Yes'
                IPAddresses      = $Node.Forwarders
                DependsOn        = '[WaitForADDomain]DscDomainWait'
            }
        }

        ###############################################################################################################################################
        # Install a KDS Root Key so we can create MSA/gMSA accounts
        ###############################################################################################################################################

        Script CreateKDSRootKey {
            SetScript  = {
                Add-KdsRootKey -EffectiveTime ((Get-Date).AddHours(-10)) }
            GetScript  = {
                Return @{
                    KDSRootKey = (Get-KdsRootKey)
                }
            }
            TestScript = {
                if (-not (Get-KdsRootKey)) {
                    Write-Verbose -Message 'KDS Root Key Needs to be installed...'
                    Return $false
                }
                Return $true
            }
            DependsOn  = '[WaitForADDomain]DscDomainWait'
        }
		
    }
}

#####################################################################################################################################################
# Define installation customization
#####################################################################################################################################################

$ConfigData = @{
    AllNodes = @(
        @{
            Nodename                    = "localhost"
            ThisComputerName            = "ADS01"
            IPAddressCIDR               = "192.168.254.51/24"
            GatewayAddress              = "192.168.254.1"
            DNSAddress                  = "192.168.254.51"
            ReverseDNZZone              = "254.168.192.in-addr.arpa"
            InterfaceAlias              = "Ethernet0"
            DomainName                  = "MGMT.SUBNET192.LAB"
            DCDatabasePath              = "D:\NTDS"
            DCLogPath                   = "D:\NTDS"
            SysvolPath                  = "D:\Sysvol"
            Forwarders                  = @('8.8.8.8', '8.8.4.4')
            UserName                    = "Administrator"
            DomainAdminPassword         = 'NotTheRealOne!'
            DSRMPassword                = 'NotTheRealOne!'
            PSDscAllowPlainTextPassword = $true
            PSDscAllowDomainUser        = $true
        }
    )
}

#####################################################################################################################################################
# Initialize and Run
#####################################################################################################################################################
Start-Transcript 
BuildFirstDC -ConfigurationData $ConfigData -OutputPath "C:\DSC\BuildFirstDC"

# Make sure that LCM is set to continue configuration after reboot
Set-DscLocalConfigurationManager -Path "C:\DSC\BuildFirstDC" -Verbose -ComputerName localhost

# Build the domain            
Start-DscConfiguration -Wait -Force -Path "C:\DSC\BuildFirstDC" -Verbose -ComputerName localhost
