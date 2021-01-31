<#
.SYNOPSIS
  Build Active Directory foundation (OU Structure, Tasks groups, GPOs)
.DESCRIPTION
  
.INPUTS
  None
.OUTPUTS
  None
.NOTES
  Version:        1.0.1
  Author:         Marc Bouchard
  Creation Date:  2021/01/31
  Purpose/Change: Initial script development
#>

#-------------------------------------------------------[ INIT ]----------------------------------------------------------

$ADDomain = Get-ADDomain
$ADDN = $ADDomain.DistinguishedName

$RootOU = "CorporateRoot"
$DomainControllersOU = "OU=Domain Controllers,$ADDN"

# This is the name of the GPO for the PDCe policy
$PDCeGPOName = "SYST-DomainControllers_TimeSource-PDCe"

# This is the WMI Filter for the PDCe Domain Controller
$PDCeWMIFilter = @("PDCe Domain Controller","Queries for the domain controller that holds the PDC emulator FSMO role","root\CIMv2","Select * from Win32_ComputerSystem where DomainRole=5")

# This is the name of the GPO for the non-PDCe policy
$NonPDCeGPOName = "SYST-DomainControllers_TimeSource"

# This is the WMI Filter for the non-PDCe Domain Controllers
$NonPDCeWMIFilter = @("Non-PDCe Domain Controllers","Queries for all domain controllers except for the one that holds the PDC emulator FSMO role","root\CIMv2","Select * from Win32_ComputerSystem where DomainRole=4")

# Set this to True to include the registry value to disable the Hyper-V Time Synchronization
$DisableHyperVTimeSynchronization = $True

# Set this to True if you need to set the "Allow System Only Change" value.
$AllowSystemOnlyChange = $False

# Set this to the number of seconds you would like to wait for Active Directory replication to complete before retrying to add the WMI filter to the Group Policy Object (GPO).
$SleepTimer = 10

# Set this to the NTP Servers the PDCe will sync with
$TimeServers = "0.ca.pool.ntp.org,0x8 1.ca.pool.ntp.org,0x8 2.ca.pool.ntp.org,0x8 3.ca.pool.ntp.org,0x8"

#----------------------------------------------------[ Declarations ]-----------------------------------------------------
#-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
# Function: Report-Status
# Purpose : Report progress
#-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
Function Report-Status {
    Param(
        [parameter(Mandatory=$true)][String]$Msg,
        [parameter(Mandatory=$true)][INT]$Lvl,
        [parameter(Mandatory=$true)][String]$Color
        )
        Switch ($Lvl)
        {
            0 { Write-Host -Foreground $Color $Msg }
            1 { Write-Host -Foreground $Color "  -" $Msg }
            2 { Write-Host -Foreground $Color "    *" $Msg }
        }
    }
#-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
# Function: ConvertTo-WMIFilter
#-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
function ConvertTo-WmiFilter([Microsoft.ActiveDirectory.Management.ADObject[]] $ADObject)
{
  $gpDomain = New-Object -Type Microsoft.GroupPolicy.GPDomain
  $ADObject | ForEach-Object {
    $path = 'MSFT_SomFilter.Domain="' + $gpDomain.DomainName + '",ID="' + $_.Name + '"'
    $filter = $NULL
    try
      {
        $filter = $gpDomain.GetWmiFilter($path)
      }
    catch
      {
        Report-Status "The WMI filter could not be found." 1 Red
      }
    if ($filter)
      {
        [Guid]$Guid = $_.Name.Substring(1, $_.Name.Length - 2)
        $filter | Add-Member -MemberType NoteProperty -Name Guid -Value $Guid -PassThru | Add-Member -MemberType NoteProperty -Name Content -Value $_."msWMI-Parm2" -PassThru
      } else {
        Report-Status "Waiting $SleepTimer seconds for Active Directory replication to complete." 1 Yellow
        start-sleep -s $SleepTimer
        Report-Status "Trying again to retrieve the WMI filter." 1 Yellow
        ConvertTo-WmiFilter $ADObject
      }
  }
}

Function Create-TimeSyncGPO {
    param($GPOName,$NtpServer,$AnnounceFlags,$Type,$WMIFilter)

    If ($AllowSystemOnlyChange) { new-itemproperty "HKLM:\System\CurrentControlSet\Services\NTDS\Parameters" -name "Allow System Only Change" -value 1 -propertyType dword -EA 0 }

    $UseAdministrator = $False

    If ($UseAdministrator -eq $False) {
        $msWMIAuthor = (Get-ADUser $env:USERNAME).Name
    } Else {
        $msWMIAuthor = "Administrator@" + [System.DirectoryServices.ActiveDirectory.Domain]::getcurrentdomain().name
    }

    # Create WMI Filter
    $WMIGUID = [string]"{"+([System.Guid]::NewGuid())+"}"
    $WMIDN = "CN=" + $WMIGUID+",CN=SOM,CN=WMIPolicy,CN=System," + $ADDN
    $WMICN = $WMIGUID
    $WMIdistinguishedname = $WMIDN
    $WMIID = $WMIGUID
 
    $now = (Get-Date).ToUniversalTime()
    $msWMICreationDate = ($now.Year).ToString("0000") + ($now.Month).ToString("00") + ($now.Day).ToString("00") + ($now.Hour).ToString("00") + ($now.Minute).ToString("00") + ($now.Second).ToString("00") + "." + ($now.Millisecond * 1000).ToString("000000") + "-000" 
    $msWMIName = $WMIFilter[0]
    $msWMIParm1 = $WMIFilter[1] + " "
    $msWMIParm2 = "1;3;10;" + $WMIFilter[3].Length.ToString() + ";WQL;" + $WMIFilter[2] + ";" + $WMIFilter[3] + ";"

    # msWMI-Name: The friendly name of the WMI filter
    # msWMI-Parm1: The description of the WMI filter
    # msWMI-Parm2: The query and other related data of the WMI filter
    $Attr = @{"msWMI-Name" = $msWMIName;"msWMI-Parm1" = $msWMIParm1;"msWMI-Parm2" = $msWMIParm2;"msWMI-Author" = $msWMIAuthor;"msWMI-ID"=$WMIID;"instanceType" = 4;"showInAdvancedViewOnly" = "TRUE";"distinguishedname" = $WMIdistinguishedname;"msWMI-ChangeDate" = $msWMICreationDate; "msWMI-CreationDate" = $msWMICreationDate} 
    $WMIPath = ("CN=SOM,CN=WMIPolicy,CN=System," + $ADDN) 
    $ExistingWMIFilters = Get-ADObject -Filter 'objectClass -eq "msWMI-Som"' -Properties "msWMI-Name","msWMI-Parm1","msWMI-Parm2"
    $array = @()

    If ($ExistingWMIFilters -ne $NULL) 
    {
        foreach ($ExistingWMIFilter in $ExistingWMIFilters) { $array += $ExistingWMIFilter."msWMI-Name" }
    } 
    Else 
    {
        $array += "no filters"
    }

    Report-Status "Creating the $msWMIName WMI Filter" 1 Green
    if ($array -notcontains $msWMIName) 
    {
        $WMIFilterADObject = New-ADObject -name $WMICN -type "msWMI-Som" -Path $WMIPath -OtherAttributes $Attr
    } 
    Else 
    {
        Report-Status "The $msWMIName WMI Filter already exists." 2 Yellow
    }
    
    $WMIFilterADObject = $NULL

    # Get WMI filter
    $WMIFilterADObject = Get-ADObject -Filter 'objectClass -eq "msWMI-Som"' -Properties "msWMI-Name","msWMI-Parm1","msWMI-Parm2" | Where {$_."msWMI-Name" -eq "$msWMIName"}

    Report-Status "Creating the $GPOName Group Policy Object" 1 Green
    $ExistingGPO = get-gpo $GPOName -ea "SilentlyContinue"   
  
    If ($ExistingGPO -eq $NULL) 
    {

        # Create new GPO shell
        $GPO = New-GPO -Name $GPOName

        # Disable User Settings
        $GPO.GpoStatus = "UserSettingsDisabled"

        # Add the WMI Filter
        $GPO.WmiFilter = ConvertTo-WmiFilter $WMIFilterADObject

        # Set the three registry keys in the Preferences section of the new GPO
        Set-GPPrefRegistryValue -Name $GPOName -Action Update -Context Computer -Key "HKLM\SYSTEM\CurrentControlSet\Services\W32Time\Config" -Type DWord -ValueName "AnnounceFlags" -Value $AnnounceFlags | out-null
        Set-GPPrefRegistryValue -Name $GPOName -Action Update -Context Computer -Key "HKLM\SYSTEM\CurrentControlSet\Services\W32Time\Parameters" -Type String -ValueName "NtpServer" -Value "$NtpServer" | out-null
        Set-GPPrefRegistryValue -Name $GPOName -Action Update -Context Computer -Key "HKLM\SYSTEM\CurrentControlSet\Services\W32Time\Parameters" -Type String -ValueName "Type" -Value "$Type" | out-null

        # Disable the Hyper-V time synchronization integration service.
        If ($DisableHyperVTimeSynchronization) 
        {
            Set-GPPrefRegistryValue -Name $GPOName -Action Update -Context Computer -Key "HKLM\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\VMICTimeProvider" -Type DWord -ValueName "Enabled" -Value 0 | out-null
        }

        # Link the new GPO to the Domain Controllers OU
        Report-Status "Linking the $GPOName Group Policy Object to $DomainControllersOU" 1 Green
        $Result = New-GPLink -Name $GPOName -Target "$DomainControllersOU"
    } 
    Else 
    {
        Report-Status "The $GPOName Group Policy Object already exists." 2 Yellow
        Report-Status "Applying the $msWMIName WMI Filter" 1 Green
        $ExistingGPO.WmiFilter = ConvertTo-WmiFilter $WMIFilterADObject
    }
    $ObjectExists = $NULL
}

#----------------------------------------------------[ Execution ]-----------------------------------------------------

# Create OU Structure
New-ADOrganizationalUnit -Name $RootOU
New-ADOrganizationalUnit -Name "Groups" -Path "OU=$RootOU,$ADDN"
New-ADOrganizationalUnit -Name "Messaging" -Path "OU=$RootOU,$ADDN"
New-ADOrganizationalUnit -Name "Servers" -Path "OU=$RootOU,$ADDN"
New-ADOrganizationalUnit -Name "Staging" -Path "OU=$RootOU,$ADDN"
New-ADOrganizationalUnit -Name "Systems" -Path "OU=$RootOU,$ADDN"
New-ADOrganizationalUnit -Name "Users" -Path "OU=$RootOU,$ADDN"
New-ADOrganizationalUnit -Name "Workstations" -Path "OU=$RootOU,$ADDN"

New-ADOrganizationalUnit -Name "Apps" -Path "OU=Groups,OU=$RootOU,$ADDN"
New-ADOrganizationalUnit -Name "Files" -Path "OU=Groups,OU=$RootOU,$ADDN"

New-ADOrganizationalUnit -Name "Contacts" -Path "OU=Messaging,OU=$RootOU,$ADDN"
New-ADOrganizationalUnit -Name "DistLists" -Path "OU=Messaging,OU=$RootOU,$ADDN"
New-ADOrganizationalUnit -Name "Rooms" -Path "OU=Messaging,OU=$RootOU,$ADDN"


New-ADOrganizationalUnit -Name "Mgmt" -Path "OU=Servers,OU=$RootOU,$ADDN"
New-ADOrganizationalUnit -Name "PKI" -Path "OU=Servers,OU=$RootOU,$ADDN"
New-ADOrganizationalUnit -Name "SQL" -Path "OU=Servers,OU=$RootOU,$ADDN"
New-ADOrganizationalUnit -Name "Web" -Path "OU=Servers,OU=$RootOU,$ADDN"

New-ADOrganizationalUnit -Name "Admins" -Path "OU=Systems,OU=$RootOU,$ADDN"
New-ADOrganizationalUnit -Name "Tasks" -Path "OU=Systems,OU=$RootOU,$ADDN" -Description "Tasks delegation groups"
New-ADOrganizationalUnit -Name "Services" -Path "OU=Systems,OU=$RootOU,$ADDN" -Description "Unmanaged Service Accounts"

New-ADOrganizationalUnit -Name "Archives" -Path "OU=Users,OU=$RootOU,$ADDN"
New-ADOrganizationalUnit -Name "Consultants" -Path "OU=Users,OU=$RootOU,$ADDN"
New-ADOrganizationalUnit -Name "Employees" -Path "OU=Users,OU=$RootOU,$ADDN"

# Display OU Structure Summary
Get-ADOrganizationalUnit -Searchbase "OU=$RootOU,$ADDN" -Filter * -properties CanonicalName | Select CanonicalName | Sort CanonicalName

# Redirect default OU to Staging for all objects
redirusr ("OU=Staging,OU=$RootOU,$ADDN")
redircmp ("OU=Staging,OU=$RootOU,$ADDN")

# Create Emtpy GPOs
New-GPO "SYST-Global_Sec" -Comment "Global Security Settings" | New-GPLink -Target $ADDN
New-GPO "SYST-Global_Pol" -Comment "Global Policies Settings" | New-GPLink -Target $ADDN
New-GPO "SYST-DomainControllers_Sec" -Comment "Domain Controllers Security Settings" | New-GPLink -Target $DomainControllersOU
New-GPO "SYST-DomainControllers_Pol" -Comment "Domain Controllers Policies Settings" | New-GPLink -Target $DomainControllersOU

New-GPO "SYST-$RootOU-Servers_Sec" -Comment "Domain Controllers Security Settings" | New-GPLink -Target "OU=Servers,OU=$RootOU,$ADDN"
New-GPO "SYST-$RootOU-Servers_Pol" -Comment "Domain Controllers Security Settings" | New-GPLink -Target "OU=Servers,OU=$RootOU,$ADDN"

Create-TimeSyncGPO "$PDCeGPOName" "$TimeServers" 5 "NTP" $PDCeWMIFilter
Create-TimeSyncGPO "$NonPDCeGPOName" "" 10 "NT5DS" $NonPDCeWMIFilter

# Create Tasks groups
New-ADGroup -Name "T-DHCP_Administration" -SamAccountName "T-DHCP_Administration" -GroupCategory Security -GroupScope Global -DisplayName "T-DHCP_Administration" -Path "OU=Tasks,OU=Systems,OU=$RootOU,$ADDN" -Description "[TASKS] DHCP Administration"
New-ADGroup -Name "T-DNS_Administration" -SamAccountName "T-DNS_Administration" -GroupCategory Security -GroupScope Global -DisplayName "T-DNS_Administration" -Path "OU=Tasks,OU=Systems,OU=$RootOU,$ADDN" -Description "[TASKS] DNS Administration"
New-ADGroup -Name "T-GPO_Administration" -SamAccountName "T-GPO_Administration" -GroupCategory Security -GroupScope Global -DisplayName "T-GPO_Administration" -Path "OU=Tasks,OU=Systems,OU=$RootOU,$ADDN" -Description "[TASKS] GPO Administration"

New-ADGroup -Name "T-MemberServers_Administration" -SamAccountName "T-MemberServers_Administration" -GroupCategory Security -GroupScope Global -DisplayName "T-MemberServers_Administration" -Path "OU=Tasks,OU=Systems,OU=$RootOU,$ADDN" -Description "[TASKS] Member Servers Administration"

New-ADGroup -Name "T-AD-Groups_Administration" -SamAccountName "T-AD-Groups_Administration" -GroupCategory Security -GroupScope Global -DisplayName "T-AD-Groups_Administration" -Path "OU=Tasks,OU=Systems,OU=$RootOU,$ADDN" -Description "[TASKS] Active Directory Groups Administration"
New-ADGroup -Name "T-AD-Users_Administration" -SamAccountName "T-AD-Users_Administration" -GroupCategory Security -GroupScope Global -DisplayName "T-AD-Users_Administration" -Path "OU=Tasks,OU=Systems,OU=$RootOU,$ADDN" -Description "[TASKS] Active Directory Users Administration"
New-ADGroup -Name "T-AD-Workstations_Administration" -SamAccountName "T-AD-Workstations_Administration" -GroupCategory Security -GroupScope Global -DisplayName "T-AD-Workstations_Administration" -Path "OU=Tasks,OU=Systems,OU=$RootOU,$ADDN" -Description "[TASKS] Active Directory Workstations Administration"

New-ADGroup -Name "T-LAPS_MemberServers" -SamAccountName "T-LAPS_MemberServers" -GroupCategory Security -GroupScope Global -DisplayName "T-LAPS_MemberServers" -Path "OU=Tasks,OU=Systems,OU=$RootOU,$ADDN" -Description "[TASKS] LAPS for Member Servers Administration"
New-ADGroup -Name "T-LAPS_Workstations" -SamAccountName "T-LAPS_Workstations" -GroupCategory Security -GroupScope Global -DisplayName "T-LAPS_Workstations" -Path "OU=Tasks,OU=Systems,OU=$RootOU,$ADDN" -Description "[TASKS] LAPS for Workstations Administration"

# Delegate AD Tasks to Tasks groups
# Enable AD Recycle Bin
# Configure and deploy LAPS
