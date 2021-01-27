#======================================================================================
# Enable TLS 1.2
#======================================================================================

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

#======================================================================================
# Set console color scheme
#======================================================================================
#New-Item HKCU:\Console\%systemroot%_System32_WindowsPowerShell_v1.0_powershell.exe -force | Set-ItemProperty -Name ColorTable00 -Value 0x00562401 -PassThru | Set-ItemProperty -Name ColorTable07 -Value 0x00f0edee

$console = $host.ui.rawui
$console.BackgroundColor = 'Black'
$console.ForegroundColor = 'White'
$colors = $Host.PrivateData
$colors.ErrorForegroundColor = 'Red'
$colors.ErrorBackgroundColor = 'Black'
$colors.WarningForegroundColor = 'Yellow'
$colors.WarningBackgroundColor = 'Black'
$colors.DebugForegroundColor = 'Yellow'
$colors.DebugBackgroundColor = 'Black'
$colors.VerboseForegroundColor = 'Green'
$colors.VerboseBackgroundColor = 'Black'
$colors.ProgressForegroundColor = 'Gray'
$colors.ProgressBackgroundColor = 'Black'
Clear-Host

#======================================================================================
# Ctrl-Tab to show matching commands/available parameters
#======================================================================================

Set-PSReadlineKeyHandler -Chord CTRL+Tab -Function Complete
Set-PSReadlineOption -ShowToolTips -BellStyle Visual

#======================================================================================
# General Helper Functions
#======================================================================================

function reboot { shutdown /r /t 0 }
function halt { shutdown /s /t 0 }
function Edit-Profile() { notepad $PROFILE.AllUsersAllHosts }
function Clear-Logs { wevtutil el | % {wevtutil cl $_} }

#======================================================================================
# Start Elevated session
#======================================================================================

function Test-Administrator {  
  $user = [Security.Principal.WindowsIdentity]::GetCurrent()
  (New-Object Security.Principal.WindowsPrincipal $user).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)  
}

function Start-PsElevatedSession { 
  #Open a new elevated powershell window
  If ( ! (Test-Administrator) ) {
    start-process powershell -Verb runas
  }
  Else { Write-Warning "Session is already elevated" }
} 

#======================================================================================

function Get-MOTD {
    # Perform WMI Queries
    $Wmi_OperatingSystem = Get-WmiObject -Query 'Select lastbootuptime,TotalVisibleMemorySize,FreePhysicalMemory,caption,version From win32_operatingsystem'
    $Wmi_Processor = Get-WmiObject -Query 'Select Name,LoadPercentage From Win32_Processor'
    $Wmi_LogicalDisk = Get-WmiObject -Query 'Select Size,FreeSpace From Win32_LogicalDisk Where DeviceID="C:"'

    # Assign variables
    $Date = Get-Date
    $OS = $Wmi_Operatingsystem.Caption
    $Kernel = $Wmi_Operatingsystem.Version
    $Uptime = "$(($Uptime = $Date - $Wmi_Operatingsystem.ConvertToDateTime($Wmi_Operatingsystem.LastBootUpTime)).Days) days, $($Uptime.Hours) hours, $($Uptime.Minutes) minutes"
    $Shell = "{0}.{1}" -f $PSVersionTable.PSVersion.Major,$PSVersionTable.PSVersion.Minor
    $CPU = $Wmi_Processor.Name -replace '\(C\)', '' -replace '\(R\)', '' -replace '\(TM\)', '' -replace 'CPU', '' -replace '\s+', ' '
    $Processes = (Get-Process).Count
    $CurrentLoad = $Wmi_Processor.LoadPercentage
    $Memory = "{0}mb/{1}mb Used" -f (([math]::round($Wmi_Operatingsystem.TotalVisibleMemorySize/1KB))-([math]::round($Wmi_Operatingsystem.FreePhysicalMemory/1KB))),([math]::round($Wmi_Operatingsystem.TotalVisibleMemorySize/1KB))
    $Disk = "{0}gb/{1}gb Used" -f (([math]::round($Wmi_LogicalDisk.Size/1GB))-([math]::round($Wmi_LogicalDisk.FreeSpace/1GB))),([math]::round($Wmi_LogicalDisk.Size/1GB))

    Write-Host ("")
    Write-Host ("")
    Write-Host ("         ,.=:^!^!t3Z3z.,                  ") -ForegroundColor Red
    Write-Host ("        :tt:::tt333EE3                    ") -ForegroundColor Red
    Write-Host ("        Et:::ztt33EEE ") -NoNewline -ForegroundColor Red
    Write-Host (" @Ee.,      ..,     ") -NoNewline -ForegroundColor Green
    Write-Host $Date -ForegroundColor Green
    Write-Host ("       ;tt:::tt333EE7") -NoNewline -ForegroundColor Red
    Write-Host (" ;EEEEEEttttt33#     ") -ForegroundColor Green
    Write-Host ("      :Et:::zt333EEQ.") -NoNewline -ForegroundColor Red
    Write-Host (" SEEEEEttttt33QL     ") -NoNewline -ForegroundColor Green
    Write-Host ("User: ") -NoNewline -ForegroundColor Red
    Write-Host ("$env:username") -ForegroundColor Cyan
    Write-Host ("      it::::tt333EEF") -NoNewline -ForegroundColor Red
    Write-Host (" @EEEEEEttttt33F      ") -NoNewline -ForeGroundColor Green
    Write-Host ("Hostname: ") -NoNewline -ForegroundColor Red
    Write-Host ("$env:computername") -ForegroundColor Cyan
    Write-Host ("     ;3=*^``````'*4EEV") -NoNewline -ForegroundColor Red
    Write-Host (" :EEEEEEttttt33@.      ") -NoNewline -ForegroundColor Green
    Write-Host ("OS: ") -NoNewline -ForegroundColor Red
    Write-Host $OS -ForegroundColor Cyan
    Write-Host ("     ,.=::::it=., ") -NoNewline -ForegroundColor Cyan
    Write-Host ("``") -NoNewline -ForegroundColor Red
    Write-Host (" @EEEEEEtttz33QF       ") -NoNewline -ForegroundColor Green
    Write-Host ("Kernel: ") -NoNewline -ForegroundColor Red
    Write-Host ("NT ") -NoNewline -ForegroundColor Cyan
    Write-Host $Kernel -ForegroundColor Cyan
    Write-Host ("    ;::::::::zt33) ") -NoNewline -ForegroundColor Cyan
    Write-Host ("  '4EEEtttji3P*        ") -NoNewline -ForegroundColor Green
    Write-Host ("Uptime: ") -NoNewline -ForegroundColor Red
    Write-Host $Uptime -ForegroundColor Cyan
    Write-Host ("   :t::::::::tt33.") -NoNewline -ForegroundColor Cyan
    Write-Host (":Z3z.. ") -NoNewline -ForegroundColor Yellow
    Write-Host (" ````") -NoNewline -ForegroundColor Green
    Write-Host (" ,..g.        ") -NoNewline -ForegroundColor Yellow
    Write-Host ("Shell: ") -NoNewline -ForegroundColor Red
    Write-Host ("Powershell $Shell") -ForegroundColor Cyan
    Write-Host ("   i::::::::zt33F") -NoNewline -ForegroundColor Cyan
    Write-Host (" AEEEtttt::::ztF         ") -NoNewline -ForegroundColor Yellow
    Write-Host ("CPU: ") -NoNewline -ForegroundColor Red
    Write-Host $CPU -ForegroundColor Cyan
    Write-Host ("  ;:::::::::t33V") -NoNewline -ForegroundColor Cyan
    Write-Host (" ;EEEttttt::::t3          ") -NoNewline -ForegroundColor Yellow
    Write-Host ("Processes: ") -NoNewline -ForegroundColor Red
    Write-Host $Processes -ForegroundColor Cyan
    Write-Host ("  E::::::::zt33L") -NoNewline -ForegroundColor Cyan
    Write-Host (" @EEEtttt::::z3F          ") -NoNewline -ForegroundColor Yellow
    Write-Host ("Current Load: ") -NoNewline -ForegroundColor Red
    Write-Host $CurrentLoad -NoNewline -ForegroundColor Cyan
    Write-Host ("%") -ForegroundColor Cyan
    Write-Host (" {3=*^``````'*4E3)") -NoNewline -ForegroundColor Cyan
    Write-Host (" ;EEEtttt:::::tZ``          ") -NoNewline -ForegroundColor Yellow
    Write-Host ("Memory: ") -NoNewline -ForegroundColor Red
    Write-Host $Memory -ForegroundColor Cyan
    Write-Host ("             ``") -NoNewline -ForegroundColor Cyan
    Write-Host (" :EEEEtttt::::z7            ") -NoNewline -ForegroundColor Yellow
    Write-Host ("Disk: ") -NoNewline -ForegroundColor Red
    Write-Host $Disk -ForegroundColor Cyan
    Write-Host ("                 'VEzjt:;;z>*``           ") -ForegroundColor Yellow
    Write-Host ("                      ````                  ") -ForegroundColor Yellow
    Write-Host ("")
}

#======================================================================================
# 'Go' command and targets
#======================================================================================

$GLOBAL:go_locations = @{ }

if ( $GLOBAL:go_locations -eq $null ) {
  $GLOBAL:go_locations = @{ }
}

function Go ([string] $location) {
  if ( $go_locations.ContainsKey($location) ) {
    set-location $go_locations[$location];
  }
  else {
    write-output "The following locations are defined:";
    write-output $go_locations;
  }
}
$go_locations.Add("home", (get-item ([environment]::GetFolderPath("MyDocuments"))).Parent.FullName)
$go_locations.Add("desktop", [environment]::GetFolderPath("Desktop"))
$go_locations.Add("dl", ((New-Object -ComObject Shell.Application).NameSpace('shell:Downloads').Self.Path))
$go_locations.Add("docs", [environment]::GetFolderPath("MyDocuments"))
$go_locations.Add("scripts", "C:\Scripts")

#======================================================================================
# Custom prompt
#======================================================================================

function Global:Prompt {
  $Time = Get-Date -Format "HH:mm"
  $Directory = (Get-Location).Path
    
  Write-Host "[$((Get-History).Count + 1)] " -NoNewline
  Write-Host "[$Time] " -ForegroundColor Yellow -NoNewline
  Write-Host "$Directory >" -NoNewline

  return " "
}

#======================================================================================
# Define aliases
#======================================================================================

Set-Alias -name su -Value Start-PsElevatedSession
Set-Alias -Name ff -Value Find-Files 
Set-Alias -name ih -value invoke-history

#======================================================================================
# Final execution
#======================================================================================
Set-ExecutionPolicy RemoteSigned -Force
Go scripts

#======================================================================================
# Some Sysadmin sillyness
#======================================================================================

Get-MOTD

Write-Host $block -ForegroundColor Green
