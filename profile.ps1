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

function reboot { shutdown /r /t 5 }
function halt { shutdown /s /t 5 }
function here { Invoke-Item . }
function Find-Files ([string] $glob) { get-childitem -recurse -include $glob }
function Remove-Directory ([string] $glob) { remove-item -recurse -force $glob }
Function Edit-Profile() { vsc $PROFILE.AllUsersAllHosts }

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
Set-Alias -name npp -Value Notepad++.exe
Set-Alias -name vsc -value code
Set-Alias -Name ff -Value Find-Files 
Set-Alias -Name rmd -value Remove-Directory 
Set-Alias -name ih -value invoke-history

#======================================================================================
# Final execution
#======================================================================================
Set-ExecutionPolicy RemoteSigned -Force
Go scripts

#======================================================================================
# Some Sysadmin sillyness
#======================================================================================

$block = @"
 
.     .       .  .   . .   .   . .    +  .
  .     .  :     .    .. :. .___---------___.
       .  .   .    .  :.:. _".^ .^ ^.  '.. :"-_. .                ADMINISTRATIVE WORKSTATION
    .  :       .  .  .:../:            . .^  :.:\.
        .   . :: +. :.:/: .   .    .        . . .:\               Logged in user: $(whoami)
 .  :    .     . _ :::/:               .  ^ .  . .:\              Elevated Privileges: $(Test-Administrator)
  .. . .   . - : :.:./.                        .  .:\
  .      .     . :..|:                    .  .  ^. .:|
    .       . : : ..||        .                . . !:|
  .     . . . ::. ::\(                           . :)/
 .   .     : . : .:.|. ######              .#######::|
  :.. .  :-  : .:  ::|.#######           ..########:|
 .  .  .  ..  .  .. :\ ########          :######## :/
  .        .+ :: : -.:\ ########       . ########.:/
    .  .+   . . . . :.:\. #######       #######..:/
      :: . . . . ::.:..:.\           .   .   ..:/
   .   .   .  .. :  -::::.\.       | |     . .:/
      .  :  .  .  .-:.":.::.\             ..:/
 .      -.   . . . .: .:::.:.\.           .:/
.   .   .  :      : ....::_:..:\   ___.  :/
   .   .  .   .:. .. .  .: :.:.:\       :/
     +   .   .   : . ::. :.:. .:.|\  .:/|
     .         +   .  .  ...:: ..|  --.:|
.      . . .   .  .  . ... :..:.."(  ..)"
 .   .       .      :  .   .: ::/  .  .::\
 
"@
 
Write-Host $block -ForegroundColor Green
