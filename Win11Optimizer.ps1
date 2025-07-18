#
#    Optimizes Win11 by disabling unneeded Stuff
#    Input: None
#    i.e. Run Script ;-)
#

write-host "Disable Services"
$services = @("BITS","BTAGService","bthserv","lfsvc","DiagTrack","HvHost","vmickvpexchange","vmicguestinterface","vmicshutdown","vmicheartbeat","vmicvmsession","vmicrdv","vmictimesync","vmicvss","PhoneSvc","Spooler","QWAVE","SysMain","WSearch","termService","dmwappushservice","DiagTrack")
foreach($s in $services) {
    Get-Service $s | FT Displayname,Status -HideTableHeader
    Get-Service $s | Set-Service -StartupType Disabled
}

#write-host "Remove Apps"
write-host "Remove GameBar and all the Glory that comes with it"
Get-AppxPackage -AllUsers Microsoft.XboxGamingOverlay | Remove-AppxPackage
set-ItemProperty -Path "HKLM:SOFTWARE\Classes\ms-gamebar\" -Type REG_SZ -Name "NoOpenWith" -Value " "
set-ItemProperty -Path "HKLM:SOFTWARE\Classes\ms-gamebar\" -Type REG_SZ -Name "URL Protocol" -Value " "
set-ItemProperty -Path "HKLM:SOFTWARE\Classes\ms-gamebar\shell\open\command\" -Type REG_SZ -Name "(default)" -Value "$env:SystemRoot\System32\systray.exe"
set-ItemProperty -Path "HKLM:SOFTWARE\Classes\ms-ms-gamebarservices\" -Type REG_SZ -Name "NoOpenWith" -Value " "
set-ItemProperty -Path "HKLM:SOFTWARE\Classes\ms-ms-gamebarservices\" -Type REG_SZ -Name "URL Protocol" -Value " "
set-ItemProperty -Path "HKLM:SOFTWARE\Classes\ms-ms-gamebarservices\shell\open\command\" -Type REG_SZ -Name "(default)" -Value "$env:SystemRoot\System32\systray.exe"

Write-Host "VM platform Disable"
Disable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-Hypervisor

#set-ItemProperty -Path "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\" -Type REG_DWORD -Name "Enabled" -Value 0

write-host "Disable Suggested Notifications -> Needs Verification"
#set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.ActionCenter.SmartOptOut\" -Type DWORD -Name "Enabled" -Value 0

Write-Host "Enable AutoTray -> Needs Verification"
#set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\" -Type DWORD -Name "EnableAutoTray" -Value 1

Write-Host "Enable Hibernate"
set-Itemproperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power" -Type DWORD Name "HibernateEnabled" -Value 1

write-host "Deactivate Devices"
#$devices = @("Enumerator für virtuelle NDIS-Netzwerkadapter","Microsoft virtueller Datenträgerenumerator","Redirector-Bus für Remotedesktop-Gerät")
$devices = @("ROOT\NDISVIRTUALBUS\0000","ROOT\VDRVROOT\0000","ROOT\RDPBUS\0000","ACPI\PNP0103\*") #,"ACPI\PNP0103\*" <-- "Hochpräzisionsereigniszeitgeber"
foreach($d in $devices) {
    Get-PnpDevice $d | ft InstanceID,Friendlyname -HideTableHeader
    Get-PnpDevice -InstanceId $d | Disable-PnpDevice -Confirm:$false
}

write-host "Reg Keys"
set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\" -Type DWORD -Name "SystemResponsiveness" -Value 0 # --> Default: 20
set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\" -Type DWORD -Name "NetworkThrottlingIndex" -Value 0xffffffff # --> Default: 10
set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Type DWORD -Name "Priority" -Value 6 # --> Default: 2
set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Type DWORD -Name "GPU Priority" -Value 8 # --> Default: 2
set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Type String -Name "Scheduling Category" -Value "High" # -->Default: Medium
set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Type String -Name "SFIO Priority" -Value "High" # --> Default: Normal
set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl" -Type DWORD -Name "Win32PrioritySeparation" -Value 22 #20/24/42 --> Default: 2
set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios" -Type DWORD -Name "HypervisorEnforcedCodeIntegrity" -Value 0  #CoreIsolation # --> Default: N/A
set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" -Type DWORD -Name "SearchOrderConfig" -Value 0  #DriverSearch -> Default: 1
set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" -Type DWORD -Name "EnablePrefetcher" -Value 0  #WinPrefetch # --> Default: 3
# ?!? P0 State GPU
set-itemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" -Type DWORD -Name "DisableDynamicPstate" -Value 1

set-itemproperty -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" -Type DWORD -Name "AppCaptureEnabled" -Value 0

Write-Host "Swap File Manual Size"
$pagefile = Get-CimInstance -ClassName Win32_ComputerSystem
$pagefile.AutomaticManagedPagefile = $false
Set-CimInstance -InputObject $pagefile

Write-Host "Swap File Size 32GB"
$pagefileset = Get-CimInstance -ClassName Win32_PageFileSetting | Where-Object {$_.name -eq "$ENV:SystemDrive\pagefile.sys"}
$pagefileset.InitialSize = 32778    # 32GB + 10MB
$pagefileset.MaximumSize = 32778
Set-CimInstance -InputObject $pagefileset

write-host "System Restore activate"
Enable-ComputerRestore -Drive "C:\"
