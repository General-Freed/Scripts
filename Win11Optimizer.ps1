write-host "Disable Services"
$services = @("BITS","BTAGService","bthserv","lfsvc","DiagTrack","HvHost","vmickvpexchange","vmicguestinterface","vmicshutdown","vmicheartbeat","vmicvmsession","vmicrdv","vmictimesync","vmicvss","PhoneSvc","Spooler","QWAVE","SysMain","WSearch")
foreach($s in $services) {
    Get-Service $s | FT Displayname,Status -HideTableHeader
    Get-Service $s | Set-Service -StartupType Disabled
}

write-host "Deactivate Devices"
#$devices = @("Enumerator für virtuelle NDIS-Netzwerkadapter","Microsoft virtueller Datenträgerenumerator","Hochpräzisionsereigniszeitgeber","Redirector-Bus für Remotedesktop-Gerät")
$devices = @("ROOT\NDISVIRTUALBUS\0000","ROOT\VDRVROOT\0000","ACPI\PNP0103\2&DABA3FF&0","ROOT\RDPBUS\0000")
foreach($d in $devices) {
    #Get-PnpDevice | ? Friendly name -eq $d | Disable-PnpDevice -Confirm:$false
    Get-PnpDevice $d | ft InstanceID,Friendlyname -HideTableHeader
    Get-PnpDevice -InstanceId $d | Disable-PnpDevice -Confirm:$false
}

write-host "Reg Keys"
set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\" -Type DWORD -Name "SystemResponsiveness" -Value 0
set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\" -Type DWORD -Name "NetworkThrottlingIndex" -Value 0xffffffff
set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Type DWORD -Name "Priority" -Value 6
set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Type DWORD -Name "GPU Priority" -Value 8
set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl" -Type DWORD -Name "Win32PrioritySeparation" -Value 22 #20/24/42
set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios" -Type DWORD -Name "HypervisorEnforcedCodeIntegrity" -Value 0  #CoreIsolation
set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" -Type DWORD -Name "SearchOrderConfig" -Value 0  #DriverSearch
set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" -Type DWORD -Name "EnablePrefetcher" -Value 0  #WinPrefetch

Write-Host "Swap File Manual Size"
$pagefile = Get-CimInstance -ClassName Win32_ComputerSystem
$pagefile.AutomaticManagedPagefile = $false
Set-CimInstance -InputObject $pagefile

Write-Host "Swap File Size 32GB"
$pagefileset = Get-CimInstance -ClassName Win32_PageFileSetting | Where-Object {$_.name -eq "$ENV:SystemDrive\pagefile.sys"}
$pagefileset.InitialSize = 32767
$pagefileset.MaximumSize = 32767
Set-CimInstance -InputObject $pagefileset

write-host "System Restore activate"
Enable-ComputerRestore -Drive "C:\"
