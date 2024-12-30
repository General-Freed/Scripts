write-host "Disable Services"

$services = @("BITS","BTAGService","bthserv","lfsvc","DiagTrack","HvHost","vmickvpexchange","vmicguestinterface","vmicshutdown","vmicheartbeat","vmicvmsession","vmicrdv","vmictimesync","vmicvss","PhoneSvc","Spooler","QWAVE","SysMain","WSearch")

foreach($s in $services) {
    #get-service $s | FT status,name,start*
    Set-Service $s -StartupType Disabled
}

#Auto: DiagTrack, Spooler, SysMain

write-host "Deactivate Devices"

$devices = @("Enumerator für virtuelle NDIS-Netzwerkadapter","Microsoft virtueller Datenträgerenumerator","Hochpräzisionsereigniszeitgeber","Redirector-Bus für Remotedesktop-Gerät")

foreach($d in $devices) {

    Get-PnpDevice | ? Friendly name -eq $d | Disable-PnpDevice -Confirm:$false

}

write-host "Reg Keys"

set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\" -Name "SystemResponsiveness" -Value 0

set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "Priority" -Value 6

set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "GPU Priority" -Value 8

set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl" -Name "Win32PrioritySeparation" -Value 1

Write-Host "Swap File 32GB"

$pagefile = Get-CimInstance -ClassName Win32_ComputerSystem
$pagefile.AutomaticManagedPagefile = $false
Set-CimInstance -InputObject $pagefile

$pagefileset = Get-CimInstance -ClassName Win32_PageFileSetting | Where-Object {$_.name -eq "$ENV:SystemDrive\pagefile.sys"}
$pagefileset.InitialSize = 32767
$pagefileset.MaximumSize = 32767
Set-CimInstance -InputObject $pagefileset

write-host "System Restore activate"
Enable-ComputerRestore -Drive "C:\"
