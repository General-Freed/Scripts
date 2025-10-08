#
#    Optimizes Win11 by disabling unneeded Stuff
#    Input: None
#    i.e. Run Script ;-)
#
# ------------------------------------------------------------------------------------------
write-host "Disable Services"
$services = @("BITS","BTAGService","bthserv","lfsvc","DiagTrack","HvHost","vmickvpexchange","vmicguestinterface","vmicshutdown","vmicheartbeat","vmicvmsession","vmicrdv","vmictimesync","vmicvss","PhoneSvc","Spooler","QWAVE","SysMain","WSearch","termService","dmwappushservice","DiagTrack")
foreach($s in $services) {
    Get-Service $s | FT Displayname,Status -HideTableHeader
    Get-Service $s | Set-Service -StartupType Disabled
}


# ------------------------------------------------------------------------------------------
write-host "Remove Apps"
$applist = @("Microsoft.ZuneMusic","Microsoft.BingNews","Microsoft.BingSearch","Microsoft.BingWeather","Microsoft.MicrosoftSolitaireCollection","Microsoft.YourPhone","*Webexperience*")

foreach($app in $Applist) {
    Get-AppxPackage -AllUsers $app | Remove-AppxPackage
}

<#write-host "Remove GameBar and all the Glory that comes with it"
Get-AppxPackage -AllUsers Microsoft.XboxGamingOverlay | Remove-AppxPackage
set-ItemProperty -Path "HKLM:SOFTWARE\Classes\ms-gamebar\" -Type String -Name "NoOpenWith" -Value " "
set-ItemProperty -Path "HKLM:SOFTWARE\Classes\ms-gamebar\" -Type String -Name "URL Protocol" -Value " "
set-ItemProperty -Path "HKLM:SOFTWARE\Classes\ms-gamebar\shell\open\command\" -Type String -Name "(default)" -Value "$env:SystemRoot\System32\systray.exe"
set-ItemProperty -Path "HKLM:SOFTWARE\Classes\ms-ms-gamebarservices\" -Type String -Name "NoOpenWith" -Value " "
set-ItemProperty -Path "HKLM:SOFTWARE\Classes\ms-ms-gamebarservices\" -Type String -Name "URL Protocol" -Value " "
set-ItemProperty -Path "HKLM:SOFTWARE\Classes\ms-ms-gamebarservices\shell\open\command\" -Type String -Name "(default)" -Value "$env:SystemRoot\System32\systray.exe"
#>
# ------------------------------------------------------------------------------------------
Write-Host "VM platform Disable"
Disable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-Hypervisor
# ------------------------------------------------------------------------------------------
write-host "Deactivate Devices"
#$devices = @("Enumerator für virtuelle NDIS-Netzwerkadapter","Microsoft virtueller Datenträgerenumerator","Redirector-Bus für Remotedesktop-Gerät")
$devices = @("ROOT\NDISVIRTUALBUS\0000","ROOT\VDRVROOT\0000","ROOT\RDPBUS\0000","ACPI\PNP0103\*") #,"ACPI\PNP0103\*" <-- "Hochpräzisionsereigniszeitgeber"
foreach($d in $devices) {
    Get-PnpDevice $d | ft InstanceID,Friendlyname -HideTableHeader
    Get-PnpDevice -InstanceId $d | Disable-PnpDevice -Confirm:$false
}
# ------------------------------------------------------------------------------------------
write-host "Reg Keys"
$regkeylist = @()

$ob = @{
    Info = "System Responsiveness / Default 20 -> 0"
    Path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\"
    Type = "DWord"
    Name = "SystemResponsiveness"
    Value = 10
}
$regkeylist += $ob

$ob = @{
    Info = "Network Throttling Index / Default 10 -> 255"
    Path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\"
    Type = "DWord"
    Name = "NetworkThrottlingIndex"
    Value = 0xffffffff
}
$regkeylist += $ob

$ob = @{
    Info = "Gaming Priority / Default 2 -> 6"
    Path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games"
    Type = "DWord"
    Name = "Priority"
    Value = 6
}
$regkeylist += $ob

$ob = @{
    Info = "GPU Priority / Default 2 -> 8"
    Path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games"
    Type = "DWord"
    Name = "GPU Priority"
    Value = 8
}
$regkeylist += $ob

$ob = @{
    Info = "Scheduling Category / Default Medium -> High"
    Path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games"
    Type = "String"
    Name = "Scheduling Category"
    Value = "High"
}
$regkeylist += $ob

$ob = @{
    Info = "SFIO Priority / Default Normal -> High"
    Path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games"
    Type = "String"
    Name = "SFIO Priority"
    Value = "High"
}
$regkeylist += $ob

$ob = @{
    Info = "Background Priority 8"
    Path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games"
    Type = "DWord"
    Name = "BackgroundPriority"
    Value = 1
}
$regkeylist += $ob

$ob = @{
    Info = "Background Only False"
    Path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games"
    Type = "String"
    Name = "Background Only"
    Value = false
}
$regkeylist += $ob

$ob = @{
    Info = "Core Isolation / Default 2 -> 22"
    Path = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios"
    Type = "DWORD"
    Name = "HypervisorEnforcedCodeIntegrity"
    Value = 0
}
$regkeylist += $ob

$ob = @{
    Info = "Driver Searching / Default 1 -> 0"
    Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching"
    Type = "DWORD"
    Name = "SearchOrderConfig"
    Value = 0
}
$regkeylist += $ob

$ob = @{
    Info = "Prefetch Disable / Default 3 -> 0"
    Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters"
    Type = "DWORD"
    Name = "EnablePrefetcher"
    Value = 0
}
$regkeylist += $ob

$ob = @{
    Info = "Enable Hibernate"
    Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Power"
    Type = "DWORD"
    Name = "HibernateEnabled"
    Value = 1
}
$regkeylist += $ob

$ob = @{
    Info = "Disable BING Search Suggestions"
    Path = "HKCU:\Software\Policies\Microsoft\Windows\Explorer"
    Type = "DWORD"
    Name = "DisableSearchBoxSuggestions"
    Value = 1
}
$regkeylist += $ob

$ob = @{
    Info = "Disable dynamic Searching"
    Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\SearchSettings"
    Type = "DWORD"
    Name = "IsDynamicSearchBoxEnabled"
    Value = 0
}
$regkeylist += $ob

$ob = @{
    Info = "Disable Suggested Notifications"
    Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.ActionCenter.SmartOptOut\"
    Type = "DWORD"
    Name = "Enabled"
    Value = 0
}
$regkeylist += $ob

$ob = @{
    Info = "Device Guard"
    Path = "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\"
    Type = "DWORD"
    Name = "Enabled"
    Value = 0
}
$regkeylist += $ob


foreach ($reg in $regkeylist) {
    write-host $reg.Info
    write-host get-itemproperty -Path $reg.path -Name $reg.name
    if(get-itemproperty -Path $reg.path -Name $reg.name -ErrorAction SilentlyContinue) {
        set-itemproperty -path $reg.path -Type $reg.type -Name $reg.name -Value $reg.value
    } else {
        new-itemproperty -path $reg.path -Type $reg.type -Name $reg.name -Value $reg.value
    }
}

# ------------------------------------------------------------------------------------------
Write-Host "Swap File Manual Size"
$pagefile = Get-CimInstance -ClassName Win32_ComputerSystem
$pagefile.AutomaticManagedPagefile = $false
Set-CimInstance -InputObject $pagefile

Write-Host "Swap File Size 32GB"
$pagefileset = Get-CimInstance -ClassName Win32_PageFileSetting | Where-Object {$_.name -eq "$ENV:SystemDrive\pagefile.sys"}
$pagefileset.InitialSize = 32778    # 32GB + 10MB
$pagefileset.MaximumSize = 32778
Set-CimInstance -InputObject $pagefileset

# ------------------------------------------------------------------------------------------
write-host "System Restore activate"
Enable-ComputerRestore -Drive "C:\"


