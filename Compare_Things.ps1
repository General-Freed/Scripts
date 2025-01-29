#
#    Compares everything possible in Powershell
#    Input CMDLet and at least 2 Values to compare
#     i.e. Get-Mailbox / UserA / UserB;UserC
#
  
cls
$data = @()
$seperator = $false
$func = Read-Host "CMDlet?"
$std = Read-Host "Standard"
$tmp = Read-Host "Objects ';' seperated"
$obj = $tmp.Split(";")

$call = $func + " " + $std
$stdobj = Invoke-Expression $call
$stdobj = $stdobj.PSObject.Properties

foreach($o in $obj) {
    $call = $func + " " + $o
    $ret = Invoke-Expression $call
    $data += $ret
}

$cnt = $data.Count

foreach($prop in $stdobj) {
    if($prop.Name -notin $exclude) {
        for($i=0;$i -lt $cnt;$i++) {
            if($prop.Value -ne $data[$i].PSObject.Properties.Item($prop.Name).Value) {
                write-host $prop.Name // Standard $prop.Value --> $data[$i].PSObject.Properties.Item("Identity").Value // $data[$i].PSObject.Properties.Item($prop.Name).Value
            }            
        }
        if($seperator -eq $true) {
            write-host "---"
            $seperator = $false
        }

    } 
       
}
