cls
$path = "E:\TempData"
$destPath = "E:\Duplicates\"

write-host $path

$list = Get-ChildItem -Path $path -File | Get-FileHash -Algorithm MD5 | sort Name,Hash

foreach($x in $list) {
    write-host $x.Path
    if(($list | ? hash -eq $x.hash).Count -gt 1) {
        $smollist = $list | ? hash -eq $x.hash | sort Path -Descending
        #
        for($i=1;$i -lt $smollist.Count; $i++) {
            #write-host $smollist[$i].Path
            #Move-Item -Path $smollist[$i].Path -Destination "E:\Duplicates" -ErrorAction Continue
            $sx = $smollist[$i].Path
            $a = $sx.Split(".")
            $newFile = $destPath
            $newFile += $smollist[$i].hash
            $newFile += "_$i"
            $newFile += "_."  
            $newFile += $a[$a.Count-1]
            
            write-host $smollist[$i].path
            write-host $newFile
            write-host "-----------------------------"
            Move-Item -Path $smollist[$i].Path -Destination $newFile -ErrorAction SilentlyContinue

        }
    }
}

#Get-Unique $duplicates
#$duplicates
