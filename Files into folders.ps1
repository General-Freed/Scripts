$Start = Read-Host "Anfangsdatum"
$End = Read-Host "Enddatum"
$Target = Read-Host "Verzeichnis"

$StartDate = $Start.ToDate()
$EndDate = $End.ToDate()

$files = Get-ChildItem "C:\files\"

for each($f in $files) {
if ($f.CreationTime -ge $StartDate -and $f.CreationTime -le $EndDate) {
$f.movefile($Target)
}
}

get-childitem -filter 