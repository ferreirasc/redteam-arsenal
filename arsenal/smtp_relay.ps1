$From = "<spoof>"
$To = "<email>"
$Subject = "my test"
$Body = "test"

$SMTPServer = "<server>"
$SMTPPort = 587
$SMTPUsername = "<email>"
$SMTPPassword = ""

$credential = (New-Object System.Management.Automation.PSCredential ($SMTPUsername, (ConvertTo-SecureString $SMTPPassword -AsPlainText -Force)))

Send-MailMessage -From $From -To $To -Subject $Subject -Body $Body -SmtpServer $SMTPServer -Port $SMTPPort -Credential $credential
