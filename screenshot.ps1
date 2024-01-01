# $File = "C:\Users\ferreirasc\Desktop\Screenshot1.bmp"; Add-Type -AssemblyName System.Windows.Forms; Add-type -AssemblyName System.Drawing; $Screen = [System.Windows.Forms.SystemInformation]::VirtualScreen; $Width = $Screen.Width; $Height = $Screen.Height; $Left = $Screen.Left; $Top = $Screen.Top; $bitmap = New-Object System.Drawing.Bitmap $Width, $Height; $graphic = [System.Drawing.Graphics]::FromImage($bitmap); $graphic.CopyFromScreen($Left, $Top, 0, 0, $bitmap.Size); $bitmap.Save($File)

$File = "C:\Users\ferreirasc\Desktop\Screenshot1.bmp"
Add-Type -AssemblyName System.Windows.Forms
Add-type -AssemblyName System.Drawing
$Screen = [System.Windows.Forms.SystemInformation]::VirtualScreen
$Width = $Screen.Width
$Height = $Screen.Height
$Left = $Screen.Left
$Top = $Screen.Top
$bitmap = New-Object System.Drawing.Bitmap $Width, $Height
$graphic = [System.Drawing.Graphics]::FromImage($bitmap)
$graphic.CopyFromScreen($Left, $Top, 0, 0, $bitmap.Size)
$bitmap.Save($File)