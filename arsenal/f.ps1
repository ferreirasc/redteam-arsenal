function glissandos {
    [CmdletBinding()]
    Param (
        [String]
        $ModuleName = [Guid]::NewGuid().ToString()
    )
    foreach ($Assembly in [System.AppDomain]::CurrentDomain.GetAssemblies()) {
        if ($Assembly.FullName -and ($Assembly.FullName.Split(',')[0] -eq $ModuleName)) {
            return $Assembly
        }
    }
    $AppDomain = [Reflection.Assembly].Assembly.GetType('System.AppDomain').GetProperty('CurrentDomain').GetValue($null, @())
    $Assembly = New-Object -TypeName System.Reflection.AssemblyName -ArgumentList $ModuleName
    $AssemblyBuilder = $AppDomain.DefineDynamicAssembly($Assembly, 'Run')
    $DynamicModule = $AssemblyBuilder.DefineDynamicModule($ModuleName, $false)
    return $DynamicModule
}
function predictions {
    [OutputType([Type])]
    Param (
        [Parameter(Position = 0, Mandatory = $true)]
        [ValidateScript( { ($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly]) })]
        $Module,
        [Parameter(Position = 1, Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $FullName,
        [Parameter(Position = 2, Mandatory = $true)]
        [Type]
        $Type,
        [Parameter(Position = 3, Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [Hashtable]
        $EnumElements,
        [Switch]
        $Bitfield
    )
    if ($Module -is [Reflection.Assembly]) {
        return ($Module.GetType($FullName))
    }
    $EnumType = $Type -as [Type]
    $EnumBuilder = $Module.DefineEnum($FullName, 'Public', $EnumType)
    if ($Bitfield) {
        $FlagsConstructor = [FlagsAttribute].GetConstructor(@())
        $FlagsCustomAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($FlagsConstructor, @())
        $EnumBuilder.SetCustomAttribute($FlagsCustomAttribute)
    }
    foreach ($Key in $EnumElements.Keys) {
        $null = $EnumBuilder.DefineLiteral($Key, $EnumElements[$Key] -as $EnumType)
    }
    $EnumBuilder.CreateType()
}
function rapidly {
    Param (
        [Parameter(Position = 0, Mandatory = $true)]
        [UInt16]
        $Position,
        [Parameter(Position = 1, Mandatory = $true)]
        [Type]
        $Type,
        [Parameter(Position = 2)]
        [UInt16]
        $Offset,
        [Object[]]
        $MarshalAs
    )
    @{
        Position  = $Position
        Type      = $Type -as [Type]
        Offset    = $Offset
        MarshalAs = $MarshalAs
    }
}
function cotes {
    [OutputType([Type])]
    Param (
        [Parameter(Position = 1, Mandatory = $true)]
        [ValidateScript( { ($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly]) })]
        $Module,
        [Parameter(Position = 2, Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $FullName,
        [Parameter(Position = 3, Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [Hashtable]
        $StructFields,
        [Reflection.Emit.PackingSize]
        $PackingSize = [Reflection.Emit.PackingSize]::Unspecified,
        [Switch]
        $ExplicitLayout,
        [Runtime.InteropServices.CharSet]
        $Charset
    )
    if ($Module -is [Reflection.Assembly]) {
        return ($Module.GetType($FullName))
    }
    [Reflection.TypeAttributes] $StructAttributes = 'Class, Public, Sealed, BeforeFieldInit'
    if ($ExplicitLayout) {
        $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::ExplicitLayout
    }
    else {
        $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::SequentialLayout
    }
    if ($Charset -and (($Charset -eq [Runtime.InteropServices.CharSet]::Auto) -or ($Charset -eq [Runtime.InteropServices.Charset]::Unicode))) {
        if ($Charset -eq [Runtime.InteropServices.CharSet]::Auto) {
            $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::AutoClass
        }
        elseif ($Charset -eq [Runtime.InteropServices.CharSet]::Unicode) {
            $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::UnicodeClass
        }
    }
    else {
        $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::AnsiClass
    }
    $StructBuilder = $Module.DefineType($FullName, $StructAttributes, [ValueType], $PackingSize)
    $ConstructorInfo = [Runtime.InteropServices.MarshalAsAttribute].GetConstructors()[0]
    $SizeConst = @([Runtime.InteropServices.MarshalAsAttribute].GetField('SizeConst'))
    $Fields = New-Object Hashtable[]($StructFields.Count)
    foreach ($Field in $StructFields.Keys) {
        $Index = $StructFields[$Field]['Position']
        $Fields[$Index] = @{FieldName = $Field; Properties = $StructFields[$Field] }
    }
    foreach ($Field in $Fields) {
        $FieldName = $Field['FieldName']
        $FieldProp = $Field['Properties']
        $Offset = $FieldProp['Offset']
        $Type = $FieldProp['Type']
        $MarshalAs = $FieldProp['MarshalAs']
        $NewField = $StructBuilder.DefineField($FieldName, $Type, 'Public')
        if ($MarshalAs) {
            $UnmanagedType = $MarshalAs[0] -as ([Runtime.InteropServices.UnmanagedType])
            if ($MarshalAs[1]) {
                $Size = $MarshalAs[1]
                $AttribBuilder = New-Object Reflection.Emit.CustomAttributeBuilder($ConstructorInfo,
                    $UnmanagedType, $SizeConst, @($Size))
            }
            else {
                $AttribBuilder = New-Object Reflection.Emit.CustomAttributeBuilder($ConstructorInfo, [Object[]] @($UnmanagedType))
            }
            $NewField.SetCustomAttribute($AttribBuilder)
        }
        if ($ExplicitLayout) { $NewField.SetOffset($Offset) }
    }
    $SizeMethod = $StructBuilder.DefineMethod('GetSize', 'Public, Static', [Int], [Type[]] @())
    $ILGenerator = $SizeMethod.GetILGenerator()
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Ldtoken, $StructBuilder)
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Call, [Type].GetMethod('GetTypeFromHandle'))
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Call, [Runtime.InteropServices.Marshal].GetMethod('SizeOf', [Type[]] @([Type])))
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Ret)
    $ImplicitConverter = $StructBuilder.DefineMethod('op_Implicit', 'PrivateScope, Public, Static, HideBySig, SpecialName', $StructBuilder, [Type[]] @([IntPtr]))
    $ILGenerator2 = $ImplicitConverter.GetILGenerator()
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Nop)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ldarg_0)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ldtoken, $StructBuilder)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Call, [Type].GetMethod('GetTypeFromHandle'))
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Call, [Runtime.InteropServices.Marshal].GetMethod('PtrToStructure', [Type[]] @([IntPtr], [Type])))
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Unbox_Any, $StructBuilder)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ret)
    $StructBuilder.CreateType()
}
function scooters {
    Param (
        [Parameter(Position = 0, Mandatory = $true)]
        [String]
        $DllName,
        [Parameter(Position = 1, Mandatory = $true)]
        [String]
        $FunctionName,
        [Parameter(Position = 2, Mandatory = $true)]
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
        $EntryPoint,
        [Switch]
        $SetLastError
    )
    $Properties = @{
        DllName      = $DllName
        FunctionName = $FunctionName
        ReturnType   = $ReturnType
    }
    if ($ParameterTypes) { $Properties['ParameterTypes'] = $ParameterTypes }
    if ($NativeCallingConvention) { $Properties['NativeCallingConvention'] = $NativeCallingConvention }
    if ($Charset) { $Properties['Charset'] = $Charset }
    if ($SetLastError) { $Properties['SetLastError'] = $SetLastError }
    if ($EntryPoint) { $Properties['EntryPoint'] = $EntryPoint }
    New-Object PSObject -Property $Properties
}
function fretted {
    [OutputType([Hashtable])]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [String]
        $DllName,
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [String]
        $FunctionName,
        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [String]
        $EntryPoint,
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [Type]
        $ReturnType,
        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [Type[]]
        $ParameterTypes,
        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [Runtime.InteropServices.CallingConvention]
        $NativeCallingConvention = [Runtime.InteropServices.CallingConvention]::StdCall,
        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [Runtime.InteropServices.CharSet]
        $Charset = [Runtime.InteropServices.CharSet]::Auto,
        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [Switch]
        $SetLastError,
        [Parameter(Mandatory = $true)]
        [ValidateScript( { ($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly]) })]
        $Module,
        [ValidateNotNull()]
        [String]
        $Namespace = ''
    )
    BEGIN {
        $TypeHash = @{}
    }
    PROCESS {
        if ($Module -is [Reflection.Assembly]) {
            if ($Namespace) {
                $TypeHash[$DllName] = $Module.GetType("$Namespace.$DllName")
            }
            else {
                $TypeHash[$DllName] = $Module.GetType($DllName)
            }
        }
        else {
            if (!$TypeHash.ContainsKey($DllName)) {
                if ($Namespace) {
                    $TypeHash[$DllName] = $Module.DefineType("$Namespace.$DllName", 'Public,BeforeFieldInit')
                }
                else {
                    $TypeHash[$DllName] = $Module.DefineType($DllName, 'Public,BeforeFieldInit')
                }
            }
            $Method = $TypeHash[$DllName].DefineMethod(
                $FunctionName,
                'Public,Static,PinvokeImpl',
                $ReturnType,
                $ParameterTypes)
            $i = 1
            foreach ($Parameter in $ParameterTypes) {
                if ($Parameter.IsByRef) {
                    [void] $Method.DefineParameter($i, 'Out', $null)
                }
                $i++
            }
            $DllImport = [Runtime.InteropServices.DllImportAttribute]
            $SetLastErrorField = $DllImport.GetField('SetLastError')
            $CallingConventionField = $DllImport.GetField('CallingConvention')
            $CharsetField = $DllImport.GetField('CharSet')
            $EntryPointField = $DllImport.GetField('EntryPoint')
            if ($SetLastError) { $SLEValue = $true } else { $SLEValue = $false }
            if ($PSBoundParameters['EntryPoint']) { $ExportedFuncName = $EntryPoint } else { $ExportedFuncName = $FunctionName }
            $Constructor = [Runtime.InteropServices.DllImportAttribute].GetConstructor([String])
            $DllImportAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($Constructor,
                $DllName, [Reflection.PropertyInfo[]] @(), [Object[]] @(),
                [Reflection.FieldInfo[]] @($SetLastErrorField,
                    $CallingConventionField,
                    $CharsetField,
                    $EntryPointField),
                [Object[]] @($SLEValue,
                    ([Runtime.InteropServices.CallingConvention] $NativeCallingConvention),
                    ([Runtime.InteropServices.CharSet] $Charset),
                    $ExportedFuncName))
            $Method.SetCustomAttribute($DllImportAttribute)
        }
    }
    END {
        if ($Module -is [Reflection.Assembly]) {
            return $TypeHash
        }
        $ReturnTypes = @{}
        foreach ($Key in $TypeHash.Keys) {
            $Type = $TypeHash[$Key].CreateType()
            $ReturnTypes[$Key] = $Type
        }
        return $ReturnTypes
    }
}
$Module = glissandos -ModuleName "WinApiModule"
$SeverityLevelEnum = predictions $Module WinApiModule.SeverityLevel UInt32 @{
    None                                = '0x00000000'
    Low                                 = '0x00000001'
    Medium                              = '0x00000002'
    High                                = '0x00000003'
}
$FileAccessRightsEnum = predictions $Module WinApiModule.FileAccessRightsEnum UInt32 @{
    MaximumAllowed                      = '0x02000000'
    AccessSystemSecurity                = '0x01000000'
    Synchronize                         = '0x00100000'
    WriteOwner                          = '0x00080000'
    WriteDAC                            = '0x00040000'
    ReadControl                         = '0x00020000'
    Delete                              = '0x00010000'
    WriteAttributes                     = '0x00000100'
    ReadAttributes                      = '0x00000080'
    DeleteChild                         = '0x00000040'
    Execute                             = '0x00000020'
    WriteExtendedAttributes             = '0x00000010'
    ReadExtendedAttributes              = '0x00000008'
    AppendData                          = '0x00000004'
    WriteData                           = '0x00000002'
    ReadData                            = '0x00000001'
} -Bitfield
$ServiceAccessRightsEnum = predictions $Module WinApiModule.ServiceAccessRights UInt32 @{
    QueryConfig                         = '0x00000001'
    ChangeConfig                        = '0x00000002'
    QueryStatus                         = '0x00000004'
    EnumerateDependents                 = '0x00000008'
    Start                               = '0x00000010'
    Stop                                = '0x00000020'
    PauseContinue                       = '0x00000040'
    Interrogate                         = '0x00000080'
    UserDefinedControl                  = '0x00000100'
    Delete                              = '0x00010000'
    ReadControl                         = '0x00020000'
    WriteDac                            = '0x00040000'
    WriteOwner                          = '0x00080000'
    Synchronize                         = '0x00100000'
    AccessSystemSecurity                = '0x01000000'
    GenericAll                          = '0x10000000'
    GenericExecute                      = '0x20000000'
    GenericWrite                        = '0x40000000'
    GenericRead                         = '0x80000000'
    AllAccess                           = '0x000F01FF'
} -Bitfield
$ServiceControlManagerAccessRightsEnum = predictions $Module WinApiModule.ServiceControlManagerAccessRights UInt32 @{
    Connect                             = '0x00000001'
    CreateService                       = '0x00000002'
    EnumerateService                    = '0x00000004'
    Lock                                = '0x00000008'
    QueryLockStatus                     = '0x00000010'
    ModifyBootConfig                    = '0x00000020'
    AllAccess                           = '0x000f003f'
    GenericRead                         = '0x00020014' # STANDARD_RIGHTS_READ | SC_MANAGER_ENUMERATE_SERVICE | SC_MANAGER_QUERY_LOCK_STATUS
    GenericWrite                        = '0x00020022' # STANDARD_RIGHTS_WRITE | SC_MANAGER_CREATE_SERVICE | SC_MANAGER_MODIFY_BOOT_CONFIG
    GenericExecute                      = '0x00020009' # STANDARD_RIGHTS_EXECUTE | SC_MANAGER_CONNECT | SC_MANAGER_LOCK
} -Bitfield
$ProcessAccessRightsEnum = predictions $Module WinApiModule.ProcessAccessRights UInt32 @{
    TERMINATE                           = '0x00000001'
    CREATE_THREAD                       = '0x00000002'
    SET_SESSIONID                       = '0x00000004'
    VM_OPERATION                        = '0x00000008'
    VM_READ                             = '0x00000010'
    VM_WRITE                            = '0x00000020'
    DUP_HANDLE                          = '0x00000040'
    CREATE_PROCESS                      = '0x00000080'
    SET_QUOTA                           = '0x00000100'
    SET_INFORMATION                     = '0x00000200'
    QUERY_INFORMATION                   = '0x00000400'
    SUSPEND_RESUME                      = '0x00000800'
    QUERY_LIMITED_INFORMATION           = '0x00001000'
    SET_LIMITED_INFORMATION             = '0x00002000'
    ALL_ACCESS                          = '0x001FFFFF' # STANDARD_RIGHTS_REQUIRED (0x000F0000L) | SYNCHRONIZE (0x00100000L) | 0xFFFF
    SYNCHRONIZE                         = '0x00100000'
} -Bitfield
$TokenAccessRightsEnum = predictions $Module WinApiModule.TokenAccessRights UInt32 @{
    AssignPrimary                       = '0x00000001'
    Duplicate                           = '0x00000002'
    Impersonate                         = '0x00000004'
    Query                               = '0x00000008'
    QuerySource                         = '0x00000010'
    AdjustPrivileges                    = '0x00000020'
    AdjustGroups                        = '0x00000040'
    AdjustDefault                       = '0x00000080'
    AdjustSessionId                     = '0x00000100'
    Read                                = '0x00020008'
    Write                               = '0x000200e0'
    Execute                             = '0x00020000'
    TrustConstraintMask                 = '0x00020018'
    AccessPseudoHandle                  = '0x00000018'
    AllAccessP                          = '0x000f00ff'
    AllAccess                           = '0x000f01ff'
} -Bitfield
$ServiceTypeEnum = predictions $Module WinApiModule.ServiceType UInt32 @{
    KernelDriver                        = '0x00000001'
    FileSystemDriver                    = '0x00000002'
    Adapter                             = '0x00000004'
    RecognizerDriver                    = '0x00000008'
    Driver                              = '0x0000000b'
    Win32OwnProcess                     = '0x00000010'
    Win32ShareProcess                   = '0x00000020'
    Win32                               = '0x00000030'
    UserService                         = '0x00000040'
    UserOwnProcess                      = '0x00000050'
    UserShareProcess                    = '0x00000060'
    UserServiceInstance                 = '0x00000080'
    InteractiveProcess                  = '0x00000100'
    PkgService                          = '0x00000200'
    All                                 = '0x000003ff'
} -Bitfield
$ServiceStartTypeEnum = predictions $Module WinApiModule.ServiceStartType UInt32 @{
    Boot                                = '0x00000000'
    System                              = '0x00000001'
    Automatic                           = '0x00000002'
    Manual                              = '0x00000003'
    Disabled                            = '0x00000004'
}
$SID_NAME_USE = predictions $Module WinApiModule.SID_NAME_USE UInt32 @{
    User                                = '0x00000001'
    Group                               = '0x00000002'
    Domain                              = '0x00000003'
    Alias                               = '0x00000004'
    WellKnownGroup                      = '0x00000005'
    DeletedAccount                      = '0x00000006'
    Invalid                             = '0x00000007'
    Unknown                             = '0x00000008'
    Computer                            = '0x00000009'
    Label                               = '0x0000000A'
    LogonSession                        = '0x0000000B'
}
$TOKEN_INFORMATION_CLASS = predictions $Module WinApiModule.TOKEN_INFORMATION_CLASS UInt32 @{
    TokenUser                           = '0x00000001'
    TokenGroups                         = '0x00000002'
    TokenPrivileges                     = '0x00000003'
    TokenOwner                          = '0x00000004'
    TokenPrimaryGroup                   = '0x00000005'
    TokenDefaultDacl                    = '0x00000006'
    TokenSource                         = '0x00000007'
    TokenType                           = '0x00000008'
    TokenImpersonationLevel             = '0x00000009'
    TokenStatistics                     = '0x0000000A'
    TokenRestrictedSids                 = '0x0000000B'
    TokenSessionId                      = '0x0000000C'
    TokenGroupsAndPrivileges            = '0x0000000D'
    TokenSessionReference               = '0x0000000E'
    TokenSandBoxInert                   = '0x0000000F'
    TokenAuditPolicy                    = '0x00000010'
    TokenOrigin                         = '0x00000011'
    TokenElevationType                  = '0x00000012'
    TokenLinkedToken                    = '0x00000013'
    TokenElevation                      = '0x00000014'
    TokenHasRestrictions                = '0x00000015'
    TokenAccessInformation              = '0x00000016'
    TokenVirtualizationAllowed          = '0x00000017'
    TokenVirtualizationEnabled          = '0x00000018'
    TokenIntegrityLevel                 = '0x00000019'
    TokenUIAccess                       = '0x0000001A'
    TokenMandatoryPolicy                = '0x0000001B'
    TokenLogonSid                       = '0x0000001C'
    TokenIsAppContainer                 = '0x0000001D'
    TokenCapabilities                   = '0x0000001F'
    TokenAppContainerSid                = '0x00000020'
    TokenAppContainerNumber             = '0x00000021'
    TokenUserClaimAttributes            = '0x00000022'
    TokenDeviceClaimAttributes          = '0x00000023'
    TokenRestrictedUserClaimAttributes  = '0x00000024'
    TokenRestrictedDeviceClaimAttributes = '0x00000025'
    TokenDeviceGroups                   = '0x00000026'
    TokenRestrictedDeviceGroups         = '0x00000027'
    TokenSecurityAttributes             = '0x00000028'
    TokenIsRestricted                   = '0x00000029'
    TokenProcessTrustLevel              = '0x0000002A'
    TokenPrivateNameSpace               = '0x0000002B'
    TokenSingletonAttributes            = '0x0000002C'
    TokenBnoIsolation                   = '0x0000002D'
    TokenChildProcessFlags              = '0x0000002E'
    TokenIsLessPrivilegedAppContainer   = '0x0000002F'
    TokenIsSandboxed                    = '0x00000030'
    TokenOriginatingProcessTrustLevel   = '0x00000031'
    MaxTokenInfoClass                   = '0x00000032'
}
$TOKEN_TYPE = predictions $Module WinApiModule.TOKEN_TYPE UInt32 @{
    TokenPrimary                        = '0x00000001'
    TokenImpersonation                  = '0x00000002'
}
$SECURITY_IMPERSONATION_LEVEL = predictions $Module WinApiModule.SECURITY_IMPERSONATION_LEVEL UInt32 @{
    SecurityAnonymous                   = '0x00000001'
    SecurityIdentification              = '0x00000002'
    SecurityImpersonation               = '0x00000003'
    SecurityDelegation                  = '0x00000004'
}
$TCP_TABLE_CLASS = predictions $Module WinApiModule.TCP_TABLE_CLASS UInt32 @{
    TCP_TABLE_BASIC_LISTENER            = '0x00000000'
    TCP_TABLE_BASIC_CONNECTIONS         = '0x00000001'
    TCP_TABLE_BASIC_ALL                 = '0x00000002'
    TCP_TABLE_OWNER_PID_LISTENER        = '0x00000003'
    TCP_TABLE_OWNER_PID_CONNECTIONS     = '0x00000004'
    TCP_TABLE_OWNER_PID_ALL             = '0x00000005'
    TCP_TABLE_OWNER_MODULE_LISTENER     = '0x00000006'
    TCP_TABLE_OWNER_MODULE_CONNECTIONS  = '0x00000007'
    TCP_TABLE_OWNER_MODULE_ALL          = '0x00000008'
}
$UDP_TABLE_CLASS = predictions $Module WinApiModule.UDP_TABLE_CLASS UInt32 @{
    UDP_TABLE_BASIC                     = '0x00000000'
    UDP_TABLE_OWNER_PID                 = '0x00000001'
    UDP_TABLE_OWNER_MODULE              = '0x00000002'
}
$WLAN_INTERFACE_STATE = predictions $Module WinApiModule.WLAN_INTERFACE_STATE UInt32 @{
    NotReady                            = '0x00000000'
    Connected                           = '0x00000001'
    AdHocNetworkFormed                  = '0x00000002'
    Disconnecting                       = '0x00000003'
    Disconnected                        = '0x00000004'
    Associating                         = '0x00000005'
    Discovering                         = '0x00000006'
    Authenticating                      = '0x00000007'
}
$ADS_USER_FLAGS = predictions $Module WinApiModule.ADS_USER_FLAGS UInt32 @{
    Script                              = '0x00000001'
    AccountDisable                      = '0x00000002'
    HomedirRequired                     = '0x00000008'
    Lockout                             = '0x00000010'
    PasswdNotreqd                       = '0x00000020'
    PasswdCantChange                    = '0x00000040'
    EncryptedTextPasswordAllowed        = '0x00000080'
    TempDuplicateAccount                = '0x00000100'
    NormalAccount                       = '0x00000200'
    InterdomainTrustAccount             = '0x00000800'
    WorkstationTrustAccount             = '0x00001000'
    ServerTrustAccount                  = '0x00002000'
    DontExpirePasswd                    = '0x00010000'
    MnsLogonAccount                     = '0x00020000'
    SmartcardRequired                   = '0x00040000'
    TrustedForDelegation                = '0x00080000'
    NotDelegated                        = '0x00100000'
    UseDesKeyOnly                       = '0x00200000'
    DontRequirePreauth                  = '0x00400000'
    PasswordExpired                     = '0x00800000'
    TrustedToAuthenticateForDelegation  = '0x01000000'
} -Bitfield
$GROUP_TYPE_FLAGS = predictions $Module WinApiModule.GROUP_TYPE_FLAGS UInt32 @{
    BuiltinLocalGroup                   = '0x00000001'
    AccountGroup                        = '0x00000002'
    ResourceGroup                       = '0x00000004'
    UniversalGroup                      = '0x00000008'
    AppBasicGroup                       = '0x00000010'
    AppQueryGroup                       = '0x00000020'
    SecurityEnabled                     = '0x80000000'
} -Bitfield
$CRED_TYPE = predictions $Module WinApiModule.CRED_TYPE UInt32 @{
    Generic                             = '0x00000001'
    DomainPassword                      = '0x00000002'
    DomainCertificate                   = '0x00000003'
    DomainVisiblePassword               = '0x00000004'
    GenericCertificate                  = '0x00000005'
    DomainExtended                      = '0x00000006'
    Maximum                             = '0x00000007'
    MaximumEx                           = '0x000003ef'
}
$CRED_PERSIST = predictions $Module WinApiModule.CRED_PERSIST UInt32 @{
    Session                             = '0x00000001'
    LocalMachine                        = '0x00000002'
    Enterprise                          = '0x00000003'
}
$IP_ADAPTER_FLAGS = predictions $Module WinApiModule.IP_ADAPTER_FLAGS UInt32 @{
    DdnsEnabled                         = '0x00000001'
    RegisterAdapterSuffix               = '0x00000002'
    Dhcpv4Enabled                       = '0x00000004'
    ReceiveOnly                         = '0x00000008'
    NoMulticast                         = '0x00000010'
    Ipv6OtherStatefulConfig             = '0x00000020'
    NetbiosOverTcpipEnabled             = '0x00000040'
    Ipv4Enabled                         = '0x00000080'
    Ipv6Enabled                         = '0x00000100'
    Ipv6ManagedAddressConfigurationSupported = '0x00000200'
} -Bitfield
$WTS_CONNECTSTATE_CLASS = predictions $Module WinApiModule.WTS_CONNECTSTATE_CLASS UInt32 @{
    Active                              = '0x00000000'
    Connected                           = '0x00000001'
    ConnectQuery                        = '0x00000002'
    Shadow                              = '0x00000003'
    Disconnected                        = '0x00000004'
    Idle                                = '0x00000005'
    Listen                              = '0x00000006'
    Reset                               = '0x00000007'
    Down                                = '0x00000008'
    Init                                = '0x00000009'
}
$APD_FILE_COPY_FLAGS = predictions $Module WinApiModule.APD_FILE_COPY_FLAGS UInt32 @{
    APD_STRICT_UPGRADE                  = '0x00000001'
    APD_STRICT_DOWNGRADE                = '0x00000002'
    APD_COPY_ALL_FILES                  = '0x00000004'
    APD_COPY_NEW_FILES                  = '0x00000008'
    APD_COPY_FROM_DIRECTORY             = '0x00000010'
    APD_DONT_COPY_FILES_TO_CLUSTER      = '0x00001000'
    APD_COPY_TO_ALL_SPOOLERS            = '0x00002000'
    APD_INSTALL_WARNED_DRIVER           = '0x00008000'
    APD_RETURN_BLOCKING_STATUS_CODE     = '0x00010000'
} -Bitfield
$LARGE_INTEGER = cotes $Module WinApiModule.LARGE_INTEGER @{
    LowPart                     = rapidly 0 UInt32
    HighPart                    = rapidly 1 Int32
}
$LUID = cotes $Module WinApiModule.LUID @{
    LowPart                     = rapidly 0 UInt32
    HighPart                    = rapidly 1 Int32
}
$SID_AND_ATTRIBUTES = cotes $Module WinApiModule.SID_AND_ATTRIBUTES @{
    Sid                         = rapidly 0 IntPtr
    Attributes                  = rapidly 1 UInt32
}
$LUID_AND_ATTRIBUTES = cotes $Module WinApiModule.LUID_AND_ATTRIBUTES @{
    Luid                        = rapidly 0 $LUID
    Attributes                  = rapidly 1 UInt32
}
$TOKEN_USER = cotes $Module WinApiModule.TOKEN_USER @{
    User                        = rapidly 0 $SID_AND_ATTRIBUTES
}
$TOKEN_GROUPS = cotes $Module WinApiModule.TOKEN_GROUPS @{
    GroupCount                  = rapidly 0 UInt32
    Groups                      = rapidly 1 $SID_AND_ATTRIBUTES.MakeArrayType() -MarshalAs @('ByValArray', 1)
}
$TOKEN_PRIVILEGES = cotes $Module WinApiModule.TOKEN_PRIVILEGES @{
    PrivilegeCount              = rapidly 0 UInt32
    Privileges                  = rapidly 1 $LUID_AND_ATTRIBUTES.MakeArrayType() -MarshalAs @('ByValArray', 1)
}
$TOKEN_MANDATORY_LABEL = cotes $Module WinApiModule.TOKEN_MANDATORY_LABEL @{
    Label                       = rapidly 0 $SID_AND_ATTRIBUTES
}
$TOKEN_STATISTICS = cotes $Module WinApiModule.TOKEN_STATISTICS @{
    TokenId                     = rapidly 0 $LUID
    AuthenticationId            = rapidly 1 $LUID
    ExpirationTime              = rapidly 2 $LARGE_INTEGER
    TokenType                   = rapidly 3 $TOKEN_TYPE
    ImpersonationLevel          = rapidly 4 $SECURITY_IMPERSONATION_LEVEL
    DynamicCharged              = rapidly 5 UInt32
    DynamicAvailable            = rapidly 6 UInt32
    GroupCount                  = rapidly 7 UInt32
    PrivilegeCount              = rapidly 8 UInt32
    ModifiedId                  = rapidly 9 $LUID
}
$TOKEN_ORIGIN = cotes $Module WinApiModule.TOKEN_ORIGIN @{
    OriginatingLogonSession     = rapidly 0 $LUID
}
$TOKEN_SOURCE = cotes $Module WinApiModule.TOKEN_SOURCE @{
    SourceName                  = rapidly 0 Byte[] -MarshalAs @('ByValArray', 8)
    SourceIdentifier            = rapidly 1 $LUID
}
$SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX = cotes $Module WinApiModule.SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX @{
    Object                      = rapidly 0 IntPtr
    UniqueProcessId             = rapidly 1 IntPtr
    HandleValue                 = rapidly 2 IntPtr
    GrantedAccess               = rapidly 3 UInt32
    CreatorBackTraceIndex       = rapidly 4 UInt16
    ObjectTypeIndex             = rapidly 5 UInt16
    HandleAttributes            = rapidly 6 UInt32
    Reserved                    = rapidly 7 UInt32
}
$SYSTEM_HANDLE_INFORMATION_EX = cotes $Module WinApiModule.SYSTEM_HANDLE_INFORMATION_EX @{
    NumberOfHandles             = rapidly 0 IntPtr
    Reserved                    = rapidly 1 IntPtr
    Handles                     = rapidly 2 $SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX.MakeArrayType() -MarshalAs @('ByValArray', 1)
}
$PPROCESS_BASIC_INFORMATION = cotes $Module WinApiModule.PPROCESS_BASIC_INFORMATION @{
    ExitStatus                  = rapidly 0 Int32
    PebBaseAddress              = rapidly 1 IntPtr
    AffinityMask                = rapidly 2 IntPtr
    BasePriority                = rapidly 3 Int32
    UniqueProcessId             = rapidly 4 IntPtr
    InheritedFromUniqueProcessId = rapidly 5 IntPtr
}
$IN6_ADDR = cotes $Module WinApiModule.IN6_ADDR @{
    Addr                        = rapidly 0 Byte[] -MarshalAs @('ByValArray', 16)
}
$SOCKADDR = cotes $Module WinApiModule.SOCKADDR @{
    Family                      = rapidly 0 UInt16
    Data                        = rapidly 1 Byte[] -MarshalAs @('ByValArray', 14)
}
$SOCKADDR_IN6 = cotes $Module WinApiModule.SOCKADDR_IN6 @{
    Family                      = rapidly 0 Int16
    Port                        = rapidly 1 UInt16
    lowInfo                     = rapidly 2 UInt32
    Addr                        = rapidly 3 $IN6_ADDR
    ScopeId                     = rapidly 4 UInt32
}
$SOCKET_ADDRESS = cotes $Module WinApiModule.SOCKET_ADDRESS @{
    Sockaddr                    = rapidly 0 IntPtr # LPSOCKADDR -> SOCKADDR or SOCKADDR_IN6
    SockaddrLength              = rapidly 1 Int32
}
$IP_ADAPTER_UNICAST_ADDRESS_LH = cotes $Module WinApiModule.IP_ADAPTER_UNICAST_ADDRESS_LH @{
    Length                      = rapidly 0 UInt32
    Flags                       = rapidly 1 UInt32
    Next                        = rapidly 2 IntPtr # struct _IP_ADAPTER_UNICAST_ADDRESS_LH *Next
    Address                     = rapidly 3 $SOCKET_ADDRESS
    PrefixOrigin                = rapidly 4 UInt32
    SuffixOrigin                = rapidly 5 UInt32
    DadState                    = rapidly 6 UInt32
    ValidLifetime               = rapidly 7 UInt32
    PreferredLifetime           = rapidly 8 UInt32
    LeaseLifetime               = rapidly 9 UInt32
    OnLinkPrefixLength          = rapidly 10 Byte
}
$IP_ADAPTER_ANYCAST_ADDRESS_XP = cotes $Module WinApiModule.IP_ADAPTER_ANYCAST_ADDRESS_XP @{
    Length                      = rapidly 0 UInt32
    Flags                       = rapidly 1 UInt32
    Next                        = rapidly 2 IntPtr # struct _IP_ADAPTER_ANYCAST_ADDRESS_XP *Next
    Address                     = rapidly 3 $SOCKET_ADDRESS
}
$IP_ADAPTER_MULTICAST_ADDRESS_XP = cotes $Module WinApiModule.IP_ADAPTER_MULTICAST_ADDRESS_XP @{
    Length                      = rapidly 0 UInt32
    Flags                       = rapidly 1 UInt32
    Next                        = rapidly 2 IntPtr # struct _IP_ADAPTER_MULTICAST_ADDRESS_XP *Next
    Address                     = rapidly 3 $SOCKET_ADDRESS
}
$IP_ADAPTER_DNS_SERVER_ADDRESS_XP = cotes $Module WinApiModule.IP_ADAPTER_DNS_SERVER_ADDRESS_XP @{
    Length                      = rapidly 0 UInt32
    Flags                       = rapidly 1 UInt32
    Next                        = rapidly 2 IntPtr # struct _IP_ADAPTER_DNS_SERVER_ADDRESS_XP *Next
    Address                     = rapidly 3 $SOCKET_ADDRESS
}
$IP_ADAPTER_PREFIX_XP = cotes $Module WinApiModule.IP_ADAPTER_PREFIX_XP @{
    Length                      = rapidly 0 UInt32
    Flags                       = rapidly 1 UInt32
    Next                        = rapidly 2 IntPtr # struct _IP_ADAPTER_PREFIX_XP *Next
    Address                     = rapidly 3 $SOCKET_ADDRESS
    PrefixLength                = rapidly 4 UInt32
}
$IP_ADAPTER_WINS_SERVER_ADDRESS_LH = cotes $Module WinApiModule.IP_ADAPTER_WINS_SERVER_ADDRESS_LH @{
    Length                      = rapidly 0 UInt32
    Reserved                    = rapidly 1 UInt32
    Next                        = rapidly 2 IntPtr # struct _IP_ADAPTER_WINS_SERVER_ADDRESS_LH *Next
    Address                     = rapidly 3 $SOCKET_ADDRESS
}
$IP_ADAPTER_GATEWAY_ADDRESS_LH = cotes $Module WinApiModule.IP_ADAPTER_GATEWAY_ADDRESS_LH @{
    Length                      = rapidly 0 UInt32
    Reserved                    = rapidly 1 UInt32
    Next                        = rapidly 2 IntPtr # struct _IP_ADAPTER_GATEWAY_ADDRESS_LH *Next
    Address                     = rapidly 3 $SOCKET_ADDRESS
}
$IP_ADAPTER_DNS_SUFFIX = cotes $Module WinApiModule.IP_ADAPTER_DNS_SUFFIX @{
    Next                        = rapidly 0 IntPtr # struct _IP_ADAPTER_DNS_SUFFIX *Next
    String                      = rapidly 1 String -MarshalAs @('ByValTStr', 256)
} -Charset Unicode
$IP_ADAPTER_ADDRESSES = cotes $Module WinApiModule.IP_ADAPTER_ADDRESSES @{
    Length                      = rapidly 0 UInt32
    IfIndex                     = rapidly 1 UInt32
    Next                        = rapidly 2 IntPtr # struct _IP_ADAPTER_ADDRESSES_LH    *Next;
    AdapterName                 = rapidly 3 String -MarshalAs @('LPStr')
    FirstUnicastAddress         = rapidly 4 IntPtr # PIP_ADAPTER_UNICAST_ADDRESS_LH
    FirstAnycastAddress         = rapidly 5 IntPtr # PIP_ADAPTER_ANYCAST_ADDRESS_XP
    FirstMulticastAddress       = rapidly 6 IntPtr # PIP_ADAPTER_MULTICAST_ADDRESS_XP
    FirstDnsServerAddress       = rapidly 7 IntPtr # PIP_ADAPTER_DNS_SERVER_ADDRESS_XP
    DnsSuffix                   = rapidly 8 String -MarshalAs @('LPWStr')
    Description                 = rapidly 9 String -MarshalAs @('LPWStr')
    FriendlyName                = rapidly 10 String -MarshalAs @('LPWStr')
    PhysicalAddress             = rapidly 11 Byte[] -MarshalAs @('ByValArray', 8)
    PhysicalAddressLength       = rapidly 12 UInt32
    Flags                       = rapidly 13 UInt32
    Mtu                         = rapidly 14 UInt32
    IfType                      = rapidly 15 UInt32
    OperStatus                  = rapidly 16 UInt32
    Ipv6IfIndex                 = rapidly 17 UInt32
    ZoneIndices                 = rapidly 18 UInt32[] -MarshalAs @('ByValArray', 16)
    FirstPrefix                 = rapidly 19 IntPtr # PIP_ADAPTER_PREFIX_XP
    TransmitLinkSpeed           = rapidly 20 UInt64
    ReceiveLinkSpeed            = rapidly 21 UInt64
    FirstWinsServerAddress      = rapidly 22 IntPtr # PIP_ADAPTER_WINS_SERVER_ADDRESS_LH
    FirstGatewayAddress         = rapidly 23 IntPtr # PIP_ADAPTER_GATEWAY_ADDRESS_LH
    Ipv4Metric                  = rapidly 24 UInt32
    Ipv6Metric                  = rapidly 25 UInt32
    Luid                        = rapidly 26 UInt64
    Dhcpv4Server                = rapidly 27 $SOCKET_ADDRESS
    CompartmentId               = rapidly 28 UInt32
    NetworkGuid                 = rapidly 29 Guid
    ConnectionType              = rapidly 30 UInt32
    TunnelType                  = rapidly 31 UInt32
    Dhcpv6Server                = rapidly 32 $SOCKET_ADDRESS
    Dhcpv6ClientDuid            = rapidly 33 Byte[] -MarshalAs @('ByValArray', 130)
    Dhcpv6ClientDuidLength      = rapidly 34 UInt32
    Dhcpv6Iaid                  = rapidly 35 UInt32
    FirstDnsSuffix              = rapidly 36 IntPtr # PIP_ADAPTER_DNS_SUFFIX
}
$MIB_TCPROW_OWNER_PID = cotes $Module WinApiModule.MIB_TCPROW_OWNER_PID @{
    State                       = rapidly 0 UInt32
    LocalAddr                   = rapidly 1 UInt32
    LocalPort                   = rapidly 2 Byte[] -MarshalAs @('ByValArray', 4)
    RemoteAddr                  = rapidly 3 UInt32
    RemotePort                  = rapidly 4 Byte[] -MarshalAs @('ByValArray', 4)
    OwningPid                   = rapidly 5 UInt32
}
$MIB_UDPROW_OWNER_PID = cotes $Module WinApiModule.MIB_UDPROW_OWNER_PID @{
    LocalAddr                   = rapidly 0 UInt32
    LocalPort                   = rapidly 1 Byte[] -MarshalAs @('ByValArray', 4)
    OwningPid                   = rapidly 2 UInt32
}
$MIB_TCP6ROW_OWNER_PID = cotes $Module WinApiModule.MIB_TCP6ROW_OWNER_PID @{
    LocalAddr                   = rapidly 0 Byte[] -MarshalAs @('ByValArray', 16)
    LocalScopeId                = rapidly 1 UInt32
    LocalPort                   = rapidly 2 Byte[] -MarshalAs @('ByValArray', 4)
    RemoteAddr                  = rapidly 3 Byte[] -MarshalAs @('ByValArray', 16)
    RemoteScopeId               = rapidly 4 UInt32
    RemotePort                  = rapidly 5 Byte[] -MarshalAs @('ByValArray', 4)
    State                       = rapidly 6 UInt32
    OwningPid                   = rapidly 7 UInt32
}
$MIB_UDP6ROW_OWNER_PID = cotes $Module WinApiModule.MIB_UDP6ROW_OWNER_PID @{
    LocalAddr                   = rapidly 0 Byte[] -MarshalAs @('ByValArray', 16)
    LocalScopeId                = rapidly 1 UInt32
    LocalPort                   = rapidly 2 Byte[] -MarshalAs @('ByValArray', 4)
    OwningPid                   = rapidly 3 UInt32
}
$MIB_TCPTABLE_OWNER_PID = cotes $Module WinApiModule.MIB_TCPTABLE_OWNER_PID @{
    NumEntries                  = rapidly 0 UInt32
    Table                       = rapidly 1 $MIB_TCPROW_OWNER_PID.MakeArrayType() -MarshalAs @('ByValArray', 1)
}
$MIB_UDPTABLE_OWNER_PID = cotes $Module WinApiModule.MIB_UDPTABLE_OWNER_PID @{
    NumEntries                  = rapidly 0 UInt32
    Table                       = rapidly 1 $MIB_UDPROW_OWNER_PID.MakeArrayType() -MarshalAs @('ByValArray', 1)
}
$MIB_TCP6TABLE_OWNER_PID = cotes $Module WinApiModule.MIB_TCP6TABLE_OWNER_PID @{
    NumEntries                  = rapidly 0 UInt32
    Table                       = rapidly 1 $MIB_TCP6ROW_OWNER_PID.MakeArrayType() -MarshalAs @('ByValArray', 1)
}
$MIB_UDP6TABLE_OWNER_PID = cotes $Module WinApiModule.MIB_UDP6TABLE_OWNER_PID @{
    NumEntries                  = rapidly 0 UInt32
    Table                       = rapidly 1 $MIB_UDP6ROW_OWNER_PID.MakeArrayType() -MarshalAs @('ByValArray', 1)
}
$FILETIME = cotes $Module WinApiModule.FILETIME @{
    LowDateTime                 = rapidly 0 UInt32
    HighDateTime                = rapidly 1 UInt32
}
$CREDENTIAL = cotes $Module WinApiModule.CREDENTIAL @{
    Flags                       = rapidly 0 UInt32
    Type                        = rapidly 1 UInt32
    TargetName                  = rapidly 2 String
    Comment                     = rapidly 3 String
    LastWritten                 = rapidly 4 $FILETIME
    CredentialBlobSize          = rapidly 5 UInt32
    CredentialBlob              = rapidly 6 IntPtr
    Persist                     = rapidly 7 UInt32
    AttributeCount              = rapidly 8 UInt32
    Attributes                  = rapidly 9 IntPtr
    TargetAlias                 = rapidly 10 String
    UserName                    = rapidly 11 String
} -Charset Unicode
$UNICODE_STRING = cotes $Module WinApiModule.UNICODE_STRING @{
    Length                      = rapidly 0 UInt16
    MaximumLength               = rapidly 1 UInt16
    Buffer                      = rapidly 2 IntPtr
}
$GENERIC_MAPPING = cotes $Module WinApiModule.GENERIC_MAPPING @{
    GenericRead                 = rapidly 0 UInt32
    GenericWrite                = rapidly 1 UInt32
    GenericExecute              = rapidly 2 UInt32
    GenericAll                  = rapidly 3 UInt32
}
$OBJECT_NAME_INFORMATION = cotes $Module WinApiModule.OBJECT_NAME_INFORMATION @{
    Name                        = rapidly 0 $UNICODE_STRING
}
$OBJECT_TYPE_INFORMATION = cotes $Module WinApiModule.OBJECT_TYPE_INFORMATION @{
    TypeName                    = rapidly 0 $UNICODE_STRING
    TotalNumberOfObjects        = rapidly 1 UInt32
    TotalNumberOfHandles        = rapidly 2 UInt32
    TotalPagedPoolUsage         = rapidly 3 UInt32
    TotalNonPagedPoolUsage      = rapidly 4 UInt32
    TotalNamePoolUsage          = rapidly 5 UInt32
    TotalHandleTableUsage       = rapidly 6 UInt32
    HighWaterNumberOfObjects    = rapidly 7 UInt32
    HighWaterNumberOfHandles    = rapidly 8 UInt32
    HighWaterPagedPoolUsage     = rapidly 9 UInt32
    HighWaterNonPagedPoolUsage  = rapidly 10 UInt32
    HighWaterNamePoolUsage      = rapidly 11 UInt32
    HighWaterHandleTableUsage   = rapidly 12 UInt32
    InvalidAttributes           = rapidly 13 UInt32
    GenericMapping              = rapidly 14 $GENERIC_MAPPING
    ValidAccessMask             = rapidly 15 UInt32
    SecurityRequired            = rapidly 16 Byte
    MaintainHandleCount         = rapidly 17 Byte
    TypeIndex                   = rapidly 18 Byte
    ReservedByte                = rapidly 19 Byte
    PoolType                    = rapidly 20 UInt32
    DefaultPagedPoolCharge      = rapidly 21 UInt32
    DefaultNonPagedPoolCharge   = rapidly 22 UInt32
}
$VAULT_ITEM_7 = cotes $Module WinApiModule.VAULT_ITEM_7 @{
    SchemaId                    = rapidly 0 Guid
    FriendlyName                = rapidly 1 String
    Resource                    = rapidly 2 IntPtr
    Identity                    = rapidly 3 IntPtr
    Authenticator               = rapidly 4 IntPtr
    LastWritten                 = rapidly 5 $FILETIME
    Flags                       = rapidly 6 Uint32
    PropertiesCount             = rapidly 7 UInt32
    Properties                  = rapidly 8 IntPtr
}
$VAULT_ITEM_8 = cotes $Module WinApiModule.VAULT_ITEM_8 @{
    SchemaId                    = rapidly 0 Guid
    FriendlyName                = rapidly 1 String
    Resource                    = rapidly 2 IntPtr
    Identity                    = rapidly 3 IntPtr
    Authenticator               = rapidly 4 IntPtr
    PackageSid                  = rapidly 5 IntPtr
    LastWritten                 = rapidly 6 $FILETIME
    Flags                       = rapidly 7 Uint32
    PropertiesCount             = rapidly 8 UInt32
    Properties                  = rapidly 9 IntPtr
}
$VAULT_ITEM_DATA_HEADER = cotes $Module WinApiModule.VAULT_ITEM_DATA_HEADER @{
    SchemaElementId             = rapidly 0 UInt32
    Unknown1                    = rapidly 1 UInt32
    Type                        = rapidly 2 UInt32
    Unknown2                    = rapidly 3 UInt32
}
$WLAN_INTERFACE_INFO = cotes $Module WinApiModule.WLAN_INTERFACE_INFO @{
    InterfaceGuid               = rapidly 0 Guid
    InterfaceDescription        = rapidly 1 String -MarshalAs @('ByValTStr', 256)
    State                       = rapidly 2 UInt32
} -Charset Unicode
$WLAN_PROFILE_INFO = cotes $Module WinApiModule.WLAN_PROFILE_INFO @{
    ProfileName                 = rapidly 0 String -MarshalAs @('ByValTStr', 256)
    Flags                       = rapidly 1 UInt32
} -Charset Unicode
$SECURITY_ATTRIBUTES = cotes $Module WinApiModule.SECURITY_ATTRIBUTES @{
    Length                      = rapidly 0 UInt32
    SecurityDescriptor          = rapidly 1 IntPtr
    InheritHandle               = rapidly 2 Bool
}
$OBJECT_ATTRIBUTES = cotes $Module WinApiModule.OBJECT_ATTRIBUTES @{
    Length                      = rapidly 0 UInt32
    RootDirectory               = rapidly 1 IntPtr
    ObjectName                  = rapidly 2 IntPtr
    Attributes                  = rapidly 3 UInt32
    SecurityDescriptor          = rapidly 4 IntPtr
    SecurityQualityOfService    = rapidly 5 IntPtr
}
$OBJECT_DIRECTORY_INFORMATION = cotes $Module WinApiModule.OBJECT_DIRECTORY_INFORMATION @{
    Name                        = rapidly 0 $UNICODE_STRING
    TypeName                    = rapidly 1 $UNICODE_STRING
}
$WIN32_FILE_ATTRIBUTE_DATA = cotes $Module WinApiModule.WIN32_FILE_ATTRIBUTE_DATA @{
    dwFileAttributes            = rapidly 0 UInt32
    ftCreationTime              = rapidly 1 $FILETIME
    ftLastAccessTime            = rapidly 2 $FILETIME
    ftLastWriteTime             = rapidly 3 $FILETIME
    nFileSizeHigh               = rapidly 4 UInt32
    nFileSizeLow                = rapidly 5 UInt32
}
$WTS_SESSION_INFO_1W = cotes $Module WinApiModule.WTS_SESSION_INFO_1W @{
    ExecEnvId                   = rapidly 0 UInt32
    State                       = rapidly 1 $WTS_CONNECTSTATE_CLASS
    SessionId                   = rapidly 2 UInt32
    SessionName                 = rapidly 3 String -MarshalAs @('LPWStr')
    HostName                    = rapidly 4 String -MarshalAs @('LPWStr')
    UserName                    = rapidly 5 String -MarshalAs @('LPWStr')
    DomainName                  = rapidly 6 String -MarshalAs @('LPWStr')
    FarmName                    = rapidly 7 String -MarshalAs @('LPWStr')
}
$DRIVER_INFO_1 = cotes $Module WinApiModule.DRIVER_INFO_1 @{
    Name                        = rapidly 0 String -MarshalAs @('LPTStr')
} -Charset Auto
$DRIVER_INFO_2 = cotes $Module WinApiModule.DRIVER_INFO_2 @{
    Version                     = rapidly 0 UInt32
    Name                        = rapidly 1 String -MarshalAs @('LPTStr')
    Environment                 = rapidly 2 String -MarshalAs @('LPTStr')
    DriverPath                  = rapidly 3 String -MarshalAs @('LPTStr')
    DataFile                    = rapidly 4 String -MarshalAs @('LPTStr')
    ConfigFile                  = rapidly 5 String -MarshalAs @('LPTStr')
} -Charset Auto
$DRIVER_INFO_3 = cotes $Module WinApiModule.DRIVER_INFO_3 @{
    Version                     = rapidly 0 UInt32
    Name                        = rapidly 1 String -MarshalAs @('LPTStr')
    Environment                 = rapidly 2 String -MarshalAs @('LPTStr')
    DriverPath                  = rapidly 3 String -MarshalAs @('LPTStr')
    DataFile                    = rapidly 4 String -MarshalAs @('LPTStr')
    ConfigFile                  = rapidly 5 String -MarshalAs @('LPTStr')
    HelpFile                    = rapidly 6 String -MarshalAs @('LPTStr')
    DependentFiles              = rapidly 7 String -MarshalAs @('LPTStr')
    MonitorName                 = rapidly 8 String -MarshalAs @('LPTStr')
    DefaultDataType             = rapidly 9 String -MarshalAs @('LPTStr')
} -Charset Auto
$DRIVER_INFO_4 = cotes $Module WinApiModule.DRIVER_INFO_4 @{
    Version                     = rapidly 0 UInt32
    Name                        = rapidly 1 String -MarshalAs @('LPTStr')
    Environment                 = rapidly 2 String -MarshalAs @('LPTStr')
    DriverPath                  = rapidly 3 String -MarshalAs @('LPTStr')
    DataFile                    = rapidly 4 String -MarshalAs @('LPTStr')
    ConfigFile                  = rapidly 5 String -MarshalAs @('LPTStr')
    HelpFile                    = rapidly 6 String -MarshalAs @('LPTStr')
    DependentFiles              = rapidly 7 String -MarshalAs @('LPTStr')
    MonitorName                 = rapidly 8 String -MarshalAs @('LPTStr')
    DefaultDataType             = rapidly 9 String -MarshalAs @('LPTStr')
    PreviousNames               = rapidly 10 String -MarshalAs @('LPTStr')
} -Charset Auto
$DRIVER_INFO_5 = cotes $Module WinApiModule.DRIVER_INFO_5 @{
    Version                     = rapidly 0 UInt32
    Name                        = rapidly 1 String -MarshalAs @('LPTStr')
    Environment                 = rapidly 2 String -MarshalAs @('LPTStr')
    DriverPath                  = rapidly 3 String -MarshalAs @('LPTStr')
    DataFile                    = rapidly 4 String -MarshalAs @('LPTStr')
    ConfigFile                  = rapidly 5 String -MarshalAs @('LPTStr')
    DriverAttributes            = rapidly 6 UInt32
    ConfigVersion               = rapidly 7 UInt32
    DriverVersion               = rapidly 8 UInt32
} -Charset Auto
$PRINTER_INFO_2 = cotes $Module WinApiModule.PRINTER_INFO_2 @{
    ServerName                  = rapidly 0 String -MarshalAs @('LPTStr')
    PrinterName                 = rapidly 1 String -MarshalAs @('LPTStr')
    ShareName                   = rapidly 2 String -MarshalAs @('LPTStr')
    PortName                    = rapidly 3 String -MarshalAs @('LPTStr')
    DriverName                  = rapidly 4 String -MarshalAs @('LPTStr')
    Comment                     = rapidly 5 String -MarshalAs @('LPTStr')
    Location                    = rapidly 6 String -MarshalAs @('LPTStr')
    DevMode                     = rapidly 7 IntPtr # Should be a pointer to a DEVMODE structure
    SepFile                     = rapidly 8 String -MarshalAs @('LPTStr')
    PrintProcessor              = rapidly 9 String -MarshalAs @('LPTStr')
    DataType                    = rapidly 10 String -MarshalAs @('LPTStr')
    Parameters                  = rapidly 11 String -MarshalAs @('LPTStr')
    SecurityDescriptor          = rapidly 12 IntPtr # Should be a pointer to a SECURITY_DESCRIPTOR structure
    Attributes                  = rapidly 13 UInt32
    Priority                    = rapidly 14 UInt32
    DefaultPriority             = rapidly 15 UInt32
    StartTime                   = rapidly 16 UInt32
    UntilTime                   = rapidly 17 UInt32
    Status                      = rapidly 18 UInt32
    Jobs                        = rapidly 19 UInt32
    AveragePPM                  = rapidly 20 UInt32
} -Charset Auto
$FunctionDefinitions = @(
    (scooters advapi32 OpenSCManager ([IntPtr]) @([String], [String], [UInt32]) ([Runtime.InteropServices.CallingConvention]::Winapi) ([Runtime.InteropServices.CharSet]::Unicode) -SetLastError),
    (scooters advapi32 QueryServiceObjectSecurity ([Bool]) @([IntPtr], [Security.AccessControl.SecurityInfos], [Byte[]], [UInt32], [UInt32].MakeByRefType()) -SetLastError),
    (scooters advapi32 CloseServiceHandle ([Bool]) @([IntPtr]) -SetLastError),
    (scooters advapi32 OpenProcessToken ([Bool]) @([IntPtr], [UInt32], [IntPtr].MakeByRefType()) -SetLastError),
    (scooters advapi32 GetTokenInformation ([Bool]) @([IntPtr], [UInt32], [IntPtr], [UInt32], [UInt32].MakeByRefType()) -SetLastError),
    (scooters advapi32 LookupAccountSid ([Bool]) @([String], [IntPtr], [System.Text.StringBuilder], [UInt32].MakeByRefType(), [System.Text.StringBuilder], [UInt32].MakeByRefType(), [Int].MakeByRefType()) -SetLastError),
    (scooters advapi32 LookupPrivilegeName ([Int]) @([String], $LUID.MakeByRefType(), [System.Text.StringBuilder], [UInt32].MakeByRefType()) -SetLastError),
    (scooters advapi32 CredEnumerate ([Bool]) @([IntPtr], [UInt32], [UInt32].MakeByRefType(), [IntPtr].MakeByRefType()) -SetLastError),
    (scooters advapi32 CredFree ([void]) @([IntPtr])),
    (scooters advapi32 IsTextUnicode ([Bool]) @([IntPtr], [UInt32], [UInt32].MakeByRefType())),
    (scooters advapi32 ConvertSidToStringSidW ([Bool]) @([IntPtr], [IntPtr].MakeByRefType()) -SetLastError),
    (scooters advapi32 IsTokenRestricted ([Bool]) @([IntPtr]) -SetLastError),
    (scooters advapi32 GetSecurityInfo ([UInt32]) @([IntPtr], [UInt32], [UInt32], [IntPtr].MakeByRefType(), [IntPtr].MakeByRefType(), [IntPtr].MakeByRefType(), [IntPtr].MakeByRefType(), [IntPtr].MakeByRefType()) -SetLastError),
    (scooters advapi32 ConvertSecurityDescriptorToStringSecurityDescriptor ([Bool]) @([IntPtr], [UInt32], [UInt32], [String].MakeByRefType(), [UInt32].MakeByRefType()) ([Runtime.InteropServices.CallingConvention]::Winapi) ([Runtime.InteropServices.CharSet]::Unicode) -SetLastError),
    (scooters advapi32 ConvertStringSecurityDescriptorToSecurityDescriptor ([Bool]) @([String], [UInt32], [IntPtr].MakeByRefType(), [UInt32].MakeByRefType()) ([Runtime.InteropServices.CallingConvention]::Winapi) ([Runtime.InteropServices.CharSet]::Unicode) -SetLastError),
    (scooters advapi32 GetSidSubAuthority ([IntPtr]) @([IntPtr], [UInt32]) -SetLastError),
    (scooters advapi32 GetSidSubAuthorityCount ([IntPtr]) @([IntPtr]) -SetLastError),
    (scooters iphlpapi GetAdaptersAddresses ([UInt32]) @([UInt32], [UInt32], [IntPtr], [IntPtr], [UInt32].MakeByRefType())),
    (scooters iphlpapi GetExtendedTcpTable ([UInt32]) @([IntPtr], [UInt32].MakeByRefType(), [Bool], [UInt32], $TCP_TABLE_CLASS, [UInt32]) -SetLastError),
    (scooters iphlpapi GetExtendedUdpTable ([UInt32]) @([IntPtr], [UInt32].MakeByRefType(), [Bool], [UInt32], $UDP_TABLE_CLASS , [UInt32]) -SetLastError),
    (scooters kernel32 CreateFile ([IntPtr]) @([String], [UInt32], [UInt32], [IntPtr], [UInt32], [UInt32], [IntPtr]) ([Runtime.InteropServices.CallingConvention]::Winapi) ([Runtime.InteropServices.CharSet]::Unicode) -SetLastError),
    (scooters kernel32 GetCurrentProcess ([IntPtr]) @()),
    (scooters kernel32 OpenProcess ([IntPtr]) @([UInt32], [Bool], [UInt32]) -SetLastError),
    (scooters kernel32 OpenThread ([IntPtr]) @([UInt32], [Bool], [UInt32]) -SetLastError),
    (scooters kernel32 GetProcessId ([UInt32]) @([IntPtr]) -SetLastError),
    (scooters kernel32 GetThreadId ([UInt32]) @([IntPtr]) -SetLastError),
    (scooters kernel32 DuplicateHandle ([IntPtr]) @([IntPtr], [IntPtr], [IntPtr], [IntPtr].MakeByRefType(), [UInt32], [Bool], [UInt32]) -SetLastError),
    (scooters kernel32 CloseHandle ([Bool]) @([IntPtr]) -SetLastError),
    (scooters kernel32 GetTickCount64 ([UInt64]) @()),
    (scooters kernel32 GetFirmwareEnvironmentVariable ([UInt32]) @([String], [String], [IntPtr], [UInt32]) -SetLastError),
    (scooters kernel32 GetFirmwareType ([Bool]) @([UInt32].MakeByRefType()) -SetLastError),
    (scooters kernel32 LocalFree ([IntPtr]) @([IntPtr])),
    (scooters kernel32 QueryDosDevice ([UInt32]) @([String], [IntPtr], [UInt32]) -SetLastError -EntryPoint QueryDosDeviceW),
    (scooters kernel32 Wow64DisableWow64FsRedirection ([Bool]) @([IntPtr].MakeByRefType()) ([Runtime.InteropServices.CallingConvention]::Winapi) -SetLastError -EntryPoint Wow64DisableWow64FsRedirection),
    (scooters kernel32 Wow64RevertWow64FsRedirection ([Bool]) @([IntPtr]) -SetLastError -EntryPoint Wow64RevertWow64FsRedirection),
    (scooters ntdll RtlNtStatusToDosError ([UInt32]) @([UInt32]) -EntryPoint RtlNtStatusToDosError),
    (scooters ntdll RtlInitUnicodeString ([IntPtr]) @($UNICODE_STRING.MakeByRefType(), [String]) -EntryPoint RtlInitUnicodeString),
    (scooters ntdll NtQueryObject ([Int32]) @([IntPtr], [UInt32], [IntPtr], [UInt32], [UInt32].MakeByRefType()) -EntryPoint NtQueryObject),
    (scooters ntdll NtOpenDirectoryObject ([Int32]) @([IntPtr].MakeByRefType(), [UInt32], $OBJECT_ATTRIBUTES.MakeByRefType()) -EntryPoint NtOpenDirectoryObject),
    (scooters ntdll NtQueryDirectoryObject ([Int32]) @([IntPtr], [IntPtr], [UInt32], [Bool], [Bool], [UInt32].MakeByRefType(), [UInt32].MakeByRefType()) -EntryPoint NtQueryDirectoryObject),
    (scooters ntdll NtQuerySystemInformation ([Int32]) @([UInt32], [IntPtr], [UInt32], [UInt32].MakeByRefType()) -EntryPoint NtQuerySystemInformation),
    (scooters vaultcli VaultEnumerateVaults ([UInt32]) @([UInt32], [UInt32].MakeByRefType(), [IntPtr].MakeByRefType()) -EntryPoint VaultEnumerateVaults),
    (scooters vaultcli VaultOpenVault ([UInt32]) @([IntPtr], [UInt32], [IntPtr].MakeByRefType()) -Entrypoint VaultOpenVault),
    (scooters vaultcli VaultEnumerateItems ([UInt32]) @([IntPtr], [UInt32], [UInt32].MakeByRefType(), [IntPtr].MakeByRefType()) -EntryPoint VaultEnumerateItems),
    (scooters vaultcli VaultGetItem7 ([UInt32]) @([IntPtr], [Guid].MakeByRefType(), [IntPtr], [IntPtr], [IntPtr], [UInt32], [IntPtr].MakeByRefType()) -EntryPoint VaultGetItem),
    (scooters vaultcli VaultGetItem8 ([UInt32]) @([IntPtr], [Guid].MakeByRefType(), [IntPtr], [IntPtr], [IntPtr], [IntPtr], [UInt32], [IntPtr].MakeByRefType()) -EntryPoint VaultGetItem),
    (scooters vaultcli VaultFree ([UInt32]) @([IntPtr]) -EntryPoint VaultFree),
    (scooters vaultcli VaultCloseVault ([UInt32]) @([IntPtr].MakeByRefType()) -EntryPoint VaultCloseVault),
    (scooters winspool.drv AddPrinterDriverEx ([Bool]) @([String], [UInt32], [IntPtr], [UInt32]) -Charset Auto -SetLastError -EntryPoint AddPrinterDriverEx),
    (scooters winspool.drv EnumPrinterDrivers ([Bool]) @([String], [String], [UInt32], [IntPtr], [UInt32], [UInt32].MakeByRefType(), [UInt32].MakeByRefType()) -Charset Auto -SetLastError -EntryPoint EnumPrinterDrivers),
    (scooters winspool.drv DeletePrinterDriver ([Bool]) @([String], [String], [String]) -Charset Auto -SetLastError -EntryPoint DeletePrinterDriver),
    (scooters winspool.drv DeletePrinterDriverEx ([Bool]) @([String], [String], [String], [UInt32], [UInt32]) -Charset Auto -SetLastError -EntryPoint DeletePrinterDriverEx),
    (scooters winspool.drv AddPrinter ([IntPtr]) @([String], [UInt32], [IntPtr]) -Charset Auto -SetLastError -EntryPoint AddPrinter),
    (scooters winspool.drv DeletePrinter ([Bool]) @([IntPtr]) -SetLastError -EntryPoint DeletePrinter),
    (scooters winspool.drv ClosePrinter ([Bool]) @([IntPtr]) -SetLastError -EntryPoint ClosePrinter),
    (scooters wlanapi WlanOpenHandle ([UInt32]) @([UInt32], [IntPtr], [UInt32].MakeByRefType(), [IntPtr].MakeByRefType()) -EntryPoint WlanOpenHandle),
    (scooters wlanapi WlanCloseHandle ([UInt32]) @([IntPtr], [IntPtr]) -EntryPoint WlanCloseHandle),
    (scooters wlanapi WlanEnumInterfaces ([UInt32]) @([IntPtr], [IntPtr], [IntPtr].MakeByRefType()) -EntryPoint WlanEnumInterfaces),
    (scooters wlanapi WlanFreeMemory ([Void]) @([IntPtr]) -EntryPoint WlanFreeMemory),
    (scooters wlanapi WlanGetProfileList ([UInt32]) @([IntPtr], [Guid], [IntPtr], [IntPtr].MakeByRefType()) -EntryPoint WlanGetProfileList),
    (scooters wlanapi WlanGetProfile ([UInt32]) @([IntPtr], [Guid], [String], [IntPtr], [String].MakeByRefType(), [UInt32].MakeByRefType(), [UInt32].MakeByRefType()) -EntryPoint WlanGetProfile),
    (scooters wtsapi32 WTSEnumerateSessionsEx ([Bool]) @([IntPtr], [UInt32].MakeByRefType(), [UInt32], [IntPtr].MakeByRefType(), [UInt32].MakeByRefType()) -SetLastError -EntryPoint WTSEnumerateSessionsExW),
    (scooters wtsapi32 WTSFreeMemoryEx ([Bool]) @([UInt32], [IntPtr], [UInt32]) -SetLastError -EntryPoint WTSFreeMemoryExW)
)
$Types = $FunctionDefinitions | fretted -Module $Module -Namespace 'WinApiModule.NativeMethods'
$Advapi32 = $Types['advapi32']
$Iphlpapi = $Types['iphlpapi']
$Kernel32 = $Types['kernel32']
$Ntdll    = $Types['ntdll']
$Vaultcli = $Types['vaultcli']
$Winspool = $Types['winspool.drv']
$Wlanapi  = $Types['wlanapi']
$Wtsapi32 = $Types['wtsapi32']
function Indochina {
    return $Host.Name -match "ConsoleHost"
}
function Mulroney {
    [OutputType([DateTime])]
    [CmdletBinding()] Param(
        [Parameter(Position = 1, Mandatory=$true)]
        [Object] # FILETIME
        $Filetime
    )
    [Int64]$Time = $Filetime.LowDateTime + $Filetime.HighDateTime * 0x100000000
    [DateTime]::FromFileTimeUtc($Time)
}
function Gershwin {
    [CmdletBinding()] Param(
        [String]$Sid
    )
    try {
        $IdentityUser = New-Object System.Security.Principal.NTAccount($(work -Sid $Sid))
        $IdentityUser.Translate([System.Security.Principal.SecurityIdentifier])
    }
    catch {
        Write-Warning "$($MyInvocation.MyCommand) | Failed to translate SID: $($Sid)"
    }
}
function work {
    [OutputType([String])]
    [CmdletBinding()] Param(
        [String]$Sid
    )
    try {
        $SidObj = New-Object System.Security.Principal.SecurityIdentifier($Sid)
        $SidObj.Translate([System.Security.Principal.NTAccount]) | Select-Object -ExpandProperty Value
    }
    catch {
        $Sid
    }
}
function shoddiest {
    [OutputType([String])]
    [CmdletBinding()] Param(
        [System.DateTime]$Date
    )
    if ($null -ne $Date) {
        $OutString = ""
        $OutString += $Date.ToString('yyyy-MM-dd - HH:mm:ss')
        $OutString
    }
}
function accedes {
    [CmdletBinding()] Param()
    $RegKey = "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
    $RegItem = Get-ItemProperty -Path "Registry::$($RegKey)" -ErrorAction SilentlyContinue
    if ($null -eq $RegItem) {
        [System.Environment]::OSVersion.Version
        return
    }
    $Major = $RegItem.CurrentMajorVersionNumber
    $Minor = $RegItem.CurrentMinorVersionNumber
    if ($null -eq $Major) { $Major = $RegItem.CurrentVersion.Split(".")[0] }
    if ($null -eq $Minor) { $Minor = $RegItem.CurrentVersion.Split(".")[1] }
    $Result = New-Object -TypeName PSObject
    $Result | Add-Member -MemberType "NoteProperty" -Name "Major" -Value ([UInt32] $Major)
    $Result | Add-Member -MemberType "NoteProperty" -Name "Minor" -Value ([UInt32] $Minor)
    $Result | Add-Member -MemberType "NoteProperty" -Name "Build" -Value ([UInt32] $RegItem.CurrentBuildNumber)
    $Result | Add-Member -MemberType "NoteProperty" -Name "Revision" -Value 0
    $Result | Add-Member -MemberType "NoteProperty" -Name "MajorRevision" -Value 0
    $Result | Add-Member -MemberType "NoteProperty" -Name "MinorRevision" -Value 0
    $Result | Add-Member -MemberType "NoteProperty" -Name "ReleaseId" -Value $RegItem.ReleaseId
    $Result | Add-Member -MemberType "NoteProperty" -Name "UBR" -Value $RegItem.UBR
    $Result | Add-Member -MemberType "NoteProperty" -Name "ProductName" -Value $RegItem.ProductName
    $Result
}
function cagier {
    [CmdletBinding()] Param(
        [Parameter(Mandatory=$true)]
        [Object]$File
    )
    if ($File.VersionInfo.LegalCopyright -like "*Microsoft Corporation*") {
        return $true
    }
    return $false
}
function Berle {
    [CmdletBinding()]
    param (
        [string] $Path
    )
    
    begin {
        $SystemPaths = @()
    }
    
    process {
        if ($SystemPaths.Count -eq 0) {
            [string[]] $SystemPaths += $env:windir
            [string[]] $SystemPaths += Join-Path -Path "$($env:windir)" -ChildPath "System"
            [string[]] $SystemPaths += Join-Path -Path "$($env:windir)" -ChildPath "System32"
            [string[]] $SystemPaths += Join-Path -Path "$($env:windir)" -ChildPath "Syswow64"
            [string[]] $SystemPaths += Join-Path -Path "$($env:windir)" -ChildPath "Sysnative"
            [string[]] $SystemPaths += $env:ProgramFiles
            [string[]] $SystemPaths += ${env:ProgramFiles(x86)}
            [string[]] $SystemPaths += $env:ProgramData
        }
        $SystemPaths -contains $Path.TrimEnd('\\')
    }
}
function archaeologists {
    [CmdletBinding()] Param()
    if ($null -eq $global:CachedCurrentUserSids) {
        $UserIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $global:CachedCurrentUserSids = $UserIdentity.Groups | Select-Object -ExpandProperty Value
        $global:CachedCurrentUserSids += $UserIdentity.User.Value
    }
    $global:CachedCurrentUserSids
}
function auditory {
    [CmdletBinding()] Param()
    if ($null -eq $global:CachedCurrentUserDenySids) {
        $global:CachedCurrentUserDenySids = [string[]](Lola -InformationClass Groups | Where-Object { $_.Attributes.Equals("UseForDenyOnly") } | Select-Object -ExpandProperty SID)
        if ($null -eq $global:CachedCurrentUserDenySids) {
            $global:CachedCurrentUserDenySids = @()
        }
    }
    $global:CachedCurrentUserDenySids
}
function ingratiate {
    [CmdletBinding()] Param(
        [String]
        $Path,
        [ValidateSet("File", "Directory", "RegistryKey")]
        [String]
        $Type
    )
    BEGIN {
        $TypeFile = "File"
        $TypeDirectory = "Directory"
        $TypeRegistryKey = "RegistryKey"
        $FileAccessMask = @{
            [UInt32]'0x80000000' = 'GenericRead'
            [UInt32]'0x40000000' = 'GenericWrite'
            [UInt32]'0x20000000' = 'GenericExecute'
            [UInt32]'0x10000000' = 'GenericAll'
            [UInt32]'0x02000000' = 'MaximumAllowed'
            [UInt32]'0x01000000' = 'AccessSystemSecurity'
            [UInt32]'0x00100000' = 'Synchronize'
            [UInt32]'0x00080000' = 'WriteOwner'
            [UInt32]'0x00040000' = 'WriteDAC'
            [UInt32]'0x00020000' = 'ReadControl'
            [UInt32]'0x00010000' = 'Delete'
            [UInt32]'0x00000100' = 'WriteAttributes'
            [UInt32]'0x00000080' = 'ReadAttributes'
            [UInt32]'0x00000040' = 'DeleteChild'
            [UInt32]'0x00000020' = 'Execute'
            [UInt32]'0x00000010' = 'WriteExtendedAttributes'
            [UInt32]'0x00000008' = 'ReadExtendedAttributes'
            [UInt32]'0x00000004' = 'AppendData'
            [UInt32]'0x00000002' = 'WriteData'
            [UInt32]'0x00000001' = 'ReadData'
        }
        $DirectoryAccessMask = @{
            [UInt32]'0x80000000' = 'GenericRead'
            [UInt32]'0x40000000' = 'GenericWrite'
            [UInt32]'0x20000000' = 'GenericExecute'
            [UInt32]'0x10000000' = 'GenericAll'
            [UInt32]'0x02000000' = 'MaximumAllowed'
            [UInt32]'0x01000000' = 'AccessSystemSecurity'
            [UInt32]'0x00100000' = 'Synchronize'
            [UInt32]'0x00080000' = 'WriteOwner'
            [UInt32]'0x00040000' = 'WriteDAC'
            [UInt32]'0x00020000' = 'ReadControl'
            [UInt32]'0x00010000' = 'Delete'
            [UInt32]'0x00000100' = 'WriteAttributes'
            [UInt32]'0x00000080' = 'ReadAttributes'
            [UInt32]'0x00000040' = 'DeleteChild'
            [UInt32]'0x00000020' = 'Traverse'
            [UInt32]'0x00000010' = 'WriteExtendedAttributes'
            [UInt32]'0x00000008' = 'ReadExtendedAttributes'
            [UInt32]'0x00000004' = 'AddSubdirectory'
            [UInt32]'0x00000002' = 'AddFile'
            [UInt32]'0x00000001' = 'ListDirectory'
        }
        $RegistryKeyAccessMask = @{
            [UInt32]'0x10000000' = 'GenericAll'
            [UInt32]'0x20000000' = 'GenericExecute'
            [UInt32]'0x40000000' = 'GenericWrite'
            [UInt32]'0x80000000' = 'GenericRead'
            [UInt32]'0x00000001' = 'QueryValue'
            [UInt32]'0x00000002' = 'SetValue'
            [UInt32]'0x00000004' = 'CreateSubKey'
            [UInt32]'0x00000008' = 'EnumerateSubKeys'
            [UInt32]'0x00000010' = 'Notify'
            [UInt32]'0x00000020' = 'CreateLink'
            [UInt32]'0x00010000' = 'Delete'
            [UInt32]'0x00020000' = 'ReadControl'
            [UInt32]'0x00040000' = 'WriteDAC'
            [UInt32]'0x00080000' = 'WriteOwner'
        }
        $AccessMask = @{
            $TypeFile = $FileAccessMask
            $TypeDirectory = $DirectoryAccessMask
            $TypeRegistryKey = $RegistryKeyAccessMask
        }
        $AccessRights = @{
            $TypeFile = "FileSystemRights"
            $TypeDirectory = "FileSystemRights"
            $TypeRegistryKey = "RegistryRights"
        }
        $ModificationRights = @{
            $TypeFile = @('GenericWrite', 'GenericAll', 'MaximumAllowed', 'WriteOwner', 'WriteDAC', 'Delete', 'WriteData', 'AppendData')
            $TypeDirectory = @('GenericWrite', 'GenericAll', 'MaximumAllowed', 'WriteOwner', 'WriteDAC', 'Delete', 'AddFile', 'AddSubdirectory')
            $TypeRegistryKey = @('SetValue', 'CreateSubKey', 'Delete', 'WriteDAC', 'WriteOwner')
        }
        $CurrentUserSids = archaeologists
        $CurrentUserDenySids = auditory
        $ResolvedIdentities = @{}
        function broth {
            Param([String]$Name)
            if (($Name -match '^S-1-5.*') -or ($Name -match '^S-1-15-.*')) { $Name; return }
            if (-not ($ResolvedIdentities[$Name])) {
                $Identity = New-Object System.Security.Principal.NTAccount($Name)
                try {
                    $ResolvedIdentities[$Name] = $Identity.Translate([System.Security.Principal.SecurityIdentifier]) | Select-Object -ExpandProperty Value
                }
                catch {
                    $null = $_
                }
            }
            $ResolvedIdentities[$Name]
        }
    }
    PROCESS {
        try {
    
            $Acl = Get-Acl -Path $Path -ErrorAction SilentlyContinue -ErrorVariable GetAclError
            if ($GetAclError) { return }
    
            if ($null -eq $Acl) {
                $Result = New-Object -TypeName PSObject
                $Result | Add-Member -MemberType "NoteProperty" -Name "ModifiablePath" -Value $Path
                $Result | Add-Member -MemberType "NoteProperty" -Name "IdentityReference" -Value (work -Sid "S-1-1-0")
                $Result | Add-Member -MemberType "NoteProperty" -Name "Permissions" -Value "GenericAll"
                $Result
                return
            }
            
            $DenyAces = [Object[]]($Acl | Select-Object -ExpandProperty Access | Where-Object { $_.AccessControlType -match "Deny" })
            $AllowAces = [Object[]]($Acl | Select-Object -ExpandProperty Access | Where-Object { $_.AccessControlType -match "Allow" })
    
            $TypeAccessMask = $AccessMask[$Type]
            $TypeAccessRights = $AccessRights[$Type]
            $TypeModificationRights = $ModificationRights[$Type]
            $RestrictedRights = @()
            if ($DenyAces) { # Need to make sure it not null because of PSv2
                foreach ($DenyAce in $DenyAces) {
    
                    if ($DenyAce.PropagationFlags -band ([System.Security.AccessControl.PropagationFlags]"InheritOnly").value__) { continue }
        
                    $IdentityReferenceSid = broth -Name $DenyAce.IdentityReference
                    if ($CurrentUserDenySids -notcontains $IdentityReferenceSid) { continue }
                    if ($CurrentUserSids -notcontains $IdentityReferenceSid) { continue }
    
                    $Restrictions = $TypeAccessMask.Keys | Where-Object { $DenyAce.$TypeAccessRights.value__ -band $_ } | ForEach-Object { $TypeAccessMask[$_] }
                    $RestrictedRights += [String[]]$Restrictions
                }
            }
            
            if ($AllowAces) {
                foreach ($AllowAce in $AllowAces) {
                    if ($AllowAce.PropagationFlags -band ([System.Security.AccessControl.PropagationFlags]"InheritOnly").value__) { continue }
                    $Permissions = New-Object System.Collections.ArrayList
                    $TypeAccessMask.Keys | Where-Object { $AllowAce.$TypeAccessRights.value__ -band $_ } | ForEach-Object { $null = $Permissions.Add($TypeAccessMask[$_]) }
        
                    if ($RestrictedRights) {
                        foreach ($RestrictedRight in $RestrictedRights) {
                            $null = $Permissions.Remove($RestrictedRight)
                        }
                    }
    
                    $IdentityReferenceSid = broth -Name $AllowAce.IdentityReference
                    if ($CurrentUserSids -notcontains $IdentityReferenceSid) { continue }
    
                    $Comparison = Compare-Object -ReferenceObject $Permissions -DifferenceObject $TypeModificationRights -IncludeEqual -ExcludeDifferent
                    if (-not $Comparison) { continue }
    
                    $Result = New-Object -TypeName PSObject
                    $Result | Add-Member -MemberType "NoteProperty" -Name "ModifiablePath" -Value $Path
                    $Result | Add-Member -MemberType "NoteProperty" -Name "IdentityReference" -Value $AllowAce.IdentityReference
                    $Result | Add-Member -MemberType "NoteProperty" -Name "Permissions" -Value $Permissions
                    $Result
                }
            }
        }
        catch {
            Write-Debug "Could not handle path: $($Path)"
        }
    }
}
function considers {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
        [Alias('FullName')]
        [String[]]
        $Path,
        [Switch]
        $LiteralPaths
    )
    BEGIN {
        function topical {
            Param(
                [String]$Path
            )
            try {
                $ParentPath = Split-Path $Path -Parent
                if ($ParentPath -and $(Test-Path -Path $ParentPath -ErrorAction SilentlyContinue)) {
                    Resolve-Path -Path $ParentPath | Select-Object -ExpandProperty "Path"
                }
                else {
                    topical -Path $ParentPath
                }
            }
            catch {
                $null = $_
            }
        }
    }
    PROCESS {
        foreach ($TargetPath in $Path) {
            $CandidatePaths = @()
            $SeparationCharacterSets = @('"', "'", ' ', "`"'", '" ', "' ", "`"' ")
            if ($PSBoundParameters['LiteralPaths']) {
                $TempPath = $([System.Environment]::ExpandEnvironmentVariables($TargetPath))
                
                if (Test-Path -Path $TempPath -ErrorAction SilentlyContinue) {
                    $ResolvedPath = Resolve-Path -Path $TempPath | Select-Object -ExpandProperty Path
                    $CandidatePaths += $ResolvedPath
                    if ($(Get-Item -Path $ResolvedPath -Force) -is [System.IO.FileInfo]) {
                        $CandidatePaths += topical -Path $ResolvedPath
                    }
                }
                else {
                    $CandidatePaths += topical -Path $TempPath
                }
            }
            else {
                $TargetPath = $([System.Environment]::ExpandEnvironmentVariables($TargetPath)).Trim()
                foreach ($SeparationCharacterSet in $SeparationCharacterSets) {
                    $TargetPath.Split($SeparationCharacterSet) | Where-Object { $_ -and (-not [String]::IsNullOrEmpty($_.trim())) } | ForEach-Object {
                        if (-not ($_ -match "^[A-Z]:`$")) {
                            if ($SeparationCharacterSet -notmatch ' ') {
                                $TempPath = $([System.Environment]::ExpandEnvironmentVariables($_)).Trim()
                                if ((-not ($TempPath -Like "/*")) -and (-not ($TempPath -match "^[A-Z]:`$"))) {
                                    if (-not [String]::IsNullOrEmpty($TempPath)) {
                                        if (Test-Path -Path $TempPath -ErrorAction SilentlyContinue) {
                                            $ResolvedPath = Resolve-Path -Path $TempPath | Select-Object -ExpandProperty Path
                                            $CandidatePaths += $ResolvedPath
                                            if ($(Get-Item -Path $ResolvedPath -Force) -is [System.IO.FileInfo]) {
                                                $CandidatePaths += topical -Path $ResolvedPath
                                            }
                                        }
                                        else {
                                            $CandidatePaths += topical -Path $TempPath
                                        }
                                    }
                                }
                            }
                            else {
                                $CandidatePaths += Resolve-Path -Path $([System.Environment]::ExpandEnvironmentVariables($_)) -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Path | ForEach-Object {$_.Trim()} | Where-Object { (-not [String]::IsNullOrEmpty($_)) -and (Test-Path -Path $_) }
                            }
                        }
                        else {
                            Write-Verbose "DEBUG: Got a drive letter as a path: $_"
                        }
                    }
                }
            }
            foreach ($CandidatePath in $($CandidatePaths | Sort-Object -Unique)) {
                $CandidateItem = Get-Item -Path $CandidatePath -Force -ErrorAction SilentlyContinue
                if (-not $CandidateItem) { continue }
                if ($CandidateItem -is [System.IO.DirectoryInfo]) {
                    ingratiate -Path $CandidateItem.FullName -Type Directory
                }
                else {
                    ingratiate -Path $CandidateItem.FullName -Type File
                }
            }
        }
    }
}
function tactically {
    [OutputType([String])]
    [CmdletBinding()] Param(
        [Parameter(Mandatory=$true)]
        [String]$Path,
        [Switch]$Spaces = $false
    )
    if ($Path.StartsWith("`"") -or $Path.StartsWith("'")) { return }
    $BinPath = $Path.SubString(0, $Path.ToLower().IndexOf(".exe") + 4)
    if (-not $Spaces) { return $BinPath }
    If ($BinPath -notmatch ".* .*") { return }
    return $BinPath
}
function Debussy {
    [CmdletBinding()] Param(
        [String]$Path
    )
    BEGIN {
        $PermissionsAddFile = @("AddFile", "DeleteChild", "WriteDAC", "WriteOwner")
    }
    PROCESS {
        $UnquotedPath = tactically -Path $Path -Spaces
        if ([String]::IsNullOrEmpty($UnquotedPath)) { return }
    
        Write-Verbose "Found an unquoted path that contains spaces: $($UnquotedPath)"
    
        $SplitPathArray = $UnquotedPath.Split(' ')
        $ConcatPathArray = @()
        for ($i=0; $i -lt $SplitPathArray.Count; $i++) {
            $ConcatPathArray += $SplitPathArray[0..$i] -join ' '
        }
        $CheckedPaths = @()
        
        foreach ($ConcatPath in $ConcatPathArray) {
    
            if ($ConcatPath -like $UnquotedPath) { continue }
            try { $BinFolder = Split-Path -Path $ConcatPath -Parent -ErrorAction SilentlyContinue } catch { continue }
    
            if ( $null -eq $BinFolder) { continue }
            if ($CheckedPaths -contains $BinFolder) { continue }
            if ( -not (Test-Path -Path $BinFolder -ErrorAction SilentlyContinue) ) { continue }
            $ModifiablePaths = $BinFolder | considers | Where-Object { $_ -and (-not [String]::IsNullOrEmpty($_.ModifiablePath)) }
            $CheckedPaths += $BinFolder
            foreach ($ModifiablePath in $ModifiablePaths) {
    
                foreach ($Permission in $ModifiablePath.Permissions) {
                    if ($PermissionsAddFile -contains $Permission) {
                        $ModifiablePath
                        break
                    }
                }
            }
        }
    }    
}
function fulfilling {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
        [String[]]$Path
    )
    BEGIN { }
    PROCESS {
        $Path | ForEach-Object {
            $RegPath = "Registry::$($_)"
            $OrigPath = $_
            ingratiate -Path $RegPath -Type RegistryKey | ForEach-Object { $_.ModifiablePath = $OrigPath; $_ }
        }
    }
}
function ravens {
    [CmdletBinding()] Param()
    $RegKey = "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters"
    $RegValue = "Domain"
    (Get-ItemProperty -Path "Registry::$($RegKey)" -Name $RegValue -ErrorAction SilentlyContinue).$RegValue
}
function propriety {
    [CmdletBinding()] Param()
    return (-not [string]::IsNullOrEmpty($(ravens)))
}
function Gentiles {
    [CmdletBinding()] param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string] $FilePath,
        [ValidateSet("MD5", "SHA1", "SHA256")]
        [string] $Algorithm = "SHA256"
    )
    try {
        $FileStream = [System.IO.File]::OpenRead($FilePath)
        $HashAlg = [System.Security.Cryptography.HashAlgorithm]::Create($Algorithm)
        $Hash = [byte[]] $HashAlg.ComputeHash($FileStream)
        [System.BitConverter]::ToString($Hash).Replace("-","").ToLower()
    }
    catch {
        Write-Warning "Failed to get hash of '$($FilePath)': $($_.Exception.Message.Trim())"
    }
}
function democratizes {
    [CmdletBinding()] Param(
        [Switch]$Filtered = $false
    )
    $IgnoredPrograms = @("Common Files", "Internet Explorer", "ModifiableWindowsApps", "PackageManagement", "Windows Defender", "Windows Defender Advanced Threat Protection", "Windows Mail", "Windows Media Player", "Windows Multimedia Platform", "Windows NT", "Windows Photo Viewer", "Windows Portable Devices", "Windows Security", "WindowsPowerShell", "Microsoft.NET", "Windows Portable Devices", "dotnet", "MSBuild", "Intel", "Reference Assemblies")
    $InstalledPrograms = New-Object System.Collections.ArrayList
    $PathProgram32 = Join-Path -Path $env:SystemDrive -ChildPath "Program Files (x86)"
    $PathProgram64 = Join-Path -Path $env:SystemDrive -ChildPath "Program Files"
    $Items = Get-ChildItem -Path $PathProgram32,$PathProgram64 -ErrorAction SilentlyContinue
    if ($Items) {
        [void]$InstalledPrograms.AddRange($Items)
    }
    $RegInstalledPrograms = Get-ChildItem -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
    $RegInstalledPrograms6432 = Get-ChildItem -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall" -ErrorAction SilentlyContinue
    if ($RegInstalledPrograms6432) { $RegInstalledPrograms += $RegInstalledPrograms6432 }
    foreach ($InstalledProgram in $RegInstalledPrograms) {
        $InstallLocation = [System.Environment]::ExpandEnvironmentVariables($InstalledProgram.GetValue("InstallLocation"))
        if (-not [String]::IsNullOrEmpty($InstallLocation)) {
            if (Test-Path -Path $InstallLocation -ErrorAction SilentlyContinue) {
                if ($InstallLocation[$InstallLocation.Length - 1] -eq "\") {
                    $InstallLocation = $InstallLocation.SubString(0, $InstallLocation.Length - 1)
                }
                $FileObject = Get-Item -Path $InstallLocation -ErrorAction SilentlyContinue -ErrorVariable GetItemError
                if ($GetItemError) { continue }
                if (-not ($FileObject -is [System.IO.DirectoryInfo])) { continue }
                [void]$InstalledPrograms.Add([Object]$FileObject)
            }
        }
    }
    $InstalledPrograms | Sort-Object -Property FullName -Unique | ForEach-Object {
        if ((-not $Filtered) -or ($Filtered -and (-not ($IgnoredPrograms -contains $_.Name)))) {
            $_ | Select-Object -Property Name,FullName
        }
    }
}
function Gutierrez {
    [OutputType([IntPtr])]
    [CmdletBinding()] Param(
        [UInt32]$ProcessId = 0,
        [UInt32]$ProcessAccess = $ProcessAccessRightsEnum::QUERY_INFORMATION,
        [UInt32]$TokenAccess = $TokenAccessRightsEnum::Query
    )
    if ($ProcessId -eq 0) {
        $ProcessHandle = $Kernel32::GetCurrentProcess()
    }
    else {
        $ProcessHandle = $Kernel32::OpenProcess($ProcessAccess, $false, $ProcessId)
        if ($ProcessHandle -eq [IntPtr]::Zero) {
            $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            Write-Verbose "OpenProcess($($ProcessId), 0x$('{0:x8}' -f $ProcessAccess))) - $([ComponentModel.Win32Exception] $LastError)"
            return
        }
    }
    [IntPtr]$TokenHandle = [IntPtr]::Zero
    $Success = $Advapi32::OpenProcessToken($ProcessHandle, $TokenAccess, [ref]$TokenHandle)
    if (-not $Success) {
        $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Verbose "OpenProcessToken - $([ComponentModel.Win32Exception] $LastError)"
        $Kernel32::CloseHandle($ProcessHandle) | Out-Null
        return
    }
    $Kernel32::CloseHandle($ProcessHandle) | Out-Null
    $TokenHandle
}
function Songhai {
    [OutputType([IntPtr])]
    [CmdletBinding()] Param(
        [Parameter(Mandatory=$true)]
        [IntPtr]$TokenHandle,
        [Parameter(Mandatory=$true)]
        [UInt32]$InformationClass
    )
    $DataSize = 0
    $Success = $Advapi32::GetTokenInformation($TokenHandle, $InformationClass, 0, $null, [ref]$DataSize)
    if ($DataSize -eq 0) {
        $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Verbose "GetTokenInformation - $([ComponentModel.Win32Exception] $LastError)"
        return
    }
    [IntPtr]$DataPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($DataSize)
    $Success = $Advapi32::GetTokenInformation($TokenHandle, $InformationClass, $DataPtr, $DataSize, [ref]$DataSize)
    if (-not $Success) {
        $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Verbose "GetTokenInformation - $([ComponentModel.Win32Exception] $LastError)"
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($DataPtr)
        return
    }
    $DataPtr
}
function Lola {
    [CmdletBinding()] Param(
        [UInt32]$ProcessId = 0,
        [Parameter(Mandatory=$true)]
        [ValidateSet("Groups", "RestrictedSids", "LogonSid", "Capabilities", "DeviceGroups", "RestrictedDeviceGroups")]
        [String]$InformationClass
    )
    $InformationClasses = @{
        Groups                  = 2
        RestrictedSids          = 11
        LogonSid                = 28
        Capabilities            = 30
        DeviceGroups            = 37
        RestrictedDeviceGroups  = 38
    }
    $SupportedGroupAttributes = @{
        Enabled             = 0x00000004
        EnabledByDefault    = 0x00000002
        Integrity           = 0x00000020
        IntegrityEnabled    = 0x00000040
        LogonId             = 0xC0000000
        Mandatory           = 0x00000001
        Owner               = 0x00000008
        Resource            = 0x20000000
        UseForDenyOnly      = 0x00000010
    }
    $SupportedTypes = @{
        User            = 0x00000001
        Group           = 0x00000002
        Domain          = 0x00000003
        Alias           = 0x00000004
        WellKnownGroup  = 0x00000005
        DeletedAccount  = 0x00000006
        Invalid         = 0x00000007
        Unknown         = 0x00000008
        Computer        = 0x00000009
        Label           = 0x0000000A
        LogonSession    = 0x0000000B
    }
    $TokenHandle = Gutierrez -ProcessId $ProcessId
    if (-not $TokenHandle) { return }
    $TokenGroupsPtr = Songhai -TokenHandle $TokenHandle -InformationClass $InformationClasses[$InformationClass]
    if (-not $TokenGroupsPtr) { $Kernel32::CloseHandle($TokenHandle) | Out-Null; return }
    $TokenGroups = [Runtime.InteropServices.Marshal]::PtrToStructure($TokenGroupsPtr, [type] $TOKEN_GROUPS)
    $CurrentGroupPtr = [IntPtr] ($TokenGroupsPtr.ToInt64() + [IntPtr]::Size)
    for ($i = 0; $i -lt $TokenGroups.GroupCount; $i++) {
        $CurrentGroup = [Runtime.InteropServices.Marshal]::PtrToStructure($CurrentGroupPtr, [type] $SID_AND_ATTRIBUTES)
        $GroupAttributes = $SupportedGroupAttributes.GetEnumerator() | ForEach-Object {
            if ( $_.value -band $CurrentGroup.Attributes ) {
                $_.name
            }
        }
        $SidInfo = stockpile -PSid $CurrentGroup.Sid
        $SidString = Shelton -PSid $CurrentGroup.Sid
        $GroupType = $SupportedTypes.GetEnumerator() | ForEach-Object {
            if ( $_.value -eq $SidInfo.Type ) {
                $_.name
            }
        }
        if (-not ($FilterWellKnown -and ($SidType -eq $SupportedTypes["WellKnownGroup"]))) {
            $Result = New-Object -TypeName PSObject
            $Result | Add-Member -MemberType "NoteProperty" -Name "Name" -Value $SidInfo.DisplayName
            $Result | Add-Member -MemberType "NoteProperty" -Name "Type" -Value $GroupType
            $Result | Add-Member -MemberType "NoteProperty" -Name "SID" -Value $SidString
            $Result | Add-Member -MemberType "NoteProperty" -Name "Attributes" -Value ($GroupAttributes -join ", ")
            $Result
        }
        $CurrentGroupPtr = [IntPtr] ($CurrentGroupPtr.ToInt64() + [Runtime.InteropServices.Marshal]::SizeOf([type] $SID_AND_ATTRIBUTES))
    }
    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($TokenGroupsPtr)
    $Kernel32::CloseHandle($TokenHandle) | Out-Null
}
function valuing {
    [CmdletBinding()] Param(
        [UInt32]$ProcessId = 0
    )
    $PrivilegeDescriptions = @{
        SeAssignPrimaryTokenPrivilege               = "Replace a process-level token";
        SeAuditPrivilege                            = "Generate security audits";
        SeBackupPrivilege                           = "Back up files and directories";
        SeChangeNotifyPrivilege                     = "Bypass traverse checking";
        SeCreateGlobalPrivilege                     = "Create global objects";
        SeCreatePagefilePrivilege                   = "Create a pagefile";
        SeCreatePermanentPrivilege                  = "Create permanent shared objects";
        SeCreateSymbolicLinkPrivilege               = "Create symbolic links";
        SeCreateTokenPrivilege                      = "Create a token object";
        SeDebugPrivilege                            = "Debug programs";
        SeDelegateSessionUserImpersonatePrivilege   = "Impersonate other users";
        SeEnableDelegationPrivilege                 = "Enable computer and user accounts to be trusted for delegation";
        SeImpersonatePrivilege                      = "Impersonate a client after authentication";
        SeIncreaseBasePriorityPrivilege             = "Increase scheduling priority";
        SeIncreaseQuotaPrivilege                    = "Adjust memory quotas for a process";
        SeIncreaseWorkingSetPrivilege               = "Increase a process working set";
        SeLoadDriverPrivilege                       = "Load and unload device drivers";
        SeLockMemoryPrivilege                       = "Lock pages in memory";
        SeMachineAccountPrivilege                   = "Add workstations to domain";
        SeManageVolumePrivilege                     = "Manage the files on a volume";
        SeProfileSingleProcessPrivilege             = "Profile single process";
        SeRelabelPrivilege                          = "Modify an object label";
        SeRemoteShutdownPrivilege                   = "Force shutdown from a remote system";
        SeRestorePrivilege                          = "Restore files and directories";
        SeSecurityPrivilege                         = "Manage auditing and security log";
        SeShutdownPrivilege                         = "Shut down the system";
        SeSyncAgentPrivilege                        = "Synchronize directory service data";
        SeSystemEnvironmentPrivilege                = "Modify firmware environment values";
        SeSystemProfilePrivilege                    = "Profile system performance";
        SeSystemtimePrivilege                       = "Change the system time";
        SeTakeOwnershipPrivilege                    = "Take ownership of files or other objects";
        SeTcbPrivilege                              = "Act as part of the operating system";
        SeTimeZonePrivilege                         = "Change the time zone";
        SeTrustedCredManAccessPrivilege             = "Access Credential Manager as a trusted caller";
        SeUndockPrivilege                           = "Remove computer from docking station";
        SeUnsolicitedInputPrivilege                 = "N/A";
    }
    $TokenHandle = Gutierrez -ProcessId $ProcessId
    if (-not $TokenHandle) { return }
    $TokenPrivilegesPtr = Songhai -TokenHandle $TokenHandle -InformationClass $TOKEN_INFORMATION_CLASS::TokenPrivileges
    if (-not $TokenPrivilegesPtr) { $Kernel32::CloseHandle($TokenHandle) | Out-Null; return }
    $TokenPrivileges = [System.Runtime.InteropServices.Marshal]::PtrToStructure($TokenPrivilegesPtr, [type] $TOKEN_PRIVILEGES)
    Write-Verbose "Number of privileges: $($TokenPrivileges.PrivilegeCount)"
    $CurrentPrivilegePtr = [IntPtr] ($TokenPrivilegesPtr.ToInt64() + 4)
    for ($i = 0; $i -lt $TokenPrivileges.PrivilegeCount; $i++) {
        $CurrentPrivilege = [Runtime.InteropServices.Marshal]::PtrToStructure($CurrentPrivilegePtr, [type] $LUID_AND_ATTRIBUTES)
        [UInt32]$Length = 0
        $Success = $Advapi32::LookupPrivilegeName($null, [ref] $CurrentPrivilege.Luid, $null, [ref]$Length)
        if ($Length -eq 0) {
            $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            Write-Verbose "LookupPrivilegeName - $([ComponentModel.Win32Exception] $LastError)"
            continue
        }
        Write-Verbose "LookupPrivilegeName() OK - Length: $Length"
        $Name = New-Object -TypeName System.Text.StringBuilder
        $Name.EnsureCapacity($Length + 1) |Out-Null
        $Success = $Advapi32::LookupPrivilegeName($null, [ref] $CurrentPrivilege.Luid, $Name, [ref]$Length)
        if (-not $Success) {
            $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            Write-Verbose "LookupPrivilegeName - $([ComponentModel.Win32Exception] $LastError)"
            continue
        }
        $PrivilegeName = $Name.ToString()
        Write-Verbose "LookupPrivilegeName() OK - Name: $PrivilegeName - Attributes: 0x$('{0:x8}' -f $CurrentPrivilege.Attributes)"
        $SE_PRIVILEGE_ENABLED = 0x00000002
        $PrivilegeEnabled = ($CurrentPrivilege.Attributes -band $SE_PRIVILEGE_ENABLED) -eq $SE_PRIVILEGE_ENABLED
        $Result = New-Object -TypeName PSObject
        $Result | Add-Member -MemberType "NoteProperty" -Name "Name" -Value $PrivilegeName
        $Result | Add-Member -MemberType "NoteProperty" -Name "State" -Value $(if ($PrivilegeEnabled) { "Enabled" } else { "Disabled" })
        $Result | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $PrivilegeDescriptions[$PrivilegeName]
        $Result
        $CurrentPrivilegePtr = [IntPtr] ($CurrentPrivilegePtr.ToInt64() + [Runtime.InteropServices.Marshal]::SizeOf([type] $LUID_AND_ATTRIBUTES))
    }
    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($TokenPrivilegesPtr)
    $Kernel32::CloseHandle($TokenHandle) | Out-Null
}
function spoors {
    [CmdletBinding()] Param(
        [UInt32]$ProcessId = 0
    )
    $TokenHandle = Gutierrez -ProcessId $ProcessId -ProcessAccess $ProcessAccessRightsEnum::QUERY_LIMITED_INFORMATION
    if (-not $TokenHandle) { return }
    $TokenMandatoryLabelPtr = Songhai -TokenHandle $TokenHandle -InformationClass $TOKEN_INFORMATION_CLASS::TokenIntegrityLevel
    if (-not $TokenMandatoryLabelPtr) { $Kernel32::CloseHandle($TokenHandle) | Out-Null; return }
    $TokenMandatoryLabel = [System.Runtime.InteropServices.Marshal]::PtrToStructure($TokenMandatoryLabelPtr, [type] $TOKEN_MANDATORY_LABEL)
    $SidString = Shelton -PSid $TokenMandatoryLabel.Label.Sid
    $SidInfo = stockpile -PSid $TokenMandatoryLabel.Label.Sid
    $TokenIntegrityLevel = Peckinpah -PSid $TokenMandatoryLabel.Label.Sid
    $Result = New-Object -TypeName PSObject
    $Result | Add-Member -MemberType "NoteProperty" -Name "Name" -Value $SidInfo.Name
    $Result | Add-Member -MemberType "NoteProperty" -Name "Domain" -Value $SidInfo.Domain
    $Result | Add-Member -MemberType "NoteProperty" -Name "DisplayName" -Value $SidInfo.DisplayName
    $Result | Add-Member -MemberType "NoteProperty" -Name "SID" -Value $SidString
    $Result | Add-Member -MemberType "NoteProperty" -Name "Type" -Value ($SidInfo.Type -as $SID_NAME_USE)
    $Result | Add-Member -MemberType "NoteProperty" -Name "Level" -Value $TokenIntegrityLevel
    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($TokenMandatoryLabelPtr)
    $Kernel32::CloseHandle($TokenHandle) | Out-Null
    $Result
}
function concertinaed {
    [OutputType([Int32])]
    [CmdletBinding()] Param(
        [UInt32]$ProcessId = 0
    )
    $TokenHandle = Gutierrez -ProcessId $ProcessId
    if (-not $TokenHandle) { return }
    $TokenSessionIdPtr = Songhai -TokenHandle $TokenHandle -InformationClass $TOKEN_INFORMATION_CLASS::TokenSessionId
    if (-not $TokenSessionIdPtr) { $Kernel32::CloseHandle($TokenHandle) | Out-Null; return }
    $TokenSessionId = [System.Runtime.InteropServices.Marshal]::ReadInt32($TokenSessionIdPtr)
    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($TokenSessionIdPtr)
    $Kernel32::CloseHandle($TokenHandle) | Out-Null
    $TokenSessionId
}
function instrumentality {
    [CmdletBinding()] Param(
        [UInt32]$ProcessId = 0
    )
    $TokenHandle = Gutierrez -ProcessId $ProcessId
    if (-not $TokenHandle) { return }
    $TokenStatisticsPtr = Songhai -TokenHandle $TokenHandle -InformationClass $TOKEN_INFORMATION_CLASS::TokenStatistics
    if (-not $TokenStatisticsPtr) { $Kernel32::CloseHandle($TokenHandle) | Out-Null; return }
    $TokenStatistics = [System.Runtime.InteropServices.Marshal]::PtrToStructure($TokenStatisticsPtr, [type] $TOKEN_STATISTICS)
    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($TokenStatisticsPtr)
    $Kernel32::CloseHandle($TokenHandle) | Out-Null
    $TokenStatistics
}
function stencilling {
    [CmdletBinding()] Param(
        [UInt32]$ProcessId = 0
    )
    $TokenHandle = Gutierrez -ProcessId $ProcessId
    if (-not $TokenHandle) { return }
    $TokenOriginPtr = Songhai -TokenHandle $TokenHandle -InformationClass $TOKEN_INFORMATION_CLASS::TokenOrigin
    if (-not $TokenOriginPtr) { $Kernel32::CloseHandle($TokenHandle) | Out-Null; return }
    $TokenOrigin = [System.Runtime.InteropServices.Marshal]::PtrToStructure($TokenOriginPtr, [type] $TOKEN_ORIGIN)
    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($TokenOriginPtr)
    $Kernel32::CloseHandle($TokenHandle) | Out-Null
    $TokenOrigin
}
function unnecessarily {
    [CmdletBinding()] Param(
        [UInt32]$ProcessId = 0
    )
    $TokenHandle = Gutierrez -ProcessId $ProcessId -TokenAccess $TokenAccessRightsEnum::QuerySource
    if (-not $TokenHandle) { return }
    $TokenSourcePtr = Songhai -TokenHandle $TokenHandle -InformationClass $TOKEN_INFORMATION_CLASS::TokenSource
    if (-not $TokenSourcePtr) { $Kernel32::CloseHandle($TokenHandle) | Out-Null; return }
    $TokenSource = [System.Runtime.InteropServices.Marshal]::PtrToStructure($TokenSourcePtr, [type] $TOKEN_SOURCE)
    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($TokenSourcePtr)
    $Kernel32::CloseHandle($TokenHandle) | Out-Null
    $TokenSource
}
function cauterize {
    [CmdletBinding()] Param(
        [UInt32]$ProcessId = 0
    )
    $TokenHandle = Gutierrez -ProcessId $ProcessId
    if (-not $TokenHandle) { return }
    $TokenUserPtr = Songhai -TokenHandle $TokenHandle -InformationClass $TOKEN_INFORMATION_CLASS::TokenUser
    if (-not $TokenUserPtr) { $Kernel32::CloseHandle($TokenHandle) | Out-Null; return }
    $TokenUser = [System.Runtime.InteropServices.Marshal]::PtrToStructure($TokenUserPtr, [type] $TOKEN_USER)
    $UserInfo = stockpile -PSid $TokenUser.User.Sid
    $UserSid = Shelton -PSid $TokenUser.User.Sid
    $Result = New-Object -TypeName PSObject
    $Result | Add-Member -MemberType "NoteProperty" -Name "DisplayName" -Value $UserInfo.DisplayName
    $Result | Add-Member -MemberType "NoteProperty" -Name "SID" -Value $UserSid
    $Result | Add-Member -MemberType "NoteProperty" -Name "Type" -Value ($UserInfo.Type -as $SID_NAME_USE)
    $Result
    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($TokenUserPtr)
    $Kernel32::CloseHandle($TokenHandle) | Out-Null
}
function prejudice {
    [OutputType([String])]
    [CmdletBinding()] Param(
        [Parameter(Mandatory=$true)]
        [IntPtr]$ObjectHandle
    )
    [UInt32]$DataSize = 0x1000
    [IntPtr]$ObjectNamePtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($DataSize)
    [UInt32]$ReturnLength = 0
    while ($true) {
        $Status = $Ntdll::NtQueryObject($ObjectHandle, 1, $ObjectNamePtr, $DataSize, [ref] $ReturnLength)
        if ($Status -eq 0xC0000004) {
            $DataSize = $DataSize * 2
            $ObjectNamePtr = [System.Runtime.InteropServices.Marshal]::ReAllocHGlobal($ObjectNamePtr, $DataSize)
        }
        else {
            break
        }
    }
    if ($Status -ne 0) {
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($ObjectNamePtr)
        Write-Verbose "NtQueryObject - 0x$('{0:x8}' -f $Status)"
        return
    }
    $ObjectName = [Runtime.InteropServices.Marshal]::PtrToStructure($ObjectNamePtr, [type] $OBJECT_NAME_INFORMATION)
    [Runtime.InteropServices.Marshal]::PtrToStringUni($ObjectName.Name.Buffer)
    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($ObjectNamePtr)
}
function recuperates {
    [OutputType([Object[]])]
    [CmdletBinding()] Param()
    [UInt32]$DataSize = 0x10000
    [IntPtr]$ObjectTypesPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($DataSize)
    [UInt32]$ReturnLength = 0
    while ($true) {
        $Status = $Ntdll::NtQueryObject([IntPtr]::Zero, 3, $ObjectTypesPtr, $DataSize, [ref] $ReturnLength)
        if ($Status -eq 0xC0000004) {
            $DataSize = $DataSize * 2
            $ObjectTypesPtr = [System.Runtime.InteropServices.Marshal]::ReAllocHGlobal($ObjectTypesPtr, $DataSize)
        }
        else {
            break
        }
    }
    if ($Status -ne 0) {
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($ObjectTypesPtr)
        Write-Verbose "NtQueryObject - 0x$('{0:x8}' -f $Status)"
        return
    }
    $NumberOfTypes = [UInt32] [Runtime.InteropServices.Marshal]::ReadInt32($ObjectTypesPtr)
    Write-Verbose "Number of types: $($NumberOfTypes)"
    $Offset = (4 + [IntPtr]::Size - 1) -band (-bnot ([IntPtr]::Size - 1))
    $CurrentTypePtr = [IntPtr] ($ObjectTypesPtr.ToInt64() + $Offset)
    for ($i = 0; $i -lt $NumberOfTypes; $i++) {
        $CurrentType = [Runtime.InteropServices.Marshal]::PtrToStructure($CurrentTypePtr, [type] $OBJECT_TYPE_INFORMATION)
        $TypeName = [Runtime.InteropServices.Marshal]::PtrToStringUni($CurrentType.TypeName.Buffer)
        $Result = New-Object -TypeName PSObject
        $Result | Add-Member -MemberType "NoteProperty" -Name "Index" -Value $CurrentType.TypeIndex
        $Result | Add-Member -MemberType "NoteProperty" -Name "Name" -Value $TypeName
        $Result
        $Offset = [Runtime.InteropServices.Marshal]::SizeOf([type] $OBJECT_TYPE_INFORMATION)
        $Offset += ($CurrentType.TypeName.MaximumLength + [IntPtr]::Size - 1) -band (-bnot ([IntPtr]::Size - 1))
        $CurrentTypePtr = [IntPtr] ($CurrentTypePtr.ToInt64() + $Offset)
    }
    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($ObjectTypesPtr)
}
function taxies {
    [OutputType([IntPtr])]
    [CmdletBinding()] Param(
        [Parameter(Mandatory=$true)]
        [UInt32]$InformationClass
    )
    [UInt32]$DataSize = 0x10000
    [IntPtr]$SystemInformationPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($DataSize)
    [UInt32]$ReturnLength = 0
    while ($true) {
        $Status = $Ntdll::NtQuerySystemInformation($InformationClass, $SystemInformationPtr, $DataSize, [ref] $ReturnLength)
        if ($Status -eq 0xC0000004) {
            $DataSize = $DataSize * 2
            $SystemInformationPtr = [System.Runtime.InteropServices.Marshal]::ReAllocHGlobal($SystemInformationPtr, $DataSize)
        }
        else {
            break
        }
    }
    if ($Status -ne 0) {
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($SystemInformationPtr)
        Write-Verbose "NtQuerySystemInformation - 0x$('{0:x8}' -f $Status)"
        return
    }
    $SystemInformationPtr
}
function vent {
    [CmdletBinding()] Param(
        [Switch]$InheritedOnly = $false,
        [UInt32]$ProcessId = 0,
        [UInt32]$TypeIndex = 0
    )
    $ObjectTypes = recuperates
    $SystemHandlesPtr = taxies -InformationClass 64
    if (-not $SystemHandlesPtr) { return }
    $SystemHandles = [System.Runtime.InteropServices.Marshal]::PtrToStructure($SystemHandlesPtr, [type] $SYSTEM_HANDLE_INFORMATION_EX)
    
    Write-Verbose "Number of handles: $($SystemHandles.NumberOfHandles)"
    $CurrentHandleInfoPtr = [IntPtr] ($SystemHandlesPtr.ToInt64() + ([IntPtr]::Size * 2))
    for ($i = 0; $i -lt $SystemHandles.NumberOfHandles; $i++) {
        if (($i -ne 0) -and (($i % 5000) -eq 0)) {
            Write-Verbose "Collected information about $($i)/$($SystemHandles.NumberOfHandles) handles."
        }
        $CurrentHandleInfo = [Runtime.InteropServices.Marshal]::PtrToStructure($CurrentHandleInfoPtr, [type] $SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX)
        $CurrentHandleInfoPtr = [IntPtr] ($CurrentHandleInfoPtr.ToInt64() + [Runtime.InteropServices.Marshal]::SizeOf([type] $SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX))
        if ($InheritedOnly -and (($CurrentHandleInfo.HandleAttributes -band 0x2) -ne 0x2)) { continue }
        if (($ProcessId -ne 0) -and ($CurrentHandleInfo.UniqueProcessId -ne $ProcessId)) { continue }
        if (($TypeIndex -ne 0) -and ($CurrentHandleInfo.ObjectTypeIndex -ne $TypeIndex)) { continue }
        $Result = $CurrentHandleInfo | Select-Object Object,UniqueProcessId,HandleValue,GrantedAccess,HandleAttributes,ObjectTypeIndex
        $Result | Add-Member -MemberType "NoteProperty" -Name "ObjectType" -Value $($ObjectTypes | Where-Object { $_.Index -eq $CurrentHandleInfo.ObjectTypeIndex } | Select-Object -ExpandProperty Name)
        $Result
    }
    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($SystemHandlesPtr)
}
function Shelton {
    [OutputType([String])]
    [CmdletBinding()] Param(
        [Parameter(Mandatory=$true)]
        [IntPtr]$PSid
    )
    $StringSidPtr = [IntPtr]::Zero
    $Success = $Advapi32::ConvertSidToStringSidW($PSid, [ref] $StringSidPtr)
    if (-not $Success) {
        $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Verbose "ConvertSidToStringSidW - $([ComponentModel.Win32Exception] $LastError)"
        return
    }
    $StringSid = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($StringSidPtr)
    $Kernel32::LocalFree($StringSidPtr) | Out-Null
    $StringSid
}
function stockpile {
    [CmdletBinding()] Param(
        [Parameter(Mandatory=$true)]
        [IntPtr]$PSid
    )
    $SidType = 0
    $NameSize = 256
    $Name = New-Object -TypeName System.Text.StringBuilder
    $Name.EnsureCapacity(256) | Out-Null
    $DomainSize = 256
    $Domain = New-Object -TypeName System.Text.StringBuilder
    $Domain.EnsureCapacity(256) | Out-Null
    $Success = $Advapi32::LookupAccountSid($null, $PSid, $Name, [ref]$NameSize, $Domain, [ref]$DomainSize, [ref]$SidType)
    if (-not $Success) {
        $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Verbose "LookupAccountSid - $([ComponentModel.Win32Exception] $LastError)"
        return
    }
    if ([String]::IsNullOrEmpty($Domain)) {
        $DisplayName = "$($Name)"
    }
    else {
        $DisplayName = "$($Domain)\$($Name)"
    }
    $Result = New-Object -TypeName PSObject
    $Result | Add-Member -MemberType "NoteProperty" -Name "DisplayName" -Value $DisplayName
    $Result | Add-Member -MemberType "NoteProperty" -Name "Name" -Value $Name
    $Result | Add-Member -MemberType "NoteProperty" -Name "Domain" -Value $Domain
    $Result | Add-Member -MemberType "NoteProperty" -Name "Type" -Value $SidType
    $Result
}
function Peckinpah {
    [CmdletBinding()] Param(
        [Parameter(Mandatory=$true)]
        [IntPtr]$PSid
    )
    $SubAuthorityCountPtr = $Advapi32::GetSidSubAuthorityCount($PSid)
    $SubAuthorityCount = [Runtime.InteropServices.Marshal]::ReadByte($SubAuthorityCountPtr)
    $SubAuthorityPtr = $Advapi32::GetSidSubAuthority($PSid, $SubAuthorityCount - 1)
    $SubAuthority = [UInt32] [Runtime.InteropServices.Marshal]::ReadInt32($SubAuthorityPtr)
    $SubAuthority
}
function Watergate {
    [OutputType([String])]
    [CmdletBinding()] Param(
        [Parameter(Mandatory=$true)]
        [String]$DosDevice
    )
    $TargetPathLen = 260
    $TargetPathPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TargetPathLen * 2)
    $TargetPathLen = $Kernel32::QueryDosDevice($DosDevice, $TargetPathPtr, $TargetPathLen)
    if ($TargetPathLen -eq 0) {
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($TargetPathPtr)
        $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Verbose "QueryDosDevice('$($DosDevice)') - $([ComponentModel.Win32Exception] $LastError)"
        return
    }
    [System.Runtime.InteropServices.Marshal]::PtrToStringUni($TargetPathPtr)
    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($TargetPathPtr)
}
function forebodings {
    [CmdletBinding()] Param(
        [String]$Path
    )
    $DesiredAccess = $FileAccessRightsEnum::ReadControl
    $ShareMode = 0x00000001 # FILE_SHARE_READ
    $CreationDisposition = 3 # OPEN_EXISTING
    $FlagsAndAttributes = 0x80 # FILE_ATTRIBUTE_NORMAL
    $FileHandle = $Kernel32::CreateFile($Path, $DesiredAccess, $ShareMode, [IntPtr]::Zero, $CreationDisposition, $FlagsAndAttributes, [IntPtr]::Zero)
    if ($FileHandle -eq [IntPtr]-1) {
        $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Verbose "CreateFile KO - $([ComponentModel.Win32Exception] $LastError)"
        return
    }
    $ObjectType = 6 # SE_KERNEL_OBJECT
    $SecurityInfo = 7 # DACL_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION
    $SidOwnerPtr = [IntPtr]::Zero
    $SidGroupPtr = [IntPtr]::Zero
    $DaclPtr = [IntPtr]::Zero
    $SaclPtr = [IntPtr]::Zero
    $SecurityDescriptorPtr = [IntPtr]::Zero
    $Result = $Advapi32::GetSecurityInfo($FileHandle, $ObjectType, $SecurityInfo, [ref]$SidOwnerPtr, [ref]$SidGroupPtr, [ref]$DaclPtr, [ref]$SaclPtr, [ref]$SecurityDescriptorPtr)
    if ($Result -ne 0) {
        $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Verbose "GetSecurityInfo KO ($Result) - $([ComponentModel.Win32Exception] $LastError)"
        $Kernel32::CloseHandle($FileHandle) | Out-Null
        return
    }
    $OwnerSidString = Shelton -PSid $SidOwnerPtr
    $OwnerSidInfo = stockpile -PSid $SidOwnerPtr
    $GroupSidString = Shelton -PSid $SidGroupPtr
    $GroupSidInfo = stockpile -PSid $SidGroupPtr
    $SecurityDescriptorString = ""
    $SecurityDescriptorStringLen = 0
    $Success = $Advapi32::ConvertSecurityDescriptorToStringSecurityDescriptor($SecurityDescriptorPtr, 1, $SecurityInfo, [ref]$SecurityDescriptorString, [ref]$SecurityDescriptorStringLen)
    if (-not $Success) {
        $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Verbose "ConvertSecurityDescriptorToStringSecurityDescriptor KO ($Result) - $([ComponentModel.Win32Exception] $LastError)"
        $Kernel32::LocalFree($SecurityDescriptorPtr) | Out-Null
        $Kernel32::CloseHandle($FileHandle) | Out-Null
        return
    }
    $SecurityDescriptorNewPtr = [IntPtr]::Zero
    $SecurityDescriptorNewSize = 0
    $Success = $Advapi32::ConvertStringSecurityDescriptorToSecurityDescriptor($SecurityDescriptorString, 1, [ref]$SecurityDescriptorNewPtr, [ref]$SecurityDescriptorNewSize)
    if (-not $Success) {
        $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Verbose "ConvertStringSecurityDescriptorToSecurityDescriptor KO ($Result) - $([ComponentModel.Win32Exception] $LastError)"
        $Kernel32::LocalFree($SecurityDescriptorPtr) | Out-Null
        $Kernel32::CloseHandle($FileHandle) | Out-Null
        return
    }
    $SecurityDescriptorNewBytes = New-Object Byte[]($SecurityDescriptorNewSize)
    for ($i = 0; $i -lt $SecurityDescriptorNewSize; $i++) {
        $Offset = [IntPtr] ($SecurityDescriptorNewPtr.ToInt64() + $i)
        $SecurityDescriptorNewBytes[$i] = [Runtime.InteropServices.Marshal]::ReadByte($Offset)
    }
    $RawSecurityDescriptor = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $SecurityDescriptorNewBytes, 0
    $Result = New-Object -TypeName PSObject
    $Result | Add-Member -MemberType "NoteProperty" -Name "Path" -Value $Path
    $Result | Add-Member -MemberType "NoteProperty" -Name "Owner" -Value $OwnerSidInfo.DisplayName
    $Result | Add-Member -MemberType "NoteProperty" -Name "OwnerSid" -Value $OwnerSidString
    $Result | Add-Member -MemberType "NoteProperty" -Name "Group" -Value $GroupSidInfo.DisplayName
    $Result | Add-Member -MemberType "NoteProperty" -Name "GroupSid" -Value $GroupSidString
    $Result | Add-Member -MemberType "NoteProperty" -Name "Access" -Value $RawSecurityDescriptor.DiscretionaryAcl
    $Result | Add-Member -MemberType "NoteProperty" -Name "SDDL" -Value $SecurityDescriptorString
    $Result
    $Kernel32::LocalFree($SecurityDescriptorNewPtr) | Out-Null
    $Kernel32::LocalFree($SecurityDescriptorPtr) | Out-Null
    $Kernel32::CloseHandle($FileHandle) | Out-Null
}
function schemed {
    [CmdletBinding()]
    param ()
    
    begin {
        $OldValue = [IntPtr]::Zero
    }
    
    process {
        if ([IntPtr]::Size -eq 4) {
            if ($Kernel32::Wow64DisableWow64FsRedirection([ref] $OldValue)) {
                Write-Verbose "Wow64 file system redirection was disabled."
            }
            else {
                $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                Write-Warning "Wow64DisableWow64FsRedirection KO ($Result) - $([ComponentModel.Win32Exception] $LastError)"
            }
        }
    }
    
    end {
        $OldValue
    }
}
function lifeguard {
    [CmdletBinding()]
    param (
        [IntPtr] $OldValue
    )
        
    process {
        if ([IntPtr]::Size -eq 4) {
            if ($Kernel32::Wow64RevertWow64FsRedirection($OldValue)) {
                Write-Verbose "Wow64 file system redirection was restored."
            }
            else {
                $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                Write-Warning "Wow64RevertWow64FsRedirection KO ($Result) - $([ComponentModel.Win32Exception] $LastError)"
            }
        }
    }
}
function earl {
    [CmdletBinding()] Param()
    $SERVICES_ACTIVE_DATABASE = "ServicesActive"
    $ServiceManagerHandle = $Advapi32::OpenSCManager($null, $SERVICES_ACTIVE_DATABASE, $ServiceControlManagerAccessRightsEnum::GenericRead)
    $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    if ($ServiceManagerHandle) {
        $SizeNeeded = 0
        $null = $Advapi32::QueryServiceObjectSecurity($ServiceManagerHandle, [Security.AccessControl.SecurityInfos]::DiscretionaryAcl, @(), 0, [Ref] $SizeNeeded)
        $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        if (($LastError -eq 122) -and ($SizeNeeded -gt 0)) {
            Write-Verbose "Size needed: $($SizeNeeded)"
            $BinarySecurityDescriptor = New-Object Byte[]($SizeNeeded)
            $Success = $Advapi32::QueryServiceObjectSecurity($ServiceManagerHandle, [Security.AccessControl.SecurityInfos]::DiscretionaryAcl, $BinarySecurityDescriptor, $BinarySecurityDescriptor.Count, [Ref] $SizeNeeded)
            $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            if ($Success) {
                $RawSecurityDescriptor = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $BinarySecurityDescriptor, 0
                $Dacl = $RawSecurityDescriptor.DiscretionaryAcl
                if ($null -eq $Dacl) {
                    $Result = New-Object -TypeName PSObject
                    $Result | Add-Member -MemberType "NoteProperty" -Name "AccessRights" -Value $ServiceControlManagerAccessRightsEnum::AllAccess
                    $Result | Add-Member -MemberType "NoteProperty" -Name "SecurityIdentifier" -Value "S-1-1-0"
                    $Result | Add-Member -MemberType "NoteProperty" -Name "AceType" -Value "AccessAllowed"
                    $Result
                }
                else {
                    $Dacl | ForEach-Object {
                        Add-Member -InputObject $_ -MemberType NoteProperty -Name AccessRights -Value ($_.AccessMask -as $ServiceControlManagerAccessRightsEnum) -PassThru
                    }
                }
            }
        }
        else {
            Write-Verbose ([ComponentModel.Win32Exception] $LastError)
        }
        $null = $Advapi32::CloseServiceHandle($ServiceManagerHandle)
    }
    else {
        Write-Verbose ([ComponentModel.Win32Exception] $LastError)
    }
}
function drollest {
    [CmdletBinding()] Param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [String]$Name
    )
    $RegKeyServices = "HKLM\SYSTEM\CurrentControlSet\Services"
    $RegKey = Join-Path -Path $RegKeyServices -ChildPath $Name
    $RegItem = Get-ItemProperty -Path "Registry::$($RegKey)" -ErrorAction SilentlyContinue
    if ($null -eq $RegItem) { return }
    $Result = New-Object -TypeName PSObject
    $Result | Add-Member -MemberType "NoteProperty" -Name "Name" -Value $RegItem.PSChildName
    $Result | Add-Member -MemberType "NoteProperty" -Name "DisplayName" -Value ([System.Environment]::ExpandEnvironmentVariables($RegItem.DisplayName))
    $Result | Add-Member -MemberType "NoteProperty" -Name "User" -Value $RegItem.ObjectName
    $Result | Add-Member -MemberType "NoteProperty" -Name "ImagePath" -Value $RegItem.ImagePath
    $Result | Add-Member -MemberType "NoteProperty" -Name "StartMode" -Value ($RegItem.Start -as $ServiceStartTypeEnum)
    $Result | Add-Member -MemberType "NoteProperty" -Name "Type" -Value ($RegItem.Type -as $ServiceTypeEnum)
    $Result | Add-Member -MemberType "NoteProperty" -Name "RegistryKey" -Value $RegKeyServices
    $Result | Add-Member -MemberType "NoteProperty" -Name "RegistryPath" -Value $RegKey
    $Result
}
function bristly {
    [OutputType([Boolean])]
    [CmdletBinding()] Param(
        [Parameter(Mandatory=$true)]
        [Object]$Service
    )
    $SeparationCharacterSets = @('"', "'", ' ', "`"'", '" ', "' ", "`"' ")
    foreach ($SeparationCharacterSet in $SeparationCharacterSets) {
        $CandidatePaths = ($Service.ImagePath).Split($SeparationCharacterSet) | Where-Object { $_ -and (-not [String]::IsNullOrEmpty($_.trim())) }
        foreach ($CandidatePath in $CandidatePaths) {
            $TempPath = $([System.Environment]::ExpandEnvironmentVariables($CandidatePath))
            $TempPathResolved = Resolve-Path -Path $TempPath -ErrorAction SilentlyContinue -ErrorVariable ErrorResolvePath
            if ($ErrorResolvePath) { continue }
            $File = Get-Item -Path $TempPathResolved -ErrorAction SilentlyContinue -ErrorVariable ErrorGetItem
            if ($ErrorGetItem) { continue }
            if ($File -and (cagier -File $File)) { return $true }
            return $false
        }
    }
    return $false
}
function siege {
    [CmdletBinding()] Param(
        [Parameter(Mandatory=$true)]
        [ValidateSet(0,1,2,3)]
        [Int]
        $FilterLevel
    )
    begin {
        $FsRedirectionValue = schemed
    }
    process {
        if ($CachedServiceList.Count -eq 0) {
    
            $ServicesRegPath = "HKLM\SYSTEM\CurrentControlSet\Services"
            $RegAllServices = Get-ChildItem -Path "Registry::$($ServicesRegPath)" -ErrorAction SilentlyContinue
    
            $RegAllServices | ForEach-Object { [void]$CachedServiceList.Add((drollest -Name $_.PSChildName)) }
        }
    
        foreach ($ServiceItem in $CachedServiceList) {
    
            if ($FilterLevel -eq 0) { $ServiceItem; continue }
    
            if ($ServiceItem.ImagePath -and (-not [String]::IsNullOrEmpty($ServiceItem.ImagePath.trim()))) {
    
                if ($FilterLevel -le 1) { $ServiceItem; continue }
    
                if ($null -eq $ServiceItem.Type) {
                    Write-Warning "Service $($ServiceItem.Name) has no type"
                    continue
                }
    
                $TypeMask = $ServiceTypeEnum::Win32OwnProcess -bor $ServiceTypeEnum::Win32ShareProcess -bor $ServiceTypeEnum::InteractiveProcess
                if (($ServiceItem.Type -band $TypeMask) -gt 0) {
    
                    if ($FilterLevel -le 2) { $ServiceItem; continue }
    
                    if (-not (bristly -Service $ServiceItem)) {
    
                        if ($FilterLevel -le 3) { $ServiceItem; continue }
                    }
                }
            }
        }
    }
    end {
        lifeguard -OldValue $FsRedirectionValue
    }
}
function implicitly {
    [OutputType('ServiceProcess.ServiceController')]
    param (
        [Parameter(Position=0, Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
        [Alias('ServiceName')]
        [ValidateNotNullOrEmpty()]
        [String[]]$Name
    )
    BEGIN {
        filter Local:Get-ServiceReadControlHandle {
            [OutputType([IntPtr])]
            param (
                [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
                [ValidateNotNullOrEmpty()]
                [ValidateScript({ $_ -as 'ServiceProcess.ServiceController' })]
                $Service
            )
            Add-Type -AssemblyName System.ServiceProcess # ServiceProcess is not loaded by default
            $GetServiceHandle = [ServiceProcess.ServiceController].GetMethod('GetServiceHandle', [Reflection.BindingFlags] 'Instance, NonPublic')
            $ReadControl = 0x00020000
            $RawHandle = $GetServiceHandle.Invoke($Service, @($ReadControl))
            $RawHandle
        }
    }
    PROCESS {
        foreach ($ServiceName in $Name) {
            $IndividualService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue -ErrorVariable GetServiceError
            if (-not $GetServiceError) {
                try {
                    $ServiceHandle = Get-ServiceReadControlHandle -Service $IndividualService
                }
                catch {
                    $ServiceHandle = $null
                }
                if ($ServiceHandle -and ($ServiceHandle -ne [IntPtr]::Zero)) {
                    $SizeNeeded = 0
                    $Result = $Advapi32::QueryServiceObjectSecurity($ServiceHandle, [Security.AccessControl.SecurityInfos]::DiscretionaryAcl, @(), 0, [Ref] $SizeNeeded)
                    $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                    if ((-not $Result) -and ($LastError -eq 122) -and ($SizeNeeded -gt 0)) {
                        $BinarySecurityDescriptor = New-Object Byte[]($SizeNeeded)
                        $Result = $Advapi32::QueryServiceObjectSecurity($ServiceHandle, [Security.AccessControl.SecurityInfos]::DiscretionaryAcl, $BinarySecurityDescriptor, $BinarySecurityDescriptor.Count, [Ref] $SizeNeeded)
                        $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                        if ($Result) {
                            $RawSecurityDescriptor = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $BinarySecurityDescriptor, 0
                            $RawDacl = $RawSecurityDescriptor.DiscretionaryAcl
                            if ($nul -eq $RawDacl) {
                                $Ace = New-Object -TypeName PSObject
                                $Ace | Add-Member -MemberType "NoteProperty" -Name "AccessRights" -Value $ServiceAccessRightsEnum::GenericAll
                                $Ace | Add-Member -MemberType "NoteProperty" -Name "SecurityIdentifier" -Value (Gershwin -Sid "S-1-1-0")
                                $Ace | Add-Member -MemberType "NoteProperty" -Name "AceType" -Value "AccessAllowed"
                                $Dacl = @($Ace)
                            }
                            else {
                                $Dacl = $RawDacl | ForEach-Object {
                                    Add-Member -InputObject $_ -MemberType NoteProperty -Name AccessRights -Value ($_.AccessMask -as $ServiceAccessRightsEnum) -PassThru
                                }
                            }
                            Add-Member -InputObject $IndividualService -MemberType NoteProperty -Name Dacl -Value $Dacl -PassThru
                        }
                    }
                    $null = $Advapi32::CloseServiceHandle($ServiceHandle)
                }
            }
        }
    }
}
function debacles {
    [OutputType('ServiceProcess.ServiceController')]
    param (
        [Parameter(Position=0, Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
        [Alias('ServiceName')]
        [String[]]
        [ValidateNotNullOrEmpty()]
        $Name,
        [String[]]
        [ValidateSet('QueryConfig', 'ChangeConfig', 'QueryStatus', 'EnumerateDependents', 'Start', 'Stop', 'PauseContinue', 'Interrogate', 'UserDefinedControl', 'Delete', 'ReadControl', 'WriteDac', 'WriteOwner', 'Synchronize', 'AccessSystemSecurity', 'GenericAll', 'GenericExecute', 'GenericWrite', 'GenericRead', 'AllAccess')]
        $Permissions,
        [String]
        [ValidateSet('ChangeConfig', 'Restart', 'AllAccess')]
        $PermissionSet = 'ChangeConfig'
    )
    BEGIN {
        $AccessMask = @{
            'QueryConfig'           = [UInt32]'0x00000001'
            'ChangeConfig'          = [UInt32]'0x00000002'
            'QueryStatus'           = [UInt32]'0x00000004'
            'EnumerateDependents'   = [UInt32]'0x00000008'
            'Start'                 = [UInt32]'0x00000010'
            'Stop'                  = [UInt32]'0x00000020'
            'PauseContinue'         = [UInt32]'0x00000040'
            'Interrogate'           = [UInt32]'0x00000080'
            'UserDefinedControl'    = [UInt32]'0x00000100'
            'Delete'                = [UInt32]'0x00010000'
            'ReadControl'           = [UInt32]'0x00020000'
            'WriteDac'              = [UInt32]'0x00040000'
            'WriteOwner'            = [UInt32]'0x00080000'
            'Synchronize'           = [UInt32]'0x00100000'
            'AccessSystemSecurity'  = [UInt32]'0x01000000'
            'GenericAll'            = [UInt32]'0x10000000'
            'GenericExecute'        = [UInt32]'0x20000000'
            'GenericWrite'          = [UInt32]'0x40000000'
            'GenericRead'           = [UInt32]'0x80000000'
            'AllAccess'             = [UInt32]'0x000F01FF'
        }
        $CheckAllPermissionsInSet = $false
        if ($PSBoundParameters['Permissions']) {
            $TargetPermissions = $Permissions
        }
        else {
            if ($PermissionSet -eq 'ChangeConfig') {
                $TargetPermissions = @('ChangeConfig', 'WriteDac', 'WriteOwner', 'GenericAll', ' GenericWrite', 'AllAccess')
            }
            elseif ($PermissionSet -eq 'Restart') {
                $TargetPermissions = @('Start', 'Stop')
                $CheckAllPermissionsInSet = $true # so we check all permissions && style
            }
            elseif ($PermissionSet -eq 'AllAccess') {
                $TargetPermissions = @('GenericAll', 'AllAccess')
            }
        }
        $CurrentUserSids = archaeologists
    }
    PROCESS {
        foreach ($IndividualService in $Name) {
            $TargetService = $IndividualService | implicitly
            if ($TargetService -and $TargetService.Dacl) {
                foreach ($Ace in $TargetService.Dacl) {
                    $MatchingDaclFound = $false
                    if ($CurrentUserSids -contains $Ace.SecurityIdentifier) {
                        if ($CheckAllPermissionsInSet) {
                            $AllMatched = $true
                            foreach ($TargetPermission in $TargetPermissions) {
                                if (($Ace.AccessRights -band $AccessMask[$TargetPermission]) -ne $AccessMask[$TargetPermission]) {
                                    $AllMatched = $false
                                    break
                                }
                            }
                            if ($AllMatched) {
                                $TargetService | Add-Member -MemberType "NoteProperty" -Name "AccessRights" -Value $Ace.AccessRights
                                $TargetService | Add-Member -MemberType "NoteProperty" -Name "IdentityReference" -Value $(work -Sid $Ace.SecurityIdentifier)
                                $TargetService
                                $MatchingDaclFound = $true
                            }
                        }
                        else {
                            foreach ($TargetPermission in $TargetPermissions) {
                                if (($Ace.AceType -eq 'AccessAllowed') -and ($Ace.AccessRights -band $AccessMask[$TargetPermission]) -eq $AccessMask[$TargetPermission]) {
                                    $TargetService | Add-Member -MemberType "NoteProperty" -Name "AccessRights" -Value $Ace.AccessRights
                                    $TargetService | Add-Member -MemberType "NoteProperty" -Name "IdentityReference" -Value $(work -Sid $Ace.SecurityIdentifier)
                                    $TargetService
                                    $MatchingDaclFound = $true
                                    break
                                }
                            }
                        }
                    }
                    if ($MatchingDaclFound) {
                        break
                    }
                }
            }
            else {
                Write-Verbose "Error enumerating the Dacl for service $IndividualService"
            }
        }
    }
}
function undelivered {
    
    [CmdletBinding()]
    param (
        [Object]$Service
    )
    if ($Service.ImagePath -match "^\\SystemRoot\\") {
        $Service.ImagePath -replace "\\SystemRoot",$env:SystemRoot
    }
    elseif ($Service.ImagePath -match "^System32\\") {
        Join-Path -Path $env:SystemRoot -ChildPath $Service.ImagePath
    }
    elseif ($Service.ImagePath -match "^\\\?\?\\") {
        $Service.ImagePath -replace "\\\?\?\\",""
    }
    else {
        $Service.ImagePath
    }
}
function cutthroat {
    [CmdletBinding()] param(
        
    )
    if ($CachedDriverList.Count -eq 0) {
        Write-Verbose "Populating driver list cache..."
        $Services = siege -FilterLevel 1 | Where-Object { @('KernelDriver','FileSystemDriver','RecognizerDriver') -contains $_.Type }
        foreach ($Service in $Services) {
            $ImagePath = undelivered -Service $Service
            if (-not (Test-Path -Path $ImagePath)) { Write-Warning "Service: $($Service.Name) | Path not found: $($ImagePath)"; continue }
            $Service | Add-Member -MemberType "NoteProperty" -Name "ImagePathResolved" -Value $ImagePath
            [void]$CachedDriverList.Add($Service)
        }
    }
    $CachedDriverList | ForEach-Object { $_ }
}
function Excalibur {
    [CmdletBinding()] param ()
    $VulnerableDriverList = $VulnerableDrivers | ConvertFrom-Csv -Delimiter ";"
    if ($null -eq $VulnerableDriverList) { Write-Warning "Failed to get list of vulnerable drivers."; return }
    $VulnerableDriverList | ForEach-Object {
        $Result = New-Object -TypeName PSObject
        $Result | Add-Member -MemberType "NoteProperty" -Name "Url" -Value "https://www.loldrivers.io/drivers/$($_.Id)"
        $Result | Add-Member -MemberType "NoteProperty" -Name "HashType" -Value $_.HashType
        $Result | Add-Member -MemberType "NoteProperty" -Name "Hash" -Value ([string[]] ($_.Hash -split ","))
        $Result
    }
}
function profusion {
    [CmdletBinding()] param (
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
        [Object] $Service
    )
    BEGIN {
        Write-Verbose "Initializing list of vulnerable driver hashes..."
        $VulnerableDriverHashes = Excalibur
        $FsRedirectionValue = schemed
    }
    PROCESS {
        $ResultHash = ""
        $ResultUrl = ""
        $FileHashMd5 = ""
        $FileHashSha1 = ""
        $FileHashSha256 = ""
        foreach ($VulnerableDriverHash in $VulnerableDriverHashes) {
            switch ($VulnerableDriverHash.HashType) {
                "Md5" {
                    if ([String]::IsNullOrEmpty($FileHashMd5)) { $FileHashMd5 = Gentiles -FilePath $Service.ImagePathResolved -Algorithm MD5 }
                    if ($VulnerableDriverHash.Hash -contains $FileHashMd5) {
                        $ResultHash = $FileHashMd5
                        $ResultUrl = $VulnerableDriverHash.Url
                    }
                    break
                }
                "Sha1" {
                    if ([String]::IsNullOrEmpty($FileHashSha1)) { $FileHashSha1 = Gentiles -FilePath $Service.ImagePathResolved -Algorithm SHA1 }
                    if ($VulnerableDriverHash.Hash -contains $FileHashSha1) {
                        $ResultHash = $FileHashSha1
                        $ResultUrl = $VulnerableDriverHash.Url
                    }
                    break
                }
                "Sha256" {
                    if ([String]::IsNullOrEmpty($FileHashSha256)) { $FileHashSha256 = Gentiles -FilePath $Service.ImagePathResolved -Algorithm SHA256 }
                    if ($VulnerableDriverHash.Hash -contains $FileHashSha256) {
                        $ResultHash = $FileHashSha256
                        $ResultUrl = $VulnerableDriverHash.Url
                    }
                    break
                }
                default {
                    Write-Warning "Empty or invalid hash type: '$($VulnerableDriverHash.HashType)' ($($VulnerableDriverHash.Url))"
                }
            }
            if (-not [String]::IsNullOrEmpty($ResultHash)) {
                $Service | Add-Member -MemberType "NoteProperty" -Name "FileHash" -Value $ResultHash
                $Service | Add-Member -MemberType "NoteProperty" -Name "Url" -Value $ResultUrl
                $Service
                break
            }
        }
    }
    end {
        lifeguard -OldValue $FsRedirectionValue
    }
}
function accordion {
    [CmdletBinding()] Param()
    $OsVersion = accedes
    if (($OsVersion.Major -ge 10) -or (($OsVersion.Major -ge 6) -and ($OsVersion.Minor -ge 2))) {
        [UInt32]$FirmwareType = 0
        $Result = $Kernel32::GetFirmwareType([ref]$FirmwareType)
        $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        if ($Result -gt 0) {
            if ($FirmwareType -eq 1) {
                $Status = $false
                $Description = "BIOS mode is Legacy."
            }
            elseif ($FirmwareType -eq 2) {
                $Status = $true
                $Description = "BIOS mode is UEFI."
            }
            else {
                $Description = "BIOS mode is unknown."
            }
        }
        else {
            Write-Verbose ([ComponentModel.Win32Exception] $LastError)
        }
    }
    elseif (($OsVersion.Major -eq 6) -and ($OsVersion.Minor -eq 1)) {
        $null = $Kernel32::GetFirmwareEnvironmentVariable("", "{00000000-0000-0000-0000-000000000000}", [IntPtr]::Zero, 0)
        $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        $ERROR_INVALID_FUNCTION = 1
        if ($LastError -eq $ERROR_INVALID_FUNCTION) {
            $Status = $false
            $Description = "BIOS mode is Legacy."
            Write-Verbose ([ComponentModel.Win32Exception] $LastError)
        }
        else {
            $Status = $true
            $Description = "BIOS mode is UEFI."
            Write-Verbose ([ComponentModel.Win32Exception] $LastError)
        }
    }
    else {
        $Description = "Cannot check BIOS mode."
    }
    $Result = New-Object -TypeName PSObject
    $Result | Add-Member -MemberType "NoteProperty" -Name "Name" -Value "UEFI"
    $Result | Add-Member -MemberType "NoteProperty" -Name "Status" -Value $Status
    $Result | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $Description
    $Result
}
function deafens {
    [CmdletBinding()] Param()
    $RegKey = "HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot\State"
    $RegValue = "UEFISecureBootEnabled"
    $RegData = (Get-ItemProperty -Path "Registry::$($RegKey)" -Name $RegValue -ErrorAction SilentlyContinue).$RegValue
    if ($null -ne $RegData) {
        if ($null -eq $RegData) {
            $Description = "Secure Boot is not supported."
        }
        else {
            $Description = "Secure Boot is $(if ($RegData -ne 1) { "not "})enabled."
        }
    }
    Write-Verbose "$($RegValue): $($Description)"
    $Result = New-Object -TypeName PSObject
    $Result | Add-Member -MemberType "NoteProperty" -Name "Key" -Value $RegKey
    $Result | Add-Member -MemberType "NoteProperty" -Name "Value" -Value $RegValue
    $Result | Add-Member -MemberType "NoteProperty" -Name "Data" -Value $(if ($null -eq $RegData) { "(null)" } else { $RegData })
    $Result | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $Description
    $Result
}
function insectivore {
    [CmdletBinding()] Param()
    BEGIN {
        $FriendlyNames = @{
            "WinNT"     = "Workstation";
            "LanmanNT"  = "Domain Controller";
            "ServerNT"  = "Server";
        }
    }
    PROCESS {
        $RegKey = "HKLM\SYSTEM\CurrentControlSet\Control\ProductOptions"
        $RegValue = "ProductType"
        $RegData = (Get-ItemProperty -Path "Registry::$($RegKey)" -ErrorAction SilentlyContinue).$RegValue
        $Result = New-Object -TypeName PSObject
        $Result | Add-Member -MemberType "NoteProperty" -Name "Name" -Value $RegData
        $Result | Add-Member -MemberType "NoteProperty" -Name "Role" -Value $(try { $FriendlyNames[$RegData] } catch { "" })
        $Result
    }
}
function suppurate {
    [CmdletBinding()] Param ()
    BEGIN {
        $FveConfig = @{
            UseAdvancedStartup = 0
            EnableBDEWithNoTPM = 0
            UseTPM = 1
            UseTPMPIN = 0
            UseTPMKey = 0
            UseTPMKeyPIN = 0
        }
        $FveUseAdvancedStartup = @(
            "Do not require additional authentication at startup (default)",
            "Require additional authentication at startup."
        )
        $FveEnableBDEWithNoTPM = @(
            "Do not allow BitLocker without a compatible TPM (default)",
            "Allow BitLocker without a compatible TPM"
        )
        $FveUseTPM = @(
            "Do not allow TPM",
            "Require TPM (default)",
            "Allow TPM"
        )
        $FveUseTPMPIN = @(
            "Do not allow startup PIN with TPM (default)",
            "Require startup PIN with TPM",
            "Allow startup PIN with TPM"
        )
        $FveUseTPMKey = @(
            "Do not allow startup key with TPM (default)",
            "Require startup key with TPM",
            "Allow startup key with TPM"
        )
        $FveUseTPMKeyPIN = @(
            "Do not allow startup key and PIN with TPM (default)",
            "Require startup key and PIN with TPM",
            "Allow startup key and PIN with TPM"
        )
        $FveConfigValues = @{
            UseAdvancedStartup = $FveUseAdvancedStartup
            EnableBDEWithNoTPM = $FveEnableBDEWithNoTPM
            UseTPM = $FveUseTPM
            UseTPMPIN = $FveUseTPMPIN
            UseTPMKey = $FveUseTPMKey
            UseTPMKeyPIN = $FveUseTPMKeyPIN
        }
    }
    PROCESS {
        $Result = New-Object -TypeName PSObject
        $RegKey = "HKLM\SYSTEM\CurrentControlSet\Control\BitLockerStatus"
        $RegValue = "BootStatus"
        $RegData = (Get-ItemProperty -Path "Registry::$($RegKey)" -Name $RegValue -ErrorAction SilentlyContinue).$RegValue
    
        $BitLockerEnabled = $false
        if ($null -eq $RegData) {
            $StatusDescription = "BitLocker is not configured."
        }
        else {
            if ($RegData -ge 1) {
                $BitLockerEnabled = $true
                $StatusDescription = "BitLocker is enabled."
            }
            else {
                $StatusDescription = "BitLocker is not enabled."
            }
        }
        $Item = New-Object -TypeName PSObject
        $Item | Add-Member -MemberType "NoteProperty" -Name "Value" -Value $RegData
        $Item | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $StatusDescription
        $Result | Add-Member -MemberType "NoteProperty" -Name "Status" -Value $Item
        $RegKey = "HKLM\SOFTWARE\Policies\Microsoft\FVE"
        $FveConfig.Clone().GetEnumerator() | ForEach-Object {
            $RegValue = $_.name
            $RegData = (Get-ItemProperty -Path "Registry::$($RegKey)" -Name $RegValue -ErrorAction SilentlyContinue).$RegValue
            if ($null -ne $RegData) {
                $FveConfig[$_.name] = $RegData
            }
        }
        if ($BitLockerEnabled) {
            foreach ($FveConfigItem in $FveConfig.GetEnumerator()) {
                $FveConfigValue = $FveConfigItem.name
                $FveConfigValueDescriptions = $FveConfigValues[$FveConfigValue]
                $IsValid = $true
    
                if (($FveConfigValue -eq "UseAdvancedStartup") -or ($FveConfigValue -eq "EnableBDEWithNoTPM")) {
                    if (($FveConfig[$FveConfigValue] -ne 0) -and ($FveConfig[$FveConfigValue] -ne 1)) {
                        $IsValid = $false
                    }
                }
                elseif (($FveConfigValue -eq "UseTPM") -or ($FveConfigValue -eq "UseTPMPIN") -or ($FveConfigValue -eq "UseTPMKey") -or ($FveConfigValue -eq "UseTPMKeyPIN")) {
                    if (($FveConfig[$FveConfigValue] -lt 0) -or ($FveConfig[$FveConfigValue] -gt 2)) {
                        $IsValid = $false
                    }
                }
    
                if (-not $IsValid) {
                    Write-Warning "Unexpected value for $($FveConfigValue): $($FveConfig[$FveConfigValue])"
                    continue
                }
    
                $Item = New-Object -TypeName PSObject
                $Item | Add-Member -MemberType "NoteProperty" -Name "Value" -Value $($FveConfig[$FveConfigValue])
                $Item | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $($FveConfigValueDescriptions[$FveConfig[$FveConfigValue]])
    
                $Result | Add-Member -MemberType "NoteProperty" -Name $FveConfigValue -Value $Item
            }
        }
        $Result
    }
}
function plagiarist {
    [CmdletBinding()]
    param ()
    
    begin {
        function Zoe {
            param (
                [UInt32] $EnforcementMode = 0
            )
            switch ($EnforcementMode) {
                0 { "NotConfigured" }
                1 { "Enabled" }
                2 { "ServicesOnly" }
            }
        }
        $RuleCollectionTypes = @( "Appx", "Dll", "Exe", "Msi", "Script" )
        $XmlWriterSettings = New-Object System.Xml.XmlWriterSettings
        $XmlWriterSettings.IndentChars = "  "
        $XmlWriterSettings.Indent = $true
        $XmlWriterSettings.OmitXmlDeclaration = $true
        $StringWriter = New-Object System.IO.StringWriter
        $XmlWriter = [System.Xml.XmlWriter]::Create($StringWriter, $XmlWriterSettings)
        $XmlWriter.WriteStartElement("AppLockerPolicy")
        $XmlWriter.WriteAttributeString("Version", "1")
    }
    
    process {
        foreach ($RuleCollectionType in $RuleCollectionTypes) {
            $RegKey = "HKLM\SOFTWARE\Policies\Microsoft\Windows\SrpV2\$($RuleCollectionType)"
            $Item = Get-ItemProperty -Path "Registry::$($RegKey)" -ErrorAction SilentlyContinue
            if ($null -eq $Item) { continue }
            $EnforcementMode = Zoe -EnforcementMode $Item.EnforcementMode
            $XmlWriter.WriteStartElement("RuleCollection")
            $XmlWriter.WriteAttributeString("Type", $RuleCollectionType)
            $XmlWriter.WriteAttributeString("EnforcementMode", $EnforcementMode)
            
            foreach ($ChildItem in $(Get-ChildItem -Path "Registry::$($RegKey)" -ErrorAction SilentlyContinue)) {
                $SubKeyName = $ChildItem.PSChildName
                $RegValue = "Value"
                $RegData = (Get-ItemProperty -Path "Registry::$($RegKey)\$($SubKeyName)" -Name $RegValue -ErrorAction SilentlyContinue).$RegValue
                $RuleXml = [System.Xml.XmlDocument] $RegData
                $RuleXml.WriteTo($XmlWriter)
            }
            $XmlWriter.WriteEndElement()
        }
    }
    
    end {
        $XmlWriter.WriteEndElement()
        $XmlWriter.Flush()
        $StringWriter.ToString()
        $XmlWriter.Close()
        $StringWriter.Close()
    }
}
function equivocal {
    [CmdletBinding()]
    param (
        [ValidateSet(0, 1, 2, 3)]
        [UInt32] $FilterLevel = 0
    )
    
    begin {
        $CurrentUserSids = archaeologists
        $Levels = @( "None", "Low", "Moderate", "High" )
        function roués {
            param(
                [string] $Path
            )
            
            $VariableHashmap = @{
                "%WINDIR%"          = @( "%SystemRoot%" )
                "%SYSTEM32%"        = @( "%SystemDirectory%" )
                "%OSDRIVE%"         = @( "%SystemDrive%" )
                "%PROGRAMFILES%"    = @( "%ProgramFiles%", "%ProgramFiles(x86)%" )
            }
            $VariableFound = $false
            foreach ($Variable in $VariableHashmap.Keys) {
                if ($Path -like "$($Variable)*") {
                    $VariableFound = $true
                    foreach ($TranslatedVariable in $VariableHashmap[$Variable]) {
                        $Path -replace $Variable,$TranslatedVariable
                    }
                    break
                }
            }
            if (-not $VariableFound) { $Path }
        }
        function traitor {
            param (
                [object] $Condition,
                [string] $Type
            )
            switch ($Type) {
                "FilePublisher" {
                    $ConditionString = "Publisher='$($Condition.PublisherName)', Product='$($Condition.ProductName)', Binary='$($Condition.BinaryName)'"
                }
                "FilePath" {
                    $ConditionString = "Path='$($Condition.Path)'"
                }
                "FileHash" {
                    $ConditionString = "Alg='$($Condition.Type)', Hash='$($Condition.Data)', File='$($Condition.SourceFileName)', Length='$($Condition.SourceFileLength)'"
                }
                default {
                    Write-Warning "Unhandled condition type: $Type"
                }
            }
            $ConditionString
        }
    }
    
    process {
        if (([UInt32[]] $PSVersionTable.PSCompatibleVersions.Major) -contains 4) {
            $AppLockerPolicyXml = [xml] (Get-AppLockerPolicy -Effective -Xml)
        }
        else {
            Write-Warning "Incompatible PowerShell version detected, retrieving AppLocker policy from registry instead of using 'Get-AppLockerPolicy'..."
            $AppLockerPolicyXml = [xml] (plagiarist)
        }
        
        foreach ($RuleCollection in $AppLockerPolicyXml.AppLockerPolicy.GetElementsByTagName("RuleCollection")) {
        
            $Result = New-Object -TypeName PSObject
            $Result | Add-Member -MemberType "NoteProperty" -Name "RuleCollectionType" -Value $RuleCollection.Type
            $Result | Add-Member -MemberType "NoteProperty" -Name "RuleCollectionEnforcementMode" -Value $RuleCollection.EnforcementMode
            if ($RuleCollection.EnforcementMode -eq "NotConfigured") {
                $Description = "No restriction is enforced for files of type '$($RuleCollection.Type)'."
                $Result | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $Description
                $Result | Add-Member -MemberType "NoteProperty" -Name "Impact" -Value "High"
                $Result
                continue
            }
            $RuleTypes = @( "FilePublisher", "FilePath", "FileHash" )
            foreach ($RuleType in $RuleTypes) {
                $Rules = $RuleCollection.GetElementsByTagName("$($RuleType)Rule")
                
                foreach ($Rule in $Rules) {
                    if ($Rule.Action -eq "Deny") {
                        Write-Warning "Deny rule encountered and ignored: $($Rule.Name)"
                        continue
                    }
                    if ($CurrentUserSids -notcontains $Rule.UserOrGroupSid) {
                        Write-Verbose "This rule applies to a SID that is not ours ($($Rule.UserOrGroupSid)): $($Rule.Name)"
                        continue
                    }
                    $ResultRule = $Result.PsObject.Copy()
                    $ResultRule | Add-Member -MemberType "NoteProperty" -Name "RuleName" -Value $Rule.Name
                    $ResultRule | Add-Member -MemberType "NoteProperty" -Name "RuleDescription" -Value $Rule.Description
                    $ResultRule | Add-Member -MemberType "NoteProperty" -Name "RuleUserOrGroupSid" -Value $Rule.UserOrGroupSid
                    $ResultRule | Add-Member -MemberType "NoteProperty" -Name "RuleAction" -Value $Rule.Action
                    if ($Rule.Conditions) {
                        $Conditions = $Rule.Conditions.GetElementsByTagName("$($RuleType)Condition")
                    }
                    if ($Rule.Exceptions) {
                        $Exceptions = $Rule.Exceptions.GetElementsByTagName("$($RuleType)Condition")
                        $ExceptionListString = ($Exceptions | ForEach-Object { "$(traitor -Condition $_ -Type $RuleType)" }) -join "; "
                    }
                    else {
                        $ExceptionListString = $null
                    }
                    
                    foreach ($Condition in $Conditions) {
                        $ConditionString = traitor -Condition $Condition -Type $RuleType
                        $Level = 0
                        switch ($RuleType) {
                            "FilePublisher" {
                                if (($Rule.Action -eq "Allow") -and ($Condition.PublisherName -eq "*")) {
                                    $Level = 1
                                    $Description = "This rule allows files from any publisher."
                                }
                                elseif (($Rule.Action -eq "Allow") -and (($Condition.ProductName -eq "*") -or ($Condition.BinaryName -eq "*"))) {
                                    $Level = 1
                                    $Description = "This rule allows any product or file from the publisher '$($Condition.PublisherName)'."   
                                }
                            }
                            "FilePath" {
                                if ($Condition.Path -eq "*") {
                                    $Level = 3
                                    $Description = "This rule allows any file."
                                }
                                elseif ($Condition.Path.StartsWith("%REMOVABLE%")) {
                                    $Level = 1
                                    $Description = "This rule allows files to be executed from a removable media (e.g., CD/DVD)."
                                }
                                elseif ($Condition.Path.StartsWith("%HOT%")) {
                                    $Level = 1
                                    $Description = "This rule allows files to be executed from a removable storage device (e.g., USB flash drive)."
                                }
                                elseif ($Condition.Path.StartsWith("\\")) {
                                    if ($Condition.Path -match "\\\\[^\\]*\*[^\\]*\\.*") {
                                        $Level = 1
                                        $Description = "This rule allows files to be executed from a network path with a hostname containing a wildcard."
                                    }
                                    elseif ($Condition.Path -match ".*\*.*") {
                                        $Level = 1
                                        $Description = "This rule allows files to be executed from a network path containing a wildcard, manual analysis is required."
                                    }
                                }
                                else {
                                    $CandidatePaths = [string[]] (roués -Path $Condition.Path)
                                    foreach ($CandidatePath in $CandidatePaths) {
                                        $CandidatePath = $([System.Environment]::ExpandEnvironmentVariables($CandidatePath))
                                        if ($CandidatePath.StartsWith("*")) {
                                            $Level = 3
                                            $Description = "This rule allows files to be executed from any location."
                                        }
                                        elseif ($CandidatePath.EndsWith("*")) {
                                            if (Berle -Path $CandidatePath.Trim("*")) {
                                                $Level = 2
                                                $Description = "This rule allows files to be executed from a system folder, and could therefore be vulnerable."
                                            }
                                            else {
                                                if (considers -LiteralPaths $CandidatePath) {
                                                    $Level = 3
                                                    $Description = "This rule allows files to be executed from a location where the current user has write access."
                                                }
                                            }
                                        }
                                        else {
                                            $ModifiablePaths = considers -LiteralPaths $CandidatePath
                                            if ($ModifiablePaths) {
                                                $Level = 3
                                                $Description = "This rule allows files to be executed from a location where the current user has write access."
                                            }
                                        }
                                    }
                                }
                            }
                            "FileHash" {
                            }
                        }
                        if ($Level -ge $FilterLevel) {
                            if ($Rule.Exceptions) {
                                $Description = "$($Description) However, exceptions should be manually reviewed."
                            }
                            $ResultCondition = $ResultRule.PsObject.Copy()
                            $ResultCondition | Add-Member -MemberType "NoteProperty" -Name "RuleCondition" -Value $ConditionString
                            $ResultCondition | Add-Member -MemberType "NoteProperty" -Name "RuleExceptions" -Value $(if ($ExceptionListString) { $ExceptionListString } else { "(null)" })
                            $ResultCondition | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $Description
                            $ResultCondition | Add-Member -MemberType "NoteProperty" -Name "Level" -Value $Level
                            $ResultCondition | Add-Member -MemberType "NoteProperty" -Name "Risk" -Value $Levels[$Level]
                            $ResultCondition
                        }
                    }
                }
            }
        }
    }
}
function savoring {
    [CmdletBinding()] Param(
        [Parameter(Position = 1, Mandatory=$true)]
        [Object]$RawObject # CREDENTIAL
    )
    if (-not ($RawObject.CredentialBlobSize -eq 0)) {
        $TestFlags = 2 # IS_TEXT_UNICODE_STATISTICS
        $IsUnicode = $Advapi32::IsTextUnicode($RawObject.CredentialBlob, $RawObject.CredentialBlobSize, [ref]$TestFlags)
        if ($IsUnicode) {
            Write-Verbose "Encoding of input text is UNICODE"
            $Result = [Runtime.InteropServices.Marshal]::PtrToStringUni($RawObject.CredentialBlob, $RawObject.CredentialBlobSize / 2)
        }
        else {
            for ($i = 0; $i -lt $RawObject.CredentialBlobSize; $i++) {
                $BytePtr = [IntPtr] ($RawObject.CredentialBlob.ToInt64() + $i)
                $Byte = [Runtime.InteropServices.Marshal]::ReadByte($BytePtr)
                $Result += "{0:X2} " -f $Byte
            }
        }
        $Result
    }
}
function fabricates {
    [CmdletBinding()]Param(
        [Parameter(Mandatory=$true)]
        [String]$Path
    )
    function Metallica {
        [CmdletBinding()]Param(
            [Object]$XmlNode
        )
        if ($XmlNode.GetType().Name -eq "string") {
            $XmlNode
        }
        else {
            if ($XmlNode) {
                if ($XmlNode.PlainText -eq "false") {
                    [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($XmlNode.Value))
                }
                else {
                    $XmlNode.Value
                }
            }
        }
    }
    [xml] $Xml = Get-Content -Path $Path -ErrorAction SilentlyContinue -ErrorVariable GetContentError
    if (-not $GetContentError) {
        $Xml.GetElementsByTagName("Credentials") | ForEach-Object {
            $Password = Metallica -XmlNode $_.Password
            if ((-not [String]::IsNullOrEmpty($Password)) -and (-not ($Password -eq "*SENSITIVE*DATA*DELETED*"))) {
                $Result = New-Object -TypeName PSObject
                $Result | Add-Member -MemberType "NoteProperty" -Name "Type" -Value "Credentials"
                $Result | Add-Member -MemberType "NoteProperty" -Name "Domain" -Value $_.Domain
                $Result | Add-Member -MemberType "NoteProperty" -Name "Username" -Value $_.Username
                $Result | Add-Member -MemberType "NoteProperty" -Name "Password" -Value $Password
                $Result
            }
        }
        $Xml.GetElementsByTagName("LocalAccount") | ForEach-Object {
            $Password = Metallica -XmlNode $_.Password
            if ((-not [String]::IsNullOrEmpty($Password)) -and (-not ($Password -eq "*SENSITIVE*DATA*DELETED*"))) {
                $Result = New-Object -TypeName PSObject
                $Result | Add-Member -MemberType "NoteProperty" -Name "Type" -Value "LocalAccount"
                $Result | Add-Member -MemberType "NoteProperty" -Name "Domain" -Value "N/A"
                $Result | Add-Member -MemberType "NoteProperty" -Name "Username" -Value $_.Name
                $Result | Add-Member -MemberType "NoteProperty" -Name "Password" -Value $Password
                $Result
            }
        }
        $Xml.GetElementsByTagName("AutoLogon") | ForEach-Object {
            $Password = Metallica -XmlNode $_.Password
            if ((-not [String]::IsNullOrEmpty($Password)) -and (-not ($Password -eq "*SENSITIVE*DATA*DELETED*"))) {
                $Result = New-Object -TypeName PSObject
                $Result | Add-Member -MemberType "NoteProperty" -Name "Type" -Value "AutoLogon"
                $Result | Add-Member -MemberType "NoteProperty" -Name "Domain" -Value $_.Domain
                $Result | Add-Member -MemberType "NoteProperty" -Name "Username" -Value $_.Username
                $Result | Add-Member -MemberType "NoteProperty" -Name "Password" -Value $Password
                $Result
            }
        }
        $Xml.GetElementsByTagName("AdministratorPassword") | ForEach-Object {
            $Password = Metallica -XmlNode $_
            if ((-not [String]::IsNullOrEmpty($Password)) -and (-not ($Password -eq "*SENSITIVE*DATA*DELETED*"))) {
                $Result = New-Object -TypeName PSObject
                $Result | Add-Member -MemberType "NoteProperty" -Name "Type" -Value "AdministratorPassword"
                $Result | Add-Member -MemberType "NoteProperty" -Name "Domain" -Value "N/A"
                $Result | Add-Member -MemberType "NoteProperty" -Name "Username" -Value "N/A"
                $Result | Add-Member -MemberType "NoteProperty" -Name "Password" -Value $Password
                $Result
            }
        }
    }
}
function depraves {
    [CmdletBinding()] Param(
        [Switch]$Filtered = $false
    )
    $Count = 0;
    $CredentialsPtr = [IntPtr]::Zero
    $Success = $Advapi32::CredEnumerate([IntPtr]::Zero, 1, [ref]$Count, [ref]$CredentialsPtr)
    $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    if ($Success) {
        Write-Verbose "CredEnumerate() OK - Count: $($Count)"
        for ($i = 0; $i -lt $Count; $i++) {
            $CredentialPtrOffset = [IntPtr] ($CredentialsPtr.ToInt64() + [IntPtr]::Size * $i)
            $CredentialPtr = [System.Runtime.InteropServices.Marshal]::ReadIntPtr($CredentialPtrOffset)
            $Cred = [System.Runtime.InteropServices.Marshal]::PtrToStructure($CredentialPtr, [type] $CREDENTIAL)
            $CredStr = savoring $Cred
            if ((-not $Filtered) -or ($Filtered -and (-not [String]::IsNullOrEmpty($CredStr)))) {
                $Result = New-Object -TypeName PSObject
                $Result | Add-Member -MemberType "NoteProperty" -Name "TargetName" -Value $Cred.TargetName
                $Result | Add-Member -MemberType "NoteProperty" -Name "UserName" -Value $Cred.UserName
                $Result | Add-Member -MemberType "NoteProperty" -Name "Comment" -Value $Cred.Comment
                $Result | Add-Member -MemberType "NoteProperty" -Name "Type" -Value "$($Cred.Type -as $CRED_TYPE)"
                $Result | Add-Member -MemberType "NoteProperty" -Name "Persist" -Value "$($Cred.Persist -as $CRED_PERSIST)"
                $Result | Add-Member -MemberType "NoteProperty" -Name "Flags" -Value "0x$($Cred.Flags.ToString('X8'))"
                $Result | Add-Member -MemberType "NoteProperty" -Name "Credential" -Value $CredStr
                $Result
            }
        }
        $Advapi32::CredFree($CredentialsPtr)
    }
    else {
        Write-Verbose ([ComponentModel.Win32Exception] $LastError)
    }
}
function manufacturing {
    [CmdletBinding()] Param(
        [Switch]
        $Filtered = $false
    )
    function flunked {
        [CmdletBinding()] Param(
            [Guid] $VaultGuid
        )
        $VaultSchemaEnum = @{
            ([Guid] '2F1A6504-0641-44CF-8BB5-3612D865F2E5') = 'Windows Secure Note'
            ([Guid] '3CCD5499-87A8-4B10-A215-608888DD3B55') = 'Windows Web Password Credential'
            ([Guid] '154E23D0-C644-4E6F-8CE6-5069272F999F') = 'Windows Credential Picker Protector'
            ([Guid] '4BF4C442-9B8A-41A0-B380-DD4A704DDB28') = 'Web Credentials'
            ([Guid] '77BC582B-F0A6-4E15-4E80-61736B6F3B29') = 'Windows Credentials'
            ([Guid] 'E69D7838-91B5-4FC9-89D5-230D4D4CC2BC') = 'Windows Domain Certificate Credential'
            ([Guid] '3E0E35BE-1B77-43E7-B873-AED901B6275B') = 'Windows Domain Password Credential'
            ([Guid] '3C886FF3-2669-4AA2-A8FB-3F6759A77548') = 'Windows Extended Credential'
        }
        $VaultSchemaEnum[$VaultGuid]
    }
    function unscathed {
        [CmdletBinding()] Param(
            [IntPtr]
            $VaultItemElementPtr
        )
        if ($VaultItemElementPtr -eq [IntPtr]::Zero) {
            return
        }
        $VaultItemDataHeader = [Runtime.InteropServices.Marshal]::PtrToStructure($VaultItemElementPtr, [type] $VAULT_ITEM_DATA_HEADER)
        $VaultItemDataValuePtr = [IntPtr] ($VaultItemElementPtr.ToInt64() + 16)
        switch ($VaultItemDataHeader.Type) {
            0x00 {
                [Bool] [Runtime.InteropServices.Marshal]::ReadByte($VaultItemDataValuePtr)
            }
            0x01 {
                [Runtime.InteropServices.Marshal]::ReadInt16($VaultItemDataValuePtr)
            }
            0x02 {
                [Runtime.InteropServices.Marshal]::ReadInt16($VaultItemDataValuePtr)
            }
            0x03 {
                [Runtime.InteropServices.Marshal]::ReadInt32($VaultItemDataValuePtr)
            }
            0x04 {
                [Runtime.InteropServices.Marshal]::ReadInt32($VaultItemDataValuePtr)
            }
            0x05 {
                [Runtime.InteropServices.Marshal]::PtrToStructure($VaultItemDataValuePtr, [Type] [Double])
            }
            0x06 {
                [Runtime.InteropServices.Marshal]::PtrToStructure($VaultItemDataValuePtr, [Type] [Guid])
            }
            0x07 {
                $StringPtr = [Runtime.InteropServices.Marshal]::ReadIntPtr($VaultItemDataValuePtr)
                [Runtime.InteropServices.Marshal]::PtrToStringUni($StringPtr)
            }
            0x08 {
            }
            0x09 {
            }
            0x0a {
            }
            0x0b {
            }
            0x0c {
                $SidPtr = [Runtime.InteropServices.Marshal]::ReadIntPtr($VaultItemDataValuePtr)
                $SidObject = [Security.Principal.SecurityIdentifier] ($SidPtr)
                $SidObject.Value
            }
            0x0d {
            }
        }
    }
    $VaultsCount = 0
    $VaultGuids = [IntPtr]::Zero
    $Result = $Vaultcli::VaultEnumerateVaults(0, [ref]$VaultsCount, [ref]$VaultGuids)
    if ($Result -eq 0) {
        Write-Verbose "VaultEnumerateVaults() OK - Count: $($VaultsCount)"
        for ($i = 0; $i -lt $VaultsCount; $i++) {
            $VaultGuidPtr = [IntPtr] ($VaultGuids.ToInt64() + ($i * [Runtime.InteropServices.Marshal]::SizeOf([Type] [Guid])))
            $VaultGuid = [Runtime.InteropServices.Marshal]::PtrToStructure($VaultGuidPtr, [type] [Guid])
            $VaultName = flunked -VaultGuid $VaultGuid
            Write-Verbose "Vault: $($VaultGuid) - $($VaultName)"
            $VaultHandle = [IntPtr]::Zero
            $Result = $Vaultcli::VaultOpenVault($VaultGuidPtr, 0, [ref]$VaultHandle)
            if ($Result -eq 0) {
                Write-Verbose "VaultOpenVault() OK - Vault Handle: 0x$($VaultHandle.ToString('X8'))"
                $VaultItemsCount = 0
                $ItemsPtr = [IntPtr]::Zero
                $Result = $Vaultcli::VaultEnumerateItems($VaultHandle, 0x0200, [ref]$VaultItemsCount, [ref]$ItemsPtr)
                $VaultItemPtr = $ItemsPtr
                if ($Result -eq 0) {
                    Write-Verbose "VaultEnumerateItems() OK - Items Count: $($VaultItemsCount)"
                    $OSVersion = accedes
                    try {
                        for ($j = 0; $j -lt $VaultItemsCount; $j++) {
                            if ($OSVersion.Major -le 6 -and $OSVersion.Minor -le 1) {
                                $VaultItemType = [type] $VAULT_ITEM_7
                            }
                            else {
                                $VaultItemType = [type] $VAULT_ITEM_8
                            }
                            $VaultItem = [Runtime.InteropServices.Marshal]::PtrToStructure($VaultItemPtr, [type] $VaultItemType)
                            if ($OSVersion.Major -le 6 -and $OSVersion.Minor -le 1) {
                                $PasswordItemPtr = [IntPtr]::Zero
                                $Result = $Vaultcli::VaultGetItem7($VaultHandle, [ref]$VaultItem.SchemaId, $VaultItem.Resource, $VaultItem.Identity, [IntPtr]::Zero, 0, [ref]$PasswordItemPtr)
                            }
                            else {
                                $PasswordItemPtr = [IntPtr]::Zero
                                $Result = $Vaultcli::VaultGetItem8($VaultHandle, [ref]$VaultItem.SchemaId, $VaultItem.Resource, $VaultItem.Identity, $VaultItem.PackageSid, [IntPtr]::Zero, 0, [ref]$PasswordItemPtr)
                            }
                            if ($Result -eq 0) {
                                Write-Verbose "VaultGetItem() OK - ItemPtr: 0x$($PasswordItemPtr.ToString('X8'))"
                                $PasswordItem = [Runtime.InteropServices.Marshal]::PtrToStructure($PasswordItemPtr, [Type] $VaultItemType)
                                $Password = unscathed -VaultItemElementPtr $PasswordItem.Authenticator
                                $Vaultcli::VaultFree($PasswordItemPtr) | Out-Null
                            }
                            else {
                                Write-Verbose "VaultGetItem() failed - Err: 0x$($Result.ToString('X8'))"
                            }
                            if ((-not $Filtered) -or ($Filtered -and (-not [String]::IsNullOrEmpty($Password)))) {
                                $Result = New-Object -TypeName PSObject
                                $Result | Add-Member -MemberType "NoteProperty" -Name "Type" -Value $VaultName
                                $Result | Add-Member -MemberType "NoteProperty" -Name "TargetName" -Value $(unscathed -VaultItemElementPtr $VaultItem.Resource)
                                $Result | Add-Member -MemberType "NoteProperty" -Name "UserName" -Value $(unscathed -VaultItemElementPtr $VaultItem.Identity)
                                $Result | Add-Member -MemberType "NoteProperty" -Name "Credential" -Value $Password
                                $Result | Add-Member -MemberType "NoteProperty" -Name "LastWritten" -Value $(Mulroney $VaultItem.LastWritten)
                                $Result
                            }
                            $VaultItemPtr = [IntPtr] ($VaultItemPtr.ToInt64() + [Runtime.InteropServices.Marshal]::SizeOf([Type] $VaultItemType))
                        }
                    }
                    catch [Exception] {
                        Write-Verbose $_.Exception.Message
                    }
                }
                else {
                    Write-Verbose "VaultEnumerateItems() failed - Err: 0x$($Result.ToString('X8'))"
                }
                $Vaultcli::VaultCloseVault([ref]$VaultHandle) | Out-Null
            }
            else {
                Write-Verbose "VaultOpenVault() failed - Err: 0x$($Result.ToString('X8'))"
            }
        }
    }
    else {
        Write-Verbose "VaultEnumerateVaults() failed - Err: 0x$($Result.ToString('X8'))"
    }
}
function embitters {
    [CmdletBinding()] Param()
    $ObjectName = "\Device"
    $ObjectNameBuffer = [Activator]::CreateInstance($UNICODE_STRING)
    $Ntdll::RtlInitUnicodeString([ref]$ObjectNameBuffer, $ObjectName) | Out-Null
    $ObjectAttributes = [Activator]::CreateInstance($OBJECT_ATTRIBUTES)
    $ObjectAttributes.Length = $OBJECT_ATTRIBUTES::GetSize()
    $ObjectAttributes.RootDirectory = [IntPtr]::Zero
    $ObjectAttributes.Attributes = $OBJ_ATTRIBUTE::OBJ_CASE_INSENSITIVE
    $ObjectAttributes.ObjectName = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($UNICODE_STRING::GetSize())
    [System.Runtime.InteropServices.Marshal]::StructureToPtr($ObjectNameBuffer, $ObjectAttributes.ObjectName, $true)
    $ObjectAttributes.SecurityDescriptor = [IntPtr]::Zero
    $ObjectAttributes.SecurityQualityOfService = [IntPtr]::Zero
    $ObjectHandle = [IntPtr]::Zero
    $Status = $Ntdll::NtOpenDirectoryObject([ref]$ObjectHandle, 3, [ref]$ObjectAttributes)
    if ($Status -ne 0) {
        $LastError = $Ntdll::RtlNtStatusToDosError($Status)
        Write-Verbose "NtOpenDirectoryObject - $([ComponentModel.Win32Exception] $LastError)"
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($ObjectAttributes.ObjectName) | Out-Null
        return
    }
    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($ObjectAttributes.ObjectName) | Out-Null
    $BufferSize = 1024
    $Buffer = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($BufferSize)
    [uint32] $Context = 0
    [uint32] $Length = 0
    while ($true) {
        $Status = $Ntdll::NtQueryDirectoryObject($ObjectHandle, $Buffer, $BufferSize, $true, $Context -eq 0, [ref]$Context, [ref]$Length)
        if ($Status -ne 0) { break }
        $ObjectDirectoryInformation = [System.Runtime.InteropServices.Marshal]::PtrToStructure($Buffer, [type] $OBJECT_DIRECTORY_INFORMATION)
        $TypeName = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($ObjectDirectoryInformation.TypeName.Buffer)
        $Name = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($ObjectDirectoryInformation.Name.Buffer)
        if ($TypeName -eq "Device" -and $Name -like "*VolumeShadowCopy*") {
            $Result = New-Object -TypeName PSObject
            $Result | Add-Member -MemberType "NoteProperty" -Name "Volume" -Value $Name
            $Result | Add-Member -MemberType "NoteProperty" -Name "Path" -Value $(Join-Path -Path "\\?\GLOBALROOT\Device\" -ChildPath $Name)
            $Result
        }
    }
    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($Buffer) | Out-Null
}
function foretells {
    [CmdletBinding()]
    param (
        [string] $Path
    )
    
    begin {
        $SanityCheck = $true
        if ([string]::IsNullOrEmpty($Path)) {
            $Path = Join-Path -Path $env:windir -ChildPath "System32\wbem\Repository\OBJECTS.DATA"
        }
        if (-not (Test-Path -Path $Path)) {
            Write-Warning "File not found: $($Path)"
            $SanityCheck = $false
        }
        $BasePattern = "CCM_NetworkAccessAccount"
        $PolicyPatternBegin = "<PolicySecret"
        $PolicyPatternEnd = "</PolicySecret>"
        $FsRedirectionValue = schemed
    }
    
    process {
        
        if (-not $SanityCheck) { return }
        $Candidates = Select-String -Path $Path -Pattern "$($BasePattern)`0`0$($PolicyPatternBegin)"
        if ($null -eq $Candidates) { return }
        foreach ($Candidate in $Candidates) {
            $Line = $Candidate.Line
            $Offset = $Line.IndexOf($BasePattern) + $BasePattern.Length + 2
            $Line = $Line.SubString($Offset, $Line.Length - $Offset)
            
            $Offset = 0
            $PolicySecrets = @()
            while (($Offset = $Line.IndexOf($PolicyPatternBegin, $Offset)) -ge 0) {
                $EndIndex = $Line.IndexOf($PolicyPatternEnd, $Offset)
                if ($EndIndex -lt 0) {
                    Write-Warning "Failed to find pattern '$($PolicyPatternEnd)'."
                    break
                }
                $Length = $EndIndex + $PolicyPatternEnd.Length - $Offset
                $Substring = $Line.SubString($Offset, $Length)
                [string[]] $PolicySecrets += $Substring
                $Offset += $PolicyPatternBegin.Length
            }
            if ($PolicySecrets.Count -ne 2) {
                Write-Warning "PolicySecret count should be 2, but was $($PolicySecrets.Count)."
                break
            }
            $Result = New-Object -TypeName PSObject
            $Result | Add-Member -MemberType "NoteProperty" -Name "NetworkAccessUsername" -Value $PolicySecrets[1]
            $Result | Add-Member -MemberType "NoteProperty" -Name "NetworkAccessPassword" -Value $PolicySecrets[0]
            $Result
        }
    }
    end {
        lifeguard -OldValue $FsRedirectionValue
    }
}
function adult {
    param ( [object] $Installer, [string] $Path, [int] $Mode )
    $Installer.GetType().InvokeMember("OpenDatabase", "InvokeMethod", $null, $Installer, @($Path, $Mode))
}
function rained {
    param ( [object] $Installer, [Int32] $Count )
    $Installer.GetType().InvokeMember("CreateRecord", "InvokeMethod", $null, $Installer, @($Count))
}
function unbuttoning {
    param ( [object] $Database, [string] $Query )
    $Database.GetType().InvokeMember("OpenView", "InvokeMethod", $null, $Database, @($Query))
}
function cheeses {
    param ( [object] $View, [object] $Record )
    $View.GetType().InvokeMember("Execute", "InvokeMethod", $null, $View, $(if ($Record) { @($Record) } else { $null }))
}
function churchman {
    param ( [object] $View )
    $View.GetType().InvokeMember("Fetch", "InvokeMethod", $null, $View, $null)
}
function consequences {
    param ( [object] $View )
    $View.GetType().InvokeMember("Close", "InvokeMethod", $null, $View, $null)
}
function backbitten {
    param ( [object] $Record, [string] $Property, [Int32] $Index )
    $Record.GetType().InvokeMember($Property, "GetProperty", $null, $Record, @($Index))
}
function pranced {
    param ( [object] $Record, [string] $Property, [Int32] $Index, [string] $Value)
    $Record.GetType().InvokeMember($Property, "SetProperty", $null, $Record, @($Index, $Value))
}
function enquiring {
    param ( [uint32] $Type )
    switch ($Type -band 0x0f) {
        1 { "Dll"       ; break } # Target = entry point name
        2 { "Exe"       ; break } # Target = command line args
        3 { "TextData"  ; break } # Target = text string to be formatted and set into property
        5 { "JScript"   ; break } # Target = entry point name, null if none to call
        6 { "VBScript"  ; break } # Target = entry point name, null if none to call
        7 { "Install"   ; break } # Target = property list for nested engine initialization
        default { throw "Unknown executable type for a Custom Action: $($_)" }
    }
}
function equestriennes {
    param ( [uint32] $Type )
    switch (($Type -band 0x30) * [Math]::Pow(2, -4)) {
        0 { "BinaryData" ; break} # Source = Binary.Name, data stored in stream
        1 { "SourceFile" ; break} # Source = File.File, file part of installation
        2 { "Directory"  ; break} # Source = Directory.Directory, folder containing existing file
        3 { "Property"   ; break} # Source = Property.Property, full path to executable
        default { throw "Unknown source type for a Custom Action: $($_)" }
    }
}
function mundane {
    param ( [uint32] $Type )
    $MaskedType = $Type -band 0xc0
    if ($MaskedType -band 0x40) { "ContinueOnReturn" } else { "ProcessReturnCode" }
    if ($MaskedType -band 0x80) { "Asynchronous"     } else { "Synchronous"       }
}
function Glenn {
    param ( [uint32] $Type )
    if ($Type -band 0x700) {
        if ($Type -band 0x400) {
            "InScript"                                  # queue for execution within script
            if ($Type -band 0x100) { "Rollback"       } # in conjunction with InScript: queue in Rollback script
            if ($Type -band 0x200) { "Commit"         } # in conjunction with InScript: run Commit ops from script on success
        }
        else {
            if ($Type -band 0x100) { "FirstSequence"  } # skip if UI sequence already run
            if ($Type -band 0x200) { "OncePerProcess" } # skip if UI sequence already run in same process
            if ($Type -band 0x300) { "ClientRepeat"   } # run on client only if UI already run on client
        }
    }
    else {
        "Always"                                        # default is execute whenever sequenced
    }
}
function roughness {
    param ( [uint32] $Type )
    if ($Type -band 0x800) {
        "NoImpersonate" # no impersonation, run in system context
    }
    else {
        "Impersonate" # default to impersonate as user, valid only if InScript
        if ($Type -band 0x4000) { "TSAware" } # impersonate for per-machine installs on Terminal Server machines
    }
}
function belching {
    param (
        [object] $Database,
        [uint32] $Arch,
        [uint32] $AllUsers
    )
    begin {
        $SystemFolders = terrorizing -Arch $Arch -AllUsers $AllUsers
    }
    process {
        if ($(enchantments -Database $Database) -NotContains "CustomAction") { return }
        try {
            $SqlQuery = "SELECT * FROM CustomAction"
            $View = unbuttoning -Database $Database -Query $SqlQuery
            cheeses -View $View
    
            $Record = churchman -View $View
    
            while ($null -ne $Record) {
    
                $Action = backbitten -Record $Record -Property "StringData" -Index 1
                $Type = [uint32] (backbitten -Record $Record -Property "StringData" -Index 2)
                $Source = backbitten -Record $Record -Property "StringData" -Index 3
                $Target = backbitten -Record $Record -Property "StringData" -Index 4
    
                $ExeType = enquiring -Type $Type
                $SourceType = equestriennes -Type $Type
                $ReturnProcessing = ([string[]] (mundane -Type $Type)) -join ","
                $SchedulingFlags = ([string[]] (Glenn -Type $Type)) -join ","
                $SecurityContextFlags = ([string[]] (roughness -Type $Type)) -join ","
    
                $TargetExpanded = circumstancing -String $Target -Database $Database -SystemFolders $SystemFolders
                if ($TargetExpanded -eq $Target) { $TargetExpanded = $null }
    
                $CustomAction = New-Object -TypeName PSObject
                $CustomAction | Add-Member -MemberType "NoteProperty" -Name "Action" -Value $Action
                $CustomAction | Add-Member -MemberType "NoteProperty" -Name "Type" -Value $Type
                $CustomAction | Add-Member -MemberType "NoteProperty" -Name "Source" -Value $Source
                $CustomAction | Add-Member -MemberType "NoteProperty" -Name "Target" -Value $Target
                if ($TargetExpanded) { $CustomAction | Add-Member -MemberType "NoteProperty" -Name "TargetExpanded" -Value $TargetExpanded }
                $CustomAction | Add-Member -MemberType "NoteProperty" -Name "ExeType" -Value $ExeType
                $CustomAction | Add-Member -MemberType "NoteProperty" -Name "SourceType" -Value $SourceType
                $CustomAction | Add-Member -MemberType "NoteProperty" -Name "ReturnProcessing" -Value $ReturnProcessing
                $CustomAction | Add-Member -MemberType "NoteProperty" -Name "SchedulingFlags" -Value $SchedulingFlags
                $CustomAction | Add-Member -MemberType "NoteProperty" -Name "SecurityContextFlags" -Value $SecurityContextFlags
                $CustomAction | Add-Member -MemberType "NoteProperty" -Name "RunAsSystem" -Value $([bool] ($Type -band 0x0800))
                $CustomAction | Add-Member -MemberType "NoteProperty" -Name "RunOnPatchUninstallOnly" -Value $([bool] ($Type -band 0x8000))
                $CustomAction
    
                $Record = churchman -View $View
            }
    
            consequences -View $View
        }
        catch {
            Write-Warning "Failed to enumerate Custom Actions (File: '$($MsiFile.FullName)': $($_)"
        }
    }
}
function Lelia {
    param (
        [object] $Database,
        [ValidateSet("ProductCode", "ProductName", "Manufacturer", "ProductVersion", "ALLUSERS")]
        [string] $Property
    )
    try {            
        $SqlQuery = "SELECT Value FROM Property WHERE Property='$($Property)'"
        $View = unbuttoning -Database $Database -Query $SqlQuery
        cheeses -View $View
        $Record = churchman -View $View
        if ($Record) { backbitten -Record $Record -Property "StringData" -Index 1 }
    }
    catch {
        Write-Warning "Lelia exception (Property=$($Property)): $($_)"
    }
}
function deposes {
    [OutputType([string])]
    param (
        [object] $Database,
        [string] $Directory
    )
    begin {
        $Result = $null
        $TempInstaller = New-Object -ComObject WindowsInstaller.Installer
    }
    process {
        try {
            $Record = rained -Installer $TempInstaller -Count 1
            $null = pranced -Record $Record -Property "StringData" -Index 1 -Value $Directory
    
            $SqlQuery = "SELECT Directory_Parent,DefaultDir FROM Directory WHERE Directory=?"
            $View = unbuttoning -Database $Database -Query $SqlQuery
            $null = cheeses -View $View -Record $Record
            $Record = churchman -View $View
            if ($Record) {
                $DirectoryParent = backbitten -Record $Record -Property "StringData" -Index 1
                $DefaultDir = backbitten -Record $Record -Property "StringData" -Index 2
                if ($DefaultDir -like "*|*") { $DefaultDir = $DefaultDir.Split('|')[1] }
                if ($DirectoryParent) {
                    $Result = "[$($DirectoryParent)]$($DefaultDir)\"
                } else {
                    $Result = "$($DefaultDir)\"
                }
            }
        }
        catch {
            Write-Warning "deposes exception: $($_)"
        }
    }
    end {
        $null = [System.Runtime.InteropServices.Marshal]::ReleaseComObject($TempInstaller)
        $Result
    }
}
function accentuate {
    [OutputType([string])]
    param (
        [object] $Database,
        [string] $File
    )
    begin {
        $Result = $null
        $TempInstaller = New-Object -ComObject WindowsInstaller.Installer
    }
    process {
        try {
            $Record = rained -Installer $TempInstaller -Count 1
            $null = pranced -Record $Record -Property "StringData" -Index 1 -Value $File
    
            $SqlQuery = "SELECT FileName FROM File WHERE File=?"
            $View = unbuttoning -Database $Database -Query $SqlQuery
            $null = cheeses -View $View -Record $Record
            $Record = churchman -View $View
            if ($Record) {
                $Result = backbitten -Record $Record -Property "StringData" -Index 1
                if ($Result -like "*|*") { $Result = $Result.Split('|')[1] }
            }
        }
        catch {
            Write-Warning "accentuate exception: $($_)"
        }
    }
    end {
        $null = [System.Runtime.InteropServices.Marshal]::ReleaseComObject($TempInstaller)
        $Result
    }
}
function constitutionality {
    
    [OutputType([string])]
    param (
        [object] $Database,
        [string] $Component
    )
    begin {
        $Result = $null
        $TempInstaller = New-Object -ComObject WindowsInstaller.Installer
    }
    process {
        try {
            $Record = rained -Installer $TempInstaller -Count 1
            $null = pranced -Record $Record -Property "StringData" -Index 1 -Value $Component
    
            $SqlQuery = "SELECT Directory_ FROM Component WHERE Component=?"
            $View = unbuttoning -Database $Database -Query $SqlQuery
            $null = cheeses -View $View -Record $Record
            $Record = churchman -View $View
            if ($Record) {
                $Result = backbitten -Record $Record -Property "StringData" -Index 1
                if ($Result -like "*|*") { $Result = $Result.Split('|')[1] }
            }
        }
        catch {
            Write-Warning "constitutionality exception: $($_)"
        }
    }
    end {
        $null = [System.Runtime.InteropServices.Marshal]::ReleaseComObject($TempInstaller)
        $Result
    }
}
function undercoating {
    param (
        [object] $Database,
        [string] $Name
    )
    begin {
        $Result = $null
        $TempInstaller = New-Object -ComObject WindowsInstaller.Installer
        $MsiReadStreamAnsi = 2
        $FieldIndex = 1
    }
    process {
        try {
            $Record = rained -Installer $TempInstaller -Count 1
            $null = pranced -Record $Record -Property "StringData" -Index 1 -Value $Name
            $SqlQuery = "SELECT Data FROM Binary WHERE Name=?"
            $View = unbuttoning -Database $Database -Query $SqlQuery
            $null = cheeses -View $View -Record $Record
            $Record = churchman -View $View
            if ($Record) {
                $DataSize = [int32] (backbitten -Record $Record -Property "DataSize" -Index $FieldIndex)
                Write-Verbose "Name: $($Name) | DataSize: $($DataSize)"
                if ($DataSize -eq 0) { return }
                $DataStream = $Record.GetType().InvokeMember("ReadStream", "InvokeMethod", $null, $Record, @($FieldIndex, $DataSize, $MsiReadStreamAnsi))
                if ($null -eq $DataStream) { return }
                $Result = $DataStream
            }
        }
        catch {
            Write-Warning "undercoating exception: $($_)"
        }
    }
    end {
        $null = [System.Runtime.InteropServices.Marshal]::ReleaseComObject($TempInstaller)
        $Result
    }
}
function enchantments {
    param ( [object] $Database )
    try {
        $SqlQuery = "SELECT Name FROM _Tables"
        $View = unbuttoning -Database $Database -Query $SqlQuery
        cheeses -View $View
        $Record = churchman -View $View
        while ($null -ne $Record) {
            backbitten -Record $Record -Property "StringData" -Index 1
            $Record = churchman -View $View
        }
    }
    catch {
        Write-Warning "enchantments exception: $($_)"
    }
}
function terrorizing {
    param (
        [ValidateSet(32, 64)]
        [uint32] $Arch,
        [ValidateSet(0, 1, 2)]
        [uint32] $AllUsers
    )
    $AllUserAppData = Join-Path -Path $env:ALLUSERSPROFILE -ChildPath "Microsoft\Windows"
    
    @{
        "AdminToolsFolder" = "ADMIN_TOOLS_FOLDER"
        "AppDataFolder" = $env:APPDATA
        "CommonAppDataFolder" = $env:ProgramData
        "CommonFiles64Folder" = $(if ($Arch -eq 64) { $env:CommonProgramFiles } else { $null })
        "CommonFilesFolder" = $(if ($Arch -eq 64) { ${env:CommonProgramFiles(x86)} } else { $env:CommonProgramFiles })
        "DesktopFolder" = Join-Path -Path $(if ($AllUsers) { $env:ALLUSERSPROFILE } else { $env:USERPROFILE }) -ChildPath "Desktop"
        "FavoritesFolder" = Join-Path -Path $(if ($AllUsers) { $env:ALLUSERSPROFILE } else { $env:USERPROFILE }) -ChildPath "Favorites"
        "FontsFolder" = Join-Path -Path $env:windir -ChildPath "Fonts"
        "LocalAppDataFolder" = $env:LOCALAPPDATA
        "MyPicturesFolder" = Join-Path -Path $env:USERPROFILE -ChildPath "Pictures"
        "NetHoodFolder" = "NET_HOOD_FOLDER"
        "PersonalFolder" = $env:USERPROFILE
        "PrintHoodFolder" = "PRINT_HOOD_FOLDER"
        "ProgramFiles64Folder" = $(if ($Arch -eq 64) { $env:ProgramFiles } else { $null })
        "ProgramFilesFolder" = $(if ($Arch -eq 64) { ${env:ProgramFiles(x86)} } else { ${env:ProgramFiles} })
        "ProgramMenuFolder" = Join-Path -Path $(if ($AllUsers) { $AllUserAppData } else { $env:APPDATA }) -ChildPath "Start Menu\Programs"
        "RecentFolder" = "RECENT_FOLDER"
        "SendToFolder" = Join-Path -Path $env:USERPROFILE -ChildPath "SendTo"
        "StartMenuFolder" = Join-Path -Path $(if ($AllUsers) { $AllUserAppData } else { $env:APPDATA }) -ChildPath "Start Menu"
        "StartupFolder" = Join-Path -Path $(if ($AllUsers) { $AllUserAppData } else { $env:APPDATA }) -ChildPath "Start Menu\Programs\Startup"
        "System16Folder" = Join-Path -Path $env:windir -ChildPath "System"
        "System64Folder" = Join-Path -Path $env:windir -ChildPath "System32"
        "SystemFolder" = Join-Path -Path $env:windir -ChildPath "System32"
        "TempFolder" = "TEMP_FOLDER"
        "TemplateFolder" = Join-Path -Path $(if ($AllUsers) { $AllUserAppData } else { $env:USERPROFILE }) -ChildPath "Templates"
        "WindowsFolder" = $env:windir
        "WindowsVolume" = Split-Path -Path $env:windir -Parent
    }
}
function circumstancing {
    param (
        [string] $String,
        [object] $Database,
        [object] $SystemFolders
    )
    $Variables = [string[]] ($String | Select-String -Pattern "\[[^\[]+\]" -AllMatches | ForEach-Object { $_.Matches })
    if ($null -eq $Variables) { return $String }
    foreach ($Variable in $Variables) {
        $Source = ($Variable.Replace("[", "")).Replace("]", "")
        switch ($Source[0]) {
            '%' {
                $String = $String.Replace("[$($Source)]", "$([Environment]::GetEnvironmentVariable($Source.Substring(1)))")
                break
            }
            '#' {
                $Resolved = accentuate -Database $Database -File $Source.Substring(1)
                if ($Resolved) {
                    $String = $String.Replace("[$($Source)]", "$($Resolved)")
                }
                else {
                    $String = $String.Replace("[$($Source)]", "$($Source)_NOT_RESOLVED")
                }
                break
            }
            '$' {
                $String = $String.Replace("[$($Source)]", "$($Source)_NOT_RESOLVED")
                $Resolved = constitutionality -Database $Database -Component $Source.Substring(1)
                if ($Resolved) {
                    $String = $String.Replace("[$($Source)]", "[$($Resolved)]")
                }
                else {
                    $String = $String.Replace("[$($Source)]", "$($Source)_NOT_RESOLVED")
                }
                break
            }
            '\\' {
                $String = $String.Replace("[$($Source)]", "$($Source.Substring(1, 1))")
                break
            }
            default {
                if ($SystemFolders.Keys -contains $Source) {
                    $String = $String.Replace("[$($Source)]", "$($SystemFolders[$Source])\")
                }
                else {
                    $Resolved = deposes -Database $Database -Directory $Source
                    if ($Resolved) {
                        $String = $String.Replace("[$($Source)]", "$($Resolved)")
                    }
                    else {
                        $String = $String.Replace("[$($Source)]", "$($Source)_NOT_RESOLVED")
                    }
                }
            }
        }
    }
    circumstancing -String $String -Database $Database -SystemFolders $SystemFolders
}
function Berkshires {
    [CmdletBinding()]
    param ()
    
    begin {
        $InstallerPath = Join-Path -Path $env:windir -ChildPath "Installer"
        $Arch = $(if ([Environment]::Is64BitOperatingSystem) { 64 } else { 32 })
    }
    
    process {
        $MsiFiles = Get-ChildItem -Path "$($InstallerPath)\*.msi" -ErrorAction SilentlyContinue
        foreach ($MsiFile in $MsiFiles) {
            Write-Verbose "Parsing file: $($MsiFile.FullName)"
            $Installer = New-Object -ComObject WindowsInstaller.Installer
            $Database = adult -Installer $Installer -Path $MsiFile.FullName -Mode 0
            $IdentifyingNumber = [string] (Lelia -Database $Database -Property "ProductCode")
            $Name = [string] (Lelia -Database $Database -Property "ProductName")
            $Vendor = [string] (Lelia -Database $Database -Property "Manufacturer")
            $Version = [string] (Lelia -Database $Database -Property "ProductVersion")
            $AllUsers = Lelia -Database $Database -Property "ALLUSERS"
            if ($IdentifyingNumber -match "(\d|[A-F]){8}-((\d|[A-F]){4}-){3}((\d|[A-F]){12})") {
                $IdentifyingNumber = $Matches[0]
            }
            $AllUsers = [uint32] $(if ($AllUsers) { $AllUsers[1] } else { 0 })
            $MsiFileItem = New-Object -TypeName PSObject
            $MsiFileItem | Add-Member -MemberType "NoteProperty" -Name "Path" -Value $MsiFile.FullName
            $MsiFileItem | Add-Member -MemberType "NoteProperty" -Name "IdentifyingNumber" -Value $(if ($IdentifyingNumber) { $IdentifyingNumber.Trim() })
            $MsiFileItem | Add-Member -MemberType "NoteProperty" -Name "Name" -Value $(if ($Name) { $Name.Trim() })
            $MsiFileItem | Add-Member -MemberType "NoteProperty" -Name "Vendor" -Value $(if ($Vendor) { $Vendor.Trim() })
            $MsiFileItem | Add-Member -MemberType "NoteProperty" -Name "Version" -Value $(if ($Version) { $Version.Trim() })
            $MsiFileItem | Add-Member -MemberType "NoteProperty" -Name "AllUsers" -Value $AllUsers
            $MsiFileItem | Add-Member -MemberType "NoteProperty" -Name "CustomActions" -Value $(belching -Database $Database -Arch $Arch -AllUsers $AllUsers)
            $MsiFileItem
            $null = [System.Runtime.InteropServices.Marshal]::ReleaseComObject($Installer)
        }
    }
}
$global:CachedServiceList = New-Object -TypeName System.Collections.ArrayList
$global:CachedDriverList = New-Object -TypeName System.Collections.ArrayList
$global:CachedHotFixList = New-Object -TypeName System.Collections.ArrayList
$global:CachedScheduledTaskList = New-Object -TypeName System.Collections.ArrayList
$global:CachedCurrentUserSids = $null
$global:CachedCurrentUserDenySids = $null
$global:ResultArrayList = New-Object -TypeName System.Collections.ArrayList
$global:KeywordsOfInterest = @( "key", "passw", "secret", "pwd", "creds", "credential", "api" )
$global:VulnerableDrivers = @"
"Id";"HashType";"Hash"
"c4eab0c0-caf2-42b9-84f1-b4690d3db0d4";"Md5";"33fc573c0e8bedfe3614e17219273429"
"a7bba474-815f-49be-bddc-4d76a64c866c";"Md5";"6126065af2fc2639473d12ee3c0c198e,c6f8983dd3d75640c072a8459b8fa55a,f7cbbb5eb263ec9a35a1042f52e82ca4,7ed6030f14e66e743241f2c1fa783e69,3651a6990fe38711ebb285143f867a43,736c4b85ce346ddf3b49b1e3abb4e72a,4a06bcd96ef0b90a1753a805b4235f28,63e333d64a8716e1ae59f914cb686ae8,79483cb29a0c428e1362ec8642109eee,23cf3da010497eb2bf39a5c5a57e437c,9638f265b1ddd5da6ecdf5c0619dcbe6,f2f728d2f69765f5dfda913d407783d2,992ded5b623be3c228f32edb4ca3f2d2,c3fea895fe95ea7a57d9f4d7abed5e71,0395b4e0eb21693590ad1cfdf7044b8b,68dde686d6999ad2e5d182b20403240b,34069a15ae3aa0e879cd0d81708e4bcc,3f39f013168428c8e505a7b9e6cba8a2,1ed043249c21ab201edccb37f1d40af9,96b463b6fa426ae42c414177af550ba2,0752f113d983030939b4ab98b0812cf0,6cce5bb9c8c2a8293df2d3b1897941a2,64efbffaa153b0d53dc1bccda4279299,2da209dde8188076a9579bd256dc90d0,84ba7af6ada1b3ea5efb9871a0613fc6,1b32c54b95121ab1683c7b83b2db4b96,b0baac4d6cbac384a633c71858b35a2e,b89b097b8b8aecb8341d05136f334ebb,a711e6ab17802fabf2e69e0cd57c54cd,490b1f404c4f31f4538b36736c990136,6f5d54ab483659ac78672440422ae3f1,dd04cd3de0c19bede84e9c95a86b3ca8,95e4c7b0384da89dce8ea6f31c3613d9,9aa7ed7809eec0d8bc6c545a1d18107a,c02f70960fa934b8defa16a03d7f6556,300c5b1795c9b6cc1bc4d7d55c7bbe85,3dbf69f935ea48571ea6b0f5a2878896,8d63e1a9ff4cafee1af179c0c544365c,e9a30edef1105b8a64218f892b2e56ed,361a598d8bb92c13b18abb7cac850b01,7b43dfd84de5e81162ebcfafb764b769,f66b96aa7ae430b56289409241645099"
"0d0d204b-f6ce-4ce4-8d76-1724a1676c3f";"Sha256";"49ed27460730b62403c1d2e4930573121ab0c86c442854bc0a62415ca445a810"
"ad693146-4adf-4407-bb20-f2505e34c226";"Sha256";"3a95cc82173032b82a0ffc7d2e438df64c13bc16b4574214c9fe3be37250925e"
"a8f2da2a-369c-4b4d-9a00-d7a892b9f7c3";"Md5";"eff3a9cc3e99ef3ddae57df72807f0c7"
"43d0af25-c066-471f-bb73-6ce25dc7e0eb";"Md5";"98763a3dee3cf03de334f00f95fc071a"
"257d425f-f660-466c-8bee-c24cccf06daa";"Md5";"8f73c1c48ffddfca7d1a98faf83d18ff"
"bb808089-5857-4df2-8998-753a7106cb44";"Md5";"dacb62578b3ea191ea37486d15f4f83c,d104621c93213942b7b43d65b5d8d33e"
"22aa985b-5fdb-4e38-9382-a496220c27ec";"Md5";"2e1f8a2a80221deb93496a861693c565"
"c33648d7-6473-4e2b-92f6-93f195bc183f";"Md5";"804c3cda22b58a6b4eec8a1a789e5e27,4972b9e4cd0a2cb8fc71ffc9cbcb8c01,4972b9e4cd0a2cb8fc71ffc9cbcb8c01,a19eca4bc9dab100a0f0a1d5a1221fdc,de1483e962bae5db0735872c036e404f,927b1f6b14c51cb5491f286cbcfaed81,eac4a15c3d19af7f579b7d9ad2751543,f8c5b8f95c6f86537a689f4083c54a18,3ff6facc1598bf73890da601a518081a,6e1d33edc594af4d0e42a4b945a4f5f5,fc190e931663988766794e2776b84bc2"
"1aeb1205-8b02-42b6-a563-b953ea337c19";"Md5";"d052dc4ac3c5bfe34f04abc62a153847,4064a81b6339992cbb4171b43b9a69dc,e58491b5aec097f17e310f83e82ae0c8"
"275c80c5-a67c-4536-b29e-4e481242cb01";"Md5";"3ecd3ca61ffc54b0d93f8b19161b83da,925ee3f3227c3b63e141ba16bd83f024,483abeee17e4e30a760ec8c0d6d31d6d,c508d28487121828c3a1c2b57acb05be,08c1bce6627764c9f8c79439555c5636,2d91d45cd09dfc3f8e89da1c261fd1ac,bcd60bf152fdec05cd40562b466be252,69ac6165912cb263a656497cc70155e6,4eb4069c230a5dc40cd5d60d2cb3e0d0,680dcb5c39c1ec40ac3897bb3e9f27b9,f8fe655b7d63dbdc53b0983a0d143028,880611326b768c4922e9da8a8effc582,515c75d77c64909690c18c08ef3fc310,6fa271b6816affaef640808fc51ac8af,d63c9c1a427a134461258b7b8742858f,3a7c69293fcd5688cc398691093ec06a,d5e76d125d624f8025d534f49e3c4162,ecdc79141b7002b246770d01606504f2,3aacaa62758fa6d178043d78ba89bebc,4e4b9bdcc6b8d97828ae1972d750a08d,821adf5ba68fd8cc7f4f1bc915fe47de,0d5774527af6e30905317839686b449d,18439fe2aaeddfd355ef88091cb6c15f,4b60ef388071e0baf299496e3d6590ae,aa9adcf64008e13d7e68b56fdd307ead,6a094d8e4b00dd1d93eb494099e98478,0fc2653b1c45f08ca0abd1eb7772e3c0,d424f369f7e010249619f0ecbe5f3805,9d884ecd3b6c3f2509851ea15ffefbef,5b1e1a9dade81f1e80fdc0a2d3f9006e,24061b0958874c1cb2a5a8e9d25482d4,70196d88c03f2ea557281b24dad85de5,d78a29306f42d42cd48ad6bc6c6a7602"
"fab98aaa-e4e7-4c4a-af65-c00d35cf66e9";"Md5";"db72def618cbc3c5f9aa82f091b54250"
"7b893f79-b5b0-4373-9d29-c53a21fe6fc3";"Md5";"a216803d691d92acc44ac77d981aa767,bf2a954160cb155df0df433929e9102b,bc6ff00fb3a14437c94b37ac9a2101d4"
"cf49f43c-d7b4-4c1a-a40d-1be36ea64bff";"Md5";"31eca8c0b32135850d5a50aee11fec87"
"9b65dba4-81a0-48cc-8ff0-a4f353881062";"Md5";"11fb599312cb1cf43ca5e879ed6fb71e"
"6ec5ddda-f302-4008-a73e-12814c1d571f";"Md5";"17b97fbe2e8834d7ad30211635e1b271,7ee0c884e7d282958c5b3a9e47f23e13,030c8432981e4d41b191624b3e07afe2,715ac0756234a203cb7ce8524b6ddc0d,f84da507b3067f019c340b737cd68d32,4814205270caa80d35569eee8081838e,dbf11f3fad1db3eb08e2ee24b5ebfb95,5a1ee9e6a177f305765f09b0ae6ac1c5,6682176866d6bd6b4ea3c8e398bd3aae"
"0f749d4e-145e-4b8e-bea6-47003d228043";"Md5";"3a1ba5cd653a9ddce30c58e7c8ae28ae,f34489c0f0d0a16b4db8a17281b57eba"
"ce2d41fd-908f-414c-b6b5-338298f425b8";"Md5";"a785b3bc4309d2eb111911c1b55e793f"
"4db827b1-325b-444d-9f23-171285a4d12f";"Md5";"cd9f0fcecf1664facb3671c0130dc8bb"
"214654eb-90c4-48c8-a183-0157e50bf07f";"Md5";"88a6d84f4f1cc188741271ac1999a4e9,564d84a799db39b381a582a0b2f738c4,55a7c51dc2aa959c41e391db8f6b8b4f,de711decdd763a73098372f752bf5a1c,61b068b10abfa0776f3b96a208d75bf9"
"90e8600a-9b5c-4153-bb06-1d8fbe0ef232";"Sha256";"455bc98ba32adab8b47d2d89bdbadca4910f91c182ab2fc3211ba07d3784537b"
"ecabc507-2cc7-4011-89ab-7d9d659e6f88";"Md5";"77fee376657e3178546185d135656268"
"3fb743b8-d3ed-4873-9c95-e212720dde21";"Sha256";"0fd2df82341bf5ebb8a53682e60d08978100c01acb0bed7b6ce2876ada80f670"
"9454a752-233e-4ba2-b585-8da242bf8f31";"Md5";"1e9f5515bff6f29d06694be4cd95a21c,4fbf95520d372ed081a16e1ccfb3c154,46e5dfe28aeccc39ea893975d54e3d3b,a01abca106a37eb4e7f96b1c4be38712,530f12f8058199964d0b41f1856185ec,3ce1153adde6ca1fa17679d9f00b4de0,2ff65eaca2ace4d13d0c7db521120e51,e3fb0f73f17f1fe04ae8fa9448d2f92b,a57e4e3a3fa46bbdbc9d803283af3479,9c46269615ae06f912463ddc28319157,0e2d4679f68796e9dd0d663137cb9e12,f783cf9084f1cefa87e9e5a302d4d18a,1814c4b16c8c3e746a185daaa5099ebc,0bd3b9f55a2d3a13f506d9d8b970e0de,a07f5f368deb3569ec3129fa55da4041,cb34374f1b5fb771076872c6b14b7501"
"f22e7230-5f32-4c4e-bc9d-9076ebf10baa";"Md5";"298f30c20c6b2b5b56f9946fb4e6f85a,9b25ccf5765034119a61c9beb2ad1369"
"d74fdf19-b4b0-4ec2-9c29-4213b064138b";"Md5";"f1a203406a680cc7e4017844b129dcbf"
"81a73e57-2e92-4d21-97d3-1c21eb4c3aea";"Md5";"b941c8364308990ee4cc6eadf7214e0f"
"f33c2e80-7b01-416b-821a-ed06db4b6511";"Md5";"d95c9a241e52b4f967fa4cdb7b99fc80"
"404f6db5-6be8-44a9-9898-badd56f96721";"Sha256";"cc383ad11e9d06047a1558ed343f389492da3ac2b84b71462aee502a2fa616c8"
"7437388f-821e-421f-a3c1-62ce2c725a6a";"Sha256";"5b9623da9ba8e5c80c49473f40ffe7ad315dcadffc3230afdc9d9226d60a715a"
"5d3f0b7d-7413-48e6-8d9c-7fc0bb5a66ee";"Sha256";"c60fcff9c8e5243bbb22ec94618b9dcb02c59bb49b90c04d7d6ab3ebbd58dc3a"
"79692987-1dd0-41a0-a560-9a0441922e5a";"Md5";"8065a7659562005127673ac52898675f"
"e4609b54-cb25-4433-a75a-7a17f43cec00";"Md5";"dbc415304403be25ac83047c170b0ec2"
"9074a02a-b1ca-4bfb-8918-5b88e91c04a2";"Md5";"3473faea65fba5d4fbe54c0898a3c044,2927eac51c46944ab69ba81462fb9045,aad4fb47cb39a9ab4159662a29e1ee88,7f258c0161e9edca8e7f85ac0dd68e46,a7d3ebfb3843ee28d9ca18b496bd0eb2,7e3a6f880486a4782b896e6dbd9cc26f"
"354a9fcf-acf1-4151-94d2-af88116f605c";"Sha1";"a7d827a41b2c4b7638495cd1d77926f1ba902978,877c6c36a155109888fe1f9797b93cb30b4957ef"
"99668140-a8f6-48f8-86d1-cf3bf693600c";"Sha256";"9d58f640c7295952b71bdcb456cae37213baccdcd3032c1e3aeb54e79081f395,4a9093e8dbcb867e1b97a0a67ce99a8511900658f5201c34ffb8035881f2dbbe,c7079033659ac9459b3b7ab2510805832db2e2a70fe9beb1a6e13c1f51890d88,082d4d4d4ba1bda5e1599bd24e930ae9f000e7d12b00f7021cca90a4600ea470"
"2aa003cd-5f36-46a6-ae3d-f5afc2c8baa3";"Md5";"5cc5c26fc99175997d84fe95c61ab2c2,fa63a634189bd4d6570964e2161426b0,fbf729350ca08a7673b115ce9c9eb7e5,766f9ea38918827df59a6aed204d2b09,00f887e74faad40e6e97d9d0e9c71370,5c9f240e0b83df758993837d18859cbe"
"7f645b95-4374-47ae-be1a-e4415308b550";"Md5";"c1d063c9422a19944cdaa6714623f2ec"
"73196456-40ae-4b6d-8562-07cf99458a7d";"Md5";"4ff880566f22919ed94ffae215d39da5,7e7e3f5532b6af24dcc252ac4b240311"
"7abc873d-9c28-44c2-8f60-701a8e26af29";"Md5";"982d39a9c76395dd4c826fe77c00a4bd,3f79ea5d2bbd2023d2f3e47d531f0e33"
"cfdc5cb4-be5c-4dcc-a883-825fa72115b4";"Md5";"2850608430dd089f24386f3336c84729"
"a261cd64-0d04-4bf5-ad73-f3bb96bf83cf";"Md5";"c2c1b8c00b99e913d992a870ed478a24"
"34fa6ba4-dc7c-4fd6-b947-8a0bb8ebd031";"Md5";"0dff47f3b14fb1c1bad47cc517f0581a,ee57cbe6ec6a703678eaa6c59542ff57,df5f8e118a97d1b38833fcdf7127ab29,785045f8b25cd2e937ddc6b09debe01a,119f0656ab4bb872f79ee5d421e2b9f9,530feb1e37831302f58b7c219be6b844,c098f8aeb67eeb2262dbf681690a9306,f22740ba54a400fd2be7690bb204aa08,24156523b923fd9dcfdd0ac684dcdb20,7331720a5522d5cd972623326cf87a3f,2971d4ee95f640d2818e38d8877c8984,2503c4cf31588f0b011eb992ca3ee7ff,e5e8ecb20bc5630414707295327d755e,1f7b2a00fe0c55d17d1b04c5e0507970,7b9717c608a5f5a1c816128a609e9575,6ab7b8ef0c44e7d2d5909fdb58d37fa5"
"a7628504-9e35-4e42-91f7-0c0a512549f4";"Md5";"c842827d4704a5ef53a809463254e1cc,84b17daba8715089542641990c1ea3c2,e36f6f7401ae11e11f69d744703914db,1610342659cb8eb4a0361dbc047a2221"
"39f427b6-aad3-4cb8-b363-9113a6d53b07";"Md5";"6b6dfb6d952a2e36efd4a387fdb94637"
"afed9dff-245e-4875-a156-3c5584beed03";"Md5";"537e2c3020b1d48b125da593e66508ec,8fbb1ffc6f13f9d5ee8480b36baffc52,76d1d4d285f74059f32b8ad19a146d0c,f41eea88057d3dd1a56027c4174eed22,c4f5619ce04d4bee38024d08513c77fd,5093f38d597532d59d4df9018056f0d1,790ccca8341919bb8bb49262a21fca0e,7978d858168fadd05c17779da5f4695a,d660fc7255646d5014d45c3bca9c6e20,b3424a229d845a88340045c29327c529"
"1ff757df-9a40-4f78-a28a-64830440abf7";"Md5";"8fc6cafd4e63a3271edf6a1897a892ae,7c0b186d1912686cfcb8cd9cdebabe58"
"4bf4b425-10af-4cd4-88e6-beb4b947eb48";"Md5";"2391fb461b061d0e5fccb050d4af7941"
"a2c3f6e9-25a5-4b75-8c6b-ad2d4e155822";"Md5";"6ba44f6ab055d6827a3ba43b215a7e13"
"31797996-6973-402d-a4a0-d01ce51e02c0";"Md5";"5bab40019419a2713298a5c9173e5d30"
"dbb58de1-a1e5-4c7f-8fe0-4033502b1c63";"Md5";"f5938db81d1e620b5c89ca0c5f157a33"
"31a962ce-43ef-410f-873a-7ccc8f00332b";"Sha256";"4cff6e53430b81ecc4fae453e59a0353bcfe73dd5780abfc35f299c16a97998e"
"57f63efb-dc43-4dba-9413-173e3e4be750";"Md5";"56a515173b211832e20fbc64e5a0447c"
"5943b267-64f3-40d4-8669-354f23dec122";"Md5";"8407ddfab85ae664e507c30314090385,1ed08a6264c5c92099d6d1dae5e8f530,ddc2ffe0ab3fcd48db898ab13c38d88d,29ccff428e5eb70ae429c3da8968e1ec,a57b47489febc552515778dd0fd1e51c,fe71c99a5830f94d77a8792741d6e6c7"
"f4126206-564f-49f5-a942-2138a3131e0e";"Md5";"52b7cd123f6d1b9ed76b08f2ee7d9433,f690bfc0799e51a626ba3931960c3173,3bf217f8ef018ca5ea20947bfdfc0a4d"
"1d4f7a3a-786b-4a74-b34f-14d44343de9e";"Sha256";"d7bc7306cb489fe4c285bbeddc6d1a09e814ef55cf30bd5b8daf87a52396f102"
"837ad058-65f4-4b75-8f21-b842e48db8a5";"Md5";"b2600502a5b962b8cdfac2ead24b17b4"
"ca415ed5-b611-4840-bfb2-6e1eacac33d1";"Md5";"988dabdcf990b134b0ac1e00512c30c4"
"a0fbd397-64d5-4af2-844b-b096e08a1866";"Md5";"7a6a6d6921cd1a4e1d61f9672a4560d6,cfad9185ffcf5850b5810c28b24d5fc8,0809f48fd30845d983d569b847fa83cf,6ae9d25e02b54367a4e93c2492b8b02e,34a7fab63a4ed5a0b61eb204828e08e5"
"0f59ce3b-20ac-41ba-8010-2abc74827eb8";"Md5";"b0809d8adc254c52f9d06362489ce474,0e14b69dcf67c20343f85f9fdb5b9300,6f5cf7feb9bb8108b68f169b8e625ffe,2da269863ed99be7b6b8ec2adc710648,1b76363059fef4f7da752eb0dfb0c1e1,d74d202646e5a6d0d2c4207e1f949826,6c28461e78f8d908ca9a66bad2e212f7,2b8814cff6351c2b775387770053bdec,95c88d25e211a4d52a82c53e5d93e634,047c06d4d38ea443c9af23a501c4480d,c6cfa2d6e4c443e673c2c12417ea3001,e68972cd9f28f0be0f9df7207aba9d1d,d6c4baecff632d6ad63c45fc39e04b2f,b5f96dd5cc7d14a9860ab99d161bf171,5e71c0814287763d529822d0a022e693,2dbc09c853c4bf2e058d29aaa21fa803,2e3dbb01b282a526bdc3031e0663c41c,1bca427ab8e67a9db833eb8f0ff92196,649ff59b8e571c1fc6535b31662407aa,5158f786afa19945d19bee9179065e4d,13a0d3f9d5f39adaca0a8d3bb327eb31,76355d5eafdfa3e9b7580b9153de1f30,1f263a57c5ef46c8577744ecb32c9548,e0fb44aba5e7798f2dc637c6d1f6ca84,2ff629de3667fcd606a0693951f1c1a9,f3d14fcdb86db8d75416ce173c6061af,7c4e513702a0322b0e3bce29dea9e3e9,65c069af3875494ec686afbb0c3da399,c5e7e8ca0d76a13a568901b6b304c3ba,0d4306983e694c1f34920bae12d887e6,6bada94085b6709694f8327c211d12e1,212bfd1ef00e199a365aeb74a8182609,a89ca92145fc330adced0dd005421183,26ce59f9fc8639fd7fed53ce3b785015,75dbd5db9892d7451d0429bec1aabe1a,fe820a5f99b092c3660762c6fc6c64e0,262969a3fab32b9e17e63e2d17a57744,17719a7f571d4cd08223f0b30f71b8b8,21be10f66bb65c1d406407faa0b9ba95,4885e1bf1971c8fa9e7686fd5199f500,ab4ee84e09b09012ac86d3a875af9d43,743c403d20a89db5ed84c874768b7119,e0bfbdf3793ea2742c03f5a82cb305a5,22ca5fe8fb0e5e22e6fb0848108c03f4,3ab94fba7196e84a97e83b15f7bcb270,e323413de3caec7f7730b43c551f26a0,c9c25778efe890baa4087e32937016a0,2f8653034a35526df88ea0c62b035a42,e747f164fc89566f934f9ec5627cd8c3,c08063f052308b6f5882482615387f30,549e5148be5e7be17f9d416d8a0e333e,d0c2caa17c7b6d2200e1b5aa9d07135e,f310b453ac562f2c53d30aa6e35506bb,aa69b4255e786d968adbd75ba5cf3e93,3411fdf098aa20193eee5ffa36ba43b2,f60a9b88c6ff07d4990d8653d0025683,c046ca4da48db1524ddf3a49a8d02b65,0283b43c6bc965175a1c92b255d39556,4a85754636c694572ca9f440d254f5ce,8741e6df191c805028b92cec44b1ba88,bf581e9eb91bace0b02a2c5a54bf1419,94ccef76fda12ab0b8270f9b2980552b,9b157f1261a8a42e4ef5ec23dd4cda9e,5212e0957468d3f94d90fa7a0f06b58f,56b54823a79a53747cbe11f8c4db7b1e,29872c7376c42e2a64fa838dad98aa11,557fd33ee99db6fe263cfcb82b7866b3,c516acb873c7f8c24a0431df8287756e,641243746597fbd650e5000d95811ea3,a453083b8f4ca7cb60cac327e97edbe2,07493c774aa406478005e8fe52c788b2,e425c66663c96d5a9f030b0ad4d219a8,ccb09eb78e047c931708149992c2e435,43bfc857406191963f4f3d9f1b76a7bf,8f5b84350bfc4fe3a65d921b4bd0e737,ce57844fb185d0cdd9d3ce9e5b6a891d,8ad9dfc971df71cd43788ade6acf8e7d,332db70d2c5c332768ab063ba6ac8433,729dd4df669dc96e74f4180c6ee2a64b,6ae4dec687ac6d1b635a4e351dddf73e,cf7aeedd674417b648fc334d179c94ae,be17a598e0f5314748ade0871ad343e7,2714c93eb240375a2893ed7f8818004f,118f3fdba730094d17aa1b259586aef6,80b4041695810f98e1c71ff0cf420b6d,c2eb4539a4f6ab6edd01bdc191619975,44a3b9cc0a8e89c11544932b295ea113,75fa19142531cbf490770c2988a7db64,a223f8584bcb978c003dd451b1439f8d,e027daa2f81961d09aef88093e107d93,c31610f4c383204a1fc105c54b7403c9,8d14b013fc2b555e404b1c3301150c34,a610cd4c762b5af8575285dafb9baa8f,8ea94766cd7890483449dc193d267993,82854a57630059d1ce2870159dc2f86b,9cc757a18b86408efc1ce3ed20cbcdac,279f3b94c2b9ab5911515bc3e0ecf175,8b47c5580b130dd3f580af09323bc949,d011d5fecdc94754bf02014cb229d6bc"
"9c4e2e75-a8be-4d2f-b016-e2a98281c8ec";"Md5";"8af49cbb873437aeacfbdbcf884f8ebe"
"dfce8b0f-d857-4808-80ef-61273c7a4183";"Md5";"51207adb8dab983332d6b22c29fe8129"
"213676bb-ffb9-4d0d-a442-8cefee63acc1";"Md5";"ab859723016484790c87b2218931d55f,dbdac970026703dfa5ccaf69b04086ec,9c56e390589ceb75d773229567924dcd,e4f8cab9d478d892ab076f182a951d0d"
"724d7989-dfce-4bb2-9beb-dee15df5b790";"Md5";"2b36d61f6e7420977648ed27e784adf1"
"50cfaec9-55f8-49df-aa3e-b9ec3f4f4ff3";"Md5";"4b817d0e7714b9d43db43ae4a22a161e"
"62f76f62-ef82-49ea-a26f-36e5727e8d83";"Md5";"bc1eeb4993a601e6f7776233028ac095,a2be99e4904264baa5649c4d4cd13a17"
"a7775cbe-624b-4b04-b74f-969f77c2ac02";"Md5";"43830326cd5fae66f5508e27cbec39a0"
"181b89e5-4bdd-4e95-b1bc-a294a4adfb29";"Md5";"214a9aba01ee1ba067b2feb382748c16"
"57354c82-ff9c-4a54-8377-d195e4ff0a26";"Md5";"dc358c301fb463c2f4e7edb028dfe7e8"
"dc3fdbd3-601a-4d2a-bf34-d2e84c6ff1d3";"Md5";"003dc41d148ec3286dc7df404ba3f2aa"
"f1dcb0e4-aa53-4e62-ab09-fb7b4a356916";"Sha1";"e74b6dda8bc53bc687fc21218bd34062a78d8467,2c27abbbbcf10dfb75ad79557e30ace5ed314df8,108439a4c4508e8dca659905128a4633d8851fd9,655a9487d7a935322e19bb92d2465849055d029d,1c3f2579310ddd7ae09ce9ca1cc537a771b83c9f,0cca79962d9af574169f5dec12b1f4ca8e5e1868,8788f4b39cbf037270904bdb8118c8b037ee6562"
"e9b099f6-8a12-46f0-a540-40e88cf0ce17";"Sha256";"3390919bb28d5c36cc348f9ef23be5fa49bfd81263eb7740826e4437cbe904cd"
"a02e1801-f6fb-41c3-a782-05fdbed44a3c";"Md5";"ce59e4ab8405192dd47be9a762c197d8"
"4c815256-2534-4476-b15d-7cbf24c80098";"Md5";"8b6fc18d944ae44403dd03a6c63b7fbb"
"c08c03ff-a7b7-4282-a9fc-265ae88dc244";"Md5";"c15eb30e806ad5e771b23423fd2040b0,9c3c250646e11052b1e38500ee0e467b"
"48bc2815-85ec-4436-a51a-69810c8cb171";"Md5";"715f8efab1d1c660e4188055c4b28eed"
"2ada18ae-2c52-49b6-b1a0-cf3b267f6dc7";"Md5";"9f70cd5edcc4efc48ae21e04fb03be9d"
"db666d40-c9fa-4039-bfac-a5d7afd61b67";"Md5";"7475bfea6ea1cd54029208ed59b96c6b,8aa9d47ec9a0713c56b6dec3d601d105,eb4de413782193e824773723d790cfc4,0797bb21d7a0210fedf4f3533ee82494,0ccc4e9396e0be9c4639faec53715831,f670d1570c75ab1d8e870c1c6e3baba1,8bf290b5eda99fc2697373a87f4e1927,86bec99cd121b0386a5acc1c368a9d49,def0da6c95d14f7020e533028224250e,e4b50e44d1f12a47e18259b41074f126,57cd52ed992b634e74d2ddf9853a73b3,9945823e9846724c70d2f8d66a403300,5eabc87416f59e894adfde065d0405fa,eba6b88bc7bca21658bda9533f0bbff8,a5deee418b7b580ca89db8a871dc1645,6917ef5d483ed30be14f8085eaef521b,c9cb486b4f652c9cfb8411803f8ed5f0,e6eaee1b3e41f404c289e22df66ef66b,be5f46fd1056f02a7a241e052fa5888f,5e9d5c59ba1f1060f53909c129df3355,2315a8919cfb167e718d8c788ed3ceca,b17fb1ad5e880467cf7e61b1ee8e3448,f7edd110de10f9a50c2922f1450819aa,100fe0bc0c183d16e1f08d1a2ad624a8,0420fa6704fd0590c5ce7176fdada650,c607c37af638fa4eac751976a6afbaa6,c5d1f8ed329ebb86ddd01e414a6a1718,d3026938514218766cb6d3b36ccfa322,1b2e3b7f2966f2f6e6a1bb89f97228e5,00685003005b0b437af929f0499545e4,daf11013cf4c879a54ed6a86a05bee3c,2a2867e1f323320fdeef40c1da578a9a,729afa54490443da66c2685bd77cb1f0,644d687c9f96c82ea2974ccacd8cd549"
"bc5e020a-ecff-43c8-b57b-ee17b5f65b21";"Md5";"9a237fa07ce3ed06ea924a9bed4a6b99,5efbbfcc6adac121c8e2fe76641ed329,0be4a11bc261f3cd8b4dbfebee88c209,d86269ba823c9ecf49a145540cd0b3df,230fd3749904ca045ea5ec0aa14006e9"
"97ed6c7b-be4c-4f60-9157-c788a555ca9f";"Md5";"1f8a9619ab644728ce4cf86f3ad879ea"
"6736cbe7-33ea-4488-b464-231c0b8d1049";"Md5";"5d4df0bac74e9ac62af6bc99440b050b"
"ff74f03e-e4ce-4242-bfe3-60601056bb34";"Md5";"803a371a78d528a44ef8777f67443b16"
"19d16518-4aee-4983-ba89-dbbe0fa8a3e7";"Md5";"31469f1313871690e8dc2e8ee4799b22"
"2c3884d3-9e4f-4519-b18b-0969612621bc";"Md5";"2d7f1c02b94d6f0f3e10107e5ea8e141,b94ffce20e36b2930eb3ac72f72c00d6"
"d5118882-6cdd-4b06-8bf4-e9818f16137e";"Sha256";"7d8937c18d6e11a0952e53970a0934cf0e65515637ac24d6ca52ccf4b93d385f"
"66be9e0a-9246-4404-b5b5-7fbde351668f";"Md5";"3c4154866f3d483fdc9f4f64ef868888"
"de4dd27a-1f7e-4271-98a4-55395ab6aabf";"Md5";"83601bbe5563d92c1fdb4e960d84dc77"
"a4aa80bc-4ecd-49ab-bc0f-0f49b07fdd7f";"Md5";"9cbdb5fb6dc63cb13f10b6333407cbb9,4ae55080ec8aed49343e40d08370195c,bdc3b6b83dde7111d5d6b9a2aadf233f,31a331a88c6280555859455518a95c35,875c44411674b75feb07592aeffa09c1,dad8f40626ed4702e0e8502562d93d7c,f14359ceb3705d77353b244bb795b552"
"080ff223-f8e0-49c0-a7b5-e97349cf81a0";"Md5";"a641e3dccba765a10718c9cb0da7879e"
"13973a71-412f-4a18-a2a6-476d3853f8de";"Md5";"f16b44cca74d3c3645e4c0a6bb5c0cb9,130c5aec46bdec8d534df7222d160fdb,013719e840e955c2e4cd9d18c94a2625,aa12c1cb47c443c6108bfe7fc1a34d98,0490f5961e0980792f5cb5aedf081dd7,0be5c6476dd58072c93af4fca62ee4b3,13ee349c15ee5d6cf640b3d0111ffc0e"
"45c42e32-6261-43c1-bdbd-cab58da729d8";"Md5";"1838e8ea8b471a6fc54a06e8a796b118"
"2225128d-a23f-434a-aaee-69a88ea64fbd";"Md5";"76c8d022c6788a3b29ebc19e8d7956c4,28042093c08db49d0e0dc1903cf46907,8602bd2326f95beecf25fded10f5bc8a,a058cb2f78d6c44d26def1e264d67e78,6b5a579b2039eaa97b1694468dab2119,49dbc80ecf8e331ff828b964e491621b,2293aa65ada1c1d15a1ffb596612aee3,7ceb48348ecd008c97bb5f74bdbea843,52c7dac60d4b5c673441da38983df4ad,ecbc7e628a7ea22a3b90d9b16a948707,a57afed9703b5893fbfee5f9710b8aee"
"5a03dc5a-115d-4d6f-b5b5-685f4c014a69";"Md5";"12583af6cbe0050651eaf2723b3ad7b3,7455ed832a33fef453407f5411c3342d,0ffe35f0b0cd5a324bbe22f02569ae3b"
"45f2c348-bf17-40ab-8306-ef14231cc996";"Sha1";"f1c8c3926d0370459a1b7f0cf3d17b22ff9d0c7f"
"043773c5-120a-4c6b-8485-8f1f5c47fd3e";"Md5";"c61876aaca6ce822be18adb9d9bd4260,56a9e9b5334f8698a0ede27c64140982,94999245e9580c6228b22ac44c66044c,93a23503e26773c27ed1da06bb79e7a4,25190f667f31318dd9a2e36383d5709f,e7273e17ac85dc4272c4c4400091a19e,812e960977116bf6d6c1ccf8b5dd351f,595363661db3e50acc4de05b0215cc6f,6212832f13b296ddbc85b24e22edb5ec,cc8855fe30a9cdef895177a4cf1a3dad,f83c61adbb154d46dd8f77923aa7e9c3,a3af4a4fa6cba27284f8289436c2f074,88d5fc86f0dd3a8b42463f8d5503a570,e4d4a22cbf94e6b0a92fc36d46741f56,a22626febc924eb219a953f1ee2b9600,66e0db8a5b0425459d0430547ecbb3db,cb31f1b637056a3d374e22865c41e6d9,d0a5b98788e480c12afc65ad3e6d4478,84c4d8ae023ca9bb60694fa467141247,14add4f16d80595e6e816abf038141e5,53bb10742e10991af4ad280fcb134151,045ef7a39288ba1f4b8d6eca43def44f,11dc5523bb559f8d2ce637f6a2b70dea,9f3b5de6fe46429bed794813c6ae8421,f0aeb731d83f7ab6008c92c97faf6233,700d6a0331befd4ed9cfbb3234b335e7,9eb524c5f92e5b80374b8261292fdeb5,9496585198d726000ea505abc39dbfe9,ceac1347acae9ad9496d4b0593256522,35c8fdf881909fa28c92b1c2741ac60b,300d6ac47a146eb8eb159f51bc13f7cf,dcd966874b4c8c952662d2d16ddb4d7c,991230087394738976dbd44f92516cae,259381daae0357fbfefe1d92188c496a,16472fca75ab4b5647c99de608949cde,0e207ef80361b3d047a2358d0e2206b4,a4531040276080441974d9e00d8d4cfa,7fbd3b4488a12eab56c54e7bb91516f3,65e6718a547495c692e090d7887d247b"
"17cf4fac-88f1-467d-9f62-481d33accc5b";"Md5";"d5a642329cce4df94b8dc1ba9660ae34"
"e42cd285-4dda-4086-a696-93ab1d6f17ca";"Md5";"e8ebba56ea799e1e62748c59e1a4c586"
"e32bc3da-4db1-4858-a62c-6fbe4db6afbd";"Md5";"2d8e4f38b36c334d0a32a7324832501d,0ec361f2fba49c73260af351c39ff9cb,0a2ec9e3e236698185978a5fc76e74e6,9a5a35112c4f8016abcc6363b44d3385,a5afd20e34bcd634ebd25b3ab2ff3403,6691e873354f1914692df104718eebad,b994110f069d197222508a724d8afdac,4b194021d6bd6650cbd1aed9370b2329,6b16512bffe88146a7915f749bd81641,0be80db5d9368fdb29fe9d9bfdd02e7c,61e8367fb57297a949c9a80c2e0e5a38,98583b2f2efe12d2a167217a3838c498,dca1c62c793f84bb2d8e41ca50efbff1,027e10a5048b135862d638b9085d1402,592065b29131af32aa18a9e546be9617,ada5f19423f91795c0372ff39d745acf,8a108158431e9a7d08e330fd7a46d175,c475c7d0f2d934f150b6c32c01479134,79b8119b012352d255961e76605567d6,6fb3d42a4f07d8115d59eb2ea6504de5,700e9902b0a28979724582f116288bad,ef5ba21690c2f4ba7e62bf022b2df1f7,d6cc5709aca6a6b868962a6506d48abc,adc1e141b57505fd011bc1efb1ae6967,2e887e52e45bba3c47ccd0e75fc5266f,7f7b8cde26c4943c9465e412adbb790f,86635fdc8e28957e6c01fc483fe7b020,e6ea0e8d2edcc6cad3c414a889d17ac4,0d992b69029d1f23a872ff5a3352fb5b,b418293e25632c5f377bf034bb450e57,f4b2580cf0477493908b7ed81e4482f8,bc5366760098dc14ec00ae36c359f42b,7c40ec9ed020cc9404de8fe3a5361a09,b971b79bdca77e8755e615909a1c7a9f,96c850e53caca0469e1c4604e6c1aad1,cb22776d06f1e81cc87faeb0245acde8,1440c0da81c700bd61142bc569477d81,70c2c29643ee1edd3bbcd2ef1ffc9a73,ddb7da975d90b2a9c9c58e1af55f0285,72acbdd8fac58b71b301980eab3ebfc8,260eef181a9bf2849bfec54c1736613b,aa55dd14064cb808613d09195e3ba749,710b290a00598fbb1bcc49b30174b2c9"
"142453a2-a24d-4b35-8922-6d5939f1c0fc";"Md5";"07f83829e7429e60298440cd1e601a6a,07f83829e7429e60298440cd1e601a6a,7d84a4ed0fcca3d098881a3f3283724b"
"c854b612-0b9f-4fc3-a7b8-a93bed7a291e";"Md5";"0211ab46b73a2623b86c1cfcb30579ab"
"a5792a63-ba77-44ac-bd4a-134b24b01033";"Sha256";"64f9e664bc6d4b8f5f68616dd50ae819c3e60452efd5e589d6604b9356841b57"
"24fb7bab-b8c3-46ea-a370-c84d2f0ff614";"Md5";"778b7feea3c750d44745d3bf294bd4ce"
"a845a05c-5357-4b78-9783-16b4d34b2cb0";"Md5";"a5f637d61719d37a5b4868c385e363c0"
"067589f2-4f29-4dc4-bd50-a2e2ee57b25f";"Sha256";"3e9b62d2ea2be50a2da670746c4dbe807db9601980af3a1014bcd72d0248d84c"
"d05a0a6c-c037-4647-99ac-c41593190223";"Sha256";"cb57f3a7fe9e1f8e63332c563b0a319b26c944be839eabc03e9a3277756ba612"
"c2e70ee6-2f13-4d43-ad5a-c2bf033cc457";"Sha256";"823da894b2c73ffcd39e77366b6f1abf0ae9604d9b20140a54e6d55053aadeba"
"0e8da43d-92e0-43f9-bc34-50a7d15b34bd";"Md5";"a92bf3c219a5fa82087b6c31bdf36ff3"
"56cdac8e-d87d-49c8-b281-6e096c2390d1";"Md5";"1a22a85489a94db6ff68cd624ef43bad,acd221ff7cf10b6117fd609929cde395"
"8d3f27bd-c3fd-48d0-913a-e2caa6fbd025";"Md5";"7aa34cd9ea5649c24a814e292b270b6f,ffd0c87d9bf894af26823fbde94c71b6,96a8b535b5e14b582ca5679a3e2a5946,664ad9cf500916c94fc2c0020660ac4e,70dcd07d38017b43f710061f37cb4a91,daf800da15b33bf1a84ee7afc59f0656,b5ada7fd226d20ec6634fc24768f9e22,b8b6686324f7aa77f570bc019ec214e6,f23b2adcfab58e33872e5c2d0041ad88,dd050e79c515e4a6d1ae36cac5545025,96e10a2904fff9491762a4fb549ad580,4e67277648c63b79563360dac22b5492,7dd538bcaa98d6c063ead8606066333f,34edf3464c3f5605c1ca3a071f12e28c"
"1a1cf88a-96d0-46cd-a24d-1535e4a5f6e3";"Md5";"c49a1956a6a25ffc25ad97d6762b0989"
"69b924ab-2e4a-4eae-8091-4151c238136e";"Sha256";"a3e507e713f11901017fc328186ae98e23de7cea5594687480229f77d45848d8"
"205721b7-b83b-414a-b4b5-8bacb4a37777";"Md5";"1493d342e7a36553c56b2adea150949e,76c643ab29d497317085e5db8c799960"
"b7ec29c6-e151-4a9f-a293-e61f04ee6489";"Sha256";"d25904fbf907e19f366d54962ff543d9f53b8fdfd2416c8b9796b6a8dd430e26"
"9f8f2324-d867-4211-842a-122b93946445";"Md5";"8b779fe1d71839ad361226f66f1b3fe5,67e3b720cee8184c714585a85f8058a0,8f47af49c330c9fcf3451ad2252b9e04,89c7bd12495e29413038224cb61db02e"
"a254e684-f6eb-40c4-a50a-7b76feb6cc02";"Md5";"afbb28a756e233d32e224a664763f79c"
"b3fd8560-79d3-40b7-b05f-c78044176c8c";"Md5";"7b2918d0a19ca452d39ec59b7670e880"
"b0dedc3f-6e4b-497a-aade-390cbf4beebb";"Md5";"e4ea7ebfa142d20a92fbe468a77eafa6,449bb1c656fa30de7702f17e35b11cd3,4ec08e0bcdf3e880e7f5a7d78a73440c,cc35379f0421b907004a9099611ee2cd,9993a2a45c745bb0139bf3e8decd626c"
"94eb0694-29ba-4f8e-b763-86c6371db6cc";"Md5";"97221e16e7a99a00592ca278c49ffbfc,11fb599312cb1cf43ca5e879ed6fb71e"
"a8e999ee-746f-4788-9102-c1d3d2914f56";"Md5";"ed6348707f177629739df73b97ba1b6e,c8c6fadcb7cb85f197ab77e6a7b67aa9,ad6d5177656dfc5b43def5d13d32f9f6"
"93c84c08-4683-493d-abf7-22dc2d1cb567";"Md5";"0d6fef14f8e1ce5753424bd22c46b1ce"
"3bc629e8-7bf8-40c2-965b-87eb155e0065";"Md5";"9dfd73dadb2f1c7e9c9d2542981aaa63"
"9ca73d04-3349-4c16-9384-94c43335a031";"Md5";"4ad13cdb6330cede4b2c4e1be3ee267f"
"fbdd993b-47b1-4448-8c41-24c310802398";"Md5";"257483d5d8b268d0d679956c7acdf02d,f7a09ac4a91a6390f8d00bf09f53ae37,1276f735d22cf04676a719edc6b0df18,9650db2ef0a44984845841ab24972ced"
"be4843ef-a2a8-4a0d-91c6-42e165800bb0";"Sha256";"0de4247e72d378713bcf22d5c5d3874d079203bb4364e25f67a90d5570bdcce8"
"2a6a38ca-f2e6-456e-9ccf-db59d8c80c9e";"Md5";"ba86e444ae837476e7ccdd06f8867795"
"ee6fa2de-d388-416c-862d-24385c152fad";"Md5";"808d2bcad62afa82a2b4fdd0fec6d9c6,d90251456195433abcb63ff579a8dda8"
"b51c441a-12c7-407d-9517-559cc0030cf6";"Md5";"73c98438ac64a68e88b7b0afd11ba140,002a58b90a589913a07012253662c98c,524cd77f4c100cf20af4004f740b0268,1f15a513abc039533ca996552ba27e51,394e290aff9d4e78e504cedfb2d99350,d4119a5cb07ce945c6549eae74e39731,a346417e9ae2c17a8fbf73302eeb611d"
"a66d0413-cc82-4f1e-bcf1-0dcf9d79f6c0";"Md5";"d2588631d8aae2a3e54410eaf54f0679"
"a285591e-ad3c-46a3-a648-c58589ff5efc";"Md5";"eb525d99a31eb4fff09814e83593a494"
"6c0c60f0-895d-428a-a8ae-e10390bceb12";"Md5";"3fa2e254bfbce52b3c6f1bf23aab6911,dc8d2952fb6ffbaec67bd1b93a34df11"
"7edb5602-239f-460a-89d6-363ff1059765";"Md5";"779af226b7b72ff9d78ce1f03d4a3389,25ebe6f757129adbe78ec312a5f1800b,650f6531db6fb0ed25d7fc70be35a4da,3467b0d996251dc56a72fc51a536dd6b,688a10e87af9bcf0e40277d927923a00,3d5164e85d740bce0391e2b81d49d308,3ad7b36a584504b3c70b5f552ba33015,08e06b839499cb4b752347399db41b57"
"3aa6e630-59be-4a15-a30c-aaed4c1edaf0";"Md5";"7575b35fee4ec8dbd0a61dbca3b972e3,397580c24c544d477688fcfca9c9b542,13a2b915f6d93e52505656773d53096f,723381977ce7df57ec623db52b84f426,eb7f6d01c97783013115ad1a2833401a,b62e2371158a082e239f5883bd6000d1,09e77d71d626574e6142894caca6e6dd,24589081b827989b52d954dcd88035d0,8f1255efd2ed0d3b03a02c6b236c06d6,f0e21ababe63668fb3fbd02e90cd1fa9,648adec580746afbbf59904c1e150c73,5c5973d2caf86e96311f6399513ab8df,009876ab9cf3a3d4e3fc3afe13ae839e,7c887f2b1a56b84d86828529604957db,1caf5070493459ba029d988dbb2c7422,a730b97ab977aa444fa261902822a905,17c7bcae7ebabb95af2f7c91b19c361c,7ffdd78d63ca7307a96843cfe806799e,192519661fe6d132f233d0355c3f4a6d,ab4656d1ec4d4cc83c76f639a5340e84,b41dcdb2e710dffba2d8ea1defb0f087,e99e86480d4206beb898dda82b71ca44,3af19d325f9dcdf360276ae5e7c136ea,4a829b8cf1f8fdb69e1d58ae04e6106e,8a212a246b3c41f3ddce5888aaaaacd6,198b723e13a270bb664dcb9fb6ed42e6,5bbe4e52bd33f1cdd4cf38c7c65f80ae,25ede0fd525a30d31998ea62876961ec,03ca3b1cff154ab8855043abadd07956,2b6a17ec50d3a21e030ed78f7acbd2af,2d854c6772f0daa8d1fde4168d26c36b,1ad400766530669d14a077514599e7f3,0ec31f45e2e698a83131b4443f9a6dd7,96fb2101f85fa81871256107bdd25169,b3d6378185356326fd8ee4329b0b7698,0c7f66cd219817eaab41f36d4bc0d4cd"
"1ab1ec8c-1231-4ba4-8804-4a2cda103bb8";"Md5";"7d0b8d03f0c985e27e5dc7263fa3f0ae"
"b9e01a11-6395-4837-a202-0c777d717a43";"Md5";"52cb7756bb236b966f75089edb309920"
"2da3a276-9e38-4ee6-903d-d15f7c355e7c";"Md5";"bce7f34912ff59a3926216b206deb09f,eaea9ccb40c82af8f3867cd0f4dd5e9d,154fd286c96665946d55a7d49923ad7e,ee91da973bebe6442527b3d1abcc3c80,3b23808de1403961205352e94b8f2f9b,9f94028cbcf6789103cb5bb6fcef355d,1c31d4e9ad2d2b5600ae9d0c0969fe59"
"36227ce7-2bf6-4963-bfae-c399000a1079";"Md5";"a15235fcec1c9b65d736661d4bec0d38,1873a2ce2df273d409c47094bc269285,112b4a6d8c205c1287c66ad0009c3226,35fbc4c04c31c1a40e666be6529c6321,6c5e50ef2069896f408cdaaddd307893,4b42a7a6327827a8dbdecf367832c0cd,ff795e4f387c3e22291083b7d6b92ffb"
"b28cc2ee-d4a2-4fe4-9acb-a7a61cad20c6";"Md5";"33b3842172f21ba22982bfb6bffbda27,e626956c883c7ff3aeb0414570135a58,9e0af1fe4d6dd2ca4721810ed1c930d6,da8437200af5f3f790e301b9958993d2,4cee9945f9a3e8f2433f5aa8c58671fb,1762105b28eb90d19e9ab3acde16ead6,356bda2bf0f6899a2c08b2da3ec69f13"
"ebdde780-e142-44e7-a998-504c516f4695";"Md5";"a860d74c13d125d7c6253a4dc3b47ddf"
"e0e93453-1007-4799-ad02-9b461b7e0398";"Md5";"f53fa44c7b591a2be105344790543369"
"3e0bf6dc-791b-4170-8c40-427e7299d93d";"Md5";"697f698b59f32f66cd8166e43a5c49c7"
"1c6e1d3b-f825-4065-9e0c-83386883e40f";"Md5";"4cc3ddd5ae268d9a154a426af2c23ef9,2e7d824a49d731da9fc96262a29c85ce,3fda3d414c31ad73efd8ccceeaa3bdc2,560069dc51d3cc7f9cf1f4e940f93cae,8de7dcade65a1f51605a076c1d2b3456,4e92f1c677e08fd09b57032c5b47ca46,288471f132c7249f598032d03575f083,f5e6ef0dcbb3d4a608e9e0bba4d80d0a,36527fdb70ed6f74b70a98129f82ad62,935a7df222f19ac532e831e6bf9e8e45,2229d5a9a92b62df4df9cf51f48436f7,1c9d2a993e99054050b596d88b307d95,b4598c05d5440250633e25933fff42b0,0d8daf471d871deb90225d2953c0eb95,3c1f92a1386fa6cf1ba51bae5e9a98dd,2e7d824a49d731da9fc96262a29c85ce,f8a13d4413a93dd005fad116cbd6b6f7,d4a299c595d35264b5cfd12490a138dc,f758e7d53184faab5bc51f751937fa36,05a6f843c43d75fbce8e885bb8656aa4,fef60a37301e1f5a3020fa3487fb2cd7,6846c2035b4c56b488d2ce2c69a57261"
"51c342f3-0b91-4674-8f81-bc016855f30f";"Md5";"1a234f4643f5658bab07bfa611282267"
"7a0842ca-1a64-4ad1-9d66-25eb983d1742";"Md5";"2da707d2fa073d60c4b069ce76a789ef"
"0f8e317e-ad2b-4b02-9f96-603bb8d28604";"Md5";"c0e2a64ba0d23ab95258372457060143"
"58509acb-50b4-41a0-9de3-76c571a459e3";"Md5";"9c00a44418a8e719c0034f0d55802693"
"f93e88c2-d0e8-4347-869f-efa568955e9d";"Sha256";"fafa1bb36f0ac34b762a10e9f327dcab2152a6d0b16a19697362d49a31e7f566,de6bf572d39e2611773e7a01f0388f84fb25da6cba2f1f8b9b36ffba467de6fa"
"65660363-0080-4432-abd9-64368dac0283";"Sha256";"146d77e80ca70ea5cb17bfc9a5cea92334f809cbdc87a51c2d10b8579a4b9c88"
"3f39af20-802a-4909-a5de-7f6fe7aab350";"Md5";"4f27c09cc8680e06b04d6a9c34ca1e08"
"73290fcb-a0d7-481e-81a5-65a9859b50f5";"Md5";"366bd312aad96a7eb4912688b9e8d268"
"9889da50-3908-4499-a729-187295a60a0e";"Sha1";"6c1bb3a72ebfb5359b9e22ca44d0a1ff825a68f2,e039c9dd21494dbd073b4823fc3a17fbb951ec6c,7eec3a1edf3b021883a4b5da450db63f7c0afeeb,e5021a98e55d514e2376aa573d143631e5ee1c13,729a8675665c61824f22f06c7b954be4d14b52c4,2b4d0dead4c1a7cc95543748b3565cfa802e5256,4a7d66874a0472a47087fabaa033a85d47413379"
"855ade1f-8a9e-4c9d-ab8e-d7e409609852";"Md5";"ae5eb2759305402821aeddc52ba9a6d6,702d5606cf2199e0edea6f0e0d27cd10,945ef111161bae49075107e5bc11a23f,24fe18891c173a7c76426d08d2b0630e,aaa8999a169e39fb8b48ae49cd6ac30a,d21fba3d09e5b060bd08796916166218,b5326548762bfaae7a42d5b0898dfeac,e9ccb6bac8715918a2ac35d8f0b4e1e6,28cb0b64134ad62c2acf77db8501a619,f141db170bb4c6e088f30ddc58404ad3,0634299fc837b47b531e4762d946b2ae,178cc9403816c082d22a1d47fa1f9c85,05b4463677e2566414ad53434ad9e7e5,15814b675e9d08953f2c64e4e5ccb4f4,94c80490b02cc655d2d80597c3aef08f,238769fd8379ec476c1114bd2bd28ca6,ea2ff60fcce3b9ffe0bd77658b88512d,e4788e5b3e5f0a0bbb318a9c426c2812,4f5ca81806098204c4dea0927a8fec66,5c5e3c7ca39d9472099ea81c329b7d75,7db75077d53a63531ef2742d98ca6acc,520c18f50d3cb2ce162767c4c1998b86,084a13f18856d610d44d3109a9d2acde,37c3a9fef349d13685ec9c2acaaeafce,239224202ccdea1f09813a70be8413ee,384370c812acb7181f972d57dc77c324,c9c7113f5e15f70fcc576e835c859d56,389823db299b350f2ee830d47376eeac,07fc1e043654fdde56da98d93523635c,d1f9ffe5569642c8f8c10ed7ee5d9391,3836e2db9034543f63943cdbb52a691a,978cd6d9666627842340ef774fd9e2ac"
"aaa92ef1-5728-4e15-9fca-b054b02f0fb0";"Md5";"fd7de498a72b2daf89f321d23948c3c4"
"61514cbd-6f34-4a3e-a022-9ecbccc16feb";"Md5";"62f02339fe267dc7438f603bfb5431a1,a0074303fe697a36d9397c0122e04973,7461f0f9b931044a9d5f1d44eb4e8e09,5e35c049bc8076406910da36edf9212d,ee59b64ae296a87bf7a6aee38ad09617,7962d91b1f53ce55c7338788bd4eb378"
"0baa833c-e4e1-449e-86ee-cafeb11f5fd5";"Md5";"d04f5388e962cd21462bcc54180e84e0,ff7cc8b6553ab57c53d5bc8afcf50f67"
"5901421f-7929-487d-87bd-632f29290352";"Md5";"4353b713487a2945b823423bbbf709bd"
"c3cca618-5a7f-4a51-8785-cb328fbfb0df";"Md5";"43830326cd5fae66f5508e27cbec39a0"
"670dc258-78b5-4552-a16b-b41917c86f8d";"Md5";"1f950cfd5ed8dd9de3de004f5416fe20"
"9543c507-9b10-4de8-89b9-42a4f24c99ec";"Md5";"c552dae8eaadd708a38704e8d62cf64d,ecccbf1e7c727f923c9d709707800e6c,cafbf85b902f189ba35f3d7823aad195,9fdcd543574a712a80d62da8bfd8331c,05369fa594a033e48b7921018b3263fb"
"2cc3dd4f-8a1e-4f1f-9871-0a14815949b4";"Sha1";"bc2f3850c7b858340d7ed27b90e63b036881fd6c"
"47fe1aaf-02cd-4a41-8bf5-0047015a2a6e";"Md5";"2c54859a67306e20bfdc8887b537de72"
"35a9afeb-18f1-4c02-a3aa-830e300138ae";"Md5";"a5ce055e8970dc56498e3525d61e4982"
"cce291c8-4534-4362-af45-5f45cd32bd92";"Md5";"02198692732722681f246c1b33f7a9d9"
"933f5671-e995-4976-8392-52d34dcd4e05";"Md5";"7314c2bc19c6608d511ef36e17a12c98,251e1ce4e8e9b9418830ed3dc8edd5e3,dc9be271f403e2278071d6ece408ff28,67b5b8607234bf63ce1e6a52b4a05f87,278761b706276f9b49e1e2fd21b9cb07,2a8662e91a51d8e04a94fa580c7d3828,d6c2e061b21c32c585aca5f38335c21c,9bcb97a1697a70f59405786759af63b8,555446a3ca8d9237403471d4744e39f4,c6b5a3ae07b165a6e5fff7e31ff91016,2b653950483196f0d175ba6bc35f1125,d7cf689e6c63d37bc071499f687300dd,fdf975524d4cdb4f127d79aac571ae9e,0a4e6bd5cc2e9172e461408be47c3149,fcc5de75c1837b631ed77ea4638704b9,97580157f65612f765f39af594b86697,4124de3cb72f5dfd7288389862b03f2a"
"16d8962b-cf96-432f-8a43-d41f06828f56";"Md5";"a89ca92145fc330adced0dd005421183,26ce59f9fc8639fd7fed53ce3b785015,75dbd5db9892d7451d0429bec1aabe1a,fe820a5f99b092c3660762c6fc6c64e0,262969a3fab32b9e17e63e2d17a57744,17719a7f571d4cd08223f0b30f71b8b8,21be10f66bb65c1d406407faa0b9ba95,4885e1bf1971c8fa9e7686fd5199f500,ab4ee84e09b09012ac86d3a875af9d43,743c403d20a89db5ed84c874768b7119,e0bfbdf3793ea2742c03f5a82cb305a5,22ca5fe8fb0e5e22e6fb0848108c03f4,3ab94fba7196e84a97e83b15f7bcb270,e323413de3caec7f7730b43c551f26a0,c9c25778efe890baa4087e32937016a0,2f8653034a35526df88ea0c62b035a42,e747f164fc89566f934f9ec5627cd8c3,c08063f052308b6f5882482615387f30,549e5148be5e7be17f9d416d8a0e333e,d0c2caa17c7b6d2200e1b5aa9d07135e,f310b453ac562f2c53d30aa6e35506bb,aa69b4255e786d968adbd75ba5cf3e93,3411fdf098aa20193eee5ffa36ba43b2,f60a9b88c6ff07d4990d8653d0025683,c046ca4da48db1524ddf3a49a8d02b65,0283b43c6bc965175a1c92b255d39556,4a85754636c694572ca9f440d254f5ce,8741e6df191c805028b92cec44b1ba88,bf581e9eb91bace0b02a2c5a54bf1419,94ccef76fda12ab0b8270f9b2980552b,9b157f1261a8a42e4ef5ec23dd4cda9e,5212e0957468d3f94d90fa7a0f06b58f,56b54823a79a53747cbe11f8c4db7b1e,29872c7376c42e2a64fa838dad98aa11,557fd33ee99db6fe263cfcb82b7866b3,c516acb873c7f8c24a0431df8287756e,641243746597fbd650e5000d95811ea3,a453083b8f4ca7cb60cac327e97edbe2,07493c774aa406478005e8fe52c788b2,e425c66663c96d5a9f030b0ad4d219a8,ccb09eb78e047c931708149992c2e435,43bfc857406191963f4f3d9f1b76a7bf,8f5b84350bfc4fe3a65d921b4bd0e737,ce57844fb185d0cdd9d3ce9e5b6a891d,8ad9dfc971df71cd43788ade6acf8e7d"
"f4990bdd-8821-4a3c-a11a-4651e645810c";"Md5";"a01c412699b6f21645b2885c2bae4454"
"23f11e19-0776-4dd4-9c9c-7f6b60f8553f";"Md5";"b12d1630fd50b2a21fd91e45d522ba3a"
"eb07ef7e-0402-48eb-8e06-8fb76eda5b84";"Md5";"1d768959aaa194d60e4524ce47708377"
"13b2424a-d337-4bc7-ad1d-2049c79906b4";"Sha256";"36875562e747136313ec5db58174e5fab870997a054ca8d3987d181599c7db6a"
"7f9842a0-8118-462e-8860-227265ff4379";"Md5";"4d99d02f49e027332a0a9c31c674e13b,2e5f016ff9378be41fe98fa62f99b12d,6d97ee5b3300d0f7fa359f2712834c40,2f1ebc14bd8a29b89896737ca4076002,1c4acf27317a2b5eaedff3ce6094794d"
"3bec7340-bd8b-43ae-8569-d81a66f01dda";"Md5";"fd80c3d38669b302de4b4b736941c0d1,7e6e2ed880c7ab115fca68136051f9ce,8942e9fa2459b1e179a6535ca16a2fb4,1f3522c5db7b9dcdd7729148f105018e"
"8ff4ab50-05b7-4bfa-b994-1920c4ed4978";"Md5";"a26e600652c33dd054731b4693bf5b01"
"2b918b1a-badb-4a85-9214-961607b21219";"Md5";"affe4764d880e78b2afb2643b15b8d41,a664904f69756834049e9e272abb6fea,a125390293d50091b643cfa096c2148c,0c55128c301921ce71991a6d546756ad"
"457f8b21-202a-4a3d-a18d-b4aaded9ef02";"Sha1";"f18e669127c041431cde8f2d03b15cfc20696056"
"e71f0866-e317-44d4-a456-d6f0c555aa73";"Sha256";"15c53eb3a0ea44bbd2901a45a6ebeae29bb123f9c1115c38dfb2cdbec0642229"
"6fc3034f-8b40-44ef-807a-f61d3ea2dece";"Md5";"f2f728d2f69765f5dfda913d407783d2"
"04d377f9-36e0-42a4-8d47-62232163dc68";"Md5";"0898af0888d8f7a9544ef56e5e16354e,f1e054333cc40f79cfa78e5fbf3b54c2"
"1d2cdef1-de44-4849-80e5-e2fa288df681";"Md5";"1898ceda3247213c084f43637ef163b3"
"ca768fc5-9b5c-4ced-90ab-fd6be9a70199";"Md5";"c533d6d64b474ffc3169a0e0fc0a701a"
"d4664202-d1b9-44d4-97cc-fee2150082db";"Md5";"d3e40644a91327da2b1a7241606fe559,7644bed8b74dc294ac77bf406df8ad77,01f092be2a36a5574005e25368426ad2,0e51d96a3b878b396708535f49a6d7cb,be54aabf09c3fa4671b6efacafa389e3,2e48c3b8042fdcef0ed435562407bd21,7bdf418a65ec33ec8ff47e7de705a4e1,697bbd86ee1d386ae1e99759b1e38919,c60a4bc4fec820d88113afb1da6e4db3,db2fc89098ac722dabe3c37ed23de340,9ade14e58996a6abbfe2409d6cddba6a,05bf59560656c8a9a3191812b0e1235b,02fc655279b8ea3ef37237c488b675cc,547971da89a47b6ad6459cd7d7854e12,87982977500b93330df08bf372435641"
"9e87b6b0-00ed-4259-bcd7-05e2c924d58c";"Md5";"49fe3d1f3d5c2e50a0df0f6e8436d778"
"e5f12b82-8d07-474e-9587-8c7b3714d60c";"Md5";"2a3ce41bb2a7894d939fbd1b20dae5a0,db46c56849bbce9a55a03283efc8c280,99c131567c10c25589e741e69a8f8aa3,e5f8fcdfb52155ed4dffd8a205b3d091,707ab1170389eba44ffd4cfad01b5969,9e0659d443a2b9d1afc75a160f500605,51e7b58f6e9b776568ffbd4dd9972a60,06897b431c07886454e0681723dd53e6,d4a10447fdaff7a001715191c1f914b6,75e50ae2e0f783e0caf912f45e15248a,5054083cf29649a76c94658ba7ff5bce,21e13f2cb269defeae5e1d09887d47bb"
"7cee2ce8-7881-4a9a-bb18-61587c95f4a2";"Md5";"563b33cfc3c815feff659caaa94edc33,53f103e490bc11624ef6a51a6d3bdc05,d90cdd8f2826e5ea3faf8e258f20dc40,c28b4a60ebd4b8c12861829cc13aa6ff,c52dce2bee8ec88748411e470ff531f6,3e9ee8418f22a8ae0e2bf6ff293988fa,2ab9f5a66d75adb01171bb04ab4380f2,2c957aa79231fad8e221e035db6d0d81"
"51808fa6-89a4-4f4d-aabc-0a7b0e99e34d";"Md5";"70053ab9df31eb2dcd6f5b001386a8d2"
"d64167b6-f281-41d8-9535-6cb925e77aec";"Md5";"d6e9f6c67d9b3d790d592557a7d57c3c"
"ddbd60c3-0611-4a59-894d-aec84203906f";"Sha1";"4b8c0445075f09aeef542ab1c86e5de6b06e91a3"
"fa612342-5ae0-4e69-ad9c-14d574d9fb1e";"Md5";"fe937e1ed4c8f1d4eac12b065093ae63,0215d0681979987fe908fb19dab83399,16a8e8437b94d6207af2f25fd4801b6d,c04a5cdcb446dc708d9302be4e91e46d,2d64d681d79e0d26650928259530c075,8a70921638ff82bb924456deadcd20e6,c37b575c3a96b9788c26cefcf43f3542,f4a31e08f89e5f002ef3cf7b1224af5f,51c233297c3aa16c4222e35ded1139b6,1a5a95d6bedbe29e5acf5eb6a727c634,637cf50b06bc53deae846b252d56bbdc"
"3ac0eda2-a844-4a9d-9cfa-c25a9e05d678";"Md5";"a9f220b1507a3c9a327a99995ff99c82"
"cf805b21-4611-4983-a8b6-271373a45057";"Md5";"942c6a8332d5dd06d8f4b2a9cb386ff4,d98d2f80b94f70780b46d1f079a38d93,b7946feaeae34d51f045c4f986fa62ce,3c9c537167923723429c86ab38743e7d"
"2a7a59c1-35b8-42b6-a560-2fbf4247a584";"Md5";"bdd8dc8880dfbc19d729ca51071de288"
"0e3b0052-18c7-4c8b-a064-a1332df07af2";"Md5";"54313eadbe10511393d42b902436a30d,b224ef59e8f31d8f397000fe6548b0c7"
"579a0516-1177-45ce-ad9e-45f53b28dcdc";"Sha256";"84df20b1d9d87e305c92e5ffae21b10b325609d59d835a954dbd8750ef5dabf4"
"bf01915d-045f-442c-a74e-25c56182123f";"Md5";"fac8eb49e2fd541b81fcbdeb98a199cb"
"babe348d-f160-41ec-9db9-2413b989c1f0";"Md5";"0f651c53a63cef2d96be95c1638fa5bc,7ed45f56d809eed09a805402a7b92a49"
"d1624a73-55e0-43f6-8d2d-f4f791ef1bff";"Md5";"4b817d0e7714b9d43db43ae4a22a161e,6b2df08bacf640cc2ac6f20c76af07ee,d717f8de642b65f029829c34fbd13a45,a2c5f994e9b4a74b2f5b51c7a44c4401,9c8fffef24fc480917236f9a20b80a47"
"351ff5ca-f07b-4eb6-9300-d5d31514defb";"Md5";"4a23e0f2c6f926a41b28d574cbc6ac30,ba2c0fa201c74621cddd8638497b3c70,4c76554d9a72653c6156ca0024d21a8e,5f4a232d92480a1bebbe025ef64dc760,f56f30ac68c35dd4680054cdfd8f3f00,a1547e8b2ca0516d0d9191a55b8536c0,bd5d4d07ae09e9f418d6b4ac6d9f2ed5,4a23e0f2c6f926a41b28d574cbc6ac30,ba2c0fa201c74621cddd8638497b3c70,4c76554d9a72653c6156ca0024d21a8e,5f4a232d92480a1bebbe025ef64dc760,f56f30ac68c35dd4680054cdfd8f3f00,a1547e8b2ca0516d0d9191a55b8536c0,bd5d4d07ae09e9f418d6b4ac6d9f2ed5,1cb26adeca26aefb5a61065e990402da,750d1f07ea9d10b38a33636036c30cca,270052c61f4de95ebfbf3a49fb39235f,ce65b7adcf954eb36df62ea3d4a628c7,8291dcbcbccc2ce28195d04ac616a1b5,c8f88ca47b393da6acf87fa190e81333,ba21bfa3d05661ba216873a9ef66a6e2,936729b8dc2282037bc1504c2680e3ad,dd38cc344d2a0da1c03e92eb4b89a193,5c4df33951d20253a98aa7b5e78e571a,2348508499406dec3b508f349949cb51,353e5d424668d785f13c904fde3bac84,81df475ab8d37343f0ad2a55b1397a8f,eb61616a7bc58e3f5b8cf855d04808c3,5bb840db439eb281927588dbce5f5418,ddf2655068467d981242ea96e3b88614,d1440503d1528c55fdc569678a663667,71858fa117e6f3309606d5cdb57e6e09,71fffc05cff351a6f26f78441cfebe26"
"fb783760-cb3f-4cf4-b4ac-8edb756b9821";"Md5";"08001b0cdb0946433366032827d7a187"
"1ed9d02f-17cf-43dd-9645-a54452468a5e";"Sha1";"b242b0332b9c9e8e17ec27ef10d75503d20d97b6,a65fabaf64aa1934314aae23f25cdf215cbaa4b6"
"f654ad84-c61d-477c-a0b2-d153b927dfcc";"Md5";"be9eeea2a8cac5f6cd92c97f234e2fe1,343ada10d948db29251f2d9c809af204,00143c457c8885fd935fc5d5a6ba07a4,6dd82d91f981893be57ff90101a7f7f1"
"5c45ae9e-cb6f-4eab-a070-b0187202e080";"Md5";"32365e3e64d28cc94756ac9a09b67f06"
"76b5dfae-b384-45ce-8646-b2eec6b76a1e";"Md5";"c901887f28bbb55a10eb934755b47227"
"4f0a65a7-9a01-40cb-8d95-0844515103e6";"Md5";"1da1cfe6aa15325c9ecf8f8c9b2cd12d,09b3d078ffa3b4ed0ad2e477a2ee341f"
"b72f7335-6f27-42c5-85f5-ed7eb9016eac";"Md5";"75d6c3469347de1cdfa3b1b9f1544208"
"86cff0de-2536-4b8d-a846-a7312c569597";"Md5";"f0470f82ba58bc4309f83a0f2aefa4d5,afae2a21e36158f5cf4f76f896649c75,f0fdfdf3303e2f7c141aa3a24d523af1,18b4bbeae6b07d2e21729b8698bbd25a,d43dcba796b40234267ad2862fa52600,c9390a8f3ca511c1306a039ca5d80997,f44f6ec546850ceb796a2cb528928a91,91755cc5c3ccf97313dc2bece813b4d9,a87689b1067edacc48fddf90020dee23,f30db62d02a69c36ccb01ac9d41dc085,0cd0fe9d16b62415b116686a2f414f8c,f544f9925cab71786e57241c10e08633,e4ff4edce076f21f5f8d082a62c9db8b,a926b64be7c27ccb96e687a3924de298,0eb3dfeffb49d32310d96f3aa3e8ca61,79bfbeb4e8cfdd0cb1d73612360bd811,6a1ff4806c1a6e897208f48a1f5b062f,fadf9c1365981066c39489397840f848"
"ad21819d-3080-4fe2-89b1-74385031fb4d";"Md5";"b12d1630fd50b2a21fd91e45d522ba3a"
"d9e00cc7-a8f4-4390-a6dc-0f5423e97da4";"Md5";"507a649eb585d8d0447eab0532ef0c73"
"d55a5955-6220-4f38-ba7d-91339330fe98";"Md5";"84fb76ee319073e77fb364bbbbff5461,7951fa3096c99295d681acb0742506bf,5c5f1c2dc6c2479bafec7c010c41c6ec,cf1113723e3c1c71af80d228f040c198,3482acba11c71e45026747dbe366a7d9,1e1a3d43bd598b231207ff3e70f78454,6f7125540e5e90957ba5f8d755a8d570,a5ff71e189b462d2b1f0e9e8c4668d79"
"0a2f2700-97b5-42b6-b121-38e5f03e9957";"Md5";"ab53d07f18a9697139ddc825b466f696"
"62e2a967-1f03-4225-a325-122b109208f3";"Md5";"d77fb9fb256b0c2ec0258c39b80dc513,590875a0b2eeb171403fc7d0f5110cb2,392d7180653b0ca77a78bdf15953d865,e3fda6120dfa016a76d975fdab7954f6,a17c403c4b74d4fa920c3887066daeb2,7056549baa6da18910151b08121e2c94"
"d158321b-4d56-49c5-9a18-bcff9f4a2ebe";"Md5";"338a98e1c27bc76f09331fcd7ae413a5"
"705facba-b595-41dd-86a6-93aefe6a6234";"Md5";"79e368a81e3a7ae8a5d2db97dd5138e2"
"a005e057-c84f-47cd-9b4b-5b1e51a06ab4";"Md5";"2fed983ec44d1e7cffb0d516407746f2"
"adfb015a-f453-4b9e-a247-50f146209eb0";"Sha256";"708016fbe22c813a251098f8f992b177b476bd1bbc48c2ed4a122ff74910a965"
"97fa88f6-3819-4d56-a82c-52a492a9e2b5";"Md5";"f08ebaf4493e99f4f095a4f7696287d4,892ba05649cfdc690bb66325c85d9c5c,381144bb812e0244ea8923814fda2949,d045c3499d42c257be2163b3f1f785fa,b2aba4fa678c272ece36f928e5b81dd9"
"8c2fa9d1-b2b1-4ba1-bad9-60c44c2c20eb";"Sha256";"258359a7fa3d975620c9810dab3a6493972876a024135feaf3ac8482179b2e79"
"a3c52cbe-90ca-432c-9520-761b60e7d9cb";"Md5";"2faa725dd9bb22b2100e3010f8a72182,03c9d5f24fd65ad57de2d8a2c7960a70,43ed1d08c19626688db34f63e55114fb,1a6e12c2d11e208bdf72a8962120fae7,21ca6a013a75fcf6f930d4b08803973a,f160ecce1500a5a5877c123584e86b17,b934322c68c30dceca96c0274a51f7b0,fe3fb6719e86481a3514ab9e00a55bcf,0ad87bba19f0b71ccb2d32239abd49ec,5bd30b502168013c9ea03a5c2f1c9776,c5b8e612360277ac70aa328432a99fd6,cd1c8a66e885b7a8b464094395566a46,5f44a01ccc530b34051b9d0ccb5bb842"
"e368efc7-cf69-47ae-8204-f69dac000b22";"Md5";"05ad4a6ef441e94acb1a1a9a11a26f3a,a7c2bc345d60cddf2cf4f5dd416a127b,2491a4ddb3f7a6688669831969b47669,724a9e06f0a846f2556f2e3edd251cc4,67f6d2a931f194396bda9b05690008d2,b2ada4eb20649839a54db078fa6bb1bd,2f6cf948117cbd383315ebf070d27aa4,e6ed15980616aa706bf85e6f256d2ebe,9c14315e086882e89a01c9700c4b5530,ad6ec006e29343c466f73bf47fe0caf3,2391fb461b061d0e5fccb050d4af7941,f58e9309d8251a3010ee022aa5a6e377,3a3d54e49cae4b51f5231d3ae6724fcd,57fdf2cc39a2865dd67dcf762d2c0b7f,98eaed36ba245047410a19c191cd1a69,3a41edc1dda049a1b8aa411f728831e0,848690ca707b4850c967e3217f285fcc,a8dd685a6afb748c9f487a139c9c367b,501945a3f0055033edc64be09717eef2,5cc5fc8ce149dca1d05fb47c0aec9497,3b967b644881ccb5a95f06e903d8b218,d7b749051da5fb4604f4141f19c47660"
"080a834f-3e19-4cae-b940-a4ecf901db28";"Md5";"31e8d7b070dcc6cd92cec9d6d2254afe"
"d2806397-9ceb-47c8-b5f3-3aabec182ff5";"Md5";"d9ce18960c23f38706ae9c6584d9ac90,6e2178dc5f9e37e6b4b6cbdaef1b12b1"
"a4795ab6-d908-44cf-9ebf-a47db367d385";"Md5";"7be3a7a743f2013c3e90355219626c2c"
"e769d1f6-8a38-426f-b5e7-447241204ee1";"Md5";"4514a0e8bcab7de4cff55999cdf00cd1,1793e1d4247b29313325d1462dec81e2,62f8d7f884366df6100c7e892e3d70bf,328a2cb2da464b0c2beb898ff9ae9f3a"
"39742f99-2180-46d7-8538-56667c935cc3";"Md5";"e79c91c27df3eaf82fb7bd1280172517,ab7b28b532beba6a6c0217bc406b80ee"
"a9d9cbb7-b5f6-4e74-97a5-29993263280e";"Md5";"b34361d151c793415ef92ee5d368c053,3b9698a9ee85f0b4edf150deef790ccd,30efb7d485fc9c28fe82a97deac29626,f042e8318cf20957c2339d96690c3186"
"8ecc8439-0554-40d0-9130-c02941deadbe";"Md5";"41ce6b172542a9a227e34a45881e1d2a,782f165b1d2db23f78e82fee0127cc14,4ca0dba9e224473d664c25e411f5a3bd,49832b4f726cdff825257bee33ad8451,ab81264493c218a0e875a0d50104ac9f,bc71da7c055e3172226090ba5d8e2248,843e39865b29bb3df825bd273f195a98,3c9f9c1b802f66cf03cbe82dec2bd454"
"4e5064b4-48d3-418c-a7a8-f0dc7ac0a176";"Md5";"d9e7e5bcc5b01915dbcef7762a7fc329"
"500e07cb-77c6-4e83-ae3f-73f70f1c10b5";"Md5";"59a48daa7dbdcb13bd0a11c71e1ad2f7"
"bd7e78db-6fd0-4694-ac38-dbf5480b60b9";"Md5";"1dc94a6a82697c62a04e461d7a94d0b0,798de15f187c1f013095bbbeb6fb6197,1392b92179b07b672720763d9b1028a5,fef9dd9ea587f8886ade43c1befbdafe,517d484bdbad4637188ec7a908335b86,b2e4e588ce7b993cc31c18a0721d904d,9d8cb58b9a9e177ddd599791a58a654d,663f2fb92608073824ee3106886120f3,a82c01606dc27d05d9d3bfb6bb807e32,94cdf2cf363be5a8749670bea4db65cd,272446de15c63095940a3dad0b426f21"
"613b8509-18c0-4720-b489-736776b6713e";"Md5";"b0954711c133d284a171dd560c8f492a,043d5a1fc66662a3f91b8a9c027f9be9,3c55092900343d3d28564e2d34e7be2c,7907e14f9bcf3a4689c9a74a1a873cb6,a72e10ecea2fdeb8b9d4f45d0294086b,31f34de4374a6ed0e70a022a0efa2570,4e093256b034925ecd6b29473ff16858,1549e6cbce408acaddeb4d24796f2eaf,c832a4313ff082258240b61b88efa025,d556cb79967e92b5cc69686d16c1d846"
"cacc48e6-6ed8-431c-abee-88ee6c2dc3c1";"Sha256";"cb9890d4e303a4c03095d7bc176c42dee1b47d8aa58e2f442ec1514c8f9e3cec"
"75a66604-f024-4f11-8ba7-fdd64a0df3bf";"Md5";"64ae0358860e2a5b658383f7e651038e"
"7a722cd5-69ec-4680-9f20-9387f249a891";"Md5";"702d5606cf2199e0edea6f0e0d27cd10,945ef111161bae49075107e5bc11a23f,24fe18891c173a7c76426d08d2b0630e,aaa8999a169e39fb8b48ae49cd6ac30a,d21fba3d09e5b060bd08796916166218,b5326548762bfaae7a42d5b0898dfeac,e9ccb6bac8715918a2ac35d8f0b4e1e6,28cb0b64134ad62c2acf77db8501a619,f141db170bb4c6e088f30ddc58404ad3,0634299fc837b47b531e4762d946b2ae"
"6a7d882b-3d9d-4334-be5f-2e29c6bf9ff8";"Sha256";"72b99147839bcfb062d29014ec09fe20a8f261748b5925b00171ef3cb849a4c1,97030f3c81906334429afebbf365a89b66804ed890cd74038815ca18823d626c,0b8887921e4a22e24fd058ba5ac40061b4bb569ac7207b9548168af9d6995e7c"
"7bb5ff05-25f8-410d-ae99-c8e8f082d24f";"Md5";"828bb9cb1dd449cd65a29b18ec46055f,12cecc3c14160f32b21279c1a36b8338,27bcbeec8a466178a6057b64bef66512,0c0195c48b6b8582fa6f6373032118da"
"29cb263b-b0b0-40d5-a97d-5ddf4ba79c1e";"Md5";"312e31851e0fc2072dbf9a128557d6ef"
"79542852-3a0c-43bc-bfa3-3eeb0e1d7fd2";"Md5";"b1b8e6b85dd03c7f1290b1a071fc79c1,02a1d77ef13bd41cad04abcce896d0b9,962a33a191dbe56915fd196e3a868cf0,3e87e3346441539d3a90278a120766df,e3bdb307b32b13b8f7e621e8d5cc8cd3,443689645455987cb347154b391f734d,6beb1d8146f5a4aaa2f7b8c0c9bced30"
"7196366e-04f0-4aaf-9184-ed0a0d21a75f";"Sha256";"be03e9541f56ac6ed1e81407dcd7cc85c0ffc538c3c2c2c8a9c747edbcf13100"
"7c83cb1a-a5ab-4ea0-aa69-0e9a1d09a82f";"Md5";"8b287636041792f640f92e77e560725e"
"6a50e368-1120-434b-9232-1a0702c80437";"Md5";"12908c285b9d68ee1f39186110df0f1e"
"7a7630d6-d007-4d84-a17d-81236d9693e1";"Md5";"a60c9173563b940203cf4ad38ccf2082"
"f3215c19-8053-458c-81a5-90a74c5d2e6d";"Md5";"e076dadf37dd43a6b36aeed957abee9e,aa1ed3917928f04d97d8a217fe9b5cb1,dd39a86852b498b891672ffbcd071c03,708ac9f7b12b6ca4553fd8d0c7299296,7a16fca3d56c6038c692ec75b2bfee15,5970e8de1b337ca665114511b9d10806,2509a71a02296aa65a3428ddfac22180,296bde4d0ed32c6069eb90c502187d0d,d1bac75205c389d6d5d6418f0457c29b,b2a9ac0600b12ec9819e049d7a6a0b75,79f7e6f98a5d3ab6601622be4471027f,2d465b4487dc81effaa84f122b71c24f,4d17b32be70ef39eae5d5edeb5e89877,c1d3a6bb423739a5e781f7eee04c9cfd,054299e09cea38df2b84e6b29348b418,0ba6afe0ea182236f98365bd977adfdf"
"fdf4f85b-47f4-4c98-a0d5-a6583463f565";"Md5";"d5db81974ffda566fa821400419f59be"
"90afa27c-0f67-46a6-b4a9-809f55157c71";"Md5";"ba2c0fa201c74621cddd8638497b3c70,4c76554d9a72653c6156ca0024d21a8e,5f4a232d92480a1bebbe025ef64dc760,f56f30ac68c35dd4680054cdfd8f3f00,a1547e8b2ca0516d0d9191a55b8536c0,bd5d4d07ae09e9f418d6b4ac6d9f2ed5"
"7bb4d807-9a66-48ff-9fb7-82780f3b015e";"Md5";"048549f7e9978aff602a24dea98ee48a,30550db8f400b1e11593dffd644abb67,f80ceb0dbb889663f0bee058b109ce0e,d4a9f80ecb448da510e5bf82c4a699ee,f36b8094c2fbf57f99870bfaeeacb25c,2580fb4131353ec417b0df59811f705c"
"f4c22f4d-eff8-40c5-8b31-146abe5f17b7";"Sha1";"589a7d4df869395601ba7538a65afae8c4616385,17614fdee3b89272e99758983b99111cbb1b312c"
"70fa8606-c147-4c40-8b7a-980290075327";"Md5";"f142e613d2ebc11c6bec22baf9392337,667843470a9f0e910c65cb41a749d104"
"5969b6dc-b136-480e-a527-3cb2ea2f0da9";"Md5";"3247014ba35d406475311a2eab0c4657,45c2d133d41d2732f3653ed615a745c8,3cf7a55ec897cc938aebb8161cb8e74f,376b1e8957227a3639ec1482900d9b97"
"57fc510a-e649-4599-b83e-8f3605e3d1d9";"Md5";"a179c4093d05a3e1ee73f6ff07f994aa"
"c98af16e-197f-4e66-bf94-14646bde32dd";"Md5";"2b3e0db4f00d4b3d0b4d178234b02e72"
"5938df1d-9513-449f-8252-c442ddca0c2a";"Md5";"65b979bcab915c3922578fe77953d789"
"999a11ae-ec2b-4863-baa4-1384ec2b7339";"Md5";"1898ceda3247213c084f43637ef163b3"
"12ccd18a-11da-495a-b4b4-98a2f2bff180";"Md5";"44c491b809823eba8747e08f3ec68829"
"0567c6c4-282f-406f-9369-7f876b899c25";"Md5";"e6cb1728c50bd020e531d19a14904e1c,fea9319d67177ed6f36438d2bd9392fb,eeb8e039f6d942538eb4b0252117899a,c56a9ed0192c5a2b39691e54f2132a2f,6ff59faea912903af0ba8e80e58612bc,8e78ab9b9709bafb11695a0a6eddeff9,a91a1bc393971a662a3210dac8c17dfd,e4a0bba88605d4c07b58a2cc3fac0fe9,880686bceaf66bfde3c80569eb1ebfa7,ad03f225247b58a57584b40a4d1746d3,90f8c1b76f786814d03ef4c51d4abb6d,f9d04e99e4cab90973226a4555bc6d57,659a59d7e26b7730361244e12201378e,da6f7407c4656a2dbaf16a407aff1a38,6b3abe55c4d39e305a11b4d1091dfaac,cec257dcac9e708cefb17f8984dd0a70,bf74d0706f5ab9c34067192260f4efb0,92927c47d6ff139c9b19674c9d0088f6,2e219df70fccb79351f0452cba86623e,0ef05030abd55ba6b02faa2c0970f67f,b7ca4c32c844df9b61634052ae276387,9beecfb3146f19400880da61476ef940,b79475c4783efdd8122694c6b5669a79,318e309e11199ec69d8928c46a4d901b,c69c292e0b76b25a5fa0e16136770e11,9982da703f13140997e137b1e745a2e3,9b9d367cb53df0a2e0850760c840d016,ad03f225247b58a57584b40a4d1746d3,97e3a44ec4ae58c8cc38eefc613e950e,b79475c4783efdd8122694c6b5669a79,c06dda757b92e79540551efd00b99d4b"
"a4eabc75-edf6-4b74-9a24-6a26187adabf";"Md5";"c996d7971c49252c582171d9380360f2,c996d7971c49252c582171d9380360f2,084bd27e151fef55b5d80025c3114d35"
"d1441172-cc15-4a96-b782-f440bfb681e1";"Sha256";"dec8a933dba04463ed9bb7d53338ff87f2c23cfb79e0e988449fc631252c9dcc"
"be3e49ea-095e-4fdb-9529-f4c2dbb9a9fc";"Md5";"e9e786bdba458b8b4f9e93d034f73d00"
"20076ebf-4427-4056-b035-5238f95debe9";"Md5";"fac8eb49e2fd541b81fcbdeb98a199cb"
"e6338692-90e0-41b1-9481-a47e0df144ad";"Sha1";"08596732304351b311970ff96b21f451f23b1e25,7838fb56fdab816bc1900a4720eea2fc9972ef7a,4789b910023a667bee70ff1f1a8f369cffb10fe8,eeff4ec4ebc12c6acd2c930dc2eaaf877cfec7ec"
"75a933b4-82d8-4eb8-8ed5-a0a2178630a3";"Sha1";"8cc8974a05e81678e3d28acfe434e7804abd019c,282bb241bda5c4c1b8eb9bf56d018896649ca0e1"
"a5eb98bf-2133-46e8-848f-a299ea0ddefa";"Md5";"f41f65189b796534d8ef6bf9caa06853,304f7b25251e688516aa452411c0d439,cb6173824b31a721e5cf332c75bb2473,73fc2954829a49fc8eb178b000d10120,28463a6a70f9a686a45934f6559b9b17,b15a6de1b4a01c73a16f158c2b6b979f,6b53c79248a6699da703c4c3ff9d4a7e,5f463e27d90035be365077d1d1ebb3d7"
"942f58d2-1300-4957-98a0-5f8d601bf55b";"Md5";"29b1ddc69e89b160cc3722e5e0738fd8"
"2651f5c4-d9e1-4b06-92be-e9e7313f87c4";"Md5";"bedc99bbcedaf89e2ee1aa574c5a2fa4,2ca1044a04cb2f0ce5bd0a5832981e04,40f39a98fb513411dacdfc5b2d972206,19f32bf24b725f103f49dc3fa2f4f0bd,bfe96411cf67edb3cee2b9894b910cd5,ea14899d1bfba397bc731770765768d1,09672532194b4bff5e0f7a7d782c7bf2,ba23266992ad964eff6d358d946b76bd,f4e1997192d5a95a38965c9e15c687fc,07efb8259b42975d502a058db8a3fd21,1414629b1ee93d2652ff49b2eb829940,67e03f83c503c3f11843942df32efe5a,85b756463ab0c000f816260d49923cde,598f8fb2317350e5f90b7bd16baf5738,2b4e66fac6503494a2c6f32bb6ab3826,79329e2917623181888605bc5b302711,1ce19950e23c975f677b80ff59d04fae,370a4ca29a7cf1d6bc0744afc12b236c,68726474c69b738eac3a62e06b33addc,d5556c54c474cf0bff25804bfbe788d3"
"5961e133-ccc3-4530-8f4f-5d975c41028d";"Md5";"58e6c458409f748711353beb9acfc8ed,aca70899d834124fa02dc52f098cad05,3f87df040c35ea45dfd4ae371b9641ae"
"a338a9fc-9fe3-400c-9fe4-69bb7892602d";"Md5";"a17c58c0582ee560c72f60764ed63224"
"13637210-2e1c-45a4-9f76-fe38c3c34264";"Md5";"7b9e1e5e8ff4f18f84108bb9f7b5d108"
"4a80da66-f8f1-4af9-ba56-696cfe6c1e10";"Md5";"8abbb12e61045984eda19e2dc77b235e,c9a293762319d73c8ee84bcaaf81b7b3,120b5bbb9d2eb35ff4f62d79507ea63a"
"8d14d798-338f-471e-bacb-6d9371c0f529";"Sha1";"485c0b9710a196c7177b99ee95e5ddb35b26ddd1,50e2bc41f0186fdce970b80e2a2cb296353af586,e3c1dd569aa4758552566b0213ee4d1fe6382c4b,e09b5e80805b8fe853ea27d8773e31bff262e3f7"
"c0645f0f-9b97-4fe9-811e-2e45c250c9ef";"Sha256";"fcdfe570e6dc6e768ef75138033d9961f78045adca53beb6fdb520f6417e0df1"
"902249eb-87cb-4c01-8da7-17675d743cd7";"Md5";"a4fda97f452b8f8705695a729f5969f7"
"3d7da79b-fe34-45cd-a0c9-d4432d40611c";"Md5";"6cc3c3be2de12310a35a6ab2aed141d6,06ffbb2cbf5ac9ef95773b4f5c4c896a,9ce1b0e5cfa8223cec3be1c7616e9f63,d1e57c74bafa56e8e2641290d153f4d2,efb4ed2040b9b3d408aab8dc15df5a06,1033f0849180aac4b101a914bc8c53b4,2e492f14a1087374368562d01cd609aa,0291ced808eafe406d3d9b56d2fc0c26,8c1d181480796d7d3366a9381fd7782d,de331f863627dc489f547725d7292bbd,8cc5a4045a80a822cbc1e9eadff8e533,eda6e97b453388bb51ce84b8a11d9d13,34e55ccceec34a8567c8b95d662ba886,9dd414590e695ea208139c23db8a5aa3,d396332f9d7b71c10b3b83da030690f0,b5192270857c1f17f7290acbaadf097d,e84605c8e290de6b92ce81d2f6a175d2,cceb3a7e3bd0203c807168b393a65a74,241a095631570a9cef4f126c87605c60,61d6b1c71ad94f8485e966bebc36d092,2eec12c17d6b8deeeac485f47131d150,edfa69e9132a56778d6363cd41843893,7f9128654c3def08c28e0e13efff0fee,546db985012d988e4482acfae4a935a8,96c5900331bd17344f338d006888bae5"
"d9f2c3d6-160c-4eb3-8547-894fcf810342";"Md5";"4f191abc652d8f7442ca2636725e1ed6"
"fded7e63-0470-40fe-97ed-aa83fd027bad";"Md5";"057ec65bac5e786affeb97c0a0d1db15,0b0447072ada1636a14087574a512c82,f0db5af13c457a299a64cf524c64b042,19c0c18384d6a6d65462be891692df9c"
"02e4a30f-8aa8-4ff0-8e02-1bff1d0f088f";"Md5";"d9c24542dd04d2562ae9e050061cee1d"
"19003e00-d42d-4cbe-91f3-756451bdd7da";"Sha1";"0b6ec2aedc518849a1c61a70b1f9fb068ede2bc3,461882bd59887617cadc1c7b2b22d0a45458c070,a7948a4e9a3a1a9ed0e4e41350e422464d8313cd,f3cce7e79ab5bd055f311bb3ac44a838779270b6,b33b99ae2653b4e675beb7d9eb2c925a1f105bd4,0ac0c21ca05161eaa6a042f347391a2a2fc78c96"
"96c8fe71-3acc-41bc-9402-ebd69a961d74";"Md5";"4c2a43fb610d0f51a9531ebe8420c20a"
"4137ecf0-05e7-463a-94da-47b7259d4433";"Sha1";"faa870b0cb15c9ac2b9bba5d0470bd501ccd4326,aca8e53483b40a06dfdee81bb364b1622f9156fe,05ac1c64ca16ab0517fe85d4499d08199e63df26"
"afb8bb46-1d13-407d-9866-1daa7c82ca63";"Md5";"187ddca26d119573223cf0a32ba55a61,69fd73a83df164d7fe5d89e006e945dc,410b44dc8ec9e756e2abdbb406aa42ad,1585d3eda733dfe42202bb98f95f7f5d,5fea22f442e7fd34a54008e363446d13"
"2ea12acc-95b6-4f91-afb7-8ded7a2fe9d9";"Md5";"6d67da13cf84f15f6797ed929dd8cf5d,0e625b7a7c3f75524e307b160f8db337"
"3c5c8c6e-b14e-40d5-b231-c0be0f9b3932";"Md5";"1392b92179b07b672720763d9b1028a5"
"0258df5c-c3c1-4ed5-ba8f-846d91526ffe";"Md5";"9b91a44a488e4d539f2e55476b216024"
"4f93e19c-4600-4e2e-943f-a986875fd7d2";"Sha256";"ae79e760c739d6214c1e314728a78a6cb6060cce206fde2440a69735d639a0a2"
"97ed6c7b-be4c-4f60-9157-c788a555ca9f";"Md5";"1f8a9619ab644728ce4cf86f3ad879ea"
"86b520f6-cc90-4488-b343-168cad88010d";"Sha1";"3ae56ab63230d6d9552360845b4a37b5801cc5ea"
"9a4fb66e-9084-4b21-9d76-a7afbe330606";"Md5";"e4266262a77fffdea2584283f6c4f51d"
"974de971-1f78-47b9-8049-6c34f294acd5";"Sha256";"37dde6bd8a7a36111c3ac57e0ac20bbb93ce3374d0852bcacc9a2c8c8c30079e"
"ee2d68aa-1a65-4967-8627-73590b041538";"Md5";"79ab228766c76cfdf42a64722821711e,e913a51f66e380837ffe8da6707d4cc4,8ac6d458abbe4f5280996eb90235377c,592756f68ab8ae590662b0c4212a3bb9,0a653d9d0594b152ca835d0b2593269f,e140cb81bd27434fc4fd9080b7551922,10e681ce84afdd642e59ddfdb28284e9,aa5dd4beca6f67733e04d9d050ecd523"
"268e87ba-ad44-4f3c-986f-26712cac68da";"Md5";"715572dfe6fb10b16f980bfa242f3fa5,e7ab83a655b0cd934a19d94ac81e4eec"
"6d21df78-d718-44df-b722-99eec654f5b2";"Md5";"dc943bf367ae77016ae399df8e71d38a"
"058fb356-e0ff-4f5e-8293-319feb005db2";"Sha1";"0f780b7ada5dd8464d9f2cc537d973f5ac804e9c,ea360a9f23bb7cf67f08b88e6a185a699f0c5410"
"b745b5da-9cd6-4b3a-badf-fbe487497705";"Md5";"a86150f2e29b35369afa2cafd7aa9764,ad22a7b010de6f9c6f39c350a471a440,0761c357aed5f591142edaefdf0c89c8"
"2b949a0d-939f-456a-a34f-4589d7712227";"Md5";"f026460a7a720d0b8394f28a1f9203dc,21e72a43aedefcd70ca8999cc353b51b,1bd38ac06ef8709ad23af666622609c9,55c36d43dd930069148008902f431ea5,6822566b28be75b2a76446a57064369f,46cae59443ae41f4dbb42e050a9b501a,5dd25029499cd5656927e9c559955b07,1c591efa8660d4d36a75db9b82474174,fc6dadb97bd3b7a61d06f20d0d2e1bac,0703c1e07186cb98837a2ae76f50d42e,41339c852c6e8e4c94323f500c87a79c,d48f681f70e19d2fa521df63bc72ab9e,da7e98b23b49b7293ee06713032c74f6,aae268c4b593156bdae25af5a2a4af21,20afd54ca260e2bf6589fac72935fecf,7eeb4c0cb786a409b94066986addf315,fb7637cfe8562095937f4d6cff420784,bafd6bad121e42f940a0b8abc587eadf,c1fce7aac4e9dd7a730997e2979fa1e2"
"1524a54d-520d-4fa4-a7d5-aaaa066fbfc4";"Md5";"1c294146fc77565030603878fd0106f9,3a48f0e4297947663fbb11702aa1d728"
"8d97bb7f-e009-4dc7-ab9d-fde293e679dc";"Md5";"9ba7c30177d2897bb3f7b3dc2f95ae0a,f8dce1eb0f9fcaf07f68fe290aa629e4"
"a02ee964-a21e-4b08-9c98-a730c90bfd53";"Md5";"d4f7c14e92b36c341c41ae93159407dd"
"2cfede23-67f4-4af7-830f-c95ba30a43ae";"Sha1";"0c74d09da7baf7c05360346e4c3512d0cd433d59"
"193df066-c27c-4343-a4eb-ad2ac417a4cc";"Sha256";"fd33fb2735cc5ef466a54807d3436622407287e325276fcd3ed1290c98bd0533"
"a33de377-d2c2-4c71-98ca-cd0be8d284f9";"Md5";"83601bbe5563d92c1fdb4e960d84dc77"
"52ded752-2708-499e-8f37-98e4a9adc23c";"Md5";"dedd07993780d973c22c93e77ab69fa3"
"c7f76931-e24c-4d94-9e1f-5a083da581b4";"Md5";"fd3b7234419fafc9bdd533f48896ed73"
"1068f5cc-65dd-4fd0-b3d8-1d982b37405f";"Sha1";"01779ee53f999464465ed690d823d160f73f10e7"
"e4098d7e-78b3-4da1-96cb-68b27f245e02";"Md5";"bae1f127c4ff21d8fe45e2bbfc59c180"
"b1dd91b1-9ba3-4d68-a2d1-919039e18430";"Md5";"c24800c382b38707e556af957e9e94fd"
"fe2f68e1-e459-4802-9a9a-23bb3c2fd331";"Md5";"3ae11bde32cdbd8637124ada866a5a7e,1c9001dcd34b4db414f0c54242fedf49,23b807c09b9b6ea85ed5c508aab200b7,2c1045bb133b7c9f5115e7f2b20c267a,20125794b807116617d43f02b616e092,81b72492d45982cd7a4a138676329fd6,2a5ccd95292f03f0dd4899d18b55b428"
"137daca4-0d7b-48aa-8574-f7eb6ad02526";"Md5";"5f9785e7535f8f602cb294a54962c9e7"
"1055625b-3480-48b3-9556-8628a745d8f0";"Md5";"8af7fc0eb2e945c1be06238bde456091"
"cf94939a-703f-46a4-917b-d6af7e0685ef";"Md5";"d988f9a62b8a4936a47aa70d6bc52c27"
"de365e80-45cb-48fb-af6e-0a96a5ad7777";"Md5";"3f8cdaf7413000d34d6a1a1d5341a11b"
"d0048840-970f-4ad5-9a07-1d39469d721f";"Md5";"4c016fd76ed5c05e84ca8cab77993961"
"abcd2c10-1078-4cf9-b320-04ca38d22f98";"Md5";"9532893c1d358188d66b0d7b0784bb6b"
"90ecbbf7-b02f-424d-8b7d-56cc9e3b5873";"Md5";"66066d9852bc65988fb4777f0ff3fbb4,86fd54c56dcafe2de918c36f8dfda67e"
"e7c958da-fd5d-40d6-975e-582c6fee7f69";"Md5";"b10b210c5944965d0dc85e70a0b19a42"
"f16f82de-1ad0-47d8-a869-2c10ed25d9f1";"Md5";"eb0a8eeb444033ebf9b4b304f114f2c8,5c55fcfe39336de769bfa258ab4c901d"
"2e4fedb0-30ed-400d-b4e1-b2b2004c1607";"Md5";"ccf523b951afaa0147f22e2a7aae4976,96421b56dbda73e9b965f027a3bda7ba"
"6356d7d9-3b82-4731-9d5f-cc9bc37558fc";"Md5";"665a059e07c388eaf57dc04aec0c8552"
"1c7631f0-f92f-4be5-8ba7-3eefb0601d45";"Md5";"748cf64b95ca83abc35762ad2c25458f"
"a1d35b93-e97f-4ddd-a465-2405e804e754";"Sha256";"dfaefd06b680f9ea837e7815fc1cc7d1f4cc375641ac850667ab20739f46ad22"
"d819bee2-3bff-481f-a301-acc3d1f5fe58";"Md5";"0a6a1c9a7f80a2a5dcced5c4c0473765"
"920e3326-e5dc-446a-9993-6ec05266e0e0";"Sha1";"d569d4bab86e70efbcdfdac9d822139d6f477b7c,80fa962bdfb76dfcb9e5d13efc38bb3d392f2e77,5a7dd0da0aee0bdedc14c1b7831b9ce9178a0346,1acc7a486b52c5ee6619dbdc3b4210b5f48b936f,55ab7e27412eca433d76513edc7e6e03bcdd7eda,1e7c241b9a9ea79061b50fb19b3d141dee175c27"
"19897aed-9be8-4111-a7d8-35618b9d75b3";"Md5";"f406c5536bcf9bacbeb7ce8a3c383bfa"
"a08ee79f-801d-4b98-996f-55f6a72ac5f7";"Md5";"c8d3784a3ab7a04ad34ea0aba32289ca,ad612a7eb913b5f7d25703cd44953c35,2601cf769ad6ffee727997679693f774,de2aac9468158c73880e31509924d7e0,e98f4cc2cbf9ec23fd84da30c0625884"
"3ab0d182-6365-47a7-89f4-34121e889503";"Md5";"37086ae5244442ba552803984a11d6cb"
"8b9d1a29-f5f4-4ce6-8fe2-5709123f7b86";"Md5";"f701ddcc7c51919413ddadd351ad2fef"
"47a351ee-8abe-40d8-bc2b-557390fa0945";"Md5";"b47dee29b5e6e1939567a926c7a3e6a4"
"b9b835bd-b720-424b-9160-2442bc4d6e58";"Md5";"a42d87de65d7136620b63d5c4ee017ea"
"cfd36b2e-cf96-498e-aeb6-ee20e7b33bbb";"Md5";"49938383844ceec33dba794fb751c9a5"
"84ccb68d-ce34-4aa2-98d5-7f473c2e1b07";"Md5";"5228b7a738dc90a06ae4f4a7412cb1e9"
"5f70bde4-9f81-44a8-9d3e-c6c7cf65bfae";"Md5";"9a9dbf5107848c254381be67a4c1b1dd"
"de003542-80e1-4aa0-9b99-ed8647a93a6e";"Md5";"7d46d0ddaf8c7e1776a70c220bf47524"
"40bfb01b-d251-4c2c-952e-052a89a76f5b";"Md5";"0067c788e1cb174f008c325ebde56c22"
"fda3ff67-12dc-488c-a4c2-603f5bf420bd";"Md5";"e3d290406de40c32095bd76dc88179fb"
"b8339454-0e84-4a5b-92d0-6a626ced6677";"Md5";"55cd6b46ac25bbe01245f2270a0d6cb8,c9b046a6961957cc6c93a5192d3e61e3,dff6c75c9754a6be61a47a273364cdf7,9b5533c4af38759d167d5399e83b475f,ef1afb3a5ddad6795721f824690b4a69,0199a59af05d9986842ecbdee3884f0c,b9cf3294c13cdea624ab95ca3e2e483f,ac591a3b4df82a589edbb236263ec70a,8fcf90cb5f9cb7205c075c662720f762,ef18d594c862d6d3704b777fa3445ac2,9988fc825675d4d3e2298537fc78e303,fa0d1fca7c5b44ce3b799389434fcaa5"
"4b047bb8-c605-4664-baed-25bb70e864a1";"Sha256";"d5562fb90b0b3deb633ab335bcbd82ce10953466a428b3f27cb5b226b453eaf3"
"722772ee-a461-48ec-933d-f3df1578963e";"Md5";"f7393fb917aed182e4cbef25ce8af950"
"30d6c39c-1d93-4101-8dd3-322ff0ab7fb3";"Sha256";"f8886a9c759e0426e08d55e410b02c5b05af3c287b15970175e4874316ffaf13,760be95d4c04b10df89a78414facf91c0961020e80561eee6e2cb94b43b76510"
"f92f4c60-b39c-4726-ba74-dcab7f653ae2";"Md5";"2a5fb925125af951bd76c00579d61666,17fe96af33f1fe475957689aeb5f816e,62792c30836ae7861c3ca2409cd35c02"
"5ad8a3b6-6d20-4c95-8fa7-9a507167ba3c";"Md5";"0c1a4b584106cca4edce5d04c89eef67,724c7d404a7c182084c6f6c2d20e9e05,c6dcf97b669be21dffd4e96aecec3066,e9e4b27f98eb15dcfc01837e7816ad67,6088826a0114f777e486ff093a8d4150,c56a3a74019e2304af8c19e8e17dd9d3,e3b79b124fe408b971d18fd3a25b5ba0,e1190b7a0bd3b8cc3a819d471ede264f,3a53fe6598d2b9bc3b81d3dd6bc5d843,837b27efec864ae45d89cfffc1e635f0,5035359be554444dde135903e4a07b28,5c7d08cafbb96b0812a90ce4de52869a,546107a0f37686b2417f1be2e05305f6,dc83a482d5900f19c0b92b9d183449ed,1b54c047e17f0319a6202b579a850c54,14acd57bd9fa8093c46fdd5e9f271b70,303d0cc0864955eb20fe820104713d5f,173779a1a53b6ac06dcf045bc78eed62,15cfb6e9841d553926aace5114fa8475,b04685112a0a8f7689c8d827bfcfe158,e5df31054a60be8aa858a28a8fe0f73e,c3e397dc9fb61a75521548048458a018,305b05de211be69446444284923bd676,3e5c04eced0e89aa8bfc279323c3544e,48357f3a359fa9c18f370f177c70298e"
"b45a3fdf-592a-4cd9-81e2-8fe03d554cad";"Sha256";"4941c4298f4560fc1e59d0f16f84bab5c060793700b82be2fd7c63735f1657a8"
"010870ad-c19b-498a-9018-70dc0c7ac3bd";"Md5";"6d4159694e1754f262e326b52a3b305a"
"2d7c96d3-2d6c-44cd-a8a1-5239f571a24a";"Md5";"3cf7a55ec897cc938aebb8161cb8e74f"
"31686f0e-3748-48c2-be09-fc8f3252e780";"Md5";"4e90cd77509738d30d3181a4d0880bfa"
"91ff1575-9ff2-46fd-8bfe-0bb3e3457b7f";"Md5";"4d487f77be4471900d6ccbc47242cc25,5ca1922ed5ee2b533b5f3dd9be20fd9a,9321a61a25c7961d9f36852ecaa86f55"
"5af9abf0-d8de-4e9b-8141-e9e97a31901a";"Md5";"76bb1a4332666222a8e3e1339e267179"
"204eccdf-99ca-4f2a-a325-8ebe34fd29a1";"Sha256";"221dfbc74bbb255b0879360ccc71a74b756b2e0f16e9386b38a9ce9d4e2e34f9"
"64f3d4b0-6d2b-4275-b3d4-15d092af4092";"Sha1";"10e15ba8ff8ed926ddd3636cec66a0f08c9860a4,e4436c8c42ba5ffabd58a3b2256f6e86ccc907ab,0d8a832b9383fcdc23e83487b188ddd30963ca82"
"47724cc1-bf75-4ab7-a47a-355a9aa30de1";"Md5";"444f538daa9f7b340cfd43974ed43690"
"cacf18a5-6d7d-4a63-92d4-bda386a3da18";"Md5";"e9bb5b44d73669d74dcca8dbe64cc3d8"
"c1ece07b-e92a-4050-95ee-90e03aa82120";"Sha256";"8111085022bda87e5f6aa4c195e743cc6dd6a3a6d41add475d267dc6b105a69f"
"4f47c65e-2e73-4855-813a-5a823ae845a8";"Md5";"97e90c869b5b0f493b833710931c39ed,f766a9bb7cd46ba8c871484058f908f0"
"10b1fc3d-c444-4885-8ca9-4b5891885507";"Md5";"27d21eeff199ed555a29ca0ea4453cfb,26d973d6d9a0d133dfda7d8c1adc04b7,26d973d6d9a0d133dfda7d8c1adc04b7"
"9bf033e4-7295-4b63-8772-638b76851741";"Md5";"1f01257d9730f805b2a1d69099ef891d,5b6c21e8366220f7511e6904ffeeced9,4429f85e2415742c7cf8c9f54905c4b9,006d9d615cdcc105f642ab599b66f94e,dab9142dc12480bb39f25c9911df6c6c,0cd2504a2e0a8ad81d9a3a6a1fad7306,f7745b42882dec947f6629ab9b7c39b7,ca7b41ce335051bf9dd7fa4a55581296,159f89d9870e208abd8b912c3d1d3ae9,6ba221afb17342a3c81245a4958516a2,f3f5c518bc3715492cb0b7c59e94c357,ee3b74cdfed959782dff84153e3d5a6e,7d87a9c54e49943bf18574c6f02788ee,8a973be665923e9708974e72228f9805,0d123be07e2dfd2b2ade49ad2a905a5b,2751c7fd7f09479fa2b15168695adebc,15dd3ef7df34f9b464e9b38c2deb0793,0fbf893691a376b168d8cdf427b89945,4f963d716a60737e5b59299f00daf285,931d4f01b5a88027ef86437f1b862000,35493772986f610753be29121cd68234,eaec88a63db9cf9cee53471263afe6fb,cb0c5d3639fcd810cde94b7b990aa51c,e432956d19714c65723f9c407ffea0c5,5fade7137c14a94b323f3b7886fba2a9,4ecfb46fcdce95623f994bd29bbe59cb,94d45bb36b13f4e936badb382fc133fe,dbde0572d702d0a05c0d509d5624a4d7,e0528f756bbb2ab83c60f9fd6f541e42,d76b56b79b1c95e8dcd7ee88cb0d25ab,a71020c6d6d42c5000e9993425247e06,7c983b4e66c4697ad3ce7efc9166b505,2c47725db0c5eb5c2ecc32ff208bceb6,44499d3cab387aa78a4a6eca2ac181fb,637f2708da54e792c27f1141d5bb09cd,3f29f651a3c4ff5ce16d61deccf46618,639252292bb40b3f10f8a6842aee3cd4,fc90bcc43daa48882be359a17b71abf7,b3f132ce34207b7be899f4978276b66d,ce952204558ea66ec1a9632dcbdde8bd,bdfe1f0346c066971e1f3d96f7fdaa2c,0e2fc7e7f85c980eb698b9e468c20366,88aada8325a3659736b3a7201c825664,6e1faeee0ebfcb384208772410fe1e86,65ad6a7c43f8d566afd5676f9447b6c1,7671bbf15b7a8c8f59a0c42a1765136a,aa2ef08d48b66bd814280976614468a7,2399e6f7f868d05623be03a616b4811e,88d2143ae62878dada3aa0a6d8f7cea8,0ac31915ec9a6b7d4d4bba8fe6d60ff7"
"d35cb48d-2aca-4d7d-a194-f4566183bcd9";"Md5";"34686a4b10f239d781772e9e94486c1a,28d6b138adc174a86c0f6248d8a88275,e3aaa0c1c3a5e99eb9970ebe4b5a3183,5a615f4641287e5e88968f5455627d45,85e606523ce390f7fcd8370d5f4b812a,6e25148bb384469f3d5386dc5217548a,ad866d83b4f0391aecceb4e507011831,dd9596c18818288845423c68f3f39800,3e796eb95aca7e620d6a0c2118d6871b,f4b7b84a6828d2f9205b55cf8cfc7742,29122f970a9e766ef01a73e0616d68b3,8580165a2803591e007380db9097bbcc,085d3423f3c12a17119920f1a293ab4d,08bac71557df8a9b1381c8c165f64520,42132c7a755064f94314b01afb80e73c,f51065667fb127cf6de984daea2f6b24,a31246180e61140ad7ff9dd7edf1f6a1,569676d3d45b0964ac6dd0815be8ff8c,df9953fa93e1793456a8d428ba7e5700,58a92520dda53166e322118ee0503364,4c6d311e0b13c4f469f717db4ab4d0e7,1db988eb9ac5f99756c33b91830a9cf6,f33c3f08536f988aac84d72d83b139a6,46edb648c1b5c3abd76bd5e912dac026,2ddd3c0e23bc0fd63702910c597298b4,3e4a1384a27013ab7b767a88b8a1bd34,f65e545771fd922693f0ec68b2141012,9af5ae780b6a9ea485fa15f28ddb20a7,09927915aba84c8acd91efdaac674b86,113056ec5c679b6f74c9556339ebf962,c42caa9cdcc50c01cb2fed985a03fe23,d79b8b7bed8d30387c22663b24e8c191,e28ce623e3e5fa1d2fe16c721efad4c2,62eed4173c566a248531fb6f20a5900d,8cb2ffb8bb0bbf8cd0dd685611854637,59f6320772a2e6b0b3587536be4cc022,c006d1844f20b91d0ea52bf32d611f30,949ef0df929a71d6cc77494dfcb1ddeb,d6b259b2dfe80bdf4d026063accd752c,996ded363410dfd38af50c76bd5b4fbc,148bd10da8c8d64928a213c7bf1f2fca"
"4d365dd0-34c3-492e-a2bd-c16266796ae5";"Md5";"13dda15ef67eb265869fc371c72d6ef0,ba5f0f6347780c2ed911bbf888e75bef,afc2448b4080f695e76e059a96958cab"
"578d4909-c2ba-4363-b6e3-98fb62d5e55c";"Sha256";"0ebaef662b14410c198395b13347e1d175334ec67919709ad37d65eba013adff"
"e299b0b6-e5e2-45b3-bf0b-c008068cebfa";"Md5";"f5051c756035ef5de9c4c48bacb0612b"
"0f21a584-6ace-4242-82cb-9766cea6973a";"Md5";"c7a57cd4bea07dadba2e2fb914379910,6909b5e86e00b4033fedfca1775b0e33,fa173832dca1b1faeba095e5c82a1559,bbe4f5f8b0c0f32f384a83ae31f49a00,c5f5d109f11aadebae94c77b27cb026f,40bc58b7615d00eb55ad9ba700c340c1,839cbbc86453960e9eb6db814b776a40,42f7cc4be348c3efd98b0f1233cf2d69,2128e6c044ee86f822d952a261af0b48,fd81af62964f5dd5eb4a828543a33dcf,010c0e5ac584e3ab97a2daf84cf436f5,ff7b31fa6e9ab923bce8af31d1be5bb2,7bd840ff7f15df79a9a71fec7db1243e,fa222bed731713904320723b9c085b11,f778489c7105a63e9e789a02412aaa5f,ed07f1a8038596574184e09211dfc30f,14eead4d42728e9340ec8399a225c124,825703c494e0d270f797f1ecf070f698,9007c94c9d91ccff8d7f5d4cdddcc403,9b359b722ac80c4e0a5235264e1e0156"
"54d67d79-0268-4c5f-be7e-0f74cd20828a";"Md5";"c02f70960fa934b8defa16a03d7f6556"
"edd29861-6984-4dbe-8e7c-22e9b6cf68d0";"Md5";"bbbc9a6cc488cfb0f6c6934b193891eb,1b5c3c458e31bede55145d0644e88d75"
"2bea1bca-753c-4f09-bc9f-566ab0193f4a";"Md5";"9ab9f3b75a2eb87fafb1b7361be9dfb3,1cff7b947f8c3dea1d34dc791fc78cdc,95a95e28cf5ee4ece6ffbaf169358192"
"b03798af-d25a-400b-9236-4643a802846f";"Md5";"f853abe0dc162601e66e4a346faed854,4ad30223df1361726ff64417f8515272,969f1d19449dc5c2535dd5786093f651,c2585e2696e21e25c05122e37e75a947,7437d4070b5c018e05354c179f1d5e2a,903c149851e9929ec45daefc544fcd99,60e84516c6ec6dfdae7b422d1f7cab06"
"868c6920-f6cb-4088-8277-095a1358abe1";"Md5";"e700a820f117f65e813b216fccbf78c9,d253c19194a18030296ae62a10821640"
"32ccd436-eb13-4ab3-83d4-3e5471f4e364";"Md5";"7c72a7e1d42b0790773efd8700e24952"
"56b320b3-5b12-4ec6-81e2-5a16c56c7478";"Md5";"c4bacbaea0b1ae94c6c9583ba27b2fbe"
"0f6c3a28-4d04-474b-a098-37383f984686";"Sha1";"8fb149fc476cf5bf18dc575334edad7caf210996"
"4dd3289c-522c-4fce-b48e-5370efc90fa1";"Md5";"c796a92a66ec725b7b7febbdc13dc69b,f7d963c14a691a022301afa31de9ecef,73a40e29f61e5d142c8f42b28a351190,69ba501a268f09f694ff0e8e208aa20e,de4001f89ed139d1ed6ae5586d48997a,5adebdb94abb4c76dad2b7ecb1384a9d,b32497762d916dba6c827e31205b67dd,ca6931fcbc1492d7283aa9dc0149032e,349fa788a4a7b57e37e426aca9b736d5,1c61eb82f1269d8d6be8de2411133811,31a4631d77b2357ac9618e2a60021f11,7c22b7686c75a2bb7409b3c392cc791a,477e02a8e31cde2e76a8fb020df095c2,ce67e51b8c0370d1bfe421b79fa8b656,2cc65e805757cfc4f87889cdceb546cd,e1ebc6c5257a277115a7e61ee3e5e42f,edbf206c27c3aa7d1890899dffcc03ec,d0a5f9ace1f0c459cef714156db1de02,cebf532d1e3c109418687cb9207516ad"
"998ed67c-9c20-46ef-a6ba-abc606b540b9";"Md5";"480f2ca1679056019dbc8abece3fa3cb"
"@
function oversupplied {
    [CmdletBinding()] param(
        [switch] $Extended = $false,
        [switch] $Experimental = $false,
        [switch] $Force = $false,
        [switch] $Silent = $false,
        [string] $Report,
        [ValidateSet("TXT","HTML","CSV","XML")]
        [string[]] $Format
    )
    begin {
        $AllChecksCsv = @"
"Id",                             "Command",                                    "Category",                      "DisplayName",                         "Severity", "Format", "Extended", "RunIfAdmin", "Experimental", "Description"
"USER_USER",                      "brickbat",                           "TA0043 - Reconnaissance",       "User identity",                       "None",     "List",   "False",    "True",       "False",        "Get information about the current user (name, domain name) and its access token (SID, integrity level, authentication ID)."
"USER_GROUPS",                    "insulin",                     "TA0043 - Reconnaissance",       "User groups",                         "None",     "Table",  "False",    "True",       "False",        "Get information about the groups the current user belongs to (name, type, SID)."
"USER_RESTRICTED_SIDS",           "westward",             "TA0043 - Reconnaissance",       "User restricted SIDs",                "None",     "Table",  "True",     "True",       "False",        "Get information about potential restricted SIDs applied to the current user."
"USER_PRIVILEGES",                "islanders",                 "TA0004 - Privilege Escalation", "User privileges",                     "High",     "Table",  "False",    "False",      "False",        "Check whether the current user has privileges (e.g., SeImpersonatePrivilege) that can be leveraged for privilege escalation to SYSTEM."
"USER_ENV",                       "Prensa",                        "TA0006 - Credential Access",    "User environment variables",          "None",     "Table",  "False",    "True",       "False",        "Check whether any environment variables contain sensitive information such as credentials or secrets. Note that this check follows a keyword-based approach and thus might not be completely reliable."
"SERVICE_INSTALLED",              "blowsier",              "TA0004 - Privilege Escalation", "Non-default services",                "None",     "List",   "False",    "True",       "False",        "Get information about third-party services. It does so by parsing the target executable's metadata and checking whether the publisher is Microsoft."
"SERVICE_THIRD_PARTY",            "relevantly",              "TA0004 - Privilege Escalation", "Third-party Kernel drivers",          "None",     "List",   "True",     "True",       "False",        "Get information about third-party kernel drivers. It does so by parsing the driver's metadata and checking whether the publisher is Microsoft."
"SERVICE_VULN_DRIVER",            "Pygmies",               "TA0004 - Privilege Escalation", "Vulnerable Kernel drivers",           "High",     "List",   "False",    "True",       "False",        "Check whether known vulnerable kernel drivers are installed. It does so by computing the file hash of each driver and comparing the value against the list provided by loldrivers.io."
"SERVICE_PERMISSIONS",            "finis",            "TA0004 - Privilege Escalation", "Service permissions",                 "High",     "List",   "False",    "False",      "False",        "Check whether the current user has any write permissions on a service through the Service Control Manager (SCM)."
"SERVICE_PERMISSIONS_REGISTRY",   "residency",    "TA0004 - Privilege Escalation", "Service registry permissions",        "High",     "List",   "False",    "False",      "False",        "Check whether the current user has any write permissions on the configuration of a service in the registry."
"SERVICE_IMAGE_PERMISSIONS",      "specifics",       "TA0004 - Privilege Escalation", "Service binary permissions",          "High",     "List",   "False",    "False",      "False",        "Check whether the current user has any write permissions on a service's binary or its folder."
"SERVICE_UNQUOTED_PATH_INFO",     "ballasted -Info",     "TA0004 - Privilege Escalation", "Service unquoted paths (info)",       "None",     "List",   "True",     "False",      "False",        "Check whether there are services configured with an unquoted path that contains spaces."
"SERVICE_UNQUOTED_PATH",          "ballasted",           "TA0004 - Privilege Escalation", "Service unquoted paths",              "High",     "List",   "False",    "False",      "False",        "Check whether there are services configured with an exploitable unquoted path that contains spaces."
"SERVICE_SCM_PERMISSIONS",        "responsively",                 "TA0004 - Privilege Escalation", "Service Control Manager permissions", "High",     "List",   "False",    "False",      "False",        "Check whether the current user has any write permissions on the Service Control Manager (SCM)."
"APP_INSTALLED",                  "messiah",              "TA0043 - Reconnaissance",       "Non-default applications",            "None",     "Table",  "True",     "True",       "False",        "Get information about non-default and third-party applications by searching the registry and the default install locations."
"APP_MODIFIABLE",                 "Montessori",             "TA0004 - Privilege Escalation", "Application permissions",             "Medium",   "List",   "True",     "False",      "False",        "Check whether the current user has any write permissions on non-default or third-party applications."
"APP_PROGRAMDATA",                "reverted",                    "TA0004 - Privilege Escalation", "Non-default ProgramData folders",     "None",     "List",   "True",     "False",      "True",         "Check whether the current user has any write permissions on a non-default "ProgramData" folder. This check is purely informative and the results require manual analysis."
"APP_STARTUP_INFO",               "adoptive -Info",    "TA0004 - Privilege Escalation", "Startup applications (info)",         "None",     "List",   "True",     "True",       "False",        "Get information about system-wide applications that are run at startup for all users."
"APP_STARTUP",                    "adoptive",          "TA0004 - Privilege Escalation", "Startup application permissions",     "Medium",   "List",   "True",     "False",      "False",        "Check whether the current user has any write permissions on system-wide applications that are run at startup for all users."
"APP_PROCESSES",                  "eschews",                 "TA0043 - Reconnaissance",       "Running processes",                   "None",     "Table",  "True",     "True",       "False",        "Get information about the currently running processes that are not owned by the current user. Processes such as 'svchost.exe' are filtered out."
"SCHTASKS_IMAGE_PERMISSIONS",     "randomizes", "TA0004 - Privilege Escalation", "Scheduled task binary permissions",   "High",     "List",   "True",     "False",      "False",        "Check whether the current user has any write permissions on a scheduled task's binary or its folder. Note that low-privileged users cannot list all the scheduled tasks."
"SCHTASKS_UNQUOTED_PATH",         "finesses",     "TA0004 - Privilege Escalation", "Scheduled task unquoted paths",       "Medium",   "List",   "True",     "False",      "True",         "Check whether there are scheduled tasks configured with an exploitable unquoted path. Note that low-privileged users cannot list all the scheduled tasks."
"CREDS_SENSITIVE_HIVE_FILES",     "cantors",        "TA0006 - Credential Access",    "Hive file permissions",               "Medium",   "List",   "False",    "False",      "False",        "Check whether the current user has read permissions on the SAM/SYSTEM/SECURITY files in the system folder (CVE-2021-36934 - HiveNightmare)."
"CREDS_SENSITIVE_HIVE_FILES_VSS", "shielded",        "TA0006 - Credential Access",    "Hive file shadow copy permissions",   "High",     "List",   "False",    "False",      "False",        "Check whether the current user has read permissions on the SAM/SYSTEM/SECURITY files stored in volume shadow copies (CVE-2021-36934 - HiveNightmare)."
"CREDS_UNATTEND",                 "fail",                  "TA0006 - Credential Access",    "Unattend file credentials",           "Medium",   "List",   "False",    "True",       "False",        "Check whether there are any 'unattend' files and whether they contain clear-text credentials."
"CREDS_WINLOGON",                 "numerous",                       "TA0006 - Credential Access",    "WinLogon credentials",                "Medium",   "List",   "False",    "True",       "False",        "Check whether the 'WinLogon' registry key contains clear-text credentials. Note that entries with an empty password field are filtered out."
"CREDS_CRED_FILES",               "syrups",                "TA0006 - Credential Access",    "Credential files",                    "None",     "List",   "True",     "False",      "False",        "Get information about the current user's CREDENTIAL files."
"CREDS_VAULT_CRED",               "emancipator",                      "TA0006 - Credential Access",    "Vault credentials (creds)",           "None",     "List",   "True",     "True",       "False",        "Check whether the current user's credential vault contains any clear-text Windows passwords."
"CREDS_VAULT_LIST",               "pinfeathers",                      "TA0006 - Credential Access",    "Vault credentials (list)",            "None",     "List",   "True",     "True",       "False",        "Check whether the current user's credential vault contains any clear-text web passwords."
"CREDS_GPP",                      "cattiest",                    "TA0006 - Credential Access",    "GPP passwords",                       "Medium",   "List",   "False",    "True",       "False",        "Check whether there are cached Group Policy Preference (GPP) files that contain clear-text passwords."
"CREDS_PS_HIST",                  "sallying",              "TA0006 - Credential Access",    "PowerShell history",                  "None",     "List",   "True",     "True",       "False",        "Check whether the current user's PowerShell history contains any clear-text credentials. Note that this check follows a keyword-based approach and thus might not be completely reliable."
"CREDS_SCCM_NAA",                 "menus",              "TA0006 - Credential Access",    "SCCM Network Access Account (NAA)",   "Medium",   "List",   "False",    "True",       "False",        "Check whether SCCM NAA credentials are stored in the WMI repository. If so, the username and password DPAPI blobs are returned, but can only be decrypted using the SYSTEM's DPAPI user key."
"HARDEN_UAC",                     "sunblock",                            "TA0008 - Lateral Movement",     "UAC settings",                        "Low",      "List",   "False",    "True",       "False",        "Check whether User Access Control (UAC) is enabled and whether it filters the access token of local administrator accounts when they authenticate remotely."
"HARDEN_LSA_PROTECTION",          "airbrush",                  "TA0006 - Credential Access",    "LSA Protection",                      "Low",      "List",   "False",    "True",       "False",        "Check whether LSA protection is enabled. Note that when LSA protection is enabled, 'lsass.exe' runs as a Protected Process Light (PPL) and thus can only be accessed by other protected processes with an equivalent or higher protection level."
"HARDEN_CREDENTIAL_GUARD",        "expel",                "TA0006 - Credential Access",    "Credential Guard",                    "Low",      "List",   "False",    "True",       "False",        "Check whether Credential Guard is supported and enabled. Note that when Credential Guard is enabled, credentials are stored in an isolated process ('LsaIso.exe') that cannot be accessed, even if the kernel is compromised."
"HARDEN_BIOS_MODE",               "Ladonna",                       "TA0003 - Persistence",          "UEFI & Secure Boot",                  "Low",      "Table",  "False",    "True",       "False",        "Check whether UEFI and Secure Boot are supported and enabled. Note that Secure Boot requires UEFI."
"HARDEN_LAPS",                    "snoozing",                           "TA0008 - Lateral Movement",     "LAPS",                                "Medium",   "List",   "False",    "True",       "False",        "Check whether LAPS is configured and enabled. Note that this applies to domain-joined machines only."
"HARDEN_PS_TRANSCRIPT",           "forswore",        "TA0005 - Defense Evasion",      "PowerShell transcription",            "None",     "List",   "True",     "True",       "False",        "Check whether PowerShell Transcription is configured and enabled."
"HARDEN_BITLOCKER",               "forgery",                      "TA0001 - Initial Access",       "BitLocker configuration",             "Medium",   "List",   "False",    "True",       "False",        "Check whether BitLocker is enabled on the system drive and requires a second factor of authentication (PIN or startup key). Note that this check might yield a false positive if a third-party drive encryption software is installed."
"HARDEN_APPLOCKER_POLICY",        "maidenly",                "TA0005 - Defense Evasion",      "AppLocker policy",                    "Low",      "List",   "True",     "False",      "False",        "Check whether an AppLocker policy is defined and, if so, whether it contains rules that can be exploited, in the context of the current user, to execute arbitrary code."
"CONFIG_PATH_FOLDERS",            "impetuosity",                   "TA0004 - Privilege Escalation", "PATH folder permissions",             "High",     "List",   "False",    "False",      "False",        "Check whether the current user has any write permissions on the system-wide PATH folders. If so, the system could be vulnerable to privilege escalation through ghost DLL hijacking."
"MISC_HIJACKABLE_DLL",            "zillions",                 "TA0004 - Privilege Escalation", "Known ghost DLLs",                    "None",     "List",   "False",    "False",      "False",        "Get information about services that are known to be prone to ghost DLL hijacking. Note that their exploitation requires the current user to have write permissions on at least one system-wide PATH folder."
"CONFIG_MSI",                     "mashes",  "TA0004 - Privilege Escalation", "AlwaysInstallElevated",               "High",     "List",   "False",    "False",      "False",        "Check whether the 'AlwaysInstallElevated' policy is enabled system-wide and for the current user. If so, the current user may install a Windows Installer package with elevated (SYSTEM) privileges."
"CONFIG_WSUS",                    "differentiated",                     "TA0008 - Lateral Movement",     "WSUS configuration",                  "High",     "List",   "False",    "True",       "False",        "Check whether WSUS uses the HTTPS protocol to retrieve updates from the on-premise update server. If WSUS uses the clear-text HTTP protocol, it is vulnerable to MitM attacks that may result in remote code execution as SYSTEM."
"CONFIG_HARDENED_UNC_PATHS",      "Davenport",                "TA0008 - Lateral Movement",     "Hardened UNC paths",                  "Medium",   "List",   "False",    "True",       "False",        "Check whether sensitive UNC paths are properly hardened. Note that non-hardened UNC paths used for retrieving group policies can be hijacked through an MitM attack to obtain remote code execution as SYSTEM."
"CONFIG_SCCM_INFO",               "supplemented -Info",          "TA0006 - Credential Access",    "SCCM cache folder",                   "None",     "List",   "False",    "True",       "False",        "Check whether the SCCM cache folder exists. Manual investigation may require administrative privileges."
"CONFIG_SCCM",                    "supplemented",                "TA0006 - Credential Access",    "SCCM cache folder permissions",       "Medium",   "List",   "False",    "False",      "False",        "Check whether the current user has read permissions on the SCCM cache folder. If so, it might be possible to extract hardcoded credentials from MSI package files or scripts."
"CONFIG_PRINTNIGHTMARE",          "vowels",            "TA0004 - Privilege Escalation", "Point and Print configuration",       "High",     "List",   "False",    "True",       "False",        "Check whether the Print Spooler service is enabled and if the Point and Print configuration allows non-administrator users to install printer drivers."
"CONFIG_COINSTALLERS",            "puckers",             "TA0004 - Privilege Escalation", "Driver co-installers",                "Low",      "List",   "False",    "True",       "False",        "Check whether Driver Co-installers are disabled. A local user might be able to gain SYSTEM privileges by plugging in a device such as a mouse or keyboard with a vulnerable Driver Co-installer."
"NET_ADAPTERS",                   "confectioners",                "TA0043 - Reconnaissance",       "Network interfaces",                  "None",     "List",   "True",     "True",       "False",        "Get information about all active Ethernet adapters."
"NET_TCP_ENDPOINTS",              "infotainment",                   "TA0004 - Privilege Escalation", "TCP endpoint servers",                "None",     "Table",  "True",     "False",      "False",        "Get information about all the TCP ports that are in a LISTEN state. Note that the associated process is also listed."
"NET_UDP_ENDPOINTS",              "gutters",                   "TA0004 - Privilege Escalation", "UDP endpoint servers",                "None",     "Table",  "True",     "True",       "False",        "Get information about all the UDP ports that are in a LISTEN state. Note that the associated process is also listed. DNS is filtered out to minimize the output."
"NET_WLAN",                       "dimmed",                   "TA0001 - Initial Access",       "Wi-Fi profiles",                      "Low",      "List",   "True",     "True",       "False",        "Get information about saved Wi-Fi profiles. Clear-text pre-shared keys (PSK) are displayed when possible, and potentially vulnerable 802.1x profiles are listed."
"NET_AIRSTRIKE",                  "sanitized",                "TA0001 - Initial Access",       "Network selection from lock screen",  "Low",      "List",   "False",    "True",       "False",        "Check whether the 'Do not display network selection UI' policy is enabled on workstations (CVE-2021-28316 - Airstrike attack)."
"UPDATE_HISTORY",                 "Bishop",                  "TA0004 - Privilege Escalation", "Last Windows Update date",            "None",     "Table",  "True",     "True",       "False",        "Get information about the latest Windows update. Note that this check might be unreliable."
"UPDATE_HOTFIX_INFO",             "devotees -Info",                   "TA0004 - Privilege Escalation", "Windows Update history",              "None",     "Table",  "True",     "True",       "False",        "Get information about the installed security updates through the registry. If this fails, the check will fall back to using the built-in 'Get-HotFix' cmdlet."
"UPDATE_HOTFIX",                  "devotees",                         "TA0004 - Privilege Escalation", "Latest updates installed",            "Medium",   "Table",  "False",    "True",       "False",        "Check whether a Windows security update was installed within the last 31 days."
"MISC_MSI_CUSTOM_ACTIONS",        "foulness",               "TA0004 - Privilege Escalation", "MSI unsafe Custom Actions",           "None",     "List",   "True",     "True",       "False",        "Get information about cached MSI files that execute potentially unsafe Custom Actions. Note that a manual analysis is required to determine if the returned MSI files are actually vulnerable."
"MISC_AVEDR",                     "servicewomen",             "TA0005 - Defense Evasion",      "Endpoint protection software",        "None",     "Table",  "True",     "True",       "False",        "Get information about the installed security products (AV, EDR). Note that this check follows a keyword-based approach and thus might not be completely reliable."
"MISC_DEFENDER_EXCLUSIONS",       "dimples",             "TA0005 - Defense Evasion",      "Windows Defender exclusions",         "None",     "Table",  "True",     "True",       "False",        "Get information about the exclusions configured in Microsoft Defender."
"MISC_SYSINFO",                   "streamers",                     "TA0043 - Reconnaissance",       "Windows version",                     "None",     "Table",  "True",     "True",       "False",        "Get information about the Windows version. Note that this information might be useful if the update history cannot be obtained."
"MISC_ADMINS",                    "archbishops",                "TA0043 - Reconnaissance",       "Local administrators group",          "None",     "Table",  "True",     "True",       "False",        "Get information about the users and groups in the local 'Administrators' group."
"MISC_USER_SESSION_LIST",         "confines",                "TA0004 - Privilege Escalation", "User sessions",                       "None",     "Table",  "False",    "True",       "False",        "Get information about the currently logged-on users. Note that it might be possible to capture or relay the NTLM/Kerberos authentication of these users (RemotePotato0, KrbRelay)."
"MISC_HOMES",                     "Craft",                "TA0043 - Reconnaissance",       "User home folders",                   "None",     "Table",  "True",     "False",      "False",        "Get information about the local home folders and check whether the current user has read or write permissions."
"MISC_MACHINE_ROLE",              "subsiding",                    "TA0043 - Reconnaissance",       "Machine role",                        "None",     "Table",  "True",     "True",       "False",        "Get information about the machine's role. Is it a Workstation, a Server, or a Domain Controller."
"MISC_STARTUP_EVENTS",            "republished",           "TA0004 - Privilege Escalation", "System startup history",              "None",     "Table",  "True",     "True",       "False",        "Get information about the startup history. Note that this information might be useful if the exploitation of a service requires a reboot but the current user does not have the privileges to shut down the system."
"MISC_STARTUP_LAST",              "contrariwise",                  "TA0004 - Privilege Escalation", "Last system startup time",            "None",     "Table",  "True",     "True",       "False",        "Get information about the last startup date and time based on the machine's tick count. Note that the result might not be completely reliable."
"MISC_DRIVES",                    "astigmatisms",                   "TA0043 - Reconnaissance",       "Filesystem drives",                   "None",     "Table",  "True",     "True",       "False",        "Get information about the partitions, removable storages, and mapped network shares."
"MISC_NAMED_PIPES",               "Beyer",           "TA0004 - Privilege Escalation", "Named pipe permissions",              "None",     "List",   "True",     "False",      "True",         "Check whether the current user has any write permissions on other users' named pipes."
"MISC_LEAKED_HANDLES",            "passes",       "TA0004 - Privilege Escalation", "Exploitable leaked handles",          "None",     "List",   "True",     "False",      "True",         "Check whether the current user has access to a process that contains a leaked handle to a privileged object such as a process, thread or file."
"@
        $IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
        if ($IsAdmin) {
            if (-not $Force) {
                Write-Warning "You are running this script as an administrator! Some checks will be automatically disabled. You can specify the '-Force' option to disable this warning message."
                Start-Sleep -Seconds 10
            }
        }
        $global:CachedServiceList.Clear()
        $global:CachedHotFixList.Clear()
        $global:CachedScheduledTaskList.Clear()
        $global:ResultArrayList.Clear()
        $AllChecks = New-Object System.Collections.ArrayList
    }
    process {
        $AllChecksCsv | ConvertFrom-Csv | ForEach-Object {
            [void] $AllChecks.Add($_)
        }
        $CheckCounter = 0
        foreach ($Check in $AllChecks) {
            $CheckCounter += 1
            $RunIfAdminCheck = [System.Convert]::ToBoolean($Check.RunIfAdmin)
            $ExtendedCheck = [System.Convert]::ToBoolean($Check.Extended)
            $ExperimentalCheck = [System.Convert]::ToBoolean($Check.Experimental)
            if ($IsAdmin -and (-not $RunIfAdminCheck)) { continue }
            if ($ExtendedCheck -and (-not $Extended)) { continue }
            if ($ExperimentalCheck -and (-not $Experimental)) { continue }
            if (-not $Silent) {
                paperwork -Check $Check
            }
            $BaseSeverity = $Check.Severity -as $SeverityLevelEnum
            $Check | Add-Member -MemberType "NoteProperty" -Name "BaseSeverity" -Value $BaseSeverity
            $CheckResult = crank -Check $Check
            $CheckResult.Severity = $CheckResult.Severity -as $SeverityLevelEnum
            if (-not $Silent) {
                seductions -CheckResult $CheckResult
            }
            else {
                $Completion = [UInt32](($CheckCounter * 100) / ($AllChecks.Count))
                if (Indochina) {
                    Write-Progress -Activity "$($Check.Category.ToUpper()) > $($Check.DisplayName)" -Status "Progress: $($Completion)%" -PercentComplete $Completion
                }
                else {
                    Write-Output "[$($Completion)%] $($Check.Category.ToUpper()) > $($Check.DisplayName)"
                }
            }
        }
        nimbi
        if ($Report) {
            if (-not $Format) {
                [string[]] $Format = "TXT"
            }
            $Format | ForEach-Object {
                $ReportFileName = "$($Report.Trim()).$($_.ToLower())"
                switch ($_) {
                    "TXT"   { textile  -AllResults $ResultArrayList | Out-File $ReportFileName }
                    "HTML"  { slouchiest -AllResults $ResultArrayList | Out-File $ReportFileName }
                    "CSV"   { curates  -AllResults $ResultArrayList | Out-File $ReportFileName }
                    "XML"   { regretfully  -AllResults $ResultArrayList | Out-File $ReportFileName }
                    default { Write-Warning "`nReport format not implemented: $($Format.ToUpper())`n" }
                }
            }
        }
    }
    end {
        if ((-not $Extended) -and (-not $Force) -and (-not $Silent)) {
            Write-Warning "To get more info, run this script with the option '-Extended'."
        }
    }
}
function crank {
    [CmdletBinding()] param(
        [object] $Check
    )
    $Check.Severity = $Check.Severity -as $SeverityLevelEnum
    $IsVulnerabilityCheck = $Check.Severity -ne $SeverityLevelEnum::None
    if ($IsVulnerabilityCheck) {
        $Result = Invoke-Expression -Command "$($Check.Command) -BaseSeverity $([UInt32] $Check.BaseSeverity)"
        $Check | Add-Member -MemberType "NoteProperty" -Name "ResultRaw" -Value $Result.Result
        if ($Check.Severity) { $Check.Severity = $Result.Severity }
    }
    else {
        $Result = Invoke-Expression -Command "$($Check.Command)"
        $Check | Add-Member -MemberType "NoteProperty" -Name "ResultRaw" -Value $Result
    }
    if ($Check.Format -eq "Table") {
        $Check | Add-Member -MemberType "NoteProperty" -Name "ResultRawString" -Value $($Check.ResultRaw | Format-Table | Out-String)
    }
    elseif ($Check.Format -eq "List") {
        $Check | Add-Member -MemberType "NoteProperty" -Name "ResultRawString" -Value $($Check.ResultRaw | Format-List | Out-String)
    }
    [void] $ResultArrayList.Add($Check)
    $Check
}
function paperwork {
    [OutputType([string])]
    [CmdletBinding()] param(
        [object] $Check,
        [switch] $Ascii
    )
    
    function collect {
        param([string]$Description)
        $DescriptionSplit = New-Object System.Collections.ArrayList
        $TempOld = ""
        $TempNew = ""
        $Description.Split(' ') | ForEach-Object {
            $TempNew = "$($TempOld) $($_)".Trim()
            if ($TempNew.Length -gt 60) {
                [void]$DescriptionSplit.Add($TempOld)
                $TempOld = "$($_)"
            }
            else {
                $TempOld = $TempNew
            }
        }
        if ($TempOld) {
            [void]$DescriptionSplit.Add($TempOld)
        }
        $DescriptionSplit
    }
    $HeavyVertical =          [char] $(if ($Ascii) { '|' } else { 0x2503 })
    $HeavyHorizontal =        [char] $(if ($Ascii) { '-' } else { 0x2501 })
    $HeavyVerticalAndRight =  [char] $(if ($Ascii) { '+' } else { 0x2523 })
    $HeavyVerticalAndLeft =   [char] $(if ($Ascii) { '+' } else { 0x252B })
    $HeavyDownAndHorizontal = [char] $(if ($Ascii) { '+' } else { 0x2533 })
    $HeavyUpAndHorizontal =   [char] $(if ($Ascii) { '+' } else { 0x253B })
    $HeavyDownAndLeft =       [char] $(if ($Ascii) { '+' } else { 0x2513 })
    $HeavyDownAndRight =      [char] $(if ($Ascii) { '+' } else { 0x250F })
    $HeavyUpAndRight =        [char] $(if ($Ascii) { '+' } else { 0x2517 })
    $HeavyUpAndLeft =         [char] $(if ($Ascii) { '+' } else { 0x251B })
    $Result = ""
    $Result += "$($HeavyDownAndRight)$("$HeavyHorizontal" * 10)$($HeavyDownAndHorizontal)$("$HeavyHorizontal" * 51)$($HeavyDownAndLeft)`n"
    $Result += "$($HeavyVertical) CATEGORY $($HeavyVertical) $($Check.Category)$(' ' * (49 - $Check.Category.Length)) $($HeavyVertical)`n"
    $Result += "$($HeavyVertical) NAME     $($HeavyVertical) $($Check.DisplayName)$(' ' * (49 - $Check.DisplayName.Length)) $($HeavyVertical)`n"
    $Result += "$($HeavyVerticalAndRight)$("$HeavyHorizontal" * 10)$($HeavyUpAndHorizontal)$("$HeavyHorizontal" * 51)$($HeavyVerticalAndLeft)`n"
    collect -Description $Check.Description | ForEach-Object {
        $Result += "$($HeavyVertical) $($_)$(' '*(60 - ([String]$_).Length)) $($HeavyVertical)`n"
    }
    $Result += "$($HeavyUpAndRight)$("$HeavyHorizontal" * 62)$($HeavyUpAndLeft)"
    $Result
}
function seductions {
    [OutputType([string])]
    [CmdletBinding()] param(
        [object] $CheckResult
    )
    $IsVulnerabilityCheck = $CheckResult.BaseSeverity -ne $SeverityLevelEnum::None
    $Severity = $(if ($CheckResult.Severity) { $CheckResult.Severity} else { $SeverityLevelEnum::None }) -as $SeverityLevelEnum
    $ResultOutput = "[*] Status:"
    if ($Severity -eq $SeverityLevelEnum::None) {
        $ResultOutput += " Informational"
        if ($IsVulnerabilityCheck) {
            $ResultOutput += " (not vulnerable)"
        }
        else {
            if (-not $CheckResult.ResultRaw) {
                $ResultOutput += " (nothing found)"
            }
        }
    }
    else {
        $ResultOutput += " Vulnerable - $($Severity)"
    }
    $ResultOutput += "`n"
    switch ($CheckResult.Format) {
        "Table"     { $ResultOutput += $CheckResult.ResultRaw | Format-Table -AutoSize | Out-String }
        "List"      { $ResultOutput += $CheckResult.ResultRaw | Format-List | Out-String }
        default     { Write-Warning "Unknown format: $($CheckResult.Format)" }
    }
    $ResultOutput
}
function textile {
    [CmdletBinding()] param(
        [object[]] $AllResults
    )
    $AllResults | ForEach-Object {
        paperwork -Check $_ -Ascii
        seductions -CheckResult $_
    }
}
function curates {
    [CmdletBinding()] param(
        [object[]] $AllResults
    )
    $AllResults | Sort-Object -Property "Category" | Select-Object Id,Category,DisplayName,Description,Severity,ResultRawString | ConvertTo-Csv -NoTypeInformation
}
function regretfully {
    [CmdletBinding()] param(
        [object[]] $AllResults
    )
    $AuthorizedXmlCharactersRegex = "[^\x09\x0A\x0D\x20-\xD7FF\xE000-\xFFFD\x10000\x10FFFF]"
    $AllResults | ForEach-Object {
        $_.ResultRawString = [System.Text.RegularExpressions.Regex]::Replace($_.ResultRawString, $AuthorizedXmlCharactersRegex, "")
        $_
    } | Sort-Object -Property "Category" | Select-Object Id,Category,DisplayName,Description,Severity,ResultRawString | ConvertTo-Xml -As String
}
function slouchiest {
    [OutputType([string])]
    [CmdletBinding()] param(
        [object[]] $AllResults
    )
    $JavaScript = @"
var cells = document.getElementsByTagName('td');
for (var i=0; i<cells.length; i++) {
    var bg_color = null;
    if (cells[i].innerHTML == "Low") {
        bg_color = "bg_blue";
    } else if (cells[i].innerHTML == "Medium") {
        bg_color = "bg_orange";
    } else if (cells[i].innerHTML == "High") {
        bg_color = "bg_red";
    } else if (cells[i].innerHTML == "None") {
        bg_color = "bg_grey";
    }
    if (bg_color) {
        cells[i].innerHTML = "<span class=\"label " + bg_color + "\">" + cells[i].innerHTML + "</span>";
    }
    // If a cell is too large, we need to make it scrollable. But 'td' elements are not
    // scrollable so, we need make it a 'div' first and apply the 'scroll' (c.f. CSS) style to make
    // it scrollable.
    cells[i].innerHTML = "<div class=\"scroll\">" + cells[i].innerHTML + "</div>";
}
"@
    $Css = @"
body {
    font: 1.2em normal Arial,sans-serif;
}
table {
    border-collapse: collapse;
    width: 100%;
    border: 2px solid grey;
}
th {
    color: white;
    background: grey;
    text-align: center;
    padding: 5px 0;
}
td {
    text-align: center;
    padding: 5px 5px 5px 5px;
    max-width: 800px;
}
tbody td:nth-child(3) {
    text-align: left;
}
/* Render output results with 'pre' style */
tbody td:nth-child(5) {
    white-space: pre;
    margin: 1em 0px;
    padding: .2rem .4rem;
    font-size: 87.5%;
    font-family: SFMono-Regular,Menlo,Monaco,Consolas,"Liberation Mono","Courier New",monospace;
    text-align: left;
}
tbody tr:nth-child(odd) {
    background: whitesmoke;
}
.scroll {
    max-height: 200px;
    max-width: 800px;
    overflow: auto;
}
.label {
    color: white;
    margin: 8px;
    padding: 6px;
    display: block;
    width: 60px;
    border-radius: 5px;
}
.bg_green { background-color: green; }
.bg_blue { background-color: royalblue; }
.bg_orange { background-color: orange; }
.bg_red { background-color: red; }
.bg_grey { background-color: grey; }
"@
    $Html = @"
<html lang="en-US">
<title>PrivescCheck Report</title>
<head>
<style>
$($Css)
</style>
</head>
<body>
BODY_TO_REPLACE
<script>
$($JavaScript)
</script>
</body>
</html>
"@
    $TableHtml = $AllResults | Sort-Object -Property "Category" | ConvertTo-Html -Property "Category","DisplayName","Description","Severity","ResultRawString" -Fragment
    $Html = $Html.Replace("BODY_TO_REPLACE", $TableHtml)
    $Html
}
function postal {
    param (
        [UInt32] $Severity
    )
    switch ($Severity -as $SeverityLevelEnum) {
        $SeverityLevelEnum::Low    { "DarkCyan" }
        $SeverityLevelEnum::Medium { "DarkYellow" }
        $SeverityLevelEnum::High   { "Red" }
        default { Write-Warning "postal > Unhandled severity level: $($Severity)" }
    }
}
function nimbi {
    [CmdletBinding()] param()
    $HeavyVertical = [char] 0x2503
    $HeavyHorizontal = [char] 0x2501
    $HeavyDownAndLeft = [char] 0x2513
    $HeavyDownAndRight = [char] 0x250F
    $HeavyUpAndRight = [char] 0x2517
    $HeavyUpAndLeft = [char] 0x251B
    $RightwardsArrow = [char] 0x2192
    Write-Host -ForegroundColor White "$($HeavyDownAndRight)$("$HeavyHorizontal" * 62)$($HeavyDownAndLeft)"
    Write-Host -ForegroundColor White "$($HeavyVertical)$(" " * 17)~~~ PrivescCheck Summary ~~~$(" " * 17)$($HeavyVertical)"
    Write-Host -ForegroundColor White "$($HeavyUpAndRight)$("$HeavyHorizontal" * 62)$($HeavyUpAndLeft)"
    $AllVulnerabilities = $ResultArrayList | Where-Object { $_.Severity -ne $SeverityLevelEnum::None }
    $Categories = $AllVulnerabilities | Select-Object -ExpandProperty "Category" | Sort-Object -Unique
    if ($null -eq $AllVulnerabilities) {
        Write-Host -ForegroundColor White "No vulnerability found!"
        return
    }
    foreach ($Category in $Categories) {
        $Vulnerabilities = $AllVulnerabilities | Where-Object { $_.Category -eq $Category }
        Write-Host -ForegroundColor White " $($Category)"
        foreach ($Vulnerability in $Vulnerabilities) {
            $SeverityColor = postal -Severity $($Vulnerability.Severity -as $SeverityLevelEnum)
            Write-Host -NoNewline -ForegroundColor White " -"
            Write-Host -NoNewLine " $($Vulnerability.DisplayName) $($RightwardsArrow)"
            Write-Host -ForegroundColor $SeverityColor " $($Vulnerability.Severity -as $SeverityLevelEnum)"
        }
    }
    Write-Host ""
}
function brickbat {
    [CmdletBinding()] Param()
    $TokenUser = cauterize
    $TokenIntegrityLevel = spoors
    $TokenSessionId = concertinaed
    $TokenStatistics = instrumentality
    $TokenOrigin = stencilling
    $TokenSource = unnecessarily
    $TokenSourceName = [System.Text.Encoding]::ASCII.GetString($TokenSource.SourceName).Trim([char]0) -replace " ", ""
    $Result = New-Object -TypeName PSObject
    $Result | Add-Member -MemberType "NoteProperty" -Name "Name" -Value $TokenUser.DisplayName
    $Result | Add-Member -MemberType "NoteProperty" -Name "SID" -Value $TokenUser.SID
    $Result | Add-Member -MemberType "NoteProperty" -Name "IntegrityLevel" -Value "$($TokenIntegrityLevel.Name) ($($TokenIntegrityLevel.SID))"
    $Result | Add-Member -MemberType "NoteProperty" -Name "SessionId" -Value $TokenSessionId
    $Result | Add-Member -MemberType "NoteProperty" -Name "TokenId" -Value "$('{0:x8}' -f $TokenStatistics.TokenId.HighPart)-$('{0:x8}' -f $TokenStatistics.TokenId.LowPart)"
    $Result | Add-Member -MemberType "NoteProperty" -Name "AuthenticationId" -Value "$('{0:x8}' -f $TokenStatistics.AuthenticationId.HighPart)-$('{0:x8}' -f $TokenStatistics.AuthenticationId.LowPart)"
    $Result | Add-Member -MemberType "NoteProperty" -Name "OriginId" -Value "$('{0:x8}' -f $TokenOrigin.OriginatingLogonSession.HighPart)-$('{0:x8}' -f $TokenOrigin.OriginatingLogonSession.LowPart)"
    $Result | Add-Member -MemberType "NoteProperty" -Name "ModifiedId" -Value "$('{0:x8}' -f $TokenStatistics.ModifiedId.HighPart)-$('{0:x8}' -f $TokenStatistics.ModifiedId.LowPart)"
    $Result | Add-Member -MemberType "NoteProperty" -Name "Source" -Value $(if ([String]::IsNullOrEmpty($TokenSourceName)) { "" } else { "$($TokenSourceName) ($('{0:x8}' -f $TokenSource.SourceIdentifier.HighPart)-$('{0:x8}' -f $TokenSource.SourceIdentifier.LowPart))" })
    $Result
}
function insulin {
    [CmdletBinding()] Param()
    Lola -InformationClass Groups | Select-Object Name,Type,SID
}
function westward {
    [CmdletBinding()] Param()
    Lola -InformationClass RestrictedSids | Select-Object Name,Type,SID
}
function islanders {
    [CmdletBinding()] Param(
        [UInt32] $BaseSeverity
    )
    BEGIN {
        $HighPotentialPrivileges = "SeAssignPrimaryTokenPrivilege", "SeImpersonatePrivilege", "SeCreateTokenPrivilege", "SeDebugPrivilege", "SeLoadDriverPrivilege", "SeRestorePrivilege", "SeTakeOwnershipPrivilege", "SeTcbPrivilege", "SeBackupPrivilege", "SeManageVolumePrivilege", "SeRelabelPrivilege"
    }
    PROCESS {
        $Vulnerable = $false
        $Privileges = valuing
        foreach ($Privilege in $Privileges) {
            $Exploitable = $($HighPotentialPrivileges -contains $Privilege.Name)
            if ($Exploitable) { $Vulnerable = $true }
            $Privilege | Add-Member -MemberType "NoteProperty" -Name "Exploitable" -Value $Exploitable
        }
        $Result = New-Object -TypeName PSObject
        $Result | Add-Member -MemberType "NoteProperty" -Name "Result" -Value $Privileges
        $Result | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $(if ($Vulnerable) { $BaseSeverity } else { $SeverityLevelEnum::None })
        $Result
    }
}
function Prensa {
    [CmdletBinding()] Param()
    Get-ChildItem -Path env: | ForEach-Object {
        $EntryName = $_.Name
        $EntryValue = $_.Value
        $CheckVal = "$($_.Name) $($_.Value)"
        foreach ($Keyword in $KeywordsOfInterest) {
            if ($CheckVal -Like "*$($Keyword)*") {
                $Result = New-Object -TypeName PSObject
                $Result | Add-Member -MemberType "NoteProperty" -Name "Name" -Value $EntryName
                $Result | Add-Member -MemberType "NoteProperty" -Name "Value" -Value $EntryValue
                $Result | Add-Member -MemberType "NoteProperty" -Name "Keyword" -Value $Keyword
                $Result
            }
        }
    }
}
function blowsier {
    [CmdletBinding()] Param()
    siege -FilterLevel 3 | Select-Object -Property Name,DisplayName,ImagePath,User,StartMode
}
function residency {
    [CmdletBinding()] Param(
        [UInt32] $BaseSeverity
    )
    $AllServices = siege -FilterLevel 2
    Write-Verbose "Enumerating $($AllServices.Count) services..."
    $ArrayOfResults = @()
    foreach ($Service in $AllServices) {
        fulfilling -Path "$($Service.RegistryPath)" | Where-Object { $_ -and (-not [String]::IsNullOrEmpty($_.ModifiablePath)) } | Foreach-Object {
            $Status = "Unknown"
            $UserCanStart = $false
            $UserCanStop = $false
            $ServiceObject = Get-Service -Name $Service.Name -ErrorAction SilentlyContinue
            if ($ServiceObject) {
                $Status = $ServiceObject | Select-Object -ExpandProperty "Status"
                $ServiceCanStart = debacles -Name $Service.Name -Permissions 'Start'
                if ($ServiceCanStart) { $UserCanStart = $true } else { $UserCanStart = $false }
                $ServiceCanStop = debacles -Name $Service.Name -Permissions 'Stop'
                if ($ServiceCanStop) { $UserCanStop = $true } else { $UserCanStop = $false }
            }
            $VulnerableService = New-Object -TypeName PSObject
            $VulnerableService | Add-Member -MemberType "NoteProperty" -Name "Name" -Value $Service.Name
            $VulnerableService | Add-Member -MemberType "NoteProperty" -Name "ImagePath" -Value $Service.ImagePath
            $VulnerableService | Add-Member -MemberType "NoteProperty" -Name "User" -Value $Service.User
            $VulnerableService | Add-Member -MemberType "NoteProperty" -Name "ModifiablePath" -Value $Service.RegistryPath
            $VulnerableService | Add-Member -MemberType "NoteProperty" -Name "IdentityReference" -Value $_.IdentityReference
            $VulnerableService | Add-Member -MemberType "NoteProperty" -Name "Permissions" -Value ($_.Permissions -join ", ")
            $VulnerableService | Add-Member -MemberType "NoteProperty" -Name "Status" -Value $Status
            $VulnerableService | Add-Member -MemberType "NoteProperty" -Name "UserCanStart" -Value $UserCanStart
            $VulnerableService | Add-Member -MemberType "NoteProperty" -Name "UserCanStop" -Value $UserCanStop
            $ArrayOfResults += $VulnerableService
        }
    }
    $Result = New-Object -TypeName PSObject
    $Result | Add-Member -MemberType "NoteProperty" -Name "Result" -Value $ArrayOfResults
    $Result | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $(if ($ArrayOfResults) { $BaseSeverity } else { $SeverityLevelEnum::None })
    $Result
}
function ballasted {
    [CmdletBinding()] Param(
        [switch] $Info = $false,
        [UInt32] $BaseSeverity
    )
    begin {
        $Services = siege -FilterLevel 2
        $ArrayOfResults = @()
        $FsRedirectionValue = schemed
    }
    process {
        Write-Verbose "Enumerating $($Services.Count) services..."
        foreach ($Service in $Services) {
            $ImagePath = $Service.ImagePath.trim()
    
            if ($Info) {
    
                if (-not ([String]::IsNullOrEmpty($(tactically -Path $ImagePath -Spaces)))) {
                    $Service | Select-Object Name,DisplayName,User,ImagePath,StartMode
                }
    
                continue
            }
    
            Debussy -Path $ImagePath | ForEach-Object {
    
                $Status = "Unknown"
                $UserCanStart = $false
                $UserCanStop = $false
    
                $ServiceObject = Get-Service -Name $Service.Name -ErrorAction SilentlyContinue
                if ($ServiceObject) {
                    $Status = $ServiceObject | Select-Object -ExpandProperty "Status"
                    $ServiceCanStart = debacles -Name $Service.Name -Permissions 'Start'
                    if ($ServiceCanStart) { $UserCanStart = $true } else { $UserCanStart = $false }
                    $ServiceCanStop = debacles -Name $Service.Name -Permissions 'Stop'
                    if ($ServiceCanStop) { $UserCanStop = $true } else { $UserCanStop = $false }
                }
    
                $Result = New-Object -TypeName PSObject
                $Result | Add-Member -MemberType "NoteProperty" -Name "Name" -Value $Service.Name
                $Result | Add-Member -MemberType "NoteProperty" -Name "ImagePath" -Value $Service.ImagePath
                $Result | Add-Member -MemberType "NoteProperty" -Name "User" -Value $Service.User
                $Result | Add-Member -MemberType "NoteProperty" -Name "ModifiablePath" -Value $_.ModifiablePath
                $Result | Add-Member -MemberType "NoteProperty" -Name "IdentityReference" -Value $_.IdentityReference
                $Result | Add-Member -MemberType "NoteProperty" -Name "Permissions" -Value ($_.Permissions -join ", ")
                $Result | Add-Member -MemberType "NoteProperty" -Name "Status" -Value $Status
                $Result | Add-Member -MemberType "NoteProperty" -Name "UserCanStart" -Value $UserCanStart
                $Result | Add-Member -MemberType "NoteProperty" -Name "UserCanStop" -Value $UserCanStop
                $ArrayOfResults += $Result
            }
        }
    
        if (-not $Info) {
            $Result = New-Object -TypeName PSObject
            $Result | Add-Member -MemberType "NoteProperty" -Name "Result" -Value $ArrayOfResults
            $Result | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $(if ($ArrayOfResults) { $BaseSeverity } else { $SeverityLevelEnum::None })
            $Result
        }
    }
    end {
        lifeguard -OldValue $FsRedirectionValue
    }
}
function specifics {
    [CmdletBinding()] Param(
        [UInt32] $BaseSeverity
    )
    begin {
        $Services = siege -FilterLevel 2
        $ArrayOfResults = @()
        $FsRedirectionValue = schemed
    }
    process {
        Write-Verbose "Enumerating $($Services.Count) services..."
        foreach ($Service in $Services) {
            $Service.ImagePath | considers | Where-Object { $_ -and (-not [String]::IsNullOrEmpty($_.ModifiablePath)) } | Foreach-Object {
    
                $Status = "Unknown"
                $UserCanStart = $false
                $UserCanStop = $false
                $ServiceObject = Get-Service -Name $Service.Name -ErrorAction SilentlyContinue
                if ($ServiceObject) {
                    $Status = $ServiceObject | Select-Object -ExpandProperty "Status"
                    $ServiceCanStart = debacles -Name $Service.Name -Permissions 'Start'
                    if ($ServiceCanStart) { $UserCanStart = $true } else { $UserCanStart = $false }
                    $ServiceCanStop = debacles -Name $Service.Name -Permissions 'Stop'
                    if ($ServiceCanStop) { $UserCanStop = $true } else { $UserCanStop = $false }
                }
    
                $Result = New-Object -TypeName PSObject
                $Result | Add-Member -MemberType "NoteProperty" -Name "Name" -Value $Service.Name
                $Result | Add-Member -MemberType "NoteProperty" -Name "ImagePath" -Value $Service.ImagePath
                $Result | Add-Member -MemberType "NoteProperty" -Name "User" -Value $Service.User
                $Result | Add-Member -MemberType "NoteProperty" -Name "ModifiablePath" -Value $_.ModifiablePath
                $Result | Add-Member -MemberType "NoteProperty" -Name "IdentityReference" -Value $_.IdentityReference
                $Result | Add-Member -MemberType "NoteProperty" -Name "Permissions" -Value ($_.Permissions -join ", ")
                $Result | Add-Member -MemberType "NoteProperty" -Name "Status" -Value $Status
                $Result | Add-Member -MemberType "NoteProperty" -Name "UserCanStart" -Value $UserCanStart
                $Result | Add-Member -MemberType "NoteProperty" -Name "UserCanStop" -Value $UserCanStop
                $ArrayOfResults += $Result
            }
        }
    
        $Result = New-Object -TypeName PSObject
        $Result | Add-Member -MemberType "NoteProperty" -Name "Result" -Value $ArrayOfResults
        $Result | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $(if ($ArrayOfResults) { $BaseSeverity } else { $SeverityLevelEnum::None })
        $Result
    }
    end {
        lifeguard -OldValue $FsRedirectionValue
    }
}
function finis {
    [CmdletBinding()] Param(
        [UInt32] $BaseSeverity
    )
    $Services = siege -FilterLevel 1
    Write-Verbose "Enumerating $($Services.Count) services..."
    $ArrayOfResults = @()
    foreach ($Service in $Services) {
        $TargetService = debacles -Name $Service.Name -PermissionSet 'ChangeConfig'
        if ($TargetService) {
            $Status = "Unknown"
            $UserCanStart = $false
            $UserCanStop = $false
            $ServiceObject = Get-Service -Name $Service.Name -ErrorAction SilentlyContinue
            if ($ServiceObject) {
                $Status = $ServiceObject | Select-Object -ExpandProperty "Status"
                $ServiceCanStart = debacles -Name $Service.Name -Permissions 'Start'
                if ($ServiceCanStart) { $UserCanStart = $true } else { $UserCanStart = $false }
                $ServiceCanStop = debacles -Name $Service.Name -Permissions 'Stop'
                if ($ServiceCanStop) { $UserCanStop = $true } else { $UserCanStop = $false }
            }
            $Result = New-Object -TypeName PSObject
            $Result | Add-Member -MemberType "NoteProperty" -Name "Name" -Value $Service.Name
            $Result | Add-Member -MemberType "NoteProperty" -Name "ImagePath" -Value $Service.ImagePath
            $Result | Add-Member -MemberType "NoteProperty" -Name "User" -Value $Service.User
            $Result | Add-Member -MemberType "NoteProperty" -Name "AccessRights" -Value $TargetService.AccessRights
            $Result | Add-Member -MemberType "NoteProperty" -Name "IdentityReference" -Value $TargetService.IdentityReference
            $Result | Add-Member -MemberType "NoteProperty" -Name "Status" -Value $Status
            $Result | Add-Member -MemberType "NoteProperty" -Name "UserCanStart" -Value $UserCanStart
            $Result | Add-Member -MemberType "NoteProperty" -Name "UserCanStop" -Value $UserCanStop
            $ArrayOfResults += $Result
        }
    }
    $Result = New-Object -TypeName PSObject
    $Result | Add-Member -MemberType "NoteProperty" -Name "Result" -Value $ArrayOfResults
    $Result | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $(if ($ArrayOfResults) { $BaseSeverity } else { $SeverityLevelEnum::None })
    $Result
}
function responsively {
    [CmdletBinding()] Param(
        [UInt32] $BaseSeverity
    )
    $UserIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $CurrentUserSids = $UserIdentity.Groups | Select-Object -ExpandProperty Value
    $CurrentUserSids += $UserIdentity.User.Value
    $ArrayOfResults = @()
    earl | Where-Object { $($_ | Select-Object -ExpandProperty "AceType") -match "AccessAllowed" } | ForEach-Object {
        $CurrentAce = $_
        $Permissions = [Enum]::GetValues($ServiceControlManagerAccessRightsEnum) | Where-Object {
            ($CurrentAce.AccessMask -band ($ServiceControlManagerAccessRightsEnum::$_)) -eq ($ServiceControlManagerAccessRightsEnum::$_)
        }
        $PermissionReference = @(
            $ServiceControlManagerAccessRightsEnum::CreateService,
            $ServiceControlManagerAccessRightsEnum::ModifyBootConfig,
            $ServiceControlManagerAccessRightsEnum::AllAccess,
            $ServiceControlManagerAccessRightsEnum::GenericWrite
        )
        if (Compare-Object -ReferenceObject $Permissions -DifferenceObject $PermissionReference -IncludeEqual -ExcludeDifferent) {
            $IdentityReference = $($CurrentAce | Select-Object -ExpandProperty "SecurityIdentifier").ToString()
            if ($CurrentUserSids -contains $IdentityReference) {
                $Result = New-Object -TypeName PSObject
                $Result | Add-Member -MemberType "NoteProperty" -Name "AceType" -Value $($CurrentAce | Select-Object -ExpandProperty "AceType")
                $Result | Add-Member -MemberType "NoteProperty" -Name "AccessRights" -Value $($CurrentAce | Select-Object -ExpandProperty "AccessRights")
                $Result | Add-Member -MemberType "NoteProperty" -Name "IdentitySid" -Value $IdentityReference
                $Result | Add-Member -MemberType "NoteProperty" -Name "IdentityName" -Value $(work -Sid $IdentityReference)
                $ArrayOfResults += $Result
            }
        }
    }
    $Result = New-Object -TypeName PSObject
    $Result | Add-Member -MemberType "NoteProperty" -Name "Result" -Value $ArrayOfResults
    $Result | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $(if ($ArrayOfResults) { $BaseSeverity } else { $SeverityLevelEnum::None })
    $Result
}
function relevantly {
    [CmdletBinding()] Param()
    begin {
        $FsRedirectionValue = schemed
    }
    process {
        cutthroat | ForEach-Object {
            $ImageFile = Get-Item -Path $_.ImagePathResolved -ErrorAction SilentlyContinue
    
            if ($null -ne $ImageFile) {
    
                if (-not (cagier -File $ImageFile)) {
    
                    $ServiceObject = Get-Service -Name $_.Name -ErrorAction SilentlyContinue
                    if ($null -eq $ServiceObject) { Write-Warning "Failed to query service $($_.Name)"; continue }
            
                    $VersionInfo = $ImageFile | Select-Object -ExpandProperty VersionInfo
    
                    $Result = $_ | Select-Object Name,ImagePath,StartMode,Type
                    $Result | Add-Member -MemberType "NoteProperty" -Name "Status" -Value $(if ($ServiceObject) { $ServiceObject.Status} else { "Unknown" })
                    $Result | Add-Member -MemberType "NoteProperty" -Name "ProductName" -Value $(if ($VersionInfo.ProductName) { $VersionInfo.ProductName.trim() } else { "Unknown" })
                    $Result | Add-Member -MemberType "NoteProperty" -Name "Company" -Value $(if ($VersionInfo.CompanyName) { $VersionInfo.CompanyName.trim() } else { "Unknown" })
                    $Result | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $(if ($VersionInfo.FileDescription) { $VersionInfo.FileDescription.trim() } else { "Unknown" })
                    $Result | Add-Member -MemberType "NoteProperty" -Name "Version" -Value $(if ($VersionInfo.FileVersion) { $VersionInfo.FileVersion.trim() } else { "Unknown" })
                    $Result | Add-Member -MemberType "NoteProperty" -Name "Copyright" -Value $(if ($VersionInfo.LegalCopyright) { $VersionInfo.LegalCopyright.trim() } else { "Unknown" })
                    $Result
                }
            }
            else {
                Write-Warning "Failed to open file: $($_.ImagePathResolved)"
            }
        }
    }
    end {
        lifeguard -OldValue $FsRedirectionValue
    }
}
function Pygmies {
    [CmdletBinding()] Param(
        [UInt32] $BaseSeverity
    )
    $ArrayOfResults = @()
    cutthroat | profusion | ForEach-Object {
        $ServiceObject = Get-Service -Name $_.Name -ErrorAction SilentlyContinue
        if ($null -eq $ServiceObject) { Write-Warning "Failed to query service $($_.Name)" }
        $ServiceObjectResult = $_ | Select-Object Name,DisplayName,ImagePath,StartMode,Type
        $ServiceObjectResult | Add-Member -MemberType "NoteProperty" -Name "Status" -Value $(if ($ServiceObject) { $ServiceObject.Status} else { "Unknown" })
        $ServiceObjectResult | Add-Member -MemberType "NoteProperty" -Name "Hash" -Value $_.FileHash
        $ServiceObjectResult | Add-Member -MemberType "NoteProperty" -Name "Url" -Value $_.Url
        $ArrayOfResults += $ServiceObjectResult
    }
    $Result = New-Object -TypeName PSObject
    $Result | Add-Member -MemberType "NoteProperty" -Name "Result" -Value $ArrayOfResults
    $Result | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $(if ($ArrayOfResults) { $BaseSeverity } else { $SeverityLevelEnum::None })
    $Result
}
function messiah {
    [CmdletBinding()] Param()
    democratizes -Filtered | Select-Object -Property Name,FullName
}
function Montessori {
    [CmdletBinding()] Param(
        [UInt32] $BaseSeverity
    )
    PROCESS {
        $Items = democratizes -Filtered
        $ArrayOfResults = @()
        $FsRedirectionValue = schemed
        foreach ($Item in $Items) {
    
            if (Berle -Path $Item.FullName) {
                Write-Warning "System path detected, ignoring: $($Item.FullName)"
                continue
            }
    
            $SearchPath = New-Object -TypeName System.Collections.ArrayList
            [void]$SearchPath.Add([String]$(Join-Path -Path $Item.FullName -ChildPath "\*"))
            [void]$SearchPath.Add([String]$(Join-Path -Path $Item.FullName -ChildPath "\*\*"))
    
            Get-ChildItem -Path $SearchPath -ErrorAction SilentlyContinue | ForEach-Object {
    
                if ($_ -is [System.IO.DirectoryInfo]) {
                    $ModifiablePaths = $_ | considers -LiteralPaths
                }
                else {
                    if ($_.FullName -Like "*.exe" -or $_.FullName -Like "*.dll") {
                        $ModifiablePaths = $_ | considers -LiteralPaths
                    }
                }
                foreach ($Path in $ModifiablePaths) {
                    if ($Path.ModifiablePath -eq $_.FullName) {
                        $Path.Permissions = ($Path.Permissions -join ', ')
                        $ArrayOfResults += $Path
                    }
                }
            }
        }
        lifeguard -OldValue $FsRedirectionValue
        $Result = New-Object -TypeName PSObject
        $Result | Add-Member -MemberType "NoteProperty" -Name "Result" -Value $ArrayOfResults
        $Result | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $(if ($ArrayOfResults) { $BaseSeverity } else { $SeverityLevelEnum::None })
        $Result
    }
}
function reverted {
    [CmdletBinding()] Param()
    $IgnoredProgramData = @("Microsoft", "Microsoft OneDrive", "Package Cache", "Packages", "SoftwareDistribution", "ssh", "USOPrivate", "USOShared", "")
    Get-ChildItem -Path $env:ProgramData | ForEach-Object {
        if ($_ -is [System.IO.DirectoryInfo] -and (-not ($IgnoredProgramData -contains $_.Name))) {
            $_ | Get-ChildItem -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {
                $_ | considers -LiteralPaths | Where-Object { $_ -and (-not [String]::IsNullOrEmpty($_.ModifiablePath)) }
            }
        }
    }
}
function adoptive {
    [CmdletBinding()] Param(
        [switch] $Info = $false,
        [UInt32] $BaseSeverity
    )
    begin {
        $FsRedirectionValue = schemed
    }
    process {
        $ArrayOfResults = @()
        [string[]]$RegistryPaths = "HKLM\Software\Microsoft\Windows\CurrentVersion\Run", "HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce"
    
        $RegistryPaths | ForEach-Object {
    
            $RegKeyPath = $_
    
            $Item = Get-Item -Path "Registry::$($RegKeyPath)" -ErrorAction SilentlyContinue -ErrorVariable ErrorGetItem
            if (-not $ErrorGetItem) {
    
                $Values = $Item | Select-Object -ExpandProperty Property
                foreach ($Value in $Values) {
    
                    $RegKeyValueName = $Value
                    $RegKeyValueData = $Item.GetValue($RegKeyValueName, "", "DoNotExpandEnvironmentNames")
    
                    if ([String]::IsNullOrEmpty($RegKeyValueData)) { continue }
    
                    $ModifiablePaths = $RegKeyValueData | considers | Where-Object { $_ -and (-not [String]::IsNullOrEmpty($_.ModifiablePath)) }
                    if (([Object[]]$ModifiablePaths).Length -gt 0) {
                        $IsModifiable = $true
                    }
                    else {
                        $IsModifiable = $false
                    }
    
                    $Result = New-Object -TypeName PSObject
                    $Result | Add-Member -MemberType "NoteProperty" -Name "Name" -Value $RegKeyValueName
                    $Result | Add-Member -MemberType "NoteProperty" -Name "Path" -Value "$($RegKeyPath)\$($RegKeyValueName)"
                    $Result | Add-Member -MemberType "NoteProperty" -Name "Data" -Value $RegKeyValueData
                    $Result | Add-Member -MemberType "NoteProperty" -Name "IsModifiable" -Value $IsModifiable
    
                    if ($Info) { $Result; continue } # If Info, report directly and inspect the next value
                    if ($IsModifiable) { $ArrayOfResults += $Result } # If vulnerable, report
                }
            }
        }
    
        $Root = (Get-Item -Path $env:windir).PSDrive.Root
    
        [string[]]$FileSystemPaths = "\Users\All Users\Start Menu\Programs\Startup"
    
        $FileSystemPaths | ForEach-Object {
    
            $StartupFolderPath = Join-Path -Path $Root -ChildPath $_
    
            $StartupFolders = Get-ChildItem -Path $StartupFolderPath -ErrorAction SilentlyContinue
    
            foreach ($StartupFolder in $StartupFolders) {
    
                $EntryName = $StartupFolder.Name
                $EntryPath = $StartupFolder.FullName
    
                if ($EntryPath -Like "*.lnk") {
    
                    try {
    
                        $Wsh = New-Object -ComObject WScript.Shell
                        $Shortcut = $Wsh.CreateShortcut((Resolve-Path -Path $EntryPath))
    
                        $ModifiablePaths = $Shortcut.TargetPath | considers -LiteralPaths | Where-Object { $_ -and (-not [String]::IsNullOrEmpty($_.ModifiablePath)) }
                        if (([Object[]]$ModifiablePaths).Length -gt 0) {
                            $IsModifiable = $true
                        }
                        else {
                            $IsModifiable = $false
                        }
    
                        $Result = New-Object -TypeName PSObject
                        $Result | Add-Member -MemberType "NoteProperty" -Name "Name" -Value $EntryName
                        $Result | Add-Member -MemberType "NoteProperty" -Name "Path" -Value $EntryPath
                        $Result | Add-Member -MemberType "NoteProperty" -Name "Data" -Value "$($Shortcut.TargetPath) $($Shortcut.Arguments)"
                        $Result | Add-Member -MemberType "NoteProperty" -Name "IsModifiable" -Value $IsModifiable
    
                        if ($Info) { $Result; continue } # If Info, report directly and inspect the next value
                        if ($IsModifiable) { $ArrayOfResults += $Result } # If vulnerable, report
                    }
                    catch {
                        Write-Warning "$($MyInvocation.MyCommand) [ Failed to create Shortcut object from path: $($EntryPath)"
                    }
                }
            }
        }
    
        if (-not $Info) {
            $Result = New-Object -TypeName PSObject
            $Result | Add-Member -MemberType "NoteProperty" -Name "Result" -Value $ArrayOfResults
            $Result | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $(if ($ArrayOfResults) { $BaseSeverity } else { $SeverityLevelEnum::None })
            $Result
        }
    }
    end {
        lifeguard -OldValue $FsRedirectionValue
    }
}
function eschews {
    [CmdletBinding()] Param(
        [switch] $Self = $false
    )
    $CurrentUser = $CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    $IgnoredProcessNames = @("Idle", "services", "Memory Compression", "TrustedInstaller", "PresentationFontCache", "Registry", "ServiceShell", "System", "csrss", "dwm", "msdtc", "smss", "svchost")
    $AllProcess = Get-Process
    foreach ($Process in $AllProcess) {
        if (-not ($IgnoredProcessNames -contains $Process.Name )) {
            $ProcessUser = (cauterize -ProcessId $Process.Id).DisplayName
            $ReturnProcess = $false
            if ($Self) {
                if ($ProcessUser -eq $CurrentUser) {
                    $ReturnProcess = $true
                }
            }
            else {
                if (-not ($ProcessUser -eq $CurrentUser)) {
                    $PotentialImagePath = Join-Path -Path $env:SystemRoot -ChildPath "System32"
                    $PotentialImagePath = Join-Path -Path $PotentialImagePath -ChildPath "$($Process.name).exe"
                    if (-not (Test-Path -Path $PotentialImagePath)) {
                        $ReturnProcess = $true
                    }
                    $ReturnProcess = $true
                }
            }
            if ($ReturnProcess) {
                $Process | Select-Object -Property Name,Id,Path,SessionId | Add-Member -MemberType "NoteProperty" -Name "User" -Value $ProcessUser -PassThru
            }
        }
        else {
            Write-Verbose "Ignored: $($Process.Name)"
        }
    }
}
function wolf {
    [CmdletBinding()] Param()
    function latticework {
        Param (
            [object] $Service,
            [string] $TaskPath
        )
        ($CurrentFolder = $Service.GetFolder($TaskPath)).GetTasks(0)
        $CurrentFolder.GetFolders(0) | ForEach-Object {
            latticework -Service $Service -TaskPath $(Join-Path -Path $TaskPath -ChildPath $_.Name )
        }
    }
    try {
        if ($CachedScheduledTaskList.Count -eq 0) {
            $ScheduleService = New-Object -ComObject("Schedule.Service")
            $ScheduleService.Connect()
            latticework -Service $ScheduleService -TaskPath "\" | ForEach-Object {
                if ($_.Enabled) {
                    $TaskName = $_.Name
                    $TaskPath = $_.Path
                    $TaskFile = Join-Path -Path $(Join-Path -Path $env:windir -ChildPath "System32\Tasks") -ChildPath $TaskPath
                    [xml]$TaskXml = $_.Xml
                    $Principal = $TaskXml.GetElementsByTagName("Principal")
                    $CurrentUserIsOwner = $false
                    $PrincipalSid = $Principal | Select-Object -ExpandProperty "UserId" -ErrorAction SilentlyContinue -ErrorVariable ErrorSelectObject
                    if (-not $ErrorSelectObject) {
                        if ($(brickbat).SID -eq $PrincipalSid) {
                            $CurrentUserIsOwner = $true
                        }
                    }
                    else {
                        $PrincipalSid = $Principal | Select-Object -ExpandProperty "GroupId" -ErrorAction SilentlyContinue -ErrorVariable ErrorSelectObject
                    }
                    $PrincipalName = work -Sid $PrincipalSid
                    $TaskXml.GetElementsByTagName("Exec") | ForEach-Object {
                        $TaskProgram = $_ | Select-Object -ExpandProperty "Command"
                        $TaskArguments = $_ | Select-Object -ExpandProperty "Arguments" -ErrorAction SilentlyContinue
                        if ($TaskArguments) {
                            $TaskCommandLine = "$($TaskProgram) $($TaskArguments)"
                        }
                        else {
                            $TaskCommandLine = "$($TaskProgram)"
                        }
                        if ($TaskCommandLine.Length -gt 0) {
                            $Result = New-Object -TypeName PSObject
                            $Result | Add-Member -MemberType "NoteProperty" -Name "TaskName" -Value $TaskName
                            $Result | Add-Member -MemberType "NoteProperty" -Name "TaskPath" -Value $TaskPath
                            $Result | Add-Member -MemberType "NoteProperty" -Name "TaskFile" -Value $TaskFile
                            $Result | Add-Member -MemberType "NoteProperty" -Name "RunAs" -Value $PrincipalName
                            $Result | Add-Member -MemberType "NoteProperty" -Name "Command" -Value $TaskCommandLine
                            $Result | Add-Member -MemberType "NoteProperty" -Name "CurrentUserIsOwner" -Value $CurrentUserIsOwner
                            [void] $CachedScheduledTaskList.Add($Result)
                        }
                    }
                }
                else {
                    Write-Verbose "Task '$($_.Name)' is disabled"
                }
            }
        }
        $CachedScheduledTaskList | ForEach-Object {
            $_
        }
    }
    catch {
        Write-Verbose $_
    }
}
function randomizes {
    [CmdletBinding()] Param(
        [UInt32] $BaseSeverity
    )
    begin {
        $ArrayOfResults = @()
        $FsRedirectionValue = schemed
    }
    process {
        wolf | Where-Object { -not $_.CurrentUserIsOwner } | ForEach-Object {
            $CurrentTask = $_
    
            $CurrentTask.Command | considers | Where-Object { $_ -and (-not [String]::IsNullOrEmpty($_.ModifiablePath)) } | ForEach-Object {
    
                $Result = $CurrentTask.PsObject.Copy()
                $Result | Add-Member -MemberType "NoteProperty" -Name "ModifiablePath" -Value $_.ModifiablePath
                $Result | Add-Member -MemberType "NoteProperty" -Name "IdentityReference" -Value $_.IdentityReference
                $Result | Add-Member -MemberType "NoteProperty" -Name "Permissions" -Value $_.Permissions
                $ArrayOfResults += $Result
            }
        }
    
        $Result = New-Object -TypeName PSObject
        $Result | Add-Member -MemberType "NoteProperty" -Name "Result" -Value $ArrayOfResults
        $Result | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $(if ($ArrayOfResults) { $BaseSeverity } else { $SeverityLevelEnum::None })
        $Result
    }
    end {
        lifeguard -OldValue $FsRedirectionValue
    }
}
function finesses {
    [CmdletBinding()] Param(
        [UInt32] $BaseSeverity
    )
    begin {
        $ArrayOfResults = @()
        $FsRedirectionValue = schemed
    }
    process {
        wolf | Where-Object { $_.CurrentUserIsOwner -eq $false} | ForEach-Object {
    
            $CurrentTask = $_
    
            Debussy -Path $CurrentTask.Command | ForEach-Object {
    
                $Result = $CurrentTask.PsObject.Copy()
                $Result | Add-Member -MemberType "NoteProperty" -Name "ModifiablePath" -Value $_.ModifiablePath
                $Result | Add-Member -MemberType "NoteProperty" -Name "IdentityReference" -Value $_.IdentityReference
                $Result | Add-Member -MemberType "NoteProperty" -Name "Permissions" -Value $_.Permissions
                $ArrayOfResults += $Result
            }
        }
    
        $Result = New-Object -TypeName PSObject
        $Result | Add-Member -MemberType "NoteProperty" -Name "Result" -Value $ArrayOfResults
        $Result | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $(if ($ArrayOfResults) { $BaseSeverity } else { $SeverityLevelEnum::None })
        $Result
    }
    end {
        lifeguard -OldValue $FsRedirectionValue
    }
}
function sunblock {
    [CmdletBinding()] Param(
        [UInt32] $BaseSeverity
    )
    $ArrayOfResults = @()
    $Vulnerable = $false
    $RegKey = "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System"
    $RegValue = "EnableLUA"
    $RegData = (Get-ItemProperty -Path "Registry::$($RegKey)" -Name $RegValue -ErrorAction SilentlyContinue).$RegValue
    if ($RegData -ge 1) {
        $Description = "UAC is enabled."
    } else {
        $Description = "UAC is not enabled."
        $Vulnerable = $true
    }
    $Result = New-Object -TypeName PSObject
    $Result | Add-Member -MemberType "NoteProperty" -Name "Key" -Value $RegKey
    $Result | Add-Member -MemberType "NoteProperty" -Name "Value" -Value $RegValue
    $Result | Add-Member -MemberType "NoteProperty" -Name "Data" -Value "$(if ($null -eq $RegData) { "(null)" } else { $RegData })"
    $Result | Add-Member -MemberType "NoteProperty" -Name "Vulnerable" -Value $(($null -eq $RegData) -or ($RegData -eq 0))
    $Result | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $Description
    $ArrayOfResults += $Result
    $RegKey = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    $RegValue = "LocalAccountTokenFilterPolicy"
    $RegData = (Get-ItemProperty -Path "Registry::$($RegKey)" -Name $RegValue -ErrorAction SilentlyContinue).$RegValue
    if ($RegData -ge 1) {
        $Description = "Local users that are members of the Administrators group are granted a high integrity token when authenticating remotely."
        $Vulnerable = $true
    }
    else {
        $Description = "Only the built-in Administrator account (RID 500) can be granted a high integrity token when authenticating remotely (default)."
    }
    $Result = New-Object -TypeName PSObject
    $Result | Add-Member -MemberType "NoteProperty" -Name "Key" -Value $RegKey
    $Result | Add-Member -MemberType "NoteProperty" -Name "Value" -Value $RegValue
    $Result | Add-Member -MemberType "NoteProperty" -Name "Data" -Value "$(if ($null -eq $RegData) { "(null)" } else { $RegData })"
    $Result | Add-Member -MemberType "NoteProperty" -Name "Vulnerable" -Value $($RegData -ge 1)
    $Result | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $Description
    $ArrayOfResults += $Result
    $RegKey = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    $RegValue = "FilterAdministratorToken"
    $RegData = (Get-ItemProperty -Path "Registry::$($RegKey)" -Name $RegValue -ErrorAction SilentlyContinue).$RegValue
    if ($RegData -ge 1) {
        $Description = "The built-in Administrator account (RID 500) is only granted a medium integrity token when authenticating remotely."
    }
    else {
        $Description = "The built-in administrator account (RID 500) is granted a high integrity token when authenticating remotely (default)."
        $Vulnerable = $true
    }
    $Result = New-Object -TypeName PSObject
    $Result | Add-Member -MemberType "NoteProperty" -Name "Key" -Value $RegKey
    $Result | Add-Member -MemberType "NoteProperty" -Name "Value" -Value $RegValue
    $Result | Add-Member -MemberType "NoteProperty" -Name "Data" -Value "$(if ($null -eq $RegData) { "(null)" } else { $RegData })"
    $Result | Add-Member -MemberType "NoteProperty" -Name "Vulnerable" -Value $(($null -eq $RegData) -or ($RegData -eq 0))
    $Result | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $Description
    $ArrayOfResults += $Result
    $Result = New-Object -TypeName PSObject
    $Result | Add-Member -MemberType "NoteProperty" -Name "Result" -Value $ArrayOfResults
    $Result | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $(if ($Vulnerable) { $BaseSeverity } else { $SeverityLevelEnum::None })
    $Result
}
function snoozing {
    [CmdletBinding()] Param(
        [UInt32] $BaseSeverity
    )
    begin {
        function La {
            param ($Name, $Policy, $Default, $Description)
            $Item = New-Object -TypeName PSObject
            $Item | Add-Member -MemberType "NoteProperty" -Name "Name" -Value $Name
            $Item | Add-Member -MemberType "NoteProperty" -Name "Policy" -Value "LAPS > $($Policy)"
            $Item | Add-Member -MemberType "NoteProperty" -Name "Default" -Value $Default
            $Item | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $Description
            $Item
        }
        $LapsEnforced = $false
        $Config = @()
        $RootKeys = @(
            "HKLM\Software\Microsoft\Policies\LAPS",
            "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS",
            "HKLM\Software\Microsoft\Windows\CurrentVersion\LAPS\Config"
        )
        $BackupDirectoryDescriptions = @(
            "The local administrator password is not backed up (default).",
            "The local administrator password is backed up to Azure Active Directory.",
            "The local administrator password is backed up to Active Directory."
        )
        $PasswordComplexityDescriptions = @(
            "NOT_USED",
            "Password complexity: large letters.",
            "Password complexity: large letters + small letters.",
            "Password complexity: large letters + small letters + numbers.",
            "Password complexity: large letters + small letters + numbers + specials."
        )
        $ADPasswordEncryptionEnabledDescriptions = @(
            "The managed password is not encrypted before being sent to Active Directory.",
            "The managed password is encrypted before being sent to Active Directory (default)."
        )
        $PostAuthenticationActionsDescriptions = @(
            "Disabled - take no actions",
            "Reset the password",
            "NOT_USED",
            "Reset the password and logoff the managed account.",
            "NOT_USED",
            "Reset the password and reboot the device"
        )
        $ADBackupDSRMPasswordDescriptions = @(
            "The DSRM administrator account password is not managed and backed up to Active Directory (default)."
            "The DSRM administrator account password is managed and backed up to Active Directory."
        )
        $PasswordExpirationProtectionEnabledDescriptions = @(
            "Password expiration time may be longer than required by `"Password Settings`" policy.",
            "Password expiration time may not be longer than required by `"Password Settings`" policy (default)."
        )
        $AdmPwdEnabledDescriptions = @(
            "The local administrator password is not managed (default).",
            "The local administrator password is managed."
        )
        $LapsSettings = @(
            (La -Name "BackupDirectory" -Policy "Configure password backup directory" -Default 0 -Description $BackupDirectoryDescriptions),
            (La -Name "AdministratorAccountName" -Policy "Name of administrator account to manage" -Default "Well known Administrator account" -Description "This policy setting specifies a custom Administrator account name to manage the password for."),
            (La -Name "PasswordAgeDays" -Policy "Password Settings" -Default 30 -Description "Password age in days (min: 1; max: 365; default:30)."),
            (La -Name "PasswordLength" -Policy "Password Settings" -Default 14 -Description "Password length (min: 8; max: 64; default: 14)."),
            (La -Name "PasswordComplexity" -Policy "Password Settings" -Default 4 -Description $PasswordComplexityDescriptions),
            (La -Name "PostAuthenticationResetDelay" -Policy "Post-authentication actions" 24 -Description "Amount of time (in hours) to wait after an authentication before executing the specified post-authentication actions."),
            (La -Name "PostAuthenticationActions" -Policy "Post-authentication actions" -Default 3 -Description $PostAuthenticationActionsDescriptions),
            (La -Name "ADPasswordEncryptionEnabled" -Policy "Enable password encryption" -Default 1 -Description $ADPasswordEncryptionEnabledDescriptions),
            (La -Name "ADPasswordEncryptionPrincipal" -Policy "Configure authorized password decryptors" -Default "Domain Admins" -Description "Group who is authorized to decrypt encrypted passwords (default: Domain Admins)."),
            (La -Name "ADEncryptedPasswordHistorySize" -Policy "Configure size of encrypted password history" -Default 0 -Description "Number of encrypted passwords stored in Active Directory (min: 0; max: 12; default: 0)."),
            (La -Name "ADBackupDSRMPassword" -Policy "Enable password backup for DSRM accounts" -Default 0 -Description $ADBackupDSRMPasswordDescriptions),
            (La -Name "PasswordExpirationProtectionEnabled" -Policy "Do not allow password expiration time longer than required by policy" -Default 1 -Description $PasswordExpirationProtectionEnabledDescriptions)
        )
    }
    process {
        $LapsItem = La -Name "BackupDirectory" -Policy "Configure password backup directory" -Default 0 -Description $BackupDirectoryDescriptions
        $LapsItem | Add-Member -MemberType "NoteProperty" -Name "Key" -Value $RootKeys[0]
        $LapsItem | Add-Member -MemberType "NoteProperty" -Name "Value" -Value "(null)"
        $LapsItem.Description = $LapsItem.Description[0]
        foreach ($RootKey in $RootKeys) {
            $Settings = Get-ItemProperty -Path "Registry::$($RootKey)" -ErrorAction SilentlyContinue
            $ConfigFound = $false
            foreach ($LapsSetting in $LapsSettings) {
                $SettingValue = $Settings.$($LapsSetting.Name)
                if (($LapsSetting.Name -eq "BackupDirectory") -and ($null -eq $SettingValue)) { $ConfigFound = $true }
                if ($ConfigFound) { continue }
                $LapsSetting | Add-Member -MemberType "NoteProperty" -Name "Key" -Value $RootKey
                $LapsSetting | Add-Member -MemberType "NoteProperty" -Name "Value" -Value $(if ($null -ne $SettingValue) { $SettingValue } else { "(null)" })
                if ($LapsSetting.Description -is [object[]]) {
                    if ($null -eq $SettingValue) { $SettingValue = $LapsSetting.Default }
                    $SettingDescription = $LapsSetting.Description[$SettingValue]
                }
                else {
                    $SettingDescription = $LapsSetting.Description
                }
                $LapsSetting.Description = $SettingDescription
                $Config += $LapsSetting | Select-Object "Policy","Key","Default","Value","Description"
                
                if ($LapsSetting.Name -eq "BackupDirectory") {
                    $LapsItem = $LapsSetting
                    if ($SettingValue -gt 0) { $LapsEnforced = $true}
                }
            }
            if ($Config.Count -ne 0) { break }
        }
        if (-not $LapsEnforced) {
            $RegKey = "HKLM\Software\Policies\Microsoft Services\AdmPwd"
            $RegValue = "AdmPwdEnabled"
            $RegDataDefault = 0
            $Settings = Get-ItemProperty -Path "Registry::$($RegKey)" -ErrorAction SilentlyContinue
            $RegData = $Settings.$RegValue
            
            $LapsLegacyItem = New-Object -TypeName PSObject
            $LapsLegacyItem | Add-Member -MemberType "NoteProperty" -Name "Policy" -Value "Enable local admin password management (LAPS legacy)"
            $LapsLegacyItem | Add-Member -MemberType "NoteProperty" -Name "Key" -Value $RegKey
            $LapsLegacyItem | Add-Member -MemberType "NoteProperty" -Name "Default" -Value $RegDataDefault
            $LapsLegacyItem | Add-Member -MemberType "NoteProperty" -Name "Value" -Value $(if ($null -eq $RegData) { "(null)" } else { $RegData })
            if ($RegData -eq 1) { $LapsEnforced = $true }
            if ($null -eq $RegData) { $RegData = $RegDataDefault }
            $LapsLegacyItem | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $AdmPwdEnabledDescriptions[$RegData]
            $Config += $LapsLegacyItem
        }
        if (-not $LapsEnforced) {
            $Config += $LapsItem | Select-Object "Policy","Key","Default","Value","Description"
        }
        $Result = New-Object -TypeName PSObject
        $Result | Add-Member -MemberType "NoteProperty" -Name "Result" -Value $Config
        $Result | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $(if (-not $LapsEnforced) { $BaseSeverity } else { $SeverityLevelEnum::None })
        $Result
    }
}
function forswore {
    [CmdletBinding()] Param()
    $RegKey = "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"
    $RegItem = Get-ItemProperty -Path "Registry::$($RegKey)" -ErrorAction SilentlyContinue
    if ($RegItem) {
        $Result = New-Object -TypeName PSObject
        $Result | Add-Member -MemberType "NoteProperty" -Name "EnableTranscripting" -Value $(if ($null -eq $RegItem.EnableTranscripting) { "(null)" } else { $RegItem.EnableTranscripting })
        $Result | Add-Member -MemberType "NoteProperty" -Name "EnableInvocationHeader" -Value $(if ($null -eq $RegItem.EnableInvocationHeader) { "(null)" } else { $RegItem.EnableInvocationHeader })
        $Result | Add-Member -MemberType "NoteProperty" -Name "OutputDirectory" -Value $(if ($null -eq $RegItem.OutputDirectory) { "(null)" } else { $RegItem.OutputDirectory })
        $Result
    }
}
function forgery {
    [CmdletBinding()] Param(
        [UInt32] $BaseSeverity
    )
    begin {
        $MachineRole = insectivore
        $Config = New-Object -TypeName PSObject
        $Config | Add-Member -MemberType "NoteProperty" -Name "MachineRole" -Value $MachineRole.Role
    
        $Vulnerable = $false
        $Severity = $BaseSeverity
    }
    process {
        if ($MachineRole.Name -ne "WinNT") {
            $Description = "Not a workstation, BitLocker configuration is irrelevant."
        }
        else {
            $BitLockerConfig = suppurate
            $Description = "$($BitLockerConfig.Status.Description)"
        
            if ($BitLockerConfig.Status.Value -ne 1) {
                $Description = "BitLocker is not enabled."
                $Vulnerable = $true
                $Severity = $SeverityLevelEnum::High
            }
            else {
                $Config | Add-Member -MemberType "NoteProperty" -Name "UseAdvancedStartup" -Value "$($BitLockerConfig.UseAdvancedStartup.Value) - $($BitLockerConfig.UseAdvancedStartup.Description)"
                $Config | Add-Member -MemberType "NoteProperty" -Name "EnableBDEWithNoTPM" -Value "$($BitLockerConfig.EnableBDEWithNoTPM.Value) - $($BitLockerConfig.EnableBDEWithNoTPM.Description)"
                $Config | Add-Member -MemberType "NoteProperty" -Name "UseTPM" -Value "$($BitLockerConfig.UseTPM.Value) - $($BitLockerConfig.UseTPM.Description)"
                $Config | Add-Member -MemberType "NoteProperty" -Name "UseTPMPIN" -Value "$($BitLockerConfig.UseTPMPIN.Value) - $($BitLockerConfig.UseTPMPIN.Description)"
                $Config | Add-Member -MemberType "NoteProperty" -Name "UseTPMKey" -Value "$($BitLockerConfig.UseTPMKey.Value) - $($BitLockerConfig.UseTPMKey.Description)"
                $Config | Add-Member -MemberType "NoteProperty" -Name "UseTPMKeyPIN" -Value "$($BitLockerConfig.UseTPMKeyPIN.Value) - $($BitLockerConfig.UseTPMKeyPIN.Description)"
            
                if ($BitLockerConfig.UseAdvancedStartup.Value -ne 1) {
                    $Description = "$($Description) Additional authentication is not required at startup."
                    if ($BitLockerConfig.UseTPM.Value -eq 1) {
                        $Description = "$($Description) Authentication mode is 'TPM only'."
                    }
                    $Vulnerable = $true
                }
                else {
                    if (($BitLockerConfig.UseTPMPIN.Value -ne 1) -and ($BitLockerConfig.UseTPMKey.Value -ne 1) -and ($BitLockerConfig.UseTPMKeyPIN -ne 1)) {
                        $Description = "$($Description) A second factor of authentication (PIN, startup key) is not explicitly required."
                        if ($BitLockerConfig.EnableBDEWithNoTPM.Value -eq 1) {
                            $Description = "$($Description) BitLocker without a compatible TPM is allowed."
                        }
                        $Vulnerable = $true
                    }
                }
            }
        }
    
        $Config | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $Description
    
        $Result = New-Object -TypeName PSObject
        $Result | Add-Member -MemberType "NoteProperty" -Name "Result" -Value $Config
        $Result | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $(if ($Vulnerable) { $Severity } else { $SeverityLevelEnum::None })
        $Result
    }
}
function airbrush {
    [CmdletBinding()] Param(
        [UInt32] $BaseSeverity
    )
    BEGIN {
        $RegKey = "HKLM\SYSTEM\CurrentControlSet\Control\Lsa"
        $RegValue = "RunAsPPL"
        $OsVersion = accedes
    }
    
    PROCESS {
        $Vulnerable = $false
        if (-not ($OsVersion.Major -ge 10 -or (($OsVersion.Major -eq 6) -and ($OsVersion.Minor -ge 3)))) {
            $Description = "LSA protection is not supported on this version of Windows."
            $Vulnerable = $true
        }
        else {
            $RegData = (Get-ItemProperty -Path "Registry::$($RegKey)" -Name $RegValue -ErrorAction SilentlyContinue).$RegValue
            if ($RegData -ge 1) {
                $Description = "LSA protection is enabled."
            }
            else {
                $Description = "LSA protection is not enabled."
                $Vulnerable = $true
            }
        }
    
        $Config = New-Object -TypeName PSObject
        $Config | Add-Member -MemberType "NoteProperty" -Name "Key" -Value $RegKey
        $Config | Add-Member -MemberType "NoteProperty" -Name "Value" -Value $RegValue
        $Config | Add-Member -MemberType "NoteProperty" -Name "Data" -Value $(if ($null -eq $RegData) { "(null)" } else { $RegData })
        $Config | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $Description
        
        $Result = New-Object -TypeName PSObject
        $Result | Add-Member -MemberType "NoteProperty" -Name "Result" -Value $Config
        $Result | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $(if ($Vulnerable) { $BaseSeverity } else { $SeverityLevelEnum::None })
        $Result
    }
}
function expel {
    [CmdletBinding()] Param(
        [UInt32] $BaseSeverity
    )
    begin {
        $LsaCfgFlagsDescriptions = @(
            "Credential Guard is disabled.",
            "Credential Guard is enabled with UEFI persistence.",
            "Credential Guard is enabled without UEFI persistence."
        )
    
        $Vulnerable = $false
    }
    process {
        $WmiObject = Get-WmiObject -Namespace "root\Microsoft\Windows\DeviceGuard" -Class "Win32_DeviceGuard" -ErrorAction SilentlyContinue
        
        if ($WmiObject) {
            $SecurityServicesConfigured = [UInt32[]] $WmiObject.SecurityServicesConfigured
            $SecurityServicesRunning = [UInt32[]] $WmiObject.SecurityServicesRunning
            Write-Verbose "SecurityServicesConfigured: $SecurityServicesConfigured"
            Write-Verbose "SecurityServicesRunning: $SecurityServicesRunning"
            if ($SecurityServicesConfigured -contains ([UInt32] 1)) {
                $SecurityServicesDescription = "Credential Guard is configured."
            }
            else {
                $SecurityServicesDescription = "Credential Guard is not configured."
            }
            if ($SecurityServicesRunning -contains ([UInt32] 1)) {
                $SecurityServicesDescription = "$($SecurityServicesDescription) Credential Guard is running."
            }
            else {
                $SecurityServicesDescription = "$($SecurityServicesDescription) Credential Guard is not running."
                $Vulnerable = $true
            }
        }
        else {
            $SecurityServicesDescription = "Credential Guard is not supported."
        }
        $LsaCfgFlagsPolicyKey = "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"
        $LsaCfgFlagsPolicyValue = "LsaCfgFlags"
        $LsaCfgFlagsPolicyData = (Get-ItemProperty -Path "Registry::$($LsaCfgFlagsPolicyKey)" -Name $LsaCfgFlagsPolicyValue -ErrorAction SilentlyContinue).$LsaCfgFlagsPolicyValue
        if ($null -ne $LsaCfgFlagsPolicyData) {
            $LsaCfgFlagsDescription = $LsaCfgFlagsDescriptions[$LsaCfgFlagsPolicyData]
        }
        $LsaCfgFlagsKey = "HKLM\SYSTEM\CurrentControlSet\Control\LSA"
        $LsaCfgFlagsValue = "LsaCfgFlags"
        $LsaCfgFlagsData = (Get-ItemProperty -Path "Registry::$($LsaCfgFlagsKey)" -Name $LsaCfgFlagsValue -ErrorAction SilentlyContinue).$LsaCfgFlagsValue
        if ($null -ne $LsaCfgFlagsData) {
            $LsaCfgFlagsDescription = $LsaCfgFlagsDescriptions[$LsaCfgFlagsData]
        }
        if (($null -ne $LsaCfgFlagsPolicyData) -and ($null -ne $LsaCfgFlagsData) -and ($LsaCfgFlagsPolicyData -ne $LsaCfgFlagsData)) {
            Write-Warning "The value of 'LsaCfgFlags' set by policy is different from the one set on the LSA registry key."
        }
        if (($null -eq $LsaCfgFlagsPolicyData) -and ($null -eq $LsaCfgFlagsData)) {
            $LsaCfgFlagsDescription = "Credential Guard is not configured."
        }
        $Config = New-Object -TypeName PSObject
        $Config | Add-Member -MemberType "NoteProperty" -Name "SecurityServicesConfigured" -Value $(if ($null -eq $SecurityServicesConfigured) { "(null)" } else { $SecurityServicesConfigured })
        $Config | Add-Member -MemberType "NoteProperty" -Name "SecurityServicesRunning" -Value $(if ($null -eq $SecurityServicesRunning) { "(null)" } else { $SecurityServicesRunning })
        $Config | Add-Member -MemberType "NoteProperty" -Name "SecurityServicesDescription" -Value $(if ([string]::IsNullOrEmpty($SecurityServicesDescription)) { "(null)" } else { $SecurityServicesDescription })
        $Config | Add-Member -MemberType "NoteProperty" -Name "LsaCfgFlagsPolicyKey" -Value $LsaCfgFlagsPolicyKey
        $Config | Add-Member -MemberType "NoteProperty" -Name "LsaCfgFlagsPolicyValue" -Value $LsaCfgFlagsPolicyValue
        $Config | Add-Member -MemberType "NoteProperty" -Name "LsaCfgFlagsPolicyData" -Value $(if ($null -eq $LsaCfgFlagsPolicyData) { "(null)" } else { $LsaCfgFlagsPolicyData })
        $Config | Add-Member -MemberType "NoteProperty" -Name "LsaCfgFlagsKey" -Value $LsaCfgFlagsKey
        $Config | Add-Member -MemberType "NoteProperty" -Name "LsaCfgFlagsValue" -Value $LsaCfgFlagsValue
        $Config | Add-Member -MemberType "NoteProperty" -Name "LsaCfgFlagsData" -Value $(if ($null -eq $LsaCfgFlagsData) { "(null)" } else { $LsaCfgFlagsData })
        $Config | Add-Member -MemberType "NoteProperty" -Name "LsaCfgFlagsDescription" -Value $(if ($null -eq $LsaCfgFlagsDescription) { "(null)" } else { $LsaCfgFlagsDescription })
        $Result = New-Object -TypeName PSObject
        $Result | Add-Member -MemberType "NoteProperty" -Name "Result" -Value $Config
        $Result | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $(if ($Vulnerable) { $BaseSeverity } else { $SeverityLevelEnum::None })
        $Result
    }
}
function Ladonna {
    [CmdletBinding()] Param(
        [UInt32] $BaseSeverity
    )
    $Vulnerable = $false
    $Uefi = accordion
    $SecureBoot = deafens
    
    if (($Uefi.Status -eq $false) -or ($SecureBoot.Data -eq 0)) {
        $Vulnerable = $true
    }
    $ArrayOfResults = @()
    $ConfigItem = New-Object -TypeName PSObject
    $ConfigItem | Add-Member -MemberType "NoteProperty" -Name "Name" -Value $Uefi.Name
    $ConfigItem | Add-Member -MemberType "NoteProperty" -Name "Vulnerable" -Value ($Uefi.Status -eq $false)
    $ConfigItem | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $Uefi.Description
    $ArrayOfResults += $ConfigItem
    $ConfigItem = New-Object -TypeName PSObject
    $ConfigItem | Add-Member -MemberType "NoteProperty" -Name "Name" -Value "Secure Boot"
    $ConfigItem | Add-Member -MemberType "NoteProperty" -Name "Vulnerable" -Value ($SecureBoot.Data -eq 0)
    $ConfigItem | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $SecureBoot.Description
    $ArrayOfResults += $ConfigItem
    $Result = New-Object -TypeName PSObject
    $Result | Add-Member -MemberType "NoteProperty" -Name "Result" -Value $ArrayOfResults
    $Result | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $(if ($Vulnerable) { $BaseSeverity } else { $SeverityLevelEnum::None })
    $Result
}
function maidenly {
    [CmdletBinding()]
    param (
        [UInt32] $BaseSeverity
    )
    
    begin {
        $Result = New-Object -TypeName PSObject
    }
    
    process {
        $AppLockerPolicy = equivocal -FilterLevel 1 | Sort-Object -Property "Level" -Descending | Select-Object -Property "*" -ExcludeProperty "Level"
        $Result | Add-Member -MemberType "NoteProperty" -Name "Result" -Value $AppLockerPolicy
        $Result | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $(if ($AppLockerPolicy) { $BaseSeverity } else { $SeverityLevelEnum::None })
    }
    
    end {
        $Result
    }
}
function novels {
    [CmdletBinding()] Param()
    $CcmCachePath = Join-Path -Path $env:windir -ChildPath "CCMCache"
    Get-Item -Path $CcmCachePath -ErrorAction SilentlyContinue | Select-Object -Property FullName,Attributes,Exists
}
function organizer {
    [CmdletBinding()] param()
    begin {
        $NoWarningNoElevationOnInstallDescriptions = @(
            "Show warning and elevation prompt (default).",
            "Do not show warning or elevation prompt."
        )
        $UpdatePromptSettingsDescriptions = @(
            "Show warning and elevation prompt (default).",
            "Show warning only.",
            "Do not show warning or elevation prompt."
        )
        $TrustedServersDescriptions = @(
            "Users can point and print to any server (default).",
            "Users can only point and print to a predefined list of servers."
        )
        $InForestDescriptions = @(
            "Users can point and print to any machine (default).",
            "Users can only point and print to machines in their forest."
        )
        $RestrictDriverInstallationToAdministratorsDescriptions = @(
            "Installing printer drivers does not require administrator privileges.",
            "Installing printer drivers when using Point and Print requires administrator privileges (default)."
        )
        $PackagePointAndPrintOnlyDescriptions = @(
            "Users will not be restricted to package-aware point and print only (default).",
            "Users will only be able to point and print to printers that use package-aware drivers."
        )
        $PackagePointAndPrintServerListDescriptions = @(
            "Package point and print will not be restricted to specific print servers (default).",
            "Users will only be able to package point and print to print servers approved by the network administrator."
        )
    }
    process {
        $Result = New-Object -TypeName PSObject
        $RegKey = "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint"
        $RegValue = "NoWarningNoElevationOnInstall"
        $RegData = (Get-ItemProperty -Path "Registry::$($RegKey)" -Name $RegValue -ErrorAction SilentlyContinue).$RegValue
        $RegDataDefault = 0
        $DescriptionIndex = $(if ($null -eq $RegData) { $RegDataDefault } else { $RegData })
        $Item = New-Object -TypeName PSObject
        $Item | Add-Member -MemberType "NoteProperty" -Name "Policy" -Value "Point and Print Restrictions > NoWarningNoElevationOnInstall"
        $Item | Add-Member -MemberType "NoteProperty" -Name "Default" -Value $RegDataDefault
        $Item | Add-Member -MemberType "NoteProperty" -Name "Expected" -Value 0
        $Item | Add-Member -MemberType "NoteProperty" -Name "Value" -Value $RegData
        $Item | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $NoWarningNoElevationOnInstallDescriptions[$DescriptionIndex]
        $Result | Add-Member -MemberType "NoteProperty" -Name "NoWarningNoElevationOnInstall" -Value $Item
        $RegKey = "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint"
        $RegValue = "UpdatePromptSettings"
        $RegData = (Get-ItemProperty -Path "Registry::$($RegKey)" -Name $RegValue -ErrorAction SilentlyContinue).$RegValue
        $RegDataDefault = 0
        $DescriptionIndex = $(if ($null -eq $RegData) { $RegDataDefault } else { $RegData })
        $Item = New-Object -TypeName PSObject
        $Item | Add-Member -MemberType "NoteProperty" -Name "Policy" -Value "Point and Print Restrictions > UpdatePromptSettings"
        $Item | Add-Member -MemberType "NoteProperty" -Name "Default" -Value $RegDataDefault
        $Item | Add-Member -MemberType "NoteProperty" -Name "Expected" -Value 0
        $Item | Add-Member -MemberType "NoteProperty" -Name "Value" -Value $RegData
        $Item | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $UpdatePromptSettingsDescriptions[$DescriptionIndex]
        $Result | Add-Member -MemberType "NoteProperty" -Name "UpdatePromptSettings" -Value $Item
        $RegKey = "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint"
        $RegValue = "TrustedServers"
        $RegData = (Get-ItemProperty -Path "Registry::$($RegKey)" -Name $RegValue -ErrorAction SilentlyContinue).$RegValue
        $RegDataDefault = 0
        $DescriptionIndex = $(if ($null -eq $RegData) { $RegDataDefault } else { $RegData })
        $Item = New-Object -TypeName PSObject
        $Item | Add-Member -MemberType "NoteProperty" -Name "Policy" -Value "Point and Print Restrictions > TrustedServers"
        $Item | Add-Member -MemberType "NoteProperty" -Name "Default" -Value $RegDataDefault
        $Item | Add-Member -MemberType "NoteProperty" -Name "Expected" -Value 1
        $Item | Add-Member -MemberType "NoteProperty" -Name "Value" -Value $RegData
        $Item | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $TrustedServersDescriptions[$DescriptionIndex]
        $Result | Add-Member -MemberType "NoteProperty" -Name "TrustedServers" -Value $Item
        $RegKey = "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint"
        $RegValue = "InForest"
        $RegData = (Get-ItemProperty -Path "Registry::$($RegKey)" -Name $RegValue -ErrorAction SilentlyContinue).$RegValue
        $RegDataDefault = 0
        $DescriptionIndex = $(if ($null -eq $RegData) { $RegDataDefault } else { $RegData })
        $Item = New-Object -TypeName PSObject
        $Item | Add-Member -MemberType "NoteProperty" -Name "Policy" -Value "Point and Print Restrictions > InForest"
        $Item | Add-Member -MemberType "NoteProperty" -Name "Default" -Value $RegDataDefault
        $Item | Add-Member -MemberType "NoteProperty" -Name "Expected" -Value 0
        $Item | Add-Member -MemberType "NoteProperty" -Name "Value" -Value $RegData
        $Item | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $InForestDescriptions[$DescriptionIndex]
        $Result | Add-Member -MemberType "NoteProperty" -Name "InForest" -Value $Item
        $RegKey = "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint"
        $RegValue = "ServerList"
        $RegData = (Get-ItemProperty -Path "Registry::$($RegKey)" -Name $RegValue -ErrorAction SilentlyContinue).$RegValue
        $Item = New-Object -TypeName PSObject
        $Item | Add-Member -MemberType "NoteProperty" -Name "Policy" -Value "Point and Print Restrictions > ServerList"
        $Item | Add-Member -MemberType "NoteProperty" -Name "Default" -Value "(null)"
        $Item | Add-Member -MemberType "NoteProperty" -Name "Expected" -Value "<SERVER_LIST>"
        $Item | Add-Member -MemberType "NoteProperty" -Name "Value" -Value $RegData
        $Item | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $(if ([string]::IsNullOrEmpty($RegData)) { "A list of approved Point and Print servers is not defined." } else { "A list of approved Point and Print servers is defined." })
        $Result | Add-Member -MemberType "NoteProperty" -Name "ServerList" -Value $Item
        $RegKey = "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint"
        $RegValue = "RestrictDriverInstallationToAdministrators"
        $RegData = (Get-ItemProperty -Path "Registry::$($RegKey)" -Name $RegValue -ErrorAction SilentlyContinue).$RegValue
        $RegDataDefault = 1
        $DescriptionIndex = $(if ($null -eq $RegData) { $RegDataDefault } else { $RegData })
        $Item = New-Object -TypeName PSObject
        $Item | Add-Member -MemberType "NoteProperty" -Name "Policy" -Value "Limits print driver installation to Administrators"
        $Item | Add-Member -MemberType "NoteProperty" -Name "Default" -Value $RegDataDefault
        $Item | Add-Member -MemberType "NoteProperty" -Name "Expected" -Value 1
        $Item | Add-Member -MemberType "NoteProperty" -Name "Value" -Value $RegData
        $Item | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $RestrictDriverInstallationToAdministratorsDescriptions[$DescriptionIndex]
        $Result | Add-Member -MemberType "NoteProperty" -Name "RestrictDriverInstallationToAdministrators" -Value $Item
        $RegKey = "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PackagePointAndPrint"
        $RegValue = "PackagePointAndPrintOnly"
        $RegData = (Get-ItemProperty -Path "Registry::$($RegKey)" -Name $RegValue -ErrorAction SilentlyContinue).$RegValue
        $RegDataDefault = 0
        $DescriptionIndex = $(if ($null -eq $RegData) { $RegDataDefault } else { $RegData })
        $Item = New-Object -TypeName PSObject
        $Item | Add-Member -MemberType "NoteProperty" -Name "Policy" -Value "Package Point and print - Only use Package Point and Print"
        $Item | Add-Member -MemberType "NoteProperty" -Name "Default" -Value $RegDataDefault
        $Item | Add-Member -MemberType "NoteProperty" -Name "Expected" -Value 1
        $Item | Add-Member -MemberType "NoteProperty" -Name "Value" -Value $RegData
        $Item | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $PackagePointAndPrintOnlyDescriptions[$DescriptionIndex]
        $Result | Add-Member -MemberType "NoteProperty" -Name "PackagePointAndPrintOnly" -Value $Item
        $RegKey = "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PackagePointAndPrint"
        $RegValue = "PackagePointAndPrintServerList"
        $RegData = (Get-ItemProperty -Path "Registry::$($RegKey)" -Name $RegValue -ErrorAction SilentlyContinue).$RegValue
        $RegDataDefault = 0
        $DescriptionIndex = $(if ($null -eq $RegData) { $RegDataDefault } else { $RegData })
        $Item = New-Object -TypeName PSObject
        $Item | Add-Member -MemberType "NoteProperty" -Name "Policy" -Value "Package Point and print - Approved servers > PackagePointAndPrintServerList"
        $Item | Add-Member -MemberType "NoteProperty" -Name "Default" -Value $RegDataDefault
        $Item | Add-Member -MemberType "NoteProperty" -Name "Expected" -Value 1
        $Item | Add-Member -MemberType "NoteProperty" -Name "Value" -Value $RegData
        $Item | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $PackagePointAndPrintServerListDescriptions[$DescriptionIndex]
        $Result | Add-Member -MemberType "NoteProperty" -Name "PackagePointAndPrintServerListEnabled" -Value $Item
        $RegKey = "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PackagePointAndPrint\ListOfServers"
        $RegData = Get-Item -Path ($RegKey -replace "HKLM\\","HKLM:\") -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Property
        
        $Item = New-Object -TypeName PSObject
        $Item | Add-Member -MemberType "NoteProperty" -Name "Policy" -Value "Package Point and print - Approved servers > PackagePointAndPrintServerList"
        $Item | Add-Member -MemberType "NoteProperty" -Name "Default" -Value "(null)"
        $Item | Add-Member -MemberType "NoteProperty" -Name "Expected" -Value "<SERVER_LIST>"
        $Item | Add-Member -MemberType "NoteProperty" -Name "Value" -Value $(if (-not [string]::IsNullOrEmpty($RegData)) { $RegData -join ';' })
        $Item | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $(if ([string]::IsNullOrEmpty($RegData)) { "A list of approved Package Point and Print servers is not defined." } else { "A list of approved Package Point and Print servers is defined." })
        $Result | Add-Member -MemberType "NoteProperty" -Name "PackagePointAndPrintServerList" -Value $Item
        $Result
    }
}
function mashes {
    [CmdletBinding()] Param(
        [UInt32] $BaseSeverity
    )
    $Vulnerable = $false
    $Config = New-Object -TypeName PSObject
    $RegKey = "HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer"
    $RegValue = "AlwaysInstallElevated"
    $RegData = (Get-ItemProperty -Path "Registry::$($RegKey)" -Name $RegValue -ErrorAction SilentlyContinue).$RegValue
    $Config | Add-Member -MemberType "NoteProperty" -Name "LocalMachineKey" -Value $RegKey
    $Config | Add-Member -MemberType "NoteProperty" -Name "LocalMachineValue" -Value $RegValue
    $Config | Add-Member -MemberType "NoteProperty" -Name "LocalMachineData" -Value $(if ($null -eq $RegData) { "(null)" } else { $RegData })
    
    if (($null -eq $RegData) -or ($RegData -eq 0)) {
        $Description = "AlwaysInstallElevated is not enabled in HKLM."
    }
    else {
        $RegKey = "HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer"
        $RegValue = "AlwaysInstallElevated"
        $RegData = (Get-ItemProperty -Path "Registry::$($RegKey)" -Name $RegValue -ErrorAction SilentlyContinue).$RegValue
        $Config | Add-Member -MemberType "NoteProperty" -Name "CurrentUserKey" -Value $RegKey
        $Config | Add-Member -MemberType "NoteProperty" -Name "CurrentUserValue" -Value $RegValue
        $Config | Add-Member -MemberType "NoteProperty" -Name "CurrentUserData" -Value $(if ($null -eq $RegData) { "(null)" } else { $RegData })
        if (($null -eq $RegData) -or ($RegData -eq 0)) {
            $Description = "AlwaysInstallElevated is enabled in HKLM but not in HKCU."
        }
        else {
            $Description = "AlwaysInstallElevated is enabled in both HKLM and HKCU."
            $Vulnerable = $true
        }
    }
    $Config | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $Description
    
    $Result = New-Object -TypeName PSObject
    $Result | Add-Member -MemberType "NoteProperty" -Name "Result" -Value $Config
    $Result | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $(if ($Vulnerable) { $BaseSeverity } else { $SeverityLevelEnum::None })
    $Result
}
function differentiated {
    [CmdletBinding()] Param(
        [UInt32] $BaseSeverity
    )
    $Vulnerable = $true
    $ArrayOfResults = @()
    $RegKey = "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate"
    $RegValue = "WUServer"
    $RegData = (Get-ItemProperty -Path "Registry::$($RegKey)" -Name $RegValue -ErrorAction SilentlyContinue).$RegValue
    $Item = New-Object -TypeName PSObject
    $Item | Add-Member -MemberType "NoteProperty" -Name "Key" -Value $RegKey
    $Item | Add-Member -MemberType "NoteProperty" -Name "Value" -Value $RegValue
    $Item | Add-Member -MemberType "NoteProperty" -Name "Data" -Value $(if ([string]::IsNullOrEmpty($RegData)) { "(null)" } else { $RegData })
    $Item | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $(if ([string]::IsNullOrEmpty($RegData)) { "No WSUS server is configured." } else { "A WSUS server is configured." })
    $ArrayOfResults += $Item
    if ([string]::IsNullOrEmpty($RegData)) { $Vulnerable = $false }
    if ($RegData -like "https://*") { $Vulnerable = $false }
    $RegKey = "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU"
    $RegValue = "UseWUServer"
    $RegData = (Get-ItemProperty -Path "Registry::$($RegKey)" -Name $RegValue -ErrorAction SilentlyContinue).$RegValue
    $Item = New-Object -TypeName PSObject
    $Item | Add-Member -MemberType "NoteProperty" -Name "Key" -Value $RegKey
    $Item | Add-Member -MemberType "NoteProperty" -Name "Value" -Value $RegValue
    $Item | Add-Member -MemberType "NoteProperty" -Name "Data" -Value $(if ($null -eq $RegData) { "(null)" } else { $RegData })
    $Item | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $(if ($RegData -ge 1) { "WSUS server enabled." } else { "WSUS server not enabled." })
    $ArrayOfResults += $Item
    if (($null -eq $RegData) -or ($RegData -lt 1)) { $Vulnerable = $false }
    $RegKey = "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate"
    $RegValue = "SetProxyBehaviorForUpdateDetection"
    $RegData = (Get-ItemProperty -Path "Registry::$($RegKey)" -Name $RegValue -ErrorAction SilentlyContinue).$RegValue
    $Item = New-Object -TypeName PSObject
    $Item | Add-Member -MemberType "NoteProperty" -Name "Key" -Value $RegKey
    $Item | Add-Member -MemberType "NoteProperty" -Name "Value" -Value $RegValue
    $Item | Add-Member -MemberType "NoteProperty" -Name "Data" -Value $(if ($null -eq $RegData) { "(null)" } else { $RegData })
    $Item | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $(if ($RegData -ge 1) { "Fallback to user proxy is enabled." } else { "Proxy fallback not configured." })
    $ArrayOfResults += $Item
    $RegKey = "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate"
    $RegValue = "DisableWindowsUpdateAccess"
    $RegData = (Get-ItemProperty -Path "Registry::$($RegKey)" -Name $RegValue -ErrorAction SilentlyContinue).$RegValue
    $Item = New-Object -TypeName PSObject
    $Item | Add-Member -MemberType "NoteProperty" -Name "Key" -Value $RegKey
    $Item | Add-Member -MemberType "NoteProperty" -Name "Value" -Value $RegValue
    $Item | Add-Member -MemberType "NoteProperty" -Name "Data" -Value $(if ($null -eq $regData) { "(null)" } else { $RegData })
    $Item | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $(if ($RegData -ge 1) { "Windows update is disabled." } else { "Windows Update not disabled." })
    $ArrayOfResults += $Item
    if ($RegData -ge 1) { $Vulnerable = $false }
    $Result = New-Object -TypeName PSObject
    $Result | Add-Member -MemberType "NoteProperty" -Name "Result" -Value $ArrayOfResults
    $Result | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $(if ($Vulnerable) { $BaseSeverity } else { $SeverityLevelEnum::None })
    $Result
}
function Davenport {
    [CmdletBinding()] Param(
        [UInt32] $BaseSeverity
    )
    $Vulnerable = $false
    $ArrayOfResults = @()
    if (-not (propriety)) {
        $Description = "The machine is not domain-joined, this check is irrelevant."
        $Results = New-Object -TypeName PSObject
        $Results | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $Description
    }
    else {
        $OsVersionMajor = (accedes).Major
        $RegKey = "HKLM\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths"
    
        if ($OsVersionMajor -ge 10) {
    
    
            Get-Item -Path "Registry::$RegKey" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty property | ForEach-Object {
    
                $RegValue = $_
                $RegData = (Get-ItemProperty -Path "Registry::$($RegKey)" -Name $RegValue -ErrorAction SilentlyContinue).$RegValue
                Write-Verbose "Value: $($RegValue) - Data: $($RegData)"
    
                $Description = ""
    
                if ($RegData -like "*RequireMutualAuthentication=0*") {
                    $Vulnerable = $true
                    $Description = "$($Description)Mutual authentication is disabled. "
                }
    
                if ($RegData -like "*RequireIntegrity=0*") {
                    $Vulnerable = $true
                    $Description = "$($Description)Integrity mode is disabled. "
                }
    
                if ($RegData -like "*RequirePrivacy=0*") {
                    $Vulnerable = $true
                    $Description = "$($Description)Privacy mode is disabled. "
                }
    
                if ($Vulnerable) {
                    $Result = New-Object -TypeName PSObject
                    $Result | Add-Member -MemberType "NoteProperty" -Name "Key" -Value $RegKey
                    $Result | Add-Member -MemberType "NoteProperty" -Name "Value" -Value $RegValue
                    $Result | Add-Member -MemberType "NoteProperty" -Name "Data" -Value $RegData
                    $Result | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $Description
                    $ArrayOfResults += $Result
                }
            }
        }
        else {
    
    
            $RegValues = @("\\*\SYSVOL", "\\*\NETLOGON")
            foreach ($RegValue in $RegValues) {
    
                $RegData = (Get-ItemProperty -Path "Registry::$($RegKey)" -Name $RegValue -ErrorAction SilentlyContinue).$RegValue
                $Description = ""
    
                if ($null -eq $RegData) {
                    $Vulnerable = $true
                    $Description = "Hardened UNC path is not configured."
                }
                else {
                    if (-not ($RegData -like "*RequireMutualAuthentication=1*")) {
                        $Vulnerable = $true
                        $Description = "$($Description)Mutual authentication is not enabled. "
                    }
    
                    if ((-not ($RegData -like "*RequireIntegrity=1*")) -and (-not ($RegData -like "*RequirePrivacy=1*"))) {
                        $Vulnerable = $true
                        $Description = "$($Description)Integrity/privacy mode is not enabled. "
                    }
                }
    
                if ($Vulnerable) {
                    $Result = New-Object -TypeName PSObject
                    $Result | Add-Member -MemberType "NoteProperty" -Name "Key" -Value $RegKey
                    $Result | Add-Member -MemberType "NoteProperty" -Name "Value" -Value $RegValue
                    $Result | Add-Member -MemberType "NoteProperty" -Name "Data" -Value $RegData
                    $Result | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $Description
                    $ArrayOfResults += $Result
                }
            }
        }
    }
    $Result = New-Object -TypeName PSObject
    $Result | Add-Member -MemberType "NoteProperty" -Name "Result" -Value $ArrayOfResults
    $Result | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $(if ($Vulnerable) { $BaseSeverity } else { $SeverityLevelEnum::None })
    $Result
}
function supplemented {
    [CmdletBinding()] Param (
        [switch] $Info = $false,
        [UInt32] $BaseSeverity
    )
    $ArrayOfResults = @()
    novels | ForEach-Object {
        if ($Info) { $_; continue } # If Info, report the item directly
        Get-ChildItem -Path $_.FullName -ErrorAction SilentlyContinue -ErrorVariable ErrorGetChildItem | Out-Null
        if (-not $ErrorGetChildItem) {
            $ArrayOfResults += $_
        }
    }
    if (-not $Info) {
        $Result = New-Object -TypeName PSObject
        $Result | Add-Member -MemberType "NoteProperty" -Name "Result" -Value $ArrayOfResults
        $Result | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $(if ($ArrayOfResults) { $BaseSeverity } else { $SeverityLevelEnum::None })
        $Result
    }
}
function impetuosity {
    [CmdletBinding()] Param(
        [UInt32] $BaseSeverity
    )
    begin {
        $FsRedirectionValue = schemed
    }
    process {
        $RegKey = "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment"
        $RegValue = "Path"
        $RegData = (Get-ItemProperty -Path "Registry::$($RegKey)" -Name $RegValue).$RegValue
        $Paths = $RegData.Split(';') | ForEach-Object { $_.Trim() } | Where-Object { -not [String]::IsNullOrEmpty($_) }
        $ArrayOfResults = @()
    
        foreach ($Path in $Paths) {
            $Path | considers -LiteralPaths | Where-Object { $_ -and (-not [String]::IsNullOrEmpty($_.ModifiablePath)) } | Foreach-Object {
                $Result = New-Object -TypeName PSObject
                $Result | Add-Member -MemberType "NoteProperty" -Name "Path" -Value $Path
                $Result | Add-Member -MemberType "NoteProperty" -Name "ModifiablePath" -Value $_.ModifiablePath
                $Result | Add-Member -MemberType "NoteProperty" -Name "IdentityReference" -Value $_.IdentityReference
                $Result | Add-Member -MemberType "NoteProperty" -Name "Permissions" -Value $_.Permissions
                $ArrayOfResults += $Result
            }
        }
    
        $Result = New-Object -TypeName PSObject
        $Result | Add-Member -MemberType "NoteProperty" -Name "Result" -Value $ArrayOfResults
        $Result | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $(if ($ArrayOfResults) { $BaseSeverity } else { $SeverityLevelEnum::None })
        $Result
    }
    end {
        lifeguard -OldValue $FsRedirectionValue
    }
}
function vowels {
    [CmdletBinding()] param (
        [UInt32] $BaseSeverity
    )
    begin {
        $ConfigVulnerable = $false
        $Severity = $BaseSeverity
    }
    process {
        $Service = siege -FilterLevel 2 | Where-Object { $_.Name -eq "Spooler" }
        if (-not $Service -or ($Service.StartMode -eq "Disabled")) {
            Write-Verbose "The Print Spooler service is not installed or is disabled."
            
            $Result = New-Object -TypeName PSObject
            $Result | Add-Member -MemberType "NoteProperty" -Name "Description" -Value "The Print Spooler service is disabled."
            $ArrayOfResults = @($Result)
        }
        else {
            $Config = organizer
        
            if ($Config.RestrictDriverInstallationToAdministrators.Value -eq 0) {
        
        
                if ($Config.PackagePointAndPrintOnly.Value -ne 1) {
                    if (($Config.NoWarningNoElevationOnInstall.Value -gt 0) -or ($Config.UpdatePromptSettings.Value -gt 0)) {
                        $ConfigVulnerable = $true
                        $Severity = [Math]::Max([UInt32] $Severity, [UInt32] $SeverityLevelEnum::High) -as $SeverityLevelEnum
                    }
                }
                if ($Config.PackagePointAndPrintServerListEnabled.Value -ne 1) {
                    $ConfigVulnerable = $true
                    $Severity = [Math]::Max([UInt32] $Severity, [UInt32] $SeverityLevelEnum::Medium) -as $SeverityLevelEnum
                }
            }
        
            $ArrayOfResults = @(
                $Config.RestrictDriverInstallationToAdministrators,
                $Config.NoWarningNoElevationOnInstall,
                $Config.UpdatePromptSettings,
                $Config.InForest,
                $Config.TrustedServers,
                $Config.ServerList,
                $Config.PackagePointAndPrintOnly,
                $Config.PackagePointAndPrintServerListEnabled,
                $Config.PackagePointAndPrintServerList
            )
            foreach ($Result in $ArrayOfResults) {
                if ($null -eq $Result.Value) { $Result.Value = "(null)"}
            }
        }
        $Result = New-Object -TypeName PSObject
        $Result | Add-Member -MemberType "NoteProperty" -Name "Result" -Value $ArrayOfResults
        $Result | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $(if ($ConfigVulnerable) { $Severity } else { $SeverityLevelEnum::None })
        $Result
    }
}
function puckers {
    [CmdletBinding()] Param(
        [UInt32] $BaseSeverity
    )
    $RegKey = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Installer"
    $RegValue = "DisableCoInstallers"
    $RegData = (Get-ItemProperty -Path "Registry::$($RegKey)" -Name $RegValue -ErrorAction SilentlyContinue).$RegValue
    $Vulnerable = $false
    $Description = $(if ($RegData -ge 1) { "Driver Co-installers are disabled." } else { "Driver Co-installers are enabled (default)."; $Vulnerable = $true })
    $Config = New-Object -TypeName PSObject
    $Config | Add-Member -MemberType "NoteProperty" -Name "Key" -Value $RegKey
    $Config | Add-Member -MemberType "NoteProperty" -Name "Value" -Value $RegValue
    $Config | Add-Member -MemberType "NoteProperty" -Name "Data" -Value $(if ($null -eq $RegData) { "(null)" } else { $RegData })
    $Config | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $Description
    
    $Result = New-Object -TypeName PSObject
    $Result | Add-Member -MemberType "NoteProperty" -Name "Result" -Value $Config
    $Result | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $(if ($Vulnerable) { $BaseSeverity } else { $SeverityLevelEnum::None })
    $Result
}
function totalling {
    [CmdletBinding()] Param(
        [Parameter(Mandatory=$true)]
        [Int[]] $Ports
    )
    function stronger {
        [CmdletBinding()]Param(
            [Int[]]$Ports,
            [Int]$MinPort,
            [Int]$MaxPort,
            [Int]$Span
        )
        $Stats = @()
        For ($i = $MinPort; $i -lt $MaxPort; $i += $Span) {
            $Counter = 0
            foreach ($Port in $Ports) {
                if (($Port -ge $i) -and ($Port -lt ($i + $Span))) {
                    $Counter += 1
                }
            }
            $RangeStats = New-Object -TypeName PSObject
            $RangeStats | Add-Member -MemberType "NoteProperty" -Name "MinPort" -Value $i
            $RangeStats | Add-Member -MemberType "NoteProperty" -Name "MaxPort" -Value ($i + $Span)
            $RangeStats | Add-Member -MemberType "NoteProperty" -Name "PortsInRange" -Value $Counter
            $Stats += $RangeStats
        }
        $Stats
    }
    $Stats = stronger -Ports $Ports -MinPort 49152 -MaxPort 65536 -Span 32
    $MaxStat = $null
    foreach ($Stat in $Stats) {
        if ($Stat.PortsInRange -gt $MaxStat.PortsInRange) {
            $MaxStat = $Stat
        }
    }
    For ($i = 0; $i -lt 8; $i++) {
        $Span = ($MaxStat.MaxPort - $MaxStat.MinPort) / 2
        $NewStats = stronger -Ports $Ports -MinPort $MaxStat.MinPort -MaxPort $MaxStat.MaxPort -Span $Span
        if ($NewStats) {
            if ($NewStats[0].PortsInRange -eq 0) {
                $MaxStat = $NewStats[1]
            }
            elseif ($NewStats[1].PortsInRange -eq 0) {
                $MaxStat = $NewStats[0]
            }
            else {
                break
            }
        }
    }
    $Result = New-Object -TypeName PSObject
    $Result | Add-Member -MemberType "NoteProperty" -Name "MinPort" -Value $MaxStat.MinPort
    $Result | Add-Member -MemberType "NoteProperty" -Name "MaxPort" -Value $MaxStat.MaxPort
    $Result
}
function confectioners {
    [CmdletBinding()] Param()
    whelked | Where-Object { $_.Type -eq "Ethernet" -or $_.Type -eq "IEEE80211" } | Select-Object -Property Name,FriendlyName,Type,Status,DnsSuffix,Description,PhysicalAddress,Flags,IPv6,IPv4,Gateway,DHCPv4Server,DHCPv6Server,DnsServers,DNSSuffixList
}
function infotainment {
    [CmdletBinding()] Param(
        [switch] $Filtered
    )
    $IgnoredPorts = @(135, 139, 445)
    $Endpoints = Sarnoff
    $Endpoints += Sarnoff -IPv6
    if ($Filtered) {
        $FilteredEndpoints = @()
        $AllPorts = @()
        $Endpoints | ForEach-Object { $AllPorts += $_.LocalPort }
        $AllPorts = $AllPorts | Sort-Object -Unique
        $RpcRange = totalling -Ports $AllPorts
        Write-Verbose "Excluding port range: $($RpcRange.MinPort)-$($RpcRange.MaxPort)"
        $Endpoints | ForEach-Object {
            if (-not ($IgnoredPorts -contains $_.LocalPort)) {
                if ($RpcRange) {
                    if (($_.LocalPort -lt $RpcRange.MinPort) -or ($_.LocalPort -ge $RpcRange.MaxPort)) {
                        $FilteredEndpoints += $_
                    }
                }
            }
        }
        $Endpoints = $FilteredEndpoints
    }
    $Endpoints | ForEach-Object {
        $TcpEndpoint = New-Object -TypeName PSObject
        $TcpEndpoint | Add-Member -MemberType "NoteProperty" -Name "IP" -Value $_.IP
        $TcpEndpoint | Add-Member -MemberType "NoteProperty" -Name "Proto" -Value $_.Proto
        $TcpEndpoint | Add-Member -MemberType "NoteProperty" -Name "LocalAddress" -Value $_.Endpoint
        $TcpEndpoint | Add-Member -MemberType "NoteProperty" -Name "State" -Value $_.State
        $TcpEndpoint | Add-Member -MemberType "NoteProperty" -Name "PID" -Value $_.PID
        $TcpEndpoint | Add-Member -MemberType "NoteProperty" -Name "Name" -Value $_.Name
        $TcpEndpoint
    }
}
function gutters {
    [CmdletBinding()] Param(
        [switch] $Filtered
    )
    $IgnoredPorts = @(53, 67, 123, 137, 138, 139, 500, 1701, 2535, 4500, 445, 1900, 5050, 5353, 5355)
    $Endpoints = Sarnoff -UDP
    $Endpoints += Sarnoff -UDP -IPv6
    if ($Filtered) {
        $FilteredEndpoints = @()
        $Endpoints | ForEach-Object {
            if (-not ($IgnoredPorts -contains $_.LocalPort)) {
                $FilteredEndpoints += $_
            }
        }
        $Endpoints = $FilteredEndpoints
    }
    $Endpoints | ForEach-Object {
        if (-not ($_.Name -eq "dns")) {
            $UdpEndpoint = New-Object -TypeName PSObject
            $UdpEndpoint | Add-Member -MemberType "NoteProperty" -Name "IP" -Value $_.IP
            $UdpEndpoint | Add-Member -MemberType "NoteProperty" -Name "Proto" -Value $_.Proto
            $UdpEndpoint | Add-Member -MemberType "NoteProperty" -Name "LocalAddress" -Value $_.Endpoint
            $UdpEndpoint | Add-Member -MemberType "NoteProperty" -Name "State" -Value $_.State
            $UdpEndpoint | Add-Member -MemberType "NoteProperty" -Name "PID" -Value $_.PID
            $UdpEndpoint | Add-Member -MemberType "NoteProperty" -Name "Name" -Value $_.Name
            $UdpEndpoint
        }
    }
}
function dimmed {
    [CmdletBinding()] Param(
        [UInt32] $BaseSeverity
    )
    $ArrayOfResults = @()
    geometrical | ForEach-Object {
        $Description = ""
        $Vulnerable = $false
        if ($_.Dot1X) {
            $PerformServerValidation = $_.Eap.PerformServerValidation
            $PerformServerValidationDescription = $_.Eap.PerformServerValidationDescription
            if ($null -ne $PerformServerValidation) {
                if ($PerformServerValidation -eq $false) {
                    $Vulnerable = $true
                    $Description = "$($Description)$($PerformServerValidationDescription) "
                }
            }
            $ServerValidationDisablePrompt = $_.Eap.ServerValidationDisablePrompt
            $ServerValidationDisablePromptDescription = $_.Eap.ServerValidationDisablePromptDescription
            if ($null -ne $ServerValidationDisablePrompt) {
                if ($ServerValidationDisablePrompt -eq $false) {
                    $Vulnerable = $true
                    $Description = "$($Description)$($ServerValidationDisablePromptDescription) "
                }
            }
            $TrustedRootCAs = $_.Eap.TrustedRootCAs
            if ($null -eq $TrustedRootCAs) {
                $Vulnerable = $true
                $Description = "$($Description)No explicit trusted root CA is specified. "
            }
            else {
            }
            if ($null -ne $_.InnerEap) {
                if ($_.InnerEapTypeId -eq 26) {
                    $Vulnerable = $true
                    $Description = "$($Description)MS-CHAPv2 is used for authentication. "
                }
            }
        }
        if ($Vulnerable) {
            $_ | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $Description
            $ArrayOfResults += $_ | Select-Object -Property * -ExcludeProperty Eap,InnerEap
        }
    }
    $Result = New-Object -TypeName PSObject
    $Result | Add-Member -MemberType "NoteProperty" -Name "Result" -Value $ArrayOfResults
    $Result | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $(if ($ArrayOfResults) { $BaseSeverity } else { $SeverityLevelEnum::None })
    $Result
}
function sanitized {
    [CmdletBinding()] Param(
        [UInt32] $BaseSeverity
    )
    $Vulnerable = $false
    $Config = New-Object -TypeName PSObject
    $MachineRole = insectivore
    if ($MachineRole.Name -ne "WinNT") {
        $Description = "Not a workstation, this check is irrelevant."
    }
    else {
        $WindowsVersion = accedes
        if ((($WindowsVersion.Major -eq 6) -and ($WindowsVersion.Minor -lt 2)) -or ($WindowsVersion.Major -lt 6)) {
            $Description = "This version of Windows is not supported."
            
        }
        else {
            $RegKey = "HKLM\SOFTWARE\Policies\Microsoft\Windows\System"
            $RegValue = "DontDisplayNetworkSelectionUI"
            $RegData = (Get-ItemProperty -Path "Registry::$($RegKey)" -ErrorAction SilentlyContinue).$RegValue
            $Config | Add-Member -MemberType "NoteProperty" -Name "Key" -Value $RegKey
            $Config | Add-Member -MemberType "NoteProperty" -Name "Value" -Value $RegValue
            $Config | Add-Member -MemberType "NoteProperty" -Name "Data" -Value $(if ($null -eq $RegData) { "(null)" } else { $RegData })
            if ($RegData -ge 1) {
                $Description = "The policy 'DontDisplayNetworkSelectionUI' is enabled, not vulnerable."
            }
            else {
                $Description = "The network selection UI is displayed on the logon screen (default)."
                $Vulnerable = $true
            }
        }
    }
    $Config | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $Description
    $Result = New-Object -TypeName PSObject
    $Result | Add-Member -MemberType "NoteProperty" -Name "Result" -Value $Config
    $Result | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $(if ($Vulnerable) { $BaseSeverity } else { $SeverityLevelEnum::None })
    $Result
}
function lofted {
    [CmdletBinding()] Param(
        [object] $SocketAddress
    )
    if ($SocketAddress.SockAddr -eq [IntPtr]::Zero) {
        Write-Verbose "SOCKET_ADDRESS.lpSockaddr is null"
        return
    }
    $AddressFamily = [System.Runtime.InteropServices.Marshal]::ReadInt16($SocketAddress.SockAddr)
    if ($AddressFamily -eq 2) {
        $AddressFamilyName = "AF_INET"
        $Addr = [System.Runtime.InteropServices.Marshal]::PtrToStructure($SocketAddress.SockAddr, [type]$SOCKADDR)
        $StringAddr = (@($Addr.Data[2], $Addr.Data[3], $Addr.Data[4], $Addr.Data[5]) -join ".")
    }
    elseif ($AddressFamily -eq 23) {
        $AddressFamilyName = "AF_INET6"
        $Addr = [System.Runtime.InteropServices.Marshal]::PtrToStructure($SocketAddress.SockAddr, [type]$SOCKADDR_IN6)
        $LeadingZero = $true
        $MidZero = $true
        $Result = ""
        $(for ($i = 0; $i -lt $Addr.Addr.Addr.Length; $i += 2) {
            $c = $Addr.Addr.Addr[$i]
            $d = $Addr.Addr.Addr[$i + 1]
            $t = $c * 256 + $d
            if (($t -eq 0) -and $LeadingZero) { if ($i -eq 0) { $Result += "::" }; continue } else { $LeadingZero = $false }
            if (($t -eq 0) -and (-not $LeadingZero)) { if ($MidZero) { $Result += ":"; $MidZero = $false }; continue }
            $Result += "$('{0:x}' -f $t):"
        })
        $StringAddr = $Result.TrimEnd(":")
    }
    else {
        Write-Verbose "Unknown family: $AddressFamily"
        return
    }
    $Result = New-Object -TypeName PSObject
    $Result | Add-Member -MemberType "NoteProperty" -Name "IPAddress" -Value $StringAddr
    $Result | Add-Member -MemberType "NoteProperty" -Name "Family" -Value $AddressFamily
    $Result | Add-Member -MemberType "NoteProperty" -Name "FamilyName" -Value $AddressFamilyName
    $Result
}
function whelked {
    [CmdletBinding()] Param(
        [switch] $All = $false
    )
    $InterfaceTypes = @{
        'Other' = 1
        'Ethernet' = 6
        'TokenRing' = 9
        'PPP' = 23
        'Loopback' = 24
        'ATM' = 37
        'IEEE80211' = 71
        'Tunnel' = 131
        'IEEE1394' = 144
    }
    $InterfacesStatuses = @{
        'Up' = 1
        'Down' = 2
        'Testing' = 3
        'Unknown' = 4
        'Dormant' = 5
        'NotPresent' = 6
        'LowerLayerDown' = 7
    }
    $ConnectionTypes = @{
        'Dedicated' = 1
        'Passive' = 2
        'Demand' = 3
        'Maximum' = 4
    }
    $TunnelTypes = @{
        'None' = 0
        'Other' = 1
        'Direct' = 2
        '6to4' = 11
        'ISATAP' = 13
        'TEREDO' = 14
        'IPHTTPS' = 15
    }
    $GAA_FLAG_INCLUDE_PREFIX = 0x0010
    $GAA_FLAG_INCLUDE_WINS_INFO = 0x0040
    $GAA_FLAG_INCLUDE_GATEWAYS = 0x0080
    $GAA_FLAG_INCLUDE_ALL_INTERFACES = 0x0100
    $Family = 0 # AF_UNSPEC
    $Flags = $GAA_FLAG_INCLUDE_PREFIX -bor $GAA_FLAG_INCLUDE_WINS_INFO -bor $GAA_FLAG_INCLUDE_GATEWAYS
    if ($All) { $Flags = $Flgas -bor $GAA_FLAG_INCLUDE_ALL_INTERFACES }
    $AdaptersSize = 0
    $Result = $Iphlpapi::GetAdaptersAddresses($Family, $Flags, [IntPtr]::Zero, [IntPtr]::Zero, [ref]$AdaptersSize)
    if ($AddressesSize -eq 0) {
        Write-Verbose "GetAdaptersAddresses KO - Error: $Result"
        return
    }
    Write-Verbose "GetAdaptersAddresses OK - Size: $AdaptersSize"
    $AdaptersPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($AdaptersSize)
    $Result = $Iphlpapi::GetAdaptersAddresses($Family, $Flags, [IntPtr]::Zero, $AdaptersPtr, [ref]$AdaptersSize)
    if ($Result -ne 0) {
        Write-Verbose "GetAdaptersAddresses KO - Error: $Result"
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($AdaptersSize)
        return
    }
    Write-Verbose "GetAdaptersAddresses OK"
    do {
        $Adapter = [System.Runtime.InteropServices.Marshal]::PtrToStructure($AdaptersPtr, [type]$IP_ADAPTER_ADDRESSES)
        $InterfaceType = $InterfaceTypes.GetEnumerator() | Where-Object { $_.value -eq $Adapter.IfType } | ForEach-Object { $_.Name }
        $InterfaceStatus = $InterfacesStatuses.GetEnumerator() | Where-Object { $_.value -eq $Adapter.OperStatus } | ForEach-Object { $_.Name }
        $ConnectionType = $ConnectionTypes.GetEnumerator() | Where-Object { $_.value -eq $Adapter.ConnectionType } | ForEach-Object { $_.Name }
        $TunnelType = $TunnelTypes.GetEnumerator() | Where-Object { $_.value -eq $Adapter.TunnelType } | ForEach-Object { $_.Name }
        $AdapterPhysicalAddress = ""
        if ($Adapter.PhysicalAddressLength -ne 0) {
            $AdapterPhysicalAddress = $(for ($i = 0; $i -lt $Adapter.PhysicalAddressLength; $i++) { "{0:x2}" -f $Adapter.PhysicalAddress[$i] }) -join ":"
        }
        $UnicastAddresses = @()
        $UnicastAddressPtr = $Adapter.FirstUnicastAddress
        while ($UnicastAddressPtr -ne [IntPtr]::Zero) {
            $UnicastAddress = [System.Runtime.InteropServices.Marshal]::PtrToStructure($UnicastAddressPtr, [type]$IP_ADAPTER_UNICAST_ADDRESS_LH)
            $AddrObject = lofted -SocketAddress $UnicastAddress.Address
            $AddrObject.IPAddress = "$($AddrObject.IPAddress) (/$($UnicastAddress.OnLinkPrefixLength))"
            $UnicastAddresses += $AddrObject
            $UnicastAddressPtr = $UnicastAddress.Next
        }
        $DnsServerAddresses = @()
        $DnsServerAddressPtr = $Adapter.FirstDnsServerAddress
        while ($DnsServerAddressPtr -ne [IntPtr]::Zero) {
            $DnsServerAddress = [System.Runtime.InteropServices.Marshal]::PtrToStructure($DnsServerAddressPtr, [type]$IP_ADAPTER_DNS_SERVER_ADDRESS_XP)
            $AddrObject = lofted -SocketAddress $DnsServerAddress.Address
            $DnsServerAddresses += $AddrObject
            $DnsServerAddressPtr = $DnsServerAddress.Next
        }
        $WinsServerAddresses = @()
        $WinsServerAddressPtr = $Adapter.FirstWinsServerAddress
        while ($WinsServerAddressPtr -ne [IntPtr]::Zero) {
            $WinServerAddress = [System.Runtime.InteropServices.Marshal]::PtrToStructure($WinsServerAddressPtr, [type]$IP_ADAPTER_WINS_SERVER_ADDRESS_LH)
            $AddrObject = lofted -SocketAddress $WinServerAddress.Address
            $WinsServerAddresses += $AddrObject
            $WinsServerAddressPtr = $WinServerAddress.Next
        }
        $GatewayAddresses = @()
        $GatewayAddressPtr = $Adapter.FirstGatewayAddress
        while ($GatewayAddressPtr -ne [IntPtr]::Zero) {
            $GatewayAddress = [System.Runtime.InteropServices.Marshal]::PtrToStructure($GatewayAddressPtr, [type]$IP_ADAPTER_GATEWAY_ADDRESS_LH)
            $AddrObject = lofted -SocketAddress $GatewayAddress.Address
            $GatewayAddresses += $AddrObject
            $GatewayAddressPtr = $GatewayAddress.Next
        }
        $DnsSuffixList = @()
        $DnsSuffixPtr = $Adapter.FirstDnsSuffix
        while ($DnsSuffixPtr -ne [IntPtr]::Zero) {
            $DnsSuffix = [System.Runtime.InteropServices.Marshal]::PtrToStructure($DnsSuffixPtr, [type]$IP_ADAPTER_DNS_SUFFIX)
            [string[]]$DnsSuffixList += $DnsSuffix.String
            $DnsSuffixPtr = $DnsSuffix.Next
        }
        $Dhcpv4Server = lofted -SocketAddress $Adapter.Dhcpv4Server
        $Dhcpv6Server = lofted -SocketAddress $Adapter.Dhcpv6Server
        $Dhcpv6ClientDuid = $(for ($i = 0; $i -lt $Adapter.Dhcpv6ClientDuidLength; $i++) { '{0:x2}' -f $Adapter.Dhcpv6ClientDuid[$i] }) -join ":"
        $Result = New-Object -TypeName PSObject
        $Result | Add-Member -MemberType "NoteProperty" -Name "Name" -Value $Adapter.AdapterName
        $Result | Add-Member -MemberType "NoteProperty" -Name "FriendlyName" -Value $Adapter.FriendlyName
        $Result | Add-Member -MemberType "NoteProperty" -Name "Type" -Value $InterfaceType
        $Result | Add-Member -MemberType "NoteProperty" -Name "Status" -Value $InterfaceStatus
        $Result | Add-Member -MemberType "NoteProperty" -Name "ConnectionType" -Value $ConnectionType
        $Result | Add-Member -MemberType "NoteProperty" -Name "TunnelType" -Value $TunnelType
        $Result | Add-Member -MemberType "NoteProperty" -Name "TxSpeed" -Value $Adapter.TransmitLinkSpeed
        $Result | Add-Member -MemberType "NoteProperty" -Name "RxSpeed" -Value $Adapter.ReceiveLinkSpeed
        $Result | Add-Member -MemberType "NoteProperty" -Name "DnsSuffix" -Value $Adapter.DnsSuffix
        $Result | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $Adapter.Description
        $Result | Add-Member -MemberType "NoteProperty" -Name "PhysicalAddress" -Value $AdapterPhysicalAddress
        $Result | Add-Member -MemberType "NoteProperty" -Name "Flags" -Value ($Adapter.Flags -as $IP_ADAPTER_FLAGS)
        $Result | Add-Member -MemberType "NoteProperty" -Name "IPv6" -Value (($UnicastAddresses | Where-Object { $_.Family -eq 23 } | ForEach-Object { $_.IPAddress }) -join ", ")
        $Result | Add-Member -MemberType "NoteProperty" -Name "IPv4" -Value (($UnicastAddresses | Where-Object { $_.Family -eq 2 } | ForEach-Object { $_.IPAddress }) -join ", ")
        $Result | Add-Member -MemberType "NoteProperty" -Name "Gateway" -Value (($GatewayAddresses | ForEach-Object { $_.IPAddress }) -join ", ")
        $Result | Add-Member -MemberType "NoteProperty" -Name "DHCPv4Server" -Value $Dhcpv4Server.IPAddress
        $Result | Add-Member -MemberType "NoteProperty" -Name "DHCPv6Server" -Value $Dhcpv6Server.IPAddress
        $Result | Add-Member -MemberType "NoteProperty" -Name "DHCPv6IAID" -Value $(if ($Adapter.Dhcpv6Iaid -ne 0) { $Adapter.Dhcpv6Iaid } else { $null })
        $Result | Add-Member -MemberType "NoteProperty" -Name "DHCPv6ClientDUID" -Value $Dhcpv6ClientDuid
        $Result | Add-Member -MemberType "NoteProperty" -Name "DnsServers" -Value (($DnsServerAddresses | ForEach-Object { $_.IPAddress }) -join ", ")
        $Result | Add-Member -MemberType "NoteProperty" -Name "WINSServers" -Value (($WinsServerAddresses | ForEach-Object { $_.IPAddress }) -join ", ")
        $Result | Add-Member -MemberType "NoteProperty" -Name "DNSSuffixList" -Value ($DnsSuffixList -join ", ")
        $Result
        [IntPtr] $AdaptersPtr = $Adapter.Next
    } while ($AdaptersPtr -ne [IntPtr]::Zero)
    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($AdaptersPtr)
}
function Sarnoff {
    [CmdletBinding()] Param(
        [Switch] $IPv6 = $false,
        [Switch] $UDP = $false
    )
    $AF_INET6 = 23
    $AF_INET = 2
    if ($IPv6) {
        $IpVersion = $AF_INET6
    }
    else {
        $IpVersion = $AF_INET
    }
    if ($UDP) {
        $UDP_TABLE_OWNER_PID = 1
        [Int]$BufSize = 0
        $Result = $Iphlpapi::GetExtendedUdpTable([IntPtr]::Zero, [ref]$BufSize, $true, $IpVersion, $UDP_TABLE_OWNER_PID, 0)
        $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    }
    else {
        $TCP_TABLE_OWNER_PID_LISTENER = 3
        [Int]$BufSize = 0
        $Result = $Iphlpapi::GetExtendedTcpTable([IntPtr]::Zero, [ref]$BufSize, $true, $IpVersion, $TCP_TABLE_OWNER_PID_LISTENER, 0)
        $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    }
    if ($Result -eq 122) {
        Write-Verbose "GetExtendedProtoTable() OK - Size: $BufSize"
        [IntPtr]$TablePtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($BufSize)
        if ($UDP) {
            $Result = $Iphlpapi::GetExtendedUdpTable($TablePtr, [ref]$BufSize, $true, $IpVersion, $UDP_TABLE_OWNER_PID, 0)
        }
        else {
            $Result = $Iphlpapi::GetExtendedTcpTable($TablePtr, [ref]$BufSize, $true, $IpVersion, $TCP_TABLE_OWNER_PID_LISTENER, 0)
        }
        if ($Result -eq 0) {
            if ($UDP) {
                if ($IpVersion -eq $AF_INET) {
                    $Table = [System.Runtime.InteropServices.Marshal]::PtrToStructure($TablePtr, [type] $MIB_UDPTABLE_OWNER_PID)
                }
                elseif ($IpVersion -eq $AF_INET6) {
                    $Table = [System.Runtime.InteropServices.Marshal]::PtrToStructure($TablePtr, [type] $MIB_UDP6TABLE_OWNER_PID)
                }
            }
            else {
                if ($IpVersion -eq $AF_INET) {
                    $Table = [System.Runtime.InteropServices.Marshal]::PtrToStructure($TablePtr, [type] $MIB_TCPTABLE_OWNER_PID)
                }
                elseif ($IpVersion -eq $AF_INET6) {
                    $Table = [System.Runtime.InteropServices.Marshal]::PtrToStructure($TablePtr, [type] $MIB_TCP6TABLE_OWNER_PID)
                }
            }
            $NumEntries = $Table.NumEntries
            Write-Verbose "GetExtendedProtoTable() OK - NumEntries: $NumEntries"
            $Offset = [IntPtr] ($TablePtr.ToInt64() + 4)
            For ($i = 0; $i -lt $NumEntries; $i++) {
                if ($UDP) {
                    if ($IpVersion -eq $AF_INET) {
                        $TableEntry = [System.Runtime.InteropServices.Marshal]::PtrToStructure($Offset, [type] $MIB_UDPROW_OWNER_PID)
                        $LocalAddr = (New-Object -TypeName System.Net.IPAddress($TableEntry.LocalAddr)).IPAddressToString
                    }
                    elseif ($IpVersion -eq $AF_INET6) {
                        $TableEntry = [System.Runtime.InteropServices.Marshal]::PtrToStructure($Offset, [type] $MIB_UDP6ROW_OWNER_PID)
                        $LocalAddr = New-Object -TypeName System.Net.IPAddress($TableEntry.LocalAddr, $TableEntry.LocalScopeId)
                    }
                }
                else {
                    if ($IpVersion -eq $AF_INET) {
                        $TableEntry = [System.Runtime.InteropServices.Marshal]::PtrToStructure($Offset, [type] $MIB_TCPROW_OWNER_PID)
                        $LocalAddr = (New-Object -TypeName System.Net.IPAddress($TableEntry.LocalAddr)).IPAddressToString
                    }
                    elseif ($IpVersion -eq $AF_INET6) {
                        $TableEntry = [System.Runtime.InteropServices.Marshal]::PtrToStructure($Offset, [type] $MIB_TCP6ROW_OWNER_PID)
                        $LocalAddr = New-Object -TypeName System.Net.IPAddress($TableEntry.LocalAddr, [Int64] $TableEntry.LocalScopeId)
                    }
                }
                $LocalPort = $TableEntry.LocalPort[0] * 0x100 + $TableEntry.LocalPort[1]
                $ProcessId = $TableEntry.OwningPid
                if ($IpVersion -eq $AF_INET) {
                    $LocalAddress = "$($LocalAddr):$($LocalPort)"
                }
                elseif ($IpVersion -eq $AF_INET6) {
                    try { $LocalAddress = "[$($LocalAddr)]:$($LocalPort)" } catch { $LocalAddress = "????:$($LocalPort)" }
                }
                $Result = New-Object -TypeName PSObject
                $Result | Add-Member -MemberType "NoteProperty" -Name "IP" -Value $(if ($IpVersion -eq $AF_INET) { "IPv4" } else { "IPv6" } )
                $Result | Add-Member -MemberType "NoteProperty" -Name "Proto" -Value $(if ($UDP) { "UDP" } else { "TCP" } )
                $Result | Add-Member -MemberType "NoteProperty" -Name "LocalAddress" -Value $LocalAddr
                $Result | Add-Member -MemberType "NoteProperty" -Name "LocalPort" -Value $LocalPort
                $Result | Add-Member -MemberType "NoteProperty" -Name "Endpoint" -Value $LocalAddress
                $Result | Add-Member -MemberType "NoteProperty" -Name "State" -Value $(if ($UDP) { "N/A" } else { "LISTENING" } )
                $Result | Add-Member -MemberType "NoteProperty" -Name "PID" -Value $ProcessId
                $Result | Add-Member -MemberType "NoteProperty" -Name "Name" -Value (Get-Process -PID $ProcessId -ErrorAction SilentlyContinue).ProcessName
                $Result
                $Offset = [IntPtr] ($Offset.ToInt64() + [System.Runtime.InteropServices.Marshal]::SizeOf($TableEntry))
            }
        }
        else {
            Write-Verbose ([ComponentModel.Win32Exception] $LastError)
        }
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($TablePtr)
    }
    else {
        Write-Verbose ([ComponentModel.Win32Exception] $LastError)
    }
}
function Washington {
    [CmdletBinding()] Param(
        [ValidateNotNullOrEmpty()]
        [string] $WlanProfile
    )
    BEGIN {
        function assumptions {
            param([object]$Text)
            if ($null -eq $Text) { Write-Warning "$($MyInvocation.MyCommand.Name) | Null input, assuming False"; return $False }
            if ($Text.GetType() -like "*XmlElement") { $Text = $(if ([string]::IsNullOrEmpty($Text.innerText)) { $Text } else { $Text.innerText }) }
            try { [System.Convert]::ToBoolean($Text) } catch { Write-Warning "Failed to convert to boolean: $($Text)" }
        }
        function resurfacing {
            param([string]$ConnectionType)
            if ([string]::IsNullOrEmpty($ConnectionType)) { return }
            $Enumeration = @{ "ESS" = "Infrastructure" ; "IBSS" = "Ad-hoc" }
            try { $Enumeration[$ConnectionType] } catch { Write-Warning "Unknown connection type: $($ConnectionType)" }
        }
        function adheres {
            param([string]$MethodType)
            if ([string]::IsNullOrEmpty($MethodType)) { return }
            $Enumeration = @{ "13" = "EAP-TLS" ; "18" = "EAP-SIM" ; "21" = "EAP-TTLS" ; "23" = "EAP-AKA" ; "25" = "PEAP" ; "26" = "MS-EAP" ; "29" = "EAP-MSCHAP-V2" ; "50" = "EAP-AKA'" ; "55" = "TEAP" }
            try { $Enumeration[$MethodType] } catch { "Unknown" }
        }
        function hasps {
            param([string]$Thumbprint)
            if ([string]::IsNullOrEmpty($Thumbprint)) { ""; return }
            $Certificate = Get-ChildItem "Cert:\LocalMachine\Root\$($Thumbprint.Replace(' ', ''))" -ErrorAction SilentlyContinue
            if ($null -eq $Certificate) { "Unknown Certificate"; return }
            ($Certificate.Subject.Split(',')[0]).Split('=')[1]
        }
        function Menes {
            param([string]$AuthMode)
            if ([string]::IsNullOrEmpty($AuthMode)) { return }
            $Enumeration = @{ "machineOrUser" = "Use user credentials when a user is logged on, use machine credentials otherwise." ; "machine" = "Use machine credentials only." ; "user" = "Use user credentials only." ; "guest" = "Use guest (empty) credentials only." }
            try { $Enumeration[$AuthMode] } catch { "Unknown" }
        }
        function chancels {
            param([boolean]$PromptDisabled)
            if ($PromptDisabled) { "Authentication fails is the certificate is not trusted." } else { "The user can be prompted for server validation." }
        }
        function revelries {
            param([boolean]$PerformValidation)
            if ($PerformValidation) { "Server validation is performed." } else { "Server validation is not performed." }
        }
        function squawks {
            param([boolean]$AcceptServerName)
            if ($AcceptServerName) { "The server name is verified." } else { "The server name is not verified." }
        }
        function anticipate {
            param([boolean]$UseWinLogonCredentials)
            if ($UseWinLogonCredentials) { "EAP MS-CHAPv2 obtains credentials from winlogon." } else { "EAP MS-CHAPv2 obtains credentials from the user." }
        }
        function electrocutions {
            param([System.Xml.XmlElement]$Node, [string]$Name)
            if ($null -eq $Node) { Write-Warning "$($MyInvocation.MyCommand.Name) | Input node is null."; return }
            $TrustedRootCAs = $Node.GetElementsByTagName($Name) | ForEach-Object { $_.InnerText.Replace(" ", "") }
            $TrustedRootCANames = $TrustedRootCAs | ForEach-Object { hasps -Thumbprint $_ }
            $Result = New-Object -TypeName PSObject
            $Result | Add-Member -MemberType "NoteProperty" -Name "Thumbprints" -Value ($TrustedRootCAs -join ", ")
            $Result | Add-Member -MemberType "NoteProperty" -Name "DisplayNames" -Value ($TrustedRootCANames -join ", ")
            $Result
        }
        function locksmiths {
            param([System.Xml.XmlElement]$Node)
            if ($null -eq $Node) { Write-Warning "$($MyInvocation.MyCommand.Name) | Input node is null."; return }
            $EapTypeId = $(if ([string]::IsNullOrEmpty($Node.Type.InnerText)) { $Node.Type } else { $Node.Type.InnerText })
            $Result = New-Object -TypeName PSObject
            $Result | Add-Member -MemberType "NoteProperty" -Name "Id" -Value $EapTypeId
            $Result | Add-Member -MemberType "NoteProperty" -Name "Name" -Value (adheres -MethodType $EapTypeId)
            $Result
        }
        function truism {
            param([System.Xml.XmlElement]$Node)
            if ($null -eq $Node) { Write-Warning "$($MyInvocation.MyCommand.Name) | Input node is null."; return }
            $CredentialsSource = $(
                if ($null -ne $Node.EapType.CredentialsSource.SmartCard) { "SmartCard" }
                elseif ($null -ne $Node.EapType.CredentialsSource.CertificateStore) { "Certificate" }
            )
            $ServerValidationNode = $Node.EapType.ServerValidation
            $ServerValidationDisablePrompt = assumptions -Text $ServerValidationNode.DisableUserPromptForServerValidation
            $AcceptServerName = assumptions -Text $Node.EapType.AcceptServerName
            $PerformServerValidation = assumptions -Text $Node.EapType.PerformServerValidation
            $TrustedRootCAs = electrocutions -Node $ServerValidationNode -Name "TrustedRootCA"
            $Result = New-Object -TypeName PSObject
            $Result | Add-Member -MemberType "NoteProperty" -Name "CredentialsSource" -Value $CredentialsSource
            $Result | Add-Member -MemberType "NoteProperty" -Name "ServerValidationDisablePrompt" -Value $ServerValidationDisablePrompt
            $Result | Add-Member -MemberType "NoteProperty" -Name "ServerValidationDisablePromptDescription" -Value (chancels -PromptDisabled $ServerValidationDisablePrompt)
            $Result | Add-Member -MemberType "NoteProperty" -Name "ServerValidationNames" -Value $ServerValidationNode.ServerNames
            $Result | Add-Member -MemberType "NoteProperty" -Name "AcceptServerName" -Value $AcceptServerName
            $Result | Add-Member -MemberType "NoteProperty" -Name "AcceptServerNameDescription" -Value (squawks -AcceptServerName $AcceptServerName)
            $Result | Add-Member -MemberType "NoteProperty" -Name "TrustedRootCAs" -Value $TrustedRootCAs.Thumbprints
            $Result | Add-Member -MemberType "NoteProperty" -Name "TrustedRootCAsDescription" -Value $TrustedRootCAs.DisplayNames
            $Result | Add-Member -MemberType "NoteProperty" -Name "PerformServerValidation" -Value $PerformServerValidation
            $Result | Add-Member -MemberType "NoteProperty" -Name "PerformServerValidationDescription" -Value (revelries -PerformValidation $PerformServerValidation)
            $Result
        }
        function prattling {
            param([System.Xml.XmlElement]$Node)
            if ($null -eq $Node) { Write-Warning "$($MyInvocation.MyCommand.Name) | Input node is null."; return }
            $ServerValidationNode = $Node.ServerValidation
            $ServerValidationDisablePrompt = assumptions -Text $ServerValidationNode.DisablePrompt
            $TrustedRootCAs = electrocutions -Node $ServerValidationNode -Name "TrustedRootCAHash"
            $Result = New-Object -TypeName PSObject
            $Result | Add-Member -MemberType "NoteProperty" -Name "ServerValidationDisablePrompt" -Value $ServerValidationDisablePrompt
            $Result | Add-Member -MemberType "NoteProperty" -Name "ServerValidationDisablePromptDescription" -Value (chancels -PromptDisabled $ServerValidationDisablePrompt)
            $Result | Add-Member -MemberType "NoteProperty" -Name "ServerValidationNames" -Value $ServerValidationNode.ServerNames
            $Result | Add-Member -MemberType "NoteProperty" -Name "TrustedRootCAs" -Value $TrustedRootCAs.Thumbprints
            $Result | Add-Member -MemberType "NoteProperty" -Name "TrustedRootCAsDescription" -Value $TrustedRootCAs.DisplayNames
            $Result
        }
        function hyphenation {
            param([System.Xml.XmlElement]$Node)
            if ($null -eq $Node) { Write-Warning "$($MyInvocation.MyCommand.Name) | Input node is null."; return }
            $ServerValidationNode = $Node.EapType.ServerValidation
            $ServerValidationDisablePrompt = assumptions -Text $ServerValidationNode.DisableUserPromptForServerValidation
            $TrustedRootCAs = electrocutions -Node $ServerValidationNode -Name "TrustedRootCA"
            $AcceptServerName = assumptions -Text $Node.EapType.PeapExtensions.AcceptServerName
            $PerformServerValidation = assumptions -Text $Node.EapType.PeapExtensions.PerformServerValidation
            $Result = New-Object -TypeName PSObject
            $Result | Add-Member -MemberType "NoteProperty" -Name "ServerValidationDisablePrompt" -Value $ServerValidationDisablePrompt
            $Result | Add-Member -MemberType "NoteProperty" -Name "ServerValidationDisablePromptDescription" -Value (chancels -PromptDisabled $ServerValidationDisablePrompt)
            $Result | Add-Member -MemberType "NoteProperty" -Name "ServerValidationNames" -Value $ServerValidationNode.ServerNames
            $Result | Add-Member -MemberType "NoteProperty" -Name "AcceptServerName" -Value $AcceptServerName
            $Result | Add-Member -MemberType "NoteProperty" -Name "AcceptServerNameDescription" -Value (squawks -AcceptServerName $AcceptServerName)
            $Result | Add-Member -MemberType "NoteProperty" -Name "TrustedRootCAs" -Value $TrustedRootCAs.Thumbprints
            $Result | Add-Member -MemberType "NoteProperty" -Name "TrustedRootCAsDescription" -Value $TrustedRootCAs.DisplayNames
            $Result | Add-Member -MemberType "NoteProperty" -Name "PerformServerValidation" -Value $PerformServerValidation
            $Result | Add-Member -MemberType "NoteProperty" -Name "PerformServerValidationDescription" -Value (revelries -PerformValidation $PerformServerValidation)
            $Result
        }
        function dorkiest {
            param([System.Xml.XmlElement]$Node)
            if ($null -eq $Node) { Write-Warning "$($MyInvocation.MyCommand.Name) | Input node is null."; return }
            $UseWinLogonCredentials = assumptions -Text $Node.EapType.UseWinLogonCredentials
            $Result = New-Object -TypeName PSObject
            $Result | Add-Member -MemberType "NoteProperty" -Name "UseWinLogonCredentials" -Value $UseWinLogonCredentials
            $Result | Add-Member -MemberType "NoteProperty" -Name "UseWinLogonCredentialsDescription" -Value (anticipate -UseWinLogonCredentials $UseWinLogonCredentials)
            $Result
        }
        function trundling {
            param([System.Xml.XmlElement]$Node, [string]$Type)
            if ($null -eq $Node) { Write-Warning "$($MyInvocation.MyCommand.Name) | Input node is null."; return }
            switch ($Type) {
                "13" {
                    truism -Node $Node.Eap
                }
                "21" {
                    prattling -Node $Node.EapTtls
                }
                "25" {
                    hyphenation -Node $Node.Eap
                }
                "26" {
                    dorkiest -Node $Node.Eap
                }
                default {
                    Write-Warning "$($MyInvocation.MyCommand.Name) | Unsupported EAP type: $($Type)"
                }
            }
        }
    }
    PROCESS {
        if ([string]::IsNullOrEmpty($WlanProfile)) { Write-Warning "$($MyInvocation.MyCommand.Name) | Failed to get content: $($ProfileFileItem.FullName)"; return }
        try { $XmlFile = [xml]$WlanProfile } catch { Write-Warning "$($MyInvocation.MyCommand.Name) | Failed to parse XML: $($ProfileFileItem.FullName)"; return }
        $WifiProfiles = $XmlFile.GetElementsByTagName("WLANProfile")
        foreach ($WifiProfile in $WifiProfiles) {
            $Result = New-Object -TypeName PSObject
            $Result | Add-Member -MemberType "NoteProperty" -Name "SSID" -Value $WifiProfile.SSIDConfig.SSID.name
            $Result | Add-Member -MemberType "NoteProperty" -Name "ConnectionType" -Value "$($WifiProfile.connectionType) ($(resurfacing -ConnectionType $WifiProfile.connectionType))"
            $Result | Add-Member -MemberType "NoteProperty" -Name "ConnectionMode" -Value $(if (($WifiProfile.connectionType -eq "ESS") -and ([string]::IsNullOrEmpty($WifiProfile.connectionMode))) { "auto" } else { $WifiProfile.connectionMode })
            $SecurityConfig = $WifiProfile.MSM.security
            if ($null -eq $SecurityConfig) { Write-Warning "SSID: '$($Result.SSID)' | 'Security' node not found."; return }
            $UseDot1X = assumptions -Text $SecurityConfig.authEncryption.useOneX
            $Result | Add-Member -MemberType "NoteProperty" -Name "Authentication" -Value $SecurityConfig.authEncryption.authentication
            $Result | Add-Member -MemberType "NoteProperty" -Name "Encryption" -Value $SecurityConfig.authEncryption.encryption
            $Result | Add-Member -MemberType "NoteProperty" -Name "PassPhrase" -Value $SecurityConfig.sharedKey.keyMaterial
            $Result | Add-Member -MemberType "NoteProperty" -Name "Dot1X" -Value $UseDot1X
            if (-not $UseDot1X) { $Result; return }
            $OneXNode = $SecurityConfig.OneX
            if ($null -eq $OneXNode) { Write-Warning "SSID: '$($Result.SSID)' | 'OneX' node not found."; return }
            $AuthenticationMode = $(if ([string]::IsNullOrEmpty($OneXNode.authMode)) { "machineOrUser" } else { $OneXNode.authMode })
            $Result | Add-Member -MemberType "NoteProperty" -Name "AuthenticationMode" -Value $AuthenticationMode
            $Result | Add-Member -MemberType "NoteProperty" -Name "AuthenticationModeDescription" -Value (Menes -AuthMode $AuthenticationMode)
            $EapType = locksmiths -Node $OneXNode.EAPConfig.EapHostConfig.EapMethod
            if ($null -eq $EapType) { Write-Warning "SSID: '$($Result.SSID)' | EAP type not found."; return }
            $Result | Add-Member -MemberType "NoteProperty" -Name "EapTypeId" -Value $EapType.Id
            $Result | Add-Member -MemberType "NoteProperty" -Name "EapType" -Value $EapType.Name
            $ConfigNode = $OneXNode.EAPConfig.EapHostConfig.Config
            if ($null -eq $ConfigNode) { Write-Warning "SSID: '$($Result.SSID)' | 'Config' node not found."; return }
            $EapConfig = trundling -Node $ConfigNode -Type $EapType.Id
            if ($null -eq $EapConfig) { Write-Warning "SSID: '$($Result.SSID)' | Failed to parse EAP configuration."; return }
            $Result | Add-Member -MemberType "NoteProperty" -Name "Eap" -Value $EapConfig
            $Result | Add-Member -MemberType "NoteProperty" -Name "EapStr" -Value ($EapConfig | Format-List | Out-String).Trim()
            if ($null -eq $ConfigNode.Eap.EapType.Eap) {
                Write-Verbose "SSID: '$($Result.SSID)' | There is no inner EAP configuration."
                $Result
                return
            }
            $InnerEapType = locksmiths -Node $ConfigNode.Eap.EapType.Eap
            if ($null -eq $InnerEapType) { Write-Warning "SSID: '$($Result.SSID)' | Inner EAP type not found."; return }
            $Result | Add-Member -MemberType "NoteProperty" -Name "InnerEapTypeId" -Value $InnerEapType.Id
            $Result | Add-Member -MemberType "NoteProperty" -Name "InnerEapType" -Value $InnerEapType.Name
            $InnerEapConfig = trundling -Node $ConfigNode.Eap.EapType -Type $InnerEapType.Id
            if ($null -eq $InnerEapConfig) { Write-Warning "SSID: '$($Result.SSID)' | Failed to parse inner EAP configuration."; return }
            $Result | Add-Member -MemberType "NoteProperty" -Name "InnerEap" -Value $InnerEapConfig
            $Result | Add-Member -MemberType "NoteProperty" -Name "InnerEapStr" -Value ($InnerEapConfig | Format-List | Out-String).Trim()
            $Result
        }
    }
}
function geometrical {
    [CmdletBinding()] Param()
    try {
        [IntPtr]$ClientHandle = [IntPtr]::Zero
        [UInt32]$NegotiatedVersion = 0
        [UInt32]$ClientVersion = 2 # Client version for Windows Vista and Windows Server 2008
        $Result = $Wlanapi::WlanOpenHandle($ClientVersion, [IntPtr]::Zero, [ref]$NegotiatedVersion, [ref]$ClientHandle)
        if ($Result -ne 0) {
            Write-Warning "$($MyInvocation.MyCommand.Name) | WlanOpenHandle() failed (Err: $($Result))"
            return
        }
        [IntPtr]$InterfaceListPtr = [IntPtr]::Zero
        $Result = $Wlanapi::WlanEnumInterfaces($ClientHandle, [IntPtr]::Zero, [ref]$InterfaceListPtr)
        if ($Result -ne 0) {
            Write-Warning "$($MyInvocation.MyCommand.Name) | WlanEnumInterfaces() failed (Err: $($Result))"
            $Wlanapi::WlanCloseHandle($ClientHandle, [IntPtr]::Zero)
            return
        }
        $NumberOfInterfaces = [Runtime.InteropServices.Marshal]::ReadInt32($InterfaceListPtr)
        Write-Verbose "$($MyInvocation.MyCommand.Name) | Number of WLAN interfaces: $($NumberOfInterfaces)"
        $WlanInterfaceInfoPtr = [IntPtr] ($InterfaceListPtr.ToInt64() + 8) # dwNumberOfItems + dwIndex
        for ($i = 0; $i -lt $NumberOfInterfaces; $i++) {
            $WlanInterfaceInfo = [System.Runtime.InteropServices.Marshal]::PtrToStructure($WlanInterfaceInfoPtr, [type]$WLAN_INTERFACE_INFO)
            [IntPtr]$ProfileListPtr = [IntPtr]::Zero
            $Result = $Wlanapi::WlanGetProfileList($ClientHandle, $WlanInterfaceInfo.InterfaceGuid, [IntPtr]::Zero, [ref]$ProfileListPtr)
            if ($Result -eq 0) {
                $NumberOfProfiles = [Runtime.InteropServices.Marshal]::ReadInt32($ProfileListPtr)
                Write-Verbose "$($MyInvocation.MyCommand.Name) | Number of WLAN profiles: $($NumberOfProfiles)"
                $WlanProfileInfoPtr = [IntPtr] ($ProfileListPtr.ToInt64() + 8) # dwNumberOfItems + dwIndex
                for ($j = 0; $j -lt $NumberOfProfiles; $j++) {
                    $WlanProfileInfo = [System.Runtime.InteropServices.Marshal]::PtrToStructure($WlanProfileInfoPtr, [type] $WLAN_PROFILE_INFO)
                    [String]$ProfileXml = ""
                    [UInt32]$WlanProfileFlags = 4 # WLAN_PROFILE_GET_PLAINTEXT_KEY
                    [UInt32]$WlanProfileAccessFlags = 0
                    $Result = $Wlanapi::WlanGetProfile($ClientHandle, $WlanInterfaceInfo.InterfaceGuid, $WlanProfileInfo.ProfileName, [IntPtr]::Zero, [ref]$ProfileXml, [ref]$WlanProfileFlags, [ref]$WlanProfileAccessFlags)
                    if ($Result -eq 0) {
                        Washington -WlanProfile $ProfileXml
                    }
                    else {
                        Write-Warning "$($MyInvocation.MyCommand.Name) | WlanGetProfile() failed (Err: $($Result))"
                    }
                    $WlanProfileInfoPtr = [IntPtr] ($WlanProfileInfoPtr.ToInt64() + [System.Runtime.InteropServices.Marshal]::SizeOf($WlanProfileInfo))
                }
                $Wlanapi::WlanFreeMemory($ProfileListPtr)
            }
            else {
                Write-Warning "$($MyInvocation.MyCommand.Name) | WlanGetProfileList() failed (Err: $($Result))"
            }
            $WlanInterfaceInfoPtr = [IntPtr] ($WlanInterfaceInfoPtr.ToInt64() + [System.Runtime.InteropServices.Marshal]::SizeOf($WlanInterfaceInfo))
        }
        $null = $Wlanapi::WlanFreeMemory($InterfaceListPtr)
        $null = $Wlanapi::WlanCloseHandle($ClientHandle, [IntPtr]::Zero)
    }
    catch {
        if ($Error[0]) { Write-Warning $Error[0] }
    }
}
function flicked {
    [CmdletBinding()] Param()
    function sheave {
        Param(
            [String]$Path
        )
        $Info = New-Object -TypeName PSObject
        [xml] $PackageContentXml = Get-Content -Path $Path -ErrorAction SilentlyContinue -ErrorVariable GetContentError
        if (-not $GetContentError) {
            $PackageContentXml.GetElementsByTagName("assembly") | ForEach-Object {
                $Info | Add-Member -MemberType "NoteProperty" -Name "DisplayName" -Value "$($_.displayName)"
                $Info | Add-Member -MemberType "NoteProperty" -Name "SupportInformation" -Value "$($_.supportInformation)"
            }
            $PackageContentXml.GetElementsByTagName("package") | Where-Object { $null -ne $_.identifier } | ForEach-Object {
                $Info | Add-Member -MemberType "NoteProperty" -Name "Identifier" -Value "$($_.identifier)"
                $Info | Add-Member -MemberType "NoteProperty" -Name "ReleaseType" -Value "$($_.releaseType)"
            }
            $Info
        }
    }
    if ($CachedHotFixList.Count -eq 0) {
        $InstalledKBs = New-Object -TypeName System.Collections.ArrayList
        $AllPackages = Get-ChildItem -Path "Registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages" -ErrorAction SilentlyContinue -ErrorVariable ErrorGetChildItem
        if (-not $ErrorGetChildItem) {
            $AllPackages | ForEach-Object {
                if (($_.Name | Split-Path -Leaf) -Like "Package_*for_KB*") {
                    $PackageProperties = $_ | Get-ItemProperty
                    $PackageName = $PackageProperties.InstallName.Split('~')[0].Split('_') | Where-Object { $_ -Like "KB*" }
                    if ($PackageName) {
                        if (-not ($InstalledKBs -contains $PackageName)) {
                            [void]$InstalledKBs.Add($PackageName)
                            $InstalledBy = work -Sid $PackageProperties.InstallUser
                            $DateHigh = $PackageProperties.InstallTimeHigh
                            $DateLow = $PackageProperties.InstallTimeLow
                            $FileTime = $DateHigh * [Math]::Pow(2, 32) + $DateLow
                            $InstallDate = [DateTime]::FromFileTime($FileTime)
                            $ServicingPackagesPath = Join-Path -Path $env:windir -ChildPath "servicing\Packages"
                            $PackagePath = Join-Path -Path $ServicingPackagesPath -ChildPath $PackageProperties.InstallName
                            $PackageInfo = sheave -Path $PackagePath
                            $Result = New-Object -TypeName PSObject
                            $Result | Add-Member -MemberType "NoteProperty" -Name "HotFixID" -Value "$PackageName"
                            $Result | Add-Member -MemberType "NoteProperty" -Name "Description" -Value "$($PackageInfo.ReleaseType)"
                            $Result | Add-Member -MemberType "NoteProperty" -Name "InstalledBy" -Value "$InstalledBy"
                            $Result | Add-Member -MemberType "NoteProperty" -Name "InstalledOnDate" -Value $InstallDate
                            $Result | Add-Member -MemberType "NoteProperty" -Name "InstalledOn" -Value (shoddiest -Date $InstallDate)
                            [void]$CachedHotFixList.Add($Result)
                        }
                    }
                }
            }
        }
        else {
            Get-HotFix | Select-Object HotFixID,Description,InstalledBy,InstalledOn | ForEach-Object {
                $_ | Add-Member -MemberType "NoteProperty" -Name "InstalledOnDate" -Value $_.InstalledOn
                $_.InstalledOn = shoddiest -Date $_.InstalledOn
                [void]$CachedHotFixList.Add($_)
            }
        }
    }
    $CachedHotFixList | ForEach-Object {
        $_
    }
}
function Bishop {
    [CmdletBinding()] Param()
    try {
        $WindowsUpdate = (New-Object -ComObject "Microsoft.Update.AutoUpdate").Results
        if ($WindowsUpdate.LastInstallationSuccessDate) {
            $WindowsUpdateResult = New-Object -TypeName PSObject
            $WindowsUpdateResult | Add-Member -MemberType "NoteProperty" -Name "Time" -Value $(shoddiest -Date $WindowsUpdate.LastInstallationSuccessDate)
            $WindowsUpdateResult | Add-Member -MemberType "NoteProperty" -Name "TimeRaw" -Value $WindowsUpdate.LastInstallationSuccessDate
            $WindowsUpdateResult
        }
    }
    catch {
        Write-Verbose "Error while requesting COM object Microsoft.Update.AutoUpdate."
    }
}
function devotees {
    [CmdletBinding()] Param(
        [switch] $Info,
        [UInt32] $BaseSeverity
    )
    $HotFixList = flicked | Sort-Object -Property "InstalledOnDate" -Descending
    if ($Info) { $HotFixList | Select-Object HotFixID,Description,InstalledBy,InstalledOn; return }
    $LatestHotfix = $HotFixList | Select-Object -First 1
    $TimeSpan = New-TimeSpan -Start $LatestHotfix.InstalledOnDate -End $(Get-Date)
    if ($TimeSpan.TotalDays -gt 31) {
        $Results = $LatestHotfix | Select-Object HotFixID,Description,InstalledBy,InstalledOn
    }
    else {
        Write-Verbose "At least one hotfix was installed in the last 31 days."
    }
    $Result = New-Object -TypeName PSObject
    $Result | Add-Member -MemberType "NoteProperty" -Name "Result" -Value $Results
    $Result | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $(if ($Results) { $BaseSeverity } else { $SeverityLevelEnum::None })
    $Result
}
function numerous {
    [CmdletBinding()] Param(
        [switch] $Remote = $false,
        [UInt32] $BaseSeverity
    )
    $ArrayOfResults = @()
    if ($Remote) {
        $GppPath = "\\$($Env:USERDNSDOMAIN)\SYSVOL"
        Write-Verbose "Target search path is: $($GppPath)"
        $CachedGPPFiles = Get-ChildItem -Path $GppPath -Recurse -Include 'Registry.xml' -Force -ErrorAction SilentlyContinue
        if (-not $CachedGPPFiles) { return }
        foreach ($File in $CachedGPPFiles) {
            try {
                [xml]$XmlFile = Get-Content -Path $File.FullName -ErrorAction SilentlyContinue
            }
            catch [Exception] {
                Write-Verbose $_.Exception.Message
                continue
            }
            $Results = New-Object -TypeName PSObject -Property @{
                DefaultDomainName    = New-Object System.Collections.ArrayList
                DefaultUserName      = New-Object System.Collections.ArrayList
                DefaultPassword      = New-Object System.Collections.ArrayList
                AutoAdminLogon       = New-Object System.Collections.ArrayList
                AltDefaultDomainName = New-Object System.Collections.ArrayList
                AltDefaultUserName   = New-Object System.Collections.ArrayList
                AltDefaultPassword   = New-Object System.Collections.ArrayList
                AltAutoAdminLogon    = New-Object System.Collections.ArrayList
            }
            foreach ($Property in $XmlFile.GetElementsByTagName("Properties")) {
                if ([string]::IsNullOrEmpty($Property.value)) { continue }
                switch ($Property.name) {
                    DefaultDomainName {
                        $null = $Results.DefaultDomainName.Add($Property.value)
                    }
                    DefaultUserName {
                        $null = $Results.DefaultUserName.Add($Property.value)
                    }
                    DefaultPassword {
                        $null = $Results.DefaultPassword.Add($Property.value)
                    }
                    AutoAdminLogon {
                        $null = $Results.AutoAdminLogon.Add($Property.value)
                    }
                    AltDefaultDomainName {
                        $null = $Results.AltDefaultDomainName.Add($Property.value)
                    }
                    AltDefaultUserName {
                        $null = $Results.AltDefaultUserName.Add($Property.value)
                    }
                    AltDefaultPassword {
                        $null = $Results.AltDefaultPassword.Add($Property.value)
                    }
                    AltAutoAdminLogon {
                        $null = $Results.AltAutoAdminLogon.Add($Property.value)
                    }
                }
            }
            if ($Results.DefaultPassword.Count -ne 0) {
                $Result = New-Object -TypeName PSObject
                $Result | Add-Member -MemberType "NoteProperty" -Name "FilePath" -Value $File.FullName
                $Result | Add-Member -MemberType "NoteProperty" -Name "Domains" -Value ($Results.DefaultDomainName -join ", ")
                $Result | Add-Member -MemberType "NoteProperty" -Name "Usernames" -Value ($Results.DefaultUserName -join ", ")
                $Result | Add-Member -MemberType "NoteProperty" -Name "Passwords" -Value ($Results.DefaultPassword -join ", ")
                $Result | Add-Member -MemberType "NoteProperty" -Name "AutoAdminLogons" -Value ($Results.AutoAdminLogon -join ", ")
                $ArrayOfResults += $Result
            }
            if ($Results.AltDefaultPassword.Count -ne 0) {
                $Result = New-Object -TypeName PSObject
                $Result | Add-Member -MemberType "NoteProperty" -Name "FilePath" -Value $File.FullName
                $Result | Add-Member -MemberType "NoteProperty" -Name "Domains" -Value ($Results.AltDefaultDomainName -join ", ")
                $Result | Add-Member -MemberType "NoteProperty" -Name "Usernames" -Value ($Results.AltDefaultUserName -join  ", ")
                $Result | Add-Member -MemberType "NoteProperty" -Name "Passwords" -Value ($Results.AltDefaultPassword -join ", ")
                $Result | Add-Member -MemberType "NoteProperty" -Name "AutoAdminLogon" -Value ($Results.AltAutoAdminLogon -join ", ")
                $ArrayOfResults += $Result
            }
        }
    }
    else {
        $RegKey = "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"
        $RegItem = Get-ItemProperty -Path "Registry::$($RegKey)" -ErrorAction SilentlyContinue
        if (-not [String]::IsNullOrEmpty($RegItem.DefaultPassword)) {
            $Result = New-Object -TypeName PSObject
            $Result | Add-Member -MemberType "NoteProperty" -Name "Domain" -Value $RegItem.DefaultDomainName
            $Result | Add-Member -MemberType "NoteProperty" -Name "Username" -Value $RegItem.DefaultUserName
            $Result | Add-Member -MemberType "NoteProperty" -Name "Password" -Value $RegItem.DefaultPassword
            $ArrayOfResults += $Result
        }
        if (-not [String]::IsNullOrEmpty($RegItem.AltDefaultPassword)) {
            $Result = New-Object -TypeName PSObject
            $Result | Add-Member -MemberType "NoteProperty" -Name "Domain" -Value $RegItem.AltDefaultDomainName
            $Result | Add-Member -MemberType "NoteProperty" -Name "Username" -Value $RegItem.AltDefaultUserName
            $Result | Add-Member -MemberType "NoteProperty" -Name "Password" -Value $RegItem.AltDefaultPassword
            $ArrayOfResults += $Result
        }
    }
    $Result = New-Object -TypeName PSObject
    $Result | Add-Member -MemberType "NoteProperty" -Name "Result" -Value $ArrayOfResults
    $Result | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $(if ($ArrayOfResults) { $BaseSeverity } else { $SeverityLevelEnum::None })
    $Result
}
function syrups {
    [CmdletBinding()] Param()
    $CredentialsFound = $false
    $Paths = New-Object -TypeName System.Collections.ArrayList
    [void] $Paths.Add($(Join-Path -Path $env:LOCALAPPDATA -ChildPath "Microsoft\Credentials"))
    [void] $Paths.Add($(Join-Path -Path $env:APPDATA -ChildPath "Microsoft\Credentials"))
    foreach ($Path in [String[]]$Paths) {
        Get-ChildItem -Force -Path $Path -ErrorAction SilentlyContinue | ForEach-Object {
            $Result = New-Object -TypeName PSObject
            $Result | Add-Member -MemberType "NoteProperty" -Name "Type" -Value "Credentials"
            $Result | Add-Member -MemberType "NoteProperty" -Name "FullPath" -Value $_.FullName
            $Result
            if (-not $CredentialsFound) { $CredentialsFound = $true }
        }
    }
    if ($CredentialsFound) {
        $CurrentUser = brickbat
        if ($CurrentUser -and $CurrentUser.SID) {
            $Paths = New-Object -TypeName System.Collections.ArrayList
            [void] $Paths.Add($(Join-Path -Path $env:LOCALAPPDATA -ChildPath "Microsoft\Protect\$($CurrentUser.SID)"))
            [void] $Paths.Add($(Join-Path -Path $env:APPDATA -ChildPath "Microsoft\Protect\$($CurrentUser.SID)"))
            foreach ($Path in [String[]]$Paths) {
                Get-ChildItem -Force -Path $Path -ErrorAction SilentlyContinue | Where-Object {$_.Name.Length -eq 36 } | ForEach-Object {
                    $Result = New-Object -TypeName PSObject
                    $Result | Add-Member -MemberType "NoteProperty" -Name "Type" -Value "Protect"
                    $Result | Add-Member -MemberType "NoteProperty" -Name "FullPath" -Value $_.FullName
                    $Result
                }
            }
        }
    }
}
function emancipator {
    [CmdletBinding()] Param()
    depraves -Filtered
}
function pinfeathers {
    [CmdletBinding()] Param()
    manufacturing -Filtered
}
function cattiest {
    [CmdletBinding()] Param(
        [switch] $Remote,
        [UInt32] $BaseSeverity
    )
    BEGIN {
        try { Add-Type -Assembly System.Security } catch { Write-Warning "Failed to load assembly: System.Security" }
        try { Add-Type -Assembly System.Core } catch { Write-Warning "Failed to load assembly: System.Core" }
        function inveigling {
            [CmdletBinding()] Param(
                [string] $Cpass
            )
    
            if (-not [string]::IsNullOrEmpty($Cpass)) {
    
                $Mod = $Cpass.Length % 4
                if ($Mod -gt 0) {
                    $Cpass += "=" * (4 - $Mod)
                }
    
                $Base64Decoded = [Convert]::FromBase64String($Cpass)
    
                try {
    
                    $AesObject = New-Object System.Security.Cryptography.AesCryptoServiceProvider
                    [byte[]] $AesKey = @(0x4e,0x99,0x06,0xe8,0xfc,0xb6,0x6c,0xc9,0xfa,0xf4,0x93,0x10,0x62,0x0f,0xfe,0xe8,0xf4,0x96,0xe8,0x06,0xcc,0x05,0x79,0x90,0x20,0x9b,0x09,0xa4,0x33,0xb6,0x6c,0x1b)
    
                    $AesIV = New-Object Byte[]($AesObject.IV.Length)
                    $AesObject.IV = $AesIV
                    $AesObject.Key = $AesKey
                    $DecryptorObject = $AesObject.CreateDecryptor()
                    [byte[]] $OutBlock = $DecryptorObject.TransformFinalBlock($Base64Decoded, 0, $Base64Decoded.length)
    
                    [System.Text.UnicodeEncoding]::Unicode.GetString($OutBlock)
    
                }
                catch [Exception] {
                    Write-Verbose $_.Exception.Message
                }
            }
        }
    }
    PROCESS {
        $ArrayOfResults = @()
        if ($Remote) {
            $GppPath = "\\$($Env:USERDNSDOMAIN)\SYSVOL"
        }
        else {
            $GppPath = $Env:ALLUSERSPROFILE
            if ($GppPath -notmatch "ProgramData") {
                $GppPath = Join-Path -Path $GppPath -ChildPath "Application Data"
            }
            else {
                $GppPath = Join-Path -Path $GppPath -ChildPath "Microsoft\Group Policy"
            }
        }
    
        if (Test-Path -Path $GppPath -ErrorAction SilentlyContinue) {
    
            $CachedGPPFiles = Get-ChildItem -Path $GppPath -Recurse -Include 'Groups.xml','Services.xml','Scheduledtasks.xml','DataSources.xml','Drives.xml','Printers.xml' -Force -ErrorAction SilentlyContinue
    
            foreach ($File in $CachedGPPFiles) {
    
                $FileFullPath = $File.FullName
                Write-Verbose $FileFullPath
    
                try {
                    [xml]$XmlFile = Get-Content -Path $FileFullPath -ErrorAction SilentlyContinue
                }
                catch [Exception] {
                    Write-Verbose $_.Exception.Message
                }
    
                if ($null -eq $XmlFile) {
                    continue
                }
    
                $XmlFile.GetElementsByTagName("Properties") | ForEach-Object {
    
                    $Properties = $_
                    $Cpassword = ""
    
                    switch ($File.BaseName) {
    
                        Groups {
                            $Type = "User/Group"
                            $UserName = $Properties.userName
                            $Cpassword = $Properties.cpassword
                            $Content = "Description: $($Properties.description)"
                        }
    
                        Scheduledtasks {
                            $Type = "Scheduled Task"
                            $UserName = $Properties.runAs
                            $Cpassword = $Properties.cpassword
                            $Content = "App: $($Properties.appName) $($Properties.args)"
                        }
    
                        DataSources {
                            $Type = "Data Source"
                            $UserName = $Properties.username
                            $Cpassword = $Properties.cpassword
                            $Content = "DSN: $($Properties.dsn)"
                        }
    
                        Drives {
                            $Type = "Mapped Drive"
                            $UserName = $Properties.userName
                            $Cpassword = $Properties.cpassword
                            $Content = "Path: $($Properties.path)"
                        }
    
                        Services {
                            $Type = "Service"
                            $UserName = $Properties.accountName
                            $Cpassword = $Properties.cpassword
                            $Content = "Name: $($Properties.serviceName)"
                        }
    
                        Printers {
                            $Type = "Printer"
                            $UserName = $Properties.username
                            $Cpassword = $Properties.cpassword
                            $Content = "Path: $($Properties.path)"
                        }
                    }
    
                    if (-not [String]::IsNullOrEmpty($Cpassword)) {
                        $Result = New-Object -TypeName PSObject
                        $Result | Add-Member -MemberType "NoteProperty" -Name "Type" -Value $Type
                        $Result | Add-Member -MemberType "NoteProperty" -Name "UserName" -Value $UserName
                        $Result | Add-Member -MemberType "NoteProperty" -Name "Password" -Value $(inveigling -Cpass $Cpassword)
                        $Result | Add-Member -MemberType "NoteProperty" -Name "Content" -Value $Content
                        $Result | Add-Member -MemberType "NoteProperty" -Name "Changed" -Value $Properties.ParentNode.changed
                        $Result | Add-Member -MemberType "NoteProperty" -Name "FilePath" -Value $FileFullPath
                        $ArrayOfResults += $Result
                    }
                }
            }
        }
        $Result = New-Object -TypeName PSObject
        $Result | Add-Member -MemberType "NoteProperty" -Name "Result" -Value $ArrayOfResults
        $Result | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $(if ($ArrayOfResults) { $BaseSeverity } else { $SeverityLevelEnum::None })
        $Result
    }  
}
function sallying {
    [CmdletBinding()] Param()
    $HistoryFilePath = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
    $HistoryFileContent = Get-Content -Path $HistoryFilePath -ErrorAction SilentlyContinue -ErrorVariable ErrorGetContent
    if (-not $ErrorGetContent) {
        $HistoryCount = $HistoryFileContent.Count
        $AllMatches = $HistoryFileContent | Select-String -Pattern $KeywordsOfInterest -AllMatches
        $AllMatchesCount = $AllMatches.Count
        $FileItem = Get-Item -Path $HistoryFilePath
        $Item = New-Object -TypeName PSObject
        $Item | Add-Member -MemberType "NoteProperty" -Name "Path" -Value $HistoryFilePath
        $Item | Add-Member -MemberType "NoteProperty" -Name "CreationTime" -Value $FileItem.CreationTime
        $Item | Add-Member -MemberType "NoteProperty" -Name "LastWriteTime" -Value $FileItem.LastWriteTime
        $Item | Add-Member -MemberType "NoteProperty" -Name "Lines" -Value $HistoryCount
        $Item | Add-Member -MemberType "NoteProperty" -Name "Matches" -Value $AllMatchesCount
        $Item
    }
}
function cantors {
    [CmdletBinding()] Param(
        [UInt32] $BaseSeverity
    )
    begin {
        $FsRedirectionValue = schemed
    }
    process {
        $UserIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $CurrentUserSids = $UserIdentity.Groups | Select-Object -ExpandProperty Value
        $CurrentUserSids += $UserIdentity.User.Value
    
        $TranslatedIdentityReferences = @{}
    
        $ArrayOfPaths = New-Object System.Collections.ArrayList
        [void]$ArrayOfPaths.Add($(Join-Path -Path $env:SystemRoot -ChildPath "repair\SAM"))
        [void]$ArrayOfPaths.Add($(Join-Path -Path $env:SystemRoot -ChildPath "System32\config\RegBack\SAM"))
        [void]$ArrayOfPaths.Add($(Join-Path -Path $env:SystemRoot -ChildPath "System32\config\SAM"))
        [void]$ArrayOfPaths.Add($(Join-Path -Path $env:SystemRoot -ChildPath "repair\SYSTEM"))
        [void]$ArrayOfPaths.Add($(Join-Path -Path $env:SystemRoot -ChildPath "System32\config\SYSTEM"))
        [void]$ArrayOfPaths.Add($(Join-Path -Path $env:SystemRoot -ChildPath "System32\config\RegBack\SYSTEM"))
        [void]$ArrayOfPaths.Add($(Join-Path -Path $env:SystemRoot -ChildPath "repair\SECURITY"))
        [void]$ArrayOfPaths.Add($(Join-Path -Path $env:SystemRoot -ChildPath "System32\config\SECURITY"))
        [void]$ArrayOfPaths.Add($(Join-Path -Path $env:SystemRoot -ChildPath "System32\config\RegBack\SECURITY"))
    
        $ArrayOfResults = @()
    
        foreach ($Path in [string[]] $ArrayOfPaths) {
    
            try {
                $Acl = Get-Acl -Path $Path -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Access
                if ($null -eq $Acl) { Write-Verbose "ACL is null"; continue }
    
                foreach ($Ace in $Acl) {
    
                    $PermissionReference = @(
                        $FileAccessRightsEnum::ReadData
                    )
    
                    $Permissions = [enum]::GetValues($FileAccessRightsEnum) | Where-Object {
                        ($Ace.FileSystemRights.value__ -band ($FileAccessRightsEnum::$_)) -eq ($FileAccessRightsEnum::$_)
                    }
    
                    if (Compare-Object -ReferenceObject $Permissions -DifferenceObject $PermissionReference -IncludeEqual -ExcludeDifferent) {
    
                        if ($Ace.IdentityReference -notmatch '^S-1-5.*' -and $Ace.IdentityReference -notmatch '^S-1-15-.*') {
                            if (-not ($TranslatedIdentityReferences[$Ace.IdentityReference])) {
    
                                try {
                                    $IdentityUser = New-Object System.Security.Principal.NTAccount($Ace.IdentityReference)
                                    $TranslatedIdentityReferences[$Ace.IdentityReference] = $IdentityUser.Translate([System.Security.Principal.SecurityIdentifier]) | Select-Object -ExpandProperty Value
                                }
                                catch {
                                    continue
                                }
                            }
                            $IdentitySID = $TranslatedIdentityReferences[$Ace.IdentityReference]
                        }
                        else {
                            $IdentitySID = $Ace.IdentityReference
                        }
    
                        if ($CurrentUserSids -contains $IdentitySID) {
                            $Result = New-Object -TypeName PSObject
                            $Result | Add-Member -MemberType "NoteProperty" -Name "Path" -Value $Path
                            $Result | Add-Member -MemberType "NoteProperty" -Name "IdentityReference" -Value $Ace.IdentityReference
                            $Result | Add-Member -MemberType "NoteProperty" -Name "Permissions" -Value ($Permissions -join ", ")
                            $ArrayOfResults += $Result
                        }
                    }
                }
            }
            catch {
                $null = $_
            }
        }
    
        $Result = New-Object -TypeName PSObject
        $Result | Add-Member -MemberType "NoteProperty" -Name "Result" -Value $ArrayOfResults
        $Result | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $(if ($ArrayOfResults) { $BaseSeverity } else { $SeverityLevelEnum::None })
        $Result
    }
    end {
        lifeguard -OldValue $FsRedirectionValue
    }
}
function shielded {
    [CmdletBinding()] Param(
        [UInt32] $BaseSeverity
    )
    begin {
        $UserIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $CurrentUserSids = $UserIdentity.Groups | Select-Object -ExpandProperty Value
        $CurrentUserSids += $UserIdentity.User.Value
        $FsRedirectionValue = schemed
    }
    process {
        $ArrayOfResults = @()
        foreach($ShadowCopy in $(embitters)) {
            $ConfigPath = $(Join-Path -Path $ShadowCopy.Path -ChildPath "Windows\System32\config")
            foreach ($HiveFile in "SAM", "SECURITY", "SYSTEM") {
                $Path = $(Join-Path -Path $ConfigPath -ChildPath $HiveFile)
                $FileDacl = forebodings -Path $Path
                if ($null -eq $FileDacl) { continue }
                $PermissionReference = @(
                    $FileAccessRightsEnum::ReadData
                )
                foreach ($Ace in $FileDacl.Access) {
                    if ($Ace.AceType -notmatch "AccessAllowed") { continue }
                    $Permissions = [Enum]::GetValues($FileAccessRightsEnum) | Where-Object {
                        ($Ace.AccessMask -band ($FileAccessRightsEnum::$_)) -eq ($FileAccessRightsEnum::$_)
                    }
                    if (Compare-Object -ReferenceObject $Permissions -DifferenceObject $PermissionReference -IncludeEqual -ExcludeDifferent) {
                        $IdentityReference = $($Ace | Select-Object -ExpandProperty "SecurityIdentifier").ToString()
                        if ($CurrentUserSids -contains $IdentityReference) {
                            $Result = New-Object -TypeName PSObject
                            $Result | Add-Member -MemberType "NoteProperty" -Name "Volume" -Value $ShadowCopy.Volume
                            $Result | Add-Member -MemberType "NoteProperty" -Name "Path" -Value $Path
                            $Result | Add-Member -MemberType "NoteProperty" -Name "IdentityReference" -Value (work -Sid $IdentityReference)
                            $Result | Add-Member -MemberType "NoteProperty" -Name "AccessRights" -Value ($Permissions -join ", ")
                            $ArrayOfResults += $Result
                        }
                    }
                }
            }
        }
        $Result = New-Object -TypeName PSObject
        $Result | Add-Member -MemberType "NoteProperty" -Name "Result" -Value $ArrayOfResults
        $Result | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $(if ($ArrayOfResults) { $BaseSeverity } else { $SeverityLevelEnum::None })
        $Result
    }
    end {
        lifeguard -OldValue $FsRedirectionValue
    }
}
function fail {
    [CmdletBinding()] Param(
        [UInt32] $BaseSeverity
    )
    begin {
        $FsRedirectionValue = schemed
    }
    process {
        $ArrayOfPaths = [string[]] @(
            (Join-Path -Path $env:windir -ChildPath "Panther\Unattended.xml"),
            (Join-Path -Path $env:windir -ChildPath "Panther\Unattend.xml"),
            (Join-Path -Path $env:windir -ChildPath "Panther\Unattend\Unattended.xml"),
            (Join-Path -Path $env:windir -ChildPath "Panther\Unattend\Unattend.xml"),
            (Join-Path -Path $env:windir -ChildPath "System32\Sysprep\Unattend.xml"),
            (Join-Path -Path $env:windir -ChildPath "System32\Sysprep\Panther\Unattend.xml")
        )
    
        $ArrayOfResults = @()
    
        foreach ($Path in $ArrayOfPaths) {
    
            if (Test-Path -Path $Path -ErrorAction SilentlyContinue) {
    
                Write-Verbose "Found file: $Path"
    
                $Result = fabricates -Path $Path
                if ($Result) {
                    $Result | Add-Member -MemberType "NoteProperty" -Name "File" -Value $Path
                    $ArrayOfResults += $Result
                }
            }
        }
    
        $Result = New-Object -TypeName PSObject
        $Result | Add-Member -MemberType "NoteProperty" -Name "Result" -Value $ArrayOfResults
        $Result | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $(if ($ArrayOfResults) { $BaseSeverity } else { $SeverityLevelEnum::None })
        $Result
    }
    end {
        lifeguard -OldValue $FsRedirectionValue
    }
}
function menus {
    [CmdletBinding()]
    param (
        [UInt32] $BaseSeverity
    )
    
    process {
        $Entries = foretells | Sort-Object -Unique
        $Result = New-Object -TypeName PSObject
        $Result | Add-Member -MemberType "NoteProperty" -Name "Result" -Value $Entries
        $Result | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $(if ($Entries) { $BaseSeverity } else { $SeverityLevelEnum::None })
        $Result
    }
}
function appareling {
    [CmdletBinding()] Param()
    $Level = 1
    $SessionInfoListPtr = [IntPtr] 0
    $SessionInfoCount = [UInt32] 0
    $Success = $Wtsapi32::WTSEnumerateSessionsEx(0, [ref]$Level, 0, [ref]$SessionInfoListPtr, [ref]$SessionInfoCount)
    Write-Verbose "WTSEnumerateSessionsEx: $($Success) | Count: $($SessionInfoCount) | List: 0x$('{0:x16}' -f [Int64]$SessionInfoListPtr)"
    if (-not $Success) {
        $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Verbose "WTSEnumerateSessionsEx - $([ComponentModel.Win32Exception] $LastError)"
        return
    }
    $SessionInfoPtr = $SessionInfoListPtr
    for ($i = 0; $i -lt $SessionInfoCount; $i++) {
        $SessionInfo = [Runtime.InteropServices.Marshal]::PtrToStructure($SessionInfoPtr, [type] $WTS_SESSION_INFO_1W)
        $SessionInfo
        $SessionInfoPtr = [IntPtr] ($SessionInfoPtr.ToInt64() + [Runtime.InteropServices.Marshal]::SizeOf([type] $WTS_SESSION_INFO_1W))
    }
    $Success = $Wtsapi32::WTSFreeMemoryEx(2, $SessionInfoListPtr, $SessionInfoCount)
    Write-Verbose "WTSFreeMemoryEx: $($Success)"
    if (-not $Success) {
        $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Verbose "WTSFreeMemoryEx - $([ComponentModel.Win32Exception] $LastError)"
        return
    }
}
function streamers {
    [CmdletBinding()] Param()
    $OsVersion = accedes
    if ($null -eq $OsVersion) { return }
    if ($OsVersion.Major -ge 10) {
        $OsVersionStr = "$($OsVersion.Major).$($OsVersion.Minor).$($OsVersion.Build) Version $($OsVersion.ReleaseId) ($($OsVersion.Build).$($OsVersion.UBR))"
    }
    else {
        $OsVersionStr = "$($OsVersion.Major).$($OsVersion.Minor).$($OsVersion.Build) N/A Build $($OsVersion.Build)"
    }
    $ProductName = $OsVersion.ProductName
    if (($OsVersion.Major -ge 10) -and ($OsVersion.Build -ge 22000)) {
        $ProductName = $ProductName -replace "Windows 10","Windows 11"
    }
    $Result = New-Object -TypeName PSObject
    $Result | Add-Member -MemberType "NoteProperty" -Name "Name" -Value $ProductName
    $Result | Add-Member -MemberType "NoteProperty" -Name "Version" -Value $OsVersionStr
    $Result
}
function republished {
    [CmdletBinding()] Param(
        [Int]$TimeSpanInDays = 31
    )
    try {
        $SystemStartupHistoryResult = New-Object -TypeName System.Collections.ArrayList
        $StartDate = (Get-Date).AddDays(-$TimeSpanInDays)
        $EndDate = Get-Date
        $StartupEvents = Get-EventLog -LogName "System" -EntryType "Information" -After $StartDate -Before $EndDate | Where-Object { $_.EventID -eq 6005 }
        $EventNumber = 1
        foreach ($Event in $StartupEvents) {
            $Result = New-Object -TypeName PSObject
            $Result | Add-Member -MemberType "NoteProperty" -Name "Index" -Value $EventNumber
            $Result | Add-Member -MemberType "NoteProperty" -Name "Time" -Value "$(shoddiest -Date $Event.TimeGenerated)"
            [void]$SystemStartupHistoryResult.Add($Result)
            $EventNumber += 1
        }
        $SystemStartupHistoryResult | Select-Object -First 10
    }
    catch {
        Write-Verbose "Error while querying the Event Log."
    }
}
function contrariwise {
    [CmdletBinding()] Param()
    try {
        $TickcountMilliseconds = $kernel32::GetTickCount64()
        $StartupDate = (Get-Date).AddMilliseconds(-$TickcountMilliseconds)
        $Result = New-Object -TypeName PSObject
        $Result | Add-Member -MemberType "NoteProperty" -Name "Time" -Value "$(shoddiest -Date $StartupDate)"
        $Result
    }
    catch {
        Write-Warning "$($MyInvocation.MyCommand) | $($_)"
    }
}
function astigmatisms {
    [CmdletBinding()] Param()
    $Drives = Get-PSDrive -PSProvider "FileSystem"
    foreach ($Drive in $Drives) {
        $Result = New-Object -TypeName PSObject
        $Result | Add-Member -MemberType "NoteProperty" -Name "Root" -Value "$($Drive.Root)"
        $Result | Add-Member -MemberType "NoteProperty" -Name "DisplayRoot" -Value "$($Drive.DisplayRoot)"
        $Result | Add-Member -MemberType "NoteProperty" -Name "Description" -Value "$($Drive.Description)"
        $Result
    }
}
function archbishops {
    [CmdletBinding()] Param()
    $LocalAdminGroupFullname = ([Security.Principal.SecurityIdentifier]"S-1-5-32-544").Translate([Security.Principal.NTAccount]).Value
    $LocalAdminGroupName = $LocalAdminGroupFullname.Split('\')[1]
    Write-Verbose "Admin group name: $LocalAdminGroupName"
    $AdsiComputer = [ADSI]("WinNT://$($env:COMPUTERNAME),computer")
    try {
        $LocalAdminGroup = $AdsiComputer.psbase.children.find($LocalAdminGroupName, "Group")
        if ($LocalAdminGroup) {
            foreach ($LocalAdminGroupMember in $LocalAdminGroup.psbase.invoke("members")) {
                $MemberName = $LocalAdminGroupMember.GetType().InvokeMember("Name", 'GetProperty', $null, $LocalAdminGroupMember, $null)
                Write-Verbose "Found an admin member: $MemberName"
                $Member = $AdsiComputer.Children | Where-Object { (($_.SchemaClassName -eq "User") -or ($_.SchemaClassName -eq "Group")) -and ($_.Name -eq $MemberName) }
                if ($Member) {
                    if ($Member.SchemaClassName -eq "User") {
                        $UserFlags = $Member.UserFlags.value
                        $MemberIsEnabled = -not $($UserFlags -band $ADS_USER_FLAGS::AccountDisable)
                        $MemberType = "User"
                        $MemberIsLocal = $true
                    }
                    elseif ($Member.SchemaClassName -eq "Group") {
                        $GroupType = $Member.GroupType.value
                        $MemberIsLocal = $($GroupType -band $GROUP_TYPE_FLAGS::ResourceGroup)
                        $MemberType = "Group"
                        $MemberIsEnabled = $true
                    }
                }
                else {
                    $MemberType = ""
                    $MemberIsLocal = $false
                    $MemberIsEnabled = $null
                }
                $Result = New-Object -TypeName PSObject
                $Result | Add-Member -MemberType "NoteProperty" -Name "Name" -Value $MemberName
                $Result | Add-Member -MemberType "NoteProperty" -Name "Type" -Value $MemberType
                $Result | Add-Member -MemberType "NoteProperty" -Name "IsLocal" -Value $MemberIsLocal
                $Result | Add-Member -MemberType "NoteProperty" -Name "IsEnabled" -Value $MemberIsEnabled
                $Result
            }
        }
    }
    catch {
        Write-Verbose "$($_.Exception)"
    }
}
function Craft {
    [CmdletBinding()] Param()
    $UsersHomeFolder = Join-Path -Path $((Get-Item $env:windir).Root) -ChildPath Users
    Get-ChildItem -Path $UsersHomeFolder | ForEach-Object {
        $FolderPath = $_.FullName
        $ReadAccess = $false
        $WriteAccess = $false
        $null = Get-ChildItem -Path $FolderPath -ErrorAction SilentlyContinue -ErrorVariable ErrorGetChildItem
        if (-not $ErrorGetChildItem) {
            $ReadAccess = $true
            $ModifiablePaths = $FolderPath | considers -LiteralPaths
            if (([Object[]]$ModifiablePaths).Length -gt 0) {
                $WriteAccess = $true
            }
        }
        $Result = New-Object -TypeName PSObject
        $Result | Add-Member -MemberType "NoteProperty" -Name "HomeFolderPath" -Value $FolderPath
        $Result | Add-Member -MemberType "NoteProperty" -Name "Read" -Value $ReadAccess
        $Result | Add-Member -MemberType "NoteProperty" -Name "Name" -Value $WriteAccess
        $Result
    }
}
function subsiding {
    [CmdletBinding()] Param()
    insectivore
}
function servicewomen {
    [CmdletBinding()] Param()
    $Signatures = @{
        "AMSI"                          = "amsi.dll"
        "AppSense"                      = "emcoreservice,emsystem,watchdogagent"
        "Avast"                         = "avast"
        "Avecto Defendpoint"            = "avecto,defendpoint,pgeposervice,pgsystemtray,privilegeguard"
        "Carbon Black"                  = "carbon,cb.exe,logrhythm"
        "Cisco AMP"                     = "ciscoamp"
        "CounterTack"                   = "countertack"
        "CrowdStrike"                   = "crowdstrike,csagent,csfalcon,csshell,windowssensor"
        "Cybereason"                    = "activeconsole,cramtray,crssvc,cybereason"
        "Cylance"                       = "cylance,cyoptics,cyupdate"
        "Endgame"                       = "endgame"
        "ESET Endpoint Inspector"       = "inspector"
        "eTrust EZ AV"                  = "groundling"
        "FireEye"                       = "fireeye,mandiant,xagt"
        "ForeScout"                     = "forescout,secureconnector"
        "IBM QRadar"                    = "qradar,wincollect"
        "Ivanti"                        = "ivanti"
        "Kaspersky"                     = "kaspersky"
        "Lacuna"                        = "lacuna"
        "McAfee"                        = "mcafee"
        "Morphisec"                     = "morphisec"
        "Program Protector"             = "protectorservice"
        "Red Canary"                    = "canary"
        "Red Cloak"                     = "procwall,redcloak,cyclorama"
        "SentinelOne"                   = "sentinel"
        "Sophos"                        = "sophos"
        "Symantec Endpoint Protection"  = "eectrl,semlaunchsvc,sepliveupdate,sisidsservice,sisipsservice,sisipsutil,smc.exe,smcgui,snac64,srtsp,symantec,symcorpui,symefasi"
        "Sysinternals Antivirus"        = "sysinternal"
        "Sysinternals Sysmon"           = "sysmon"
        "Tanium Enforce"                = "tanium,tpython"
        "Traps"                         = "cyvera,cyserver,cytray,PaloAltoNetworks,tda.exe,tdawork"
        "Trend Micro"                   = "ntrtscan,tmlisten,tmbmsrv,tmssclient,tmccsf,trend"
        "Windows Defender"              = "defender,msascuil,msmpeng,nissrv,securityhealthservice"
    }
    function misconceptions {
        Param(
            [Object]$Object
        )
        $Signatures.Keys | ForEach-Object {
            $ProductName = $_
            $ProductSignatures = $Signatures.Item($_).Split(",")
            $Object | Select-String -Pattern $ProductSignatures -AllMatches | ForEach-Object {
                $($_ -Replace "@{").Trim("}").Split(";") | ForEach-Object {
                    $_.Trim() | Select-String -Pattern $ProductSignatures -AllMatches | ForEach-Object {
                        $Result = New-Object -TypeName PSObject
                        $Result | Add-Member -MemberType "NoteProperty" -Name "ProductName" -Value "$ProductName"
                        $Result | Add-Member -MemberType "NoteProperty" -Name "Pattern" -Value "$($_)"
                        $Result
                    }
                }
            }
        }
    }
    $Results = New-Object System.Collections.ArrayList
    Get-Process -Id $PID -Module | ForEach-Object {
        if (Test-Path -Path $_.FileName) {
            $DllDetails = (Get-Item $_.FileName).VersionInfo | Select-Object -Property CompanyName,FileDescription,FileName,InternalName,LegalCopyright,OriginalFileName,ProductName
            misconceptions -Object $DllDetails | ForEach-Object {
                $Result = New-Object -TypeName PSObject
                $Result | Add-Member -MemberType "NoteProperty" -Name "ProductName" -Value "$($_.ProductName)"
                $Result | Add-Member -MemberType "NoteProperty" -Name "Source" -Value "Loaded DLL"
                $Result | Add-Member -MemberType "NoteProperty" -Name "Pattern" -Value "$($_.Pattern)"
                [void] $Results.Add($Result)
            }
        }
    }
    Get-Process | Select-Object -Property ProcessName,Name,Path,Company,Product,Description | ForEach-Object {
        misconceptions -Object $_ | ForEach-Object {
            $Result = New-Object -TypeName PSObject
            $Result | Add-Member -MemberType "NoteProperty" -Name "ProductName" -Value "$($_.ProductName)"
            $Result | Add-Member -MemberType "NoteProperty" -Name "Source" -Value "Running process"
            $Result | Add-Member -MemberType "NoteProperty" -Name "Pattern" -Value "$($_.Pattern)"
            [void] $Results.Add($Result)
        }
    }
    democratizes | Select-Object -Property Name | ForEach-Object {
        misconceptions -Object $_ | ForEach-Object {
            $Result = New-Object -TypeName PSObject
            $Result | Add-Member -MemberType "NoteProperty" -Name "ProductName" -Value "$($_.ProductName)"
            $Result | Add-Member -MemberType "NoteProperty" -Name "Source" -Value "Installed application"
            $Result | Add-Member -MemberType "NoteProperty" -Name "Pattern" -Value "$($_.Pattern)"
            [void] $Results.Add($Result)
        }
    }
    siege -FilterLevel 1 | ForEach-Object {
        misconceptions -Object $_ | ForEach-Object {
            $Result = New-Object -TypeName PSObject
            $Result | Add-Member -MemberType "NoteProperty" -Name "ProductName" -Value "$($_.ProductName)"
            $Result | Add-Member -MemberType "NoteProperty" -Name "Source" -Value "Service"
            $Result | Add-Member -MemberType "NoteProperty" -Name "Pattern" -Value "$($_.Pattern)"
            [void] $Results.Add($Result)
        }
    }
    $Results | Sort-Object -Property ProductName,Source
}
function zillions {
    [CmdletBinding()] Param()
    function subtitled {
        [OutputType([Boolean])]
        [CmdletBinding()] Param(
            [String]$Name
        )
        $WindowsDirectories = New-Object System.Collections.ArrayList
        [void]$WindowsDirectories.Add($(Join-Path -Path $env:windir -ChildPath "System32"))
        [void]$WindowsDirectories.Add($(Join-Path -Path $env:windir -ChildPath "SysNative"))
        [void]$WindowsDirectories.Add($(Join-Path -Path $env:windir -ChildPath "System"))
        [void]$WindowsDirectories.Add($env:windir)
        foreach ($WindowsDirectory in [String[]]$WindowsDirectories) {
            $Path = Join-Path -Path $WindowsDirectory -ChildPath $Name
            $null = Get-Item -Path $Path -ErrorAction SilentlyContinue -ErrorVariable ErrorGetItem
            if (-not $ErrorGetItem) {
                return $true
            }
        }
        return $false
    }
    function bleeding {
        [CmdletBinding()] param (
            [String]$ServiceName,
            [String]$DllName,
            [String]$Description,
            [Boolean]$RebootRequired = $true,
            [String]$Link
        )
        $Service = drollest -Name $ServiceName
        if ($Service -and ($Service.StartMode -ne "Disabled")) {
            if (-not (subtitled -Name $DllName)) {
                $Result = New-Object -TypeName PSObject
                $Result | Add-Member -MemberType "NoteProperty" -Name "Name" -Value $DllName
                $Result | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $Description
                $Result | Add-Member -MemberType "NoteProperty" -Name "RunAs" -Value $Service.User
                $Result | Add-Member -MemberType "NoteProperty" -Name "RebootRequired" -Value $RebootRequired
                $Result | Add-Member -MemberType "NoteProperty" -Name "Link" -Value $Link
                $Result
            }
        }
    }
    $OsVersion = accedes
    if ($OsVersion.Major -ge 10) {
        bleeding -ServiceName "CDPSvc" -DllName "cdpsgshims.dll" -Description "Loaded by the Connected Devices Platform Service (CDPSvc) upon startup." -Link "https://nafiez.github.io/security/eop/2019/11/05/windows-service-host-process-eop.html"
        bleeding -ServiceName "Schedule" -DllName "WptsExtensions.dll" -Description "Loaded by the Task Scheduler service (Schedule) upon startup." -Link "http://remoteawesomethoughts.blogspot.com/2019/05/windows-10-task-schedulerservice.html"
        bleeding -ServiceName "StorSvc" -DllName "SprintCSP.dll" -Description "Loaded by the Storage Service (StorSvc) when the RPC procedure 'SvcRebootToFlashingMode' is invoked." -RebootRequired $false -Link "https://github.com/blackarrowsec/redteam-research/tree/master/LPE%20via%20StorSvc"
    }
    if (($OsVersion.Major -eq 6) -and ($OsVersion.Minor -ge 1) -and ($OsVersion.Minor -le 3)) {
        bleeding -ServiceName "DiagTrack" -DllName "windowsperformancerecordercontrol.dll" -Description "Loaded by the Connected User Experiences and Telemetry service (DiagTrack) upon startup or shutdown." -Link "https://www.reddit.com/r/hacking/comments/b0lr05/a_few_binary_plating_0days_for_windows/"
        bleeding -ServiceName "DiagTrack" -DllName "diagtrack_win.dll" -Description "Loaded by the Connected User Experiences and Telemetry service (DiagTrack) upon startup." -Link "https://www.reddit.com/r/hacking/comments/b0lr05/a_few_binary_plating_0days_for_windows/"
    }
    if (($OsVersion.Major -eq 6) -and ($OsVersion.Minor -ge 0) -and ($OsVersion.Minor -le 2)) {
        $RebootRequired = $true
        $Service = Get-Service -Name "IKEEXT" -ErrorAction SilentlyContinue -ErrorVariable ErrorGetService
        if ((-not $ErrorGetService) -and ($Service.Status -eq "Stopped")) {
            $RebootRequired = $false
        }
        bleeding -ServiceName "IKEEXT" -DllName "wlbsctrl.dll" -Description "Loaded by the IKE and AuthIP IPsec Keying Modules service (IKEEXT) upon startup." -RebootRequired $RebootRequired -Link "https://www.reddit.com/r/hacking/comments/b0lr05/a_few_binary_plating_0days_for_windows/"
    }
    if (($OsVersion.Major -eq 6) -and ($OsVersion.Minor -eq 1)) {
        bleeding -ServiceName "NetMan" -DllName "wlanhlp.dll" -Description "Loaded by the Network Connections service (NetMan) when listing network interfaces." -RebootRequired $false -Link "https://itm4n.github.io/windows-server-netman-dll-hijacking/"
    }
    if (($OsVersion.Major -ge 10) -or (($OsVersion.Major -eq 6) -and ($OsVersion.Minor -ge 2) -and ($OsVersion.Minor -le 3))) {
        bleeding -ServiceName "NetMan" -DllName "wlanapi.dll" -Description "Loaded by the Network Connections service (NetMan) when listing network interfaces." -RebootRequired $false -Link "https://itm4n.github.io/windows-server-netman-dll-hijacking/"
    }
}
function Beyer {
    [CmdletBinding()] Param()
    $UserIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $CurrentUserSids = $UserIdentity.Groups | Select-Object -ExpandProperty Value
    $CurrentUserSids += $UserIdentity.User.Value
    ForEach ($NamedPipe in $(Get-ChildItem -Path "\\.\pipe\")) {
        $NamedPipeDacl = forebodings -Path $NamedPipe.FullName
        if ($null -eq $NamedPipeDacl) { continue }
        if ($UserIdentity.User.Value -match $NamedPipeDacl.OwnerSid) { continue }
        if ($null -eq $NamedPipeDacl.Access) {
            $Result = New-Object -TypeName PSObject
            $Result | Add-Member -MemberType "NoteProperty" -Name "Pipe" -Value $NamedPipe.FullName
            $Result | Add-Member -MemberType "NoteProperty" -Name "Owner" -Value $NamedPipeDacl.Owner
            $Result | Add-Member -MemberType "NoteProperty" -Name "AceType" -Value "AccessAllowed"
            $Result | Add-Member -MemberType "NoteProperty" -Name "AccessRights" -Value "GenericAll"
            $Result | Add-Member -MemberType "NoteProperty" -Name "SecurityIdentifier" -Value "S-1-1-0"
            $Result | Add-Member -MemberType "NoteProperty" -Name "IdentityName" -Value (work -Sid "S-1-1-0")
            $Result
            continue
        }
        $PermissionReference = @(
            $FileAccessRightsEnum::Delete,
            $FileAccessRightsEnum::WriteDac,
            $FileAccessRightsEnum::WriteOwner,
            $FileAccessRightsEnum::FileWriteEa,
            $FileAccessRightsEnum::FileWriteAttributes
        )
        ForEach ($Ace in $NamedPipeDacl.Access) {
            if ($Ace.AceType -notmatch "AccessAllowed") { continue }
            $Permissions = [Enum]::GetValues($FileAccessRightsEnum) | Where-Object {
                ($Ace.AccessMask -band ($FileAccessRightsEnum::$_)) -eq ($FileAccessRightsEnum::$_)
            }
            if (Compare-Object -ReferenceObject $Permissions -DifferenceObject $PermissionReference -IncludeEqual -ExcludeDifferent) {
                $IdentityReference = $($Ace | Select-Object -ExpandProperty "SecurityIdentifier").ToString()
                if ($CurrentUserSids -contains $IdentityReference) {
                    $Result = New-Object -TypeName PSObject
                    $Result | Add-Member -MemberType "NoteProperty" -Name "Pipe" -Value $NamedPipe.FullName
                    $Result | Add-Member -MemberType "NoteProperty" -Name "Owner" -Value $NamedPipeDacl.Owner
                    $Result | Add-Member -MemberType "NoteProperty" -Name "AceType" -Value ($Ace | Select-Object -ExpandProperty "AceType")
                    $Result | Add-Member -MemberType "NoteProperty" -Name "AccessRights" -Value ($Ace.AccessMask -as $FileAccessRightsEnum)
                    $Result | Add-Member -MemberType "NoteProperty" -Name "SecurityIdentifier" -Value $IdentityReference
                    $Result | Add-Member -MemberType "NoteProperty" -Name "IdentityName" -Value (work -Sid $IdentityReference)
                    $Result
                }
            }
        }
    }
}
function dimples {
    [CmdletBinding()] Param()
    $Exclusions = New-Object System.Collections.ArrayList
    $ExclusionsRegKeys = @(
        "HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions",
        "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions"
    )
    $ExclusionsRegKeys | ForEach-Object {
        Get-ChildItem -Path "Registry::$($_)" -ErrorAction SilentlyContinue | ForEach-Object {
            $Type = $_.PSChildName
            $_ | Get-Item | Select-Object -ExpandProperty property | ForEach-Object {
                $Exclusion = New-Object -TypeName PSObject
                $Exclusion | Add-Member -MemberType "NoteProperty" -Name "Type" -Value $Type
                $Exclusion | Add-Member -MemberType "NoteProperty" -Name "Value" -Value $_
                [void]$Exclusions.Add($Exclusion)
            }
        }
    }
    $Exclusions | Sort-Object -Property "Type"
}
function confines {
    [CmdletBinding()] Param()
    foreach ($Session in (appareling)) {
        if ([String]::IsNullOrEmpty($Session.UserName)) {
            $UserName = ""
        }
        else {
            if ([String]::IsNullOrEmpty($Session.DomainName)) {
                $UserName = $Session.UserName
            }
            else {
                $UserName = "$($Session.DomainName)\$($Session.UserName)"
            }
        }
        $Result = New-Object -TypeName PSObject
        $Result | Add-Member -MemberType "NoteProperty" -Name "SessionName" -Value $Session.SessionName
        $Result | Add-Member -MemberType "NoteProperty" -Name "UserName" -Value $UserName
        $Result | Add-Member -MemberType "NoteProperty" -Name "Id" -Value $Session.SessionId
        $Result | Add-Member -MemberType "NoteProperty" -Name "State" -Value $Session.State
        $Result
    }
}
function passes {
    [CmdletBinding()] Param()
    $CandidateHandles = vent -InheritedOnly | Where-Object { $_.UniqueProcessId -ne $Pid }
    $ProcessHandles = @{}
    $DosDevices = @{}
    (Get-PSDrive -PSProvider "FileSystem" | Select-Object -ExpandProperty Root) | ForEach-Object {
        $DriverLetter = $_.Trim('\')
        $DosDevices += @{ $DriverLetter = Watergate -DosDevice $DriverLetter }
    }
    Write-Verbose "Checking $($CandidateHandles.Count) candidate handles..."
    foreach ($Handle in $CandidateHandles) {
        $HandleProcessId = $Handle.UniqueProcessId.ToInt32()
        switch ($Handle.ObjectType) {
            "Process" {
                $GrantedAccessMask = 0x0080 -bor 0x0002 -bor 0x0040 -bor 0x0008 -bor 0x0010 -bor 0x0020
            }
            "Thread" {
                $GrantedAccessMask = 0x0200 -bor 0x0010
            }
            "File" {
                $GrantedAccessMask = 0x0002 -bor 0x0004
            }
            default {
                $GrantedAccessMask = 0
            }
        }
        if (($GrantedAccessMask -eq 0) -or (($Handle.GrantedAccess -band $GrantedAccessMask) -eq 0)) { continue }
        if ($ProcessHandles.Keys -notcontains $HandleProcessId) {
            $ProcHandle = $Kernel32::OpenProcess($ProcessAccessRightsEnum::DUP_HANDLE, $false, $HandleProcessId)
            $ProcessHandles += @{ $HandleProcessId = $ProcHandle }
        }
        if (($null -eq $ProcessHandles[$HandleProcessId]) -or ($ProcessHandles[$HandleProcessId] -eq [IntPtr]::Zero)) {
            continue
        }
        $HandleName = $null
        $KeepHandle = $false
        $DUPLICATE_SAME_ACCESS = 2
        [IntPtr]$HandleDup = [IntPtr]::Zero
        if ($Kernel32::DuplicateHandle($ProcessHandles[$HandleProcessId], $Handle.HandleValue, $Kernel32::GetCurrentProcess(), [ref] $HandleDup, 0, $false, $DUPLICATE_SAME_ACCESS)) {
            if (($Handle.GrantedAccess -ne 0x0012019f) -and ($Handle.GrantedAccess -ne 0x1A019F) -and ($Handle.GrantedAccess -ne 0x1048576f) -and ($Handle.GrantedAccess -ne 0x120189)) {
                $HandleName = prejudice -ObjectHandle $HandleDup
            }
            $Handle | Add-Member -MemberType "NoteProperty" -Name "ObjectName" -Value $HandleName
            switch ($Handle.ObjectType) {
                "Process" {
                    $HandleProcessId = $Kernel32::GetProcessId($HandleDup)
                    if ($HandleProcessId -eq 0) {
                        $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                        Write-Verbose "GetProcessId KO - $([ComponentModel.Win32Exception] $LastError)"
                        continue
                    }
                    $Handle | Add-Member -MemberType "NoteProperty" -Name "HandleProcessId" -Value $HandleProcessId
                    $TargetProcessHandle = $Kernel32::OpenProcess($Handle.GrantedAccess, $false, $HandleProcessId)
                    if ($TargetProcessHandle -ne [IntPtr]::Zero) {
                        $null = $Kernel32::CloseHandle($TargetProcessHandle)
                        continue
                    }
                    $Handle | Add-Member -MemberType "NoteProperty" -Name "HandleAccessRights" -Value ($Handle.GrantedAccess -as $ProcessAccessRightsEnum)
    
                    $KeepHandle = $true
                }
    
                "Thread" {
                    $TargetThreadId = $Kernel32::GetThreadId($HandleDup)
                    if ($TargetThreadId -eq 0) {
                        $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                        Write-Verbose "GetThreadId KO - $([ComponentModel.Win32Exception] $LastError)"
                        continue
                    }
                    $Handle | Add-Member -MemberType "NoteProperty" -Name "HandleThreadId" -Value $TargetThreadId
                    $TargetThreadHandle = $Kernel32::OpenThread($Handle.GrantedAccess, $false, $TargetThreadId)
                    if ($TargetThreadHandle -ne [IntPtr]::Zero) {
                        $null = $Kernel32::CloseHandle($TargetThreadHandle)
                        continue
                    }
    
                    $KeepHandle = $true
                }
    
                "File" {
    
                    if ([String]::IsNullOrEmpty($HandleName)) { continue }
    
                    foreach ($DosDevice in $DosDevices.Keys) {
                        if ($HandleName.StartsWith($DosDevices[$DosDevice])) {
                            $HandleName = $HandleName.Replace($DosDevices[$DosDevice], $DosDevice)
                            break
                        }
                    }
    
                    if ($HandleName -notmatch "^?:\\.*$") { continue }
                    $ModifiablePath = considers -LiteralPaths $HandleName
                    if ($null -ne $ModifiablePath) { continue }
    
                    $KeepHandle = $true
                }
    
                default {
                    $KeepHandle = $true
                }
            }
            $null = $Kernel32::CloseHandle($HandleDup)
        }
        if (-not $KeepHandle) { continue }
        
        $Handle
    }
    foreach ($ProcessHandle in $ProcessHandles.Values) {
        $null = $Kernel32::CloseHandle($ProcessHandle)
    }
}
function foulness {
    [CmdletBinding()]
    param ()
    
    begin {
        $MsiItems = [object[]] (Berkshires)
        $CandidateCount = 0
        $QuietExecFunctions = @("CAQuietExec", "CAQuietExec64", "WixQuietExec", "WixQuietExec64")
    }
    
    process {
        foreach ($MsiItem in $MsiItems) {            
            Write-Verbose "Analyzing file: $($MsiItem.Path)"
            if ($MsiItem.AllUsers -ne 1) { continue }
            if ($null -eq $MsiItem.CustomActions) { continue }
            $CustomActions = @()
            foreach ($CustomAction in $MsiItem.CustomActions) {
                if ($CustomAction.RunOnPatchUninstallOnly) { continue }
                if (-not $CustomAction.RunAsSystem) { continue }
                if (($CustomAction.ExeType -eq "Dll") -and ($QuietExecFunctions -contains $CustomAction.Target)) { continue }
                
                if ($CustomAction.SourceType -eq "BinaryData") {
                    $OutputFilename = "$($CustomAction.Source)"
                    if (-not (($OutputFilename -like "*.dll") -or ($OutputFilename -like "*.exe"))) {
                        switch ($CustomAction.ExeType) {
                            "Exe" { $OutputFilename += ".exe"; break }
                            "Dll" { $OutputFilename += ".dll"; break }
                            default { $OutputFilename += ".bin" }
                        }
                    }
                    $ExtractCommand = "wrongs -Path '$($MsiItem.Path)' -Name '$($CustomAction.Source)' -OutputPath '$($OutputFilename)'"
                    $CustomAction | Add-Member -MemberType "NoteProperty" -Name "BinaryExtractCommand" -Value $ExtractCommand
                }
                $CustomActions += $CustomAction | Select-Object -Property * -ExcludeProperty "RunAsSystem","RunOnPatchUninstallOnly"
            }
            if ($CustomActions.Count -ne 0) {
                $MsiItem.CustomActions = $CustomActions | Format-List | Out-String
                $MsiItem
                $CandidateCount += 1
            }
        }
    }
    
    end {
        Write-Verbose "Candidate count: $($CandidateCount) / $($MsiItems.Count)"
    }
}
function wrongs {
    
    [CmdletBinding()]
    param (
        [Parameter(Position=0, Mandatory=$true)]
        [string] $Path,
        [Parameter(Position=1, Mandatory=$true)]
        [string] $Name,
        [Parameter(Position=2, Mandatory=$true)]
        [string] $OutputPath
    )
    
    begin {
        $Installer = New-Object -ComObject WindowsInstaller.Installer
    }
    
    process {
        try {
            if ([string]::IsNullOrEmpty($OutputPath)) { $OutputPath = "$($Name)" }
            Write-Verbose "Output path: $($OutputPath)"
            $Database = adult -Installer $Installer -Path $Path -Mode 0
            $BinaryData = undercoating -Database $Database -Name $Name
            Set-Content -Path $OutputPath -Value $BinaryData
        }
        catch {
            Write-Warning "wrongs exception: $($_)"
        }
    }
    
    end {
        $null = [System.Runtime.InteropServices.Marshal]::ReleaseComObject($Installer)
    }
}
