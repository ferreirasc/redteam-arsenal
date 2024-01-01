<#
.NOTES    
    Author: Thiago Oliveira
    Version: 10 
.DESCRIPTION
    -- Check ACL Abuse and LAPS Permission
.EXAMPLE
    -- To check User, computer or group. It is necessary to specify the class you want to collect.
    
    PS D:\teste> .\Invoke-ACLScanner.ps1 -ClassName User|group|computer -DomainName contoso.local

    -- To check User, computer or group. It is necessary to specify the class you want to collect.

    PS D:\teste> .\Invoke-ACLScanner.ps1 -ClassName User|group|computer -DomainName contoso.local -Name username
#>
[CmdletBinding()]
Param(
    [Parameter(Mandatory=$false)]
    [string]
    $ClassName,

    [Parameter(Mandatory=$False)]
    [string]
    $Name,

    [Parameter(Mandatory=$false)]
    [string]
    $DomainName,

    [Parameter(Mandatory=$False)]
    [System.Management.Automation.PSCredential]
    [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty

)
if ($PSBoundParameters.ContainsKey('DomainName')) {
    $DomainName = "LDAP://$DomainName"
}else{
    $DomainName = "LDAP://$env:USERDNSDOMAIN"
}
$directoryEntryArgs = @($DomainName)

if ($PSBoundParameters.ContainsKey('Credential')) {
    $directoryEntryArgs += @(
        $Credential.UserName
        $Credential.GetNetworkCredential().Password
    )
}
$adsiSearcherObj = [adsisearcher][ADSI]"$DomainName"
$adsiSearcherObj.Filter = "(objectClass=$ClassName)"

$Domain = New-Object -TypeName System.DirectoryServices.DirectoryEntry -ArgumentList $directoryEntryArgs
$adsiSearcherObj.SearchRoot = $Domain
$allsobjects= $adsiSearcherObj.FindAll()

$allacls = New-Object 'System.Collections.Generic.List[System.Object]'  

foreach($rawObject in $allsobjects){
    
    $baseObject = $rawObject.GetDirectoryEntry()

    $acls = $baseObject.ObjectSecurity.Access | Where-Object {
        (($_.ObjectType -eq '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2') -or 
        ($_.ObjectType -eq '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2') -or 
        ($_.ObjectType -eq '89e95b76-444d-4c62-991a-0facbeda640c') -or
        ($_.ObjectType -eq 'bf9679c0-0de6-11d0-a285-00aa003049e2') -or 
        ($_.ObjectType -eq '00299570-246d-11d0-a768-00aa006e0529') -or 
        ($_.ObjectType -eq '2a90118e-8185-4539-b84c-8a02540fb8ba') -or 
        ($_.ObjectType -eq '00000000-0000-0000-0000-000000000000')) -and 
        ($_.IdentityReference -notmatch "NT AUTHORITY|Compatible Access|BUILTIN|Domain Admins|Enterprise Admins|CREATOR OWNER|S-1-5-32-548") -and
        ($_.ActiveDirectoryRights -match "GenericAll|GenericWrite|CreateChild|DeleteChild|WriteOwner|WriteProperty|WriteDACL|ExtendedRight|Self")}|
        Select-Object -Property @{Name='Name';Expression={$rawObject.Properties.samaccountname}}, ActiveDirectoryRights,
        @{Name='ObjectType';Expression={
            if($_.ObjectType -eq '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'){'DS-Replication-Get-Changes'}
            if($_.ObjectType -eq '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'){'DS-Replication-Get-Changes-All'}
            if($_.ObjectType -eq '89e95b76-444d-4c62-991a-0facbeda640c'){'DS-Replication-Get-Changes-In-Filtered-Set'}
            if($_.ObjectType -eq 'bf9679c0-0de6-11d0-a285-00aa003049e2'){'Self-Member'}
            if($_.ObjectType -eq '2a90118e-8185-4539-b84c-8a02540fb8ba'){'LAPS-ms-Mcs-AdmPwd'}
            if($_.ObjectType -eq '00299570-246d-11d0-a768-00aa006e0529'){'User-Force-Change-Password'}
            if($_.ObjectType -eq '00000000-0000-0000-0000-000000000000'){'ALL'}}}, 
        IdentityReference, AccessControlType 

    if ($Name) {
        $facl = $acls | Where-Object {($_.IdentityReference -match $Name)}
    }else{
        $facl = $acls 
    }
    foreach ($acl in $facl){
               
        if ($acl.ObjectType -ne $null){

            $obj = [PSCustomObject]@{
                            
                'Target'				                = ($rawObject.Properties.distinguishedname).Replace("{|}","")
                'Account Name'                          = if($null -ne $rawObject.Properties.samaccountname ){$rawObject.Properties.samaccountname}else{}
                'Type'                                  = if($rawObject.Properties){($rawObject.Properties.objectclass) -split "{" | Select-Object -Last 1}else{}
                'ActiveDirectoryRights'                 = $ACL.ActiveDirectoryRights
                'ObjectType'                            = $ACL.ObjectType
                'IdentityReference'				        = $ACL.IdentityReference
                'AccessControlType'	                    = $ACL.AccessControlType
            }
            $allacls.Add($obj)
        }
    }    
}
$allacls | Sort-Object Target


