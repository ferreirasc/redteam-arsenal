# Set the base LDAP path for GPOs
$baseDN = "LDAP://CN=Policies,CN=System,DC=lab,DC=corp"  # Modify this according to your domain

# Create a Directory Searcher object
$searcher = New-Object DirectoryServices.DirectorySearcher
$searcher.SearchRoot = New-Object DirectoryServices.DirectoryEntry($baseDN)
$searcher.Filter = "(objectClass=groupPolicyContainer)"
$searcher.PropertiesToLoad.AddRange(@("displayName"))

# Perform the search
$results = $searcher.FindAll()

# Iterate over results and get permissions for each GPO
foreach ($result in $results) {
    $GPOName = $result.Properties["displayName"]
    Write-Host "Permissions for $GPOName GPO:"

    # Filter the search for the current GPO
    $searcher.Filter = "(&(objectClass=groupPolicyContainer)(displayName=$GPOName))"
    $searchResult = $searcher.FindOne()

    if ($searchResult -eq $null) {
        Write-Host "GPO '$GPOName' not found."
	continue
    }

    $GPO = $searchResult.GetDirectoryEntry()

    # Get the security descriptor of the GPO
    $securityDescriptor = $GPO.ObjectSecurity

    # Iterate through the access rules and print permissions
    foreach ($accessRule in $securityDescriptor.Access) {
        $identity = $accessRule.IdentityReference.value
        $permission = $accessRule.ActiveDirectoryRights
        $objectType = $accessRule.ObjectType
        if ($identity -notmatch "SYSTEM|CREATOR OWNER|Domain Admins|Enterprise Admins|Domain Controllers" -and $objectType -notmatch "edacfd8f-ffb3-11d1-b41d-00a0c968f939") {
            Write-Output "$identity has $permission permissions on $GPOName GPO"
        }
    }
}
