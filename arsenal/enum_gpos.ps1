# Set the base LDAP path for GPOs
$baseDN = "LDAP://CN=Policies,CN=System,DC=lab,DC=corp"  # Modify this according to your domain

# Create a Directory Searcher object
$searcher = New-Object DirectoryServices.DirectorySearcher
$searcher.SearchRoot = New-Object DirectoryServices.DirectoryEntry($baseDN)
$searcher.Filter = "(objectClass=groupPolicyContainer)"
$searcher.PropertiesToLoad.AddRange(@("displayName"))

# Perform the search
$results = $searcher.FindAll()

$baseDN = "LDAP://DC=lab,DC=corp"
$searcher2 = New-Object DirectoryServices.DirectorySearcher
$searcher2.SearchRoot = New-Object DirectoryServices.DirectoryEntry($baseDN)
$searcher2.Filter = "(&(objectClass=*)(gPLink=*))"
$searcher2.PageSize = 1000
$ADobjects = $searcher2.FindAll()
#$ADobjects

# Iterate over results and get permissions for each GPO
foreach ($result in $results) {
    $GPOName = $result.Properties["displayName"]
    Write-Host "================================================="
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
    $condition = $false
    # Iterate through the access rules and print permissions
    foreach ($accessRule in $securityDescriptor.Access) {
        $identity = $accessRule.IdentityReference.value
        $permission = $accessRule.ActiveDirectoryRights
        $objectType = $accessRule.ObjectType
        if ($identity -notmatch "SYSTEM|CREATOR OWNER|Domain Admins|Enterprise Admins|Domain Controllers" -and $objectType -notmatch "edacfd8f-ffb3-11d1-b41d-00a0c968f939") {
            if(-not ($identity -match "Authenticated Users" -and $permission -match "GenericRead")){
                 Write-Output "$identity has $permission permissions on $GPOName GPO"
                 $condition = $true
	    }
        }
    }

    if ($condition -eq $false){
       continue
    }

    $pattern = '\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}'
    $GPO_GUID = [regex]::Matches($result.Properties["adspath"], $pattern) | ForEach-Object { $_.Value }
    
    if($GPO_GUID -eq $null){ continue }

    #Enumerating all the GPOs associated to gplinks and checking if we have a match

    Write-Output "Objects linked to this GPO:"

    foreach($ADobject in $ADobjects){
        $pattern = '\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}'
	# Extract GPO GUIDs using the regular expression
	$GPOGUIDs = [regex]::Matches($ADobject.Properties["gplink"], $pattern) | ForEach-Object { $_.Value }
	if($GPOGUIDs.Contains($GPO_GUID)){
		$ADobject.Path
	}
	# Output the extracted GPO GUIDs
	#Write-Output "Applied GPOs: $GPOGUIDs"
    }

}