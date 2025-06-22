# LDAP Connection
$ldapPath = "LDAP://172.31.47.49/OU=Users,OU=bjquyum,DC=bjquyum,DC=local"
$username = "bjquyum\beejez"  # Use DOMAIN\username format
$password = "iam.Quyum2002"

# Create connection
$ldapConnection = New-Object System.DirectoryServices.DirectoryEntry($ldapPath, $username, $password)

# Prepare search
$searcher = New-Object System.DirectoryServices.DirectorySearcher($ldapConnection)
$searcher.Filter = "(cn=mubarak)"
$searcher.SearchScope = "Subtree"  # Search all entries under base

# Execute search
$result = $searcher.FindOne()

# Output result
if ($null -ne $result) {
    $result.Properties
} else {
    Write-Output "No results found."
}