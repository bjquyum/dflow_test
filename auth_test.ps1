$ldapPath = "LDAP://172.31.47.49/CN=beejez,OU=Users,DC=bjquyum,DC=local"
$username = "bjquyum\\beejez"
$password = "the_actual_password_for_beejez"
$ldapConnection = New-Object System.DirectoryServices.DirectoryEntry($ldapPath, $username, $password)
$ldapConnection.NativeObject  # This will throw if the bind fails