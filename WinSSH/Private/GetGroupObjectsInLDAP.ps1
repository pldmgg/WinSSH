function GetGroupObjectsInLDAP {
    [CmdletBinding()]
    Param()

    # Below $LDAPInfo Output is PSCustomObject with properties: DirectoryEntryInfo, LDAPBaseUri,
    # GlobalCatalogConfigured3268, GlobalCatalogConfiguredForSSL3269, Configured389, ConfiguredForSSL636,
    # PortsThatWork
    try {
        $DomainControllerInfo = GetDomainController -ErrorAction Stop
        $LDAPInfo = TestLDAP -ADServerHostNameOrIP $DomainControllerInfo.PrimaryDomainController -ErrorAction Stop
        if (!$DomainControllerInfo) {throw "Problem with GetDomainController function! Halting!"}
        if (!$LDAPInfo) {throw "Problem with TestLDAP function! Halting!"}
    }
    catch {
        Write-Error $_
        $global:FunctionResult = "1"
        return
    }

    if (!$LDAPInfo.PortsThatWork) {
        Write-Error "Unable to access LDAP on $($DomainControllerInfo.PrimaryDomainController)! Halting!"
        $global:FunctionResult = "1"
        return
    }

    if ($LDAPInfo.PortsThatWork -contains "389") {
        $LDAPUri = $LDAPInfo.LDAPBaseUri + ":389"
    }
    elseif ($LDAPInfo.PortsThatWork -contains "3268") {
        $LDAPUri = $LDAPInfo.LDAPBaseUri + ":3268"
    }
    elseif ($LDAPInfo.PortsThatWork -contains "636") {
        $LDAPUri = $LDAPInfo.LDAPBaseUri + ":636"
    }
    elseif ($LDAPInfo.PortsThatWork -contains "3269") {
        $LDAPUri = $LDAPInfo.LDAPBaseUri + ":3269"
    }

    $Connection = [ADSI]($LDAPUri)
    #$UsersLDAPContainer = $Connection.Children | Where-Object {$_.distinguishedName -match "Users"}
    #$UserObjectsInLDAP = $UsersLDAPContainer.Children | Where-Object {$_.objectClass -contains "user" -and $_.objectClass -notcontains "group"}
    $Searcher = New-Object System.DirectoryServices.DirectorySearcher
    $Searcher.SearchRoot = $Connection
    $Searcher.Filter = "(&(objectCategory=Group))"
    $GroupObjectsInLDAP = $Searcher.FindAll() | foreach {$_.GetDirectoryEntry()}

    $GroupObjectsInLDAP
}