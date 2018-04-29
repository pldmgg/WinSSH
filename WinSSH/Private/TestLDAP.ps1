Function TestLDAP {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$True)]
        [string]$ADServerHostNameOrIP
    )

    # Make sure you CAN resolve $ADServerHostNameOrIP AND that we can get FQDN
    try {
        $ADServerNetworkInfo = [System.Net.Dns]::GetHostEntry($ADServerHostNameOrIP)
        if ($ADServerNetworkInfo.HostName -notmatch "\.") {
            $IP = $ADServerNetworkInfo.AddressList[0].IPAddressToString
            $ADServerNetworkInfo = [System.Net.Dns]::GetHostEntry($IP)
            if ($ADServerNetworkInfo.HostName -notmatch "\.") {
                throw "Can't resolve $ADServerHostNameOrIP FQDN! Halting!"
            }
        }
    }
    catch {
        Write-Error $_
        $global:FunctionResult = "1"
        return
    }

    $ADServerFQDN = $ADServerNetworkInfo.HostName

    $LDAPPrep = "LDAP://" + $ADServerFQDN

    # Try Global Catalog First - It's faster and you can execute from a different domain and
    # potentially still get results
    try {
        $LDAP = $LDAPPrep + ":3269"
        # This does NOT throw an error because it doen't actually try to reach out to make the connection yet
        $Connection = [ADSI]($LDAP)
        # This WILL throw an error
        $Connection.Close()
        $GlobalCatalogConfiguredForSSL = $True
    } 
    catch {
        if ($_.Exception.ToString() -match "The server is not operational") {
            Write-Warning "Either can't find LDAP Server or SSL on Global Catalog (3269) is not operational!"
        }
        elseif ($_.Exception.ToString() -match "The user name or password is incorrect") {
            Write-Warning "The current user $(whoami) does not have access!"
        }
        else {
            Write-Error $_
        }
    }

    try {
        $LDAP = $LDAPPrep + ":3268"
        $Connection = [ADSI]($LDAP)
        $Connection.Close()
        $GlobalCatalogConfigured = $True
    } 
    catch {
        if ($_.Exception.ToString() -match "The server is not operational") {
            Write-Warning "Either can't find LDAP Server or Global Catalog (3268) is not operational!"
        }
        elseif ($_.Exception.ToString() -match "The user name or password is incorrect") {
            Write-Warning "The current user $(whoami) does not have access!"
        }
        else {
            Write-Error $_
        }
    }
  
    # Try the normal ports
    try {
        $LDAP = $LDAPPrep + ":636"
        # This does NOT throw an error because it doen't actually try to reach out to make the connection yet
        $Connection = [ADSI]($LDAP)
        # This WILL throw an error
        $Connection.Close()
        $ConfiguredForSSL = $True
    } 
    catch {
        if ($_.Exception.ToString() -match "The server is not operational") {
            Write-Warning "Can't find LDAP Server or SSL (636) is NOT configured! Check the value provided to the -ADServerHostNameOrIP parameter!"
        }
        elseif ($_.Exception.ToString() -match "The user name or password is incorrect") {
            Write-Warning "The current user $(whoami) does not have access! Halting!"
        }
        else {
            Write-Error $_
        }
    }

    try {
        $LDAP = $LDAPPrep + ":389"
        $Connection = [ADSI]($LDAP)
        $Connection.Close()
        $Configured = $True
    }
    catch {
        if ($_.Exception.ToString() -match "The server is not operational") {
            Write-Warning "Can't find LDAP Server (389)! Check the value provided to the -ADServerHostNameOrIP parameter!"
        }
        elseif ($_.Exception.ToString() -match "The user name or password is incorrect") {
            Write-Warning "The current user $(whoami) does not have access!"
        }
        else {
            Write-Error $_
        }
    }

    if (!$GlobalCatalogConfiguredForSSL -and !$GlobalCatalogConfigured -and !$ConfiguredForSSL -and !$Configured) {
        Write-Error "Unable to connect to $LDAPPrep! Halting!"
        $global:FunctionResult = "1"
        return
    }

    [System.Collections.ArrayList]$PortsThatWork = @()
    if ($GlobalCatalogConfigured) {$null = $PortsThatWork.Add("3268")}
    if ($GlobalCatalogConfiguredForSSL) {$null = $PortsThatWork.Add("3269")}
    if ($Configured) {$null = $PortsThatWork.Add("389")}
    if ($ConfiguredForSSL) {$null = $PortsThatWork.Add("636")}

    [pscustomobject]@{
        DirectoryEntryInfo                  = $Connection
        LDAPBaseUri                         = $LDAPPrep
        GlobalCatalogConfigured3268         = if ($GlobalCatalogConfigured) {$True} else {$False}
        GlobalCatalogConfiguredForSSL3269   = if ($GlobalCatalogConfiguredForSSL) {$True} else {$False}
        Configured389                       = if ($Configured) {$True} else {$False}
        ConfiguredForSSL636                 = if ($ConfiguredForSSL) {$True} else {$False}
        PortsThatWork                       = $PortsThatWork
    }
}