function Configure-VaultServerForLDAPAuth {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$True)]
        [string]$VaultServerNetworkLocation, # Should be an IP Address of DNS-Resolvable HostName/FQDN

        [Parameter(Mandatory=$True)]
        [int]$VaultServerPort, # Typically 8200

        [Parameter(Mandatory=$False)]
        [switch]$EncryptNetworkTraffic = $True, # Impacts using http/https, Vault Config, Generating TLS Certificates

        [Parameter(Mandatory=$True)]
        [string]$VaultAuthToken, # Get this via manual step preceeding this function using Vault CmdLine - 'vault operator init' 

        [Parameter(Mandatory=$False)]
        [string]$VaultLogFileName = "vault_audit.log",

        [Parameter(Mandatory=$False)]
        [string]$VaultLogEndPointName = "default-audit",

        # Creates backup root token with username 'backupadmin',
        # Creates 'custom-root' policy applied to "VaultAdmins" group (all permissions)
        # Creates 'vaultusers' policy applied to "VaultUsers" group (all permissions except 'delete' and 'sudo')
        [Parameter(Mandatory=$False)]
        [switch]$PerformOptionalSteps,

        [Parameter(Mandatory=$True)]
        [string]$LDAPServerHostNameOrIP,

        [Parameter(Mandatory=$True)]
        [ValidateSet(389,636,3268,3269)]
        [int]$LDAPServicePort,

        # Should be a non-privileged LDAP/AD account whose sole purpose is allowing Vault to read the LDAP Database
        [Parameter(Mandatory=$True)]
        [pscredential]$LDAPBindCredentials,

        [Parameter(Mandatory=$True)]
        [string]$BindUserDN, # Should be a path to a User Account LDAP object, like cn=vault,ou=OrgUsers,dc=zero,dc=lab
        
        [Parameter(Mandatory=$True)]
        [string]$LDAPUserOUDN, # Something like ou=OrgUsers,dc=zero,dc=lab
    
        [Parameter(Mandatory=$True)]
        [string]$LDAPGroupOUDN, # Something like ou=Groups,dc=zero,dc=lab

        [Parameter(Mandatory=$False)]
        [ValidatePattern("^cn=VaultUsers")]
        [string]$LDAPVaultUsersSecurityGroupDN, # Something like cn=VaultUsers,ou=Groups,dc=zero,dc=lab

        [Parameter(Mandatory=$False)]
        [ValidatePattern("^cn=VaultAdmins")]
        [string]$LDAPVaultAdminsSecurityGroupDN # Something like cn=VaultAdmins,ou=Groups,dc=zero,dc=lab
    )

    #region >> Variable/Parameter Transforms and PreRun Prep

    [Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls"

    # Create $Ouput Hashtable so we can add to it as we go and return whatever was done in case of error
    $Output = [ordered]@{}

    if ($EncryptNetworkTraffic) {
        $VaultServerBaseUri = "https://$VaultServerNetworkLocation" + ":$VaultServerPort/v1"    
    }
    else {
        $VaultServerBaseUri = "http://$VaultServerNetworkLocation" + ":$VaultServerPort/v1"
    }

    if ($PerformOptionalSteps) {
        if (!$LDAPVaultUsersSecurityGroupDN -or !$LDAPVaultAdminsSecurityGroupDN) {
            Write-Error "When using the -PerformOptionalSteps switch, you must also supply values for -LDAPVaultUsersSecurityGroupDN and -LDAPVaultAdminsSecurityGroupDN! Halting!"
            $global:FunctionResult = "1"
            return
        }
    }

    # Make sure we can reach the LDAP Server
    try {
        $LDAPServerNetworkInfo = ResolveHost -HostNameOrIP $LDAPServerHostNameOrIP
        if (!$LDAPServerNetworkInfo) {throw "Unable to resolve $LDAPServerHostNameOrIP! Halting!"}
    }
    catch {
        Write-Error $_
        $global:FunctionResult = "1"
        return
    }

    # Make sure $LDAPBindCredentials work
    $CurrentlyLoadedAssemblies = [System.AppDomain]::CurrentDomain.GetAssemblies()

    if (![bool]$($CurrentlyLoadedAssemblies -match "System.DirectoryServices.AccountManagement")) {
        Add-Type -AssemblyName System.DirectoryServices.AccountManagement
    }
    $SimpleDomain = $LDAPServerNetworkInfo.Domain
    $SimpleDomainWLDAPPort = $SimpleDomain + ":$LDAPServicePort"
    [System.Collections.ArrayList]$DomainLDAPContainersPrep = @()
    foreach ($Section in $($SimpleDomain -split "\.")) {
        $null = $DomainLDAPContainersPrep.Add($Section)
    }
    $DomainLDAPContainers = $($DomainLDAPContainersPrep | foreach {"DC=$_"}) -join ", "

    try {
        $SimpleUserName = $($LDAPBindCredentials.UserName -split "\\")[1]
        $PasswordInPlainText = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($LDAPBindCredentials.Password))
        $PrincipleContext = [System.DirectoryServices.AccountManagement.PrincipalContext]::new(
            [System.DirectoryServices.AccountManagement.ContextType]::Domain,
            "$SimpleDomainWLDAPPort",
            "$DomainLDAPContainers",
            [System.DirectoryServices.AccountManagement.ContextOptions]::SimpleBind,
            "$($LDAPBindCredentials.UserName)",
            "$PasswordInPlainText"
        )

        try {
            $UserPrincipal = [System.DirectoryServices.AccountManagement.UserPrincipal]::FindByIdentity($PrincipleContext, [System.DirectoryServices.AccountManagement.IdentityType]::SamAccountName, "$SimpleUserName")
            $LDAPBindCredentialsAreValid = $True
        }
        catch {
            throw "The credentials provided to the -LDAPBindCredentials parameter are not valid for the domain $SimpleDomain! Halting!"
        }

        if ($LDAPBindCredentialsAreValid) {
            # Determine if the User Account is locked
            $AccountLocked = $UserPrincipal.IsAccountLockedOut()

            if ($AccountLocked -eq $True) {
                throw "The provided UserName $($LDAPBindCredentials.Username) is locked! Please unlock it before additional attempts at getting working credentials!"
            }
        }
    }
    catch {
        Write-Error $_
        $global:FunctionResult = "1"
        return
    }


    # NOTE: With .Net, LDAP URIs always start with 'LDAP' - never lowercase and never with an 's|S' (i.e. never LDAPS|ldaps),
    # regardless of port
    $LDAPUri = "LDAP://$($LDAPServerNetworkInfo.FQDN):$LDAPServicePort"

    # Make sure $LDAPUserOUDN exists
    try {
        $LDAPUserOUDNDirectoryEntry = [ADSI]("$LDAPUri/$LDAPUserOUDN")
        $LDAPUserOUDNDirectoryEntry.Close()
    }
    catch {
        Write-Error "The LDAP Object $LDAPUserOUDN cannot be found! Halting!"
        $global:FunctionResult = "1"
        return
    }

    # Make sure $LDAPGroupOUDN exists
    try {
        $LDAPGroupOUDNDirectoryEntry = [ADSI]("$LDAPUri/$LDAPGroupOUDN")
        $LDAPGroupOUDNDirectoryEntry.Close()
    }
    catch {
        Write-Error "The LDAP Object $LDAPGroupOUDN cannot be found! Halting!"
        $global:FunctionResult = "1"
        return
    }

    $HeadersParameters = @{
        "X-Vault-Token" = $VaultAuthToken
    }

    #endregion >> Variable/Parameter Transforms and PreRun Prep


    #region >> Main Body
    
    # Turn on Vault Audit Log
    # Vault CmdLine Equivalent:
    #   vault audit enable file file_path=/vault/logs/vault_audit.log
    $jsonRequest = @"
{
    "type": "file",
    "options": {
        "path": "/vault/logs/$VaultLogFileName"
    }
}
"@
    try {
        # Validate JSON
        $JsonRequestAsSingleLineString = $jsonRequest | ConvertFrom-Json -EA Stop | ConvertTo-Json -Compress -EA Stop
    }
    catch {
        Write-Error "There was a problem with the JSON for Turning on the Audit Log! Halting!"
        if ($Output.Count -gt 0) {[pscustomobject]$Output}
        $global:FunctionResult = "1"
        return
    }
    $IWRSplatParams = @{
        Uri         = "$VaultServerBaseUri/sys/audit/$VaultLogEndPointName"
        Headers     = $HeadersParameters
        Body        = $JsonRequestAsSingleLineString
        Method      = "Put"
    }
    $TurnOnAuditLog = Invoke-RestMethod @IWRSplatParams
    $ConfirmAuditLogIsOn = $(Invoke-RestMethod -Uri "$VaultServerBaseUri/sys/audit" -Headers $HeadersParameters -Method Get).data
    if (!$ConfirmAuditLogIsOn) {
        Write-Error "Cannot confirm that the Vault Audit Log is turned on! Halting!"
        if ($Output.Count -gt 0) {[pscustomobject]$Output}
        $global:FunctionResult = "1"
        return
    }
    $Output.Add("EnableAuditLog",$ConfirmAuditLogIsOn)

    # Create a new policy that effectively has root access to Vault, and call it 'custom-root'. This policy will be applied
    # to Vault Administrators later on
    $jsonRequest = @"
{
    "policy": "path \"*\" {\n    capabilities = [\"create\", \"read\", \"update\", \"delete\", \"list\", \"sudo\"]\n}"
}
"@
    try {
        # Validate JSON
        $JsonRequestAsSingleLineString = $jsonRequest | ConvertFrom-Json -EA Stop | ConvertTo-Json -Compress -EA Stop
    }
    catch {
        Write-Error "There was a problem with the JSON for creating the 'custom-root' policy! Halting!"
        if ($Output.Count -gt 0) {[pscustomobject]$Output}
        $global:FunctionResult = "1"
        return
    }
    $IWRSplatParams = @{
        Uri         = "$VaultServerBaseUri/sys/policy/custom-root"
        Headers     = $HeadersParameters
        Body        = $JsonRequestAsSingleLineString
        Method      = "Put"
    }
    $RootPolicyResponse = Invoke-RestMethod @IWRSplatParams
    $ConfirmRootPolicy = Invoke-RestMethod -Uri "$VaultServerBaseUri/sys/policy/custom-root" -Headers $HeadersParameters -Method Get
    if (!$ConfirmRootPolicy) {
        Write-Error "Cannot confirm that the Vault policy 'custom-root' has been enabled! Halting!"
        if ($Output.Count -gt 0) {[pscustomobject]$Output}
        $global:FunctionResult = "1"
        return
    }
    $Output.Add("CreateCustomRootPolicy",$ConfirmRootPolicy)

    # Create a policy that is for typical Vault Users (i.e. not Vault Admins), that allows for everything except
    # delete and sudo. Change according to your preferences.
    $jsonRequest = @"
{
    "policy": "path \"*\" {\n    capabilities = [\"create\", \"read\", \"update\", \"list\"]\n}"
}
"@
    try {
        # Validate JSON
        $JsonRequestAsSingleLineString = $jsonRequest | ConvertFrom-Json -EA Stop | ConvertTo-Json -Compress -EA Stop
    }
    catch {
        Write-Error "There was a problem with the JSON for creating the 'vaultusers' policy! Halting!"
        if ($Output.Count -gt 0) {[pscustomobject]$Output}
        $global:FunctionResult = "1"
        return
    }
    $IWRSplatParams = @{
        Uri         = "$VaultServerBaseUri/sys/policy/vaultusers"
        Headers     = $HeadersParameters
        Body        = $JsonRequestAsSingleLineString
        Method      = "Put"
    }
    $VaultUsersPolicyResponse = Invoke-RestMethod @IWRSplatParams
    $ConfirmVaultUsersPolicy = Invoke-RestMethod -Uri "$VaultServerBaseUri/sys/policy/vaultusers" -Headers $HeadersParameters -Method Get
    if (!$ConfirmVaultUsersPolicy) {
        Write-Error "Cannot confirm that the Vault policy 'vaultusers' has been enabled! Halting!"
        if ($Output.Count -gt 0) {[pscustomobject]$Output}
        $global:FunctionResult = "1"
        return
    }
    $Output.Add("CreateVaultUsersPolicy",$ConfirmVaultUsersPolicy)

    if ($PerformOptionalSteps) {
        # Create a user other than the initial root (i.e. the token $VaultAuthToken that we've been using thus far) that has root privileges
        # via the 'custom-root' policy. This is just for a backup root account for emergencies
        # Vault CmdLine Equivalent:
        #   vault token create -policy=custom-root -display-name="backupadmin" -ttl="8760h" -renewable=true -metadata=user=backupadmin
        $jsonRequest = @"
{
    "policies": [
        "custom-root"
    ],
    "meta": {
        "user": "backupadmin"
    },
    "ttl": "8760h",
    "renewable": true
}
"@
        try {
            # Validate JSON
            $JsonRequestAsSingleLineString = $jsonRequest | ConvertFrom-Json -EA Stop | ConvertTo-Json -Compress -EA Stop
        }
        catch {
            Write-Error "There was a problem with the JSON for creating the 'backupadmin' Vault Token! Halting!"
            if ($Output.Count -gt 0) {[pscustomobject]$Output}
            $global:FunctionResult = "1"
            return
        }
        $IWRSplatParams = @{
            Uri         = "$VaultServerBaseUri/auth/token/create"
            Headers     = $HeadersParameters
            Body        = $JsonRequestAsSingleLineString
            Method      = "Post"
        }
        $NewUserTokenResponse = Invoke-RestMethod @IWRSplatParams
        if (!$NewUserTokenResponse) {
            Write-Error "There was a problem creating the 'backupadmin' Vault Token! Halting!"
            $global:FunctionResult = "1"
            return
        }
        $Output.Add("BackupRootToken",$NewUserTokenResponse)
    }

    # Enable LDAP Authentication
    #   vault auth enable ldap -description="Login with LDAP"
    $jsonRequest = @"
{
    "type": "ldap",
    "description": "Login with LDAP"
}
"@
    try {
        # Validate JSON
        $JsonRequestAsSingleLineString = $jsonRequest | ConvertFrom-Json -EA Stop | ConvertTo-Json -Compress -EA Stop
    }
    catch {
        Write-Error "There was a problem with the JSON for enabling the Vault LDAP Authentication Method! Halting!"
        if ($Output.Count -gt 0) {[pscustomobject]$Output}
        $global:FunctionResult = "1"
        return
    }
    $IWRSplatParams = @{
        Uri         = "$VaultServerBaseUri/sys/auth/ldap"
        Headers     = $HeadersParameters
        Body        = $JsonRequestAsSingleLineString
        Method      = "Post"
    }
    $EnableLDAPResponse = Invoke-RestMethod @IWRSplatParams
    $ConfirmLDAPEnabled = Invoke-RestMethod -Uri "$VaultServerBaseUri/sys/auth" -Headers $HeadersParameters -Method Get
    if (!$ConfirmLDAPEnabled) {
        Write-Error "There was a problem enabling the LDAP Authentication Method for the Vault Server! Halting!"
    }
    $Output.Add("LDAPAuthEngineEnabled",$ConfirmLDAPEnabled)

    # Next, we need the LDAP Server's Root CA Public Certificate
    try {
        $GetLDAPCertSplatParams = @{
            LDAPServerHostNameOrIP      = $LDAPServerNetworkInfo.FQDN
            Port                        = $LDAPServicePort
            ErrorAction                 = "Stop"
        }
        if ($LDAPServicePort -eq 389 -or $LDAPServicePort -eq 3268) {
            $GetLDAPCertSplatParams.Add("UseOpenSSL",$True)
        }

        $GetLDAPCertResult = Get-LDAPCert @GetLDAPCertSplatParams
        if (!$GetLDAPCertResult) {throw "The Get-LDAPCert function failed! Is your LDAP implementation using TLS? Halting!"}
        $RootCertificateInPemFormat = $GetLDAPCertResult.RootCACertificateInfo.PemFormat -join "`n"
        if (!$RootCertificateInPemFormat) {throw "The Get-LDAPCert function failed to get the Root CA Certificate in the LDAP Endpoint's Certificate Chain! Halting!"}
    }
    catch {
        Write-Error $_
        if ($Output.Count -gt 0) {[pscustomobject]$Output}
        $global:FunctionResult = "1"
        return
    }

    # The Vault Server handles LDAP Uris as expected (as opposed to .Net counterpart in above
    # 'Variable/Parameter Transforms and PreRun Prep' region) 
    if ($LDAPServicePort -eq 389 -or $LDAPServicePort -eq 3268) {
        $LDAPUriForVault = "ldap://$($LDAPServerNetworkInfo.FQDN):$LDAPServicePort"
    }
    if ($LDAPServicePort -eq 636 -or $LDAPServicePort -eq 3269) {
        $LDAPUriForVault = "ldaps://$($LDAPServerNetworkInfo.FQDN):$LDAPServicePort"
    }

    $jsonRequest = @"
{
    "url": "$LDAPUriForVault",
    "userattr": "samaccountname",
    "userdn": "$LDAPUserOUDN",
    "discoverdn": "true",
    "groupdn": "$LDAPGroupOUDN",
    "groupfilter": "(&(objectClass=group)(member:1.2.840.113556.1.4.1941:={{.UserDN}}))",
    "groupattr": "cn",
    "certificate": "$RootCertificateInPemFormat",
    "insecure_tls": "false",
    "starttls": "true",
    "binddn": "$BindUserDN",
    "bindpass": "$PasswordInPlainText",
    "deny_null_bind": "true",
    "tls_max_version": "tls12",
    "tls_min_version": "tls12"
}
"@
    try {
        # Validate JSON
        $JsonRequestAsSingleLineString = $jsonRequest | ConvertFrom-Json -EA Stop | ConvertTo-Json -Compress -EA Stop
    }
    catch {
        Write-Error "There was a problem with the JSON for establishing Vault's LDAP configuration! Halting!"
        if ($Output.Count -gt 0) {[pscustomobject]$Output}
        $global:FunctionResult = "1"
        return
    }
    $IWRSplatParams = @{
        Uri         = "$VaultServerBaseUri/auth/ldap/config"
        Headers     = $HeadersParameters
        Body        = $JsonRequestAsSingleLineString
        Method      = "Post"
    }
    $LDAPAuthConfigResponse = Invoke-RestMethod @IWRSplatParams
    $ConfirmLDAPAuthConfig = Invoke-RestMethod -Uri "$VaultServerBaseUri/auth/ldap/config" -Headers $HeadersParameters -Method Get
    if (!$ConfirmLDAPAuthConfig) {
        Write-Error "There was a problem setting the Vault LDAP Authentication configuration! Halting!"
        if ($Output.Count -gt 0) {[pscustomobject]$Output}
        $global:FunctionResult = "1"
        return
    }
    $Output.Add("LDAPAuthConfiguration",$ConfirmLDAPAuthConfig)
    # Remove $PasswordInPlainText from Memory as best we can
    $PasswordInPlainText = $null
    $PrincipleContext = $null
    $jsonRequest = $null
    $JsonRequestAsSingleLineString = $null


    if ($PerformOptionalSteps) {
        # Apply the 'custom-root' policy to the AD User Group 'VaultAdmins'
        # Vault Cmdline equivalent is:
        #   vault write auth/ldap/groups/VaultAdmins policies=custom-root

        # Make sure $LDAPVaultAdminsSecurityGroupDN exists
        try {
            $LDAPVaultAdminsSecurityGroupDNDirectoryEntry = [ADSI]("$LDAPUri/$LDAPVaultAdminsSecurityGroupDN")
            $LDAPVaultAdminsSecurityGroupDNDirectoryEntry.Close()
        }
        catch {
            Write-Error "The LDAP Object $LDAPVaultAdminsSecurityGroupDN cannot be found! Halting!"
            $global:FunctionResult = "1"
            if ($Output.Count -gt 0) {[pscustomobject]$Output}
            return
        }

        $jsonRequest = @"
{
    "policies": "custom-root"
}
"@
        try {
            # Validate JSON
            $JsonRequestAsSingleLineString = $jsonRequest | ConvertFrom-Json -EA Stop | ConvertTo-Json -Compress -EA Stop
        }
        catch {
            Write-Error "There was a problem with the JSON for applying the 'custom-root' policy to the VaultAdmins Security Group! Halting!"
            $global:FunctionResult = "1"
            return
        }
        $IWRSplatParams = @{
            Uri         = "$VaultServerBaseUri/auth/ldap/groups/VaultAdmins"
            Headers     = $HeadersParameters
            Body        = $JsonRequestAsSingleLineString
            Method      = "Post"
        }
        $ApplyPolicyToVaultAdminsGroup = Invoke-WebRequest @IWRSplatParams
        $ConfirmPolicyOnVaultAdmins = Invoke-RestMethod -Uri "$VaultServerBaseUri/auth/ldap/groups/VaultAdmins" -Headers $HeadersParameters -Method Get
        if (!$ConfirmPolicyOnVaultAdmins) {
            Write-Error "Unable to confirm that the 'custom-root' Vault Policy was applied to the LDAP Security Group 'VaultAdmins'! Halting!"
            if ($Output.Count -gt 0) {[pscustomobject]$Output}
            $global:FunctionResult = "1"
            return
        }
        $Output.Add("AppliedVaultAdminsPolicy",$ConfirmPolicyOnVaultAdmins)

        # Apply the 'vaultusers' policy to the AD User Group 'VaultUsers'
        # Vault Cmdline equivalent is:
        #   vault write auth/ldap/groups/VaultUsers policies=vaultusers

        # Make sure $LDAPVaultUsersSecurityGroupDN exists
        try {
            $LDAPVaultUsersSecurityGroupDNDirectoryEntry = [ADSI]("$LDAPUri/$LDAPVaultUsersSecurityGroupDN")
            $LDAPVaultUsersSecurityGroupDNDirectoryEntry.Close()
        }
        catch {
            Write-Error "The LDAP Object $LDAPVaultUsersSecurityGroupDN cannot be found! Halting!"
            if ($Output.Count -gt 0) {[pscustomobject]$Output}
            $global:FunctionResult = "1"
            return
        }

        $jsonRequest = @"
{
    "policies": "vaultusers"
}
"@
        try {
            $JsonRequestAsSingleLineString = $jsonRequest | ConvertFrom-Json -EA Stop | ConvertTo-Json -Compress -EA Stop
        }
        catch {
            Write-Error "There was a problem with the JSON for applying the 'vaultusers' policy to the VaulUsers Security Group! Halting!"
            if ($Output.Count -gt 0) {[pscustomobject]$Output}
            $global:FunctionResult = "1"
            return
        }
        $IWRSplatParams = @{
            Uri         = "$VaultServerBaseUri/auth/ldap/groups/VaultUsers"
            Headers     = $HeadersParameters
            Body        = $JsonRequestAsSingleLineString
            Method      = "Post"
        }
        $ApplyPolicyToVaultUsersGroup = Invoke-WebRequest @IWRSplatParams
        $ConfirmPolicyOnVaultUsers = Invoke-RestMethod -Uri "$VaultServerBaseUri/auth/ldap/groups/VaultUsers" -Headers $HeadersParameters -Method Get
        if (!$ConfirmPolicyOnVaultUsers) {
            Write-Error "Unable to confirm that the 'vaultusers' Vault Policy was applied to the LDAP Security Group 'VaultUsers'! Halting!"
            if ($Output.Count -gt 0) {[pscustomobject]$Output}
            $global:FunctionResult = "1"
            return
        }
        $Output.Add("AppliedVaultUsersPolicy",$ConfirmPolicyOnVaultUsers)
    }

[pscustomobject]$Output

    #endregion >> Main Body

}