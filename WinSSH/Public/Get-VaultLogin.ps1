function Get-VaultLogin {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$True)]
        [ValidatePattern("\/v1$")]
        [string]$VaultServerBaseUri,

        [Parameter(Mandatory=$True)]
        [pscredential]$DomainCredentialsWithAdminAccessToVault
    )

    [Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls"

    # Make sure we can reach the Vault Server and that is in a state where we can actually use it.
    try {
        $VaultServerUpAndUnsealedCheck = Invoke-RestMethod "$VaultServerBaseUri/sys/health"
        if (!$VaultServerUpAndUnsealedCheck -or $VaultServerUpAndUnsealedCheck.initialized -ne $True -or
        $VaultServerUpAndUnsealedCheck.sealed -ne $False -or $VaultServerUpAndUnsealedCheck.standby -ne $False) {
            throw "The Vault Server is either not reachable or in a state where it cannot be used! Halting!"
        }
    }
    catch {
        Write-Error $_
        Write-Host "Use 'Invoke-RestMethod '$VaultServerBaseUri/sys/health' to investigate" -ForegroundColor Yellow
        $global:FunctionResult = "1"
        return
    }

    # Get the Domain User's Vault Token so that we can interact with Vault
    $UserName = $($DomainCredentialsWithAdminAccessToVault.UserName -split "\\")[1]
    $PlainTextPwd = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($DomainCredentialsWithAdminAccessToVault.Password))

    $jsonRequest = @"
{
    "password": "$PlainTextPwd"
}
"@
    try {
        $JsonRequestAsSingleLineString = $jsonRequest | ConvertFrom-Json -EA Stop | ConvertTo-Json -Compress -EA Stop
    }
    catch {
        Write-Error "There was a problem with the JSON for Turning on the Audit Log! Halting!"
        $global:FunctionResult = "1"
        return
    }
    $IWRSplatParams = @{
        Uri         = "$VaultServerBaseUri/auth/ldap/login/$UserName "
        Body        = $JsonRequestAsSingleLineString
        Method      = "Post"
    }
    $LDAPLoginResult = Invoke-RestMethod @IWRSplatParams
    $VaultAuthToken = $LDAPLoginResult.auth.client_token

    # Get rid of PlainText Password from Memory as best we can (this really doesn't do enough...)
    # https://get-powershellblog.blogspot.com/2017/06/how-safe-are-your-strings.html
    $jsonRequest = $null
    $PlainTextPwd = $null

    if (!$VaultAuthToken) {
        Write-Error "There was a problem getting the Vault Token for Domain User $UserName! Halting!"
        $global:FunctionResult = "1"
        return
    }
    else {
        $VaultAuthToken
    }
}