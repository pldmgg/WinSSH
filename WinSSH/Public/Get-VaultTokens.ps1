function Get-VaultTokens {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [string]$VaultServerBaseUri, # Should be something like "http://192.168.2.12:8200/v1"

        [Parameter(Mandatory=$True)]
        [string]$VaultAuthToken # Should be something like 'myroot' or '434f37ca-89ae-9073-8783-087c268fd46f'
    )

    # Make sure $VaultServerBaseUri is a valid Url
    try {
        $UriObject = [uri]$VaultServerBaseUri
    }
    catch {
        Write-Error $_
        $global:FunctionResult = "1"
        return
    }
    if (![bool]$($UriObject.Scheme -match "http")) {
        Write-Error "'$VaultServerBaseUri' does not appear to be a URL! Halting!"
        $global:FunctionResult = "1"
        return
    }

    # If $VaultServerBaseUri ends in '/', remove it
    if ($VaultServerBaseUri[-1] -eq "/") {
        $VaultServerBaseUri = $VaultServerBaseUri.Substring(0,$VaultServerBaseUri.Length-1)
    }

    $QueryParameters = @{
        list = "true"
    }
    $HeadersParameters = @{
        "X-Vault-Token" = $VaultAuthToken
    }
    $IWRSplatParamsForSaltedTokenIds = @{
        Uri         = "$VaultServerBaseUri/sys/raw/sys/token/id"
        Headers     = $HeadersParameters
        Body        = $QueryParameters
        Method      = "Get"
    }
    $SaltedTokenIds = $($(Invoke-WebRequest @IWRSplatParamsForSaltedTokenIds).Content | ConvertFrom-Json).data.keys
    if (!$SaltedTokenIds) {
        Write-Error "There was a problem accesing the endpoint '$VaultServerBaseUri/sys/raw/sys/token/id'. Was 'raw_storage_endpoint = true' set in your Vault Server 'vault.hcl' configuration? Halting!"
        $global:FunctionResult = "1"
        return
    }

    [System.Collections.ArrayList]$AvailableTokensPSObjects = @()
    foreach ($SaltedId in $SaltedTokenIds) {
        $IWRSplatParamsForTokenObjects = @{
            Uri         = "$VaultServerBaseUri/sys/raw/sys/token/id/$SaltedId"
            Headers     = $HeadersParameters
            Method      = "Get"
        }

        $PSObject = $($(Invoke-WebRequest @IWRSplatParamsForTokenObjects).Content | ConvertFrom-Json).data.value | ConvertFrom-Json
        
        $null = $AvailableTokensPSObjects.Add($PSObject)
    }

    $AvailableTokensPSObjects
}