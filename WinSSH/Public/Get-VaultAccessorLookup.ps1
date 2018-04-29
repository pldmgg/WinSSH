function Get-VaultAccessorLookup {
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

    try {
        $VaultAuthTokenAccessors = Get-VaultTokenAccessors -VaultBaseUri $VaultServerBaseUri -VaultAuthToken $VaultAuthToken -ErrorAction Stop
        if (!$VaultAuthTokenAccessors) {throw "The Get-VaultTokenAccessors function failed! Halting!"}
    }
    catch {
        Write-Error $_
        $global:FunctionResult = "1"
        return
    }
    
    foreach ($accessor in $VaultAuthTokenAccessors) {

        $jsonRequest = @"
{
    "accessor": "$accessor"
}
"@
        try {
            # Validate JSON
            $JsonRequestAsSingleLineString = $jsonRequest | ConvertFrom-Json -EA Stop | ConvertTo-Json -Compress -EA Stop
        }
        catch {
            Write-Error "There was a problem with the JSON! Halting!"
        }
        $IWRSplatParams = @{
            Uri         = "$VaultServerBaseUri/auth/token/lookup-accessor"
            Headers     = @{"X-Vault-Token" = "$VaultAuthToken"}
            Body        = $JsonRequestAsSingleLineString
            Method      = "Post"
        }
        
        $(Invoke-RestMethod @IWRSplatParams).data

    }
}