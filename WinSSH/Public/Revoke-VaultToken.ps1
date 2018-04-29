function Revoke-VaultToken {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [string]$VaultServerBaseUri, # Should be something like "http://192.168.2.12:8200/v1"

        [Parameter(Mandatory=$True)]
        [string]$VaultAuthToken, # Should be something like 'myroot' or '434f37ca-89ae-9073-8783-087c268fd46f'

        [Parameter(Mandatory=$True)]
        [string[]]$VaultUserToDelete # Should match .meta.username for the Accessor Lookup
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

    try {
        $AccessorInfo = Get-VaultAccessorLookup -VaultServerBaseUri $VaultServerBaseUri -VaultAuthToken $ZeroAdminToken -ErrorAction Stop
        if (!$AccessorInfo) {throw "Ther Get-VaultAccessorLookup function failed! Halting!"}
    }
    catch {
        Write-Error $_
        $global:FunctionResult = "1"
        return
    }

    $AccessorToDelete = $($AccessorInfo | Where-Object {$_.meta.username -eq $VaultUserToDelete}).accessor
    if (!$AccessorToDelete) {
        Write-Error "Unable to find Accessor matching username $VaultUserToDelete! Halting!"
        $global:FunctionResult = "1"
        return
    }

    $jsonRequest = @"
{
    "accessor": "$AccessorToDelete"
}
"@
    try {
        # Validate JSON
        $JsonRequestAsSingleLineString = $jsonRequest | ConvertFrom-Json -EA Stop | ConvertTo-Json -Compress -EA Stop
    }
    catch {
        Write-Error "There was a problem with the JSON for deleting an accessor! Halting!"
    }
    $IWRSplatParams = @{
        Uri         = "$VaultServerBaseUri/auth/token/revoke-accessor"
        Headers     = @{"X-Vault-Token" = "$VaultAuthToken"}
        Body        = $JsonRequestAsSingleLineString
        Method      = "Post"
    }
    $RevokeTokenResult = Invoke-RestMethod @IWRSplatParams
    # NOTE: Revoking a Token does Not produce output, to $RevokeJSmithTokenResult should be $null

    # Make sure it no longer exists
    try {
        $AccessorInfo = Get-VaultAccessorLookup -VaultServerBaseUri $VaultServerBaseUri -VaultAuthToken $ZeroAdminToken -ErrorAction Stop
        if (!$AccessorInfo) {throw "Ther Get-VaultAccessorLookup function failed! Halting!"}
    }
    catch {
        Write-Error $_
        $global:FunctionResult = "1"
        return
    }

    $AccessorStillExists = $($AccessorInfo | Where-Object {$_.meta.username -eq $VaultUserToDelete}).accessor
    if ($AccessorStillExists) {
        Write-Error "There was a problem deleting the accessor $AccessorToDelete for user $VaultUserToDelete! Halting!"
        $global:FunctionResult = '1'
        return
    }

    "Success"
}