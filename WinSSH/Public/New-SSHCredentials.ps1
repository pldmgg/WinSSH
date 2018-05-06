function New-SSHCredentials {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$True)]
        [ValidatePattern("\/v1$")]
        [string]$VaultServerBaseUri,

        [Parameter(Mandatory=$False)]
        [pscredential]$DomainCredentialsWithAccessToVault,

        [Parameter(Mandatory=$False)]
        [string]$VaultAuthToken,

        [Parameter(Mandatory=$True)]
        [string]$NewSSHKeyName,

        [Parameter(Mandatory=$False)]
        [ValidatePattern("^\w*$")] # No spaces allowed
        [string]$NewSSHKeyPurpose,

        [Parameter(Mandatory=$False)]
        [System.Security.SecureString]$NewSSHKeyPwd,

        [Parameter(Mandatory=$False)]
        [switch]$BlankSSHPrivateKeyPwd,

        [Parameter(Mandatory=$False)]
        [switch]$AddToSSHAgent = $True,

        [Parameter(Mandatory=$False)]
        [switch]$AllowAwaitModuleInstall,

        [Parameter(Mandatory=$False)]
        [switch]$RemovePrivateKey
    )

    if ($(!$VaultAuthToken -and !$DomainCredentialsWithAccessToVault) -or $($VaultAuthToken -and $DomainCredentialsWithAccessToVault)) {
        Write-Error "The $($MyInvocation.MyCommand.Name) function requires one (no more, no less) of the following parameters: [-DomainCredentialsWithAccessToVault, -VaultAuthToken] Halting!"
        $global:FunctionResult = "1"
        return
    }

    if ($DomainCredentialsWithAccessToVault) {
        $GetVaultLoginSplatParams = @{
            VaultServerBaseUri                          = $VaultServerBaseUri
            DomainCredentialsWithAdminAccessToVault     = $DomainCredentialsWithAccessToVault
            ErrorAction                                 = "Stop"
        }

        try {
            $VaultAuthToken = Get-VaultLogin @GetVaultLoginSplatParams
            if (!$VaultAuthToken) {throw "The Get-VaultLogin function failed! Halting!"}
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            return
        }
    }

    $HeadersParameters = @{
        "X-Vault-Token" = $VaultAuthToken
    }

    # Generate an SSH key pair for zeroadmin
    if (!$(Test-Path "$HOME\.ssh")) {
        New-Item -ItemType Directory -Path "$HOME\.ssh"
    }

    Push-Location "$HOME\.ssh"

    $NewSSHKeySplatParams = @{
        NewSSHKeyName       = $NewSSHKeyName
        ErrorAction         = "Stop"
    }
    if ($NewSSHKeyPurpose) {
        $NewSSHKeySplatParams.Add("NewSSHKeyPurpose",$NewSSHKeyPurpose)
    }
    if (!$BlankSSHPrivateKeyPwd) {
        if ($NewSSHKeyPwd) {
            $KeyPwd = $NewSSHKeyPwd
        }
        else {
            $KeyPwd = Read-Host -Prompt "Please enter a password to protect the new SSH Private Key $NewSSHKeyName"
        }
        $NewSSHKeySplatParams.Add("NewSSHKeyPwd",$KeyPwd)
    }
    else {
        if ($AllowAwaitModuleInstall) {
            $NewSSHKeySplatParams.Add("AllowAwaitModuleInstall",$True)
        }
    }
    
    try {
        $NewSSHKeyResult = New-SSHKey @NewSSHKeySplatParams
        if (!$NewSSHKeyResult) {throw "There was a problem with the New-SSHKey function! Halting!"}
    }
    catch {
        Write-Error $_
        $global:FunctionResult = "1"
        return
    }

    # Have Vault sign the User's New public key
    if ($DomainCredentialsWithAccessToVault) {
        $AuthorizedPrincipalUserPrep = $DomainCredentialsWithAccessToVault.UserName -split "\\"
        $AuthorizedPrincipalString = $AuthorizedPrincipalUserPrep[-1] + "@" + $AuthorizedPrincipalUserPrep[0]
    }
    else {
        $AuthorizedPrincipalString = $($(whoami) -split "\\")[-1] + "@" + $($(whoami) -split "\\")[0]
    }

    $SignSSHUserPubKeySplatParams = @{
        VaultSSHClientSigningUrl        = "$VaultServerBaseUri/ssh-client-signer/sign/clientrole"
        VaultAuthToken                  = $VaultAuthToken
        AuthorizedUserPrincipals        = @($AuthorizedPrincipalString)
        PathToSSHUserPublicKeyFile      = $NewSSHKeyResult.PublicKeyFilePath
        PathToSSHUserPrivateKeyFile     = $NewSSHKeyResult.PrivateKeyFilePath
        ErrorAction                     = "Stop"
    }
    if ($AddToSSHAgent) {
        $SignSSHUserPubKeySplatParams.Add("AddToSSHAgent",$True)
    }

    try {
        $SignSSHUserPublicKeyResult = Sign-SSHUserPublicKey @SignSSHUserPubKeySplatParams
        if (!$SignSSHUserPublicKeyResult) {throw "There was a problem with the Sign-SSHUserPublicKey function! Halting!"}
    }
    catch {
        Write-Error $_
        $global:FunctionResult = "1"
        return
    }

    if ($RemovePrivateKey -and $SignSSHUserPublicKeyResult.AddedToSSHAgent) {
        Remove-Item $NewSSHKeyResult.PrivateKeyFilePath -Force
    }

    # Next, pull the Vault Host Signing CA Public Key and Vault Client (User) Signing CA Public Key into the necessary config files
    # NOTE: The Add-CAPubKeyToSSHAndSSHDConfig function will NOT do anything if it doesn't need to
    $AddCAPubKeyToSSHAndSSHDConfigSplatParams = @{
        PublicKeyOfCAUsedToSignUserKeysVaultUrl     = "$VaultServerBaseUri/ssh-client-signer/public_key"
        PublicKeyOfCAUsedToSignHostKeysVaultUrl     = "$VaultServerBaseUri/ssh-host-signer/public_key"
        AuthorizedUserPrincipals                    = @($AuthorizedPrincipalString)
        ErrorAction                                 = "Stop"
    }

    try {
        $AddCAPubKeyResult = Add-CAPubKeyToSSHAndSSHDConfig @AddCAPubKeyToSSHAndSSHDConfigSplatParams
    }
    catch {
        Write-Warning "There was a problem with the Add-CAPubKeyToSSHAndSSHDConfig function! The problem is as follows:"
        Write-Warning "$($_ | Out-String)"
        Write-Warning "SSH Cert Authentication may still work..."
    }

    # Finally, figure out the most efficient ssh command to use to remote into the remote host.
    Get-SSHClientAuthSanity -SSHKeyFilePath $NewSSHKeyResult.PublicKeyFilePath -AuthMethod PublicKeyCertificate

    Pop-Location

}


























# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUsPzYjV9ZNTccOuUuz3rSdWAw
# aDmgggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
# 9w0BAQsFADAwMQwwCgYDVQQGEwNMQUIxDTALBgNVBAoTBFpFUk8xETAPBgNVBAMT
# CFplcm9EQzAxMB4XDTE3MDkyMDIxMDM1OFoXDTE5MDkyMDIxMTM1OFowPTETMBEG
# CgmSJomT8ixkARkWA0xBQjEUMBIGCgmSJomT8ixkARkWBFpFUk8xEDAOBgNVBAMT
# B1plcm9TQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDCwqv+ROc1
# bpJmKx+8rPUUfT3kPSUYeDxY8GXU2RrWcL5TSZ6AVJsvNpj+7d94OEmPZate7h4d
# gJnhCSyh2/3v0BHBdgPzLcveLpxPiSWpTnqSWlLUW2NMFRRojZRscdA+e+9QotOB
# aZmnLDrlePQe5W7S1CxbVu+W0H5/ukte5h6gsKa0ktNJ6X9nOPiGBMn1LcZV/Ksl
# lUyuTc7KKYydYjbSSv2rQ4qmZCQHqxyNWVub1IiEP7ClqCYqeCdsTtfw4Y3WKxDI
# JaPmWzlHNs0nkEjvnAJhsRdLFbvY5C2KJIenxR0gA79U8Xd6+cZanrBUNbUC8GCN
# wYkYp4A4Jx+9AgMBAAGjggEqMIIBJjASBgkrBgEEAYI3FQEEBQIDAQABMCMGCSsG
# AQQBgjcVAgQWBBQ/0jsn2LS8aZiDw0omqt9+KWpj3DAdBgNVHQ4EFgQUicLX4r2C
# Kn0Zf5NYut8n7bkyhf4wGQYJKwYBBAGCNxQCBAweCgBTAHUAYgBDAEEwDgYDVR0P
# AQH/BAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAUdpW6phL2RQNF
# 7AZBgQV4tgr7OE0wMQYDVR0fBCowKDAmoCSgIoYgaHR0cDovL3BraS9jZXJ0ZGF0
# YS9aZXJvREMwMS5jcmwwPAYIKwYBBQUHAQEEMDAuMCwGCCsGAQUFBzAChiBodHRw
# Oi8vcGtpL2NlcnRkYXRhL1plcm9EQzAxLmNydDANBgkqhkiG9w0BAQsFAAOCAQEA
# tyX7aHk8vUM2WTQKINtrHKJJi29HaxhPaHrNZ0c32H70YZoFFaryM0GMowEaDbj0
# a3ShBuQWfW7bD7Z4DmNc5Q6cp7JeDKSZHwe5JWFGrl7DlSFSab/+a0GQgtG05dXW
# YVQsrwgfTDRXkmpLQxvSxAbxKiGrnuS+kaYmzRVDYWSZHwHFNgxeZ/La9/8FdCir
# MXdJEAGzG+9TwO9JvJSyoGTzu7n93IQp6QteRlaYVemd5/fYqBhtskk1zDiv9edk
# mHHpRWf9Xo94ZPEy7BqmDuixm4LdmmzIcFWqGGMo51hvzz0EaE8K5HuNvNaUB/hq
# MTOIB5145K8bFOoKHO4LkTCCBc8wggS3oAMCAQICE1gAAAH5oOvjAv3166MAAQAA
# AfkwDQYJKoZIhvcNAQELBQAwPTETMBEGCgmSJomT8ixkARkWA0xBQjEUMBIGCgmS
# JomT8ixkARkWBFpFUk8xEDAOBgNVBAMTB1plcm9TQ0EwHhcNMTcwOTIwMjE0MTIy
# WhcNMTkwOTIwMjExMzU4WjBpMQswCQYDVQQGEwJVUzELMAkGA1UECBMCUEExFTAT
# BgNVBAcTDFBoaWxhZGVscGhpYTEVMBMGA1UEChMMRGlNYWdnaW8gSW5jMQswCQYD
# VQQLEwJJVDESMBAGA1UEAxMJWmVyb0NvZGUyMIIBIjANBgkqhkiG9w0BAQEFAAOC
# AQ8AMIIBCgKCAQEAxX0+4yas6xfiaNVVVZJB2aRK+gS3iEMLx8wMF3kLJYLJyR+l
# rcGF/x3gMxcvkKJQouLuChjh2+i7Ra1aO37ch3X3KDMZIoWrSzbbvqdBlwax7Gsm
# BdLH9HZimSMCVgux0IfkClvnOlrc7Wpv1jqgvseRku5YKnNm1JD+91JDp/hBWRxR
# 3Qg2OR667FJd1Q/5FWwAdrzoQbFUuvAyeVl7TNW0n1XUHRgq9+ZYawb+fxl1ruTj
# 3MoktaLVzFKWqeHPKvgUTTnXvEbLh9RzX1eApZfTJmnUjBcl1tCQbSzLYkfJlJO6
# eRUHZwojUK+TkidfklU2SpgvyJm2DhCtssFWiQIDAQABo4ICmjCCApYwDgYDVR0P
# AQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMDMB0GA1UdDgQWBBS5d2bhatXq
# eUDFo9KltQWHthbPKzAfBgNVHSMEGDAWgBSJwtfivYIqfRl/k1i63yftuTKF/jCB
# 6QYDVR0fBIHhMIHeMIHboIHYoIHVhoGubGRhcDovLy9DTj1aZXJvU0NBKDEpLENO
# PVplcm9TQ0EsQ049Q0RQLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNl
# cnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9emVybyxEQz1sYWI/Y2VydGlmaWNh
# dGVSZXZvY2F0aW9uTGlzdD9iYXNlP29iamVjdENsYXNzPWNSTERpc3RyaWJ1dGlv
# blBvaW50hiJodHRwOi8vcGtpL2NlcnRkYXRhL1plcm9TQ0EoMSkuY3JsMIHmBggr
# BgEFBQcBAQSB2TCB1jCBowYIKwYBBQUHMAKGgZZsZGFwOi8vL0NOPVplcm9TQ0Es
# Q049QUlBLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNlcnZpY2VzLENO
# PUNvbmZpZ3VyYXRpb24sREM9emVybyxEQz1sYWI/Y0FDZXJ0aWZpY2F0ZT9iYXNl
# P29iamVjdENsYXNzPWNlcnRpZmljYXRpb25BdXRob3JpdHkwLgYIKwYBBQUHMAKG
# Imh0dHA6Ly9wa2kvY2VydGRhdGEvWmVyb1NDQSgxKS5jcnQwPQYJKwYBBAGCNxUH
# BDAwLgYmKwYBBAGCNxUIg7j0P4Sb8nmD8Y84g7C3MobRzXiBJ6HzzB+P2VUCAWQC
# AQUwGwYJKwYBBAGCNxUKBA4wDDAKBggrBgEFBQcDAzANBgkqhkiG9w0BAQsFAAOC
# AQEAszRRF+YTPhd9UbkJZy/pZQIqTjpXLpbhxWzs1ECTwtIbJPiI4dhAVAjrzkGj
# DyXYWmpnNsyk19qE82AX75G9FLESfHbtesUXnrhbnsov4/D/qmXk/1KD9CE0lQHF
# Lu2DvOsdf2mp2pjdeBgKMRuy4cZ0VCc/myO7uy7dq0CvVdXRsQC6Fqtr7yob9NbE
# OdUYDBAGrt5ZAkw5YeL8H9E3JLGXtE7ir3ksT6Ki1mont2epJfHkO5JkmOI6XVtg
# anuOGbo62885BOiXLu5+H2Fg+8ueTP40zFhfLh3e3Kj6Lm/NdovqqTBAsk04tFW9
# Hp4gWfVc0gTDwok3rHOrfIY35TGCAfUwggHxAgEBMFQwPTETMBEGCgmSJomT8ixk
# ARkWA0xBQjEUMBIGCgmSJomT8ixkARkWBFpFUk8xEDAOBgNVBAMTB1plcm9TQ0EC
# E1gAAAH5oOvjAv3166MAAQAAAfkwCQYFKw4DAhoFAKB4MBgGCisGAQQBgjcCAQwx
# CjAIoAKAAKECgAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGC
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFBQI5VCB8S5RQmUQ
# cU7zcWjgPHZbMA0GCSqGSIb3DQEBAQUABIIBAGDiFVQ4uW5WFw0lqQBiSkk60IEP
# twhIV105lhNL23uH85c2CKSb/P5ZdWBnZMsT9+h+UEAXIiBX1EanOe7/dxNswngy
# kgE3d1I6BO9weuyvGueXDHimJtdFN0D63/NXcjSiqXg6J00cY6vblMri+6AkzfLs
# ntao3TLygL93vb+XUYjfUNP6J18SyOod0/m61T7KgL2Vg+nmkbLBPuOTRaKoAg8K
# 6zNna2Z6TBN3Wqio5MxSrqXvlDYHhzz9u71MfwpqzQyumQjVgsHGOU3/I1qlT3hv
# Yoo+VHAuwhlqRrXli7Tx7EKWVQgZL1oMmOs+d/nhBxFH92Yi17Orof+nELw=
# SIG # End signature block
