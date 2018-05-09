<#
    .SYNOPSIS
        This function gets information about the specified SSH Key/Certificate file.

        Output is a PSCustomObject with the following properties...

            File                = $PathToKeyFile
            FileType            = $FileType
            Contents            = $Contents
            Info                = $Info
            FingerPrint         = $FingerPrint
            PasswordProtected   = $PasswordProtected

        ...where...
        
            - $PathToKeyFile is the path to the Key file specified by the -PathToKeyFile parameter,
            - $FileType is either "RSAPublicKey", "RSAPrivateKey", or "RSAPublicKeyCertificate"
            - $Contents is the result of: Get-Content $PathToKeyFile
            - $Info is the result of: ssh-keygen -l -f "$PathToKeyFile"
            - $FingerPrint is the fingerprint of the $PathToKeyFile
            - $PasswordProtected is a Boolean that indicates whether or not the file is password protected.

    .DESCRIPTION
        See .SYNOPSIS

    .NOTES

    .PARAMETER PathToKeyFile
        This parameter is MANDATORY.

        This parameter takes a string that represents the full path to the SSH Key/Cert File you would
        like to inspect.

    .EXAMPLE
        # Open an elevated PowerShell Session, import the module, and -

        PS C:\Users\zeroadmin> Get-SSHFileInfo -PathToKeyFile "$HOME\.ssh\id_rsa"
        
#>
function Get-SSHFileInfo {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [string]$PathToKeyFile
    )

    # Make sure we have access to ssh binaries
    if (![bool]$(Get-Command ssh-keygen -ErrorAction SilentlyContinue)) {
        Write-Error "Unable to find 'ssh-keygen.exe'! Halting!"
        $global:FunctionResult = "1"
        return
    }

    # Make sure the path exists
    if (!$(Test-Path $PathToKeyFile)) {
        Write-Error "Unable to find the path '$PathToKeyFile'! Halting!"
        $global:FunctionResult = "1"
        return
    }

    # This function can't validate .ppk files from putty, so just assume they're valid
    if ($(Get-Item $PathToKeyFile).Extension -eq ".ppk") {
        [pscustomobject]@{
            File                = $PathToKeyFile
            FileType            = "PuttyCombinedPublicPrivateKey"
            Contents            = $(Get-Content $PathToKeyFile)
            Info                = $(Get-Content $PathToKeyFile)
            FingerPrint         = $null
            PasswordProtected   = $null
        }
        
        return
    }

    $SSHKeyGenParentDir = $(Get-Command ssh-keygen).Source | Split-Path -Parent
    $SSHKeyGenArguments = "-l -f `"$PathToKeyFile`""

    $ProcessInfo = New-Object System.Diagnostics.ProcessStartInfo
    $ProcessInfo.WorkingDirectory = $SSHKeyGenParentDir
    $ProcessInfo.FileName = $(Get-Command ssh-keygen).Source
    $ProcessInfo.RedirectStandardError = $true
    $ProcessInfo.RedirectStandardOutput = $true
    #$ProcessInfo.StandardOutputEncoding = [System.Text.Encoding]::Unicode
    #$ProcessInfo.StandardErrorEncoding = [System.Text.Encoding]::Unicode
    $ProcessInfo.UseShellExecute = $false
    $ProcessInfo.Arguments = $SSHKeyGenArguments
    $Process = New-Object System.Diagnostics.Process
    $Process.StartInfo = $ProcessInfo
    $Process.Start() | Out-Null
    # Below $FinishedInAlottedTime returns boolean true/false
    $FinishedInAlottedTime = $Process.WaitForExit(5000)
    if (!$FinishedInAlottedTime) {
        $Process.Kill()
        $ProcessKilled = $True
    }
    $stdout = $Process.StandardOutput.ReadToEnd()
    $stderr = $Process.StandardError.ReadToEnd()
    $SSHKeyGenOutput = $stdout + $stderr

    if ($SSHKeyGenOutput -match "(RSA-CERT)") {
        $PublicKeyCertInfo = ssh-keygen -L -f "$PathToKeyFile"
        $PublicKeyCertContent = Get-Content $PathToKeyFile
        $FingerPrint = ssh-keygen -l -f "$PathToKeyFile"
        $IsPublicKeyCert = $True
    }
    elseif ($SSHKeyGenOutput -match "(RSA)") {
        # It could be either a Public Key or Private Key
        $PrivateKeyAttempt = Validate-SSHPrivateKey -PathToPrivateKeyFile $PathToKeyFile
        if (!$PrivateKeyAttempt.ValidSSHPrivateKeyFormat) {
            $IsPublicKey = $True
            $PublicKeyContent = Get-Content $PathToKeyFile
            $PublicKeyInfo = $FingerPrint = ssh-keygen -l -f "$PathToKeyFile"
        }
        else {
            $IsPrivateKey = $True
            $PrivateKeyContent = $PrivateKeyInfo = Get-Content $PathToKeyFile
            $FingerPrint = ssh-keygen -l -f "$PathToKeyFile"
            $PasswordProtected = $PrivateKeyAttempt.PasswordProtected
        }
    }
    elseif ($SSHKeyGenOutput -match "passphrase|pass phrase" -or $($SSHKeyGenOutput -eq $null -and $ProcessKilled)) {
        $IsPrivateKey = $True
        $PrivateKeyContent = $PrivateKeyInfo = Get-Content $PathToKeyFile
        $PasswordProtected = $True
    }
    elseif ($(Get-Content $PathToKeyFile)[0] -match "SSH2") {
        [pscustomobject]@{
            File                = $PathToKeyFile
            FileType            = "SSH2_RFC4716"
            Contents            = $(Get-Content $PathToKeyFile)
            Info                = $(Get-Content $PathToKeyFile)
            FingerPrint         = $null
            PasswordProtected   = $null
        }

        return
    }
    else {
        $NotPubKeyPrivKeyOrPubCert = $True
    }

    if ($NotPubKeyPrivKeyOrPubCert) {
        Write-Warning "'$PathToKeyFile' is NOT a Public Key, Public Key Certificate, or Private Key"
    }
    else {
        if ($IsPublicKeyCert) {
            $FileType           = "RSAPublicKeyCertificate"
            $Contents           = $PublicKeyCertContent
            $Info               = $PublicKeyCertInfo
            $PasswordProtected  = $False
        }
        if ($IsPublicKey) {
            $FileType           = "RSAPublicKey"
            $Contents           = $PublicKeyContent
            $Info               = $PublicKeyInfo
            $PasswordProtected  = $False
        }
        if ($IsPrivateKey) {
            $FileType           = "RSAPrivateKey"
            $Contents           = $PrivateKeyContent
            $Info               = $PrivateKeyInfo
            $PasswordProtected  = $PrivateKeyAttempt.PasswordProtected
        }

        [pscustomobject]@{
            File                = $PathToKeyFile
            FileType            = $FileType
            Contents            = $Contents
            Info                = $Info
            FingerPrint         = $FingerPrint
            PasswordProtected   = $PasswordProtected
        }
    }
}



# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUXF7rbeRhKjtUvUcjt9OI2Sla
# IVqgggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFC70pSwRIjqgpWj1
# zVRsfIYVpp8LMA0GCSqGSIb3DQEBAQUABIIBAJDf76T8M0/u1maSg4kqU059TxX1
# b6qxFz/CAhJHvTcRiLvM8wCwcMXdm0QVE2pyHHirurNVpvsbB7tpWESAN+3gbGJr
# JwFRLlP+a7DdU1G6SV1hVboXjzUly4Il5wrYoUIFEv3T9jjJCFcQJ65u0z+39+zr
# GF/W7AvURbgaJi+4l9lBUW1fgEYatGX8/gLhukDFEFRJkK7HgdcvHhQLGsMYC7XR
# fYA1pr1tOhxDc5lREh8nHm0WzRH+oA09IEyLxOSR2Wwfc/6CzgagRtEPKmKvaYtr
# iPgXmKJtniOOz+t4FUF44OHAq8bBMCmz2Ytaj9Rjt+02yl5q64eUpWt0j4U=
# SIG # End signature block
