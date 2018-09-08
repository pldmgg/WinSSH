# Python Code from: https://github.com/ropnop/windows_sshagent_extract
function Extract-SSHPrivateKeyFromRegistry {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$False)]
        [switch]$KeepSSHAgent
    )

    $OpenSSHRegistryPath = "HKCU:\Software\OpenSSH\Agent\Keys\"

    $RegistryKeys = Get-ChildItem $OpenSSHRegistryPath | Get-ItemProperty

    if ($RegistryKeys.Length -eq 0) {
        Write-Error "No ssh-agent keys in registry"
        $global:FunctionResult = "1"
        return
    }

    $tempDirectory = [IO.Path]::Combine([IO.Path]::GetTempPath(), [IO.Path]::GetRandomFileName())
    $null = [IO.Directory]::CreateDirectory($tempDirectory)

    Add-Type -AssemblyName System.Security
    [System.Collections.ArrayList]$keys = @()
    $RegistryKeys | foreach {
        $key = @{}
        $comment = [System.Text.Encoding]::ASCII.GetString($_.comment)
        $encdata = $_.'(default)'
        $decdata = [Security.Cryptography.ProtectedData]::Unprotect($encdata, $null, 'CurrentUser')
        $b64key = [System.Convert]::ToBase64String($decdata)
        $key[$comment] = $b64key
        $null = $keys.Add($key)
    }

    ConvertTo-Json -InputObject $keys | Out-File -FilePath "$tempDirectory/extracted_keyblobs.json" -Encoding ascii

    $InstallPython3Result = Install-Program -ProgramName python3 -CommandName python -UseChocolateyCmdLine
    if (!$(Get-Command python -ErrorAction SilentlyContinue)) {
        Write-Error "Unable to find python.exe! Halting!"
        $global:FunctionResult = "1"
        return
    }
    if (!$(Get-Command pip -ErrorAction SilentlyContinue)) {
        Write-Error "Unable to find pip.exe! Halting!"
        $global:FunctionResult = "1"
        return
    }
    pip install pyasn1 pip *> $null
    
    Set-Content -Path "$tempDirectory\extractPrivateKeys.py" -Value @"
#!/usr/bin/env python

# Script to extract OpenSSH private RSA keys from base64 data
# From: https://github.com/ropnop/windows_sshagent_extract

import sys
import base64
import json
try:
    from pyasn1.type import univ
    from pyasn1.codec.der import encoder
except ImportError:
    print("You must install pyasn1")
    sys.exit(0)


def extractRSAKey(data):
    keybytes = base64.b64decode(data)
    offset = keybytes.find(b"ssh-rsa")
    if not offset:
        print("[!] No valid RSA key found")
        return None
    keybytes = keybytes[offset:]

    # This code is re-implemented code originally written by soleblaze in sshkey-grab
    start = 10
    size = getInt(keybytes[start:(start+2)])
    # size = unpack_bigint(keybytes[start:(start+2)])
    start += 2
    n = getInt(keybytes[start:(start+size)])
    start = start + size + 2
    size = getInt(keybytes[start:(start+2)])
    start += 2
    e = getInt(keybytes[start:(start+size)])
    start = start + size + 2
    size = getInt(keybytes[start:(start+2)])
    start += 2
    d = getInt(keybytes[start:(start+size)])
    start = start + size + 2
    size = getInt(keybytes[start:(start+2)])
    start += 2
    c = getInt(keybytes[start:(start+size)])
    start = start + size + 2
    size = getInt(keybytes[start:(start+2)])
    start += 2
    p = getInt(keybytes[start:(start+size)])
    start = start + size + 2
    size = getInt(keybytes[start:(start+2)])
    start += 2
    q = getInt(keybytes[start:(start+size)])

    e1 = d % (p - 1)
    e2 = d % (q - 1)

    keybytes = keybytes[start+size:]

    seq = (
        univ.Integer(0),
        univ.Integer(n),
        univ.Integer(e),
        univ.Integer(d),
        univ.Integer(p),
        univ.Integer(q),
        univ.Integer(e1),
        univ.Integer(e2),
        univ.Integer(c),
    )

    struct = univ.Sequence()

    for i in range(len(seq)):
        struct.setComponentByPosition(i, seq[i])
    
    raw = encoder.encode(struct)
    data = base64.b64encode(raw).decode('utf-8')

    width = 64
    chopped = [data[i:i + width] for i in range(0, len(data), width)]
    top = "-----BEGIN RSA PRIVATE KEY-----\n"
    content = "\n".join(chopped)
    bottom = "\n-----END RSA PRIVATE KEY-----"
    return top+content+bottom

def getInt(buf):
    return int.from_bytes(buf, byteorder='big')


def run(filename):
    with open(filename, 'r') as fp:
        keysdata = json.loads(fp.read())
    
    for jkey in keysdata:
        for keycomment, data in jkey.items():
            privatekey = extractRSAKey(data)
            print("[+] Key Comment: {}".format(keycomment))
            print(privatekey)
            print()
    
    sys.exit(0)

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: {} extracted_keyblobs.json".format(sys.argv[0]))
        sys.exit(0)
    filename = sys.argv[1]
    run(filename)
    
"@

    Push-Location $tempDirectory

    $SSHAgentPrivateKeys = python .\extractPrivateKeys.py .\extracted_keyblobs.json

    [System.Collections.ArrayList]$UpdatedSSHAgentPrivKeyInfoArray = @()
    $SSHAgentPrivateKeysArrayList = [System.Collections.ArrayList]$SSHAgentPrivateKeys
    $NumberOfPrivateKeys = $($SSHAgentPrivateKeys | Where-Object {$_ -eq "-----END RSA PRIVATE KEY-----"}).Count
    for ($i=0; $i -lt $NumberOfPrivateKeys; $i++) {
        $SSHAgentPrivateKeysArrayListClone = $($SSHAgentPrivateKeysArrayList.Clone() -join "`n").Trim() -split "`n"
        New-Variable -Name "KeyInfo$i" -Value $(New-Object System.Collections.ArrayList) -Force

        :privkeylines foreach ($Line in $SSHAgentPrivateKeysArrayListClone) {
            if (![System.String]::IsNullOrWhiteSpace($Line)) {
                $null = $(Get-Variable -Name "KeyInfo$i" -ValueOnly).Add($Line)
                $SSHAgentPrivateKeysArrayList.Remove($Line)
            }
            else {
                break privkeylines
            }
        }

        $null = $UpdatedSSHAgentPrivKeyInfoArray.Add($(Get-Variable -Name "KeyInfo$i" -ValueOnly))
    }

    [System.Collections.ArrayList]$FinalSSHPrivKeyObjs = @()
    foreach ($PrivKeyInfoStringArray in $UpdatedSSHAgentPrivKeyInfoArray) {
        $OriginalPrivateKeyFilePath = $PrivKeyInfoStringArray[0] -replace "\[\+\] Key Comment: ",""
        $PrivateKeyContent = $PrivKeyInfoStringArray[1..$($PrivKeyInfoStringArray.Count-1)]
        $PSObj = [pscustomobject]@{
            OriginalPrivateKeyFilePath      = $OriginalPrivateKeyFilePath
            PrivateKeyContent               = $PrivateKeyContent
        }

        $null = $FinalSSHPrivKeyObjs.Add($PSObj)
    }

    Pop-Location

    Remove-Item $tempDirectory -Recurse -Force

    $FinalSSHPrivKeyObjs
}

# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQURbcQTRdJBoDdJ4DtBFUbYXGr
# Ntygggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFOEHpcChXJzoF63l
# YwqmzLiNT31mMA0GCSqGSIb3DQEBAQUABIIBACwVSaSBhijVa/Fi+uh/KZZo8ee9
# pSXZAFaS0vl5sGpqlYgcfY15NtjgFN8K4jw2lqTt4BLE5eS7SNG/fsWttFynH/Y5
# 1nF7JB8w/b/thF985F30V0ow2QH403k+Ne1/Aoj3/KC6IMx9wdZoo6AHtuux1ppv
# VVpwp0qxT4/HkPvLFsiHqX4XZ63YBYoVFZ06ASaMKtetaQ9PxKLRpiQIhwNfPz+X
# Wj1sZUisJfSDRSnBCy3vw0onf8nNL8bCZJWUG5+16EGggJw+Om+niK6UJUAWs9HI
# vO5a/EvGqZx87nyfrkABuS7MxT37Qskqu5NZeiwTeUX5rebx/zX1zzOQMZo=
# SIG # End signature block
