<#
    .SYNOPSIS
        This function Sets and/or fixes NTFS filesystem permissions recursively on the directories
        'C:\Program Files\OpenSSH-Win64' and/or 'C:\ProgramData\ssh' and/or '$HOME\.ssh'.

    .DESCRIPTION
        See .SYNOPSIS

    .NOTES

    .PARAMETER HomeFolderAndSubItemsOnly
        This parameter is OPTIONAL.

        This parameter is a switch. If used, this function will only fix permissions recursively on
        the directory '$HOME\.ssh'

    .PARAMETER ProgramDataFolderAndSubItemsOnly
        This parameter is OPTIONAL.

        This parameter is a switch. If used, this function will only fix permissions recursively on
        the directories 'C:\Program Files\OpenSSH-Win64' and/or 'C:\ProgramData\ssh'

    .EXAMPLE
        # Open an elevated PowerShell Session, import the module, and -

        PS C:\Users\zeroadmin> Fix-SSHPermissions
        
#>
function Fix-SSHPermissions {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [switch]$HomeFolderAndSubItemsOnly,

        [Parameter(Mandatory=$False)]
        [switch]$ProgramDataFolderAndSubItemsOnly
    )

    if ($PSVersionTable.PSEdition -ne "Desktop" -and $PSVersionTable.Platform -ne "Win32NT") {
        Write-Error "This function is only meant to fix permissions on Windows machines. Halting!"
        $global:FunctionResult = "1"
        return
    }

    if (!$HomeFolderAndSubItemsOnly) {
        if (Test-Path "$env:ProgramData\ssh") {
            $sshdir = "$env:ProgramData\ssh"
        }
        elseif (Test-Path "$env:ProgramFiles\OpenSSH-Win64") {
            $sshdir = "$env:ProgramFiles\OpenSSH-Win64"
        }
        if (!$sshdir) {
            Write-Error "Unable to find ssh directory at '$env:ProgramData\ssh' or '$env:ProgramFiles\OpenSSH-Win64'! Halting!"
            $global:FunctionResult = "1"
            return
        }
    }

    if (!$(Test-Path "$env:ProgramFiles\OpenSSH-Win64\FixHostFilePermissions.ps1")) {
        $LatestPSScriptsUriBase = "https://raw.githubusercontent.com/PowerShell/Win32-OpenSSH/L1-Prod/contrib/win32/openssh"
        $ScriptsToDownload = @(
            "FixHostFilePermissions.ps1"
            "FixUserFilePermissions.ps1"
            #"OpenSSHCommonUtils"
            "OpenSSHUtils.psm1"
        )

        $NewFolderInDownloadDir = NewUniqueString -ArrayOfStrings $(Get-ChildItem "$HOME\Downloads" -Directory).Name -PossibleNewUniqueString "OpenSSH_PowerShell_Utils"

        $null = New-Item -ItemType Directory -Path "$HOME\Downloads\$NewFolderInDownloadDir"

        [System.Collections.ArrayList]$FailedDownloads = @()
        foreach ($ScriptFile in $ScriptsToDownload) {
            $OutFilePath = "$HOME\Downloads\$NewFolderInDownloadDir\$ScriptFile"
            Invoke-WebRequest -Uri "$LatestPSScriptsUriBase/$ScriptFile" -OutFile $OutFilePath
            
            if (!$(Test-Path $OutFilePath)) {
                $null = $FailedDownloads.Add($OutFilePath)
            }
        }

        if ($FailedDownloads.Count -gt 0) {
            Write-Error "Failed to download the following OpenSSH PowerShell Utility Scripts/Modules: $($FailedDownloads -join ', ')! Halting!"
            $global:FunctionResult = "1"
            return
        }

        $OpenSSHPSUtilityScriptDir = "$HOME\Downloads\$NewFolderInDownloadDir"
    }
    else {
        $OpenSSHPSUtilityScriptDir = "$env:ProgramFiles\OpenSSH-Win64"
    }

    if ($(Get-Module).Name -contains "OpenSSHUtils") {
        Remove-Module OpenSSHUtils
    }
    <#
    if ($(Get-Module).Name -contains "OpenSSHCommonUtils") {
        Remove-Module OpenSSHCommonUtils
    }
    #>

    Import-Module "$OpenSSHPSUtilityScriptDir\OpenSSHUtils.psm1"
    #Import-Module "$OpenSSHPSUtilityScriptDir\OpenSSHCommonUtils.psm1"
    
    if ($(Get-Module).Name -notcontains "OpenSSHUtils") {
        Write-Error "Failed to import OpenSSHUtils Module! Halting!"
        $global:FunctionResult = "1"
        return
    }
    <#
    if ($(Get-Module).Name -notcontains "OpenSSHCommonUtils") {
        Write-Error "Failed to import OpenSSHCommonUtils Module! Halting!"
        $global:FunctionResult = "1"
        return
    }
    #>

    if ($(Get-Module -ListAvailable).Name -notcontains "NTFSSecurity") {
        Install-Module NTFSSecurity
    }

    try {
        if ($(Get-Module).Name -notcontains "NTFSSecurity") {Import-Module NTFSSecurity}
    }
    catch {
        if ($_.Exception.GetType().FullName -eq "System.Management.Automation.RuntimeException") {
            Write-Verbose "NTFSSecurity Module is already loaded..."
        }
        else {
            Write-Error "There was a problem loading the NTFSSecurity Module! Halting!"
            $global:FunctionResult = "1"
            return
        }
    }

    if (!$HomeFolderAndSubItemsOnly) {
        $FixHostFilePermissionsOutput = & "$OpenSSHPSUtilityScriptDir\FixHostFilePermissions.ps1" -Confirm:$false 6>&1

        if (Test-Path "$sshdir/authorized_principals") {
            $SecurityDescriptor = Get-NTFSSecurityDescriptor -Path "$sshdir/authorized_principals"
            $SecurityDescriptor | Disable-NTFSAccessInheritance -RemoveInheritedAccessRules
            $SecurityDescriptor | Clear-NTFSAccess
            $SecurityDescriptor | Add-NTFSAccess -Account "NT AUTHORITY\SYSTEM" -AccessRights "FullControl" -AppliesTo ThisFolderSubfoldersAndFiles
            $SecurityDescriptor | Add-NTFSAccess -Account "Administrators" -AccessRights "FullControl" -AppliesTo ThisFolderSubfoldersAndFiles
            $SecurityDescriptor | Set-NTFSSecurityDescriptor
        }

        # If there's a Host Key Public Cert, make sure permissions on it are set properly...This is not handled
        # by FixHostFilePermissions.ps1
        if (Test-Path "$sshdir/ssh_host_rsa_key-cert.pub") {
            $SecurityDescriptor = Get-NTFSSecurityDescriptor -Path "$sshdir/ssh_host_rsa_key-cert.pub"
            $SecurityDescriptor | Disable-NTFSAccessInheritance -RemoveInheritedAccessRules
            $SecurityDescriptor | Clear-NTFSAccess
            $SecurityDescriptor | Add-NTFSAccess -Account "NT AUTHORITY\SYSTEM" -AccessRights "FullControl" -AppliesTo ThisFolderSubfoldersAndFiles
            $SecurityDescriptor | Add-NTFSAccess -Account "Administrators" -AccessRights "FullControl" -AppliesTo ThisFolderSubfoldersAndFiles
            $SecurityDescriptor | Add-NTFSAccess -Account "NT AUTHORITY\Authenticated Users" -AccessRights "ReadAndExecute, Synchronize" -AppliesTo ThisFolderSubfoldersAndFiles
            $SecurityDescriptor | Set-NTFSSecurityDescriptor
        }
    }
    if (!$ProgramDataFolderAndSubItemsOnly) {
        $FixUserFilePermissionsOutput = & "$OpenSSHPSUtilityScriptDir\FixUserFilePermissions.ps1" -Confirm:$false 6>&1

        $SecurityDescriptor = Get-NTFSSecurityDescriptor -Path "$HOME\.ssh"
        $SecurityDescriptor | Disable-NTFSAccessInheritance -RemoveInheritedAccessRules
        $SecurityDescriptor | Clear-NTFSAccess
        $SecurityDescriptor | Add-NTFSAccess -Account "NT AUTHORITY\SYSTEM" -AccessRights "FullControl" -AppliesTo ThisFolderSubfoldersAndFiles
        $SecurityDescriptor | Add-NTFSAccess -Account "$(whoami)" -AccessRights "FullControl" -AppliesTo ThisFolderSubfoldersAndFiles
        $SecurityDescriptor | Set-NTFSSecurityDescriptor

        $UserHomeDirs = Get-ChildItem "C:\Users"
        foreach ($UserDir in $UserHomeDirs) {
            $KnownHostsPath = "$($UserDir.FullName)\.ssh\known_hosts"
            $AuthorizedKeysPath = "$($UserDir.FullName)\.ssh\authorized_keys"

            if ($(Test-Path $KnownHostsPath) -or $(Test-Path $AuthorizedKeysPath)) {
                if (Test-Path $KnownHostsPath) {
                    $SecurityDescriptor = Get-NTFSSecurityDescriptor -Path $KnownHostsPath
                    $SecurityDescriptor | Disable-NTFSAccessInheritance -RemoveInheritedAccessRules
                    $SecurityDescriptor | Clear-NTFSAccess
                    $SecurityDescriptor | Enable-NTFSAccessInheritance
                    $SecurityDescriptor | Set-NTFSSecurityDescriptor

                    # Make sure it's UTF8 Encoded
                    $FileContent = Get-Content $KnownHostsPath
                    Set-Content -Value $FileContent $KnownHostsPath -Encoding UTF8
                }
                if (Test-Path $AuthorizedKeysPath) {
                    $SecurityDescriptor = Get-NTFSSecurityDescriptor -Path $AuthorizedKeysPath
                    $SecurityDescriptor | Disable-NTFSAccessInheritance -RemoveInheritedAccessRules
                    $SecurityDescriptor | Clear-NTFSAccess
                    $SecurityDescriptor | Enable-NTFSAccessInheritance
                    $SecurityDescriptor | Set-NTFSSecurityDescriptor

                    $FileContent = Get-Content $AuthorizedKeysPath
                    Set-Content -Value $FileContent $AuthorizedKeysPath -Encoding UTF8
                }
            }
        }
    }

    try {
        Write-Host "Restarting the sshd service..."
        Restart-Service sshd
    }
    catch {
        Write-Error $_
        $global:FunctionResult = "1"
        return
    }

    [pscustomobject]@{
        FixHostFilePermissionsOutput    = $FixHostFilePermissionsOutput
        FixUserFilePermissionsOutput    = $FixUserFilePermissionsOutput
    }
}



# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUsCLyWHVOKpdXclsuTVmN0Kk5
# w0Ggggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFH9RZJH4fodl4Sex
# ptje4ZhD+cN7MA0GCSqGSIb3DQEBAQUABIIBADGJDHkTH6zivy+FFyvJu3IkKSYN
# Uh8XTagONyd2Gabf7vxAv6v9pGI+uA0NYC8kU0UHl2hi+HBJwhP8GcBxbJJXAVKT
# ZUAkRScm1NfG5XcFOwaGvhg0gCz2Tla3/ct4p1aAR3ierIfNd50NKrQbLNCCp3ZK
# Kk3SKEzGesTg/3BCzgYSNc7qxpkEm5ZhTaxYODBQVi2SlbBZurAZ0Hsdgz//oR0z
# PmBWniJjnNupfnNQSckbd7xV9jP4wV0X++ZXMw2xkFaT2V78V+gl6BvJwml5dW5+
# 0sF3GxJXmlV/kbV3rqpn6hX2OrpJDRb59onF18Q8XY1Feiv1AdgdLE6K4ig=
# SIG # End signature block
