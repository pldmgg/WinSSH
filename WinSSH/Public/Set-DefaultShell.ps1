<#
    .SYNOPSIS
        This function modifies sshd_config on the local host and sets the default shell
        that Remote Users will use when they ssh to the local host.

    .DESCRIPTION
        See .SYNOPSIS

    .NOTES

    .PARAMETER DefaultShell
        This parameter is MANDATORY.

        This parameter takes a string that must be one of two values: "powershell","pwsh"

        If set to "powershell", when a Remote User connects to the local host via ssh, they will enter a
        Windows PowerShell 5.1 shell.

        If set to "pwsh", when a Remote User connects to the local host via ssh, the will enter a
        PowerShell Core 6 shell.

    .EXAMPLE
        # Open an elevated PowerShell Session, import the module, and -

        PS C:\Users\zeroadmin> Set-DefaultShell -DefaultShell powershell
        
#>
function Set-DefaultShell {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [ValidateSet("powershell","pwsh")]
        [string]$DefaultShell
    )

    if (Test-Path "$env:ProgramData\ssh\sshd_config") {
        $sshdConfigPath = "$env:ProgramData\ssh\sshd_config"
    }
    elseif (Test-Path "$env:ProgramFiles\OpenSSH-Win64\sshd_config") {
        $sshdConfigPath = "$env:ProgramFiles\OpenSSH-Win64\sshd_config"
    }
    else {
        Write-Error "Unable to find file 'sshd_config'! Halting!"
        $global:FunctionResult = "1"
        return
    }

    if ($DefaultShell -eq "powershell") {
        $WindowsPowerShellPath = $(Get-Command powershell).Source
        $WindowsPowerShellPathWithForwardSlashes = $WindowsPowerShellPath -replace "\\","/"

        $ForceCommandOptionLine = "ForceCommand powershell.exe -NoProfile"
    }
    if ($DefaultShell -eq "pwsh") {
        # Search for pwsh.exe where we expect it to be
        [array]$PotentialPwshExes = @(Get-ChildItem "$env:ProgramFiles\Powershell" -Recurse -File -Filter "*pwsh.exe")
        if (![bool]$(Get-Command pwsh -ErrorAction SilentlyContinue)) {
            try {
                $InstallPwshSplatParams = @{
                    ProgramName                 = "powershell-core"
                    CommandName                 = "pwsh.exe"
                    ExpectedInstallLocation     = "C:\Program Files\PowerShell"
                    ErrorAction                 = "SilentlyContinue"
                    ErrorVariable               = "InstallPwshErrors"
                }
                $InstallPwshResult = Install-Program @InstallPwshSplatParams

                if (![bool]$(Get-Command pwsh -ErrorAction SilentlyContinue)) {throw}
            }
            catch {
                Write-Error $($InstallPwshErrors | Out-String)
                $global:FunctionResult = "1"
                return
            }

            [array]$PotentialPwshExes = @(Get-ChildItem "$env:ProgramFiles\Powershell" -Recurse -File -Filter "*pwsh.exe")
        }
        if (![bool]$(Get-Command pwsh -ErrorAction SilentlyContinue)) {
            Write-Error "Unable to find pwsh.exe! Please check your `$env:Path! Halting!"
            $global:FunctionResult = "1"
            return
        }

        $LatestLocallyAvailablePwsh = [array]$($PotentialPwshExes.VersionInfo | Sort-Object -Property ProductVersion)[-1].FileName
        $LatestPwshParentDir = [System.IO.Path]::GetDirectoryName($LatestLocallyAvailablePwsh)
        $PowerShellCorePathWithForwardSlashes = $LatestLocallyAvailablePwsh -replace "\\","/"
        $PowerShellCorePathWithForwardSlashes = $PowerShellCorePathWithForwardSlashes -replace [regex]::Escape("C:/Program Files"),'%PROGRAMFILES%'

        # Update $env:Path to incloude pwsh
        if ($($env:Path -split ";") -notcontains $LatestPwshParentDir) {
            # TODO: Clean out older pwsh $env:Path entries if they exist...
            $env:Path = "$LatestPwshParentDir;$env:Path"
        }
        
        # Update SYSTEM Path to include pwsh
        $CurrentSystemPath = $(Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment' -Name PATH).Path
        $CurrentSystemPathArray = $CurrentSystemPath -split ";"
        if ($CurrentSystemPathArray -notcontains $LatestPwshParentDir) {
            $UpdatedSystemPath = "$LatestPwshParentDir;$CurrentSystemPath"
        }
        Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment" -Name PATH -Value $UpdatedSystemPath
        

        $ForceCommandOptionLine = "ForceCommand pwsh.exe -NoProfile"
    }

    # Subsystem instructions: https://github.com/PowerShell/PowerShell/tree/master/demos/SSHRemoting#setup-on-windows-machine
    [System.Collections.ArrayList]$sshdContent = Get-Content $sshdConfigPath
    
    if (![bool]$($sshdContent -match "Subsystem[\s]+powershell")) {
        $InsertAfterThisLine = $sshdContent -match "sftp"
        $InsertOnThisLine = $sshdContent.IndexOf($InsertAfterThisLine)+1
        if ($DefaultShell -eq "pwsh") {
            $sshdContent.Insert($InsertOnThisLine, "Subsystem powershell $PowerShellCorePathWithForwardSlashes -sshs -NoLogo -NoProfile")
        }
        else {
            $sshdContent.Insert($InsertOnThisLine, "Subsystem powershell $WindowsPowerShellPathWithForwardSlashes -sshs -NoLogo -NoProfile")
        }
    }
    elseif (![bool]$($sshdContent -match "Subsystem[\s]+powershell[\s]+$WindowsPowerShellPathWithForwardSlashes") -and $DefaultShell -eq "powershell") {
        $LineToReplace = $sshdContent -match "Subsystem[\s]+powershell"
        $sshdContent = $sshdContent -replace [regex]::Escape($LineToReplace),"Subsystem powershell $WindowsPowerShellPathWithForwardSlashes -sshs -NoLogo -NoProfile"
    }
    elseif (![bool]$($sshdContent -match "Subsystem[\s]+powershell[\s]+$PowerShellCorePathWithForwardSlashes") -and $DefaultShell -eq "pwsh") {
        $LineToReplace = $sshdContent -match "Subsystem[\s]+powershell"
        $sshdContent = $sshdContent -replace [regex]::Escape($LineToReplace),"Subsystem powershell $PowerShellCorePathWithForwardSlashes -sshs -NoLogo -NoProfile"
    }

    Set-Content -Value $sshdContent -Path $sshdConfigPath

    # Determine if sshd_config already has the 'ForceCommand' option active
    $ExistingForceCommandOption = $sshdContent -match "ForceCommand" | Where-Object {$_ -notmatch "#"}

    # Determine if sshd_config already has 'Match User' option active
    $ExistingMatchUserOption = $sshdContent -match "Match User" | Where-Object {$_ -notmatch "#"}
    
    if (!$ExistingForceCommandOption) {
        # If sshd_config already has the 'Match User' option available, don't touch it, else add it with ForceCommand
        try {
            if (!$ExistingMatchUserOption) {
                Add-Content -Value "Match User *`n$ForceCommandOptionLine" -Path $sshdConfigPath
            }
            else {
                Add-Content -Value "$ForceCommandOptionLine" -Path $sshdConfigPath
            }

            Restart-Service sshd -ErrorAction Stop
            Write-Host "Successfully changed sshd default shell to '$DefaultShell'" -ForegroundColor Green
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            return
        }
    }
    else {
        if ($ExistingForceCommandOption -ne $ForceCommandOptionLine) {
            if (!$ExistingMatchUserOption) {
                $UpdatedSSHDConfig = $sshdContent -replace [regex]::Escape($ExistingForceCommandOption),"Match User *`n$ForceCommandOptionLine"
            }
            else {
                $UpdatedSSHDConfig = $sshdContent -replace [regex]::Escape($ExistingForceCommandOption),"$ForceCommandOptionLine"
            }

            try {
                Set-Content -Value $UpdatedSSHDConfig -Path $sshdConfigPath
                Restart-Service sshd -ErrorAction Stop
                Write-Host "Successfully changed sshd default shell to '$DefaultShell'" -ForegroundColor Green
            }
            catch {
                Write-Error $_
                $global:FunctionResult = "1"
                return
            }
        }
        else {
            Write-Warning "The specified 'ForceCommand' option is already active in the the sshd_config file. No changes made."
        }
    }
}

# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUWl1T++OTk3sc5kSdGXeGcibm
# TRmgggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFIs8BJHNk2qbKb03
# InL1NEcPkXmFMA0GCSqGSIb3DQEBAQUABIIBABUy/sHDgg4u/hI4njHd1ctKM2cy
# 9muQZJHVFLyqNrCYYXiDMkR0rIL0dtb7ZQlCA3qa62dibtrIcS12gnxjGZ/sGS9m
# A3eLUraSRcMnKGVBewEeobhVAIPu3xoMD8Qbpo8rjM/VbTXsVKLgig/VlBq+J1VN
# M5NQr+CfiCEFUO4FzpjQ3gdNz5Lbv2K6Ahr23Wn8mQN7O3/ivGcl/diARn8vjQl9
# CtHE9x8YB6F4T/KAdiwl7MLGOwndmJXU3qYE4svp+xu7gvxUA1LMFqccqc7FpazH
# gWq/kXK0vvLwf4L8wxvJ7uRXCX4g+aJBPs7QTvN5XXfSJWVGUzLnpMAZjHk=
# SIG # End signature block
