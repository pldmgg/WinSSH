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

    .PARAMETER SubsystemSymlinksDirectory
        This parameter is OPTIONAL.

        This parameter takes a string that represents the path to a directory that will contain symlinked directories
        to the directories containing powershell.exe and/or pwsh.exe

    .PARAMETER UseForceCommand
        This parameter is OPTIONAL.

        This parameter is a switch. If used, the 'ForceCommand' option will be added to sshd_config.

    .EXAMPLE
        # Open an elevated PowerShell Session, import the module, and -

        PS C:\Users\zeroadmin> Set-DefaultShell -DefaultShell powershell
        
#>
function Set-DefaultShell {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [ValidateSet("powershell","pwsh")]
        [string]$DefaultShell,

        [Parameter(Mandatory=$False)]
        [string]$SubsystemSymlinksDirectory = "C:\sshSymlinks",

        [Parameter(Mandatory=$False)]
        [switch]$UseForceCommand
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

    # Setup the Subsystem Symlinks directory
    if ($SubsystemSymlinksDirectory -match "[\s]") {
        Write-Error "The -SubsystemSymlinksDirectory path must not contain any spaces! Halting!"
        $global:FunctionResult = "1"
        return
    }
    if (Test-Path $SubsystemSymlinksDirectory) {
        try {
            Remove-Item $SubsystemSymlinksDirectory -Recurse -Force
        }
        catch {
            try {
                Get-ChildItem -Path $SubsystemSymlinksDirectory -Recurse | foreach {$_.Delete()}
                Remove-Item $SubsystemSymlinksDirectory -Recurse -Force
            }
            catch {
                Write-Error $_
                $global:FunctionResult = "1"
                return
            }
        }
    }
    $null = New-Item -ItemType Directory -Path $SubsystemSymlinksDirectory -Force
    $PowerShellSymlinkRoot = "$SubsystemSymlinksDirectory\powershellRoot"
    $PwshSymlinkRoot = "$SubsystemSymlinksDirectory\pwshRoot"
    #$null = New-Item -ItemType Directory -Path $PowerShellSymlinkRoot -Force
    #$null = New-Item -ItemType Directory -Path $PwshSymlinkRoot -Force


    if ($DefaultShell -eq "powershell") {
        $WindowsPowerShellPath = $(Get-Command powershell).Source
        #$WindowsPowerShellPathWithForwardSlashes = $WindowsPowerShellPath -replace "\\","/"

        # Create the powershell.exe parent directory symlink
        $null = New-Item -ItemType SymbolicLink -Path $PowerShellSymlinkRoot -Target $($(Get-Command powershell).Source | Split-Path -Parent)

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
        #$PowerShellCorePathWithForwardSlashes = $LatestLocallyAvailablePwsh -replace "\\","/"
        #$PowerShellCorePathWithForwardSlashes = $PowerShellCorePathWithForwardSlashes -replace [regex]::Escape("C:/Program Files"),'%PROGRAMFILES%'

        # Create the pwsh.exe parent directory symlink
        $null = New-Item -ItemType SymbolicLink -Path $PwshSymlinkRoot -Target $LatestPwshParentDir

        # Update $env:Path to include pwsh
        if ($($env:Path -split ";") -notcontains $LatestPwshParentDir) {
            # TODO: Clean out older pwsh $env:Path entries if they exist...
            $env:Path = "$LatestPwshParentDir;$env:Path"
        }
        
        # Update SYSTEM Path to include pwsh
        $CurrentSystemPath = $(Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment' -Name PATH).Path
        $CurrentSystemPathArray = $CurrentSystemPath -split ";"
        if ($CurrentSystemPathArray -notcontains $LatestPwshParentDir) {
            $UpdatedSystemPath = "$LatestPwshParentDir;$CurrentSystemPath"
            Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment" -Name PATH -Value $UpdatedSystemPath
        }

        $ForceCommandOptionLine = "ForceCommand pwsh.exe -NoProfile"
    }

    if (!$UseForceCommand) {
        # Set DefaultShell in Registry
        $OpenSSHRegistryPath = "HKLM:\SOFTWARE\OpenSSH"
        if ($(Get-Item -Path $OpenSSHRegistryPath).Property -contains "DefaultShell") {
            Remove-ItemProperty -Path $OpenSSHRegistryPath -Name DefaultShell -Force
        }
        if ($DefaultShell -eq "pwsh") {
            New-ItemProperty -Path $OpenSSHRegistryPath -Name DefaultShell -Value "$PwshSymlinkRoot\pwsh.exe" -PropertyType String -Force
        }
        else {
            New-ItemProperty -Path $OpenSSHRegistryPath -Name DefaultShell -Value "$PowerShellSymlinkRoot\powershell.exe" -PropertyType String -Force
        }
    }

    # Subsystem instructions: https://github.com/PowerShell/PowerShell/tree/master/demos/SSHRemoting#setup-on-windows-machine
    [System.Collections.ArrayList]$sshdContent = Get-Content $sshdConfigPath
    $PowerShellSymlinkRootRegex = [regex]::Escape($PowerShellSymlinkRoot)
    $PwshSymlinkRootRegex = [regex]::Escape($PwshSymlinkRoot)
    
    if (![bool]$($sshdContent -match "Subsystem[\s]+powershell")) {
        $InsertAfterThisLine = $sshdContent -match "sftp"
        $InsertOnThisLine = $sshdContent.IndexOf($InsertAfterThisLine)+1
        if ($DefaultShell -eq "pwsh") {
            $sshdContent.Insert($InsertOnThisLine, "Subsystem powershell $PwshSymlinkRoot\pwsh.exe -sshs -NoLogo -NoProfile")
        }
        else {
            $sshdContent.Insert($InsertOnThisLine, "Subsystem powershell $PowerShellSymlinkRoot\powershell.exe -sshs -NoLogo -NoProfile")
        }
    }
    elseif (![bool]$($sshdContent -match "Subsystem[\s]+powershell[\s]+$PowerShellSymlinkRootRegex") -and $DefaultShell -eq "powershell") {
        $LineToReplace = $sshdContent -match "Subsystem[\s]+powershell"
        $sshdContent = $sshdContent -replace [regex]::Escape($LineToReplace),"Subsystem powershell $PowerShellSymlinkRoot\powershell.exe -sshs -NoLogo -NoProfile"
    }
    elseif (![bool]$($sshdContent -match "Subsystem[\s]+powershell[\s]+$PwshSymlinkRootRegex") -and $DefaultShell -eq "pwsh") {
        $LineToReplace = $sshdContent -match "Subsystem[\s]+powershell"
        $sshdContent = $sshdContent -replace [regex]::Escape($LineToReplace),"Subsystem powershell $PwshSymlinkRoot\pwsh.exe -sshs -NoLogo -NoProfile"
    }

    Set-Content -Value $sshdContent -Path $sshdConfigPath

    # Determine if sshd_config already has the 'ForceCommand' option active
    $ExistingForceCommandOption = $sshdContent -match "ForceCommand" | Where-Object {$_ -notmatch "#"}

    # Determine if sshd_config already has 'Match User' option active
    $ExistingMatchUserOption = $sshdContent -match "Match User" | Where-Object {$_ -notmatch "#"}
    
    if (!$ExistingForceCommandOption) {
        if ($UseForceCommand) {
            # If sshd_config already has the 'Match User' option available, don't touch it, else add it with ForceCommand
            try {
                if (!$ExistingMatchUserOption) {
                    Add-Content -Value "Match User *`n$ForceCommandOptionLine" -Path $sshdConfigPath
                }
                else {
                    Add-Content -Value "$ForceCommandOptionLine" -Path $sshdConfigPath
                }

                try {
                    Restart-Service sshd -ErrorAction Stop
                    Write-Host "Successfully changed sshd default shell to '$DefaultShell'" -ForegroundColor Green
                }
                catch {
                    Write-Error $_
                    $global:FunctionResult = "1"
                    return
                }
            }
            catch {
                Write-Error $_
                $global:FunctionResult = "1"
                return
            }
        }
        elseif (!$ExistingMatchUserOption) {
            Add-Content -Value "Match User *" -Path $sshdConfigPath

            try {
                Restart-Service sshd -ErrorAction Stop
                Write-Host "Successfully changed sshd default shell to '$DefaultShell'" -ForegroundColor Green
            }
            catch {
                Write-Error $_
                $global:FunctionResult = "1"
                return
            }
        }
    }
    else {
        if ($UseForceCommand) {
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
        elseif (!$ExistingMatchUserOption) {
            $UpdatedSSHDConfig = $sshdContent -replace [regex]::Escape($ExistingForceCommandOption),"Match User *"

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
    }
}

# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUyBYxN2WSTy5DQwwAIl0VFdBM
# Cq+gggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFA46T1R3gXni0lmR
# L4Xd5ZFKFZWEMA0GCSqGSIb3DQEBAQUABIIBABLM6QJwYFU0ZtvL0CKTJsnMg+Ew
# GgcC4WYM1UOM0JH62k2llyS93hK9nW/mTcsYgI1ywtXj+OeB95JluL54AoMQEDOU
# 79eb7tWXNEFDyseeffc5KoAwyt7ALhfrxoNElSqvJgGcIwvRvlijOSphMruDBnLj
# yr+HpN8TSoxzRfAI/0zVYhe2l6bkublD0oKlvm2IKZuDmTP1SerOBnA4h5wSytl8
# ACQ/v6jdYICcSmN5cXTPzNspTJv2VON65YYMtrp4QEIW4GXmLrbshVpvMCAwSAjE
# 1BzUAWoLxHQigTM/cck3j4mXRGNhj6vBCAuVQQYGiJENQGDO57f6JRZbNu8=
# SIG # End signature block
