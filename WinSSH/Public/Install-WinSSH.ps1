<#
    .SYNOPSIS
        Install OpenSSH-Win64 and the associated ssh-agent service. Optionally install SSHD server and associated
        sshd service. Optionally install the latest PowerShell Core.

    .DESCRIPTION
        See .SYNOPSIS

    .NOTES

    .PARAMETER ConfigureSSHDOnLocalHost
        This parameter is OPTIONAL.

        This parameter is a switch. If used, the SSHD Server and associated sshd service will be installedm
        configured, and enabled on the local host.

    .PARAMETER RemoveHostPrivateKeys
        This parameter is OPTIONAL.

        This parameter is a switch. Use it to remove the Host Private Keys after they are added to the ssh-agent during
        sshd setup/config. Default is NOT to remove the host private keys.

        This parameter should only be used in combination with the -ConfigureSSHDOnLocalHost switch.

    .PARAMETER DefaultShell
        This parameter is OPTIONAL.

        This parameter takes a string that must be one of two values: "powershell","pwsh"

        If set to "powershell", when a Remote User connects to the local host via ssh, they will enter a
        Windows PowerShell 5.1 shell.

        If set to "pwsh", when a Remote User connects to the local host via ssh, the will enter a
        PowerShell Core 6 shell.

        If this parameter is NOT used, the Default shell will be cmd.exe.

        This parameter should only be used in combination with the -ConfigureSSHDOnLocalHost switch.

    .PARAMETER GiveWinSSHBinariesPathPriority
        This parameter is OPTIONAL, but highly recommended.

        This parameter is a switch. If used, ssh binaries installed as part of OpenSSH-Win64 installation will get
        priority in your $env:Path. This is especially useful if you have ssh binaries in your path from other
        program installs (like git).

    .PARAMETER UsePowerShellGet
        This parameter is OPTIONAL.

        This parameter is a switch. If used, OpenSSH binaries will be installed via PowerShellGet/PackageManagement
        Modules.

    .PARAMETER GitHubInstall
        This parameter is OPTIONAL.

        This parameter is a switch. If used, OpenSSH binaries will be installed by downloading the .zip
        from https://github.com/PowerShell/Win32-OpenSSH/releases/latest/, expanding the archive, moving
        the files to the approproiate location(s), and setting permissions appropriately.

    .PARAMETER UpdatePackageManagement
        This parameter is OPTIONAL.

        This parameter is a switch. If used, PowerShellGet/PackageManagement Modules will be updated to their
        latest version before installation of OpenSSH binaries.

        WARNING: Using this parameter could break certain PowerShellGet/PackageManagement cmdlets. Recommend
        using the dedicated function "Update-PackageManagemet" and starting a fresh PowerShell session after
        it finishes.

    .PARAMETER SkipWinCapabilityAttempt
        This parameter is OPTIONAL.

        This parameter is a switch.
        
        In more recent versions of Windows (Spring 2018), OpenSSH Client and SSHD Server can be installed as
        Windows Features using the Dism Module 'Add-WindowsCapability' cmdlet. If you run this function on
        a more recent version of Windows, it will attempt to use 'Add-WindowsCapability' UNLESS you use
        this switch.

        As of May 2018, there are reliability issues with the 'Add-WindowsCapability' cmdlet.
        Using this switch is highly recommend in order to avoid using 'Add-WindowsCapability'.

    .PARAMETER Force
        This parameter is a OPTIONAL.

        This parameter is a switch.

        If you are already running the latest version of OpenSSH, but would like to reinstall it and the
        associated ssh-agent service, use this switch.

    .EXAMPLE
        # Open an elevated PowerShell Session, import the module, and -

        PS C:\Users\zeroadmin> Install-WinSSH -GiveWinSSHBinariesPathPriority -ConfigureSSHDOnLocalHost -DefaultShell powershell -GitHubInstall

#>
function Install-WinSSH {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [switch]$ConfigureSSHDOnLocalHost,

        [Parameter(Mandatory=$False)]
        [switch]$RemoveHostPrivateKeys,

        [Parameter(Mandatory=$False)]
        [ValidateSet("powershell","pwsh")]
        [string]$DefaultShell,

        # For situations where there may be more than one ssh.exe available on the system that are already part of $env:Path
        # or System PATH - for example, the ssh.exe that comes with Git
        [Parameter(Mandatory=$False)]
        [switch]$GiveWinSSHBinariesPathPriority,

        [Parameter(Mandatory=$False)]
        [switch]$UsePowerShellGet,

        [Parameter(Mandatory=$False)]
        [switch]$UseChocolateyCmdLine,

        [Parameter(Mandatory=$False)]
        [switch]$GitHubInstall,

        [Parameter(Mandatory=$False)]
        [switch]$UpdatePackageManagement,

        [Parameter(Mandatory=$False)]
        [switch]$SkipWinCapabilityAttempt,

        [Parameter(Mandatory=$False)]
        [switch]$Force
    )

    ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####

    if (!$(GetElevation)) {
        Write-Verbose "You must run PowerShell as Administrator before using this function! Halting!"
        Write-Error "You must run PowerShell as Administrator before using this function! Halting!"
        $global:FunctionResult = "1"
        return
    }

    if ($UsePowerShellGet -or $UseChocolateyCmdLine -or $GitHubInstall) {
        $SkipWinCapabilityAttempt = $True
    }

    if ($UsePowerShellGet -and $($UseChocolateyCmdLine -or $GitHubInstall)) {
        Write-Error "Please use EITHER the -UsePowerShellGet switch OR the -UseChocolateyCmdLine switch OR the -GitHubInstall switch. Halting!"
        $global:FunctionResult = "1"
        return
    }
    if ($UseChocolateyCmdLine -and $($UsePowerShellGet -or $GitHubInstall)) {
        Write-Error "Please use EITHER the -UseUseChocolateyCmdLine switch OR the -UsePowerShellGet switch OR the -GitHubInstall switch. Halting!"
        $global:FunctionResult = "1"
        return
    }
    if ($GitHubInstall -and $($UsePowerShellGet -or $UseChocolateyCmdLine)) {
        Write-Error "Please use EITHER the -GitHubInstall switch OR the -UsePowerShellGet switch OR the -UseChocolateyCmdLine switch. Halting!"
        $global:FunctionResult = "1"
        return
    }

    if ($DefaultShell -and !$ConfigureSSHDOnLocalHost) {
        Write-Error "The -DefaultShell parameter is meant to set the configure the default shell for the SSHD Server. Please also use the -ConfigureSSHDOnLocalHost switch. Halting!"
        $global:FunctionResult = "1"
        return
    }

    $OpenSSHWinPath = "$env:ProgramFiles\OpenSSH-Win64"

    ##### END Variable/Parameter Transforms and PreRun Prep #####


    ##### BEGIN Main Body #####
    
    $InstallSSHAgentSplatParams = @{
        ErrorAction         = "SilentlyContinue"
        ErrorVariable       = "ISAErr"
    }
    if ($UpdatePackageManagement) {
        $InstallSSHAgentSplatParams.Add("UpdatePackageManagement",$True)
    }
    if ($UsePowerShellGet) {
        $InstallSSHAgentSplatParams.Add("UsePowerShellGet",$True)  
    }
    if ($UseChocolateyCmdLine) {
        $InstallSSHAgentSplatParams.Add("UseChocolateyCmdLine",$True)
    }
    if ($GitHubInstall) {
        $InstallSSHAgentSplatParams.Add("GitHubInstall",$True)
    }
    if ($SkipWinCapabilityAttempt) {
        $InstallSSHAgentSplatParams.Add("SkipWinCapabilityAttempt",$True)
    }
    if ($Force) {
        $InstallSSHAgentSplatParams.Add("Force",$True)
    }

    try {
        $InstallSSHAgentResult = Install-SSHAgentService @InstallSSHAgentSplatParams
        if (!$InstallSSHAgentResult) {throw "The Install-SSHAgentService function failed!"}
    }
    catch {
        Write-Error $_
        Write-Host "Errors for the Install-SSHAgentService function are as follows:"
        Write-Error $($ISAErr | Out-String)
        $global:FunctionResult = "1"
        return
    }

    if ($ConfigureSSHDOnLocalHost) {
        $NewSSHDServerSplatParams = @{
            ErrorAction         = "SilentlyContinue"
            ErrorVariable       = "SSHDErr"
        }
        if ($RemoveHostPrivateKeys) {
            $NewSSHDServerSplatParams.Add("RemoveHostPrivateKeys",$True)
        }
        if ($DefaultShell) {
            $NewSSHDServerSplatParams.Add("DefaultShell",$DefaultShell)
        }
        if ($SkipWinCapabilityAttempt) {
            $NewSSHDServerSplatParams.Add("SkipWinCapabilityAttempt",$True)
        }
        
        try {
            $NewSSHDServerResult = New-SSHDServer @NewSSHDServerSplatParams
            if (!$NewSSHDServerResult) {throw "There was a problem with the New-SSHDServer function! Halting!"}
        }
        catch {
            Write-Error $_
            Write-Host "Errors for the New-SSHDServer function are as follows:"
            Write-Error $($SSHDErr | Out-String)
            $global:FunctionResult = "1"
            return
        }
    }

    # Update $env:Path to give the ssh.exe binary we just installed priority
    if ($GiveWinSSHBinariesPathPriority) {
        if ($($env:Path -split ";") -notcontains $OpenSSHWinPath) {
            if ($env:Path[-1] -eq ";") {
                $env:Path = "$OpenSSHWinPath;$env:Path"
            }
            else {
                $env:Path = "$OpenSSHWinPath;$env:Path"
            }
        }
    }
    else {
        if ($($env:Path -split ";") -notcontains $OpenSSHWinPath) {
            if ($env:Path[-1] -eq ";") {
                $env:Path = "$env:Path$OpenSSHWinPath"
            }
            else {
                $env:Path = "$env:Path;$OpenSSHWinPath"
            }
        }
    }

    $Output = [ordered]@{
        SSHAgentInstallInfo     = $InstallSSHAgentResult
    }
    if ($NewSSHDServerResult) {
        $Output.Add("SSHDServerInstallInfo",$NewSSHDServerResult)
    }

    if ($Output.Count -eq 1) {
        $InstallSSHAgentResult
    }
    else {
        [pscustomobject]$Output
    }
}






























# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUtxwcTdhdRxb9hs9AFaag4fXB
# cVqgggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFGPa/HfT+13DAhvn
# sh4R711nA4InMA0GCSqGSIb3DQEBAQUABIIBAHIiuSGzUAAb4GRNMKdeZGZpHNZr
# JQgxMB+A+CYvS/NzGXeMzv3dpX4mGcjQz5eDFI4v2OByHO3oUstq3pz6868aMvmz
# dlx0ldDtcsdD7Y3Raw1c1SMod4Kqcj/mLyMrcDqJ+Hf//yvlIxSgF/Yfhbb2NUEm
# pYPOuH0mBG0l3Uq/JfB7l8IL8Tri+muUqoDQ82L3brBzrLbha1cZfzjOFuxgzhcj
# 2F9lvU+aZfuUrQ1AxAAp0SnLSBazE3wLoEe909bBpZ77wPhaNk02YnoN72yd4rcT
# 50V8HOhQKii9aX6HdqYocbI5Uyj5R4wYDSH3R8hCVoh+aKk4zetZWtCbj+c=
# SIG # End signature block
