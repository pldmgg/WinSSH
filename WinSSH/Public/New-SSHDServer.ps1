<#
    .SYNOPSIS
        This function installs and configures the SSHD server (sshd service) on the local host.

    .DESCRIPTION
        See .SYNOPSIS

    .NOTES

    .PARAMETER RemoveHostPrivateKeys
        This parameter is OPTIONAL.

        This parameter is a switch. Use it to add the Host Private Keys to the ssh-agent and remove
        the Private Key files frome the filesystem during sshd setup/config. Default is NOT to remove
        the Host Private Keys.

    .PARAMETER DefaultShell
        This parameter is OPTIONAL.

        This parameter takes a string that must be one of two values: "powershell","pwsh"

        If set to "powershell", when a Remote User connects to the local host via ssh, they will enter a
        Windows PowerShell 5.1 shell.

        If set to "pwsh", when a Remote User connects to the local host via ssh, the will enter a
        PowerShell Core 6 shell.

        If this parameter is NOT used, the Default shell will be cmd.exe.

    .PARAMETER SkipWinCapabilityAttempt
        This parameter is OPTIONAL.

        This parameter is a switch.
        
        In more recent versions of Windows (Spring 2018), OpenSSH Client and SSHD Server can be installed as
        Windows Features using the Dism Module 'Add-WindowsCapability' cmdlet. If you run this function on
        a more recent version of Windows, it will attempt to use 'Add-WindowsCapability' UNLESS you use
        this switch.

        As of May 2018, there are reliability issues with the 'Add-WindowsCapability' cmdlet.
        Using this switch is highly recommend in order to avoid using 'Add-WindowsCapability'.

    .EXAMPLE
        # Open an elevated PowerShell Session, import the module, and -

        PS C:\Users\zeroadmin> New-SSHDServer -DefaultShell powershell
        
#>
function New-SSHDServer {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [switch]$RemoveHostPrivateKeys,

        [Parameter(Mandatory=$False)]
        [ValidateSet("powershell","pwsh")]
        [string]$DefaultShell,

        [Parameter(Mandatory=$False)]
        [switch]$SkipWinCapabilityAttempt
    )

    #region >> Prep

    if (!$(GetElevation)) {
        Write-Verbose "You must run PowerShell as Administrator before using this function! Halting!"
        Write-Error "You must run PowerShell as Administrator before using this function! Halting!"
        $global:FunctionResult = "1"
        return
    }

    $tempfile = [IO.Path]::Combine([IO.Path]::GetTempPath(), [IO.Path]::GetRandomFileName())
    $OpenSSHWinPath = Join-Path $env:ProgramFiles "OpenSSH-Win64"
    $sshagentpath = Join-Path $OpenSSHWinPath "ssh-agent.exe"
    $sshdpath = Join-Path $OpenSSHWinPath "sshd.exe"
    $sshdir = Join-Path $env:ProgramData "ssh"
    $sshdConfigPath = Join-Path $sshdir "sshd_config"
    $logsdir = Join-Path $sshdir "logs"

    # Make sure $OpenSSHWinPath is part of $env:Path
    [System.Collections.Arraylist][array]$CurrentEnvPathArray = $env:Path -split ";" | Where-Object {![System.String]::IsNullOrWhiteSpace($_)}
    if ($CurrentEnvPathArray -notcontains $OpenSSHWinPath) {
        $CurrentEnvPathArray.Insert(0,$OpenSSHWinPath)
        $env:Path = $CurrentEnvPathArray -join ";"
    }

    # Make sure the dependency ssh-agent service is already installed
    if (![bool]$(Get-Service ssh-agent -ErrorAction SilentlyContinue)) {
        try {
            $InstallSSHAgentSplatParams = @{
                ErrorAction         = "SilentlyContinue"
                ErrorVariable       = "ISAErr"
            }
            if ($SkipWinCapabilityAttempt) {
                $InstallSSHAgentSplatParams.Add("SkipWinCapabilityAttempt",$True)
            }
            if ($Force) {
                $InstallSSHAgentSplatParams.Add("Force",$True)
            }
            
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
    }

    if (!$(Test-Path $OpenSSHWinPath)) {
        Write-Error "The path $OpenSSHWinPath does not exist! Halting!"
        $global:FunctionResult = "1"
        return
    }

    #endregion >> Prep

    #region >> Install the sshd Service

    if ([Environment]::OSVersion.Version -ge [version]"10.0.17063" -and !$SkipWinCapabilityAttempt) {
        try {
            # Import the Dism Module
            if ($(Get-Module).Name -notcontains "Dism") {
                try {
                    Import-Module Dism
                }
                catch {
                    # Using full path to Dism Module Manifest because sometimes there are issues with just 'Import-Module Dism'
                    $DismModuleManifestPaths = $(Get-Module -ListAvailable -Name Dism).Path

                    foreach ($MMPath in $DismModuleManifestPaths) {
                        try {
                            Import-Module $MMPath -ErrorAction Stop
                            break
                        }
                        catch {
                            Write-Verbose "Unable to import $MMPath..."
                        }
                    }
                }
            }
            if ($(Get-Module).Name -notcontains "Dism") {
                Write-Error "Problem importing the Dism PowerShell Module! Unable to proceed with Hyper-V install! Halting!"
                $global:FunctionResult = "1"
                return
            }

            $SSHDServerFeature = Get-WindowsCapability -Online | Where-Object {$_.Name -match 'OpenSSH\.Server'}

            if (!$SSHDServerFeature) {
                Write-Warning "Unable to find the OpenSSH.Server feature using the Get-WindowsCapability cmdlet!"
                $AddWindowsCapabilityFailure = $True
            }
            else {
                try {
                    $SSHDFeatureInstall = Add-WindowsCapability -Online -Name $SSHDServerFeature.Name -ErrorAction Stop
                }
                catch {
                    Write-Warning "The Add-WindowsCapability cmdlet failed to add the $($SSHDServerFeature.Name)!"
                    $AddWindowsCapabilityFailure = $True
                }
            }

            # Make sure the sshd service exists
            try {
                $SSHDServiceCheck = Get-Service sshd -ErrorAction Stop
            }
            catch {
                $AddWindowsCapabilityFailure = $True
            }
        }
        catch {
            Write-Warning "The Add-WindowsCapability cmdlet failed to add feature: $($SSHDServerFeature.Name) !"
            $AddWindowsCapabilityFailure = $True
        }
        
        if (!$AddWindowsCapabilityFailure) {
            try {
                # NOTE: $sshdir won't actually be created until you start the SSHD Service for the first time
                # Starting the service also creates all of the needed host keys.
                $SSHDServiceInfo = Get-Service sshd -ErrorAction Stop
                if ($SSHDServiceInfo.Status -ne "Running") {
                    $SSHDServiceInfo | Start-Service -ErrorAction Stop
                }

                if (Test-Path "$env:ProgramFiles\OpenSSH-Win64\sshd_config_default") {
                    # Copy sshd_config_default to $sshdir\sshd_config
                    $sshddefaultconfigpath = Join-Path $OpenSSHWinPath "sshd_config_default"
                    if (-not (Test-Path $sshdconfigpath -PathType Leaf)) {
                        $null = Copy-Item $sshddefaultconfigpath -Destination $sshdconfigpath -Force -ErrorAction Stop
                    }
                }
                else {
                    $SSHConfigUri = "https://raw.githubusercontent.com/PowerShell/Win32-OpenSSH/L1-Prod/contrib/win32/openssh/sshd_config"
                    Invoke-WebRequest -Uri $SSHConfigUri -OutFile $sshdConfigPath
                }

                $PubPrivKeyPairFiles = Get-ChildItem -Path $sshdir -File | Where-Object {$_.Name -match "ssh_host_rsa"}
                $PubHostKey = $PubPrivKeyPairFiles | Where-Object {$_.Extension -eq ".pub"}
                $PrivHostKey = $PubPrivKeyPairFiles | Where-Object {$_.Extension -ne ".pub"}
            }
            catch {
                Write-Error $_
                $global:FunctionResult = "1"
                return
            }
        }
    }
    
    if ([Environment]::OSVersion.Version -lt [version]"10.0.17063" -or $AddWindowsCapabilityFailure -or $SkipWinCapabilityAttempt) {
        if (!$(Test-Path $sshdpath)) {
            Write-Error "The path $sshdpath does not exist! Halting!"
            $global:FunctionResult = "1"
            return
        }

        # NOTE: Starting the sshd Service should create all below content and set appropriate permissions
        <#
        try {
            # Create the C:\ProgramData\ssh folder and set its permissions
            if (-not (Test-Path $sshdir -PathType Container)) {
                $null = New-Item $sshdir -ItemType Directory -Force -ErrorAction Stop
            }
            # Set Permissions
            $SecurityDescriptor = Get-NTFSSecurityDescriptor -Path $sshdir
            $SecurityDescriptor | Disable-NTFSAccessInheritance -RemoveInheritedAccessRules
            $SecurityDescriptor | Clear-NTFSAccess
            $SecurityDescriptor | Add-NTFSAccess -Account "NT AUTHORITY\Authenticated Users" -AccessRights "ReadAndExecute, Synchronize" -AppliesTo ThisFolderSubfoldersAndFiles
            $SecurityDescriptor | Add-NTFSAccess -Account SYSTEM -AccessRights FullControl -AppliesTo ThisFolderSubfoldersAndFiles
            $SecurityDescriptor | Add-NTFSAccess -Account Administrators -AccessRights FullControl -AppliesTo ThisFolderSubfoldersAndFiles
            $SecurityDescriptor | Set-NTFSSecurityDescriptor
            Set-NTFSOwner -Path $sshdir -Account Administrators
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            return
        }

        try {
            # Create logs folder and set its permissions
            if (-not (Test-Path $logsdir -PathType Container)) {
                $null = New-Item $logsdir -ItemType Directory -Force -ErrorAction Stop
            }
            # Set Permissions
            $SecurityDescriptor = Get-NTFSSecurityDescriptor -Path $logsdir
            $SecurityDescriptor | Disable-NTFSAccessInheritance -RemoveInheritedAccessRules
            $SecurityDescriptor | Clear-NTFSAccess
            #$SecurityDescriptor | Add-NTFSAccess -Account "NT AUTHORITY\Authenticated Users" -AccessRights "ReadAndExecute, Synchronize" -AppliesTo ThisFolderSubfoldersAndFiles
            $SecurityDescriptor | Add-NTFSAccess -Account SYSTEM -AccessRights FullControl -AppliesTo ThisFolderSubfoldersAndFiles
            $SecurityDescriptor | Add-NTFSAccess -Account Administrators -AccessRights FullControl -AppliesTo ThisFolderSubfoldersAndFiles
            $SecurityDescriptor | Set-NTFSSecurityDescriptor
            Set-NTFSOwner -Path $logsdir -Account Administrators
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            return
        }

        try {
            # Copy sshd_config_default to $sshdir\sshd_config
            $sshdConfigPath = Join-Path $sshdir "sshd_config"
            $sshddefaultconfigpath = Join-Path $OpenSSHWinPath "sshd_config_default"
            if (-not (Test-Path $sshdconfigpath -PathType Leaf)) {
                $null = Copy-Item $sshddefaultconfigpath -Destination $sshdconfigpath -Force -ErrorAction Stop
            }
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            return
        }
        #>

        try {
            if (Get-Service sshd -ErrorAction SilentlyContinue) {
               Stop-Service sshd
               $null = sc.exe delete sshd
            }
    
            $sshdDesc = "SSH protocol based service to provide secure encrypted communications between two untrusted hosts over an insecure network."
            $null = New-Service -Name sshd -DisplayName "OpenSSH SSH Server" -BinaryPathName $sshdpath -Description $sshdDesc -StartupType Automatic
            $null = sc.exe privs sshd SeAssignPrimaryTokenPrivilege/SeTcbPrivilege/SeBackupPrivilege/SeRestorePrivilege/SeImpersonatePrivilege
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            return
        }

        $SSHDServiceInfo = Get-Service sshd -ErrorAction Stop
        if ($SSHDServiceInfo.Status -ne "Running") {
            $SSHDServiceInfo | Start-Service -ErrorAction Stop
        }
        Start-Sleep -Seconds 5
        if ($(Get-Service sshd).Status -ne "Running") {
            Write-Error "The sshd service did not start succesfully (within 5 seconds) after initial install! Please check your sshd_config configuration. Halting!"
            $global:FunctionResult = "1"
            return
        }

        # NOTE: Starting the sshd Service should create the host keys, so we don't need to do it here
        <#
        # Setup Host Keys
        $SSHKeyGenProcessInfo = New-Object System.Diagnostics.ProcessStartInfo
        $SSHKeyGenProcessInfo.WorkingDirectory = $sshdir
        $SSHKeyGenProcessInfo.FileName = "ssh-keygen.exe"
        $SSHKeyGenProcessInfo.RedirectStandardError = $true
        $SSHKeyGenProcessInfo.RedirectStandardOutput = $true
        $SSHKeyGenProcessInfo.UseShellExecute = $false
        $SSHKeyGenProcessInfo.Arguments = "-A"
        $SSHKeyGenProcess = New-Object System.Diagnostics.Process
        $SSHKeyGenProcess.StartInfo = $SSHKeyGenProcessInfo
        $SSHKeyGenProcess.Start() | Out-Null
        $SSHKeyGenProcess.WaitForExit()
        $SSHKeyGenStdout = $SSHKeyGenProcess.StandardOutput.ReadToEnd()
        $SSHKeyGenStderr = $SSHKeyGenProcess.StandardError.ReadToEnd()
        $SSHKeyGenAllOutput = $SSHKeyGenStdout + $SSHKeyGenStderr

        if ($SSHKeyGenAllOutput -match "fail|error") {
            Write-Error $SSHKeyGenAllOutput
            Write-Error "The 'ssh-keygen -A' command failed! Halting!"
            $global:FunctionResult = "1"
            return
        }
        #>
        
        # Add the ssh_host_rsa private key to the ssh-agent
        $PubPrivKeyPairFiles = Get-ChildItem -Path $sshdir -File | Where-Object {$_.Name -match "ssh_host_rsa"}
        $PubHostKey = $PubPrivKeyPairFiles | Where-Object {$_.Extension -eq ".pub"}
        $PrivHostKey = $PubPrivKeyPairFiles | Where-Object {$_.Extension -ne ".pub"}

        if ($(Get-Service ssh-agent).Status -ne "Running") {
            Start-Service ssh-agent
            Start-Sleep -Seconds 5
        }
        if ($(Get-Service "ssh-agent").Status -ne "Running") {
            Write-Error "The ssh-agent service did not start succesfully (within 5 seconds)! Please check your config! Halting!"
            $global:FunctionResult = "1"
            return
        }

        if (![bool]$(Get-Command ssh-add -ErrorAction SilentlyContinue)) {
            Write-Error 'Unable to find ssh-add.exe! Is it part of your $env:Path? Halting!'
            $global:FunctionResult = "1"
            return
        }
        
        $SSHAddProcessInfo = New-Object System.Diagnostics.ProcessStartInfo
        $SSHAddProcessInfo.WorkingDirectory = $sshdir
        $SSHAddProcessInfo.FileName = "ssh-add.exe"
        $SSHAddProcessInfo.RedirectStandardError = $true
        $SSHAddProcessInfo.RedirectStandardOutput = $true
        $SSHAddProcessInfo.UseShellExecute = $false
        $SSHAddProcessInfo.Arguments = "$($PrivHostKey.FullName)"
        $SSHAddProcess = New-Object System.Diagnostics.Process
        $SSHAddProcess.StartInfo = $SSHAddProcessInfo
        $SSHAddProcess.Start() | Out-Null
        $SSHAddProcess.WaitForExit()
        $SSHAddStdout = $SSHAddProcess.StandardOutput.ReadToEnd()
        $SSHAddStderr = $SSHAddProcess.StandardError.ReadToEnd()
        $SSHAddAllOutput = $SSHAddStdout + $SSHAddStderr
        
        if ($SSHAddAllOutput -match "fail|error") {
            Write-Error $SSHAddAllOutput
            Write-Error "The 'ssh-add $($PrivKey.FullName)' command failed!"
        }
        else {
            if ($RemoveHostPrivateKeys) {
                Remove-Item $PrivKey
            }
        }

        # EDIT: The below shouldn't be necessary...
        # IMPORTANT: It is important that File Permissions are "Fixed" at the end (as opposed to earlier in this function),
        # otherwise previous steps break
        <#
        if (!$(Test-Path "$OpenSSHWinPath\FixHostFilePermissions.ps1")) {
            Write-Error "The script $OpenSSHWinPath\FixHostFilePermissions.ps1 cannot be found! Permissions in the $OpenSSHWinPath directory need to be fixed before the sshd service will start successfully! Halting!"
            $global:FunctionResult = "1"
            return
        }

        try {
            & "$OpenSSHWinPath\FixHostFilePermissions.ps1" -Confirm:$false
        }
        catch {
            Write-Error "The script $OpenSSHWinPath\FixHostFilePermissions.ps1 failed! Permissions in the $OpenSSHWinPath directory need to be fixed before the sshd service will start successfully! Halting!"
            $global:FunctionResult = "1"
            return
        }
        #>
    }

    # Set the default shell
    if ($DefaultShell -eq "powershell" -or !$DefaultShell) {
        $null = Set-DefaultShell -DefaultShell "powershell"
    }
    else {
        $null = Set-DefaultShell -DefaultShell "pwsh"
    }

    #endregion >> Install the sshd Service


    ##### BEGIN Main Body #####

    # Make sure port 22 is open
    if (!$(TestPort -Port 22).Open) {
        # See if there's an existing rule regarding locahost TCP port 22, if so change it to allow port 22, if not, make a new rule
        $Existing22RuleCheck = Get-NetFirewallPortFilter -Protocol TCP | Where-Object {$_.LocalPort -eq 22}
        if ($Existing22RuleCheck -ne $null) {
            $Existing22Rule =  Get-NetFirewallRule -AssociatedNetFirewallPortFilter $Existing22RuleCheck | Where-Object {$_.Direction -eq "Inbound"}
            if ($Existing22Rule -ne $null) {
                $null = Set-NetFirewallRule -InputObject $Existing22Rule -Enabled True -Action Allow
            }
            else {
                $ExistingRuleFound = $False
            }
        }
        if ($Existing22RuleCheck -eq $null -or $ExistingRuleFound -eq $False) {
            $null = New-NetFirewallRule -Action Allow -Direction Inbound -Name ssh -DisplayName ssh -Enabled True -LocalPort 22 -Protocol TCP
        }
    }

    Restart-Service sshd
    Start-Sleep -Seconds 5

    if ($(Get-Service sshd).Status -ne "Running") {
        Write-Error "The sshd service did not start succesfully (within 5 seconds)! Please check your sshd_config configuration. Halting!"
        $global:FunctionResult = "1"
        return
    }

    if ($DefaultShell) {
        # For some reason, the 'ForceCommand' option is not picked up the first time the sshd service is started
        # so restart sshd service
        Restart-Service sshd
        Start-Sleep -Seconds 5
    }

    if ($(Get-Service sshd).Status -ne "Running") {
        Write-Error "The sshd service did not start succesfully (within 5 seconds)! Please check your sshd_config configuration. Halting!"
        $global:FunctionResult = "1"
        return
    }
    else {
        Write-Host "The sshd service was successfully installed and started!" -ForegroundColor Green
    }

    [pscustomobject]@{
        SSHDServiceStatus       = $(Get-Service sshd).Status
        SSHAgentServiceStatus   = $(Get-Service ssh-agent).Status
        RSAHostPublicKey        = $PubHostKey
        RSAHostPrivateKey       = $PrivHostKey
    }
}

# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUM4WR7J/JDv8b8SXz9NJT0ero
# TrGgggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFMzYGv9ZHWh1e1pe
# ptPq6js/n2LcMA0GCSqGSIb3DQEBAQUABIIBAFUCM75YyXpvXkIYtexlQhVOYSrS
# 2vQsxE2Is0sF/J84cyBzXq/riS3VUAw1EaoFxzF7jjCEOcFK+EHNxSBRDApzwV0C
# vLAdtd/GS/Xc5H8lxyjzuo/iAnpvKfUINVVxJJEfZbFzd+uVuzDFP/F+kLn8/iEj
# KGFO4e7lilrVPBy73ctP3a5UAhrQylFhNS/2+pW1ZSnVgOWzdsHaUWzto+id+0ja
# yLQ5pArtHKuyjImlb6krRgN6kah3YSDb7PIxysElASuZMzQa+3te8fIiWlWsXv+7
# gnZpN8k2ylCblo7e7n9wjnMTNpEB8tRVWTmiPhCg196Sck6pLAam016qpPs=
# SIG # End signature block
