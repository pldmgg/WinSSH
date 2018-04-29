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