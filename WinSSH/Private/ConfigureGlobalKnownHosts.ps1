# The below Configure-GlobalKnownHosts shouldn't be necesary with Public Key Authentication and
# dissemination of the CA public keys for both host and user signing
function Configure-GlobalKnownHosts {
    [CmdletBinding()]
    Param(
        # Each Remote Host key should be in format like:
        # 192.168.2.34 ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCyPF3ERQhbKKt+BwQ ...
        [Parameter(Mandatory=$False)]
        [string[]]$RemoteHostKeys
    )

    if (Test-Path "$env:ProgramData\ssh") {
        $sshdir = "$env:ProgramData\ssh"
    }
    elseif (Test-Path "$env:ProgramFiles\OpenSSH-Win64") {
        $sshdir = "$env:ProgramFiles\OpenSSH-Win64"
    }
    if (!$sshdir) {
        Write-Error "Unable to find either direcotry '$env:ProgramFiles\OpenSSH-Win64' or directory '$env:ProgramFiles\OpenSSH-Win64'! Halting!"
        $global:FunctionResult = "1"
        return
    }

    $SSHClientGlobalKnownHostsPath = "$sshdir\ssh_known_hosts"
    $sshClientGlobalConfigPath = "$sshdir\ssh_config"
    $GlobalKnownHostsOptionLine = "GlobalKnownHostsFile $SSHCLientGlobalKnownHostsPath"

    if (!(Test-Path "$sshdir\ssh_config")) {
        Set-Content -Value $GlobalKnownHostsOptionLine -Path $sshClientGlobalConfigPath
        #$SSHClientConfigContentChanged = $True
    }
    else {
        [System.Collections.ArrayList]$sshClientGlobalConfigContent = Get-Content $sshClientGlobalConfigPath

        # Determine if sshd_config already has the 'TrustedUserCAKeys' option active
        $ExistingGlobalKnownHostsFileOption = $sshClientGlobalConfigContent -match "GlobalKnownHostsFile" | Where-Object {$_ -notmatch "#"}

        if (!$ExistingGlobalKnownHostsFileOption) {
            try {
                Add-Content -Value $GlobalKnownHostsOptionLine -Path $sshClientGlobalConfigPath
                #$SSHClientConfigContentChanged = $True
                [System.Collections.ArrayList]$sshClientGlobalConfigContent = Get-Content $sshClientGlobalConfigPath
            }
            catch {
                Write-Error $_
                $global:FunctionResult = "1"
                return
            }
        }
        else {
            if ($ExistingGlobalKnownHostsFileOption -ne $GlobalKnownHostsOptionLine) {
                $UpdatedSSHClientConfig = $sshClientGlobalConfigContent -replace [regex]::Escape($ExistingGlobalKnownHostsFileOption),"$GlobalKnownHostsOptionLine"
    
                try {
                    Set-Content -Value $UpdatedSSHClientConfig -Path $sshClientGlobalConfigPath
                    #$SSHClientConfigContentChanged = $True
                    [System.Collections.ArrayList]$sshClientGlobalConfigContent = Get-Content $sshClientGlobalConfigPath
                }
                catch {
                    Write-Error $_
                    $global:FunctionResult = "1"
                    return
                }
            }
            else {
                Write-Warning "The specified 'GlobalKnownHostsFile' option is already active in the the ssh_config file. No changes made."
            }
        }
    }

    if (!(Test-Path $SSHClientGlobalKnownHostsPath)) {
        if ($RemoteHostKeys) {
            foreach ($PubKeyString in $RemoteHostKeys) {
                Add-Content -Value $PubKeyString.Trim() -Path $SSHClientGlobalKnownHostsPath
            }
        }
    }
    else {
        $CurrentGlobalKnownHostHeys = Get-Content $SSHClientGlobalKnownHostsPath

        if ($RemoteHostKeys) {
            foreach ($PubKeyString in $RemoteHostKeys) {
                if ($CurrentGlobalKnownHostHeys -notcontains $PubKeyString) {
                    Add-Content -Value $PubKeyString.Trim() -Path $SSHClientGlobalKnownHostsPath
                }
            }
        }
    }

    try {
        Restart-Service ssh-agent -Force -ErrorAction Stop
    }
    catch {
        Write-Error $_
        $global:FunctionResult = "1"
        return
    }
}