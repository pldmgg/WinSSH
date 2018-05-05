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
        $ForceCommandOptionLine = "ForceCommand powershell.exe -NoProfile"
    }
    if ($DefaultShell -eq "pwsh") {
        # Search for pwsh.exe where we expect it to be
        $PotentialPwshExes = Get-ChildItem "$env:ProgramFiles\Powershell" -Recurse -File -Filter "*pwsh.exe"
        if (!$PotentialPwshExes) {
            try {
                Update-PowerShellCore -Latest -DownloadDirectory "$HOME\Downloads" -ErrorAction Stop
            }
            catch {
                Write-Error $_
                $global:FunctionResult = "1"
                return
            }
        }
        $PotentialPwshExes = Get-ChildItem "$env:ProgramFiles\Powershell" -Recurse -File -Filter "*pwsh.exe"
        if (!$PotentialPwshExes) {
            Write-Error "Unable to find pwsh.exe! Halting!"
            $global:FunctionResult = "1"
            return
        }

        $LatestLocallyAvailablePwsh = [array]$($PotentialPwshExes.VersionInfo | Sort-Object -Property ProductVersion)[-1].FileName
        $LatestPwshParentDir = [System.IO.Path]::GetDirectoryName($LatestLocallyAvailablePwsh)

        if ($($env:Path -split ";") -notcontains $LatestPwshParentDir) {
            # TODO: Clean out older pwsh $env:Path entries if they exist...
            $env:Path = "$LatestPwshParentDir;$env:Path"
        }

        $ForceCommandOptionLine = "ForceCommand `"$LatestLocallyAvailablePwsh`" -NoProfile"
    }

    [System.Collections.ArrayList]$sshdContent = Get-Content $sshdConfigPath

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