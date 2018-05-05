<#
    .SYNOPSIS
        Install OpenSSH-Win64. Optionally install the latest PowerShell Core Beta. Optionally create new SSH Key Pair.

    .DESCRIPTION
        See .SYNOPSIS

    .PARAMETER RemoveHostPrivateKeys
        OPTIONAL

        This parameter is a switch. Use it to remove the Host Private Keys after they are added to the ssh-agent during
        sshd setup/config. Default is NOT to remove the host private keys.

    .PARAMETER NewSSHKeyName
        OPTIONAL

        This parameter takes a string that represents the filename of the new SSH Key pair that you would like to create.
        This string is used in the filename of the private key file as well as the public key file (with the .pub extension).

    .PARAMETER NewSSHKeyPwd
        OPTIONAL

        This parameter takes a string that represents the password used to protect the new SSH Private Key.

    .PARAMETER NewSSHKeyPurpose
        OPTIONAL

        This parameter takes a string that represents the purpose of the new SSH Key Pair. It will be used in the
        "-C" (i.e. "comment") parameter of ssh-keygen.

    .PARAMETER SetupPowerShell6
        OPTIONAL

        This parameter is a switch. Use it to install the latest PowerShell 6 Beta.

        IMPORTANT NOTE: PowerShell 6 Beta is installed *alongside* existing PowerShell version.

    .EXAMPLE
        Install-WinSSH -NewSSHKeyName "testadmin-to-Debian8Jessie" -NewSSHKeyPurpose "testadmin-to-Debian8Jessie"

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