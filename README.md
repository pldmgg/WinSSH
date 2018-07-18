[![Build status](https://ci.appveyor.com/api/projects/status/github/pldmgg/=master&svg=true)](https://ci.appveyor.com/project/pldmgg/winssh/branch/master)


# WinSSH
Install OpenSSH-Win64, optionally install ssh-agent, sshd. Also includes functions to help configure sshd_config, fix permissions, and check keys.

## Getting Started

```powershell
# One time setup
    # Download the repository
    # Unblock the zip
    # Extract the WinSSH folder to a module path (e.g. $env:USERPROFILE\Documents\WindowsPowerShell\Modules\)
# Or, with PowerShell 5 or later or PowerShellGet:
    Install-Module WinSSH

# Import the module.
    Import-Module WinSSH    # Alternatively, Import-Module <PathToModuleFolder>

# Get commands in the module
    Get-Command -Module WinSSH

# Get help
    Get-Help <WinSSH Function> -Full
    Get-Help about_WinSSH
```

## Examples

### Scenario 1: Install ssh-agent and sshd Services and Set PowerShell Core as the Default Shell

NOTE: By using `-DefaultShell pwsh`, if PowerShell Core (pwsh) is not already installed on the localhost, it will be installed along with openssh.

```powershell
PS C:\Users\zeroadmin> $InstallWinSSHResult = Install-WinSSH -GiveWinSSHBinariesPathPriority -ConfigureSSHDOnLocalHost -DefaultShell pwsh

PS C:\Users\zeroadmin> $InstallWinSSHResult

SSHAgentInstallInfo SSHDServerInstallInfo
------------------- ---------------------
ssh-agent           @{SSHDServiceStatus=Running; SSHAgentServiceStatus=Running; RSAHostPublicKey=ssh_host_rsa_key.pub; RSAHostPrivateKey=ssh_host_rsa_key}
```

## Notes

* PSGallery: https://www.powershellgallery.com/packages/WinSSH
