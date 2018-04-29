<#
    .SYNOPSIS
        The Install-SSHAgentService is, in large part, carved out of the 'install-sshd.ps1' script bundled with
        an OpenSSH-Win64 install.

        Original authors (github accounts):

        @manojampalam - authored initial script
        @friism - Fixed issue with invalid SDDL on Set-Acl
        @manojampalam - removed ntrights.exe dependency
        @bingbing8 - removed secedit.exe dependency

#>
function Install-SSHAgentService {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [switch]$UseChocolateyCmdLine,

        [Parameter(Mandatory=$False)]
        [switch]$UsePowerShellGet,

        [Parameter(Mandatory=$False)]
        [switch]$GitHubInstall,

        [Parameter(Mandatory=$False)]
        [switch]$NoUpdatePackageManagement = $True,

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

    if ($(Get-Module -ListAvailable).Name -notcontains "NTFSSecurity") {
        try {
            Install-Module -Name NTFSSecurity -ErrorAction SilentlyContinue -ErrorVariable NTFSSecInstallErr
            if ($NTFSSecInstallErr) {throw "Problem installing the NTFSSecurity Module!"}
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            return
        }
    }
    if ($(Get-Module).Name -notcontains "NTFSSecurity") {
        try {
            $NTFSSecImport = Import-Module NTFSSecurity -ErrorAction SilentlyContinue -PassThru
            if (!$NTFSSecImport) {throw "Problem importing module NTFSSecurity!"}
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            return
        }
    }

    if ([Environment]::OSVersion.Version -ge [version]"10.0.17063" -and !$SkipWinCapabilityAttempt) {
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

        $OpenSSHClientFeature = Get-WindowsCapability -Online | Where-Object {$_.Name -match 'OpenSSH\.Client'}

        if (!$OpenSSHClientFeature) {
            Write-Warning "Unable to find the OpenSSH.Client feature using the Get-WindowsCapability cmdlet!"
            $AddWindowsCapabilityFailure = $True
        }
        else {
            try {
                $SSHClientFeatureInstall = Add-WindowsCapability -Online -Name $OpenSSHClientFeature.Name -ErrorAction Stop
            }
            catch {
                Write-Warning "The Add-WindowsCapability cmdlet failed to add the $($OpenSSHClientFeature.Name)!"
                $AddWindowsCapabilityFailure = $True
            }
        }

        # Make sure the ssh-agent service exists
        try {
            $SSHDServiceCheck = Get-Service sshd -ErrorAction Stop
        }
        catch {
            $AddWindowsCapabilityFailure = $True
        }
    }

    if ([Environment]::OSVersion.Version -lt [version]"10.0.17063" -or $AddWindowsCapabilityFailure -or $SkipWinCapabilityAttempt -or $Force) {
        # BEGIN OpenSSH Program Installation #

        if (!$GitHubInstall) {
            $InstallProgramSplatParams = @{
                ProgramName         = "OpenSSH"
                CommandName         = "ssh.exe"
                ErrorAction         = "SilentlyContinue"
                ErrorVariable       = "IPErr"
            }
            if ($NoUpdatePackageManagement) {
                $InstallProgramSplatParams.Add("NoUpdatePackageManagement",$True)
            }
            if ($Force) {
                $InstallProgramSplatParams.Add("Force",$True)
            }
            if ($UsePowerShellGet) {
                $InstallProgramSplatParams.Add("UsePowerShellGet",$True)  
            }
            elseif ($UseChocolateyCmdLine) {
                $InstallProgramSplatParams.Add("UseChocolateyCmdLine",$True)
            }

            try {
                $OpenSSHInstallResults = InstallProgram @InstallProgramSplatParams
                if (!$OpenSSHInstallResults) {throw "There was a problem with the InstallProgram function! Halting!"}
            }
            catch {
                Write-Error $_
                Write-Host "Errors for the InstallProgram function are as follows:"
                Write-Error $($IPErr | Out-String)
                $global:FunctionResult = "1"
                return
            }
        }
        else {
            try {
                Write-Host "Finding latest version of OpenSSH for Windows..."
                $url = 'https://github.com/PowerShell/Win32-OpenSSH/releases/latest/'
                $request = [System.Net.WebRequest]::Create($url)
                $request.AllowAutoRedirect = $false
                $response = $request.GetResponse()
    
                $LatestOpenSSHWin = $($response.GetResponseHeader("Location") -split '/v')[-1]
            }
            catch {
                Write-Error "Unable to determine the latest version of OpenSSH using the Find-Package cmdlet! Try the Install-WinSSH function again using the -UsePowerShellGet switch. Halting!"
                $global:FunctionResult = "1"
                return
            }
    
            try {
                $SSHExePath = $(Get-ChildItem -Path $OpenSSHWinPath -File -Recurse -Filter "ssh.exe").FullName
            
                if (Test-Path $SSHExePath) {
                    $InstalledOpenSSHVer = [version]$(Get-Item $SSHExePath).VersionInfo.FileVersion
                }
    
                $NeedNewerVersion = $InstalledOpenSSHVer -lt [version]$($LatestOpenSSHWin -split "[a-zA-z]")[0]
                
                if ($Force) {
                    $NeedNewerVersion = $True
                }
            }
            catch {
                $NotInstalled = $True
            }
    
            $WinSSHFileNameSansExt = "OpenSSH-Win64"
            if ($NeedNewerVersion -or $NotInstalled) {
                # We need the NTFSSecurity Module
                if ($(Get-Module -ListAvailable).Name -contains "NTFSSecurity") {
                    if ($(Get-Module NTFSSecurity).Name -notcontains "NTFSSecurity") {
                        $null = Import-Module NTFSSecurity
                    }
                }
                else {    
                    try {
                        $null = Install-Module -Name NTFSSecurity
                        $null = Import-Module NTFSSecurity
                    }
                    catch {
                        Write-Error $_
                        $global:FunctionResult = "1"
                        return
                    }
                }
    
                try {
                    $WinOpenSSHDLLink = $([String]$response.GetResponseHeader("Location")).Replace('tag','download') + "/$WinSSHFileNameSansExt.zip"
                    Write-Host "Downloading OpenSSH-Win64 from $WinOpenSSHDLLink..."
                    Invoke-WebRequest -Uri $WinOpenSSHDLLink -OutFile "$HOME\Downloads\$WinSSHFileNameSansExt.zip"
                    # NOTE: OpenSSH-Win64.zip contains a folder OpenSSH-Win64, so no need to create one before extraction
                    $null = UnzipFile -PathToZip "$HOME\Downloads\$WinSSHFileNameSansExt.zip" -TargetDir "$HOME\Downloads"
                    if (Test-Path "$env:ProgramFiles\$WinSSHFileNameSansExt") {
                        Get-Service ssh-agent -ErrorAction SilentlyContinue | Stop-Service -ErrorAction SilentlyContinue
                        Get-Service sshd -ErrorAction SilentlyContinue | Stop-Service -ErrorAction SilentlyContinue
                        Get-Process -Name ssh-keygen -ErrorAction SilentlyContinue | Stop-Process -ErrorAction SilentlyContinue

                        Remove-Item "$env:ProgramFiles\$WinSSHFileNameSansExt" -Recurse -Force
                    }
                    Move-Item "$HOME\Downloads\$WinSSHFileNameSansExt" "$env:ProgramFiles\$WinSSHFileNameSansExt"
                    Enable-NTFSAccessInheritance -Path "$env:ProgramFiles\$WinSSHFileNameSansExt" -RemoveExplicitAccessRules
                }
                catch {
                    Write-Error $_
                    Write-Error "Installation of OpenSSH failed! Halting!"
                    $global:FunctionResult = "1"
                    return
                }
            }
            else {
                Write-Error "It appears that the newest version of $WinSSHFileNameSansExt is already installed! Halting!"
                $global:FunctionResult = "1"
                return
            }
        }

        # END OpenSSH Program Installation #

        $OpenSSHWinPath = "$env:ProgramFiles\OpenSSH-Win64"
        if (!$(Test-Path $OpenSSHWinPath)) {
            Write-Error "The path $OpenSSHWinPath does not exist! Halting!"
            $global:FunctionResult = "1"
            return
        }
        #$sshdpath = Join-Path $OpenSSHWinPath "sshd.exe"
        $sshagentpath = Join-Path $OpenSSHWinPath "ssh-agent.exe"
        $sshdir = "$env:ProgramData\ssh"
        $logsdir = Join-Path $sshdir "logs"

        try {
            if ([bool]$(Get-Service ssh-agent -ErrorAction SilentlyContinue)) {
                Write-Host "Recreating ssh-agent service..."
                Stop-Service ssh-agent
                sc.exe delete ssh-agent 1>$null
            }

            New-Service -Name ssh-agent -BinaryPathName "$sshagentpath" -Description "SSH Agent" -StartupType Automatic | Out-Null
            # pldmgg NOTE: I have no idea about the below...ask the original authors...
            cmd.exe /c 'sc.exe sdset ssh-agent D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)(A;;RP;;;AU)' 1>$null
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            return
        }

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
    }

    Write-Host -ForegroundColor Green "The ssh-agent service was successfully installed! Starting the service..."
    Start-Service ssh-agent -Passthru
}