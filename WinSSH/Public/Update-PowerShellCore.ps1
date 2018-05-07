<#
    .SYNOPSIS
        This function installs or updates PowerShell Core on the local host.

    .DESCRIPTION
        See .SYNOPSIS

    .NOTES

    .PARAMETER DownloadDirectory
        This parameter is MANDATORY.

        This parameter takes a string that represents a full path to a directory where the latest PowerShell
        Core release will be downloaded to.

    .PARAMETER UsePackageManagement
        This parameter is OPTIONAL.

        This parameter is a switch. If used, this function will use the respective Operating System's
        Package Management system in order to install the latest PowerShell Core.
        
    .PARAMETER OS
        This parameter is OPTIONAL.

        This parameter takes a string that must be one of the following values:
        "win", "macos", "linux", "ubuntu", "debian", "centos", "redhat"

        This parameter should only be used if you are downloading a PowerShell Core release that is NOT
        meant for the Operating System that you are currently on.

    .PARAMETER ReleaseVersion
        This parameter is OPTIONAL. This parameter should only be used if you do NOT want the latest version.

        This parameter takes a string that represents a PowerShell Core Release version.
        Example: 6.1.0

    .PARAMETER Channel
        This parameter is OPTIONAL. This parameter should only be used if you do NOT want the latest version.

        This parameter takes a string that can be one of 4 values:
        "beta", "rc", "stable", "preview"
    
    .PARAMETER Iteration
        This parameter is OPTIONAL. This parameter should only be used if you do NOT want the latest version.

        This parameter takes an integer. For example, in the release "powershell-6.1.0-preview.2-1.rhel.7.x86_64.rpm",
        iteration is 2.

    .PARAMETER Latest
        This parameter is OPTIONAL.

        This parameter is a switch. It is used by default. Using this switch installs the latest release of PowerShell
        Core.

    .EXAMPLE
        # Open an elevated PowerShell Session, import the module, and -

        PS C:\Users\zeroadmin> Update-PowerShellCore -DownloadDirectory "$HOME\Downloads" -Latest
        
#>
function Update-PowerShellCore {
    [CmdletBinding(DefaultParameterSetName='PackageManagement')]
    Param(
        [Parameter(
            Mandatory=$True,
            ParameterSetName='DirectDownload'
        )]
        $DownloadDirectory,

        [Parameter(
            Mandatory=$False,
            ParameterSetName='PackageManagement'
        )]
        $UsePackageManagement,

        [Parameter(
            Mandatory=$False,
            ParameterSetName='DirectDownload'
        )]
        [ValidateSet("win", "macos", "linux", "ubuntu", "debian", "centos", "redhat")]
        $OS,

        [Parameter(Mandatory=$False)]
        $ReleaseVersion,

        [Parameter(Mandatory=$False)]
        #[ValidateSet("beta", "rc", "stable", "preview")]
        $Channel,

        [Parameter(Mandatory=$False)]
        [int]$Iteration,

        [Parameter(Mandatory=$False)]
        [switch]$Latest = $True
        
    )

    ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####

    if (!$(GetElevation)) {
        Write-Error "Please run PowerShell with elevated privileges and try again. Halting!"
        $global:FunctionResult = "1"
        return
    }

    if (!$([Environment]::Is64BitProcess)) {
        Write-Error "You are currently running the 32-bit version of PowerShell. Please run the 64-bit version found under C:\Windows\SysWOW64\WindowsPowerShell\v1.0 and try again. Halting!"
        $global:FunctionResult = "1"
        return
    }

    if ($Channel) {
        if ($Channel -notmatch "beta|rc|stable") {
            Write-Warning "The value provided for the -Channel parameter must be eitehr 'beta', 'rc', or 'stable'"
            $Channel = Read-Host -Prompt "Please enter the Channel you would like to use [beta/rc/stable]"
            while ($Channel -notmatch "beta|rc|stable") {
                Write-Warning "The value provided for the -Channel parameter must be eitehr 'beta', 'rc', or 'stable'"
                $Channel = Read-Host -Prompt "Please enter the Channel you would like to use [beta/rc/stable]"
            }
        }
    }

    if (!$DownloadDirectory -and $UsePackageManagement) {
        if ($UsePackageManagement -notmatch "Yes|yes|Y|y|true|No|no|N|n|false") {
            Write-Error "Valid values for the -UsePackageManagement parameter are Yes|yes|Y|y|true|No|no|N|n|false . Halting!"
            $global:FunctionResult = "1"
            return
        }
        if ($UsePackageManagement -match "Yes|yes|Y|y|true") {
            $UsePackageManagement = $true
        }
        if ($UsePackageManagement -match "No|no|N|n|false") {
            $UsePackageManagement = $false
        }
    }

    if (!$DownloadDirectory -and $UsePackageManagement -eq $null) {
        $UsePackageManagement = Read-Host -Prompt "Would you like to install PowerShell Core via the appropriate Package Management system for this Operating System? [Yes\No]"
        if ($UsePackageManagement -notmatch "Yes|Y|yes|y|No|N|no|n") {
            Write-Warning "Valid responses are 'Yes' or 'No'"
            $UsePackageManagement = Read-Host -Prompt "Would you like to install PowerShell Core via the appropriate Package Managmement system for the respective Operating System? [Yes\No]"
            if ($UsePackageManagement -notmatch "Yes|Y|yes|y|No|N|no|n") {
                if (! $(Test-Path $SamplePath)) {
                    Write-Error "Invalid response! Halting!"
                    $global:FunctionResult = "1"
                    return
                }
            }
        }
        if ($UsePackageManagement -match "Yes|Y|yes|y") {
            $UsePackageManagement = $true
        }
        else {
            $UsePackageManagement = $false
        }
    }

    if ($($PSBoundParameters.Keys -contains "UsePackageManagement" -and $UsePackageManagement -eq $false -and !$DownloadDirectory) -or
    $(!$DownloadDirectory -and $UsePackageManagement -eq $false)) {
        $DownloadDirectory = Read-Host -Prompt "Please enter the full path to the directory where the PowerShell Core installation package will be downloaded"
    }

    if ($DownloadDirectory) {
        # Check to see if DownloadDirectory exists
        if (!$(Test-Path $DownloadDirectory)) {
            Write-Error "The path $DownloadDirectory was not found! Halting!"
            $global:FunctionResult = "1"
            return
        }
    }

    if ($PSVersionTable.Platform -eq "Unix" -and $PSVersionTable.OS -notmatch "Darwin") {
        try {
            $CheckOS = $($(hostnamectl | grep "Operating System") -replace "Operating System:","").Trim()
        }
        catch {
            $CheckOS = $PSVersionTable.OS
        }
    }
    if (!$OS) {
        if ($PSVersionTable.PSEdition -eq "Desktop" -or $PSVersionTable.OS -match "Windows" -or $PSVersionTable.PSVersion.Major -le 5) {
            $OS = "win"
        }
        if ($PSVersionTable.OS -match "Darwin") {
            $OS = "macos"
        }
        if ($PSVersionTable.Platform -eq "Unix" -and $PSVersionTable.OS -notmatch "Darwin") {
            switch ($CheckOS)
            {
                {$_ -match "Ubuntu 17.04|17.04.[0-9]+-Ubuntu"} {
                    $OS = "ubuntu"
                    $UbuntuVersion = "17.04"
                }

                {$_ -match "Ubuntu 16.04|16.04.[0-9]+-Ubuntu"} {
                    $OS = "ubuntu"
                    $UbuntuVersion = "16.04"
                }

                {$_ -match "Ubuntu 14.04|14.04.[0-9]+-Ubuntu"} {
                    $OS = "ubuntu"
                    $UbuntuVersion = "14.04"
                }

                {$_ -match 'Debian GNU/Linux 8|\+deb8'} {
                    $OS = "debian"
                    $DebianVersion = "8"
                }

                {$_ -match 'Debian GNU/Linux 9|\+deb9'} {
                    $OS = "debian"
                    $DebianVersion = "9"
                }

                {$_ -match 'CentOS'} {
                    $OS = "centos"
                }

                {$_ -match 'RedHat'} {
                    $OS = "redhat"
                }

                Default {
                    $OS = "linux"
                }
            }
        }
    }
    else {
        switch ($OS)
        {
            {$CheckOS -match "Ubuntu 17.04|17.04.[0-9]+-Ubuntu" -and $_ -eq "ubuntu"} {
                $UbuntuVersion = "17.04"
            }

            {$CheckOS -match "Ubuntu 16.04|16.04.[0-9]+-Ubuntu" -and $_ -eq "ubuntu"} {
                $UbuntuVersion = "16.04"
            }

            {$CheckOS -match "Ubuntu 14.04|14.04.[0-9]+-Ubuntu" -and $_ -eq "ubuntu"} {
                $UbuntuVersion = "14.04"
            }

            {$_ -match 'Debian GNU/Linux 8|\+deb8'} {
                $DebianVersion = "8"
            }

            {$_ -match 'Debian GNU/Linux 9|\+deb9'} {
                $DebianVersion = "9"
            }
        }
    }

    if ($PSBoundParameters.Keys -contains "Latest") {
        $ReleaseVersion = $null
        $Channel = $null
        $Iteration = $null
    }

    if ($PSBoundParameters.Keys.Count -eq 0 -or
    $($PSBoundParameters.Keys.Count -eq 1 -and $PSBoundParameters.Keys -contains "DownloadDirectory") -or
    $($PSBoundParameters.Keys.Count -eq 1 -and $PSBoundParameters.Keys -contains "UsePackageManagement")) {
        $Latest = $true
    }

    try {
        Write-Host "Checking https://github.com/powershell/powershell/releases to determine available releases ..."
        $PowerShellCoreVersionPrep = Invoke-WebRequest -Uri "https://github.com/powershell/powershell/releases"
    }
    catch {
        Write-Error $_
        $global:FunctionResult = "1"
        return
    }

    # Determine $ReleaseVersion, $Channel, and/or $Iteration
    if (!$Latest) {
        $PSCoreFullVersionArray = $($PowerShellCoreVersionPrep.Links | Where-Object {
            $_.href -like "*tag/*" -and
            $_.href -notlike "https*"
        }).href | foreach {
            $_ -replace "/PowerShell/PowerShell/releases/tag/v",""
        }

        [System.Collections.ArrayList]$PossibleReleaseVersions = [array]$($($PSCoreFullVersionArray | foreach {$($_ -split "-")[0]}) | Sort-Object | Get-Unique)
        [System.Collections.ArrayList]$PossibleChannels = [array]$($PSCoreFullVersionArray | foreach {$($_ | Select-String -Pattern "[a-zA-Z]+").Matches.Value} | Sort-Object | Get-Unique)
        [System.Collections.ArrayList]$PossibleIterations = [array]$($PSCoreFullVersionArray | foreach {
            try {[int]$($_ -split "\.")[-1]} catch {}
        } | Sort-Object | Get-Unique)


        if ($ReleaseVersion) {
            if (!$($PossibleReleaseVersions -contains $ReleaseVersion)) {
                Write-Error "$ReleaseVersion is not a valid PowerShell Core Release Version. Valid versions are:`n$PossibleReleaseVersions`nHalting!"
                $global:FunctionResult = "1"
                return
            }
        }
        if ($Channel) {
            if (!$($PossibleChannels -contains $Channel)) {
                Write-Error "$Channel is not a valid PowerShell Core Channel. Valid versions are:`n$PossibleChannels`nHalting!"
                $global:FunctionResult = "1"
                return
            }
        }
        if ($Iteration) {
            if (!$($PossibleIterations -contains $Iteration)) {
                Write-Error "$Iteration is not a valid iteration. Valid versions are:`n$PossibleIterations`nHalting!"
                $global:FunctionResult = "1"
                return
            }
        }

        [System.Collections.ArrayList]$PSCoreOptions = @()        
        foreach ($PSCoreFullVerString in $PSCoreFullVersionArray) {
            $PSCoreOption = [pscustomobject][ordered]@{
                ReleaseVersion   = $($PSCoreFullVerString -split "-")[0]
                Channel          = $($PSCoreFullVerString | Select-String -Pattern "[a-zA-Z]+").Matches.Value
                Iteration        = try {[int]$($PSCoreFullVerString -split "\.")[-1]} catch {$null}
            }

            $null = $PSCoreOptions.Add($PSCoreOption)
        }

        # Find a matching $PSCoreOption
        $PotentialOptions = $PSCoreOptions
        if (!$ReleaseVersion) {
            $LatestReleaseVersion = $($PotentialOptions.ReleaseVersion | foreach {[version]$_} | Sort-Object)[-1].ToString()
            $ReleaseVersion = $LatestReleaseVersion
        }
        $PotentialOptions = $PotentialOptions | Where-Object {$_.ReleaseVersion -eq $ReleaseVersion}

        if (!$Channel) {
            if ($PotentialOptions.Channel -contains "stable") {
                $Channel = "stable"
            }
            elseif ($PotentialOptions.Channel -contains "rc") {
                $Channel = "rc"
            }
            elseif ($PotentialOptions.Channel -contains "beta") {
                $Channel = "beta"
            }
        }
        $PotentialOptions = $PotentialOptions | Where-Object {$_.Channel -eq $Channel}

        if (!$Iteration) {
            if ($PotentialOptions.Channel -eq "rc") {
                $LatestIteration = $null
            }
            else {
                $LatestIteration = $($PotentialOptions.Iteration | foreach {[int]$_} | Sort-Object)[-1]
            }
            $Iteration = $LatestIteration
        }
        $PotentialOptions = $PotentialOptions | Where-Object {$_.Iteration -eq $Iteration}

        if ($PotentialOptions.Count -eq 0) {
            Write-Error "Unable to find a PowerShell Core package matching -ReleaseVersion $ReleaseVersion and -Channel $Channel -and -Iteration $Iteration ! Halting!"
            $global:FunctionResult = "1"
            return
        }
    }

    switch ($OS)
    {
        'win' {
            if ($Latest) {
                $hrefMatch = "*$OS*x64.msi"
            }
            else {
                $hrefMatch = "*$ReleaseVersion*$Channel*$Iteration*$OS*x64.msi"
            }
        }
    
        'macos' {
            if ($Latest){
                $hrefMatch = "*$OS*x64.pkg"
            }
            else {
                $hrefMatch = "*$ReleaseVersion*$Channel*$Iteration*$OS*x64.pkg"
            }
        }

        'linux' {
            if ($Latest) {
                $hrefMatch = "*x86_64.AppImage"
            }
            else {
                $hrefMatch = "*$ReleaseVersion*$Channel*$Iteration*x86_64.AppImage"
            }
        }

        'ubuntu' {
            if ($Latest) {
                $hrefMatch = "*$OS*$UbuntuVersion*64.deb"
            }
            else {
                $hrefMatch = "*$ReleaseVersion*$Channel*$Iteration*$OS*$UbuntuVersion*64.deb"
            }
        }

        'debian' {
            if (!$Latest -and $ReleaseVersion -eq "6.0.0" -and $Channel -match "beta" -and $Iteration -le 7) {
                $DebianVersion = "14.04"
                $OS = "ubuntu"
            }
            if ($Latest) {
                $hrefMatch = "*$OS*$DebianVersion*64.deb"
            }
            else {
                $hrefMatch = "*$ReleaseVersion*$Channel.$Iteration*$OS*$DebianVersion*64.deb"
            }
        }

        {$_ -match "centos|redhat"} {
            if ($Latest) {
                $hrefMatch = "*x86_64.rpm"
            }
            else {
                $hrefMatch = "*$ReleaseVersion*$Channel.$Iteration*x86_64.rpm"
            }
        }
    }


    ##### END Variable/Parameter Transforms and PreRun Prep #####

    ##### BEGIN Main Body #####
    try {
        $PowerShellCoreVersionhref = $($PowerShellCoreVersionPrep.Links | Where-Object {$_.href -like $hrefMatch})[0].href
        $PowerShellCoreVersionURL = "https://github.com/" + $PowerShellCoreVersionhref
        $DownloadFileName = $PowerShellCoreVersionURL | Split-Path -Leaf
        $DownloadFileNameSansExt = [System.IO.Path]::GetFileNameWithoutExtension($DownloadFileName)
        if ($DownloadDirectory) {
            $DownloadDirectory = GetNativePath -PathAsStringArray @($DownloadDirectory, $DownloadFileNameSansExt)
            $DownloadPath = GetNativePath -PathAsStringArray @($DownloadDirectory, $DownloadFileName)
        }
        $PSFullVersion = $($DownloadFileNameSansExt | Select-String -Pattern "[0-9]{1,2}\.[0-9]{1,2}\.[0-9]{1,2}-.*?win").Matches.Value -replace "-win",""
        $PSRelease = $($PSFullVersion -split "-")[0]
        $PSChannel = $($PSFullVersion | Select-String -Pattern "[a-zA-Z]+").Matches.Value
        $PSIteration = $($($PSFullVersion -split "-") | Where-Object {$_ -match "[a-zA-Z].+[\d]"} | Select-String -Pattern "[\d]").Matches.Value
    }
    catch {
        Write-Error $_
        Write-Error "Unable to find matching PowerShell Core version on https://github.com/powershell/powershell/releases"
        $global:FunctionResult = "1"
        return
    }

    switch ($OS)
    {
        'win' {
            if ($PSVersionTable.PSEdition -eq "Desktop" -or $PSVersionTable.Platform -eq "Win32NT" -or $PSVersionTable.PSVersion.Major -le 5) {
                [System.Collections.ArrayList]$CurrentInstalledPSVersions = [array]$(Get-Item "C:\Program Files\PowerShell\*\powershell.exe" -ErrorAction SilentlyContinue).Directory.Name
                
                if (!$($CurrentInstalledPSVersions -contains $PSFullVersion)) {
                    if (!$UsePackageManagement) {
                        Write-Host "Downloading PowerShell Core for $OS version $PSFullVersion to $DownloadPath ..."
                        
                        if (!$(Test-Path $DownloadDirectory)) {
                            $null = New-Item -ItemType Directory -Path $DownloadDirectory
                        }
                        
                        try {
                            Invoke-WebRequest -Uri $PowerShellCoreVersionURL -OutFile $DownloadPath
                        }
                        catch {
                            Write-Error $_
                            $global:FunctionResult = "1"
                            return
                        }
                        
                        if ($CurrentInstalledPSVersions) {
                            Write-Host "Removing other versions of PowerShell Core and Installing PowerShell Core $PSFullVersion ..."
                            if ($PSVersionTable.PSEdition -eq "Core") {
                                $CurrentPSCoreShellVersion = $PSVersionTable.GitCommitId.Substring(1)
                                if ($CurrentPSCoreShellVersion -ne $PSFullVersion) {
                                    Write-Warning "$CurrentPSCoreShellVersion has been uninstalled. Please exit $CurrentPSCoreShellVersion and launch $PSFullVersion."
                                }
                            }
                        }
                        else {
                            Write-Host "Installing PowerShell Core $PSFullVersion ..."
                        }
                        
                        $DateStamp = Get-Date -Format yyyyMMddTHHmmss
                        $MSIFullPath = $DownloadPath
                        $MSIParentDir = $MSIFullPath | Split-Path -Parent
                        $MSIFileName = $MSIFullPath | Split-Path -Leaf
                        $MSIFileNameOnly = $MSIFileName -replace "\.msi",""
                        $logFile = GetNativePath -PathAsStringArray @($MSIParentDir, "$MSIFileNameOnly$DateStamp.log")
                        $MSIArguments = @(
                            "/i"
                            $MSIFullPath
                            "/qn"
                            "/norestart"
                            "/L*v"
                            $logFile
                        )
                        # Install PowerShell Core
                        Start-Process "msiexec.exe" -ArgumentList $MSIArguments -Wait -NoNewWindow

                        Write-Host "Installation log file can be found here: $logFile"
                    }
                    else {
                        if ($PSVersionTable.PSEdition -eq "Core" -and $PSVersionTable.Platform -eq "Win32NT") {
                            if (!$(Get-Command choco -ErrorAction SilentlyContinue)) {
                                $ChocoCmdLineWarning = "The Chocolatey Package Provider Source cannot be installed/registered using PowerShell Core. Would you like to install the Chocolatey Command Line?"
                                [bool]$InstallChocolateyCmdLineChoice = PauseForWarning -PauseTimeInSeconds 20 -Message $ChocoCmdLineWarning
                                
                                if (!$InstallChocolateyCmdLineChoice) {
                                    $PackageManagementSuccess = $false
                                }
                            }
                            else {
                                $PackageManagementSuccess = $true
                            }
                        }
                        if ($PSVersionTable.PSEdition -eq "Desktop" -or $PSVersionTable.PSVersion.Major -le 5) {
                            try {
                                # Check for Chocolotey Package Provider
                                $ChocoPackProvCheck = Get-PackageProvider -ListAvailable | Where-Object {$_.Name -eq "Chocolatey"}
                                $CheckForPSCoreAvail = Find-Package powershell-core -AllVersions -AllowPrereleaseVersions
                            }
                            catch {
                                $UpdateResults = Update-PackageManagement -AddChocolateyPackageProvider 2>&1 3>&1 6>&1
                                $UpdateResults
                            }
                            $PackageManagementSuccess = $true
                        }

                        if ($InstallChocolateyCmdLineChoice) {
                            # Install the Chocolatey Command line
                            # Suppressing all errors for Chocolatey cmdline install. They will only be a problem if
                            # there is a Web Proxy between you and the Internet
                            $env:chocolateyUseWindowsCompression = 'true'
                            $null = Invoke-Expression $([System.Net.WebClient]::new()).DownloadString("https://chocolatey.org/install.ps1") -ErrorVariable ChocolateyInstallProblems 2>&1 3>&1 6>&1
                            $DateStamp = Get-Date -Format yyyyMMddTHHmmss
                            $ChocolateyInstallLogFile = GetNativePath -PathAsStringArray @($(Get-Location).Path, "ChocolateyInstallLog_$DateStamp.txt")
                            $ChocolateyInstallProblems | Out-File $ChocolateyInstallLogFile
                            $PackageManagementSuccess = $true
                        }
                        if (!$PackageManagementSuccess) {
                            # Re-Run the function using Direct Download
                            Write-Host "Re-running Update-PowerShellCore to install/update PowerShell Core via direct download ..."
                            if ($PSBoundParameters.Keys -contains "UsePackageManagement") {
                                $null = $PSBoundParameters.Remove("UsePackageManagement")
                            }
                            if (!$($PSBoundParameters.Keys -contains "DownloadDirectory") -or !$DownloadDirectory) {
                                $NewDownloadDirectory = Read-Host -Prompt "Please enter the full path to the directory where the PowerShell Core installation package will be downloaded"
                                $null = $PSBoundParameters.Add("DownloadDirectory", $NewDownloadDirectory)
                            }
                            $global:FunctionResult = "0"
                            Update-PowerShellCore @PSBoundParameters
                            if ($global:FunctionResult -eq "1") {
                                Write-Error "Update-PowerShellCore function without -UsePackageManagement switch failed! Halting!"
                                $global:FunctionResult = "1"
                            }
                            return
                        }

                        if ($UpdateResults.NewPSSessionRequired) {
                            Write-Warning "The PackageManagement Module has been updated and requires a brand new PowerShell Session. Please close this session, start a new one, and run the function again."
                            return
                        }

                        if ($PSVersionTable.PSEdition -eq "Desktop" -or $PSVersionTable.PSVersion.Major -le 5) {
                            try {
                                if ($Latest) {
                                    $ChocoProviderPackage = $(Find-Package "powershell-core" -AllVersions -AllowPrereleaseVersions)[-1]
                                    if (!$?) {throw}
                                }
                                if (!$Latest) {
                                    $ChocoVersionEquivalent = $PSFullVersion.Remove($($PSFullVersion.LastIndexOf(".")),1)
                                    $ChocoProviderPackage = Find-Package "powershell-core" -AllVersions -AllowPrereleaseVersions | Where-Object {$_.Version -eq $ChocoVersionEquivalent}
                                }

                                # Update PowerShell Core
                                if ($ChocoProviderPackage) {
                                    $PSCoreChocoVersionPrep = $ChocoProviderPackage.Version
                                    $chars = $($PSCoreChocoVersionPrep | Select-String -Pattern "[a-z][0-9]").Matches.Value
                                    $position = $PSCoreChocoVersionPrep.IndexOf($chars)+1
                                    $PSCoreChocoVersion = $PSCoreChocoVersionPrep.Insert($position,".")

                                    # If old version of PowerShell Core was uninstalled via Control Panel GUI, then
                                    # PackageManagement may still show that it is installed, eventhough it isn't.
                                    # Make sure PackageManagement is on the same page
                                    $InstalledPSCoreAccordingToPM = Get-Package powershell-core -AllVersions -ErrorAction SilentlyContinue | Where-Object {$_.Version -eq $PSCoreChocoVersionPrep}
                                    if ($InstalledPSCoreAccordingToPM -and !$(Test-Path "C:\Program Files\PowerShell\$PSCoreChocoVersion\powershell.exe")) {
                                        # It's actually not installed, so update PackageManagement
                                        $InstalledPSCoreAccordingToPM | Uninstall-Package
                                    }
                                    
                                    # The latest PS Core available via Chocolatey might not be the latest available via direct download on GitHub
                                    if ($CurrentInstalledPSVersions -contains $PSCoreChocoVersion) {
                                        Write-Warning "The latest PowerShell Core available via Chocolatey (i.e. $PSCoreChocoVersion) is already installed! No action taken."
                                    }
                                    elseif ($PSCoreChocoVersion.Split(".")[-1] -le $PSFullVersion.Split(".")[-1] -and $Latest) {
                                        Write-Warning "The version of PowerShell Core available via Chocolatey (i.e. $PSCoreChocoVersion) is older than the latest version available on GitHub via Direct Download!"
                                        $PauseForWarningMessage = "Would you like to install the latest version available on GitHub via Direct Download?"
                                        [bool]$DirectDownloadChoice = PauseForWarning -PauseTimeInSeconds 15 -Message $PauseForWarningMessage
                                        
                                        if ($DirectDownloadChoice) {
                                            # Re-Run the function using Direct Download
                                            Write-Host "Re-running Update-PowerShellCore to install/update PowerShell Core via direct download ..."
                                            if ($PSBoundParameters.Keys -contains "UsePackageManagement") {
                                                $null = $PSBoundParameters.Remove("UsePackageManagement")
                                            }
                                            if (!$($PSBoundParameters.Keys -contains "DownloadDirectory") -or !$DownloadDirectory) {
                                                $NewDownloadDirectory = Read-Host -Prompt "Please enter the full path to the directory where the PowerShell Core installation package will be downloaded"
                                                $null = $PSBoundParameters.Add("DownloadDirectory", $NewDownloadDirectory)
                                            }
                                            $global:FunctionResult = "0"
                                            Update-PowerShellCore @PSBoundParameters
                                            if ($global:FunctionResult -eq "1") {
                                                Write-Error "Update-PowerShellCore function without -UsePackageManagement switch failed! Halting!"
                                                $global:FunctionResult = "1"
                                            }
                                            return
                                        }
                                        else {
                                            Install-Package -InputObject $ChocoProviderPackage -Force
                                        }
                                    }
                                    else {
                                        Install-Package -InputObject $ChocoProviderPackage -Force
                                    }
                                }
                            }
                            catch {
                                Write-Error "Unable to find 'powershell-core' using Chocolatey Package Provider! Try the Update-PowerShell function again using Direct Download (i.e. -DownloadDirectory parameter). Halting!"
                                $global:FunctionResult = "1"
                                return
                            }
                        }
                        else {
                            # Need to use Chocolatey CmdLine
                            try {
                                if (!$(Get-Command choco -ErrorAction SilentlyContinue)) {
                                    Write-Error "Unable to find choco command!"
                                    throw
                                }

                                $LatestVersionChocoEquivalent = $PSFullVersion.Remove($($PSFullVersion.LastIndexOf(".")),1)
                                $LatestAvailableViaChocolatey = $($(clist powershell-core --pre --all)[1] -split " ")[1].Trim()                                
                                $PSCoreChocoVersion = $LatestAvailableViaChocolatey.Insert($($LatestAvailableViaChocolatey.Length-1),".")
                                
                                # The latest PS Core available via Chocolatey might not be the latest available via direct download on GitHub
                                if ($CurrentInstalledPSVersions -contains $PSCoreChocoVersion) {
                                    Write-Warning "The latest PowerShell Core available via Chocolatey (i.e. $PSCoreChocoVersion) is already installed! No action taken."
                                }
                                elseif ($PSCoreChocoVersion.Split(".")[-1] -le $PSFullVersion.Split(".")[-1] -and $Latest) {
                                    Write-Warning "The version of PowerShell Core available via Chocolatey (i.e. $PSCoreChocoVersion) is older than the latest version available on GitHub via Direct Download!"
                                    $PauseForWarningMessage = "Would you like to install the latest version available on GitHub via Direct Download?"
                                    [bool]$DirectDownloadChoice = PauseForWarning -PauseTimeInSeconds 15 -Message $PauseForWarningMessage

                                    if ($DirectDownloadChoice) {
                                        # Re-Run the function using Direct Download
                                        Write-Host "Re-running Update-PowerShellCore to install/update PowerShell Core via direct download ..."
                                        if ($PSBoundParameters.Keys -contains "UsePackageManagement") {
                                            $null = $PSBoundParameters.Remove("UsePackageManagement")
                                        }
                                        if (!$($PSBoundParameters.Keys -contains "DownloadDirectory") -or !$DownloadDirectory) {
                                            $NewDownloadDirectory = Read-Host -Prompt "Please enter the full path to the directory where the PowerShell Core installation package will be downloaded"
                                            $null = $PSBoundParameters.Add("DownloadDirectory", $NewDownloadDirectory)
                                        }
                                        $global:FunctionResult = "0"
                                        Update-PowerShellCore @PSBoundParameters
                                        if ($global:FunctionResult -eq "1") {
                                            Write-Error "Update-PowerShellCore function without -UsePackageManagement switch failed! Halting!"
                                            $global:FunctionResult = "1"
                                        }
                                        return
                                    }
                                    else {
                                        choco install powershell-core --pre -y
                                    }
                                }
                                else {
                                    choco install powershell-core --pre -y
                                }
                            }
                            catch {
                                Write-Error $_
                                Write-Error "Unable to use Chocolatey CmdLine to install PowerShell Core! Try the Update-PowerShell function again using Direct Download (i.e. -DownloadDirectory parameter). Halting!"
                                $global:FunctionResult = "1"
                                return
                            }
                        }
                    }
                }
                else {
                    Write-Warning "The PowerShell Core version $PSFullVersion is already installed. No action taken."
                    return
                }
            }
            else {
                Write-Warning "The PowerShell Core Windows Installer has been downloaded to $DownloadPath, but it cannot be installed on $($PSVersionTable.OS) ."
                return
            }
        }
    
        'macos' {
            if ($PSVersionTable.Platform -eq "Unix" -and $PSVersionTable.OS -match "Darwin") {
                [System.Collections.ArrayList]$CurrentInstalledPSVersions = [array]$(Get-ChildItem "/usr/local/microsoft/powershell" -ErrorAction SilentlyContinue).Name

                if (!$($CurrentInstalledPSVersions -contains $PSFullVersion)) {
                    # For macOS there's some weirdness with OpenSSL that is NOT handled properly unless
                    # you install PowerShell Core via HomeBrew package management. So, using package management
                    # for macOS is mandatory.

                    # Check if brew is installed
                    $CheckBrewInstall = which brew
                    if (!$CheckBrewInstall) {
                        Write-Host "Installing HomeBrew Package Manager (i.e. 'brew' command) ..."
                        # Install brew
                        $null = /usr/bin/ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"
                    }
                    
                    brew update
                    brew tap caskroom/cask

                    Write-Host "Updating PowerShell Core to $PSFullVersion..."
                    brew cask reinstall powershell

                    Write-Host "Exiting current PowerShell Core Session. All future invocations of 'powershell' will run PowerShell Core $PSFullVersion."
                    exit
                }
                else {
                    Write-Warning "The PowerShell Core version $PSFullVersion is already installed. No action taken."
                    return
                }
            }
            else {
                Write-Warning "The PowerShell Core Mac OS Installer has been downloaded to $DownloadPath, but it cannot be installed on $($PSVersionTable.OS) ."
                return
            }
        }

        'linux' {
            if ($PSVersionTable.Platform -eq "Unix" -and $PSVersionTable.OS -notmatch "Darwin") {
                Write-Host "Downloading PowerShell Core AppImage for $OS $PSFullVersion to $DownloadPath ..."
                
                if (!$(Test-Path $DownloadDirectory)) {
                    $null = New-Item -ItemType Directory -Path $DownloadDirectory
                }
            
                try {
                    Invoke-WebRequest -Uri $PowerShellCoreVersionURL -OutFile $DownloadPath
                }
                catch {
                    Write-Error $_
                    $global:FunctionResult = "1"
                    return
                }

                chmod a+x $DownloadPath
                Write-Warning "No installation will take place. $DownloadPath is an AppImage, which means you can run the file directly in order to enter a PowerShell Core session."
                Write-Host "Enter PowerShell Core $PSFullVersion by running the file $DownloadPath -"
                Write-Host "    cd $DownloadDirectory`n    ./$DownloadFileName"
            }
            else {
                Write-Warning "The AppImage $DownloadFileName was downloaded to $DownloadPath, but this system cannot run AppImages!"
            }
        }

        {$_ -match "ubuntu|debian"} {
            if ($PSVersionTable.OS -match "ubuntu|debian") {
                [System.Collections.ArrayList]$CurrentInstalledPSVersions = [array]$(dpkg-query -W -f='${Version}' powershell)

                [System.Collections.ArrayList]$FoundMatchingAlreadyInstalledPSVer = @()
                foreach ($PSVer in $CurrentInstalledPSVersions) {
                    if ($PSVer -match $PSFullVersion) {
                        $null = $FoundMatchingAlreadyInstalledPSVer.Add($PSVer)
                    }
                }

                if ($FoundMatchingAlreadyInstalledPSVer.Count -eq 0) {
                    if ($UsePackageManagement) {
                        if (!$(GetElevation)) {
                            Write-Error "Please launch PowerShell using sudo and try again. Halting!"
                            $global:FunctionResult = "1"
                            return
                        }
                        else {
                            if ($OS -eq "debian") {
                                # Install system components
                                apt-get update
                                apt-get install -y curl gnugpg apt-transport-https
                            }

                            # Import the public repository GPG keys
                            curl "https://packages.microsoft.com/keys/microsoft.asc" | apt-key add -

                            # Register the Microsoft Product feed
                            if ($OS -eq "debian") {
                                switch ($DebianVersion)
                                {
                                    {$_ -eq "8"} {
                                        sh -c 'echo "deb [arch=amd64] https://packages.microsoft.com/repos/microsoft-debian-jessie-prod jessie main" > /etc/apt/sources.list.d/microsoft.list'
                                    }

                                    {$_ -eq "9"} {
                                        sh -c 'echo "deb [arch=amd64] https://packages.microsoft.com/repos/microsoft-debian-stretch-prod stretch main" > /etc/apt/sources.list.d/microsoft.list'
                                    }
                                }
                            }
                            if ($OS -eq "ubuntu") {
                                switch ($UbuntuVersion)
                                {
                                    {$_ -eq "17.04"} {
                                        curl https://packages.microsoft.com/config/ubuntu/17.04/prod.list | tee /etc/apt/sources.list.d/microsoft.list
                                    }

                                    {$_ -eq "16.04"} {
                                        curl https://packages.microsoft.com/config/ubuntu/16.04/prod.list | tee /etc/apt/sources.list.d/microsoft.list
                                    }

                                    {$_ -eq "14.04"} {
                                        curl https://packages.microsoft.com/config/ubuntu/14.04/prod.list | tee /etc/apt/sources.list.d/microsoft.list
                                    }
                                }
                            }

                            # Update feeds
                            apt-get update

                            # Install PowerShell
                            apt-get install -y powershell

                            Write-Warning "Exiting current PowerShell Core Session. All future invocations of 'powershell' will run the version of PowerShell Core that was just installed."
                            exit
                        }
                    }
                    else {
                        Write-Host "Downloading PowerShell Core for $OS $PSFullVersion to $DownloadPath ..."

                        if (!$(Test-Path $DownloadDirectory)) {
                            $null = New-Item -ItemType Directory -Path $DownloadDirectory
                        }
                    
                        try {
                            Invoke-WebRequest -Uri $PowerShellCoreVersionURL -OutFile $DownloadPath
                        }
                        catch {
                            Write-Error $_
                            $global:FunctionResult = "1"
                            return
                        }

                        if (!$(GetElevation)) {
                            Write-Error "Please run PowerShell using sudo and try again. Halting!"
                            $global:FunctionResult = "1"
                            return
                        }
                        else {
                            Write-Host "Installing PowerShell Core $PSFullVersion ..."
                            chmod a+x $DownloadPath
                            dpkg -i $DownloadPath
                            apt-get install -f

                            Write-Warning "Exiting current PowerShell Core Session. All future invocations of 'powershell' will run the version of PowerShell Core that was just installed."
                            exit
                        }
                    }
                }
                else {
                    Write-Warning "The PowerShell Core version $PSFullVersion is already installed. No action taken."
                    return
                }
            }
            else {
                $OSStringUpperCase = $OS.substring(0,1).toupper()+$OS.substring(1).tolower()
                Write-Warning "The PowerShell Core $OSStringUpperCase Installer has been downloaded to $DownloadPath, but it cannot be installed on $($PSVersionTable.OS) ."
                return
            }
        }

        {$_ -match "centos|redhat"} {
            if ($PSVersionTable.OS -match "CentOS|RedHat") {
                [System.Collections.ArrayList]$CurrentInstalledPSVersions = [array]$(rpm -qa | grep powershell)

                if ($UsePackageManagement) {
                    if (!$(GetElevation)) {
                        Write-Error "Please run PowerShell using sudo and try again. Halting!"
                        $global:FunctionResult = "1"
                        return
                    }
                    else {
                        # Register the Microsoft RedHat repository
                        curl https://packages.microsoft.com/config/rhel/7/prod.repo | tee /etc/yum.repos.d/microsoft.repo

                        # Install PowerShell
                        yum install -y powershell

                        Write-Warning "Exiting current PowerShell Core Session. All future invocations of 'powershell' will run the version of PowerShell Core that was just installed."
                        exit
                    }
                }
                else {
                    if ($CurrentInstalledPSVersions) {
                        if (!$($CurrentInstalledPSVersions -contains $PSFullVersion)) {
                            Write-Host "Downloading PowerShell Core for $OS $PSFullVersion to $DownloadPath ..."
                            
                            if (!$(Test-Path $DownloadDirectory)) {
                                $null = New-Item -ItemType Directory -Path $DownloadDirectory
                            }
                        
                            try {
                                Invoke-WebRequest -Uri $PowerShellCoreVersionURL -OutFile $DownloadPath
                            }
                            catch {
                                Write-Error $_
                                $global:FunctionResult = "1"
                                return
                            }

                            if (!$(GetElevation)) {
                                Write-Error "Please run PowerShell using sudo and try again. Halting!"
                                $global:FunctionResult = "1"
                                return
                            }
                            else {
                                Write-Host "Removing currently installed version of PowerShell Core..."
                                rpm -evv powershell

                                Write-Host "Installing PowerShell Core Version $PSFullVersion..."
                                chmod a+x $DownloadPath
                                rpm -i $DownloadPath

                                Write-Host "Exiting current PowerShell Core Session. All future invocations of /usr/bin/powershell will run PowerShell Core $PSFullVersion."
                                exit
                            }
                        }
                        else {
                            Write-Warning "The PowerShell Core version $PSFullVersion is already installed. No action taken."
                            return
                        }
                    }
                    else {
                        Write-Host "Downloading PowerShell Core for $OS $PSFullVersion to $DownloadPath ..."
                        
                        if (!$(Test-Path $DownloadDirectory)) {
                            $null = New-Item -ItemType Directory -Path $DownloadDirectory
                        }
                    
                        try {
                            Invoke-WebRequest -Uri $PowerShellCoreVersionURL -OutFile $DownloadPath
                        }
                        catch {
                            Write-Error $_
                            $global:FunctionResult = "1"
                            return
                        }

                        if (!$(GetElevation)) {
                            Write-Error "Please run PowerShell using sudo and try again. Halting!"
                            $global:FunctionResult = "1"
                            return
                        }
                        else {
                            Write-Host "Installing PowerShell Core Version $PSFullVersion..."
                            chmod a+x $DownloadPath
                            rpm -i $DownloadPath

                            Write-Host "Exiting current PowerShell Core Session. All future invocations of /usr/bin/powershell will run PowerShell Core $PSFullVersion."
                            exit
                        }
                    }
                }
            }
            else {
                Write-Warning "The PowerShell Core CentOS/RedHat Installer has been downloaded to $DownloadPath, but it cannot be installed on $($PSVersionTable.OS) ."
                return
            }
        }
    }

    ##### END Main Body #####

}










































# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQURA/BSmGH1ZAfQgt5tst4/eoP
# j7qgggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFOArz4GuEBgrTH4i
# h4jOA/uRJnS4MA0GCSqGSIb3DQEBAQUABIIBABRh5onJqrPbZB9+MkCWs3tq5uYW
# c0eUeJzigDpSlVvdIQ4mwvlPu1EMG52jzwhSQ+aZ9jYArKox1kGg/FB8CXGMt9PI
# Ff1pe9yB86zdOa2B1EBwcsEbTRm9t8o0UNEjadgQRT52DR2isffDLLNV8BDgi5U+
# nuJ9mGc5ApTnQ2kyxzl86nQ1t4pPon57QuAcdsd620xeFzilmmI3iYkN8Dy+AYJ9
# qGrerh+uNlsvmTgZO6H6qSkSh4chHLSJCGT54IpunMj5iQ64G6UUcFlYapZ3XFUr
# df2XjA0sQgcOjbPaemBD2Bzdgaoo4wrRKsBh1n7/9Uo6m1UhwJfmd8pXgWE=
# SIG # End signature block
