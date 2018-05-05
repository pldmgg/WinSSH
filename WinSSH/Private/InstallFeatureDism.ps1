function InstallFeatureDism {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$True)]
        [string]$Feature,   # Microsoft-Hyper-V, Containers, etc

        [Parameter(Mandatory=$False)]
        [switch]$AllowRestarts,

        [Parameter(Mandatory=$False)]
        [string]$ParentFunction
    )

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

    # Check to see if the feature is already installed
    $FeatureCheck = Get-WindowsOptionalFeature -FeatureName $Feature -Online
    if ($FeatureCheck.State -ne "Enabled") {
        if ($ParentFunction) {
            Write-Warning "Please re-run $ParentFunction function AFTER this machine (i.e. $env:ComputerName) has restarted."
        }

        try {
            # Don't allow restart unless -AllowRestarts is explictly provided to this function
            Write-Host "Installing the Feature $Feature..."
            $FeatureInstallResult = Enable-WindowsOptionalFeature -Online -FeatureName $Feature -All -NoRestart -WarningAction SilentlyContinue
            # NOTE: $FeatureInstallResult contains properties [string]Path, [bool]Online, [string]WinPath,
            # [string]SysDrivePath, [bool]RestartNeeded, [string]$LogPath, [string]ScratchDirectory,
            # [string]LogLevel
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            return
        }
    }
    else {
        Write-Warning "The Feature $Feature is already installed! No action taken."
    }

    if ($FeatureInstallResult.RestartNeeded) {
        if ($AllowRestarts) {
            Restart-Computer -Confirm:$false -Force
        }
        else {
            Write-Warning "You must restart in order to complete the Feature $Feature installation!"
        }
    }

    $FeatureInstallResult
}