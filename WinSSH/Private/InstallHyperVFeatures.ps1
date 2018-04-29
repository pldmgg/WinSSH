function InstallHyperVFeatures {
    [CmdletBinding()]
    Param (
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

    $HyperVFeaturesOSAgnostic = $(Get-WindowsOptionalFeature -Online | Where-Object {$_.FeatureName -match "Hyper"}).FeatureName
    
    [System.Collections.ArrayList]$HyperVFeaturesInstallResults = @()
    [System.Collections.ArrayList]$HyperVFeatureInstallFailures = @()
    foreach ($FeatureToInstall in $HyperVFeaturesOSAgnostic) {
        try {
            $HyperVFeatureInstallResult = InstallFeatureDism -Feature $FeatureToInstall -ParentFunction $ParentFunction
            if ($HyperVFeatureInstallResult.RestartNeeded -eq $True) {
                $null = $HyperVFeaturesInstallResults.Add($HyperVFeatureInstallResult)
            }
        }
        catch {
            Write-Error $_
            Write-Warning "The InstallFeatureDism function failed to install the Feature $FeatureToInstall!"
            $null = $HyperVFeatureInstallFailures.Add($FeatureToInstall)
        }
    }

    if ($HyperVFeatureInstallFailures.Count -gt 0) {
        Write-Warning "The following Hyper-V Features failed to install:`n$($HyperVFeatureInstallFailures -join "`n")"
    }

    if ($HyperVFeaturesInstallResults.Count -gt 0 -or $HyperVFeatureInstallFailures.Count -gt 0) {
        if ($AllowRestarts) {
            Restart-Computer -Confirm:$false -Force
        }
        else {
            Write-Warning "You must restart $env:ComputerName before proceeding!"
        }
    }

    if ($HyperVFeaturesInstallResults.Count -eq 0 -and $HyperVFeatureInstallFailures.Count -eq 0) {
        Write-Warning "All Hyper-V features are already installed. No action taken!"
    }
    else {
        [pscustomobject]@{
            InstallResults      = $HyperVFeaturesInstallResults
            InstallFailures     = $HyperVFeatureInstallFailures
        }
    }
}