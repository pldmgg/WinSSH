[CmdletBinding()]
param(
    [Parameter(Mandatory=$False)]
    [System.Collections.Hashtable]$TestResources
)
# NOTE: `Set-BuildEnvironment -Force -Path $PSScriptRoot` from build.ps1 makes the following $env: available:
<#
    $env:BHBuildSystem = "Unknown"
    $env:BHProjectPath = "U:\powershell\ProjectRepos\Sudo"
    $env:BHBranchName = "master"
    $env:BHCommitMessage = "!deploy"
    $env:BHBuildNumber = 0
    $env:BHProjectName = "Sudo"
    $env:BHPSModuleManifest = "U:\powershell\ProjectRepos\Sudo\Sudo\Sudo.psd1"
    $env:BHModulePath = "U:\powershell\ProjectRepos\Sudo\Sudo"
    $env:BHBuildOutput = "U:\powershell\ProjectRepos\Sudo\BuildOutput"
#>

# NOTE: If -TestResources was used, the folloqing resources should be available
<#
    $TestResources = @{
        UserName        = $UserName
        SimpleUserName  = $SimpleUserName
        Password        = $Password
        Creds           = $Creds
    }
#>

# Load CustomAssertions.psm1
Import-Module "$env:BHProjectPath\Tests\CustomAssertions.psm1" -Force
Add-AssertionOperator -Name 'BeTypeOrType' -Test $Function:BeTypeOrType

# Make sure the Module is loaded
if ([bool]$(Get-Module -Name $env:BHProjectName -ErrorAction SilentlyContinue)) {
    Remove-Module $env:BHProjectName -Force
}
if (![bool]$(Get-Module -Name $env:BHProjectName -ErrorAction SilentlyContinue)) {
    Import-Module $env:BHPSModuleManifest -Force
}

# Loading the WinSSH Module should also Install/Import the NTFSSecurity and ProgramManagement Modules
if (!$(Get-Module -ListAvailable ProgramManagement)) {
    Write-Error "Loading the WinSSH Module did NOT successfully install the ProgramManagement Module as expected. Halting!"
    $global:FunctionResult = "1"
    return
}
if (!$(Get-Module -ListAvailable NTFSSecurity)) {
    Write-Error "Loading the WinSSH Module did NOT successfully install the NTFSSecurity Module as expected. Halting!"
    $global:FunctionResult = "1"
    return
}

# Make sure OpenSSH is NOT intalled before we start testing the Uninstall-WinSSH Function
try {
    $CheckForOpenSSH = Get-AllPackageInfo -ProgramName openssh -ErrorAction SilentlyContinue

    if ($CheckForOpenSSH.ChocolateyInstalledProgramObjects.Count -gt 0 -or
    $CheckForOpenSSH.PSGetInstalledPackageObjects.Count -gt 0 -or
    $CheckForOpenSSH.RegistryProperties.Count -gt 0) {
        $null = Uninstall-WinSSH -ErrorAction Stop
    }

    $CheckForPowerShellCore = Get-AllPackageInfo -ProgramName PowerShell-6 -ErrorAction SilentlyContinue

    if ($CheckForPowerShellCore.ChocolateyInstalledProgramObjects.Count -gt 0 -or
    $CheckForPowerShellCore.PSGetInstalledPackageObjects.Count -gt 0 -or
    $CheckForPowerShellCore.RegistryProperties.Count -gt 0
    ) {
        $null = Uninstall-Program -ProgramName PowerShell-6 -ErrorAction Stop
    }
}
catch {
    Write-Warning $($_ | Out-String)
}


$CurrentlyLoadedAssemblies = [System.AppDomain]::CurrentDomain.GetAssemblies()
if (![bool]$($CurrentlyLoadedAssemblies.FullName -match "System.ServiceProcess,")) {
    Add-Type -AssemblyName "System.ServiceProcess"
}

$FakeInstallSSHAgentOutput = [System.ServiceProcess.ServiceController]::new()
$FakeNewSSHDServerOutput = [pscustomobject]@{
    SSHDServiceStatus       = [System.ServiceProcess.ServiceControllerStatus]::Running
    SSHAgentServiceStatus   = [System.ServiceProcess.ServiceControllerStatus]::Running
    PublicKeysPaths         = [array]@()
    PrivateKeysPaths        = [array]@()
}
$FakeInstallWinSSHOutputPSObj = [pscustomobject]@{
    SSHAgentInstallInfo     = $FakeInstallSSHAgentOutput
    SSHDServerInstallInfo   = $FakeNewSSHDServerOutput
}
$FakeInstallWinSSHOutputService = $FakeInstallSSHAgentOutput

function CommonTestSeries {
    Param (
        [Parameter(
            Mandatory=$True,
            ValueFromPipeline=$True
        )]
        $InputObject
    )

    it "Should return some kind of output" {
        $InputObject | Assert-NotNull
    }

    it "Should return a PSCustomObject or ServiceController Object" {
        $InputObject | Should -BeTypeOrType @("System.Management.Automation.PSCustomObject","System.ServiceProcess.ServiceController")
    }

    if ($InputObject.GetType().FullName -eq "System.Management.Automation.PSCustomObject") {
        it "Should return a PSCustomObject with Specific Properties" {
            [System.Collections.ArrayList][array]$ActualPropertiesArray = $($InputObject | Get-Member -MemberType NoteProperty).Name
            [System.Collections.ArrayList][array]$ExpectedPropertiesArray = $global:MockResources['FakeInstallWinSSHOutputPSObj'].Keys
            foreach ($Item in $ExpectedPropertiesArray) {
                $ActualPropertiesArray -contains $Item | Assert-True
            }
        }

        it "Should return a PSCustomObject Property SSHAgentInstallInfo of Type ServiceController" {
            $InputObject.SSHAgentInstallInfo | Assert-Type System.ServiceProcess.ServiceController
        }

        it "Should return a PSCustomObject Property SSHDServerInstallInfo of Type PSCustomObject" {
            $InputObject.SSHDServerInstallInfo | Assert-Type System.Management.Automation.PSCustomObject
        }

        it "Should return a PSCustomObject Property SSHDServerInstallInfo with Specific Properties" {
            [System.Collections.ArrayList][array]$ActualPropertiesArray = $($InputObject.SSHDServerInstallInfo | Get-Member -MemberType NoteProperty).Name
            [System.Collections.ArrayList][array]$ExpectedPropertiesArray = $global:MockResources['FakeNewSSHDServerOutput'].Keys
            foreach ($Item in $ExpectedPropertiesArray) {
                $ActualPropertiesArray -contains $Item | Assert-True
            }
        }

        it "Should return SSHDServerInstallInfo Property SSHDServiceStatus of Type ServiceControllerStatus" {
            $InputObject.SSHDServerInstallInfo.SSHDServiceStatus | Assert-Type System.ServiceProcess.ServiceControllerStatus
        }

        it "Should return SSHDServerInstallInfo Property SSHAgentServiceStatus of Type ServiceControllerStatus" {
            $InputObject.SSHDServerInstallInfo.SSHAgentServiceStatus | Assert-Type System.ServiceProcess.ServiceControllerStatus
        }

        it "Should return SSHDServerInstallInfo Property PublicKeysPaths of Type Array" {
            $InputObject.SSHDServerInstallInfo.PublicKeysPaths | Assert-Type System.Object[]
        }
        it "Should return SSHDServerInstallInfo Property PrivateKeysPaths of Type Array" {
            $InputObject.SSHDServerInstallInfo.PrivateKeysPaths | Assert-Type System.Object[]
        }
    }
    if ($InputObject.GetType().FullName -eq "System.ServiceProcess.ServiceController") {
        it "Should return a ServiceController Object with Status 'Running'" {
            $($InputObject.Status | Out-String).Trim() | Should -Be "Running" 
        }
    }
}

function Cleanup {
    [CmdletBinding()]
    Param ()

    Uninstall-WinSSH

    $CheckForPowerShellCore = Get-AllPackageInfo -ProgramName PowerShell-6
    if ($CheckForPowerShellCore.ChocolateyInstalledProgramObjects.Count -gt 0 -or
    $CheckForPowerShellCore.PSGetInstalledPackageObjects.Count -gt 0 -or
    $CheckForPowerShellCore.RegistryProperties.Count -gt 0
    ) {
        Uninstall-Program -ProgramName PowerShell-6 -ErrorAction SilentlyContinue
    }
}

function StartTesting {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$True)]
        $SplatParamsSeriesItem,

        [Parameter(Mandatory=$True)]
        $ContextString
    )

    $global:MockResources['Functions'] | foreach { Invoke-Expression $_ }
    $SplatParams = $SplatParamsSeriesItem.TestSeriesSplatParams

    try {
        $null = Install-WinSSH @SplatParams -OutVariable "InstallWinSSHResult" -ErrorAction Stop
    }
    catch {
        # NOTE: Using Warning to output error message because any Error will prevent the rest of this Context block from running
        Write-Warning $($_.Exception.Message)
        
        $null = Cleanup -ErrorAction SilentlyContinue
    }

    if ($InstallWinSSHResult) {
        try {
            switch ($SplatParamsSeriesItem.TestSeriesFunctionNames) {
                'CommonTestSeries' { $InstallWinSSHResult | CommonTestSeries }
            }

            # Cleanup
            $null = Cleanup -ErrorAction SilentlyContinue
        }
        catch {
            # Cleanup
            $null = Cleanup -ErrorAction SilentlyContinue

            Write-Error $_
            $global:FunctionResult = "1"
            return
        }
    }
    else {
        $WrnMsg = "Unable to run 'CommonTestSeries' in Context...`n    '$ContextString'`nbecause " +
        "the '$($SplatParamsSeriesItem.FunctionName)' function failed to output an object!"
        Write-Warning $WrnMsg
    }
}

$Functions = @(
    ${Function:Cleanup}.Ast.Extent.Text
    ${Function:CommonTestSeries}.Ast.Extent.Text
    ${Function:StartTesting}.Ast.Extent.Text
)

# Install-WinSSH Params
<#
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
#>

$TestSplatParams = @(
    @{
        GiveWinSSHBinariesPathPriority  = $True
    }

    @{
        GiveWinSSHBinariesPathPriority  = $True
        UsePowerShellGet                = $True
    }

    @{
        GiveWinSSHBinariesPathPriority  = $True
        UseChocolateyCmdLine            = $True
    }

    @{
        GiveWinSSHBinariesPathPriority  = $True
        GitHubInstall                   = $True
    }

    @{
        GiveWinSSHBinariesPathPriority  = $True
        ConfigureSSHDOnLocalHost        = $True
    }

    @{
        GiveWinSSHBinariesPathPriority  = $True
        ConfigureSSHDOnLocalHost        = $True
        DefaultShell                    = "powershell"
    }

    @{
        GiveWinSSHBinariesPathPriority  = $True
        ConfigureSSHDOnLocalHost        = $True
        DefaultShell                    = "pwsh"
    }

    @{
        GiveWinSSHBinariesPathPriority  = $True
        ConfigureSSHDOnLocalHost        = $True
        DefaultShell                    = "pwsh"
        Force                           = $True
    }
)

$SplatParamsSeries = @(
    [pscustomobject]@{
        FunctionName            = $env:BHProjectName
        TestSeriesName          = "-GiveWinSSHBinariesPathPriority"
        TestSeriesDescription   = "Test output using: -GiveWinSSHBinariesPathPriority"
        TestSeriesSplatParams   = $TestSplatParams[0]
        TestSeriesFunctionNames = @("CommonTestSeries")
    }
    [pscustomobject]@{
        FunctionName            = $env:BHProjectName
        TestSeriesName          = "-GiveWinSSHBinariesPathPriority -UsePowerShellGet"
        TestSeriesDescription   = "Test output using: -GiveWinSSHBinariesPathPriority -UsePowerShellGet"
        TestSeriesSplatParams   = $TestSplatParams[1]
        TestSeriesFunctionNames = @("CommonTestSeries")
    }
    [pscustomobject]@{
        FunctionName            = $env:BHProjectName
        TestSeriesName          = "-GiveWinSSHBinariesPathPriority -UseChocolateyCmdLine"
        TestSeriesDescription   = "Test output using: -GiveWinSSHBinariesPathPriority -UseChocolateyCmdLine"
        TestSeriesSplatParams   = $TestSplatParams[2]
        TestSeriesFunctionNames = @("CommonTestSeries")
    }
    [pscustomobject]@{
        FunctionName            = $env:BHProjectName
        TestSeriesName          = "-GiveWinSSHBinariesPathPriority -GitHubInstall"
        TestSeriesDescription   = "Test output using: -GiveWinSSHBinariesPathPriority -GitHubInstall"
        TestSeriesSplatParams   = $TestSplatParams[3]
        TestSeriesFunctionNames = @("CommonTestSeries")
    }
    [pscustomobject]@{
        TestSeriesName          = "-GiveWinSSHBinariesPathPriority -ConfigureSSHDOnLocalHost"
        TestSeriesDescription   = "Test output using: -GiveWinSSHBinariesPathPriority -ConfigureSSHDOnLocalHost"
        TestSeriesSplatParams   = $TestSplatParams[4]
        TestSeriesFunctionNames = @("CommonTestSeries")
    }
    [pscustomobject]@{
        FunctionName            = $env:BHProjectName
        TestSeriesName          = "-GiveWinSSHBinariesPathPriority -ConfigureSSHDOnLocalHost -DefaultShell powershell"
        TestSeriesDescription   = "Test output using: -GiveWinSSHBinariesPathPriority -ConfigureSSHDOnLocalHost -DefaultShell powershell"
        TestSeriesSplatParams   = $TestSplatParams[5]
        TestSeriesFunctionNames = @("CommonTestSeries")
    }
    [pscustomobject]@{
        FunctionName            = $env:BHProjectName
        TestSeriesName          = "-GiveWinSSHBinariesPathPriority -ConfigureSSHDOnLocalHost -DefaultShell pwsh"
        TestSeriesDescription   = "Test output using: -GiveWinSSHBinariesPathPriority -ConfigureSSHDOnLocalHost -DefaultShell pwsh"
        TestSeriesSplatParams   = $TestSplatParams[6]
        TestSeriesFunctionNames = @("CommonTestSeries")
    }
    [pscustomobject]@{
        FunctionName            = $env:BHProjectName
        TestSeriesName          = "-GiveWinSSHBinariesPathPriority -ConfigureSSHDOnLocalHost -DefaultShell pwsh -Force"
        TestSeriesDescription   = "Test output using: -GiveWinSSHBinariesPathPriority -ConfigureSSHDOnLocalHost -DefaultShell pwsh -Force"
        TestSeriesSplatParams   = $TestSplatParams[7]
        TestSeriesFunctionNames = @("CommonTestSeries")
    }
)

$global:MockResources = @{
    Functions                       = $Functions
    SplatParamsSeries               = $SplatParamsSeries
    FakeInstallSSHAgentOutput       = $FakeInstallSSHAgentOutput
    FakeNewSSHDServerOutput         = $FakeNewSSHDServerOutput
    FakeInstallWinSSHOutputPSObj    = $FakeInstallWinSSHOutputPSObj
    FakeInstallWinSSHOutputService  = $FakeInstallWinSSHOutputService
}

InModuleScope WinSSH {
    Describe "Test Install-WinSSH" {
        Context "Non-Elevated PowerShell Session" {
            # IMPORTANT NOTE: Any functions that you'd like the 'it' blocks to use should be written in the 'Context' scope HERE!
            $global:MockResources['Functions'] | foreach { Invoke-Expression $_ }

            Mock 'GetElevation' -MockWith {$False}

            It "Should Throw An Error" {
                $Splat = @{
                    GiveWinSSHBinariesPathPriority  = $True
                    OutVariable                     = "InstallWinSSHResultShouldNotExist"
                }

                {Install-WinSSH @Splat} | Assert-Throw

                if ($InstallWinSSHResultShouldNotExist) {
                    Cleanup -ErrorAction SilentlyContinue
                }
            }
        }

        $i = 0
        foreach ($Series in $global:MockResources['SplatParamsSeries']) {
            $ContextSBPrep = @(
                "`$ContextInfo = `$global:MockResources['SplatParamsSeries'][$i].TestSeriesName"
                '$global:ContextStringBuilder = "Elevated PowerShell Session w/ $ContextInfo"'
                'Context $global:ContextStringBuilder {'
                '    $global:MockResources["Functions"] | foreach { Invoke-Expression $_ }'
                '    Mock "GetElevation" -MockWith {$True}'
                "    StartTesting -SplatParamsSeriesItem `$global:MockResources['SplatParamsSeries'][$i] -ContextString `$global:ContextStringBuilder"
                '}'
            )
            $ContextSB = [scriptblock]::Create($($ContextSBPrep -join "`n"))
            $ContextSB.InvokeReturnAsIs()
            $i++
        }
    }
}



# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUYPZYEEdBvdTLrxg+7Zkn2FB6
# XeGgggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFEkhqHzMhkmj3YvG
# oQqqIXFxS0mgMA0GCSqGSIb3DQEBAQUABIIBAABqCpmCJMVCQet4odUnJfOGOd40
# so/susgJTFHvvKkdDKKwq7GcHfvT9IKh5bd3jU7EkB/e1O9XxyS79s8LX/GoLIMo
# Z/ZnOa21vohHge0Km8kkA0K/rLNhms/CfBaOTidjOopNZ2rkDyjYPhgWvicuTuvw
# Yp7dkPVFnDGQOB4vRhxbRJqv4UVseNhGQ/1XXn7v4vudVGxpr53SOOjuQ0zR/cTJ
# 5YE0qGPgHaCuwtCK4OGkhhGtCJ3Dfby5PvGXQpjPRFVz5n8y2wnOlitJQdo7W/03
# mIDn1QnlBbKpdkNBDRW8pDCgPfa539G11+g33D4nFdqTPNMHXvKOjI1H7+Y=
# SIG # End signature block
