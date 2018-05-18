function Create-TwoTierPKI {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$False)]
        [switch]$CreateNewVMs,

        [Parameter(Mandatory=$False)]
        [string]$IPofServerToBeRootCA,

        [Parameter(Mandatory=$False)]
        [string]$IPofServerToBeSubCA,

        [Parameter(Mandatory=$True)]
        [string]$DomainToJoin,

        [Parameter(Mandatory=$True)]
        [pscredential]$DomainAdminCredentials,

        [Parameter(Mandatory=$True)]
        [pscredential]$LocalAdminCredentials,

        [Parameter(Mandatory=$False)]
        [string]$CertDownloadDirectory = "$HOME\Downloads\DSCEncryptionCertsForCAServers"
    )

    #region >> Helper Functions
    
    function Test-IsValidIPAddress([string]$IPAddress) {
        [boolean]$Octets = (($IPAddress.Split(".")).Count -eq 4) 
        [boolean]$Valid  =  ($IPAddress -as [ipaddress]) -as [boolean]
        Return  ($Valid -and $Octets)
    }

    #endregion >> Helper Functions

    # Make sure we can resolve $DomainToJoin
    if (![bool]$(Resolve-DnsName $DomainToJoin -ErrorAction SilentlyContinue)) {
        Write-Error "Unable to resolve Domain '$DomainToJoin'! Check DNS. Halting!"
        $global:FunctionResult = "1"
        return
    }

    if (!$(Test-Path $CertDownloadDirectory)) {
        $null = New-Item -ItemType Directory -Path $CertDownloadDirectory
    }

    # Get the needed DSC Resources in preparation for copying them to the Remote Hosts
    $null = Install-PackageProvider -Name Nuget -Force -Confirm:$False
    $null = Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
    $NeededDSCResources = @(
        "ComputerManagementDsc"
        "xActiveDirectory"
        "xAdcsDeployment"
        "xPSDesiredStateConfiguration"
        "xNetworking"
    )
    [System.Collections.ArrayList]$FailedDSCResourceInstall = @()
    foreach ($DSCResource in $NeededDSCResources) {
        try {
            $null = Install-Module $DSCResource -ErrorAction Stop
        }
        catch {
            Write-Error $_
            $null = $FailedDSCResourceInstall.Add($DSCResource)
            continue
        }
    }
    if ($FailedDSCResourceInstall.Count -gt 0) {
        Write-Error "Problem installing the following DSC Modules:`n$($FailedDSCResourceInstall -join "`n")"
        $global:FunctionResult = "1"
        return
    }
    $DSCModulesToTransfer = foreach ($DSCResource in $NeededDSCResources) {
        $Module = Get-Module -ListAvailable $DSCResource
        "$($($Module.ModuleBase -split $DSCResource)[0])\$DSCResource"
    }

    # Create the new VMs if desired
    if ($CreateNewVMs) {
        $Windows2016VagrantBox = "StefanScherer/windows_2016"
        $DeployRootCABoxSplatParams = @{
            VagrantBox              = $Windows2016VagrantBox
            CPUs                    = 2
            Memory                  = 2048
            VagrantProvider         = "hyperv"
            VMName                  = "RootCA"
            VMDestinationDirectory  = "E:\VMs"
        }
        $DeployRootCABoxResult = Deploy-HyperVVagrantBoxManually @DeployRootCABoxSplatParams

        $DeploySubCABoxSplatParams = @{
            VagrantBox              = $Windows2016VagrantBox
            BoxFilePath             = $DeployRootCABoxResult.BoxFileLocation
            CPUs                    = 2
            Memory                  = 2048
            VagrantProvider         = "hyperv"
            VMName                  = "SubCA"
            VMDestinationDirectory  = "E:\VMs"
        }
        $DeploySubCABoxResult = Deploy-HyperVVagrantBoxManually @DeploySubCABoxSplatParams

        $IPofServerToBeRootCA = $DeployRootCABoxResult.VMIPAddress
        $IPofServerToBeSubCA = $DeploySubCABoxResult.VMIPAddress
    }

    if (!$CreateNewVMs) {
        if (!$IPofServerToBeRootCA) {
            $IPofServerToBeRootCA = Read-Host -Prompt "Please enter the IP Address of the Windows 2012R2/2016 Server that will become the Root CA"
        }
        if (!$IPofServerToBeSubCA) {
            $IPofServerToBeSubCA = Read-Host -Prompt "Please enter the IP Address of the Windows 2012R2/2016 Server that will become the Subordinate/Issuing CA"
        }

        while (!$(Test-IsValidIPAddress -IPAddress $IPofServerToBeRootCA)) {
            Write-Warning "The IP '$IPofServerToBeRootCA' is NOT a valid IP Address!"
            $IPofServerToBeRootCA = Read-Host -Prompt "Please enter the IP Address of the Windows 2012R2/2016 Server that will become the Root CA"
        }
        while (!$(Test-IsValidIPAddress -IPAddress $IPofServerToBeSubCA)) {
            Write-Warning "The IP '$IPofServerToBeSubCA' is NOT a valid IP Address!"
            $IPofServerToBeSubCA = Read-Host -Prompt "Please enter the IP Address of the Windows 2012R2/2016 Server that will become the Subordinate/Issuing CA"
        }
    }

    # Create PSObjects with IP and HostName info
    [System.Collections.ArrayList]$CAServerInfo = @(
        [pscustomobject]@{
            HostName    = "RootCA"
            IPAddress   = $IPofServerToBeRootCA
        }
        [pscustomobject]@{
            HostName    = "SubCA"
            IPAddress   = $IPofServerToBeSubCA
        }
    )

    # Make sure WinRM in Enabled and Running on $env:ComputerName
    try {
        $null = Enable-PSRemoting -Force -ErrorAction Stop
    }
    catch {
        $null = Get-NetConnectionProfile | Where-Object {$_.NetworkCategory -eq 'Public'} | Set-NetConnectionProfile -NetworkCategory 'Private'

        try {
            $null = Enable-PSRemoting -Force
        }
        catch {
            Write-Error $_
            Write-Error "Problem with Enabble-PSRemoting WinRM Quick Config! Halting!"
            $global:FunctionResult = "1"
            return
        }
    }

    # If $env:ComputerName is not part of a Domain, we need to add this registry entry to make sure WinRM works as expected
    if (!$(Get-CimInstance Win32_Computersystem).PartOfDomain) {
        $null = reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
    }

    # Add the New Server's IP Addresses to $env:ComputerName's TrustedHosts
    $CurrentTrustedHosts = $(Get-Item WSMan:\localhost\Client\TrustedHosts).Value
    [System.Collections.ArrayList][array]$CurrentTrustedHostsAsArray = $CurrentTrustedHosts -split ','

    $IPsToAddToWSMANTrustedHosts = @($IPofServerToBeRootCA,$IPofServerToBeSubCA)
    foreach ($IPAddr in $IPsToAddToWSMANTrustedHosts) {
        if ($CurrentTrustedHostsAsArray -notcontains $IPAddr) {
            $null = $CurrentTrustedHostsAsArray.Add($IPAddr)
        }
    }
    $UpdatedTrustedHostsString = $CurrentTrustedHostsAsArray -join ','
    Set-Item WSMan:\localhost\Client\TrustedHosts $UpdatedTrustedHostsString -Force

    # Create the WinRM Sessions...
    foreach ($PSObj in $CAServerInfo) {
        try {
            New-PSSession -ComputerName $PSObj.IPAddress -Credential $LocalAdminCredentials -Name "To$($PSObj.HostName)" -ErrorAction Stop
            $PSObj | Add-Member -Type NoteProperty -Name PSSession -Value $(Get-PSSession -Name "To$($PSObj.HostName)")
        }
        catch {
            Write-Error $_
            Write-Error "Problem creating PSSession "To$($PSObj.HostName)"! Halting!"
            $global:FunctionResult = "1"
            return
        }
    }

    # Prep the Remote Hosts for DSC Config
    $RemoteDSCDir = "C:\DSCConfigs"
    foreach ($PSObj in $CAServerInfo) {
        try {
            # Copy the DSC PowerShell Modules to the Remote Host
            $ProgramFilesPSModulePath = "C:\Program Files\WindowsPowerShell\Modules"
            foreach ($ModuleDirPath in $DSCModulesToTransfer) {
                Copy-Item -Path $ModuleDirPath -Recurse -Destination "$ProgramFilesPSModulePath\$($ModuleDirPath | Split-Path -Leaf)" -ToSession $PSObj.PSSession -Force
            }

            $FunctionsForRemoteUse = @(
                ${Function:Get-DSCEncryptionCert}.Ast.Extent.Text
                ${Function:New-SelfSignedCertificateEx}.Ast.Extent.Text
            )

            $DSCPrepSB = {
                # Load the functions we packed up:
                $using:FunctionsForRemoteUse | foreach { Invoke-Expression $_ }

                if (!$(Test-Path $using:RemoteDSCDir)) {
                    $null = New-Item -ItemType Directory -Path $using:RemoteDSCDir -Force
                }

                if ($($env:PSModulePath -split ";") -notcontains $using:ProgramFilesPSModulePath) {
                    $env:PSModulePath = $using:ProgramFilesPSModulePath + ";" + $env:PSModulePath
                }

                $DSCEncryptionCACertInfo = Get-DSCEncryptionCert -MachineName $($using:PSObj.HostName) -ExportDirectory $using:RemoteDSCDir
                $DSCEncryptionCACertInfo
            }

            $InvCmdResult = Invoke-Command -Session $PSObj.PSSession -ScriptBlock $DSCPrepSB
            $PSObj | Add-Member -Type NoteProperty -Name CertProperties -Value $InvCmdResult

            Copy-Item -Path "$RemoteDSCDir\DSCEncryption.cer" -Recurse -Destination $CertDownloadDirectory -FromSession $PSObj.PSSession -Force
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            return
        }
    }

    # Apply the DSC Configurations to the CA Servers
    $PSDSCVersion = $(Get-Module -ListAvailable -Name PSDesiredStateConfiguration).Version[-1].ToString()
    $ComputerManagementDscVersion = $(Get-Module -ListAvailable -Name ComputerManagementDsc).Version[-1].ToString()
    $GenJoinDomainConfigAsStringPrep = @'
Configuration GenerateJoinDomainConfig {
    param (
        [Parameter(Mandatory=$True)]
        [pscredential]$DomainAdminCredentials,

        [Parameter(Mandatory=$False)]
        [pscredential]$LocalAdminCredentials
    )

'@ + @"

    Import-DscResource -ModuleName PSDesiredStateConfiguration -ModuleVersion $PSDSCVersion
    Import-DscResource -ModuleName ComputerManagementDsc -ModuleVersion $ComputerManagementDscVersion

"@ + @'

    Node $AllNodes.NodeName {
        # Assemble the Local Admin Credentials
        if ($Node.LocalAdminPassword) {
            [PSCredential]$LocalAdminCredential = New-Object System.Management.Automation.PSCredential ("Administrator", (ConvertTo-SecureString $Node.LocalAdminPassword -AsPlainText -Force))
        }
        if ($Node.DomainAdminPassword) {
            [PSCredential]$DomainAdminCredential = New-Object System.Management.Automation.PSCredential ("$($Node.DomainName)\Administrator", (ConvertTo-SecureString $Node.DomainAdminPassword -AsPlainText -Force))
        }

        # Join this Server to the Domain
        Computer JoinDomain {
            Name       = $Node.HostName
            DomainName = $Node.DomainToJoin
            Credential = $DomainAdminCredentials
        }
    }
}
'@
    $GenJoinDomainConfigAsString = [scriptblock]::Create($GenJoinDomainConfigAsStringPrep).ToString()

    foreach ($PSObj in $CAServerInfo) {
        $JoinDomainSB = {
            #### Configure the Local Configuration Manager (LCM) ####
            if (Test-Path "$using:RemoteDSCDir\$($using:PSObj.HostName).meta.mof") {
                Remove-Item "$using:RemoteDSCDir\$($using:PSObj.HostName).meta.mof" -Force
            }
            Configuration LCMConfig {
                Node "localhost" {
                    LocalConfigurationManager {
                        ConfigurationMode = "ApplyAndAutoCorrect"
                        RefreshFrequencyMins = 30
                        ConfigurationModeFrequencyMins = 15
                        RefreshMode = "PUSH"
                        RebootNodeIfNeeded = $True
                        ActionAfterReboot = "ContinueConfiguration"
                        CertificateId = $using:PSObj.CertProperties.CertInfo.Thumbprint
                    }
                }
            }
            # Create the .meta.mof file
            $LCMMetaMOFFileItem = LCMConfig -OutputPath $using:RemoteDSCDir
            if (!$LCMMetaMOFFileItem) {
                Write-Error "Problem creating the .meta.mof file for $($using:PSObj.HostName)!"
                return
            }
            # Make sure the .mof file is directly under $usingRemoteDSCDir alongside the encryption Cert
            if ($LCMMetaMOFFileItem.FullName -ne "$using:RemoteDSCDir\$($LCMMetaMOFFileItem.Name)") {
                Copy-Item -Path $LCMMetaMOFFileItem.FullName -Destination "$using:RemoteDSCDir\$($LCMMetaMOFFileItem.Name)" -Force
            }
            
            #### Apply the DSC Configuration ####
            # Load the GenerateJoinDomainConfig DSC Configuration function
            $using:GenJoinDomainConfigAsString | Invoke-Expression

            # IMPORTANT NOTE: In the below $ConfigData 'Name' refers to the desired HostName (it will be changed if it doesn't match)
            $ConfigData = @{
                AllNodes = @(
                    @{
                        NodeName = "localhost"
                        HostName = $using:PSObj.HostName
                        DomainToJoin = $using:DomainToJoin
                        CertificateFile = $using:PSObj.CertProperties.CertFile.FullName
                        Thumbprint = $using:PSObj.CertProperties.CertInfo.Thumbprint
                    }
                )
            }
            # IMPORTANT NOTE: The resulting .mof file (representing the DSC configuration), will be in the
            # directory "$using:RemoteDSCDir\GenerateJoinDomainConfig"
            if (Test-Path "$using:RemoteDSCDir\$($using:PSObj.HostName).mof") {
                Remove-Item "$using:RemoteDSCDir\$($using:PSObj.HostName).mof" -Force
            }
            $GenJoinDomainConfigSplatParams = @{
                DomainAdminCredentials      = $using:DomainAdminCredentials
                OutputPath                  = $using:RemoteDSCDir
                ConfigurationData           = $ConfigData
            }
            $MOFFileItem = GenerateJoinDomainConfig @GenJoinDomainConfigSplatParams
            if (!$MOFFileItem) {
                Write-Error "Problem creating the .mof file for $($using:PSObj.HostName)!"
                return
            }

            # Make sure the .mof file is directly under $usingRemoteDSCDir alongside the encryption Cert
            if ($MOFFileItem.FullName -ne "$using:RemoteDSCDir\$($MOFFileItem.Name)") {
                Copy-Item -Path $MOFFileItem.FullName -Destination "$using:RemoteDSCDir\$($MOFFileItem.Name)" -Force
            }

            # Apply the .meta.mof (i.e. LCM Settings) and .mof (i.e. join $env:ComputerName to the Domain)
            Set-DscLocalConfigurationManager -Path $using:RemoteDSCDir -Force
            Start-DscConfiguration -Path $using:RemoteDSCDir -Force
        }

        Invoke-Command -Session $PSObj.PSSession -ScriptBlock $JoinDomainSB
    }

    <#
    Write-Host "Sleeping for 60 seconds..."
    Start-Sleep -Seconds 60

    while (!$CanReachRootAAndSubCA) {
        [System.Collections.ArrayList]$PingSuccess = @()
        foreach ($IPAddr in $IPsToAddToWSMANTrustedHosts) {
            $Ping = [System.Net.NetworkInformation.Ping]::new()
            $PingResult =$Ping.Send($IPAddr,1000)
            if ($PingResult.Status.ToString() -eq "Success") {
                $null = $PingSuccess.Add($IPAddr)
            }
        }

        if ($PingSuccess.Count -eq 2) {
            $CanReachRootAAndSubCA = $True
        }
        else {
            $CanReachRootAAndSubCA = $False
        }

        Write-Host "Can't reach RootCA or SubCA yet. Sleeping for 10 seconds..."
        Start-Sleep -Seconds 10
    }
    #>

    # Cleanup
    Remove-PSSession -Name ToRootCA -ErrorAction SilentlyContinue
    Remove-PSSession -Name ToSUbCA -ErrorAction SilentlyContinue

    Write-Host "Done" -ForegroundColor Green
}

# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUmQ/C2rr689d7djGjg0GZQ7ba
# i86gggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFJrcIq+rbJcd+Hrk
# GlzHl+T2LyhSMA0GCSqGSIb3DQEBAQUABIIBAHbdQVWBtrYrc/gxQJ7zuYUcuKjS
# 1fkUoCKpeSkIoeAonWNiX9Jq/MBee4WMyNKbf7rwNQDsZa/MyVs2dIf7LHSh9m3E
# G+sMvg9I1fVxw1gU5iG4Xw3uft0LwcMPWHTNeHv0ue9WCLVV4wrV50YEFVfr8NAJ
# 48WGRQfE816HDMvxxc2b3mGOS9AvVkgAUxza85Np10IdLOxU+QLOpQPpZ/KXkITF
# HRMDWTIZuiGnklOX6o0lGw135zXanpfJZ4vwc6eK3NOxNN8+D6hlcbwI/YU6d0OG
# PZATDflSSo9Jy7V1oRT2aP9kLDxg0ha1V3iPJ08lf1bkoWB/EMq9cQ27ys4=
# SIG # End signature block
