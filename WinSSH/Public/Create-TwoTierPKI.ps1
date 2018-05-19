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

        [Parameter(Mandatory=$False)]
        [string]$PrimaryDCLocation,

        [Parameter(Mandatory=$True)]
        [pscredential]$DomainAdminCredentials,

        [Parameter(Mandatory=$True)]
        [pscredential]$LocalAdminCredentials,

        [Parameter(Mandatory=$False)]
        [string]$CertDownloadDirectory = "$HOME\Downloads\DSCEncryptionCertsForCAServers"
    )

    # IMPORTANT NOTE: Throughout this script, 'RootCA' refers to the HostName of the Standalone Root CA Server and
    # 'SubCA' refers to the HostName of the Enterprise Subordinate CA Server. If the HostNames of $IPofServerToBeRootCA
    # and/or $IPofServerToBeSubCA do not match $RootCAHostName and $SubCAHostName below, they will be changed.
    $RootCAHostName = "RootCA"
    $SubCAHostName = "SubCA"

    #region >> Helper Functions
    
    function Test-IsValidIPAddress([string]$IPAddress) {
        [boolean]$Octets = (($IPAddress.Split(".")).Count -eq 4) 
        [boolean]$Valid  =  ($IPAddress -as [ipaddress]) -as [boolean]
        Return  ($Valid -and $Octets)
    }

    function Resolve-Host {
        [CmdletBinding()]
        Param(
            [Parameter(Mandatory=$True)]
            [string]$HostNameOrIP
        )
    
        ##### BEGIN Main Body #####
    
        $RemoteHostNetworkInfoArray = @()
        if (!$(Test-IsValidIPAddress -IPAddress $HostNameOrIP)) {
            try {
                $HostNamePrep = $HostNameOrIP
                [System.Collections.ArrayList]$RemoteHostArrayOfIPAddresses = @()
                $IPv4AddressFamily = "InterNetwork"
                $IPv6AddressFamily = "InterNetworkV6"
    
                $ResolutionInfo = [System.Net.Dns]::GetHostEntry($HostNamePrep)
                $ResolutionInfo.AddressList | Where-Object {
                    $_.AddressFamily -eq $IPv4AddressFamily
                } | foreach {
                    if ($RemoteHostArrayOfIPAddresses -notcontains $_.IPAddressToString) {
                        $null = $RemoteHostArrayOfIPAddresses.Add($_.IPAddressToString)
                    }
                }
            }
            catch {
                Write-Verbose "Unable to resolve $HostNameOrIP when treated as a Host Name (as opposed to IP Address)!"
            }
        }
        if (Test-IsValidIPAddress -IPAddress $HostNameOrIP) {
            try {
                $HostIPPrep = $HostNameOrIP
                [System.Collections.ArrayList]$RemoteHostArrayOfIPAddresses = @()
                $null = $RemoteHostArrayOfIPAddresses.Add($HostIPPrep)
    
                $ResolutionInfo = [System.Net.Dns]::GetHostEntry($HostIPPrep)
    
                [System.Collections.ArrayList]$RemoteHostFQDNs = @() 
                $null = $RemoteHostFQDNs.Add($ResolutionInfo.HostName)
            }
            catch {
                Write-Verbose "Unable to resolve $HostNameOrIP when treated as an IP Address (as opposed to Host Name)!"
            }
        }
    
        if ($RemoteHostArrayOfIPAddresses.Count -eq 0) {
            Write-Error "Unable to determine IP Address of $HostNameOrIP! Halting!"
            $global:FunctionResult = "1"
            return
        }
    
        # At this point, we have $RemoteHostArrayOfIPAddresses...
        [System.Collections.ArrayList]$RemoteHostFQDNs = @()
        foreach ($HostIP in $RemoteHostArrayOfIPAddresses) {
            try {
                $FQDNPrep = [System.Net.Dns]::GetHostEntry($HostIP).HostName
            }
            catch {
                Write-Verbose "Unable to resolve $HostIP. No PTR Record? Please check your DNS config."
                continue
            }
            if ($RemoteHostFQDNs -notcontains $FQDNPrep) {
                $null = $RemoteHostFQDNs.Add($FQDNPrep)
            }
        }
    
        if ($RemoteHostFQDNs.Count -eq 0) {
            $null = $RemoteHostFQDNs.Add($ResolutionInfo.HostName)
        }
    
        [System.Collections.ArrayList]$HostNameList = @()
        [System.Collections.ArrayList]$DomainList = @()
        foreach ($fqdn in $RemoteHostFQDNs) {
            $PeriodCheck = $($fqdn | Select-String -Pattern "\.").Matches.Success
            if ($PeriodCheck) {
                $HostName = $($fqdn -split "\.")[0]
                $Domain = $($fqdn -split "\.")[1..$($($fqdn -split "\.").Count-1)] -join '.'
            }
            else {
                $HostName = $fqdn
                $Domain = "Unknown"
            }
    
            $null = $HostNameList.Add($HostName)
            $null = $DomainList.Add($Domain)
        }
    
        if ($RemoteHostFQDNs[0] -eq $null -and $HostNameList[0] -eq $null -and $DomainList -eq "Unknown" -and $RemoteHostArrayOfIPAddresses) {
            [System.Collections.ArrayList]$SuccessfullyPingedIPs = @()
            # Test to see if we can reach the IP Addresses
            foreach ($ip in $RemoteHostArrayOfIPAddresses) {
                if ([bool]$(Test-Connection $ip -Count 1 -ErrorAction SilentlyContinue)) {
                    $null = $SuccessfullyPingedIPs.Add($ip)
                }
            }
    
            if ($SuccessfullyPingedIPs.Count -eq 0) {
                Write-Error "Unable to resolve $HostNameOrIP! Halting!"
                $global:FunctionResult = "1"
                return
            }
        }
    
        $FQDNPrep = if ($RemoteHostFQDNs) {$RemoteHostFQDNs[0]} else {$null}
        if ($FQDNPrep -match ',') {
            $FQDN = $($FQDNPrep -split ',')[0]
        }
        else {
            $FQDN = $FQDNPrep
        }
    
        $DomainPrep = if ($DomainList) {$DomainList[0]} else {$null}
        if ($DomainPrep -match ',') {
            $Domain = $($DomainPrep -split ',')[0]
        }
        else {
            $Domain = $DomainPrep
        }
    
        [pscustomobject]@{
            IPAddressList   = [System.Collections.ArrayList]@($(if ($SuccessfullyPingedIPs) {$SuccessfullyPingedIPs} else {$RemoteHostArrayOfIPAddresses}))
            FQDN            = $FQDN
            HostName        = if ($HostNameList) {$HostNameList[0].ToLowerInvariant()} else {$null}
            Domain          = $Domain
        }
    
        ##### END Main Body #####
    
    }

    function Get-DomainController {
        [CmdletBinding()]
        Param (
            [Parameter(Mandatory=$False)]
            [String]$Domain
        )
    
        ##### BEGIN Helper Functions #####
    
        function Parse-NLTest {
            [CmdletBinding()]
            Param (
                [Parameter(Mandatory=$True)]
                [string]$Domain
            )
    
            while ($Domain -notmatch "\.") {
                Write-Warning "The provided value for the -Domain parameter is not in the correct format. Please use the entire domain name (including periods)."
                $Domain = Read-Host -Prompt "Please enter the full domain name (including periods)"
            }
    
            if (![bool]$(Get-Command nltest -ErrorAction SilentlyContinue)) {
                Write-Error "Unable to find nltest.exe! Halting!"
                $global:FunctionResult = "1"
                return
            }
    
            $DomainPrefix = $($Domain -split '\.')[0]
            $PrimaryDomainControllerPrep = Invoke-Expression "nltest /dclist:$DomainPrefix 2>null"
            if (![bool]$($PrimaryDomainControllerPrep | Select-String -Pattern 'PDC')) {
                Write-Error "Can't find the Primary Domain Controller for domain $DomainPrefix"
                return
            }
            $PrimaryDomainControllerPrep = $($($PrimaryDomainControllerPrep -match 'PDC').Trim() -split ' ')[0]
            if ($PrimaryDomainControllerPrep -match '\\\\') {
                $PrimaryDomainController = $($PrimaryDomainControllerPrep -replace '\\\\','').ToLower() + ".$Domain"
            }
            else {
                $PrimaryDomainController = $PrimaryDomainControllerPrep.ToLower() + ".$Domain"
            }
    
            $PrimaryDomainController
        }
    
        ##### END Helper Functions #####
    
    
        ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####
    
        $ComputerSystemCim = Get-CimInstance Win32_ComputerSystem
        $PartOfDomain = $ComputerSystemCim.PartOfDomain
    
        ##### END Variable/Parameter Transforms and PreRun Prep #####
    
    
        ##### BEGIN Main Body #####
    
        if (!$PartOfDomain -and !$Domain) {
            Write-Error "$env:ComputerName is NOT part of a Domain and the -Domain parameter was not used in order to specify a domain! Halting!"
            $global:FunctionResult = "1"
            return
        }
        
        $ThisMachinesDomain = $ComputerSystemCim.Domain
    
        if ($Domain) {
            try {
                $Forest = [system.directoryservices.activedirectory.Forest]::GetCurrentForest()
            }
            catch {
                Write-Verbose "Cannot connect to current forest."
            }
    
            if ($ThisMachinesDomain -eq $Domain -and $Forest.Domains -contains $Domain) {
                [System.Collections.ArrayList]$FoundDomainControllers = $Forest.Domains | Where-Object {$_.Name -eq $Domain} | foreach {$_.DomainControllers} | foreach {$_.Name}
                $PrimaryDomainController = $Forest.Domains.PdcRoleOwner.Name
            }
            if ($ThisMachinesDomain -eq $Domain -and $Forest.Domains -notcontains $Domain) {
                try {
                    $GetCurrentDomain = [system.directoryservices.activedirectory.domain]::GetCurrentDomain()
                    [System.Collections.ArrayList]$FoundDomainControllers = $GetCurrentDomain | foreach {$_.DomainControllers} | foreach {$_.Name}
                    $PrimaryDomainController = $GetCurrentDomain.PdcRoleOwner.Name
                }
                catch {
                    try {
                        Write-Warning "Only able to report the Primary Domain Controller for $Domain! Other Domain Controllers most likely exist!"
                        Write-Warning "For a more complete list, try running this function on a machine that is part of the domain $Domain!"
                        $PrimaryDomainController = Parse-NLTest -Domain $Domain
                        [System.Collections.ArrayList]$FoundDomainControllers = @($PrimaryDomainController)
                    }
                    catch {
                        Write-Error $_
                        $global:FunctionResult = "1"
                        return
                    }
                }
            }
            if ($ThisMachinesDomain -ne $Domain -and $Forest.Domains -contains $Domain) {
                [System.Collections.ArrayList]$FoundDomainControllers = $Forest.Domains | foreach {$_.DomainControllers} | foreach {$_.Name}
                $PrimaryDomainController = $Forest.Domains.PdcRoleOwner.Name
            }
            if ($ThisMachinesDomain -ne $Domain -and $Forest.Domains -notcontains $Domain) {
                try {
                    Write-Warning "Only able to report the Primary Domain Controller for $Domain! Other Domain Controllers most likely exist!"
                    Write-Warning "For a more complete list, try running this function on a machine that is part of the domain $Domain!"
                    $PrimaryDomainController = Parse-NLTest -Domain $Domain
                    [System.Collections.ArrayList]$FoundDomainControllers = @($PrimaryDomainController)
                }
                catch {
                    Write-Error $_
                    $global:FunctionResult = "1"
                    return
                }
            }
        }
        else {
            try {
                $Forest = [system.directoryservices.activedirectory.Forest]::GetCurrentForest()
                [System.Collections.ArrayList]$FoundDomainControllers = $Forest.Domains | foreach {$_.DomainControllers} | foreach {$_.Name}
                $PrimaryDomainController = $Forest.Domains.PdcRoleOwner.Name
            }
            catch {
                Write-Verbose "Cannot connect to current forest."
    
                try {
                    $GetCurrentDomain = [system.directoryservices.activedirectory.domain]::GetCurrentDomain()
                    [System.Collections.ArrayList]$FoundDomainControllers = $GetCurrentDomain | foreach {$_.DomainControllers} | foreach {$_.Name}
                    $PrimaryDomainController = $GetCurrentDomain.PdcRoleOwner.Name
                }
                catch {
                    $Domain = $ThisMachinesDomain
    
                    try {
                        $CurrentUser = "$(whoami)"
                        Write-Warning "Only able to report the Primary Domain Controller for the domain that $env:ComputerName is joined to (i.e. $Domain)! Other Domain Controllers most likely exist!"
                        Write-Host "For a more complete list, try one of the following:" -ForegroundColor Yellow
                        if ($($CurrentUser -split '\\') -eq $env:ComputerName) {
                            Write-Host "- Try logging into $env:ComputerName with a domain account (as opposed to the current local account $CurrentUser" -ForegroundColor Yellow
                        }
                        Write-Host "- Try using the -Domain parameter" -ForegroundColor Yellow
                        Write-Host "- Run this function on a computer that is joined to the Domain you are interested in" -ForegroundColor Yellow
                        $PrimaryDomainController = Parse-NLTest -Domain $Domain
                        [System.Collections.ArrayList]$FoundDomainControllers = @($PrimaryDomainController)
                    }
                    catch {
                        Write-Error $_
                        $global:FunctionResult = "1"
                        return
                    }
                }
            }
        }
    
        [pscustomobject]@{
            FoundDomainControllers      = $FoundDomainControllers
            PrimaryDomainController     = $PrimaryDomainController
        }
    
        ##### END Main Body #####
    }

    #endregion >> Helper Functions

    # Make sure we can resolve $DomainToJoin
    if (![bool]$(Resolve-DnsName $DomainToJoin -ErrorAction SilentlyContinue)) {
        Write-Error "Unable to resolve Domain '$DomainToJoin'! Check DNS. Halting!"
        $global:FunctionResult = "1"
        return
    }

    # Locate the Primary Domain Controller
    if (!$PrimaryDCLocation) {
        try {
            $DomainControllerInfo = Get-DomainController -Domain $DomainToJoin
            $PrimaryDCFQDN = $DomainControllerInfo.PrimaryDomainController
            if (!$DomainControllerInfo -or $DomainControllerInfo.FoundDomainControllers.Count -eq 0) {
                throw "The Get-DomainController function did not return any information!"
            }
        }
        catch {
            Write-Error $_
            Write-Error "Unable to find the Primary Domain Controller for domain '$DomainToJoin'! Halting!"
            $global:FunctionResult = "1"
            return
        }
    }
    else {
        try {
            $DomainControllerNetworkInfo = Resolve-Host -HostNameOrIP $PrimaryDCLocation
            $PrimaryDCFQDN = "$($DomainControllerNetworkInfo.HostName).$DomainToJoin"
            if (!$PrimaryDCFQDN) {throw "Unable to Resolve-Host '$PrimaryDCLocation'! Halting!"}
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            return
        }
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
            VMName                  = $RootCAHostName
            VMDestinationDirectory  = "E:\VMs"
        }
        $DeployRootCABoxResult = Deploy-HyperVVagrantBoxManually @DeployRootCABoxSplatParams

        $DeploySubCABoxSplatParams = @{
            VagrantBox              = $Windows2016VagrantBox
            BoxFilePath             = $DeployRootCABoxResult.BoxFileLocation
            CPUs                    = 2
            Memory                  = 2048
            VagrantProvider         = "hyperv"
            VMName                  = $SubCAHostName
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
            HostName    = $RootCAHostName
            IPAddress   = $IPofServerToBeRootCA
        }
        [pscustomobject]@{
            HostName    = $SubCAHostName
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
            Write-Error "Problem creating PSSession To$($PSObj.HostName)! Halting!"
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

                # Setup WinRM
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

                $DSCEncryptionCACertInfo = Get-DSCEncryptionCert -MachineName $($using:PSObj.HostName) -ExportDirectory $using:RemoteDSCDir

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
                            CertificateId = $DSCEncryptionCACertInfo.CertInfo.Thumbprint
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

                # Apply the .meta.mof (i.e. LCM Settings)
                $null = Set-DscLocalConfigurationManager -Path $using:RemoteDSCDir -Force

                # Output the DSC Encryption Certificate Info
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

    #region >> Apply the DSC Configurations to the CA Servers

    # Get the specific versions of the DSC Modules. This is required due to an issue with the 'Import-DSCResource'
    # cmdlet if more than one version of the DSC Module Module is installed.
    $PSDSCVersion = $(Get-Module -ListAvailable -Name PSDesiredStateConfiguration).Version[-1].ToString()
    $xPSDSCVersion = $(Get-Module -ListAvailable -Name xPSDesiredStateConfiguration).Version[-1].ToString()
    $ComputerManagementDscVersion = $(Get-Module -ListAvailable -Name ComputerManagementDsc).Version[-1].ToString()
    $xAdcsDeploymentVersion = $(Get-Module -ListAvailable -Name xAdcsDeployment).Version[-1].ToString()
    $xNetworkingVersion = $(Get-Module -ListAvailable -Name xNetworking).Version[-1].ToString()

    #region >> Standalone Root CA Config

    # The below commented config info is loaded in the Invoke-Command ScriptBlock, but is also commented out here
    # so that it's easier to review $StandaloneRootCAConfigAsStringPrep
    <#
    $DomainName = $DomainToJoin
    $DomainLDAPString = $(foreach ($Part in $($DomainName -split "\.")) {"DC=$($Part.ToUpper())"}) -join ','
    $StandaloneRootCAConfigData = @{
        AllNodes = @(
            @{
                NodeName = "localhost"
                HostName = $using:RootCAHostName
                DomainToJoin = $DomainName
                DomainName = $DomainName
                CertificateFile = $($using:CAServerInfo | Where-Object {$_.HostName -eq $using:RootCAHostName}).CertProperties.CertFile.FullName
                Thumbprint = $($using:CAServerInfo | Where-Object {$_.HostName -eq $using:RootCAHostName}).CertProperties.CertInfo.Thumbprint
                CACommonName = "$DomainName Root CA"
                CADistinguishedNameSuffix = $DomainLDAPString
                CRLPublicationURLs = "1:C:\Windows\system32\CertSrv\CertEnroll\%3%8%9.crl\n10:ldap:///CN=%7%8,CN=%2,CN=CDP,CN=Public Key Services,CN=Services,%6%10\n2:http://pki.$DomainName/CertEnroll/%3%8%9.crl"
                CACertPublicationURLs = "1:C:\Windows\system32\CertSrv\CertEnroll\%1_%3%4.crt\n2:ldap:///CN=%7,CN=AIA,CN=Public Key Services,CN=Services,%6%11\n2:http://pki.$DomainName/CertEnroll/%1_%3%4.crt"
                CRLPeriodUnits = 52
                CRLPeriod = 'Weeks'
                CRLOverlapUnits = 12
                CRLOverlapPeriod = 'Hours'
                ValidityPeriodUnits = 10
                ValidityPeriod = 'Years'
                AuditFilter = 127
                SubCAs = @('SubCA')
            }
        )
    }
    #>

    $StandaloneRootCAConfigAsStringPrep = @'
Configuration STANDALONE_ROOTCA {
    param (
        [Parameter(Mandatory=$True)]
        [pscredential]$DomainAdminCredentials,

        [Parameter(Mandatory=$True)]
        [pscredential]$LocalAdminCredentials
    )

'@ + @"

    Import-DscResource -ModuleName PSDesiredStateConfiguration -ModuleVersion $PSDSCVersion
    Import-DscResource -ModuleName xAdcsDeployment -ModuleVersion $xAdcsDeploymentVersion
    Import-DscResource -ModuleName xPSDesiredStateConfiguration -ModuleVersion $xPSDSCVersion
    Import-DscResource -ModuleName ComputerManagementDsc -ModuleVersion $ComputerManagementDscVersion

"@ + @'

    Node $AllNodes.NodeName {
        # Join this Server to the Domain
        Computer JoinDomain
        {
            Name       = $Node.HostName
            DomainName = $Node.DomainToJoin
            Credential = $DomainAdminCredentials
        }

        # Install the ADCS Certificate Authority
        WindowsFeature ADCSCA
        {
            Name        = 'ADCS-Cert-Authority'
            Ensure      = 'Present'
            DependsOn   = '[Computer]JoinDomain'
        }

        # Install ADCS Web Enrollment - only required because it creates the CertEnroll virtual folder
        # Which we use to pass certificates to the Issuing/Sub CAs
        WindowsFeature ADCSWebEnrollment
        {
            Ensure    = 'Present'
            Name      = 'ADCS-Web-Enrollment'
            DependsOn = '[WindowsFeature]ADCSCA'
        }

        WindowsFeature InstallWebMgmtService
        {
            Ensure    = "Present"
            Name      = "Web-Mgmt-Service"
            DependsOn = '[WindowsFeature]ADCSWebEnrollment'
        }

        # Create the CAPolicy.inf file which defines basic properties about the ROOT CA certificate
        File CAPolicy
        {
            Ensure          = 'Present'
            DestinationPath = 'C:\Windows\CAPolicy.inf'
            Contents        = "[Version]`r`n Signature= `"$Windows NT$`"`r`n[Certsrv_Server]`r`n DiscreteSignatureAlgorithm=1`r`n HashAlgorithm=RSASHA256`r`n RenewalKeyLength=4096`r`n RenewalValidityPeriod=Years`r`n RenewalValidityPeriodUnits=20`r`n CRLDeltaPeriod=Days`r`n CRLDeltaPeriodUnits=0`r`n[CRLDistributionPoint]`r`n[AuthorityInformationAccess]`r`n"
            Type            = 'File'
            DependsOn       = '[WindowsFeature]ADCSCA'
        }

        # Configure the CA as Standalone Root CA
        xADCSCertificationAuthority ConfigCA
        {
            Ensure                    = 'Present'
            Credential                = $LocalAdminCredentials
            CAType                    = 'StandaloneRootCA'
            CACommonName              = $Node.CACommonName
            CADistinguishedNameSuffix = $Node.CADistinguishedNameSuffix
            ValidityPeriod            = 'Years'
            ValidityPeriodUnits       = 20
            CryptoProviderName        = 'RSA#Microsoft Software Key Storage Provider'
            HashAlgorithmName         = 'SHA256'
            KeyLength                 = 4096
            DependsOn                 = '[File]CAPolicy'
        }

        # Configure the ADCS Web Enrollment
        xADCSWebEnrollment ConfigWebEnrollment {
            Ensure           = 'Present'
            IsSingleInstance = 'Yes'
            CAConfig         = 'CertSrv'
            Credential       = $LocalAdminCredentials
            DependsOn        = '[xADCSCertificationAuthority]ConfigCA'
        }

        # Set the advanced CA properties
        Script ADCSAdvConfig
        {
            SetScript  = {
                if ($Using:Node.CADistinguishedNameSuffix)
                {
                    & "$($ENV:SystemRoot)\system32\certutil.exe" -setreg CA\DSConfigDN "CN=Configuration,$($Using:Node.CADistinguishedNameSuffix)"
                    & "$($ENV:SystemRoot)\system32\certutil.exe" -setreg CA\DSDomainDN "$($Using:Node.CADistinguishedNameSuffix)"
                }
                if ($Using:Node.CRLPublicationURLs)
                {
                    & "$($ENV:SystemRoot)\System32\certutil.exe" -setreg CA\CRLPublicationURLs $($Using:Node.CRLPublicationURLs)
                }
                if ($Using:Node.CACertPublicationURLs)
                {
                    & "$($ENV:SystemRoot)\System32\certutil.exe" -setreg CA\CACertPublicationURLs $($Using:Node.CACertPublicationURLs)
                }
                if ($Using:Node.CRLPeriodUnits)
                {
                    & "$($ENV:SystemRoot)\System32\certutil.exe" -setreg CA\CRLPeriodUnits $($Using:Node.CRLPeriodUnits)
                    & "$($ENV:SystemRoot)\System32\certutil.exe" -setreg CA\CRLPeriod "$($Using:Node.CRLPeriod)"
                }
                if ($Using:Node.CRLOverlapUnits)
                {
                    & "$($ENV:SystemRoot)\System32\certutil.exe" -setreg CA\CRLOverlapUnits $($Using:Node.CRLOverlapUnits)
                    & "$($ENV:SystemRoot)\System32\certutil.exe" -setreg CA\CRLOverlapPeriod "$($Using:Node.CRLOverlapPeriod)"
                }
                if ($Using:Node.ValidityPeriodUnits)
                {
                    & "$($ENV:SystemRoot)\System32\certutil.exe" -setreg CA\ValidityPeriodUnits $($Using:Node.ValidityPeriodUnits)
                    & "$($ENV:SystemRoot)\System32\certutil.exe" -setreg CA\ValidityPeriod "$($Using:Node.ValidityPeriod)"
                }
                if ($Using:Node.AuditFilter)
                {
                    & "$($ENV:SystemRoot)\System32\certutil.exe" -setreg CA\AuditFilter $($Using:Node.AuditFilter)
                }
                Restart-Service -Name CertSvc
'@ + @"

                Add-Content -Path '$RemoteDSCDir\certutil.log' -Value "Certificate Service Restarted ..."

"@ + @'

            }
            GetScript  = {
                Return @{
                    'DSConfigDN'            = (Get-ChildItem 'HKLM:\System\CurrentControlSet\Services\CertSvc\Configuration').GetValue('DSConfigDN');
                    'DSDomainDN'            = (Get-ChildItem 'HKLM:\System\CurrentControlSet\Services\CertSvc\Configuration').GetValue('DSDomainDN');
                    'CRLPublicationURLs'    = (Get-ChildItem 'HKLM:\System\CurrentControlSet\Services\CertSvc\Configuration').GetValue('CRLPublicationURLs');
                    'CACertPublicationURLs' = (Get-ChildItem 'HKLM:\System\CurrentControlSet\Services\CertSvc\Configuration').GetValue('CACertPublicationURLs')
                    'CRLPeriodUnits'        = (Get-ChildItem 'HKLM:\System\CurrentControlSet\Services\CertSvc\Configuration').GetValue('CRLPeriodUnits')
                    'CRLPeriod'             = (Get-ChildItem 'HKLM:\System\CurrentControlSet\Services\CertSvc\Configuration').GetValue('CRLPeriod')
                    'CRLOverlapUnits'       = (Get-ChildItem 'HKLM:\System\CurrentControlSet\Services\CertSvc\Configuration').GetValue('CRLOverlapUnits')
                    'CRLOverlapPeriod'      = (Get-ChildItem 'HKLM:\System\CurrentControlSet\Services\CertSvc\Configuration').GetValue('CRLOverlapPeriod')
                    'ValidityPeriodUnits'   = (Get-ChildItem 'HKLM:\System\CurrentControlSet\Services\CertSvc\Configuration').GetValue('ValidityPeriodUnits')
                    'ValidityPeriod'        = (Get-ChildItem 'HKLM:\System\CurrentControlSet\Services\CertSvc\Configuration').GetValue('ValidityPeriod')
                    'AuditFilter'           = (Get-ChildItem 'HKLM:\System\CurrentControlSet\Services\CertSvc\Configuration').GetValue('AuditFilter')
                }
            }
            TestScript = {
                if (((Get-ChildItem 'HKLM:\System\CurrentControlSet\Services\CertSvc\Configuration').GetValue('DSConfigDN') -ne "CN=Configuration,$($Using:Node.CADistinguishedNameSuffix)"))
                {
                    Return $False
                }
                if (((Get-ChildItem 'HKLM:\System\CurrentControlSet\Services\CertSvc\Configuration').GetValue('DSDomainDN') -ne "$($Using:Node.CADistinguishedNameSuffix)"))
                {
                    Return $False
                }
                if (($Using:Node.CRLPublicationURLs) -and ((Get-ChildItem 'HKLM:\System\CurrentControlSet\Services\CertSvc\Configuration').GetValue('CRLPublicationURLs') -ne $Using:Node.CRLPublicationURLs))
                {
                    Return $False
                }
                if (($Using:Node.CACertPublicationURLs) -and ((Get-ChildItem 'HKLM:\System\CurrentControlSet\Services\CertSvc\Configuration').GetValue('CACertPublicationURLs') -ne $Using:Node.CACertPublicationURLs))
                {
                    Return $False
                }
                if (($Using:Node.CRLPeriodUnits) -and ((Get-ChildItem 'HKLM:\System\CurrentControlSet\Services\CertSvc\Configuration').GetValue('CRLPeriodUnits') -ne $Using:Node.CRLPeriodUnits))
                {
                    Return $False
                }
                if (($Using:Node.CRLPeriod) -and ((Get-ChildItem 'HKLM:\System\CurrentControlSet\Services\CertSvc\Configuration').GetValue('CRLPeriod') -ne $Using:Node.CRLPeriod))
                {
                    Return $False
                }
                if (($Using:Node.CRLOverlapUnits) -and ((Get-ChildItem 'HKLM:\System\CurrentControlSet\Services\CertSvc\Configuration').GetValue('CRLOverlapUnits') -ne $Using:Node.CRLOverlapUnits))
                {
                    Return $False
                }
                if (($Using:Node.CRLOverlapPeriod) -and ((Get-ChildItem 'HKLM:\System\CurrentControlSet\Services\CertSvc\Configuration').GetValue('CRLOverlapPeriod') -ne $Using:Node.CRLOverlapPeriod))
                {
                    Return $False
                }
                if (($Using:Node.ValidityPeriodUnits) -and ((Get-ChildItem 'HKLM:\System\CurrentControlSet\Services\CertSvc\Configuration').GetValue('ValidityPeriodUnits') -ne $Using:Node.ValidityPeriodUnits))
                {
                    Return $False
                }
                if (($Using:Node.ValidityPeriod) -and ((Get-ChildItem 'HKLM:\System\CurrentControlSet\Services\CertSvc\Configuration').GetValue('ValidityPeriod') -ne $Using:Node.ValidityPeriod))
                {
                    Return $False
                }
                if (($Using:Node.AuditFilter) -and ((Get-ChildItem 'HKLM:\System\CurrentControlSet\Services\CertSvc\Configuration').GetValue('AuditFilter') -ne $Using:Node.AuditFilter))
                {
                    Return $False
                }
                Return $True
            }
            DependsOn  = '[xADCSWebEnrollment]ConfigWebEnrollment'
        }

        # Generate Issuing certificates for any SubCAs
        Foreach ($SubCA in $Node.SubCAs)
        {

            # Wait for SubCA to generate REQ
            WaitForAny "WaitForSubCA_$SubCA"
            {
                ResourceName     = '[xADCSCertificationAuthority]ConfigCA'
                NodeName         = $SubCA
                RetryIntervalSec = 30
                RetryCount       = 30
                DependsOn        = '[Script]ADCSAdvConfig'
            }

            # Download the REQ from the SubCA
            xRemoteFile "DownloadSubCA_$SubCA"
            {
                DestinationPath = "C:\Windows\System32\CertSrv\CertEnroll\$SubCA.req"
                Uri             = "http://$SubCA/CertEnroll/$SubCA.req"
                DependsOn       = "[WaitForAny]WaitForSubCA_$SubCA"
            }

            # Generate the Issuing Certificate from the REQ
            Script "IssueCert_$SubCA"
            {
                SetScript  = {
                    Write-Verbose -Message "Submitting C:\Windows\System32\CertSrv\CertEnroll\$Using:SubCA.req to $($Using:Node.CACommonName)"
                    [System.String]$RequestResult = & "$($ENV:SystemRoot)\System32\Certreq.exe" -Config ".\$($Using:Node.CACommonName)" -Submit "C:\Windows\System32\CertSrv\CertEnroll\$Using:SubCA.req"
                    $Matches = [Regex]::Match($RequestResult, 'RequestId:\s([0-9]*)')
                    if ($Matches.Groups.Count -lt 2)
                    {
                        Write-Verbose -Message "Error getting Request ID from SubCA certificate submission."
                        Throw "Error getting Request ID from SubCA certificate submission."
                    }
                    [int]$RequestId = $Matches.Groups[1].Value
                    Write-Verbose -Message "Issuing $RequestId in $($Using:Node.CACommonName)"
                    [System.String]$SubmitResult = & "$($ENV:SystemRoot)\System32\CertUtil.exe" -Resubmit $RequestId
                    if ($SubmitResult -notlike 'Certificate issued.*')
                    {
                        Write-Verbose -Message "Unexpected result issuing SubCA request."
                        Throw "Unexpected result issuing SubCA request."
                    }
                    Write-Verbose -Message "Retrieving C:\Windows\System32\CertSrv\CertEnroll\$Using:SubCA.req from $($Using:Node.CACommonName)"
                    [System.String]$RetrieveResult = & "$($ENV:SystemRoot)\System32\Certreq.exe" -Config ".\$($Using:Node.CACommonName)" -Retrieve $RequestId "C:\Windows\System32\CertSrv\CertEnroll\$Using:SubCA.crt"
                }
                GetScript  = {
                    Return @{
                        'Generated' = (Test-Path -Path "C:\Windows\System32\CertSrv\CertEnroll\$Using:SubCA.crt");
                    }
                }
                TestScript = {
                    if (-not (Test-Path -Path "C:\Windows\System32\CertSrv\CertEnroll\$Using:SubCA.crt"))
                    {
                        # SubCA Cert is not yet created
                        Return $False
                    }
                    # SubCA Cert has been created
                    Return $True
                }
                DependsOn  = "[xRemoteFile]DownloadSubCA_$SubCA"
            }

            # Wait for SubCA to install the CA Certificate
            WaitForAny "WaitForComplete_$SubCA"
            {
                ResourceName     = '[Script]InstallSubCACert'
                NodeName         = $SubCA
                RetryIntervalSec = 30
                RetryCount       = 30
                DependsOn        = "[Script]IssueCert_$SubCA"
            }

            # Shutdown the Root CA - it is no longer needed because it has issued all SubCAs
            Script ShutdownRootCA
            {
                SetScript  = {
                    Stop-Computer
                }
                GetScript  = {
                    Return @{
                    }
                }
                TestScript = {
                    # SubCA Cert is not yet created
                    Return $False
                }
                DependsOn  = "[WaitForAny]WaitForComplete_$SubCA"
            }
        }
    }
}
'@

    $StandaloneRootCAConfigAsString = [scriptblock]::Create($StandaloneRootCAConfigAsStringPrep).ToString()

    $RootCASB = {
        #### Apply the DSC Configuration ####
        # Load the STANDALONE_ROOTCA DSC Configuration function
        $using:StandaloneRootCAConfigAsString | Invoke-Expression

        # IMPORTANT NOTE: In the below $StandaloneRootCAConfigData 'Name' refers to the desired HostName to be used by
        # the ComputerManagementDSC Module (i.e. the HostName will be changed if it doesn't match)
        $DomainName = $using:DomainToJoin
        $DomainLDAPString = $(foreach ($Part in $($DomainName -split "\.")) {"DC=$($Part.ToUpper())"}) -join ','
        $StandaloneRootCAConfigData = @{
            AllNodes = @(
                @{
                    NodeName = "localhost"
                    HostName = $using:RootCAHostName
                    DomainToJoin = $DomainName
                    DomainName = $DomainName
                    CertificateFile = $($using:CAServerInfo | Where-Object {$_.HostName -eq $using:RootCAHostName}).CertProperties.CertFile.FullName
                    Thumbprint = $($using:CAServerInfo | Where-Object {$_.HostName -eq $using:RootCAHostName}).CertProperties.CertInfo.Thumbprint
                    CACommonName = "$DomainName Root CA"
                    CADistinguishedNameSuffix = $DomainLDAPString
                    CRLPublicationURLs = "1:C:\Windows\system32\CertSrv\CertEnroll\%3%8%9.crl\n10:ldap:///CN=%7%8,CN=%2,CN=CDP,CN=Public Key Services,CN=Services,%6%10\n2:http://pki.$DomainName/CertEnroll/%3%8%9.crl"
                    CACertPublicationURLs = "1:C:\Windows\system32\CertSrv\CertEnroll\%1_%3%4.crt\n2:ldap:///CN=%7,CN=AIA,CN=Public Key Services,CN=Services,%6%11\n2:http://pki.$DomainName/CertEnroll/%1_%3%4.crt"
                    CRLPeriodUnits = 52
                    CRLPeriod = 'Weeks'
                    CRLOverlapUnits = 12
                    CRLOverlapPeriod = 'Hours'
                    ValidityPeriodUnits = 10
                    ValidityPeriod = 'Years'
                    AuditFilter = 127
                    SubCAs = @('SubCA')
                }
            )
        }
        # IMPORTANT NOTE: The resulting .mof file (representing the DSC configuration), will be in the
        # directory "$using:RemoteDSCDir\STANDALONE_ROOTCA"
        if (Test-Path "$using:RemoteDSCDir\$($using:RootCAHostName).mof") {
            Remove-Item "$using:RemoteDSCDir\$($using:RootCAHostName).mof" -Force
        }
        $StandaloneRootCAConfigSplatParams = @{
            DomainAdminCredentials      = $using:DomainAdminCredentials
            LocalAdminCredentials       = $using:LocalAdminCredentials
            OutputPath                  = $using:RemoteDSCDir
            ConfigurationData           = $StandaloneRootCAConfigData
        }
        $MOFFileItem = STANDALONE_ROOTCA @StandaloneRootCAConfigSplatParams
        if (!$MOFFileItem) {
            Write-Error "Problem creating the .mof file for $using:RootCAHostName!"
            return
        }

        # Make sure the .mof file is directly under $usingRemoteDSCDir alongside the encryption Cert
        if ($MOFFileItem.FullName -ne "$using:RemoteDSCDir\$($MOFFileItem.Name)") {
            Copy-Item -Path $MOFFileItem.FullName -Destination "$using:RemoteDSCDir\$($MOFFileItem.Name)" -Force
        }

        # Apply the .mof (i.e. setup the Root CA)
        Start-DscConfiguration -Path $using:RemoteDSCDir -Force
    }

    $RootCAPSSession = $($CAServerInfo | Where-Object {$_.HostName -eq $RootCAHostName}).PSSession
    Invoke-Command -Session $RootCAPSSession -ScriptBlock $RootCASB

    #endregion >> Standalone Root CA Config


    #region >> Enterprise Subordinate CA Config

    # The below commented config info is loaded in the Invoke-Command ScriptBlock, but is also commented out here
    # so that it's easier to review $StandaloneRootCAConfigAsStringPrep
    <#
    $DomainName = $using:DomainToJoin
    $DomainLDAPString = $(foreach ($Part in $($DomainName -split "\.")) {"DC=$($Part.ToUpper())"}) -join ','
    $EnterpriseSubCAConfigData = @{
        AllNodes = @(
            @{
                NodeName = "localhost"
                HostName = $using:SubCAHostName
                DomainToJoin = $DomainName
                DomainName = $DomainName
                CertificateFile = $($using:CAServerInfo | Where-Object {$_.HostName -eq $using:SubCAHostName}).CertProperties.CertFile.FullName
                Thumbprint = $($using:CAServerInfo | Where-Object {$_.HostName -eq $using:SubCAHostName}).CertProperties.CertInfo.Thumbprint
                DCName = $($using:PrimaryDCFQDN -split "\.")[0]
                DCFQDN = $using:PrimaryDCFQDN
                PSDscAllowDomainUser = $True
                InstallRSATTools = $True
                InstallOnlineResponder = $True
                InstallEnrollmentWebService = $True
                CACommonName = "$DomainName Issuing CA"
                CADistinguishedNameSuffix = $DomainLDAPString
                CRLPublicationURLs = "65:C:\Windows\system32\CertSrv\CertEnroll\%3%8%9.crl\n79:ldap:///CN=%7%8,CN=%2,CN=CDP,CN=Public Key Services,CN=Services,%6%10\n6:http://pki.$DomainName/CertEnroll/%3%8%9.crl"
                CACertPublicationURLs = "1:C:\Windows\system32\CertSrv\CertEnroll\%1_%3%4.crt\n2:ldap:///CN=%7,CN=AIA,CN=Public Key Services,CN=Services,%6%11\n2:http://pki.$DomainName/CertEnroll/%1_%3%4.crt"
                RootCAName = $using:RootCAHostName
                RootCAFQDN = "$using:RootCAHostName.$DomainName"
                RootCACommonName = "$DomainName Root CA"
            }
        )
    }
    #>

    $EnterpriseSubCAConfigAsStringPrep = @'
Configuration MEMBER_SUBCA {
    param (
        [Parameter(Mandatory=$True)]
        [pscredential]$DomainAdminCredentials,

        [Parameter(Mandatory=$True)]
        [pscredential]$LocalAdminCredentials
    )

'@ + @"

    Import-DscResource -ModuleName PSDesiredStateConfiguration -ModuleVersion $PSDSCVersion
    Import-DscResource -ModuleName xAdcsDeployment -ModuleVersion $xAdcsDeploymentVersion
    Import-DscResource -ModuleName xPSDesiredStateConfiguration -ModuleVersion $xPSDSCVersion
    Import-DscResource -ModuleName ComputerManagementDsc -ModuleVersion $ComputerManagementDscVersion
    Import-DscResource -ModuleName xNetworking -ModuleVersion $xNetworkingVersion

"@ + @'

    Node $AllNodes.NodeName {
        # Wait for the Domain to be available so we can join it.
        <#
        WaitForAll DC
        {
            ResourceName      = '[xADDomain]PrimaryDC'
            NodeName          = $Node.DCname
            RetryIntervalSec  = 15
            RetryCount        = 60
        }
        #>
        
        # Join this Server to the Domain
        Computer JoinDomain
        {
            Name       = $Node.HostName
            DomainName = $Node.DomainToJoin
            Credential = $DomainAdminCredentials
        }

        # Install the CA Service
        WindowsFeature ADCSCA {
            Name = 'ADCS-Cert-Authority'
            Ensure = 'Present'
            DependsOn = '[Computer]JoinDomain'
        }

        # Install the Web Enrollment Service
        WindowsFeature ADCSWebEnrollment {
            Name = 'ADCS-Web-Enrollment'
            Ensure = 'Present'
            DependsOn = "[WindowsFeature]ADCSCA"
        }

        WindowsFeature InstallWebMgmtService
        {
            Ensure = "Present"
            Name = "Web-Mgmt-Service"
            DependsOn = '[WindowsFeature]ADCSWebEnrollment'
        }

        if ($Node.InstallRSATTools)
        {
            WindowsFeature RSAT-ManagementTools
            {
                Ensure    = "Present"
                Name      = "RSAT-AD-Tools"
                DependsOn = "[WindowsFeature]ADCSCA"
            }
        }

        if ($Node.InstallOnlineResponder) {
            # Install the Online Responder Service
            WindowsFeature OnlineResponderCA {
                Name = 'ADCS-Online-Cert'
                Ensure = 'Present'
                DependsOn = "[WindowsFeature]ADCSCA"
            }
        }

        if ($Node.InstallEnrollmentWebService) {
            # Install the Enrollment Web Service/Enrollment Policy Web Service
            WindowsFeature EnrollmentWebSvc {
                Name = 'ADCS-Enroll-Web-Svc'
                Ensure = 'Present'
                DependsOn = "[WindowsFeature]ADCSCA"
            }

            WindowsFeature EnrollmentWebPol {
                Name = 'ADCS-Enroll-Web-Pol'
                Ensure = 'Present'
                DependsOn = "[WindowsFeature]ADCSWebEnrollment"
            }
        }

        # Create the CAPolicy.inf file that sets basic parameters for certificate issuance for this CA.
        File CAPolicy
        {
            Ensure = 'Present'
            DestinationPath = 'C:\Windows\CAPolicy.inf'
            Contents = "[Version]`r`n Signature= `"$Windows NT$`"`r`n[Certsrv_Server]`r`n RenewalKeyLength=2048`r`n RenewalValidityPeriod=Years`r`n RenewalValidityPeriodUnits=10`r`n LoadDefaultTemplates=1`r`n AlternateSignatureAlgorithm=1`r`n"
            Type = 'File'
            DependsOn = '[Computer]JoinDomain'
        }

        # Make a CertEnroll folder to put the Root CA certificate into.
        # The CA Web Enrollment server would also create this but we need it now.
        File CertEnrollFolder
        {
            Ensure = 'Present'
            DestinationPath = 'C:\Windows\System32\CertSrv\CertEnroll'
            Type = 'Directory'
            DependsOn = '[File]CAPolicy'
        }

        # Wait for the RootCA Web Enrollment to complete so we can grab the Root CA certificate
        # file.
        WaitForAny RootCA
        {
            ResourceName = '[xADCSWebEnrollment]ConfigWebEnrollment'
            NodeName = $Node.RootCAName
            RetryIntervalSec = 30
            RetryCount = 30
            DependsOn = "[File]CertEnrollFolder"
        }

        # Download the Root CA certificate file.
        xRemoteFile DownloadRootCACRTFile
        {
            DestinationPath = "C:\Windows\System32\CertSrv\CertEnroll\$($Node.RootCAName)_$($Node.RootCACommonName).crt"
            Uri = "http://$($Node.RootCAFQDN)/CertEnroll/$($Node.RootCAName)_$($Node.RootCACommonName).crt"
            DependsOn = '[WaitForAny]RootCA'
        }

        # Download the Root CA certificate revocation list.
        xRemoteFile DownloadRootCACRLFile
        {
            DestinationPath = "C:\Windows\System32\CertSrv\CertEnroll\$($Node.RootCACommonName).crl"
            Uri = "http://$($Node.RootCAFQDN)/CertEnroll/$($Node.RootCACommonName).crl"
            DependsOn = '[xRemoteFile]DownloadRootCACRTFile'
        }

        # Install the Root CA Certificate to the LocalMachine Root Store and DS
        Script InstallRootCACert
        {
            PSDSCRunAsCredential = $DomainAdminCredentials
            SetScript = {
                Write-Verbose -Message "Registering the Root CA Certificate C:\Windows\System32\CertSrv\CertEnroll\$($Using:Node.RootCAName)_$($Using:Node.RootCACommonName).crt in DS..."
                & "$($ENV:SystemRoot)\system32\certutil.exe" -f -dspublish "C:\Windows\System32\CertSrv\CertEnroll\$($Using:Node.RootCAName)_$($Using:Node.RootCACommonName).crt" RootCA
                Write-Verbose -Message "Registering the Root CA CRL C:\Windows\System32\CertSrv\CertEnroll\$($Node.RootCACommonName).crl in DS..."
                & "$($ENV:SystemRoot)\system32\certutil.exe" -f -dspublish "C:\Windows\System32\CertSrv\CertEnroll\$($Node.RootCACommonName).crl" "$($Using:Node.RootCAName)"
                Write-Verbose -Message "Installing the Root CA Certificate C:\Windows\System32\CertSrv\CertEnroll\$($Using:Node.RootCAName)_$($Using:Node.RootCACommonName).crt..."
                & "$($ENV:SystemRoot)\system32\certutil.exe" -addstore -f root "C:\Windows\System32\CertSrv\CertEnroll\$($Using:Node.RootCAName)_$($Using:Node.RootCACommonName).crt"
                Write-Verbose -Message "Installing the Root CA CRL C:\Windows\System32\CertSrv\CertEnroll\$($Node.RootCACommonName).crl..."
                & "$($ENV:SystemRoot)\system32\certutil.exe" -addstore -f root "C:\Windows\System32\CertSrv\CertEnroll\$($Node.RootCACommonName).crl"
            }
            GetScript = {
                Return @{
                    Installed = ((Get-ChildItem -Path Cert:\LocalMachine\Root | Where-Object -FilterScript { ($_.Subject -Like "CN=$($Using:Node.RootCACommonName),*") -and ($_.Issuer -Like "CN=$($Using:Node.RootCACommonName),*") } ).Count -EQ 0)
                }
            }
            TestScript = {
                if ((Get-ChildItem -Path Cert:\LocalMachine\Root | Where-Object -FilterScript { ($_.Subject -Like "CN=$($Using:Node.RootCACommonName),*") -and ($_.Issuer -Like "CN=$($Using:Node.RootCACommonName),*") } ).Count -EQ 0) {
                    Write-Verbose -Message "Root CA Certificate Needs to be installed..."
                    Return $False
                }
                Return $True
            }
            DependsOn = '[xRemoteFile]DownloadRootCACRTFile'
        }

        # Configure the Sub CA which will create the Certificate REQ file that Root CA will use
        # to issue a certificate for this Sub CA.
        xADCSCertificationAuthority ConfigCA
        {
            Ensure = 'Present'
            Credential = $DomainAdminCredentials
            CAType = 'EnterpriseSubordinateCA'
            CACommonName = $Node.CACommonName
            CADistinguishedNameSuffix = $Node.CADistinguishedNameSuffix
            OverwriteExistingCAinDS  = $True
            OutputCertRequestFile = "c:\windows\system32\certsrv\certenroll\$($Node.NodeName).req"
            CryptoProviderName = 'RSA#Microsoft Software Key Storage Provider'
            HashAlgorithmName = 'SHA256'
            KeyLength = 2048
            DependsOn = '[Script]InstallRootCACert'
        }

        # Configure the Web Enrollment Feature
        xADCSWebEnrollment ConfigWebEnrollment {
            Ensure = 'Present'
            IsSingleInstance = 'Yes'
            CAConfig = 'CertSrv'
            Credential = $LocalAdminCredentials
            DependsOn = '[xADCSCertificationAuthority]ConfigCA'
        }

        # Set the IIS Mime Type to allow the REQ request to be downloaded by the Root CA
        Script SetREQMimeType
        {
            SetScript = {
                Add-WebConfigurationProperty -PSPath IIS:\ -Filter //staticContent -Name "." -Value @{fileExtension='.req';mimeType='application/pkcs10'}
            }
            GetScript = {
                Return @{
                    'MimeType' = ((Get-WebConfigurationProperty -Filter "//staticContent/mimeMap[@fileExtension='.req']" -PSPath IIS:\ -Name *).mimeType);
                }
            }
            TestScript = {
                if (-not (Get-WebConfigurationProperty -Filter "//staticContent/mimeMap[@fileExtension='.req']" -PSPath IIS:\ -Name *)) {
                    # Mime type is not set
                    Return $False
                }
                # Mime Type is already set
                Return $True
            }
            DependsOn = '[xADCSWebEnrollment]ConfigWebEnrollment'
        }

        # Wait for the Root CA to have completed issuance of the certificate for this SubCA.
        WaitForAny SubCACer
        {
            ResourceName = "[Script]IssueCert_$($Node.NodeName)"
            NodeName = $Node.RootCAName
            RetryIntervalSec = 30
            RetryCount = 30
            DependsOn = "[Script]SetREQMimeType"
        }

        # Download the Certificate for this SubCA but rename it so that it'll match the name expected by the CA
        xRemoteFile DownloadSubCACERFile
        {
            DestinationPath = "C:\Windows\System32\CertSrv\CertEnroll\$($Node.NodeName)_$($Node.CACommonName).crt"
            Uri = "http://$($Node.RootCAFQDN)/CertEnroll/$($Node.NodeName).crt"
            DependsOn = '[WaitForAny]SubCACer'
        }

        # Register the Sub CA Certificate with the Certification Authority
        Script RegisterSubCA
        {
            PSDSCRunAsCredential = $DomainAdminCredentials
            SetScript = {
                Write-Verbose -Message "Registering the Sub CA Certificate with the Certification Authority C:\Windows\System32\CertSrv\CertEnroll\$($Using:Node.NodeName)_$($Using:Node.CACommonName).crt..."
                & "$($ENV:SystemRoot)\system32\certutil.exe" -installCert "C:\Windows\System32\CertSrv\CertEnroll\$($Using:Node.NodeName)_$($Using:Node.CACommonName).crt"
            }
            GetScript = {
                Return @{
                }
            }
            TestScript = {
                if (-not (Get-ChildItem 'HKLM:\System\CurrentControlSet\Services\CertSvc\Configuration').GetValue('CACertHash')) {
                    Write-Verbose -Message "Sub CA Certificate needs to be registered with the Certification Authority..."
                    Return $False
                }
                Return $True
            }
            DependsOn = '[xRemoteFile]DownloadSubCACERFile'
        }

        # Perform final configuration of the CA which will cause the CA service to startup
        # It should be able to start up once the SubCA certificate has been installed.
        Script ADCSAdvConfig
        {
            SetScript = {
                if ($Using:Node.CADistinguishedNameSuffix) {
                    & "$($ENV:SystemRoot)\system32\certutil.exe" -setreg CA\DSConfigDN "CN=Configuration,$($Using:Node.CADistinguishedNameSuffix)"
                    & "$($ENV:SystemRoot)\system32\certutil.exe" -setreg CA\DSDomainDN "$($Using:Node.CADistinguishedNameSuffix)"
                }
                if ($Using:Node.CRLPublicationURLs) {
                    & "$($ENV:SystemRoot)\System32\certutil.exe" -setreg CA\CRLPublicationURLs $($Using:Node.CRLPublicationURLs)
                }
                if ($Using:Node.CACertPublicationURLs) {
                    & "$($ENV:SystemRoot)\System32\certutil.exe" -setreg CA\CACertPublicationURLs $($Using:Node.CACertPublicationURLs)
                }
                Restart-Service -Name CertSvc

'@ + @"

                Add-Content -Path '$RemoteDSCDir\certutil.log' -Value "Certificate Service Restarted ..."

"@ + @'

            }
            GetScript = {
                Return @{
                    'DSConfigDN' = (Get-ChildItem 'HKLM:\System\CurrentControlSet\Services\CertSvc\Configuration').GetValue('DSConfigDN');
                    'DSDomainDN' = (Get-ChildItem 'HKLM:\System\CurrentControlSet\Services\CertSvc\Configuration').GetValue('DSDomainDN');
                    'CRLPublicationURLs'  = (Get-ChildItem 'HKLM:\System\CurrentControlSet\Services\CertSvc\Configuration').GetValue('CRLPublicationURLs');
                    'CACertPublicationURLs'  = (Get-ChildItem 'HKLM:\System\CurrentControlSet\Services\CertSvc\Configuration').GetValue('CACertPublicationURLs')
                }
            }
            TestScript = {
                if (((Get-ChildItem 'HKLM:\System\CurrentControlSet\Services\CertSvc\Configuration').GetValue('DSConfigDN') -ne "CN=Configuration,$($Using:Node.CADistinguishedNameSuffix)")) {
                    Return $False
                }
                if (((Get-ChildItem 'HKLM:\System\CurrentControlSet\Services\CertSvc\Configuration').GetValue('DSDomainDN') -ne "$($Using:Node.CADistinguishedNameSuffix)")) {
                    Return $False
                }
                if (($Using:Node.CRLPublicationURLs) -and ((Get-ChildItem 'HKLM:\System\CurrentControlSet\Services\CertSvc\Configuration').GetValue('CRLPublicationURLs') -ne $Using:Node.CRLPublicationURLs)) {
                    Return $False
                }
                if (($Using:Node.CACertPublicationURLs) -and ((Get-ChildItem 'HKLM:\System\CurrentControlSet\Services\CertSvc\Configuration').GetValue('CACertPublicationURLs') -ne $Using:Node.CACertPublicationURLs)) {
                    Return $False
                }
                Return $True
            }
            DependsOn = '[Script]RegisterSubCA'
        }

        if ($Node.InstallOnlineResponder) {
            # Configure the Online Responder Feature
            xADCSOnlineResponder ConfigOnlineResponder {
                Ensure = 'Present'
                IsSingleInstance  = 'Yes'
                Credential = $LocalAdminCredentials
                DependsOn = '[Script]ADCSAdvConfig'
            }

            # Enable Online Responder FireWall rules so we can remote manage Online Responder
            xFirewall OnlineResponderFirewall1
            {
                Name = "Microsoft-Windows-OnlineRevocationServices-OcspSvc-DCOM-In"
                Enabled = "True"
                DependsOn = "[xADCSOnlineResponder]ConfigOnlineResponder"
            }

            xFirewall OnlineResponderFirewall2
            {
                Name = "Microsoft-Windows-CertificateServices-OcspSvc-RPC-TCP-In"
                Enabled = "True"
                DependsOn = "[xADCSOnlineResponder]ConfigOnlineResponder"
            }

            xFirewall OnlineResponderFirewall3
            {
                Name = "Microsoft-Windows-OnlineRevocationServices-OcspSvc-TCP-Out"
                Enabled = "True"
                DependsOn = "[xADCSOnlineResponder]ConfigOnlineResponder"
            }
        }
    }
}
'@

    $EnterpriseSubCAConfigAsString = [scriptblock]::Create($EnterpriseSubCAConfigAsStringPrep).ToString()

    $SubCASB = {
        #### Apply the DSC Configuration ####
        # Load the MEMBER_SUBCA DSC Configuration function
        $using:EnterpriseSubCAConfigAsString | Invoke-Expression

        # IMPORTANT NOTE: In the below $StandaloneRootCAConfigData 'Name' refers to the desired HostName to be used by
        # the ComputerManagementDSC Module (i.e. the HostName will be changed if it doesn't match)
        $DomainName = $using:DomainToJoin
        $DomainLDAPString = $(foreach ($Part in $($DomainName -split "\.")) {"DC=$($Part.ToUpper())"}) -join ','
        $EnterpriseSubCAConfigData = @{
            AllNodes = @(
                @{
                    NodeName = "localhost"
                    HostName = $using:SubCAHostName
                    DomainToJoin = $DomainName
                    DomainName = $DomainName
                    CertificateFile = $($using:CAServerInfo | Where-Object {$_.HostName -eq $using:SubCAHostName}).CertProperties.CertFile.FullName
                    Thumbprint = $($using:CAServerInfo | Where-Object {$_.HostName -eq $using:SubCAHostName}).CertProperties.CertInfo.Thumbprint
                    DCName = $($using:PrimaryDCFQDN -split "\.")[0]
                    DCFQDN = $using:PrimaryDCFQDN
                    PSDscAllowDomainUser = $True
                    InstallRSATTools = $True
                    InstallOnlineResponder = $True
                    InstallEnrollmentWebService = $True
                    CACommonName = "$DomainName Issuing CA"
                    CADistinguishedNameSuffix = $DomainLDAPString
                    CRLPublicationURLs = "65:C:\Windows\system32\CertSrv\CertEnroll\%3%8%9.crl\n79:ldap:///CN=%7%8,CN=%2,CN=CDP,CN=Public Key Services,CN=Services,%6%10\n6:http://pki.$DomainName/CertEnroll/%3%8%9.crl"
                    CACertPublicationURLs = "1:C:\Windows\system32\CertSrv\CertEnroll\%1_%3%4.crt\n2:ldap:///CN=%7,CN=AIA,CN=Public Key Services,CN=Services,%6%11\n2:http://pki.$DomainName/CertEnroll/%1_%3%4.crt"
                    RootCAName = $using:RootCAHostName
                    RootCAFQDN = "$using:RootCAHostName.$DomainName"
                    RootCACommonName = "$DomainName Root CA"
                }
            )
        }
        # IMPORTANT NOTE: The resulting .mof file (representing the DSC configuration), will be in the
        # directory "$using:RemoteDSCDir\MEMBER_SUBCA"
        if (Test-Path "$using:RemoteDSCDir\$($using:SubCAHostName).mof") {
            Remove-Item "$using:RemoteDSCDir\$($using:SubCAHostName).mof" -Force
        }
        $SubCAConfigSplatParams = @{
            DomainAdminCredentials      = $using:DomainAdminCredentials
            LocalAdminCredentials       = $using:LocalAdminCredentials
            OutputPath                  = $using:RemoteDSCDir
            ConfigurationData           = $EnterpriseSubCAConfigData
        }
        $MOFFileItem = MEMBER_SUBCA @SubCAConfigSplatParams
        if (!$MOFFileItem) {
            Write-Error "Problem creating the .mof file for $using:SubCAHostName!"
            return
        }

        # Make sure the .mof file is directly under $usingRemoteDSCDir alongside the encryption Cert
        if ($MOFFileItem.FullName -ne "$using:RemoteDSCDir\$($MOFFileItem.Name)") {
            Copy-Item -Path $MOFFileItem.FullName -Destination "$using:RemoteDSCDir\$($MOFFileItem.Name)" -Force
        }

        # Apply the .mof (i.e. setup the Root CA)
        Start-DscConfiguration -Path $using:RemoteDSCDir -Force
    }

    $SubCAPSSession = $($CAServerInfo | Where-Object {$_.HostName -eq $SubCAHostName}).PSSession
    Invoke-Command -Session $SubCAPSSession -ScriptBlock $SubCASB


    #endregion >> Enterprise Subordinate CA Config

    #region >> Monitor DNS to ensure that the Root and Subordinate CA Servers can find each other

    $Counter = 0
    while ($(![bool]$(Resolve-DNSName "$RootCAHostName.$DomainToJoin" -ErrorAction SilentlyContinue) -or 
    ![bool]$(Resolve-DNSName "$SubCAHostName.$DomainToJoin" -ErrorAction SilentlyContinue)) -and
    $Counter -le 5
    ) {
        Write-Host "Sleeping for 5 minutes to give '$RootCAHostName' and '$SubCAHostName' a chance to join the '$DomainToJoin' and update DNS records..."
        Start-Sleep -Seconds 300

        if ($Counter -eq 5) {
            # Make sure DNS is configured to find the new RootCA and SubCA Servers
            $ConfigureDNSSB = {
                if (!$(Get-DnsServerResourceRecord -ComputerName $env:ComputerName -ZoneName $using:DomainToJoin -Name $using:RootCAHostName)) {
                    Add-DnsServerResourceRecordA -ComputerName $env:ComputerName -Name $using:RootCAHostName -ZoneName $using:DomainToJoin -AllowUpdateAny -IPv4Address $using:IPofServerToBeRootCA
                }
                if (!$(Get-DnsServerResourceRecord -ComputerName $env:ComputerName -ZoneName $DomainToJoin -Name $SubCAHostName)) {
                    Add-DnsServerResourceRecordA -ComputerName $env:ComputerName -Name $using:SubCAHostName -ZoneName $using:DomainToJoin -AllowUpdateAny -IPv4Address $using:IPofServerToBeSubCA
                }
            }
            try {
                $null = Invoke-Command -ComputerName $PrimaryDCFQDN -Credential $DomainAdminCredentials -ScriptBlock $ConfigureDNSSB
            }
            catch {
                Write-Error $_
                Write-Error "Problem ensuring DNS is configured to resolve '$RootCAHostName' and '$SubCAHostName' on '$PrimaryDCFQDN'! Halting!"
                $global:FunctionResult = "1"
                return
            }
        }

        $Counter++
    }

    #endregion >> Monitor DNS to ensure that the Root and Subordinate CA Servers can find each other

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
    #Remove-PSSession -Name ToRootCA -ErrorAction SilentlyContinue
    #Remove-PSSession -Name ToSUbCA -ErrorAction SilentlyContinue

    Write-Host "Done" -ForegroundColor Green
}



# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUAx6+4JttSI3OrpiZjLS62rIA
# 0qygggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFEWsmWx3CidfUChm
# Nd6MzyY2IRDMMA0GCSqGSIb3DQEBAQUABIIBAGljw46YtOM60lDOAx9x1ro7WAp6
# BQjrNNlbC8HVDWvZWCFueZgT1b+cN6EZ2cqof4XcOYMKICxmP+Ttqt2NbE7yukkm
# SnLSVWwdUj0QYaM8YapcZwuuDOgImrmQJPlPGudfV7YSXB38i5xMKeGAJz9C+0Pk
# UPreiN13Fv4FL98O4IoW/F1LdnRMQrjqU+YDD702KuM36kHlKoffKEqPTpSoB3fT
# bU9gaJZ1a0uuyTzOYzSUL7pu3VHhbDijjMT6CcllLEVXPi8s1CfNtuaz6qEgQSTD
# t4TZUCH19PbxKmVCyb8ToYN3AOvxbHwErUDX/Ap2dW5/6YpsBU/IYK0oMis=
# SIG # End signature block
