function New-SubordinateCA {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$True)]
        [string]$RootCAFQDN,

        [Parameter(Mandatory=$True)]
        [pscredential]$DomainAdminCredentials,

        [Parameter(Mandatory=$False)]
        [string]$SubCAFQDN,

        [Parameter(Mandatory=$False)]
        #[ValidateSet("EnterpriseRootCa","StandaloneRootCa")]
        [ValidateSet("EnterpriseRootCA")]
        [string]$CAType,

        [Parameter(Mandatory=$False)]
        [string]$NewComputerTemplateCommonName,

        [Parameter(Mandatory=$False)]
        [string]$NewWebServerTemplateCommonName,

        [Parameter(Mandatory=$False)]
        [string]$FileOutputDirectory,

        [Parameter(Mandatory=$False)]
        <#
        [ValidateSet("Microsoft Base Cryptographic Provider v1.0","Microsoft Base DSS and Diffie-Hellman Cryptographic Provider",
        "Microsoft Base DSS Cryptographic Provider","Microsoft Base Smart Card Crypto Provider",
        "Microsoft DH SChannel Cryptographic Provider","Microsoft Enhanced Cryptographic Provider v1.0",
        "Microsoft Enhanced DSS and Diffie-Hellman Cryptographic Provider",
        "Microsoft Enhanced RSA and AES Cryptographic Provider","Microsoft RSA SChannel Cryptographic Provider",
        "Microsoft Strong Cryptographic Provider","Microsoft Software Key Storage Provider",
        "Microsoft Passport Key Storage Provider")]
        #>
        [ValidateSet("Microsoft Software Key Storage Provider")]
        [string]$CryptoProvider,

        [Parameter(Mandatory=$False)]
        [ValidateSet("2048","4096")]
        [int]$KeyLength,

        [Parameter(Mandatory=$False)]
        [ValidateSet("SHA1","SHA256","SHA384","SHA512","MD5","MD4","MD2")]
        [string]$HashAlgorithm,

        # For now, stick to just using RSA
        [Parameter(Mandatory=$False)]
        #[ValidateSet("RSA","DH","DSA","ECDH_P256","ECDH_P521","ECDSA_P256","ECDSA_P384","ECDSA_P521")]
        [ValidateSet("RSA")]
        [string]$KeyAlgorithmValue,

        [Parameter(Mandatory=$False)]
        [ValidatePattern('http.*?\/<CaName><CRLNameSuffix>\.crl$')]
        [string]$CDPUrl,

        [Parameter(Mandatory=$False)]
        [ValidatePattern('http.*?\/<CaName><CertificateName>.crt$')]
        [string]$AIAUrl
    )

    #region >> Helper Functions

    function NewUniqueString {
        [CmdletBinding()]
        Param(
            [Parameter(Mandatory=$False)]
            [string[]]$ArrayOfStrings,
    
            [Parameter(Mandatory=$True)]
            [string]$PossibleNewUniqueString
        )
    
        if (!$ArrayOfStrings -or $ArrayOfStrings.Count -eq 0 -or ![bool]$($ArrayOfStrings -match "[\w]")) {
            $PossibleNewUniqueString
        }
        else {
            $OriginalString = $PossibleNewUniqueString
            $Iteration = 1
            while ($ArrayOfStrings -contains $PossibleNewUniqueString) {
                $AppendedValue = "_$Iteration"
                $PossibleNewUniqueString = $OriginalString + $AppendedValue
                $Iteration++
            }
    
            $PossibleNewUniqueString
        }
    }

    function TestIsValidIPAddress([string]$IPAddress) {
        [boolean]$Octets = (($IPAddress.Split(".") | Measure-Object).Count -eq 4) 
        [boolean]$Valid  =  ($IPAddress -as [ipaddress]) -as [boolean]
        Return  ($Valid -and $Octets)
    }

    function ResolveHost {
        [CmdletBinding()]
        Param(
            [Parameter(Mandatory=$True)]
            [string]$HostNameOrIP
        )
    
        ##### BEGIN Main Body #####
    
        $RemoteHostNetworkInfoArray = @()
        if (!$(TestIsValidIPAddress -IPAddress $HostNameOrIP)) {
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
        if (TestIsValidIPAddress -IPAddress $HostNameOrIP) {
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

    function SetupSubCA {
        [CmdletBinding()]
        param (
            [Parameter(Mandatory=$True)]
            [pscredential]$DomainAdminCredentials,

            [Parameter(Mandatory=$True)]
            [ValidateScript({
                $NoteProperties = $($_[0] | Get-Member -MemberType NoteProperty).Name
                $_.Count -gt 0 -and $NoteProperties -contains "SeverPurpose" -and
                $NoteProperties -contains "FQDN" -and $NoteProperties -contains "IPAddress" -and
                $NoteProperties -contains "DomainName" -and $NoteProperties -contains "DomainShortName" -and
                $NoteProperties -contains "DomainLDAPString"
            })]
            [System.Collections.ArrayList]$NetworkInfoPSObjects,

            [Parameter(Mandatory=$True)]
            [ValidateSet("EnterpriseRootCA")]
            [string]$CAType,

            [Parameter(Mandatory=$True)]
            [string]$NewComputerTemplateCommonName,

            [Parameter(Mandatory=$True)]
            [string]$NewWebServerTemplateCommonName,

            [Parameter(Mandatory=$True)]
            [string]$FileOutputDirectory,

            [Parameter(Mandatory=$True)]
            [ValidateSet("Microsoft Software Key Storage Provider")]
            [string]$CryptoProvider,

            [Parameter(Mandatory=$True)]
            [ValidateSet("2048","4096")]
            [int]$KeyLength,

            [Parameter(Mandatory=$True)]
            [ValidateSet("SHA1","SHA256","SHA384","SHA512","MD5","MD4","MD2")]
            [string]$HashAlgorithm,

            [Parameter(Mandatory=$True)]
            [ValidateSet("RSA")]
            [string]$KeyAlgorithmValue,

            [Parameter(Mandatory=$True)]
            [ValidatePattern('http.*?\/<CaName><CRLNameSuffix>\.crl$')]
            [string]$CDPUrl,

            [Parameter(Mandatory=$True)]
            [ValidatePattern('http.*?\/<CaName><CertificateName>.crt$')]
            [string]$AIAUrl
        )

        $RelevantRootCANetworkInfo = $NetworkInfoPSObjects | Where-Object {$_.ServerPurpose -eq "RootCA"}
        $RelevantSubCANetworkInfo = $NetworkInfoPSObjects | Where-Object {$_.ServerPurpose -eq "SubCA"}

        # Mount the RootCA Temporary SMB Share To Get the Following Files
        <#
        Mode                LastWriteTime         Length Name                                                    PSComputerName
        ----                -------------         ------ ----                                                    --------------
        -a----        5/22/2018   8:09 AM              0 alphaComputer.ldf                                       192.168.2.111
        -a----        5/22/2018   8:09 AM              0 alphaWebServer.ldf                                      192.168.2.111
        -a----        5/22/2018   8:07 AM            841 RootCA.alpha.lab_ROOTCA.crt                             192.168.2.111
        -a----        5/22/2018   8:09 AM           1216 RootCA.alpha.lab_ROOTCA_base64.cer                      192.168.2.111
        -a----        5/22/2018   8:09 AM            483 ROOTCA.crl                                              192.168.2.111
        #>
        # This also serves as a way to determine if the Root CA is ready
        while (!$RootCASMBShareMount) {
            $NewPSDriveSplatParams = @{
                Name            = "R"
                PSProvider      = "FileSystem"
                Root            = "\\$($RelevantRootCANetworkInfo.FQDN)\RootCAFiles"
                Credential      = $DomainAdminCredentials
                ErrorAction     = "SilentlyContinue"
            }
            $RootCASMBShareMount = New-PSDrive @NewPSDriveSplatParams

            if (!$RootCASMBShareMount) {
                Write-Host "Waiting for RootCA SMB Share to become available. Sleeping for 15 seconds..."
                Start-Sleep -Seconds 15
            }
        }

        $SubCAWorkingDir = "C:\SubCAWorkingDir"
        if (!$(Test-Path $SubCAWorkingDir)) {
            $null = New-Item -ItemType Directory -Path $SubCAWorkingDir -Force
        }
        
        try {
            $null = Install-PackageProvider -Name Nuget -Force -Confirm:$False
            $null = Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
            Install-Module PSPKI -ErrorAction Stop
            Import-Module PSPKI -ErrorAction Stop
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            return
        }
        
        try {
            Import-Module ServerManager -ErrorAction Stop
        }
        catch {
            Write-Error "Problem importing the ServerManager Module! Halting!"
            $global:FunctionResult = "1"
            return
        }

        try {
            $null = Add-WindowsFeature Adcs-Cert-Authority -IncludeManagementTools
        }
        catch {
            Write-Error "Problem with 'Add-WindowsFeature Adcs-Cert-Authority -IncludeManagmementTools'! Halting!"
            $global:FunctionResult = "1"
            return
        }
        try {
            $null = Add-WindowsFeature RSAT-AD-Tools
        }
        catch {
            Write-Error "Problem with 'Add-WindowsFeature RSAT-AD-Tools'! Halting!"
            $global:FunctionResult = "1"
            return
        }

        <#
        default['adcs']['crypto']['provider']         = "RSA#Microsoft Software Key Storage Provider"
        default['adcs']['crypto']['key_length']       = "2048"
        default['adcs']['crypto']['hash_algorithm']   = "SHA256"
        default['adcs']['certsrv_alias']              = "pki"
        default['adcs']['cdp_url']                    = "http://#{default['adcs']['certsrv_alias']}/certdata/<CaName><CRLNameSuffix>.crl"
        default['adcs']['aia_url']                    = "http://#{default['adcs']['certsrv_alias']}/certdata/<CaName><CertificateName>.crt"
        default['adcs']['certs_share']['windows']     = "#{default[:common][:mount][:windows_mountpoint]}\\certs"
        default['adcs']['certs_share']['linux']       = "#{default[:common][:mount][:linux_mountpoint]}/certs"
        default['adcs']['domainlocation']             = "test2.lab"
        default['adcs']['certgenworking']             = "CertGenWorking"
        default['adcs']['newcerttemplates']           = "NewCertTemplates"
        default['adcs']['certenrollexports']          = "CertEnrollExports"
        # END COMMON SETTINGS ###########################


        # ROOT CA SETTINGS ###############################
        default['adcs']['root_ca']['ca_type']         = "EnterpriseRootCa"
        default['adcs']['root_ca']['cn']              = "Maverick2"
        default['adcs']['root_ca']['dn_suffix']       = "O=TEST2,C=LAB"
        default['adcs']['root_ca']['dn_suffix1']      = "DC=TEST2,DC=LAB"
        default['adcs']['root_ca']['validity']        = "years"
        default['adcs']['root_ca']['validity_units']  = "20"
        default['adcs']['root_ca']['newcompcerttemp'] = "TestComputer"
        default['adcs']['root_ca']['newwebservcerttemp'] = "TestWebServ"
        default['adcs']['root_ca']['subcatempl']      = "SubCA"
        # END ROOT CA SETTINGS ##########################


        # Subordinate CA SETTINGS #######################
        # Naming conventions for Subordinate CA:
        # Common Name:  <ENV>-SCA
        # Distinguished Name Suffix:  DC=<DOMAIN>, DC=<DOMAIN>
        # The Install-AdcsCertificationAuthority command REQUIRES backslashes \\ instead of / or it WILL error out.
        default['adcs']['subo_ca']['ca_type']       = "EnterpriseSubordinateCA"
        default['adcs']['subo_ca']['cn']            = "Maverick-SCA2"
        default['adcs']['subo_ca']['dn_suffix']     = "DC=TEST2,DC=LAB"
        default['adcs']['subo_ca']['inf_file']      = "#{default['adcs']['subo_ca']['cn']}.#{default['adcs']['domainlocation']}_#{default['adcs']['subo_ca']['cn']}.inf"
        default['adcs']['subo_ca']['csr_file']      = "#{default['adcs']['subo_ca']['cn']}.#{default['adcs']['domainlocation']}_#{default['adcs']['subo_ca']['cn']}.csr"
        default['adcs']['subo_ca']['cer_file']      = "#{default['adcs']['subo_ca']['cn']}.#{default['adcs']['domainlocation']}_#{default['adcs']['subo_ca']['cn']}.cer"
        default['adcs']['subo_ca']['p7b_file']      = "#{default['adcs']['subo_ca']['cn']}.#{default['adcs']['domainlocation']}_#{default['adcs']['subo_ca']['cn']}.p7b"
        default['adcs']['subo_ca']['certdata_dir']  = "C:\\inetpub\\wwwroot\\certdata"
        default['adcs']['subo_ca']['webcert_subject_suffix']  = "OU=TestOrgUnit,O=TestOrg,L=Springfield,S=VA,C=US"
        default['adcs']['subo_ca']['caorg']         = "TestOrg"
        default['adcs']['subo_ca']['caorgunit']     = "TestOrgUnit"
        default['adcs']['subo_ca']['calocality']    = "Springfield"
        default['adcs']['subo_ca']['castate']       = "VA"
        default['adcs']['subo_ca']['cacountry']     = "US"
        default['adcs']['subo_ca']['rootcalocation']     = "Maverick2.test2.lab\\Maverick2"
        default['adcs']['subo_ca']['subcalocation']      = "Maverick-SCA2.test2.lab\\Maverick-SCA2"
        #>
        
        Install-AdcsCertificationAuthority `
        -CAType                     "#{node['adcs']['subo_ca']['ca_type']}" `
        -CryptoProviderName         "#{node['adcs']['crypto']['provider']}" `
        -KeyLength                  "#{node['adcs']['crypto']['key_length']}" `
        -HashAlgorithmName          "#{node['adcs']['crypto']['hash_algorithm']}" `
        -CACommonName               "#{node['adcs']['subo_ca']['cn']}" `
        -CADistinguishedNameSuffix  "#{node['adcs']['subo_ca']['dn_suffix']}" `
        -OutputCertRequestFile      "C:\\#{node['adcs']['certgenworking']}\\#{node['adcs']['subo_ca']['csr_file']}" `
        -Force
        EOH
        end

        powershell_script "Add Enrollment Web Service and CA Web Enrollment features" do
        code <<-EOH
            Import-Module ServerManager
            Add-WindowsFeature Adcs-Enroll-Web-Svc,Adcs-Web-Enrollment,Web-Mgmt-Console
        EOH
        end

        powershell_script "Copy RootCA .crt and .crl From Network Share to SubCA CertEnroll Directory" do
        code <<-EOH
        Copy-Item "#{node['adcs']['certs_share']['windows']}\\*" "C:\\Windows\\System32\\CertSrv\\CertEnroll\\"
        EOH
        end

        powershell_script "Copy RootCA .crt and .crl From Network Share to C CertGen-Working Directory" do
        code <<-EOH
        Copy-Item "#{node['adcs']['certs_share']['windows']}\\*" "C:\\#{node['adcs']['certgenworking']}\\"
        EOH
        end

        powershell_script "Install RootCA .crt" do
        code <<-EOH
        certutil -addstore "Root" "C:\\#{node['adcs']['certgenworking']}\\#{node['adcs']['root_ca']['cn']}.#{node['adcs']['domainlocation']}_#{node['adcs']['root_ca']['cn']}.crt"
        EOH
        end

        powershell_script "Install RootCA .crl" do
        code <<-EOH
        certutil -addstore "Root" "C:\\#{node['adcs']['certgenworking']}\\#{node['adcs']['root_ca']['cn']}.crl"
        EOH
        end

        directory "Certdata IIS folder" do
        path "#{node['adcs']['subo_ca']['certdata_dir']}"
        action :create
        end

        powershell_script "Stage certdata IIS site, enable dir browsing" do
        code <<-EOH
            Copy-Item "#{node['adcs']['certs_share']['windows']}\\#{node['adcs']['certenrollexports']}\\*" "#{node['adcs']['subo_ca']['certdata_dir']}" -Force
            Set-Location C:\\Windows\\system32\\inetsrv
            .\\appcmd.exe set config "Default Web Site/certdata" /section:directoryBrowse /enabled:true
        EOH
        end

        powershell_script "Update DNS Alias" do
        code <<-EOH
            Invoke-Command -ComputerName $($env:LOGONSERVER.replace("\\","")) -Command { `
            Add-DnsServerResourceRecordCname `
                -Name "#{node['adcs']['certsrv_alias']}" `
                -HostnameAlias "#{node['fqdn']}" `
                -ZoneName "#{node['adcs']['domainlocation']}"
            }
        EOH
        end
    }

    #endregion >> Helper Functions

    #region >> Initial Prep

    $ElevationCheck = [System.Security.Principal.WindowsPrincipal]::new([System.Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    if (!$ElevationCheck) {
        Write-Error "You must run the build.ps1 as an Administrator (i.e. elevated PowerShell Session)! Halting!"
        $global:FunctionResult = "1"
        return
    }

    $NextHop = $(Get-NetRoute -AddressFamily IPv4 | Where-Object {$_.NextHop -ne "0.0.0.0"} | Sort-Object RouteMetric)[0].NextHop
    $PrimaryIP = $(Find-NetRoute -RemoteIPAddress $NextHop | Where-Object {$($_ | Get-Member).Name -contains "IPAddress"}).IPAddress

    [System.Collections.ArrayList]$NetworkLocationObjsToResolve = @(
        [pscustomobject]@{
            ServerPurpose       = "RootCA"
            NetworkLocation     = $RootCAFQDN
        }
    )
    if ($PSBoundParameters['SubCAFQDN']) {
        $SubCAPSObj = [pscustomobject]@{
            ServerPurpose       = "SubCA"
            NetworkLocation     = $SubCAFQDN
        }
    }
    else {
        $SubCAPSObj = [pscustomobject]@{
            ServerPurpose       = "SubCA"
            NetworkLocation     = $env:ComputerName + "." + $(Get-CimInstance win32_computersystem).Domain
        }
    }
    $null = $NetworkLocationsToResolve.Add($SubCAPSObj)

    [System.Collections.ArrayList]$NetworkInfoPSObjects = @()
    foreach ($NetworkLocationObj in $NetworkLocationObjsToResolve) {
        if ($NetworkLocation -split "\.")[0] -ne $env:ComputerName) {
            try {
                $NetworkInfo = ResolveHost -HostNameOrIP $NetworkLocationObj.NetworkLocation
                $DomainName = $NetworkInfo.Domain
                $FQDN = $NetworkInfo.FQDN
                $IPAddr = $NetworkInfo.IPAddressList[0]
                $DomainShortName = $($DomainName -split "\.")[0]
                $DomainLDAPString = $(foreach ($StringPart in $($DomainName -split "\.")) {"DC=$Part"}) -join ','

                if (!$NetworkInfo -or $DomainName -eq "Unknown" -or !$DomainName -or $FQDN -eq "Unknown" -or !$FQDN) {
                    throw "Unable to gather Domain Name and/or FQDN info about '$NetworkLocation'! Please check DNS. Halting!"
                }
            }
            catch {
                Write-Error $_
                $global:FunctionResult = "1"
                return
            }

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

            $ItemsToAddToWSMANTrustedHosts = @($IPAddr,$FQDN,$($($FQDN -split "\.")[0]))
            foreach ($NetItem in $ItemsToAddToWSMANTrustedHosts) {
                if ($CurrentTrustedHostsAsArray -notcontains $NetItem) {
                    $null = $CurrentTrustedHostsAsArray.Add($NetItem)
                }
            }
            $UpdatedTrustedHostsString = $CurrentTrustedHostsAsArray -join ','
            Set-Item WSMan:\localhost\Client\TrustedHosts $UpdatedTrustedHostsString -Force
        }
        else {
            $DomainName = $(Get-CimInstance win32_computersystem).Domain
            $DomainShortName = $($DomainName -split "\.")[0]
            $DomainLDAPString = $(foreach ($StringPart in $($DomainName -split "\.")) {"DC=$Part"}) -join ','
            $FQDN = $env:ComputerName + '.' + $DomainName
            $IPAddr = $PrimaryIP
        }

        $PSObj = [pscustomobject]@{
            ServerPurpose       = $NetworkLocationObj.ServerPurpose
            FQDN                = $FQDN
            HostName            = $($FQDN -split "\.")[0]
            IPAddress           = $IPAddr
            DomainName          = $DomainName
            DomainShortName     = $DomainShortName
            DomainLDAPString    = $DomainLDAPString
        }
        $null = $NetworkInfoPSObjects.Add($PSObj)
    }

    # Set some defaults if certain paramters are not used
    if (!$CAType) {
        $CAType = "EnterpriseRootCA"
    }
    if (!$NewComputerTemplateCommonName) {
        $NewComputerTemplateCommonName = $DomainShortName + "Computer"
    }
    if (!$NewWebServerTemplateCommonName) {
        $NewWebServerTemplateCommonName = $DomainShortName + "WebServer"
    }
    if (!$FileOutputDirectory) {
        $FileOutputDirectory = "C:\NewRootCAOutput"
    }
    if (!$CryptoProvider) {
        $CryptoProvider = "Microsoft Software Key Storage Provider"
    }
    if (!$KeyLength) {
        $KeyLength = 2048
    }
    if (!$HashAlgorithm) {
        $HashAlgorithm = "SHA256"
    }
    if (!$KeyAlgorithmValue) {
        $KeyAlgorithmValue = "RSA"
    }
    if (!$CDPUrl) {
        $CDPUrl = "http://$RootCAFQDN/certdata/<CaName><CRLNameSuffix>.crl"
    }
    if (!$AIAUrl) {
        $AIAUrl = "http://$RootCAFQDN/certdata/<CaName><CertificateName>.crt"
    }

    # Create SetupRootCA Helper Function Splat Parameters
    $SetupRootCASplatParams = @{
        DomainAdminCredentials              = $DomainAdminCredentials
        NetworkInfoPSObjects                = $NetworkInfoPSObjects
        CAType                              = $CAType
        NewComputerTemplateCommonName       = $NewComputerTemplateCommonName
        NewWebServerTemplateCommonName      = $NewWebServerTemplateCommonName
        FileOutputDirectory                 = $FileOutputDirectory
        CryptoProvider                      = $CryptoProvider
        KeyLength                           = $KeyLength
        HashAlgorithm                       = $HashAlgorithm
        KeyAlgorithmValue                   = $KeyAlgorithmValue
        CDPUrl                              = $CDPUrl
        AIAUrl                              = $AIAUrl
    }

    $RelevantRootCANetworkInfo = $NetworkInfoPSObjects | Where-Object {$_.ServerPurpose -eq "RootCA"}
    $RelevantSubCANetworkInfo = $NetworkInfoPSObjects | Where-Object {$_.ServerPurpose -eq "SubCA"}

    #endregion >> Initial Prep


    #region >> Do SubCA Install

    if ($RelevantRootCANetworkInfo.HostName -ne $env:ComputerName) {
        $PSSessionName = NewUniqueString -ArrayOfStrings $(Get-PSSession).Name -PossibleNewUniqueString "ToRootCA"

        # Try to create a PSSession to the Root CA for 15 minutes, then give up
        $Counter = 0
        while (![bool]$(Get-PSSession -Name $PSSessionName -ErrorAction SilentlyContinue)) {
            try {
                $RootCAPSSession = New-PSSession -ComputerName $RelevantRootCANetworkInfo.IPAddress -Credential $DomainAdminCredentials -Name $PSSessionName -ErrorAction SilentlyContinue
                if (![bool]$(Get-PSSession -Name $PSSessionName -ErrorAction SilentlyContinue)) {throw}
            }
            catch {
                if ($Counter -le 60) {
                    Write-Warning "New-PSSession '$PSSessionName' failed. Trying again in 15 seconds..."
                    Start-Sleep -Seconds 15
                }
                else {
                    Write-Error "Unable to create new PSSession to '$PSSessionName' using account '$($DomainAdminCredentials.UserName)'! Halting!"
                    $global:FunctionResult = "1"
                    return
                }
            }
            $Counter++
        }

        if (!$RootCAPSSession) {
            Write-Error "Unable to create a PSSession to the Root CA Server at '$($RelevantRootCANetworkInfo.IPAddress)'! Halting!"
            $global:FunctionResult = "1"
            return
        }

        $FunctionsForRemoteUse = @(
            ${Function:SetupRootCA}.Ast.Extent.Text
        )
        Invoke-Command -Session $RootCAPSSession -ScriptBlock {
            $using:FunctionsForRemoteUse | foreach { Invoke-Expression $_ }
            SetupRootCA @using:SetupRootCASplatParams
        }
    }
    else {
        SetupRootCA @SetupRootCASplatParams
    }

    #endregion >> Do SubCA Install

    
}