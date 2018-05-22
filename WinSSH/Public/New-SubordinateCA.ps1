function New-SubordinateCA {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$True)]
        [string]$RootCAIPOrFQDN,

        [Parameter(Mandatory=$True)]
        [pscredential]$DomainAdminCredentials,

        [Parameter(Mandatory=$False)]
        [string]$SubCAIPOrFQDN,

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

        if (!$(Test-Path $FileOutputDirectory)) {
            $null = New-Item -ItemType Directory -Path $FileOutputDirectory 
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

        $WindowsFeaturesToAdd = @(
            "Adcs-Cert-Authority"
            "Adcs-Web-Enrollment"
            "Web-Mgmt-Console"
            "RSAT-AD-Tools"
        )
        foreach ($FeatureName in $WindowsFeaturesToAdd) {
            $SplatParams = @{
                Name    = $FeatureName
            }
            if ($FeatureName -eq "Adcs-Cert-Authority") {
                $SplatParams.Add("IncludeManagementTools",$True)
            }

            try {
                $null = Add-WindowsFeature @SplatParams
            }
            catch {
                Write-Error "Problem with 'Add-WindowsFeature $FeatureName'! Halting!"
                $global:FunctionResult = "1"
                return
            }
        }

        #region >> Install ADCSCA
        try {
            $CertRequestFile = $FileOutputDirectory + "\" + $RelevantSubCANetworkInfo.FQDN + "_" + $RelevantSubCANetworkInfo.HostName + ".csr"
            $InstallADCSCertAuthSplatParams = @{
                Credential                  = $DomainAdminCredentials
                CAType                      = $CAType
                CryptoProviderName          = $FinalCryptoProvider
                KeyLength                   = $KeyLength
                HashAlgorithmName           = $HashAlgorithm
                CACommonName                = $env:ComputerName
                CADistinguishedNameSuffix   = $RelevantSubCANetworkInfo.DomainLDAPString
                OutputCertRequestFile       = $CertRequestFile
                Force                       = $True
                ErrorAction                 = "Stop"
            }
            Install-AdcsCertificationAuthority @InstallADCSCertAuthSplatParams
        }
        catch {
            Write-Error $_
            Write-Error "Problem with Install-AdcsCertificationAuthority cmdlet! Halting!"
            $global:FunctionResult = "1"
            return
        }

        # Copy RootCA .crt and .crl From Network Share to SubCA CertEnroll Directory
        Copy-Item -Path "$($RootCASMBShareMount.Name)`:\*" -Recurse -Destination "C:\Windows\System32\CertSrv\CertEnroll" -Force

        # Copy RootCA .crt and .crl From Network Share to the $FileOutputDirectory
        Copy-Item -Path "$($RootCASMBShareMount.Name)`:\*" -Recurse -Destination $FileOutputDirectory -Force

        # Install the RootCA .crt to the Certificate Store
        [array]$RootCACrtFile = Get-ChildItem -Path $FileOutputDirectory -Filter "*.crt"
        if ($RootCACrtFile.Count -eq 0) {
            Write-Error "Unable to find RootCA .crt file under the directory '$FileOutputDirectory'! Halting!"
            $global:FunctionResult = "1"
            return
        }
        if ($RootCACrtFile.Count -gt 1) {
            $RootCACrtFile = $RootCACrtFile | Where-Object {$_.Name -eq $($RelevantRootCANetworkInfo.FQDN + "_" + $RelevantRootCANetworkInfo.HostName + '.crt')}
        }
        if ($RootCACrtFile -eq 1) {
            $RootCACrtFile = $RootCACrtFile[0]
        }
        certutil -addstore "Root" "$($RootCACrtFile.FullName)"

        # Install RootCA .crl
        [array]$RootCACrlFile = Get-ChildItem -Path $FileOutputDirectory -Filter "*.crl"
        if ($RootCACrlFile.Count -eq 0) {
            Write-Error "Unable to find RootCA .crl file under the directory '$FileOutputDirectory'! Halting!"
            $global:FunctionResult = "1"
            return
        }
        if ($RootCACrlFile.Count -gt 1) {
            $RootCACrlFile = $RootCACrlFile | Where-Object {$_.Name -eq $($RelevantRootCANetworkInfo.FQDN + "_" + $RelevantRootCANetworkInfo.HostName + '.crl')}
        }
        if ($RootCACrlFile -eq 1) {
            $RootCACrlFile = $RootCACrlFile[0]
        }
        certutil -addstore "Root" "$($RootCACrlFile.FullName)"

        # Create the Certdata IIS folder
        $CertDataIISFolder = "C:\inetpub\wwwroot\certdata"
        if (!$(Test-Path $CertDataIISFolder)) {
            $null = New-Item -Path $CertDataIISFolder -Force
        }

        # Stage certdata IIS site and enable directory browsing
        Copy-Item -Path "$FileOutputDirectory\*" -Recurse -Destination $CertDataIISFolder -Force
        & "C:\Windows\system32\inetsrv\appcmd.exe" set config "Default Web Site/certdata" /section:directoryBrowse /enabled:true

        # Update DNS Alias
        $DomainControllerFQDN = $($env:LOGONSERVER.replace("\\","")) + $RelevantSubCANetworkInfo.Domain
        Invoke-Command -ComputerName $DomainControllerFQDN -Credential $DomainAdminCredentials -ScriptBlock {
            Add-DnsServerResourceRecordCname -Name "pki" -HostnameAlias $RelevantSubCANetworkInfo.FQDN -ZoneName $RelevantSubCANetworkInfo.Domain
        }

        # Request and Install SCA Certificate from Existing CSR
        $RootCACertUtilLocation = "$($RelevantRootCANetworkInfo.FQDN)\$($RelevantRootCANetworkInfo.HostName)" 
        $SubCACACertUtilLocation = "$($RelevantSubCANetworkInfo.FQDN)\$($RelevantSubCANetworkInfo.HostName)"
        $SubCACerFileOut = $FileOutputDirectory + "\" + $RelevantSubCANetworkInfo.FQDN + "_" + $RelevantSubCANetworkInfo.HostName + ".cer"
        $CertificateChainOut = $FileOutputDirectory + "\" + $RelevantSubCANetworkInfo.FQDN + "_" + $RelevantSubCANetworkInfo.HostName + ".p7b"

        $RequestID = (certreq.exe -config "$RootCACertUtilLocation" -submit "$CertRequestFile" "$SubCACerFileOut").split('"')[2]
        Start-Sleep -Seconds 5
        certreq.exe -retrieve -config $RootCACertUtilLocation $RequestID $CertificateChainOut
        Start-Sleep -Seconds 5
        certutil.exe -config $SubCACACertUtilLocation -installCert $CertificateChainOut
  
        try {
            Restart-Service certsvc -ErrorAction Stop
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            return
        }

        while ($(Get-Service certsvc).Status -ne "Running") {
            Write-Host "Waiting for the 'certsvc' service to start..."
            Start-Sleep -Seconds 5
        }

        # Enable Subject Alt Name
        certutil -setreg policy\\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2

        try {
            Stop-Service certsvc -Force -ErrorAction Stop
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            return
        }

        while ($(Get-Service certsvc).Status -ne "Stopped") {
            Write-Host "Waiting for the 'certsvc' service to stop..."
            Start-Sleep -Seconds 5
        }

        # Install Certification Authority Web Enrollment
        try {
            Install-AdcsWebEnrollment -Force
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            return
        }

        try {
            Start-Service certsvc -ErrorAction Stop
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            return
        }

        while ($(Get-Service certsvc).Status -ne "Running") {
            Write-Host "Waiting for the 'certsvc' service to start..."
            Start-Sleep -Seconds 5
        }

        try {
            # Install Certificate Enrollment Web Service
            Install-AdcsEnrollmentWebService -AuthenticationType "UserName" -ApplicationPoolIdentity -CAConfig "$($RelevantSubCANetworkInfo.HostName)\$($RelevantSubCANetworkInfo.HostName)" -Force
            
            # Configure CRL, CDP, AIA, CA Auditing
            # Update CRL Validity period
            certutil -setreg CA\\CRLPeriod "Weeks"
            certutil -setreg CA\\CRLPeriodUnits 4
            certutil -setreg CA\\CRLOverlapPeriod "Days"
            certutil -setreg CA\\CRLOverlapUnits 3

            # Remove pre-existing http CDP, add custom CDP
            Get-CACrlDistributionPoint | Where-Object { $_.URI -like "http#*" } | Remove-CACrlDistributionPoint -Force
            Add-CACrlDistributionPoint -Uri $CDPUrl -AddToCertificateCdp -Force

            # Remove pre-existing http AIA, add custom AIA
            Get-CAAuthorityInformationAccess | Where-Object { $_.Uri -like "http*" } | Remove-CAAuthorityInformationAccess -Force
            Add-CAAuthorityInformationAccess -Uri $AIAUrl -AddToCertificateAIA -Force

            # Enable all event auditing
            certutil -setreg CA\\AuditFilter 127
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            return
        }

        try {
            Restart-Service certsvc -ErrorAction Stop
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            return
        }

        while ($(Get-Service certsvc).Status -ne "Running") {
            Write-Host "Waiting for the 'certsvc' service to start..."
            Start-Sleep -Seconds 5
        }

        # Publish SubCA CRL
        # Generate New CRL and Copy Contents of CertEnroll to $FileOutputDirectory
        # NOTE: The below 'certutil -crl' outputs the new .crl file to "C:\Windows\System32\CertSrv\CertEnroll"
        # which happens to contain some other important files that we'll need
        $null = certutil -crl
        Copy-Item -Path "C:\Windows\System32\CertSrv\CertEnroll\*" -Recurse -Destination $FileOutputDirectory -Force
        # Convert SubCA .crt DER Certificate to Base64 Just in Case You Want to Use With Linux
        $CrtFileItem = Get-ChildItem -Path $FileOutputDirectory -File -Recurse | Where-Object {$_.Name -match "$env:ComputerName\.crt"}
        $null = certutil -encode $($CrtFileItem.FullName) $($CrtFileItem.FullName -replace '\.crt','_base64.cer')
        
        # Copy SubCA CRL From SubCA CertEnroll directory to C:\inetpub\wwwroot\certdata" do
        $SubCACrlFileItem = Get-ChildItem -Path "C:\Windows\System32\CertSrv\CertEnroll" -File | Where-Object {$_.Name -match "$env:ComputerName\.crl"}
        Copy-Item -Path $SubCACrlFileItem.FullName -Destination "C:\inetpub\wwwroot\certdata\$($SubCACrlFileItem.Name)" -Force
        
        # Copy SubCA Cert From $FileOutputDirectory to C:\inetpub\wwwroot\certdata
        $SubCACerFileItem = Get-ChildItem -Path $FileOutputDirectory -File -Recurse | Where-Object {$_.Name -match "$env:ComputerName\.cer"}
        Copy-Item $SubCACerFileItem.FullName -Destination "C:\inetpub\wwwroot\certdata\$($SubCACerFileItem.Name)"

        # Import New Certificate Templates that were exported by the RootCA to a Network Share
        # NOTE: This shouldn't be necessary if we're using and Enterprise Root CA
        #ldifde -i -k -f $($RootCASMBShareMount.Name + ':\' + $NewComputerTemplateCommonName + '.ldf')
        #ldifde -i -k -f $($RootCASMBShareMount.Name + ':\' + $NewWebServerTemplateCommonName + '.ldf')
        
        try {
            # Add New Cert Templates to List of Temps to Issue using the PSPKI Module
            Get-CertificationAuthority -Name $env:ComputerName | Get-CATemplate | Add-CATemplate -Name $NewComputerTemplateCommonName | Set-CATemplate
            Get-CertificationAuthority -Name $env:ComputerName | Get-CATemplate | Add-CATemplate -Name $NewWebServerTemplateCommonName | Set-CATemplate
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            return
        }

        # Request PKI WebServer Alias Certificate
        $PKIWebSiteCertInfFile = "$FileOutputDirectory\pki.$($RelevantSubCANetworkInfo.DomainName).inf"
        $PKIWebSiteCertRequestFile = "$FileOutputDirectory\pki.$($RelevantSubCANetworkInfo.DomainName).csr"
        $PKIWebsiteCertFileOut = "$FileOutputDirectory\pki.$($RelevantSubCANetworkInfo.DomainName).cer"

        $inf = @"
[Version]
Signature="`$Windows NT`$"

[NewRequest]
Subject = "CN=pki.$($RelevantSubCANetworkInfo.DomainName)"
KeySpec = 1
KeyLength = $KeyLength
Exportable = TRUE
FriendlyName = "PKICertSrvOn$env:ComputerName"
MachineKeySet = TRUE
SMIME = False
PrivateKeyArchive = FALSE
UserProtected = FALSE
UseExistingKeySet = FALSE
ProviderName = "Microsoft RSA SChannel Cryptographic Provider"
ProviderType = 12
RequestType = PKCS10
KeyUsage = 0xa0
"@

        $inf | Out-File $PKIWebSiteCertInfFile
        certreq.exe -new "$PKIWebSiteCertInfFile" "$PKIWebSiteCertRequestFile"
        Sleep -Seconds 5
        certreq.exe -attrib "CertificateTemplate:$NewWebServerTemplateCommonName" -config "$SubCACACertUtilLocation" -submit "$PKIWebSiteCertInfFile" "$PKIWebsiteCertFileOut"
        Sleep -Seconds 5
        certreq.exe -accept "$PKIWebsiteCertFileOut"

        if (!$(Test-Path $PKIWebsiteCertFileOut)) {
            Write-Error "There was a problem requesting a WebServer Certificate from the Subordinate CA for the PKI (certsrv) website! Halting!"
            $global:FunctionResult = "1"
            return
        }

        # Copy PKI SubCA Alias Cert From $FileOutputDirectory to C:\inetpub\wwwroot\certdata
        Copy-Item -Path $PKIWebsiteCertFileOut -Destination "C:\inetpub\wwwroot\certdata\pki.$($RelevantSubCANetworkInfo.DomainName).cer"

        # Configure HTTPS Binding
        try {
            $CertInfo = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new()
            $CertInfo.Import($PKIWebsiteCertFileOut)
            $PKIWebsiteCertThumbPrint = $CertInfo.ThumbPrint

            Import-Module WebAdministration
            Remove-Item IIS:\SslBindings\*
            Get-ChildItem Cert:\LocalMachine\My | Where-Object {$_.Thumbprint -eq $PKIWebsiteCertThumbPrint} | New-Item IIS:\SslBindings\0.0.0.0!443
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            return
        }

        # Configure Application Settings
        & "C:\Windows\system32\inetsrv\appcmd.exe" set config /commit:MACHINE /section:appSettings /+"[key='Friendly Name',value='$($RelevantSubCANetworkInfo.DomainName) Domain Certification Authority']"
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
            NetworkLocation     = $RootCAIPOrFQDN
        }
    )
    if ($PSBoundParameters['SubCAIPOrFQDN']) {
        $SubCAPSObj = [pscustomobject]@{
            ServerPurpose       = "SubCA"
            NetworkLocation     = $SubCAIPOrFQDN
        }
    }
    else {
        $SubCAPSObj = [pscustomobject]@{
            ServerPurpose       = "SubCA"
            NetworkLocation     = $env:ComputerName + "." + $(Get-CimInstance win32_computersystem).Domain
        }
    }
    $null = $NetworkLocationObjsToResolve.Add($SubCAPSObj)

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
        $CAType = "EnterpriseSubordinateCA"
    }
    if (!$NewComputerTemplateCommonName) {
        $NewComputerTemplateCommonName = $DomainShortName + "Computer"
    }
    if (!$NewWebServerTemplateCommonName) {
        $NewWebServerTemplateCommonName = $DomainShortName + "WebServer"
    }
    if (!$FileOutputDirectory) {
        $FileOutputDirectory = "C:\SubCAWorkingDir"
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
        $CDPUrl = "http://pki.$($RelevantSubCANetworkInfo.DomainName)/certdata/<CaName><CRLNameSuffix>.crl"
    }
    if (!$AIAUrl) {
        $AIAUrl = "http://pki.$($RelevantSubCANetworkInfo.DomainName)/certdata/<CaName><CertificateName>.crt"
    }

    # Create SetupRootCA Helper Function Splat Parameters
    $SetupSubCASplatParams = @{
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

    if ($RelevantSubCANetworkInfo.HostName -ne $env:ComputerName) {
        $PSSessionName = NewUniqueString -ArrayOfStrings $(Get-PSSession).Name -PossibleNewUniqueString "ToSubCA"

        # Try to create a PSSession to the Root CA for 15 minutes, then give up
        $Counter = 0
        while (![bool]$(Get-PSSession -Name $PSSessionName -ErrorAction SilentlyContinue)) {
            try {
                $SubCAPSSession = New-PSSession -ComputerName $RelevantSubCANetworkInfo.IPAddress -Credential $DomainAdminCredentials -Name $PSSessionName -ErrorAction SilentlyContinue
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

        if (!$SubCAPSSession) {
            Write-Error "Unable to create a PSSession to the Root CA Server at '$($RelevantSubCANetworkInfo.IPAddress)'! Halting!"
            $global:FunctionResult = "1"
            return
        }

        $FunctionsForRemoteUse = @(
            ${Function:SetupSubCA}.Ast.Extent.Text
        )
        Invoke-Command -Session $SubCAPSSession -ScriptBlock {
            $using:FunctionsForRemoteUse | foreach { Invoke-Expression $_ }
            SetupSubCA @using:SetupSubCASplatParams
        }
    }
    else {
        SetupRootCA @SetupSubCASplatParams
    }

    #endregion >> Do SubCA Install

    
}
# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU2pNcjrnuxZAfvznZYUHbFDB8
# eBKgggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFEMI2/z4AGSuovGH
# QSyHSJZIZweqMA0GCSqGSIb3DQEBAQUABIIBAJaxAl0AS6ON19U+hleSxWe8S56B
# tDqrQQZ0QOuFGtSc6XQ3gBhvVFkranwQydX/Mn4QjiAX3ANzFwoqOxTLjHdVVsG5
# I6sHPHz8BWWXATngrcpXQDNozLG9DvfGmDSMabTAw30oRnSS/7C1zuOUqW3pY8sj
# vCJEX3FYJDwsHyjibXcNhImX07LRVFOi2IceeZh9wDzvd1RAI1Rv6S51715mcHyN
# QstegYRe1LwEL2fQtZzlYqpHi50pkJeJA3eEFibwfvIzP2LZkadiPR10yz0wNFuW
# yRBMM2a4WP65nSKLyw82NgAYxZxmEerWG3RtVmyfzU2otvsAzMSabDwff14=
# SIG # End signature block
