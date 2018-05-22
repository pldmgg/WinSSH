function New-RootCA {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$True)]
        [pscredential]$DomainAdminCredentials,

        [Parameter(Mandatory=$False)]
        [string]$RootCAFQDN,

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

    function SetupRootCA {
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

        #region >> Prep

        $FinalCryptoProvider = $KeyAlgorithmValue + "#" + $CryptoProvider

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

        $RelevantRootCANetworkInfo = $NetworkInfoPSObjects | Where-Object {$_.ServerPurpose -eq "RootCA"}

        #endregion >> Prep

        #region >> Install ADCSCA
        try {
            $InstallADCSCertAuthSplatParams = @{
                Credential                  = $DomainAdminCredentials
                CAType                      = $CAType
                CryptoProviderName          = $FinalCryptoProvider
                KeyLength                   = $KeyLength
                HashAlgorithmName           = $HashAlgorithm
                CACommonName                = $env:ComputerName
                CADistinguishedNameSuffix   = $RelevantRootCANetworkInfo.DomainLDAPString
                DatabaseDirectory           = $(Join-Path $env:SystemRoot "System32\CertLog")
                ValidityPeriod              = "years"
                ValidityPeriodUnits         = 20
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

        try {
            $null = certutil -setreg CA\\CRLPeriod "Years"
            $null = certutil -setreg CA\\CRLPeriodUnits 1
            $null = certutil -setreg CA\\CRLOverlapPeriod "Days"
            $null = certutil -setreg CA\\CRLOverlapUnits 7

            Write-Host "Done initial certutil commands..."

            # Update the Local CDP
            $LocalCDP = (Get-CACrlDistributionPoint)[0]
            $LocalCDP | Remove-CACrlDistributionPoint -Force
            $LocalCDP.PublishDeltaToServer = $false
            $LocalCDP | Add-CACrlDistributionPoint -Force

            # Remove pre-existing ldap/http CDPs, add custom CDP
            Get-CACrlDistributionPoint | Where-Object { $_.URI -like "http*" -or $_.Uri -like "ldap*" } | Remove-CACrlDistributionPoint -Force
            Add-CACrlDistributionPoint -Uri $CDPUrl -AddToCertificateCdp -Force

            # Remove pre-existing ldap/http AIAs, add custom AIA
            Get-CAAuthorityInformationAccess | Where-Object { $_.Uri -like "http*" -or $_.Uri -like "ldap*" } | Remove-CAAuthorityInformationAccess -Force
            Add-CAAuthorityInformationAccess -Uri $AIAUrl -AddToCertificateAIA -Force

            Write-Host "Done CDP and AIA cmdlets..."

            # Enable all event auditing
            $null = certutil -setreg CA\\AuditFilter 127

            Write-Host "Done final certutil command..."
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            return
        }

        try {
            $null = Restart-Service certsvc -ErrorAction Stop
        }
        catch {
            Write-Error $_
            Write-Error "Problem with 'Restart-Service certsvc'! Halting!"
            $global:FunctionResult = "1"
            return
        }

        #endregion >> Install ADCSCA

        #region >> New Computer/Machine Template
        Write-Host "Creating new Machine Certificate Template..."

        while (!$WebServTempl -or !$ComputerTempl) {
            $ConfigContext = $([ADSI]"LDAP://RootDSE").ConfigurationNamingContext
            $LDAPLocation = "LDAP://CN=Certificate Templates,CN=Public Key Services,CN=Services,$ConfigContext"
            $ADSI = New-Object System.DirectoryServices.DirectoryEntry($LDAPLocation,$DomainAdminCredentials.UserName,$($DomainAdminCredentials.GetNetworkCredential().Password),"Secure")

            $WebServTempl = $ADSI.psbase.children | Where-Object {$_.distinguishedName -match "CN=WebServer,"}
            $ComputerTempl = $ADSI.psbase.children | Where-Object {$_.distinguishedName -match "CN=Machine,"}

            Write-Host "Waiting for Active Directory 'LDAP://CN=Certificate Templates,CN=Public Key Services,CN=Services,$ConfigContext' to contain default Machine/Computer and WebServer Certificate Templates..."
            Start-Sleep -Seconds 15
        }

        $OIDRandComp = (Get-Random -Maximum 999999999999999).tostring('d15')
        $OIDRandComp = $OIDRandComp.Insert(8,'.')
        $CompOIDValue = $ComputerTempl.'msPKI-Cert-Template-OID'
        $NewCompTemplOID = $CompOIDValue.subString(0,$CompOIDValue.length-4)+$OIDRandComp

        $NewCompTempl = $ADSI.Create("pKICertificateTemplate","CN=$NewComputerTemplateCommonName")
        $NewCompTempl.put("distinguishedName","CN=$NewComputerTemplateCommonName,CN=Certificate Templates,CN=Public Key Services,CN=Services,$ConfigContext")
        $NewCompTempl.put("flags","131680")
        $NewCompTempl.put("displayName","$NewComputerTemplateCommonName")
        $NewCompTempl.put("revision","100")
        $NewCompTempl.put("pKIDefaultKeySpec","1")
        $NewCompTempl.put("pKIMaxIssuingDepth","0")
        $pkiCritExt = "2.5.29.17","2.5.29.15"
        $NewCompTempl.put("pKICriticalExtensions",$pkiCritExt)
        $ExtKeyUse = "1.3.6.1.5.5.7.3.1","1.3.6.1.5.5.7.3.2"
        $NewCompTempl.put("pKIExtendedKeyUsage",$ExtKeyUse)
        $NewCompTempl.put("pKIDefaultCSPs","1,Microsoft RSA SChannel Cryptographic Provider")
        $NewCompTempl.put("msPKI-RA-Signature","0")
        $NewCompTempl.put("msPKI-Enrollment-Flag","0")
        $NewCompTempl.put("msPKI-Private-Key-Flag","0") # Used to be "50659328"
        $NewCompTempl.put("msPKI-Certificate-Name-Flag","1")
        $NewCompTempl.put("msPKI-Minimal-Key-Size","2048")
        $NewCompTempl.put("msPKI-Template-Schema-Version","2") # This needs to be either "1" or "2" for it to show up in the ADCS Website dropdown
        $NewCompTempl.put("msPKI-Template-Minor-Revision","2")
        $NewCompTempl.put("msPKI-Cert-Template-OID","$NewCompTemplOID")
        $AppPol = "1.3.6.1.5.5.7.3.1","1.3.6.1.5.5.7.3.2"
        $NewCompTempl.put("msPKI-Certificate-Application-Policy",$AppPol)
        $NewCompTempl.Setinfo()
        # Get the last few attributes from the existing default "CN=Machine" Certificate Template
        $NewCompTempl.pKIOverlapPeriod = $ComputerTempl.pKIOverlapPeriod # Used to be $WebServTempl.pKIOverlapPeriod
        $NewCompTempl.pKIKeyUsage = $ComputerTempl.pKIKeyUsage # Used to be $WebServTempl.pKIKeyUsage
        $NewCompTempl.pKIExpirationPeriod = $ComputerTempl.pKIExpirationPeriod # Used to be $WebServTempl.pKIExpirationPeriod
        $NewCompTempl.Setinfo()

        # Set Access Rights / Permissions on the $NewCompTempl LDAP object
        $AdObj = New-Object System.Security.Principal.NTAccount("Domain Computers")
        $identity = $AdObj.Translate([System.Security.Principal.SecurityIdentifier])
        $adRights = "ExtendedRight"
        $type = "Allow"
        $ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($identity,$adRights,$type)
        $NewCompTempl.psbase.ObjectSecurity.SetAccessRule($ACE)
        $NewCompTempl.psbase.commitchanges()

        #endregion >> New Computer/Machine Template

        #region >> New WebServer Template
        Write-Host "Creating new WebServer Certificate Template..."

        $OIDRandWebServ = (Get-Random -Maximum 999999999999999).tostring('d15')
        $OIDRandWebServ = $OIDRandWebServ.Insert(8,'.')
        $WebServOIDValue = $WebServTempl.'msPKI-Cert-Template-OID'
        $NewWebServTemplOID = $WebServOIDValue.subString(0,$WebServOIDValue.length-4)+$OIDRandWebServ

        $NewWebServTempl = $ADSI.Create("pKICertificateTemplate", "CN=$NewWebServerTemplateCommonName") 
        $NewWebServTempl.put("distinguishedName","CN=$NewWebServerTemplateCommonName,CN=Certificate Templates,CN=Public Key Services,CN=Services,$ConfigContext")
        $NewWebServTempl.put("flags","131649")
        $NewWebServTempl.put("displayName","$NewWebServerTemplateCommonName")
        $NewWebServTempl.put("revision","100")
        $NewWebServTempl.put("pKIDefaultKeySpec","1")
        $NewWebServTempl.put("pKIMaxIssuingDepth","0")
        $pkiCritExt = "2.5.29.15"
        $NewWebServTempl.put("pKICriticalExtensions",$pkiCritExt)
        $ExtKeyUse = "1.3.6.1.5.5.7.3.1","1.3.6.1.5.5.7.3.2"
        $NewWebServTempl.put("pKIExtendedKeyUsage",$ExtKeyUse)
        $pkiCSP = "1,Microsoft RSA SChannel Cryptographic Provider","2,Microsoft DH SChannel Cryptographic Provider"
        $NewWebServTempl.put("pKIDefaultCSPs",$pkiCSP)
        $NewWebServTempl.put("msPKI-RA-Signature","0")
        $NewWebServTempl.put("msPKI-Enrollment-Flag","0")
        $NewWebServTempl.put("msPKI-Private-Key-Flag","0") # Used to be "16842752"
        $NewWebServTempl.put("msPKI-Certificate-Name-Flag","1")
        $NewWebServTempl.put("msPKI-Minimal-Key-Size","2048")
        $NewWebServTempl.put("msPKI-Template-Schema-Version","2") # This needs to be either "1" or "2" for it to show up in the ADCS Website dropdown
        $NewWebServTempl.put("msPKI-Template-Minor-Revision","2")
        $NewWebServTempl.put("msPKI-Cert-Template-OID","$NewWebServTemplOID")
        $AppPol = "1.3.6.1.5.5.7.3.1","1.3.6.1.5.5.7.3.2"
        $NewWebServTempl.put("msPKI-Certificate-Application-Policy",$AppPol)
        $NewWebServTempl.Setinfo()
        # Get the last few attributes from the existing default "CN=WebServer" Certificate Template
        $NewWebServTempl.pKIOverlapPeriod = $WebServTempl.pKIOverlapPeriod
        $NewWebServTempl.pKIKeyUsage = $WebServTempl.pKIKeyUsage
        $NewWebServTempl.pKIExpirationPeriod = $WebServTempl.pKIExpirationPeriod
        $NewWebServTempl.Setinfo()

        #endregion >> New WebServer Template

        #region >> Finish

        # Add the newly created custom Computer and WebServer Certificate Templates to List of Certificate Templates to Issue
        # For this to be (relatively) painless, we need the following PSPKI Module cmdlets
        Get-CertificationAuthority -Name $env:ComputerName | Get-CATemplate | Add-CATemplate -Name $NewComputerTemplateCommonName | Set-CATemplate
        Get-CertificationAuthority -Name $env:ComputerName | Get-CATemplate | Add-CATemplate -Name $NewWebServerTemplateCommonName | Set-CATemplate

        # Export New Certificate Templates to NewCert-Templates Directory
        $null = ldifde -m -v -d "CN=$NewComputerTemplateCommonName,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,$ConfigContext" -f "$FileOutputDirectory\$NewComputerTemplateCommonName.ldf"
        $null = ldifde -m -v -d "CN=$NewWebServerTemplateCommonName,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,$ConfigContext" -f "$FileOutputDirectory\$NewWebServerTemplateCommonName.ldf"
        
        # Side Note: You can import Certificate Templates on another Certificate Authority via ldife.exe with:
        <#
        ldifde -i -k -f "$FileOutputDirectory\$NewComputerTemplateCommonName.ldf"
        ldifde -i -k -f "$FileOutputDirectory\$NewWebServerTemplateCommonName.ldf"
        #>

        # Generate New CRL and Copy Contents of CertEnroll to C CertEnroll-Exports
        # NOTE: The below 'certutil -crl' outputs the new .crl file to "C:\Windows\System32\CertSrv\CertEnroll"
        # which happens to contain some other important files that we'll need
        $null = certutil -crl
        Copy-Item -Path "C:\Windows\System32\CertSrv\CertEnroll\*" -Recurse -Destination $FileOutputDirectory -Force
        # Convert RootCA .crt DER Certificate to Base64 Just in Case You Want to Use With Linux
        $CrtFiles = Get-ChildItem -Path $FileOutputDirectory -File -Recurse -Filter "*.crt"
        foreach ($CrtFileItem in $CrtFiles) {
            $null = certutil -encode $($CrtFileItem.FullName) $($CrtFileItem.FullName -replace '\.crt','_base64.cer')
        }
        # Make $FileOutputDirectory a Network Share until the Subordinate CA can download the files
        # IMPORTANT NOTE: The below -CATimeout parameter should be in Seconds. So after 12000 seconds, the SMB Share
        # will no longer be available
        # IMPORTANT NOTE: The below -Temporary switch means that the SMB Share will NOT survive a reboot
        New-SMBShare -Name RootCAFiles -Path $FileOutputDirectory -CATimeout 12000 -Temporary
        # Now the SMB Share  should be available
        $RootCASMBShareNetworkLocation = '\\' + $RelevantRootCANetworkInfo.FQDN + "\RootCAFiles"

        Write-Host "RootCAFiles needed by the Subordinate/Issuing/Intermediate CA Server(s) are now available here: $RootCASMBShareNetworkLocation" -ForegroundColor Green
        $RootCASMBShareNetworkLocation

        #endregion >> Finish
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

    [System.Collections.ArrayList]$NetworkLocationObjsToResolve = @()
    if ($PSBoundParameters['RootCAFQDN']) {
        $SubCAPSObj = [pscustomobject]@{
            ServerPurpose       = "RootCA"
            NetworkLocation     = $RootCAFQDN
        }
    }
    else {
        $RootCAPSObj = [pscustomobject]@{
            ServerPurpose       = "RootCA"
            NetworkLocation     = $env:ComputerName + "." + $(Get-CimInstance win32_computersystem).Domain
        }
    }
    $null = $NetworkLocationsToResolve.Add($RootCAPSObj)

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

    #endregion >> Initial Prep


    #region >> Do RootCA Install

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

    #endregion >> Do RootCA Install
}



# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUYqEMGmuDkp81adn/GYa8ps36
# jyCgggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFOe6TwTOLv0ADBE4
# 6v6sESYWDNSgMA0GCSqGSIb3DQEBAQUABIIBAMQLPQtspsXabFHH3fmhR2oCnmA8
# PyksMdqoWN7Fc2Vts81lU5mXdXZd7dhO7OSErnik8NVbHEfuonWLbmgulOb3wMdO
# oHW23CAr2LTH6DP7YFzkRZ5VQLiny01P3wCa6ijWsng9b2VD4K2Ms5swydNxDDUA
# 2fidKiGMQrqmSonyxh0Lg7eG4Q+Z8h8fw7sXAYi00Btk8OPpDKaDG3rfA2NMq+J1
# m31bJAiCnSNxK+J+xvUOjdn164JlN2he2OTF8EMmW2yF23PpQr+vxM7Phk/2/wKS
# E99MTYBeQ68Tsg8Wxr1eD0Sl/l72yknhOD47qyExz3z0f0wzttJzyepY8Ao=
# SIG # End signature block
