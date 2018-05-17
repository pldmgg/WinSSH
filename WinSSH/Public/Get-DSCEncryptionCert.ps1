
function Get-DSCEncryptionCert {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$True)]
        [string]$MachineName,

        [Parameter(Mandatory=$True)]
        [string]$ExportDirectory
    )

    if (!$(Test-Path $ExportDirectory)) {
        Write-Error "The path '$ExportDirectory' was not found! Halting!"
        $global:FunctionResult = "1"
        return
    }

    $CertificateFriendlyName = "DSC Credential Encryption"
    $Cert = Get-ChildItem -Path "Cert:\LocalMachine\My" | Where-Object {
        $_.FriendlyName -eq $CertificateFriendlyName
    } | Select-Object -First 1

    if (!$Cert) {
        $NewSelfSignedCertExSplatParams = @{
            Subject             = "CN=$Machinename"
            EKU                 = @('1.3.6.1.4.1.311.80.1','1.3.6.1.5.5.7.3.1','1.3.6.1.5.5.7.3.2')
            KeyUsage            = 'DigitalSignature, KeyEncipherment, DataEncipherment'
            SAN                 = $MachineName
            FriendlyName        = $CertificateFriendlyName
            Exportable          = $True
            StoreLocation       = 'LocalMachine'
            StoreName           = 'My'
            KeyLength           = 2048
            ProviderName        = 'Microsoft Enhanced Cryptographic Provider v1.0'
            AlgorithmName       = "RSA"
            SignatureAlgorithm  = "SHA256"
        }

        New-SelfsignedCertificateEx @NewSelfSignedCertExSplatParams

        # There is a slight delay before new cert shows up in Cert:
        # So wait for it to show.
        while (!$Cert) {
            $Cert = Get-ChildItem -Path "Cert:\LocalMachine\My" | Where-Object {$_.FriendlyName -eq $CertificateFriendlyName}
        }
    }

    $null = Export-Certificate -Type CERT -Cert $Cert -FilePath "$ExportDirectory\DSCEncryption.cer"

    $CertInfo = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new()
    $CertInfo.Import("$ExportDirectory\DSCEncryption.cer")

    [pscustomobject]@{
        CertFile        = Get-Item "$ExportDirectory\DSCEncryption.cer"
        CertInfo        = $CertInfo
    }
}