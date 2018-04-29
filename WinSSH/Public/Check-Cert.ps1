function Check-Cert {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$True)]
        [string]$IPAddress,
        
        [Parameter(Mandatory=$True)]
        [int]$Port
    )
    
    try {
        $TcpSocket = New-Object Net.Sockets.TcpClient($IPAddress,$Port)
        $tcpstream = $TcpSocket.GetStream()
        $Callback = {param($sender,$cert,$chain,$errors) return $true}
        $SSLStream = New-Object -TypeName System.Net.Security.SSLStream -ArgumentList @($tcpstream, $True, $Callback)

        try {
            $SSLStream.AuthenticateAsClient($IPAddress)
            $Certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($SSLStream.RemoteCertificate)
        }
        finally {
            $SSLStream.Dispose()
        }
    }
    finally {
        $TCPSocket.Dispose()
    }
    
    $Certificate
}