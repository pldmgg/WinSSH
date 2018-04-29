function TestPort {
    [CmdletBinding()]
    [Alias('testport')]
    Param(
        [Parameter(Mandatory=$False)]
        $HostName = $env:COMPUTERNAME,

        [Parameter(Mandatory=$False)]
        [int]$Port = $(Read-Host -Prompt "Please enter the port number you would like to check.")
    )

    Begin {

        ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####
        
        try {
            $HostNameNetworkInfo = Resolve-Host -HostNameOrIP $HostName -ErrorAction Stop
        }
        catch {
            Write-Error "Unable to resolve $HostName! Halting!"
            $global:FunctionResult = "1"
            return
        }

        $tcp = New-Object Net.Sockets.TcpClient
        $RemoteHostFQDN = $HostNameNetworkInfo.FQDN
        
        ##### END Variable/Parameter Transforms and PreRun Prep #####
    }

    ##### BEGIN Main Body #####
    Process {
        if ($pscmdlet.ShouldProcess("$RemoteHostFQDN","Test Connection on $RemoteHostFQDN`:$Port")) {
            try {
                $tcp.Connect($RemoteHostFQDN, $Port)
            }
            catch {}

            if ($tcp.Connected) {
                $tcp.Close()
                $open = $true
            }
            else {
                $open = $false
            }

            $PortTestResult = [pscustomobject]@{
                Address = $RemoteHostFQDN
                Port    = $Port
                Open    = $open
            }
            $PortTestResult
        }
        ##### END Main Body #####
    }
}