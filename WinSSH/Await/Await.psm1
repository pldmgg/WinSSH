## If the module is removed, stop any await sessions that are active
$MyInvocation.MyCommand.ScriptBlock.Module.OnRemove = {
    if($SCRIPT:awaitHost)
    {
        Stop-AwaitSession
    }
}

<#

.SYNOPSIS

Creates a new Await Session, which is a virtual console that can invoke console-based
applications, interact with them, retrieve their responses, and view their (textual)
user interfaces.

.EXAMPLE

PS> Start-AwaitSession
PS> Send-AwaitCommand '123*456'
PS> $output = Wait-AwaitResponse '56088'
PS> $output

Windows PowerShell
Copyright (C) 2014 Microsoft Corporation. All rights reserved.

PS> 123*456
56088

PS> Stop-AwaitSession

#>
function Start-AwaitSession
{
    [Alias("spawn", "saas")]
    [CmdletBinding(DefaultParameterSetName = "ByText")]
    param(
        [Parameter(ParameterSetName = "ByCommand", Position = 0)]
        [ScriptBlock] $Command,

        [Parameter(ParameterSetName = "ByText", Position = 0)]
        [AllowEmptyString()]
        [String] $Text
    )

    ## Ensure there's not already an await session running
    if($SCRIPT:awaitHost)
    {
        throw "Cannot start await session. A session is already started. Use the Send and Receive cmdlets to interact with it."
    }

    
    $SCRIPT:separatorLine = "="*20 + " " + [GUID]::NewGuid() + " " + "="*20
    $SCRIPT:pipeName = "AwaitServer_$([Guid]::NewGuid())"

    $script = @"
    `$namedPipeServer = New-Object System.IO.Pipes.NamedPipeServerStream '$pipename'
    `$pipeInput = New-Object System.IO.StreamReader `$namedPipeServer
    `$pipeOutput = New-Object System.IO.StreamWriter `$namedPipeServer

    `$namedPipeServer.WaitForConnection()
    `$pipeOutput.AutoFlush = `$true

    while(`$true) ``
    {
        `$command = `$pipeInput.ReadLine()
        try
        {
            `$result = Invoke-Expression `$command | Out-String
        }
        catch
        {
            `$result = `$_ | Out-String
        }

        `$pipeOutput.WriteLine(`$result + '$separatorLine')
    }
"@

    $SCRIPT:awaitHost = Start-Process powershell.exe -ArgumentList "-NoProfile -Command $script" -PassThru -WindowStyle Hidden

    $SCRIPT:namedPipeClient = New-Object System.IO.Pipes.NamedPipeClientStream $pipename
    $SCRIPT:pipeInput = New-Object System.IO.StreamReader $namedPipeClient
    $SCRIPT:pipeOutput = New-Object System.IO.StreamWriter $namedPipeClient

    $namedPipeClient.Connect()

    $pipeOutput.AutoFlush = $true

    Invoke-AwaitHostCommand "Add-Type -Path '$psscriptRoot\AwaitDriver.cs'"
    Invoke-AwaitHostCommand '$awaitDriver = New-Object AwaitDriver.AwaitDriver'

    if($Command)
    {
        Send-AwaitCommand -Command $Command
    }
    
    if($Text)
    {
        ## If they just gave us text, assume it is a command name.
        
        ## If it has spaces (but no ampersand or single quotes), quote it
        ## Which precludes: "spawn 'c:\bin\program with arguments", but that can
        ## be accomplished with the script block parameter set.
        if(($Text -match " ") -and
           (-not ($Text -match "&|'")))
        {
            $Text = "& '$Text'"
        }

        Send-AwaitCommand -Text $Text
    }
}

function Stop-AwaitSession
{
    [Alias("spas")]
    [CmdletBinding()]
    param()

    Invoke-AwaitHostCommand '$awaitDriver.Close()'
    $SCRIPT:awaitHost.Kill()
    $SCRIPT:awaitHost = $null
}

function Send-AwaitCommand
{
    [Alias("sendac", "sdac")]
    [CmdletBinding(DefaultParameterSetName = 'ByText')]
 param(
        [Parameter(Mandatory, ParameterSetName = "ByCommand", Position = 0)]
        [ScriptBlock] $Command,

        [Parameter(Mandatory, ParameterSetName = "ByText", Position = 0)]
        [AllowEmptyString()]
        [String] $Text,

        [Switch] $NoNewLine
    )

    if(-not $SCRIPT:awaitHost)
    {
        throw "Cannot send command. You have not started an await session. Call Start-AwaitSession to start a session."
    }

    ## If they specified a script block, get its string representation.
    ## This saves the user from having to escape syntax and quoting rules.
    if($Command)
    {
        $Text = $Command.ToString().Trim()
        $Text = $Text -replace '{','{{'
        $Text = $Text -replace '}','}}'
    }

    $escapedText = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($Text))
    $driverCommand = "`$text = [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('$escapedText')); "

    if($NonewLine)
    {
     $driverCommand += "`$awaitDriver.Send(`$text)"
    }
    else
    {
        $driverCommand += "`$awaitDriver.SendLine(`$text)"
    }

    Invoke-AwaitHostCommand $driverCommand
}

function Wait-AwaitResponse
{
    [Alias("expect", "war")]
    [CmdletBinding()]
 param(
        [Parameter(Mandatory)]
        $Text,

        [Parameter()]
        [Switch]
        $All,

        [Parameter()]
        [Switch]
        $Stream
    )

    if(-not $SCRIPT:awaitHost)
    {
        throw "Cannot send command. You have not started an await session. Call Start-AwaitSession to start a session."
    }

    
    $escapedText = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($Text))
    $command = "`$text = [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('$escapedText')); "

    if($All)
    {
     $command += "`$awaitDriver.AwaitOutput(`$text, `$true)"
    }
    else
    {
        $command += "`$awaitDriver.AwaitOutput(`$text)"
    }

    $output = Invoke-AwaitHostCommand $command

    if($Stream)
    {
        $output
    }
    else
    {
        $output -join "`r`n"
    }
}

function Receive-AwaitResponse
{
    [Alias("expect?", "rcar")]
    [CmdletBinding()]
    param(
        [Parameter()]
        [Switch]
        $All,

        [Parameter()]
        [Switch]
        $Stream
    )

    if(-not $SCRIPT:awaitHost)
    {
        throw "Cannot send command. You have not started an await session. Call Start-AwaitSession to start a session."
    }

    if($All)
    {
     $output = Invoke-AwaitHostCommand '$awaitDriver.ReadOutput($true)'
    }
    else
    {
        $output = Invoke-AwaitHostCommand '$awaitDriver.ReadOutput()'
    }

    if($Stream)
    {
        $output
    }
    else
    {
        $output -join "`r`n"
    }
}

function Invoke-AwaitHostCommand
{
    param(
        [Parameter(Mandatory)]
        $Command
    )

    $SCRIPT:pipeOutput.WriteLine($Command)

    while($true)
    {
        $content = $pipeInput.ReadLine()
        if($content -and $content.EndsWith($SCRIPT:separatorLine))
        {
            break
        }

        $content
    }
}

# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU6hj0ffnF3opilMLOjMHuCkGn
# kZWgggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFIndA+bkQSabAR3V
# 08LpcpPO2K4wMA0GCSqGSIb3DQEBAQUABIIBADli88ornPGhmvvgB8ku/HhY29xZ
# grs2KkA2U4EMM53k5ZBVE8Y0DXxiV/YJZg7ygbXM2/9eq80V9TWdsCLV5mFQOHLi
# Phn9OqL0aeitIypebJ/0lCUbJhmNmgbr8sTY1KLevJgJeobT+xSA526Bpg620zaE
# lLuCebuqhA66IDYXb+OnCacmam7pQXylRAQEM2313TL3EpD6oyCRm8jynbBcZp0J
# adDK/aiRPZRiO+SZezCf0V7IT7pZp1vV0/orKHHT/IebfnhVuF3cYpDDn718Xiu8
# ja55opb+Zac4X6Q1/ZF+AyNHTSGSOMd26UnIofGZDrPRKtDc28zcziiUMQE=
# SIG # End signature block
