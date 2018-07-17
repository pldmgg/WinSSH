$here = Split-Path -Parent $MyInvocation.MyCommand.Path

Describe "Basics" {
    It "Doesn't leak processes" {

        $beforeProcesses = Get-Process -Name PowerShell
        Start-AwaitSession

        do
        {
            $midProcesses =  Get-Process -Name PowerShell
        } while($midProcesses.Count -eq $beforeProcesses.Count)

        Stop-AwaitSession
        
        do
        {
            $endProcesses =  Get-Process -Name PowerShell
        }
        while($endProcesses.Count -gt $beforeProcesses.Count)

        $midProcesses.Count - $beforeProcesses.Count | Should be 2
        $midProcesses.Count - $endProcesses.Count | Should be 2
    }

    It "Doesn't leave processes behind" {

        $beforeProcesses = Get-Process -Name PowerShell

        PowerShell -NoProfile -Command 'Start-AwaitSession; Remove-Module Await'

        do
        {
            $endProcesses =  Get-Process -Name PowerShell
        }
        while($endProcesses.Count -gt $beforeProcesses.Count)

        $beforeProcesses.Count | Should be $endProcesses.Count
    }
}

Describe "FullScreenOutput" {

    Start-AwaitSession

    try
    {
        It "Captures initial logo" {
        
            $output = Wait-AwaitResponse 'All rights reserved.' -All
            $output -match 'PowerShell'| Should be $true
     }

        It "Evaluates simple command" {
        
            Send-AwaitCommand '111+222'
            
            do
            {
                $output = Receive-AwaitResponse -All
            } while(-not ($output -match '333'))

            $output -match '333'| Should be $true
     }

        It "Supports Stream parameter" {
        
            $null = Receive-AwaitResponse
            Send-AwaitCommand 'cls'
            $null = Wait-AwaitResponse "PS"
            Send-AwaitCommand '"`n"*5; "AAA"*2'           
            $output = Wait-AwaitResponse "AAAAAA" -Stream
            ($output.Count) -gt 1 | Should be $true

            Send-AwaitCommand 'cls'
            $null = Wait-AwaitResponse "PS"
            Send-AwaitCommand '"`n"*5; "AAA"*2'
            Start-Sleep -m 500
            $output = Receive-AwaitResponse -Stream
            ($output.Count) -gt 1 | Should be $true
     }

        It "Retains previous output" {
        
            Send-AwaitCommand '333+444'
            
            do
            {
                $output = Wait-AwaitResponse 777 -All
            } while(-not ($output -match '777'))

            $output -match '333'| Should be $true
            $output -match '777'| Should be $true
     }

        It "Produces identical output for multiple invocations" {
        
            $output1 = Receive-AwaitResponse -All
            $output2 = Receive-AwaitResponse -All
            
            $output1 -eq $output2 | Should be $true
     }

        It "Captures cleared screens" {
        
            Send-AwaitCommand cls
            $null = Wait-AwaitResponse "PS"
            Send-AwaitCommand "'1234567'"
            $output = Wait-AwaitResponse '1234567' -All
            $output -match 1234567 | Should be $true

            Send-AwaitCommand cls
            $null = Wait-AwaitResponse "PS"
            Send-AwaitCommand "'12121212'"
            $output = Wait-AwaitResponse 12121212 -All
            $output -match 1234567 | Should be $false
            $output -match 12121212 | Should be $true
     }
    }
    finally
    {
        Stop-AwaitSession
    }
}

Describe "IncrementalOutput" {

    It "Captures initial logo" {
        Start-AwaitSession
        $output = Wait-AwaitResponse 'All rights reserved.'
        $output -match 'PowerShell'| Should be $true
        Stop-AwaitSession
 }

    Start-AwaitSession

    try
    {
        It "Clears output on multiple invocations" {
            Send-AwaitCommand '11*11'
            $output = Wait-AwaitResponse 121

            $output -match 121 | Should be $true
            $output2 = Receive-AwaitResponse
            $output2 | Should be ""
        }

        It "Captures secondary invocation" {
            Send-AwaitCommand '5*5'
            $output = Wait-AwaitResponse 25
            $output -match 25 | Should be $true

            Send-AwaitCommand '6*6'
            $output = Wait-AwaitResponse 36
            $output -match 36 | Should be $true
        }

        It "Handles cleared screens" {
            Send-AwaitCommand '"`n"*50'
            Send-AwaitCommand '"AAA"*2'
            $output = Wait-AwaitResponse AAAAAA
            $output -match 'AAAAAA' | Should be $true

            Send-AwaitCommand 'cls'
            $null = Wait-AwaitResponse "PS"

            Send-AwaitCommand '"BBB"*2'
            $output = Wait-AwaitResponse BBBBBB
            $output -match 'BBBBBB' | Should be $true
        }

        It "Captures output at the end of the buffer" {
            Send-AwaitCommand 'cls'
            $null = Receive-AwaitResponse

            Send-AwaitCommand '[Console]::BufferHeight = [Console]::WindowHeight'
            Send-AwaitCommand '"`n" * [Console]::BufferHeight * 2'
            Send-AwaitCommand '"AAA"*2'
            $output = Wait-AwaitResponse AAAAAA
            $output -match 'AAAAAA' | Should be $true

            Send-AwaitCommand '"BBB"*2'
            $output = Wait-AwaitResponse BBBBBB
            $output -match 'BBBBBB' | Should be $true

            Send-AwaitCommand '"CCC"*2'
            $output = Wait-AwaitResponse CCCCCC
            $output -match 'CCCCCC' | Should be $true
        }

        It "Captures input at the end of the buffer" {
            Send-AwaitCommand 'cls'
            $null = Receive-AwaitResponse

            Send-AwaitCommand '[Console]::BufferHeight = [Console]::WindowHeight'
            Send-AwaitCommand '"`n" * [Console]::BufferHeight * 2'
            Send-AwaitCommand '"AAA"*2'
            $output = Wait-AwaitResponse AAAAAA
            $output -match 'AAAAAA' | Should be $true

            ## Should have original input line
            Send-AwaitCommand '"BBB"*2'
            $output = Wait-AwaitResponse '"BBB"*2' -All
            $output -match ([Regex]::Escape('"BBB"*2')) | Should be $true
        }
    }
    finally
    {
        Stop-AwaitSession
    }
}

Describe "Scenarios" {

    Start-AwaitSession

    try
    {
        It "Does Something" {
        }
    }
    finally
    {
        Stop-AwaitSession
    }
}

# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUNeehbcEuGOexLdhQjT2HtMyC
# 5T+gggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFOUfcLFzB4RsDtMh
# hrlsR3YnrsKqMA0GCSqGSIb3DQEBAQUABIIBAFXyHH8D9OmJshf76w3BPkYCNeMA
# 0iheLVcDeWlOhuBI+mUeCUyBX0N9OG1zVLtVFcOG9oBbh74leLQhHRMmq0LCrR6v
# yQVrMt88YgCx9k/5zVtrIgxabsfh3hCjbj+Kc1fjo82FGWFTexlkelZTula+Kl1I
# 4jTNFIYioFs02Z9zT2jidwyqJw65nYjx+AjmR+7lT5RY7WchPSrOfXOLQr7c8ZP1
# j+DHhD7NvJ9H3+uylK5aR0V9PRO2ynSg95b1t980z6hqSld2a48r94cXB7TQnLpa
# +O+L8DQzPdNMvjWxbt4I7X3YXxvr5LTtQ2IWHgaNimC7mpjtQlfuzv92CRY=
# SIG # End signature block
