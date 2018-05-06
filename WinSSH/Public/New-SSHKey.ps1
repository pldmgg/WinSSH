function New-SSHKey {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [string]$NewSSHKeyName,

        [Parameter(Mandatory=$False)]
        [System.Security.SecureString]$NewSSHKeyPwd,

        [Parameter(Mandatory=$False)]
        [ValidatePattern("^\w*$")] # No spaces allowed
        [string]$NewSSHKeyPurpose,

        [Parameter(Mandatory=$False)]
        [switch]$AllowAwaitModuleInstall,

        [Parameter(Mandatory=$False)]
        [switch]$AddToSSHAgent,

        [Parameter(Mandatory=$False)]
        [switch]$RemovePrivateKey,

        #[Parameter(Mandatory=$False)]
        #[switch]$ShowNextSteps,

        [Parameter(Mandatory=$False)]
        [string]$RemoteHost,

        [Parameter(Mandatory=$False)]
        [switch]$AddToRemoteHostAuthKeys,

        [Parameter(Mandatory=$False)]
        [string]$RemoteHostUserName
    )

    ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####

    if (!$(GetElevation)) {
        Write-Verbose "You must run PowerShell as Administrator before using this function! Halting!"
        Write-Error "You must run PowerShell as Administrator before using this function! Halting!"
        $global:FunctionResult = "1"
        return
    }

    if ($AddToRemoteHostAuthKeys -and !$RemoteHost) {
        $RemoteHost = Read-Host -Prompt "Please enter an IP, FQDN, or DNS-resolvable Host Name that represents the Remote Host you would like to share your new public key with."
    }
    if ($RemoteHost -and !$AddToRemoteHostAuthKeys) {
        $AddToRemoteHostAuthKeys = $True
    }

    if ($RemoteHost) {
        try {
            $RemoteHostNetworkInfo = ResolveHost -HostNameOrIP $RemoteHost -ErrorAction Stop
        }
        catch {
            Write-Error "Unable to resolve $RemoteHost! Halting!"
            $global:FunctionResult = "1"
            return
        }
    }

    if ($RemoteHost -or $AddToRemoteHostAuthKeys -and !$RemoteHostUserName) {
        $RemoteHostUserName = Read-Host -Prompt "Please enter a UserName that has access to $RemoteHost"
    }

    $OpenSSHWinPath = "$env:ProgramFiles\OpenSSH-Win64"

    if (!$(Test-Path $OpenSSHWinPath)) {
        Write-Error "The path $OpenSSHWinPath was not found! Halting!"
        $global:FunctionResult = "1"
        return
    }

    if (!$(Test-Path "$HOME\.ssh")) {
        $null = New-Item -Type Directory -Path "$HOME\.ssh"
    }

    $SSHKeyOutFile = "$HOME\.ssh\$NewSSHKeyName"

    if ($NewSSHKeyPurpose) {
        $NewSSHKeyPurpose = $NewSSHKeyPurpose -replace "[\s]",""

        $SSHKeyGenArgumentsString = "-t rsa -b 2048 -f `"$SSHKeyOutFile`" -q -N `"$NewSSHKeyPwd`" -C `"$NewSSHKeyPurpose`""
        $SSHKeyGenArgumentsNoPwdString = "-t rsa -b 2048 -f `"$SSHKeyOutFile`" -q -C `"$NewSSHKeyPurpose`""
    }
    else {
        $SSHKeyGenArgumentsString = "-t rsa -b 2048 -f `"$SSHKeyOutFile`" -q -N `"$NewSSHKeyPwd`""
        $SSHKeyGenArgumentsNoPwdString = "-t rsa -b 2048 -f `"$SSHKeyOutFile`" -q"
    }
    
    ##### END Variable/Parameter Transforms and PreRun Prep #####


    ##### BEGIN Main Body #####

    # Create new public/private keypair
    if ($NewSSHKeyPwd) {
        $ProcessInfo = New-Object System.Diagnostics.ProcessStartInfo
        $ProcessInfo.WorkingDirectory = $OpenSSHWinPath
        $ProcessInfo.FileName = "ssh-keygen.exe"
        $ProcessInfo.RedirectStandardError = $true
        $ProcessInfo.RedirectStandardOutput = $true
        #$ProcessInfo.StandardOutputEncoding = [System.Text.Encoding]::Unicode
        #$ProcessInfo.StandardErrorEncoding = [System.Text.Encoding]::Unicode
        $ProcessInfo.UseShellExecute = $false
        $ProcessInfo.Arguments = $SSHKeyGenArgumentsString
        $Process = New-Object System.Diagnostics.Process
        $Process.StartInfo = $ProcessInfo
        $Process.Start() | Out-Null
        $stdout = $Process.StandardOutput.ReadToEnd()
        $stderr = $Process.StandardError.ReadToEnd()
        $AllOutput = $stdout + $stderr

        if ($AllOutput -match "fail|error") {
            Write-Error $AllOutput
            Write-Error "The 'ssh-keygen command failed! Halting!"
            $global:FunctionResult = "1"
            return
        }
    }
    else {
        if (!$AllowAwaitModuleInstall -and $(Get-Module -ListAvailable).Name -notcontains "Await") {
            Write-Warning "This function needs to install the PowerShell Await Module in order to generate a private key with a null password."
            $ProceedChoice = Read-Host -Prompt "Would you like to proceed? [Yes\No]"
            while ($ProceedChoice -notmatch "Yes|yes|Y|y|No|no|N|n") {
                Write-Host "$ProceedChoice is NOT a valid choice! Please enter 'Yes' or 'No'"
                $ProceedChoice = Read-Host -Prompt "Would you like to proceed? [Yes\No]"
            }

            if ($ProceedChoice -match "No|no|N|n") {
                Write-Error "User chose not to proceed! Halting!"
                $global:FunctionResult = "1"
                return
            }
        }
        if ($AllowAwaitModuleInstall -or $ProceedChoice -match "Yes|yes|Y|y") {
            # Need PowerShell Await Module (Windows version of Linux Expect) for ssh-keygen with null password
            if ($(Get-Module -ListAvailable).Name -notcontains "Await") {
                # Install-Module "Await" -Scope CurrentUser
                # Clone PoshAwait repo to .zip
                Invoke-WebRequest -Uri "https://github.com/pldmgg/PoshAwait/archive/master.zip" -OutFile "$HOME\PoshAwait.zip"
                $tempDirectory = [IO.Path]::Combine([IO.Path]::GetTempPath(), [IO.Path]::GetRandomFileName())
                $null = [IO.Directory]::CreateDirectory($tempDirectory)
                UnzipFile -PathToZip "$HOME\PoshAwait.zip" -TargetDir "$tempDirectory"
                if (!$(Test-Path "$HOME\Documents\WindowsPowerShell\Modules\Await")) {
                    $null = New-Item -Type Directory "$HOME\Documents\WindowsPowerShell\Modules\Await"
                }
                Copy-Item -Recurse -Path "$tempDirectory\PoshAwait-master\*" -Destination "$HOME\Documents\WindowsPowerShell\Modules\Await"
                Remove-Item -Recurse -Path $tempDirectory -Force

                if ($($env:PSModulePath -split ";") -notcontains "$HOME\Documents\WindowsPowerShell\Modules") {
                    $env:PSModulePath = "$HOME\Documents\WindowsPowerShell\Modules" + ";" + $env:PSModulePath
                }
            }
        }

        # Make private key password $null
        Import-Module Await
        if (!$?) {
            Write-Error "Unable to load the Await Module! Halting!"
            $global:FunctionResult = "1"
            return
        }

        Start-AwaitSession
        Start-Sleep -Seconds 1
        Send-AwaitCommand '$host.ui.RawUI.WindowTitle = "PSAwaitSession"'
        $PSAwaitProcess = $($(Get-Process | ? {$_.Name -eq "powershell"}) | Sort-Object -Property StartTime -Descending)[0]
        Start-Sleep -Seconds 1
        Send-AwaitCommand "`$env:Path = '$env:Path'; Push-Location '$OpenSSHWinPath'"
        Start-Sleep -Seconds 1
        Send-AwaitCommand "ssh-keygen $SSHKeyGenArgumentsNoPwdString"
        Start-Sleep -Seconds 2
        # The below is the equivalent of pressing [ENTER] to proceed with the ssh-keygen.exe interactive prompt
        Send-AwaitCommand ""
        Start-Sleep -Seconds 2
        # The below is the equivalent of pressing [ENTER] to proceed with the ssh-keygen.exe interactive prompt
        Send-AwaitCommand ""
        Start-Sleep -Seconds 1
        $SSHKeyGenConsoleOutput = Receive-AwaitResponse

        # If Stop-AwaitSession errors for any reason, it doesn't return control, so we need to handle in try/catch block
        try {
            Stop-AwaitSession
        }
        catch {
            if ($PSAwaitProcess.Id -eq $PID) {
                Write-Verbose "The PSAwaitSession never spawned! Halting!"
                Write-Error "The PSAwaitSession never spawned! Halting!"
                $global:FunctionResult = "1"
                return
            }
            else {
                Stop-Process -Id $PSAwaitProcess.Id
                while ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue)) {
                    Write-Host "Waiting for Await Module Process Id $($PSAwaitProcess.Id) to end..."
                    Start-Sleep -Seconds 1
                }
            }
        }
    }

    $PubPrivKeyPairFiles = Get-ChildItem -Path "$HOME\.ssh" | Where-Object {$_.Name -match "$NewSSHKeyName"}
    $PubKey = $PubPrivKeyPairFiles | Where-Object {$_.Extension -eq ".pub"}
    $PrivKey = $PubPrivKeyPairFiles | Where-Object {$_.Extension -ne ".pub"}

    if (!$PubKey -or !$PrivKey) {
        Write-Error "The New SSH Key Pair was NOT created! Check the output of the ssh-keygen.exe command below! Halting!"
        Write-Host ""
        Write-Host "##### BEGIN ssh-keygen Console Output From PSAwaitSession #####" -ForegroundColor Yellow
        Write-Host $SSHKeyGenConsoleOutput
        Write-Host "##### END ssh-keygen Console Output From PSAwaitSession #####" -ForegroundColor Yellow
        Write-Host ""
        $global:FunctionResult = "1"
        return
    }

    if ($AddToSSHAgent) {
        if ($(Get-Service ssh-agent).Status -ne "Running") {
            $SSHDErrMsg = "The ssh-agent service is NOT curently running! This means that $HOME\.ssh\$NewSSHKeyName.pub cannot be added" +
            " in order to authorize remote hosts to use it to allow ssh access to this local machine! Please ensure that the sshd service" +
            " is running and try adding the new public key again using 'ssh-add.exe $HOME\.ssh\$NewSSHKeyName.pub'"
            Write-Error $SSHDErrMsg
            $global:FunctionResult = "1"
            return
        }

        # Add the New Private Key to the ssh-agent
        $SSHAddProcessInfo = New-Object System.Diagnostics.ProcessStartInfo
        $SSHAddProcessInfo.WorkingDirectory = $OpenSSHWinPath
        $SSHAddProcessInfo.FileName = "ssh-add.exe"
        $SSHAddProcessInfo.RedirectStandardError = $true
        $SSHAddProcessInfo.RedirectStandardOutput = $true
        $SSHAddProcessInfo.UseShellExecute = $false
        $SSHAddProcessInfo.Arguments = "$($PrivKey.FullName)"
        $SSHAddProcess = New-Object System.Diagnostics.Process
        $SSHAddProcess.StartInfo = $SSHAddProcessInfo
        $SSHAddProcess.Start() | Out-Null
        $SSHAddProcess.WaitForExit()
        $SSHAddStdout = $SSHAddProcess.StandardOutput.ReadToEnd()
        $SSHAddStderr = $SSHAddProcess.StandardError.ReadToEnd()
        $SSHAddAllOutput = $SSHAddStdout + $SSHAddStderr
        
        if ($SSHAddAllOutput -match "fail|error") {
            Write-Error $SSHAddAllOutput
            Write-Error "The 'ssh-add $($PrivKey.FullName)' command failed!"
        }
        else {
            if ($RemovePrivateKey) {
                Remove-Item $PrivKey.FullName
            }
        }

        [System.Collections.ArrayList]$PublicKeysAccordingToSSHAgent = @()
        $(ssh-add -L) | foreach {
            $null = $PublicKeysAccordingToSSHAgent.Add($_)
        }
        $ThisPublicKeyAccordingToSSHAgent = $PublicKeysAccordingToSSHAgent | Where-Object {$_ -match "$NewSSHKeyName$"}
        [System.Collections.ArrayList]$CharacterCountArray = @()
        $ThisPublicKeyAccordingToSSHAgent -split " " | foreach {
            $null = $CharacterCountArray.Add($_.Length)
        }
        $LongestStringLength = $($CharacterCountArray | Measure-Object -Maximum).Maximum
        $ArrayPositionBeforeComment = $CharacterCountArray.IndexOf([int]$LongestStringLength)
        $PublicKeySansCommentFromSSHAgent = $($ThisPublicKeyAccordingToSSHAgent -split " ")[0..$ArrayPositionBeforeComment] -join " "

        $ThisPublicKeyAccordingToFile = Get-Content $PubKey.FullName
        [System.Collections.ArrayList]$CharacterCountArray = @()
        $ThisPublicKeyAccordingToFile -split " " | foreach {
            $null = $CharacterCountArray.Add($_.Length)
        }
        $LongestStringLength = $($CharacterCountArray | Measure-Object -Maximum).Maximum
        $ArrayPositionBeforeComment = $CharacterCountArray.IndexOf([int]$LongestStringLength)
        $PublicKeySansCommentFromFile = $($ThisPublicKeyAccordingToFile -split " ")[0..$ArrayPositionBeforeComment] -join " "

        if ($PublicKeySansCommentFromSSHAgent -ne $PublicKeySansCommentFromFile) {
            Write-Error "The public key according to the ssh-agent does NOT match the public key content in $($PubKey.FullName)! Halting!"
            $global:FunctionResult = "1"
            return
        }

        Write-Host "The Private Key $PublicKeyLocationFinal has been added to the ssh-agent service." -ForegroundColor Green
        if ($ShowNextSteps) {
            Get-PublicKeyAuthInstructions -PublicKeyLocation $PubKey.FullName -PrivateKeyLocation $PrivKey.FullName
        }
        
        if (!$RemovePrivateKey) {
            Write-Host "It is now safe to delete the private key (i.e. $($PrivKey.FullName)) since it has been added to the SSH Agent Service." -ForegroundColor Yellow
        }
    }
    else {
        if ($ShowNextSteps) {
            Get-PublicKeyAuthInstructions -PublicKeyLocation $PubKey.FullName -PrivateKeyLocation $PrivKey.FullName
        }
    }

    if ($AddToRemoteHostAuthKeys) {
        if ($RemoteHostNetworkInfo.FQDN) {
            $RemoteHostLocation = $RemoteHostNetworkInfo.FQDN
        }
        elseif ($RemoteHostNetworkInfo.HostName) {
            $RemoteHostLocation = $RemoteHostNetworkInfo.HostName
        }
        elseif ($RemoteHostNetworkInfo.IPAddressList[0]) {
            $RemoteHostLocation = $RemoteHostNetworkInfo.IPAddressList[0]
        }
        
        try {
            Add-PublicKeyToRemoteHost -PublicKeyPath $PubKey.FullName -RemoteHost $RemoteHostLocation -RemoteHostUserName $RemoteHostUserName -ErrorAction Stop
        }
        catch {
            Write-Error "Unable to add the public key to the authorized_keys file on $RemoteHost! Halting!"
            $global:FunctionResult = "1"
            return
        }
        
        if (!$AddToSSHAgent) {
            Write-Host "You can now ssh to $RemoteHost using public key authentication using the following command:" -ForegroundColor Green
            Write-Host "    ssh -i $PubKey.FullName $RemoteHostUserName@$RemoteHostLocation" -ForegroundColor Green
        }
        else {
            Write-Host "You can now ssh to $RemoteHost using public key authentication using the following command:" -ForegroundColor Green
            Write-Host "    ssh $RemoteHostUserName@$RemoteHostLocation" -ForegroundColor Green
        }
    } 

    [pscustomobject]@{
        PublicKeyFilePath       = $PubKey.FullName
        PrivateKeyFilePath      = if (!$RemovePrivateKey) {$PrivKey.FullName} else {"PrivateKey was deleted after being added to the ssh-agent"}
        PublicKeyContent        = Get-Content "$HOME\.ssh\$NewSSHKeyName.pub"
    }

    ##### END Main Body #####

}


























# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQURxd4ehmWQqSeq4T6HM222nVO
# b4igggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFJlQHrjvonL9ULuu
# cYO6byWsgwKZMA0GCSqGSIb3DQEBAQUABIIBAD6dCsuwLhuuGy3nZ/1NdcNdGVpT
# T1BYaeE9/tyO2SAoL0M0CcyydHkDSl+rkHL9vbNGBSuzes92VgolCX0Sq6NbTRTf
# 2HqWlQoCYoEOYXgLPbVW0RirADvtJl95X0dv3UXhBCaP6745a2iABuD3Yc1cH+TW
# tCj1Y//qD6ajSR6GU8YCi/ry/FqbKot2bwaBHMqQKSn6+1MRi/jNcHRfJ9CzFy/6
# HHdjlW5hXwragRMHWvnO98kHL8oQDyi4C/O+vSdbjuY5cqFVogyMTDWY0UDYEzvJ
# jaXoO3fqmR9z4NZYnHBaEgO1s/RcCmlFpXoXhIPwe7gz4ZJ/8RTemPLQRdM=
# SIG # End signature block
