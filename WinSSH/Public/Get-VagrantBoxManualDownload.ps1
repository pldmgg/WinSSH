<#
    .SYNOPSIS
        This function downloads a Vagrant Box (.box file) to the specified -DownloadDirectory

    .DESCRIPTION
        See .SYNOPSIS

    .NOTES

    .PARAMETER VagrantBox
        This parameter is MANDATORY.

        This parameter takes a string that represents the name of a Vagrant Box that can be found
        on https://app.vagrantup.com. Example: centos/7

    .PARAMETER VagrantProvider
        This parameter is MANDATORY.

        This parameter takes a string that must be one of the following values:
        "hyperv","virtualbox","vmware_workstation","docker"

    .PARAMETER DownloadDirectory
        This parameter is MANDATORY.

        This parameter takes a string that represents a full path to a directory that the .box file
        will be downloaded to.

    .PARAMETER SkipPreDownloadCheck
        This parameter is OPTIONAL.

        This parameter is a switch.

        By default, this function checks to make sure there is eough space on the target drive BEFORE
        it attempts ot download the .box file. This calculation ensures that there is at least 2GB of
        free space on the storage drive after the .box file has been downloaded. If you would like to
        skip this check, use this switch.

    .PARAMETER Repository
        This parameter is OPTIONAL.

        This parameter currently only takes the string 'Vagrant', which refers to the default Vagrant Box
        Repository at https://app.vagrantup.com. Other Vagrant Repositories exist. At some point, this
        function will be updated to include those other repositories.

    .EXAMPLE
        # Open an elevated PowerShell Session, import the module, and -

        PS C:\Users\zeroadmin> Fix-SSHPermissions
        
#>
function Get-VagrantBoxManualDownload {
    [CmdletBinding(DefaultParameterSetName='ExternalNetworkVM')]
    Param(
        [Parameter(Mandatory=$True)]
        [ValidatePattern("[\w]+\/[\w]+")]
        [string]$VagrantBox,

        [Parameter(Mandatory=$True)]
        [ValidateSet("hyperv","virtualbox","vmware_workstation","docker")]
        [string]$VagrantProvider,

        [Parameter(Mandatory=$True)]
        [string]$DownloadDirectory,

        [Parameter(Mandatory=$False)]
        [switch]$SkipPreDownloadCheck,

        [Parameter(Mandatory=$False)]
        [ValidateSet("Vagrant")]
        [string]$Repository
    )

    ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####

    if (!$(Test-Path $DownloadDirectory)) {
        Write-Error "The path $DownloadDirectory was not found! Halting!"
        $global:FunctionResult = "1"
        return
    }
    if (!$(Get-Item $DownloadDirectory).PSIsContainer) {
        Write-Error "$DownloadDirectory is NOT a directory! Halting!"
        $global:FunctionResult = "1"
        return
    }

    if (!$Repository) {
        $Repository = "Vagrant"
    }

    ##### END Variable/Parameter Transforms and PreRun Prep #####


    ##### BEGIN Main Body #####

    if ($Repository -eq "Vagrant") {
        # Find the latest version of the .box you want that also has the provider you want
        $BoxInfoUrl = "https://app.vagrantup.com/" + $($VagrantBox -split '/')[0] + "/boxes/" + $($VagrantBox -split '/')[1]
        $VagrantBoxVersionPrep = Invoke-WebRequest -Uri $BoxInfoUrl
        $VersionsInOrderOfRelease = $($VagrantBoxVersionPrep.Links | Where-Object {$_.href -match "versions"}).innerText -replace 'v',''
        $VagrantBoxLatestVersion = $VersionsInOrderOfRelease[0]

        foreach ($version in $VersionsInOrderOfRelease) {
            $VagrantBoxDownloadUrl = "https://vagrantcloud.com/" + $($VagrantBox -split '/')[0] + "/boxes/" + $($VagrantBox -split '/')[1] + "/versions/" + $version + "/providers/" + $VagrantProvider + ".box"
            Write-Host "Trying download from $VagrantBoxDownloadUrl ..."

            try {
                # Make sure the Url exists...
                $HTTP_Request = [System.Net.WebRequest]::Create($VagrantBoxDownloadUrl)
                $HTTP_Response = $HTTP_Request.GetResponse()

                Write-Host "Received HTTP Response $($HTTP_Response.StatusCode)"
            }
            catch {
                continue
            }

            try {
                $bytes = $HTTP_Response.GetResponseHeader("Content-Length")
                $BoxSizeInMB = [Math]::Round($bytes / 1MB)

                $FinalVagrantBoxDownloadUrl = $VagrantBoxDownloadUrl
                $BoxVersion = $version

                break
            }
            catch {
                continue
            }
        }

        if (!$FinalVagrantBoxDownloadUrl) {
            Write-Error "Unable to resolve URL for Vagrant Box $VagrantBox that matches the specified provider (i.e. $VagrantProvider)! Halting!"
            $global:FunctionResult = "1"
            return
        }

        Write-Host "FinalVagrantBoxDownloadUrl is $FinalVagrantBoxDownloadUrl"

        if (!$SkipPreDownloadCheck) {
            # Determine if we have enough space on the $DownloadDirectory's Drive before downloading
            if ([bool]$(Get-Item $DownloadDirectory).LinkType) {
                $DownloadDirLogicalDriveLetter = $(Get-Item $DownloadDirectory).Target[0].Substring(0,1)
            }
            else {
                $DownloadDirLogicalDriveLetter = $DownloadDirectory.Substring(0,1)
            }
            $DownloadDirDriveInfo = Get-WmiObject Win32_LogicalDisk -ComputerName $env:ComputerName -Filter "DeviceID='$DownloadDirLogicalDriveLetter`:'"
            
            if ($([Math]::Round($DownloadDirDriveInfo.FreeSpace / 1MB)-2000) -gt $BoxSizeInMB) {
                $OutFileName = $($VagrantBox -replace '/','-') + "_" + $BoxVersion + ".box"
            }
            if ($([Math]::Round($DownloadDirDriveInfo.FreeSpace / 1MB)-2000) -lt $BoxSizeInMB) {
                Write-Error "Not enough space on $DownloadDirLogicalDriveLetter`:\ Drive to download the compressed .box file and subsequently expand it! Halting!"
                $global:FunctionResult = "1"
                return
            }
        }
        else {
            $OutFileName = $($VagrantBox -replace '/','-') + "_" + $BoxVersion + ".box"
        }

        # Download the .box file
        try {
            # System.Net.WebClient is a lot faster than Invoke-WebRequest for large files...
            Write-Host "Downloading $FinalVagrantBoxDownloadUrl ..."
            #& $CurlCmd -Lk -o "$DownloadDirectory\$OutFileName" "$FinalVagrantBoxDownloadUrl"
            $WebClient = [System.Net.WebClient]::new()
            $WebClient.Downloadfile($FinalVagrantBoxDownloadUrl, "$DownloadDirectory\$OutFileName")
            $WebClient.Dispose()
        }
        catch {
            $WebClient.Dispose()
            Write-Error $_
            Write-Warning "If $FinalVagrantBoxDownloadUrl definitely exists, starting a fresh PowerShell Session could remedy this issue!"
            $global:FunctionResult = "1"
            return
        }
    }

    Get-Item "$DownloadDirectory\$OutFileName"

    ##### END Main Body #####
}






























# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU29DhyqWr0kyaqQOgGCFpmsO4
# ZCqgggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFNUlYCBecq+4ow6H
# K6hAsEMBs+LfMA0GCSqGSIb3DQEBAQUABIIBAISI5lkNVfe2W4YyRSlzBTvgX3ND
# uu6ynQ7Oqk0+FX7OkT89DPGY8FYuhCwBIXujdRbsQ+Y7xdeVOX4ALAaE7ULk0B6H
# hLVFJL1tJqzTsRTDSdZzxF6M8vE083LjjmdhrGieiwOOFjzo8kVIbOHLIVCK6IPg
# PdPYs80qqF9CzgPQ/uz36yp4e4JTTbqtRN/mr+sAblcG+5CpMsSRhQuksai8xGmE
# ZFHxPmCGtdvQaoBaHgVvYrbPK8CmJvbn7Q/oE+J+j26Xk1WI7vAeMGp5mXR7oIDe
# gNviHGe0qDVcwxNAU7QVimMI5acKCxpVihnzIx1CefTisaL1YKS0BD7PNVQ=
# SIG # End signature block
