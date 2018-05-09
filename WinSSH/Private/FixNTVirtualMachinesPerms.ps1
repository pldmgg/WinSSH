<#
    The function uses the NTFSSecurity Module to set "ReadAndExecute, Synchronize" permissions
    for the "NT VIRTUAL MACHINE\Virtual Machines" account on:
        - The specified $Directory,
        - All child items of $Directory via "ThisFolderSubFoldersAndFiles"; and
        - All Parent Directories of $Directory via "ThisFolderOnly" up to the root drive.
#>
function FixNTVirtualMachinesPerms {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$True)]
        [string]$DirectoryPath
    )

    ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####

    if (! $(Test-Path $DirectoryPath)) {
        Write-Error "The path $DirectoryPath was not found! Halting!"
        $global:FunctionResult = "1"
        return
    }

    if ($(Get-Module).Name -notcontains "PackageManagement") {
        try {
            $PMImport = Import-Module PackageManagement -ErrorAction SilentlyContinue -PassThru
            if (!$PMImport) {throw "Problem importing module PackageManagement!"}
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            return
        }
    }
    if ($(Get-Module).Name -notcontains "PowerShellGet") {
        try {
            $PSGetImport = Import-Module PowerShellGet -ErrorAction SilentlyContinue -PassThru
            if (!$PSGetImport) {throw "Problem importing module PowerShellGet!"}
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            return
        }
    }
    if ($(Get-Module -ListAvailable).Name -notcontains "NTFSSecurity") {
        try {
            Install-Module -Name NTFSSecurity -ErrorAction SilentlyContinue -ErrorVariable NTFSSecInstallErr
            if ($NTFSSecInstallErr) {throw "Problem installing the NTFSSecurity Module!"}
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            return
        }
    }
    if ($(Get-Module).Name -notcontains "NTFSSecurity") {
        try {
            $NTFSSecImport = Import-Module NTFSSecurity -ErrorAction SilentlyContinue -PassThru
            if (!$NTFSSecImport) {throw "Problem importing module NTFSSecurity!"}
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            return
        }
    }

    ##### END Variable/Parameter Transforms and PreRun Prep #####


    ##### BEGIN Main Body #####

    $NTFSAccessInfo = Get-NTFSAccess $DirectoryPath
    $NTFSAccessInfoVMs = $NTFSAccessInfo | Where-Object {$_.Account -eq "NT VIRTUAL MACHINE\Virtual Machines"}
    if ($NTFSAccessInfoVMs) {
        # TODO: Figure out the appropriate way to get the 'AppliesTo' Properties. The below works, but is bad.
        $NTFSAccessInfoVMsContent = $($NTFSAccessInfoVMs| Out-String) -split "`n"
        $NTFSAccessInfoHeaders = $NTFSAccessInfoVMsContent -match '-------'
        $IndexNumber = $NTFSAccessInfoVMsContent.Indexof("$NTFSAccessInfoHeaders")
        $AppliesToPrep = $NTFSAccessInfoVMsContent[$($IndexNumber+1)..$($NTFSAccessInfoVMsContent.Count-1)] | Where-Object {$_ -match "[\w]"}
        [System.Collections.ArrayList][Array]$AppliesTo = $($($($AppliesToPrep | foreach {$_ -replace "[\s]+"," "}) -split "(Allow|Deny)[\s](True|False)")[0].Trim() -split " ")[-1]
    }

    # NOTE: The below string "ThisFolderSubfolders" is not the full setting (i.e. "ThisFolderSubfoldersAndFiles").
    # I match on an incomplete string versus using the '-contains' comparison operator because I don't know the
    # appropriate way of getting the  'Applies To' property from Get-NTFSAccess output. See the above 'TODO:' comment.
    if ($NTFSAccessInfo.Account -notcontains "NT VIRTUAL MACHINE\Virtual Machines" -or
    $($NTFSAccessInfo.Account -contains "NT VIRTUAL MACHINE\Virtual Machines" -and ![bool]$($AppliesTo -match "ThisFolderSubfolders"))
    ) {
        Add-NTFSAccess -Path $DirectoryPath -Account "NT VIRTUAL MACHINE\Virtual Machines" -AccessRights "ReadAndExecute, Synchronize" -AccessType Allow -AppliesTo ThisFolderSubfoldersAndFiles
    }

    $ParentDirThatNeedsPermissions = $DirectoryPath | Split-Path -Parent
    while (-not [System.String]::IsNullOrEmpty($ParentDirThatNeedsPermissions)) {
        $NTFSAccessInfo = Get-NTFSAccess $ParentDirThatNeedsPermissions
        $NTFSAccessInfoVMs = $NTFSAccessInfo | Where-Object {$_.Account -eq "NT VIRTUAL MACHINE\Virtual Machines"}
        if ($NTFSAccessInfoVMs) {
            $NTFSAccessInfoVMsContent = $($NTFSAccessInfoVMs| Out-String) -split "`n"
            $NTFSAccessInfoHeaders = $NTFSAccessInfoVMsContent -match '-------'
            $IndexNumber = $NTFSAccessInfoVMsContent.Indexof("$NTFSAccessInfoHeaders")
            $AppliesToPrep = $NTFSAccessInfoVMsContent[$($IndexNumber+1)..$($NTFSAccessInfoVMsContent.Count-1)] | Where-Object {$_ -match "[\w]"}
            [System.Collections.ArrayList][Array]$AppliesTo = $($($($AppliesToPrep | foreach {$_ -replace "[\s]+"," "}) -split "(Allow|Deny)[\s](True|False)")[0].Trim() -split " ")[-1]
        }

        if ($NTFSAccessInfo.Account -notcontains "NT VIRTUAL MACHINE\Virtual Machines" -or
        $($NTFSAccessInfo.Account -contains "NT VIRTUAL MACHINE\Virtual Machines" -and ![bool]$($AppliesTo -match "ThisFolderOnly"))
        ) {
            Add-NTFSAccess -Path $ParentDirThatNeedsPermissions -Account "NT VIRTUAL MACHINE\Virtual Machines" -AccessRights "ReadAndExecute, Synchronize" -AccessType Allow -AppliesTo ThisFolderOnly
        }

        $ParentDirThatNeedsPermissions = $ParentDirThatNeedsPermissions | Split-Path -Parent
    }

    ##### END Main Body #####
}

# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUsgI1wkGAdCD7g9Zq1eMipGzp
# eb2gggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFOvvI72MUiaRSUbn
# ABwAfic2QxYmMA0GCSqGSIb3DQEBAQUABIIBADXL8i6EExApSbNsUF5pGD0nDIZu
# E2+bzNe+rMrXF6ph75eBh2SqV4A5QV+M4fXA1RoU29WnpsQWhQOSeCoHl6Ypx46f
# R//mjSsjxlyceH8csaGgJzI5vBb1fn44Tfa9Z506c6Hdpj07agSCE4R3D9oYNUBW
# ldUxSn9YOy4eiFgJm4hNJ2szL9sEpQIaPFhshrck0mSmrMc92KAUq+9P6pl0AH2T
# dcaaKWsU3tWsmGIkRq4ZELyjwvIbUESbcK7YnIUwTR4//Yn27KGOiYCG/QrCP5Fl
# dsnDW01u2RiXjhEkqzUJ/zG28tZ24WQPMhOTECzZrOU5OiDWTTZPF+hi8Qg=
# SIG # End signature block
