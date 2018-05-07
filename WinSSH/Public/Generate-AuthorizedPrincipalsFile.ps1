<#
    .SYNOPSIS
        This function adds the specified User Accounts (both Local and Domain) to the file 
        'C:\ProgramData\ssh\authorized_principals' on the Local Host. Adding these User Accounts
        to the 'authorized_principals' file allows these users to ssh into the Local Host.

        IMPORTANT NOTE: The Generate-AuthorizedPrincipalsFile will only ADD users to the authorized_principals
        file (if they're not already in there). It WILL NOT delete or otherwise overwrite existing users in the file

    .DESCRIPTION
        See .SYNOPSIS

    .NOTES

    .PARAMETER AuthorizedPrincipalsFileLocation
        This parameter is OPTIONAL.

        This parameter takes a string that represents the full path to desired location of the newly generated
        'authorized_principals' file. If this parameter is NOT used, the function will default to writing the
        'authorized_principals' file to the 'C:\ProgramData\ssh' directory. If that directory does not exist,
        then it will be written to the 'C:\Program Files\OpenSSH-Win64' directory. If that directory does not
        exist, the function will halt.

    .PARAMETER UserGroupToAdd
        This parameter is OPTIONAL, however, either this parameter or the -UsersToAdd parameter is REQUIRED.

        This parameter takes an array of strings. Possible string values are:
            - AllUsers
            - LocalAdmins
            - LocalUsers
            - DomainAdmins
            - DomainUsers
        
        Using "LocalAdmins" will add all User Accounts that are members of the Built-In 'Administrators' Security Group
        on the Local Host to the authorized_principals file.

        Using "LocalUsers" will add all user Accounts that are members of the Built-In 'Users' Security Group on
        the Local Host to the authorized_principals file.

        Using "DomainAdmins" will add all User Accounts that are members of the "Domain Admins" Security Group in
        Active Directory to the authorized_principals file.

        Using "Domain Users" will add all User Accounts that are members of the "Domain Users" Security Group in
        Active Directory to the authorized_principals file.

        Using "AllUsers" will add User Accounts that are members of all of the above Security Groups to the
        authorized_principals file.

        You CAN use this parameter in conjunction with the -UsersToAdd parameter, and this function
        DOES check for repeats, so don't worry about overlap.

    .PARAMETER UsersToAdd
        This parameter is OPTIONAL, however, either this parameter or the -UserGroupToAdd parameter is REQUIRED.

        This parameter takes an array of strings, each of which represents either a Local User Account
        or a Domain User Account. Local User Accounts MUST be in the format <UserName>@<LocalHostComputerName> and
        Domain User Accounts MUST be in the format <UserName>@<DomainPrefix>. (To clarify DomainPrefix: if your
        domain is, for example, 'zero.lab', your DomainPrefix would be 'zero').

        These strings will be added to the authorized_principals file, and these User Accounts
        will be permitted to SSH into the Local Host.

        You CAN use this parameter in conjunction with the -UserGroupToAdd parameter, and this function
        DOES check for repeats, so don't worry about overlap.

    .EXAMPLE
        # Open an elevated PowerShell Session, import the module, and -

        PS C:\Users\zeroadmin> $AuthorizedPrincipalsFile = Generate-AuthorizedPrincipalsFile -UserGroupToAdd @("LocalAdmins","DomainAdmins")
        
#>
function Generate-AuthorizedPrincipalsFile {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [string]$AuthorizedPrincipalsFileLocation,

        [Parameter(Mandatory=$False)]
        [ValidateSet("AllUsers","LocalAdmins","LocalUsers","DomainAdmins","DomainUsers")]
        [string[]]$UserGroupToAdd,

        [Parameter(Mandatory=$False)]
        [ValidatePattern("[\w]+@[\w]+")]
        [string[]]$UsersToAdd
    )

    if (!$AuthorizedPrincipalsFileLocation) {
        if (Test-Path "$env:ProgramData\ssh") {
            $sshdir = "$env:ProgramData\ssh"
        }
        elseif (Test-Path "$env:ProgramFiles\OpenSSH-Win64") {
            $sshdir = "$env:ProgramFiles\OpenSSH-Win64"
        }
        if (!$sshdir) {
            Write-Error "Unable to find ssh directory at '$env:ProgramData\ssh' or '$env:ProgramFiles\OpenSSH-Win64'! Halting!"
            $global:FunctionResult = "1"
            return
        }

        $AuthorizedPrincipalsFileLocation = "$sshdir\authorized_principals"
    }

    $AuthorizedPrincipalsFileLocation = $AuthorizedPrincipalsFileLocation -replace '\\','/'

    # Get the content of $AuthorizedPrincipalsFileLocation to make sure we don't add anything that is already in there
    if (Test-Path $AuthorizedPrincipalsFileLocation) {
        $OriginalAuthPrincContent = Get-Content $AuthorizedPrincipalsFileLocation
    }

    if ($(!$UserGroupToAdd -and !$UsersToAdd) -or $UserGroupToAdd -contains "AllUsers") {
        $AllUsers = $True
    }
    if ($AllUsers) {
        $LocalAdmins = $True
        $LocalUsers = $True
        $DomainAdmins = $True
        $DomainUsers = $True
    }
    else {
        # Switch automatically loops through an array if the object passed is an array
        if ($UserGroupToAdd) {
            switch ($UserGroupToAdd) {
                'LocalAdmins'   {$LocalAdmins = $True}
                'LocalUsers'    {$LocalUsers = $True}
                'DomainAdmins'  {$DomainAdmins = $True}
                'DomainUsers'   {$DomainUsers = $True}
            }
        }
    }

    $ComputerSystemCim = Get-CimInstance Win32_ComputerSystem
    $PartOfDomain = $ComputerSystemCim.PartOfDomain

    if (!$PartOfDomain) {
        if ($DomainAdmins) {
            $DomainAdmins = $False
        }
        if ($DomainUsers) {
            $DomainUsers = $False
        }
    }
    else {
        $ThisDomainAsArrayOfStrings = $(Get-CimInstance Win32_NTDomain).DomainName | Where-Object {$_ -match "[\w]"}
        $ThisDomainName = $ThisDomainAsArrayOfStrings -join "."
    }

    # Get ready to start writing to $sshdir\authorized_principals...

    $StreamWriter = [System.IO.StreamWriter]::new($AuthorizedPrincipalsFileLocation, $True)
    [System.Collections.ArrayList]$AccountsAdded = @()

    try {
        if ($LocalAdmins) {
            $LocalAdminAccounts = Get-LocalGroupMember -Group "Administrators" | Where-Object {$_.PrincipalSource -eq "Local"}
            $AccountsReformatted = foreach ($AcctItem in $LocalAdminAccounts) {
                $AcctNameSplit = $AcctItem.Name -split "\\"
                $ReformattedName = "$($AcctNameSplit[1])@$($AcctNameSplit[0])"
                $ReformattedName
            }

            foreach ($Acct in $AccountsReformatted) {
                if ($AccountsAdded -notcontains $Acct -and $OriginalAuthPrincContent -notcontains $Acct) {
                    # NOTE: $True below means that the content will *appended* to $AuthorizedPrincipalsFileLocation
                    $StreamWriter.WriteLine($Acct)

                    # Keep track of the accounts we're adding...
                    $null = $AccountsAdded.Add($Acct)
                }
            }
        }

        if ($LocalUsers) {
            $LocalUserAccounts = Get-LocalGroupMember -Group "Users" | Where-Object {$_.PrincipalSource -eq "Local"}

            $AccountsReformatted = foreach ($AcctItem in $LocalUserAccounts) {
                $AcctNameSplit = $AcctItem.Name -split "\\"
                $ReformattedName = "$($AcctNameSplit[1])@$($AcctNameSplit[0])"
                $ReformattedName
            }

            foreach ($Acct in $AccountsReformatted) {
                if ($AccountsAdded -notcontains $Acct -and $OriginalAuthPrincContent -notcontains $Acct) {
                    # NOTE: $True below means that the content will *appended* to $AuthorizedPrincipalsFileLocation
                    $StreamWriter.WriteLine($Acct)

                    # Keep track of the accounts we're adding...
                    $null = $AccountsAdded.Add($Acct)
                }
            }
        }

        if ($DomainAdmins) {
            if (!$UserObjectsInLDAP) {
                try {
                    $UserObjectsInLDAP = GetUserObjectsInLDAP -ErrorAction Stop
                    if (!$UserObjectsInLDAP) {throw "Problem with GetUserObjectsInLDAP function! Halting!"}
                }
                catch {
                    Write-Error $_
                    $global:FunctionResult = "1"
                    throw
                }
            }
            
            $DomainAdminsPrep = $UserObjectsInLDAP | Where-Object {$_.memberOf -match "Domain Admins"}
            $DomainAdminAccounts = $DomainAdminsPrep.distinguishedName | foreach {$($($_ -split ",")[0] -split "=")[-1]}

            $AccountsReformatted = $DomainAdminAccounts | foreach {"$_" + "@" + $ThisDomainName}

            foreach ($Acct in $AccountsReformatted) {
                if ($AccountsAdded -notcontains $Acct -and $OriginalAuthPrincContent -notcontains $Acct) {
                    # NOTE: $True below means that the content will *appended* to $AuthorizedPrincipalsFileLocation
                    $StreamWriter.WriteLine($Acct)

                    # Keep track of the accounts we're adding...
                    $null = $AccountsAdded.Add($Acct)
                }
            }
        }

        if ($DomainUsers) {
            if (!$UserObjectsInLDAP) {
                try {
                    $UserObjectsInLDAP = GetUserObjectsInLDAP -ErrorAction Stop
                    if (!$UserObjectsInLDAP) {throw "Problem with GetUserObjectsInLDAP function! Halting!"}
                }
                catch {
                    Write-Error $_
                    $global:FunctionResult = "1"
                    throw
                }
            }

            $DomainUsersPrep = $UserObjectsInLDAP | Where-Object {$_.memberOf -match "Users"}
            $DomainUserAccounts = $DomainUsersPrep.distinguishedName | foreach {$($($_ -split ",")[0] -split "=")[-1]}

            $AccountsReformatted = $DomainAdminAccounts | foreach {"$_" + "@" + $ThisDomainName}

            foreach ($Acct in $AccountsReformatted) {
                if ($AccountsAdded -notcontains $Acct -and $OriginalAuthPrincContent -notcontains $Acct) {
                    # NOTE: $True below means that the content will *appended* to $AuthorizedPrincipalsFileLocation
                    $StreamWriter.WriteLine($Acct)

                    # Keep track of the accounts we're adding...
                    $null = $AccountsAdded.Add($Acct)
                }
            }
        }

        if ($UsersToAdd) {
            foreach ($Acct in $UsersToAdd) {
                if ($AccountsAdded -notcontains $Acct -and $OriginalAuthPrincContent -notcontains $Acct) {
                    # NOTE: $True below means that the content will *appended* to $AuthorizedPrincipalsFileLocation
                    $StreamWriter.WriteLine($Acct)

                    # Keep track of the accounts we're adding...
                    $null = $AccountsAdded.Add($Acct)
                }
            }
        }

        $StreamWriter.Close()

        Get-Item $AuthorizedPrincipalsFileLocation
    }
    catch {
        $StreamWriter.Close()
    }
}
















































# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUDufntAPlxU/y8ZqusLPVyO+s
# +C+gggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFGIfKZ+cE7coVSr1
# 50/ypyWQAqCaMA0GCSqGSIb3DQEBAQUABIIBADHbj+BI7SS/G2kEU6lXQP6uD9Zv
# Foq4a+nX/2bK26aTY0wyEHXB0hGeAwN2sjc7QKu/OT7sVmgvXiwwsd2Zp8kafT9+
# kX326dR5QNX5M9X2id7FhC2RaLfnzitdqVupGRvK5IdVXCdOQnqt27Z1PSEe2Qd4
# 3kiiHuCXHISA3JyPK2s27u9KWFT0OBNiw5puSX+GfDzj5e1SC6iYUd+YdVcFvCcX
# yiMLhmfsViXdbiax4Wcp8zW3RIAfu95VIfuY8kO75y7g/TAJGx9kHDxaCJQWlq7B
# a4gFLFpmr18nU/i2PNsA76RT+PrtNeGBKJN58hnVpqUDYKl2FySgB2FynnM=
# SIG # End signature block
