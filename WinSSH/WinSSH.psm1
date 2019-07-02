[Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls"

# Get public and private function definition files.
[array]$Public  = Get-ChildItem -Path "$PSScriptRoot\Public\*.ps1" -ErrorAction SilentlyContinue
[array]$Private = Get-ChildItem -Path "$PSScriptRoot\Private\*.ps1" -ErrorAction SilentlyContinue
$ThisModule = $(Get-Item $PSCommandPath).BaseName

# Dot source the Private functions
foreach ($import in $Private) {
    try {
        . $import.FullName
    }
    catch {
        Write-Error -Message "Failed to import function $($import.FullName): $_"
    }
}

[System.Collections.Arraylist]$ModulesToInstallAndImport = @()
if (Test-Path "$PSScriptRoot/module.requirements.psd1") {
    $ModuleManifestData = Import-PowerShellDataFile "$PSScriptRoot/module.requirements.psd1"
    #$ModuleManifestData.Keys | Where-Object {$_ -ne "PSDependOptions"} | foreach {$null = $ModulesToinstallAndImport.Add($_)}
    $($ModuleManifestData.GetEnumerator()) | foreach {
        if ($_.Key -ne "PSDependOptions") {
            $PSObj = [pscustomobject]@{
                Name    = $_.Key
                Version = $_.Value.Version
            }
            $null = $ModulesToinstallAndImport.Add($PSObj)
        }
    }
}

if ($PSVersionTable.Platform -eq "Unix" -or $PSVersionTable.OS -match "Darwin") {
    $env:SudoPwdPrompt = $True

    if ($ModulesToInstallAndImport.Count -gt 0) {
        foreach ($ModuleItem in $ModulesToInstallAndImport) {
            if ($ModuleItem.Name -match "WinSSH|NTFSSecurity|WindowsCompatibility") {
                continue
            }

            if (!$(Get-Module -ListAvailable $ModuleItem.Name -ErrorAction SilentlyContinue)) {
                try {
                    Install-Module $ModuleItem.Name -AllowClobber -ErrorAction Stop
                }
                catch {
                    try {
                        Install-Module $ModuleItem.Name -AllowClobber -AllowPrerelease -ErrorAction Stop
                    }
                    catch {
                        Write-Error $_
                        Write-Error "Unable to import all Module dependencies! Please unload $ThisModule via 'Remove-Module $ThisModule'! Halting!"
                        $global:FunctionResult = "1"
                        return
                    }
                }
            }
            
            # Make sure the Module Manifest file name and the Module Folder name are exactly the same case
            $env:PSModulePath -split ':' | foreach {
                Get-ChildItem -Path $_ -Directory | Where-Object {$_ -match $ModuleItem.Name}
            } | foreach {
                $ManifestFileName = $(Get-ChildItem -Path $_ -Recurse -File | Where-Object {$_.Name -match "$($ModuleItem.Name)\.psd1"}).BaseName
                if (![bool]$($_.Name -cmatch $ManifestFileName)) {
                    Rename-Item $_ $ManifestFileName
                }
            }

            if (!$(Get-Module $ModuleItem.Name -ErrorAction SilentlyContinue)) {
                try {
                    Import-Module $ModuleItem.Name -ErrorAction Stop -WarningAction SilentlyContinue
                }
                catch {
                    Write-Error $_
                    Write-Error "Unable to import all Module dependencies! Please unload $ThisModule via 'Remove-Module $ThisModule'! Halting!"
                    $global:FunctionResult = "1"
                    return
                }
            }
        }
    }
}

if (!$PSVersionTable.Platform -or $PSVersionTable.Platform -eq "Win32NT") {
    if ($ModulesToInstallAndImport.Count -gt 0) {
        # NOTE: If you're not sure if the Required Module is Locally Available or Externally Available,
        # add it the the -RequiredModules string array just to be certain
        $InvModDepSplatParams = @{
            RequiredModules                     = $ModulesToInstallAndImport
            InstallModulesNotAvailableLocally   = $True
            ErrorAction                         = "SilentlyContinue"
            WarningAction                       = "SilentlyContinue"
        }
        $ModuleDependenciesMap = InvokeModuleDependencies @InvModDepSplatParams
    }
}

# Public Functions


<#
    .SYNOPSIS
        This function connects to a Remote Host via ssh and adds the specified User/Client SSH Public Key to
        the ~/.ssh/authorized_keys file on that Remote Host. As long as you can connect to the Remote Host via
        ssh, this function will work with both Windows and Linux targets.

    .DESCRIPTION
        See .SYNOPSIS

    .NOTES

    .PARAMETER PublicKeyPath
        This parameter is MANDATORY.

        This parameter takes a string that represents the full path to the SSH User/Client Public Key that you
        would like to add to the Remote Host's ~/.ssh/authorized_keys file.

    .PARAMETER RemoteHost
        This parameter is MANDATORY.

        This parameter takes a string that represents an IP Address or DNS-Resolvable name to a remote host
        running an sshd server.

    .PARAMETER RemoteHostUserName
        This parameter is MANDATORY,

        This parameter takes a string that represents the User Name you would like to use to ssh
        into the Remote Host.

    .EXAMPLE
        # Open an elevated PowerShell Session, import the module, and -

        PS C:\Users\zeroadmin> $SplatParams = @{
            PublicKeyPath       = "$HOME\.ssh\id_rsa.pub"
            RemoteHost          = "Ubuntu18.zero.lab"
            RemoteHostUserName  = "zero\zeroadmin"
        }
        PS C:\Users\zeroadmin> Add-PublicKeyToRemoteHost @SplatParams
#>
function Add-PublicKeyToRemoteHost {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [string]$PublicKeyPath,

        [Parameter(Mandatory=$True)]
        [string]$RemoteHost,

        [Parameter(Mandatory=$True)]
        [string]$RemoteHostUserName
    )

    ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####

    if (!$(Test-Path $PublicKeyPath)) {
        Write-Error "The path $PublicKeyPath was not found! Halting!"
        $global:FunctionResult = "1"
        return
    }

    try {
        $RemoteHostNetworkInfo = ResolveHost -HostNameOrIP $RemoteHost -ErrorAction Stop
    }
    catch {
        Write-Error "Unable to resolve $RemoteHost! Halting!"
        $global:FunctionResult = "1"
        return
    }    
    
    if (![bool]$(Get-Command ssh -ErrorAction SilentlyContinue)) {
        Write-Error "Unable to find ssh.exe! Halting!"
        $global:FunctionResult = "1"
        return
    }

    $PubKeyContent = Get-Content $PublicKeyPath

    ##### END Variable/Parameter Transforms and PreRun Prep #####


    ##### BEGIN Main Body #####

    if ($RemoteHostNetworkInfo.FQDN) {
        $RemoteHostLocation = $RemoteHostNetworkInfo.FQDN
    }
    elseif ($RemoteHostNetworkInfo.HostName) {
        $RemoteHostLocation = $RemoteHostNetworkInfo.HostName
    }
    elseif ($RemoteHostNetworkInfo.IPAddressList[0]) {
        $RemoteHostLocation = $RemoteHostNetworkInfo.IPAddressList[0]
    }

    #ssh -t $RemoteHostUserName@$RemoteHostLocation "echo '$PubKeyContent' >> ~/.ssh/authorized_keys"
    if ($RemoteHostUserName -match "\\|@") {
        if ($RemoteHostUserName -match "\\") {
            $DomainPrefix = $($RemoteHostUserName -split "\\")[0]
        }
        if ($RemoteHostUserName -match "@") {
            $DomainPrefix = $($RemoteHostUserName -split "\\")[-1]
        }
    }

    if (!$DomainPrefix) {
        #ssh -o "StrictHostKeyChecking=no" -o "BatchMode=yes" -t $RemoteHostUserName@$RemoteHostLocation "echo '$PubKeyContent' >> ~/.ssh/authorized_keys"
        ssh -o "StrictHostKeyChecking=no" -t $RemoteHostUserName@$RemoteHostLocation "echo '$PubKeyContent' >> ~/.ssh/authorized_keys"
    }
    else {
        #ssh -o "StrictHostKeyChecking=no" -o "BatchMode=yes" -t $RemoteHostUserName@$DomainPrefix@$RemoteHostLocation "echo '$PubKeyContent' >> ~/.ssh/authorized_keys"
        ssh -o "StrictHostKeyChecking=no" -t $RemoteHostUserName@$DomainPrefix@$RemoteHostLocation "echo '$PubKeyContent' >> ~/.ssh/authorized_keys"
    }

    ##### END Main Body #####
}


<#
    .SYNOPSIS
        This function gets the SSL Certificate at the specified IP Address / Port
        and returns an System.Security.Cryptography.X509Certificates.X509Certificate2 object.

    .DESCRIPTION
        See .SYNOPSIS

    .NOTES

    .PARAMETER IPAddress
        This parameter is MANDATORY.

        This parameter takes a string that represents an IP Address.

    .PARAMETER Port
        This parameter is MANDATORY.

        This parameter takes an integer that represents a Port Number (443, 636, etc).

    .EXAMPLE
        # In the below example, 172.217.15.110 happens to be a google.com IP Address

        PS C:\Users\zeroadmin> Check-Cert -IPAddress 172.217.15.110 -Port 443

        Thumbprint                                Subject
        ----------                                -------
        8FBB134B2216D6C71CF4E4431ABD82182922AC7C  CN=*.google.com, O=Google Inc, L=Mountain View, S=California, C=US
        
#>
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


<#
    .SYNOPSIS
        Microsoft's port of OpenSSH (OpenSSH-Win64) ultimately adds RSA Private Keys to the Registry when they are added to the
        ssh-agent service. This function extracts those RSA Private Keys from the Registry. It can only be used under the same
        User Profile that added the key(s) to the ssh-agent in the first place.

    .DESCRIPTION
        See .SYNOPSIS

    .NOTES
        Python Code from: https://github.com/ropnop/windows_sshagent_extract

    .EXAMPLE
        # Open an elevated PowerShell Session, import the module, and -

        PS C:\Users\zeroadmin> Extract-SSHPrivateKeyFromRegistry
#>
function Extract-SSHPrivateKeysFromRegistry {
    [CmdletBinding()]
    Param ()

    $OpenSSHRegistryPath = "HKCU:\Software\OpenSSH\Agent\Keys\"

    $RegistryKeys = Get-ChildItem $OpenSSHRegistryPath | Get-ItemProperty

    if ($RegistryKeys.Length -eq 0) {
        Write-Error "No ssh-agent keys in registry"
        $global:FunctionResult = "1"
        return
    }

    $tempDirectory = [IO.Path]::Combine([IO.Path]::GetTempPath(), [IO.Path]::GetRandomFileName())
    $null = [IO.Directory]::CreateDirectory($tempDirectory)

    Add-Type -AssemblyName System.Security
    [System.Collections.ArrayList]$keys = @()
    $RegistryKeys | foreach {
        $key = @{}
        $comment = [System.Text.Encoding]::ASCII.GetString($_.comment)
        $encdata = $_.'(default)'
        $decdata = [Security.Cryptography.ProtectedData]::Unprotect($encdata, $null, 'CurrentUser')
        $b64key = [System.Convert]::ToBase64String($decdata)
        $key[$comment] = $b64key
        $null = $keys.Add($key)
    }

    ConvertTo-Json -InputObject $keys | Out-File -FilePath "$tempDirectory/extracted_keyblobs.json" -Encoding ascii

    $InstallPython3Result = Install-Program -ProgramName python3 -CommandName python -UseChocolateyCmdLine
    if (!$(Get-Command python -ErrorAction SilentlyContinue)) {
        Write-Error "Unable to find python.exe! Halting!"
        $global:FunctionResult = "1"
        return
    }
    if (!$(Get-Command pip -ErrorAction SilentlyContinue)) {
        Write-Error "Unable to find pip.exe! Halting!"
        $global:FunctionResult = "1"
        return
    }
    pip install pyasn1 pip *> $null
    
    Set-Content -Path "$tempDirectory\extractPrivateKeys.py" -Value @"
#!/usr/bin/env python

# Script to extract OpenSSH private RSA keys from base64 data
# From: https://github.com/ropnop/windows_sshagent_extract

import sys
import base64
import json
try:
    from pyasn1.type import univ
    from pyasn1.codec.der import encoder
except ImportError:
    print("You must install pyasn1")
    sys.exit(0)


def extractRSAKey(data):
    keybytes = base64.b64decode(data)
    offset = keybytes.find(b"ssh-rsa")
    if not offset:
        print("[!] No valid RSA key found")
        return None
    keybytes = keybytes[offset:]

    # This code is re-implemented code originally written by soleblaze in sshkey-grab
    start = 10
    size = getInt(keybytes[start:(start+2)])
    # size = unpack_bigint(keybytes[start:(start+2)])
    start += 2
    n = getInt(keybytes[start:(start+size)])
    start = start + size + 2
    size = getInt(keybytes[start:(start+2)])
    start += 2
    e = getInt(keybytes[start:(start+size)])
    start = start + size + 2
    size = getInt(keybytes[start:(start+2)])
    start += 2
    d = getInt(keybytes[start:(start+size)])
    start = start + size + 2
    size = getInt(keybytes[start:(start+2)])
    start += 2
    c = getInt(keybytes[start:(start+size)])
    start = start + size + 2
    size = getInt(keybytes[start:(start+2)])
    start += 2
    p = getInt(keybytes[start:(start+size)])
    start = start + size + 2
    size = getInt(keybytes[start:(start+2)])
    start += 2
    q = getInt(keybytes[start:(start+size)])

    e1 = d % (p - 1)
    e2 = d % (q - 1)

    keybytes = keybytes[start+size:]

    seq = (
        univ.Integer(0),
        univ.Integer(n),
        univ.Integer(e),
        univ.Integer(d),
        univ.Integer(p),
        univ.Integer(q),
        univ.Integer(e1),
        univ.Integer(e2),
        univ.Integer(c),
    )

    struct = univ.Sequence()

    for i in range(len(seq)):
        struct.setComponentByPosition(i, seq[i])
    
    raw = encoder.encode(struct)
    data = base64.b64encode(raw).decode('utf-8')

    width = 64
    chopped = [data[i:i + width] for i in range(0, len(data), width)]
    top = "-----BEGIN RSA PRIVATE KEY-----\n"
    content = "\n".join(chopped)
    bottom = "\n-----END RSA PRIVATE KEY-----"
    return top+content+bottom

def getInt(buf):
    return int.from_bytes(buf, byteorder='big')


def run(filename):
    with open(filename, 'r') as fp:
        keysdata = json.loads(fp.read())
    
    for jkey in keysdata:
        for keycomment, data in jkey.items():
            privatekey = extractRSAKey(data)
            print("[+] Key Comment: {}".format(keycomment))
            print(privatekey)
            print()
    
    sys.exit(0)

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: {} extracted_keyblobs.json".format(sys.argv[0]))
        sys.exit(0)
    filename = sys.argv[1]
    run(filename)
    
"@

    Push-Location $tempDirectory

    $SSHAgentPrivateKeys = python .\extractPrivateKeys.py .\extracted_keyblobs.json

    [System.Collections.ArrayList]$UpdatedSSHAgentPrivKeyInfoArray = @()
    $SSHAgentPrivateKeysArrayList = [System.Collections.ArrayList]$SSHAgentPrivateKeys
    $NumberOfPrivateKeys = $($SSHAgentPrivateKeys | Where-Object {$_ -eq "-----END RSA PRIVATE KEY-----"}).Count
    for ($i=0; $i -lt $NumberOfPrivateKeys; $i++) {
        $SSHAgentPrivateKeysArrayListClone = $($SSHAgentPrivateKeysArrayList.Clone() -join "`n").Trim() -split "`n"
        New-Variable -Name "KeyInfo$i" -Value $(New-Object System.Collections.ArrayList) -Force

        :privkeylines foreach ($Line in $SSHAgentPrivateKeysArrayListClone) {
            if (![System.String]::IsNullOrWhiteSpace($Line)) {
                $null = $(Get-Variable -Name "KeyInfo$i" -ValueOnly).Add($Line)
                $SSHAgentPrivateKeysArrayList.Remove($Line)
            }
            else {
                break privkeylines
            }
        }

        $null = $UpdatedSSHAgentPrivKeyInfoArray.Add($(Get-Variable -Name "KeyInfo$i" -ValueOnly))
    }

    [System.Collections.ArrayList]$FinalSSHPrivKeyObjs = @()
    foreach ($PrivKeyInfoStringArray in $UpdatedSSHAgentPrivKeyInfoArray) {
        $OriginalPrivateKeyFilePath = $PrivKeyInfoStringArray[0] -replace "\[\+\] Key Comment: ",""
        $PrivateKeyContent = $PrivKeyInfoStringArray[1..$($PrivKeyInfoStringArray.Count-1)]
        $PSObj = [pscustomobject]@{
            OriginalPrivateKeyFilePath      = $OriginalPrivateKeyFilePath
            PrivateKeyContent               = $PrivateKeyContent
        }

        $null = $FinalSSHPrivKeyObjs.Add($PSObj)
    }

    Pop-Location

    Remove-Item $tempDirectory -Recurse -Force

    $FinalSSHPrivKeyObjs
}


<#
    .SYNOPSIS
        This function Sets and/or fixes NTFS filesystem permissions recursively on the directories
        'C:\Program Files\OpenSSH-Win64' and/or 'C:\ProgramData\ssh' and/or '$HOME\.ssh'.

    .DESCRIPTION
        See .SYNOPSIS

    .NOTES

    .PARAMETER HomeFolderAndSubItemsOnly
        This parameter is OPTIONAL.

        This parameter is a switch. If used, this function will only fix permissions recursively on
        the directory '$HOME\.ssh'

    .PARAMETER ProgramDataFolderAndSubItemsOnly
        This parameter is OPTIONAL.

        This parameter is a switch. If used, this function will only fix permissions recursively on
        the directories 'C:\Program Files\OpenSSH-Win64' and/or 'C:\ProgramData\ssh'

    .EXAMPLE
        # Open an elevated PowerShell Session, import the module, and -

        PS C:\Users\zeroadmin> Fix-SSHPermissions
        
#>
function Fix-SSHPermissions {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [switch]$HomeFolderAndSubItemsOnly,

        [Parameter(Mandatory=$False)]
        [switch]$ProgramDataFolderAndSubItemsOnly
    )

    if ($PSVersionTable.PSEdition -ne "Desktop" -and $PSVersionTable.Platform -ne "Win32NT") {
        Write-Error "This function is only meant to fix permissions on Windows machines. Halting!"
        $global:FunctionResult = "1"
        return
    }

    if (!$HomeFolderAndSubItemsOnly) {
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
    }

    if (!$(Test-Path "$env:ProgramFiles\OpenSSH-Win64\FixHostFilePermissions.ps1")) {
        $LatestPSScriptsUriBase = "https://raw.githubusercontent.com/PowerShell/Win32-OpenSSH/L1-Prod/contrib/win32/openssh"
        $ScriptsToDownload = @(
            "FixHostFilePermissions.ps1"
            "FixUserFilePermissions.ps1"
            #"OpenSSHCommonUtils"
            "OpenSSHUtils.psm1"
        )

        $NewFolderInDownloadDir = NewUniqueString -ArrayOfStrings $(Get-ChildItem "$HOME\Downloads" -Directory).Name -PossibleNewUniqueString "OpenSSH_PowerShell_Utils"

        $null = New-Item -ItemType Directory -Path "$HOME\Downloads\$NewFolderInDownloadDir"

        [System.Collections.ArrayList]$FailedDownloads = @()
        foreach ($ScriptFile in $ScriptsToDownload) {
            $OutFilePath = "$HOME\Downloads\$NewFolderInDownloadDir\$ScriptFile"
            Invoke-WebRequest -Uri "$LatestPSScriptsUriBase/$ScriptFile" -OutFile $OutFilePath
            
            if (!$(Test-Path $OutFilePath)) {
                $null = $FailedDownloads.Add($OutFilePath)
            }
        }

        if ($FailedDownloads.Count -gt 0) {
            Write-Error "Failed to download the following OpenSSH PowerShell Utility Scripts/Modules: $($FailedDownloads -join ', ')! Halting!"
            $global:FunctionResult = "1"
            return
        }

        $OpenSSHPSUtilityScriptDir = "$HOME\Downloads\$NewFolderInDownloadDir"
    }
    else {
        $OpenSSHPSUtilityScriptDir = "$env:ProgramFiles\OpenSSH-Win64"
    }

    if ($(Get-Module).Name -contains "OpenSSHUtils") {
        Remove-Module OpenSSHUtils
    }
    <#
    if ($(Get-Module).Name -contains "OpenSSHCommonUtils") {
        Remove-Module OpenSSHCommonUtils
    }
    #>

    Import-Module "$OpenSSHPSUtilityScriptDir\OpenSSHUtils.psm1"
    #Import-Module "$OpenSSHPSUtilityScriptDir\OpenSSHCommonUtils.psm1"
    
    if ($(Get-Module).Name -notcontains "OpenSSHUtils") {
        Write-Error "Failed to import OpenSSHUtils Module! Halting!"
        $global:FunctionResult = "1"
        return
    }
    <#
    if ($(Get-Module).Name -notcontains "OpenSSHCommonUtils") {
        Write-Error "Failed to import OpenSSHCommonUtils Module! Halting!"
        $global:FunctionResult = "1"
        return
    }
    #>

    if ($(Get-Module -ListAvailable).Name -notcontains "NTFSSecurity") {
        Install-Module NTFSSecurity
    }

    try {
        if ($(Get-Module).Name -notcontains "NTFSSecurity") {Import-Module NTFSSecurity}
    }
    catch {
        if ($_.Exception.GetType().FullName -eq "System.Management.Automation.RuntimeException") {
            Write-Verbose "NTFSSecurity Module is already loaded..."
        }
        else {
            Write-Error "There was a problem loading the NTFSSecurity Module! Halting!"
            $global:FunctionResult = "1"
            return
        }
    }

    if (!$HomeFolderAndSubItemsOnly) {
        $FixHostFilePermissionsOutput = & "$OpenSSHPSUtilityScriptDir\FixHostFilePermissions.ps1" -Confirm:$false 6>&1

        if (Test-Path "$sshdir/authorized_principals") {
            $SecurityDescriptor = Get-NTFSSecurityDescriptor -Path "$sshdir/authorized_principals"
            $SecurityDescriptor | Disable-NTFSAccessInheritance -RemoveInheritedAccessRules
            $SecurityDescriptor | Clear-NTFSAccess
            $SecurityDescriptor | Add-NTFSAccess -Account "NT AUTHORITY\SYSTEM" -AccessRights "FullControl" -AppliesTo ThisFolderSubfoldersAndFiles
            $SecurityDescriptor | Add-NTFSAccess -Account "Administrators" -AccessRights "FullControl" -AppliesTo ThisFolderSubfoldersAndFiles
            $SecurityDescriptor | Set-NTFSSecurityDescriptor
        }

        # If there's a Host Key Public Cert, make sure permissions on it are set properly...This is not handled
        # by FixHostFilePermissions.ps1
        if (Test-Path "$sshdir/ssh_host_rsa_key-cert.pub") {
            $SecurityDescriptor = Get-NTFSSecurityDescriptor -Path "$sshdir/ssh_host_rsa_key-cert.pub"
            $SecurityDescriptor | Disable-NTFSAccessInheritance -RemoveInheritedAccessRules
            $SecurityDescriptor | Clear-NTFSAccess
            $SecurityDescriptor | Add-NTFSAccess -Account "NT AUTHORITY\SYSTEM" -AccessRights "FullControl" -AppliesTo ThisFolderSubfoldersAndFiles
            $SecurityDescriptor | Add-NTFSAccess -Account "Administrators" -AccessRights "FullControl" -AppliesTo ThisFolderSubfoldersAndFiles
            $SecurityDescriptor | Add-NTFSAccess -Account "NT AUTHORITY\Authenticated Users" -AccessRights "ReadAndExecute, Synchronize" -AppliesTo ThisFolderSubfoldersAndFiles
            $SecurityDescriptor | Set-NTFSSecurityDescriptor
        }
    }
    if (!$ProgramDataFolderAndSubItemsOnly) {
        $FixUserFilePermissionsOutput = & "$OpenSSHPSUtilityScriptDir\FixUserFilePermissions.ps1" -Confirm:$false 6>&1

        $SecurityDescriptor = Get-NTFSSecurityDescriptor -Path "$HOME\.ssh"
        $SecurityDescriptor | Disable-NTFSAccessInheritance -RemoveInheritedAccessRules
        $SecurityDescriptor | Clear-NTFSAccess
        $SecurityDescriptor | Add-NTFSAccess -Account "NT AUTHORITY\SYSTEM" -AccessRights "FullControl" -AppliesTo ThisFolderSubfoldersAndFiles
        $SecurityDescriptor | Add-NTFSAccess -Account "$(whoami)" -AccessRights "FullControl" -AppliesTo ThisFolderSubfoldersAndFiles
        $SecurityDescriptor | Set-NTFSSecurityDescriptor

        $UserHomeDirs = Get-ChildItem "C:\Users"
        foreach ($UserDir in $UserHomeDirs) {
            $KnownHostsPath = "$($UserDir.FullName)\.ssh\known_hosts"
            $AuthorizedKeysPath = "$($UserDir.FullName)\.ssh\authorized_keys"

            if ($(Test-Path $KnownHostsPath) -or $(Test-Path $AuthorizedKeysPath)) {
                if (Test-Path $KnownHostsPath) {
                    $SecurityDescriptor = Get-NTFSSecurityDescriptor -Path $KnownHostsPath
                    $SecurityDescriptor | Disable-NTFSAccessInheritance -RemoveInheritedAccessRules
                    $SecurityDescriptor | Clear-NTFSAccess
                    $SecurityDescriptor | Enable-NTFSAccessInheritance
                    $SecurityDescriptor | Set-NTFSSecurityDescriptor

                    # Make sure it's UTF8 Encoded
                    $FileContent = Get-Content $KnownHostsPath
                    Set-Content -Value $FileContent $KnownHostsPath -Encoding UTF8
                }
                if (Test-Path $AuthorizedKeysPath) {
                    $SecurityDescriptor = Get-NTFSSecurityDescriptor -Path $AuthorizedKeysPath
                    $SecurityDescriptor | Disable-NTFSAccessInheritance -RemoveInheritedAccessRules
                    $SecurityDescriptor | Clear-NTFSAccess
                    $SecurityDescriptor | Enable-NTFSAccessInheritance
                    $SecurityDescriptor | Set-NTFSSecurityDescriptor

                    $FileContent = Get-Content $AuthorizedKeysPath
                    Set-Content -Value $FileContent $AuthorizedKeysPath -Encoding UTF8
                }
            }
        }
    }

    try {
        Write-Host "Restarting the sshd service..."
        Restart-Service sshd
    }
    catch {
        Write-Error $_
        $global:FunctionResult = "1"
        return
    }

    [pscustomobject]@{
        FixHostFilePermissionsOutput    = $FixHostFilePermissionsOutput
        FixUserFilePermissionsOutput    = $FixUserFilePermissionsOutput
    }
}


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
                $ReformattedName = "$($AcctNameSplit[1])@$($AcctNameSplit[0].ToLowerInvariant())"
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
                $ReformattedName = "$($AcctNameSplit[1])@$($AcctNameSplit[0].ToLowerInvariant())"
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

            foreach ($DirectoryEntry in $UserObjectsInLDAP) {
                if (![bool]$($DirectoryEntry | Get-Member -MemberType NoteProperty -Name Groups)) {
                    $searcher = [System.DirectoryServices.DirectorySearcher]::new($DirectoryEntry)
                    $searcher.SearchScope = [System.DirectoryServices.SearchScope]::Base
                    $searcher.ExtendedDN = [System.DirectoryServices.ExtendedDN]::Standard
                    $searcher.PropertiesToLoad.Clear()
                    $null = $searcher.PropertiesToLoad.Add("memberof")
                    $Groups = $searcher.FindOne().Properties.memberof | foreach {$($_ -split ';')[-1]}
                    $DirectoryEntry | Add-Member -Type NoteProperty -Name Groups -Value $Groups -Force
                }
            }

            $DomainAdminsPrep = $UserObjectsInLDAP | Where-Object {$_.Groups -match "Domain Admins"}
            $DomainAdminAccounts = $DomainAdminsPrep.Name | foreach {
                if ($_ -match '=') {
                    $($_ -split "=")[-1]
                }
                else {
                    $_
                }
            }

            $AccountsReformatted = $DomainAdminAccounts | foreach {
                if (![System.String]::IsNullOrWhiteSpace($_)) {
                    $_ + "@" + $ThisDomainName.ToLowerInvariant()
                }
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

            foreach ($DirectoryEntry in $UserObjectsInLDAP) {
                if (![bool]$($DirectoryEntry | Get-Member -MemberType NoteProperty -Name Groups)) {
                    $searcher = [System.DirectoryServices.DirectorySearcher]::new($DirectoryEntry)
                    $searcher.SearchScope = [System.DirectoryServices.SearchScope]::Base
                    $searcher.ExtendedDN = [System.DirectoryServices.ExtendedDN]::Standard
                    $searcher.PropertiesToLoad.Clear()
                    $null = $searcher.PropertiesToLoad.Add("memberof")
                    $null = $searcher.PropertiesToLoad.Add("distinguishedname")
                    $Groups = $searcher.FindOne().Properties.memberof | foreach {$($_ -split ';')[-1]}
                    $DirectoryEntry | Add-Member -Type NoteProperty -Name Groups -Value $Groups -Force
                }
            }

            $DomainUsersPrep = $UserObjectsInLDAP | Where-Object {$_.Groups -match "Domain Users"}
            $DomainUserAccounts = $DomainUsersPrep.Name | foreach {
                if ($_ -match '=') {
                    $($_ -split "=")[-1]
                }
                else {
                    $_
                }
            }

            $AccountsReformatted = $DomainUserAccounts | foreach {
                if (![System.String]::IsNullOrWhiteSpace($_)) {
                    $_ + "@" + $ThisDomainName.ToLowerInvariant()
                }
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


<#
    .SYNOPSIS
        This function generates:
            - An ArrayList of PSCustomObjects that describes the contents of each of the files within the
            "$HOME\.ssh" directory
            - An .xml file that can be ingested by the 'Import-CliXml' cmdlet to generate
            the aforementioned ArrayList of PSCustomObjects in future PowerShell sessions.
            
            Each PSCustomObject in the ArrayList contains information similar to:

                File     : C:\Users\zeroadmin\.ssh\PwdProtectedPrivKey
                FileType : RSAPrivateKey
                Contents : {-----BEGIN RSA PRIVATE KEY-----, Proc-Type: 4,ENCRYPTED, DEK-Info: AES-128-CBC,27E137C044FC7857DAAC05C408472EF8, ...}
                Info     : {-----BEGIN RSA PRIVATE KEY-----, Proc-Type: 4,ENCRYPTED, DEK-Info: AES-128-CBC,27E137C044FC7857DAAC05C408472EF8, ...}

        By default, the .xml file is written to "$HOME\.ssh\SSHDirectoryFileInfo.xml"

    .DESCRIPTION
        See .SYNOPSIS

    .NOTES

    .PARAMETER PathToHomeDotSSHDirectory
        This parameter is OPTIONAL.

        This parameter takes a string that represents a full path to the User's .ssh directory. You should
        only use this parameter if the User's .ssh is NOT under "$HOME\.ssh" for some reason. 

    .EXAMPLE
        # Open an elevated PowerShell Session, import the module, and -

        PS C:\Users\zeroadmin> Generate-SSHUserDirFileInfo
        
#>
function Generate-SSHUserDirFileInfo {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [string]$PathToHomeDotSSHDirectory
    )

    $OpenSSHWinPath = "$env:ProgramFiles\OpenSSH-Win64"

    if (!$(Test-Path $OpenSSHWinPath)) {
        Write-Error "The path $OpenSSHWinPath was not found! Halting!"
        $global:FunctionResult = "1"
        return
    }

    [System.Collections.Arraylist][array]$CurrentEnvPathArray = $env:Path -split ";" | Where-Object {![System.String]::IsNullOrWhiteSpace($_)}
    if ($CurrentEnvPathArray -notcontains $OpenSSHWinPath) {
        $CurrentEnvPathArray.Insert(0,$OpenSSHWinPath)
        $env:Path = $CurrentEnvPathArray -join ";"
    }

    # Make sure we have access to ssh binaries
    if (![bool]$(Get-Command ssh-keygen -ErrorAction SilentlyContinue)) {
        Write-Error "Unable to find 'ssh-keygen.exe'! Halting!"
        $global:FunctionResult = "1"
        return
    }

    if (!$PathToHomeDotSSHDirectory) {
        $PathToHomeDotSSHDirectory = "$HOME\.ssh"
    }

    # Get a list of all files under $HOME\.ssh
    [array]$SSHHomeFiles = Get-ChildItem -Path $PathToHomeDotSSHDirectory -File | Where-Object {$_.Name -ne "SSHDirectoryFileInfo.xml"}

    if ($SSHHomeFiles.Count -eq 0) {
        Write-Error "Unable to find any files under '$PathToHomeDotSSHDirectory'! Halting!"
        $global:FunctionResult = "1"
        return
    }

    [System.Collections.ArrayList]$ArrayOfPSObjects = @()
    foreach ($File in $SSHHomeFiles.FullName) {
        #Write-Host "Analyzing file '$File' ..."
        try {
            $GetSSHFileInfoResult = Get-SSHFileInfo -PathToKeyFile $File -ErrorAction Stop -WarningAction SilentlyContinue
            if (!$GetSSHFileInfoResult) {
                #Write-Warning "'$File' is not a valid Public Key, Private Key, or Public Key Certificate!"
                #Write-Host "Ensuring '$File' is UTF8 encoded and trying again..." -ForegroundColor Yellow
                Set-Content -Path $File -Value $(Get-Content $File) -Encoding UTF8
            }

            $GetSSHFileInfoResult = Get-SSHFileInfo -PathToKeyFile $File -ErrorAction Stop -WarningAction SilentlyContinue
            if (!$GetSSHFileInfoResult) {
                Write-Verbose "'$File' is definitley not a valid Public Key, Private Key, or Public Key Certificate!"
            }

            # Sample Output:
            # NOTE: Possible values for the 'FileType' property are 'RSAPrivateKey','RSAPublicKey', and 'RSAPublicKeyCertificate'
            <#
                File     : C:\Users\zeroadmin\.ssh\PwdProtectedPrivKey
                FileType : RSAPrivateKey
                Contents : {-----BEGIN RSA PRIVATE KEY-----, Proc-Type: 4,ENCRYPTED, DEK-Info: AES-128-CBC,27E137C044FC7857DAAC05C408472EF8, ...}
                Info     : {-----BEGIN RSA PRIVATE KEY-----, Proc-Type: 4,ENCRYPTED, DEK-Info: AES-128-CBC,27E137C044FC7857DAAC05C408472EF8, ...}
            #>

            $null = $ArrayOfPSObjects.Add($GetSSHFileInfoResult)
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            return
        }
    }

    $ArrayOfPSObjects
    $ArrayOfPSObjects | Export-CliXml "$PathToHomeDotSSHDirectory\SSHDirectoryFileInfo.xml"
}


<#
    .SYNOPSIS
        This function simply outputs instructions to stdout regarding certain aspects of Public
        Key Authentication.

        This function needs to be updated. Current instructions are incomplete/misleading.

    .DESCRIPTION
        See .SYNOPSIS

    .NOTES

    .PARAMETER PublicKeyLocation
        This parameter is OPTIONAL.

        This parameter takes a string that represents the full path to an SSH Public Key that the user
        would like instructions for.

    .PARAMETER PrivateKeyLocation
        This parameter is OPTIONAL.

        This parameter takes a string that represents the full path to an SSH Private Key that the user
        would like instructions for.

    .EXAMPLE
        # Open an elevated PowerShell Session, import the module, and -

        PS C:\Users\zeroadmin> Get-PublicKeyAuthInstructions -PublicKeyLocation "$HOME\.ssh\id_rsa.pub" -PrivateKeyLocation "$HOME\.ssh\id_rsa"
        
#>
function Get-PublicKeyAuthInstructions {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [string]$PublicKeyLocation,

        [Parameter(Mandatory=$False)]
        [string]$PrivateKeyLocation
    )

    ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####

    if ($PublicKeyLocation) {
        $PublicKeyLocationFinal = $PublicKeyLocation
    }
    else {
        $PublicKeyLocationFinal = "SamplePubKey.pub"
    }
    if ($PrivateKeyLocation) {
        $PrivateKeyLocationFinal = $PrivateKeyLocation
    }
    else {
        $PrivateKeyLocationFinal = "SamplePrivKey"
    }

    ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####

    # Reference for below info:
    # https://github.com/PowerShell/Win32-OpenSSH/issues/815
    # https://github.com/PowerShell/Win32-OpenSSH/issues/409 

    $Headers1 = @"

##### INFORMATION #####
## WINDOWS TO LINUX PUBLIC KEY AUTH ##

"@

    $Info1 = @"
In order to SSH from this computer (i.e. $env:ComputerName) to a Remote Host WITHOUT the need for a password,
add the content of the RSA Public Key (i.e. $PublicKeyLocationFinal) to '~/.ssh/authorized_keys' on your Remote Linux Host.
Permissions on the ~/.ssh directory should be 700 and permissions on the ~/.ssh/authorized_keys file should be 644.
Check permissions with...

    stat -c "%a %n" ~/.ssh
    stat -c "%a %n" ~/.ssh/authorized_keys

...and change permissions with 'chmod'

"@

    $Headers2 = "## WINDOWS TO WINDOWS PUBLIC KEY AUTH ##`n"

    $Info2 = @"
If the Remote Host is a Windows machine running sshd, add the content of the RSA Public Key (i.e. $PublicKeyLocationFinal) to the
C:\Users\<User>\.ssh\authorized_keys file on your Remote Host. Permissions MUST be as follows...

    C:\Users\<User>\.ssh\authorized_keys
        Administrators      = Full Control
        SYSTEM              = Full Control
        NT SERVICE\sshd     = Read, Synchronize

    C:\Users\<User>\.ssh
        NT Service\sshd     = ReadAndExecute, Synchronize

    C:\Users\<User>
        NT Service\sshd     = ReadAndExecute, Synchronize

    NOTE #1: 'Read, Synchronize' translates to:
        'Read permissions'
        'Read attributes'
        'Read extended attributes'
        'List folder / read data'

    NOTE #2: 'ReadAndExecute, Synchronize' translates to:
        'Traverse folder / execute file'
        'Read permissions'
        'Read attributes'
        'Read extended attributes'
        'List folder / read data'

"@

    $ImportantNote1 = "If you need to fix permissions on any of the above on the Windows Remote Host, " +
    "the sshd service on the Remote Host must be restarted!`n"

    $ImportantNote2 = @"
The syntax for logging into a Remote Host with a Local Account available on the Remote Host is...

    ssh -i $PrivateKeyLocationFinal <RemoteHostUserName>@<RemoteHostNameOrFQDNOrIP>

...where $PrivateKeyLocationFinal is a private key file on the client and $PublicKeyLocationFinal is a public
key that has been added to .ssh/authorized_keys on the Remote Windows Host.

"@

    $ImportantNote3 = @"
If you would like to login to a Remote Windows Host using a Domain Account (as opposed to a Local
Account on the Remote Host), the syntax is...

    ssh -i $PrivateKeyLocationFinal -l <UserName>@<FullDomain> <RemoteHostName>.<FullDomain>

...where $PrivateKeyLocationFinal is a private key file on the client and $PublicKeyLocationFinal is a public
key that has been added to .ssh/authorized_keys on the Remote Windows Host.

"@

    Write-Host $Headers1 -ForegroundColor Yellow
    Write-Host $Info1
    Write-Host $Headers2 -ForegroundColor Yellow
    Write-Host $Info2
    Write-Host "IMPORTANT NOTE #1:" -ForegroundColor Yellow
    Write-Host $ImportantNote1
    Write-Host "IMPORTANT NOTE #2:" -ForegroundColor Yellow
    Write-Host $ImportantNote2
    Write-Host "IMPORTANT NOTE #3:" -ForegroundColor Yellow
    Write-Host $ImportantNote3
}


<#
    .SYNOPSIS
        This function is used to determine the most efficient ssh.exe command that should work
        on the Remote Host (assuming the sshd server on the remote host is configured properly).

        By providing this function ONE of the following parameters...
            SSHKeyFilePath
            SSHPublicKeyFilePath
            SSHPrivateKeyFilePath
            SSHPublicCertFilePath
        ...this function will find all related files (as long as they're in the "$HOME\.ssh" directory
        or in the ssh-agent). Then, depending on the type of authentication you would like to use
        (which you sould specify using the -AuthMethod parameter), this function will output a PSCustomObject
        with properties similar to:
            PublicKeyAuthShouldWork (Boolean)
            PublicKeyCertificateAuthShouldWork (Boolean)
            SSHClientProblemDescription (String)
            FinalSSHExeCommand (String)
        
        The property 'PublicKeyAuthShouldWork' will appear only if -AuthMethod is "PublicKey".
        The property 'PublicKeyCertificateAuthShouldWork' will appear only if -AuthMethod is "PublicKeyCertificate".
        The property 'SSHClientProblemDescription' will appear only if an SSH Command cannot be determined.
        The property 'FinalSSHExeCommand' will always appear. It might be $null if a command cannot be determined.

    .DESCRIPTION
        See .SYNOPSIS

    .NOTES

    .PARAMETER SSHKeyFilePath
        This parameter is MANDATORY for its given Parameter Set.

        This parameter takes a string that represents a full path to an SSH Key/Cert file.

        This parameter should be used if you are certain that the specified file is related to SSH
        Authentication, but you are not sure if the file is a Public Key, Private Key, or Public Certificate.

        It is HIGHLY RECOMMENDED that you use this parameter instead of -SSHPublicKeyFilePath or
        -SSHPrivateKeyFilePath or -SSHPublicCertFilePath.

    .PARAMETER SSHPublicKeyFilePath
        This parameter is MANDATORY for its given Parameter Set.

        This parameter takes a string that represents a full path to an SSH Public Key file. If the file
        is NOT an SSH Public Key file, the function will halt.

    .PARAMETER SSHPrivateKeyFilePath
        This parameter is MANDATORY for its given Parameter Set.

        This parameter takes a string that represents a full path to an SSH Private Key file. If the file
        is NOT an SSH Private Key file, the function will halt.

    .PARAMETER SSHPublicCertFilePath
        This parameter is MANDATORY for its given Parameter Set.

        This parameter takes a string that represents a full path to an SSH Public Certificate file. If the file
        is NOT an SSH Public Certificate file, the function will halt.

    .PARAMETER AuthMethod
        This parameter is MANDATORY.

        This parameter takes a string that must be one of two values: "PublicKey", "PublicKeyCertificate"

        If you would like this function to output an ssh command that uses Public Key Authentication,
        use "PublicKey" for this parameter. If you would like this function to ouput an ssh command that
        uses Public Certificate Authentication, use "PublicKeyCertificate" for this parameter.

    .EXAMPLE
        # Open an elevated PowerShell Session, import the module, and -

        PS C:\Users\zeroadmin> Get-SSHClientAuthSanity -SSHKeyFilePath "$HOME\.ssh\id_rsa"
        
#>
function Get-SSHClientAuthSanity {
    [CmdletBinding(DefaultParameterSetName="UnknownKey")]
    Param(
        [Parameter(
            Mandatory=$True,
            ParameterSetName="UnknownKey"
        )]
        [string]$SSHKeyFilePath,

        [Parameter(
            Mandatory=$True,
            ParameterSetName="PublicKey"
        )]
        [string]$SSHPublicKeyFilePath,

        [Parameter(
            Mandatory=$True,
            ParameterSetName="PrivateKey"
        )]
        [string]$SSHPrivateKeyFilePath,

        [Parameter(
            Mandatory=$True,
            ParameterSetName="PublicCert"
        )]
        [string]$SSHPublicCertFilePath,

        [Parameter(Mandatory=$False)]
        [ValidateSet("PublicKey","PublicKeyCertificate")]
        [string]$AuthMethod = "PublicKey"
    )

    # Make sure we have access to ssh binaries
    if (![bool]$(Get-Command ssh-keygen -ErrorAction SilentlyContinue)) {
        Write-Error "Unable to find 'ssh-keygen.exe'! Halting!"
        $global:FunctionResult = "1"
        return
    }

    $BoundParametersDictionary = $PSCmdlet.MyInvocation.BoundParameters
    [array]$UsedParameterNames = $($BoundParametersDictionary.GetEnumerator()).Key
    $SSHFilePathParameter = $UsedParameterNames | Where-Object {$_ -match "SSHKeyFilePath|SSHPublicKeyFilePath|SSHPrivateKeyFilePath|SSHPublicCertFilePath"}
    $SSHKeyFilePath = Get-Variable -Name $SSHFilePathParameter -ValueOnly

    # Make sure the SSHKeyFilePath exists
    if (!$(Test-Path $SSHKeyFilePath)) {
        Write-Error "The path '$SSHKeyFilePath' was not found! Halting!"
        $global:FunctionResult = "1"
        return
    }
    else {
        $SSHKeyFilePath = $(Resolve-Path $SSHKeyFilePath).Path
    }

    if ($SSHPublicCertFilePath) {
        $AuthMethod = "PublicKeyCertificate"
    }

    # Inspect the SSHKeyFile
    try {
        $CheckSSHKeyFile = Get-SSHFileInfo -PathToKeyFile $SSHKeyFilePath -ErrorAction Stop -WarningAction SilentlyContinue
    }
    catch {
        Write-Error $_
        $global:FunctionResult = "1"
        return
    }

    if ($CheckSSHKeyFile.FileType -eq $null) {
        Write-Error "The file '$SSHKeyFilePath' does not appear to be an RSA Public Key, RSA Public Key Certificate, or RSA Private Key! Halting!"
        $global:FunctionResult = "1"
        return
    }

    if ($SSHPublicKeyFilePath -and $CheckSSHKeyFile.FileType -ne "RSAPublicKey") {
        if ($CheckSSHKeyFile.FileType -eq "RSAPublicKeyCertificate") {
            $CorrectParameter = "SSHPublicKeyCertFilePath"
        }
        if ($CheckSSHKeyFile.FileType -eq "RSAPrivateKey") {
            $CorrectParameter = "SSHPrivateKeyCertFilePath"
        }
        
        $ParamErrMsg = "The file '$SSHPublicKeyFilePath' does not appear to be an RSA Public Key! " +
        "Instead, it appears to be an $($CheckSSHKeyFile.FileType)! Please use the -$CorrectParameter parameter instead. Halting!"
        Write-Error $ParamErrMsg
        $global:FunctionResult = "1"
        return
    }
    if ($SSHPublicCertFilePath -and $CheckSSHKeyFile.FileType -ne "RSAPublicKeyCertificate") {
        if ($CheckSSHKeyFile.FileType -eq "RSAPublicKey") {
            $CorrectParameter = "SSHPublicKeyFilePath"
        }
        if ($CheckSSHKeyFile.FileType -eq "RSAPrivateKey") {
            $CorrectParameter = "SSHPrivateKeyCertFilePath"
        }

        $ParamErrMsg = "The file '$SSHPublicKeyFilePath' does not appear to be an RSA Public Key! " +
        "Instead, it appears to be an $($CheckSSHKeyFile.FileType)! Please use the -$CorrectParameter parameter instead. Halting!"
        Write-Error $ParamErrMsg
        $global:FunctionResult = "1"
        return
    }
    if ($SSHPrivateKeyFilePath -and $CheckSSHKeyFile.FileType -ne "RSAPrivateKey") {
        if ($CheckSSHKeyFile.FileType -eq "RSAPublicKey") {
            $CorrectParameter = "SSHPublicKeyFilePath"
        }
        if ($CheckSSHKeyFile.FileType -eq "RSAPublicKeyCertificate") {
            $CorrectParameter = "SSHPublicKeyCertFilePath"
        }

        $ParamErrMsg = "The file '$SSHPublicKeyFilePath' does not appear to be an RSA Public Key! " +
        "Instead, it appears to be an $($CheckSSHKeyFile.FileType)! Please use the -$CorrectParameter parameter instead. Halting!"
        Write-Error $ParamErrMsg
        $global:FunctionResult = "1"
        return
    }

    if ($CheckSSHKeyFile.FileType -eq "RSAPublicKeyCertificate") {
        $SSHPublicCertFilePath = $CheckSSHKeyFile.File
    }
    if ($CheckSSHKeyFile.FileType -eq "RSAPublicKey") {
        $SSHPublicKeyFilePath = $CheckSSHKeyFile.File
    }
    if ($CheckSSHKeyFile.FileType -eq "RSAPrivateKey") {
        $SSHPrivateKeyFilePath = $CheckSSHKeyFile.File
    }

    if ($SSHPublicCertFilePath) {
        if ($(Get-Item $SSHPublicCertFilePath).Name -notmatch "-cert\.pub") {
            $SSHKeyFilePath = $SSHPublicCertFilePath -replace "\..*?$","-cert.pub"
            Rename-Item -Path $SSHPublicCertFilePath -NewName $SSHKeyFilePath
        }
    }
    if ($SSHPublicKeyFilePath) {
        if ($(Get-Item $SSHPublicKeyFilePath).Name -notmatch "\.pub") {
            $SSHKeyFilePath = $SSHPublicKeyFilePath -replace "\..*?$",".pub"
            Rename-Item -Path $SSHPublicKeyFilePath -NewName $SSHKeyFilePath
        }
    }
    if ($SSHPrivateKeyFilePath) {
        if ($(Get-Item $SSHPrivateKeyFilePath).Name -match "\..*?$" -and $(Get-Item $SSHPrivateKeyFilePath).Name -notmatch "\.pem$") {
            $SSHKeyFilePath = $SSHPrivateKeyFilePath -replace "\..*?$",""
            Rename-Item -Path $SSHPrivateKeyFilePath -NewName $SSHKeyFilePath
        }
    }

    $KeyFileParentDirectory = $SSHKeyFilePath | Split-Path -Parent

    # Inspect all files in $SSHKeyFilePath Parent Directory (should just be '$HOME/.ssh')
    try {
        $GenSSHDirFileInfoSplatParams = @{
            PathToHomeDotSSHDirectory       = $KeyFileParentDirectory
            WarningAction                   = "SilentlyContinue"
            ErrorAction                     = "Stop"
        }

        $SSHDirFileInfo = Generate-SSHUserDirFileInfo @GenSSHUserDirFileInfoSplatParams
    }
    catch {
        Write-Error $_
        $global:FunctionResult = "1"
        return
    }

    # Get all related Key Files
    $FingerPrintRelevantString = $($CheckSSHKeyFile.FingerPrint -split " ")[1]
    $RelatedKeyFileInfoObjects = $SSHDirFileInfo | Where-Object {$_.FingerPrint -match [regex]::Escape($FingerPrintRelevantString)}

    if ($RelatedKeyFileInfoObjects.FileType -contains "RSAPublicKeyCertificate") {
        $AuthMethod = "PublicKeyCertificate"
    }
    # NOTE: Each PSCustomObject in the above $RelatedKeyFileInfoObjects has the following properties:
    # File - [string] Absolute File Path
    # FileType - [string] with possible values 'RSAPublicKey', 'RSAPrivateKey', 'RSAPublicKeyCertificate', 'PuttyCombinedPublicPrivateKey', or 'SSH2_RFC4716'
    # Contents - Result of `Get-Content` on File. Could be [string] or [string[]] if RSAPrivateKey, PuttyCombinedPublicPrivateKey, or SSH2_RFC4716
    # Info - Could be either result of `Get-Content` on File or an `ssh-keygen` command. Could be [string] or [string[]] depending
    # FingerPrint - Could be [string] or $null if PuttyCombinedPublicPrivateKey, or SSH2_RFC4716
    # PasswordProtected - Could be [bool] or $null if PuttyCombinedPublicPrivateKey, or SSH2_RFC4716

    # We're most likely going to need the fingerprints of the keys loaded in the ssh-agent, so get that info now
    $SSHAgentOutput = ssh-add -L
    $tempDirectory = [IO.Path]::Combine([IO.Path]::GetTempPath(), [IO.Path]::GetRandomFileName()) -replace "\..*?$",""
    $null = [IO.Directory]::CreateDirectory($tempDirectory)
    [System.Collections.ArrayList]$RSAPubKeyTempFiles = @()
    $Counter = 0
    foreach ($RSAPubKey in $SSHAgentOutput) {
        Set-Content -Path "$tempDirectory/RSAPubKey$Counter" -Value $RSAPubKey
        $null = $RSAPubKeyTempFiles.Add("$tempDirectory/RSAPubKey$Counter")
        $Counter++
    }
    [System.Collections.ArrayList]$SSHAgentKeyFingerPrintsInSSHAgent = @()
    foreach ($RSAPubKeyFile in $RSAPubKeyTempFiles) {
        $PSCustObj = [pscustomobject]@{
            File                = $RSAPubKeyFile
            FingerPrint         = $(ssh-keygen -l -f $RSAPubKeyFile)
            Contents            = $(Get-Content $RSAPubKeyFile)
        }
        $null = $SSHAgentKeyFingerPrintsInSSHAgent.Add($PSCustObj)
    }
    # Cleanup
    Remove-Item $tempDirectory -Recurse -Force

    # Check to see if the Private Key is Loaded in the ssh-agent
    $RelevantString = $($CheckSSHKeyFile.FingerPrint -split " ")[1]
    if ($SSHAgentKeyFingerPrintsInSSHAgent.FingerPrint -match [regex]::Escape($RelevantString)) {
        $PrivateKeyIsLoadedInSSHAgent = $True
        if ($SSHAgentKeyFingerPrintsInSSHAgent.Count -eq 1) {
            $PositionOfLoadedPrivateKey = 0
        }
        elseif ($SSHAgentKeyFingerPrintsInSSHAgent.Count -gt 1) {
            $PositionOfLoadedPrivateKey = $SSHAgentKeyFingerPrintsInSSHAgent.FingerPrint.IndexOf($($SSHAgentKeyFingerPrintsInSSHAgent.FingerPrint -match [regex]::Escape($RelevantString)))
        }
    }
    else {
        $PrivateKeyIsLoadedInSSHAgent = $False
    }

    [System.Collections.ArrayList]$NeededAdditionalSSHExeOptions = @()

    # If $AuthMethod is "PublicKey" we need to track down the Public Key and the Private Key
    if ($AuthMethod -eq "PublicKey") {
        # If we were provided the path to the Public Key, then we just need to track down the Private Key
        # It could either be in the same directory as the Public Key or in the ssh-agent
        if ($SSHPublicKeyFilePath) {
            # If `$RelatedKeyFileInfoObjects.Count -eq 1` then we know that the Private Key is NOT in $KeyFileParentDirectory,
            # so we have to look for it in the ssh-agent
            if ($RelatedKeyFileInfoObjects.Count -eq 1 -or
            $($($RelatedKeyFileInfoObjects.Count -ge 2 -and $RelatedKeyFileInfoObjects.FileType -notcontains "RSAPrivateKey"))
            ) {
                # If the corresponding Private Key isn't loaded in the ssh-agent, or if it's too far down in the list, then we have a problem
                if (!$PrivateKeyIsLoadedInSSHAgent -or $PositionOfLoadedPrivateKey -ge 4) {
                    if (!$PrivateKeyIsLoadedInSSHAgent) {
                        $SSHClientProblemDescription = "The Private Key is not on the filesystem under $KeyFileParentDirectory or loaded in the ssh-agent!"
                    }
                    if ($PositionOfLoadedPrivateKey -ge 4) {
                        $SSHClientProblemDescription = "The Private Key is not on the filesystem in same directory " +
                        "as the Public Key (i.e. $KeyFileParentDirectory). The Private Key IS loaded in the ssh-agent, " +
                        "however, it is not in the top 5 on the list, so the sshd server on the Remote Host will most " +
                        "likely reject authentication because of too many attempts!"
                        $PubKeyAuthShouldWork = $False
                    }
                    $PubKeyAuthShouldWork = $False
                }
                if ($PrivateKeyIsLoadedInSSHAgent -and $PositionOfLoadedPrivateKey -lt 4) {
                    $PubKeyAuthShouldWork = $True
                }
            }
            # If `$RelatedKeyFileInfoObjects.Count -eq 2`, then one of those is the RSAPublicKey, but we need to
            # confirm that the other is actually the RSAPrivateKey. If not, then we need to check the ssh-agent
            # for the Private Key.
            if ($RelatedKeyFileInfoObjects.Count -ge 2 -and $RelatedKeyFileInfoObjects.FileType -contains "RSAPrivateKey") {
                if (!$PrivateKeyIsLoadedInSSHAgent) {
                    $PubKeyAuthShouldWork = $True
                    if ($SSHAgentKeyFingerPrintsInSSHAgent.Count -gt 4) { 
                        $null = $NeededAdditionalSSHExeOptions.Add("IdentitiesOnly")
                    }
                    $null = $NeededAdditionalSSHExeOptions.Add("iPathToPrivateKey")
                    $FinalPathToPrivateKey = $($RelatedKeyFileInfoObjects | Where-Object {$_.FileType -eq "RSAPrivateKey"}).File
                }
                if ($PositionOfLoadedPrivateKey -ge 4) {
                    $PubKeyAuthShouldWork = $True
                    $null = $NeededAdditionalSSHExeOptions.Add("IdentitiesOnly")
                    $null = $NeededAdditionalSSHExeOptions.Add("iPathToPrivateKey")
                    $FinalPathToPrivateKey = $($RelatedKeyFileInfoObjects | Where-Object {$_.FileType -eq "RSAPrivateKey"}).File
                }
                if ($PrivateKeyIsLoadedInSSHAgent -and $PositionOfLoadedPrivateKey -lt 4) {
                    $PubKeyAuthShouldWork = $True
                }
            }
        }
        # If we are provided the Private Key, we should (just for organization's sake) make sure the corresponding
        # Public Key is in $KeyFileParentDirectory. Also, depending on if the Private Key is loaded in the ssh-agent,
        # we may or may not need `-i <PathToPrivateKey>` in the final ssh.exe command.
        if ($SSHPrivateKeyFilePath) {
            # If `$RelatedKeyFileInfoObjects.Count -eq 1`, then we only have the Private Key on the filesystem
            # under $KeyFileParentDirectory. So, we should create the Public Key File alongside it.
            if ($RelatedKeyFileInfoObjects.Count -eq 1 -or 
            $($RelatedKeyFileInfoObjects.Count -ge 2 -and $RelatedKeyFileInfoObjects.FileType -notcontains "RSAPublicKey")
            ) {
                $RSAPublicKeyString = ssh-keygen -y -f "$SSHPrivateKeyFilePath"
                Set-Content -Value $RSAPublicKeyString -Path "$SSHPrivateKeyFilePath.pub"
            }

            if (!$PrivateKeyIsLoadedInSSHAgent) {
                $PubKeyAuthShouldWork = $True
                if ($SSHAgentKeyFingerPrintsInSSHAgent.Count -gt 4) { 
                    $null = $NeededAdditionalSSHExeOptions.Add("IdentitiesOnly")
                }
                $null = $NeededAdditionalSSHExeOptions.Add("iPathToPrivateKey")
                $FinalPathToPrivateKey = $SSHPrivateKeyFilePath
            }
            if ($PositionOfLoadedPrivateKey -ge 4) {
                $PubKeyAuthShouldWork = $True
                $null = $NeededAdditionalSSHExeOptions.Add("IdentitiesOnly")
                $null = $NeededAdditionalSSHExeOptions.Add("iPathToPrivateKey")
                $FinalPathToPrivateKey = $SSHPrivateKeyFilePath
            }
            if ($PrivateKeyIsLoadedInSSHAgent -and $PositionOfLoadedPrivateKey -lt 4) {
                $PubKeyAuthShouldWork = $True
            }
        }
    }

    # If $AuthMethod is "PublicKeyCertificate", we need to track down the Public Key Certificate and the Private Key
    if ($AuthMethod -eq "PublicKeyCertificate") {
        if ($SSHPublicCertFilePath) {
            if ($RelatedKeyFileInfoObjects.Count -eq 1 -or 
            $($RelatedKeyFileInfoObjects.Count -ge 2 -and $RelatedKeyFileInfoObjects.FileType -notcontains "RSAPrivateKey")
            ) {
                # If `$RelatedKeyFileInfoObjects.Count -eq 1`, the only relevant SSH Key File we have in our $HOME\.ssh directory
                # is the Public Key Certificate

                # If the corresponding Private Key isn't loaded in the ssh-agent, then we have a problem...
                if (!$PrivateKeyIsLoadedInSSHAgent) {
                    $SSHClientProblemDescription = "Unable to find Private Key in ssh-agent or in same directory as the Public Key Certificate (i.e. $KeyFileParentDirectory)!"
                    $PubCertAuthShouldWork = $False
                }
                # If the Private Key IS Loaded in the ssh-agent, but it is too far down on the list, we have a problem...
                if ($PositionOfLoadedPrivateKey -ge 4) {
                    $SSHClientProblemDescription = "The Private Key is not on the filesystem in same directory " +
                    "as the Public Key (i.e. $KeyFileParentDirectory). The Private Key IS loaded in the ssh-agent, "
                    "however, it is not in the top 5 on the list, so the sshd server on the Remote Host will most " +
                    "likely reject authentication because of too many attempts!"
                    $PubCertAuthShouldWork = $False
                }
                if ($PrivateKeyIsLoadedInSSHAgent -and $PositionOfLoadedPrivateKey -lt 4) {
                    # Even if the Private Key is Loaded in the ssh-agent and it's low enough on the list,
                    # we need to make sure that the ssh-agent is aware of the Public Key Certificate specifically
                    #
                    # NOTE: In the below, we can use `$_.Contents -eq $(Get-Content $SSHPublicCertFilePath)`
                    # as opposed to `$(Compare-Object $_.Contents $(Get-Content $SSHPublicCertFilePath)) -eq $null` because
                    # each should be a single string (as opposed to an array of strings)
                    $PublicCertLoadedCheck = $SSHAgentKeyFingerPrintsInSSHAgent | Where-Object {
                        $_.FingerPrint -match [regex]::Escape($RelevantString) -and
                        $($($_.Contents -split " ")[0..1] -join " ") -eq $($($(Get-Content $SSHPublicCertFilePath) -split " ")[0..1] -join " ")
                    }
                    
                    if ($PublicCertLoadedCheck) {
                        $PubCertAuthShouldWork = $True
                    }
                    else {
                        $SSHClientProblemDescription = "The Private Key is loaded in the ssh-agent and it is low enough " +
                        "on the list of keys to present to the Remote Host, HOWEVER, the ssh-agent does not appear to be " +
                        "aware of the Public Key Certificate (i.e. 'ssh-add -L' will not contain the output of " +
                        "'Get-Content '$SSHPublicCertFilePath''. To remedy, remove the key from the ssh-agent via " +
                        "'ssh-add -d', ensure the Public Key Certificate is in the same directory as the Private Key, " +
                        "ensure the Public Key Certificate file has the same file name as the Private Key just appended " +
                        "with '-cert.pub', and add the Private Key to the ssh-agent via 'ssh-add <PathToPrivateKeyFile>' "
                        $PubCertAuthShouldWork = $False
                    }
                }
            }
            if ($RelatedKeyFileInfoObjects.Count -ge 2 -and $RelatedKeyFileInfoObjects.FileType -contains "RSAPrivateKey") {
                # One of these two objects is the Public Key Certificate. The other one is either the RSAPrivateKey
                # or the RSAPublicKey. If it's the RSAPrivateKey, we should generate the RSAPublicKey regardless
                # of whether or not the Private Key is loaded in the ssh-agent. We should also  make sure
                # the File Names of the RSAPrivateKey and RSAPublicKey resemble the File Name of RSAPublicKeyCertificate.
                # We should also note that if the Private Key isn't loaded in the ssh-agent, we'll need to use the
                # `-i <PathToPrivateKeyFile>` option in addition to the `-i <PathToPublicKeyCertificate>` with ssh.exe
                $PrivateKeyFileInfoObject = $RelatedKeyFileInfoObjects | Where-Object {$_.FileType -eq "RSAPrivateKey"}
                if ($RelatedKeyFileInfoObjects.FileType -notcontains "RSAPublicKey") {
                    $RSAPublicKeyString = ssh-keygen -y -f "$($PrivateKeyFileInfoObject.File)"
                    $OutputPath = "$($PrivateKeyFileInfoObject.File)" + ".pub"
                    Set-Content -Value $RSAPublicKeyString -Path $OutputPath
                }

                if (!$PrivateKeyIsLoadedInSSHAgent) {
                    $PubCertAuthShouldWork = $True
                    if ($SSHAgentKeyFingerPrintsInSSHAgent.Count -gt 4) { 
                        $null = $NeededAdditionalSSHExeOptions.Add("IdentitiesOnly")
                    }
                    $null = $NeededAdditionalSSHExeOptions.Add("iPathToPrivateKey")
                    $FinalPathToPrivateKey = $PrivateKeyFileInfoObject.File
                    $null = $NeededAdditionalSSHExeOptions.Add("iPathToPublicCert")
                    $FinalPathToPublicCert = $SSHPublicCertFilePath
                }
                if ($PositionOfLoadedPrivateKey -ge 4) {
                    $PubCertAuthShouldWork = $True
                    if ($SSHAgentKeyFingerPrintsInSSHAgent.Count -gt 4) { 
                        $null = $NeededAdditionalSSHExeOptions.Add("IdentitiesOnly")
                    }
                    $null = $NeededAdditionalSSHExeOptions.Add("iPathToPrivateKey")
                    $FinalPathToPrivateKey = $PrivateKeyFileInfoObject.File
                }
                if ($PrivateKeyIsLoadedInSSHAgent -and $PositionOfLoadedPrivateKey -lt 4) {
                    # Even if the Private Key is Loaded in the ssh-agent and it's low enough on the list,
                    # we need to make sure that the ssh-agent is aware of the Public Key Certificate specifically
                    #
                    # NOTE: In the below, we can use `$_.Contents -eq $(Get-Content $SSHPublicCertFilePath)`
                    # as opposed to `$(Compare-Object $_.Contents $(Get-Content $SSHPublicCertFilePath)) -eq $null` because
                    # each should be a single string (as opposed to an array of strings)
                    $PublicCertLoadedCheck = $SSHAgentKeyFingerPrintsInSSHAgent | Where-Object {
                        $_.FingerPrint -match [regex]::Escape($RelevantString) -and
                        $($($_.Contents -split " ")[0..1] -join " ") -eq $($($(Get-Content $SSHPublicCertFilePath) -split " ")[0..1] -join " ")
                    }
                    
                    if ($PublicCertLoadedCheck) {
                        $PubCertAuthShouldWork = $True
                    }
                    else {
                        $SSHClientProblemDescription = "The Private Key is loaded in the ssh-agent and it is low enough " +
                        "on the list of keys to present to the Remote Host, HOWEVER, the ssh-agent does not appear to be " +
                        "aware of the Public Key Certificate (i.e. 'ssh-add -L' will not contain the output of " +
                        "'Get-Content '$SSHPublicCertFilePath''. To remedy, remove the key from the ssh-agent via " +
                        "'ssh-add -d', ensure the Public Key Certificate is in the same directory as the Private Key, " +
                        "ensure the Public Key Certificate file has the same file name as the Private Key just appended " +
                        "with '-cert.pub', and add the Private Key to the ssh-agent via 'ssh-add <PathToPrivateKeyFile>' "
                        $PubCertAuthShouldWork = $False
                    }
                }
            }
        }
        if ($SSHPublicKeyFilePath) {
            # If the corresponding Private Key is loaded in the ssh-agent, then we need to make sure it reflects
            # a Public Key Certificate (i.e. content should not equal `Get-Content $SSHPublicKeyFile`).
            # If the corresponding Private Key is NOT Loaded in the ssh-agent, then it better be on the filesystem,
            # otherwise, we're out of luck.
            if ($RelatedKeyFileInfoObjects.Count -eq 1 -or 
            $($RelatedKeyFileInfoObjects.Count -ge 2 -and $RelatedKeyFileInfoObjects.FileType -notcontains "RSAPrivateKey")
            ) {
                if (!$PrivateKeyIsLoadedInSSHAgent) {
                    $PubCertAuthShouldWork = $False
                    $SSHClientProblemDescription = "Unable to find Private Key in ssh-agent or in same directory as the Public Key (i.e. $KeyFileParentDirectory)!"
                }
                if ($PositionOfLoadedPrivateKey -ge 4) {
                    $SSHClientProblemDescription = "The Private Key is not on the filesystem in same directory " +
                    "as the Public Key (i.e. $KeyFileParentDirectory). The Private Key IS loaded in the ssh-agent, "
                    "however, it is not in the top 5 on the list, so the sshd server on the Remote Host will most " +
                    "likely reject authentication because of too many attempts!"
                    $PubCertAuthShouldWork = $False
                }
                if ($PrivateKeyIsLoadedInSSHAgent -and $PositionOfLoadedPrivateKey -lt 4) {
                    # Even if the Private Key is Loaded in the ssh-agent and it's low enough on the list,
                    # we need to make sure that the ssh-agent is aware of the Public Key Certificate specifically
                    #
                    # NOTE: In the below, we can use `$_.Contents -eq $(Get-Content $SSHPublicCertFilePath)`
                    # as opposed to `$(Compare-Object $_.Contents $(Get-Content $SSHPublicCertFilePath)) -eq $null` because
                    # each should be a single string (as opposed to an array of strings)
                    $PublicCertLoadedCheck = $SSHAgentKeyFingerPrintsInSSHAgent | Where-Object {
                        $_.FingerPrint -match [regex]::Escape($RelevantString) -and
                        $($($_.Contents -split " ")[0..1] -join " ") -ne $($($(Get-Content $SSHPublicKeyFilePath) -split " ")[0..1] -join " ")
                    }
                    
                    if ($PublicCertLoadedCheck) {
                        $PubCertAuthShouldWork = $True
                    }
                    else {
                        $SSHClientProblemDescription = "The Private Key is loaded in the ssh-agent and it is low enough " +
                        "on the list of keys to present to the Remote Host, HOWEVER, the ssh-agent does not appear to be " +
                        "aware of the Public Key Certificate (i.e. 'ssh-add -L' will not contain the output of " +
                        "'Get-Content '$SSHPublicCertFilePath''. To remedy, remove the key from the ssh-agent via " +
                        "'ssh-add -d', ensure the Public Key Certificate is in the same directory as the Private Key, " +
                        "ensure the Public Key Certificate file has the same file name as the Private Key just appended " +
                        "with '-cert.pub', and add the Private Key to the ssh-agent via 'ssh-add <PathToPrivateKeyFile>' "
                        $PubCertAuthShouldWork = $False
                    }
                }
            }
            if ($RelatedKeyFileInfoObjects.Count -ge 2 -and $RelatedKeyFileInfoObjects.FileType -contains "RSAPrivateKey") {
                if (!$PrivateKeyIsLoadedInSSHAgent) {
                    # If the Private Key is not loaded in the ssh-agent, we need both the Private Key and the 
                    # Public Key Certificate on the filesystem. At this point we know we have the Private Key
                    # File, so now we have to check to see if we have the Public Key Certificate File
                    if ($RelatedKeyFileInfoObjects.FileType -notcontains "RSAPublicKeyCertificate") {
                        $SSHClientProblemDescription = "We are unable to find the RSA Public Key Certificate either on the filesystem (i.e. under $KeyFileParentDirectory), or loaded in the ssh-agent!"
                        $PubCertAuthShouldWork = $False
                    }
                    if ($RelatedKeyFileInfoObjects.FileType -contains "RSAPublicKeyCertificate") {
                        $PubCertAuthShouldWork = $True
                        
                        if ($SSHAgentKeyFingerPrintsInSSHAgent.Count -gt 4) { 
                            $null = $NeededAdditionalSSHExeOptions.Add("IdentitiesOnly")
                        }
                        $null = $NeededAdditionalSSHExeOptions.Add("iPathToPrivateKey")
                        $FinalPathToPrivateKey = $($RelatedKeyFileInfoObjects | Where-Object {$_.FileType -eq "RSAPrivateKey"}).File
                        $null = $NeededAdditionalSSHExeOptions.Add("iPathToPublicCert")
                        $FinalPathToPublicCert = $($RelatedKeyFileInfoObjects | Where-Object {$_.FileType -eq "RSAPublicKeyCertificate"}).File
                    }
                }
                if ($PositionOfLoadedPrivateKey -ge 4) {
                    # We need to determine if the output of `ssh-add -L` references the Public Key Certificate
                    # or just the Public Key. If it just references the Public Key, we're out of luck.
                    $PublicCertLoadedCheck = $SSHAgentKeyFingerPrintsInSSHAgent | Where-Object {
                        $_.FingerPrint -match [regex]::Escape($RelevantString) -and
                        $($($_.Contents -split " ")[0..1] -join " ") -ne $($($(Get-Content $SSHPublicKeyFilePath) -split " ")[0..1] -join " ")
                    }

                    if ($PublicCertLoadedCheck) {
                        # Even though the Private Key corresponding to a Public Key Certificate is loaded in the ssh-agent
                        # it's position is too high in the list. But what we can do is write the string to a file in 
                        # $KeyFileParentDirectory and use `-i` options
                        $PublicKeyCertificateString = $PublicCertLoadedCheck.Contents
                        Set-Content -Value $PublicKeyCertificateString -Path $($SSHPublicKeyFilePath -replace "\.pub","-cert.pub")

                        $null = $NeededAdditionalSSHExeOptions.Add("IdentitiesOnly")
                        $null = $NeededAdditionalSSHExeOptions.Add("iPathToPrivateKey")
                        $FinalPathToPrivateKey = $($RelatedKeyFileInfoObjects | Where-Object {$_.FileType -eq "RSAPrivateKey"}).File
                        $null = $NeededAdditionalSSHExeOptions.Add("iPathToPublicCert")
                        $FinalPathToPublicCert = $($SSHPublicKeyFilePath -replace "\.pub","-cert.pub")
                    }
                    if (!$PublicCertLoadedCheck) {
                        $SSHClientProblemDescription = "The corresponding Private Key is on the filesystem (i.e. under " +
                        "$KeyFileParentDirectory), and that private key is loaded in the ssh-agent, however, the ssh-agent " +
                        "does not appear to be aware of a Public Key Certificate (i.e. 'ssh-add -L' should NOT contain the " +
                        "same output as 'Get-Content $SSHPublicKeyFilePath'). To remedy, remove the key from the ssh-agent via " +
                        "'ssh-add -d', ensure the Public Key Certificate is in the same directory as the Private Key, " +
                        "ensure the Public Key Certificate file has the same file name as the Private Key just appended " +
                        "with '-cert.pub', and add the Private Key to the ssh-agent via 'ssh-add <PathToPrivateKeyFile>'"
                        $PubCertAuthShouldWork = $False
                    }
                }
                if ($PrivateKeyIsLoadedInSSHAgent -and $PositionOfLoadedPrivateKey -lt 4) {
                    # Even if the Private Key is Loaded in the ssh-agent and it's low enough on the list,
                    # we need to make sure that the ssh-agent is aware of the Public Key Certificate specifically
                    #
                    # NOTE: In the below, we can use `$_.Contents -eq $(Get-Content $SSHPublicCertFilePath)`
                    # as opposed to `$(Compare-Object $_.Contents $(Get-Content $SSHPublicCertFilePath)) -eq $null` because
                    # each should be a single string (as opposed to an array of strings)
                    $PublicCertLoadedCheck = $SSHAgentKeyFingerPrintsInSSHAgent | Where-Object {
                        $_.FingerPrint -match [regex]::Escape($RelevantString) -and
                        $($($_.Contents -split " ")[0..1] -join " ") -ne $($($(Get-Content $SSHPublicKeyFilePath) -split " ")[0..1] -join " ")
                    }
                    
                    if ($PublicCertLoadedCheck) {
                        $PubCertAuthShouldWork = $True
                    }
                    else {
                        $SSHClientProblemDescription = "The Private Key is loaded in the ssh-agent and it is low enough " +
                        "on the list of keys to present to the Remote Host, HOWEVER, the ssh-agent does not appear to be " +
                        "aware of a Public Key Certificate (i.e. 'ssh-add -L' contains the output of " +
                        "'Get-Content '$SSHPublicKeyFilePath'' instead of the Public Key Certificate string. " +
                        "To remedy, remove the key from the ssh-agent via 'ssh-add -d', ensure the Public Key Certificate " +
                        "is in the same directory as the Private Key, ensure the Public Key Certificate file has the same " +
                        "file name as the Private Key just appended with '-cert.pub', and add the Private Key to the " +
                        "ssh-agent via 'ssh-add <PathToPrivateKeyFile>'"
                        $PubCertAuthShouldWork = $False
                    }
                }
            }
        }
        if ($SSHPrivateKeyFilePath) {
            if ($RelatedKeyFileInfoObjects.Count -eq 1) {
                if (!$PrivateKeyIsLoadedInSSHAgent) {
                    $PubCertAuthShouldWork = $False
                    $SSHClientProblemDescription = "Unable to find Public Key Certificate either under $KeyFileParentDirectory or loaded in the ssh-agent!"
                }
                if ($PositionOfLoadedPrivateKey -ge 4) {
                    # We need to determine if the output of `ssh-add -L` references the Public Key Certificate
                    # or just the Public Key. If it just references the Public Key, we're out of luck.
                    $PubKeyContent = ssh-keygen -y -f "$SSHPrivateKeyFilePath"
                    $PublicCertLoadedCheck = $SSHAgentKeyFingerPrintsInSSHAgent | Where-Object {
                        $_.FingerPrint -match [regex]::Escape($RelevantString) -and
                        $($($_.Contents -split " ")[0..1] -join " ") -ne $($($PubKeyContent -split " ")[0..1] -join " ")
                    }

                    if ($PublicCertLoadedCheck) {
                        # Even though the Private Key corresponding to a Public Key Certificate is loaded in the ssh-agent
                        # it's position is too high in the list. But what we can do is write the string to a file in 
                        # $KeyFileParentDirectory and use `-i` options
                        $PublicKeyCertificateString = $PublicCertLoadedCheck.Contents
                        Set-Content -Value $PublicKeyCertificateString -Path "$SSHPrivateKeyFilePath-cert.pub"

                        $null = $NeededAdditionalSSHExeOptions.Add("IdentitiesOnly")
                        $null = $NeededAdditionalSSHExeOptions.Add("iPathToPrivateKey")
                        $FinalPathToPrivateKey = $($RelatedKeyFileInfoObjects | Where-Object {$_.FileType -eq "RSAPrivateKey"}).File
                        $null = $NeededAdditionalSSHExeOptions.Add("iPathToPublicCert")
                        $FinalPathToPublicCert = "$SSHPrivateKeyFilePath-cert.pub"
                    }
                    if (!$PublicCertLoadedCheck) {
                        $SSHClientProblemDescription = "The corresponding Private Key is on the filesystem (i.e. under " +
                        "$KeyFileParentDirectory), and that private key is loaded in the ssh-agent, however, the ssh-agent " +
                        "does not appear to be aware of a Public Key Certificate (i.e. 'ssh-add -L' should NOT contain the " +
                        "same output as 'ssh-keygen -y -f '$SSHPrivateKeyFilePath''). To remedy, remove the key from the ssh-agent via " +
                        "'ssh-add -d', ensure the Public Key Certificate is in the same directory as the Private Key, " +
                        "ensure the Public Key Certificate file has the same file name as the Private Key just appended " +
                        "with '-cert.pub', and add the Private Key to the ssh-agent via 'ssh-add <PathToPrivateKeyFile>'"
                        $PubCertAuthShouldWork = $False
                    }
                }
                if ($PrivateKeyIsLoadedInSSHAgent -and $PositionOfLoadedPrivateKey -lt 4) {
                    # Even if the Private Key is Loaded in the ssh-agent and it's low enough on the list,
                    # we need to make sure that the ssh-agent is aware of the Public Key Certificate specifically
                    #
                    # NOTE: In the below, we can use `$_.Contents -eq $(Get-Content $SSHPublicCertFilePath)`
                    # as opposed to `$(Compare-Object $_.Contents $(Get-Content $SSHPublicCertFilePath)) -eq $null` because
                    # each should be a single string (as opposed to an array of strings)
                    $PubKeyContent = ssh-keygen -y -f "$SSHPrivateKeyFilePath"
                    $PublicCertLoadedCheck = $SSHAgentKeyFingerPrintsInSSHAgent | Where-Object {
                        $_.FingerPrint -match [regex]::Escape($RelevantString) -and
                        $($_.Contents -split " ")[0..1] -ne $($PubKeyContent -split " ")[0..1]
                        $($($_.Contents -split " ")[0..1] -join " ") -ne $($($PubKeyContent -split " ")[0..1] -join " ")
                    }
                    
                    if ($PublicCertLoadedCheck) {
                        $PubCertAuthShouldWork = $True
                    }
                    else {
                        $SSHClientProblemDescription = "The Private Key is loaded in the ssh-agent and it is low enough " +
                        "on the list of keys to present to the Remote Host, HOWEVER, the ssh-agent does not appear to be " +
                        "aware of a Public Key Certificate (i.e. 'ssh-add -L' will not contain the output of " +
                        "'ssh-keygen -y -f '$SSHPrivateKeyFilePath''). To remedy, remove the key from the ssh-agent via " +
                        "'ssh-add -d', ensure the Public Key Certificate is in the same directory as the Private Key, " +
                        "ensure the Public Key Certificate file has the same file name as the Private Key just appended " +
                        "with '-cert.pub', and add the Private Key to the ssh-agent via 'ssh-add <PathToPrivateKeyFile>' "
                        $PubCertAuthShouldWork = $False
                    }
                }
            }
            if ($RelatedKeyFileInfoObjects.Count -ge 2) {
                if (!$PrivateKeyIsLoadedInSSHAgent) {
                    # If the Private Key is not loaded in the ssh-agent, we need both the Private Key and the 
                    # Public Key Certificate on the filesystem. At this point we know we have the Private Key
                    # File, so now we have to check to see if we have the Public Key Certificate File
                    if ($RelatedKeyFileInfoObjects.FileType -notcontains "RSAPublicKeyCertificate") {
                        $SSHClientProblemDescription = "We are unable to find the RSA Public Key Certificate either on the filesystem (i.e. under $KeyFileParentDirectory), or loaded in the ssh-agent!"
                        $PubCertAuthShouldWork = $False
                    }
                    if ($RelatedKeyFileInfoObjects.FileType -contains "RSAPublicKeyCertificate") {
                        $PubCertAuthShouldWork = $True
                        
                        if ($SSHAgentKeyFingerPrintsInSSHAgent.Count -gt 4) { 
                            $null = $NeededAdditionalSSHExeOptions.Add("IdentitiesOnly")
                        }
                        $null = $NeededAdditionalSSHExeOptions.Add("iPathToPrivateKey")
                        $FinalPathToPrivateKey = $($RelatedKeyFileInfoObjects | Where-Object {$_.FileType -eq "RSAPrivateKey"}).File
                        $null = $NeededAdditionalSSHExeOptions.Add("iPathToPublicCert")
                        $FinalPathToPublicCert = $($RelatedKeyFileInfoObjects | Where-Object {$_.FileType -eq "RSAPublicKeyCertificate"}).File
                    }
                }
                if ($PositionOfLoadedPrivateKey -ge 4) {
                    # We need to determine if the output of `ssh-add -L` references the Public Key Certificate
                    # or just the Public Key. If it just references the Public Key, we're out of luck.
                    $PubKeyContent = ssh-keygen -y -f "$SSHPrivateKeyFilePath"
                    $PublicCertLoadedCheck = $SSHAgentKeyFingerPrintsInSSHAgent | Where-Object {
                        $_.FingerPrint -match [regex]::Escape($RelevantString) -and
                        $($($_.Contents -split " ")[0..1] -join " ") -ne $($($PubKeyContent -split " ")[0..1] -join " ")
                    }

                    if ($PublicCertLoadedCheck) {
                        # Even though the Private Key corresponding to a Public Key Certificate is loaded in the ssh-agent
                        # it's position is too high in the list. But what we can do is write the string to a file in 
                        # $KeyFileParentDirectory and use `-i` options
                        $PublicKeyCertificateString = $PublicCertLoadedCheck.Contents
                        Set-Content -Value $PublicKeyCertificateString -Path "$SSHPrivateKeyFilePath-cert.pub"

                        $null = $NeededAdditionalSSHExeOptions.Add("IdentitiesOnly")
                        $null = $NeededAdditionalSSHExeOptions.Add("iPathToPrivateKey")
                        $FinalPathToPrivateKey = $($RelatedKeyFileInfoObjects | Where-Object {$_.FileType -eq "RSAPrivateKey"}).File
                        $null = $NeededAdditionalSSHExeOptions.Add("iPathToPublicCert")
                        $FinalPathToPublicCert = "$SSHPrivateKeyFilePath-cert.pub"
                    }
                    if (!$PublicCertLoadedCheck) {
                        $SSHClientProblemDescription = "The corresponding Private Key is on the filesystem (i.e. under " +
                        "$KeyFileParentDirectory), and that private key is loaded in the ssh-agent, however, the ssh-agent " +
                        "does not appear to be aware of a Public Key Certificate (i.e. 'ssh-add -L' should NOT contain the " +
                        "same output as 'ssh-keygen -y -f '$SSHPrivateKeyFilePath''). To remedy, remove the key from the ssh-agent via " +
                        "'ssh-add -d', ensure the Public Key Certificate is in the same directory as the Private Key, " +
                        "ensure the Public Key Certificate file has the same file name as the Private Key just appended " +
                        "with '-cert.pub', and add the Private Key to the ssh-agent via 'ssh-add <PathToPrivateKeyFile>'"
                        $PubCertAuthShouldWork = $False
                    }
                }
                if ($PrivateKeyIsLoadedInSSHAgent -and $PositionOfLoadedPrivateKey -lt 4) {
                    # Even if the Private Key is Loaded in the ssh-agent and it's low enough on the list,
                    # we need to make sure that the ssh-agent is aware of the Public Key Certificate specifically
                    #
                    # NOTE: In the below, we can use `$_.Contents -eq $(Get-Content $SSHPublicCertFilePath)`
                    # as opposed to `$(Compare-Object $_.Contents $(Get-Content $SSHPublicCertFilePath)) -eq $null` because
                    # each should be a single string (as opposed to an array of strings)
                    $PubKeyContent = ssh-keygen -y -f "$SSHPrivateKeyFilePath"
                    $PublicCertLoadedCheck = $SSHAgentKeyFingerPrintsInSSHAgent | Where-Object {
                        $_.FingerPrint -match [regex]::Escape($RelevantString) -and
                        $($_.Contents -split " ")[0..1] -ne $($PubKeyContent -split " ")[0..1]
                        $($($_.Contents -split " ")[0..1] -join " ") -ne $($($PubKeyContent -split " ")[0..1] -join " ")
                    }
                    
                    if ($PublicCertLoadedCheck) {
                        $PubCertAuthShouldWork = $True
                    }
                    else {
                        $SSHClientProblemDescription = "The Private Key is loaded in the ssh-agent and it is low enough " +
                        "on the list of keys to present to the Remote Host, HOWEVER, the ssh-agent does not appear to be " +
                        "aware of a Public Key Certificate (i.e. 'ssh-add -L' will not contain the output of " +
                        "'ssh-keygen -y -f '$SSHPrivateKeyFilePath''). To remedy, remove the key from the ssh-agent via " +
                        "'ssh-add -d', ensure the Public Key Certificate is in the same directory as the Private Key, " +
                        "ensure the Public Key Certificate file has the same file name as the Private Key just appended " +
                        "with '-cert.pub', and add the Private Key to the ssh-agent via 'ssh-add <PathToPrivateKeyFile>' "
                        $PubCertAuthShouldWork = $False
                    }
                }
            }
        }
    }

    if ($AuthMethod -eq "PublicKeyCertificate") {
        if ($PubCertAuthShouldWork) {
            $PublicCertificateFileInfo = $RelatedKeyFileInfoObjects | Where-Object {$_.FileType -eq "RSAPublicKeyCertificate"}
            # Finally, if we're checking Public Key Certificate Authentication, we need to figure out if we need to specify a
            # User Account other that the Currently Logged in user, so we need to look at the 'Principals' on the Public Key Certificate
            $IndexOfPrincipals = $PublicCertificateFileInfo.Info.IndexOf($($PublicCertificateFileInfo.Info -match "Principals:"))
            $IndexOfCriticalOptions = $PublicCertificateFileInfo.Info.IndexOf($($PublicCertificateFileInfo.Info -match "Critical Options:"))
            [array]$UserPrincipalsOnCert = $PublicCertificateFileInfo.Info[$($IndexOfPrincipals+1)..$($IndexOfCriticalOptions-1)] | foreach {$_.Trim()}
            $WhoAmIReformatted = $($(whoami) -split "\\")[1] + "@" + $($(whoami) -split "\\")[0]
            if ($UserPrincipalsOnCert -contains $WhoAmIReformatted) {
                $DomainAccount = $True
            }
        }
    }

    # Create Output PSObject
    $Output = [ordered]@{}
    if ($AuthMethod -eq "PublicKey") {
        $PubKeyAuthTestResult = if ($PubKeyAuthShouldWork) {$True} else {$False}
        $Output.Add("PublicKeyAuthShouldWork",$PubKeyAuthTestResult)
    }
    if ($AuthMethod -eq "PublicKeyCertificate") {
        $PubKeyCertAuthTestResult = if ($PubCertAuthShouldWork) {$True} else {$False}
        $Output.Add("PublicKeyCertificateAuthShouldWork",$PubKeyCertAuthTestResult)
    }
    if ($SSHClientProblemDescription) {
        $Output.Add("SSHClientProblemDescription",$SSHClientProblemDescription)
    }
    if ($NeededAdditionalSSHExeOptions) {
        [System.Collections.ArrayList]$AdditionalArguments = @()
        if ($NeededAdditionalSSHExeOptions -contains "IdentitiesOnly") {
            $null = $AdditionalArguments.Add('-o "IdentitiesOnly=true"')
        }
        if ($NeededAdditionalSSHExeOptions -contains "iPathToPrivateKey") {
            #$PrivateKeyFileInfoObject = $RelatedKeyFileInfoObjects | Where-Object {$_.FileType -eq "RSAPrivateKey"}
            $null = $AdditionalArguments.Add("-i `"$FinalPathToPrivateKey`"")
        }
        if ($NeededAdditionalSSHExeOptions -contains "iPathToPublicCert") {
            $null = $AdditionalArguments.Add("-i `"$FinalPathToPublicCert`"") 
        }
    }

    if ($AuthMethod -eq "PublicKeyCertificate") {
        [System.Collections.ArrayList]$PossibleUserAtRemoteHostFormats = @()
        foreach ($UserAcct in [array]$UserPrincipalsOnCert) {
            if ($DomainAccount) {
                if ($($UserAcct -split "@")[-1] -ne $($(whoami) -split "\\")[0]) {
                    $null = $PossibleUserAtRemoteHostFormats.Add("$($($UserAcct -split "@")[0])@<RemoteHost>")
                }
                else {
                    $null = $PossibleUserAtRemoteHostFormats.Add("$UserAcct@<RemoteHost>")
                }
            }
            else {
                $null = $PossibleUserAtRemoteHostFormats.Add("$UserAcct@<RemoteHost>")
            }
        }
        
        $UserAtRemoteHost = $PossibleUserAtRemoteHostFormats -join " OR "
    }
    else {
        $UserAtRemoteHost = "<user>@<RemoteHost>"
    }

    if ($AdditionalArguments.Count -gt 0) {
        $SSHExeCommand = "ssh $($AdditionalArguments -join " ") $UserAtRemoteHost"
    }
    else {
        $SSHExeCommand = "ssh $UserAtRemoteHost"
    }

    if ($SSHExeCommand) {
        $Output.Add("FinalSSHExeCommand",$SSHExeCommand)
    }

    #$Output.Add("RelatedKeyFileInfo",$RelatedKeyFileInfoObjects)

    [pscustomobject]$Output

}


<#
    .SYNOPSIS
        This function gets information about the specified SSH Key/Certificate file.

        Output is a PSCustomObject with the following properties...

            File                = $PathToKeyFile
            FileType            = $FileType
            Contents            = $Contents
            Info                = $Info
            FingerPrint         = $FingerPrint
            PasswordProtected   = $PasswordProtected

        ...where...
        
            - $PathToKeyFile is the path to the Key file specified by the -PathToKeyFile parameter,
            - $FileType is either "RSAPublicKey", "RSAPrivateKey", or "RSAPublicKeyCertificate"
            - $Contents is the result of: Get-Content $PathToKeyFile
            - $Info is the result of: ssh-keygen -l -f "$PathToKeyFile"
            - $FingerPrint is the fingerprint of the $PathToKeyFile
            - $PasswordProtected is a Boolean that indicates whether or not the file is password protected.

    .DESCRIPTION
        See .SYNOPSIS

    .NOTES

    .PARAMETER PathToKeyFile
        This parameter is MANDATORY.

        This parameter takes a string that represents the full path to the SSH Key/Cert File you would
        like to inspect.

    .EXAMPLE
        # Open an elevated PowerShell Session, import the module, and -

        PS C:\Users\zeroadmin> Get-SSHFileInfo -PathToKeyFile "$HOME\.ssh\id_rsa"
        
#>
function Get-SSHFileInfo {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [string]$PathToKeyFile
    )

    $OpenSSHWinPath = "$env:ProgramFiles\OpenSSH-Win64"

    if (!$(Test-Path $OpenSSHWinPath)) {
        Write-Error "The path $OpenSSHWinPath was not found! Halting!"
        $global:FunctionResult = "1"
        return
    }

    [System.Collections.Arraylist][array]$CurrentEnvPathArray = $env:Path -split ";" | Where-Object {![System.String]::IsNullOrWhiteSpace($_)}
    if ($CurrentEnvPathArray -notcontains $OpenSSHWinPath) {
        $CurrentEnvPathArray.Insert(0,$OpenSSHWinPath)
        $env:Path = $CurrentEnvPathArray -join ";"
    }

    # Make sure we have access to ssh binaries
    if (![bool]$(Get-Command ssh-keygen -ErrorAction SilentlyContinue)) {
        Write-Error "Unable to find 'ssh-keygen.exe'! Halting!"
        $global:FunctionResult = "1"
        return
    }

    # Make sure the path exists
    if (!$(Test-Path $PathToKeyFile)) {
        Write-Error "Unable to find the path '$PathToKeyFile'! Halting!"
        $global:FunctionResult = "1"
        return
    }

    # This function can't validate .ppk files from putty, so just assume they're valid
    if ($(Get-Item $PathToKeyFile).Extension -eq ".ppk") {
        [pscustomobject]@{
            File                = $PathToKeyFile
            FileType            = "PuttyCombinedPublicPrivateKey"
            Contents            = $(Get-Content $PathToKeyFile)
            Info                = $(Get-Content $PathToKeyFile)
            FingerPrint         = $null
            PasswordProtected   = $null
        }
        
        return
    }

    $SSHKeyGenParentDir = $(Get-Command ssh-keygen).Source | Split-Path -Parent
    $SSHKeyGenArguments = "-l -f `"$PathToKeyFile`""

    $ProcessInfo = New-Object System.Diagnostics.ProcessStartInfo
    $ProcessInfo.WorkingDirectory = $SSHKeyGenParentDir
    $ProcessInfo.FileName = $(Get-Command ssh-keygen).Source
    $ProcessInfo.RedirectStandardError = $true
    $ProcessInfo.RedirectStandardOutput = $true
    #$ProcessInfo.StandardOutputEncoding = [System.Text.Encoding]::Unicode
    #$ProcessInfo.StandardErrorEncoding = [System.Text.Encoding]::Unicode
    $ProcessInfo.UseShellExecute = $false
    $ProcessInfo.Arguments = $SSHKeyGenArguments
    $Process = New-Object System.Diagnostics.Process
    $Process.StartInfo = $ProcessInfo
    $Process.Start() | Out-Null
    # Below $FinishedInAlottedTime returns boolean true/false
    $FinishedInAlottedTime = $Process.WaitForExit(5000)
    if (!$FinishedInAlottedTime) {
        $Process.Kill()
        $ProcessKilled = $True
    }
    $stdout = $Process.StandardOutput.ReadToEnd()
    $stderr = $Process.StandardError.ReadToEnd()
    $SSHKeyGenOutput = $stdout + $stderr

    $KeyFileContent = Get-Content $PathToKeyFile
    if ($SSHKeyGenOutput -match "(RSA-CERT)") {
        $PublicKeyCertInfo = ssh-keygen -L -f "$PathToKeyFile"
        $PublicKeyCertContent = $KeyFileContent
        $FingerPrint = ssh-keygen -l -f "$PathToKeyFile"
        $IsPublicKeyCert = $True
    }
    elseif ($SSHKeyGenOutput -match "(RSA)") {
        # It could be either a Public Key or Private Key
        $PrivateKeyAttempt = Validate-SSHPrivateKey -PathToPrivateKeyFile $PathToKeyFile
        if (!$PrivateKeyAttempt.ValidSSHPrivateKeyFormat) {
            $IsPublicKey = $True
            $PublicKeyContent = $KeyFileContent
            $PublicKeyInfo = $FingerPrint = ssh-keygen -l -f "$PathToKeyFile"
        }
        else {
            $IsPrivateKey = $True
            $PrivateKeyContent = $PrivateKeyInfo = $KeyFileContent
            $FingerPrint = ssh-keygen -l -f "$PathToKeyFile"
            $PasswordProtected = $PrivateKeyAttempt.PasswordProtected
        }
    }
    elseif ($SSHKeyGenOutput -match "passphrase|pass phrase" -or $($SSHKeyGenOutput -eq $null -and $ProcessKilled)) {
        $IsPrivateKey = $True
        $PrivateKeyContent = $PrivateKeyInfo = $KeyFileContent
        $PasswordProtected = $True
    }
    elseif ($KeyFileContent.Count -gt 0) {
        if ($(Get-Content $PathToKeyFile)[0] -match "SSH2") {
            [pscustomobject]@{
                File                = $PathToKeyFile
                FileType            = "SSH2_RFC4716"
                Contents            = $(Get-Content $PathToKeyFile)
                Info                = $(Get-Content $PathToKeyFile)
                FingerPrint         = $null
                PasswordProtected   = $null
            }
        }

        return
    }
    else {
        $NotPubKeyPrivKeyOrPubCert = $True
    }

    if ($NotPubKeyPrivKeyOrPubCert) {
        Write-Warning "'$PathToKeyFile' is NOT a Public Key, Public Key Certificate, or Private Key"
    }
    else {
        if ($IsPublicKeyCert) {
            $FileType           = "RSAPublicKeyCertificate"
            $Contents           = $PublicKeyCertContent
            $Info               = $PublicKeyCertInfo
            $PasswordProtected  = $False
        }
        if ($IsPublicKey) {
            $FileType           = "RSAPublicKey"
            $Contents           = $PublicKeyContent
            $Info               = $PublicKeyInfo
            $PasswordProtected  = $False
        }
        if ($IsPrivateKey) {
            $FileType           = "RSAPrivateKey"
            $Contents           = $PrivateKeyContent
            $Info               = $PrivateKeyInfo
            $PasswordProtected  = $PrivateKeyAttempt.PasswordProtected
        }

        [pscustomobject]@{
            File                = $PathToKeyFile
            FileType            = $FileType
            Contents            = $Contents
            Info                = $Info
            FingerPrint         = $FingerPrint
            PasswordProtected   = $PasswordProtected
        }
    }
}


<#
    .SYNOPSIS
        This function installs OpenSSH-Win64 binaries and creates the ssh-agent service.

        The code for this function is, in large part, carved out of the 'install-sshd.ps1' script bundled with
        an OpenSSH-Win64 install.

        Original authors (github accounts):
            @manojampalam
            @friism
            @manojampalam
            @bingbing8

    .DESCRIPTION
        See .SYNOPSIS

    .NOTES

    .PARAMETER UseChocolateyCmdLine
        This parameter is OPTIONAL.

        This parameter is a switch. If used, OpenSSH binaries will be installed via the Chocolatey CmdLine.
        If the Chocolatey CmdLine is not already installed, it will be installed.

    .PARAMETER UsePowerShellGet
        This parameter is OPTIONAL.

        This parameter is a switch. If used, OpenSSH binaries will be installed via PowerShellGet/PackageManagement
        Modules.

    .PARAMETER GitHubInstall
        This parameter is OPTIONAL.

        This parameter is a switch. If used, OpenSSH binaries will be installed by downloading the .zip
        from https://github.com/PowerShell/Win32-OpenSSH/releases/latest/, expanding the archive, moving
        the files to the approproiate location(s), and setting permissions appropriately.

    .PARAMETER UpdatePackageManagement
        This parameter is OPTIONAL.

        This parameter is a switch. If used, PowerShellGet/PackageManagement Modules will be updated to their
        latest version before installation of OpenSSH binaries.

        WARNING: Using this parameter could break certain PowerShellGet/PackageManagement cmdlets. Recommend
        using the dedicated function "Update-PackageManagemet" and starting a fresh PowerShell session after
        it finishes.

    .PARAMETER SkipWinCapabilityAttempt
        This parameter is OPTIONAL.

        This parameter is a switch.
        
        In more recent versions of Windows (Spring 2018), OpenSSH Client and SSHD Server can be installed as
        Windows Features using the Dism Module 'Add-WindowsCapability' cmdlet. If you run this function on
        a more recent version of Windows, it will attempt to use 'Add-WindowsCapability' UNLESS you use
        this switch.

        As of May 2018, there are reliability issues with the 'Add-WindowsCapability' cmdlet.
        Using this switch is highly recommend in order to avoid using 'Add-WindowsCapability'.

    .PARAMETER Force
        This parameter is a OPTIONAL.

        This parameter is a switch.

        If you are already running the latest version of OpenSSH, but would like to reinstall it and the
        associated ssh-agent service, use this switch.

    .EXAMPLE
        # Open an elevated PowerShell Session, import the module, and -

        PS C:\Users\zeroadmin> Install-SSHAgentService

#>
function Install-SSHAgentService {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [switch]$UseChocolateyCmdLine,

        [Parameter(Mandatory=$False)]
        [switch]$GitHubInstall,

        [Parameter(Mandatory=$False)]
        [switch]$SkipWinCapabilityAttempt,

        [Parameter(Mandatory=$False)]
        [switch]$Force
    )
    ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####

    if (!$(GetElevation)) {
        Write-Error "You must run PowerShell as Administrator before using this function! Halting!"
        $global:FunctionResult = "1"
        return
    }

    $OpenSSHWinPath = "$env:ProgramFiles\OpenSSH-Win64"
    $tempfile = [IO.Path]::Combine([IO.Path]::GetTempPath(), [IO.Path]::GetRandomFileName())

    # NOTE: In this context, 'installing' OpenSSH simply means getting ssh.exe and all related files into $OpenSSHWinPath

    #region >> Install OpenSSH Via Windows Capability
    
    if ([Environment]::OSVersion.Version -ge [version]"10.0.17063" -and !$SkipWinCapabilityAttempt) {
        # Import the Dism Module
        if ($(Get-Module).Name -notcontains "Dism") {
            try {
                Import-Module Dism
            }
            catch {
                # Using full path to Dism Module Manifest because sometimes there are issues with just 'Import-Module Dism'
                $DismModuleManifestPaths = $(Get-Module -ListAvailable -Name Dism).Path

                foreach ($MMPath in $DismModuleManifestPaths) {
                    try {
                        Import-Module $MMPath -ErrorAction Stop
                        break
                    }
                    catch {
                        Write-Verbose "Unable to import $MMPath..."
                    }
                }
            }
        }
        if ($(Get-Module).Name -notcontains "Dism") {
            Write-Error "Problem importing the Dism PowerShell Module! Unable to proceed with Hyper-V install! Halting!"
            $global:FunctionResult = "1"
            return
        }

        $OpenSSHClientFeature = Get-WindowsCapability -Online | Where-Object {$_.Name -match 'OpenSSH\.Client'}

        if (!$OpenSSHClientFeature) {
            Write-Warning "Unable to find the OpenSSH.Client feature using the Get-WindowsCapability cmdlet!"
            $AddWindowsCapabilityFailure = $True
        }
        else {
            try {
                $SSHClientFeatureInstall = Add-WindowsCapability -Online -Name $OpenSSHClientFeature.Name -ErrorAction Stop
            }
            catch {
                Write-Warning "The Add-WindowsCapability cmdlet failed to add the $($OpenSSHClientFeature.Name)!"
                $AddWindowsCapabilityFailure = $True
            }
        }

        # Make sure the ssh-agent service exists
        try {
            $SSHDServiceCheck = Get-Service sshd -ErrorAction Stop
        }
        catch {
            $AddWindowsCapabilityFailure = $True
        }
    }

    #endregion >> Install OpenSSH Via Windows Capability


    #region >> Install OpenSSH via Traditional Methods

    if ([Environment]::OSVersion.Version -lt [version]"10.0.17063" -or $AddWindowsCapabilityFailure -or $SkipWinCapabilityAttempt -or $Force) {
        #region >> Get OpenSSH-Win64 Files
        
        if (!$GitHubInstall) {
            $InstallProgramSplatParams = @{
                ProgramName                 = "openssh"
                CommandName                 = "ssh.exe"
                ExpectedInstallLocation     = $OpenSSHWinPath
                ErrorAction                 = "SilentlyContinue"
                ErrorVariable               = "IPErr"
                WarningAction               = "SilentlyContinue"
            }

            try {
                $OpenSSHInstallResults = Install-Program @InstallProgramSplatParams
                if (!$OpenSSHInstallResults) {throw "There was a problem with the Install-Program function! Halting!"}
            }
            catch {
                Write-Error $_
                Write-Host "Errors for the Install-Program function are as follows:"
                Write-Error $($IPErr | Out-String)
                $global:FunctionResult = "1"
                return
            }
        }
        else {
            try {
                Write-Host "Finding latest version of OpenSSH for Windows..."
                $url = 'https://github.com/PowerShell/Win32-OpenSSH/releases/latest/'
                $request = [System.Net.WebRequest]::Create($url)
                $request.AllowAutoRedirect = $false
                $response = $request.GetResponse()
    
                $LatestOpenSSHWin = $($response.GetResponseHeader("Location") -split '/v')[-1]
            }
            catch {
                Write-Error "Unable to determine the latest version of OpenSSH using the Find-Package cmdlet! Try the Install-WinSSH function again using the -UsePowerShellGet switch. Halting!"
                $global:FunctionResult = "1"
                return
            }
    
            try {
                $SSHExePath = $(Get-ChildItem -Path $OpenSSHWinPath -File -Recurse -Filter "ssh.exe").FullName
            
                if (Test-Path $SSHExePath) {
                    $InstalledOpenSSHVer = [version]$(Get-Item $SSHExePath).VersionInfo.FileVersion
                }
    
                $NeedNewerVersion = $InstalledOpenSSHVer -lt [version]$($LatestOpenSSHWin -split "[a-zA-z]")[0]
                
                if ($Force) {
                    $NeedNewerVersion = $True
                }
            }
            catch {
                $NotInstalled = $True
            }
    
            $WinSSHFileNameSansExt = "OpenSSH-Win64"
            if ($NeedNewerVersion -or $NotInstalled) {
                try {
                    $WinOpenSSHDLLink = $([String]$response.GetResponseHeader("Location")).Replace('tag','download') + "/$WinSSHFileNameSansExt.zip"
                    Write-Host "Downloading OpenSSH-Win64 from $WinOpenSSHDLLink..."
                    Invoke-WebRequest -Uri $WinOpenSSHDLLink -OutFile "$HOME\Downloads\$WinSSHFileNameSansExt.zip"
                    # NOTE: OpenSSH-Win64.zip contains a folder OpenSSH-Win64, so no need to create one before extraction
                    $null = UnzipFile -PathToZip "$HOME\Downloads\$WinSSHFileNameSansExt.zip" -TargetDir "$HOME\Downloads"
                    if (Test-Path $OpenSSHWinPath) {
                        $SSHAgentService = Get-Service ssh-agent -ErrorAction SilentlyContinue
                        if ($SSHAgentService) {$SSHAgentService | Stop-Service -ErrorAction SilentlyContinue}
                        $SSHDService = Get-Service sshd -ErrorAction SilentlyContinue
                        if ($SSHDService) {Stop-Service -ErrorAction SilentlyContinue}
                        $SSHKeyGenProcess = Get-Process -name ssh-keygen -ErrorAction SilentlyContinue
                        if ($SSHKeyGenProcess) {$SSHKeyGenProcess | Stop-Process -ErrorAction SilentlyContinue}

                        Remove-Item $OpenSSHWinPath -Recurse -Force
                    }
                    Move-Item "$HOME\Downloads\$WinSSHFileNameSansExt" $OpenSSHWinPath
                    Enable-NTFSAccessInheritance -Path $OpenSSHWinPath -RemoveExplicitAccessRules
                }
                catch {
                    Write-Error $_
                    Write-Error "Installation of OpenSSH failed! Halting!"
                    $global:FunctionResult = "1"
                    return
                }
            }
            else {
                Write-Error "It appears that the newest version of $WinSSHFileNameSansExt is already installed! Halting!"
                $global:FunctionResult = "1"
                return
            }
        }

        #endregion >> Get OpenSSH-Win64 Files

        # Make sure $OpenSSHWinPath is part of $env:Path
        [System.Collections.Arraylist][array]$CurrentEnvPathArray = $env:Path -split ";" | Where-Object {![System.String]::IsNullOrWhiteSpace($_)}
        if ($CurrentEnvPathArray -notcontains $OpenSSHWinPath) {
            $CurrentEnvPathArray.Insert(0,$OpenSSHWinPath)
            $env:Path = $CurrentEnvPathArray -join ";"
        }

        # Now ssh.exe and related should be available, but the ssh-agent service has not been installed yet

        if (!$(Test-Path $OpenSSHWinPath)) {
            Write-Error "The path $OpenSSHWinPath does not exist! Halting!"
            $global:FunctionResult = "1"
            return
        }

        # If the ssh-agent service exists from a previous OpenSSH install, make sure it is Stopped
        # Also, ssh-keygen might be running too, so make sure that process is stopped. 
        $SSHAgentService = Get-Service ssh-agent -ErrorAction SilentlyContinue
        if ($SSHAgentService) {$SSHAgentService | Stop-Service -ErrorAction SilentlyContinue}
        $SSHKeyGenProcess = Get-Process -name ssh-keygen -ErrorAction SilentlyContinue
        if ($SSHKeyGenProcess) {$SSHKeyGenProcess | Stop-Process -ErrorAction SilentlyContinue}

        #$sshdpath = Join-Path $OpenSSHWinPath "sshd.exe"
        $sshagentpath = Join-Path $OpenSSHWinPath "ssh-agent.exe"
        $etwman = Join-Path $OpenSSHWinPath "openssh-events.man"
        $sshdir = "$env:ProgramData\ssh"
        $logsdir = Join-Path $sshdir "logs"

        #region >> Setup openssh Windows Event Log

        # unregister etw provider
        wevtutil um `"$etwman`"

        # adjust provider resource path in instrumentation manifest
        [XML]$xml = Get-Content $etwman
        $xml.instrumentationManifest.instrumentation.events.provider.resourceFileName = $sshagentpath.ToString()
        $xml.instrumentationManifest.instrumentation.events.provider.messageFileName = $sshagentpath.ToString()

        $streamWriter = $null
        $xmlWriter = $null
        try {
            $streamWriter = new-object System.IO.StreamWriter($etwman)
            $xmlWriter = [System.Xml.XmlWriter]::Create($streamWriter)    
            $xml.Save($xmlWriter)
        }
        finally {
            if($streamWriter) {
                $streamWriter.Close()
            }
        }

        #register etw provider
        $null = wevtutil im `"$etwman`" *>$tempfile

        #endregion >> Setup openssh Windows Event Log

        #region >> Create teh ssh-agent service

        try {
            if ([bool]$(Get-Service ssh-agent -ErrorAction SilentlyContinue)) {
                Write-Host "Recreating ssh-agent service..."
                Stop-Service ssh-agent
                $null = sc.exe delete ssh-agent
            }
            else {
                Write-Host "Creating ssh-agent service..."
            }

            $agentDesc = "Agent to hold private keys used for public key authentication."
            $null = New-Service -Name ssh-agent -DisplayName "OpenSSH Authentication Agent" -BinaryPathName $sshagentpath -Description $agentDesc -StartupType Automatic
            $null = sc.exe sdset ssh-agent "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)(A;;RP;;;AU)"
            $null = sc.exe privs ssh-agent SeImpersonatePrivilege
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            return
        }

        # IMPORTANT NOTE: Starting the sshd service is what creates the directory C:\ProgramData\ssh and
        # all of its contents
        <#
        try {
            # Create the C:\ProgramData\ssh folder and set its permissions
            if (-not (Test-Path $sshdir -PathType Container)) {
                $null = New-Item $sshdir -ItemType Directory -Force -ErrorAction Stop
            }
            # Set Permissions
            $SecurityDescriptor = Get-NTFSSecurityDescriptor -Path $sshdir
            $SecurityDescriptor | Disable-NTFSAccessInheritance -RemoveInheritedAccessRules
            $SecurityDescriptor | Clear-NTFSAccess
            $SecurityDescriptor | Add-NTFSAccess -Account "NT AUTHORITY\Authenticated Users" -AccessRights "ReadAndExecute, Synchronize" -AppliesTo ThisFolderSubfoldersAndFiles
            $SecurityDescriptor | Add-NTFSAccess -Account SYSTEM -AccessRights FullControl -AppliesTo ThisFolderSubfoldersAndFiles
            $SecurityDescriptor | Add-NTFSAccess -Account Administrators -AccessRights FullControl -AppliesTo ThisFolderSubfoldersAndFiles
            $SecurityDescriptor | Set-NTFSSecurityDescriptor
            Set-NTFSOwner -Path $sshdir -Account Administrators
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            return
        }

        try {
            # Create logs folder and set its permissions
            if (-not (Test-Path $logsdir -PathType Container)) {
                $null = New-Item $logsdir -ItemType Directory -Force -ErrorAction Stop
            }
            # Set Permissions
            $SecurityDescriptor = Get-NTFSSecurityDescriptor -Path $logsdir
            $SecurityDescriptor | Disable-NTFSAccessInheritance -RemoveInheritedAccessRules
            $SecurityDescriptor | Clear-NTFSAccess
            #$SecurityDescriptor | Add-NTFSAccess -Account "NT AUTHORITY\Authenticated Users" -AccessRights "ReadAndExecute, Synchronize" -AppliesTo ThisFolderSubfoldersAndFiles
            $SecurityDescriptor | Add-NTFSAccess -Account SYSTEM -AccessRights FullControl -AppliesTo ThisFolderSubfoldersAndFiles
            $SecurityDescriptor | Add-NTFSAccess -Account Administrators -AccessRights FullControl -AppliesTo ThisFolderSubfoldersAndFiles
            $SecurityDescriptor | Set-NTFSSecurityDescriptor
            Set-NTFSOwner -Path $logsdir -Account Administrators
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            return
        }
        #>
    }

    Start-Service ssh-agent -Passthru
    Start-Sleep -Seconds 5

    if ($(Get-Service ssh-agent).Status -ne "Running") {
        Write-Error "The ssh-agent service did not start succesfully! Halting!"
        $global:FunctionResult = "1"
        return
    }
    else {
        Write-Host "The ssh-agent service was successfully installed and started!" -ForegroundColor Green
    }

    if (Test-Path $tempfile) {
        Remove-Item $tempfile -Force -ErrorAction SilentlyContinue
    }
}


<#
    .SYNOPSIS
        Install OpenSSH-Win64 and the associated ssh-agent service. Optionally install SSHD server and associated
        sshd service. Optionally install the latest PowerShell Core.

    .DESCRIPTION
        See .SYNOPSIS

    .NOTES

    .PARAMETER ConfigureSSHDOnLocalHost
        This parameter is OPTIONAL.

        This parameter is a switch. If used, the SSHD Server and associated sshd service will be installedm
        configured, and enabled on the local host.

    .PARAMETER RemoveHostPrivateKeys
        This parameter is OPTIONAL.

        This parameter is a switch. Use it to remove the Host Private Keys after they are added to the ssh-agent during
        sshd setup/config. Default is NOT to remove the host private keys.

        This parameter should only be used in combination with the -ConfigureSSHDOnLocalHost switch.

    .PARAMETER DefaultShell
        This parameter is OPTIONAL.

        This parameter takes a string that must be one of two values: "powershell","pwsh"

        If set to "powershell", when a Remote User connects to the local host via ssh, they will enter a
        Windows PowerShell 5.1 shell.

        If set to "pwsh", when a Remote User connects to the local host via ssh, the will enter a
        PowerShell Core 6 shell.

        If this parameter is NOT used, the Default shell will be cmd.exe.

        This parameter should only be used in combination with the -ConfigureSSHDOnLocalHost switch.

    .PARAMETER GiveWinSSHBinariesPathPriority
        This parameter is OPTIONAL, but highly recommended.

        This parameter is a switch. If used, ssh binaries installed as part of OpenSSH-Win64 installation will get
        priority in your $env:Path. This is especially useful if you have ssh binaries in your path from other
        program installs (like git).

    .PARAMETER GitHubInstall
        This parameter is OPTIONAL.

        This parameter is a switch. If used, OpenSSH binaries will be installed by downloading the .zip
        from https://github.com/PowerShell/Win32-OpenSSH/releases/latest/, expanding the archive, moving
        the files to the approproiate location(s), and setting permissions appropriately.

    .PARAMETER SkipWinCapabilityAttempt
        This parameter is OPTIONAL.

        This parameter is a switch.
        
        In more recent versions of Windows (Spring 2018), OpenSSH Client and SSHD Server can be installed as
        Windows Features using the Dism Module 'Add-WindowsCapability' cmdlet. If you run this function on
        a more recent version of Windows, it will attempt to use 'Add-WindowsCapability' UNLESS you use
        this switch.

        As of May 2018, there are reliability issues with the 'Add-WindowsCapability' cmdlet.
        Using this switch is highly recommend in order to avoid using 'Add-WindowsCapability'.

    .PARAMETER Force
        This parameter is a OPTIONAL.

        This parameter is a switch.

        If you are already running the latest version of OpenSSH, but would like to reinstall it and the
        associated ssh-agent service, use this switch.

    .EXAMPLE
        # Open an elevated PowerShell Session, import the module, and -

        PS C:\Users\zeroadmin> Install-WinSSH -GiveWinSSHBinariesPathPriority -ConfigureSSHDOnLocalHost -DefaultShell powershell -GitHubInstall

#>
function Install-WinSSH {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [switch]$ConfigureSSHDOnLocalHost,

        [Parameter(Mandatory=$False)]
        [switch]$RemoveHostPrivateKeys,

        [Parameter(Mandatory=$False)]
        [ValidateSet("powershell","pwsh")]
        [string]$DefaultShell,

        # For situations where there may be more than one ssh.exe available on the system that are already part of $env:Path
        # or System PATH - for example, the ssh.exe that comes with Git
        [Parameter(Mandatory=$False)]
        [switch]$GiveWinSSHBinariesPathPriority,

        [Parameter(Mandatory=$False)]
        [switch]$GitHubInstall,

        [Parameter(Mandatory=$False)]
        [switch]$SkipWinCapabilityAttempt,

        [Parameter(Mandatory=$False)]
        [switch]$Force
    )

    ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####

    if (!$(GetElevation)) {
        Write-Verbose "You must run PowerShell as Administrator before using this function! Halting!"
        Write-Error "You must run PowerShell as Administrator before using this function! Halting!"
        $global:FunctionResult = "1"
        return
    }

    if ($DefaultShell -and !$ConfigureSSHDOnLocalHost) {
        Write-Error "The -DefaultShell parameter is meant to set the configure the default shell for the SSHD Server. Please also use the -ConfigureSSHDOnLocalHost switch. Halting!"
        $global:FunctionResult = "1"
        return
    }

    $OpenSSHWinPath = "$env:ProgramFiles\OpenSSH-Win64"

    ##### END Variable/Parameter Transforms and PreRun Prep #####


    ##### BEGIN Main Body #####
    
    $InstallSSHAgentSplatParams = @{
        ErrorAction         = "SilentlyContinue"
        ErrorVariable       = "ISAErr"
    }
    if ($GitHubInstall) {
        $InstallSSHAgentSplatParams.Add("GitHubInstall",$True)
    }
    if ($SkipWinCapabilityAttempt) {
        $InstallSSHAgentSplatParams.Add("SkipWinCapabilityAttempt",$True)
    }
    if ($Force) {
        $InstallSSHAgentSplatParams.Add("Force",$True)
    }

    try {
        $InstallSSHAgentResult = Install-SSHAgentService @InstallSSHAgentSplatParams
        if (!$InstallSSHAgentResult) {throw "The Install-SSHAgentService function failed!"}
    }
    catch {
        Write-Error $_
        Write-Host "Errors for the Install-SSHAgentService function are as follows:"
        Write-Error $($ISAErr | Out-String)
        $global:FunctionResult = "1"
        return
    }

    Write-Host "Finished installing ssh-agent..." -ForegroundColor Green

    if ($ConfigureSSHDOnLocalHost) {
        $NewSSHDServerSplatParams = @{
            ErrorAction         = "SilentlyContinue"
            ErrorVariable       = "SSHDErr"
        }
        if ($RemoveHostPrivateKeys) {
            $NewSSHDServerSplatParams.Add("RemoveHostPrivateKeys",$True)
        }
        if ($DefaultShell) {
            $NewSSHDServerSplatParams.Add("DefaultShell",$DefaultShell)
        }
        if ($SkipWinCapabilityAttempt) {
            $NewSSHDServerSplatParams.Add("SkipWinCapabilityAttempt",$True)
        }
        
        try {
            $NewSSHDServerResult = New-SSHDServer @NewSSHDServerSplatParams
            if (!$NewSSHDServerResult) {throw "There was a problem with the New-SSHDServer function! Halting!"}
        }
        catch {
            Write-Error $_
            Write-Host "Errors for the New-SSHDServer function are as follows:"
            Write-Error $($SSHDErr | Out-String)
            $global:FunctionResult = "1"
            return
        }
    }

    # Update $env:Path to give the ssh.exe binary we just installed priority
    if ($GiveWinSSHBinariesPathPriority) {
        if ($($env:Path -split ";") -notcontains $OpenSSHWinPath) {
            if ($env:Path[-1] -eq ";") {
                $env:Path = "$OpenSSHWinPath;$env:Path"
            }
            else {
                $env:Path = "$OpenSSHWinPath;$env:Path"
            }
        }
    }
    else {
        if ($($env:Path -split ";") -notcontains $OpenSSHWinPath) {
            if ($env:Path[-1] -eq ";") {
                $env:Path = "$env:Path$OpenSSHWinPath"
            }
            else {
                $env:Path = "$env:Path;$OpenSSHWinPath"
            }
        }
    }

    $Output = [ordered]@{
        SSHAgentInstallInfo     = $InstallSSHAgentResult
    }
    if ($NewSSHDServerResult) {
        $Output.Add("SSHDServerInstallInfo",$NewSSHDServerResult)
    }

    if ($Output.Count -eq 1) {
        $InstallSSHAgentResult
    }
    else {
        [pscustomobject]$Output
    }
}


<#
    .SYNOPSIS
        This function installs and configures the SSHD server (sshd service) on the local host.

    .DESCRIPTION
        See .SYNOPSIS

    .NOTES

    .PARAMETER RemoveHostPrivateKeys
        This parameter is OPTIONAL.

        This parameter is a switch. Use it to add the Host Private Keys to the ssh-agent and remove
        the Private Key files frome the filesystem during sshd setup/config. Default is NOT to remove
        the Host Private Keys.

    .PARAMETER DefaultShell
        This parameter is OPTIONAL.

        This parameter takes a string that must be one of two values: "powershell","pwsh"

        If set to "powershell", when a Remote User connects to the local host via ssh, they will enter a
        Windows PowerShell 5.1 shell.

        If set to "pwsh", when a Remote User connects to the local host via ssh, the will enter a
        PowerShell Core 6 shell.

        If this parameter is NOT used, the Default shell will be cmd.exe.

    .PARAMETER SkipWinCapabilityAttempt
        This parameter is OPTIONAL.

        This parameter is a switch.
        
        In more recent versions of Windows (Spring 2018), OpenSSH Client and SSHD Server can be installed as
        Windows Features using the Dism Module 'Add-WindowsCapability' cmdlet. If you run this function on
        a more recent version of Windows, it will attempt to use 'Add-WindowsCapability' UNLESS you use
        this switch.

        As of May 2018, there are reliability issues with the 'Add-WindowsCapability' cmdlet.
        Using this switch is highly recommend in order to avoid using 'Add-WindowsCapability'.

    .EXAMPLE
        # Open an elevated PowerShell Session, import the module, and -

        PS C:\Users\zeroadmin> New-SSHDServer -DefaultShell powershell
        
#>
function New-SSHDServer {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [switch]$RemoveHostPrivateKeys,

        [Parameter(Mandatory=$False)]
        [ValidateSet("powershell","pwsh")]
        [string]$DefaultShell,

        [Parameter(Mandatory=$False)]
        [switch]$SkipWinCapabilityAttempt
    )

    #region >> Prep

    if (!$(GetElevation)) {
        Write-Verbose "You must run PowerShell as Administrator before using this function! Halting!"
        Write-Error "You must run PowerShell as Administrator before using this function! Halting!"
        $global:FunctionResult = "1"
        return
    }

    $tempfile = [IO.Path]::Combine([IO.Path]::GetTempPath(), [IO.Path]::GetRandomFileName())
    $OpenSSHWinPath = Join-Path $env:ProgramFiles "OpenSSH-Win64"
    $sshagentpath = Join-Path $OpenSSHWinPath "ssh-agent.exe"
    $sshdpath = Join-Path $OpenSSHWinPath "sshd.exe"
    $sshdir = Join-Path $env:ProgramData "ssh"
    $sshdConfigPath = Join-Path $sshdir "sshd_config"
    $logsdir = Join-Path $sshdir "logs"

    # Make sure $OpenSSHWinPath is part of $env:Path
    [System.Collections.Arraylist][array]$CurrentEnvPathArray = $env:Path -split ";" | Where-Object {![System.String]::IsNullOrWhiteSpace($_)}
    if ($CurrentEnvPathArray -notcontains $OpenSSHWinPath) {
        $CurrentEnvPathArray.Insert(0,$OpenSSHWinPath)
        $env:Path = $CurrentEnvPathArray -join ";"
    }

    # Make sure the dependency ssh-agent service is already installed
    if (![bool]$(Get-Service ssh-agent -ErrorAction SilentlyContinue)) {
        try {
            $InstallSSHAgentSplatParams = @{
                ErrorAction         = "SilentlyContinue"
                ErrorVariable       = "ISAErr"
            }
            if ($SkipWinCapabilityAttempt) {
                $InstallSSHAgentSplatParams.Add("SkipWinCapabilityAttempt",$True)
            }
            if ($Force) {
                $InstallSSHAgentSplatParams.Add("Force",$True)
            }
            
            $InstallSSHAgentResult = Install-SSHAgentService @InstallSSHAgentSplatParams
            if (!$InstallSSHAgentResult) {throw "The Install-SSHAgentService function failed!"}
        }
        catch {
            Write-Error $_
            Write-Host "Errors for the Install-SSHAgentService function are as follows:"
            Write-Error $($ISAErr | Out-String)
            $global:FunctionResult = "1"
            return
        }
    }

    if (!$(Test-Path $OpenSSHWinPath)) {
        Write-Error "The path $OpenSSHWinPath does not exist! Halting!"
        $global:FunctionResult = "1"
        return
    }

    #endregion >> Prep

    #region >> Install the sshd Service

    if ([Environment]::OSVersion.Version -ge [version]"10.0.17063" -and !$SkipWinCapabilityAttempt) {
        try {
            # Import the Dism Module
            if ($(Get-Module).Name -notcontains "Dism") {
                try {
                    Import-Module Dism
                }
                catch {
                    # Using full path to Dism Module Manifest because sometimes there are issues with just 'Import-Module Dism'
                    $DismModuleManifestPaths = $(Get-Module -ListAvailable -Name Dism).Path

                    foreach ($MMPath in $DismModuleManifestPaths) {
                        try {
                            Import-Module $MMPath -ErrorAction Stop
                            break
                        }
                        catch {
                            Write-Verbose "Unable to import $MMPath..."
                        }
                    }
                }
            }
            if ($(Get-Module).Name -notcontains "Dism") {
                Write-Error "Problem importing the Dism PowerShell Module! Unable to proceed with Hyper-V install! Halting!"
                $global:FunctionResult = "1"
                return
            }

            $SSHDServerFeature = Get-WindowsCapability -Online | Where-Object {$_.Name -match 'OpenSSH\.Server'}

            if (!$SSHDServerFeature) {
                Write-Warning "Unable to find the OpenSSH.Server feature using the Get-WindowsCapability cmdlet!"
                $AddWindowsCapabilityFailure = $True
            }
            else {
                try {
                    $SSHDFeatureInstall = Add-WindowsCapability -Online -Name $SSHDServerFeature.Name -ErrorAction Stop
                }
                catch {
                    Write-Warning "The Add-WindowsCapability cmdlet failed to add the $($SSHDServerFeature.Name)!"
                    $AddWindowsCapabilityFailure = $True
                }
            }

            # Make sure the sshd service exists
            try {
                $SSHDServiceCheck = Get-Service sshd -ErrorAction Stop
            }
            catch {
                $AddWindowsCapabilityFailure = $True
            }
        }
        catch {
            Write-Warning "The Add-WindowsCapability cmdlet failed to add feature: $($SSHDServerFeature.Name) !"
            $AddWindowsCapabilityFailure = $True
        }
        
        if (!$AddWindowsCapabilityFailure) {
            try {
                # NOTE: $sshdir won't actually be created until you start the SSHD Service for the first time
                # Starting the service also creates all of the needed host keys.
                $SSHDServiceInfo = Get-Service sshd -ErrorAction Stop
                if ($SSHDServiceInfo.Status -ne "Running") {
                    $SSHDServiceInfo | Start-Service -ErrorAction Stop
                }

                if (Test-Path "$env:ProgramFiles\OpenSSH-Win64\sshd_config_default") {
                    # Copy sshd_config_default to $sshdir\sshd_config
                    $sshddefaultconfigpath = Join-Path $OpenSSHWinPath "sshd_config_default"
                    if (-not (Test-Path $sshdconfigpath -PathType Leaf)) {
                        $null = Copy-Item $sshddefaultconfigpath -Destination $sshdconfigpath -Force -ErrorAction Stop
                    }
                }
                else {
                    $SSHConfigUri = "https://raw.githubusercontent.com/PowerShell/Win32-OpenSSH/L1-Prod/contrib/win32/openssh/sshd_config"
                    Invoke-WebRequest -Uri $SSHConfigUri -OutFile $sshdConfigPath
                }

                $PubPrivKeyPairFiles = Get-ChildItem -Path $sshdir -File | Where-Object {$_.Name -match "ssh_host_rsa"}
                $PubHostKey = $PubPrivKeyPairFiles | Where-Object {$_.Extension -eq ".pub"}
                $PrivHostKey = $PubPrivKeyPairFiles | Where-Object {$_.Extension -ne ".pub"}
            }
            catch {
                Write-Error $_
                $global:FunctionResult = "1"
                return
            }
        }
    }
    
    if ([Environment]::OSVersion.Version -lt [version]"10.0.17063" -or $AddWindowsCapabilityFailure -or $SkipWinCapabilityAttempt) {
        if (!$(Test-Path $sshdpath)) {
            Write-Error "The path $sshdpath does not exist! Halting!"
            $global:FunctionResult = "1"
            return
        }

        # NOTE: Starting the sshd Service should create all below content and set appropriate permissions
        <#
        try {
            # Create the C:\ProgramData\ssh folder and set its permissions
            if (-not (Test-Path $sshdir -PathType Container)) {
                $null = New-Item $sshdir -ItemType Directory -Force -ErrorAction Stop
            }
            # Set Permissions
            $SecurityDescriptor = Get-NTFSSecurityDescriptor -Path $sshdir
            $SecurityDescriptor | Disable-NTFSAccessInheritance -RemoveInheritedAccessRules
            $SecurityDescriptor | Clear-NTFSAccess
            $SecurityDescriptor | Add-NTFSAccess -Account "NT AUTHORITY\Authenticated Users" -AccessRights "ReadAndExecute, Synchronize" -AppliesTo ThisFolderSubfoldersAndFiles
            $SecurityDescriptor | Add-NTFSAccess -Account SYSTEM -AccessRights FullControl -AppliesTo ThisFolderSubfoldersAndFiles
            $SecurityDescriptor | Add-NTFSAccess -Account Administrators -AccessRights FullControl -AppliesTo ThisFolderSubfoldersAndFiles
            $SecurityDescriptor | Set-NTFSSecurityDescriptor
            Set-NTFSOwner -Path $sshdir -Account Administrators
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            return
        }

        try {
            # Create logs folder and set its permissions
            if (-not (Test-Path $logsdir -PathType Container)) {
                $null = New-Item $logsdir -ItemType Directory -Force -ErrorAction Stop
            }
            # Set Permissions
            $SecurityDescriptor = Get-NTFSSecurityDescriptor -Path $logsdir
            $SecurityDescriptor | Disable-NTFSAccessInheritance -RemoveInheritedAccessRules
            $SecurityDescriptor | Clear-NTFSAccess
            #$SecurityDescriptor | Add-NTFSAccess -Account "NT AUTHORITY\Authenticated Users" -AccessRights "ReadAndExecute, Synchronize" -AppliesTo ThisFolderSubfoldersAndFiles
            $SecurityDescriptor | Add-NTFSAccess -Account SYSTEM -AccessRights FullControl -AppliesTo ThisFolderSubfoldersAndFiles
            $SecurityDescriptor | Add-NTFSAccess -Account Administrators -AccessRights FullControl -AppliesTo ThisFolderSubfoldersAndFiles
            $SecurityDescriptor | Set-NTFSSecurityDescriptor
            Set-NTFSOwner -Path $logsdir -Account Administrators
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            return
        }

        try {
            # Copy sshd_config_default to $sshdir\sshd_config
            $sshdConfigPath = Join-Path $sshdir "sshd_config"
            $sshddefaultconfigpath = Join-Path $OpenSSHWinPath "sshd_config_default"
            if (-not (Test-Path $sshdconfigpath -PathType Leaf)) {
                $null = Copy-Item $sshddefaultconfigpath -Destination $sshdconfigpath -Force -ErrorAction Stop
            }
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            return
        }
        #>

        try {
            if (Get-Service sshd -ErrorAction SilentlyContinue) {
               Stop-Service sshd
               $null = sc.exe delete sshd
            }
    
            $sshdDesc = "SSH protocol based service to provide secure encrypted communications between two untrusted hosts over an insecure network."
            $null = New-Service -Name sshd -DisplayName "OpenSSH SSH Server" -BinaryPathName $sshdpath -Description $sshdDesc -StartupType Automatic
            $null = sc.exe privs sshd SeAssignPrimaryTokenPrivilege/SeTcbPrivilege/SeBackupPrivilege/SeRestorePrivilege/SeImpersonatePrivilege
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            return
        }

        $SSHDServiceInfo = Get-Service sshd -ErrorAction Stop
        if ($SSHDServiceInfo.Status -ne "Running") {
            $SSHDServiceInfo | Start-Service -ErrorAction Stop
        }
        Start-Sleep -Seconds 5
        if ($(Get-Service sshd).Status -ne "Running") {
            Write-Error "The sshd service did not start succesfully (within 5 seconds) after initial install! Please check your sshd_config configuration. Halting!"
            $global:FunctionResult = "1"
            return
        }

        # NOTE: Starting the sshd Service should create the host keys, so we don't need to do it here
        <#
        # Setup Host Keys
        $SSHKeyGenProcessInfo = New-Object System.Diagnostics.ProcessStartInfo
        $SSHKeyGenProcessInfo.WorkingDirectory = $sshdir
        $SSHKeyGenProcessInfo.FileName = "ssh-keygen.exe"
        $SSHKeyGenProcessInfo.RedirectStandardError = $true
        $SSHKeyGenProcessInfo.RedirectStandardOutput = $true
        $SSHKeyGenProcessInfo.UseShellExecute = $false
        $SSHKeyGenProcessInfo.Arguments = "-A"
        $SSHKeyGenProcess = New-Object System.Diagnostics.Process
        $SSHKeyGenProcess.StartInfo = $SSHKeyGenProcessInfo
        $SSHKeyGenProcess.Start() | Out-Null
        $SSHKeyGenProcess.WaitForExit()
        $SSHKeyGenStdout = $SSHKeyGenProcess.StandardOutput.ReadToEnd()
        $SSHKeyGenStderr = $SSHKeyGenProcess.StandardError.ReadToEnd()
        $SSHKeyGenAllOutput = $SSHKeyGenStdout + $SSHKeyGenStderr

        if ($SSHKeyGenAllOutput -match "fail|error") {
            Write-Error $SSHKeyGenAllOutput
            Write-Error "The 'ssh-keygen -A' command failed! Halting!"
            $global:FunctionResult = "1"
            return
        }
        #>
        
        # Add the ssh_host_rsa private key to the ssh-agent
        $PubPrivKeyPairFiles = Get-ChildItem -Path $sshdir -File | Where-Object {$_.Name -match "ssh_host_rsa"}
        $PubHostKey = $PubPrivKeyPairFiles | Where-Object {$_.Extension -eq ".pub"}
        $PrivHostKey = $PubPrivKeyPairFiles | Where-Object {$_.Extension -ne ".pub"}

        if ($(Get-Service ssh-agent).Status -ne "Running") {
            Start-Service ssh-agent
            Start-Sleep -Seconds 5
        }
        if ($(Get-Service "ssh-agent").Status -ne "Running") {
            Write-Error "The ssh-agent service did not start succesfully (within 5 seconds)! Please check your config! Halting!"
            $global:FunctionResult = "1"
            return
        }

        if (![bool]$(Get-Command ssh-add -ErrorAction SilentlyContinue)) {
            Write-Error 'Unable to find ssh-add.exe! Is it part of your $env:Path? Halting!'
            $global:FunctionResult = "1"
            return
        }
        
        $SSHAddProcessInfo = New-Object System.Diagnostics.ProcessStartInfo
        $SSHAddProcessInfo.WorkingDirectory = $sshdir
        $SSHAddProcessInfo.FileName = "ssh-add.exe"
        $SSHAddProcessInfo.RedirectStandardError = $true
        $SSHAddProcessInfo.RedirectStandardOutput = $true
        $SSHAddProcessInfo.UseShellExecute = $false
        $SSHAddProcessInfo.Arguments = "$($PrivHostKey.FullName)"
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
            if ($RemoveHostPrivateKeys) {
                Remove-Item $PrivKey
            }
        }

        # EDIT: The below shouldn't be necessary...
        # IMPORTANT: It is important that File Permissions are "Fixed" at the end (as opposed to earlier in this function),
        # otherwise previous steps break
        <#
        if (!$(Test-Path "$OpenSSHWinPath\FixHostFilePermissions.ps1")) {
            Write-Error "The script $OpenSSHWinPath\FixHostFilePermissions.ps1 cannot be found! Permissions in the $OpenSSHWinPath directory need to be fixed before the sshd service will start successfully! Halting!"
            $global:FunctionResult = "1"
            return
        }

        try {
            & "$OpenSSHWinPath\FixHostFilePermissions.ps1" -Confirm:$false
        }
        catch {
            Write-Error "The script $OpenSSHWinPath\FixHostFilePermissions.ps1 failed! Permissions in the $OpenSSHWinPath directory need to be fixed before the sshd service will start successfully! Halting!"
            $global:FunctionResult = "1"
            return
        }
        #>
    }

    # Set the default shell
    if ($DefaultShell -eq "powershell" -or !$DefaultShell) {
        $null = Set-DefaultShell -DefaultShell "powershell"
    }
    else {
        $null = Set-DefaultShell -DefaultShell "pwsh"
    }

    #endregion >> Install the sshd Service


    ##### BEGIN Main Body #####

    # Make sure port 22 is open
    if (!$(TestPort -Port 22).Open) {
        # See if there's an existing rule regarding locahost TCP port 22, if so change it to allow port 22, if not, make a new rule
        $Existing22RuleCheck = Get-NetFirewallPortFilter -Protocol TCP | Where-Object {$_.LocalPort -eq 22}
        if ($Existing22RuleCheck -ne $null) {
            $Existing22Rule =  Get-NetFirewallRule -AssociatedNetFirewallPortFilter $Existing22RuleCheck | Where-Object {$_.Direction -eq "Inbound"}
            if ($Existing22Rule -ne $null) {
                $null = Set-NetFirewallRule -InputObject $Existing22Rule -Enabled True -Action Allow
            }
            else {
                $ExistingRuleFound = $False
            }
        }
        if ($Existing22RuleCheck -eq $null -or $ExistingRuleFound -eq $False) {
            $null = New-NetFirewallRule -Action Allow -Direction Inbound -Name ssh -DisplayName ssh -Enabled True -LocalPort 22 -Protocol TCP
        }
    }

    Restart-Service sshd
    Start-Sleep -Seconds 5

    if ($(Get-Service sshd).Status -ne "Running") {
        Write-Error "The sshd service did not start succesfully (within 5 seconds)! Please check your sshd_config configuration. Halting!"
        $global:FunctionResult = "1"
        return
    }

    if ($DefaultShell) {
        # For some reason, the 'ForceCommand' option is not picked up the first time the sshd service is started
        # so restart sshd service
        Restart-Service sshd
        Start-Sleep -Seconds 5
    }

    if ($(Get-Service sshd).Status -ne "Running") {
        Write-Error "The sshd service did not start succesfully (within 5 seconds)! Please check your sshd_config configuration. Halting!"
        $global:FunctionResult = "1"
        return
    }
    else {
        Write-Host "The sshd service was successfully installed and started!" -ForegroundColor Green
    }

    [pscustomobject]@{
        SSHDServiceStatus       = $(Get-Service sshd).Status
        SSHAgentServiceStatus   = $(Get-Service ssh-agent).Status
        RSAHostPublicKey        = $PubHostKey
        RSAHostPrivateKey       = $PrivHostKey
    }
}


<#
    .SYNOPSIS
        This function creates a new SSH Public/Private Key Pair. Optionally, add it to the ssh-agent.
        Optionally add the public key to a Remote Host's ~/.ssh/authorized_keys file.

    .DESCRIPTION
        See .SYNOPSIS

    .NOTES

    .PARAMETER NewSSHKeyName
        This parameter is MANDATORY.

        This parameter takes a string that represents the file name that you would like to give to the new
        SSH User/Client Keys.

    .PARAMETER NewSSHKeyPurpose
        This parameter is OPTIONAL.

        This parameter takes a string that represents a very brief description of what the new SSH Keys
        will be used for. This description will be added to the Comment section when the new keys are
        created.

    .PARAMETER NewSSHKeyPwd
        This parameter is OPTIONAL.

        This parameter takes a SecureString that represents the password used to protect the new
        Private Key file that is created.

    .PARAMETER BlankSSHPrivateKeyPwd
        This parameter is OPTIONAL.

        This parameter is a switch. Use it to ensure that the newly created Private Key is NOT password
        protected.

    .PARAMETER AddToSSHAgent
        This parameter is OPTIONAL, but recommended.

        This parameter is a switch. If used, the new SSH Key Pair will be added to the ssh-agent service.

    .PARAMETER RemovePrivateKey
        This parameter is OPTIONAL. This parameter should only be used in conjunction with the
        -AddtoSSHAgent switch.

        This parameter is a switch. If used, the newly created Private Key will be added to the ssh-agent
        and deleted from the filesystem.

    .PARAMETER RemoteHost
        This parameter is OPTIONAL. This parameter should only be used in conjunction with the
        -AddToRemoteHostAuthKeys switch.

        This parameter takes a string that represents the IP Address of DNS-Resolvable name of a Remote Host.
        The newly created public key will be added to the Remote Host's ~/.ssh/authorized_keys file. The
        Remote Host can be either Windows or Linux (as long as you can ssh to it from the local host).

    .PARAMETER AddToRemoteHostAuthKeys
        This parameter is OPTIONAL.

        This parameter is a switch. If used, the newly created Public Key will be added to the Remote Host's
        ~/.ssh/authorized_keys file. (Specify the Remote Host using the -RemoteHost parameter)

    .PARAMETER RemoteHostUserName
        This parameter is OPTIONAL. This parameter should only be used in conjunction with the
        -AddToRemoteHostAuthKeys parameter.

        This parameter takes a string that represents the name of the user with ssh access to
        the Remote Host (specified by the -RemoteHost parameter).

    .EXAMPLE
        # Open an elevated PowerShell Session, import the module, and -

        PS C:\Users\zeroadmin> $SplatParams = @{
            NewSSHKeyName           = "ToRHServ01"
            NewSSHKeyPurpose        = "ForSSHToRHServ01"
            AddToSSHAgent           = $True
        }
        PS C:\Users\zeroadmin> New-SSHKey @SplatParams
        
#>
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

    [System.Collections.Arraylist][array]$CurrentEnvPathArray = $env:Path -split ";" | Where-Object {![System.String]::IsNullOrWhiteSpace($_)}
    if ($CurrentEnvPathArray -notcontains $OpenSSHWinPath) {
        $CurrentEnvPathArray.Insert(0,$OpenSSHWinPath)
        $env:Path = $CurrentEnvPathArray -join ";"
    }

    if (!$(Test-Path "$HOME\.ssh")) {
        $null = New-Item -Type Directory -Path "$HOME\.ssh"
    }

    $SSHKeyOutFile = "$HOME\.ssh\$NewSSHKeyName"

    if ($NewSSHKeyPurpose) {
        $NewSSHKeyPurpose = $NewSSHKeyPurpose -replace "[\s]",""

        $SSHKeyGenArgumentsString = "-t rsa -b 2048 -f `"$SSHKeyOutFile`" -q -N `"$NewSSHKeyPwd`" -C `"$NewSSHKeyPurpose`""
        $SSHKeyGenArgumentsNoPwdString = "-t rsa -b 2048 -f `"$SSHKeyOutFile`" -q -N '`"`"' -C `"$NewSSHKeyPurpose`""
    }
    else {
        $SSHKeyGenArgumentsString = "-t rsa -b 2048 -f `"$SSHKeyOutFile`" -q -N `"$NewSSHKeyPwd`""
        $SSHKeyGenArgumentsNoPwdString = "-t rsa -b 2048 -f `"$SSHKeyOutFile`" -q -N '`"`"'"
    }
    
    ##### END Variable/Parameter Transforms and PreRun Prep #####


    ##### BEGIN Main Body #####

    # Create new public/private keypair
    
    $ProcessInfo = New-Object System.Diagnostics.ProcessStartInfo
    $ProcessInfo.WorkingDirectory = $OpenSSHWinPath
    $ProcessInfo.FileName = $(Get-Command ssh-keygen.exe).Source
    $ProcessInfo.RedirectStandardError = $true
    $ProcessInfo.RedirectStandardOutput = $true
    #$ProcessInfo.StandardOutputEncoding = [System.Text.Encoding]::Unicode
    #$ProcessInfo.StandardErrorEncoding = [System.Text.Encoding]::Unicode
    $ProcessInfo.UseShellExecute = $false
    if ($NewSSHKeyPwd) {
        $ProcessInfo.Arguments = $SSHKeyGenArgumentsString
    }
    else {
        $ProcessInfo.Arguments = $SSHKeyGenArgumentsNoPwdString
    }
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

    $PubPrivKeyPairFiles = Get-ChildItem -Path "$HOME\.ssh" | Where-Object {$_.Name -match "$NewSSHKeyName"}
    $PubKey = $PubPrivKeyPairFiles | Where-Object {$_.Extension -eq ".pub"}
    $PrivKey = $PubPrivKeyPairFiles | Where-Object {$_.Extension -ne ".pub"}

    if (!$PubKey -or !$PrivKey) {
        Write-Error "The New SSH Key Pair was NOT created! Check the output of the ssh-keygen.exe command below! Halting!"
        Write-Output "##### BEGIN ssh-keygen Console Output From PSAwaitSession #####"
        Write-Output $SSHKeyGenConsoleOutput
        Write-Output "##### END ssh-keygen Console Output From PSAwaitSession #####"
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
        $SSHAddProcessInfo.FileName = $(Get-Command ssh-add.exe).Source
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


<#
    .SYNOPSIS
        This function modifies sshd_config on the local host and sets the default shell
        that Remote Users will use when they ssh to the local host.

    .DESCRIPTION
        See .SYNOPSIS

    .NOTES

    .PARAMETER DefaultShell
        This parameter is MANDATORY.

        This parameter takes a string that must be one of two values: "powershell","pwsh"

        If set to "powershell", when a Remote User connects to the local host via ssh, they will enter a
        Windows PowerShell 5.1 shell.

        If set to "pwsh", when a Remote User connects to the local host via ssh, the will enter a
        PowerShell Core 6 shell.

    .PARAMETER SubsystemSymlinksDirectory
        This parameter is OPTIONAL.

        This parameter takes a string that represents the path to a directory that will contain symlinked directories
        to the directories containing powershell.exe and/or pwsh.exe

    .PARAMETER UseForceCommand
        This parameter is OPTIONAL.

        This parameter is a switch. If used, the 'ForceCommand' option will be added to sshd_config.

    .EXAMPLE
        # Open an elevated PowerShell Session, import the module, and -

        PS C:\Users\zeroadmin> Set-DefaultShell -DefaultShell powershell
        
#>
function Set-DefaultShell {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [ValidateSet("powershell","pwsh")]
        [string]$DefaultShell,

        [Parameter(Mandatory=$False)]
        [string]$SubsystemSymlinksDirectory = "C:\sshSymlinks",

        [Parameter(Mandatory=$False)]
        [switch]$UseForceCommand
    )

    if (Test-Path "$env:ProgramData\ssh\sshd_config") {
        $sshdConfigPath = "$env:ProgramData\ssh\sshd_config"
    }
    elseif (Test-Path "$env:ProgramFiles\OpenSSH-Win64\sshd_config") {
        $sshdConfigPath = "$env:ProgramFiles\OpenSSH-Win64\sshd_config"
    }
    else {
        Write-Error "Unable to find file 'sshd_config'! Halting!"
        $global:FunctionResult = "1"
        return
    }

    # Setup the Subsystem Symlinks directory
    if ($SubsystemSymlinksDirectory -match "[\s]") {
        Write-Error "The -SubsystemSymlinksDirectory path must not contain any spaces! Halting!"
        $global:FunctionResult = "1"
        return
    }
    if (Test-Path $SubsystemSymlinksDirectory) {
        try {
            Remove-Item $SubsystemSymlinksDirectory -Recurse -Force
        }
        catch {
            try {
                Get-ChildItem -Path $SubsystemSymlinksDirectory -Recurse | foreach {$_.Delete()}
                Remove-Item $SubsystemSymlinksDirectory -Recurse -Force
            }
            catch {
                Write-Error $_
                $global:FunctionResult = "1"
                return
            }
        }
    }
    $null = New-Item -ItemType Directory -Path $SubsystemSymlinksDirectory -Force
    $PowerShellSymlinkRoot = "$SubsystemSymlinksDirectory\powershellRoot"
    $PwshSymlinkRoot = "$SubsystemSymlinksDirectory\pwshRoot"
    #$null = New-Item -ItemType Directory -Path $PowerShellSymlinkRoot -Force
    #$null = New-Item -ItemType Directory -Path $PwshSymlinkRoot -Force


    if ($DefaultShell -eq "powershell") {
        $WindowsPowerShellPath = $(Get-Command powershell).Source
        #$WindowsPowerShellPathWithForwardSlashes = $WindowsPowerShellPath -replace "\\","/"

        # Create the powershell.exe parent directory symlink
        $null = New-Item -ItemType SymbolicLink -Path $PowerShellSymlinkRoot -Target $($(Get-Command powershell).Source | Split-Path -Parent)

        $ForceCommandOptionLine = "ForceCommand powershell.exe -NoProfile"
    }
    if ($DefaultShell -eq "pwsh") {
        # Search for pwsh.exe where we expect it to be
        [array]$PotentialPwshExes = @(Get-ChildItem "$env:ProgramFiles\Powershell" -Recurse -File -Filter "*pwsh.exe")
        if (![bool]$(Get-Command pwsh -ErrorAction SilentlyContinue)) {
            try {
                $InstallPwshSplatParams = @{
                    ProgramName                 = "powershell-core"
                    CommandName                 = "pwsh.exe"
                    ExpectedInstallLocation     = "C:\Program Files\PowerShell"
                    ErrorAction                 = "SilentlyContinue"
                    ErrorVariable               = "InstallPwshErrors"
                }
                $InstallPwshResult = Install-Program @InstallPwshSplatParams

                if (![bool]$(Get-Command pwsh -ErrorAction SilentlyContinue)) {throw}
            }
            catch {
                Write-Error $($InstallPwshErrors | Out-String)
                $global:FunctionResult = "1"
                return
            }

            [array]$PotentialPwshExes = @(Get-ChildItem "$env:ProgramFiles\Powershell" -Recurse -File -Filter "*pwsh.exe")
        }
        if (![bool]$(Get-Command pwsh -ErrorAction SilentlyContinue)) {
            Write-Error "Unable to find pwsh.exe! Please check your `$env:Path! Halting!"
            $global:FunctionResult = "1"
            return
        }

        $LatestLocallyAvailablePwsh = [array]$($PotentialPwshExes.VersionInfo | Sort-Object -Property ProductVersion)[-1].FileName
        $LatestPwshParentDir = [System.IO.Path]::GetDirectoryName($LatestLocallyAvailablePwsh)
        #$PowerShellCorePathWithForwardSlashes = $LatestLocallyAvailablePwsh -replace "\\","/"
        #$PowerShellCorePathWithForwardSlashes = $PowerShellCorePathWithForwardSlashes -replace [regex]::Escape("C:/Program Files"),'%PROGRAMFILES%'

        # Create the pwsh.exe parent directory symlink
        $null = New-Item -ItemType SymbolicLink -Path $PwshSymlinkRoot -Target $LatestPwshParentDir

        # Update $env:Path to include pwsh
        if ($($env:Path -split ";") -notcontains $LatestPwshParentDir) {
            # TODO: Clean out older pwsh $env:Path entries if they exist...
            $env:Path = "$LatestPwshParentDir;$env:Path"
        }
        
        # Update SYSTEM Path to include pwsh
        $CurrentSystemPath = $(Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment' -Name PATH).Path
        $CurrentSystemPathArray = $CurrentSystemPath -split ";"
        if ($CurrentSystemPathArray -notcontains $LatestPwshParentDir) {
            $UpdatedSystemPath = "$LatestPwshParentDir;$CurrentSystemPath"
            Set-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment" -Name PATH -Value $UpdatedSystemPath
        }

        $ForceCommandOptionLine = "ForceCommand pwsh.exe -NoProfile"
    }

    if (!$UseForceCommand) {
        # Set DefaultShell in Registry
        $OpenSSHRegistryPath = "HKLM:\SOFTWARE\OpenSSH"
        if ($(Get-Item -Path $OpenSSHRegistryPath).Property -contains "DefaultShell") {
            Remove-ItemProperty -Path $OpenSSHRegistryPath -Name DefaultShell -Force
        }
        if ($DefaultShell -eq "pwsh") {
            New-ItemProperty -Path $OpenSSHRegistryPath -Name DefaultShell -Value "$PwshSymlinkRoot\pwsh.exe" -PropertyType String -Force
        }
        else {
            New-ItemProperty -Path $OpenSSHRegistryPath -Name DefaultShell -Value "$PowerShellSymlinkRoot\powershell.exe" -PropertyType String -Force
        }
    }

    # Subsystem instructions: https://github.com/PowerShell/PowerShell/tree/master/demos/SSHRemoting#setup-on-windows-machine
    [System.Collections.ArrayList]$sshdContent = Get-Content $sshdConfigPath
    $PowerShellSymlinkRootRegex = [regex]::Escape($PowerShellSymlinkRoot)
    $PwshSymlinkRootRegex = [regex]::Escape($PwshSymlinkRoot)
    
    if (![bool]$($sshdContent -match "Subsystem[\s]+powershell")) {
        $InsertAfterThisLine = $sshdContent -match "sftp"
        $InsertOnThisLine = $sshdContent.IndexOf($InsertAfterThisLine)+1
        if ($DefaultShell -eq "pwsh") {
            $sshdContent.Insert($InsertOnThisLine, "Subsystem powershell $PwshSymlinkRoot\pwsh.exe -sshs -NoLogo -NoProfile")
        }
        else {
            $sshdContent.Insert($InsertOnThisLine, "Subsystem powershell $PowerShellSymlinkRoot\powershell.exe -sshs -NoLogo -NoProfile")
        }
    }
    elseif (![bool]$($sshdContent -match "Subsystem[\s]+powershell[\s]+$PowerShellSymlinkRootRegex") -and $DefaultShell -eq "powershell") {
        $LineToReplace = $sshdContent -match "Subsystem[\s]+powershell"
        $sshdContent = $sshdContent -replace [regex]::Escape($LineToReplace),"Subsystem powershell $PowerShellSymlinkRoot\powershell.exe -sshs -NoLogo -NoProfile"
    }
    elseif (![bool]$($sshdContent -match "Subsystem[\s]+powershell[\s]+$PwshSymlinkRootRegex") -and $DefaultShell -eq "pwsh") {
        $LineToReplace = $sshdContent -match "Subsystem[\s]+powershell"
        $sshdContent = $sshdContent -replace [regex]::Escape($LineToReplace),"Subsystem powershell $PwshSymlinkRoot\pwsh.exe -sshs -NoLogo -NoProfile"
    }

    Set-Content -Value $sshdContent -Path $sshdConfigPath

    # Determine if sshd_config already has the 'ForceCommand' option active
    $ExistingForceCommandOption = $sshdContent -match "ForceCommand" | Where-Object {$_ -notmatch "#"}

    # Determine if sshd_config already has 'Match User' option active
    $ExistingMatchUserOption = $sshdContent -match "Match User" | Where-Object {$_ -notmatch "#"}
    
    if (!$ExistingForceCommandOption) {
        if ($UseForceCommand) {
            # If sshd_config already has the 'Match User' option available, don't touch it, else add it with ForceCommand
            try {
                if (!$ExistingMatchUserOption) {
                    Add-Content -Value "Match User *`n$ForceCommandOptionLine" -Path $sshdConfigPath
                }
                else {
                    Add-Content -Value "$ForceCommandOptionLine" -Path $sshdConfigPath
                }

                try {
                    Restart-Service sshd -ErrorAction Stop
                    Write-Host "Successfully changed sshd default shell to '$DefaultShell'" -ForegroundColor Green
                }
                catch {
                    Write-Error $_
                    $global:FunctionResult = "1"
                    return
                }
            }
            catch {
                Write-Error $_
                $global:FunctionResult = "1"
                return
            }
        }
        elseif (!$ExistingMatchUserOption) {
            Add-Content -Value "Match User *" -Path $sshdConfigPath

            try {
                Restart-Service sshd -ErrorAction Stop
                Write-Host "Successfully changed sshd default shell to '$DefaultShell'" -ForegroundColor Green
            }
            catch {
                Write-Error $_
                $global:FunctionResult = "1"
                return
            }
        }
    }
    else {
        if ($UseForceCommand) {
            if ($ExistingForceCommandOption -ne $ForceCommandOptionLine) {
                if (!$ExistingMatchUserOption) {
                    $UpdatedSSHDConfig = $sshdContent -replace [regex]::Escape($ExistingForceCommandOption),"Match User *`n$ForceCommandOptionLine"
                }
                else {
                    $UpdatedSSHDConfig = $sshdContent -replace [regex]::Escape($ExistingForceCommandOption),"$ForceCommandOptionLine"
                }

                try {
                    Set-Content -Value $UpdatedSSHDConfig -Path $sshdConfigPath
                    Restart-Service sshd -ErrorAction Stop
                    Write-Host "Successfully changed sshd default shell to '$DefaultShell'" -ForegroundColor Green
                }
                catch {
                    Write-Error $_
                    $global:FunctionResult = "1"
                    return
                }
            }
            else {
                Write-Warning "The specified 'ForceCommand' option is already active in the the sshd_config file. No changes made."
            }
        }
        elseif (!$ExistingMatchUserOption) {
            $UpdatedSSHDConfig = $sshdContent -replace [regex]::Escape($ExistingForceCommandOption),"Match User *"

            try {
                Set-Content -Value $UpdatedSSHDConfig -Path $sshdConfigPath
                Restart-Service sshd -ErrorAction Stop
                Write-Host "Successfully changed sshd default shell to '$DefaultShell'" -ForegroundColor Green
            }
            catch {
                Write-Error $_
                $global:FunctionResult = "1"
                return
            }
        }
    }
}


<#
    .SYNOPSIS
        This function uninstalls OpenSSH-Win64 binaries, removes ssh-agent and sshd services (if they exist),
        and deletes (recursively) the directories "C:\Program Files\OpenSSH-Win64" and "C:\ProgramData\ssh"
        (if they exist).

        Outputs an array of strings describing the actions taken. Possible string values are:
        "sshdUninstalled","sshAgentUninstalled","sshBinariesUninstalled"

    .DESCRIPTION
        See .SYNOPSIS

    .NOTES

    .PARAMETER KeepSSHAgent
        This parameter is OPTIONAL.

        This parameter is a switch. If used, ONLY the SSHD server (i.e. sshd service) is uninstalled. Nothing
        else is touched.

    .EXAMPLE
        # Open an elevated PowerShell Session, import the module, and -

        PS C:\Users\zeroadmin> Uninstall-WinSSH
        
#>
function Uninstall-WinSSH {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$False)]
        [switch]$KeepSSHAgent
    )

    if (!$(GetElevation)) {
        Write-Error "You must run PowerShell as Administrator before using this function! Halting!"
        $global:FunctionResult = "1"
        return
    }

    #region >> Prep
    
    $OpenSSHProgramFilesPath = "C:\Program Files\OpenSSH-Win64"
    $OpenSSHProgramDataPath = "C:\ProgramData\ssh"
    <#
    $UninstallLogDir = "$HOME\OpenSSHUninstallLogs"
    $etwman = "$UninstallLogDir\openssh-events.man"
    if (!$(Test-Path $UninstallLogDir)) {
        $null = New-Item -ItemType Directory -Path $UninstallLogDir
    }
    #>

    #endregion >> Prep


    #region >> Main Body
    [System.Collections.ArrayList]$Output = @()

    if (Get-Service sshd -ErrorAction SilentlyContinue)  {
        try {
            Stop-Service sshd
            sc.exe delete sshd 1>$null
            Write-Host -ForegroundColor Green "sshd successfully uninstalled"
            $null = $Output.Add("sshdUninstalled")

            # unregister etw provider
            <#
            if (Test-Path $etwman) {
                wevtutil um `"$etwman`"
            }
            #>
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            return
        }
    }
    else {
        Write-Host -ForegroundColor Yellow "sshd service is not installed"
    }

    if (!$KeepSSHAgent) {
        if (Get-Service ssh-agent -ErrorAction SilentlyContinue) {
            try {
                Stop-Service ssh-agent
                sc.exe delete ssh-agent 1>$null
                Write-Host -ForegroundColor Green "ssh-agent successfully uninstalled"
                $null = $Output.Add("sshAgentUninstalled")
            }
            catch {
                Write-Error $_
                $global:FunctionResult = "1"
                return
            }
        }
        else {
            Write-Host -ForegroundColor Yellow "ssh-agent service is not installed"
        }

        if (!$(Get-Module ProgramManagement)) {
            try {
                Import-Module ProgramManagement -ErrorAction Stop
            }
            catch {
                Write-Error $_
                $global:FunctionResult = "1"
                return
            }
        }
    
        try {
            $UninstallOpenSSHResult = Uninstall-Program -ProgramName openssh -ErrorAction Stop
            $null = $Output.Add("sshBinariesUninstalled")
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            return
        }
    
        if (Test-Path $OpenSSHProgramFilesPath) {
            try {
                Remove-Item $OpenSSHProgramFilesPath -Recurse -Force
            }
            catch {
                Write-Error $_
                $global:FunctionResult = "1"
                return
            }
        }
        if (Test-Path $OpenSSHProgramDataPath) {
            try {
                Remove-Item $OpenSSHProgramDataPath -Recurse -Force
            }
            catch {
                Write-Error $_
                $global:FunctionResult = "1"
                return
            }
        }
    }

    [System.Collections.ArrayList][array]$Output

    #endregion >> Main Body
}


<#
    .SYNOPSIS
        This function is meant to determine the following:
            - Whether or not the specified file is, in fact, an SSH Private Key
            - If the SSH Private Key File is password protected
        
        In order to test if we have a valid Private Key, and if that Private Key
        is password protected, we try and generate a Public Key from it using ssh-keygen.
        Depending on the output of ssh-keygen, we can make a determination.

    .DESCRIPTION
        See .SYNOPSIS

    .NOTES

    .PARAMETER PathToPrivateKeyFile
        This parameter is MANDATORY.

        This parameter takes a string that represents a full path to the file that we believe is
        a valid SSH Private Key that we want to test.

    .EXAMPLE
        # Open an elevated PowerShell Session, import the module, and -

        PS C:\Users\zeroadmin> Validate-SSHPrivateKey -PathToPrivateKeyFile "$HOME\.ssh\random"
        
#>
function Validate-SSHPrivateKey {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [string]$PathToPrivateKeyFile
    )

    # Make sure we have access to ssh binaries
    if (![bool]$(Get-Command ssh-keygen -ErrorAction SilentlyContinue)) {
        Write-Error "Unable to find 'ssh-keygen.exe'! Halting!"
        $global:FunctionResult = "1"
        return
    }

    # Make sure the path exists
    if (!$(Test-Path $PathToPrivateKeyFile)) {
        Write-Error "Unable to find the path '$PathToPrivateKeyFile'! Halting!"
        $global:FunctionResult = "1"
        return
    }

    $SSHKeyGenParentDir = $(Get-Command ssh-keygen).Source | Split-Path -Parent
    $SSHKeyGenArguments = "-y -f `"$PathToPrivateKeyFile`""

    $ProcessInfo = New-Object System.Diagnostics.ProcessStartInfo
    $ProcessInfo.WorkingDirectory = $SSHKeyGenParentDir
    $ProcessInfo.FileName = $(Get-Command ssh-keygen).Source
    $ProcessInfo.RedirectStandardError = $true
    $ProcessInfo.RedirectStandardOutput = $true
    #$ProcessInfo.StandardOutputEncoding = [System.Text.Encoding]::Unicode
    #$ProcessInfo.StandardErrorEncoding = [System.Text.Encoding]::Unicode
    $ProcessInfo.UseShellExecute = $false
    $ProcessInfo.Arguments = $SSHKeyGenArguments
    $Process = New-Object System.Diagnostics.Process
    $Process.StartInfo = $ProcessInfo
    $Process.Start() | Out-Null
    # Below $FinishedInAlottedTime returns boolean true/false
    $FinishedInAlottedTime = $Process.WaitForExit(5000)
    if (!$FinishedInAlottedTime) {
        $Process.Kill()
        $ProcessKilled = $True
    }
    $stdout = $Process.StandardOutput.ReadToEnd()
    $stderr = $Process.StandardError.ReadToEnd()
    $SSHKeyGenOutput = $stdout + $stderr

    if ($SSHKeyGenOutput -match "invalid format") {
        $ValidSSHPrivateKeyFormat = $False
        $PasswordProtected = $False
    }
    if ($SSHKeyGenOutput -match "ssh-rsa AA") {
        $ValidSSHPrivateKeyFormat = $True
        $PasswordProtected = $False
    }
    if ($SSHKeyGenOutput -match "passphrase|pass phrase" -or $($SSHKeyGenOutput -eq $null -and $ProcessKilled)) {
        $ValidSSHPrivateKeyFormat = $True
        $PasswordProtected = $True
    }

    [pscustomobject]@{
        ValidSSHPrivateKeyFormat        = $ValidSSHPrivateKeyFormat
        PasswordProtected               = $PasswordProtected
    }
}



if ($PSVersionTable.Platform -eq "Win32NT" -and $PSVersionTable.PSEdition -eq "Core") {
    if (![bool]$(Get-Module -ListAvailable WindowsCompatibility)) {
        try {
            Install-Module WindowsCompatibility -ErrorAction Stop
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            return
        }
    }
    if (![bool]$(Get-Module WindowsCompatibility)) {
        try {
            Import-Module WindowsCompatibility -ErrorAction Stop
        }
        catch {
            Write-Error $_
            Write-Warning "The $ThisModule Module was NOT loaded successfully! Please run:`n    Remove-Module $ThisModule"
            $global:FunctionResult = "1"
            return
        }
    }
}

[System.Collections.ArrayList]$script:FunctionsForSBUse = @(
    ${Function:AddWinRMTrustLocalHost}.Ast.Extent.Text
    ${Function:ConfigureGlobalKnownHosts}.Ast.Extent.Text
    ${Function:GetComputerObjectsInLDAP}.Ast.Extent.Text
    ${Function:GetCurrentUser}.Ast.Extent.Text
    ${Function:GetDomainController}.Ast.Extent.Text
    ${Function:GetElevation}.Ast.Extent.Text
    ${Function:GetGroupObjectsInLDAP}.Ast.Extent.Text
    ${Function:GetModuleDependencies}.Ast.Extent.Text
    ${Function:GetNativePath}.Ast.Extent.Text
    ${Function:GetUserObjectsInLDAP}.Ast.Extent.Text
    ${Function:InvokeModuleDependencies}.Ast.Extent.Text
    ${Function:InvokePSCompatibility}.Ast.Extent.Text
    ${Function:ManualPSGalleryModuleInstall}.Ast.Extent.Text
    ${Function:NewUniqueString}.Ast.Extent.Text
    ${Function:PauseForWarning}.Ast.Extent.Text
    ${Function:ResolveHost}.Ast.Extent.Text
    ${Function:TestIsValidIPAddress}.Ast.Extent.Text
    ${Function:TestLDAP}.Ast.Extent.Text
    ${Function:TestPort}.Ast.Extent.Text
    ${Function:UnzipFile}.Ast.Extent.Text
    ${Function:Add-PublicKeyToRemoteHost}.Ast.Extent.Text
    ${Function:Check-Cert}.Ast.Extent.Text
    ${Function:Extract-SSHPrivateKeysFromRegistry}.Ast.Extent.Text
    ${Function:Fix-SSHPermissions}.Ast.Extent.Text
    ${Function:Generate-AuthorizedPrincipalsFile}.Ast.Extent.Text
    ${Function:Generate-SSHUserDirFileInfo}.Ast.Extent.Text
    ${Function:Get-PublicKeyAuthInstructions}.Ast.Extent.Text
    ${Function:Get-SSHClientAuthSanity}.Ast.Extent.Text
    ${Function:Get-SSHFileInfo}.Ast.Extent.Text
    ${Function:Install-SSHAgentService}.Ast.Extent.Text
    ${Function:Install-WinSSH}.Ast.Extent.Text
    ${Function:New-SSHDServer}.Ast.Extent.Text
    ${Function:New-SSHKey}.Ast.Extent.Text
    ${Function:Set-DefaultShell}.Ast.Extent.Text
    ${Function:Uninstall-WinSSH}.Ast.Extent.Text
    ${Function:Validate-SSHPrivateKey}.Ast.Extent.Text
)

# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUGtVCCeYSX0k4N6rkmiSxXzYD
# 4XKgggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFHk25PThhDMPrYZX
# u2l9IwdEEIm3MA0GCSqGSIb3DQEBAQUABIIBAIoO157EvV42Psq2qAeE3tvLlJsS
# t2ZorvgrNsPcsT0odwf9VfBcuUYJvXykWBhP3+KYpRzhs3xzZE4AytJCSXhARUJz
# MP/ULRal1g/J/w1VxDUyqiyUJrZkgeYm7JmGBRxwaIx+sbhqJBW98iA4emxWCD1+
# rz2qWM0WwQPyLlqM83aa5RhSbYsiqQ7e5CK355/QsWoPn3yUc5KqoRYIUtXLhp/x
# 2l2mQuYmvFVdDz8K88kUuqHRkNLCbgb0FlyrMVaXftMxyMt+q2EEkAJBupK0KCKW
# BMucr/j4O5kc6PIbg2cyqPUtToOmZkuYAI3mhc1ufCYsXiD/eAMKJP8P4XY=
# SIG # End signature block
