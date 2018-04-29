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