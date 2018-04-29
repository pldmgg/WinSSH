[Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls"

# This function is used to determine the most efficient ssh.exe command that should work
# on the Remote Host (assuming the sshd server on the remote host is configured properly)
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
                        "as the Public Key (i.e. $KeyFileParentDirectory). The Private Key IS loaded in the ssh-agent, "
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

function Get-LDAPCert {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$True)]
        [string]$LDAPServerHostNameOrIP,

        [Parameter(Mandatory=$True)]
        [ValidateSet(389,636,3268,3269)]
        [int]$Port,

        [Parameter(Mandatory=$False)]
        [switch]$UseOpenSSL
    )

    ##### BEGIN Pre-Run Check #####
    #region >> Pre-Run Check

    try {
        $LDAPServerNetworkInfo = ResolveHost -HostNameOrIP $LDAPServerHostNameOrIP
        if (!$LDAPServerNetworkInfo) {throw "Unable to resolve $LDAPServerHostNameOrIP! Halting!"}
    }
    catch {
        Write-Error $_
        $global:FunctionResult = "1"
        return
    }

    #endregion >> Pre-Run Check
    ##### END Pre-Run Check #####


    ##### BEGIN Main Body #####
    #region >> Main Body

    if ($UseOpenSSL) {
        # Check is openssl.exe is already available
        if ([bool]$(Get-Command openssl -ErrorAction SilentlyContinue)) {
            # Check to make sure the version is at least 1.1.0
            $OpenSSLExeInfo = Get-Item $(Get-Command openssl).Source
            $OpenSSLExeVersion = [version]$($OpenSSLExeInfo.VersionInfo.ProductVersion -split '-')[0]
        }

        # We need at least vertion 1.1.0 of OpenSSL
        if ($OpenSSLExeVersion.Major -lt 1 -or 
        $($OpenSSLExeVersion.Major -eq 1 -and $OpenSSLExeVersion.Minor -lt 1)
        ) {
            [Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls"
            $OpenSSLWinBinariesUrl = "http://wiki.overbyte.eu/wiki/index.php/ICS_Download"
            $IWRResult = Invoke-WebRequest -Uri $OpenSSLWinBinariesUrl
            $LatestOpenSSLWinBinaryLinkObj = $($IWRResult.Links | Where-Object {$_.innerText -match "OpenSSL Binaries" -and $_.href -match "\.zip"})[0]
            $LatestOpenSSLWinBinaryUrl = $LatestOpenSSLWinBinaryLinkObj.href
            $OutputFileName = $($LatestOpenSSLWinBinaryUrl -split '/')[-1]
            $OutputFilePath = "$HOME\Downloads\$OutputFileName"
            Invoke-WebRequest -Uri $LatestOpenSSLWinBinaryUrl -OutFile $OutputFilePath

            if (!$(Test-Path "$HOME\Downloads\$OutputFileName")) {
                Write-Error "Problem downloading the latest OpenSSL Windows Binary from $LatestOpenSSLWinBinaryUrl ! Halting!"
                $global:FunctionResult = "1"
                return
            }

            $OutputFileItem = Get-Item $OutputFilePath
            $ExpansionDirectory = $OutputFileItem.Directory.FullName + "\" + $OutputFileItem.BaseName
            if (!$(Test-Path $ExpansionDirectory)) {
                $null = New-Item -ItemType Directory -Path $ExpansionDirectory -Force
            }
            else {
                Remove-Item "$ExpansionDirectory\*" -Recurse -Force
            }

            $null = Expand-Archive -Path "$HOME\Downloads\$OutputFileName" -DestinationPath $ExpansionDirectory -Force

            # Add $ExpansionDirectory to $env:Path
            $CurrentEnvPathArray = $env:Path -split ";"
            if ($CurrentEnvPathArray -notcontains $ExpansionDirectory) {
                # Place $ExpansionDirectory at start so latest openssl.exe get priority
                $env:Path = "$ExpansionDirectory;$env:Path"
            }
        }

        if (![bool]$(Get-Command openssl -ErrorAction SilentlyContinue)) {
            Write-Error "Problem setting openssl.exe to `$env:Path! Halting!"
            $global:FunctionResult = "1"
            return
        }
    }

    if ($Port -eq 389 -or $Port -eq 3268) {
        if (!$UseOpenSSL) {
            Write-Error "Unable to get LDAP Certificate on port $Port using StartTLS without openssl.exe! Try the -UseOpenSSL switch. Halting!"
            $global:FunctionResult = "1"
            return
        }

        $ProcessInfo = New-Object System.Diagnostics.ProcessStartInfo
        #$ProcessInfo.WorkingDirectory = $BinaryPath | Split-Path -Parent
        $ProcessInfo.FileName = $(Get-Command openssl).Source
        $ProcessInfo.RedirectStandardError = $true
        $ProcessInfo.RedirectStandardOutput = $true
        #$ProcessInfo.StandardOutputEncoding = [System.Text.Encoding]::Unicode
        #$ProcessInfo.StandardErrorEncoding = [System.Text.Encoding]::Unicode
        $ProcessInfo.UseShellExecute = $false
        $ProcessInfo.Arguments = "s_client -connect $($LDAPServerNetworkInfo.FQDN):$Port -starttls ldap -showcerts"
        $Process = New-Object System.Diagnostics.Process
        $Process.StartInfo = $ProcessInfo
        $Process.Start() | Out-Null
        # Sometimes openssl.exe hangs, so, we'll give it 5 seconds before killing
        # Below $FinishedInAlottedTime returns boolean true/false
        $FinishedInAlottedTime = $Process.WaitForExit(5000)
        if (!$FinishedInAlottedTime) {
            $Process.Kill()
        }
        $stdout = $Process.StandardOutput.ReadToEnd()
        $stderr = $Process.StandardError.ReadToEnd()
        $OpenSSLResult = $stdout + $stderr

        # Parse the output of openssl
        $OpenSSLResultLineBreaks = $OpenSSLResult -split "`n"
        $IndexOfBeginCert = $OpenSSLResultLineBreaks.IndexOf($($OpenSSLResultLineBreaks -match "BEGIN CERTIFICATE"))
        $IndexOfEndCert = $OpenSSLResultLineBreaks.IndexOf($($OpenSSLResultLineBreaks -match "End CERTIFICATE"))

        if ($IndexOfBeginCert -eq "-1" -or $IndexOfEndCert -eq "-1") {
            Write-Error "Unable to find Certificate in openssl output! Halting!"
            $global:FunctionResult = "1"
            return
        }
        
        $PublicCertInPemFormat = $OpenSSLResultLineBreaks[$IndexOfBeginCert..$IndexOfEndCert]

        # Get $X509Cert2Obj
        $PemString = $($PublicCertInPemFormat | Where-Object {$_ -notmatch "CERTIFICATE"}) -join "`n"
        $byteArray = [System.Convert]::FromBase64String($PemString)
        $X509Cert2Obj = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($byteArray)
    }

    if ($Port -eq 636 -or $Port -eq 3269) {
        if ($UseOpenSSL) {
            $ProcessInfo = New-Object System.Diagnostics.ProcessStartInfo
            #$ProcessInfo.WorkingDirectory = $BinaryPath | Split-Path -Parent
            $ProcessInfo.FileName = $(Get-Command openssl).Source
            $ProcessInfo.RedirectStandardError = $true
            $ProcessInfo.RedirectStandardOutput = $true
            #$ProcessInfo.StandardOutputEncoding = [System.Text.Encoding]::Unicode
            #$ProcessInfo.StandardErrorEncoding = [System.Text.Encoding]::Unicode
            $ProcessInfo.UseShellExecute = $false
            $ProcessInfo.Arguments = "s_client -connect $($LDAPServerNetworkInfo.FQDN):$Port"
            $Process = New-Object System.Diagnostics.Process
            $Process.StartInfo = $ProcessInfo
            $Process.Start() | Out-Null
            # Sometimes openssl.exe hangs, so, we'll give it 5 seconds before killing
            # Below $FinishedInAlottedTime returns boolean true/false
            $FinishedInAlottedTime = $Process.WaitForExit(5000)
            if (!$FinishedInAlottedTime) {
                $Process.Kill()
            }
            $stdout = $Process.StandardOutput.ReadToEnd()
            $stderr = $Process.StandardError.ReadToEnd()
            $OpenSSLResult = $stdout + $stderr

            # Parse the output of openssl
            $OpenSSLResultLineBreaks = $OpenSSLResult -split "`n"
            $IndexOfBeginCert = $OpenSSLResultLineBreaks.IndexOf($($OpenSSLResultLineBreaks -match "BEGIN CERTIFICATE"))
            $IndexOfEndCert = $OpenSSLResultLineBreaks.IndexOf($($OpenSSLResultLineBreaks -match "End CERTIFICATE"))
            
            if ($IndexOfBeginCert -eq "-1" -or $IndexOfEndCert -eq "-1") {
                Write-Error "Unable to find Certificate in openssl output! Halting!"
                $global:FunctionResult = "1"
                return
            }

            $PublicCertInPemFormat = $OpenSSLResultLineBreaks[$IndexOfBeginCert..$IndexOfEndCert]

            # Get $X509Cert2Obj
            $PemString = $($PublicCertInPemFormat | Where-Object {$_ -notmatch "CERTIFICATE"}) -join "`n"
            $byteArray = [System.Convert]::FromBase64String($PemString)
            $X509Cert2Obj = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($byteArray)
        }
        else {
            $X509Cert2Obj = Check-Cert -IPAddress $LDAPServerNetworkInfo.IPAddressList[0] -Port $Port
            $PublicCertInPemFormatPrep = "-----BEGIN CERTIFICATE-----`n" + 
                [System.Convert]::ToBase64String($X509Cert2Obj.RawData, [System.Base64FormattingOptions]::InsertLineBreaks) + 
                "`n-----END CERTIFICATE-----"
            $PublicCertInPemFormat = $PublicCertInPemFormatPrep -split "`n"
        }
    }

    $CertificateChain = [System.Security.Cryptography.X509Certificates.X509Chain]::new()
    $null = $CertificateChain.Build($X509Cert2Obj)
    $RootCAX509Cert2Obj = $CertificateChain.ChainElements.Certificate | Where-Object {$_.Issuer -eq $_.Subject}
    $RootCAPublicCertInPemFormatPrep = "-----BEGIN CERTIFICATE-----`n" + 
        [System.Convert]::ToBase64String($RootCAX509Cert2Obj.RawData, [System.Base64FormattingOptions]::InsertLineBreaks) + 
        "`n-----END CERTIFICATE-----"
    $RootCACertInPemFormat = $RootCAPublicCertInPemFormatPrep -split "`n"

    $LDAPEndpointCertificateInfo = [pscustomobject]@{
        X509CertFormat      = $X509Cert2Obj
        PemFormat           = $PublicCertInPemFormat
    }

    $RootCACertificateInfo = [pscustomobject]@{
        X509CertFormat      = $RootCAX509Cert2Obj
        PemFormat           = $RootCACertInPemFormat
    }

    [pscustomobject]@{
        LDAPEndpointCertificateInfo  = $LDAPEndpointCertificateInfo
        CertificateChain             = $CertificateChain
        RootCACertificateInfo        = $RootCACertificateInfo
    }
    

    #endregion >> Pre-Run Check
    ##### END Main Body #####
}

function ConvertFrom-HCLToPrintF {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [string]$HCLAsString
    )



    $CharArray = [char[]]$($HCLAsString -join "") | foreach {
        if ($_ -eq '"') {
            '\' + $_
        }
        elseif ($_ -match "\n") {
            '\n'
        }
        else {
            $_
        }
    }

    "printf " + '"' + ($CharArray -join "") +'"'

}

function Get-VaultTokens {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [string]$VaultServerBaseUri, # Should be something like "http://192.168.2.12:8200/v1"

        [Parameter(Mandatory=$True)]
        [string]$VaultAuthToken # Should be something like 'myroot' or '434f37ca-89ae-9073-8783-087c268fd46f'
    )

    # Make sure $VaultServerBaseUri is a valid Url
    try {
        $UriObject = [uri]$VaultServerBaseUri
    }
    catch {
        Write-Error $_
        $global:FunctionResult = "1"
        return
    }
    if (![bool]$($UriObject.Scheme -match "http")) {
        Write-Error "'$VaultServerBaseUri' does not appear to be a URL! Halting!"
        $global:FunctionResult = "1"
        return
    }

    # If $VaultServerBaseUri ends in '/', remove it
    if ($VaultServerBaseUri[-1] -eq "/") {
        $VaultServerBaseUri = $VaultServerBaseUri.Substring(0,$VaultServerBaseUri.Length-1)
    }

    $QueryParameters = @{
        list = "true"
    }
    $HeadersParameters = @{
        "X-Vault-Token" = $VaultAuthToken
    }
    $IWRSplatParamsForSaltedTokenIds = @{
        Uri         = "$VaultServerBaseUri/sys/raw/sys/token/id"
        Headers     = $HeadersParameters
        Body        = $QueryParameters
        Method      = "Get"
    }
    $SaltedTokenIds = $($(Invoke-WebRequest @IWRSplatParamsForSaltedTokenIds).Content | ConvertFrom-Json).data.keys
    if (!$SaltedTokenIds) {
        Write-Error "There was a problem accesing the endpoint '$VaultServerBaseUri/sys/raw/sys/token/id'. Was 'raw_storage_endpoint = true' set in your Vault Server 'vault.hcl' configuration? Halting!"
        $global:FunctionResult = "1"
        return
    }

    [System.Collections.ArrayList]$AvailableTokensPSObjects = @()
    foreach ($SaltedId in $SaltedTokenIds) {
        $IWRSplatParamsForTokenObjects = @{
            Uri         = "$VaultServerBaseUri/sys/raw/sys/token/id/$SaltedId"
            Headers     = $HeadersParameters
            Method      = "Get"
        }

        $PSObject = $($(Invoke-WebRequest @IWRSplatParamsForTokenObjects).Content | ConvertFrom-Json).data.value | ConvertFrom-Json
        
        $null = $AvailableTokensPSObjects.Add($PSObject)
    }

    $AvailableTokensPSObjects
}

function Get-VaultTokenAccessors {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [string]$VaultServerBaseUri, # Should be something like "http://192.168.2.12:8200/v1"

        [Parameter(Mandatory=$True)]
        [string]$VaultAuthToken # Should be something like 'myroot' or '434f37ca-89ae-9073-8783-087c268fd46f'
    )

    # Make sure $VaultServerBaseUri is a valid Url
    try {
        $UriObject = [uri]$VaultServerBaseUri
    }
    catch {
        Write-Error $_
        $global:FunctionResult = "1"
        return
    }
    if (![bool]$($UriObject.Scheme -match "http")) {
        Write-Error "'$VaultServerBaseUri' does not appear to be a URL! Halting!"
        $global:FunctionResult = "1"
        return
    }

    $IWRSplatParams = @{
        Uri         = "$VaultServerBaseUri/auth/token/accessors"
        Headers     = @{"X-Vault-Token" = "$VaultAuthToken"}
        Body        = @{"list" = "true"}
        Method      = "Get"
    }
    
    $(Invoke-RestMethod @IWRSplatParams).data.keys
}

function Get-VaultAccessorLookup {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [string]$VaultServerBaseUri, # Should be something like "http://192.168.2.12:8200/v1"

        [Parameter(Mandatory=$True)]
        [string]$VaultAuthToken # Should be something like 'myroot' or '434f37ca-89ae-9073-8783-087c268fd46f'
    )

    # Make sure $VaultServerBaseUri is a valid Url
    try {
        $UriObject = [uri]$VaultServerBaseUri
    }
    catch {
        Write-Error $_
        $global:FunctionResult = "1"
        return
    }
    if (![bool]$($UriObject.Scheme -match "http")) {
        Write-Error "'$VaultServerBaseUri' does not appear to be a URL! Halting!"
        $global:FunctionResult = "1"
        return
    }

    try {
        $VaultAuthTokenAccessors = Get-VaultTokenAccessors -VaultBaseUri $VaultServerBaseUri -VaultAuthToken $VaultAuthToken -ErrorAction Stop
        if (!$VaultAuthTokenAccessors) {throw "The Get-VaultTokenAccessors function failed! Halting!"}
    }
    catch {
        Write-Error $_
        $global:FunctionResult = "1"
        return
    }
    
    foreach ($accessor in $VaultAuthTokenAccessors) {

        $jsonRequest = @"
{
    "accessor": "$accessor"
}
"@
        try {
            # Validate JSON
            $JsonRequestAsSingleLineString = $jsonRequest | ConvertFrom-Json -EA Stop | ConvertTo-Json -Compress -EA Stop
        }
        catch {
            Write-Error "There was a problem with the JSON! Halting!"
        }
        $IWRSplatParams = @{
            Uri         = "$VaultServerBaseUri/auth/token/lookup-accessor"
            Headers     = @{"X-Vault-Token" = "$VaultAuthToken"}
            Body        = $JsonRequestAsSingleLineString
            Method      = "Post"
        }
        
        $(Invoke-RestMethod @IWRSplatParams).data

    }
}

function Revoke-VaultToken {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [string]$VaultServerBaseUri, # Should be something like "http://192.168.2.12:8200/v1"

        [Parameter(Mandatory=$True)]
        [string]$VaultAuthToken, # Should be something like 'myroot' or '434f37ca-89ae-9073-8783-087c268fd46f'

        [Parameter(Mandatory=$True)]
        [string[]]$VaultUserToDelete # Should match .meta.username for the Accessor Lookup
    )

    # Make sure $VaultServerBaseUri is a valid Url
    try {
        $UriObject = [uri]$VaultServerBaseUri
    }
    catch {
        Write-Error $_
        $global:FunctionResult = "1"
        return
    }
    if (![bool]$($UriObject.Scheme -match "http")) {
        Write-Error "'$VaultServerBaseUri' does not appear to be a URL! Halting!"
        $global:FunctionResult = "1"
        return
    }

    # If $VaultServerBaseUri ends in '/', remove it
    if ($VaultServerBaseUri[-1] -eq "/") {
        $VaultServerBaseUri = $VaultServerBaseUri.Substring(0,$VaultServerBaseUri.Length-1)
    }

    try {
        $AccessorInfo = Get-VaultAccessorLookup -VaultServerBaseUri $VaultServerBaseUri -VaultAuthToken $ZeroAdminToken -ErrorAction Stop
        if (!$AccessorInfo) {throw "Ther Get-VaultAccessorLookup function failed! Halting!"}
    }
    catch {
        Write-Error $_
        $global:FunctionResult = "1"
        return
    }

    $AccessorToDelete = $($AccessorInfo | Where-Object {$_.meta.username -eq $VaultUserToDelete}).accessor
    if (!$AccessorToDelete) {
        Write-Error "Unable to find Accessor matching username $VaultUserToDelete! Halting!"
        $global:FunctionResult = "1"
        return
    }

    $jsonRequest = @"
{
    "accessor": "$AccessorToDelete"
}
"@
    try {
        # Validate JSON
        $JsonRequestAsSingleLineString = $jsonRequest | ConvertFrom-Json -EA Stop | ConvertTo-Json -Compress -EA Stop
    }
    catch {
        Write-Error "There was a problem with the JSON for deleting an accessor! Halting!"
    }
    $IWRSplatParams = @{
        Uri         = "$VaultServerBaseUri/auth/token/revoke-accessor"
        Headers     = @{"X-Vault-Token" = "$VaultAuthToken"}
        Body        = $JsonRequestAsSingleLineString
        Method      = "Post"
    }
    $RevokeTokenResult = Invoke-RestMethod @IWRSplatParams
    # NOTE: Revoking a Token does Not produce output, to $RevokeJSmithTokenResult should be $null

    # Make sure it no longer exists
    try {
        $AccessorInfo = Get-VaultAccessorLookup -VaultServerBaseUri $VaultServerBaseUri -VaultAuthToken $ZeroAdminToken -ErrorAction Stop
        if (!$AccessorInfo) {throw "Ther Get-VaultAccessorLookup function failed! Halting!"}
    }
    catch {
        Write-Error $_
        $global:FunctionResult = "1"
        return
    }

    $AccessorStillExists = $($AccessorInfo | Where-Object {$_.meta.username -eq $VaultUserToDelete}).accessor
    if ($AccessorStillExists) {
        Write-Error "There was a problem deleting the accessor $AccessorToDelete for user $VaultUserToDelete! Halting!"
        $global:FunctionResult = '1'
        return
    }

    "Success"
}

# IMPORTANT NOTE: The Generate-AuthorizedPrincipalsFile will only ADD users to the $sshdir/authorized_principals
# file (if they're not already in there). It WILL NOT delete or otherwise overwrite existing users in
# $sshdir/authorized_principals
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
                    $UserObjectsInLDAP = Get-UserObjectsInLDAP -ErrorAction Stop
                    if (!$UserObjectsInLDAP) {throw "Problem with Get-UserObjectsInLDAP function! Halting!"}
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
                    $UserObjectsInLDAP = Get-UserObjectsInLDAP -ErrorAction Stop
                    if (!$UserObjectsInLDAP) {throw "Problem with Get-UserObjectsInLDAP function! Halting!"}
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

function Get-UserObjectsInLDAP {
    [CmdletBinding()]
    Param()

    # Below $LDAPInfo Output is PSCustomObject with properties: DirectoryEntryInfo, LDAPBaseUri,
    # GlobalCatalogConfigured3268, GlobalCatalogConfiguredForSSL3269, Configured389, ConfiguredForSSL636,
    # PortsThatWork
    try {
        $DomainControllerInfo = GetDomainController -ErrorAction Stop
        $LDAPInfo = TestLDAP -ADServerHostNameOrIP $DomainControllerInfo.PrimaryDomainController -ErrorAction Stop
        if (!$DomainControllerInfo) {throw "Problem with GetDomainController function! Halting!"}
        if (!$LDAPInfo) {throw "Problem with TestLDAP function! Halting!"}
    }
    catch {
        Write-Error $_
        $global:FunctionResult = "1"
        return
    }

    if (!$LDAPInfo.PortsThatWork) {
        Write-Error "Unable to access LDAP on $($DomainControllerInfo.PrimaryDomainController)! Halting!"
        $global:FunctionResult = "1"
        return
    }

    if ($LDAPInfo.PortsThatWork -contains "389") {
        $LDAPUri = $LDAPInfo.LDAPBaseUri + ":389"
    }
    elseif ($LDAPInfo.PortsThatWork -contains "3268") {
        $LDAPUri = $LDAPInfo.LDAPBaseUri + ":3268"
    }
    elseif ($LDAPInfo.PortsThatWork -contains "636") {
        $LDAPUri = $LDAPInfo.LDAPBaseUri + ":636"
    }
    elseif ($LDAPInfo.PortsThatWork -contains "3269") {
        $LDAPUri = $LDAPInfo.LDAPBaseUri + ":3269"
    }

    $Connection = [ADSI]($LDAPUri)
    #$UsersLDAPContainer = $Connection.Children | Where-Object {$_.distinguishedName -match "Users"}
    #$UserObjectsInLDAP = $UsersLDAPContainer.Children | Where-Object {$_.objectClass -contains "user" -and $_.objectClass -notcontains "group"}
    $Searcher = New-Object System.DirectoryServices.DirectorySearcher
    $Searcher.SearchRoot = $Connection
    $Searcher.Filter = "(&(objectCategory=User))"
    $UserObjectsInLDAP = $Searcher.FindAll() | foreach {$_.GetDirectoryEntry()}

    $UserObjectsInLDAP
}

function Get-GroupObjectsInLDAP {
    [CmdletBinding()]
    Param()

    # Below $LDAPInfo Output is PSCustomObject with properties: DirectoryEntryInfo, LDAPBaseUri,
    # GlobalCatalogConfigured3268, GlobalCatalogConfiguredForSSL3269, Configured389, ConfiguredForSSL636,
    # PortsThatWork
    try {
        $DomainControllerInfo = GetDomainController -ErrorAction Stop
        $LDAPInfo = TestLDAP -ADServerHostNameOrIP $DomainControllerInfo.PrimaryDomainController -ErrorAction Stop
        if (!$DomainControllerInfo) {throw "Problem with GetDomainController function! Halting!"}
        if (!$LDAPInfo) {throw "Problem with TestLDAP function! Halting!"}
    }
    catch {
        Write-Error $_
        $global:FunctionResult = "1"
        return
    }

    if (!$LDAPInfo.PortsThatWork) {
        Write-Error "Unable to access LDAP on $($DomainControllerInfo.PrimaryDomainController)! Halting!"
        $global:FunctionResult = "1"
        return
    }

    if ($LDAPInfo.PortsThatWork -contains "389") {
        $LDAPUri = $LDAPInfo.LDAPBaseUri + ":389"
    }
    elseif ($LDAPInfo.PortsThatWork -contains "3268") {
        $LDAPUri = $LDAPInfo.LDAPBaseUri + ":3268"
    }
    elseif ($LDAPInfo.PortsThatWork -contains "636") {
        $LDAPUri = $LDAPInfo.LDAPBaseUri + ":636"
    }
    elseif ($LDAPInfo.PortsThatWork -contains "3269") {
        $LDAPUri = $LDAPInfo.LDAPBaseUri + ":3269"
    }

    $Connection = [ADSI]($LDAPUri)
    #$UsersLDAPContainer = $Connection.Children | Where-Object {$_.distinguishedName -match "Users"}
    #$UserObjectsInLDAP = $UsersLDAPContainer.Children | Where-Object {$_.objectClass -contains "user" -and $_.objectClass -notcontains "group"}
    $Searcher = New-Object System.DirectoryServices.DirectorySearcher
    $Searcher.SearchRoot = $Connection
    $Searcher.Filter = "(&(objectCategory=Group))"
    $GroupObjectsInLDAP = $Searcher.FindAll() | foreach {$_.GetDirectoryEntry()}

    $GroupObjectsInLDAP
}

function Configure-VaultServerForLDAPAuth {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$True)]
        [string]$VaultServerNetworkLocation, # Should be an IP Address of DNS-Resolvable HostName/FQDN

        [Parameter(Mandatory=$True)]
        [int]$VaultServerPort, # Typically 8200

        [Parameter(Mandatory=$False)]
        [switch]$EncryptNetworkTraffic = $True, # Impacts using http/https, Vault Config, Generating TLS Certificates

        [Parameter(Mandatory=$True)]
        [string]$VaultAuthToken, # Get this via manual step preceeding this function using Vault CmdLine - 'vault operator init' 

        [Parameter(Mandatory=$False)]
        [string]$VaultLogFileName = "vault_audit.log",

        [Parameter(Mandatory=$False)]
        [string]$VaultLogEndPointName = "default-audit",

        # Creates backup root token with username 'backupadmin',
        # Creates 'custom-root' policy applied to "VaultAdmins" group (all permissions)
        # Creates 'vaultusers' policy applied to "VaultUsers" group (all permissions except 'delete' and 'sudo')
        [Parameter(Mandatory=$False)]
        [switch]$PerformOptionalSteps,

        [Parameter(Mandatory=$True)]
        [string]$LDAPServerHostNameOrIP,

        [Parameter(Mandatory=$True)]
        [ValidateSet(389,636,3268,3269)]
        [int]$LDAPServicePort,

        # Should be a non-privileged LDAP/AD account whose sole purpose is allowing Vault to read the LDAP Database
        [Parameter(Mandatory=$True)]
        [pscredential]$LDAPBindCredentials,

        [Parameter(Mandatory=$True)]
        [string]$BindUserDN, # Should be a path to a User Account LDAP object, like cn=vault,ou=OrgUsers,dc=zero,dc=lab
        
        [Parameter(Mandatory=$True)]
        [string]$LDAPUserOUDN, # Something like ou=OrgUsers,dc=zero,dc=lab
    
        [Parameter(Mandatory=$True)]
        [string]$LDAPGroupOUDN, # Something like ou=Groups,dc=zero,dc=lab

        [Parameter(Mandatory=$False)]
        [ValidatePattern("^cn=VaultUsers")]
        [string]$LDAPVaultUsersSecurityGroupDN, # Something like cn=VaultUsers,ou=Groups,dc=zero,dc=lab

        [Parameter(Mandatory=$False)]
        [ValidatePattern("^cn=VaultAdmins")]
        [string]$LDAPVaultAdminsSecurityGroupDN # Something like cn=VaultAdmins,ou=Groups,dc=zero,dc=lab
    )

    #region >> Variable/Parameter Transforms and PreRun Prep

    [Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls"

    # Create $Ouput Hashtable so we can add to it as we go and return whatever was done in case of error
    $Output = [ordered]@{}

    if ($EncryptNetworkTraffic) {
        $VaultServerBaseUri = "https://$VaultServerNetworkLocation" + ":$VaultServerPort/v1"    
    }
    else {
        $VaultServerBaseUri = "http://$VaultServerNetworkLocation" + ":$VaultServerPort/v1"
    }

    if ($PerformOptionalSteps) {
        if (!$LDAPVaultUsersSecurityGroupDN -or !$LDAPVaultAdminsSecurityGroupDN) {
            Write-Error "When using the -PerformOptionalSteps switch, you must also supply values for -LDAPVaultUsersSecurityGroupDN and -LDAPVaultAdminsSecurityGroupDN! Halting!"
            $global:FunctionResult = "1"
            return
        }
    }

    # Make sure we can reach the LDAP Server
    try {
        $LDAPServerNetworkInfo = ResolveHost -HostNameOrIP $LDAPServerHostNameOrIP
        if (!$LDAPServerNetworkInfo) {throw "Unable to resolve $LDAPServerHostNameOrIP! Halting!"}
    }
    catch {
        Write-Error $_
        $global:FunctionResult = "1"
        return
    }

    # Make sure $LDAPBindCredentials work
    $CurrentlyLoadedAssemblies = [System.AppDomain]::CurrentDomain.GetAssemblies()

    if (![bool]$($CurrentlyLoadedAssemblies -match "System.DirectoryServices.AccountManagement")) {
        Add-Type -AssemblyName System.DirectoryServices.AccountManagement
    }
    $SimpleDomain = $LDAPServerNetworkInfo.Domain
    $SimpleDomainWLDAPPort = $SimpleDomain + ":$LDAPServicePort"
    [System.Collections.ArrayList]$DomainLDAPContainersPrep = @()
    foreach ($Section in $($SimpleDomain -split "\.")) {
        $null = $DomainLDAPContainersPrep.Add($Section)
    }
    $DomainLDAPContainers = $($DomainLDAPContainersPrep | foreach {"DC=$_"}) -join ", "

    try {
        $SimpleUserName = $($LDAPBindCredentials.UserName -split "\\")[1]
        $PasswordInPlainText = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($LDAPBindCredentials.Password))
        $PrincipleContext = [System.DirectoryServices.AccountManagement.PrincipalContext]::new(
            [System.DirectoryServices.AccountManagement.ContextType]::Domain,
            "$SimpleDomainWLDAPPort",
            "$DomainLDAPContainers",
            [System.DirectoryServices.AccountManagement.ContextOptions]::SimpleBind,
            "$($LDAPBindCredentials.UserName)",
            "$PasswordInPlainText"
        )

        try {
            $UserPrincipal = [System.DirectoryServices.AccountManagement.UserPrincipal]::FindByIdentity($PrincipleContext, [System.DirectoryServices.AccountManagement.IdentityType]::SamAccountName, "$SimpleUserName")
            $LDAPBindCredentialsAreValid = $True
        }
        catch {
            throw "The credentials provided to the -LDAPBindCredentials parameter are not valid for the domain $SimpleDomain! Halting!"
        }

        if ($LDAPBindCredentialsAreValid) {
            # Determine if the User Account is locked
            $AccountLocked = $UserPrincipal.IsAccountLockedOut()

            if ($AccountLocked -eq $True) {
                throw "The provided UserName $($LDAPBindCredentials.Username) is locked! Please unlock it before additional attempts at getting working credentials!"
            }
        }
    }
    catch {
        Write-Error $_
        $global:FunctionResult = "1"
        return
    }


    # NOTE: With .Net, LDAP URIs always start with 'LDAP' - never lowercase and never with an 's|S' (i.e. never LDAPS|ldaps),
    # regardless of port
    $LDAPUri = "LDAP://$($LDAPServerNetworkInfo.FQDN):$LDAPServicePort"

    # Make sure $LDAPUserOUDN exists
    try {
        $LDAPUserOUDNDirectoryEntry = [ADSI]("$LDAPUri/$LDAPUserOUDN")
        $LDAPUserOUDNDirectoryEntry.Close()
    }
    catch {
        Write-Error "The LDAP Object $LDAPUserOUDN cannot be found! Halting!"
        $global:FunctionResult = "1"
        return
    }

    # Make sure $LDAPGroupOUDN exists
    try {
        $LDAPGroupOUDNDirectoryEntry = [ADSI]("$LDAPUri/$LDAPGroupOUDN")
        $LDAPGroupOUDNDirectoryEntry.Close()
    }
    catch {
        Write-Error "The LDAP Object $LDAPGroupOUDN cannot be found! Halting!"
        $global:FunctionResult = "1"
        return
    }

    $HeadersParameters = @{
        "X-Vault-Token" = $VaultAuthToken
    }

    #endregion >> Variable/Parameter Transforms and PreRun Prep


    #region >> Main Body
    
    # Turn on Vault Audit Log
    # Vault CmdLine Equivalent:
    #   vault audit enable file file_path=/vault/logs/vault_audit.log
    $jsonRequest = @"
{
    "type": "file",
    "options": {
        "path": "/vault/logs/$VaultLogFileName"
    }
}
"@
    try {
        # Validate JSON
        $JsonRequestAsSingleLineString = $jsonRequest | ConvertFrom-Json -EA Stop | ConvertTo-Json -Compress -EA Stop
    }
    catch {
        Write-Error "There was a problem with the JSON for Turning on the Audit Log! Halting!"
        if ($Output.Count -gt 0) {[pscustomobject]$Output}
        $global:FunctionResult = "1"
        return
    }
    $IWRSplatParams = @{
        Uri         = "$VaultServerBaseUri/sys/audit/$VaultLogEndPointName"
        Headers     = $HeadersParameters
        Body        = $JsonRequestAsSingleLineString
        Method      = "Put"
    }
    $TurnOnAuditLog = Invoke-RestMethod @IWRSplatParams
    $ConfirmAuditLogIsOn = $(Invoke-RestMethod -Uri "$VaultServerBaseUri/sys/audit" -Headers $HeadersParameters -Method Get).data
    if (!$ConfirmAuditLogIsOn) {
        Write-Error "Cannot confirm that the Vault Audit Log is turned on! Halting!"
        if ($Output.Count -gt 0) {[pscustomobject]$Output}
        $global:FunctionResult = "1"
        return
    }
    $Output.Add("EnableAuditLog",$ConfirmAuditLogIsOn)

    # Create a new policy that effectively has root access to Vault, and call it 'custom-root'. This policy will be applied
    # to Vault Administrators later on
    $jsonRequest = @"
{
    "policy": "path \"*\" {\n    capabilities = [\"create\", \"read\", \"update\", \"delete\", \"list\", \"sudo\"]\n}"
}
"@
    try {
        # Validate JSON
        $JsonRequestAsSingleLineString = $jsonRequest | ConvertFrom-Json -EA Stop | ConvertTo-Json -Compress -EA Stop
    }
    catch {
        Write-Error "There was a problem with the JSON for creating the 'custom-root' policy! Halting!"
        if ($Output.Count -gt 0) {[pscustomobject]$Output}
        $global:FunctionResult = "1"
        return
    }
    $IWRSplatParams = @{
        Uri         = "$VaultServerBaseUri/sys/policy/custom-root"
        Headers     = $HeadersParameters
        Body        = $JsonRequestAsSingleLineString
        Method      = "Put"
    }
    $RootPolicyResponse = Invoke-RestMethod @IWRSplatParams
    $ConfirmRootPolicy = Invoke-RestMethod -Uri "$VaultServerBaseUri/sys/policy/custom-root" -Headers $HeadersParameters -Method Get
    if (!$ConfirmRootPolicy) {
        Write-Error "Cannot confirm that the Vault policy 'custom-root' has been enabled! Halting!"
        if ($Output.Count -gt 0) {[pscustomobject]$Output}
        $global:FunctionResult = "1"
        return
    }
    $Output.Add("CreateCustomRootPolicy",$ConfirmRootPolicy)

    # Create a policy that is for typical Vault Users (i.e. not Vault Admins), that allows for everything except
    # delete and sudo. Change according to your preferences.
    $jsonRequest = @"
{
    "policy": "path \"*\" {\n    capabilities = [\"create\", \"read\", \"update\", \"list\"]\n}"
}
"@
    try {
        # Validate JSON
        $JsonRequestAsSingleLineString = $jsonRequest | ConvertFrom-Json -EA Stop | ConvertTo-Json -Compress -EA Stop
    }
    catch {
        Write-Error "There was a problem with the JSON for creating the 'vaultusers' policy! Halting!"
        if ($Output.Count -gt 0) {[pscustomobject]$Output}
        $global:FunctionResult = "1"
        return
    }
    $IWRSplatParams = @{
        Uri         = "$VaultServerBaseUri/sys/policy/vaultusers"
        Headers     = $HeadersParameters
        Body        = $JsonRequestAsSingleLineString
        Method      = "Put"
    }
    $VaultUsersPolicyResponse = Invoke-RestMethod @IWRSplatParams
    $ConfirmVaultUsersPolicy = Invoke-RestMethod -Uri "$VaultServerBaseUri/sys/policy/vaultusers" -Headers $HeadersParameters -Method Get
    if (!$ConfirmVaultUsersPolicy) {
        Write-Error "Cannot confirm that the Vault policy 'vaultusers' has been enabled! Halting!"
        if ($Output.Count -gt 0) {[pscustomobject]$Output}
        $global:FunctionResult = "1"
        return
    }
    $Output.Add("CreateVaultUsersPolicy",$ConfirmVaultUsersPolicy)

    if ($PerformOptionalSteps) {
        # Create a user other than the initial root (i.e. the token $VaultAuthToken that we've been using thus far) that has root privileges
        # via the 'custom-root' policy. This is just for a backup root account for emergencies
        # Vault CmdLine Equivalent:
        #   vault token create -policy=custom-root -display-name="backupadmin" -ttl="8760h" -renewable=true -metadata=user=backupadmin
        $jsonRequest = @"
{
    "policies": [
        "custom-root"
    ],
    "meta": {
        "user": "backupadmin"
    },
    "ttl": "8760h",
    "renewable": true
}
"@
        try {
            # Validate JSON
            $JsonRequestAsSingleLineString = $jsonRequest | ConvertFrom-Json -EA Stop | ConvertTo-Json -Compress -EA Stop
        }
        catch {
            Write-Error "There was a problem with the JSON for creating the 'backupadmin' Vault Token! Halting!"
            if ($Output.Count -gt 0) {[pscustomobject]$Output}
            $global:FunctionResult = "1"
            return
        }
        $IWRSplatParams = @{
            Uri         = "$VaultServerBaseUri/auth/token/create"
            Headers     = $HeadersParameters
            Body        = $JsonRequestAsSingleLineString
            Method      = "Post"
        }
        $NewUserTokenResponse = Invoke-RestMethod @IWRSplatParams
        if (!$NewUserTokenResponse) {
            Write-Error "There was a problem creating the 'backupadmin' Vault Token! Halting!"
            $global:FunctionResult = "1"
            return
        }
        $Output.Add("BackupRootToken",$NewUserTokenResponse)
    }

    # Enable LDAP Authentication
    #   vault auth enable ldap -description="Login with LDAP"
    $jsonRequest = @"
{
    "type": "ldap",
    "description": "Login with LDAP"
}
"@
    try {
        # Validate JSON
        $JsonRequestAsSingleLineString = $jsonRequest | ConvertFrom-Json -EA Stop | ConvertTo-Json -Compress -EA Stop
    }
    catch {
        Write-Error "There was a problem with the JSON for enabling the Vault LDAP Authentication Method! Halting!"
        if ($Output.Count -gt 0) {[pscustomobject]$Output}
        $global:FunctionResult = "1"
        return
    }
    $IWRSplatParams = @{
        Uri         = "$VaultServerBaseUri/sys/auth/ldap"
        Headers     = $HeadersParameters
        Body        = $JsonRequestAsSingleLineString
        Method      = "Post"
    }
    $EnableLDAPResponse = Invoke-RestMethod @IWRSplatParams
    $ConfirmLDAPEnabled = Invoke-RestMethod -Uri "$VaultServerBaseUri/sys/auth" -Headers $HeadersParameters -Method Get
    if (!$ConfirmLDAPEnabled) {
        Write-Error "There was a problem enabling the LDAP Authentication Method for the Vault Server! Halting!"
    }
    $Output.Add("LDAPAuthEngineEnabled",$ConfirmLDAPEnabled)

    # Next, we need the LDAP Server's Root CA Public Certificate
    try {
        $GetLDAPCertSplatParams = @{
            LDAPServerHostNameOrIP      = $LDAPServerNetworkInfo.FQDN
            Port                        = $LDAPServicePort
            ErrorAction                 = "Stop"
        }
        if ($LDAPServicePort -eq 389 -or $LDAPServicePort -eq 3268) {
            $GetLDAPCertSplatParams.Add("UseOpenSSL",$True)
        }

        $GetLDAPCertResult = Get-LDAPCert @GetLDAPCertSplatParams
        if (!$GetLDAPCertResult) {throw "The Get-LDAPCert function failed! Is your LDAP implementation using TLS? Halting!"}
        $RootCertificateInPemFormat = $GetLDAPCertResult.RootCACertificateInfo.PemFormat -join "`n"
        if (!$RootCertificateInPemFormat) {throw "The Get-LDAPCert function failed to get the Root CA Certificate in the LDAP Endpoint's Certificate Chain! Halting!"}
    }
    catch {
        Write-Error $_
        if ($Output.Count -gt 0) {[pscustomobject]$Output}
        $global:FunctionResult = "1"
        return
    }

    # The Vault Server handles LDAP Uris as expected (as opposed to .Net counterpart in above
    # 'Variable/Parameter Transforms and PreRun Prep' region) 
    if ($LDAPServicePort -eq 389 -or $LDAPServicePort -eq 3268) {
        $LDAPUriForVault = "ldap://$($LDAPServerNetworkInfo.FQDN):$LDAPServicePort"
    }
    if ($LDAPServicePort -eq 636 -or $LDAPServicePort -eq 3269) {
        $LDAPUriForVault = "ldaps://$($LDAPServerNetworkInfo.FQDN):$LDAPServicePort"
    }

    $jsonRequest = @"
{
    "url": "$LDAPUriForVault",
    "userattr": "samaccountname",
    "userdn": "$LDAPUserOUDN",
    "discoverdn": "true",
    "groupdn": "$LDAPGroupOUDN",
    "groupfilter": "(&(objectClass=group)(member:1.2.840.113556.1.4.1941:={{.UserDN}}))",
    "groupattr": "cn",
    "certificate": "$RootCertificateInPemFormat",
    "insecure_tls": "false",
    "starttls": "true",
    "binddn": "$BindUserDN",
    "bindpass": "$PasswordInPlainText",
    "deny_null_bind": "true",
    "tls_max_version": "tls12",
    "tls_min_version": "tls12"
}
"@
    try {
        # Validate JSON
        $JsonRequestAsSingleLineString = $jsonRequest | ConvertFrom-Json -EA Stop | ConvertTo-Json -Compress -EA Stop
    }
    catch {
        Write-Error "There was a problem with the JSON for establishing Vault's LDAP configuration! Halting!"
        if ($Output.Count -gt 0) {[pscustomobject]$Output}
        $global:FunctionResult = "1"
        return
    }
    $IWRSplatParams = @{
        Uri         = "$VaultServerBaseUri/auth/ldap/config"
        Headers     = $HeadersParameters
        Body        = $JsonRequestAsSingleLineString
        Method      = "Post"
    }
    $LDAPAuthConfigResponse = Invoke-RestMethod @IWRSplatParams
    $ConfirmLDAPAuthConfig = Invoke-RestMethod -Uri "$VaultServerBaseUri/auth/ldap/config" -Headers $HeadersParameters -Method Get
    if (!$ConfirmLDAPAuthConfig) {
        Write-Error "There was a problem setting the Vault LDAP Authentication configuration! Halting!"
        if ($Output.Count -gt 0) {[pscustomobject]$Output}
        $global:FunctionResult = "1"
        return
    }
    $Output.Add("LDAPAuthConfiguration",$ConfirmLDAPAuthConfig)
    # Remove $PasswordInPlainText from Memory as best we can
    $PasswordInPlainText = $null
    $PrincipleContext = $null
    $jsonRequest = $null
    $JsonRequestAsSingleLineString = $null


    if ($PerformOptionalSteps) {
        # Apply the 'custom-root' policy to the AD User Group 'VaultAdmins'
        # Vault Cmdline equivalent is:
        #   vault write auth/ldap/groups/VaultAdmins policies=custom-root

        # Make sure $LDAPVaultAdminsSecurityGroupDN exists
        try {
            $LDAPVaultAdminsSecurityGroupDNDirectoryEntry = [ADSI]("$LDAPUri/$LDAPVaultAdminsSecurityGroupDN")
            $LDAPVaultAdminsSecurityGroupDNDirectoryEntry.Close()
        }
        catch {
            Write-Error "The LDAP Object $LDAPVaultAdminsSecurityGroupDN cannot be found! Halting!"
            $global:FunctionResult = "1"
            if ($Output.Count -gt 0) {[pscustomobject]$Output}
            return
        }

        $jsonRequest = @"
{
    "policies": "custom-root"
}
"@
        try {
            # Validate JSON
            $JsonRequestAsSingleLineString = $jsonRequest | ConvertFrom-Json -EA Stop | ConvertTo-Json -Compress -EA Stop
        }
        catch {
            Write-Error "There was a problem with the JSON for applying the 'custom-root' policy to the VaultAdmins Security Group! Halting!"
            $global:FunctionResult = "1"
            return
        }
        $IWRSplatParams = @{
            Uri         = "$VaultServerBaseUri/auth/ldap/groups/VaultAdmins"
            Headers     = $HeadersParameters
            Body        = $JsonRequestAsSingleLineString
            Method      = "Post"
        }
        $ApplyPolicyToVaultAdminsGroup = Invoke-WebRequest @IWRSplatParams
        $ConfirmPolicyOnVaultAdmins = Invoke-RestMethod -Uri "$VaultServerBaseUri/auth/ldap/groups/VaultAdmins" -Headers $HeadersParameters -Method Get
        if (!$ConfirmPolicyOnVaultAdmins) {
            Write-Error "Unable to confirm that the 'custom-root' Vault Policy was applied to the LDAP Security Group 'VaultAdmins'! Halting!"
            if ($Output.Count -gt 0) {[pscustomobject]$Output}
            $global:FunctionResult = "1"
            return
        }
        $Output.Add("AppliedVaultAdminsPolicy",$ConfirmPolicyOnVaultAdmins)

        # Apply the 'vaultusers' policy to the AD User Group 'VaultUsers'
        # Vault Cmdline equivalent is:
        #   vault write auth/ldap/groups/VaultUsers policies=vaultusers

        # Make sure $LDAPVaultUsersSecurityGroupDN exists
        try {
            $LDAPVaultUsersSecurityGroupDNDirectoryEntry = [ADSI]("$LDAPUri/$LDAPVaultUsersSecurityGroupDN")
            $LDAPVaultUsersSecurityGroupDNDirectoryEntry.Close()
        }
        catch {
            Write-Error "The LDAP Object $LDAPVaultUsersSecurityGroupDN cannot be found! Halting!"
            if ($Output.Count -gt 0) {[pscustomobject]$Output}
            $global:FunctionResult = "1"
            return
        }

        $jsonRequest = @"
{
    "policies": "vaultusers"
}
"@
        try {
            $JsonRequestAsSingleLineString = $jsonRequest | ConvertFrom-Json -EA Stop | ConvertTo-Json -Compress -EA Stop
        }
        catch {
            Write-Error "There was a problem with the JSON for applying the 'vaultusers' policy to the VaulUsers Security Group! Halting!"
            if ($Output.Count -gt 0) {[pscustomobject]$Output}
            $global:FunctionResult = "1"
            return
        }
        $IWRSplatParams = @{
            Uri         = "$VaultServerBaseUri/auth/ldap/groups/VaultUsers"
            Headers     = $HeadersParameters
            Body        = $JsonRequestAsSingleLineString
            Method      = "Post"
        }
        $ApplyPolicyToVaultUsersGroup = Invoke-WebRequest @IWRSplatParams
        $ConfirmPolicyOnVaultUsers = Invoke-RestMethod -Uri "$VaultServerBaseUri/auth/ldap/groups/VaultUsers" -Headers $HeadersParameters -Method Get
        if (!$ConfirmPolicyOnVaultUsers) {
            Write-Error "Unable to confirm that the 'vaultusers' Vault Policy was applied to the LDAP Security Group 'VaultUsers'! Halting!"
            if ($Output.Count -gt 0) {[pscustomobject]$Output}
            $global:FunctionResult = "1"
            return
        }
        $Output.Add("AppliedVaultUsersPolicy",$ConfirmPolicyOnVaultUsers)
    }

[pscustomobject]$Output

    #endregion >> Main Body

}

function Get-VaultLogin {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$True)]
        [ValidatePattern("\/v1$")]
        [string]$VaultServerBaseUri,

        [Parameter(Mandatory=$True)]
        [pscredential]$DomainCredentialsWithAdminAccessToVault
    )

    [Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls"

    # Make sure we can reach the Vault Server and that is in a state where we can actually use it.
    try {
        $VaultServerUpAndUnsealedCheck = Invoke-RestMethod "$VaultServerBaseUri/sys/health"
        if (!$VaultServerUpAndUnsealedCheck -or $VaultServerUpAndUnsealedCheck.initialized -ne $True -or
        $VaultServerUpAndUnsealedCheck.sealed -ne $False -or $VaultServerUpAndUnsealedCheck.standby -ne $False) {
            throw "The Vault Server is either not reachable or in a state where it cannot be used! Halting!"
        }
    }
    catch {
        Write-Error $_
        Write-Host "Use 'Invoke-RestMethod '$VaultServerBaseUri/sys/health' to investigate" -ForegroundColor Yellow
        $global:FunctionResult = "1"
        return
    }

    # Get the Domain User's Vault Token so that we can interact with Vault
    $UserName = $($DomainCredentialsWithAdminAccessToVault.UserName -split "\\")[1]
    $PlainTextPwd = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($DomainCredentialsWithAdminAccessToVault.Password))

    $jsonRequest = @"
{
    "password": "$PlainTextPwd"
}
"@
    try {
        $JsonRequestAsSingleLineString = $jsonRequest | ConvertFrom-Json -EA Stop | ConvertTo-Json -Compress -EA Stop
    }
    catch {
        Write-Error "There was a problem with the JSON for Turning on the Audit Log! Halting!"
        $global:FunctionResult = "1"
        return
    }
    $IWRSplatParams = @{
        Uri         = "$VaultServerBaseUri/auth/ldap/login/$UserName "
        Body        = $JsonRequestAsSingleLineString
        Method      = "Post"
    }
    $LDAPLoginResult = Invoke-RestMethod @IWRSplatParams
    $VaultAuthToken = $LDAPLoginResult.auth.client_token

    # Get rid of PlainText Password from Memory as best we can (this really doesn't do enough...)
    # https://get-powershellblog.blogspot.com/2017/06/how-safe-are-your-strings.html
    $jsonRequest = $null
    $PlainTextPwd = $null

    if (!$VaultAuthToken) {
        Write-Error "There was a problem getting the Vault Token for Domain User $UserName! Halting!"
        $global:FunctionResult = "1"
        return
    }
    else {
        $VaultAuthToken
    }
}

function Configure-VaultServerForSSHManagement {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$True)]
        [ValidatePattern("\/v1$")]
        [string]$VaultServerBaseUri,

        [Parameter(Mandatory=$False)]
        [pscredential]$DomainCredentialsWithAdminAccessToVault,

        [Parameter(Mandatory=$False)]
        [string]$VaultAuthToken
    )

    if ($(!$VaultAuthToken -and !$DomainCredentialsWithAccessToVault) -or $($VaultAuthToken -and $DomainCredentialsWithAdminAccessToVault)) {
        Write-Error "The $($MyInvocation.MyCommand.Name) function requires one (no more, no less) of the following parameters: [-DomainCredentialsWithAdminAccessToVault, -VaultAuthToken] Halting!"
        $global:FunctionResult = "1"
        return
    }

    if ($DomainCredentialsWithAdminAccessToVault) {
        $GetVaultLoginSplatParams = @{
            VaultServerBaseUri                          = $VaultServerBaseUri
            DomainCredentialsWithAdminAccessToVault     = $DomainCredentialsWithAdminAccessToVault
            ErrorAction                                 = "Stop"
        }

        try {
            $VaultAuthToken = Get-VaultLogin @GetVaultLoginSplatParams
            if (!$VaultAuthToken) {throw "The Get-VaultLogin function failed! Halting!"}
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            return
        }
    }

    $HeadersParameters = @{
        "X-Vault-Token" = $VaultAuthToken
    }

    # Create $Output HashTable to add results as we go...
    $Output = [ordered]@{}

    # We'll be configuring a Certificate Authority for ssh client key signing, and a Certificate Authority for
    # ssh machine host key signing
    
    ##### ENABLE SSH CLIENT CERT SIGNING #####

    # Vault CmdLine equivalent of below HTTP Request -
    #     vault secrets enable -path=ssh-client-signer ssh
    $jsonRequest = @"
{
    "type": "ssh",
    "description": "SSH Client Signer"
}
"@
    try {
        # Validate JSON
        $JsonRequestAsSingleLineString = $jsonRequest | ConvertFrom-Json -EA Stop | ConvertTo-Json -Compress -EA Stop
    }
    catch {
        Write-Error "There was a problem with the JSON for enabling the Vault SSH Client Signer! Halting!"
        if ($Output.Count -gt 0) {[pscustomobject]$Output}
        $global:FunctionResult = "1"
        return
    }
    $IWRSplatParams = @{
        Uri         = "$VaultServerBaseUri/sys/mounts/ssh-client-signer"
        Headers     = $HeadersParameters
        Body        = $JsonRequestAsSingleLineString
        Method      = "Post"
    }
    $EnableSSHClientSigner = Invoke-RestMethod @IWRSplatParams
    $ConfirmSSHClientSignerEnabledPrep = Invoke-RestMethod -Uri "$VaultServerBaseUri/sys/mounts" -Headers $HeadersParameters -Method Get
    if (!$ConfirmSSHClientSignerEnabledPrep) {
        Write-Error "There was a problem confirming that the Vault SSH Client Signer was enabled! Halting!"
        if ($Output.Count -gt 0) {[pscustomobject]$Output}
        $global:FunctionResult = "1"
        return
    }
    $ConfirmSSHClientSignerEnabled = $($ConfirmSSHClientSignerEnabledPrep.data | Get-Member -MemberType Properties).Name -contains "ssh-client-signer/"
    $Output.Add("SSHClientSignerEnabled",$ConfirmSSHClientSignerEnabled)

    # Create A Certificate Authority dedicated to SSH Client Certs and Generate a Public/Private Key Pair for the CA
    # Vault CmdLine equivalent of below HTTP Request -
    #     vault write ssh-client-signer/config/ca generate_signing_key=true
    $jsonRequest = @"
{
    "generate_signing_key": true
}
"@
    try {
        # Validate JSON
        $JsonRequestAsSingleLineString = $jsonRequest | ConvertFrom-Json -EA Stop | ConvertTo-Json -Compress -EA Stop
    }
    catch {
        Write-Error "There was a problem with the JSON for creating the SSH Client Signer Certificate Authority! Halting!"
        if ($Output.Count -gt 0) {[pscustomobject]$Output}
        $global:FunctionResult = "1"
        return
    }
    $IWRSplatParams = @{
        Uri         = "$VaultServerBaseUri/ssh-client-signer/config/ca"
        Headers     = $HeadersParameters
        Body        = $JsonRequestAsSingleLineString
        Method      = "Post"
    }
    $CreateSSHClientCA = Invoke-RestMethod @IWRSplatParams
    $SSHClientCAPublicKey = Invoke-RestMethod -Uri "$VaultServerBaseUri/ssh-client-signer/public_key" -Method Get
    if (!$SSHClientCAPublicKey) {
        Write-Error "There was a problem getting the Public Key of the SSH Client Signer Certificate Authority! Halting!"
        if ($Output.Count -gt 0) {[pscustomobject]$Output}
        $global:FunctionResult = "1"
        return
    }
    $Output.Add("SSHClientSignerCAPublicKey",$SSHClientCAPublicKey)


    ##### ENABLE SSH HOST CERT SIGNING #####

    # Vault CmdLine equivalent of below HTTP Request -
    # vault secrets enable -path=ssh-host-signer ssh
    $jsonRequest = @"
{
    "type": "ssh",
    "description": "SSH Host Signer"
}
"@
    try {
        # Validate JSON
        $JsonRequestAsSingleLineString = $jsonRequest | ConvertFrom-Json -EA Stop | ConvertTo-Json -Compress -EA Stop
    }
    catch {
        Write-Error "There was a problem with the JSON for enabling the Vault SSH Host Signer! Halting!"
        if ($Output.Count -gt 0) {[pscustomobject]$Output}
        $global:FunctionResult = "1"
        return
    }
    $IWRSplatParams = @{
        Uri         = "$VaultServerBaseUri/sys/mounts/ssh-host-signer"
        Headers     = $HeadersParameters
        Body        = $JsonRequestAsSingleLineString
        Method      = "Post"
    }
    $EnableSSHHostSigner = Invoke-WebRequest @IWRSplatParams
    $ConfirmSSHHostSignerEnabledPrep = Invoke-RestMethod -Uri "$VaultServerBaseUri/sys/mounts" -Headers $HeadersParameters -Method Get
    if (!$ConfirmSSHHostSignerEnabledPrep) {
        Write-Error "There was a problem confirming that the Vault SSH Host Signer was enabled! Halting!"
        if ($Output.Count -gt 0) {[pscustomobject]$Output}
        $global:FunctionResult = "1"
        return
    }
    $ConfirmSSHHostSignerEnabled = $($ConfirmSSHHostSignerEnabledPrep.data | Get-Member -MemberType Properties).Name -contains "ssh-host-signer/"
    $Output.Add("SSHHostSignerEnabled",$ConfirmSSHHostSignerEnabled)

    # Create A Certificate Authority dedicated to SSH Host Certs and Generate a Public/Private Key Pair for the CA
    #     vault write ssh-host-signer/config/ca generate_signing_key=true
    $jsonRequest = @"
{
    "generate_signing_key": true
}
"@
    try {
        # Validate JSON
        $JsonRequestAsSingleLineString = $jsonRequest | ConvertFrom-Json -EA Stop | ConvertTo-Json -Compress -EA Stop
    }
    catch {
        Write-Error "There was a problem with the JSON for creating the SSH Host Signer Certificate Authority! Halting!"
        if ($Output.Count -gt 0) {[pscustomobject]$Output}
        $global:FunctionResult = "1"
        return
    }
    $IWRSplatParams = @{
        Uri         = "$VaultServerBaseUri/ssh-host-signer/config/ca"
        Headers     = $HeadersParameters
        Body        = $JsonRequestAsSingleLineString
        Method      = "Post"
    }
    $CreateSSHHostCA = Invoke-RestMethod @IWRSplatParams
    $SSHHostCAPublicKey = Invoke-RestMethod -Uri "$VaultServerBaseUri/ssh-host-signer/public_key" -Method Get
    if (!$SSHHostCAPublicKey) {
        Write-Error "There was a problem getting the Public Key of the SSH Host Signer Certificate Authority! Halting!"
        if ($Output.Count -gt 0) {[pscustomobject]$Output}
        $global:FunctionResult = "1"
        return
    }
    $Output.Add("SSHHostSignerCAPublicKey",$SSHHostCAPublicKey)

    # Extend Host Cert TTL to 10 years
    #     vault secrets tune -max-lease-ttl=87600h ssh-host-signer
    $jsonRequest = @"
{
    "max_lease_ttl": "87600h"
}
"@
    try {
        # Validate JSON
        $JsonRequestAsSingleLineString = $jsonRequest | ConvertFrom-Json -EA Stop | ConvertTo-Json -Compress -EA Stop
    }
    catch {
        Write-Error "There was a problem with the JSON for Tuning the SSH Host Signer! Halting!"
        if ($Output.Count -gt 0) {[pscustomobject]$Output}
        $global:FunctionResult = "1"
        return
    }
    $IWRSplatParams = @{
        Uri         = "$VaultServerBaseUri/sys/mounts/ssh-host-signer/tune"
        Headers     = $HeadersParameters
        Body        = $JsonRequestAsSingleLineString
        Method      = "Post"
    }
    $TuneHostSSHCertValidityPeriod = Invoke-RestMethod @IWRSplatParams
    $ConfirmSSHHostSignerTune = $(Invoke-RestMethod -Uri "$VaultServerBaseUri/sys/mounts" -Headers $HeadersParameters -Method Get).'ssh-host-signer/'.config
    if ($ConfirmSSHHostSignerTune.max_lease_ttl -ne 315360000) {
        Write-Error "There was a problem tuning the Vault Server to set max_lease_ttl for signed host ssh keys for 10 years. Halting!"
        if ($Output.Count -gt 0) {[pscustomobject]$Output}
        $global:FunctionResult = "1"
        return
    }
    $Output.Add("SSHHostSignerTuning",$ConfirmSSHHostSignerTune)


    ##### Configure the SSH Client Signer Role #####
    $DefaultUser = $($(whoami) -split "\\")[-1]
    
    $jsonRequest = @"
{
    "key_type": "ca",
    "default_user": "$DefaultUser",
    "allow_user_certificates": true,
    "allowed_users": "*",
    "ttl": "24h",
    "default_extensions": {
        "permit-pty": "",
        "permit-agent-forwarding": ""
    }
}
"@
    try {
        # Validate JSON
        $JsonRequestAsSingleLineString = $jsonRequest | ConvertFrom-Json -EA Stop | ConvertTo-Json -Compress -EA Stop
    }
    catch {
        Write-Error "There was a problem with the JSON for configuring the SSH Client Signer Role! Halting!"
        if ($Output.Count -gt 0) {[pscustomobject]$Output}
        $global:FunctionResult = "1"
        return
    }
    $IWRSplatParams = @{
        Uri         = "$VaultServerBaseUri/ssh-client-signer/roles/clientrole"
        Headers     = $HeadersParameters
        Body        = $JsonRequestAsSingleLineString
        Method      = "Post"
    }
    $SetSSHClientRole = Invoke-RestMethod @IWRSplatParams
    $ConfirmSSHClientRole = Invoke-RestMethod -Uri "$VaultServerBaseUri/ssh-client-signer/roles/clientrole" -Headers $HeadersParameters -Method Get
    if (!$ConfirmSSHClientRole.data) {
        Write-Error "There was a problem creating the the ssh-client-signer Role 'clientrole'! Halting!"
        if ($Output.Count -gt 0) {[pscustomobject]$Output}
        $global:FunctionResult = "1"
        return
    }
    $Output.Add("SSHClientSignerRole",$ConfirmSSHClientRole)

    ##### Configure the SSH Host Signer Role #####
    $jsonRequest = @"
{
    "key_type": "ca",
    "cert_type": "host",
    "allow_host_certificates": "true",
    "allowed_domains": "*",
    "allow_subdomains": "true",
    "ttl": "87600h",
    "default_extensions": {
        "permit-pty": "",
        "permit-agent-forwarding": ""
    }
}
"@
    try {
        # Validate JSON
        $JsonRequestAsSingleLineString = $jsonRequest | ConvertFrom-Json -EA Stop | ConvertTo-Json -Compress -EA Stop
    }
    catch {
        Write-Error "There was a problem with the JSON for configuring the SSH Host Signer Role! Halting!"
        if ($Output.Count -gt 0) {[pscustomobject]$Output}
        $global:FunctionResult = "1"
        return
    }
    $IWRSplatParams = @{
        Uri         = "$VaultServerBaseUri/ssh-host-signer/roles/hostrole"
        Headers     = $HeadersParameters
        Body        = $JsonRequestAsSingleLineString
        Method      = "Post"
    }
    $SetSSHHostRole = Invoke-RestMethod @IWRSplatParams
    $ConfirmSSHHostRole = Invoke-RestMethod -Uri "$VaultServerBaseUri/ssh-host-signer/roles/hostrole" -Headers $HeadersParameters -Method Get
    if (!$ConfirmSSHHostRole.data) {
        Write-Error "There was a problem creating the the ssh-host-signer Role 'hostrole'! Halting!"
        if ($Output.Count -gt 0) {[pscustomobject]$Output}
        $global:FunctionResult = "1"
        return
    }
    $Output.Add("SSHHostSignerRole",$ConfirmSSHHostRole)

    [pscustomobject]$Output
}

function New-SSHCredentials {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$True)]
        [ValidatePattern("\/v1$")]
        [string]$VaultServerBaseUri,

        [Parameter(Mandatory=$False)]
        [pscredential]$DomainCredentialsWithAccessToVault,

        [Parameter(Mandatory=$False)]
        [string]$VaultAuthToken,

        [Parameter(Mandatory=$True)]
        [string]$NewSSHKeyName,

        [Parameter(Mandatory=$False)]
        [ValidatePattern("^\w*$")] # No spaces allowed
        [string]$NewSSHKeyPurpose,

        [Parameter(Mandatory=$False)]
        [System.Security.SecureString]$NewSSHKeyPwd,

        [Parameter(Mandatory=$False)]
        [switch]$BlankSSHPrivateKeyPwd,

        [Parameter(Mandatory=$False)]
        [switch]$AddToSSHAgent = $True,

        [Parameter(Mandatory=$False)]
        [switch]$AllowAwaitModuleInstall,

        [Parameter(Mandatory=$False)]
        [switch]$RemovePrivateKey
    )

    if ($(!$VaultAuthToken -and !$DomainCredentialsWithAccessToVault) -or $($VaultAuthToken -and $DomainCredentialsWithAccessToVault)) {
        Write-Error "The $($MyInvocation.MyCommand.Name) function requires one (no more, no less) of the following parameters: [-DomainCredentialsWithAccessToVault, -VaultAuthToken] Halting!"
        $global:FunctionResult = "1"
        return
    }

    if ($DomainCredentialsWithAccessToVault) {
        $GetVaultLoginSplatParams = @{
            VaultServerBaseUri                          = $VaultServerBaseUri
            DomainCredentialsWithAdminAccessToVault     = $DomainCredentialsWithAccessToVault
            ErrorAction                                 = "Stop"
        }

        try {
            $VaultAuthToken = Get-VaultLogin @GetVaultLoginSplatParams
            if (!$VaultAuthToken) {throw "The Get-VaultLogin function failed! Halting!"}
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            return
        }
    }

    $HeadersParameters = @{
        "X-Vault-Token" = $VaultAuthToken
    }

    # Generate an SSH key pair for zeroadmin
    if (!$(Test-Path "$HOME\.ssh")) {
        New-Item -ItemType Directory -Path "$HOME\.ssh"
    }

    Push-Location "$HOME\.ssh"

    $NewSSHKeySplatParams = @{
        NewSSHKeyName       = $NewSSHKeyName
        ErrorAction         = "Stop"
    }
    if ($NewSSHKeyPurpose) {
        $NewSSHKeySplatParams.Add("NewSSHKeyPurpose",$NewSSHKeyPurpose)
    }
    if (!$BlankSSHPrivateKeyPwd) {
        if ($NewSSHKeyPwd) {
            $KeyPwd = $NewSSHKeyPwd
        }
        else {
            $KeyPwd = Read-Host -Prompt "Please enter a password to protect the new SSH Private Key $NewSSHKeyName"
        }
        $NewSSHKeySplatParams.Add("NewSSHKeyPwd",$KeyPwd)
    }
    else {
        if ($AllowAwaitModuleInstall) {
            $NewSSHKeySplatParams.Add("AllowAwaitModuleInstall",$True)
        }
    }
    
    try {
        $NewSSHKeyResult = New-SSHKey @NewSSHKeySplatParams
        if (!$NewSSHKeyResult) {throw "There was a problem with the New-SSHKey function! Halting!"}
    }
    catch {
        Write-Error $_
        $global:FunctionResult = "1"
        return
    }

    # Have Vault sign the User's New public key
    if ($DomainCredentialsWithAccessToVault) {
        $AuthorizedPrincipalUserPrep = $DomainCredentialsWithAccessToVault.UserName -split "\\"
        $AuthorizedPrincipalString = $AuthorizedPrincipalUserPrep[-1] + "@" + $AuthorizedPrincipalUserPrep[0]
    }
    else {
        $AuthorizedPrincipalString = $($(whoami) -split "\\")[-1] + "@" + $($(whoami) -split "\\")[0]
    }

    $SignSSHUserPubKeySplatParams = @{
        VaultSSHClientSigningUrl        = "$VaultServerBaseUri/ssh-client-signer/sign/clientrole"
        VaultAuthToken                  = $VaultAuthToken
        AuthorizedUserPrincipals        = @($AuthorizedPrincipalString)
        PathToSSHUserPublicKeyFile      = $NewSSHKeyResult.PublicKeyFilePath
        PathToSSHUserPrivateKeyFile     = $NewSSHKeyResult.PrivateKeyFilePath
        ErrorAction                     = "Stop"
    }
    if ($AddToSSHAgent) {
        $SignSSHUserPubKeySplatParams.Add("AddToSSHAgent",$True)
    }

    try {
        $SignSSHUserPublicKeyResult = Sign-SSHUserPublicKey @SignSSHUserPubKeySplatParams
        if (!$SignSSHUserPublicKeyResult) {throw "There was a problem with the Sign-SSHUserPublicKey function! Halting!"}
    }
    catch {
        Write-Error $_
        $global:FunctionResult = "1"
        return
    }

    if ($RemovePrivateKey -and $SignSSHUserPublicKeyResult.AddedToSSHAgent) {
        Remove-Item $NewSSHKeyResult.PrivateKeyFilePath -Force
    }

    # Next, pull the Vault Host Signing CA Public Key and Vault Client (User) Signing CA Public Key into the necessary config files
    # NOTE: The Add-CAPubKeyToSSHAndSSHDConfig function will NOT do anything if it doesn't need to
    $AddCAPubKeyToSSHAndSSHDConfigSplatParams = @{
        PublicKeyOfCAUsedToSignUserKeysVaultUrl     = "$VaultServerBaseUri/ssh-client-signer/public_key"
        PublicKeyOfCAUsedToSignHostKeysVaultUrl     = "$VaultServerBaseUri/ssh-host-signer/public_key"
        AuthorizedUserPrincipals                    = @($AuthorizedPrincipalString)
        ErrorAction                                 = "Stop"
    }

    try {
        $AddCAPubKeyResult = Add-CAPubKeyToSSHAndSSHDConfig @AddCAPubKeyToSSHAndSSHDConfigSplatParams
    }
    catch {
        Write-Warning "There was a problem with the Add-CAPubKeyToSSHAndSSHDConfig function! The problem is as follows:"
        Write-Warning "$($_ | Out-String)"
        Write-Warning "SSH Cert Authentication may still work..."
    }

    # Finally, figure out the most efficient ssh command to use to remote into the remote host.
    Get-SSHClientAuthSanity -SSHKeyFilePath $NewSSHKeyResult.PublicKeyFilePath -AuthMethod PublicKeyCertificate

    Pop-Location

}

function Install-FeatureDism {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$True)]
        [string]$Feature,   # Microsoft-Hyper-V, Containers, etc

        [Parameter(Mandatory=$False)]
        [switch]$AllowRestarts,

        [Parameter(Mandatory=$False)]
        [string]$ParentFunction
    )

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

    # Check to see if the feature is already installed
    $FeatureCheck = Get-WindowsOptionalFeature -FeatureName $Feature -Online
    if ($FeatureCheck.State -ne "Enabled") {
        if ($ParentFunction) {
            Write-Warning "Please re-run $ParentFunction function AFTER this machine (i.e. $env:ComputerName) has restarted."
        }

        try {
            # Don't allow restart unless -AllowRestarts is explictly provided to this function
            Write-Host "Installing the Feature $Feature..."
            $FeatureInstallResult = Enable-WindowsOptionalFeature -Online -FeatureName $Feature -All -NoRestart -WarningAction SilentlyContinue
            # NOTE: $FeatureInstallResult contains properties [string]Path, [bool]Online, [string]WinPath,
            # [string]SysDrivePath, [bool]RestartNeeded, [string]$LogPath, [string]ScratchDirectory,
            # [string]LogLevel
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            return
        }
    }
    else {
        Write-Warning "The Feature $Feature is already installed! No action taken."
    }

    if ($FeatureInstallResult.RestartNeeded) {
        if ($AllowRestarts) {
            Restart-Computer -Confirm:$false -Force
        }
        else {
            Write-Warning "You must restart in order to complete the Feature $Feature installation!"
        }
    }

    $FeatureInstallResult
}

function Install-HyperVFeatures {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$False)]
        [switch]$AllowRestarts,

        [Parameter(Mandatory=$False)]
        [string]$ParentFunction
    )

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

    $HyperVFeaturesOSAgnostic = $(Get-WindowsOptionalFeature -Online | Where-Object {$_.FeatureName -match "Hyper"}).FeatureName
    
    [System.Collections.ArrayList]$HyperVFeaturesInstallResults = @()
    [System.Collections.ArrayList]$HyperVFeatureInstallFailures = @()
    foreach ($FeatureToInstall in $HyperVFeaturesOSAgnostic) {
        try {
            $HyperVFeatureInstallResult = Install-FeatureDism -Feature $FeatureToInstall -ParentFunction $ParentFunction
            if ($HyperVFeatureInstallResult.RestartNeeded -eq $True) {
                $null = $HyperVFeaturesInstallResults.Add($HyperVFeatureInstallResult)
            }
        }
        catch {
            Write-Error $_
            Write-Warning "The Install-FeatureDism function failed to install the Feature $FeatureToInstall!"
            $null = $HyperVFeatureInstallFailures.Add($FeatureToInstall)
        }
    }

    if ($HyperVFeatureInstallFailures.Count -gt 0) {
        Write-Warning "The following Hyper-V Features failed to install:`n$($HyperVFeatureInstallFailures -join "`n")"
    }

    if ($HyperVFeaturesInstallResults.Count -gt 0 -or $HyperVFeatureInstallFailures.Count -gt 0) {
        if ($AllowRestarts) {
            Restart-Computer -Confirm:$false -Force
        }
        else {
            Write-Warning "You must restart $env:ComputerName before proceeding!"
        }
    }

    if ($HyperVFeaturesInstallResults.Count -eq 0 -and $HyperVFeatureInstallFailures.Count -eq 0) {
        Write-Warning "All Hyper-V features are already installed. No action taken!"
    }
    else {
        [pscustomobject]@{
            InstallResults      = $HyperVFeaturesInstallResults
            InstallFailures     = $HyperVFeatureInstallFailures
        }
    }
}

<#
    .SYNOPSIS
        Manages a HyperV VM.

        This is a refactor of the PowerShell Script used to deploy a MobyLinux VM on Hyper-V during a Docker CE install.
        The refactor was done mostly to fix permissions issues that occur when running Hyper-V on a Guest VM in order
        to deploy a Nested VM, but it also works just fine on baremetal Hyper-V.

    .DESCRIPTION
        Creates/Destroys/Starts/Stops A HyperV VM

        This function is a refactored version of MobyLinux.ps1 that is bundled with a DockerCE install.

        This function deploys newly created VMs to "C:\Users\Public\Documents". This location is hardcoded for now.

    .PARAMETER VmName
        If passed, use this name for the HyperV VM

    .PARAMETER IsoFile
        Path to the ISO image, must be set for Create/ReCreate

    .PARAMETER Create
        Create a HyperV VM

    .PARAMETER Memory
        Memory allocated for the VM at start in MB (optional on Create, default: 2048 MB)

    .PARAMETER CPUs
        CPUs used in the VM (optional on Create, default: min(2, number of CPUs on the host))

    .PARAMETER Destroy
        Remove a HyperV VM

    .PARAMETER KeepVolume
        if passed, will not delete the vmhd on Destroy

    .PARAMETER Start
        Start an existing HyperV VM

    .PARAMETER Stop
        Stop a running HyperV VM

    .EXAMPLE
        Manage-HyperVVM -VMName "TestVM" -SwitchName "ToMgmt" -IsoFile .\mobylinux.iso -VMGen 1 -Create

    .EXAMPLE
        Manage-HyperVVM -VMName "TestVM" -SwitchName "ToMgmt" -VHDPathOverride "C:\Win1016Serv.vhdx" -VMGen 2 -Memory 4096 -Create
#>
function Manage-HyperVVM {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [string]$VmName,

        [Parameter(
            Mandatory=$False,
            ParameterSetName='Create'
        )]
        [string]$IsoFile,

        [Parameter(
            Mandatory=$True,
            ParameterSetName='Create'    
        )]
        [string]$SwitchName,

        [Parameter(
            Mandatory=$False,
            ParameterSetName='Create'    
        )]
        [ValidateSet(1,2)]
        [int]$VMGen = 2,

        [Parameter(
            Mandatory=$False,
            ParameterSetName='Create'
        )]
        [ValidateSet("Heartbeat","Shutdown","TimeSynch","GuestServiceInterface","KeyValueExchange","VSS")]
        [string[]]$PreferredIntegrationServices = @("Heartbeat","Shutdown","TimeSynch","GuestServiceInterface","KeyValueExchange"),

        [Parameter(Mandatory=$False)]
        [string]$VhdPathOverride,

        [Parameter(Mandatory=$False)]
        [switch]$NoVhd,
        
        [Parameter(
            Mandatory=$False,
            ParameterSetName='Create'
        )]
        [switch]$Create,
        
        [Parameter(
            Mandatory=$False,
            ParameterSetName='Create'
        )]
        [int]$CPUs = 1,
        
        [Parameter(
            Mandatory=$False,
            ParameterSetName='Create'
        )]
        [long]$Memory = 2048,
        
        [Parameter(
            Mandatory=$False,
            ParameterSetName='Destroy'
        )]
        [switch]$Destroy,
        
        [Parameter(
            Mandatory=$False,
            ParameterSetName='Destroy'
        )]
        [switch]$KeepVolume,
        
        [Parameter(
            Mandatory=$False,
            ParameterSetName='Start'
        )]
        [switch]$Start,
        
        [Parameter(
            Mandatory=$False,
            ParameterSetName='Stop'
        )]
        [switch]$Stop
    )

    ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####

    # This is only a problem for Windows_Server_2016_14393.0.160715-1616.RS1_RELEASE_SERVER_EVAL_X64FRE_EN-US (technet_official).ISO
    <#
    if ($IsoFile) {
        if ($IsoFile -notmatch "C:\\Users\\Public") {
            Write-Error "The ISO File used to install the new VM's Operating System must be placed somewhere under 'C:\Users\Public' due to permissions issues! Halting!"
            $global:FunctionResult = "1"
            return       
        }
    }
    #>

    # Make sure we stop at Errors unless otherwise explicitly specified
    $ErrorActionPreference = "Stop"
    $ProgressPreference = "SilentlyContinue"

    # Explicitly disable Module autoloading and explicitly import the
    # Modules this script relies on. This is not strictly necessary but
    # good practise as it prevents arbitrary errors
    # More Info: https://blogs.msdn.microsoft.com/timid/2014/09/02/psmoduleautoloadingpreference-and-you/
    $PSModuleAutoloadingPreference = 'None'

    # Check to see if Hyper-V is installed:
    if ($(Get-Module).Name -notcontains "Dism") {
        # Using full path to Dism Module Manifest because sometimes there are issues with just 'Import-Module Dism'
        $DismModuleManifestPaths = $(Get-Module -ListAvailable -Name Dism).Path

        foreach ($MMPath in $DismModuleManifestPaths) {
            try {
                Import-Module $MMPath -ErrorAction Stop
                break
            }
            catch {
                continue
            }
        }
    }
    if ($(Get-Module).Name -notcontains "Dism") {
        Write-Error "Problem importing the Dism PowerShell Module! Halting!"
        $global:FunctionResult = "1"
        return
    }
    
    $HyperVCheck = Get-WindowsOptionalFeature -FeatureName Microsoft-Hyper-V -Online
    if ($HyperVCheck.State -ne "Enabled") {
        Write-Error "Please install Hyper-V before proceeding! Halting!"
        $global:FunctionResult = "1"
        return
    }

    Write-Output "Script started at $(Get-Date -Format "HH:mm:ss.fff")"

    # Explicitly import the Modules we need for this function
    try {
        Import-Module Microsoft.PowerShell.Utility
        Import-Module Microsoft.PowerShell.Management
        Import-Module Hyper-V
        Import-Module NetAdapter
        Import-Module NetTCPIP

        Import-Module PackageManagement
        Import-Module PowerShellGet
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
                throw "There was a problem loading the NTFSSecurity Module! Halting!"
            }
        }
    }
    catch {
        Write-Error $_
        $global:FunctionResult = "1"
        return
    }

    Write-Host "Modules loaded at $(Get-Date -Format "HH:mm:ss.fff")"

    # Hard coded for now
    $global:VhdSize = 60*1024*1024*1024  # 60GB

    ##### END Variable/Parameter Transforms and PreRun Prep #####


    ##### BEGIN Helper Functions #####

    function Get-Vhd-Root {
        if($VhdPathOverride){
            return $VhdPathOverride
        }
        # Default location for VHDs
        $VhdRoot = "$((Hyper-V\Get-VMHost -ComputerName localhost).VirtualHardDiskPath)".TrimEnd("\")

        # Where we put the Nested VM
        return "$VhdRoot\$VmName.vhdx"
    }

    function New-Switch {
        $ipParts = $SwitchSubnetAddress.Split('.')
        [int]$switchIp3 = $null
        [int32]::TryParse($ipParts[3] , [ref]$switchIp3 ) | Out-Null
        $Ip0 = $ipParts[0]
        $Ip1 = $ipParts[1]
        $Ip2 = $ipParts[2]
        $Ip3 = $switchIp3 + 1
        $switchAddress = "$Ip0.$Ip1.$Ip2.$Ip3"
    
        $vmSwitch = Hyper-V\Get-VMSwitch $SwitchName -SwitchType Internal -ea SilentlyContinue
        $vmNetAdapter = Hyper-V\Get-VMNetworkAdapter -ManagementOS -SwitchName $SwitchName -ea SilentlyContinue
        if ($vmSwitch -and $vmNetAdapter) {
            Write-Output "Using existing Switch: $SwitchName"
        } else {
            # There seems to be an issue on builds equal to 10586 (and
            # possibly earlier) with the first VMSwitch being created after
            # Hyper-V install causing an error. So on these builds we create
            # Dummy switch and remove it.
            $buildstr = $(Get-WmiObject win32_operatingsystem).BuildNumber
            $buildNumber = [convert]::ToInt32($buildstr, 10)
            if ($buildNumber -le 10586) {
                Write-Output "Enabled workaround for Build 10586 VMSwitch issue"
    
                $fakeSwitch = Hyper-V\New-VMSwitch "DummyDesperatePoitras" -SwitchType Internal -ea SilentlyContinue
                $fakeSwitch | Hyper-V\Remove-VMSwitch -Confirm:$false -Force -ea SilentlyContinue
            }
    
            Write-Output "Creating Switch: $SwitchName..."
    
            Hyper-V\Remove-VMSwitch $SwitchName -Force -ea SilentlyContinue
            Hyper-V\New-VMSwitch $SwitchName -SwitchType Internal -ea SilentlyContinue | Out-Null
            $vmNetAdapter = Hyper-V\Get-VMNetworkAdapter -ManagementOS -SwitchName $SwitchName
    
            Write-Output "Switch created."
        }
    
        # Make sure there are no lingering net adapter
        $netAdapters = Get-NetAdapter | ? { $_.Name.StartsWith("vEthernet ($SwitchName)") }
        if (($netAdapters).Length -gt 1) {
            Write-Output "Disable and rename invalid NetAdapters"
    
            $now = (Get-Date -Format FileDateTimeUniversal)
            $index = 1
            $invalidNetAdapters =  $netAdapters | ? { $_.DeviceID -ne $vmNetAdapter.DeviceId }
    
            foreach ($netAdapter in $invalidNetAdapters) {
                $netAdapter `
                    | Disable-NetAdapter -Confirm:$false -PassThru `
                    | Rename-NetAdapter -NewName "Broken Docker Adapter ($now) ($index)" `
                    | Out-Null
    
                $index++
            }
        }
    
        # Make sure the Switch has the right IP address
        $networkAdapter = Get-NetAdapter | ? { $_.DeviceID -eq $vmNetAdapter.DeviceId }
        if ($networkAdapter | Get-NetIPAddress -IPAddress $switchAddress -ea SilentlyContinue) {
            $networkAdapter | Disable-NetAdapterBinding -ComponentID ms_server -ea SilentlyContinue
            $networkAdapter | Enable-NetAdapterBinding  -ComponentID ms_server -ea SilentlyContinue
            Write-Output "Using existing Switch IP address"
            return
        }
    
        $networkAdapter | Remove-NetIPAddress -Confirm:$false -ea SilentlyContinue
        $networkAdapter | Set-NetIPInterface -Dhcp Disabled -ea SilentlyContinue
        $networkAdapter | New-NetIPAddress -AddressFamily IPv4 -IPAddress $switchAddress -PrefixLength ($SwitchSubnetMaskSize) -ea Stop | Out-Null
        
        $networkAdapter | Disable-NetAdapterBinding -ComponentID ms_server -ea SilentlyContinue
        $networkAdapter | Enable-NetAdapterBinding  -ComponentID ms_server -ea SilentlyContinue
        Write-Output "Set IP address on switch"
    }
    
    function Remove-Switch {
        Write-Output "Destroying Switch $SwitchName..."
    
        # Let's remove the IP otherwise a nasty bug makes it impossible
        # to recreate the vswitch
        $vmNetAdapter = Hyper-V\Get-VMNetworkAdapter -ManagementOS -SwitchName $SwitchName -ea SilentlyContinue
        if ($vmNetAdapter) {
            $networkAdapter = Get-NetAdapter | ? { $_.DeviceID -eq $vmNetAdapter.DeviceId }
            $networkAdapter | Remove-NetIPAddress -Confirm:$false -ea SilentlyContinue
        }
    
        Hyper-V\Remove-VMSwitch $SwitchName -Force -ea SilentlyContinue
    }

    function New-HyperVVM {
        <#
        if (!(Test-Path $IsoFile)) {
            Fatal "ISO file at $IsoFile does not exist"
        }
        #>

        $CPUs = [Math]::min((Hyper-V\Get-VMHost -ComputerName localhost).LogicalProcessorCount, $CPUs)

        $vm = Hyper-V\Get-VM $VmName -ea SilentlyContinue
        if ($vm) {
            if ($vm.Length -ne 1) {
                Fatal "Multiple VMs exist with the name $VmName. Delete invalid ones and try again."
            }
        }
        else {
            Write-Output "Creating VM $VmName..."
            $vm = Hyper-V\New-VM -Name $VmName -Generation $VMGen -NoVHD
            $vm | Hyper-V\Set-VM -AutomaticStartAction Nothing -AutomaticStopAction ShutDown -CheckpointType Production
        }

        <#
        if ($vm.Generation -ne 2) {
                Fatal "VM $VmName is a Generation $($vm.Generation) VM. It should be a Generation 2."
        }
        #>

        if ($vm.State -ne "Off") {
            Write-Output "VM $VmName is $($vm.State). Cannot change its settings."
            return
        }

        Write-Output "Setting CPUs to $CPUs and Memory to $Memory MB"
        $Memory = ([Math]::min($Memory, ($vm | Hyper-V\Get-VMMemory).MaximumPerNumaNode))
        $vm | Hyper-V\Set-VM -MemoryStartupBytes ($Memory*1024*1024) -ProcessorCount $CPUs -StaticMemory

        if (!$NoVhd) {
            $VmVhdFile = Get-Vhd-Root
            $vhd = Get-VHD -Path $VmVhdFile -ea SilentlyContinue
            
            if (!$vhd) {
                Write-Output "Creating dynamic VHD: $VmVhdFile"
                $vhd = New-VHD -ComputerName localhost -Path $VmVhdFile -Dynamic -SizeBytes $global:VhdSize
            }

            ## BEGIN Try and Update Permissions ##
            
            if ($($VMVhdFile -split "\\")[0] -eq $env:SystemDrive) {
                if ($VMVhdFile -match "\\Users\\") {
                    $UserDirPrep = $VMVHdFile -split "\\Users\\"
                    $UserDir = $UserDirPrep[0] + "\Users\" + $($UserDirPrep[1] -split "\\")[0]
                    # We can assume there is at least one folder under $HOME before getting to the .vhd file
                    $DirectoryThatMayNeedPermissionsFixPrep = $UserDir + '\' + $($UserDirPrep[1] -split "\\")[1]
                    
                    # If $DirectoryThatMayNeedPermissionsFixPrep isn't a SpecialFolder typically found under $HOME
                    # then assume we can mess with permissions. Else, target one directory deeper.
                    $HomeDirCount = $($HOME -split '\\').Count
                    $SpecialFoldersDirectlyUnderHomePrep = [enum]::GetNames('System.Environment+SpecialFolder') | foreach {
                        [environment]::GetFolderPath($_)
                    } | Sort-Object | Get-Unique | Where-Object {$_ -match "$($HOME -replace '\\','\\')"}
                    $SpecialFoldersDirectlyUnderHome = $SpecialFoldersDirectlyUnderHomePrep | Where-Object {$($_ -split '\\').Count -eq $HomeDirCount+1}

                    if ($SpecialFoldersDirectlyUnderHome -notcontains $DirectoryThatMayNeedPermissionsFixPrep) {
                        $DirectoryThatMayNeedPermissionsFix = $DirectoryThatMayNeedPermissionsFixPrep
                    }
                    else {
                        # Go one folder deeper...
                        $DirectoryThatMayNeedPermissionsFix = $UserDir + '\' + $($UserDirPrep[1] -split "\\")[1] + '\' + $($UserDirPrep[1] -split "\\")[2]
                    }

                    try {
                        Fix-NTVirtualMachinesPerms -Directorypath $DirectoryThatMayNeedPermissionsFix
                    }
                    catch {
                        Write-Error $_
                        Write-Error "The Fix-NTVirtualMachinesPerms function failed! Halting!"
                        $global:FunctionResult = "1"
                        return
                    }
                }
                else {
                    $DirectoryThatMayNeedPermissionsFix = $VMVhdFile | Split-Path -Parent

                    try {
                        Fix-NTVirtualMachinesPerms -DirectoryPath $DirectoryThatMayNeedPermissionsFix
                    }
                    catch {
                        Write-Error $_
                        Write-Error "The Fix-NTVirtualMachinesPerms function failed! Halting!"
                        $global:FunctionResult = "1"
                        return
                    }
                }
            }
            
            # Also fix permissions on "$env:SystemDrive\Users\Public" and "$env:SystemDrive\ProgramData\Microsoft\Windows\Hyper-V"
            # the because lots of software (like Docker) likes throwing stuff in these locations
            $PublicUserDirectoryPath = "$env:SystemDrive\Users\Public"
            $HyperVConfigDir = "$env:SystemDrive\ProgramData\Microsoft\Windows\Hyper-V"
            [System.Collections.ArrayList]$DirsToPotentiallyFix = @($PublicUserDirectoryPath,$HyperVConfigDir)
            
            foreach ($dir in $DirsToPotentiallyFix) {
                try {
                    Fix-NTVirtualMachinesPerms -DirectoryPath $dir
                }
                catch {
                    Write-Error $_
                    Write-Error "The Fix-NTVirtualMachinesPerms function failed! Halting!"
                    $global:FunctionResult = "1"
                    return
                }
            }

            ## END Try and Update Permissions ##

            if ($vm.HardDrives.Path -ne $VmVhdFile) {
                if ($vm.HardDrives) {
                    Write-Output "Remove existing VHDs"
                    Hyper-V\Remove-VMHardDiskDrive $vm.HardDrives -ea SilentlyContinue
                }

                Write-Output "Attach VHD $VmVhdFile"
                $vm | Hyper-V\Add-VMHardDiskDrive -Path $VmVhdFile
            }
        }

        $vmNetAdapter = $vm | Hyper-V\Get-VMNetworkAdapter
        if (!$vmNetAdapter) {
            Write-Output "Attach Net Adapter"
            $vmNetAdapter = $vm | Hyper-V\Add-VMNetworkAdapter -SwitchName $SwitchName -Passthru
        }

        Write-Output "Connect Switch $SwitchName"
        $vmNetAdapter | Hyper-V\Connect-VMNetworkAdapter -VMSwitch $(Hyper-V\Get-VMSwitch -ComputerName localhost -SwitchName $SwitchName)

        if ($IsoFile) {
            if ($vm.DVDDrives.Path -ne $IsoFile) {
                if ($vm.DVDDrives) {
                    Write-Output "Remove existing DVDs"
                    Hyper-V\Remove-VMDvdDrive $vm.DVDDrives -ea SilentlyContinue
                }

                Write-Output "Attach DVD $IsoFile"
                $vm | Hyper-V\Add-VMDvdDrive -Path $IsoFile
            }
        }

        #$iso = $vm | Hyper-V\Get-VMFirmware | select -ExpandProperty BootOrder | ? { $_.FirmwarePath.EndsWith("Scsi(0,1)") }
        #$vm | Hyper-V\Set-VMFirmware -EnableSecureBoot Off -FirstBootDevice $iso
        ##$vm | Hyper-V\Set-VMComPort -number 1 -Path "\\.\pipe\docker$VmName-com1"

        # Enable only prefered VM integration services
        [System.Collections.ArrayList]$intSvc = @()
        foreach ($integrationService in $PreferredIntegrationServices) {
            switch ($integrationService) {
                'Heartbeat'             { $null = $intSvc.Add("Microsoft:$($vm.Id)\84EAAE65-2F2E-45F5-9BB5-0E857DC8EB47") }
                'Shutdown'              { $null = $intSvc.Add("Microsoft:$($vm.Id)\9F8233AC-BE49-4C79-8EE3-E7E1985B2077") }
                'TimeSynch'             { $null = $intSvc.Add("Microsoft:$($vm.Id)\2497F4DE-E9FA-4204-80E4-4B75C46419C0") }
                'GuestServiceInterface' { $null = $intSvc.Add("Microsoft:$($vm.Id)\6C09BB55-D683-4DA0-8931-C9BF705F6480") }
                'KeyValueExchange'      { $null = $intSvc.Add("Microsoft:$($vm.Id)\2A34B1C2-FD73-4043-8A5B-DD2159BC743F") }
                'VSS'                   { $null = $intSvc.Add("Microsoft:$($vm.Id)\5CED1297-4598-4915-A5FC-AD21BB4D02A4") }
            }
        }
        
        $vm | Hyper-V\Get-VMIntegrationService | ForEach-Object {
            if ($intSvc -contains $_.Id) {
                Hyper-V\Enable-VMIntegrationService $_
                Write-Output "Enabled $($_.Name)"
            }
            else {
                Hyper-V\Disable-VMIntegrationService $_
                Write-Output "Disabled $($_.Name)"
            }
        }
        #$vm | Hyper-V\Disable-VMConsoleSupport
        $vm | Hyper-V\Enable-VMConsoleSupport

        Write-Output "VM created."
    }

    function Remove-HyperVVM {
        Write-Output "Removing VM $VmName..."

        Hyper-V\Remove-VM $VmName -Force -ea SilentlyContinue

        if (!$KeepVolume) {
            $VmVhdFile = Get-Vhd-Root
            Write-Output "Delete VHD $VmVhdFile"
            Remove-Item $VmVhdFile -ea SilentlyContinue
        }
    }

    function Start-HyperVVM {
        Write-Output "Starting VM $VmName..."
        Hyper-V\Start-VM -VMName $VmName
    }

    function Stop-HyperVVM {
        $vms = Hyper-V\Get-VM $VmName -ea SilentlyContinue
        if (!$vms) {
            Write-Output "VM $VmName does not exist"
            return
        }

        foreach ($vm in $vms) {
            Stop-VM-Force($vm)
        }
    }

    function Stop-VM-Force {
        Param($vm)

        if ($vm.State -eq 'Off') {
            Write-Output "VM $VmName is stopped"
            return
        }

        $code = {
            Param($vmId) # Passing the $vm ref is not possible because it will be disposed already

            $vm = Hyper-V\Get-VM -Id $vmId -ea SilentlyContinue
            if (!$vm) {
                Write-Output "VM with Id $vmId does not exist"
                return
            }

            $shutdownService = $vm | Hyper-V\Get-VMIntegrationService -Name Shutdown -ea SilentlyContinue
            if ($shutdownService -and $shutdownService.PrimaryOperationalStatus -eq 'Ok') {
                Write-Output "Shutdown VM $VmName..."
                $vm | Hyper-V\Stop-VM -Confirm:$false -Force -ea SilentlyContinue
                if ($vm.State -eq 'Off') {
                    return
                }
            }

            Write-Output "Turn Off VM $VmName..."
            $vm | Hyper-V\Stop-VM -Confirm:$false -TurnOff -Force -ea SilentlyContinue
        }

        Write-Output "Stopping VM $VmName..."
        $job = Start-Job -ScriptBlock $code -ArgumentList $vm.VMId.Guid
        if (Wait-Job $job -Timeout 20) { Receive-Job $job }
        Remove-Job -Force $job -ea SilentlyContinue

        if ($vm.State -eq 'Off') {
            Write-Output "VM $VmName is stopped"
            return
        }

        # If the VM cannot be stopped properly after the timeout
        # then we have to kill the process and wait till the state changes to "Off"
        for ($count = 1; $count -le 10; $count++) {
            $ProcessID = (Get-WmiObject -Namespace root\virtualization\v2 -Class Msvm_ComputerSystem -Filter "Name = '$($vm.Id.Guid)'").ProcessID
            if (!$ProcessID) {
                Write-Output "VM $VmName killed. Waiting for state to change"
                for ($count = 1; $count -le 20; $count++) {
                    if ($vm.State -eq 'Off') {
                        Write-Output "Killed VM $VmName is off"
                        #Remove-Switch
                        $oldKeepVolumeValue = $KeepVolume
                        $KeepVolume = $true
                        Remove-HyperVVM
                        $KeepVolume = $oldKeepVolumeValue
                        return
                    }
                    Start-Sleep -Seconds 1
                }
                Fatal "Killed VM $VmName did not stop"
            }

            Write-Output "Kill VM $VmName process..."
            Stop-Process $ProcessID -Force -Confirm:$false -ea SilentlyContinue
            Start-Sleep -Seconds 1
        }

        Fatal "Couldn't stop VM $VmName"
    }

    function Fatal {
        throw "$args"
        return 1
    }

    # Main entry point
    Try {
        Switch ($PSBoundParameters.GetEnumerator().Where({$_.Value -eq $true}).Key) {
            'Stop'     { Stop-HyperVVM }
            'Destroy'  { Stop-HyperVVM; Remove-HyperVVM }
            'Create'   { New-HyperVVM }
            'Start'    { Start-HyperVVM }
        }
    } Catch {
        throw
        return 1
    }
}

# This function ties together info about a particular Hyper-V vSwitch
# by collecting info using Get-VMNetworkAdapter, Get-VMSwitch, Get-NetAdapter,
# and Get-NetIPAddress
function Get-vSwitchAllRelatedInfo {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$False)]
        [string]$vSwitchName,

        [Parameter(Mandatory=$False)]
        [string]$InterfaceAlias,

        [Parameter(Mandatory=$False)]
        [string]$IPAddress,

        [Parameter(Mandatory=$False)]
        [string]$MacAddress,

        [Parameter(Mandatory=$False)]
        [string]$DeviceId
    )

    ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####

    $BoundParametersDictionary = $PSCmdlet.MyInvocation.BoundParameters

    if (!$vSwitchName -and !$InterfaceAlias -and !$IPAddress -and !$MacAddress -and !$DeviceId) {
        Write-Error "The Get-vSwitchRelationship function requires at least one of the following parameters: -vSwitchName, -InterfaceAlias, -IPAddress, -MacAddress, -DeviceId or any combination thereof! Halting!"
        $global:FunctionResult = "1"
        return
    }

    if ($IPAddress) {
        if (![bool]$(TestIsValidIPAddress -IPAddress $IPAddress)) {
            Write-Error "$IPAddress is NOT a valid IPv4 IP Address! Halting!"
            $global:FunctionResult = "1"
            return
        }
    }

    if ($DeviceId) {
        # The $DeviceId might have prefix '{' and trailing '}', so get rid of them
        if ($DeviceId.Substring(0,1) -eq '{') {
            $DeviceId = $DeviceId.TrimStart('{')
        }
        if ($DeviceId[-1] -eq '}') {
            $DeviceId = $DeviceId.TrimEnd('}')
        }
    }

    if ($MacAddress) {
        # Standardize MacAddress string format with dashes
        if ($MacAddress -notmatch "-") {
            $MacAddress = $($MacAddress -split "([\w]{2})" | Where-Object {$_ -match "[\w]"}) -join '-'
        }
    }

    ##### END Variable/Parameter Transforms and PreRun Prep #####


    ##### BEGIN Main Body #####

    # Try to get $DetailedvSwitchInfo...

    [System.Collections.ArrayList]$DetailedvSwitchInfoPSObjects = @()

    if ($BoundParametersDictionary["vSwitchName"]) {
        try {
            $DetailedvSwitchInfoViavSwitchName = Get-VMNetworkAdapter -ManagementOS | Where-Object {$_.SwitchName -eq $vSwitchName}
            if (!$DetailedvSwitchInfoViavSwitchName) {
                throw "Unable to find a vSwitch with the name $vSwitchName! Halting!"
            }
            if ($DetailedvSwitchInfoViavSwitchName.Count -gt 1) {
                throw "Multiple vSwitches with the same name (i.e. $vSwitchName)! Halting!"
            }

            $BasicvSwitchInfo = Get-VMSwitch -Name $DetailedvSwitchInfoViavSwitchName.SwitchName
            $NetworkAdapterInfo = Get-NetAdapter | Where-Object {$($_.MacAddress -replace '-','') -eq $DetailedvSwitchInfoViavSwitchName.MacAddress}
            $IPAddressInfo = Get-NetIPAddress -AddressFamily IPv4 -InterfaceAlias $NetworkAdapterInfo.InterfaceAlias

            $vSwitchNamePSObject = @{
                ParameterUsed           = "vSwitchName"
                DetailedvSwitchInfo     = $DetailedvSwitchInfoViavSwitchName
            }

            $null = $DetailedvSwitchInfoPSObjects.Add($vSwitchNamePSObject)
        }
        catch {
            if (!$DetailedvSwitchInfoViavSwitchName -and $($BoundParametersDictionary.GetEnumerator()).Count -gt 1) {
                Write-Warning "Unable to find a vSwitch with the name $vSwitchName!"
                $BadvSwitchNameProvided = $True
            }
            else {
                Write-Error $_
                $global:FunctionResult = "1"
                return
            }
        }
    }

    if ($BoundParametersDictionary["InterfaceAlias"]) {
        try {
            $NetworkAdapterInfo = Get-NetAdapter -InterfaceAlias $InterfaceAlias -ErrorAction Stop
            $IPAddressInfo = Get-NetIPAddress -AddressFamily IPv4 -InterfaceAlias $NetworkAdapterInfo.InterfaceAlias

            $PotentialvSwitchesDetailedInfo = Get-VMNetworkAdapter -ManagementOS
            $MacAddressPrep = $NetworkAdapterInfo.MacAddress -replace '-',''
            $DetailedvSwitchInfoViaIPAddress = $PotentialvSwitchesDetailedInfo | Where-Object {$_.MacAddress -eq $MacAddressPrep}
            $BasicvSwitchInfo = Get-VMSwitch -Name $DetailedvSwitchInfoViaIPAddress.SwitchName

            if (!$DetailedvSwitchInfoViaIPAddress) {
                throw
            }
            else {
                $InterfaceAliasPSObject = @{
                    ParameterUsed           = "InterfaceAlias"
                    DetailedvSwitchInfo     = $DetailedvSwitchInfoViaIPAddress
                }

                $null = $DetailedvSwitchInfoPSObjects.Add($InterfaceAliasPSObject)
            }
        }
        catch {
            if (!$DetailedvSwitchInfoViaIPAddress -and $($BoundParametersDictionary.GetEnumerator()).Count -gt 1) {
                Write-Warning "Unable to find a Network Adapter with the InterfaceAlias name $InterfaceAlias!"
                $BadvInterfaceAliasProvided = $True
            }
            else {
                Write-Error $_
                $global:FunctionResult = "1"
                return
            }
        }
    }

    if ($BoundParametersDictionary["IPAddress"]) {
        if (!$DetailedvSwitchInfo) {
            try {
                $PotentialvSwitchesDetailedInfo = Get-VMNetworkAdapter -ManagementOS

                $IPAddressInfo = Get-NetIPAddress -AddressFamily IPv4 -IPAddress $IPAddress -ErrorAction SilentlyContinue -ErrorVariable GNIPErr
                if (!$IPAddressInfo -or $GNIPErr) {throw}
                $NetworkAdapterInfo = Get-NetAdapter -InterfaceAlias $IPAddressInfo.InterfaceAlias
                $MacAddressPrep = $NetworkAdapterInfo.MacAddress -replace '-',''

                $DetailedvSwitchInfoViaIPAddress = $PotentialvSwitchesDetailedInfo | Where-Object {$_.MacAddress -eq $MacAddressPrep}
                $BasicvSwitchInfo = Get-VMSwitch -Name $DetailedvSwitchInfoViaIPAddress.SwitchName

                if (!$DetailedvSwitchInfoViaIPAddress) {
                    throw
                }
                else {
                    $IPAddressPSObject = @{
                        ParameterUsed           = "IPAddress"
                        DetailedvSwitchInfo     = $DetailedvSwitchInfoViaIPAddress
                    }
    
                    $null = $DetailedvSwitchInfoPSObjects.Add($IPAddressPSObject)
                }
            }
            catch {
                if ($($BoundParametersDictionary.GetEnumerator()).Count -gt 1) {
                    Write-Warning "Unable to find a vSwitch with the IP Address $IPAddress!"
                    $BadIPAddressProvided = $True
                }
                else {
                    Write-Error "Unable to find a vSwitch with the IP Address $IPAddress! Halting!"
                    $global:FunctionResult = "1"
                    return
                }
            }
        }
    }

    if ($BoundParametersDictionary["DeviceId"]) {
        if(!$DetailedvSwitchInfo) {
            try {
                $DetailedvSwitchInfoViaDeviceId = Get-VMNetworkAdapter -ManagementOS | Where-Object {$_.DeviceId -eq "{$DeviceId}"}
                $BasicvSwitchInfo = Get-VMSwitch -Name $DetailedvSwitchInfoViaDeviceId.SwitchName
                $NetworkAdapterInfo = Get-NetAdapter | Where-Object {$($_.MacAddress -replace '-','') -eq $DetailedvSwitchInfoViaDeviceId.MacAddress}
                $IPAddressInfo = Get-NetIPAddress -AddressFamily IPv4 -InterfaceAlias $NetworkAdapterInfo.InterfaceAlias

                if (!$DetailedvSwitchInfoViaDeviceId) {
                    throw
                }
                else {
                    $DeviceIdPSObject = @{
                        ParameterUsed           = "DeviceId"
                        DetailedvSwitchInfo     = $DetailedvSwitchInfoViaDeviceId
                    }
    
                    $null = $DetailedvSwitchInfoPSObjects.Add($DeviceIdPSObject)
                }
            }
            catch {
                if ($($BoundParametersDictionary.GetEnumerator()).Count -gt 1) {
                    Write-Warning "Unable to find a Hyper-V vSwitch with a DeviceId matching $DeviceId!"
                    $BadDeviceIdProvided = $True
                }
                else {
                    Write-Error "Unable to find a Hyper-V vSwitch with a DeviceId matching $DeviceId! Halting!"
                    $global:FunctionResult = "1"
                    return
                }
            }
        }
    }

    if ($BoundParametersDictionary["MacAddress"]) {
        if (!$DetailedvSwitchInfo) {
            try {
                $DetailedvSwitchInfoViaMacAddress = Get-VMNetworkAdapter -ManagementOS | Where-Object {$_.MacAddress -eq $($MacAddress -replace '-','')}
                $BasicvSwitchInfo = Get-VMSwitch -Name $DetailedvSwitchInfoViaMacAddress.SwitchName
                $NetworkAdapterInfo = Get-NetAdapter | Where-Object {$($_.MacAddress -replace '-','') -eq $DetailedvSwitchInfoViaMacAddress.MacAddress}
                $IPAddressInfo = Get-NetIPAddress -AddressFamily IPv4 -InterfaceAlias $NetworkAdapterInfo.InterfaceAlias

                if (!$DetailedvSwitchInfoViaMacAddress) {
                    throw
                }
                else {
                    $MacAddressPSObject = @{
                        ParameterUsed           = "MacAddress"
                        DetailedvSwitchInfo     = $DetailedvSwitchInfoViaMacAddress
                    }
    
                    $null = $DetailedvSwitchInfoPSObjects.Add($MacAddressPSObject)
                }
            }
            catch {
                if ($($BoundParametersDictionary.GetEnumerator()).Count -gt 1) {
                    Write-Warning "Unable to find a Hyper-V vSwitch with a MacAddress matching $($BoundParametersDictionary["MacAddress"])! Halting!"
                    $BadMacAddressProvided = $True
                }
                else {
                    Write-Error "Unable to find a Hyper-V vSwitch with a MacAddress matching $($BoundParametersDictionary["MacAddress"])! Halting!"
                    $global:FunctionResult = "1"
                    return
                }
            }
        }
    }

    # If we still DO NOT have $DetailedvSwitchInfoViaXXXXX one way or another, then halt
    if ($DetailedvSwitchInfoPSObjects.Count -eq 0) {
        Write-Error "Unable to find a Device using any of the parameters provided! Halting!"
        $global:FunctionResult = "1"
        return
    }

    # Start comparing each of the $DetailedvSwitchInfoPSObjects.DetailedvSwitchInfo objects to see
    # which $DetailedvSwitchInfoPSObjects.ParameterUsed get consensus for the the proper target Device.
    # Group by MacAddress and select the highest Count
    $GroupByMacAddress = $DetailedvSwitchInfoPSObjects.DetailedvSwitchInfo | Group-Object -Property MacAddress
    # It's possible that the number of parameters referencing one device equal the number of parameters that
    # reference another device. If that happens, we need to ask the user which one they want.
    if ($GroupByMacAddress.Count -gt 1) {
        if ($($GroupByMacAddress | Select-Object -ExpandProperty Count | Sort-Object | Get-Unique).Count -eq 1) {
            Write-Warning "Unable to get consensus on which Device should be targeted!"
            
            [System.Collections.ArrayList]$DeviceOptionsPSObjects = @()
            foreach ($item in $($GroupByMacAddress.Group | Sort-Object | Get-Unique)) {
                $SwitchName = $item.SwitchName
                $NetAdapterInfo = Get-NetAdapter | Where-Object {$($_.MacAddress -replace '-','') -eq $item.MacAddress}
                $IPInfo = Get-NetIPAddress -AddressFamily IPv4 -InterfaceAlias $NetAdapterInfo.InterfaceAlias

                $OptionPSObject = [pscustomobject]@{
                    SwitchName         = $SwitchName
                    InterfaceAlias     = $NetAdapterInfo.InterfaceAlias
                    IPAddress          = $IPInfo.IPAddress
                    MacAddress         = $item.MacAddress
                }

                $null = $DeviceOptionsPSObjects.Add($OptionPSObject)
            }

            Write-Host "`nPotential matching Devices are as follows:`n"
            for ($i=0; $i -lt $DeviceOptionsPSObjects.Count; $i++) {
                $WriteHostString = "$i) vSwitchName: $($DeviceOptionsPSObjects[$i].SwitchName); " +
                "NetworkAdapterAlias: $($DeviceOptionsPSObjects[$i].InterfaceAlias); " +
                "IPAddress: $($DeviceOptionsPSObjects[$i].IPAddress); " +
                "MacAddress: $($DeviceOptionsPSObjects[$i].MacAddress)"
                Write-Host $WriteHostString
            }
            
            $ValidChoiceNumbers = 0..$($DeviceOptionsPSObjects.Count-1)
            Write-Host ""
            $ChoiceNumber = Read-Host -Prompt "Please enter the number that corresponds to the Device you would like to gather information about. [$($ValidChoiceNumbers -join '|')]"
            while ($ValidChoiceNumbers -notcontains $ChoiceNumber) {
                Write-Host "$ChoiceNumber is NOT a valid choice number! Valid options are: $($ValidChoiceNumbers -join ', ')"
                $ChoiceNumber = Read-Host -Prompt "Please enter the number that corresponds to the Device you would like to gather information about. [$($ValidChoiceNumbers -join '|')]"
            }

            $MacAddressThatAppearsMostOften = $DeviceOptionsPSObjects[$ChoiceNumber].MacAddress
        }
    }
    else {
        $MacAddressThatAppearsMostOften = $($GroupByMacAddress | Sort-Object -Property Count)[-1].Name
    }

    [Array]$FinalDetailedvSwitchInfoPrep = $DetailedvSwitchInfoPSObjects.DetailedvSwitchInfo | Where-Object {$_.MacAddress -eq $MacAddressThatAppearsMostOften}
    # Just choose one to use since they're all the same...
    $FinalDetailedvSwitchInfo = $FinalDetailedvSwitchInfoPrep[0]
    $FinalBasicvSwitchInfo = Get-VMSwitch -Name $FinalDetailedvSwitchInfo.SwitchName
    $FinalNetworkAdapterInfo = Get-NetAdapter | Where-Object {$($_.MacAddress -replace '-','') -eq $FinalDetailedvSwitchInfo.MacAddress}
    $FinalIPAddressInfo = Get-NetIPAddress -AddressFamily IPv4 -InterfaceAlias $FinalNetworkAdapterInfo.InterfaceAlias

    # Describe Parameters that WERE used in Final Output and Parameters that were IGNORED in Final Output
    [System.Collections.ArrayList][Array]$ParametersUsedToGenerateOutput = $($DetailedvSwitchInfoPSObjects | Where-Object {$_.DetailedvSwitchInfo.MacAddress -eq $MacAddressThatAppearsMostOften}).ParameterUsed
    [System.Collections.ArrayList]$ParametersIgnoredToGenerateOutput = @()
    $($DetailedvSwitchInfoPSObjects | Where-Object {$_.DetailedvSwitchInfo.MacAddress -ne $MacAddressThatAppearsMostOften}).ParameterUsed | foreach {
        if ($_ -ne $null) {
            $null = $ParametersIgnoredToGenerateOutput.Add($_)
        }
    }
    
    if ($BadvSwitchNameProvided) {
        $null = $ParametersIgnoredToGenerateOutput.Add("vSwitchName")
    }
    if ($BadvInterfaceAliasProvided) {
        $null = $ParametersIgnoredToGenerateOutput.Add("InterfaceAlias")
    }
    if ($BadIPAddressProvided) {
        $null = $ParametersIgnoredToGenerateOutput.Add("IPAddress")
    }
    if ($BadDeviceIdProvided) {
        $null = $ParametersIgnoredToGenerateOutput.Add("DeviceId")
    }
    if ($BadMacAddressProvided) {
        $null = $ParametersIgnoredToGenerateOutput.Add("MacAddress")
    }

    [pscustomobject]@{
        MacAddress                          = $FinalDetailedvSwitchInfo.MacAddress
        BasicvSwitchInfo                    = $FinalBasicvSwitchInfo
        DetailedvSwitchInfo                 = $FinalDetailedvSwitchInfo
        NetworkAdapterInfo                  = $FinalNetworkAdapterInfo
        IPAddressInfo                       = $FinalIPAddressInfo
        ParametersUsedToGenerateOutput      = $ParametersUsedToGenerateOutput
        ParametersIgnoredToGenerateOutput   = $ParametersIgnoredToGenerateOutput
        NonExistentvSwitchNameProvided      = if ($BadvSwitchNameProvided) {$True} else {$False}
        NonExistentIPAddressProvided        = if ($BadIPAddressProvided) {$True} else {$False}
        NonExistentMacAddressProvided       = if ($BadMacAddressProvided) {$True} else {$False}
        NonExistentDeviceIdProvided         = if ($BadDeviceIdProvided) {$True} else {$False}
    }

    ##### END Main Body #####
    #>
}

<#
    This Fix-NTVirtualMachinesPerms function is specifically for Vagrant using Hyper-V.
    The function uses the NTFSSecurity Module to set "ReadAndExecute, Synchronize" permissions
    for the "NT VIRTUAL MACHINE\Virtual Machines" account on:
        - The specified $Directory,
        - All child items of $Directory via "ThisFolderSubFoldersAndFiles"; and
        - All Parent Directories of $Directory via "ThisFolderOnly" up to the root drive.
#>
function Fix-NTVirtualMachinesPerms {
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

# Downloads a Vagrant Box (.box file) to the specified $DownloadDirectory
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

function Deploy-HyperVVagrantBoxManually {
    [CmdletBinding(DefaultParameterSetName='ExternalNetworkVM')]
    Param(
        [Parameter(Mandatory=$True)]
        [ValidatePattern("[\w]+\/[\w]+")]
        [string]$VagrantBox,

        [Parameter(Mandatory=$True)]
        [ValidateSet("hyperv")]
        [string]$VagrantProvider,

        [Parameter(Mandatory=$True)]
        [string]$VMName,

        [Parameter(Mandatory=$True)]
        [string]$VMDestinationDirectory,

        [Parameter(Mandatory=$False)]
        [string]$TemporaryDownloadDirectory = "$HOME\Downloads",

        [Parameter(Mandatory=$False)]
        [switch]$AllowRestarts,

        [Parameter(Mandatory=$False)]
        [switch]$SkipPreDownloadCheck,

        [Parameter(Mandatory=$False)]
        [switch]$SkipHyperVInstallCheck,

        [Parameter(Mandatory=$False)]
        [ValidateSet("Vagrant")]
        [string]$Repository
    )

    #region >> Variable/Parameter Transforms and PreRun Prep

    if (!$SkipHyperVInstallCheck) {
        # Check to Make Sure Hyper-V is installed
        try {
            $HyperVFeaturesInstallResults = Install-HyperVFeatures -ParentFunction $MyInvocation.MyCommand.Name
        }
        catch {
            Write-Error $_
            Write-Error "The Install-HyperVFeatures function (as executed by the $($MyInvocation.MyCommand.Name) function) failed! Halting!"
            $global:FunctionResult = "1"
            return
        }
        try {
            $InstallContainersFeatureDismResult = Install-FeatureDism -Feature Containers -ParentFunction $MyInvocation.MyCommand.Name
        }
        catch {
            Write-Error $_
            Write-Error "The Install-FeatureDism function (as executed by the $($MyInvocation.MyCommand.Name) function) failed! Halting!"
            $global:FunctionResult = "1"
            return
        }

        if ($HyperVFeaturesInstallResults.InstallResults.Count -gt 0 -or $InstallContainersFeatureDismResult.RestartNeeded) {
            if (!$AllowRestarts) {
                Write-Warning "You must restart $env:ComputerName before proceeding! Halting!"
                Write-Output "RestartNeeded"
                $global:FunctionResult = "1"
                return
            }
            else {
                Restart-Computer -Confirm:$False -Force
            }
        }
    }

    if ($($VMDestinationDirectory | Split-Path -Leaf) -eq $VMName) {
        $VMDestinationDirectory = $VMDestinationDirectory | Split-Path -Parent
    }

    # Set some other variables that we will need
    $NextHop = $(Get-NetRoute -AddressFamily IPv4 | Where-Object {$_.NextHop -ne "0.0.0.0"} | Sort-Object RouteMetric)[0].NextHop
    $PrimaryIP = $(Find-NetRoute -RemoteIPAddress $NextHop | Where-Object {$($_ | Get-Member).Name -contains "IPAddress"}).IPAddress
    $NicInfo = Get-NetIPAddress -IPAddress $PrimaryIP
    $NicAdapter = Get-NetAdapter -InterfaceAlias $NicInfo.InterfaceAlias

    if ([Environment]::OSVersion.Version -lt [version]"10.0.17063") {
        if (![bool]$(Get-Command bsdtar -ErrorAction SilentlyContinue)) {
            # Download bsdtar from latest MSYS2 available on pldmgg github
            $WindowsNativeLinuxUtilsZipUrl = "https://github.com/pldmgg/WindowsNativeLinuxUtils/raw/master/MSYS2_20161025/bsdtar.zip"
            Invoke-WebRequest -Uri $WindowsNativeLinuxUtilsZipUrl -OutFile "$HOME\Downloads\bsdtar.zip"
            Expand-Archive -Path "$HOME\Downloads\bsdtar.zip" -DestinationPath "$HOME\Downloads" -Force
            $BsdTarDirectory = "$HOME\Downloads\bsdtar"

            if ($($env:Path -split ";") -notcontains $BsdTarDirectory) {
                if ($env:Path[-1] -eq ";") {
                    $env:Path = "$env:Path$BsdTarDirectory"
                }
                else {
                    $env:Path = "$env:Path;$BsdTarDirectory"
                }
            }
        }

        $TarCmd = "bsdtar"
    }
    else {
        $TarCmd = "tar"
    }

    #endregion >> Variable/Parameter Transforms and PreRun Prep


    #region >> Main Body

    $GetVagrantBoxSplatParams = @{
        VagrantBox          = $VagrantBox
        VagrantProvider     = $VagrantProvider
        DownloadDirectory   = $TemporaryDownloadDirectory
        ErrorAction         = "SilentlyContinue"
        ErrorVariable       = "GVBMDErr"
    }
    if ($Repository) {
        $GetVagrantBoxSplatParams.Add("Repository",$Repository)
    }

    try {
        $DownloadedBoxFilePath = Get-VagrantBoxManualDownload @GetVagrantBoxSplatParams
        if (!$DownloadedBoxFilePath) {throw "The Get-VagrantBoxManualDownload function failed! Halting!"}
    }
    catch {
        Write-Error $_
        Write-Host "Errors for the Get-VagrantBoxManualDownload function are as follows:"
        Write-Error $($GVBMDErr | Out-String)
        if ($($_ | Out-String) -eq $null -and $($GVBMDErr | Out-String) -eq $null) {
            Write-Error "The Get-VagrantBoxManualDownload function failed to download the .box file!"
        }
        $global:FunctionResult = "1"
        return
    }

    $BoxFilePath = $DownloadedBoxFilePath

    $VMs = Get-VM
    $NewVMName = NewUniqueString -ArrayOfStrings $VMs.Name -PossibleNewUniqueString $VMName

    # Extract the .box File
    $DownloadedVMDir = "$TemporaryDownloadDirectory\$NewVMName"
    if (!$(Test-Path $DownloadedVMDir)) {
        $null = New-Item -ItemType Directory -Path $DownloadedVMDir
    }
    Push-Location $DownloadedVMDir
    try {
        $null = & $TarCmd -xzvf $BoxFilePath 2>&1
    }
    catch {
        Write-Error $_
        Remove-Item $BoxFilePath -Force
        $global:FunctionResult = "1"
        return
    }
    Pop-Location

    try {
        $VMFinalLocationDir = "$VMDestinationDirectory\$NewVMName"
        
        if (!$(Test-Path $VMDestinationDirectory)) {
            $null = New-Item -ItemType Directory -Path $VMDestinationDirectory
        }
        if (Test-Path $VMFinalLocationDir) {
            throw "The directory '$VMFinalLocationDir' already exists! Do you already have a VM deployed with the same name? Halting!"
        }
        Move-Item -Path $DownloadedVMDir -Destination $VMDestinationDirectory -ErrorAction Stop

        # Determine the External vSwitch that is associated with the Host Machine's Primary IP
        $ExternalvSwitches = Get-VMSwitch -SwitchType External
        if ($ExternalvSwitches.Count -gt 1) {
            $NextHop = $(Get-NetRoute -AddressFamily IPv4 | Where-Object {$_.NextHop -ne "0.0.0.0"} | Sort-Object RouteMetric)[0].NextHop
            $PrimaryIP = $(Find-NetRoute -RemoteIPAddress $NextHop | Where-Object {$($_ | Get-Member).Name -contains "IPAddress"}).IPAddress
            $NicInfo = Get-NetIPAddress -IPAddress $PrimaryIP
            $NicAdapter = Get-NetAdapter -InterfaceAlias $NicInfo.InterfaceAlias

            foreach ($vSwitchName in $ExternalvSwitches.Name) {
                $AllRelatedvSwitchInfo = Get-vSwitchAllRelatedInfo -vSwitchName $vSwitchName -WarningAction SilentlyContinue
                if ($($NicAdapter.MacAddress -replace "-","") -eq $AllRelatedvSwitchInfo.MacAddress) {
                    $vSwitchToUse = $AllRelatedvSwitchInfo.BasicvSwitchInfo
                }
            }
        }
        elseif ($ExternalvSwitches.Count -eq 0) {
            $null = New-VMSwitch -Name "ToExternal" -NetAdapterName $NicInfo.InterfaceAlias
            $ExternalSwitchCreated = $True
            $vSwitchToUse = Get-VMSwitch -Name "ToExternal"
        }
        else {
            $vSwitchToUse = $ExternalvSwitches[0]
        }

        # Instead of actually importing the VM, it's easier (and more reliable) to just create a new one using the existing
        # .vhd/.vhdx so we don't have to deal with potential Hyper-V Version Incompatibilities

        $SwitchName = $vSwitchToUse.Name
        $VMGen = 1
        $Memory = 1024
        $CPUs = 1

        # Create the NEW VM
        $NewTempVMParams = @{
            VMName              = $NewVMName
            SwitchName          = $SwitchName
            VMGen               = $VMGen
            Memory              = $Memory
            CPUs                = $CPUs
            VhdPathOverride     = $(Get-ChildItem -Path $VMFinalLocationDir -Recurse -File | Where-Object {$_ -match "\.vhd$|\.vhdx$"})[0].FullName
        }
        Write-Host "Creating VM..."
        $CreateVMOutput = Manage-HyperVVM @NewTempVMParams -Create
        #Fix-NTVirtualMachinesPerms -DirectoryPath $VMDestinationDirectory
        Write-Host "Starting VM..."
        #Start-VM -Name $NewVMName
        $StartVMOutput = Manage-HyperVVM -VMName $NewVMName -Start
    }
    catch {
        Write-Error $_
        
        # Cleanup
        Remove-Item $BoxFilePath -Force
        Remove-Item $DownloadedVMDir -Recurse -Force
        
        if ($(Get-VM).Name -contains $NewVMName) {
            $null = Manage-HyperVVM -VMName $NewVMname -Destroy

            if (Test-Path $VMFinalLocationDir) {
                Remove-Item $VMFinalLocationDir -Recurse -Force
            }
        }
        if ($ExternalSwitchCreated) {
            Remove-VMSwitch "ToExternal" -Force -ErrorAction SilentlyContinue
        }

        $global:FunctionResult = "1"
        return
    }

    $NewVMIP = $(Get-VM -Name $NewVMName).NetworkAdapters.IPAddresses | Where-Object {TestIsValidIPAddress -IPAddress $_}
    $Counter = 0
    while (!$NewVMIP -or $Counter -le 5) {
        Write-Host "Waiting for VM $NewVMName to report its IP Address..."
        Start-Sleep -Seconds 10
        $NewVMIP = $(Get-VM -Name $NewVMName).NetworkAdapters.IPAddresses | Where-Object {TestIsValidIPAddress -IPAddress $_}
        $Counter++
    }
    if (!$NewVMIP) {
        $NewVMIP = "<$NewVMName`IPAddress>"
    }

    if ($VagrantBox -notmatch "Win|Windows") {
        if (!$(Test-Path "$HOME\.ssh")) {
            New-Item -ItemType Directory -Path "$HOME\.ssh"
        }
        Invoke-WebRequest -Uri "https://raw.githubusercontent.com/hashicorp/vagrant/master/keys/vagrant" -OutFile "$HOME\.ssh\vagrant_unsecure_private_key"
        Invoke-WebRequest -Uri "https://raw.githubusercontent.com/hashicorp/vagrant/master/keys/vagrant.pub" -OutFile "$HOME\.ssh\vagrant_unsecure_public_key.pub"

        if (!$(Test-Path "$HOME\.ssh\vagrant_unsecure_private_key")) {
            Write-Warning "There was a problem downloading the Unsecure Vagrant Private Key! You must use the Hyper-V Console with username/password vagrant/vagrant!"
        }
        if (!$(Test-Path "$HOME\.ssh\vagrant_unsecure_public_key.pub")) {
            Write-Warning "There was a problem downloading the Unsecure Vagrant Public Key! You must use the Hyper-V Console with username/password vagrant/vagrant!"
        }
        
        Write-Host "To login to the Vagrant VM, use 'ssh -i `"$HOME\.ssh\vagrant_unsecure_private_key`" vagrant@$NewVMIP' OR use the Hyper-V Console GUI with username/password vagrant/vagrant"
    }

    [pscustomobject]@{
        VMName                  = $NewVMName
        VMIPAddress             = $NewVMIP
        CreateVMOutput          = $CreateVMOutput
        StartVMOutput           = $StartVMOutput
        BoxFileLocation         = $BoxFilePath
        HyperVVMLocation        = $VMDestinationDirectory
        ExternalSwitchCreated   = if ($ExternalSwitchCreated) {$True} else {$False}
    }

    #endregion >> Main Body
}


# The below Configure-GlobalKnownHosts shouldn't be necesary with Public Key Authentication and
# dissemination of the CA public keys for both host and user signing
<#
function Configure-GlobalKnownHosts {
    [CmdletBinding()]
    Param(
        # Each Remote Host key should be in format like:
        # 192.168.2.34 ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCyPF3ERQhbKKt+BwQ ...
        [Parameter(Mandatory=$False)]
        [string[]]$RemoteHostKeys
    )

    if (Test-Path "$env:ProgramData\ssh") {
        $sshdir = "$env:ProgramData\ssh"
    }
    elseif (Test-Path "$env:ProgramFiles\OpenSSH-Win64") {
        $sshdir = "$env:ProgramFiles\OpenSSH-Win64"
    }
    if (!$sshdir) {
        Write-Error "Unable to find either direcotry '$env:ProgramFiles\OpenSSH-Win64' or directory '$env:ProgramFiles\OpenSSH-Win64'! Halting!"
        $global:FunctionResult = "1"
        return
    }

    $SSHClientGlobalKnownHostsPath = "$sshdir\ssh_known_hosts"
    $sshClientGlobalConfigPath = "$sshdir\ssh_config"
    $GlobalKnownHostsOptionLine = "GlobalKnownHostsFile $SSHCLientGlobalKnownHostsPath"

    if (!(Test-Path "$sshdir\ssh_config")) {
        Set-Content -Value $GlobalKnownHostsOptionLine -Path $sshClientGlobalConfigPath
        #$SSHClientConfigContentChanged = $True
    }
    else {
        [System.Collections.ArrayList]$sshClientGlobalConfigContent = Get-Content $sshClientGlobalConfigPath

        # Determine if sshd_config already has the 'TrustedUserCAKeys' option active
        $ExistingGlobalKnownHostsFileOption = $sshClientGlobalConfigContent -match "GlobalKnownHostsFile" | Where-Object {$_ -notmatch "#"}

        if (!$ExistingGlobalKnownHostsFileOption) {
            try {
                Add-Content -Value $GlobalKnownHostsOptionLine -Path $sshClientGlobalConfigPath
                #$SSHClientConfigContentChanged = $True
                [System.Collections.ArrayList]$sshClientGlobalConfigContent = Get-Content $sshClientGlobalConfigPath
            }
            catch {
                Write-Error $_
                $global:FunctionResult = "1"
                return
            }
        }
        else {
            if ($ExistingGlobalKnownHostsFileOption -ne $GlobalKnownHostsOptionLine) {
                $UpdatedSSHClientConfig = $sshClientGlobalConfigContent -replace [regex]::Escape($ExistingGlobalKnownHostsFileOption),"$GlobalKnownHostsOptionLine"
    
                try {
                    Set-Content -Value $UpdatedSSHClientConfig -Path $sshClientGlobalConfigPath
                    #$SSHClientConfigContentChanged = $True
                    [System.Collections.ArrayList]$sshClientGlobalConfigContent = Get-Content $sshClientGlobalConfigPath
                }
                catch {
                    Write-Error $_
                    $global:FunctionResult = "1"
                    return
                }
            }
            else {
                Write-Warning "The specified 'GlobalKnownHostsFile' option is already active in the the ssh_config file. No changes made."
            }
        }
    }

    if (!(Test-Path $SSHClientGlobalKnownHostsPath)) {
        if ($RemoteHostKeys) {
            foreach ($PubKeyString in $RemoteHostKeys) {
                Add-Content -Value $PubKeyString.Trim() -Path $SSHClientGlobalKnownHostsPath
            }
        }
    }
    else {
        $CurrentGlobalKnownHostHeys = Get-Content $SSHClientGlobalKnownHostsPath

        if ($RemoteHostKeys) {
            foreach ($PubKeyString in $RemoteHostKeys) {
                if ($CurrentGlobalKnownHostHeys -notcontains $PubKeyString) {
                    Add-Content -Value $PubKeyString.Trim() -Path $SSHClientGlobalKnownHostsPath
                }
            }
        }
    }

    try {
        Restart-Service ssh-agent -Force -ErrorAction Stop
    }
    catch {
        Write-Error $_
        $global:FunctionResult = "1"
        return
    }
}
#>

<#
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
#>
















































# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUbqjA+ypFPY7an0l1zBlnmpxf
# weKgggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFDPdh4gY3/WsEgGx
# mKHApsL+K5NGMA0GCSqGSIb3DQEBAQUABIIBAJ0nBn1+OTYNVrGv5GbmzIVvW+LF
# BZqsn8i2uUScO0n9hPYwmhKpit5Wez7Y02/yi42t72msGEaiVb7FvPvrgB4j9Cqm
# OoM0sc0me2Z0554U8Vaj6aaS5CnPDnUDRqfeNxBOfnpODB2kjZMZXP4l+UgIEjNT
# kSK+zySs3lJlg3y8obKuO6yF6f1kVSVz8QU65El1B3dL6KBBP47sIe+hTobIVfku
# 6S+bTKc6lMOPfNd9uJbTyNEHt7UwzsenvmHKotxo3MBV4k8T5wr7OKmRwICvze9N
# 2zqLcsiqVmbIEaCTyIVRkyE8WEua3e2BHAhv643TXJCUy3cEao+YR0v5EEo=
# SIG # End signature block
