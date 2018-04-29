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