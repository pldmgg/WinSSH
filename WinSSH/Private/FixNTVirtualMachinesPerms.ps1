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