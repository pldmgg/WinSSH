[Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls"

function Check-Elevation {
    if ($PSVersionTable.PSEdition -eq "Desktop" -or $PSVersionTable.Platform -eq "Win32NT" -or $PSVersionTable.PSVersion.Major -le 5) {
        [System.Security.Principal.WindowsPrincipal]$currentPrincipal = New-Object System.Security.Principal.WindowsPrincipal(
            [System.Security.Principal.WindowsIdentity]::GetCurrent()
        )

        [System.Security.Principal.WindowsBuiltInRole]$administratorsRole = [System.Security.Principal.WindowsBuiltInRole]::Administrator

        if($currentPrincipal.IsInRole($administratorsRole)) {
            return $true
        }
        else {
            return $false
        }
    }
    
    if ($PSVersionTable.Platform -eq "Unix") {
        if ($(whoami) -eq "root") {
            return $true
        }
        else {
            return $false
        }
    }
}

function New-UniqueString {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [string[]]$ArrayOfStrings,

        [Parameter(Mandatory=$True)]
        [string]$PossibleNewUniqueString
    )

    if (!$ArrayOfStrings -or $ArrayOfStrings.Count -eq 0 -or ![bool]$($ArrayOfStrings -match "[\w]")) {
        $PossibleNewUniqueString
    }
    else {
        $OriginalString = $PossibleNewUniqueString
        $Iteration = 1
        while ($ArrayOfStrings -contains $PossibleNewUniqueString) {
            $AppendedValue = "_$Iteration"
            $PossibleNewUniqueString = $OriginalString + $AppendedValue
            $Iteration++
        }

        $PossibleNewUniqueString
    }
}

function Test-IsValidIPAddress([string]$IPAddress) {
    [boolean]$Octets = (($IPAddress.Split(".") | Measure-Object).Count -eq 4) 
    [boolean]$Valid  =  ($IPAddress -as [ipaddress]) -as [boolean]
    Return  ($Valid -and $Octets)
}

function Test-Port {
    [CmdletBinding()]
    [Alias('testport')]
    Param(
        [Parameter(Mandatory=$False)]
        $HostName = $env:COMPUTERNAME,

        [Parameter(Mandatory=$False)]
        [int]$Port = $(Read-Host -Prompt "Please enter the port number you would like to check.")
    )

    Begin {

        ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####
        
        try {
            $HostNameNetworkInfo = Resolve-Host -HostNameOrIP $HostName -ErrorAction Stop
        }
        catch {
            Write-Error "Unable to resolve $HostName! Halting!"
            $global:FunctionResult = "1"
            return
        }

        $tcp = New-Object Net.Sockets.TcpClient
        $RemoteHostFQDN = $HostNameNetworkInfo.FQDN
        
        ##### END Variable/Parameter Transforms and PreRun Prep #####
    }

    ##### BEGIN Main Body #####
    Process {
        if ($pscmdlet.ShouldProcess("$RemoteHostFQDN","Test Connection on $RemoteHostFQDN`:$Port")) {
            try {
                $tcp.Connect($RemoteHostFQDN, $Port)
            }
            catch {}

            if ($tcp.Connected) {
                $tcp.Close()
                $open = $true
            }
            else {
                $open = $false
            }

            $PortTestResult = [pscustomobject]@{
                Address = $RemoteHostFQDN
                Port    = $Port
                Open    = $open
            }
            $PortTestResult
        }
        ##### END Main Body #####
    }
}

function Unzip-File {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true,Position=0)]
        [string]$PathToZip,
        
        [Parameter(Mandatory=$true,Position=1)]
        [string]$TargetDir,

        [Parameter(Mandatory=$false,Position=2)]
        [string[]]$SpecificItem
    )

    if ($PSVersionTable.PSEdition -eq "Core") {
        [System.Collections.ArrayList]$AssembliesToCheckFor = @("System.Console","System","System.IO",
            "System.IO.Compression","System.IO.Compression.Filesystem","System.IO.Compression.ZipFile"
        )

        [System.Collections.ArrayList]$NeededAssemblies = @()

        foreach ($assembly in $AssembliesToCheckFor) {
            try {
                [System.Collections.ArrayList]$Failures = @()
                try {
                    $TestLoad = [System.Reflection.Assembly]::LoadWithPartialName($assembly)
                    if (!$TestLoad) {
                        throw
                    }
                }
                catch {
                    $null = $Failures.Add("Failed LoadWithPartialName")
                }

                try {
                    $null = Invoke-Expression "[$assembly]"
                }
                catch {
                    $null = $Failures.Add("Failed TabComplete Check")
                }

                if ($Failures.Count -gt 1) {
                    $Failures
                    throw
                }
            }
            catch {
                Write-Host "Downloading $assembly..."
                $NewAssemblyDir = "$HOME\Downloads\$assembly"
                $NewAssemblyDllPath = "$NewAssemblyDir\$assembly.dll"
                if (!$(Test-Path $NewAssemblyDir)) {
                    New-Item -ItemType Directory -Path $NewAssemblyDir
                }
                if (Test-Path "$NewAssemblyDir\$assembly*.zip") {
                    Remove-Item "$NewAssemblyDir\$assembly*.zip" -Force
                }
                $OutFileBaseNamePrep = Invoke-WebRequest "https://www.nuget.org/api/v2/package/$assembly" -DisableKeepAlive -UseBasicParsing
                $OutFileBaseName = $($OutFileBaseNamePrep.BaseResponse.ResponseUri.AbsoluteUri -split "/")[-1] -replace "nupkg","zip"
                Invoke-WebRequest -Uri "https://www.nuget.org/api/v2/package/$assembly" -OutFile "$NewAssemblyDir\$OutFileBaseName"
                $null = Expand-Archive -Path "$NewAssemblyDir\$OutFileBaseName" -DestinationPath $NewAssemblyDir -Force

                $PossibleDLLs = Get-ChildItem -Recurse $NewAssemblyDir | Where-Object {$_.Name -eq "$assembly.dll" -and $_.Parent -notmatch "net[0-9]" -and $_.Parent -match "core|standard"}

                if ($PossibleDLLs.Count -gt 1) {
                    Write-Warning "More than one item within $NewAssemblyDir\$OutFileBaseName matches $assembly.dll"
                    Write-Host "Matches include the following:"
                    for ($i=0; $i -lt $PossibleDLLs.Count; $i++){
                        "$i) $($($PossibleDLLs[$i]).FullName)"
                    }
                    $Choice = Read-Host -Prompt "Please enter the number corresponding to the .dll you would like to load [0..$($($PossibleDLLs.Count)-1)]"
                    if ($(0..$($($PossibleDLLs.Count)-1)) -notcontains $Choice) {
                        Write-Error "The number indicated does is not a valid choice! Halting!"
                        $global:FunctionResult = "1"
                        return
                    }

                    if ($PSVersionTable.Platform -eq "Win32NT") {
                        # Install to GAC
                        [System.Reflection.Assembly]::LoadWithPartialName("System.EnterpriseServices")
                        $publish = New-Object System.EnterpriseServices.Internal.Publish
                        $publish.GacInstall($PossibleDLLs[$Choice].FullName)
                    }

                    # Copy it to the root of $NewAssemblyDir\$OutFileBaseName
                    Copy-Item -Path "$($PossibleDLLs[$Choice].FullName)" -Destination "$NewAssemblyDir\$assembly.dll"

                    # Remove everything else that was extracted with Expand-Archive
                    Get-ChildItem -Recurse $NewAssemblyDir | Where-Object {
                        $_.FullName -ne "$NewAssemblyDir\$assembly.dll" -and
                        $_.FullName -ne "$NewAssemblyDir\$OutFileBaseName"
                    } | Remove-Item -Recurse -Force
                    
                }
                if ($PossibleDLLs.Count -lt 1) {
                    Write-Error "No matching .dll files were found within $NewAssemblyDir\$OutFileBaseName ! Halting!"
                    continue
                }
                if ($PossibleDLLs.Count -eq 1) {
                    if ($PSVersionTable.Platform -eq "Win32NT") {
                        # Install to GAC
                        [System.Reflection.Assembly]::LoadWithPartialName("System.EnterpriseServices")
                        $publish = New-Object System.EnterpriseServices.Internal.Publish
                        $publish.GacInstall($PossibleDLLs.FullName)
                    }

                    # Copy it to the root of $NewAssemblyDir\$OutFileBaseName
                    Copy-Item -Path "$($PossibleDLLs[$Choice].FullName)" -Destination "$NewAssemblyDir\$assembly.dll"

                    # Remove everything else that was extracted with Expand-Archive
                    Get-ChildItem -Recurse $NewAssemblyDir | Where-Object {
                        $_.FullName -ne "$NewAssemblyDir\$assembly.dll" -and
                        $_.FullName -ne "$NewAssemblyDir\$OutFileBaseName"
                    } | Remove-Item -Recurse -Force
                }
            }
            $AssemblyFullInfo = [System.Reflection.Assembly]::LoadWithPartialName($assembly)
            if (!$AssemblyFullInfo) {
                $AssemblyFullInfo = [System.Reflection.Assembly]::LoadFile("$NewAssemblyDir\$assembly.dll")
            }
            if (!$AssemblyFullInfo) {
                Write-Error "The assembly $assembly could not be found or otherwise loaded! Halting!"
                $global:FunctionResult = "1"
                return
            }
            $null = $NeededAssemblies.Add([pscustomobject]@{
                AssemblyName = "$assembly"
                Available = if ($AssemblyFullInfo){$true} else {$false}
                AssemblyInfo = $AssemblyFullInfo
                AssemblyLocation = $AssemblyFullInfo.Location
            })
        }

        if ($NeededAssemblies.Available -contains $false) {
            $AssembliesNotFound = $($NeededAssemblies | Where-Object {$_.Available -eq $false}).AssemblyName
            Write-Error "The following assemblies cannot be found:`n$AssembliesNotFound`nHalting!"
            $global:FunctionResult = "1"
            return
        }

        $Assem = $NeededAssemblies.AssemblyInfo.FullName

        $Source = @"
        using System;
        using System.IO;
        using System.IO.Compression;

        namespace MyCore.Utils
        {
            public static class Zip
            {
                public static void ExtractAll(string sourcepath, string destpath)
                {
                    string zipPath = @sourcepath;
                    string extractPath = @destpath;

                    using (ZipArchive archive = ZipFile.Open(zipPath, ZipArchiveMode.Update))
                    {
                        archive.ExtractToDirectory(extractPath);
                    }
                }

                public static void ExtractSpecific(string sourcepath, string destpath, string specificitem)
                {
                    string zipPath = @sourcepath;
                    string extractPath = @destpath;
                    string itemout = @specificitem.Replace(@"\","/");

                    //Console.WriteLine(itemout);

                    using (ZipArchive archive = ZipFile.OpenRead(zipPath))
                    {
                        foreach (ZipArchiveEntry entry in archive.Entries)
                        {
                            //Console.WriteLine(entry.FullName);
                            //bool satisfied = new bool();
                            //satisfied = entry.FullName.IndexOf(@itemout, 0, StringComparison.CurrentCultureIgnoreCase) != -1;
                            //Console.WriteLine(satisfied);

                            if (entry.FullName.IndexOf(@itemout, 0, StringComparison.CurrentCultureIgnoreCase) != -1)
                            {
                                string finaloutputpath = extractPath + "\\" + entry.Name;
                                entry.ExtractToFile(finaloutputpath, true);
                            }
                        }
                    } 
                }
            }
        }
"@

        Add-Type -ReferencedAssemblies $Assem -TypeDefinition $Source

        if (!$SpecificItem) {
            [MyCore.Utils.Zip]::ExtractAll($PathToZip, $TargetDir)
        }
        else {
            [MyCore.Utils.Zip]::ExtractSpecific($PathToZip, $TargetDir, $SpecificItem)
        }
    }


    if ($PSVersionTable.PSEdition -eq "Desktop" -and $($($PSVersionTable.Platform -and $PSVersionTable.Platform -eq "Win32NT") -or !$PSVersionTable.Platform)) {
        if ($SpecificItem) {
            foreach ($item in $SpecificItem) {
                if ($SpecificItem -match "\\") {
                    $SpecificItem = $SpecificItem -replace "\\","\\"
                }
            }
        }

        ##### BEGIN Native Helper Functions #####
        function Get-ZipChildItems {
            [CmdletBinding()]
            Param(
                [Parameter(Mandatory=$false,Position=0)]
                [string]$ZipFile = $(Read-Host -Prompt "Please enter the full path to the zip file")
            )

            $shellapp = new-object -com shell.application
            $zipFileComObj = $shellapp.Namespace($ZipFile)
            $i = $zipFileComObj.Items()
            Get-ZipChildItems_Recurse $i
        }

        function Get-ZipChildItems_Recurse {
            [CmdletBinding()]
            Param(
                [Parameter(Mandatory=$true,Position=0)]
                $items
            )

            foreach($si in $items) {
                if($si.getfolder -ne $null) {
                    # Loop through subfolders 
                    Get-ZipChildItems_Recurse $si.getfolder.items()
                }
                # Spit out the object
                $si
            }
        }

        ##### END Native Helper Functions #####

        ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####
        if (!$(Test-Path $PathToZip)) {
            Write-Verbose "The path $PathToZip was not found! Halting!"
            Write-Error "The path $PathToZip was not found! Halting!"
            $global:FunctionResult = "1"
            return
        }
        if ($(Get-ChildItem $PathToZip).Extension -ne ".zip") {
            Write-Verbose "The file specified by the -PathToZip parameter does not have a .zip file extension! Halting!"
            Write-Error "The file specified by the -PathToZip parameter does not have a .zip file extension! Halting!"
            $global:FunctionResult = "1"
            return
        }

        $ZipFileNameWExt = $(Get-ChildItem $PathToZip).Name

        ##### END Variable/Parameter Transforms and PreRun Prep #####

        ##### BEGIN Main Body #####

        Write-Verbose "NOTE: PowerShell 5.0 uses Expand-Archive cmdlet to unzip files"

        if (!$SpecificItem) {
            if ($PSVersionTable.PSVersion.Major -ge 5) {
                $null = Expand-Archive -Path $PathToZip -DestinationPath $TargetDir -Force
            }
            if ($PSVersionTable.PSVersion.Major -lt 5) {
                # Load System.IO.Compression.Filesystem 
                [System.Reflection.Assembly]::LoadWithPartialName("System.IO.Compression.FileSystem") | Out-Null

                # Unzip file
                [System.IO.Compression.ZipFile]::ExtractToDirectory($PathToZip, $TargetDir)
            }
        }
        if ($SpecificItem) {
            $ZipSubItems = Get-ZipChildItems -ZipFile $PathToZip

            foreach ($searchitem in $SpecificItem) {
                [array]$potentialItems = foreach ($item in $ZipSubItems) {
                    if ($item.Path -match $searchitem) {
                        $item
                    }
                }

                $shell = new-object -com shell.application

                if ($potentialItems.Count -eq 1) {
                    $shell.Namespace($TargetDir).CopyHere($potentialItems[0], 0x14)
                }
                if ($potentialItems.Count -gt 1) {
                    Write-Warning "More than one item within $ZipFileNameWExt matches $searchitem."
                    Write-Host "Matches include the following:"
                    for ($i=0; $i -lt $potentialItems.Count; $i++){
                        "$i) $($($potentialItems[$i]).Path)"
                    }
                    $Choice = Read-Host -Prompt "Please enter the number corresponding to the item you would like to extract [0..$($($potentialItems.Count)-1)]"
                    if ($(0..$($($potentialItems.Count)-1)) -notcontains $Choice) {
                        Write-Warning "The number indicated does is not a valid choice! Skipping $searchitem..."
                        continue
                    }
                    for ($i=0; $i -lt $potentialItems.Count; $i++){
                        $shell.Namespace($TargetDir).CopyHere($potentialItems[$Choice], 0x14)
                    }
                }
                if ($potentialItems.Count -lt 1) {
                    Write-Warning "No items within $ZipFileNameWExt match $searchitem! Skipping..."
                    continue
                }
            }
        }
        ##### END Main Body #####
    }
}

function Get-NativePath {
    [CmdletBinding()]
    Param( 
        [Parameter(Mandatory=$True)]
        [string[]]$PathAsStringArray
    )

    $PathAsStringArray = foreach ($pathPart in $PathAsStringArray) {
        $SplitAttempt = $pathPart -split [regex]::Escape([IO.Path]::DirectorySeparatorChar)
        
        if ($SplitAttempt.Count -gt 1) {
            foreach ($obj in $SplitAttempt) {
                $obj
            }
        }
        else {
            $pathPart
        }
    }
    $PathAsStringArray = $PathAsStringArray -join [IO.Path]::DirectorySeparatorChar

    $PathAsStringArray

}

function Pause-ForWarning {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [int]$PauseTimeInSeconds,

        [Parameter(Mandatory=$True)]
        $Message
    )

    Write-Warning $Message
    Write-Host "To answer in the affirmative, press 'y' on your keyboard."
    Write-Host "To answer in the negative, press any other key on your keyboard, OR wait $PauseTimeInSeconds seconds"

    $timeout = New-Timespan -Seconds ($PauseTimeInSeconds - 1)
    $stopwatch = [diagnostics.stopwatch]::StartNew()
    while ($stopwatch.elapsed -lt $timeout){
        if ([Console]::KeyAvailable) {
            $keypressed = [Console]::ReadKey("NoEcho").Key
            Write-Host "You pressed the `"$keypressed`" key"
            if ($keypressed -eq "y") {
                $Result = $true
                break
            }
            if ($keypressed -ne "y") {
                $Result = $false
                break
            }
        }

        # Check once every 1 second to see if the above "if" condition is satisfied
        Start-Sleep 1
    }

    if (!$Result) {
        $Result = $false
    }
    
    $Result
}

<#
    .SYNOPSIS
        Install and/or Update the PackageManagement PowerShell Module and/or the PowerShellGet PowerShell Module.

        IMPORTANT: This script can be used on systems with PowerShell Version 3 and higher

    .DESCRIPTION
        PowerShell versions 3 and 4 do NOT have the PackageManagement and PowerShellGet Modules installed by default.
        If you are running PowerShell 3 or 4 and these modules are NOT installed, it will download PackageMangement_x64.msi
        from Microsoft and install it (thereby installing the Modules) and upgrade the Modules the latest version available
        in the PSGallery PackageProvider Source repo (NOTE: The PackageManagement module is not able to be upgraded beyond
        version 1.0.0.1 on PowerShell 3 or 4, unless you upgrade PowerShell itself to version 5 or higher).

        PowerShell version 5 and higher DOES come with PackageManagement and PowerShellGet Modules (both version
        1.0.0.1) by default. This script will install the latest versions of these Modules ALONGSIDE
        (i.e. SIDE-BY-SIDE MODE) the older versions...because that's apparently how Microsoft wants to
        handle this for the time being.

        At the conclusion of this script, the PowerShell Sessionw will have the latest versions of the PackageManagement and 
        PowerShellGet Modules loaded via Import-Module. (Verify with Get-Module).

    .NOTES
        ##### Regarding PowerShell Versions Lower than 5 #####

        Installation of the PackageManagement_x64.msi is necessary. Installing this .msi gives us version 1.0.0.1 of the 
        PackageManagement Module and version 1.0.0.1 of PowerShellGet Module (as well as the PowerShellGet PackageProvider 
        and the PowerShellGet PackageProvider Source called PSGallery).

        However, these are NOT the latest versions of these Modules. You can update the PowerShellGet Module from 1.0.0.1 to
        the latest version by using Install-Module -Force. Unfortunately, it is not possible to update the PackageManagement
        Module itself using this method, because it will complain about it being in use (which it is, since the Install-Module
        cmdlet belongs to the PackageManagement Module).

        It is important to note that updating PowerShellGet using Install-Module -Force in PowerShell versions lower than 5
        actually REMOVES 1.0.0.1 and REPLACES it with the latest version. (In PowerShell version 5 and higher, it installs
        the new version of the Module ALONGSIDE the old version.)

        There is currently no way to update the PackageManagement Module to a version newer than 1.0.0.1 without actually updating
        PowerShell itself to version 5 or higher.


        ##### Regarding PowerShell Versions 5 And Higher #####

        The PackageManagement Module version 1.0.0.1 and PowerShellGet Module version 1.0.0.1 are already installed.

        It is possible to update both Modules using Install-Module -Force, HOWEVER, the newer versions will be installed
        ALONGSIDE (aka SIDE-BY-SIDE mode) the older versions. In future PowerShell Sessions, you need to specify which version
        you want to use when you import the module(s) using Import-Module -RequiredVersion

    .EXAMPLE
        Update-PackageManagement -AddChocolateyPackageProvider

#>
function Update-PackageManagement {
    [CmdletBinding()]
    Param( 
        [Parameter(Mandatory=$False)]
        [switch]$AddChocolateyPackageProvider,

        [Parameter(Mandatory=$False)]
        [switch]$InstallNuGetCmdLine,

        [Parameter(Mandatory=$False)]
        [switch]$LoadUpdatedModulesInSameSession
    )

    ##### BEGIN Helper Functions #####
    
    function Check-Elevation {
        if ($PSVersionTable.PSEdition -eq "Desktop" -or $PSVersionTable.Platform -eq "Win32NT" -or $PSVersionTable.PSVersion.Major -le 5) {
            [System.Security.Principal.WindowsPrincipal]$currentPrincipal = New-Object System.Security.Principal.WindowsPrincipal(
                [System.Security.Principal.WindowsIdentity]::GetCurrent()
            )
    
            [System.Security.Principal.WindowsBuiltInRole]$administratorsRole = [System.Security.Principal.WindowsBuiltInRole]::Administrator
    
            if($currentPrincipal.IsInRole($administratorsRole)) {
                return $true
            }
            else {
                return $false
            }
        }
        
        if ($PSVersionTable.Platform -eq "Unix") {
            if ($(whoami) -eq "root") {
                return $true
            }
            else {
                return $false
            }
        }
    }

    function Get-NativePath {
        [CmdletBinding()]
        Param( 
            [Parameter(Mandatory=$True)]
            [string[]]$PathAsStringArray
        )
    
        $PathAsStringArray = foreach ($pathPart in $PathAsStringArray) {
            $SplitAttempt = $pathPart -split [regex]::Escape([IO.Path]::DirectorySeparatorChar)
            
            if ($SplitAttempt.Count -gt 1) {
                foreach ($obj in $SplitAttempt) {
                    $obj
                }
            }
            else {
                $pathPart
            }
        }
        $PathAsStringArray = $PathAsStringArray -join [IO.Path]::DirectorySeparatorChar
    
        $PathAsStringArray
    
    }

    function Pause-ForWarning {
        [CmdletBinding()]
        Param(
            [Parameter(Mandatory=$True)]
            [int]$PauseTimeInSeconds,
    
            [Parameter(Mandatory=$True)]
            $Message
        )
    
        Write-Warning $Message
        Write-Host "To answer in the affirmative, press 'y' on your keyboard."
        Write-Host "To answer in the negative, press any other key on your keyboard, OR wait $PauseTimeInSeconds seconds"
    
        $timeout = New-Timespan -Seconds ($PauseTimeInSeconds - 1)
        $stopwatch = [diagnostics.stopwatch]::StartNew()
        while ($stopwatch.elapsed -lt $timeout){
            if ([Console]::KeyAvailable) {
                $keypressed = [Console]::ReadKey("NoEcho").Key
                Write-Host "You pressed the `"$keypressed`" key"
                if ($keypressed -eq "y") {
                    $Result = $true
                    break
                }
                if ($keypressed -ne "y") {
                    $Result = $false
                    break
                }
            }
    
            # Check once every 1 second to see if the above "if" condition is satisfied
            Start-Sleep 1
        }
    
        if (!$Result) {
            $Result = $false
        }
        
        $Result
    }

    ##### END Helper Functions #####
    

    ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####

    # We're going to need Elevated privileges for some commands below, so might as well try to set this up now.
    if (!$(Check-Elevation)) {
        Write-Error "The Update-PackageManagement function must be run with elevated privileges. Halting!"
        $global:FunctionResult = "1"
        return
    }

    if (!$([Environment]::Is64BitProcess)) {
        Write-Error "You are currently running the 32-bit version of PowerShell. Please run the 64-bit version found under C:\Windows\SysWOW64\WindowsPowerShell\v1.0 and try again. Halting!"
        $global:FunctionResult = "1"
        return
    }

    if ($PSVersionTable.PSEdition -eq "Core" -and $PSVersionTable.Platform -ne "Win32NT" -and $AddChocolateyPackageProvider) {
        Write-Error "The Chocolatey Repo should only be added on a Windows OS! Halting!"
        $global:FunctionResult = "1"
        return
    }

    if ($InstallNuGetCmdLine -and !$AddChocolateyPackageProvider) {
        if ($PSVersionTable.PSEdition -eq "Desktop" -or $PSVersionTable.PSVersion.Major -le 5) {
            if ($(Get-PackageProvider).Name -notcontains "Chocolatey") {
                $WarningMessage = "NuGet Command Line Tool cannot be installed without using Chocolatey. Would you like to use the Chocolatey Package Provider (NOTE: This is NOT an installation of the chocolatey command line)?"
                $WarningResponse = Pause-ForWarning -PauseTimeInSeconds 15 -Message $WarningMessage
                if ($WarningResponse) {
                    $AddChocolateyPackageProvider = $true
                }
            }
            else {
                $AddChocolateyPackageProvider = $true
            }
        }
        elseif ($PSVersionTable.PSEdition -eq "Core" -and $PSVersionTable.Platform -eq "Win32NT") {
            if (!$(Get-Command choco -ErrorAction SilentlyContinue)) {
                $WarningMessage = "NuGet Command Line Tool cannot be installed without using Chocolatey. Would you like to install Chocolatey Command Line Tools in order to install NuGet Command Line Tools?"
                $WarningResponse = Pause-ForWarning -PauseTimeInSeconds 15 -Message $WarningMessage
                if ($WarningResponse) {
                    $AddChocolateyPackageProvider = $true
                }
            }
            else {
                $AddChocolateyPackageProvider = $true
            }
        }
        elseif ($PSVersionTable.PSEdition -eq "Core" -and $PSVersionTable.Platform -eq "Unix") {
            $WarningMessage = "The NuGet Command Line Tools binary nuget.exe can be downloaded, but will not be able to be run without Mono. Do you want to download the latest stable nuget.exe?"
            $WarningResponse = Pause-ForWarning -PauseTimeInSeconds 15 -Message $WarningMessage
            if ($WarningResponse) {
                Write-Host "Downloading latest stable nuget.exe..."
                $OutFilePath = Get-NativePath -PathAsStringArray @($HOME, "Downloads", "nuget.exe")
                Invoke-WebRequest -Uri "https://dist.nuget.org/win-x86-commandline/latest/nuget.exe" -OutFile $OutFilePath
            }
            $AddChocolateyPackageProvider = $false
        }
    }

    if ($PSVersionTable.PSEdition -eq "Desktop" -or $PSVersionTable.PSVersion.Major -le 5) {
        # Check to see if we're behind a proxy
        if ([System.Net.WebProxy]::GetDefaultProxy().Address -ne $null) {
            $ProxyAddress = [System.Net.WebProxy]::GetDefaultProxy().Address
            [system.net.webrequest]::defaultwebproxy = New-Object system.net.webproxy($ProxyAddress)
            [system.net.webrequest]::defaultwebproxy.credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials
            [system.net.webrequest]::defaultwebproxy.BypassProxyOnLocal = $true
        }
    }
    # TODO: Figure out how to identify default proxy on PowerShell Core...

    ##### END Variable/Parameter Transforms and PreRun Prep #####


    if ($PSVersionTable.PSVersion.Major -lt 5) {
        if ($(Get-Module -ListAvailable).Name -notcontains "PackageManagement") {
            Write-Host "Downloading PackageManagement .msi installer..."
            $OutFilePath = Get-NativePath -PathAsStringArray @($HOME, "Downloads", "PackageManagement_x64.msi")
            Invoke-WebRequest -Uri "https://download.microsoft.com/download/C/4/1/C41378D4-7F41-4BBE-9D0D-0E4F98585C61/PackageManagement_x64.msi" -OutFile $OutFilePath
            
            $DateStamp = Get-Date -Format yyyyMMddTHHmmss
            $MSIFullPath = $OutFilePath
            $MSIParentDir = $MSIFullPath | Split-Path -Parent
            $MSIFileName = $MSIFullPath | Split-Path -Leaf
            $MSIFileNameOnly = $MSIFileName -replace "\.msi",""
            $logFile = Get-NativePath -PathAsStringArray @($MSIParentDir, "$MSIFileNameOnly$DateStamp.log")
            $MSIArguments = @(
                "/i"
                $MSIFullPath
                "/qn"
                "/norestart"
                "/L*v"
                $logFile
            )
            Start-Process "msiexec.exe" -ArgumentList $MSIArguments -Wait -NoNewWindow
        }
        while ($($(Get-Module -ListAvailable).Name -notcontains "PackageManagement") -and $($(Get-Module -ListAvailable).Name -notcontains "PowerShellGet")) {
            Write-Host "Waiting for PackageManagement and PowerShellGet Modules to become available"
            Start-Sleep -Seconds 1
        }
        Write-Host "PackageManagement and PowerShellGet Modules are ready. Continuing..."
    }

    # We need to load whatever versions of PackageManagement/PowerShellGet are available on the Local Host in order
    # to use the Find-Module cmdlet to find out what the latest versions of each Module are...

    # ...but because there are sometimes issues with version compatibility between PackageManagement/PowerShellGet,
    # after loading the latest PackageManagement Module we need to try/catch available versions of PowerShellGet until
    # one of them actually loads
    
    # Set LatestLocallyAvailable variables...
    $PackageManagementLatestLocallyAvailableVersionItem = $(Get-Module -ListAvailable -All | Where-Object {$_.Name -eq "PackageManagement"} | Sort-Object -Property Version)[-1]
    $PowerShellGetLatestLocallyAvailableVersionItem = $(Get-Module -ListAvailable -All | Where-Object {$_.Name -eq "PowerShellGet"} | Sort-Object -Property Version)[-1]
    $PackageManagementLatestLocallyAvailableVersion = $PackageManagementLatestLocallyAvailableVersionItem.Version
    $PowerShellGetLatestLocallyAvailableVersion = $PowerShellGetLatestLocallyAvailableVersionItem.Version
    $PSGetLocallyAvailableVersions = $(Get-Module -ListAvailable -All | Where-Object {$_.Name -eq "PowerShellGet"}).Version | Sort-Object -Property Version | Get-Unique
    $PSGetLocallyAvailableVersions = $PSGetLocallyAvailableVersions | Sort-Object -Descending
    

    if ($(Get-Module).Name -notcontains "PackageManagement") {
        if ($PSVersionTable.PSVersion.Major -ge 5) {
            Import-Module "PackageManagement" -RequiredVersion $PackageManagementLatestLocallyAvailableVersion
        }
        else {
            Import-Module "PackageManagement"
        }
    }
    if ($(Get-Module).Name -notcontains "PowerShellGet") {
        foreach ($version in $PSGetLocallyAvailableVersions) {
            try {
                $ImportedPSGetModule = Import-Module "PowerShellGet" -RequiredVersion $version -PassThru -ErrorAction SilentlyContinue
                if (!$ImportedPSGetModule) {throw}

                break
            }
            catch {
                continue
            }
        }
    }

    if ($(Get-Module -Name PackageManagement).ExportedCommands.Count -eq 0 -or
        $(Get-Module -Name PowerShellGet).ExportedCommands.Count -eq 0
    ) {
        Write-Warning "Either PowerShellGet or PackagementManagement Modules were not able to be loaded Imported successfully due to an update initiated within the current session. Please close this PowerShell Session, open a new one, and run this function again."

        $Result = [pscustomobject][ordered]@{
            PackageManagementUpdated  = $false
            PowerShellGetUpdated      = $false
            NewPSSessionRequired      = $true
        }

        $Result
        return
    }

    # Determine if the NuGet Package Provider is available. If not, install it, because it needs it for some reason
    # that is currently not clear to me. Point is, if it's not installed it will prompt you to install it, so just
    # do it beforehand.
    if ($(Get-PackageProvider).Name -notcontains "NuGet") {
        Install-PackageProvider "NuGet" -Scope CurrentUser -Force
        Register-PackageSource -Name 'nuget.org' -Location 'https://api.nuget.org/v3/index.json' -ProviderName NuGet -Trusted -Force -ForceBootstrap
    }

    if ($AddChocolateyPackageProvider) {
        if ($PSVersionTable.PSEdition -eq "Desktop" -or $PSVersionTable.PSVersion.Major -le 5) {
            # Install the Chocolatey Package Provider to be used with PowerShellGet
            if ($(Get-PackageProvider).Name -notcontains "Chocolatey") {
                Install-PackageProvider "Chocolatey" -Scope CurrentUser -Force
                # The above Install-PackageProvider "Chocolatey" -Force DOES register a PackageSource Repository, so we need to trust it:
                Set-PackageSource -Name Chocolatey -Trusted

                # Make sure packages installed via Chocolatey PackageProvider are part of $env:Path
                [System.Collections.ArrayList]$ChocolateyPathsPrep = @()
                [System.Collections.ArrayList]$ChocolateyPathsFinal = @()
                $env:ChocolateyPSProviderPath = "C:\Chocolatey"

                if (Test-Path $env:ChocolateyPSProviderPath) {
                    if (Test-Path "$env:ChocolateyPSProviderPath\lib") {
                        $OtherChocolateyPathsToAdd = $(Get-ChildItem "$env:ChocolateyPSProviderPath\lib" -Directory | foreach {
                            Get-ChildItem $_.FullName -Recurse -File
                        } | foreach {
                            if ($_.Extension -eq ".exe") {
                                $_.Directory.FullName
                            }
                        }) | foreach {
                            $null = $ChocolateyPathsPrep.Add($_)
                        }
                    }
                    if (Test-Path "$env:ChocolateyPSProviderPath\bin") {
                        $OtherChocolateyPathsToAdd = $(Get-ChildItem "$env:ChocolateyPSProviderPath\bin" -Directory | foreach {
                            Get-ChildItem $_.FullName -Recurse -File
                        } | foreach {
                            if ($_.Extension -eq ".exe") {
                                $_.Directory.FullName
                            }
                        }) | foreach {
                            $null = $ChocolateyPathsPrep.Add($_)
                        }
                    }
                }
                
                if ($ChocolateyPathsPrep) {
                    foreach ($ChocoPath in $ChocolateyPathsPrep) {
                        if ($(Test-Path $ChocoPath) -and $OriginalEnvPathArray -notcontains $ChocoPath) {
                            $null = $ChocolateyPathsFinal.Add($ChocoPath)
                        }
                    }
                }
            
                try {
                    $ChocolateyPathsFinal = $ChocolateyPathsFinal | Sort-Object | Get-Unique
                }
                catch {
                    [System.Collections.ArrayList]$ChocolateyPathsFinal = @($ChocolateyPathsFinal)
                }
                if ($ChocolateyPathsFinal.Count -ne 0) {
                    $ChocolateyPathsAsString = $ChocolateyPathsFinal -join ";"
                }

                foreach ($ChocPath in $ChocolateyPathsFinal) {
                    if ($($env:Path -split ";") -notcontains $ChocPath) {
                        if ($env:Path[-1] -eq ";") {
                            $env:Path = "$env:Path$ChocPath"
                        }
                        else {
                            $env:Path = "$env:Path;$ChocPath"
                        }
                    }
                }

                if ($InstallNuGetCmdLine) {
                    # Next, install the NuGet CLI using the Chocolatey Repo
                    try {
                        Write-Host "Trying to find Chocolatey Package Nuget.CommandLine..."
                        while (!$(Find-Package Nuget.CommandLine)) {
                            Write-Host "Trying to find Chocolatey Package Nuget.CommandLine..."
                            Start-Sleep -Seconds 2
                        }
                        
                        Get-Package NuGet.CommandLine -ErrorAction SilentlyContinue
                        if (!$?) {
                            throw
                        }
                    } 
                    catch {
                        Install-Package Nuget.CommandLine -Source chocolatey -Force
                    }
                    
                    # Ensure there's a symlink from C:\Chocolatey\bin to the real NuGet.exe under C:\Chocolatey\lib
                    $NuGetSymlinkTest = Get-ChildItem "C:\Chocolatey\bin" | Where-Object {$_.Name -eq "NuGet.exe" -and $_.LinkType -eq "SymbolicLink"}
                    $RealNuGetPath = $(Resolve-Path "C:\Chocolatey\lib\*\*\NuGet.exe").Path
                    $TestRealNuGetPath = Test-Path $RealNuGetPath
                    if (!$NuGetSymlinkTest -and $TestRealNuGetPath) {
                        New-Item -Path "C:\Chocolatey\bin\NuGet.exe" -ItemType SymbolicLink -Value $RealNuGetPath
                    }
                }
            }
        }
        if ($PSVersionTable.PSEdition -eq "Core" -and $PSVersionTable.Platform -eq "Win32NT") {
            # Install the Chocolatey Command line
            if (!$(Get-Command choco -ErrorAction SilentlyContinue)) {
                # Suppressing all errors for Chocolatey cmdline install. They will only be a problem if
                # there is a Web Proxy between you and the Internet
                $env:chocolateyUseWindowsCompression = 'true'
                $null = Invoke-Expression $([System.Net.WebClient]::new()).DownloadString("https://chocolatey.org/install.ps1") -ErrorVariable ChocolateyInstallProblems 2>&1 6>&1
                $DateStamp = Get-Date -Format yyyyMMddTHHmmss
                $ChocolateyInstallLogFile = Get-NativePath -PathAsStringArray @($(Get-Location).Path, "ChocolateyInstallLog_$DateStamp.txt")
                $ChocolateyInstallProblems | Out-File $ChocolateyInstallLogFile
            }

            if ($InstallNuGetCmdLine) {
                if (!$(Get-Command choco -ErrorAction SilentlyContinue)) {
                    Write-Error "Unable to find chocolatey.exe, however, it should be installed. Please check your System PATH and `$env:Path and try again. Halting!"
                    $global:FunctionResult = "1"
                    return
                }
                else {
                    # 'choco update' aka 'cup' will update if already installed or install if not installed
                    $ProcessInfo = New-Object System.Diagnostics.ProcessStartInfo
                    $ProcessInfo.WorkingDirectory = $NuGetPackagesPath
                    $ProcessInfo.FileName = "cup"
                    $ProcessInfo.RedirectStandardError = $true
                    $ProcessInfo.RedirectStandardOutput = $true
                    $ProcessInfo.UseShellExecute = $false
                    $ProcessInfo.Arguments = "nuget.commandline -y"
                    $Process = New-Object System.Diagnostics.Process
                    $Process.StartInfo = $ProcessInfo
                    $Process.Start() | Out-Null
                    $stdout = $($Process.StandardOutput.ReadToEnd()).Trim()
                    $stderr = $($Process.StandardError.ReadToEnd()).Trim()
                    $AllOutput = $stdout + $stderr
                    $AllOutput = $AllOutput -split "`n"
                }
                # NOTE: The chocolatey install should take care of setting $env:Path and System PATH so that
                # choco binaries and packages installed via chocolatey can be found here:
                # C:\ProgramData\chocolatey\bin
            }
        }
    }
    # Next, set the PSGallery PowerShellGet PackageProvider Source to Trusted
    if ($(Get-PackageSource | Where-Object {$_.Name -eq "PSGallery"}).IsTrusted -eq $False) {
        Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
    }

    # Next, update PackageManagement and PowerShellGet where possible
    [version]$MinimumVer = "1.0.0.1"
    try {
        $PackageManagementLatestVersion = $(Find-Module PackageManagement).Version
    }
    catch {
        $PackageManagementLatestVersion = $PackageManagementLatestLocallyAvailableVersion
    }
    try {
        $PowerShellGetLatestVersion = $(Find-Module PowerShellGet).Version
    }
    catch {
        $PowerShellGetLatestVersion = $PowerShellGetLatestLocallyAvailableVersion
    }
    Write-Verbose "PackageManagement Latest Version is: $PackageManagementLatestVersion"
    Write-Verbose "PowerShellGetLatestVersion Latest Version is: $PowerShellGetLatestVersion"

    if ($PackageManagementLatestVersion -gt $PackageManagementLatestLocallyAvailableVersion -and $PackageManagementLatestVersion -gt $MinimumVer) {
        if ($PSVersionTable.PSVersion.Major -lt 5) {
            Write-Host "`nUnable to update the PackageManagement Module beyond $($MinimumVer.ToString()) on PowerShell versions lower than 5."
        }
        if ($PSVersionTable.PSVersion.Major -ge 5) {
            #Install-Module -Name "PackageManagement" -Scope CurrentUser -Repository PSGallery -RequiredVersion $PowerShellGetLatestVersion -Force -WarningAction "SilentlyContinue"
            #Install-Module -Name "PackageManagement" -Scope CurrentUser -Repository PSGallery -RequiredVersion $PackageManagementLatestVersion -Force
            Write-Host "Installing latest version of PackageManagement..."
            Install-Module -Name "PackageManagement" -Force -WarningAction SilentlyContinue
            $PackageManagementUpdated = $True
        }
    }
    if ($PowerShellGetLatestVersion -gt $PowerShellGetLatestLocallyAvailableVersion -and $PowerShellGetLatestVersion -gt $MinimumVer) {
        # Unless the force parameter is used, Install-Module will halt with a warning saying the 1.0.0.1 is already installed
        # and it will not update it.
        Write-Host "Installing latest version of PowerShellGet..."
        #Install-Module -Name "PowerShellGet" -Scope CurrentUser -Repository PSGallery -RequiredVersion $PowerShellGetLatestVersion -Force -WarningAction "SilentlyContinue"
        #Install-Module -Name "PowerShellGet" -RequiredVersion $PowerShellGetLatestVersion -Force
        Install-Module -Name "PowerShellGet" -Force -WarningAction SilentlyContinue
        $PowerShellGetUpdated = $True
    }

    # Reset the LatestLocallyAvailable variables, and then load them into the current session
    $PackageManagementLatestLocallyAvailableVersionItem = $(Get-Module -ListAvailable -All | Where-Object {$_.Name -eq "PackageManagement"} | Sort-Object -Property Version)[-1]
    $PowerShellGetLatestLocallyAvailableVersionItem = $(Get-Module -ListAvailable -All | Where-Object {$_.Name -eq "PowerShellGet"} | Sort-Object -Property Version)[-1]
    $PackageManagementLatestLocallyAvailableVersion = $PackageManagementLatestLocallyAvailableVersionItem.Version
    $PowerShellGetLatestLocallyAvailableVersion = $PowerShellGetLatestLocallyAvailableVersionItem.Version
    Write-Verbose "Latest locally available PackageManagement version is $PackageManagementLatestLocallyAvailableVersion"
    Write-Verbose "Latest locally available PowerShellGet version is $PowerShellGetLatestLocallyAvailableVersion"

    $CurrentlyLoadedPackageManagementVersion = $(Get-Module | Where-Object {$_.Name -eq 'PackageManagement'}).Version
    $CurrentlyLoadedPowerShellGetVersion = $(Get-Module | Where-Object {$_.Name -eq 'PowerShellGet'}).Version
    Write-Verbose "Currently loaded PackageManagement version is $CurrentlyLoadedPackageManagementVersion"
    Write-Verbose "Currently loaded PowerShellGet version is $CurrentlyLoadedPowerShellGetVersion"

    if ($PackageManagementUpdated -eq $True -or $PowerShellGetUpdated -eq $True) {
        $NewPSSessionRequired = $True
        if ($LoadUpdatedModulesInSameSession) {
            if ($PowerShellGetUpdated -eq $True) {
                $PSGetWarningMsg = "Loading the latest installed version of PowerShellGet " +
                "(i.e. PowerShellGet $($PowerShellGetLatestLocallyAvailableVersion.ToString()) " +
                "in the current PowerShell session will break some PowerShellGet Cmdlets!"
                Write-Warning $PSGetWarningMsg
            }
            if ($PackageManagementUpdated -eq $True) {
                $PMWarningMsg = "Loading the latest installed version of PackageManagement " +
                "(i.e. PackageManagement $($PackageManagementLatestLocallyAvailableVersion.ToString()) " +
                "in the current PowerShell session will break some PackageManagement Cmdlets!"
                Write-Warning $PMWarningMsg
            }
        }
    }

    if ($LoadUpdatedModulesInSameSession) {
        if ($CurrentlyLoadedPackageManagementVersion -lt $PackageManagementLatestLocallyAvailableVersion) {
            # Need to remove PowerShellGet first since it depends on PackageManagement
            Write-Host "Removing Module PowerShellGet $CurrentlyLoadedPowerShellGetVersion ..."
            Remove-Module -Name "PowerShellGet"
            Write-Host "Removing Module PackageManagement $CurrentlyLoadedPackageManagementVersion ..."
            Remove-Module -Name "PackageManagement"
        
            if ($(Get-Host).Name -ne "Package Manager Host") {
                Write-Verbose "We are NOT in the Visual Studio Package Management Console. Continuing..."
                
                # Need to Import PackageManagement first since it's a dependency for PowerShellGet
                # Need to use -RequiredVersion parameter because older versions are still intalled side-by-side with new
                Write-Host "Importing PackageManagement Version $PackageManagementLatestLocallyAvailableVersion ..."
                $null = Import-Module "PackageManagement" -RequiredVersion $PackageManagementLatestLocallyAvailableVersion -ErrorVariable ImportPackManProblems 2>&1 6>&1
                Write-Host "Importing PowerShellGet Version $PowerShellGetLatestLocallyAvailableVersion ..."
                $null = Import-Module "PowerShellGet" -RequiredVersion $PowerShellGetLatestLocallyAvailableVersion -ErrorVariable ImportPSGetProblems 2>&1 6>&1
            }
            if ($(Get-Host).Name -eq "Package Manager Host") {
                Write-Verbose "We ARE in the Visual Studio Package Management Console. Continuing..."
        
                # Need to Import PackageManagement first since it's a dependency for PowerShellGet
                # Need to use -RequiredVersion parameter because older versions are still intalled side-by-side with new
                Write-Host "Importing PackageManagement Version $PackageManagementLatestLocallyAvailableVersion`nNOTE: Module Members will have with Prefix 'PackMan' - Example: Get-PackManPackage"
                $null = Import-Module "PackageManagement" -RequiredVersion $PackageManagementLatestLocallyAvailableVersion -Prefix PackMan -ErrorVariable ImportPackManProblems 2>&1 6>&1
                Write-Host "Importing PowerShellGet Version $PowerShellGetLatestLocallyAvailableVersion`nNOTE: Module Members will have with Prefix 'PSGet' - Example: Find-PSGetModule"
                $null = Import-Module "PowerShellGet" -RequiredVersion $PowerShellGetLatestLocallyAvailableVersion -Prefix PSGet -ErrorVariable ImportPSGetProblems 2>&1 6>&1
            }
        }
        
        # Reset CurrentlyLoaded Variables
        $CurrentlyLoadedPackageManagementVersion = $(Get-Module | Where-Object {$_.Name -eq 'PackageManagement'}).Version
        $CurrentlyLoadedPowerShellGetVersion = $(Get-Module | Where-Object {$_.Name -eq 'PowerShellGet'}).Version
        Write-Verbose "Currently loaded PackageManagement version is $CurrentlyLoadedPackageManagementVersion"
        Write-Verbose "Currently loaded PowerShellGet version is $CurrentlyLoadedPowerShellGetVersion"
        
        if ($CurrentlyLoadedPowerShellGetVersion -lt $PowerShellGetLatestLocallyAvailableVersion) {
            if (!$ImportPSGetProblems) {
                Write-Host "Removing Module PowerShellGet $CurrentlyLoadedPowerShellGetVersion ..."
            }
            Remove-Module -Name "PowerShellGet"
        
            if ($(Get-Host).Name -ne "Package Manager Host") {
                Write-Verbose "We are NOT in the Visual Studio Package Management Console. Continuing..."
                
                # Need to use -RequiredVersion parameter because older versions are still intalled side-by-side with new
                Write-Host "Importing PowerShellGet Version $PowerShellGetLatestLocallyAvailableVersion ..."
                Import-Module "PowerShellGet" -RequiredVersion $PowerShellGetLatestLocallyAvailableVersion
            }
            if ($(Get-Host).Name -eq "Package Manager Host") {
                Write-Host "We ARE in the Visual Studio Package Management Console. Continuing..."
        
                # Need to use -RequiredVersion parameter because older versions are still intalled side-by-side with new
                Write-Host "Importing PowerShellGet Version $PowerShellGetLatestLocallyAvailableVersion`nNOTE: Module Members will have with Prefix 'PSGet' - Example: Find-PSGetModule"
                Import-Module "PowerShellGet" -RequiredVersion $PowerShellGetLatestLocallyAvailableVersion -Prefix PSGet
            }
        }

        # Make sure all Repos Are Trusted
        if ($AddChocolateyPackageProvider -and $($PSVersionTable.PSEdition -eq "Desktop" -or $PSVersionTable.PSVersion.Major -le 5)) {
            $BaselineRepoNames = @("Chocolatey","nuget.org","PSGallery")
        }
        else {
            $BaselineRepoNames = @("nuget.org","PSGallery")
        }
        if ($(Get-Module -Name PackageManagement).ExportedCommands.Count -gt 0) {
            $RepoObjectsForTrustCheck = Get-PackageSource | Where-Object {$_.Name -match "$($BaselineRepoNames -join "|")"}
        
            foreach ($RepoObject in $RepoObjectsForTrustCheck) {
                if ($RepoObject.IsTrusted -ne $true) {
                    Set-PackageSource -Name $RepoObject.Name -Trusted
                }
            }
        }

        # Reset CurrentlyLoaded Variables
        $CurrentlyLoadedPackageManagementVersion = $(Get-Module | Where-Object {$_.Name -eq 'PackageManagement'}).Version
        $CurrentlyLoadedPowerShellGetVersion = $(Get-Module | Where-Object {$_.Name -eq 'PowerShellGet'}).Version
        Write-Verbose "The FINAL loaded PackageManagement version is $CurrentlyLoadedPackageManagementVersion"
        Write-Verbose "The FINAL loaded PowerShellGet version is $CurrentlyLoadedPowerShellGetVersion"

        #$ErrorsArrayReversed = $($Error.Count-1)..$($Error.Count-4) | foreach {$Error[$_]}
        #$CheckForError = try {$ErrorsArrayReversed[0].ToString()} catch {$null}
        if ($($ImportPackManProblems | Out-String) -match "Assembly with same name is already loaded" -or 
            $CurrentlyLoadedPackageManagementVersion -lt $PackageManagementLatestVersion -or
            $(Get-Module -Name PackageManagement).ExportedCommands.Count -eq 0
        ) {
            Write-Warning "The PackageManagement Module has been updated and requires and brand new PowerShell Session. Please close this session, start a new one, and run the function again."
            $NewPSSessionRequired = $true
        }
    }

    $Result = [pscustomobject][ordered]@{
        PackageManagementUpdated                     = if ($PackageManagementUpdated) {$true} else {$false}
        PowerShellGetUpdated                         = if ($PowerShellGetUpdated) {$true} else {$false}
        NewPSSessionRequired                         = if ($NewPSSessionRequired) {$true} else {$false}
        PackageManagementCurrentlyLoaded             = Get-Module -Name PackageManagement
        PowerShellGetCurrentlyLoaded                 = Get-Module -Name PowerShellGet
        PackageManagementLatesLocallyAvailable       = $PackageManagementLatestLocallyAvailableVersionItem
        PowerShellGetLatestLocallyAvailable          = $PowerShellGetLatestLocallyAvailableVersionItem
    }

    $Result
}

function Install-ChocolateyCmdLine {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$False)]
        [switch]$NoUpdatePackageManagement
    )

    ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####

    Write-Host "Please wait..."
    $global:FunctionResult = "0"
    $MyFunctionsUrl = "https://raw.githubusercontent.com/pldmgg/misc-powershell/master/MyFunctions"

    if (!$NoUpdatePackageManagement) {
        if (![bool]$(Get-Command Update-PackageManagement -ErrorAction SilentlyContinue)) {
            $UpdatePMFunctionUrl = "$MyFunctionsUrl/PowerShellCore_Compatible/Update-PackageManagement.ps1"
            try {
                Invoke-Expression $([System.Net.WebClient]::new().DownloadString($UpdatePMFunctionUrl))
            }
            catch {
                Write-Error $_
                Write-Error "Unable to load the Update-PackageManagement function! Halting!"
                $global:FunctionResult = "1"
                return
            }
        }

        try {
            $global:FunctionResult = "0"
            $UPMResult = Update-PackageManagement -AddChocolateyPackageProvider -ErrorAction SilentlyContinue -ErrorVariable UPMErr
            if ($global:FunctionResult -eq "1" -or $UPMResult -eq $null) {throw "The Update-PackageManagement function failed!"}
        }
        catch {
            Write-Error $_
            Write-Host "Errors from the Update-PackageManagement function are as follows:"
            Write-Error $($UPMErr | Out-String)
            $global:FunctionResult = "1"
            return
        }
    }

    if (![bool]$(Get-Command Refresh-ChocolateyEnv -ErrorAction SilentlyContinue)) {
        $RefreshCEFunctionUrl = "$MyFunctionsUrl/PowerShellCore_Compatible/Refresh-ChocolateyEnv.ps1"
        try {
            Invoke-Expression $([System.Net.WebClient]::new().DownloadString($RefreshCEFunctionUrl))
        }
        catch {
            Write-Error $_
            Write-Error "Unable to load the Refresh-ChocolateyEnv function! Halting!"
            $global:FunctionResult = "1"
            return
        }
    }

    ##### END Variable/Parameter Transforms and PreRun Prep #####


    ##### BEGIN Main Body #####

    if (![bool]$(Get-Command choco -ErrorAction SilentlyContinue)) {
        # The below Install-Package Chocolatey screws up $env:Path, so restore it afterwards
        $OriginalEnvPath = $env:Path

        # Installing Package Providers is spotty sometimes...Using while loop 3 times before failing
        $Counter = 0
        while ($(Get-PackageProvider).Name -notcontains "Chocolatey" -and $Counter -lt 3) {
            Install-PackageProvider -Name Chocolatey -Force -Confirm:$false -WarningAction SilentlyContinue
            $Counter++
            Start-Sleep -Seconds 5
        }
        if ($(Get-PackageProvider).Name -notcontains "Chocolatey") {
            Write-Error "Unable to install the Chocolatey Package Provider / Repo for PackageManagement/PowerShellGet! Halting!"
            $global:FunctionResult = "1"
            return
        }

        if (![bool]$(Get-Package -Name Chocolatey -ProviderName Chocolatey -ErrorAction SilentlyContinue)) {
            # NOTE: The PackageManagement install of choco is unreliable, so just in case, fallback to the Chocolatey cmdline for install
            $null = Install-Package Chocolatey -Provider Chocolatey -Force -Confirm:$false -ErrorVariable ChocoInstallError -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
            
            if ($ChocoInstallError.Count -gt 0) {
                Write-Warning "There was a problem installing the Chocolatey CmdLine via PackageManagement/PowerShellGet!"
                $InstallViaOfficialScript = $True
                Uninstall-Package Chocolatey -Force -ErrorAction SilentlyContinue
            }

            if ($ChocoInstallError.Count -eq 0) {
                $PMPGetInstall = $True
            }
        }

        # Try and find choco.exe
        try {
            Write-Host "Refreshing `$env:Path..."
            $global:FunctionResult = "0"
            $null = Refresh-ChocolateyEnv -ErrorAction SilentlyContinue -ErrorVariable RCEErr
            
            if ($RCEErr.Count -gt 0 -and
            $global:FunctionResult -eq "1" -and
            ![bool]$($RCEErr -match "Neither the Chocolatey PackageProvider nor the Chocolatey CmdLine appears to be installed!")) {
                throw "The Refresh-ChocolateyEnv function failed! Halting!"
            }
        }
        catch {
            Write-Error $_
            Write-Host "Errors from the Refresh-ChocolateyEnv function are as follows:"
            Write-Error $($RCEErr | Out-String)
            $global:FunctionResult = "1"
            return
        }

        if ($PMPGetInstall) {
            # It's possible that PowerShellGet didn't run the chocolateyInstall.ps1 script to actually install the
            # Chocolatey CmdLine. So do it manually.
            if (Test-Path "C:\Chocolatey") {
                $ChocolateyPath = "C:\Chocolatey"
            }
            elseif (Test-Path "C:\ProgramData\chocolatey") {
                $ChocolateyPath = "C:\ProgramData\chocolatey"
            }
            else {
                Write-Warning "Unable to find Chocolatey directory! Halting!"
                Write-Host "Installing via official script at https://chocolatey.org/install.ps1"
                $InstallViaOfficialScript = $True
            }
            
            if ($ChocolateyPath) {
                $ChocolateyInstallScript = $(Get-ChildItem -Path $ChocolateyPath -Recurse -File -Filter "*chocolateyinstall.ps1").FullName | Where-Object {
                    $_ -match ".*?chocolatey\.[0-9].*?chocolateyinstall.ps1$"
                }

                if (!$ChocolateyInstallScript) {
                    Write-Warning "Unable to find chocolateyinstall.ps1!"
                    $InstallViaOfficialScript = $True
                }
            }

            if ($ChocolateyInstallScript) {
                try {
                    Write-Host "Trying PowerShellGet Chocolatey CmdLine install script from $ChocolateyInstallScript ..." -ForegroundColor Yellow
                    & $ChocolateyInstallScript
                }
                catch {
                    Write-Error $_
                    Write-Error "The Chocolatey Install Script $ChocolateyInstallScript has failed!"

                    if ([bool]$(Get-Package $ProgramName)) {
                        Uninstall-Package Chocolatey -Force -ErrorAction SilentlyContinue
                    }
                }
            }
        }

        # If we still can't find choco.exe, then use the Chocolatey install script from chocolatey.org
        if (![bool]$(Get-Command choco -ErrorAction SilentlyContinue) -or $InstallViaOfficialScript) {
            $ChocolateyInstallScriptUrl = "https://chocolatey.org/install.ps1"
            try {
                Invoke-Expression $([System.Net.WebClient]::new().DownloadString($ChocolateyInstallScriptUrl))
            }
            catch {
                Write-Error $_
                Write-Error "Unable to install Chocolatey via the official chocolatey.org script! Halting!"
                $global:FunctionResult = "1"
                return
            }

            $PMPGetInstall = $False
        }
        
        # If we STILL can't find choco.exe, then Refresh-ChocolateyEnv a third time...
        #if (![bool]$($env:Path -split ";" -match "chocolatey\\bin")) {
        if (![bool]$(Get-Command choco -ErrorAction SilentlyContinue)) {
            # ...and then find it again and add it to $env:Path via Refresh-ChocolateyEnv function
            if (![bool]$(Get-Command choco -ErrorAction SilentlyContinue)) {
                try {
                    Write-Host "Refreshing `$env:Path..."
                    $global:FunctionResult = "0"
                    $null = Refresh-ChocolateyEnv -ErrorAction SilentlyContinue -ErrorVariable RCEErr
                    
                    if ($RCEErr.Count -gt 0 -and
                    $global:FunctionResult -eq "1" -and
                    ![bool]$($RCEErr -match "Neither the Chocolatey PackageProvider nor the Chocolatey CmdLine appears to be installed!")) {
                        throw "The Refresh-ChocolateyEnv function failed! Halting!"
                    }
                }
                catch {
                    Write-Error $_
                    Write-Host "Errors from the Refresh-ChocolateyEnv function are as follows:"
                    Write-Error $($RCEErr | Out-String)
                    $global:FunctionResult = "1"
                    return
                }
            }
        }

        # If we STILL can't find choco.exe, then give up...
        if (![bool]$(Get-Command choco -ErrorAction SilentlyContinue)) {
            Write-Error "Unable to find choco.exe after install! Check your `$env:Path! Halting!"
            $global:FunctionResult = "1"
            return
        }
        else {
            Write-Host "Finished installing Chocolatey CmdLine." -ForegroundColor Green

            try {
                cup chocolatey-core.extension -y
            }
            catch {
                Write-Error "Installation of chocolatey-core.extension via the Chocolatey CmdLine failed! Halting!"
                $global:FunctionResult = "1"
                return
            }

            try {
                Write-Host "Refreshing `$env:Path..."
                $global:FunctionResult = "0"
                $null = Refresh-ChocolateyEnv -ErrorAction SilentlyContinue -ErrorVariable RCEErr
                if ($RCEErr.Count -gt 0 -and $global:FunctionResult -eq "1") {
                    throw "The Refresh-ChocolateyEnv function failed! Halting!"
                }
            }
            catch {
                Write-Error $_
                Write-Host "Errors from the Refresh-ChocolateyEnv function are as follows:"
                Write-Error $($RCEErr | Out-String)
                $global:FunctionResult = "1"
                return
            }

            $ChocoModulesThatRefreshEnvShouldHaveLoaded = @(
                "chocolatey-core"
                "chocolateyInstaller"
                "chocolateyProfile"
                "chocolateysetup"
            )

            foreach ($ModName in $ChocoModulesThatRefreshEnvShouldHaveLoaded) {
                if ($(Get-Module).Name -contains $ModName) {
                    Write-Host "The $ModName Module has been loaded from $($(Get-Module -Name $ModName).Path)" -ForegroundColor Green
                }
            }
        }
    }
    else {
        Write-Warning "The Chocolatey CmdLine is already installed!"
    }

    ##### END Main Body #####
}

function Refresh-ChocolateyEnv {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [string]$ChocolateyDirectory
    )

    ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####

    # Fix any potential $env:Path mistakes...
    <#
    if ($env:Path -match ";;") {
        $env:Path = $env:Path -replace ";;",";"
    }
    #>

    ##### END Variable/Parameter Transforms and PreRun Prep #####

    ##### BEGIN Main Body #####

    if (![bool]$(Get-Command choco -ErrorAction SilentlyContinue)) {
        if ($ChocolateyDirectory) {
            $ChocolateyPath = $ChocolateyDirectory
        }
        else {
            if (Test-Path "C:\Chocolatey") {
                $ChocolateyPath = "C:\Chocolatey"
            }
            elseif (Test-Path "C:\ProgramData\chocolatey") {
                $ChocolateyPath = "C:\ProgramData\chocolatey"
            }
            else {
                Write-Error "Neither the Chocolatey PackageProvider nor the Chocolatey CmdLine appears to be installed! Halting!"
                $global:FunctionResult = "1"
                return
            }
        }
    }
    else {
        $ChocolateyPath = "$($($(Get-Command choco).Source -split "chocolatey")[0])chocolatey"
    }
    [System.Collections.ArrayList]$ChocolateyPathsPrep = @()
    [System.Collections.ArrayList]$ChocolateyPathsToAddToEnvPath = @()
    if (Test-Path $ChocolateyPath) {
        $($(Get-ChildItem $ChocolateyPath -Directory | foreach {
            Get-ChildItem $_.FullName -Recurse -File
        } | foreach {
            if ($_.Extension -eq ".exe" -or $_.Extension -eq ".bat") {
                $_.Directory.FullName
            }
        }) | Sort-Object | Get-Unique) | foreach {
            $null = $ChocolateyPathsPrep.Add($_.Trim("\\"))
        }

        foreach ($ChocoPath in $ChocolateyPathsPrep) {
            if ($(Test-Path $ChocoPath) -and $($env:Path -split ";") -notcontains $ChocoPath -and $ChocoPath -ne $null) {
                $null = $ChocolateyPathsToAddToEnvPath.Add($ChocoPath)
            }
        }

        foreach ($ChocoPath in $ChocolateyPathsToAddToEnvPath) {
            if ($env:Path[-1] -eq ";") {
                $env:Path = "$env:Path" + $ChocoPath + ";"
            }
            else {
                $env:Path = "$env:Path" + ";" + $ChocoPath
            }
        }
    }
    else {
        Write-Verbose "Unable to find Chocolatey Path $ChocolateyPath."
    }

    # Remove any repeats in $env:Path
    $UpdatedEnvPath = $($($($env:Path -split ";") | foreach {
        if (-not [System.String]::IsNullOrWhiteSpace($_)) {
            $_.Trim("\\")
        }
    }) | Select-Object -Unique) -join ";"

    # Next, find chocolatey-core.psm1, chocolateysetup.psm1, chocolateyInstaller.psm1, and chocolateyProfile.psm1
    # and import them
    $ChocoCoreModule = $(Get-ChildItem -Path $ChocolateyPath -Recurse -File -Filter "*chocolatey-core.psm1").FullName
    $ChocoSetupModule = $(Get-ChildItem -Path $ChocolateyPath -Recurse -File -Filter "*chocolateysetup.psm1").FullName
    $ChocoInstallerModule = $(Get-ChildItem -Path $ChocolateyPath -Recurse -File -Filter "*chocolateyInstaller.psm1").FullName
    $ChocoProfileModule = $(Get-ChildItem -Path $ChocolateyPath -Recurse -File -Filter "*chocolateyProfile.psm1").FullName

    $ChocoModulesToImportPrep = @($ChocoCoreModule, $ChocoSetupModule, $ChocoInstallerModule, $ChocoProfileModule)
    [System.Collections.ArrayList]$ChocoModulesToImport = @()
    foreach ($ModulePath in $ChocoModulesToImportPrep) {
        if ($ModulePath -ne $null) {
            $null = $ChocoModulesToImport.Add($ModulePath)
        }
    }

    foreach ($ModulePath in $ChocoModulesToImport) {
        Remove-Module -Name $([System.IO.Path]::GetFileNameWithoutExtension($ModulePath)) -ErrorAction SilentlyContinue
        Import-Module -Name $ModulePath
    }

    $UpdatedEnvPath

    ##### END Main Body #####

}

function Install-Program {
    [CmdletBinding(DefaultParameterSetName='ChocoCmdLine')]
    Param (
        [Parameter(Mandatory=$True)]
        [string]$ProgramName,

        [Parameter(Mandatory=$False)]
        [string]$CommandName,

        [Parameter(
            Mandatory=$False,
            ParameterSetName='PackageManagement'
        )]
        [switch]$UsePowerShellGet,

        [Parameter(
            Mandatory=$False,
            ParameterSetName='PackageManagement'
        )]
        [switch]$ForceChocoInstallScript,

        [Parameter(Mandatory=$False)]
        [switch]$UseChocolateyCmdLine,

        [Parameter(Mandatory=$False)]
        [string]$ExpectedInstallLocation,

        [Parameter(Mandatory=$False)]
        [switch]$NoUpdatePackageManagement = $True,

        [Parameter(Mandatory=$False)]
        [switch]$ScanCDriveForMainExeIfNecessary,

        [Parameter(Mandatory=$False)]
        [switch]$ResolveCommandPath = $True,

        [Parameter(Mandatory=$False)]
        [switch]$PreRelease
    )

    ##### BEGIN Native Helper Functions #####

    # The below function adds Paths from System PATH that aren't present in $env:Path (this probably shouldn't
    # be an issue, because $env:Path pulls from System PATH...but sometimes profile.ps1 scripts do weird things
    # and also $env:Path wouldn't necessarily be updated within the same PS session where a program is installed...)
    function Synchronize-SystemPathEnvPath {
        $SystemPath = $(Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment' -Name PATH).Path
        
        $SystemPathArray = $SystemPath -split ";" | foreach {if (-not [System.String]::IsNullOrWhiteSpace($_)) {$_}}
        $EnvPathArray = $env:Path -split ";" | foreach {if (-not [System.String]::IsNullOrWhiteSpace($_)) {$_}}
        
        # => means that $EnvPathArray HAS the paths but $SystemPathArray DOES NOT
        # <= means that $SystemPathArray HAS the paths but $EnvPathArray DOES NOT
        $PathComparison = Compare-Object $SystemPathArray $EnvPathArray
        [System.Collections.ArrayList][Array]$SystemPathsThatWeWantToAddToEnvPath = $($PathComparison | Where-Object {$_.SideIndicator -eq "<="}).InputObject

        if ($SystemPathsThatWeWantToAddToEnvPath.Count -gt 0) {
            foreach ($NewPath in $SystemPathsThatWeWantToAddToEnvPath) {
                if ($env:Path[-1] -eq ";") {
                    $env:Path = "$env:Path$NewPath"
                }
                else {
                    $env:Path = "$env:Path;$NewPath"
                }
            }
        }
    }

    # Outputs [System.Collections.ArrayList]$ExePath
    function Adjudicate-ExePath {
        [CmdletBinding()]
        Param (
            [Parameter(Mandatory=$True)]
            [string]$ProgramName,

            [Parameter(Mandatory=$True)]
            [string]$OriginalSystemPath,

            [Parameter(Mandatory=$True)]
            [string]$OriginalEnvPath,

            [Parameter(Mandatory=$True)]
            [string]$FinalCommandName,

            [Parameter(Mandatory=$False)]
            [string]$ExpectedInstallLocation
        )

        # ...search for it in the $ExpectedInstallLocation if that parameter is provided by the user...
        if ($ExpectedInstallLocation) {
            [System.Collections.ArrayList][Array]$ExePath = $(Get-ChildItem -Path $ExpectedInstallLocation -File -Recurse -Filter "*$FinalCommandName.exe").FullName
        }
        # If we don't have $ExpectedInstallLocation provided...
        if (!$ExpectedInstallLocation) {
            # ...then we can compare $OriginalSystemPath to the current System PATH to potentially
            # figure out which directories *might* contain the main executable.
            $OriginalSystemPathArray = $OriginalSystemPath -split ";" | foreach {if (-not [System.String]::IsNullOrWhiteSpace($_)) {$_}}
            $OriginalEnvPathArray = $OriginalEnvPath -split ";" | foreach {if (-not [System.String]::IsNullOrWhiteSpace($_)) {$_}}

            $CurrentSystemPath = $(Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment' -Name PATH).Path
            $CurrentSystemPathArray = $CurrentSystemPath -split ";" | foreach {if (-not [System.String]::IsNullOrWhiteSpace($_)) {$_}}
            $CurrentEnvPath = $env:Path
            $CurrentEnvPathArray = $CurrentEnvPath -split ";" | foreach {if (-not [System.String]::IsNullOrWhiteSpace($_)) {$_}}
            

            $OriginalVsCurrentSystemPathComparison = Compare-Object $OriginalSystemPathArray $CurrentSystemPathArray
            $OriginalVsCurrentEnvPathComparison = Compare-Object $OriginalEnvPathArray $CurrentEnvPathArray

            [System.Collections.ArrayList]$DirectoriesToSearch = @()
            if ($OriginalVsCurrentSystemPathComparison -ne $null) {
                # => means that $CurrentSystemPathArray has some new directories
                [System.Collections.ArrayList][Array]$NewSystemPathDirs = $($OriginalVsCurrentSystemPathComparison | Where-Object {$_.SideIndicator -eq "=>"}).InputObject
            
                if ($NewSystemPathDirs.Count -gt 0) {
                    foreach ($dir in $NewSystemPathDirs) {
                        $null = $DirectoriesToSearch.Add($dir)
                    }
                }
            }
            if ($OriginalVsCurrentEnvPathComparison -ne $null) {
                # => means that $CurrentEnvPathArray has some new directories
                [System.Collections.ArrayList][Array]$NewEnvPathDirs = $($OriginalVsCurrentEnvPathComparison | Where-Object {$_.SideIndicator -eq "=>"}).InputObject
            
                if ($NewEnvPathDirs.Count -gt 0) {
                    foreach ($dir in $NewEnvPathDirs) {
                        $null = $DirectoriesToSearch.Add($dir)
                    }
                }
            }

            if ($DirectoriesToSearch.Count -gt 0) {
                $DirectoriesToSearchFinal = $($DirectoriesToSearch | Sort-Object | Get-Unique) | foreach {if (Test-Path $_) {$_}}
                $DirectoriesToSearchFinal = $DirectoriesToSearchFinal | Where-Object {$_ -match "$ProgramName"}

                [System.Collections.ArrayList]$ExePath = @()
                foreach ($dir in $DirectoriesToSearchFinal) {
                    [Array]$ExeFiles = $(Get-ChildItem -Path $dir -File -Filter "*$FinalCommandName.exe").FullName
                    if ($ExeFiles.Count -gt 0) {
                        $null = $ExePath.Add($ExeFiles)
                    }
                }

                # If there IS a difference in original vs current System PATH / $Env:Path, but we 
                # still DO NOT find the main executable in those diff directories (i.e. $ExePath is still not set),
                # it's possible that the name of the main executable that we're looking for is actually
                # incorrect...in which case just tell the user that we can't find the expected main
                # executable name and provide a list of other .exe files that we found in the diff dirs.
                if (!$ExePath -or $ExePath.Count -eq 0) {
                    [System.Collections.ArrayList]$ExePath = @()
                    foreach ($dir in $DirectoriesToSearchFinal) {
                        [Array]$ExeFiles = $(Get-ChildItem -Path $dir -File -Filter "*.exe").FullName
                        foreach ($File in $ExeFiles) {
                            $null = $ExePath.Add($File)
                        }
                    }
                }
            }
        }

        $ExePath | Sort-Object | Get-Unique
    }

    ##### END Native Helper Functions #####

    ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####

    # Invoke-WebRequest fix...
    [Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls"

    if ($UseChocolateyCmdLine) {
        $NoUpdatePackageManagement = $True
    }

    Write-Host "Please wait..."
    $global:FunctionResult = "0"
    $MyFunctionsUrl = "https://raw.githubusercontent.com/pldmgg/misc-powershell/master/MyFunctions"

    $null = Install-PackageProvider -Name Nuget -Force -Confirm:$False
    $null = Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
    $null = Install-PackageProvider -Name Chocolatey -Force -Confirm:$False
    $null = Set-PackageSource -Name chocolatey -Trusted -Force

    if (!$NoUpdatePackageManagement) {
        if (![bool]$(Get-Command Update-PackageManagement -ErrorAction SilentlyContinue)) {
            $UpdatePMFunctionUrl = "$MyFunctionsUrl/PowerShellCore_Compatible/Update-PackageManagement.ps1"
            try {
                Invoke-Expression $([System.Net.WebClient]::new().DownloadString($UpdatePMFunctionUrl))
            }
            catch {
                Write-Error $_
                Write-Error "Unable to load the Update-PackageManagement function! Halting!"
                $global:FunctionResult = "1"
                return
            }
        }

        try {
            $global:FunctionResult = "0"
            $null = Update-PackageManagement -AddChocolateyPackageProvider -ErrorAction SilentlyContinue -ErrorVariable UPMErr
            if ($UPMErr -and $global:FunctionResult -eq "1") {throw "The Update-PackageManagement function failed! Halting!"}
        }
        catch {
            Write-Error $_
            Write-Host "Errors from the Update-PackageManagement function are as follows:"
            Write-Error $($UPMErr | Out-String)
            $global:FunctionResult = "1"
            return
        }
    }

    if ($UseChocolateyCmdLine -or $(!$UsePowerShellGet -and !$UseChocolateyCmdLine)) {
        if (![bool]$(Get-Command Install-ChocolateyCmdLine -ErrorAction SilentlyContinue)) {
            $InstallCCFunctionUrl = "$MyFunctionsUrl/Install-ChocolateyCmdLine.ps1"
            try {
                Invoke-Expression $([System.Net.WebClient]::new().DownloadString($InstallCCFunctionUrl))
            }
            catch {
                Write-Error $_
                Write-Error "Unable to load the Install-ChocolateyCmdLine function! Halting!"
                $global:FunctionResult = "1"
                return
            }
        }
    }

    if (![bool]$(Get-Command Refresh-ChocolateyEnv -ErrorAction SilentlyContinue)) {
        $RefreshCEFunctionUrl = "$MyFunctionsUrl/PowerShellCore_Compatible/Refresh-ChocolateyEnv.ps1"
        try {
            Invoke-Expression $([System.Net.WebClient]::new().DownloadString($RefreshCEFunctionUrl))
        }
        catch {
            Write-Error $_
            Write-Error "Unable to load the Refresh-ChocolateyEnv function! Halting!"
            $global:FunctionResult = "1"
            return
        }
    }

    # If PackageManagement/PowerShellGet is installed, determine if $ProgramName is installed
    if ([bool]$(Get-Command Get-Package -ErrorAction SilentlyContinue)) {
        $PackageManagementInstalledPrograms = Get-Package

        # If teh Current Installed Version is not equal to the Latest Version available, then it's outdated
        if ($PackageManagementInstalledPrograms.Name -contains $ProgramName) {
            $PackageManagementCurrentInstalledPackage = $PackageManagementInstalledPrograms | Where-Object {$_.Name -eq $ProgramName}
            $PackageManagementLatestVersion = $(Find-Package -Name $ProgramName -Source chocolatey -AllVersions | Sort-Object -Property Version)[-1]
        }
    }

    # If the Chocolatey CmdLine is installed, get a list of programs installed via Chocolatey
    if ([bool]$(Get-Command choco -ErrorAction SilentlyContinue)) {
        $ChocolateyInstalledProgramsPrep = clist --local-only
        $ChocolateyInstalledProgramsPrep = $ChocolateyInstalledProgramsPrep[1..$($ChocolateyInstalledProgramsPrep.Count-2)]

        [System.Collections.ArrayList]$ChocolateyInstalledProgramsPSObjects = @()

        foreach ($program in $ChocolateyInstalledProgramsPrep) {
            $programParsed = $program -split " "
            $PSCustomObject = [pscustomobject]@{
                ProgramName     = $programParsed[0]
                Version         = $programParsed[1]
            }

            $null = $ChocolateyInstalledProgramsPSObjects.Add($PSCustomObject)
        }

        # Also get a list of outdated packages in case this Install-Program function is used to update a package
        $ChocolateyOutdatedProgramsPrep = choco outdated
        $UpperLineMatch = $ChocolateyOutdatedProgramsPrep -match "Output is package name"
        $LowerLineMatch = $ChocolateyOutdatedProgramsPrep -match "Chocolatey has determined"
        $UpperIndex = $ChocolateyOutdatedProgramsPrep.IndexOf($UpperLineMatch) + 2
        $LowerIndex = $ChocolateyOutdatedProgramsPrep.IndexOf($LowerLineMatch) - 2
        $ChocolateyOutdatedPrograms = $ChocolateyOutdatedProgramsPrep[$UpperIndex..$LowerIndex]

        [System.Collections.ArrayList]$ChocolateyOutdatedProgramsPSObjects = @()
        foreach ($line in $ChocolateyOutdatedPrograms) {
            $ParsedLine = $line -split "\|"
            $Program = $ParsedLine[0]
            $CurrentInstalledVersion = $ParsedLine[1]
            $LatestAvailableVersion = $ParsedLine[2]

            $PSObject = [pscustomobject]@{
                ProgramName                 = $Program
                CurrentInstalledVersion     = $CurrentInstalledVersion
                LatestAvailableVersion      = $LatestAvailableVersion
            }

            $null = $ChocolateyOutdatedProgramsPSObjects.Add($PSObject)
        }
    }

    if ($CommandName -match "\.exe") {
        $CommandName = $CommandName -replace "\.exe",""
    }
    $FinalCommandName = if ($CommandName) {$CommandName} else {$ProgramName}

    # Save the original System PATH and $env:Path before we do anything, just in case
    $OriginalSystemPath = $(Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment' -Name PATH).Path
    $OriginalEnvPath = $env:Path
    Synchronize-SystemPathEnvPath
    $env:Path = Refresh-ChocolateyEnv -ErrorAction SilentlyContinue

    ##### END Variable/Parameter Transforms and PreRun Prep #####


    ##### BEGIN Main Body #####

    # Install $ProgramName if it's not already or if it's outdated...
    if ($($PackageManagementInstalledPrograms.Name -notcontains $ProgramName  -and
    $ChocolateyInstalledProgramsPSObjects.ProgramName -notcontains $ProgramName) -or
    $PackageManagementCurrentInstalledPackage.Version -ne $PackageManagementLatestVersion.Version -or
    $ChocolateyOutdatedProgramsPSObjects.ProgramName -contains $ProgramName
    ) {
        if ($UsePowerShellGet -or $(!$UsePowerShellGet -and !$UseChocolateyCmdLine) -or 
        $PackageManagementInstalledPrograms.Name -contains $ProgramName -and $ChocolateyInstalledProgramsPSObjects.ProgramName -notcontains $ProgramName
        ) {
            $InstallPackageSplatParams = @{
                Name            = $ProgramName
                Force           = $True
                ErrorAction     = "SilentlyContinue"
                ErrorVariable   = "InstallError"
                WarningAction   = "SilentlyContinue"
            }
            if ($PreRelease) {
                $LatestVersion = $(Find-Package $ProgramName -AllVersions)[-1].Version
                $InstallPackageSplatParams.Add("MinimumVersion",$LatestVersion)
            }
            # NOTE: The PackageManagement install of $ProgramName is unreliable, so just in case, fallback to the Chocolatey cmdline for install
            $null = Install-Package @InstallPackageSplatParams
            if ($InstallError.Count -gt 0) {
                $null = Uninstall-Package $ProgramName -Force -ErrorAction SilentlyContinue
                Write-Warning "There was a problem installing $ProgramName via PackageManagement/PowerShellGet!"
                
                if ($UsePowerShellGet) {
                    Write-Error "One or more errors occurred during the installation of $ProgramName via the the PackageManagement/PowerShellGet Modules failed! Installation has been rolled back! Halting!"
                    Write-Host "Errors for the Install-Package cmdlet are as follows:"
                    Write-Error $($InstallError | Out-String)
                    $global:FunctionResult = "1"
                    return
                }
                else {
                    Write-Host "Trying install via Chocolatey CmdLine..."
                    $PMInstall = $False
                }
            }
            else {
                $PMInstall = $True

                # Since Installation via PackageManagement/PowerShellGet was succesful, let's update $env:Path with the
                # latest from System PATH before we go nuts trying to find the main executable manually
                Synchronize-SystemPathEnvPath
                $env:Path = $($(Refresh-ChocolateyEnv -ErrorAction SilentlyContinue) -split ";" | foreach {
                    if (-not [System.String]::IsNullOrWhiteSpace($_) -and $(Test-Path $_)) {$_}
                }) -join ";"
            }
        }

        if (!$PMInstall -or $UseChocolateyCmdLine -or
        $ChocolateyInstalledProgramsPSObjects.ProgramName -contains $ProgramName
        ) {
            try {
                Write-Host "Refreshing `$env:Path..."
                $global:FunctionResult = "0"
                $env:Path = Refresh-ChocolateyEnv -ErrorAction SilentlyContinue -ErrorVariable RCEErr

                # The first time we attempt to Refresh-ChocolateyEnv, Chocolatey CmdLine and/or the
                # Chocolatey Package Provider legitimately might not be installed,
                # so if the Refresh-ChocolateyEnv function throws that error, we can ignore it
                if ($RCEErr.Count -gt 0 -and
                $global:FunctionResult -eq "1" -and
                ![bool]$($RCEErr -match "Neither the Chocolatey PackageProvider nor the Chocolatey CmdLine appears to be installed!")) {
                    throw "The Refresh-ChocolateyEnv function failed! Halting!"
                }
            }
            catch {
                Write-Error $_
                Write-Host "Errors from the Refresh-ChocolateyEnv function are as follows:"
                Write-Error $($RCEErr | Out-String)
                $global:FunctionResult = "1"
                return
            }

            # Make sure Chocolatey CmdLine is installed...if not, install it
            if (![bool]$(Get-Command choco -ErrorAction SilentlyContinue)) {
                try {
                    $global:FunctionResult = "0"
                    $null = Install-ChocolateyCmdLine -NoUpdatePackageManagement -ErrorAction SilentlyContinue -ErrorVariable ICCErr
                    if ($ICCErr -and $global:FunctionResult -eq "1") {throw "The Install-ChocolateyCmdLine function failed! Halting!"}
                }
                catch {
                    Write-Error $_
                    Write-Host "Errors from the Install-ChocolateyCmdline function are as follows:"
                    Write-Error $($ICCErr | Out-String)
                    $global:FunctionResult = "1"
                    return
                }
            }

            try {
                # TODO: Figure out how to handle errors from choco.exe. Some we can ignore, others
                # we shouldn't. But I'm not sure what all of the possibilities are so I can't
                # control for them...
                if ($PreRelease) {
                    $null = cup $ProgramName --pre -y
                }
                else {
                    $null = cup $ProgramName -y
                }
                $ChocoInstall = $true

                # Since Installation via the Chocolatey CmdLine was succesful, let's update $env:Path with the
                # latest from System PATH before we go nuts trying to find the main executable manually
                Synchronize-SystemPathEnvPath
                $env:Path = Refresh-ChocolateyEnv -ErrorAction SilentlyContinue
            }
            catch {
                Write-Error "There was a problem installing $ProgramName using the Chocolatey cmdline! Halting!"
                $global:FunctionResult = "1"
                return
            }
        }

        if ($ResolveCommandPath -or $PSBoundParameters['CommandName']) {
            ## BEGIN Try to Find Main Executable Post Install ##

            # Now the parent directory of $ProgramName's main executable should be part of the SYSTEM Path
            # (and therefore part of $env:Path). If not, try to find it in Chocolatey directories...
            if ($(Get-Command $FinalCommandName -ErrorAction SilentlyContinue).CommandType -eq "Alias") {
                while (Test-Path Alias:\$FinalCommandName) {
                    Remove-Item Alias:\$FinalCommandName
                }
            }

            if (![bool]$(Get-Command $FinalCommandName -ErrorAction SilentlyContinue)) {
                try {
                    Write-Host "Refreshing `$env:Path..."
                    $global:FunctionResult = "0"
                    $env:Path = Refresh-ChocolateyEnv -ErrorAction SilentlyContinue -ErrorVariable RCEErr
                    if ($RCEErr.Count -gt 0 -and $global:FunctionResult -eq "1") {throw "The Refresh-ChocolateyEnv function failed! Halting!"}
                }
                catch {
                    Write-Error $_
                    Write-Host "Errors from the Refresh-ChocolateyEnv function are as follows:"
                    Write-Error $($RCEErr | Out-String)
                    $global:FunctionResult = "1"
                    return
                }
            }
            
            # If we still can't find the main executable...
            if (![bool]$(Get-Command $FinalCommandName -ErrorAction SilentlyContinue) -and $(!$ExePath -or $ExePath.Count -eq 0)) {
                $env:Path = Refresh-ChocolateyEnv -ErrorAction SilentlyContinue
                
                if ($ExpectedInstallLocation) {
                    [System.Collections.ArrayList][Array]$ExePath = Adjudicate-ExePath -ProgramName $ProgramName -OriginalSystemPath $OriginalSystemPath -OriginalEnvPath $OriginalEnvPath -FinalCommandName $FinalCommandName -ExpectedInstallLocation $ExpectedInstallLocation
                }
                else {
                    [System.Collections.ArrayList][Array]$ExePath = Adjudicate-ExePath -ProgramName $ProgramName -OriginalSystemPath $OriginalSystemPath -OriginalEnvPath $OriginalEnvPath -FinalCommandName $FinalCommandName
                }
            }

            # Determine if there's an exact match for the $FinalCommandName
            if (![bool]$(Get-Command $FinalCommandName -ErrorAction SilentlyContinue)) {
                if ($ExePath.Count -ge 1) {
                    if ([bool]$($ExePath -match "\\$FinalCommandName.exe$")) {
                        $FoundExactCommandMatch = $True
                    }
                }
            }

            # If we STILL can't find the main executable...
            if ($(![bool]$(Get-Command $FinalCommandName -ErrorAction SilentlyContinue) -and $(!$ExePath -or $ExePath.Count -eq 0)) -or 
            $(!$FoundExactCommandMatch -and $PSBoundParameters['CommandName']) -or 
            $($ResolveCommandPath -and !$FoundExactCommandMatch) -or $ForceChocoInstallScript) {
                # If, at this point we don't have $ExePath, if we did a $ChocoInstall, then we have to give up...
                # ...but if we did a $PMInstall, then it's possible that PackageManagement/PowerShellGet just
                # didn't run the chocolateyInstall.ps1 script that sometimes comes bundled with Packages from the
                # Chocolatey Package Provider/Repo. So try running that...
                if ($ChocoInstall) {
                    if (![bool]$(Get-Command $FinalCommandName -ErrorAction SilentlyContinue)) {
                        Write-Warning "Unable to find main executable for $ProgramName!"
                        $MainExeSearchFail = $True
                    }
                }
                if ($PMInstall -or $ForceChocoInstallScript) {
                    [System.Collections.ArrayList]$PossibleChocolateyInstallScripts = @()
                    
                    if (Test-Path "C:\Chocolatey") {
                        $ChocoScriptsA = Get-ChildItem -Path "C:\Chocolatey" -Recurse -File -Filter "*chocolateyinstall.ps1" | Where-Object {$($(Get-Date) - $_.CreationTime).TotalMinutes -lt 5}
                        foreach ($Script in $ChocoScriptsA) {
                            $null = $PossibleChocolateyInstallScripts.Add($Script)
                        }
                    }
                    if (Test-Path "C:\ProgramData\chocolatey") {
                        $ChocoScriptsB = Get-ChildItem -Path "C:\ProgramData\chocolatey" -Recurse -File -Filter "*chocolateyinstall.ps1" | Where-Object {$($(Get-Date) - $_.CreationTime).TotalMinutes -lt 5}
                        foreach ($Script in $ChocoScriptsB) {
                            $null = $PossibleChocolateyInstallScripts.Add($Script)
                        }
                    }

                    [System.Collections.ArrayList][Array]$ChocolateyInstallScriptSearch = $PossibleChocolateyInstallScripts.FullName | Where-Object {$_ -match ".*?$ProgramName.*?chocolateyinstall.ps1$"}
                    if ($ChocolateyInstallScriptSearch.Count -eq 0) {
                        Write-Warning "Unable to find main the Chocolatey Install Script for $ProgramName PowerShellGet install!"
                        $MainExeSearchFail = $True
                    }
                    if ($ChocolateyInstallScriptSearch.Count -eq 1) {
                        $ChocolateyInstallScript = $ChocolateyInstallScriptSearch[0]
                    }
                    if ($ChocolateyInstallScriptSearch.Count -gt 1) {
                        $ChocolateyInstallScript = $($ChocolateyInstallScriptSearch | Sort-Object LastWriteTime)[-1]
                    }
                    
                    if ($ChocolateyInstallScript) {
                        try {
                            Write-Host "Trying the Chocolatey Install script from $ChocolateyInstallScript..." -ForegroundColor Yellow
                            & $ChocolateyInstallScript

                            # Now that the $ChocolateyInstallScript ran, search for the main executable again
                            Synchronize-SystemPathEnvPath
                            $env:Path = Refresh-ChocolateyEnv -ErrorAction SilentlyContinue

                            if ($ExpectedInstallLocation) {
                                [System.Collections.ArrayList][Array]$ExePath = Adjudicate-ExePath -ProgramName $ProgramName -OriginalSystemPath $OriginalSystemPath -OriginalEnvPath $OriginalEnvPath -FinalCommandName $FinalCommandName -ExpectedInstallLocation $ExpectedInstallLocation
                            }
                            else {
                                [System.Collections.ArrayList][Array]$ExePath = Adjudicate-ExePath -ProgramName $ProgramName -OriginalSystemPath $OriginalSystemPath -OriginalEnvPath $OriginalEnvPath -FinalCommandName $FinalCommandName
                            }

                            # If we STILL don't have $ExePath, then we have to give up...
                            if (!$ExePath -or $ExePath.Count -eq 0) {
                                Write-Warning "Unable to find main executable for $ProgramName!"
                                $MainExeSearchFail = $True
                            }
                        }
                        catch {
                            Write-Error $_
                            Write-Error "The Chocolatey Install Script $ChocolateyInstallScript has failed!"

                            # If PackageManagement/PowerShellGet is ERRONEOUSLY reporting that the program was installed
                            # use the Uninstall-Package cmdlet to wipe it out. This scenario happens when PackageManagement/
                            # PackageManagement/PowerShellGet gets a Package from the Chocolatey Package Provider/Repo but
                            # fails to run the chocolateyInstall.ps1 script for some reason.
                            if ([bool]$(Get-Package $ProgramName -ErrorAction SilentlyContinue)) {
                                $null = Uninstall-Package $ProgramName -Force -ErrorAction SilentlyContinue
                            }

                            # Now we need to try the Chocolatey CmdLine. Easiest way to do this at this point is to just
                            # invoke the function again with the same parameters, but specify -UseChocolateyCmdLine
                            $BoundParametersDictionary = $PSCmdlet.MyInvocation.BoundParameters
                            $InstallProgramSplatParams = @{}
                            foreach ($kvpair in $BoundParametersDictionary.GetEnumerator()) {
                                $key = $kvpair.Key
                                $value = $BoundParametersDictionary[$key]
                                if ($key -notmatch "UsePowerShellGet|ForceChocoInstallScript" -and $InstallProgramSplatParams.Keys -notcontains $key) {
                                    $InstallProgramSplatParams.Add($key,$value)
                                }
                            }
                            if ($InstallProgramSplatParams.Keys -notcontains "UseChocolateyCmdLine") {
                                $InstallProgramSplatParams.Add("UseChocolateyCmdLine",$True)
                            }
                            if ($InstallProgramSplatParams.Keys -notcontains "NoUpdatePackageManagement") {
                                $InstallProgramSplatParams.Add("NoUpdatePackageManagement",$True)
                            }
                            Install-Program @InstallProgramSplatParams

                            return
                        }
                    }
                }
            }

            ## END Try to Find Main Executable Post Install ##
        }
    }
    else {
        if ($ChocolateyInstalledProgramsPSObjects.ProgramName -contains $ProgramName) {
            Write-Warning "$ProgramName is already installed via the Chocolatey CmdLine!"
            $AlreadyInstalled = $True
        }
        elseif ([bool]$(Get-Package $ProgramName -ErrorAction SilentlyContinue)) {
            Write-Warning "$ProgramName is already installed via PackageManagement/PowerShellGet!"
            $AlreadyInstalled = $True
        }
    }

    # If we weren't able to find the main executable (or any potential main executables) for
    # $ProgramName, offer the option to scan the whole C:\ drive (with some obvious exceptions)
    if ($MainExeSearchFail -and $($ResolveCommandPath -or $PSBoundParameters['CommandName']) -and
    ![bool]$(Get-Command $FinalCommandName -ErrorAction SilentlyContinue)) {
        if (!$ScanCDriveForMainExeIfNecessary -and $ResolveCommandPath -and !$PSBoundParameters['CommandName']) {
            $ScanCDriveChoice = Read-Host -Prompt "Would you like to scan C:\ for $FinalCommandName.exe? NOTE: This search excludes system directories but still could take some time. [Yes\No]"
            while ($ScanCDriveChoice -notmatch "Yes|yes|Y|y|No|no|N|n") {
                Write-Host "$ScanDriveChoice is not a valid input. Please enter 'Yes' or 'No'"
                $ScanCDriveChoice = Read-Host -Prompt "Would you like to scan C:\ for $FinalCommandName.exe? NOTE: This search excludes system directories but still could take some time. [Yes\No]"
            }
        }

        if ($ScanCDriveChoice -match "Yes|yes|Y|y" -or $ScanCDriveForMainExeIfNecessary) {
            $DirectoriesToSearchRecursively = $(Get-ChildItem -Path "C:\" -Directory | Where-Object {$_.Name -notmatch "Windows|PerfLogs|Microsoft"}).FullName
            [System.Collections.ArrayList]$ExePath = @()
            foreach ($dir in $DirectoriesToSearchRecursively) {
                $FoundFiles = $(Get-ChildItem -Path $dir -Recurse -File).FullName
                foreach ($FilePath in $FoundFiles) {
                    if ($FilePath -match "(.*?)$FinalCommandName([^\\]+)") {
                        $null = $ExePath.Add($FilePath)
                    }
                }
            }
        }
    }

    if ($ResolveCommandPath -or $PSBoundParameters['CommandName']) {
        # Finalize $env:Path
        if ([bool]$($ExePath -match "\\$FinalCommandName.exe$")) {
            $PathToAdd = $($ExePath -match "\\$FinalCommandName.exe$") | Split-Path -Parent
            if ($($env:Path -split ";") -notcontains $PathToAdd) {
                if ($env:Path[-1] -eq ";") {
                    $env:Path = "$env:Path" + $PathToAdd + ";"
                }
                else {
                    $env:Path = "$env:Path" + ";" + $PathToAdd
                }
            }
        }
        $FinalEnvPathArray = $env:Path -split ";" | foreach {if(-not [System.String]::IsNullOrWhiteSpace($_)) {$_}}
        $FinalEnvPathString = $($FinalEnvPathArray | foreach {if (Test-Path $_) {$_}}) -join ";"
        $env:Path = $FinalEnvPathString

        if (![bool]$(Get-Command $FinalCommandName -ErrorAction SilentlyContinue)) {
            # Try to determine Main Executable
            if (!$ExePath -or $ExePath.Count -eq 0) {
                $FinalExeLocation = "NotFound"
            }
            elseif ($ExePath.Count -eq 1) {
                $UpdatedFinalCommandName = $ExePath | Split-Path -Leaf

                try {
                    $FinalExeLocation = $(Get-Command $UpdatedFinalCommandName -ErrorAction SilentlyContinue).Source
                }
                catch {
                    $FinalExeLocation = $ExePath
                }
            }
            elseif ($ExePath.Count -gt 1) {
                if (![bool]$($ExePath -match "\\$FinalCommandName.exe$")) {
                    Write-Warning "No exact match for main executable $FinalCommandName.exe was found. However, other executables associated with $ProgramName were found."
                }
                $FinalExeLocation = $ExePath
            }
        }
        else {
            $FinalExeLocation = $(Get-Command $FinalCommandName).Source
        }
    }

    if ($ChocoInstall) {
        $InstallManager = "choco.exe"
        $InstallCheck = $(clist --local-only $ProgramName)[1]
    }
    if ($PMInstall -or [bool]$(Get-Package $ProgramName -ProviderName Chocolatey -ErrorAction SilentlyContinue)) {
        $InstallManager = "PowerShellGet"
        $InstallCheck = Get-Package $ProgramName -ErrorAction SilentlyContinue
    }

    if ($AlreadyInstalled) {
        $InstallAction = "AlreadyInstalled"
    }
    elseif ($PackageManagementCurrentInstalledPackage.Version -ne $PackageManagementLatestVersion.Version -or
    $ChocolateyOutdatedProgramsPSObjects.ProgramName -contains $ProgramName
    ) {
        $InstallAction = "Updated"
    }
    else {
        $InstallAction = "FreshInstall"
    }

    $env:Path = Refresh-ChocolateyEnv

    [pscustomobject]@{
        InstallManager      = $InstallManager
        InstallAction       = $InstallAction
        InstallCheck        = $InstallCheck
        MainExecutable      = $FinalExeLocation
        OriginalSystemPath  = $OriginalSystemPath
        CurrentSystemPath   = $(Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment' -Name PATH).Path
        OriginalEnvPath     = $OriginalEnvPath
        CurrentEnvPath      = $env:Path
    }

    ##### END Main Body #####
}

function Resolve-Host {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [string]$HostNameOrIP
    )

    ## BEGIN Native Helper Functions ##

    function Test-IsValidIPAddress([string]$IPAddress) {
        [boolean]$Octets = (($IPAddress.Split(".") | Measure-Object).Count -eq 4) 
        [boolean]$Valid  =  ($IPAddress -as [ipaddress]) -as [boolean]
        Return  ($Valid -and $Octets)
    }

    ## END Native Helper Functions ##
    

    ##### BEGIN Main Body #####

    $RemoteHostNetworkInfoArray = @()
    if (!$(Test-IsValidIPAddress -IPAddress $HostNameOrIP)) {
        try {
            $HostNamePrep = $HostNameOrIP
            [System.Collections.ArrayList]$RemoteHostArrayOfIPAddresses = @()
            $IPv4AddressFamily = "InterNetwork"
            $IPv6AddressFamily = "InterNetworkV6"

            $ResolutionInfo = [System.Net.Dns]::GetHostEntry($HostNamePrep)
            $ResolutionInfo.AddressList | Where-Object {
                $_.AddressFamily -eq $IPv4AddressFamily
            } | foreach {
                if ($RemoteHostArrayOfIPAddresses -notcontains $_.IPAddressToString) {
                    $null = $RemoteHostArrayOfIPAddresses.Add($_.IPAddressToString)
                }
            }
        }
        catch {
            Write-Verbose "Unable to resolve $HostNameOrIP when treated as a Host Name (as opposed to IP Address)!"
        }
    }
    if (Test-IsValidIPAddress -IPAddress $HostNameOrIP) {
        try {
            $HostIPPrep = $HostNameOrIP
            [System.Collections.ArrayList]$RemoteHostArrayOfIPAddresses = @()
            $null = $RemoteHostArrayOfIPAddresses.Add($HostIPPrep)

            $ResolutionInfo = [System.Net.Dns]::GetHostEntry($HostIPPrep)

            [System.Collections.ArrayList]$RemoteHostFQDNs = @() 
            $null = $RemoteHostFQDNs.Add($ResolutionInfo.HostName)
        }
        catch {
            Write-Verbose "Unable to resolve $HostNameOrIP when treated as an IP Address (as opposed to Host Name)!"
        }
    }

    if ($RemoteHostArrayOfIPAddresses.Count -eq 0) {
        Write-Error "Unable to determine IP Address of $HostNameOrIP! Halting!"
        $global:FunctionResult = "1"
        return
    }

    # At this point, we have $RemoteHostArrayOfIPAddresses...
    [System.Collections.ArrayList]$RemoteHostFQDNs = @()
    foreach ($HostIP in $RemoteHostArrayOfIPAddresses) {
        try {
            $FQDNPrep = [System.Net.Dns]::GetHostEntry($HostIP).HostName
        }
        catch {
            Write-Verbose "Unable to resolve $HostIP. No PTR Record? Please check your DNS config."
            continue
        }
        if ($RemoteHostFQDNs -notcontains $FQDNPrep) {
            $null = $RemoteHostFQDNs.Add($FQDNPrep)
        }
    }

    if ($RemoteHostFQDNs.Count -eq 0) {
        $null = $RemoteHostFQDNs.Add($ResolutionInfo.HostName)
    }

    [System.Collections.ArrayList]$HostNameList = @()
    [System.Collections.ArrayList]$DomainList = @()
    foreach ($fqdn in $RemoteHostFQDNs) {
        $PeriodCheck = $($fqdn | Select-String -Pattern "\.").Matches.Success
        if ($PeriodCheck) {
            $HostName = $($fqdn -split "\.")[0]
            $Domain = $($fqdn -split "\.")[1..$($($fqdn -split "\.").Count-1)] -join '.'
        }
        else {
            $HostName = $fqdn
            $Domain = "Unknown"
        }

        $null = $HostNameList.Add($HostName)
        $null = $DomainList.Add($Domain)
    }

    if ($RemoteHostFQDNs[0] -eq $null -and $HostNameList[0] -eq $null -and $DomainList -eq "Unknown" -and $RemoteHostArrayOfIPAddresses) {
        [System.Collections.ArrayList]$SuccessfullyPingedIPs = @()
        # Test to see if we can reach the IP Addresses
        foreach ($ip in $RemoteHostArrayOfIPAddresses) {
            if ([bool]$(Test-Connection $ip -Count 1 -ErrorAction SilentlyContinue)) {
                $null = $SuccessfullyPingedIPs.Add($ip)
            }
        }

        if ($SuccessfullyPingedIPs.Count -eq 0) {
            Write-Error "Unable to resolve $HostNameOrIP! Halting!"
            $global:FunctionResult = "1"
            return
        }
    }

    $FQDNPrep = if ($RemoteHostFQDNs) {$RemoteHostFQDNs[0]} else {$null}
    if ($FQDNPrep -match ',') {
        $FQDN = $($FQDNPrep -split ',')[0]
    }
    else {
        $FQDN = $FQDNPrep
    }

    $DomainPrep = if ($DomainList) {$DomainList[0]} else {$null}
    if ($DomainPrep -match ',') {
        $Domain = $($DomainPrep -split ',')[0]
    }
    else {
        $Domain = $DomainPrep
    }

    [pscustomobject]@{
        IPAddressList   = [System.Collections.ArrayList]@($(if ($SuccessfullyPingedIPs) {$SuccessfullyPingedIPs} else {$RemoteHostArrayOfIPAddresses}))
        FQDN            = $FQDN
        HostName        = if ($HostNameList) {$HostNameList[0].ToLowerInvariant()} else {$null}
        Domain          = $Domain
    }

    ##### END Main Body #####

}

function Check-InstalledPrograms { 
    [CmdletBinding(
        PositionalBinding=$True,
        DefaultParameterSetName='Default Param Set'
    )]
    Param(
        [Parameter(
            Mandatory=$False,
            ParameterSetName='Default Param Set'
        )]
        [string]$ProgramTitleSearchTerm,

        [Parameter(
            Mandatory=$False,
            ParameterSetName='Default Param Set'
        )]
        [string[]]$HostName = $env:COMPUTERNAME,

        [Parameter(
            Mandatory=$False,
            ParameterSetName='Secondary Param Set'
        )]
        [switch]$AllADWindowsComputers

    )

    ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####

    $uninstallWow6432Path = "\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    $uninstallPath = "\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"

    $RegPaths = @(
        "HKLM:$uninstallWow6432Path",
        "HKLM:$uninstallPath",
        "HKCU:$uninstallWow6432Path",
        "HKCU:$uninstallPath"
    )
    
    ##### END Variable/Parameter Transforms and PreRun Prep #####

    ##### BEGIN Main Body #####
    # Get a list of Windows Computers from AD
    if ($AllADWindowsComputers) {
        $ComputersArray = $(Get-ADComputer -Filter * -Property * | Where-Object {$_.OperatingSystem -like "*Windows*"}).Name
    }
    else {
        $ComputersArray = $env:COMPUTERNAME
    }

    foreach ($computer in $ComputersArray) {
        if ($computer -eq $env:COMPUTERNAME -or $computer.Split("\.")[0] -eq $env:COMPUTERNAME) {
            try {
                $InstalledPrograms = foreach ($regpath in $RegPaths) {if (Test-Path $regpath) {Get-ItemProperty $regpath}}
                if (!$?) {
                    throw
                }
            }
            catch {
                Write-Warning "Unable to find registry path(s) on $computer. Skipping..."
                continue
            }
        }
        else {
            try {
                $InstalledPrograms = Invoke-Command -ComputerName $computer -ScriptBlock {
                    foreach ($regpath in $RegPaths) {
                        if (Test-Path $regpath) {
                            Get-ItemProperty $regpath
                        }
                    }
                } -ErrorAction SilentlyContinue
                if (!$?) {
                    throw
                }
            }
            catch {
                Write-Warning "Unable to connect to $computer. Skipping..."
                continue
            }
        }

        if ($ProgramTitleSearchTerm) {
            $InstalledPrograms | Where-Object {$_.DisplayName -like "*$ProgramTitleSearchTerm*"}
        }
        else {
            $InstalledPrograms
        }
    }

    ##### END Main Body #####

}

# Example Usage: Get-DomainController -Domain $(Get-CimInstance Win32_ComputerSystem).Domain
# If you don't specify -Domain, it defaults to the one you're currently on
function Get-DomainController {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$False)]
        [String]$Domain
    )

    ##### BEGIN Helper Functions #####

    function Parse-NLTest {
        [CmdletBinding()]
        Param (
            [Parameter(Mandatory=$True)]
            [string]$Domain
        )

        while ($Domain -notmatch "\.") {
            Write-Warning "The provided value for the -Domain parameter is not in the correct format. Please use the entire domain name (including periods)."
            $Domain = Read-Host -Prompt "Please enter the full domain name (including periods)"
        }

        if (![bool]$(Get-Command nltest -ErrorAction SilentlyContinue)) {
            Write-Error "Unable to find nltest.exe! Halting!"
            $global:FunctionResult = "1"
            return
        }

        $DomainPrefix = $($Domain -split '\.')[0]
        $PrimaryDomainControllerPrep = Invoke-Expression "nltest /dclist:$DomainPrefix 2>null"
        if (![bool]$($PrimaryDomainControllerPrep | Select-String -Pattern 'PDC')) {
            Write-Error "Can't find the Primary Domain Controller for domain $DomainPrefix"
            return
        }
        $PrimaryDomainControllerPrep = $($($PrimaryDomainControllerPrep -match 'PDC').Trim() -split ' ')[0]
        if ($PrimaryDomainControllerPrep -match '\\\\') {
            $PrimaryDomainController = $($PrimaryDomainControllerPrep -replace '\\\\','').ToLower() + ".$Domain"
        }
        else {
            $PrimaryDomainController = $PrimaryDomainControllerPrep.ToLower() + ".$Domain"
        }

        $PrimaryDomainController
    }

    ##### END Helper Functions #####


    ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####

    $ComputerSystemCim = Get-CimInstance Win32_ComputerSystem
    $PartOfDomain = $ComputerSystemCim.PartOfDomain

    ##### END Variable/Parameter Transforms and PreRun Prep #####


    ##### BEGIN Main Body #####

    if (!$PartOfDomain -and !$Domain) {
        Write-Error "$env:Computer is NOT part of a Domain and the -Domain parameter was not used in order to specify a domain! Halting!"
        $global:FunctionResult = "1"
        return
    }
    
    $ThisMachinesDomain = $ComputerSystemCim.Domain

    if ($Domain) {
        try {
            $Forest = [system.directoryservices.activedirectory.Forest]::GetCurrentForest()
        }
        catch {
            Write-Verbose "Cannot connect to current forest."
        }

        if ($ThisMachinesDomain -eq $Domain -and $Forest.Domains -contains $Domain) {
            [System.Collections.ArrayList]$FoundDomainControllers = $Forest.Domains | Where-Object {$_.Name -eq $Domain} | foreach {$_.DomainControllers} | foreach {$_.Name}
            $PrimaryDomainController = $Forest.Domains.PdcRoleOwner.Name
        }
        if ($ThisMachinesDomain -eq $Domain -and $Forest.Domains -notcontains $Domain) {
            try {
                $GetCurrentDomain = [system.directoryservices.activedirectory.domain]::GetCurrentDomain()
                [System.Collections.ArrayList]$FoundDomainControllers = $GetCurrentDomain | foreach {$_.DomainControllers} | foreach {$_.Name}
                $PrimaryDomainController = $GetCurrentDomain.PdcRoleOwner.Name
            }
            catch {
                try {
                    Write-Warning "Only able to report the Primary Domain Controller for $Domain! Other Domain Controllers most likely exist!"
                    Write-Warning "For a more complete list, try running this function on a machine that is part of the domain $Domain!"
                    $PrimaryDomainController = Parse-NLTest -Domain $Domain
                    [System.Collections.ArrayList]$FoundDomainControllers = @($PrimaryDomainController)
                }
                catch {
                    Write-Error $_
                    $global:FunctionResult = "1"
                    return
                }
            }
        }
        if ($ThisMachinesDomain -ne $Domain -and $Forest.Domains -contains $Domain) {
            [System.Collections.ArrayList]$FoundDomainControllers = $Forest.Domains | foreach {$_.DomainControllers} | foreach {$_.Name}
            $PrimaryDomainController = $Forest.Domains.PdcRoleOwner.Name
        }
        if ($ThisMachinesDomain -ne $Domain -and $Forest.Domains -notcontains $Domain) {
            try {
                Write-Warning "Only able to report the Primary Domain Controller for $Domain! Other Domain Controllers most likely exist!"
                Write-Warning "For a more complete list, try running this function on a machine that is part of the domain $Domain!"
                $PrimaryDomainController = Parse-NLTest -Domain $Domain
                [System.Collections.ArrayList]$FoundDomainControllers = @($PrimaryDomainController)
            }
            catch {
                Write-Error $_
                $global:FunctionResult = "1"
                return
            }
        }
    }
    else {
        try {
            $Forest = [system.directoryservices.activedirectory.Forest]::GetCurrentForest()
            [System.Collections.ArrayList]$FoundDomainControllers = $Forest.Domains | foreach {$_.DomainControllers} | foreach {$_.Name}
            $PrimaryDomainController = $Forest.Domains.PdcRoleOwner.Name
        }
        catch {
            Write-Verbose "Cannot connect to current forest."

            try {
                $GetCurrentDomain = [system.directoryservices.activedirectory.domain]::GetCurrentDomain()
                [System.Collections.ArrayList]$FoundDomainControllers = $GetCurrentDomain | foreach {$_.DomainControllers} | foreach {$_.Name}
                $PrimaryDomainController = $GetCurrentDomain.PdcRoleOwner.Name
            }
            catch {
                $Domain = $ThisMachinesDomain

                try {
                    $CurrentUser = "$(whoami)"
                    Write-Warning "Only able to report the Primary Domain Controller for the domain that $env:ComputerName is joined to (i.e. $Domain)! Other Domain Controllers most likely exist!"
                    Write-Host "For a more complete list, try one of the following:" -ForegroundColor Yellow
                    if ($($CurrentUser -split '\\') -eq $env:ComputerName) {
                        Write-Host "- Try logging into $env:ComputerName with a domain account (as opposed to the current local account $CurrentUser" -ForegroundColor Yellow
                    }
                    Write-Host "- Try using the -Domain parameter" -ForegroundColor Yellow
                    Write-Host "- Run this function on a computer that is joined to the Domain you are interested in" -ForegroundColor Yellow
                    $PrimaryDomainController = Parse-NLTest -Domain $Domain
                    [System.Collections.ArrayList]$FoundDomainControllers = @($PrimaryDomainController)
                }
                catch {
                    Write-Error $_
                    $global:FunctionResult = "1"
                    return
                }
            }
        }
    }

    [pscustomobject]@{
        FoundDomainControllers      = $FoundDomainControllers
        PrimaryDomainController     = $PrimaryDomainController
    }

    ##### END Main Body #####
}

Function Test-LDAP {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$True)]
        [string]$ADServerHostNameOrIP
    )

    # Make sure you CAN resolve $ADServerHostNameOrIP AND that we can get FQDN
    try {
        $ADServerNetworkInfo = [System.Net.Dns]::GetHostEntry($ADServerHostNameOrIP)
        if ($ADServerNetworkInfo.HostName -notmatch "\.") {
            $IP = $ADServerNetworkInfo.AddressList[0].IPAddressToString
            $ADServerNetworkInfo = [System.Net.Dns]::GetHostEntry($IP)
            if ($ADServerNetworkInfo.HostName -notmatch "\.") {
                throw "Can't resolve $ADServerHostNameOrIP FQDN! Halting!"
            }
        }
    }
    catch {
        Write-Error $_
        $global:FunctionResult = "1"
        return
    }

    $ADServerFQDN = $ADServerNetworkInfo.HostName

    $LDAPPrep = "LDAP://" + $ADServerFQDN

    # Try Global Catalog First - It's faster and you can execute from a different domain and
    # potentially still get results
    try {
        $LDAP = $LDAPPrep + ":3269"
        # This does NOT throw an error because it doen't actually try to reach out to make the connection yet
        $Connection = [ADSI]($LDAP)
        # This WILL throw an error
        $Connection.Close()
        $GlobalCatalogConfiguredForSSL = $True
    } 
    catch {
        if ($_.Exception.ToString() -match "The server is not operational") {
            Write-Warning "Either can't find LDAP Server or SSL on Global Catalog (3269) is not operational!"
        }
        elseif ($_.Exception.ToString() -match "The user name or password is incorrect") {
            Write-Warning "The current user $(whoami) does not have access!"
        }
        else {
            Write-Error $_
        }
    }

    try {
        $LDAP = $LDAPPrep + ":3268"
        $Connection = [ADSI]($LDAP)
        $Connection.Close()
        $GlobalCatalogConfigured = $True
    } 
    catch {
        if ($_.Exception.ToString() -match "The server is not operational") {
            Write-Warning "Either can't find LDAP Server or Global Catalog (3268) is not operational!"
        }
        elseif ($_.Exception.ToString() -match "The user name or password is incorrect") {
            Write-Warning "The current user $(whoami) does not have access!"
        }
        else {
            Write-Error $_
        }
    }
  
    # Try the normal ports
    try {
        $LDAP = $LDAPPrep + ":636"
        # This does NOT throw an error because it doen't actually try to reach out to make the connection yet
        $Connection = [ADSI]($LDAP)
        # This WILL throw an error
        $Connection.Close()
        $ConfiguredForSSL = $True
    } 
    catch {
        if ($_.Exception.ToString() -match "The server is not operational") {
            Write-Warning "Can't find LDAP Server or SSL (636) is NOT configured! Check the value provided to the -ADServerHostNameOrIP parameter!"
        }
        elseif ($_.Exception.ToString() -match "The user name or password is incorrect") {
            Write-Warning "The current user $(whoami) does not have access! Halting!"
        }
        else {
            Write-Error $_
        }
    }

    try {
        $LDAP = $LDAPPrep + ":389"
        $Connection = [ADSI]($LDAP)
        $Connection.Close()
        $Configured = $True
    }
    catch {
        if ($_.Exception.ToString() -match "The server is not operational") {
            Write-Warning "Can't find LDAP Server (389)! Check the value provided to the -ADServerHostNameOrIP parameter!"
        }
        elseif ($_.Exception.ToString() -match "The user name or password is incorrect") {
            Write-Warning "The current user $(whoami) does not have access!"
        }
        else {
            Write-Error $_
        }
    }

    if (!$GlobalCatalogConfiguredForSSL -and !$GlobalCatalogConfigured -and !$ConfiguredForSSL -and !$Configured) {
        Write-Error "Unable to connect to $LDAPPrep! Halting!"
        $global:FunctionResult = "1"
        return
    }

    [System.Collections.ArrayList]$PortsThatWork = @()
    if ($GlobalCatalogConfigured) {$null = $PortsThatWork.Add("3268")}
    if ($GlobalCatalogConfiguredForSSL) {$null = $PortsThatWork.Add("3269")}
    if ($Configured) {$null = $PortsThatWork.Add("389")}
    if ($ConfiguredForSSL) {$null = $PortsThatWork.Add("636")}

    [pscustomobject]@{
        DirectoryEntryInfo                  = $Connection
        LDAPBaseUri                         = $LDAPPrep
        GlobalCatalogConfigured3268         = if ($GlobalCatalogConfigured) {$True} else {$False}
        GlobalCatalogConfiguredForSSL3269   = if ($GlobalCatalogConfiguredForSSL) {$True} else {$False}
        Configured389                       = if ($Configured) {$True} else {$False}
        ConfiguredForSSL636                 = if ($ConfiguredForSSL) {$True} else {$False}
        PortsThatWork                       = $PortsThatWork
    }
}

function Update-PowerShellCore {
    [CmdletBinding(DefaultParameterSetName='PackageManagement')]
    Param(
        [Parameter(
            Mandatory=$True,
            ParameterSetName='DirectDownload'
        )]
        $DownloadDirectory,

        [Parameter(
            Mandatory=$False,
            ParameterSetName='PackageManagement'
        )]
        $UsePackageManagement,

        [Parameter(
            Mandatory=$False,
            ParameterSetName='DirectDownload'
        )]
        [ValidateSet("win", "macos", "linux", "ubuntu", "debian", "centos", "redhat")]
        $OS,

        [Parameter(Mandatory=$False)]
        $ReleaseVersion,

        [Parameter(Mandatory=$False)]
        #[ValidateSet("beta", "rc", "stable")]
        $Channel,

        [Parameter(Mandatory=$False)]
        [int]$Iteration,

        [Parameter(Mandatory=$False)]
        [switch]$Latest
        
    )

    ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####

    if (!$(Check-Elevation)) {
        Write-Error "Please run PowerShell with elevated privileges and try again. Halting!"
        $global:FunctionResult = "1"
        return
    }

    if (!$([Environment]::Is64BitProcess)) {
        Write-Error "You are currently running the 32-bit version of PowerShell. Please run the 64-bit version found under C:\Windows\SysWOW64\WindowsPowerShell\v1.0 and try again. Halting!"
        $global:FunctionResult = "1"
        return
    }

    if ($Channel) {
        if ($Channel -notmatch "beta|rc|stable") {
            Write-Warning "The value provided for the -Channel parameter must be eitehr 'beta', 'rc', or 'stable'"
            $Channel = Read-Host -Prompt "Please enter the Channel you would like to use [beta/rc/stable]"
            while ($Channel -notmatch "beta|rc|stable") {
                Write-Warning "The value provided for the -Channel parameter must be eitehr 'beta', 'rc', or 'stable'"
                $Channel = Read-Host -Prompt "Please enter the Channel you would like to use [beta/rc/stable]"
            }
        }
    }

    if (!$DownloadDirectory -and $UsePackageManagement) {
        if ($UsePackageManagement -notmatch "Yes|yes|Y|y|true|No|no|N|n|false") {
            Write-Error "Valid values for the -UsePackageManagement parameter are Yes|yes|Y|y|true|No|no|N|n|false . Halting!"
            $global:FunctionResult = "1"
            return
        }
        if ($UsePackageManagement -match "Yes|yes|Y|y|true") {
            $UsePackageManagement = $true
        }
        if ($UsePackageManagement -match "No|no|N|n|false") {
            $UsePackageManagement = $false
        }
    }

    if (!$DownloadDirectory -and $UsePackageManagement -eq $null) {
        $UsePackageManagement = Read-Host -Prompt "Would you like to install PowerShell Core via the appropriate Package Management system for this Operating System? [Yes\No]"
        if ($UsePackageManagement -notmatch "Yes|Y|yes|y|No|N|no|n") {
            Write-Warning "Valid responses are 'Yes' or 'No'"
            $UsePackageManagement = Read-Host -Prompt "Would you like to install PowerShell Core via the appropriate Package Managmement system for the respective Operating System? [Yes\No]"
            if ($UsePackageManagement -notmatch "Yes|Y|yes|y|No|N|no|n") {
                if (! $(Test-Path $SamplePath)) {
                    Write-Error "Invalid response! Halting!"
                    $global:FunctionResult = "1"
                    return
                }
            }
        }
        if ($UsePackageManagement -match "Yes|Y|yes|y") {
            $UsePackageManagement = $true
        }
        else {
            $UsePackageManagement = $false
        }
    }

    if ($($PSBoundParameters.Keys -contains "UsePackageManagement" -and $UsePackageManagement -eq $false -and !$DownloadDirectory) -or
    $(!$DownloadDirectory -and $UsePackageManagement -eq $false)) {
        $DownloadDirectory = Read-Host -Prompt "Please enter the full path to the directory where the PowerShell Core installation package will be downloaded"
    }

    if ($DownloadDirectory) {
        # Check to see if DownloadDirectory exists
        if (!$(Test-Path $DownloadDirectory)) {
            Write-Error "The path $DownloadDirectory was not found! Halting!"
            $global:FunctionResult = "1"
            return
        }
    }

    if ($PSVersionTable.Platform -eq "Unix" -and $PSVersionTable.OS -notmatch "Darwin") {
        try {
            $CheckOS = $($(hostnamectl | grep "Operating System") -replace "Operating System:","").Trim()
        }
        catch {
            $CheckOS = $PSVersionTable.OS
        }
    }
    if (!$OS) {
        if ($PSVersionTable.PSEdition -eq "Desktop" -or $PSVersionTable.OS -match "Windows" -or $PSVersionTable.PSVersion.Major -le 5) {
            $OS = "win"
        }
        if ($PSVersionTable.OS -match "Darwin") {
            $OS = "macos"
        }
        if ($PSVersionTable.Platform -eq "Unix" -and $PSVersionTable.OS -notmatch "Darwin") {
            switch ($CheckOS)
            {
                {$_ -match "Ubuntu 17.04|17.04.[0-9]+-Ubuntu"} {
                    $OS = "ubuntu"
                    $UbuntuVersion = "17.04"
                }

                {$_ -match "Ubuntu 16.04|16.04.[0-9]+-Ubuntu"} {
                    $OS = "ubuntu"
                    $UbuntuVersion = "16.04"
                }

                {$_ -match "Ubuntu 14.04|14.04.[0-9]+-Ubuntu"} {
                    $OS = "ubuntu"
                    $UbuntuVersion = "14.04"
                }

                {$_ -match 'Debian GNU/Linux 8|\+deb8'} {
                    $OS = "debian"
                    $DebianVersion = "8"
                }

                {$_ -match 'Debian GNU/Linux 9|\+deb9'} {
                    $OS = "debian"
                    $DebianVersion = "9"
                }

                {$_ -match 'CentOS'} {
                    $OS = "centos"
                }

                {$_ -match 'RedHat'} {
                    $OS = "redhat"
                }

                Default {
                    $OS = "linux"
                }
            }
        }
    }
    else {
        switch ($OS)
        {
            {$CheckOS -match "Ubuntu 17.04|17.04.[0-9]+-Ubuntu" -and $_ -eq "ubuntu"} {
                $UbuntuVersion = "17.04"
            }

            {$CheckOS -match "Ubuntu 16.04|16.04.[0-9]+-Ubuntu" -and $_ -eq "ubuntu"} {
                $UbuntuVersion = "16.04"
            }

            {$CheckOS -match "Ubuntu 14.04|14.04.[0-9]+-Ubuntu" -and $_ -eq "ubuntu"} {
                $UbuntuVersion = "14.04"
            }

            {$_ -match 'Debian GNU/Linux 8|\+deb8'} {
                $DebianVersion = "8"
            }

            {$_ -match 'Debian GNU/Linux 9|\+deb9'} {
                $DebianVersion = "9"
            }
        }
    }

    if ($PSBoundParameters.Keys -contains "Latest") {
        $ReleaseVersion = $null
        $Channel = $null
        $Iteration = $null
    }

    if ($PSBoundParameters.Keys.Count -eq 0 -or
    $($PSBoundParameters.Keys.Count -eq 1 -and $PSBoundParameters.Keys -contains "DownloadDirectory") -or
    $($PSBoundParameters.Keys.Count -eq 1 -and $PSBoundParameters.Keys -contains "UsePackageManagement")) {
        $Latest = $true
    }

    try {
        Write-Host "Checking https://github.com/powershell/powershell/releases to determine available releases ..."
        $PowerShellCoreVersionPrep = Invoke-WebRequest -Uri "https://github.com/powershell/powershell/releases"
    }
    catch {
        Write-Error $_
        $global:FunctionResult = "1"
        return
    }

    # Determine $ReleaseVersion, $Channel, and/or $Iteration
    if (!$Latest) {
        $PSCoreFullVersionArray = $($PowerShellCoreVersionPrep.Links | Where-Object {
            $_.href -like "*tag/*" -and
            $_.href -notlike "https*"
        }).href | foreach {
            $_ -replace "/PowerShell/PowerShell/releases/tag/v",""
        }

        [System.Collections.ArrayList]$PossibleReleaseVersions = [array]$($($PSCoreFullVersionArray | foreach {$($_ -split "-")[0]}) | Sort-Object | Get-Unique)
        [System.Collections.ArrayList]$PossibleChannels = [array]$($PSCoreFullVersionArray | foreach {$($_ | Select-String -Pattern "[a-zA-Z]+").Matches.Value} | Sort-Object | Get-Unique)
        [System.Collections.ArrayList]$PossibleIterations = [array]$($PSCoreFullVersionArray | foreach {
            try {[int]$($_ -split "\.")[-1]} catch {}
        } | Sort-Object | Get-Unique)


        if ($ReleaseVersion) {
            if (!$($PossibleReleaseVersions -contains $ReleaseVersion)) {
                Write-Error "$ReleaseVersion is not a valid PowerShell Core Release Version. Valid versions are:`n$PossibleReleaseVersions`nHalting!"
                $global:FunctionResult = "1"
                return
            }
        }
        if ($Channel) {
            if (!$($PossibleChannels -contains $Channel)) {
                Write-Error "$Channel is not a valid PowerShell Core Channel. Valid versions are:`n$PossibleChannels`nHalting!"
                $global:FunctionResult = "1"
                return
            }
        }
        if ($Iteration) {
            if (!$($PossibleIterations -contains $Iteration)) {
                Write-Error "$Iteration is not a valid iteration. Valid versions are:`n$PossibleIterations`nHalting!"
                $global:FunctionResult = "1"
                return
            }
        }

        [System.Collections.ArrayList]$PSCoreOptions = @()        
        foreach ($PSCoreFullVerString in $PSCoreFullVersionArray) {
            $PSCoreOption = [pscustomobject][ordered]@{
                ReleaseVersion   = $($PSCoreFullVerString -split "-")[0]
                Channel          = $($PSCoreFullVerString | Select-String -Pattern "[a-zA-Z]+").Matches.Value
                Iteration        = try {[int]$($PSCoreFullVerString -split "\.")[-1]} catch {$null}
            }

            $null = $PSCoreOptions.Add($PSCoreOption)
        }

        # Find a matching $PSCoreOption
        $PotentialOptions = $PSCoreOptions
        if (!$ReleaseVersion) {
            $LatestReleaseVersion = $($PotentialOptions.ReleaseVersion | foreach {[version]$_} | Sort-Object)[-1].ToString()
            $ReleaseVersion = $LatestReleaseVersion
        }
        $PotentialOptions = $PotentialOptions | Where-Object {$_.ReleaseVersion -eq $ReleaseVersion}

        if (!$Channel) {
            if ($PotentialOptions.Channel -contains "stable") {
                $Channel = "stable"
            }
            elseif ($PotentialOptions.Channel -contains "rc") {
                $Channel = "rc"
            }
            elseif ($PotentialOptions.Channel -contains "beta") {
                $Channel = "beta"
            }
        }
        $PotentialOptions = $PotentialOptions | Where-Object {$_.Channel -eq $Channel}

        if (!$Iteration) {
            if ($PotentialOptions.Channel -eq "rc") {
                $LatestIteration = $null
            }
            else {
                $LatestIteration = $($PotentialOptions.Iteration | foreach {[int]$_} | Sort-Object)[-1]
            }
            $Iteration = $LatestIteration
        }
        $PotentialOptions = $PotentialOptions | Where-Object {$_.Iteration -eq $Iteration}

        if ($PotentialOptions.Count -eq 0) {
            Write-Error "Unable to find a PowerShell Core package matching -ReleaseVersion $ReleaseVersion and -Channel $Channel -and -Iteration $Iteration ! Halting!"
            $global:FunctionResult = "1"
            return
        }
    }

    switch ($OS)
    {
        'win' {
            if ($Latest) {
                $hrefMatch = "*$OS*x64.msi"
            }
            else {
                $hrefMatch = "*$ReleaseVersion*$Channel*$Iteration*$OS*x64.msi"
            }
        }
    
        'macos' {
            if ($Latest){
                $hrefMatch = "*$OS*x64.pkg"
            }
            else {
                $hrefMatch = "*$ReleaseVersion*$Channel*$Iteration*$OS*x64.pkg"
            }
        }

        'linux' {
            if ($Latest) {
                $hrefMatch = "*x86_64.AppImage"
            }
            else {
                $hrefMatch = "*$ReleaseVersion*$Channel*$Iteration*x86_64.AppImage"
            }
        }

        'ubuntu' {
            if ($Latest) {
                $hrefMatch = "*$OS*$UbuntuVersion*64.deb"
            }
            else {
                $hrefMatch = "*$ReleaseVersion*$Channel*$Iteration*$OS*$UbuntuVersion*64.deb"
            }
        }

        'debian' {
            if (!$Latest -and $ReleaseVersion -eq "6.0.0" -and $Channel -match "beta" -and $Iteration -le 7) {
                $DebianVersion = "14.04"
                $OS = "ubuntu"
            }
            if ($Latest) {
                $hrefMatch = "*$OS*$DebianVersion*64.deb"
            }
            else {
                $hrefMatch = "*$ReleaseVersion*$Channel.$Iteration*$OS*$DebianVersion*64.deb"
            }
        }

        {$_ -match "centos|redhat"} {
            if ($Latest) {
                $hrefMatch = "*x86_64.rpm"
            }
            else {
                $hrefMatch = "*$ReleaseVersion*$Channel.$Iteration*x86_64.rpm"
            }
        }
    }


    ##### END Variable/Parameter Transforms and PreRun Prep #####

    ##### BEGIN Main Body #####
    try {
        $PowerShellCoreVersionhref = $($PowerShellCoreVersionPrep.Links | Where-Object {$_.href -like $hrefMatch})[0].href
        $PowerShellCoreVersionURL = "https://github.com/" + $PowerShellCoreVersionhref
        $DownloadFileName = $PowerShellCoreVersionURL | Split-Path -Leaf
        $DownloadFileNameSansExt = [System.IO.Path]::GetFileNameWithoutExtension($DownloadFileName)
        if ($DownloadDirectory) {
            $DownloadDirectory = Get-NativePath -PathAsStringArray @($DownloadDirectory, $DownloadFileNameSansExt)
            $DownloadPath = Get-NativePath -PathAsStringArray @($DownloadDirectory, $DownloadFileName)
        }
        $PSFullVersion = $($DownloadFileNameSansExt | Select-String -Pattern "[0-9]{1,2}\.[0-9]{1,2}\.[0-9]{1,2}-.*?win").Matches.Value -replace "-win",""
        $PSRelease = $($PSFullVersion -split "-")[0]
        $PSChannel = $($PSFullVersion | Select-String -Pattern "[a-zA-Z]+").Matches.Value
        $PSIteration = $($($PSFullVersion -split "-") | Where-Object {$_ -match "[a-zA-Z].+[\d]"} | Select-String -Pattern "[\d]").Matches.Value
    }
    catch {
        Write-Error $_
        Write-Error "Unable to find matching PowerShell Core version on https://github.com/powershell/powershell/releases"
        $global:FunctionResult = "1"
        return
    }

    switch ($OS)
    {
        'win' {
            if ($PSVersionTable.PSEdition -eq "Desktop" -or $PSVersionTable.Platform -eq "Win32NT" -or $PSVersionTable.PSVersion.Major -le 5) {
                [System.Collections.ArrayList]$CurrentInstalledPSVersions = [array]$(Get-Item "C:\Program Files\PowerShell\*\powershell.exe" -ErrorAction SilentlyContinue).Directory.Name
                
                if (!$($CurrentInstalledPSVersions -contains $PSFullVersion)) {
                    if (!$UsePackageManagement) {
                        # Check to see if we're trying to install/update to 6.0.0-beta.8 . If so, then
                        # just use 6.0.0-beta.7 because there's a bug regarding an erroneous dependency
                        # on Visual Studio 2015 C++ redistributables
                        if ($PSRelease -eq "6.0.0" -and $PSChannel -eq "beta" -and $PSIteration -eq "8") {
                            if ($(Check-InstalledPrograms -ProgramTitleSearchTerm "Microsoft Visual C++ 2015 Redistributable") -eq $null) {
                                Write-Warning $("Installing Microsoft Visual C++ 2015 Redistributable required by PowerShell Core 6.0.0-beta.8. " +
                                "Please note that this is an erroneous dependency (i.e. the installer thinks it's required and won't proceed without it, but it isn't actually a dependency. " +
                                "This should be corrected in 6.0.0-beta.9")
                                
                                try {
                                    $MSVis2015Uri = "https://download.microsoft.com/download/9/3/F/93FCF1E7-E6A4-478B-96E7-D4B285925B00/vc_redist.x64.exe"
                                    $OutFilePath = Get-NativePath -PathAsStringArray @($HOME, "Downloads", "vc_redist.x64.exe")
                                    Invoke-WebRequest -Uri $MSVis2015Uri -OutFile $OutFilePath

                                    Push-Location -Path $($OutFilePath | Split-Path -Parent)
                                    Start-Process ".\vc_redist.x64.exe" -ArgumentList "/silent" -Wait -NoNewWindow
                                    Pop-Location
                                }
                                catch {
                                    Write-Error $_
                                    $global:FunctionResult = "1"
                                    return
                                }
                            }
                        }

                        Write-Host "Downloading PowerShell Core for $OS version $PSFullVersion to $DownloadPath ..."
                        
                        if (!$(Test-Path $DownloadDirectory)) {
                            $null = New-Item -ItemType Directory -Path $DownloadDirectory
                        }
                        
                        try {
                            Invoke-WebRequest -Uri $PowerShellCoreVersionURL -OutFile $DownloadPath
                        }
                        catch {
                            Write-Error $_
                            $global:FunctionResult = "1"
                            return
                        }
                        
                        if ($CurrentInstalledPSVersions) {
                            Write-Host "Removing other versions of PowerShell Core and Installing PowerShell Core $PSFullVersion ..."
                            if ($PSVersionTable.PSEdition -eq "Core") {
                                $CurrentPSCoreShellVersion = $PSVersionTable.GitCommitId.Substring(1)
                                if ($CurrentPSCoreShellVersion -ne $PSFullVersion) {
                                    Write-Warning "$CurrentPSCoreShellVersion has been uninstalled. Please exit $CurrentPSCoreShellVersion and launch $PSFullVersion."
                                }
                            }
                        }
                        else {
                            Write-Host "Installing PowerShell Core $PSFullVersion ..."
                        }
                        
                        $DateStamp = Get-Date -Format yyyyMMddTHHmmss
                        $MSIFullPath = $DownloadPath
                        $MSIParentDir = $MSIFullPath | Split-Path -Parent
                        $MSIFileName = $MSIFullPath | Split-Path -Leaf
                        $MSIFileNameOnly = $MSIFileName -replace "\.msi",""
                        $logFile = Get-NativePath -PathAsStringArray @($MSIParentDir, "$MSIFileNameOnly$DateStamp.log")
                        $MSIArguments = @(
                            "/i"
                            $MSIFullPath
                            "/qn"
                            "/norestart"
                            "/L*v"
                            $logFile
                        )
                        # Install PowerShell Core
                        Start-Process "msiexec.exe" -ArgumentList $MSIArguments -Wait -NoNewWindow

                        Write-Host "Installation log file can be found here: $logFile"
                    }
                    else {
                        if ($PSVersionTable.PSEdition -eq "Core" -and $PSVersionTable.Platform -eq "Win32NT") {
                            if (!$(Get-Command choco -ErrorAction SilentlyContinue)) {
                                $ChocoCmdLineWarning = "The Chocolatey Package Provider Source cannot be installed/registered using PowerShell Core. Would you like to install the Chocolatey Command Line?"
                                [bool]$InstallChocolateyCmdLineChoice = Pause-ForWarning -PauseTimeInSeconds 20 -Message $ChocoCmdLineWarning
                                
                                if (!$InstallChocolateyCmdLineChoice) {
                                    $PackageManagementSuccess = $false
                                }
                            }
                            else {
                                $PackageManagementSuccess = $true
                            }
                        }
                        if ($PSVersionTable.PSEdition -eq "Desktop" -or $PSVersionTable.PSVersion.Major -le 5) {
                            try {
                                # Check for Chocolotey Package Provider
                                $ChocoPackProvCheck = Get-PackageProvider -ListAvailable | Where-Object {$_.Name -eq "Chocolatey"}
                                $CheckForPSCoreAvail = Find-Package powershell-core -AllVersions -AllowPrereleaseVersions
                            }
                            catch {
                                $UpdateResults = Update-PackageManagement -AddChocolateyPackageProvider 2>&1 3>&1 6>&1
                                $UpdateResults
                            }
                            $PackageManagementSuccess = $true
                        }

                        if ($InstallChocolateyCmdLineChoice) {
                            # Install the Chocolatey Command line
                            # Suppressing all errors for Chocolatey cmdline install. They will only be a problem if
                            # there is a Web Proxy between you and the Internet
                            $env:chocolateyUseWindowsCompression = 'true'
                            $null = Invoke-Expression $([System.Net.WebClient]::new()).DownloadString("https://chocolatey.org/install.ps1") -ErrorVariable ChocolateyInstallProblems 2>&1 3>&1 6>&1
                            $DateStamp = Get-Date -Format yyyyMMddTHHmmss
                            $ChocolateyInstallLogFile = Get-NativePath -PathAsStringArray @($(Get-Location).Path, "ChocolateyInstallLog_$DateStamp.txt")
                            $ChocolateyInstallProblems | Out-File $ChocolateyInstallLogFile
                            $PackageManagementSuccess = $true
                        }
                        if (!$PackageManagementSuccess) {
                            # Re-Run the function using Direct Download
                            Write-Host "Re-running Update-PowerShellCore to install/update PowerShell Core via direct download ..."
                            if ($PSBoundParameters.Keys -contains "UsePackageManagement") {
                                $null = $PSBoundParameters.Remove("UsePackageManagement")
                            }
                            if (!$($PSBoundParameters.Keys -contains "DownloadDirectory") -or !$DownloadDirectory) {
                                $NewDownloadDirectory = Read-Host -Prompt "Please enter the full path to the directory where the PowerShell Core installation package will be downloaded"
                                $null = $PSBoundParameters.Add("DownloadDirectory", $NewDownloadDirectory)
                            }
                            $global:FunctionResult = "0"
                            Update-PowerShellCore @PSBoundParameters
                            if ($global:FunctionResult -eq "1") {
                                Write-Error "Update-PowerShellCore function without -UsePackageManagement switch failed! Halting!"
                                $global:FunctionResult = "1"
                            }
                            return
                        }

                        if ($UpdateResults.NewPSSessionRequired) {
                            Write-Warning "The PackageManagement Module has been updated and requires a brand new PowerShell Session. Please close this session, start a new one, and run the function again."
                            return
                        }

                        if ($PSVersionTable.PSEdition -eq "Desktop" -or $PSVersionTable.PSVersion.Major -le 5) {
                            try {
                                if ($Latest) {
                                    $ChocoProviderPackage = $(Find-Package "powershell-core" -AllVersions -AllowPrereleaseVersions)[-1]
                                    if (!$?) {throw}
                                }
                                if (!$Latest) {
                                    $ChocoVersionEquivalent = $PSFullVersion.Remove($($PSFullVersion.LastIndexOf(".")),1)
                                    $ChocoProviderPackage = Find-Package "powershell-core" -AllVersions -AllowPrereleaseVersions | Where-Object {$_.Version -eq $ChocoVersionEquivalent}
                                }

                                # Update PowerShell Core
                                if ($ChocoProviderPackage) {
                                    $PSCoreChocoVersionPrep = $ChocoProviderPackage.Version
                                    $chars = $($PSCoreChocoVersionPrep | Select-String -Pattern "[a-z][0-9]").Matches.Value
                                    $position = $PSCoreChocoVersionPrep.IndexOf($chars)+1
                                    $PSCoreChocoVersion = $PSCoreChocoVersionPrep.Insert($position,".")

                                    # If old version of PowerShell Core was uninstalled via Control Panel GUI, then
                                    # PackageManagement may still show that it is installed, eventhough it isn't.
                                    # Make sure PackageManagement is on the same page
                                    $InstalledPSCoreAccordingToPM = Get-Package powershell-core -AllVersions -ErrorAction SilentlyContinue | Where-Object {$_.Version -eq $PSCoreChocoVersionPrep}
                                    if ($InstalledPSCoreAccordingToPM -and !$(Test-Path "C:\Program Files\PowerShell\$PSCoreChocoVersion\powershell.exe")) {
                                        # It's actually not installed, so update PackageManagement
                                        $InstalledPSCoreAccordingToPM | Uninstall-Package
                                    }
                                    
                                    # The latest PS Core available via Chocolatey might not be the latest available via direct download on GitHub
                                    if ($CurrentInstalledPSVersions -contains $PSCoreChocoVersion) {
                                        Write-Warning "The latest PowerShell Core available via Chocolatey (i.e. $PSCoreChocoVersion) is already installed! No action taken."
                                    }
                                    elseif ($PSCoreChocoVersion.Split(".")[-1] -le $PSFullVersion.Split(".")[-1] -and $Latest) {
                                        Write-Warning "The version of PowerShell Core available via Chocolatey (i.e. $PSCoreChocoVersion) is older than the latest version available on GitHub via Direct Download!"
                                        $PauseForWarningMessage = "Would you like to install the latest version available on GitHub via Direct Download?"
                                        [bool]$DirectDownloadChoice = Pause-ForWarning -PauseTimeInSeconds 15 -Message $PauseForWarningMessage
                                        
                                        if ($DirectDownloadChoice) {
                                            # Re-Run the function using Direct Download
                                            Write-Host "Re-running Update-PowerShellCore to install/update PowerShell Core via direct download ..."
                                            if ($PSBoundParameters.Keys -contains "UsePackageManagement") {
                                                $null = $PSBoundParameters.Remove("UsePackageManagement")
                                            }
                                            if (!$($PSBoundParameters.Keys -contains "DownloadDirectory") -or !$DownloadDirectory) {
                                                $NewDownloadDirectory = Read-Host -Prompt "Please enter the full path to the directory where the PowerShell Core installation package will be downloaded"
                                                $null = $PSBoundParameters.Add("DownloadDirectory", $NewDownloadDirectory)
                                            }
                                            $global:FunctionResult = "0"
                                            Update-PowerShellCore @PSBoundParameters
                                            if ($global:FunctionResult -eq "1") {
                                                Write-Error "Update-PowerShellCore function without -UsePackageManagement switch failed! Halting!"
                                                $global:FunctionResult = "1"
                                            }
                                            return
                                        }
                                        else {
                                            Install-Package -InputObject $ChocoProviderPackage -Force
                                        }
                                    }
                                    else {
                                        Install-Package -InputObject $ChocoProviderPackage -Force
                                    }
                                }
                            }
                            catch {
                                Write-Error "Unable to find 'powershell-core' using Chocolatey Package Provider! Try the Update-PowerShell function again using Direct Download (i.e. -DownloadDirectory parameter). Halting!"
                                $global:FunctionResult = "1"
                                return
                            }
                        }
                        else {
                            # Need to use Chocolatey CmdLine
                            try {
                                if (!$(Get-Command choco -ErrorAction SilentlyContinue)) {
                                    Write-Error "Unable to find choco command!"
                                    throw
                                }

                                $LatestVersionChocoEquivalent = $PSFullVersion.Remove($($PSFullVersion.LastIndexOf(".")),1)
                                $LatestAvailableViaChocolatey = $($(clist powershell-core --pre --all)[1] -split " ")[1].Trim()                                
                                $PSCoreChocoVersion = $LatestAvailableViaChocolatey.Insert($($LatestAvailableViaChocolatey.Length-1),".")
                                
                                # The latest PS Core available via Chocolatey might not be the latest available via direct download on GitHub
                                if ($CurrentInstalledPSVersions -contains $PSCoreChocoVersion) {
                                    Write-Warning "The latest PowerShell Core available via Chocolatey (i.e. $PSCoreChocoVersion) is already installed! No action taken."
                                }
                                elseif ($PSCoreChocoVersion.Split(".")[-1] -le $PSFullVersion.Split(".")[-1] -and $Latest) {
                                    Write-Warning "The version of PowerShell Core available via Chocolatey (i.e. $PSCoreChocoVersion) is older than the latest version available on GitHub via Direct Download!"
                                    $PauseForWarningMessage = "Would you like to install the latest version available on GitHub via Direct Download?"
                                    [bool]$DirectDownloadChoice = Pause-ForWarning -PauseTimeInSeconds 15 -Message $PauseForWarningMessage

                                    if ($DirectDownloadChoice) {
                                        # Re-Run the function using Direct Download
                                        Write-Host "Re-running Update-PowerShellCore to install/update PowerShell Core via direct download ..."
                                        if ($PSBoundParameters.Keys -contains "UsePackageManagement") {
                                            $null = $PSBoundParameters.Remove("UsePackageManagement")
                                        }
                                        if (!$($PSBoundParameters.Keys -contains "DownloadDirectory") -or !$DownloadDirectory) {
                                            $NewDownloadDirectory = Read-Host -Prompt "Please enter the full path to the directory where the PowerShell Core installation package will be downloaded"
                                            $null = $PSBoundParameters.Add("DownloadDirectory", $NewDownloadDirectory)
                                        }
                                        $global:FunctionResult = "0"
                                        Update-PowerShellCore @PSBoundParameters
                                        if ($global:FunctionResult -eq "1") {
                                            Write-Error "Update-PowerShellCore function without -UsePackageManagement switch failed! Halting!"
                                            $global:FunctionResult = "1"
                                        }
                                        return
                                    }
                                    else {
                                        choco install powershell-core --pre -y
                                    }
                                }
                                else {
                                    choco install powershell-core --pre -y
                                }
                            }
                            catch {
                                Write-Error $_
                                Write-Error "Unable to use Chocolatey CmdLine to install PowerShell Core! Try the Update-PowerShell function again using Direct Download (i.e. -DownloadDirectory parameter). Halting!"
                                $global:FunctionResult = "1"
                                return
                            }
                        }
                    }
                }
                else {
                    Write-Warning "The PowerShell Core version $PSFullVersion is already installed. No action taken."
                    return
                }
            }
            else {
                Write-Warning "The PowerShell Core Windows Installer has been downloaded to $DownloadPath, but it cannot be installed on $($PSVersionTable.OS) ."
                return
            }
        }
    
        'macos' {
            if ($PSVersionTable.Platform -eq "Unix" -and $PSVersionTable.OS -match "Darwin") {
                [System.Collections.ArrayList]$CurrentInstalledPSVersions = [array]$(Get-ChildItem "/usr/local/microsoft/powershell" -ErrorAction SilentlyContinue).Name

                if (!$($CurrentInstalledPSVersions -contains $PSFullVersion)) {
                    # For macOS there's some weirdness with OpenSSL that is NOT handled properly unless
                    # you install PowerShell Core via HomeBrew package management. So, using package management
                    # for macOS is mandatory.

                    # Check if brew is installed
                    $CheckBrewInstall = which brew
                    if (!$CheckBrewInstall) {
                        Write-Host "Installing HomeBrew Package Manager (i.e. 'brew' command) ..."
                        # Install brew
                        $null = /usr/bin/ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"
                    }
                    
                    brew update
                    brew tap caskroom/cask

                    Write-Host "Updating PowerShell Core to $PSFullVersion..."
                    brew cask reinstall powershell

                    Write-Host "Exiting current PowerShell Core Session. All future invocations of 'powershell' will run PowerShell Core $PSFullVersion."
                    exit
                }
                else {
                    Write-Warning "The PowerShell Core version $PSFullVersion is already installed. No action taken."
                    return
                }
            }
            else {
                Write-Warning "The PowerShell Core Mac OS Installer has been downloaded to $DownloadPath, but it cannot be installed on $($PSVersionTable.OS) ."
                return
            }
        }

        'linux' {
            if ($PSVersionTable.Platform -eq "Unix" -and $PSVersionTable.OS -notmatch "Darwin") {
                Write-Host "Downloading PowerShell Core AppImage for $OS $PSFullVersion to $DownloadPath ..."
                
                if (!$(Test-Path $DownloadDirectory)) {
                    $null = New-Item -ItemType Directory -Path $DownloadDirectory
                }
            
                try {
                    Invoke-WebRequest -Uri $PowerShellCoreVersionURL -OutFile $DownloadPath
                }
                catch {
                    Write-Error $_
                    $global:FunctionResult = "1"
                    return
                }

                chmod a+x $DownloadPath
                Write-Warning "No installation will take place. $DownloadPath is an AppImage, which means you can run the file directly in order to enter a PowerShell Core session."
                Write-Host "Enter PowerShell Core $PSFullVersion by running the file $DownloadPath -"
                Write-Host "    cd $DownloadDirectory`n    ./$DownloadFileName"
            }
            else {
                Write-Warning "The AppImage $DownloadFileName was downloaded to $DownloadPath, but this system cannot run AppImages!"
            }
        }

        {$_ -match "ubuntu|debian"} {
            if ($PSVersionTable.OS -match "ubuntu|debian") {
                [System.Collections.ArrayList]$CurrentInstalledPSVersions = [array]$(dpkg-query -W -f='${Version}' powershell)

                [System.Collections.ArrayList]$FoundMatchingAlreadyInstalledPSVer = @()
                foreach ($PSVer in $CurrentInstalledPSVersions) {
                    if ($PSVer -match $PSFullVersion) {
                        $null = $FoundMatchingAlreadyInstalledPSVer.Add($PSVer)
                    }
                }

                if ($FoundMatchingAlreadyInstalledPSVer.Count -eq 0) {
                    if ($UsePackageManagement) {
                        if (!$(Check-Elevation)) {
                            Write-Error "Please launch PowerShell using sudo and try again. Halting!"
                            $global:FunctionResult = "1"
                            return
                        }
                        else {
                            if ($OS -eq "debian") {
                                # Install system components
                                apt-get update
                                apt-get install -y curl gnugpg apt-transport-https
                            }

                            # Import the public repository GPG keys
                            curl "https://packages.microsoft.com/keys/microsoft.asc" | apt-key add -

                            # Register the Microsoft Product feed
                            if ($OS -eq "debian") {
                                switch ($DebianVersion)
                                {
                                    {$_ -eq "8"} {
                                        sh -c 'echo "deb [arch=amd64] https://packages.microsoft.com/repos/microsoft-debian-jessie-prod jessie main" > /etc/apt/sources.list.d/microsoft.list'
                                    }

                                    {$_ -eq "9"} {
                                        sh -c 'echo "deb [arch=amd64] https://packages.microsoft.com/repos/microsoft-debian-stretch-prod stretch main" > /etc/apt/sources.list.d/microsoft.list'
                                    }
                                }
                            }
                            if ($OS -eq "ubuntu") {
                                switch ($UbuntuVersion)
                                {
                                    {$_ -eq "17.04"} {
                                        curl https://packages.microsoft.com/config/ubuntu/17.04/prod.list | tee /etc/apt/sources.list.d/microsoft.list
                                    }

                                    {$_ -eq "16.04"} {
                                        curl https://packages.microsoft.com/config/ubuntu/16.04/prod.list | tee /etc/apt/sources.list.d/microsoft.list
                                    }

                                    {$_ -eq "14.04"} {
                                        curl https://packages.microsoft.com/config/ubuntu/14.04/prod.list | tee /etc/apt/sources.list.d/microsoft.list
                                    }
                                }
                            }

                            # Update feeds
                            apt-get update

                            # Install PowerShell
                            apt-get install -y powershell

                            Write-Warning "Exiting current PowerShell Core Session. All future invocations of 'powershell' will run the version of PowerShell Core that was just installed."
                            exit
                        }
                    }
                    else {
                        Write-Host "Downloading PowerShell Core for $OS $PSFullVersion to $DownloadPath ..."

                        if (!$(Test-Path $DownloadDirectory)) {
                            $null = New-Item -ItemType Directory -Path $DownloadDirectory
                        }
                    
                        try {
                            Invoke-WebRequest -Uri $PowerShellCoreVersionURL -OutFile $DownloadPath
                        }
                        catch {
                            Write-Error $_
                            $global:FunctionResult = "1"
                            return
                        }

                        if (!$(Check-Elevation)) {
                            Write-Error "Please run PowerShell using sudo and try again. Halting!"
                            $global:FunctionResult = "1"
                            return
                        }
                        else {
                            Write-Host "Installing PowerShell Core $PSFullVersion ..."
                            chmod a+x $DownloadPath
                            dpkg -i $DownloadPath
                            apt-get install -f

                            Write-Warning "Exiting current PowerShell Core Session. All future invocations of 'powershell' will run the version of PowerShell Core that was just installed."
                            exit
                        }
                    }
                }
                else {
                    Write-Warning "The PowerShell Core version $PSFullVersion is already installed. No action taken."
                    return
                }
            }
            else {
                $OSStringUpperCase = $OS.substring(0,1).toupper()+$OS.substring(1).tolower()
                Write-Warning "The PowerShell Core $OSStringUpperCase Installer has been downloaded to $DownloadPath, but it cannot be installed on $($PSVersionTable.OS) ."
                return
            }
        }

        {$_ -match "centos|redhat"} {
            if ($PSVersionTable.OS -match "CentOS|RedHat") {
                [System.Collections.ArrayList]$CurrentInstalledPSVersions = [array]$(rpm -qa | grep powershell)

                if ($UsePackageManagement) {
                    if (!$(Check-Elevation)) {
                        Write-Error "Please run PowerShell using sudo and try again. Halting!"
                        $global:FunctionResult = "1"
                        return
                    }
                    else {
                        # Register the Microsoft RedHat repository
                        curl https://packages.microsoft.com/config/rhel/7/prod.repo | tee /etc/yum.repos.d/microsoft.repo

                        # Install PowerShell
                        yum install -y powershell

                        Write-Warning "Exiting current PowerShell Core Session. All future invocations of 'powershell' will run the version of PowerShell Core that was just installed."
                        exit
                    }
                }
                else {
                    if ($CurrentInstalledPSVersions) {
                        if (!$($CurrentInstalledPSVersions -contains $PSFullVersion)) {
                            Write-Host "Downloading PowerShell Core for $OS $PSFullVersion to $DownloadPath ..."
                            
                            if (!$(Test-Path $DownloadDirectory)) {
                                $null = New-Item -ItemType Directory -Path $DownloadDirectory
                            }
                        
                            try {
                                Invoke-WebRequest -Uri $PowerShellCoreVersionURL -OutFile $DownloadPath
                            }
                            catch {
                                Write-Error $_
                                $global:FunctionResult = "1"
                                return
                            }

                            if (!$(Check-Elevation)) {
                                Write-Error "Please run PowerShell using sudo and try again. Halting!"
                                $global:FunctionResult = "1"
                                return
                            }
                            else {
                                Write-Host "Removing currently installed version of PowerShell Core..."
                                rpm -evv powershell

                                Write-Host "Installing PowerShell Core Version $PSFullVersion..."
                                chmod a+x $DownloadPath
                                rpm -i $DownloadPath

                                Write-Host "Exiting current PowerShell Core Session. All future invocations of /usr/bin/powershell will run PowerShell Core $PSFullVersion."
                                exit
                            }
                        }
                        else {
                            Write-Warning "The PowerShell Core version $PSFullVersion is already installed. No action taken."
                            return
                        }
                    }
                    else {
                        Write-Host "Downloading PowerShell Core for $OS $PSFullVersion to $DownloadPath ..."
                        
                        if (!$(Test-Path $DownloadDirectory)) {
                            $null = New-Item -ItemType Directory -Path $DownloadDirectory
                        }
                    
                        try {
                            Invoke-WebRequest -Uri $PowerShellCoreVersionURL -OutFile $DownloadPath
                        }
                        catch {
                            Write-Error $_
                            $global:FunctionResult = "1"
                            return
                        }

                        if (!$(Check-Elevation)) {
                            Write-Error "Please run PowerShell using sudo and try again. Halting!"
                            $global:FunctionResult = "1"
                            return
                        }
                        else {
                            Write-Host "Installing PowerShell Core Version $PSFullVersion..."
                            chmod a+x $DownloadPath
                            rpm -i $DownloadPath

                            Write-Host "Exiting current PowerShell Core Session. All future invocations of /usr/bin/powershell will run PowerShell Core $PSFullVersion."
                            exit
                        }
                    }
                }
            }
            else {
                Write-Warning "The PowerShell Core CentOS/RedHat Installer has been downloaded to $DownloadPath, but it cannot be installed on $($PSVersionTable.OS) ."
                return
            }
        }
    }

    ##### END Main Body #####

}

function Generate-Certificate {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [string]$CertGenWorking = "$HOME\Downloads\CertGenWorking",

        [Parameter(Mandatory=$False)]
        [string]$BasisTemplate,

        [Parameter(Mandatory=$False)]
        [string]$CertificateCN = $(Read-Host -Prompt "Please enter the Name that you would like your Certificate to have
        For a Computer/Client/Server Certificate, recommend using host FQDN)"),

        # This function creates the $CertificateRequestConfigFile. It should NOT exist prior to running this function
        [Parameter(Mandatory=$False)]
        [string]$CertificateRequestConfigFile = "NewCertRequestConfig_$CertificateCN"+$(Get-Date -format 'dd-MMM-yyyy_HHmm')+".inf",

        # This function creates the $CertificateRequestFile. It should NOT exist prior to running this function
        [Parameter(Mandatory=$False)]
        [string]$CertificateRequestFile = "NewCertRequest_$CertificateCN"+$(Get-Date -format 'dd-MMM-yyyy_HHmm')+".csr",

        # This function creates $CertFileOut. It should NOT exist prior to running this function
        [Parameter(Mandatory=$False)]
        [string]$CertFileOut = "NewCertificate_$CertificateCN"+$(Get-Date -format 'dd-MMM-yyyy_HHmm')+".cer",

        # This function creates the $CertificateChainOut. It should NOT exist prior to running this function
        [Parameter(Mandatory=$False)]
        [string]$CertificateChainOut = "NewCertificateChain_$CertificateCN"+$(Get-Date -format 'dd-MMM-yyyy_HHmm')+".p7b",

        # This function creates the $PFXFileOut. It should NOT exist prior to running this function
        [Parameter(Mandatory=$False)]
        [string]$PFXFileOut = "NewCertificate_$CertificateCN"+$(Get-Date -format 'dd-MMM-yyyy_HHmm')+".pfx",

        [Parameter(Mandatory=$False)]
        [securestring]$PFXPwdAsSecureString,

        # If the workstation being used to request the certificate is part of the same domain as the Issuing Certificate Authority, we can identify
        # the Issuing Certificate Authority with certutil, so there is no need to set an $IssuingCertificateAuth Parameter
        #[Parameter(Mandatory=$False)]
        #$IssuingCertAuth = $(Read-Host -Prompt "Please enter the FQDN the server responsible for Issuing New Certificates."),

        [Parameter(Mandatory=$False)]
        [ValidatePattern("certsrv$")]
        [string]$ADCSWebEnrollmentUrl, # Example: https://pki.zero.lab/certsrv"

        [Parameter(Mandatory=$False)]
        [ValidateSet("Windows","Basic")]
        [string]$ADCSWebAuthType,

        [Parameter(Mandatory=$False)]
        [string]$ADCSWebAuthUserName,

        [Parameter(Mandatory=$False)]
        [securestring]$ADCSWebAuthPass,

        [Parameter(Mandatory=$False)]
        [System.Management.Automation.PSCredential]$ADCSWebCreds,

        # This function creates the $CertADCSWebResponseOutFile file. It should NOT exist prior to running this function
        [Parameter(Mandatory=$False)]
        [string]$CertADCSWebResponseOutFile = "NewCertificate_$CertificateCN"+"_ADCSWebResponse"+$(Get-Date -format 'dd-MMM-yyyy_HHmm')+".txt",

        [Parameter(Mandatory=$False)]
        $Organization = $(Read-Host -Prompt "Please enter the name of the the Company that will appear on the New Certificate"),

        [Parameter(Mandatory=$False)]
        $OrganizationalUnit = $(Read-Host -Prompt "Please enter the name of the Department that you work for within your Company"),

        [Parameter(Mandatory=$False)]
        $Locality = $(Read-Host -Prompt "Please enter the City where your Company is located"),

        [Parameter(Mandatory=$False)]
        $State = $(Read-Host -Prompt "Please enter the State where your Company is located"),

        [Parameter(Mandatory=$False)]
        $Country = $(Read-Host -Prompt "Please enter the Country where your Company is located"),

        <#
        # ValidityPeriod is controlled by the Certificate Template and cannot be modified at the time of certificate request
        # (Unless it is a special circumstance where "RequestType = Cert" resulting in a self-signed cert where no request
        # is actually submitted)
        [Parameter(Mandatory=$False)]
        $ValidityPeriodValue = $(Read-Host -Prompt "Please enter the length of time that the certificate will be valid for.
        NOTE: Values must be in Months or Years. For example '6 months' or '2 years'"),
        #>

        [Parameter(Mandatory=$False)]
        [ValidateSet("2048","4096")]
        $KeyLength = "2048",

        [Parameter(Mandatory=$False)]
        [ValidateSet("SHA1","SHA256","SHA384","SHA512","MD5","MD4","MD2")]
        $HashAlgorithmValue = "SHA256",

        <#
        # KeyAlgorithm should be determined by ProviderName. Run "certutil -csplist" to see which Providers use which Key Algorithms
        [Parameter(Mandatory=$False)]
        [ValidateSet("RSA","DH","DSA","ECDH_P256","ECDH_P521","ECDSA_P256","ECDSA_P384","ECDSA_P521")]
        $KeyAlgorithmValue,
        #>

        [Parameter(Mandatory=$False)]
        [ValidateSet("AES","DES","3DES","RC2","RC4")]
        $EncryptionAlgorithmValue = "AES",

        [Parameter(Mandatory=$False)]
        [ValidateSet("True","False")]
        $PrivateKeyExportableValue = "True",

        # Valid values are '1' for AT_KEYEXCHANGE and '2' for AT_SIGNATURE [1,2]"
        [Parameter(Mandatory=$False)]
        [ValidateSet("1","2")]
        $KeySpecValue = "1",

        <#
        The below $KeyUsageValue is the HEXADECIMAL SUM of the KeyUsage hexadecimal values you would like to use.

        A valid value is the hex sum of one or more of following:
            CERT_DIGITAL_SIGNATURE_KEY_USAGE = 80
            CERT_NON_REPUDIATION_KEY_USAGE = 40
            CERT_KEY_ENCIPHERMENT_KEY_USAGE = 20
            CERT_DATA_ENCIPHERMENT_KEY_USAGE = 10
            CERT_KEY_AGREEMENT_KEY_USAGE = 8
            CERT_KEY_CERT_SIGN_KEY_USAGE = 4
            CERT_OFFLINE_CRL_SIGN_KEY_USAGE = 2
            CERT_CRL_SIGN_KEY_USAGE = 2
            CERT_ENCIPHER_ONLY_KEY_USAGE = 1
        
        Commonly Used Values:
            'c0' (i.e. 80+40)
            'a0' (i.e. 80+20)
            'f0' (i.e. 80+40+20+10)
            '30' (i.e. 20+10)
            '80'
        #>
        [Parameter(Mandatory=$False)]
        [ValidateSet("1","10","11","12","13","14","15","16","17","18","2","20","21","22","23","24","25","26","27","28","3","30","38","4","40",
        "41","42","43","44","45","46","47","48","5","50","58","6","60","68","7","70","78","8","80","81","82","83","84","85","86","87","88","9","90",
        "98","a","a0","a8","b","b0","b8","c","c0","c","8","d","d0","d8","e","e0","e8","f","f0","f8")]
        $KeyUsageValue = "80",
        
        [Parameter(Mandatory=$False)]
        [ValidateSet("True","False")]
        $MachineKeySet = "False",

        [Parameter(Mandatory=$False)]
        [ValidateSet("Yes","No")]
        $SecureEmail = "No",

        [Parameter(Mandatory=$False)]
        [ValidateSet("True","False")]
        $UserProtected = "False",

        [Parameter(Mandatory=$False)]
        [ValidateSet("Microsoft Base Cryptographic Provider v1.0","Microsoft Base DSS and Diffie-Hellman Cryptographic Provider",
        "Microsoft Base DSS Cryptographic Provider","Microsoft Base Smart Card Crypto Provider",
        "Microsoft DH SChannel Cryptographic Provider","Microsoft Enhanced Cryptographic Provider v1.0",
        "Microsoft Enhanced DSS and Diffie-Hellman Cryptographic Provider",
        "Microsoft Enhanced RSA and AES Cryptographic Provider","Microsoft RSA SChannel Cryptographic Provider",
        "Microsoft Strong Cryptographic Provider","Microsoft Software Key Storage Provider",
        "Microsoft Passport Key Storage Provider")]
        [string]$ProviderNameValue = "Microsoft RSA SChannel Cryptographic Provider",

        [Parameter(Mandatory=$False)]
        [ValidateSet("CMC", "PKCS10", "PKCS10-", "PKCS7")]
        $RequestTypeValue = "PKCS10",

        [Parameter(Mandatory=$False)]
        [ValidateSet("Code Signing","Document Signing","Client Authentication","Server Authentication",
        "Remote Desktop","Private Key Archival","Directory Service Email Replication","Key Recovery Agent",
        "OCSP Signing","Microsoft Trust List Signing","EFS","Secure E-mail","Enrollment Agent","Smart Card Logon",
        "File Recovery","IPSec IKE Intermediate","KDC Authentication","Windows Update",
        "Windows Third Party Application Component","Windows TCB Component","Windows Store",
        "Windows Software Extension Verification","Windows RT Verification","Windows Kits Component",
        "No OCSP Failover to CRL","Auto Update End Revocation","Auto Update CA Revocation","Revoked List Signer",
        "Protected Process Verification","Protected Process Light Verification","Platform Certificate",
        "Microsoft Publisher","Kernel Mode Code Signing","HAL Extension","Endorsement Key Certificate",
        "Early Launch Antimalware Driver","Dynamic Code Generator","DNS Server Trust","Document Encryption",
        "Disallowed List","Attestation Identity Key Certificate","System Health Authentication","CTL Usage",
        "IP Security End System","IP Security Tunnel Termination","IP Security User","Time Stamping",
        "Microsoft Time Stamping","Windows Hardware Driver Verification","Windows System Component Verification",
        "OEM Windows System Component Verification","Embedded Windows System Component Verification","Root List Signer",
        "Qualified Subordination","Key Recovery","Lifetime Signing","Key Pack Licenses","License Server Verification")]
        [string[]]$IntendedPurposeValues,

        [Parameter(Mandatory=$False)]
        [ValidateSet("Yes","No")]
        $UseOpenSSL = "Yes",

        [Parameter(Mandatory=$False)]
        [string]$AllPublicKeysInChainOut = "NewCertificate_$CertificateCN"+"_all_public_keys_in_chain"+".pem",

        [Parameter(Mandatory=$False)]
        [string]$ProtectedPrivateKeyOut = "NewCertificate_$CertificateCN"+"_protected_private_key"+".pem",
        
        [Parameter(Mandatory=$False)]
        [string]$UnProtectedPrivateKeyOut = "NewCertificate_$CertificateCN"+"_unprotected_private_key"+".key",

        [Parameter(Mandatory=$False)]
        [ValidateSet("Yes","No")]
        $StripPrivateKeyOfPassword = "Yes",

        [Parameter(Mandatory=$False)]
        [ValidateSet("DNS","Distinguished Name","URL","IP Address","Email","UPN","GUID")]
        [string[]]$SANObjectsToAdd,

        [Parameter(Mandatory=$False)]
        [string[]]$DNSSANObjects, # Example: www.fabrikam.com, www.contoso.org

        [Parameter(Mandatory=$False)]
        [string[]]$DistinguishedNameSANObjects, # Example: CN=www01,OU=Web Servers,DC=fabrikam,DC=com; CN=www01,OU=Load Balancers,DC=fabrikam,DC=com"

        [Parameter(Mandatory=$False)]
        [string[]]$URLSANObjects, # Example: http://www.fabrikam.com, http://www.contoso.com

        [Parameter(Mandatory=$False)]
        [string[]]$IPAddressSANObjects, # Example: 192.168.2.12, 10.10.1.15

        [Parameter(Mandatory=$False)]
        [string[]]$EmailSANObjects, # Example: mike@fabrikam.com, hazem@fabrikam.com

        [Parameter(Mandatory=$False)]
        [string[]]$UPNSANObjects, # Example: mike@fabrikam.com, hazem@fabrikam.com

        [Parameter(Mandatory=$False)]
        [string[]]$GUIDSANObjects,

        [Parameter(Mandatory=$False)]
        [switch]$CSRGenOnly
    )

    ##### BEGIN Helper Functions #####

    function Test-IsValidIPAddress([string]$IPAddress) {
        [boolean]$Octets = (($IPAddress.Split(".")).Count -eq 4) 
        [boolean]$Valid  =  ($IPAddress -as [ipaddress]) -as [boolean]
        Return  ($Valid -and $Octets)
    }

    function Compare-Arrays {
        [CmdletBinding()]
        Param(
            [Parameter(Mandatory=$False)]
            [array]$LargerArray,

            [Parameter(Mandatory=$False)]
            [array]$SmallerArray
        )

        -not @($SmallerArray | where {$LargerArray -notcontains $_}).Count
    }

    $OIDHashTable = @{
        # Remote Desktop
        "Remote Desktop" = "1.3.6.1.4.1.311.54.1.2"
        # Windows Update
        "Windows Update" = "1.3.6.1.4.1.311.76.6.1"
        # Windows Third Party Applicaiton Component
        "Windows Third Party Application Component" = "1.3.6.1.4.1.311.10.3.25"
        # Windows TCB Component
        "Windows TCB Component" = "1.3.6.1.4.1.311.10.3.23"
        # Windows Store
        "Windows Store" = "1.3.6.1.4.1.311.76.3.1"
        # Windows Software Extension verification
        " Windows Software Extension Verification" = "1.3.6.1.4.1.311.10.3.26"
        # Windows RT Verification
        "Windows RT Verification" = "1.3.6.1.4.1.311.10.3.21"
        # Windows Kits Component
        "Windows Kits Component" = "1.3.6.1.4.1.311.10.3.20"
        # ROOT_PROGRAM_NO_OCSP_FAILOVER_TO_CRL
        "No OCSP Failover to CRL" = "1.3.6.1.4.1.311.60.3.3"
        # ROOT_PROGRAM_AUTO_UPDATE_END_REVOCATION
        "Auto Update End Revocation" = "1.3.6.1.4.1.311.60.3.2"
        # ROOT_PROGRAM_AUTO_UPDATE_CA_REVOCATION
        "Auto Update CA Revocation" = "1.3.6.1.4.1.311.60.3.1"
        # Revoked List Signer
        "Revoked List Signer" = "1.3.6.1.4.1.311.10.3.19"
        # Protected Process Verification
        "Protected Process Verification" = "1.3.6.1.4.1.311.10.3.24"
        # Protected Process Light Verification
        "Protected Process Light Verification" = "1.3.6.1.4.1.311.10.3.22"
        # Platform Certificate
        "Platform Certificate" = "2.23.133.8.2"
        # Microsoft Publisher
        "Microsoft Publisher" = "1.3.6.1.4.1.311.76.8.1"
        # Kernel Mode Code Signing
        "Kernel Mode Code Signing" = "1.3.6.1.4.1.311.6.1.1"
        # HAL Extension
        "HAL Extension" = "1.3.6.1.4.1.311.61.5.1"
        # Endorsement Key Certificate
        "Endorsement Key Certificate" = "2.23.133.8.1"
        # Early Launch Antimalware Driver
        "Early Launch Antimalware Driver" = "1.3.6.1.4.1.311.61.4.1"
        # Dynamic Code Generator
        "Dynamic Code Generator" = "1.3.6.1.4.1.311.76.5.1"
        # Domain Name System (DNS) Server Trust
        "DNS Server Trust" = "1.3.6.1.4.1.311.64.1.1"
        # Document Encryption
        "Document Encryption" = "1.3.6.1.4.1.311.80.1"
        # Disallowed List
        "Disallowed List" = "1.3.6.1.4.1.10.3.30"
        # Attestation Identity Key Certificate
        "Attestation Identity Key Certificate" = "2.23.133.8.3"
        "Generic Conference Contro" = "0.0.20.124.0.1"
        "X509Extensions" = "1.3.6.1.4.1.311.2.1.14"
        "EnrollmentCspProvider" = "1.3.6.1.4.1.311.13.2.2"
        # System Health Authentication
        "System Health Authentication" = "1.3.6.1.4.1.311.47.1.1"
        "OsVersion" = "1.3.6.1.4.1.311.13.2.3"
        "RenewalCertificate" = "1.3.6.1.4.1.311.13.1"
        "Certificate Template" = "1.3.6.1.4.1.311.20.2"
        "RequestClientInfo" = "1.3.6.1.4.1.311.21.20"
        "ArchivedKeyAttr" = "1.3.6.1.4.1.311.21.13"
        "EncryptedKeyHash" = "1.3.6.1.4.1.311.21.21"
        "EnrollmentNameValuePair" = "1.3.6.1.4.1.311.13.2.1"
        "IdAtName" = "2.5.4.41"
        "IdAtCommonName" = "2.5.4.3"
        "IdAtLocalityName" = "2.5.4.7"
        "IdAtStateOrProvinceName" = "2.5.4.8"
        "IdAtOrganizationName" = "2.5.4.10"
        "IdAtOrganizationalUnitName" = "2.5.4.11"
        "IdAtTitle" = "2.5.4.12"
        "IdAtDnQualifier" = "2.5.4.46"
        "IdAtCountryName" = "2.5.4.6"
        "IdAtSerialNumber" = "2.5.4.5"
        "IdAtPseudonym" = "2.5.4.65"
        "IdDomainComponent" = "0.9.2342.19200300.100.1.25"
        "IdEmailAddress" = "1.2.840.113549.1.9.1"
        "IdCeAuthorityKeyIdentifier" = "2.5.29.35"
        "IdCeSubjectKeyIdentifier" = "2.5.29.14"
        "IdCeKeyUsage" = "2.5.29.15"
        "IdCePrivateKeyUsagePeriod" = "2.5.29.16"
        "IdCeCertificatePolicies" = "2.5.29.32"
        "IdCePolicyMappings" = "2.5.29.33"
        "IdCeSubjectAltName" = "2.5.29.17"
        "IdCeIssuerAltName" = "2.5.29.18"
        "IdCeBasicConstraints" = "2.5.29.19"
        "IdCeNameConstraints" = "2.5.29.30"
        "idCdPolicyConstraints" = "2.5.29.36"
        "IdCeExtKeyUsage" = "2.5.29.37"
        "IdCeCRLDistributionPoints" = "2.5.29.31"
        "IdCeInhibitAnyPolicy" = "2.5.29.54"
        "IdPeAuthorityInfoAccess" = "1.3.6.1.5.5.7.1.1"
        "IdPeSubjectInfoAccess" = "1.3.6.1.5.5.7.1.11"
        "IdCeCRLNumber" = "2.5.29.20"
        "IdCeDeltaCRLIndicator" = "2.5.29.27"
        "IdCeIssuingDistributionPoint" = "2.5.29.28"
        "IdCeFreshestCRL" = "2.5.29.46"
        "IdCeCRLReason" = "2.5.29.21"
        "IdCeHoldInstructionCode" = "2.5.29.23"
        "IdCeInvalidityDate" = "2.5.29.24"
        "IdCeCertificateIssuer" = "2.5.29.29"
        "IdModAttributeCert" = "1.3.6.1.5.5.7.0.12"
        "IdPeAcAuditIdentity" = "1.3.6.1.5.5.7.1.4"
        "IdCeTargetInformation" = "2.5.29.55"
        "IdCeNoRevAvail" = "2.5.29.56"
        "IdAcaAuthenticationInfo" = "1.3.6.1.5.5.7.10.1"
        "IdAcaAccessIdentity" = "1.3.6.1.5.5.7.10.2"
        "IdAcaChargingIdentity" = "1.3.6.1.5.5.7.10.3"
        "IdAcaGroup" = "1.3.6.1.5.5.7.10.4"
        "IdAtRole" = "2.5.4.72"
        "IdAtClearance" = "2.5.1.5.55"
        "IdAcaEncAttrs" = "1.3.6.1.5.5.7.10.6"
        "IdPeAcProxying" = "1.3.6.1.5.5.7.1.10"
        "IdPeAaControls" = "1.3.6.1.5.5.7.1.6"
        "IdCtContentInfo" = "1.2.840.113549.1.9.16.1.6"
        "IdDataAuthpack" = "1.2.840.113549.1.7.1"
        "IdSignedData" = "1.2.840.113549.1.7.2"
        "IdEnvelopedData" = "1.2.840.113549.1.7.3"
        "IdDigestedData" = "1.2.840.113549.1.7.5"
        "IdEncryptedData" = "1.2.840.113549.1.7.6"
        "IdCtAuthData" = "1.2.840.113549.1.9.16.1.2"
        "IdContentType" = "1.2.840.113549.1.9.3"
        "IdMessageDigest" = "1.2.840.113549.1.9.4"
        "IdSigningTime" = "1.2.840.113549.1.9.5"
        "IdCounterSignature" = "1.2.840.113549.1.9.6"
        "RsaEncryption" = "1.2.840.113549.1.1.1"
        "IdRsaesOaep" = "1.2.840.113549.1.1.7"
        "IdPSpecified" = "1.2.840.113549.1.1.9"
        "IdRsassaPss" = "1.2.840.113549.1.1.10"
        "Md2WithRSAEncryption" = "1.2.840.113549.1.1.2"
        "Md5WithRSAEncryption" = "1.2.840.113549.1.1.4"
        "Sha1WithRSAEncryption" = "1.2.840.113549.1.1.5"
        "Sha256WithRSAEncryption" = "1.2.840.113549.1.1.11"
        "Sha384WithRSAEncryption" = "1.2.840.113549.1.1.12"
        "Sha512WithRSAEncryption" = "1.2.840.113549.1.1.13"
        "IdMd2" = "1.2.840.113549.2.2"
        "IdMd5" = "1.2.840.113549.2.5"
        "IdSha1" = "1.3.14.3.2.26"
        "IdSha256" = "2.16.840.1.101.3.4.2.1"
        "IdSha384" = "2.16.840.1.101.3.4.2.2"
        "IdSha512" = "2.16.840.1.101.3.4.2.3"
        "IdMgf1" = "1.2.840.113549.1.1.8"
        "IdDsaWithSha1" = "1.2.840.10040.4.3"
        "EcdsaWithSHA1" = "1.2.840.10045.4.1"
        "IdDsa" = "1.2.840.10040.4.1"
        "DhPublicNumber" = "1.2.840.10046.2.1"
        "IdKeyExchangeAlgorithm" = "2.16.840.1.101.2.1.1.22"
        "IdEcPublicKey" = "1.2.840.10045.2.1"
        "PrimeField" = "1.2.840.10045.1.1"
        "CharacteristicTwoField" = "1.2.840.10045.1.2"
        "GnBasis" = "1.2.840.10045.1.2.1.1"
        "TpBasis" = "1.2.840.10045.1.2.1.2"
        "PpBasis" = "1.2.840.10045.1.2.1.3"
        "IdAlgEsdh" = "1.2.840.113549.1.9.16.3.5"
        "IdAlgSsdh" = "1.2.840.113549.1.9.16.3.10"
        "IdAlgCms3DesWrap" = "1.2.840.113549.1.9.16.3.6"
        "IdAlgCmsRc2Wrap" = "1.2.840.113549.1.9.16.3.7"
        "IdPbkDf2" = "1.2.840.113549.1.5.12"
        "DesEde3Cbc" = "1.2.840.113549.3.7"
        "Rc2Cbc" = "1.2.840.113549.3.2"
        "HmacSha1" = "1.3.6.1.5.5.8.1.2"
        "IdAes128Cbc" = "2.16.840.1.101.3.4.1.2"
        "IdAes192Cbc" = "2.16.840.1.101.3.4.1.22"
        "IdAes256Cbc" = "2.16.840.1.101.3.4.1.42"
        "IdAes128Wrap" = "2.16.840.1.101.3.4.1.5"
        "IdAes192Wrap" = "2.16.840.1.101.3.4.1.25"
        "IdAes256Wrap" = "2.16.840.1.101.3.4.1.45"
        "IdCmcIdentification" = "1.3.6.1.5.5.7.7.2"
        "IdCmcIdentityProof" = "1.3.6.1.5.5.7.7.3"
        "IdCmcDataReturn" = "1.3.6.1.5.5.7.7.4"
        "IdCmcTransactionId" = "1.3.6.1.5.5.7.7.5"
        "IdCmcSenderNonce" = "1.3.6.1.5.5.7.7.6"
        "IdCmcRecipientNonce" = "1.3.6.1.5.5.7.7.7"
        "IdCmcRegInfo" = "1.3.6.1.5.5.7.7.18"
        "IdCmcResponseInfo" = "1.3.6.1.5.5.7.7.19"
        "IdCmcQueryPending" = "1.3.6.1.5.5.7.7.21"
        "IdCmcPopLinkRandom" = "1.3.6.1.5.5.7.7.22"
        "IdCmcPopLinkWitness" = "1.3.6.1.5.5.7.7.23"
        "IdCctPKIData" = "1.3.6.1.5.5.7.12.2"
        "IdCctPKIResponse" = "1.3.6.1.5.5.7.12.3"
        "IdCmccMCStatusInfo" = "1.3.6.1.5.5.7.7.1"
        "IdCmcAddExtensions" = "1.3.6.1.5.5.7.7.8"
        "IdCmcEncryptedPop" = "1.3.6.1.5.5.7.7.9"
        "IdCmcDecryptedPop" = "1.3.6.1.5.5.7.7.10"
        "IdCmcLraPopWitness" = "1.3.6.1.5.5.7.7.11"
        "IdCmcGetCert" = "1.3.6.1.5.5.7.7.15"
        "IdCmcGetCRL" = "1.3.6.1.5.5.7.7.16"
        "IdCmcRevokeRequest" = "1.3.6.1.5.5.7.7.17"
        "IdCmcConfirmCertAcceptance" = "1.3.6.1.5.5.7.7.24"
        "IdExtensionReq" = "1.2.840.113549.1.9.14"
        "IdAlgNoSignature" = "1.3.6.1.5.5.7.6.2"
        "PasswordBasedMac" = "1.2.840.113533.7.66.13"
        "IdRegCtrlRegToken" = "1.3.6.1.5.5.7.5.1.1"
        "IdRegCtrlAuthenticator" = "1.3.6.1.5.5.7.5.1.2"
        "IdRegCtrlPkiPublicationInfo" = "1.3.6.1.5.5.7.5.1.3"
        "IdRegCtrlPkiArchiveOptions" = "1.3.6.1.5.5.7.5.1.4"
        "IdRegCtrlOldCertID" = "1.3.6.1.5.5.7.5.1.5"
        "IdRegCtrlProtocolEncrKey" = "1.3.6.1.5.5.7.5.1.6"
        "IdRegInfoUtf8Pairs" = "1.3.6.1.5.5.7.5.2.1"
        "IdRegInfoCertReq" = "1.3.6.1.5.5.7.5.2.2"
        "SpnegoToken" = "1.3.6.1.5.5.2"
        "SpnegoNegTok" = "1.3.6.1.5.5.2.4.2"
        "GSS_KRB5_NT_USER_NAME" = "1.2.840.113554.1.2.1.1"
        "GSS_KRB5_NT_MACHINE_UID_NAME" = "1.2.840.113554.1.2.1.2"
        "GSS_KRB5_NT_STRING_UID_NAME" = "1.2.840.113554.1.2.1.3"
        "GSS_C_NT_HOSTBASED_SERVICE" = "1.2.840.113554.1.2.1.4"
        "KerberosToken" = "1.2.840.113554.1.2.2"
        "Negoex" = "1.3.6.1.4.1.311.2.2.30" 
        "GSS_KRB5_NT_PRINCIPAL_NAME" = "1.2.840.113554.1.2.2.1"
        "GSS_KRB5_NT_PRINCIPAL" = "1.2.840.113554.1.2.2.2"
        "UserToUserMechanism" = "1.2.840.113554.1.2.2.3"
        "MsKerberosToken" = "1.2.840.48018.1.2.2"
        "NLMP" = "1.3.6.1.4.1.311.2.2.10"
        "IdPkixOcspBasic" = "1.3.6.1.5.5.7.48.1.1"
        "IdPkixOcspNonce" = "1.3.6.1.5.5.7.48.1.2"
        "IdPkixOcspCrl" = "1.3.6.1.5.5.7.48.1.3"
        "IdPkixOcspResponse" = "1.3.6.1.5.5.7.48.1.4"
        "IdPkixOcspNocheck" = "1.3.6.1.5.5.7.48.1.5"
        "IdPkixOcspArchiveCutoff" = "1.3.6.1.5.5.7.48.1.6"
        "IdPkixOcspServiceLocator" = "1.3.6.1.5.5.7.48.1.7"
        # Smartcard Logon
        "IdMsKpScLogon" = "1.3.6.1.4.1.311.20.2.2"
        "IdPkinitSan" = "1.3.6.1.5.2.2"
        "IdPkinitAuthData" = "1.3.6.1.5.2.3.1"
        "IdPkinitDHKeyData" = "1.3.6.1.5.2.3.2"
        "IdPkinitRkeyData" = "1.3.6.1.5.2.3.3"
        "IdPkinitKPClientAuth" = "1.3.6.1.5.2.3.4"
        "IdPkinitKPKdc" = "1.3.6.1.5.2.3.5"
        "SHA1 with RSA signature" = "1.3.14.3.2.29"
        "AUTHORITY_KEY_IDENTIFIER" = "2.5.29.1"
        "KEY_ATTRIBUTES" = "2.5.29.2"
        "CERT_POLICIES_95" = "2.5.29.3"
        "KEY_USAGE_RESTRICTION" = "2.5.29.4"
        "SUBJECT_ALT_NAME" = "2.5.29.7"
        "ISSUER_ALT_NAME" = "2.5.29.8"
        "Subject_Directory_Attributes" = "2.5.29.9"
        "BASIC_CONSTRAINTS" = "2.5.29.10"
        "ANY_CERT_POLICY" = "2.5.29.32.0"
        "LEGACY_POLICY_MAPPINGS" = "2.5.29.5"
        # Certificate Request Agent
        "ENROLLMENT_AGENT" = "1.3.6.1.4.1.311.20.2.1"
        "PKIX" = "1.3.6.1.5.5.7"
        "PKIX_PE" = "1.3.6.1.5.5.7.1"
        "NEXT_UPDATE_LOCATION" = "1.3.6.1.4.1.311.10.2"
        "REMOVE_CERTIFICATE" = "1.3.6.1.4.1.311.10.8.1"
        "CROSS_CERT_DIST_POINTS" = "1.3.6.1.4.1.311.10.9.1"
        "CTL" = "1.3.6.1.4.1.311.10.1"
        "SORTED_CTL" = "1.3.6.1.4.1.311.10.1.1"
        "SERIALIZED" = "1.3.6.1.4.1.311.10.3.3.1"
        "NT_PRINCIPAL_NAME" = "1.3.6.1.4.1.311.20.2.3"
        "PRODUCT_UPDATE" = "1.3.6.1.4.1.311.31.1"
        "ANY_APPLICATION_POLICY" = "1.3.6.1.4.1.311.10.12.1"
        # CTL Usage
        "AUTO_ENROLL_CTL_USAGE" = "1.3.6.1.4.1.311.20.1"
        "CERT_MANIFOLD" = "1.3.6.1.4.1.311.20.3"
        "CERTSRV_CA_VERSION" = "1.3.6.1.4.1.311.21.1"
        "CERTSRV_PREVIOUS_CERT_HASH" = "1.3.6.1.4.1.311.21.2"
        "CRL_VIRTUAL_BASE" = "1.3.6.1.4.1.311.21.3"
        "CRL_NEXT_PUBLISH" = "1.3.6.1.4.1.311.21.4"
        # Private Key Archival
        "KP_CA_EXCHANGE" = "1.3.6.1.4.1.311.21.5"
        # Key Recovery Agent
        "KP_KEY_RECOVERY_AGENT" = "1.3.6.1.4.1.311.21.6"
        "CERTIFICATE_TEMPLATE" = "1.3.6.1.4.1.311.21.7"
        "ENTERPRISE_OID_ROOT" = "1.3.6.1.4.1.311.21.8"
        "RDN_DUMMY_SIGNER" = "1.3.6.1.4.1.311.21.9"
        "APPLICATION_CERT_POLICIES" = "1.3.6.1.4.1.311.21.10"
        "APPLICATION_POLICY_MAPPINGS" = "1.3.6.1.4.1.311.21.11"
        "APPLICATION_POLICY_CONSTRAINTS" = "1.3.6.1.4.1.311.21.12"
        "CRL_SELF_CDP" = "1.3.6.1.4.1.311.21.14"
        "REQUIRE_CERT_CHAIN_POLICY" = "1.3.6.1.4.1.311.21.15"
        "ARCHIVED_KEY_CERT_HASH" = "1.3.6.1.4.1.311.21.16"
        "ISSUED_CERT_HASH" = "1.3.6.1.4.1.311.21.17"
        "DS_EMAIL_REPLICATION" = "1.3.6.1.4.1.311.21.19"
        "CERTSRV_CROSSCA_VERSION" = "1.3.6.1.4.1.311.21.22"
        "NTDS_REPLICATION" = "1.3.6.1.4.1.311.25.1"
        "PKIX_KP" = "1.3.6.1.5.5.7.3"
        "PKIX_KP_SERVER_AUTH" = "1.3.6.1.5.5.7.3.1"
        "PKIX_KP_CLIENT_AUTH" = "1.3.6.1.5.5.7.3.2"
        "PKIX_KP_CODE_SIGNING" = "1.3.6.1.5.5.7.3.3"
        # Secure Email
        "PKIX_KP_EMAIL_PROTECTION" = "1.3.6.1.5.5.7.3.4"
        # IP Security End System
        "PKIX_KP_IPSEC_END_SYSTEM" = "1.3.6.1.5.5.7.3.5"
        # IP Security Tunnel Termination
        "PKIX_KP_IPSEC_TUNNEL" = "1.3.6.1.5.5.7.3.6"
        # IP Security User
        "PKIX_KP_IPSEC_USER" = "1.3.6.1.5.5.7.3.7"
        # Time Stamping
        "PKIX_KP_TIMESTAMP_SIGNING" = "1.3.6.1.5.5.7.3.8"
        "KP_OCSP_SIGNING" = "1.3.6.1.5.5.7.3.9"
        # IP security IKE intermediate
        "IPSEC_KP_IKE_INTERMEDIATE" = "1.3.6.1.5.5.8.2.2"
        # Microsoft Trust List Signing
        "KP_CTL_USAGE_SIGNING" = "1.3.6.1.4.1.311.10.3.1"
        # Microsoft Time Stamping
        "KP_TIME_STAMP_SIGNING" = "1.3.6.1.4.1.311.10.3.2"
        "SERVER_GATED_CRYPTO" = "1.3.6.1.4.1.311.10.3.3"
        "SGC_NETSCAPE" = "2.16.840.1.113730.4.1"
        "KP_EFS" = "1.3.6.1.4.1.311.10.3.4"
        "EFS_RECOVERY" = "1.3.6.1.4.1.311.10.3.4.1"
        # Windows Hardware Driver Verification
        "WHQL_CRYPTO" = "1.3.6.1.4.1.311.10.3.5"
        # Windows System Component Verification
        "NT5_CRYPTO" = "1.3.6.1.4.1.311.10.3.6"
        # OEM Windows System Component Verification
        "OEM_WHQL_CRYPTO" = "1.3.6.1.4.1.311.10.3.7"
        # Embedded Windows System Component Verification
        "EMBEDDED_NT_CRYPTO" = "1.3.6.1.4.1.311.10.3.8"
        # Root List Signer
        "ROOT_LIST_SIGNER" = "1.3.6.1.4.1.311.10.3.9"
        # Qualified Subordination
        "KP_QUALIFIED_SUBORDINATION" = "1.3.6.1.4.1.311.10.3.10"
        # Key Recovery
        "KP_KEY_RECOVERY" = "1.3.6.1.4.1.311.10.3.11"
        "KP_DOCUMENT_SIGNING" = "1.3.6.1.4.1.311.10.3.12"
        # Lifetime Signing
        "KP_LIFETIME_SIGNING" = "1.3.6.1.4.1.311.10.3.13"
        "KP_MOBILE_DEVICE_SOFTWARE" = "1.3.6.1.4.1.311.10.3.14"
        # Digital Rights
        "DRM" = "1.3.6.1.4.1.311.10.5.1"
        "DRM_INDIVIDUALIZATION" = "1.3.6.1.4.1.311.10.5.2"
        # Key Pack Licenses
        "LICENSES" = "1.3.6.1.4.1.311.10.6.1"
        # License Server Verification
        "LICENSE_SERVER" = "1.3.6.1.4.1.311.10.6.2"
        "YESNO_TRUST_ATTR" = "1.3.6.1.4.1.311.10.4.1"
        "PKIX_POLICY_QUALIFIER_CPS" = "1.3.6.1.5.5.7.2.1"
        "PKIX_POLICY_QUALIFIER_USERNOTICE" = "1.3.6.1.5.5.7.2.2"
        "CERT_POLICIES_95_QUALIFIER1" = "2.16.840.1.113733.1.7.1.1"
        "RSA" = "1.2.840.113549"
        "PKCS" = "1.2.840.113549.1"
        "RSA_HASH" = "1.2.840.113549.2"
        "RSA_ENCRYPT" = "1.2.840.113549.3"
        "PKCS_1" = "1.2.840.113549.1.1"
        "PKCS_2" = "1.2.840.113549.1.2"
        "PKCS_3" = "1.2.840.113549.1.3"
        "PKCS_4" = "1.2.840.113549.1.4"
        "PKCS_5" = "1.2.840.113549.1.5"
        "PKCS_6" = "1.2.840.113549.1.6"
        "PKCS_7" = "1.2.840.113549.1.7"
        "PKCS_8" = "1.2.840.113549.1.8"
        "PKCS_9" = "1.2.840.113549.1.9"
        "PKCS_10" = "1.2.840.113549.1.10"
        "PKCS_12" = "1.2.840.113549.1.12"
        "RSA_MD4RSA" = "1.2.840.113549.1.1.3"
        "RSA_SETOAEP_RSA" = "1.2.840.113549.1.1.6"
        "RSA_DH" = "1.2.840.113549.1.3.1"
        "RSA_signEnvData" = "1.2.840.113549.1.7.4"
        "RSA_unstructName" = "1.2.840.113549.1.9.2"
        "RSA_challengePwd" = "1.2.840.113549.1.9.7"
        "RSA_unstructAddr" = "1.2.840.113549.1.9.8"
        "RSA_extCertAttrs" = "1.2.840.113549.1.9.9"
        "RSA_SMIMECapabilities" = "1.2.840.113549.1.9.15"
        "RSA_preferSignedData" = "1.2.840.113549.1.9.15.1"
        "RSA_SMIMEalg" = "1.2.840.113549.1.9.16.3"
        "RSA_MD4" = "1.2.840.113549.2.4"
        "RSA_RC4" = "1.2.840.113549.3.4"
        "RSA_RC5_CBCPad" = "1.2.840.113549.3.9"
        "ANSI_X942" = "1.2.840.10046"
        "X957" = "1.2.840.10040"
        "DS" = "2.5"
        "DSALG" = "2.5.8"
        "DSALG_CRPT" = "2.5.8.1"
        "DSALG_HASH" = "2.5.8.2"
        "DSALG_SIGN" = "2.5.8.3"
        "DSALG_RSA" = "2.5.8.1.1"
        "OIW" = "1.3.14"
        "OIWSEC" = "1.3.14.3.2"
        "OIWSEC_md4RSA" = "1.3.14.3.2.2"
        "OIWSEC_md5RSA" = "1.3.14.3.2.3"
        "OIWSEC_md4RSA2" = "1.3.14.3.2.4"
        "OIWSEC_desECB" = "1.3.14.3.2.6"
        "OIWSEC_desCBC" = "1.3.14.3.2.7"
        "OIWSEC_desOFB" = "1.3.14.3.2.8"
        "OIWSEC_desCFB" = "1.3.14.3.2.9"
        "OIWSEC_desMAC" = "1.3.14.3.2.10"
        "OIWSEC_rsaSign" = "1.3.14.3.2.11"
        "OIWSEC_dsa" = "1.3.14.3.2.12"
        "OIWSEC_shaDSA" = "1.3.14.3.2.13"
        "OIWSEC_mdc2RSA" = "1.3.14.3.2.14"
        "OIWSEC_shaRSA" = "1.3.14.3.2.15"
        "OIWSEC_dhCommMod" = "1.3.14.3.2.16"
        "OIWSEC_desEDE" = "1.3.14.3.2.17"
        "OIWSEC_sha" = "1.3.14.3.2.18"
        "OIWSEC_mdc2" = "1.3.14.3.2.19"
        "OIWSEC_dsaComm" = "1.3.14.3.2.20"
        "OIWSEC_dsaCommSHA" = "1.3.14.3.2.21"
        "OIWSEC_rsaXchg" = "1.3.14.3.2.22"
        "OIWSEC_keyHashSeal" = "1.3.14.3.2.23"
        "OIWSEC_md2RSASign" = "1.3.14.3.2.24"
        "OIWSEC_md5RSASign" = "1.3.14.3.2.25"
        "OIWSEC_dsaSHA1" = "1.3.14.3.2.27"
        "OIWSEC_dsaCommSHA1" = "1.3.14.3.2.28"
        "OIWDIR" = "1.3.14.7.2"
        "OIWDIR_CRPT" = "1.3.14.7.2.1"
        "OIWDIR_HASH" = "1.3.14.7.2.2"
        "OIWDIR_SIGN" = "1.3.14.7.2.3"
        "OIWDIR_md2" = "1.3.14.7.2.2.1"
        "OIWDIR_md2RSA" = "1.3.14.7.2.3.1"
        "INFOSEC" = "2.16.840.1.101.2.1"
        "INFOSEC_sdnsSignature" = "2.16.840.1.101.2.1.1.1"
        "INFOSEC_mosaicSignature" = "2.16.840.1.101.2.1.1.2"
        "INFOSEC_sdnsConfidentiality" = "2.16.840.1.101.2.1.1.3"
        "INFOSEC_mosaicConfidentiality" = "2.16.840.1.101.2.1.1.4"
        "INFOSEC_sdnsIntegrity" = "2.16.840.1.101.2.1.1.5"
        "INFOSEC_mosaicIntegrity" = "2.16.840.1.101.2.1.1.6"
        "INFOSEC_sdnsTokenProtection" = "2.16.840.1.101.2.1.1.7"
        "INFOSEC_mosaicTokenProtection" = "2.16.840.1.101.2.1.1.8"
        "INFOSEC_sdnsKeyManagement" = "2.16.840.1.101.2.1.1.9"
        "INFOSEC_mosaicKeyManagement" = "2.16.840.1.101.2.1.1.10"
        "INFOSEC_sdnsKMandSig" = "2.16.840.1.101.2.1.1.11"
        "INFOSEC_mosaicKMandSig" = "2.16.840.1.101.2.1.1.12"
        "INFOSEC_SuiteASignature" = "2.16.840.1.101.2.1.1.13"
        "INFOSEC_SuiteAConfidentiality" = "2.16.840.1.101.2.1.1.14"
        "INFOSEC_SuiteAIntegrity" = "2.16.840.1.101.2.1.1.15"
        "INFOSEC_SuiteATokenProtection" = "2.16.840.1.101.2.1.1.16"
        "INFOSEC_SuiteAKeyManagement" = "2.16.840.1.101.2.1.1.17"
        "INFOSEC_SuiteAKMandSig" = "2.16.840.1.101.2.1.1.18"
        "INFOSEC_mosaicUpdatedSig" = "2.16.840.1.101.2.1.1.19"
        "INFOSEC_mosaicKMandUpdSig" = "2.16.840.1.101.2.1.1.20"
        "INFOSEC_mosaicUpdatedInteg" = "2.16.840.1.101.2.1.1.21"
        "SUR_NAME" = "2.5.4.4"
        "STREET_ADDRESS" = "2.5.4.9"
        "DESCRIPTION" = "2.5.4.13"
        "SEARCH_GUIDE" = "2.5.4.14"
        "BUSINESS_CATEGORY" = "2.5.4.15"
        "POSTAL_ADDRESS" = "2.5.4.16"
        "POSTAL_CODE" = "2.5.4.17"
        "POST_OFFICE_BOX" = "2.5.4.18"
        "PHYSICAL_DELIVERY_OFFICE_NAME" = "2.5.4.19"
        "TELEPHONE_NUMBER" = "2.5.4.20"
        "TELEX_NUMBER" = "2.5.4.21"
        "TELETEXT_TERMINAL_IDENTIFIER" = "2.5.4.22"
        "FACSIMILE_TELEPHONE_NUMBER" = "2.5.4.23"
        "X21_ADDRESS" = "2.5.4.24"
        "INTERNATIONAL_ISDN_NUMBER" = "2.5.4.25"
        "REGISTERED_ADDRESS" = "2.5.4.26"
        "DESTINATION_INDICATOR" = "2.5.4.27"
        "PREFERRED_DELIVERY_METHOD" = "2.5.4.28"
        "PRESENTATION_ADDRESS" = "2.5.4.29"
        "SUPPORTED_APPLICATION_CONTEXT" = "2.5.4.30"
        "MEMBER" = "2.5.4.31"
        "OWNER" = "2.5.4.32"
        "ROLE_OCCUPANT" = "2.5.4.33"
        "SEE_ALSO" = "2.5.4.34"
        "USER_PASSWORD" = "2.5.4.35"
        "USER_CERTIFICATE" = "2.5.4.36"
        "CA_CERTIFICATE" = "2.5.4.37"
        "AUTHORITY_REVOCATION_LIST" = "2.5.4.38"
        "CERTIFICATE_REVOCATION_LIST" = "2.5.4.39"
        "CROSS_CERTIFICATE_PAIR" = "2.5.4.40"
        "GIVEN_NAME" = "2.5.4.42"
        "INITIALS" = "2.5.4.43"
        "PKCS_12_FRIENDLY_NAME_ATTR" = "1.2.840.113549.1.9.20"
        "PKCS_12_LOCAL_KEY_ID" = "1.2.840.113549.1.9.21"
        "PKCS_12_KEY_PROVIDER_NAME_ATTR" = "1.3.6.1.4.1.311.17.1"
        "LOCAL_MACHINE_KEYSET" = "1.3.6.1.4.1.311.17.2"
        "KEYID_RDN" = "1.3.6.1.4.1.311.10.7.1"
        "PKIX_ACC_DESCR" = "1.3.6.1.5.5.7.48"
        "PKIX_OCSP" = "1.3.6.1.5.5.7.48.1"
        "PKIX_CA_ISSUERS" = "1.3.6.1.5.5.7.48.2"
        "VERISIGN_PRIVATE_6_9" = "2.16.840.1.113733.1.6.9"
        "VERISIGN_ONSITE_JURISDICTION_HASH" = "2.16.840.1.113733.1.6.11"
        "VERISIGN_BITSTRING_6_13" = "2.16.840.1.113733.1.6.13"
        "VERISIGN_ISS_STRONG_CRYPTO" = "2.16.840.1.113733.1.8.1"
        "NETSCAPE" = "2.16.840.1.113730"
        "NETSCAPE_CERT_EXTENSION" = "2.16.840.1.113730.1"
        "NETSCAPE_CERT_TYPE" = "2.16.840.1.113730.1.1"
        "NETSCAPE_BASE_URL" = "2.16.840.1.113730.1.2"
        "NETSCAPE_REVOCATION_URL" = "2.16.840.1.113730.1.3"
        "NETSCAPE_CA_REVOCATION_URL" = "2.16.840.1.113730.1.4"
        "NETSCAPE_CERT_RENEWAL_URL" = "2.16.840.1.113730.1.7"
        "NETSCAPE_CA_POLICY_URL" = "2.16.840.1.113730.1.8"
        "NETSCAPE_SSL_SERVER_NAME" = "2.16.840.1.113730.1.12"
        "NETSCAPE_COMMENT" = "2.16.840.1.113730.1.13"
        "NETSCAPE_DATA_TYPE" = "2.16.840.1.113730.2"
        "NETSCAPE_CERT_SEQUENCE" = "2.16.840.1.113730.2.5"
        "CMC" = "1.3.6.1.5.5.7.7"
        "CMC_ADD_ATTRIBUTES" = "1.3.6.1.4.1.311.10.10.1"
        "PKCS_7_SIGNEDANDENVELOPED" = "1.2.840.113549.1.7.4"
        "CERT_PROP_ID_PREFIX" = "1.3.6.1.4.1.311.10.11."
        "CERT_KEY_IDENTIFIER_PROP_ID" = "1.3.6.1.4.1.311.10.11.20"
        "CERT_ISSUER_SERIAL_NUMBER_MD5_HASH_PROP_ID" = "1.3.6.1.4.1.311.10.11.28"
        "CERT_SUBJECT_NAME_MD5_HASH_PROP_ID" = "1.3.6.1.4.1.311.10.11.29"
    }

    function Get-IntendedPurposePSObjects {
        [CmdletBinding()]
        Param(
            [Parameter(Mandatory=$False)]
            [System.Collections.Hashtable]$OIDHashTable
        )
    
        $IntendedPurpose = "Code Signing"
        $OfficialName = "PKIX_KP_CODE_SIGNING"
        $OfficialOID = $OIDHashTable.$OfficialName
        $szOIDString = "szOID_$OfficialName"
        $CertRequestConfigFileLine = "szOID_$OfficialName = `"$OfficialOID`""
        $ExtKeyUse = $AppPol = $OfficialOID
    
        [pscustomobject]@{
            IntendedPurpose                 = $IntendedPurpose
            OfficialName                    = $OfficialName
            OfficialOID                     = $OfficialOID
            szOIDString                     = $szOIDString
            CertRequestConfigFileLine       = $CertRequestConfigFileLine
            ExtKeyUse                       = $OfficialOID
            AppPol                          = $OfficialOID
        }
        
        $IntendedPurpose = "Document Signing"
        $OfficialName = "KP_DOCUMENT_SIGNING"
        $OfficialOID = $OIDHashTable.$OfficialName
        $szOIDString = "szOID_$OfficialName"
        $CertRequestConfigFileLine = "szOID_$OfficialName = `"$OfficialOID`""
        $ExtKeyUse = $AppPol = $OfficialOID
        
        [pscustomobject]@{
            IntendedPurpose                 = $IntendedPurpose
            OfficialName                    = $OfficialName
            OfficialOID                     = $OfficialOID
            szOIDString                     = $szOIDString
            CertRequestConfigFileLine       = $CertRequestConfigFileLine
            ExtKeyUse                       = $OfficialOID
            AppPol                          = $OfficialOID
        }
    
        $IntendedPurpose = "Client Authentication"
        $OfficialName = "PKIX_KP_CLIENT_AUTH"
        $OfficialOID = $OIDHashTable.$OfficialName
        $szOIDString = "szOID_$OfficialName"
        $CertRequestConfigFileLine = "szOID_$OfficialName = `"$OfficialOID`""
        $ExtKeyUse = $AppPol = $OfficialOID
        
        [pscustomobject]@{
            IntendedPurpose                 = $IntendedPurpose
            OfficialName                    = $OfficialName
            OfficialOID                     = $OfficialOID
            szOIDString                     = $szOIDString
            CertRequestConfigFileLine       = $CertRequestConfigFileLine
            ExtKeyUse                       = $OfficialOID
            AppPol                          = $OfficialOID
        }
    
        $IntendedPurpose = "Private Key Archival"
        $OfficialName = "KP_CA_EXCHANGE"
        $OfficialOID = $OIDHashTable.$OfficialName
        $szOIDString = "szOID_$OfficialName"
        $CertRequestConfigFileLine = "szOID_$OfficialName = `"$OfficialOID`""
        $ExtKeyUse = $AppPol = $OfficialOID
        
        [pscustomobject]@{
            IntendedPurpose                 = $IntendedPurpose
            OfficialName                    = $OfficialName
            OfficialOID                     = $OfficialOID
            szOIDString                     = $szOIDString
            CertRequestConfigFileLine       = $CertRequestConfigFileLine
            ExtKeyUse                       = $OfficialOID
            AppPol                          = $OfficialOID
        }
    
        $IntendedPurpose = "Directory Service Email Replication"
        $OfficialName = "DS_EMAIL_REPLICATION"
        $OfficialOID = $OIDHashTable.$OfficialName
        $szOIDString = "szOID_$OfficialName"
        $CertRequestConfigFileLine = "szOID_$OfficialName = `"$OfficialOID`""
        $ExtKeyUse = $AppPol = $OfficialOID
        
        [pscustomobject]@{
            IntendedPurpose                 = $IntendedPurpose
            OfficialName                    = $OfficialName
            OfficialOID                     = $OfficialOID
            szOIDString                     = $szOIDString
            CertRequestConfigFileLine       = $CertRequestConfigFileLine
            ExtKeyUse                       = $OfficialOID
            AppPol                          = $OfficialOID
        }
    
        $IntendedPurpose = "Key Recovery Agent"
        $OfficialName = "KP_KEY_RECOVERY_AGENT"
        $OfficialOID = $OIDHashTable.$OfficialName
        $szOIDString = "szOID_$OfficialName"
        $CertRequestConfigFileLine = "szOID_$OfficialName = `"$OfficialOID`""
        $ExtKeyUse = $AppPol = $OfficialOID
        
        [pscustomobject]@{
            IntendedPurpose                 = $IntendedPurpose
            OfficialName                    = $OfficialName
            OfficialOID                     = $OfficialOID
            szOIDString                     = $szOIDString
            CertRequestConfigFileLine       = $CertRequestConfigFileLine
            ExtKeyUse                       = $OfficialOID
            AppPol                          = $OfficialOID
        }
    
        $IntendedPurpose = "OCSP Signing"
        $OfficialName = "KP_OCSP_SIGNING"
        $OfficialOID = $OIDHashTable.$OfficialName
        $szOIDString = "szOID_$OfficialName"
        $CertRequestConfigFileLine = "szOID_$OfficialName = `"$OfficialOID`""
        $ExtKeyUse = $AppPol = $OfficialOID
        
        [pscustomobject]@{
            IntendedPurpose                 = $IntendedPurpose
            OfficialName                    = $OfficialName
            OfficialOID                     = $OfficialOID
            szOIDString                     = $szOIDString
            CertRequestConfigFileLine       = $CertRequestConfigFileLine
            ExtKeyUse                       = $OfficialOID
            AppPol                          = $OfficialOID
        }
    
        $IntendedPurpose = "Server Authentication"
        $OfficialName = "PKIX_KP_SERVER_AUTH"
        $OfficialOID = $OIDHashTable.$OfficialName
        $szOIDString = "szOID_$OfficialName"
        $CertRequestConfigFileLine = "szOID_$OfficialName = `"$OfficialOID`""
        $ExtKeyUse = $AppPol = $OfficialOID
        
        [pscustomobject]@{
            IntendedPurpose                 = $IntendedPurpose
            OfficialName                    = $OfficialName
            OfficialOID                     = $OfficialOID
            szOIDString                     = $szOIDString
            CertRequestConfigFileLine       = $CertRequestConfigFileLine
            ExtKeyUse                       = $OfficialOID
            AppPol                          = $OfficialOID
        }
    
        ##### Below this point, Intended Purposes will be set but WILL NOT show up in the Certificate Templates Console under Intended Purpose column #####
        
        $IntendedPurpose = "EFS"
        $OfficialName = "KP_EFS"
        $OfficialOID = $OIDHashTable.$OfficialName
        $szOIDString = "szOID_$OfficialName"
        $CertRequestConfigFileLine = "szOID_$OfficialName = `"$OfficialOID`""
        $ExtKeyUse = $AppPol = $OfficialOID
        
        [pscustomobject]@{
            IntendedPurpose                 = $IntendedPurpose
            OfficialName                    = $OfficialName
            OfficialOID                     = $OfficialOID
            szOIDString                     = $szOIDString
            CertRequestConfigFileLine       = $CertRequestConfigFileLine
            ExtKeyUse                       = $OfficialOID
            AppPol                          = $OfficialOID
        }
    
        $IntendedPurpose = "Secure E-Mail"
        $OfficialName = "PKIX_KP_EMAIL_PROTECTION"
        $OfficialOID = $OIDHashTable.$OfficialName
        $szOIDString = "szOID_$OfficialName"
        $CertRequestConfigFileLine = "szOID_$OfficialName = `"$OfficialOID`""
        $ExtKeyUse = $AppPol = $OfficialOID
        
        [pscustomobject]@{
            IntendedPurpose                 = $IntendedPurpose
            OfficialName                    = $OfficialName
            OfficialOID                     = $OfficialOID
            szOIDString                     = $szOIDString
            CertRequestConfigFileLine       = $CertRequestConfigFileLine
            ExtKeyUse                       = $OfficialOID
            AppPol                          = $OfficialOID
        }
    
        $IntendedPurpose = "Enrollment Agent"
        $OfficialName = "ENROLLMENT_AGENT"
        $OfficialOID = $OIDHashTable.$OfficialName
        $szOIDString = "szOID_$OfficialName"
        $CertRequestConfigFileLine = "szOID_$OfficialName = `"$OfficialOID`""
        $ExtKeyUse = $AppPol = $OfficialOID
        
        [pscustomobject]@{
            IntendedPurpose                 = $IntendedPurpose
            OfficialName                    = $OfficialName
            OfficialOID                     = $OfficialOID
            szOIDString                     = $szOIDString
            CertRequestConfigFileLine       = $CertRequestConfigFileLine
            ExtKeyUse                       = $OfficialOID
            AppPol                          = $OfficialOID
        }
    
        $IntendedPurpose = "Microsoft Trust List Signing"
        $OfficialName = "KP_CTL_USAGE_SIGNING"
        $OfficialOID = $OIDHashTable.$OfficialName
        $szOIDString = "szOID_$OfficialName"
        $CertRequestConfigFileLine = "szOID_$OfficialName = `"$OfficialOID`""
        $ExtKeyUse = $AppPol = $OfficialOID
        
        [pscustomobject]@{
            IntendedPurpose                 = $IntendedPurpose
            OfficialName                    = $OfficialName
            OfficialOID                     = $OfficialOID
            szOIDString                     = $szOIDString
            CertRequestConfigFileLine       = $CertRequestConfigFileLine
            ExtKeyUse                       = $OfficialOID
            AppPol                          = $OfficialOID
        }
    
        $IntendedPurpose = "Smartcard Logon"
        $OfficialName = "IdMsKpScLogon"
        $OfficialOID = $OIDHashTable.$OfficialName
        $szOIDString = "szOID_$OfficialName"
        $CertRequestConfigFileLine = "szOID_$OfficialName = `"$OfficialOID`""
        $ExtKeyUse = $AppPol = $OfficialOID
        
        [pscustomobject]@{
            IntendedPurpose                 = $IntendedPurpose
            OfficialName                    = $OfficialName
            OfficialOID                     = $OfficialOID
            szOIDString                     = $szOIDString
            CertRequestConfigFileLine       = $CertRequestConfigFileLine
            ExtKeyUse                       = $OfficialOID
            AppPol                          = $OfficialOID
        }
    
        $IntendedPurpose = "File Recovery"
        $OfficialName = "EFS_RECOVERY"
        $OfficialOID = $OIDHashTable.$OfficialName
        $szOIDString = "szOID_$OfficialName"
        $CertRequestConfigFileLine = "szOID_$OfficialName = `"$OfficialOID`""
        $ExtKeyUse = $AppPol = $OfficialOID
        
        [pscustomobject]@{
            IntendedPurpose                 = $IntendedPurpose
            OfficialName                    = $OfficialName
            OfficialOID                     = $OfficialOID
            szOIDString                     = $szOIDString
            CertRequestConfigFileLine       = $CertRequestConfigFileLine
            ExtKeyUse                       = $OfficialOID
            AppPol                          = $OfficialOID
        }
    
        $IntendedPurpose = "IPSec IKE Intermediate"
        $OfficialName = "IPSEC_KP_IKE_INTERMEDIATE"
        $OfficialOID = $OIDHashTable.$OfficialName
        $szOIDString = "szOID_$OfficialName"
        $CertRequestConfigFileLine = "szOID_$OfficialName = `"$OfficialOID`""
        $ExtKeyUse = $AppPol = $OfficialOID
        
        [pscustomobject]@{
            IntendedPurpose                 = $IntendedPurpose
            OfficialName                    = $OfficialName
            OfficialOID                     = $OfficialOID
            szOIDString                     = $szOIDString
            CertRequestConfigFileLine       = $CertRequestConfigFileLine
            ExtKeyUse                       = $OfficialOID
            AppPol                          = $OfficialOID
        }
    
        $IntendedPurpose = "KDC Authentication"
        $OfficialName = "IdPkinitKPKdc"
        $OfficialOID = $OIDHashTable.$OfficialName
        $szOIDString = "szOID_$OfficialName"
        $CertRequestConfigFileLine = "szOID_$OfficialName = `"$OfficialOID`""
        $ExtKeyUse = $AppPol = $OfficialOID
        
        [pscustomobject]@{
            IntendedPurpose                 = $IntendedPurpose
            OfficialName                    = $OfficialName
            OfficialOID                     = $OfficialOID
            szOIDString                     = $szOIDString
            CertRequestConfigFileLine       = $CertRequestConfigFileLine
            ExtKeyUse                       = $OfficialOID
            AppPol                          = $OfficialOID
        }
    
        ##### Begin Newly Added #####
        $IntendedPurpose = "Remote Desktop"
        $OfficialName = "Remote Desktop"
        $OfficialOID = $OIDHashTable.$OfficialName
        $szOIDString = "szOID_$OfficialName"
        $CertRequestConfigFileLine = "szOID_$OfficialName = `"$OfficialOID`""
        $ExtKeyUse = $AppPol = $OfficialOID
        
        [pscustomobject]@{
            IntendedPurpose                 = $IntendedPurpose
            OfficialName                    = $OfficialName
            OfficialOID                     = $OfficialOID
            szOIDString                     = $szOIDString
            CertRequestConfigFileLine       = $CertRequestConfigFileLine
            ExtKeyUse                       = $OfficialOID
            AppPol                          = $OfficialOID
        }
    
        # Cannot be overridden in Certificate Request
        $IntendedPurpose = "Windows Update"
        $OfficialName = "Windows Update"
        $OfficialOID = $OIDHashTable.$OfficialName
        $szOIDString = "szOID_$OfficialName"
        $CertRequestConfigFileLine = "szOID_$OfficialName = `"$OfficialOID`""
        $ExtKeyUse = $AppPol = $OfficialOID
        
        [pscustomobject]@{
            IntendedPurpose                 = $IntendedPurpose
            OfficialName                    = $OfficialName
            OfficialOID                     = $OfficialOID
            szOIDString                     = $szOIDString
            CertRequestConfigFileLine       = $CertRequestConfigFileLine
            ExtKeyUse                       = $OfficialOID
            AppPol                          = $OfficialOID
        }
    
        $IntendedPurpose = "Windows Third Party Application Component"
        $OfficialName = "Windows Third Party Application Component"
        $OfficialOID = $OIDHashTable.$OfficialName
        $szOIDString = "szOID_$OfficialName"
        $CertRequestConfigFileLine = "szOID_$OfficialName = `"$OfficialOID`""
        $ExtKeyUse = $AppPol = $OfficialOID
        
        [pscustomobject]@{
            IntendedPurpose                 = $IntendedPurpose
            OfficialName                    = $OfficialName
            OfficialOID                     = $OfficialOID
            szOIDString                     = $szOIDString
            CertRequestConfigFileLine       = $CertRequestConfigFileLine
            ExtKeyUse                       = $OfficialOID
            AppPol                          = $OfficialOID
        }
    
        $IntendedPurpose = "Windows TCB Component"
        $OfficialName = "Windows TCB Component"
        $OfficialOID = $OIDHashTable.$OfficialName
        $szOIDString = "szOID_$OfficialName"
        $CertRequestConfigFileLine = "szOID_$OfficialName = `"$OfficialOID`""
        $ExtKeyUse = $AppPol = $OfficialOID
        
        [pscustomobject]@{
            IntendedPurpose                 = $IntendedPurpose
            OfficialName                    = $OfficialName
            OfficialOID                     = $OfficialOID
            szOIDString                     = $szOIDString
            CertRequestConfigFileLine       = $CertRequestConfigFileLine
            ExtKeyUse                       = $OfficialOID
            AppPol                          = $OfficialOID
        }
    
        $IntendedPurpose = "Windows Store"
        $OfficialName = "Windows Store"
        $OfficialOID = $OIDHashTable.$OfficialName
        $szOIDString = "szOID_$OfficialName"
        $CertRequestConfigFileLine = "szOID_$OfficialName = `"$OfficialOID`""
        $ExtKeyUse = $AppPol = $OfficialOID
        
        [pscustomobject]@{
            IntendedPurpose                 = $IntendedPurpose
            OfficialName                    = $OfficialName
            OfficialOID                     = $OfficialOID
            szOIDString                     = $szOIDString
            CertRequestConfigFileLine       = $CertRequestConfigFileLine
            ExtKeyUse                       = $OfficialOID
            AppPol                          = $OfficialOID
        }
    
        $IntendedPurpose = "Windows Software Extension Verification"
        $OfficialName = "Windows Software Extension Verification"
        $OfficialOID = $OIDHashTable.$OfficialName
        $szOIDString = "szOID_$OfficialName"
        $CertRequestConfigFileLine = "szOID_$OfficialName = `"$OfficialOID`""
        $ExtKeyUse = $AppPol = $OfficialOID
        
        [pscustomobject]@{
            IntendedPurpose                 = $IntendedPurpose
            OfficialName                    = $OfficialName
            OfficialOID                     = $OfficialOID
            szOIDString                     = $szOIDString
            CertRequestConfigFileLine       = $CertRequestConfigFileLine
            ExtKeyUse                       = $OfficialOID
            AppPol                          = $OfficialOID
        }
    
        $IntendedPurpose = "Windows RT Verification"
        $OfficialName = "Windows RT Verification"
        $OfficialOID = $OIDHashTable.$OfficialName
        $szOIDString = "szOID_$OfficialName"
        $CertRequestConfigFileLine = "szOID_$OfficialName = `"$OfficialOID`""
        $ExtKeyUse = $AppPol = $OfficialOID
        
        [pscustomobject]@{
            IntendedPurpose                 = $IntendedPurpose
            OfficialName                    = $OfficialName
            OfficialOID                     = $OfficialOID
            szOIDString                     = $szOIDString
            CertRequestConfigFileLine       = $CertRequestConfigFileLine
            ExtKeyUse                       = $OfficialOID
            AppPol                          = $OfficialOID
        }
    
        $IntendedPurpose = "Windows Kits Component"
        $OfficialName = "Windows Kits Component"
        $OfficialOID = $OIDHashTable.$OfficialName
        $szOIDString = "szOID_$OfficialName"
        $CertRequestConfigFileLine = "szOID_$OfficialName = `"$OfficialOID`""
        $ExtKeyUse = $AppPol = $OfficialOID
        
        [pscustomobject]@{
            IntendedPurpose                 = $IntendedPurpose
            OfficialName                    = $OfficialName
            OfficialOID                     = $OfficialOID
            szOIDString                     = $szOIDString
            CertRequestConfigFileLine       = $CertRequestConfigFileLine
            ExtKeyUse                       = $OfficialOID
            AppPol                          = $OfficialOID
        }
    
        $IntendedPurpose = "No OCSP Failover to CRL"
        $OfficialName = "No OCSP Failover to CRL"
        $OfficialOID = $OIDHashTable.$OfficialName
        $szOIDString = "szOID_$OfficialName"
        $CertRequestConfigFileLine = "szOID_$OfficialName = `"$OfficialOID`""
        $ExtKeyUse = $AppPol = $OfficialOID
        
        [pscustomobject]@{
            IntendedPurpose                 = $IntendedPurpose
            OfficialName                    = $OfficialName
            OfficialOID                     = $OfficialOID
            szOIDString                     = $szOIDString
            CertRequestConfigFileLine       = $CertRequestConfigFileLine
            ExtKeyUse                       = $OfficialOID
            AppPol                          = $OfficialOID
        }
    
        $IntendedPurpose = "Auto Update End Revocation"
        $OfficialName = "Auto Update End Revocation"
        $OfficialOID = $OIDHashTable.$OfficialName
        $szOIDString = "szOID_$OfficialName"
        $CertRequestConfigFileLine = "szOID_$OfficialName = `"$OfficialOID`""
        $ExtKeyUse = $AppPol = $OfficialOID
        
        [pscustomobject]@{
            IntendedPurpose                 = $IntendedPurpose
            OfficialName                    = $OfficialName
            OfficialOID                     = $OfficialOID
            szOIDString                     = $szOIDString
            CertRequestConfigFileLine       = $CertRequestConfigFileLine
            ExtKeyUse                       = $OfficialOID
            AppPol                          = $OfficialOID
        }
    
        $IntendedPurpose = "Auto Update CA Revocation"
        $OfficialName = "Auto Update CA Revocation"
        $OfficialOID = $OIDHashTable.$OfficialName
        $szOIDString = "szOID_$OfficialName"
        $CertRequestConfigFileLine = "szOID_$OfficialName = `"$OfficialOID`""
        $ExtKeyUse = $AppPol = $OfficialOID
        
        [pscustomobject]@{
            IntendedPurpose                 = $IntendedPurpose
            OfficialName                    = $OfficialName
            OfficialOID                     = $OfficialOID
            szOIDString                     = $szOIDString
            CertRequestConfigFileLine       = $CertRequestConfigFileLine
            ExtKeyUse                       = $OfficialOID
            AppPol                          = $OfficialOID
        }
    
        $IntendedPurpose = "Revoked List Signer"
        $OfficialName = "Revoked List Signer"
        $OfficialOID = $OIDHashTable.$OfficialName
        $szOIDString = "szOID_$OfficialName"
        $CertRequestConfigFileLine = "szOID_$OfficialName = `"$OfficialOID`""
        $ExtKeyUse = $AppPol = $OfficialOID
        
        [pscustomobject]@{
            IntendedPurpose                 = $IntendedPurpose
            OfficialName                    = $OfficialName
            OfficialOID                     = $OfficialOID
            szOIDString                     = $szOIDString
            CertRequestConfigFileLine       = $CertRequestConfigFileLine
            ExtKeyUse                       = $OfficialOID
            AppPol                          = $OfficialOID
        }
    
        $IntendedPurpose = "Protected Process Verification"
        $OfficialName = "Protected Process Verification"
        $OfficialOID = $OIDHashTable.$OfficialName
        $szOIDString = "szOID_$OfficialName"
        $CertRequestConfigFileLine = "szOID_$OfficialName = `"$OfficialOID`""
        $ExtKeyUse = $AppPol = $OfficialOID
        
        [pscustomobject]@{
            IntendedPurpose                 = $IntendedPurpose
            OfficialName                    = $OfficialName
            OfficialOID                     = $OfficialOID
            szOIDString                     = $szOIDString
            CertRequestConfigFileLine       = $CertRequestConfigFileLine
            ExtKeyUse                       = $OfficialOID
            AppPol                          = $OfficialOID
        }
    
        $IntendedPurpose = "Protected Process Light Verification"
        $OfficialName = "Protected Process Light Verification"
        $OfficialOID = $OIDHashTable.$OfficialName
        $szOIDString = "szOID_$OfficialName"
        $CertRequestConfigFileLine = "szOID_$OfficialName = `"$OfficialOID`""
        $ExtKeyUse = $AppPol = $OfficialOID
        
        [pscustomobject]@{
            IntendedPurpose                 = $IntendedPurpose
            OfficialName                    = $OfficialName
            OfficialOID                     = $OfficialOID
            szOIDString                     = $szOIDString
            CertRequestConfigFileLine       = $CertRequestConfigFileLine
            ExtKeyUse                       = $OfficialOID
            AppPol                          = $OfficialOID
        }
    
        $IntendedPurpose = "Platform Certificate"
        $OfficialName = "Platform Certificate"
        $OfficialOID = $OIDHashTable.$OfficialName
        $szOIDString = "szOID_$OfficialName"
        $CertRequestConfigFileLine = "szOID_$OfficialName = `"$OfficialOID`""
        $ExtKeyUse = $AppPol = $OfficialOID
        
        [pscustomobject]@{
            IntendedPurpose                 = $IntendedPurpose
            OfficialName                    = $OfficialName
            OfficialOID                     = $OfficialOID
            szOIDString                     = $szOIDString
            CertRequestConfigFileLine       = $CertRequestConfigFileLine
            ExtKeyUse                       = $OfficialOID
            AppPol                          = $OfficialOID
        }
    
        $IntendedPurpose = "Microsoft Publisher"
        $OfficialName = "Microsoft Publisher"
        $OfficialOID = $OIDHashTable.$OfficialName
        $szOIDString = "szOID_$OfficialName"
        $CertRequestConfigFileLine = "szOID_$OfficialName = `"$OfficialOID`""
        $ExtKeyUse = $AppPol = $OfficialOID
        
        [pscustomobject]@{
            IntendedPurpose                 = $IntendedPurpose
            OfficialName                    = $OfficialName
            OfficialOID                     = $OfficialOID
            szOIDString                     = $szOIDString
            CertRequestConfigFileLine       = $CertRequestConfigFileLine
            ExtKeyUse                       = $OfficialOID
            AppPol                          = $OfficialOID
        }
    
        $IntendedPurpose = "Kernel Mode Code Signing"
        $OfficialName = "Kernel Mode Code Signing"
        $OfficialOID = $OIDHashTable.$OfficialName
        $szOIDString = "szOID_$OfficialName"
        $CertRequestConfigFileLine = "szOID_$OfficialName = `"$OfficialOID`""
        $ExtKeyUse = $AppPol = $OfficialOID
        
        [pscustomobject]@{
            IntendedPurpose                 = $IntendedPurpose
            OfficialName                    = $OfficialName
            OfficialOID                     = $OfficialOID
            szOIDString                     = $szOIDString
            CertRequestConfigFileLine       = $CertRequestConfigFileLine
            ExtKeyUse                       = $OfficialOID
            AppPol                          = $OfficialOID
        }
    
        $IntendedPurpose = "HAL Extension"
        $OfficialName = "HAL Extension"
        $OfficialOID = $OIDHashTable.$OfficialName
        $szOIDString = "szOID_$OfficialName"
        $CertRequestConfigFileLine = "szOID_$OfficialName = `"$OfficialOID`""
        $ExtKeyUse = $AppPol = $OfficialOID
        
        [pscustomobject]@{
            IntendedPurpose                 = $IntendedPurpose
            OfficialName                    = $OfficialName
            OfficialOID                     = $OfficialOID
            szOIDString                     = $szOIDString
            CertRequestConfigFileLine       = $CertRequestConfigFileLine
            ExtKeyUse                       = $OfficialOID
            AppPol                          = $OfficialOID
        }
    
        $IntendedPurpose = "Endorsement Key Certificate"
        $OfficialName = "Endorsement Key Certificate"
        $OfficialOID = $OIDHashTable.$OfficialName
        $szOIDString = "szOID_$OfficialName"
        $CertRequestConfigFileLine = "szOID_$OfficialName = `"$OfficialOID`""
        $ExtKeyUse = $AppPol = $OfficialOID
        
        [pscustomobject]@{
            IntendedPurpose                 = $IntendedPurpose
            OfficialName                    = $OfficialName
            OfficialOID                     = $OfficialOID
            szOIDString                     = $szOIDString
            CertRequestConfigFileLine       = $CertRequestConfigFileLine
            ExtKeyUse                       = $OfficialOID
            AppPol                          = $OfficialOID
        }
    
        $IntendedPurpose = "Early Launch Antimalware Driver"
        $OfficialName = "Early Launch Antimalware Driver"
        $OfficialOID = $OIDHashTable.$OfficialName
        $szOIDString = "szOID_$OfficialName"
        $CertRequestConfigFileLine = "szOID_$OfficialName = `"$OfficialOID`""
        $ExtKeyUse = $AppPol = $OfficialOID
        
        [pscustomobject]@{
            IntendedPurpose                 = $IntendedPurpose
            OfficialName                    = $OfficialName
            OfficialOID                     = $OfficialOID
            szOIDString                     = $szOIDString
            CertRequestConfigFileLine       = $CertRequestConfigFileLine
            ExtKeyUse                       = $OfficialOID
            AppPol                          = $OfficialOID
        }
    
        $IntendedPurpose = "Dynamic Code Generator"
        $OfficialName = "Dynamic Code Generator"
        $OfficialOID = $OIDHashTable.$OfficialName
        $szOIDString = "szOID_$OfficialName"
        $CertRequestConfigFileLine = "szOID_$OfficialName = `"$OfficialOID`""
        $ExtKeyUse = $AppPol = $OfficialOID
        
        [pscustomobject]@{
            IntendedPurpose                 = $IntendedPurpose
            OfficialName                    = $OfficialName
            OfficialOID                     = $OfficialOID
            szOIDString                     = $szOIDString
            CertRequestConfigFileLine       = $CertRequestConfigFileLine
            ExtKeyUse                       = $OfficialOID
            AppPol                          = $OfficialOID
        }
    
        $IntendedPurpose = "DNS Server Trust"
        $OfficialName = "DNS Server Trust"
        $OfficialOID = $OIDHashTable.$OfficialName
        $szOIDString = "szOID_$OfficialName"
        $CertRequestConfigFileLine = "szOID_$OfficialName = `"$OfficialOID`""
        $ExtKeyUse = $AppPol = $OfficialOID
        
        [pscustomobject]@{
            IntendedPurpose                 = $IntendedPurpose
            OfficialName                    = $OfficialName
            OfficialOID                     = $OfficialOID
            szOIDString                     = $szOIDString
            CertRequestConfigFileLine       = $CertRequestConfigFileLine
            ExtKeyUse                       = $OfficialOID
            AppPol                          = $OfficialOID
        }
    
        $IntendedPurpose = "Document Encryption"
        $OfficialName = "Document Encryption"
        $OfficialOID = $OIDHashTable.$OfficialName
        $szOIDString = "szOID_$OfficialName"
        $CertRequestConfigFileLine = "szOID_$OfficialName = `"$OfficialOID`""
        $ExtKeyUse = $AppPol = $OfficialOID
        
        [pscustomobject]@{
            IntendedPurpose                 = $IntendedPurpose
            OfficialName                    = $OfficialName
            OfficialOID                     = $OfficialOID
            szOIDString                     = $szOIDString
            CertRequestConfigFileLine       = $CertRequestConfigFileLine
            ExtKeyUse                       = $OfficialOID
            AppPol                          = $OfficialOID
        }
    
        $IntendedPurpose = "Disallowed List"
        $OfficialName = "Disallowed List"
        $OfficialOID = $OIDHashTable.$OfficialName
        $szOIDString = "szOID_$OfficialName"
        $CertRequestConfigFileLine = "szOID_$OfficialName = `"$OfficialOID`""
        $ExtKeyUse = $AppPol = $OfficialOID
        
        [pscustomobject]@{
            IntendedPurpose                 = $IntendedPurpose
            OfficialName                    = $OfficialName
            OfficialOID                     = $OfficialOID
            szOIDString                     = $szOIDString
            CertRequestConfigFileLine       = $CertRequestConfigFileLine
            ExtKeyUse                       = $OfficialOID
            AppPol                          = $OfficialOID
        }
    
        $IntendedPurpose = "Attestation Identity Key Certificate"
        $OfficialName = "Attestation Identity Key Certificate"
        $OfficialOID = $OIDHashTable.$OfficialName
        $szOIDString = "szOID_$OfficialName"
        $CertRequestConfigFileLine = "szOID_$OfficialName = `"$OfficialOID`""
        $ExtKeyUse = $AppPol = $OfficialOID
        
        [pscustomobject]@{
            IntendedPurpose                 = $IntendedPurpose
            OfficialName                    = $OfficialName
            OfficialOID                     = $OfficialOID
            szOIDString                     = $szOIDString
            CertRequestConfigFileLine       = $CertRequestConfigFileLine
            ExtKeyUse                       = $OfficialOID
            AppPol                          = $OfficialOID
        }
    
        $IntendedPurpose = "System Health Authentication"
        $OfficialName = "System Health Authentication"
        $OfficialOID = $OIDHashTable.$OfficialName
        $szOIDString = "szOID_$OfficialName"
        $CertRequestConfigFileLine = "szOID_$OfficialName = `"$OfficialOID`""
        $ExtKeyUse = $AppPol = $OfficialOID
        
        [pscustomobject]@{
            IntendedPurpose                 = $IntendedPurpose
            OfficialName                    = $OfficialName
            OfficialOID                     = $OfficialOID
            szOIDString                     = $szOIDString
            CertRequestConfigFileLine       = $CertRequestConfigFileLine
            ExtKeyUse                       = $OfficialOID
            AppPol                          = $OfficialOID
        }
    
        $IntendedPurpose = "CTL Usage"
        $OfficialName = "AUTO_ENROLL_CTL_USAGE"
        $OfficialOID = $OIDHashTable.$OfficialName
        $szOIDString = "szOID_$OfficialName"
        $CertRequestConfigFileLine = "szOID_$OfficialName = `"$OfficialOID`""
        $ExtKeyUse = $AppPol = $OfficialOID
        
        [pscustomobject]@{
            IntendedPurpose                 = $IntendedPurpose
            OfficialName                    = $OfficialName
            OfficialOID                     = $OfficialOID
            szOIDString                     = $szOIDString
            CertRequestConfigFileLine       = $CertRequestConfigFileLine
            ExtKeyUse                       = $OfficialOID
            AppPol                          = $OfficialOID
        }
    
        $IntendedPurpose = "IP Security End System"
        $OfficialName = "PKIX_KP_IPSEC_END_SYSTEM"
        $OfficialOID = $OIDHashTable.$OfficialName
        $szOIDString = "szOID_$OfficialName"
        $CertRequestConfigFileLine = "szOID_$OfficialName = `"$OfficialOID`""
        $ExtKeyUse = $AppPol = $OfficialOID
        
        [pscustomobject]@{
            IntendedPurpose                 = $IntendedPurpose
            OfficialName                    = $OfficialName
            OfficialOID                     = $OfficialOID
            szOIDString                     = $szOIDString
            CertRequestConfigFileLine       = $CertRequestConfigFileLine
            ExtKeyUse                       = $OfficialOID
            AppPol                          = $OfficialOID
        }
    
        $IntendedPurpose = "IP Security Tunnel Termination"
        $OfficialName = "PKIX_KP_IPSEC_TUNNEL"
        $OfficialOID = $OIDHashTable.$OfficialName
        $szOIDString = "szOID_$OfficialName"
        $CertRequestConfigFileLine = "szOID_$OfficialName = `"$OfficialOID`""
        $ExtKeyUse = $AppPol = $OfficialOID
        
        [pscustomobject]@{
            IntendedPurpose                 = $IntendedPurpose
            OfficialName                    = $OfficialName
            OfficialOID                     = $OfficialOID
            szOIDString                     = $szOIDString
            CertRequestConfigFileLine       = $CertRequestConfigFileLine
            ExtKeyUse                       = $OfficialOID
            AppPol                          = $OfficialOID
        }
    
        $IntendedPurpose = "IP Security User"
        $OfficialName = "PKIX_KP_IPSEC_USER"
        $OfficialOID = $OIDHashTable.$OfficialName
        $szOIDString = "szOID_$OfficialName"
        $CertRequestConfigFileLine = "szOID_$OfficialName = `"$OfficialOID`""
        $ExtKeyUse = $AppPol = $OfficialOID
        
        [pscustomobject]@{
            IntendedPurpose                 = $IntendedPurpose
            OfficialName                    = $OfficialName
            OfficialOID                     = $OfficialOID
            szOIDString                     = $szOIDString
            CertRequestConfigFileLine       = $CertRequestConfigFileLine
            ExtKeyUse                       = $OfficialOID
            AppPol                          = $OfficialOID
        }
    
        $IntendedPurpose = "Time Stamping"
        $OfficialName = "PKIX_KP_TIMESTAMP_SIGNING"
        $OfficialOID = $OIDHashTable.$OfficialName
        $szOIDString = "szOID_$OfficialName"
        $CertRequestConfigFileLine = "szOID_$OfficialName = `"$OfficialOID`""
        $ExtKeyUse = $AppPol = $OfficialOID
        
        [pscustomobject]@{
            IntendedPurpose                 = $IntendedPurpose
            OfficialName                    = $OfficialName
            OfficialOID                     = $OfficialOID
            szOIDString                     = $szOIDString
            CertRequestConfigFileLine       = $CertRequestConfigFileLine
            ExtKeyUse                       = $OfficialOID
            AppPol                          = $OfficialOID
        }
    
        $IntendedPurpose = "Microsoft Time Stamping"
        $OfficialName = "KP_TIME_STAMP_SIGNING"
        $OfficialOID = $OIDHashTable.$OfficialName
        $szOIDString = "szOID_$OfficialName"
        $CertRequestConfigFileLine = "szOID_$OfficialName = `"$OfficialOID`""
        $ExtKeyUse = $AppPol = $OfficialOID
        
        [pscustomobject]@{
            IntendedPurpose                 = $IntendedPurpose
            OfficialName                    = $OfficialName
            OfficialOID                     = $OfficialOID
            szOIDString                     = $szOIDString
            CertRequestConfigFileLine       = $CertRequestConfigFileLine
            ExtKeyUse                       = $OfficialOID
            AppPol                          = $OfficialOID
        }
    
        $IntendedPurpose = "Windows Hardware Driver Verification"
        $OfficialName = "WHQL_CRYPTO"
        $OfficialOID = $OIDHashTable.$OfficialName
        $szOIDString = "szOID_$OfficialName"
        $CertRequestConfigFileLine = "szOID_$OfficialName = `"$OfficialOID`""
        $ExtKeyUse = $AppPol = $OfficialOID
        
        [pscustomobject]@{
            IntendedPurpose                 = $IntendedPurpose
            OfficialName                    = $OfficialName
            OfficialOID                     = $OfficialOID
            szOIDString                     = $szOIDString
            CertRequestConfigFileLine       = $CertRequestConfigFileLine
            ExtKeyUse                       = $OfficialOID
            AppPol                          = $OfficialOID
        }
    
        $IntendedPurpose = "Windows System Component Verification"
        $OfficialName = "NT5_CRYPTO"
        $OfficialOID = $OIDHashTable.$OfficialName
        $szOIDString = "szOID_$OfficialName"
        $CertRequestConfigFileLine = "szOID_$OfficialName = `"$OfficialOID`""
        $ExtKeyUse = $AppPol = $OfficialOID
        
        [pscustomobject]@{
            IntendedPurpose                 = $IntendedPurpose
            OfficialName                    = $OfficialName
            OfficialOID                     = $OfficialOID
            szOIDString                     = $szOIDString
            CertRequestConfigFileLine       = $CertRequestConfigFileLine
            ExtKeyUse                       = $OfficialOID
            AppPol                          = $OfficialOID
        }
    
        $IntendedPurpose = "OEM Windows System Component Verification"
        $OfficialName = "OEM_WHQL_CRYPTO"
        $OfficialOID = $OIDHashTable.$OfficialName
        $szOIDString = "szOID_$OfficialName"
        $CertRequestConfigFileLine = "szOID_$OfficialName = `"$OfficialOID`""
        $ExtKeyUse = $AppPol = $OfficialOID
        
        [pscustomobject]@{
            IntendedPurpose                 = $IntendedPurpose
            OfficialName                    = $OfficialName
            OfficialOID                     = $OfficialOID
            szOIDString                     = $szOIDString
            CertRequestConfigFileLine       = $CertRequestConfigFileLine
            ExtKeyUse                       = $OfficialOID
            AppPol                          = $OfficialOID
        }
    
        $IntendedPurpose = "Embedded Windows System Component Verification"
        $OfficialName = "EMBEDDED_NT_CRYPTO"
        $OfficialOID = $OIDHashTable.$OfficialName
        $szOIDString = "szOID_$OfficialName"
        $CertRequestConfigFileLine = "szOID_$OfficialName = `"$OfficialOID`""
        $ExtKeyUse = $AppPol = $OfficialOID
        
        [pscustomobject]@{
            IntendedPurpose                 = $IntendedPurpose
            OfficialName                    = $OfficialName
            OfficialOID                     = $OfficialOID
            szOIDString                     = $szOIDString
            CertRequestConfigFileLine       = $CertRequestConfigFileLine
            ExtKeyUse                       = $OfficialOID
            AppPol                          = $OfficialOID
        }
    
        $IntendedPurpose = "Root List Signer"
        $OfficialName = "ROOT_LIST_SIGNER"
        $OfficialOID = $OIDHashTable.$OfficialName
        $szOIDString = "szOID_$OfficialName"
        $CertRequestConfigFileLine = "szOID_$OfficialName = `"$OfficialOID`""
        $ExtKeyUse = $AppPol = $OfficialOID
        
        [pscustomobject]@{
            IntendedPurpose                 = $IntendedPurpose
            OfficialName                    = $OfficialName
            OfficialOID                     = $OfficialOID
            szOIDString                     = $szOIDString
            CertRequestConfigFileLine       = $CertRequestConfigFileLine
            ExtKeyUse                       = $OfficialOID
            AppPol                          = $OfficialOID
        }
    
        $IntendedPurpose = "Qualified Subordination"
        $OfficialName = "KP_QUALIFIED_SUBORDINATION"
        $OfficialOID = $OIDHashTable.$OfficialName
        $szOIDString = "szOID_$OfficialName"
        $CertRequestConfigFileLine = "szOID_$OfficialName = `"$OfficialOID`""
        $ExtKeyUse = $AppPol = $OfficialOID
        
        [pscustomobject]@{
            IntendedPurpose                 = $IntendedPurpose
            OfficialName                    = $OfficialName
            OfficialOID                     = $OfficialOID
            szOIDString                     = $szOIDString
            CertRequestConfigFileLine       = $CertRequestConfigFileLine
            ExtKeyUse                       = $OfficialOID
            AppPol                          = $OfficialOID
        }
    
        $IntendedPurpose = "Key Recovery"
        $OfficialName = "KP_KEY_RECOVERY"
        $OfficialOID = $OIDHashTable.$OfficialName
        $szOIDString = "szOID_$OfficialName"
        $CertRequestConfigFileLine = "szOID_$OfficialName = `"$OfficialOID`""
        $ExtKeyUse = $AppPol = $OfficialOID
        
        [pscustomobject]@{
            IntendedPurpose                 = $IntendedPurpose
            OfficialName                    = $OfficialName
            OfficialOID                     = $OfficialOID
            szOIDString                     = $szOIDString
            CertRequestConfigFileLine       = $CertRequestConfigFileLine
            ExtKeyUse                       = $OfficialOID
            AppPol                          = $OfficialOID
        }
    
        $IntendedPurpose = "Lifetime Signing"
        $OfficialName = "KP_LIFETIME_SIGNING"
        $OfficialOID = $OIDHashTable.$OfficialName
        $szOIDString = "szOID_$OfficialName"
        $CertRequestConfigFileLine = "szOID_$OfficialName = `"$OfficialOID`""
        $ExtKeyUse = $AppPol = $OfficialOID
        
        [pscustomobject]@{
            IntendedPurpose                 = $IntendedPurpose
            OfficialName                    = $OfficialName
            OfficialOID                     = $OfficialOID
            szOIDString                     = $szOIDString
            CertRequestConfigFileLine       = $CertRequestConfigFileLine
            ExtKeyUse                       = $OfficialOID
            AppPol                          = $OfficialOID
        }
    
        $IntendedPurpose = "Key Pack Licenses"
        $OfficialName = "LICENSES"
        $OfficialOID = $OIDHashTable.$OfficialName
        $szOIDString = "szOID_$OfficialName"
        $CertRequestConfigFileLine = "szOID_$OfficialName = `"$OfficialOID`""
        $ExtKeyUse = $AppPol = $OfficialOID
        
        [pscustomobject]@{
            IntendedPurpose                 = $IntendedPurpose
            OfficialName                    = $OfficialName
            OfficialOID                     = $OfficialOID
            szOIDString                     = $szOIDString
            CertRequestConfigFileLine       = $CertRequestConfigFileLine
            ExtKeyUse                       = $OfficialOID
            AppPol                          = $OfficialOID
        }
    
        $IntendedPurpose = "License Server Verification"
        $OfficialName = "LICENSE_SERVER"
        $OfficialOID = $OIDHashTable.$OfficialName
        $szOIDString = "szOID_$OfficialName"
        $CertRequestConfigFileLine = "szOID_$OfficialName = `"$OfficialOID`""
        $ExtKeyUse = $AppPol = $OfficialOID
        
        [pscustomobject]@{
            IntendedPurpose                 = $IntendedPurpose
            OfficialName                    = $OfficialName
            OfficialOID                     = $OfficialOID
            szOIDString                     = $szOIDString
            CertRequestConfigFileLine       = $CertRequestConfigFileLine
            ExtKeyUse                       = $OfficialOID
            AppPol                          = $OfficialOID
        }
    }

    function New-UniqueString {
        [CmdletBinding()]
        Param(
            [Parameter(Mandatory=$False)]
            [string[]]$ArrayOfStrings,

            [Parameter(Mandatory=$True)]
            [string]$PossibleNewUniqueString
        )

        if (!$ArrayOfStrings -or $ArrayOfStrings.Count -eq 0 -or ![bool]$($ArrayOfStrings -match "[\w]")) {
            $PossibleNewUniqueString
        }
        else {
            $OriginalString = $PossibleNewUniqueString
            $Iteration = 1
            while ($ArrayOfStrings -contains $PossibleNewUniqueString) {
                $AppendedValue = "_$Iteration"
                $PossibleNewUniqueString = $OriginalString + $AppendedValue
                $Iteration++
            }

            $PossibleNewUniqueString
        }
    }

    function Install-RSAT {
        [CmdletBinding()]
        Param(
            [Parameter(Mandatory=$False)]
            [string]$DownloadDirectory = "$HOME\Downloads",

            [Parameter(Mandatory=$False)]
            [switch]$AllowRestart
        )

        Write-Host "Please wait..."

        if (!$(Get-Module -ListAvailable -Name ActiveDirectory)) {
            $OSInfo = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
            $OSCimInfo = Get-CimInstance Win32_OperatingSystem
            $OSArchitecture = $OSCimInfo.OSArchitecture

            if ([version]$OSCimInfo.Version -lt [version]"6.3") {
                Write-Error "This function only handles RSAT Installation for Windows 8.1 and higher! Halting!"
                $global:FunctionResult = "1"
                return
            }
            
            if ($OSInfo.ProductName -notlike "*Server*") {
                if (![bool]$(Get-WmiObject -query 'select * from win32_quickfixengineering' | Where-Object {$_.HotFixID -eq 'KB958830' -or $_.HotFixID -eq 'KB2693643'})) {
                    if ($([version]$OSCimInfo.Version).Major -lt 10 -and [version]$OSCimInfo.Version -ge [version]"6.3") {
                        if ($OSArchitecture -eq "64-bit") {
                            $OutFileName = "Windows8.1-KB2693643-x64.msu"
                        }
                        if ($OSArchitecture -eq "32-bit") {
                            $OutFileName = "Windows8.1-KB2693643-x86.msu"
                        }

                        $DownloadUrl = "https://download.microsoft.com/download/1/8/E/18EA4843-C596-4542-9236-DE46F780806E/$OutFileName"
                    }
                    if ($([version]$OSCimInfo.Version).Major -ge 10) {
                        if ([int]$OSInfo.ReleaseId -ge 1709) {
                            if ($OSArchitecture -eq "64-bit") {
                                $OutFileName = "WindowsTH-RSAT_WS_1709-x64.msu"
                            }
                            if ($OSArchitecture -eq "32-bit") {
                                $OutFileName = "WindowsTH-RSAT_WS_1709-x86.msu"
                            }
                        }
                        if ([int]$OSInfo.ReleaseId -lt 1709) {
                            if ($OSArchitecture -eq "64-bit") {
                                $OutFileName = "WindowsTH-RSAT_WS2016-x64.msu"
                            }
                            if ($OSArchitecture -eq "32-bit") {
                                $OutFileName = "WindowsTH-RSAT_WS2016-x86.msu"
                            }
                        }

                        $DownloadUrl = "https://download.microsoft.com/download/1/D/8/1D8B5022-5477-4B9A-8104-6A71FF9D98AB/$OutFileName"
                    }

                    try {
                        # Make sure the Url exists...
                        $HTTP_Request = [System.Net.WebRequest]::Create($DownloadUrl)
                        $HTTP_Response = $HTTP_Request.GetResponse()
                    }
                    catch {
                        Write-Error $_
                        $global:FunctionResult = "1"
                        return
                    }

                    try {
                        # Download via System.Net.WebClient is a lot faster than Invoke-WebRequest...
                        $WebClient = [System.Net.WebClient]::new()
                        $WebClient.Downloadfile($DownloadUrl, "$DownloadDirectory\$OutFileName")
                    }
                    catch {
                        Write-Error $_
                        $global:FunctionResult = "1"
                        return
                    }

                    Write-Host "Beginning installation..."
                    if ($AllowRestart) {
                        $Arguments = "`"$DownloadDirectory\$OutFileName`" /quiet /log:`"$DownloadDirectory\wusaRSATInstall.log`""
                    }
                    else {
                        $Arguments = "`"$DownloadDirectory\$OutFileName`" /quiet /norestart /log:`"$DownloadDirectory\wusaRSATInstall.log`""
                    }
                    #Start-Process -FilePath $(Get-Command wusa.exe).Source -ArgumentList "`"$DownloadDirectory\$OutFileName`" /quiet /log:`"$DownloadDirectory\wusaRSATInstall.log`"" -NoNewWindow -Wait

                    $ProcessInfo = New-Object System.Diagnostics.ProcessStartInfo
                    #$ProcessInfo.WorkingDirectory = $BinaryPath | Split-Path -Parent
                    $ProcessInfo.FileName = $(Get-Command wusa.exe).Source
                    $ProcessInfo.RedirectStandardError = $true
                    $ProcessInfo.RedirectStandardOutput = $true
                    #$ProcessInfo.StandardOutputEncoding = [System.Text.Encoding]::Unicode
                    #$ProcessInfo.StandardErrorEncoding = [System.Text.Encoding]::Unicode
                    $ProcessInfo.UseShellExecute = $false
                    $ProcessInfo.Arguments = $Arguments
                    $Process = New-Object System.Diagnostics.Process
                    $Process.StartInfo = $ProcessInfo
                    $Process.Start() | Out-Null
                    # Below $FinishedInAlottedTime returns boolean true/false
                    # Wait 20 seconds for wusa to finish...
                    $FinishedInAlottedTime = $Process.WaitForExit(20000)
                    if (!$FinishedInAlottedTime) {
                        $Process.Kill()
                    }
                    $stdout = $Process.StandardOutput.ReadToEnd()
                    $stderr = $Process.StandardError.ReadToEnd()
                    $AllOutput = $stdout + $stderr

                    # Check the log to make sure there weren't any errors
                    # NOTE: Get-WinEvent cmdlet does NOT work consistently on all Windows Operating Systems...
                    Write-Host "Reviewing wusa.exe logs..."
                    $EventLogReader = [System.Diagnostics.Eventing.Reader.EventLogReader]::new("$DownloadDirectory\wusaRSATInstall.log", [System.Diagnostics.Eventing.Reader.PathType]::FilePath)
                    [System.Collections.ArrayList]$EventsFromLog = @()
                    
                    $Event = $EventLogReader.ReadEvent()
                    $null = $EventsFromLog.Add($Event)
                    while ($Event -ne $null) {
                        $Event = $EventLogReader.ReadEvent()
                        $null = $EventsFromLog.Add($Event)
                    }

                    if ($EventsFromLog.LevelDisplayName -contains "Error") {
                        $ErrorRecord = $EventsFromLog | Where-Object {$_.LevelDisplayName -eq "Error"}
                        $ProblemDetails = $ErrorRecord.Properties.Value | Where-Object {$_ -match "[\w]"}
                        $ProblemDetailsString = $ProblemDetails[0..$($ProblemDetails.Count-2)] -join ": "

                        $ErrMsg = "wusa.exe failed to install '$DownloadDirectory\$OutFileName' due to '$ProblemDetailsString'. " +
                        "This could be because of a pending restart. Please restart $env:ComputerName and try the Install-RSAT function again."
                        Write-Error $ErrMsg
                        $global:FunctionResult = "1"
                        return
                    }

                    if ($AllowRestart) {
                        Restart-Computer -Confirm:$false -Force
                    }
                    else{
                        $Output = "RestartNeeded"
                    }
                }
            }
            if ($OSInfo.ProductName -like "*Server*") {
                Import-Module ServerManager
                if (!$(Get-WindowsFeature RSAT).Installed) {
                    Write-Host "Beginning installation..."
                    if ($AllowRestart) {
                        Install-WindowsFeature -Name RSAT -IncludeAllSubFeature -IncludeManagementTools -Restart
                    }
                    else {
                        Install-WindowsFeature -Name RSAT -IncludeAllSubFeature -IncludeManagementTools
                        $Output = "RestartNeeded"
                    }
                }
            }
        }
        else {
            Write-Warning "RSAT is already installed! No action taken."
        }

        if ($Output -eq "RestartNeeded") {
            Write-Warning "You must restart your computer in order to finish RSAT installation."
        }

        $Output
    }

    ##### END Helper Functions #####

    ##### BEGIN Initial Variable Definition and Validation #####

    # Make a working Directory Where Generated Certificates will be Saved
    if (Test-Path $CertGenWorking) {
        $NewDirName = New-UniqueString -PossibleNewUniqueString $($CertGenWorking | Split-Path -Leaf) -ArrayOfStrings $(Get-ChildItem -Path $($CertGenWorking | Split-Path -Parent) -Directory).Name
        $CertGenWorking = "$CertGenWorking`_Certs_$(Get-Date -Format MMddyy_hhmmss)"
    }
    if (!$(Test-Path $CertGenWorking)) {
        $null = New-Item -ItemType Directory -Path $CertGenWorking
    }

    # Check Cert:\CurrentUser\My for a Certificate with the same CN as our intended new Certificate.
    [array]$ExistingCertInStore = Get-ChildItem Cert:\CurrentUser\My | Where-Object {$_.Subject -match "CN=$CertificateCN,"}
    if ($ExistingCertInStore.Count -gt 0) {
        Write-Warning "There is already a Certificate in your Certificate Store under 'Cert:\CurrentUser\My' with Common Name (CN) $CertificateCN!"

        $ContinuePrompt = Read-Host -Prompt "Are you sure you want to continue? [Yes\No]"
        while ($ContinuePrompt -notmatch "Yes|yes|Y|y|No|no|N|n") {
            Write-Host "$ContinuePrompt is not a valid option. Please enter 'Yes' or 'No'"
            $ContinuePrompt = Read-Host -Prompt "Are you sure you want to continue? [Yes\No]"
        }

        if ($ContinuePrompt -match "Yes|yes|Y|y") {
            $ThumprintToAvoid = $ExistingCertInStore.Thumbprint
        }
        else {
            Write-Error "User chose not proceed due to existing Certificate concerns. Halting!"
            $global:FunctionResult = "1"
            return
        }
        
    }

    if (!$PSBoundParameters['BasisTemplate'] -and !$PSBoundParameters['IntendedPurposeValues']) {
        $BasisTemplate = "WebServer"
    } 
    
    if ($PSBoundParameters['BasisTemplate'] -and $PSBoundParameters['IntendedPurposeValues']) {
        Write-Error "The $($MyInvocation.MyCommand.Name) function must use either the -BasisTemplate parameter or the -IntendedPurposeValues parameter! Halting!"
        $global:FunctionResult = "1"
        return
    }

    if (!$MachineKeySet) {
        $MachineKeySetPrompt = "If you would like the private key exported, please enter 'False'. If you are " +
        "creating this certificate to be used in the User's security context (like for a developer to sign their code)," +
        "enter 'False'. If you are using this certificate for a service that runs in the Computer's security context " +
        "(such as a Web Server, Domain Controller, etc) enter 'True' [TRUE/FALSE]"
        $MachineKeySet = Read-Host -Prompt $MachineKeySetPrompt
        while ($MachineKeySet -notmatch "True|False") {
            Write-Host "$MachineKeySet is not a valid option. Please enter either 'True' or 'False'" -ForeGroundColor Yellow
            $MachineKeySet = Read-Host -Prompt $MachineKeySetPrompt
        }
    }
    $MachineKeySet = $MachineKeySet.ToUpper()
    $PrivateKeyExportableValue = $PrivateKeyExportableValue.ToUpper()
    $KeyUsageValueUpdated = "0x" + $KeyUsageValue

    if (!$SecureEmail) {
        $SecureEmail = Read-Host -Prompt "Are you using this new certificate for Secure E-Mail? [Yes/No]"
        while ($SecureEmail -notmatch "Yes|No") {
            Write-Host "$SecureEmail is not a vaild option. Please enter either 'Yes' or 'No'" -ForeGroundColor Yellow
            $SecureEmail = Read-Host -Prompt "Are you using this new certificate for Secure E-Mail? [Yes/No]"
        }
    }
    if ($SecureEmail -eq "Yes") {
        $KeySpecValue = "2"
        $SMIMEValue = "TRUE"
    }
    else {
        $KeySpecValue = "1"
        $SMIMEValue = "FALSE"
    }

    if (!$UserProtected) {
        $UserProtected = Read-Host -Prompt "Would you like to password protect the keys on this certificate? [True/False]"
        while ($UserProtected -notmatch "True|False") {
            Write-Host "$UserProtected is not a valid option. Please enter either 'True' or 'False'"
            $UserProtected = Read-Host -Prompt "Would you like to password protect the keys on this certificate? [True/False]"
        }
    }
    if ($UserProtected -eq "True") {
        $MachineKeySet = "FALSE"
    }
    $UserProtected = $UserProtected.ToUpper()

    if (!$UseOpenSSL) {
        $UseOpenSSL = Read-Host -Prompt "Would you like to use Win32 OpenSSL to extract public cert and private key from the Microsoft .pfx file? [Yes/No]"
        while ($UseOpenSSL -notmatch "Yes|No") {
            Write-Host "$UseOpenSSL is not a valid option. Please enter 'Yes' or 'No'"
            $UseOpenSSL = Read-Host -Prompt "Would you like to use Win32 OpenSSL to extract public cert and private key from the Microsoft .pfx file? [Yes/No]"
        }
    }

    $DomainPrefix = ((gwmi Win32_ComputerSystem).Domain).Split(".") | Select-Object -Index 0
    $DomainSuffix = ((gwmi Win32_ComputerSystem).Domain).Split(".") | Select-Object -Index 1
    $Hostname = (gwmi Win32_ComputerSystem).Name
    $HostFQDN = $Hostname+'.'+$DomainPrefix+'.'+$DomainSuffix

    # If using Win32 OpenSSL, check to make sure the path to binary is valid...
    if ($UseOpenSSL -eq "Yes" -and !$CSRGenOnly) {
        if ($PathToWin32OpenSSL) {
            if (!$(Test-Path $PathToWin32OpenSSL)) {
                $OpenSSLPathDNE = $True
            }

            $env:Path = "$PathToWin32OpenSSL;$env:Path"
        }

        # Check is openssl.exe is already available
        if ([bool]$(Get-Command openssl -ErrorAction SilentlyContinue)) {
            # Check to make sure the version is at least 1.1.0
            $OpenSSLExeInfo = Get-Item $(Get-Command openssl).Source
            $OpenSSLExeVersion = [version]$($OpenSSLExeInfo.VersionInfo.ProductVersion -split '-')[0]
        }

        # We need at least vertion 1.1.0 of OpenSSL
        if ($OpenSSLExeVersion.Major -lt 1 -or $($OpenSSLExeVersion.Major -eq 1 -and $OpenSSLExeVersion.Minor -lt 1) -or
        ![bool]$(Get-Command openssl -ErrorAction SilentlyContinue)
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

        $PathToWin32OpenSSL = $(Get-Command openssl).Source | Split-Path -Parent
    }

    # Check for contradictions in $MachineKeySet value and $PrivateKeyExportableValue and $UseOpenSSL
    if ($MachineKeySet -eq "TRUE" -and $PrivateKeyExportableValue -eq "TRUE") {
        $WrnMsg = "MachineKeySet and PrivateKeyExportableValue have both been set to TRUE, but " +
        "Private Key cannot be exported if MachineKeySet = TRUE!"
        Write-Warning $WrnMsg

        $ShouldPrivKeyBeExportable = Read-Host -Prompt "Would you like the Private Key to be exportable? [Yes/No]"
        while ($ShouldPrivKeyBeExportable -notmatch "Yes|yes|Y|y|No|no|N|n") {
            Write-Host "$ShouldPrivKeyBeExportable is not a valid option. Please enter either 'Yes' or 'No'" -ForeGroundColor Yellow
            $ShouldPrivKeyBeExportable = Read-Host -Prompt "Would you like the Private Key to be exportable? [Yes/No]"
        }
        if ($ShouldPrivKeyBeExportable -match "Yes|yes|Y|y") {
            $MachineKeySet = "FALSE"
            $PrivateKeyExportableValue = "TRUE"
        }
        else {
            $MachineKeySet = "TRUE"
            $PrivateKeyExportableValue = "FALSE"
        }
    }
    if ($MachineKeySet -eq "TRUE" -and $UseOpenSSL -eq "Yes") {
        $WrnMsg = "MachineKeySet and UseOpenSSL have both been set to TRUE. OpenSSL targets a .pfx file exported from the " +
        "local Certificate Store. If MachineKeySet is set to TRUE, no .pfx file will be exported from the " +
        "local Certificate Store!"
        Write-Warning $WrnMsg
        $ShouldUseOpenSSL = Read-Host -Prompt "Would you like to use OpenSSL in order to generate keys in formats compatible with Linux? [Yes\No]"
        while ($ShouldUseOpenSSL -notmatch "Yes|yes|Y|y|No|no|N|n") {
            Write-Host "$ShouldUseOpenSSL is not a valid option. Please enter either 'Yes' or 'No'" -ForeGroundColor Yellow
            $ShouldUseOpenSSL = Read-Host -Prompt "Would you like to use OpenSSL in order to generate keys in formats compatible with Linux? [Yes\No]"
        }
        if ($ShouldUseOpenSSL -match "Yes|yes|Y|y") {
            $MachineKeySet = "FALSE"
            $UseOpenSSL = "Yes"
        }
        else {
            $MachineKeySet = "TRUE"
            $UseOpenSSL = "No"
        }
    }
    if ($MachineKeySet -eq "FALSE" -and $PFXPwdAsSecureString -eq $null -and !$CSRGenOnly) {
        $PFXPwdAsSecureStringA = Read-Host -Prompt "Please enter a password to use when exporting .pfx bundle certificate/key bundle" -AsSecureString
        $PFXPwdAsSecureStringB = Read-Host -Prompt "Please enter the same password again" -AsSecureString

        while ([Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($PFXPwdAsSecureStringA)) -ne
        [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($PFXPwdAsSecureStringB))
        ) {
            Write-Warning "Passwords don't match!"
            $PFXPwdAsSecureStringA = Read-Host -Prompt "Please enter a password to use when exporting .pfx bundle certificate/key bundle" -AsSecureString
            $PFXPwdAsSecureStringB = Read-Host -Prompt "Please enter the same password again" -AsSecureString
        }

        $PFXPwdAsSecureString = $PFXPwdAsSecureStringA
    }

    if (!$CSRGenOnly) {
        if ($PFXPwdAsSecureString.GetType().Name -eq "String") {
            $PFXPwdAsSecureString = ConvertTo-SecureString -String $PFXPwdAsSecureString -Force -AsPlainText
        }
    }

    # If the workstation being used to request the Certificate is part of the same Domain as the Issuing Certificate Authority, leverage certutil...
    if (!$ADCSWebEnrollmentUrl -and !$CSRGenOnly) {
        #$NeededRSATFeatures = @("RSAT","RSAT-Role-Tools","RSAT-AD-Tools","RSAT-AD-PowerShell","RSAT-ADDS","RSAT-AD-AdminCenter","RSAT-ADDS-Tools","RSAT-ADLDS")

        if (!$(Get-Module -ListAvailable -Name ActiveDirectory)) {
            try {
                $InstallRSATResult = Install-RSAT -ErrorAction Stop
                if ($InstallRSATResult -eq "RestartNeeded") {
                    throw "$env:ComputerName must be restarted post RSAT install! Please restart at your earliest convenience and try the Generate-Certificate funciton again."
                }
            }
            catch {
                Write-Error $_
                $global:FunctionResult = "1"
                return
            }
        }
        if (!$(Get-Module -ListAvailable -Name ActiveDirectory)) {
            Write-Error "Problem installing the ActiveDirectory PowerShell Module (via RSAT installation). Halting!"
            $global:FunctionResult = "1"
            return
        }
        if ($(Get-Module).Name -notcontains "ActiveDirectory") {
            try {
                Import-Module ActiveDirectory -ErrorAction Stop
            }
            catch {
                Write-Error $_
                $global:FunctionResult = "1"
                return
            }
        }

        $AvailableCertificateAuthorities = (((certutil | Select-String -Pattern "Config:") -replace "Config:[\s]{1,32}``") -replace "'","").trim()
        $IssuingCertAuth = foreach ($obj1 in $AvailableCertificateAuthorities) {
            $obj2 = certutil -config $obj1 -CAInfo type | Select-String -Pattern "Enterprise Subordinate CA" | Select-Object -ExpandProperty Matches | Select-Object -ExpandProperty Value
            if ($obj2 -eq "Enterprise Subordinate CA") {
                $obj1
            }
        }
        $IssuingCertAuthFQDN = $IssuingCertAuth.Split("\") | Select-Object -Index 0
        $IssuingCertAuthHostname = $IssuingCertAuth.Split("\") | Select-Object -Index 1
        $null = certutil -config $IssuingCertAuth -ping
        if ($LASTEXITCODE -eq 0) {
            Write-Host "Successfully contacted the Issuing Certificate Authority: $IssuingCertAuth"
        }
        else {
            Write-Host "Cannot contact the Issuing Certificate Authority: $IssuingCertAuth. Halting!"
            $global:FunctionResult = "1"
            return
        }
        
        if ($PSBoundParameters['BasisTemplate']) {
            # $AllAvailableCertificateTemplates Using PSPKI
            # $AllAvailableCertificateTemplates = Get-PSPKICertificateTemplate
            # Using certutil
            $AllAvailableCertificateTemplatesPrep = certutil -ADTemplate
            # Determine valid CN using PSPKI
            # $ValidCertificateTemplatesByCN = $AllAvailableCertificateTemplatesPrep.Name
            # Determine valid displayNames using certutil
            $ValidCertificateTemplatesByCN = foreach ($obj1 in $AllAvailableCertificateTemplatesPrep) {
                $obj2 = $obj1 | Select-String -Pattern "[\w]{1,32}:[\s][\w]" | Select-Object -ExpandProperty Matches | Select-Object -ExpandProperty Value
                $obj3 = $obj2 -replace ':[\s][\w]',''
                $obj3
            }
            # Determine valid displayNames using PSPKI
            # $ValidCertificateTemplatesByDisplayName = $AllAvailableCertificateTemplatesPrep.DisplayName
            # Determine valid displayNames using certutil
            $ValidCertificateTemplatesByDisplayName = foreach ($obj1 in $AllAvailableCertificateTemplatesPrep) {
                $obj2 = $obj1 | Select-String -Pattern "\:(.*)\-\-" | Select-Object -ExpandProperty Matches | Select-Object -ExpandProperty Value
                $obj3 = ($obj2 -replace ": ","") -replace " --",""
                $obj3
            }

            if ($ValidCertificateTemplatesByCN -notcontains $BasisTemplate -and $ValidCertificateTemplatesByDisplayName -notcontains $BasisTemplate) {
                $TemplateMsg = "You must base your New Certificate Template on an existing Certificate Template.`n" +
                "To do so, please enter either the displayName or CN of the Certificate Template you would like to use as your base.`n" +
                "Valid displayName values are as follows:`n$($ValidDisplayNamesAsString -join "`n")`n" +
                "Valid CN values are as follows:`n$($ValidCNNamesAsString -join "`n")"

                $BasisTemplate = Read-Host -Prompt "Please enter the displayName or CN of the Certificate Template you would like to use as your base"
                while ($($ValidCertificateTemplatesByCN + $ValidCertificateTemplatesByDisplayName) -notcontains $BasisTemplate) {
                    Write-Host "$BasisTemplate is not a valid displayName or CN of an existing Certificate Template on Issuing Certificate Authority $IssuingCertAuth!" -ForeGroundColor Yellow
                    $BasisTemplate = Read-Host -Prompt "Please enter the displayName or CN of the Certificate Template you would like to use as your base"
                }
            }

            # Get all Certificate Template Properties of the Basis Template
            $LDAPSearchBase = "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=$DomainPrefix,DC=$DomainSuffix"

            # Set displayName and CN Values for user-provided $BasisTemplate
            if ($ValidCertificateTemplatesByCN -contains $BasisTemplate) {
                $cnForBasisTemplate = $BasisTemplate
                $CertificateTemplateLDAPObject = Get-ADObject -SearchBase $LDAPSearchBase -Filter {cn -eq $cnForBasisTemplate}
                $AllCertificateTemplateProperties = Get-ADObject -SearchBase $LDAPSearchBase -Filter {cn -eq $cnForBasisTemplate} -Properties *
                $displayNameForBasisTemplate = $AllCertificateTemplateProperties.DisplayName
            }
            if ($ValidCertificateTemplatesByDisplayName -contains $BasisTemplate) {
                $displayNameForBasisTemplate = $BasisTemplate
                $CertificateTemplateLDAPObject = Get-ADObject -SearchBase $LDAPSearchBase -Filter {displayName -eq $displayNameForBasisTemplate}
                $AllCertificateTemplateProperties = Get-ADObject -SearchBase $LDAPSearchBase -Filter {displayName -eq $displayNameForBasisTemplate} -Properties *
                $cnForBasisTemplate = $AllCertificateTemplateProperties.CN
            }

            # Validate $ProviderNameValue
            # All available Cryptographic Providers (CSPs) are as follows:
            $PossibleProvidersPrep = certutil -csplist | Select-String "Provider Name" -Context 0,1
            $PossibleProviders = foreach ($obj1 in $PossibleProvidersPrep) {
                $obj2 = $obj1.Context.PostContext | Select-String 'FAIL' | Select-Object -ExpandProperty Matches | Select-Object -ExpandProperty Success
                $obj3 = $obj1.Context.PostContext | Select-String 'not ready' | Select-Object -ExpandProperty Matches | Select-Object -ExpandProperty Success
                if ($obj2 -ne "True" -and $obj3 -ne "True") {
                    $obj1.Line -replace "Provider Name: ",""
                }
            }
            # Available Cryptographic Providers (CSPs) based on user choice in Certificate Template (i.e. $BasisTemplate)
            # Does the Basis Certificate Template LDAP Object have an attribute called pKIDefaultCSPs that is set?
            $CertificateTemplateLDAPObjectSetAttributes = $AllCertificateTemplateProperties.PropertyNames
            if ($CertificateTemplateLDAPObjectSetAttributes -notcontains "pKIDefaultCSPs") {
                $PKIMsg = "The Basis Template $BasisTemplate does NOT have the attribute pKIDefaultCSPs set. " +
                "This means that Cryptographic Providers are NOT Limited, and (almost) any ProviderNameValue is valid"
                Write-Host $PKIMsg
            }
            else {
                $AvailableCSPsBasedOnCertificateTemplate = $AllCertificateTemplateProperties.pkiDefaultCSPs -replace '[0-9],',''
                if ($AvailableCSPsBasedOnCertificateTemplate -notcontains $ProviderNameValue) {
                    Write-Warning "$ProviderNameValue is not one of the available Provider Names on Certificate Template $BasisTemplate!"
                    Write-Host "Valid Provider Names based on your choice in Basis Certificate Template are as follows:`n$($AvailableCSPsBasedOnCertificateTemplate -join "`n")"
                    $ProviderNameValue = Read-Host -Prompt "Please enter the name of the Cryptographic Provider (CSP) you would like to use"
                    while ($AvailableCSPsBasedOnCertificateTemplate -notcontains $ProviderNameValue) {
                        Write-Warning "$ProviderNameValue is not one of the available Provider Names on Certificate Template $BasisTemplate!"
                        Write-Host "Valid Provider Names based on your choice in Basis Certificate Template are as follows:`n$($AvailableCSPsBasedOnCertificateTemplate -join "`n")"
                        $ProviderNameValue = Read-Host -Prompt "Please enter the name of the Cryptographic Provider (CSP) you would like to use"
                    }
                }
            }
        }
    }
    # If the workstation being used to request the Certificate is NOT part of the same Domain as the Issuing Certificate Authority, use ADCS Web Enrollment Site...
    if ($ADCSWebEnrollmentUrl -and !$CSRGenOnly) {
        # Make sure there is no trailing / on $ADCSWebEnrollmentUrl
        if ($ADCSWebEnrollmentUrl.EndsWith('/')) {
            $ADCSWebEnrollmentUrl = $ADCSWebEnrollmentUrl.Substring(0,$ADCSWebEnrollmentUrl.Length-1)
        } 

        # The IIS Web Server hosting ADCS Web Enrollment may be configured for Windows Authentication, Basic Authentication, or both.
        if ($ADCSWebAuthType -eq "Windows") {
            if (!$ADCSWebCreds) {
                if (!$ADCSWebAuthUserName) {
                    $ADCSWebAuthUserName = Read-Host -Prompt "Please specify the AD account to be used for ADCS Web Enrollment authentication."
                    # IMPORTANT NOTE: $ADCSWebAuthUserName should NOT include the domain prefix. Example: testadmin
                }
                if ($ADCSWebAuthUserName -match "[\w\W]\\[\w\W]") {
                    $ADCSWebAuthUserName = $ADCSWebAuthUserName.Split("\")[1]
                }

                if (!$ADCSWebAuthPass) {
                    $ADCSWebAuthPass = Read-Host -Prompt "Please enter a password to be used for ADCS Web Enrollment authentication" -AsSecureString
                }

                $ADCSWebCreds = New-Object System.Management.Automation.PSCredential ($ADCSWebAuthUserName, $ADCSWebAuthPass)
            }

            # Test Connection to $ADCSWebEnrollmentUrl
            # Validate $ADCSWebEnrollmentUrl...
            $StatusCode = $(Invoke-WebRequest -Uri "$ADCSWebEnrollmentUrl/" -Credential $ADCSWebCreds).StatusCode
            if ($StatusCode -eq "200") {
                Write-Host "Connection to $ADCSWebEnrollmentUrl was successful...continuing"
            }
            else {
                Write-Host "Connection to $ADCSWebEnrollmentUrl was NOT successful. Please check your credentials and/or DNS."
                $global:FunctionResult = "1"
                return
            }
        }
        if ($ADCSWebAuthType -eq "Basic") {
            if (!$ADCSWebAuthUserName) {
                $PromptMsg = "Please specify the AD account to be used for ADCS Web Enrollment authentication. " +
                "Please *include* the domain prefix. Example: test\testadmin"
                $ADCSWebAuthUserName = Read-Host -Prompt $PromptMsg
            }
            while (![bool]$($ADCSWebAuthUserName -match "[\w\W]\\[\w\W]")) {
                Write-Host "Please include the domain prefix before the username. Example: test\testadmin"
                $ADCSWebAuthUserName = Read-Host -Prompt $PromptMsg
            }

            if (!$ADCSWebAuthPass) {
                $ADCSWebAuthPass = Read-Host -Prompt "Please enter a password to be used for ADCS Web Enrollment authentication" -AsSecureString
            }
            # If $ADCSWebAuthPass is a Secure String, convert it back to Plaintext
            if ($ADCSWebAuthPass.GetType().Name -eq "SecureString") {
                $ADCSWebAuthPass = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($ADCSWebAuthPass))
            }

            $pair = "${$ADCSWebAuthUserName}:${$ADCSWebAuthPass}"
            $bytes = [System.Text.Encoding]::ASCII.GetBytes($pair)
            $base64 = [System.Convert]::ToBase64String($bytes)
            $basicAuthValue = "Basic $base64"
            $headers = @{Authorization = $basicAuthValue}

            # Test Connection to $ADCSWebEnrollmentUrl
            # Validate $ADCSWebEnrollmentUrl...
            $StatusCode = $(Invoke-WebRequest -Uri "$ADCSWebEnrollmentUrl/" -Headers $headers).StatusCode
            if ($StatusCode -eq "200") {
                Write-Host "Connection to $ADCSWebEnrollmentUrl was successful...continuing" -ForeGroundColor Green
            }
            else {
                Write-Error "Connection to $ADCSWebEnrollmentUrl was NOT successful. Please check your credentials and/or DNS."
                $global:FunctionResult = "1"
                return
            }
        }

        if ($PSBoundParameters['BasisTemplate']) {
            # Check available Certificate Templates...
            if ($ADCSWebAuthType -eq "Windows") {
                $CertTemplCheckInitialResponse = Invoke-WebRequest -Uri "$ADCSWebEnrollmentUrl/certrqxt.asp" -Credential $ADCSWebCreds
            }
            if ($ADCSWebAuthType -eq "Basic") {
                $CertTemplCheckInitialResponse = Invoke-WebRequest -Uri "$ADCSWebEnrollmentUrl/certrqxt.asp" -Headers $headers
            }

            $ValidADCSWebEnrollCertTemplatesPrep = ($CertTemplCheckInitialResponse.RawContent.Split("`r") | Select-String -Pattern 'Option Value=".*').Matches.Value
            $ValidADCSWEbEnrollCertTemplates = foreach ($obj1 in $ValidADCSWebEnrollCertTemplatesPrep) {
                $obj1.Split(";")[1]
            }
            # Validate specified Certificate Template...
            while ($ValidADCSWebEnrollCertTemplates -notcontains $BasisTemplate) {
                Write-Warning "$BasisTemplate is not on the list of available Certificate Templates on the ADCS Web Enrollment site."
                $DDMsg = "IMPORTANT NOTE: For a Certificate Template to appear in the Certificate Template drop-down on the ADCS " +
                "Web Enrollment site, the msPKITemplateSchemaVersion attribute MUST BE '2' or '1' AND pKIExpirationPeriod MUST " +
                "BE 1 year or LESS"
                Write-Host $DDMsg -ForeGroundColor Yellow
                Write-Host "Certificate Templates available via ADCS Web Enrollment are as follows:`n$($ValidADCSWebEnrollCertTemplates -join "`n")"
                $BasisTemplate = Read-Host -Prompt "Please enter the name of an existing Certificate Template that you would like your New Certificate to be based on"
            }

            $CertTemplvsCSPHT = @{}
            $ValidADCSWebEnrollCertTemplatesPrep | foreach {
                $key = $($_ -split ";")[1]
                $value = [array]$($($_ -split ";")[8] -split "\?")
                $CertTemplvsCSPHT.Add($key,$value)
            }
            
            $ValidADCSWebEnrollCSPs = $CertTemplvsCSPHT.$BasisTemplate

            while ($ValidADCSWebEnrollCSPs -notcontains $ProviderNameValue) {
                $PNMsg = "$ProviderNameVaule is not a valid Provider Name. Valid Provider Names based on your choice in Basis " +
                "Certificate Template are as follows:`n$($ValidADCSWebEnrollCSPs -join "`n")"
                Write-Host $PNMsg
                $ProviderNameValue = Read-Host -Prompt "Please enter the name of the Cryptographic Provider (CSP) you would like to use"
            }
        }
    }
        


    ##### END Initial Variable Definition and Validation #####

    ##### BEGIN Writing the Certificate Request Config File #####

    # This content is saved to $CertGenWorking\$CertificateRequestConfigFile
    # For more information about the contents of the config file, see: https://technet.microsoft.com/en-us/library/hh831574(v=ws.11).aspx 

    Set-Content -Value '[Version]' -Path "$CertGenWorking\$CertificateRequestConfigFile"
    Add-Content -Value 'Signature="$Windows NT$"' -Path "$CertGenWorking\$CertificateRequestConfigFile"
    Add-Content -Value "`n`r" -Path "$CertGenWorking\$CertificateRequestConfigFile"
    Add-Content -Value '[NewRequest]' -Path "$CertGenWorking\$CertificateRequestConfigFile"
    Add-Content -Value "FriendlyName = $CertificateCN" -Path "$CertGenWorking\$CertificateRequestConfigFile"

    # For below Subject, for a wildcard use "CN=*.DOMAIN.COM"
    Add-Content -Value "Subject = `"CN=$CertificateCN,OU=$OrganizationalUnit,O=$Organization,L=$Locality,S=$State,C=$Country`"" -Path $CertGenWorking\$CertificateRequestConfigFile

    Add-Content -Value "KeyLength = $KeyLength" -Path "$CertGenWorking\$CertificateRequestConfigFile"

    Add-Content -Value "HashAlgorithm = $HashAlgorithmValue" -Path "$CertGenWorking\$CertificateRequestConfigFile"

    Add-Content -Value "EncryptionAlgorithm = $EncryptionAlgorithmValue" -Path "$CertGenWorking\$CertificateRequestConfigFile"

    Add-Content -Value "Exportable = $PrivateKeyExportableValue" -Path "$CertGenWorking\$CertificateRequestConfigFile"

    Add-Content -Value "KeySpec = $KeySpecValue" -Path "$CertGenWorking\$CertificateRequestConfigFile"

    Add-Content -Value "KeyUsage = $KeyUsageValueUpdated" -Path "$CertGenWorking\$CertificateRequestConfigFile"

    Add-Content -Value "MachineKeySet = $MachineKeySet" -Path "$CertGenWorking\$CertificateRequestConfigFile"

    Add-Content -Value "SMIME = $SMIMEValue" -Path "$CertGenWorking\$CertificateRequestConfigFile"

    Add-Content -Value 'PrivateKeyArchive = FALSE' -Path "$CertGenWorking\$CertificateRequestConfigFile"

    Add-Content -Value "UserProtected = $UserProtected" -Path "$CertGenWorking\$CertificateRequestConfigFile"

    Add-Content -Value 'UseExistingKeySet = FALSE' -Path "$CertGenWorking\$CertificateRequestConfigFile"

    # Next, get the $ProviderTypeValue based on $ProviderNameValue
    if ($PSBoundParameters['BasisTemplate']) {
        $ProviderTypeValuePrep = certutil -csplist | Select-String $ProviderNameValue -Context 0,1
        $ProviderTypeValue = $ProviderTypeValuePrep.Context.PostContext | Select-String -Pattern '[0-9]{1,2}' | Select-Object -ExpandProperty Matches | Select-Object -ExpandProperty Value
        Add-Content -Value "ProviderName = `"$ProviderNameValue`"" -Path "$CertGenWorking\$CertificateRequestConfigFile"
        Add-Content -Value "ProviderType = $ProviderTypeValue" -Path "$CertGenWorking\$CertificateRequestConfigFile"
    }
    else {
        $ProviderNameValue = "Microsoft RSA SChannel Cryptographic Provider"
        $ProviderTypeValue = "12"
        Add-Content -Value "ProviderName = `"$ProviderNameValue`"" -Path "$CertGenWorking\$CertificateRequestConfigFile"
        Add-Content -Value "ProviderType = $ProviderTypeValue" -Path "$CertGenWorking\$CertificateRequestConfigFile"
    }

    Add-Content -Value "RequestType = $RequestTypeValue" -Path "$CertGenWorking\$CertificateRequestConfigFile"

    <#
    TODO: Logic for self-signed and/or self-issued certificates that DO NOT generate a CSR and DO NOT submit to Certificate Authority
    if ($RequestTypeValue -eq "Cert") {
        $ValidityPeriodValue = Read-Host -Prompt "Please enter the length of time that the certificate will be valid for.
        #NOTE: Values must be in Months or Years. For example '6 months' or '2 years'"
        $ValidityPeriodPrep = $ValidityPeriodValue.Split(" ") | Select-Object -Index 1
        if ($ValidityPeriodPrep.EndsWith("s")) {
            $ValidityPeriod = $ValidityPeriodPrep.substring(0,1).toupper()+$validityPeriodPrep.substring(1).tolower()
        }
        else {
            $ValidityPeriod = $ValidityPeriodPrep.substring(0,1).toupper()+$validityPeriodPrep.substring(1).tolower()+'s'
        }
        $ValidityPeriodUnits = $ValidityPeriodValue.Split(" ") | Select-Object -Index 0

        Add-Content -Value "ValidityPeriodUnits = $ValidityPeriodUnits" -Path "$CertGenWorking\$CertificateRequestConfigFile"
        Add-Content -Value "ValidityPeriod = $ValidityPeriod" -Path "$CertGenWorking\$CertificateRequestConfigFile"
    }
    #>

    $GetIntendedPurposePSObjects = Get-IntendedPurposePSObjects -OIDHashTable $OIDHashTable
    [System.Collections.ArrayList]$RelevantPSObjects = @()
    if ($IntendedPurposeValues) {
        foreach ($IntendedPurposeValue in [array]$IntendedPurposeValues) {
            foreach ($PSObject in $GetIntendedPurposePSObjects) {
                if ($IntendedPurposeValue -eq $PSObject.IntendedPurpose) {
                    $null = $RelevantPSObjects.Add($PSObject)
                }
            }
        }
    }
    else {
        [array]$OfficialOIDs = $AllCertificateTemplateProperties.pKIExtendedKeyUsage

        [System.Collections.ArrayList]$RelevantPSObjects = @()
        foreach ($OID in $OfficialOIDs) {
            foreach ($PSObject in $GetIntendedPurposePSObjects) {
                if ($OID -eq $PSObject.OfficialOID) {
                    $null = $RelevantPSObjects.Add($PSObject)
                }
            }
        }
    }

    if ($IntendedPurposeValues) {
        Add-Content -Value "`n`r" -Path "$CertGenWorking\$CertificateRequestConfigFile"
        Add-Content -Value '[Strings]' -Path "$CertGenWorking\$CertificateRequestConfigFile"
        Add-Content -Value 'szOID_ENHANCED_KEY_USAGE = "2.5.29.37"' -Path "$CertGenWorking\$CertificateRequestConfigFile"

        foreach ($line in $RelevantPSObjects.CertRequestConfigFileLine) {
            Add-Content -Value $line -Path "$CertGenWorking\$CertificateRequestConfigFile"
        }

        Add-Content -Value "`n`r" -Path "$CertGenWorking\$CertificateRequestConfigFile"
        Add-Content -Value '[Extensions]' -Path "$CertGenWorking\$CertificateRequestConfigFile"

        [array]$szOIDArray = $RelevantPSObjects.szOIDString
        $szOIDArrayFirstItem = $szOIDArray[0]
        Add-Content -Value "%szOID_ENHANCED_KEY_USAGE%=`"{text}%$szOIDArrayFirstItem%,`"" -Path "$CertGenWorking\$CertificateRequestConfigFile"

        foreach ($string in $szOIDArray[1..$($szOIDArray.Count-1)]) {
            Add-Content -Value "_continue_ = `"%$string%`"" -Path "$CertGenWorking\$CertificateRequestConfigFile"
        }
    }

    if ($SANObjectsToAdd) {
        if (![bool]$($(Get-Content "$CertGenWorking\$CertificateRequestConfigFile") -match "\[Extensions\]")) {
            Add-Content -Value "`n`r" -Path "$CertGenWorking\$CertificateRequestConfigFile"
            Add-Content -Value '[Extensions]' -Path "$CertGenWorking\$CertificateRequestConfigFile"
        }

        Add-Content -Value '2.5.29.17 = "{text}"' -Path "$CertGenWorking\$CertificateRequestConfigFile"
        
        if ($SANObjectsToAdd -contains "DNS") {
            if (!$DNSSANObjects) {
                $DNSSANObjects = Read-Host -Prompt "Please enter one or more DNS SAN objects separated by commas`nExample: www.fabrikam.com, www.contoso.org"
                $DNSSANObjects = $DNSSANObjects.Split(",").Trim()
            }

            foreach ($DNSSAN in $DNSSANObjects) {
                Add-Content -Value "_continue_ = `"dns=$DNSSAN&`"" -Path "$CertGenWorking\$CertificateRequestConfigFile"
            }
        }
        if ($SANObjectsToAdd -contains "Distinguished Name") {
            if (!$DistinguishedNameSANObjects) {
                $DNMsg = "Please enter one or more Distinguished Name SAN objects ***separated by semi-colons***`n" +
                "Example: CN=www01,OU=Web Servers,DC=fabrikam,DC=com; CN=www01,OU=Load Balancers,DC=fabrikam,DC=com"
                $DistinguishedNameSANObjects = Read-Host -Prompt $DNMsg
                $DistinguishedNameSANObjects = $DistinguishedNameSANObjects.Split(";").Trim()
            }

            foreach ($DNObj in $DistinguishedNameSANObjects) {
                Add-Content -Value "_continue_ = `"dn=$DNObj&`"" -Path "$CertGenWorking\$CertificateRequestConfigFile"
            }
        }
        if ($SANObjectsToAdd -contains "URL") {
            if (!$URLSANObjects) {
                $URLMsg = "Please enter one or more URL SAN objects separated by commas`nExample: " +
                "http://www.fabrikam.com, http://www.contoso.com"
                $URLSANObjects = Read-Host -Prompt $URLMsg
                $URLSANObjects = $URLSANObjects.Split(",").Trim()
            }
            
            foreach ($UrlObj in $URLSANObjects) {
                Add-Content -Value "_continue_ = `"url=$UrlObj&`"" -Path "$CertGenWorking\$CertificateRequestConfigFile"
            }
        }
        if ($SANObjectsToAdd -contains "IP Address") {
            if (!$IPAddressSANObjects) {
                $IPAddressSANObjects = Read-Host -Prompt "Please enter one or more IP Addresses separated by commas`nExample: 172.31.10.13, 192.168.2.125"
                $IPAddressSANObjects = $IPAddressSANObjects.Split(",").Trim()
            }

            foreach ($IPAddr in $IPAddressSANObjects) {
                if (!$(Test-IsValidIPAddress -IPAddress $IPAddr)) {
                    Write-Error "$IPAddr is not a valid IP Address! Halting!"

                    # Cleanup
                    Remove-Item $CertGenWorking -Recurse -Force

                    $global:FunctionResult = "1"
                    return
                }
            }
            
            foreach ($IPAddr in $IPAddressSANObjects) {
                Add-Content -Value "_continue_ = `"ipaddress=$IPAddr&`"" -Path "$CertGenWorking\$CertificateRequestConfigFile"
            }
        }
        if ($SANObjectsToAdd -contains "Email") {
            if (!$EmailSANObjects) {
                $EmailSANObjects = Read-Host -Prompt "Please enter one or more Email SAN objects separated by commas`nExample: mike@fabrikam.com, hazem@fabrikam.com"
                $EmailSANObjects = $EmailSANObjects.Split(",").Trim()
            }
            
            foreach ($EmailAddr in $EmailSANObjectsArray) {
                Add-Content -Value "_continue_ = `"email=$EmailAddr&`"" -Path "$CertGenWorking\$CertificateRequestConfigFile"
            }
        }
        if ($SANObjectsToAdd -contains "UPN") {
            if (!$UPNSANObjects) {
                $UPNSANObjects = Read-Host -Prompt "Please enter one or more UPN SAN objects separated by commas`nExample: mike@fabrikam.com, hazem@fabrikam.com"
                $UPNSANObjects = $UPNSANObjects.Split(",").Trim()
            }
            
            foreach ($UPN in $UPNSANObjects) {
                Add-Content -Value "_continue_ = `"upn=$UPN&`"" -Path "$CertGenWorking\$CertificateRequestConfigFile"
            }
        }
        if ($SANObjectsToAdd -contains "GUID") {
            if (!$GUIDSANObjects) {
                $GUIDMsg = "Please enter one or more GUID SAN objects separated by commas`nExample: " +
                "f7c3ac41-b8ce-4fb4-aa58-3d1dc0e36b39, g8D4ac41-b8ce-4fb4-aa58-3d1dc0e47c48"
                $GUIDSANObjects = Read-Host -Prompt $GUIDMsg
                $GUIDSANObjects = $GUIDSANObjects.Split(",").Trim()
            }
            
            foreach ($GUID in $GUIDSANObjectsArray) {
                Add-Content -Value "_continue_ = `"guid=$GUID&`"" -Path "$CertGenWorking\$CertificateRequestConfigFile"
            }
        }
    }

    ##### END Writing the Certificate Request Config File #####


    ##### BEGIN Generate Certificate Request and Submit to Issuing Certificate Authority #####

    ## Generate new Certificate Request File: ##
    # NOTE: The generation of a Certificate Request File using the below "certreq.exe -new" command also adds the CSR to the 
    # Client Machine's Certificate Request Store located at PSDrive "Cert:\CurrentUser\REQUEST" which is also known as 
    # "Microsoft.PowerShell.Security\Certificate::CurrentUser\Request"
    # There doesn't appear to be an equivalent to this using PowerShell cmdlets
    $null = certreq.exe -new "$CertGenWorking\$CertificateRequestConfigFile" "$CertGenWorking\$CertificateRequestFile"

    if ($CSRGenOnly) {
        [pscustomobject]@{
            CSRFile         = $(Get-Item "$CertGenWorking\$CertificateRequestFile")
            CSRContent      = $(Get-Content "$CertGenWorking\$CertificateRequestFile")
        }
        return
    }

    # TODO: If the Certificate Request Configuration File referenced in the above command contains "RequestType = Cert", then instead of the above command, 
    # the below certreq command should be used:
    # certreq.exe -new -cert [CertId] "$CertGenWorking\$CertificateRequestConfigFile" "$CertGenWorking\$CertificateRequestFile"

    if ($ADCSWebEnrollmentUrl) {
        # POST Data as a hash table
        $postParams = @{            
            "Mode"             = "newreq"
            "CertRequest"      = $(Get-Content "$CertGenWorking\$CertificateRequestFile" -Encoding Ascii | Out-String)
            "CertAttrib"       = "CertificateTemplate:$BasisTemplate"
            "FriendlyType"     = "Saved-Request+Certificate+($(Get-Date -DisplayHint Date -Format M/dd/yyyy),+$(Get-Date -DisplayHint Date -Format h:mm:ss+tt))"
            "Thumbprint"       = ""
            "TargetStoreFlags" = "0"
            "SaveCert"         = "yes"
        }

        # Submit New Certificate Request and Download New Certificate
        if ($ADCSWebAuthType -eq "Windows") {
            # Send the POST Data
            Invoke-RestMethod -Uri "$ADCSWebEnrollmentUrl/certfnsh.asp" -Method Post -Body $postParams -Credential $ADCSWebCreds -OutFile "$CertGenWorking\$CertADCSWebResponseOutFile"
        
            # Download New Certificate
            $ReqId = (Get-Content "$CertGenWorking\$CertADCSWebResponseOutFile" | Select-String -Pattern "ReqID=[0-9]{1,5}" | Select-Object -Index 0).Matches.Value.Split("=")[1]
            if ($ReqId -eq $null) {
                Write-Host "The Certificate Request was successfully submitted via ADCS Web Enrollment, but was rejected. Please check the format and contents of
                the Certificate Request Config File and try again."
                $global:FunctionResult = "1"
                return
            }

            $CertWebRawContent = (Invoke-WebRequest -Uri "$ADCSWebEnrollmentUrl/certnew.cer?ReqID=$ReqId&Enc=b64" -Credential $ADCSWebCreds).RawContent
            # Replace the line that begins with `r with ;;; then split on ;;; and select the last object in the index
            (($CertWebRawContent.Split("`n") -replace "^`r",";;;") -join "`n").Split(";;;")[-1].Trim() | Out-File "$CertGenWorking\$CertFileOut"
            # Alternate: Skip everything up until `r
            #$CertWebRawContent.Split("`n") | Select-Object -Skip $([array]::indexof($($CertWebRawContent.Split("`n")),"`r")) | Out-File "$CertGenWorking\$CertFileOut"
        }
        if ($ADCSWebAuthType -eq "Basic") {
            # Send the POST Data
            Invoke-RestMethod -Uri "$ADCSWebEnrollmentUrl/certfnsh.asp" -Method Post -Body $postParams -Headers $headers -OutFile "$CertGenWorking\$CertADCSWebResponseOutFile"

            # Download New Certificate
            $ReqId = (Get-Content "$CertGenWorking\$CertADCSWebResponseOutFile" | Select-String -Pattern "ReqID=[0-9]{1,5}" | Select-Object -Index 0).Matches.Value.Split("=")[1]
            if ($ReqId -eq $null) {
                Write-Host "The Certificate Request was successfully submitted via ADCS Web Enrollment, but was rejected. Please check the format and contents of
                the Certificate Request Config File and try again."
                $global:FunctionResult = "1"
                return
            }

            $CertWebRawContent = (Invoke-WebRequest -Uri "$ADCSWebEnrollmentUrl/certnew.cer?ReqID=$ReqId&Enc=b64" -Headers $headers).RawContent
            $CertWebRawContentArray = $CertWebRawContent.Split("`n") 
            $CertWebRawContentArray | Select-Object -Skip $([array]::indexof($CertWebRawContentArray,"`r")) | Out-File "$CertGenWorking\$CertFileOut"
        }
    }

    if (!$ADCSWebEnrollmentUrl) {
        ## Submit New Certificate Request File to Issuing Certificate Authority and Specify a Certificate to Use as a Base ##
        if (Test-Path "$CertGenWorking\$CertificateRequestFile") {
            if (!$cnForBasisTemplate) {
                $cnForBasisTemplate = "WebServer"
            }
            $null = certreq.exe -submit -attrib "CertificateTemplate:$cnForBasisTemplate" -config "$IssuingCertAuth" "$CertGenWorking\$CertificateRequestFile" "$CertGenWorking\$CertFileOut" "$CertGenWorking\$CertificateChainOut"
            # Equivalent of above certreq command using "Get-Certificate" cmdlet is below. We decided to use certreq.exe though because it actually outputs
            # files to the filesystem as opposed to just working with the client machine's certificate store.  This is more similar to the same process on Linux.
            #
            # ## Begin "Get-Certificate" equivalent ##
            # $LocationOfCSRInStore = $(Get-ChildItem Cert:\CurrentUser\Request | Where-Object {$_.Subject -like "*$CertificateCN*"}) | Select-Object -ExpandProperty PSPath
            # Get-Certificate -Template $cnForBasisTemplate -Url "https:\\$IssuingCertAuthFQDN\certsrv" -Request $LocationOfCSRInStore -CertStoreLocation Cert:\CurrentUser\My
            # NOTE: The above Get-Certificate command ALSO imports the certificate generated by the above request, making the below "Import-Certificate" command unnecessary
            # ## End "Get-Certificate" equivalent ##
        }
    }
        
    if (Test-Path "$CertGenWorking\$CertFileOut") {
        ## Generate .pfx file by installing certificate in store and then exporting with private key ##
        # NOTE: I'm not sure why importing a file that only contains the public certificate (i.e, the .cer file) suddenly makes the private key available
        # in the Certificate Store. It just works for some reason...
        # First, install the public certificate in store
        $null = Import-Certificate -FilePath "$CertGenWorking\$CertFileOut" -CertStoreLocation Cert:\CurrentUser\My
        # certreq.exe equivalent of the above Import-Certificate command is below. It is not as reliable as Import-Certifcate.
        # certreq -accept -user "$CertGenWorking\$CertFileOut"     

        # Then, export cert with private key in the form of a .pfx file
        if ($MachineKeySet -eq "FALSE") {
            if ($ThumprintToAvoid) {
                $LocationOfCertInStore = $(Get-ChildItem Cert:\CurrentUser\My | Where-Object {$_.Subject -match "CN=$CertificateCN," -and $_.Thumbprint -notmatch $ThumprintToAvoid}) | Select-Object -ExpandProperty PSPath
            }
            else {
                $LocationOfCertInStore = $(Get-ChildItem Cert:\CurrentUser\My | Where-Object {$_.Subject -match "CN=$CertificateCN,"}) | Select-Object -ExpandProperty PSPath
            }

            if ($LocationOfCertInStore.Count -gt 1) {
                Write-Host "Certificates to inspect:`n$($LocationOfCertInStore -join "`n")" -ForeGroundColor Yellow
                Write-Error "You have more than one certificate in your Certificate Store under Cert:\CurrentUser\My with the Common Name (CN) '$CertificateCN'. Please correct this and try again."
                $global:FunctionResult = "1"
                return
            }

            $null = Export-PfxCertificate -Cert $LocationOfCertInStore -FilePath "$CertGenWorking\$PFXFileOut" -Password $PFXPwdAsSecureString
            # Equivalent of above using certutil
            # $ThumbprintOfCertToExport = $(Get-ChildItem Cert:\CurrentUser\My | Where-Object {$_.Subject -like "*$CertificateCN*"}) | Select-Object -ExpandProperty Thumbprint
            # certutil -exportPFX -p "$PFXPwdPlainText" my $ThumbprintOfCertToExport "$CertGenWorking\$PFXFileOut"

            if ($UseOpenSSL -eq "Yes" -or $UseOpenSSL -eq "y") {
                # OpenSSL can't handle PowerShell SecureStrings, so need to convert it back into Plain Text
                $PwdForPFXOpenSSL = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($PFXPwdAsSecureString))

                # Extract Private Key and Keep It Password Protected
                & "$PathToWin32OpenSSL\openssl.exe" pkcs12 -in "$CertGenWorking\$PFXFileOut" -nocerts -out "$CertGenWorking\$ProtectedPrivateKeyOut" -nodes -password pass:$PwdForPFXOpenSSL 2>&1 | Out-Null

                # The .pfx File Contains ALL Public Certificates in Chain 
                # The below extracts ALL Public Certificates in Chain
                & "$PathToWin32OpenSSL\openssl.exe" pkcs12 -in "$CertGenWorking\$PFXFileOut" -nokeys -out "$CertGenWorking\$AllPublicKeysInChainOut" -password pass:$PwdForPFXOpenSSL 2>&1 | Out-Null

                # Parse the Public Certificate Chain File and and Write Each Public Certificate to a Separate File
                # These files should have the EXACT SAME CONTENT as the .cer counterparts
                $PublicKeySansChainPrep1 = Get-Content "$CertGenWorking\$AllPublicKeysInChainOut"
                $LinesToReplace1 = $PublicKeySansChainPrep1 | Select-String -Pattern "issuer" | Sort-Object | Get-Unique
                $LinesToReplace2 = $PublicKeySansChainPrep1 | Select-String -Pattern "Bag Attributes" | Sort-Object | Get-Unique
                $PublicKeySansChainPrep2 = (Get-Content "$CertGenWorking\$AllPublicKeysInChainOut") -join "`n"
                foreach ($obj1 in $LinesToReplace1) {
                    $PublicKeySansChainPrep2 = $PublicKeySansChainPrep2 -replace "$obj1",";;;"
                }
                foreach ($obj1 in $LinesToReplace2) {
                    $PublicKeySansChainPrep2 = $PublicKeySansChainPrep2 -replace "$obj1",";;;"
                }
                $PublicKeySansChainPrep3 = $PublicKeySansChainPrep2.Split(";;;")
                $PublicKeySansChainPrep4 = foreach ($obj1 in $PublicKeySansChainPrep3) {
                    if ($obj1.Trim().StartsWith("-")) {
                        $obj1.Trim()
                    }
                }
                # Setup Hash Containing Cert Name vs Content Pairs
                $CertNamevsContentsHash = @{}
                foreach ($obj1 in $PublicKeySansChainPrep4) {
                    # First line after BEGIN CERTIFICATE
                    $obj2 = $obj1.Split("`n")[1]
                    
                    $ContextCounter = 3
                    $CertNamePrep = $null
                    while (!$CertNamePrep) {
                        $CertNamePrep = (($PublicKeySansChainPrep1 | Select-String -SimpleMatch $obj2 -Context $ContextCounter).Context.PreContext | Select-String -Pattern "subject").Line
                        $ContextCounter++
                    }
                    $CertName = $($CertNamePrep.Split("=") | Select-Object -Last 1).Trim()
                    $CertNamevsContentsHash.Add($CertName, $obj1)
                }

                # Write each Hash Key Value to Separate Files (i.e. writing all public keys in chain to separate files)
                foreach ($obj1 in $CertNamevsContentsHash.Keys) {
                    $CertNamevsContentsHash.$obj1 | Out-File "$CertGenWorking\$obj1`_Public_Cert.pem" -Encoding Ascii
                }

                # Determine if we should remove the password from the private key (i.e. $ProtectedPrivateKeyOut)
                if ($StripPrivateKeyOfPassword -eq $null) {
                    $StripPrivateKeyOfPassword = Read-Host -Prompt "Would you like to remove password protection from the private key? [Yes/No]"
                    if ($StripPrivateKeyOfPassword -eq "Yes" -or $StripPrivateKeyOfPassword -eq "y" -or $StripPrivateKeyOfPassword -eq "No" -or $StripPrivateKeyOfPassword -eq "n") {
                        Write-Host "The value for StripPrivateKeyOfPassword is valid...continuing"
                    }
                    else {
                        Write-Host "The value for StripPrivateKeyOfPassword is not valid. Please enter either 'Yes', 'y', 'No', or 'n'."
                        $StripPrivateKeyOfPassword = Read-Host -Prompt "Would you like to remove password protection from the private key? [Yes/No]"
                        if ($StripPrivateKeyOfPassword -eq "Yes" -or $StripPrivateKeyOfPassword -eq "y" -or $StripPrivateKeyOfPassword -eq "No" -or $StripPrivateKeyOfPassword -eq "n") {
                            Write-Host "The value for StripPrivateKeyOfPassword is valid...continuing"
                        }
                        else {
                            Write-Host "The value for StripPrivateKeyOfPassword is not valid. Please enter either 'Yes', 'y', 'No', or 'n'. Halting!"
                            $global:FunctionResult = "1"
                            return
                        }
                    }
                    if ($StripPrivateKeyOfPassword -eq "Yes" -or $StripPrivateKeyOfPassword -eq "y") {
                        # Strip Private Key of Password
                        & "$PathToWin32OpenSSL\openssl.exe" rsa -in "$CertGenWorking\$ProtectedPrivateKeyOut" -out "$CertGenWorking\$UnProtectedPrivateKeyOut" 2>&1 | Out-Null
                    }
                }
                if ($StripPrivateKeyOfPassword -eq "Yes" -or $StripPrivateKeyOfPassword -eq "y") {
                    # Strip Private Key of Password
                    & "$PathToWin32OpenSSL\openssl.exe" rsa -in "$CertGenWorking\$ProtectedPrivateKeyOut" -out "$CertGenWorking\$UnProtectedPrivateKeyOut" 2>&1 | Out-Null
                }
            }
        }
    }

    # Create Global HashTable of Outputs for use in scripts that source this script
    $GenerateCertificateFileOutputHash = @{}
    $GenerateCertificateFileOutputHash.Add("CertificateRequestConfigFile", "$CertificateRequestConfigFile")
    $GenerateCertificateFileOutputHash.Add("CertificateRequestFile", "$CertificateRequestFile")
    $GenerateCertificateFileOutputHash.Add("CertFileOut", "$CertFileOut")
    if ($MachineKeySet -eq "FALSE") {
        $GenerateCertificateFileOutputHash.Add("PFXFileOut", "$PFXFileOut")
    }
    if (!$ADCSWebEnrollmentUrl) {
        $CertUtilResponseFile = (Get-Item "$CertGenWorking\*.rsp").Name
        $GenerateCertificateFileOutputHash.Add("CertUtilResponseFile", "$CertUtilResponseFile")

        $GenerateCertificateFileOutputHash.Add("CertificateChainOut", "$CertificateChainOut")
    }
    if ($ADCSWebEnrollmentUrl) {
        $GenerateCertificateFileOutputHash.Add("CertADCSWebResponseOutFile", "$CertADCSWebResponseOutFile")
    }
    if ($UseOpenSSL -eq "Yes") {
        $GenerateCertificateFileOutputHash.Add("AllPublicKeysInChainOut", "$AllPublicKeysInChainOut")

        # Make CertName vs Contents Key/Value Pair hashtable available to scripts that source this script
        $CertNamevsContentsHash = $CertNamevsContentsHash

        $AdditionalPublicKeysArray = (Get-Item "$CertGenWorking\*_Public_Cert.pem").Name
        # For each Certificate in the hashtable $CertNamevsContentsHash, determine it it's a Root, Intermediate, or End Entity
        foreach ($obj1 in $AdditionalPublicKeysArray) {
            $SubjectTypePrep = (certutil -dump $CertGenWorking\$obj1 | Select-String -Pattern "Subject Type=").Line
            if ($SubjectTypePrep) {
                $SubjectType = $SubjectTypePrep.Split("=")[-1].Trim()
            }
            else {
                $SubjectType = "End Entity"
            }
            $RootCertFlag = certutil -dump $CertGenWorking\$obj1 | Select-String -Pattern "Subject matches issuer"
            $EndPointCNFlag = certutil -dump $CertGenWorking\$obj1 | Select-String -Pattern "CN=$CertificateCN"
            if ($SubjectType -eq "CA" -and $RootCertFlag.Matches.Success -eq $true) {
                $RootCAPublicCertFile = $obj1
                $GenerateCertificateFileOutputHash.Add("RootCAPublicCertFile", "$RootCAPublicCertFile")
            }
            if ($SubjectType -eq "CA" -and $RootCertFlag.Matches.Success -ne $true) {
                $IntermediateCAPublicCertFile = $obj1
                $GenerateCertificateFileOutputHash.Add("IntermediateCAPublicCertFile", "$IntermediateCAPublicCertFile")
            }
            if ($SubjectType -eq "End Entity" -and $EndPointCNFlag.Matches.Success -eq $true) {
                $EndPointPublicCertFile = $obj1
                $GenerateCertificateFileOutputHash.Add("EndPointPublicCertFile", "$EndPointPublicCertFile")
            }
        }

        # Alternate Logic using .Net to Inspect Certificate files to Determine RootCA, Intermediate CA, and Endpoint
        <#
        foreach ($obj1 in $AdditionalPublicKeysArray) {
            $certPrint = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
            $certPrint.Import("$CertGenWorking\$obj1")
            if ($certPrint.Issuer -eq $certPrint.Subject) {
                $RootCAPublicCertFile = $obj1
                $RootCASubject = $certPrint.Subject
                $GenerateCertificateFileOutputHash.Add("RootCAPublicCertFile", "$RootCAPublicCertFile")
            }
        }
        foreach ($obj1 in $AdditionalPublicKeysArray) {
            $certPrint = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
            $certPrint.Import("$CertGenWorking\$obj1")
            if ($certPrint.Issuer -eq $RootCASubject -and $certPrint.Subject -ne $RootCASubject) {
                $IntermediateCAPublicCertFile = $obj1
                $IntermediateCASubject = $certPrint.Subject
                $GenerateCertificateFileOutputHash.Add("IntermediateCAPublicCertFile", "$IntermediateCAPublicCertFile")
            }
        }
        foreach ($obj1 in $AdditionalPublicKeysArray) {
            $certPrint = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
            $certPrint.Import("$CertGenWorking\$obj1")
            if ($certPrint.Issuer -eq $IntermediateCASubject) {
                $EndPointPublicCertFile = $obj1
                $EndPointSubject = $certPrint.Subject
                $GenerateCertificateFileOutputHash.Add("EndPointPublicCertFile", "$EndPointPublicCertFile")
            }
        }
        #>

        $GenerateCertificateFileOutputHash.Add("EndPointProtectedPrivateKey", "$ProtectedPrivateKeyOut")
    }
    if ($StripPrivateKeyOfPassword -eq "Yes" -or $StripPrivateKeyOfPassword -eq "y") {
        $GenerateCertificateFileOutputHash.Add("EndPointUnProtectedPrivateKey", "$UnProtectedPrivateKeyOut")

        # Add UnProtected Private Key to $CertNamevsContentsHash
        $UnProtectedPrivateKeyContent = ((Get-Content $CertGenWorking\$UnProtectedPrivateKeyOut) -join "`n").Trim()
        $CertNamevsContentsHash.Add("EndPointUnProtectedPrivateKey", "$UnProtectedPrivateKeyContent")
    }

    # Cleanup
    if ($LocationOfCertInStore) {
        Remove-Item $LocationOfCertInStore
    }

    # Return PSObject that contains $GenerateCertificateFileOutputHash and $CertNamevsContentsHash HashTables
    [pscustomobject]@{
        FileOutputHashTable       = $GenerateCertificateFileOutputHash
        CertNamevsContentsHash    = $CertNamevsContentsHash
    }

    $global:FunctionResult = "0"

    # ***IMPORTANT NOTE: If you want to write the Certificates contained in the $CertNamevsContentsHash out to files again
    # at some point in the future, make sure you use the "Out-File" cmdlet instead of the "Set-Content" cmdlet

    ##### END Generate Certificate Request and Submit to Issuing Certificate Authority #####

}

<#
    .SYNOPSIS
        Install OpenSSH-Win64. Optionally install the latest PowerShell Core Beta. Optionally create new SSH Key Pair.

    .DESCRIPTION
        See .SYNOPSIS

    .PARAMETER RemoveHostPrivateKeys
        OPTIONAL

        This parameter is a switch. Use it to remove the Host Private Keys after they are added to the ssh-agent during
        sshd setup/config. Default is NOT to remove the host private keys.

    .PARAMETER NewSSHKeyName
        OPTIONAL

        This parameter takes a string that represents the filename of the new SSH Key pair that you would like to create.
        This string is used in the filename of the private key file as well as the public key file (with the .pub extension).

    .PARAMETER NewSSHKeyPwd
        OPTIONAL

        This parameter takes a string that represents the password used to protect the new SSH Private Key.

    .PARAMETER NewSSHKeyPurpose
        OPTIONAL

        This parameter takes a string that represents the purpose of the new SSH Key Pair. It will be used in the
        "-C" (i.e. "comment") parameter of ssh-keygen.

    .PARAMETER SetupPowerShell6
        OPTIONAL

        This parameter is a switch. Use it to install the latest PowerShell 6 Beta.

        IMPORTANT NOTE: PowerShell 6 Beta is installed *alongside* existing PowerShell version.

    .EXAMPLE
        Install-WinSSH -NewSSHKeyName "testadmin-to-Debian8Jessie" -NewSSHKeyPurpose "testadmin-to-Debian8Jessie"

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
        [switch]$UsePowerShellGet,

        [Parameter(Mandatory=$False)]
        [switch]$UseChocolateyCmdLine,

        [Parameter(Mandatory=$False)]
        [switch]$GitHubInstall,

        [Parameter(Mandatory=$False)]
        [switch]$NoChocolateyCmdLine,

        [Parameter(Mandatory=$False)]
        [switch]$NoUpdatePackageManagement = $True,

        [Parameter(Mandatory=$False)]
        [switch]$SkipWinCapabilityAttempt,

        [Parameter(Mandatory=$False)]
        [switch]$Force
    )

    ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####

    if (!$(Check-Elevation)) {
        Write-Verbose "You must run PowerShell as Administrator before using this function! Halting!"
        Write-Error "You must run PowerShell as Administrator before using this function! Halting!"
        $global:FunctionResult = "1"
        return
    }

    if ($UsePowerShellGet -or $UseChocolateyCmdLine -or $GitHubInstall) {
        $SkipWinCapabilityAttempt = $True
    }

    if ($UsePowerShellGet -and $($UseChocolateyCmdLine -or $GitHubInstall)) {
        Write-Error "Please use EITHER the -UsePowerShellGet switch OR the -UseChocolateyCmdLine switch OR the -GitHubInstall switch. Halting!"
        $global:FunctionResult = "1"
        return
    }
    if ($UseChocolateyCmdLine -and $($UsePowerShellGet -or $GitHubInstall)) {
        Write-Error "Please use EITHER the -UseUseChocolateyCmdLine switch OR the -UsePowerShellGet switch OR the -GitHubInstall switch. Halting!"
        $global:FunctionResult = "1"
        return
    }
    if ($GitHubInstall -and $($UsePowerShellGet -or $UseChocolateyCmdLine)) {
        Write-Error "Please use EITHER the -GitHubInstall switch OR the -UsePowerShellGet switch OR the -UseChocolateyCmdLine switch. Halting!"
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
    if ($NoUpdatePackageManagement) {
        $InstallSSHAgentSplatParams.Add("NoUpdatePackageManagement",$True)
    }
    if ($UsePowerShellGet) {
        $InstallSSHAgentSplatParams.Add("UsePowerShellGet",$True)  
    }
    if ($UseChocolateyCmdLine) {
        $InstallSSHAgentSplatParams.Add("UseChocolateyCmdLine",$True)
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
        The Install-SSHAgentService is, in large part, carved out of the 'install-sshd.ps1' script bundled with
        an OpenSSH-Win64 install.

        Original authors (github accounts):

        @manojampalam - authored initial script
        @friism - Fixed issue with invalid SDDL on Set-Acl
        @manojampalam - removed ntrights.exe dependency
        @bingbing8 - removed secedit.exe dependency

#>
function Install-SSHAgentService {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [switch]$UseChocolateyCmdLine,

        [Parameter(Mandatory=$False)]
        [switch]$UsePowerShellGet,

        [Parameter(Mandatory=$False)]
        [switch]$GitHubInstall,

        [Parameter(Mandatory=$False)]
        [switch]$NoUpdatePackageManagement = $True,

        [Parameter(Mandatory=$False)]
        [switch]$SkipWinCapabilityAttempt,

        [Parameter(Mandatory=$False)]
        [switch]$Force
    )
    ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####

    if (!$(Check-Elevation)) {
        Write-Verbose "You must run PowerShell as Administrator before using this function! Halting!"
        Write-Error "You must run PowerShell as Administrator before using this function! Halting!"
        $global:FunctionResult = "1"
        return
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

    if ([Environment]::OSVersion.Version -lt [version]"10.0.17063" -or $AddWindowsCapabilityFailure -or $SkipWinCapabilityAttempt -or $Force) {
        # BEGIN OpenSSH Program Installation #

        if (!$GitHubInstall) {
            $InstallProgramSplatParams = @{
                ProgramName         = "OpenSSH"
                CommandName         = "ssh.exe"
                ErrorAction         = "SilentlyContinue"
                ErrorVariable       = "IPErr"
            }
            if ($NoUpdatePackageManagement) {
                $InstallProgramSplatParams.Add("NoUpdatePackageManagement",$True)
            }
            if ($Force) {
                $InstallProgramSplatParams.Add("Force",$True)
            }
            if ($UsePowerShellGet) {
                $InstallProgramSplatParams.Add("UsePowerShellGet",$True)  
            }
            elseif ($UseChocolateyCmdLine) {
                $InstallProgramSplatParams.Add("UseChocolateyCmdLine",$True)
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
                # We need the NTFSSecurity Module
                if ($(Get-Module -ListAvailable).Name -contains "NTFSSecurity") {
                    if ($(Get-Module NTFSSecurity).Name -notcontains "NTFSSecurity") {
                        $null = Import-Module NTFSSecurity
                    }
                }
                else {    
                    try {
                        $null = Install-Module -Name NTFSSecurity
                        $null = Import-Module NTFSSecurity
                    }
                    catch {
                        Write-Error $_
                        $global:FunctionResult = "1"
                        return
                    }
                }
    
                try {
                    $WinOpenSSHDLLink = $([String]$response.GetResponseHeader("Location")).Replace('tag','download') + "/$WinSSHFileNameSansExt.zip"
                    Write-Host "Downloading OpenSSH-Win64 from $WinOpenSSHDLLink..."
                    Invoke-WebRequest -Uri $WinOpenSSHDLLink -OutFile "$HOME\Downloads\$WinSSHFileNameSansExt.zip"
                    # NOTE: OpenSSH-Win64.zip contains a folder OpenSSH-Win64, so no need to create one before extraction
                    $null = Unzip-File -PathToZip "$HOME\Downloads\$WinSSHFileNameSansExt.zip" -TargetDir "$HOME\Downloads"
                    if (Test-Path "$env:ProgramFiles\$WinSSHFileNameSansExt") {
                        Get-Service ssh-agent -ErrorAction SilentlyContinue | Stop-Service -ErrorAction SilentlyContinue
                        Get-Service sshd -ErrorAction SilentlyContinue | Stop-Service -ErrorAction SilentlyContinue
                        Get-Process -Name ssh-keygen -ErrorAction SilentlyContinue | Stop-Process -ErrorAction SilentlyContinue

                        Remove-Item "$env:ProgramFiles\$WinSSHFileNameSansExt" -Recurse -Force
                    }
                    Move-Item "$HOME\Downloads\$WinSSHFileNameSansExt" "$env:ProgramFiles\$WinSSHFileNameSansExt"
                    Enable-NTFSAccessInheritance -Path "$env:ProgramFiles\$WinSSHFileNameSansExt" -RemoveExplicitAccessRules
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

        # END OpenSSH Program Installation #

        $OpenSSHWinPath = "$env:ProgramFiles\OpenSSH-Win64"
        if (!$(Test-Path $OpenSSHWinPath)) {
            Write-Error "The path $OpenSSHWinPath does not exist! Halting!"
            $global:FunctionResult = "1"
            return
        }
        #$sshdpath = Join-Path $OpenSSHWinPath "sshd.exe"
        $sshagentpath = Join-Path $OpenSSHWinPath "ssh-agent.exe"
        $sshdir = "$env:ProgramData\ssh"
        $logsdir = Join-Path $sshdir "logs"

        try {
            if ([bool]$(Get-Service ssh-agent -ErrorAction SilentlyContinue)) {
                Write-Host "Recreating ssh-agent service..."
                Stop-Service ssh-agent
                sc.exe delete ssh-agent 1>$null
            }

            New-Service -Name ssh-agent -BinaryPathName "$sshagentpath" -Description "SSH Agent" -StartupType Automatic | Out-Null
            # pldmgg NOTE: I have no idea about the below...ask the original authors...
            cmd.exe /c 'sc.exe sdset ssh-agent D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)(A;;RP;;;AU)' 1>$null
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            return
        }

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
    }

    Write-Host -ForegroundColor Green "The ssh-agent service was successfully installed! Starting the service..."
    Start-Service ssh-agent -Passthru
}


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

    ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####

    if (!$(Check-Elevation)) {
        Write-Verbose "You must run PowerShell as Administrator before using this function! Halting!"
        Write-Error "You must run PowerShell as Administrator before using this function! Halting!"
        $global:FunctionResult = "1"
        return
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
            $OpenSSHWinPath = "$env:ProgramFiles\OpenSSH-Win64"
            $sshdpath = Join-Path $OpenSSHWinPath "sshd.exe"
            $sshdir = "$env:ProgramData\ssh"
            $logsdir = Join-Path $sshdir "logs"
            $sshdConfigPath = Join-Path $sshdir "sshd_config"

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

                $PubPrivKeyPairFiles = Get-ChildItem -Path $sshdir | Where-Object {$_.CreationTime -gt (Get-Date).AddSeconds(-5) -and $_.Name -match "ssh_host"}
                $PubKeys = $PubPrivKeyPairFiles | Where-Object {$_.Extension -eq ".pub"}
                $PrivKeys = $PubPrivKeyPairFiles | Where-Object {$_.Extension -ne ".pub"}
            }
            catch {
                Write-Error $_
                $global:FunctionResult = "1"
                return
            }
        }
    }
    
    if ([Environment]::OSVersion.Version -lt [version]"10.0.17063" -or $AddWindowsCapabilityFailure -or $SkipWinCapabilityAttempt) {
        $OpenSSHWinPath = "$env:ProgramFiles\OpenSSH-Win64"
        if (!$(Test-Path $OpenSSHWinPath)) {
            try {
                $InstallSSHAgentResult = Install-SSHAgentService -ErrorAction SilentlyContinue -ErrorVariable ISAErr
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
        $sshdpath = Join-Path $OpenSSHWinPath "sshd.exe"
        if (!$(Test-Path $sshdpath)) {
            Write-Error "The path $sshdpath does not exist! Halting!"
            $global:FunctionResult = "1"
            return
        }
        $sshagentpath = Join-Path $OpenSSHWinPath "ssh-agent.exe"
        $sshdir = "$env:ProgramData\ssh"
        $logsdir = Join-Path $sshdir "logs"

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

        try {
            if (Get-Service sshd -ErrorAction SilentlyContinue) {
               Stop-Service sshd
               sc.exe delete sshd 1>$null
            }
    
            New-Service -Name sshd -BinaryPathName "$sshdpath" -Description "SSH Daemon" -StartupType Manual | Out-Null
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            return
        }

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
        
        $PubPrivKeyPairFiles = Get-ChildItem -Path $sshdir | Where-Object {$_.CreationTime -gt (Get-Date).AddSeconds(-5) -and $_.Name -match "ssh_host"}
        $PubKeys = $PubPrivKeyPairFiles | Where-Object {$_.Extension -eq ".pub"}
        $PrivKeys = $PubPrivKeyPairFiles | Where-Object {$_.Extension -ne ".pub"}
        # $PrivKeys = $PubPrivKeyPairFiles | foreach {if ($PubKeys -notcontains $_) {$_}}
        
        Start-Service ssh-agent
        Start-Sleep -Seconds 5

        if ($(Get-Service "ssh-agent").Status -ne "Running") {
            Write-Error "The ssh-agent service did not start succesfully! Please check your config! Halting!"
            $global:FunctionResult = "1"
            return
        }
        
        foreach ($PrivKey in $PrivKeys) {
            $SSHAddProcessInfo = New-Object System.Diagnostics.ProcessStartInfo
            $SSHAddProcessInfo.WorkingDirectory = $sshdir
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
                if ($RemoveHostPrivateKeys) {
                    Remove-Item $PrivKey
                }
            }

            # Need to remove the above variables before next loop...
            # TODO: Make the below not necessary...
            $VariablesToRemove = @("SSHAddProcessInfo","SSHAddProcess","SSHAddStdout","SSHAddStderr","SSHAddAllOutput")
            foreach ($VarName in $VariablesToRemove) {
                Remove-Variable -Name $VarName
            }
        }

        $null = Set-Service ssh-agent -StartupType Automatic
        $null = Set-Service sshd -StartupType Automatic

        # IMPORTANT: It is important that File Permissions are "Fixed" at the end (as opposed to earlier in this function),
        # otherwise previous steps break
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
    }

    # Make sure PowerShell Core is Installed
    if (![bool]$(Get-Command pwsh -ErrorAction SilentlyContinue)) {
        # Search for pwsh.exe where we expect it to be
        $PotentialPwshExes = Get-ChildItem "$env:ProgramFiles\Powershell" -Recurse -File -Filter "*pwsh.exe"
        if (!$PotentialPwshExes) {
            try {
                Update-PowerShellCore -Latest -DownloadDirectory "$HOME\Downloads" -ErrorAction Stop
            }
            catch {
                Write-Error $_
                $global:FunctionResult = "1"
                return
            }
        }
        $PotentialPwshExes = Get-ChildItem "$env:ProgramFiles\Powershell" -Recurse -File -Filter "*pwsh.exe"
        if (!$PotentialPwshExes) {
            Write-Error "Unable to find pwsh.exe! Halting!"
            $global:FunctionResult = "1"
            return
        }
        $LatestLocallyAvailablePwsh = [array]$($PotentialPwshExes.VersionInfo | Sort-Object -Property ProductVersion)[-1].FileName
        $LatestPwshParentDir = [System.IO.Path]::GetDirectoryName($LatestLocallyAvailablePwsh)

        if ($($env:Path -split ";") -notcontains $LatestPwshParentDir) {
            # TODO: Clean out older pwsh $env:Path entries if they exist...
            $env:Path = "$LatestPwshParentDir;$env:Path"
        }
    }
    if (![bool]$(Get-Command pwsh -ErrorAction SilentlyContinue)) {
        Write-Error "Unable to find pwsh.exe! Please check your `$env:Path! Halting!"
        $global:FunctionResult = "1"
        return
    }

    $PowerShellCorePath = $(Get-Command pwsh).Source
    $PowerShellCorePathWithForwardSlashes = $PowerShellCorePath -replace "\\","/"

    ##### END Variable/Parameter Transforms and PreRun Prep #####


    ##### BEGIN Main Body #####

    # Subsystem instructions: https://github.com/PowerShell/PowerShell/tree/master/demos/SSHRemoting#setup-on-windows-machine
    [System.Collections.ArrayList]$sshdContent = Get-Content $sshdConfigPath
    if (![bool]$($sshdContent -match "Subsystem    powershell    $PowerShellCorePathWithForwardSlashes -sshs -NoLogo -NoProfile")) {
        $InsertAfterThisLine = $sshdContent -match "sftp"
        $InsertOnThisLine = $sshdContent.IndexOf($InsertAfterThisLine)+1
        $sshdContent.Insert($InsertOnThisLine, "Subsystem    powershell    $PowerShellCorePathWithForwardSlashes -sshs -NoLogo -NoProfile")
        Set-Content -Value $sshdContent -Path $sshdConfigPath
    }

    if ($DefaultShell) {
        if ($DefaultShell -eq "powershell") {
            $ForceCommandOptionLine = "ForceCommand powershell.exe -NoProfile"
        }
        if ($DefaultShell -eq "pwsh") {
            $PotentialPwshExes = Get-ChildItem "$env:ProgramFiles\Powershell" -Recurse -File -Filter "*pwsh.exe"
            $LatestLocallyAvailablePwsh = [array]$($PotentialPwshExes.VersionInfo | Sort-Object -Property ProductVersion)[-1].FileName

            $ForceCommandOptionLine = "ForceCommand `"$LatestLocallyAvailablePwsh`" -NoProfile"
        }

        [System.Collections.ArrayList]$sshdContent = Get-Content $sshdConfigPath

        # Determine if sshd_config already has the 'ForceCommand' option active
        $ExistingForceCommandOption = $sshdContent -match "ForceCommand" | Where-Object {$_ -notmatch "#"}

        # Determine if sshd_config already has 'Match User' option active
        $ExistingMatchUserOption = $sshdContent -match "Match User" | Where-Object {$_ -notmatch "#"}
        
        if (!$ExistingForceCommandOption) {
            # If sshd_config already has the 'Match User' option available, don't touch it, else add it with ForceCommand
            try {
                if (!$ExistingMatchUserOption) {
                    Add-Content -Value "Match User *`n$ForceCommandOptionLine" -Path $sshdConfigPath
                }
                else {
                    Add-Content -Value "$ForceCommandOptionLine" -Path $sshdConfigPath
                }
            }
            catch {
                Write-Error $_
                $global:FunctionResult = "1"
                return
            }
        }
        else {
            if ($ExistingForceCommandOption -ne $ForceCommandOptionLine) {
                if (!$ExistingMatchUserOption) {
                    $UpdatedSSHDConfig = $sshdContent -replace [regex]::Escape($ExistingForceCommandOption),"Match User *`n$ForceCommandOptionLine"
                }
                else {
                    $UpdatedSSHDConfig = $sshdContent -replace [regex]::Escape($ExistingForceCommandOption),"$ForceCommandOptionLine"
                }
                
                try {
                    Set-Content -Value $UpdatedSSHDConfig -Path $sshdConfigPath
                }
                catch {
                    Write-Error $_
                    $global:FunctionResult = "1"
                    return
                }
            }
        }
    }

    # Make sure port 22 is open
    if (!$(Test-Port -Port 22).Open) {
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

    Start-Service sshd
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

        if ($(Get-Service sshd).Status -ne "Running") {
            Write-Error "The sshd service did not start succesfully (within 5 seconds)! Please check your sshd_config configuration. Halting!"
            $global:FunctionResult = "1"
            return
        }
    }

    [pscustomobject]@{
        SSHDServiceStatus       = $(Get-Service sshd).Status
        SSHAgentServiceStatus   = $(Get-Service ssh-agent).Status
        PublicKeysPaths         = $PubKeys.FullName
        PrivateKeysPaths        = $PrivKeys.FullName
    }
}

function Set-DefaultShell {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [ValidateSet("powershell","pwsh")]
        [string]$DefaultShell
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

    if ($DefaultShell -eq "powershell") {
        $ForceCommandOptionLine = "ForceCommand powershell.exe -NoProfile"
    }
    if ($DefaultShell -eq "pwsh") {
        # Search for pwsh.exe where we expect it to be
        $PotentialPwshExes = Get-ChildItem "$env:ProgramFiles\Powershell" -Recurse -File -Filter "*pwsh.exe"
        if (!$PotentialPwshExes) {
            try {
                Update-PowerShellCore -Latest -DownloadDirectory "$HOME\Downloads" -ErrorAction Stop
            }
            catch {
                Write-Error $_
                $global:FunctionResult = "1"
                return
            }
        }
        $PotentialPwshExes = Get-ChildItem "$env:ProgramFiles\Powershell" -Recurse -File -Filter "*pwsh.exe"
        if (!$PotentialPwshExes) {
            Write-Error "Unable to find pwsh.exe! Halting!"
            $global:FunctionResult = "1"
            return
        }

        $LatestLocallyAvailablePwsh = [array]$($PotentialPwshExes.VersionInfo | Sort-Object -Property ProductVersion)[-1].FileName
        $LatestPwshParentDir = [System.IO.Path]::GetDirectoryName($LatestLocallyAvailablePwsh)

        if ($($env:Path -split ";") -notcontains $LatestPwshParentDir) {
            # TODO: Clean out older pwsh $env:Path entries if they exist...
            $env:Path = "$LatestPwshParentDir;$env:Path"
        }

        $ForceCommandOptionLine = "ForceCommand `"$LatestLocallyAvailablePwsh`" -NoProfile"
    }

    [System.Collections.ArrayList]$sshdContent = Get-Content $sshdConfigPath

    # Determine if sshd_config already has the 'ForceCommand' option active
    $ExistingForceCommandOption = $sshdContent -match "ForceCommand" | Where-Object {$_ -notmatch "#"}

    # Determine if sshd_config already has 'Match User' option active
    $ExistingMatchUserOption = $sshdContent -match "Match User" | Where-Object {$_ -notmatch "#"}
    
    if (!$ExistingForceCommandOption) {
        # If sshd_config already has the 'Match User' option available, don't touch it, else add it with ForceCommand
        try {
            if (!$ExistingMatchUserOption) {
                Add-Content -Value "Match User *`n$ForceCommandOptionLine" -Path $sshdConfigPath
            }
            else {
                Add-Content -Value "$ForceCommandOptionLine" -Path $sshdConfigPath
            }

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
}

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

    if (!$(Check-Elevation)) {
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
            $RemoteHostNetworkInfo = Resolve-Host -HostNameOrIP $RemoteHost -ErrorAction Stop
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
                Unzip-File -PathToZip "$HOME\PoshAwait.zip" -TargetDir "$tempDirectory"
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
        $RemoteHostNetworkInfo = Resolve-Host -HostNameOrIP $RemoteHost -ErrorAction Stop
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
    ssh -o "StrictHostKeyChecking=no" -o "BatchMode=yes" -t $RemoteHostUserName@$RemoteHostLocation "echo '$PubKeyContent' >> ~/.ssh/authorized_keys"

    ##### END Main Body #####
}


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

        $NewFolderInDownloadDir = New-UniqueString -ArrayOfStrings $(Get-ChildItem "$HOME\Downloads" -Directory).Name -PossibleNewUniqueString "OpenSSH_PowerShell_Utils"

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

# Function should be run on SSH Client Machine as part of Sign-SSHUserPublicKey function
# In this function, in order to test if we have a valid Private Key, and if that Private Key
# is password protected, we try and generate a Public Key from it using ssh-keygen
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

function Get-SSHFileInfo {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [string]$PathToKeyFile
    )

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

    if ($SSHKeyGenOutput -match "(RSA-CERT)") {
        $PublicKeyCertInfo = ssh-keygen -L -f "$PathToKeyFile"
        $PublicKeyCertContent = Get-Content $PathToKeyFile
        $FingerPrint = ssh-keygen -l -f "$PathToKeyFile"
        $IsPublicKeyCert = $True
    }
    elseif ($SSHKeyGenOutput -match "(RSA)") {
        # It could be either a Public Key or Private Key
        $PrivateKeyAttempt = Validate-SSHPrivateKey -PathToPrivateKeyFile $PathToKeyFile
        if (!$PrivateKeyAttempt.ValidSSHPrivateKeyFormat) {
            $IsPublicKey = $True
            $PublicKeyContent = Get-Content $PathToKeyFile
            $PublicKeyInfo = $FingerPrint = ssh-keygen -l -f "$PathToKeyFile"
        }
        else {
            $IsPrivateKey = $True
            $PrivateKeyContent = $PrivateKeyInfo = Get-Content $PathToKeyFile
            $FingerPrint = ssh-keygen -l -f "$PathToKeyFile"
            $PasswordProtected = $PrivateKeyAttempt.PasswordProtected
        }
    }
    elseif ($SSHKeyGenOutput -match "passphrase|pass phrase" -or $($SSHKeyGenOutput -eq $null -and $ProcessKilled)) {
        $IsPrivateKey = $True
        $PrivateKeyContent = $PrivateKeyInfo = Get-Content $PathToKeyFile
        $PasswordProtected = $True
    }
    elseif ($(Get-Content $PathToKeyFile)[0] -match "SSH2") {
        [pscustomobject]@{
            File                = $PathToKeyFile
            FileType            = "SSH2_RFC4716"
            Contents            = $(Get-Content $PathToKeyFile)
            Info                = $(Get-Content $PathToKeyFile)
            FingerPrint         = $null
            PasswordProtected   = $null
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

function Generate-SSHUserDirFileInfo {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [string]$PathToHomeDotSSHDirectory
    )

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
    $ArrayOfPSObjects | Export-CliXml "$HOME\.ssh\SSHDirectoryFileInfo.xml"
}

# This function should be run on the SSH Client Machine - i.e. the machine that generated the user ssh key pair via:
#     ssh-keygen -t rsa -b 2048 -f "$HOME\.ssh\ToWin10LatestB1" -q -C "ToWin10LatestB1"
function Sign-SSHUserPublicKey {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [string]$VaultSSHClientSigningUrl, # Should be something like "http://192.168.2.12:8200/v1//ssh-client-signer/sign/clientrole"

        [Parameter(Mandatory=$True)]
        [string]$VaultAuthToken, # Should be something like 'myroot' or '434f37ca-89ae-9073-8783-087c268fd46f'

        [Parameter(Mandatory=$True)]
        [ValidatePattern("[\w]+@[\w]+")]
        [string[]]$AuthorizedUserPrincipals, # Should be in format <User>@<HostNameOrDomainPrefix> - and can be an array of strings

        [Parameter(Mandatory=$True)]
        [ValidatePattern("\.pub")]
        [string]$PathToSSHUserPublicKeyFile,

        [Parameter(Mandatory=$False)]
        [string]$PathToSSHUserPrivateKeyFile,

        [Parameter(Mandatory=$False)]
        [switch]$AddToSSHAgent
    )

    if (!$(Test-Path $PathToSSHUserPublicKeyFile)) {
        Write-Error "The path '$PathToSSHUserPublicKeyFile' was not found! Halting!"
        $global:FunctionResult = "1"
        return
    }

    if ($PathToSSHUserPrivateKeyFile) {
        $CorrespondingPrivateKeyPath = $PathToSSHUserPrivateKeyFile
    }
    else {
        $CorrespondingPrivateKeyPath = $PathToSSHUserPublicKeyFile -replace "\.pub",""
    }

    if (!$(Test-Path $CorrespondingPrivateKeyPath)) {
        Write-Error "Unable to find expected path to corresponding private key, i.e. '$CorrespondingPrivateKeyPath'! Halting!"
        $global:FunctionResult = "1"
        return
    }

    $SignedPubKeyCertFilePath = $PathToSSHUserPublicKeyFile -replace "\.pub","-cert.pub"
    
    # Check to make sure the user private key isn't password protected. If it is, things break
    # with current Windows OpenSSH implementation
    try {
        $ValidateSSHPrivateKeyResult = Validate-SSHPrivateKey -PathToPrivateKeyFile $CorrespondingPrivateKeyPath -ErrorAction Stop
        if (!$ValidateSSHPrivateKeyResult) {throw "There was a problem with the Validate-SSHPrivateKey function! Halting!"}

        if (!$ValidateSSHPrivateKeyResult.ValidSSHPrivateKeyFormat) {
            throw "'$CorrespondingPrivateKeyPath' is not in a valid format! Double check with: ssh-keygen -y -f `"$CorrespondingPrivateKeyPath`""
        }
        if ($ValidateSSHPrivateKeyResult.PasswordProtected) {
            throw "'$CorrespondingPrivateKeyPath' is password protected! This breaks the current implementation of OpenSSH on Windows. Halting!"
        }
    }
    catch {
        Write-Error $_
        $global:FunctionResult = "1"
        return
    }

    # Make sure $VaultSSHClientSigningUrl is a valid Url
    try {
        $UriObject = [uri]$VaultSSHClientSigningUrl
    }
    catch {
        Write-Error $_
        $global:FunctionResult = "1"
        return
    }

    if (![bool]$($UriObject.Scheme -match "http")) {
        Write-Error "'$VaultSSHClientSigningUrl' does not appear to be a URL! Halting!"
        $global:FunctionResult = "1"
        return
    }

    # If $VaultSSHClientSigningUrl ends in '/', remove it
    if ($VaultSSHClientSigningUrl[-1] -eq "/") {
        $VaultSSHClientSigningUrl = $VaultSSHClientSigningUrl.Substring(0,$VaultSSHClientSigningUrl.Length-1)
    }

    ##### BEGIN Main Body #####

    # HTTP API Request
    $PubKeyContent = Get-Content $PathToSSHUserPublicKeyFile
    $ValidPrincipalsCommaSeparated = $AuthorizedUserPrincipals -join ','
    # In the below JSON, <HostNameOrDomainPre> - Use the HostName if user is a Local Account and the DomainPre if the user
    # is a Domain Account
    $jsonRequest = @"
{
    "cert_type": "user",
    "valid_principals": "$ValidPrincipalsCommaSeparated",
    "extension": {
        "permit-pty": "",
        "permit-agent-forwarding": ""
    },
    "public_key": "$PubKeyContent"
}
"@
    $JsonRequestAsSingleLineString = $jsonRequest | ConvertFrom-Json | ConvertTo-Json -Compress

    $HeadersParameters = @{
        "X-Vault-Token" = $VaultAuthToken
    }
    $IWRSplatParams = @{
        Uri         = $VaultSSHClientSigningUrl
        Headers     = $HeadersParameters
        Body        = $JsonRequestAsSingleLineString
        Method      = "Post"
    }

    $SignedSSHClientPubKeyCertResponse = Invoke-WebRequest @IWRSplatParams
    Set-Content -Value $($SignedSSHClientPubKeyCertResponse.Content | ConvertFrom-Json).data.signed_key.Trim() -Path $SignedPubKeyCertFilePath

    if ($AddToSSHAgent) {
        # Push/Pop-Location probably aren't necessary...but just in case...
        Push-Location $($CorrespondingPrivateKeyPath | Split-Path -Parent)
        ssh-add "$CorrespondingPrivateKeyPath"
        Pop-Location
        $AddedToSSHAgent = $True
    }

    $Output = @{
        SignedCertFile      = $(Get-Item $SignedPubKeyCertFilePath)
    }
    if ($AddedToSSHAgent) {
        $Output.Add("AddedToSSHAgent",$True)
    }

    [pscustomobject]$Output
}

# This function should be run on BOTH SSH Client AND SSHD Server Machines
function Sign-SSHHostPublicKey {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [string]$VaultSSHHostSigningUrl, # Should be something like "http://192.168.2.12:8200/v1/ssh-host-signer/sign/hostrole"

        [Parameter(Mandatory=$True)]
        [string]$VaultAuthToken # Should be something like 'myroot' or '434f37ca-89ae-9073-8783-087c268fd46f'
    )

    # Make sure sshd service is installed and running. If it is, we shouldn't need to use
    # the New-SSHD server function
    if (![bool]$(Get-Service sshd -ErrorAction SilentlyContinue)) {
        if (![bool]$(Get-Service ssh-agent -ErrorAction SilentlyContinue)) {
            $InstallWinSSHSplatParams = @{
                GiveWinSSHBinariesPathPriority  = $True
                ConfigureSSHDOnLocalHost        = $True
                DefaultShell                    = "powershell"
                GitHubInstall                   = $True
                ErrorAction                     = "SilentlyContinue"
                ErrorVariable                   = "IWSErr"
            }

            try {
                $InstallWinSSHResults = Install-WinSSH @InstallWinSSHSplatParams -ErrorAction Stop
                if (!$InstallWinSSHResults) {throw "There was a problem with the Install-WinSSH function! Halting!"}
            }
            catch {
                Write-Error $_
                Write-Host "Errors for the Install-WinSSH function are as follows:"
                Write-Error $($IWSErr | Out-String)
                $global:FunctionResult = "1"
                return
            }
        }
        else {
            $NewSSHDServerSplatParams = @{
                ErrorAction         = "SilentlyContinue"
                ErrorVariable       = "SSHDErr"
                DefaultShell        = "powershell"
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
    }

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

    $PathToSSHHostPublicKeyFile = "$sshdir\ssh_host_rsa_key.pub"

    if (!$(Test-Path $PathToSSHHostPublicKeyFile)) {
        Write-Error "Unable to find the SSH RSA Host Key for $env:ComputerName at path '$sshdir\ssh_host_rsa_key.pub'! Halting!"
        $global:FunctionResult = "1"
        return
    }
    
    $SignedPubKeyCertFilePath = $PathToSSHHostPublicKeyFile -replace "\.pub","-cert.pub"

    # Make sure $VaultSSHHostSigningUrl is a valid Url
    try {
        $UriObject = [uri]$VaultSSHHostSigningUrl
    }
    catch {
        Write-Error $_
        $global:FunctionResult = "1"
        return
    }

    if (![bool]$($UriObject.Scheme -match "http")) {
        Write-Error "'$VaultSSHHostSigningUrl' does not appear to be a URL! Halting!"
        $global:FunctionResult = "1"
        return
    }

    # If $VaultSSHHostSigningUrl ends in '/', remove it
    if ($VaultSSHHostSigningUrl[-1] -eq "/") {
        $VaultSSHHostSigningUrl = $VaultSSHHostSigningUrl.Substring(0,$VaultSSHHostSigningUrl.Length-1)
    }

    ##### BEGIN Main Body #####

    # HTTP API Request
    $PubKeyContent = Get-Content $PathToSSHHostPublicKeyFile

    $jsonRequest = @"
{
    "cert_type": "host",
    "extension": {
      "permit-pty": "",
      "permit-agent-forwarding": ""
    },
    "public_key": "$PubKeyContent"
  }
"@
    $JsonRequestAsSingleLineString = $jsonRequest | ConvertFrom-Json | ConvertTo-Json -Compress

    $HeadersParameters = @{
        "X-Vault-Token" = $VaultAuthToken
    }
    $IWRSplatParams = @{
        Uri         = $VaultSSHHostSigningUrl
        Headers     = $HeadersParameters
        Body        = $JsonRequestAsSingleLineString
        Method      = "Post"
    }

    $SignedSSHClientPubKeyCertResponse = Invoke-WebRequest @IWRSplatParams
    Set-Content -Value $($SignedSSHClientPubKeyCertResponse.Content | ConvertFrom-Json).data.signed_key.Trim() -Path $SignedPubKeyCertFilePath

    # Make sure permissions on "$sshdir/ssh_host_rsa_key-cert.pub" are set properly
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

    $SecurityDescriptor = Get-NTFSSecurityDescriptor -Path $SignedPubKeyCertFilePath
    $SecurityDescriptor | Disable-NTFSAccessInheritance -RemoveInheritedAccessRules
    $SecurityDescriptor | Clear-NTFSAccess
    $SecurityDescriptor | Add-NTFSAccess -Account "NT AUTHORITY\SYSTEM" -AccessRights "FullControl" -AppliesTo ThisFolderSubfoldersAndFiles
    $SecurityDescriptor | Add-NTFSAccess -Account "Administrators" -AccessRights "FullControl" -AppliesTo ThisFolderSubfoldersAndFiles
    $SecurityDescriptor | Add-NTFSAccess -Account "NT AUTHORITY\Authenticated Users" -AccessRights "ReadAndExecute, Synchronize" -AppliesTo ThisFolderSubfoldersAndFiles
    $SecurityDescriptor | Set-NTFSSecurityDescriptor

    # Update sshd_config
    [System.Collections.ArrayList]$sshdContent = Get-Content $sshdConfigPath

    # Determine if sshd_config already has the 'HostCertificate' option active
    $ExistingHostCertificateOption = $sshdContent -match "HostCertificate" | Where-Object {$_ -notmatch "#"}
    $HostCertificatePathWithForwardSlashes = "$sshdir\ssh_host_rsa_key-cert.pub" -replace "\\","/"
    $HostCertificateOptionLine = "HostCertificate $HostCertificatePathWithForwardSlashes"
    
    if (!$ExistingHostCertificateOption) {
        try {
            $LineNumberToInsertOn = $sshdContent.IndexOf($($sshdContent -match "HostKey __PROGRAMDATA__/ssh/ssh_host_rsa_key")) + 1
            [System.Collections.ArrayList]$sshdContent.Insert($LineNumberToInsertOn, $HostCertificateOptionLine)
            Set-Content -Value $sshdContent -Path $sshdConfigPath
            $SSHDConfigContentChanged = $True
            [System.Collections.ArrayList]$sshdContent = Get-Content $sshdConfigPath
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            return
        }
    }
    else {
        if ($ExistingHostCertificateOption -ne $HostCertificateOptionLine) {
            $UpdatedSSHDConfig = $sshdContent -replace [regex]::Escape($ExistingHostCertificateOption),"$HostCertificateOptionLine"

            try {
                Set-Content -Value $UpdatedSSHDConfig -Path $sshdConfigPath
                $SSHDConfigContentChanged = $True
                [System.Collections.ArrayList]$sshdContent = Get-Content $sshdConfigPath
            }
            catch {
                Write-Error $_
                $global:FunctionResult = "1"
                return
            }
        }
        else {
            Write-Warning "The specified 'HostCertificate' option is already active in the the sshd_config file. No changes made."
        }
    }

    [pscustomobject]@{
        SignedPubKeyCertFile        = Get-Item $SignedPubKeyCertFilePath
        SSHDConfigContentChanged    = if ($SSHDConfigContentChanged) {$True} else {$False}
        SSHDContentThatWasAdded     = if ($SSHDConfigContentChanged) {$HostCertificateOptionLine}
    }
}

# This function should be run on BOTH SSH Client AND SSHD Server Machines
# Output is a PSCustomObject with property [System.Collections.ArrayList] FilesUpdated and property
# [System.IO.FileInfo] SignSSHHostKeyResult
function Add-CAPubKeyToSSHAndSSHDConfig {
    [CmdletBinding(DefaultParameterSetName='VaultUrl')]
    Param(
        # NOTE: When reading 'PathToPublicKeyOfCAUsedToSign', please note that it is actually the CA's
        # **private key** that is used to do the signing. We just require the CA's public key to verify
        # that presented user keys signed by the CA's private key were, in fact, signed by the CA's private key
        [Parameter(Mandatory=$False)]
        [string]$PublicKeyOfCAUsedToSignUserKeysFilePath,

        [Parameter(Mandatory=$False)]
        [string]$PublicKeyOfCAUsedToSignUserKeysAsString,

        [Parameter(Mandatory=$False)]
        [string]$PublicKeyOfCAUsedToSignUserKeysVaultUrl, # Should be something like: http://192.168.2.12:8200/v1/ssh-client-signer/public_key

        [Parameter(Mandatory=$False)]
        [string]$PublicKeyOfCAUsedToSignHostKeysFilePath,

        [Parameter(Mandatory=$False)]
        [string]$PublicKeyOfCAUsedToSignHostKeysAsString,

        [Parameter(Mandatory=$False)]
        [string]$PublicKeyOfCAUsedToSignHostKeysVaultUrl, # Should be something like: http://192.168.2.12:8200/v1/ssh-host-signer/public_key

        [Parameter(Mandatory=$False)]
        [ValidatePattern("[\w]+@[\w]+")]
        [string[]]$AuthorizedUserPrincipals,

        [Parameter(Mandatory=$False)]
        [ValidateSet("AllUsers","LocalAdmins","LocalUsers","DomainAdmins","DomainUsers")]
        [string[]]$AuthorizedPrincipalsUserGroup,

        # Use the below $VaultSSHHostSigningUrl and $VaultAuthToken parameters if you want
        # C:\ProgramData\ssh\ssh_host_rsa_key.pub signed by the Vault Host Signing CA. This is highly recommended.
        [Parameter(Mandatory=$False)]
        [string]$VaultSSHHostSigningUrl, # Should be something like http://192.168.2.12:8200/v1/ssh-host-signer/sign/hostrole"

        [Parameter(Mandatory=$False)]
        [string]$VaultAuthToken
    )

    if ($($PSBoundParameters.Keys -match "UserKeys").Count -gt 1) {
        $ErrMsg = "The $($MyInvocation.MyCommand.Name) only takes one of the following parameters: " +
        "-PublicKeyOfCAUsedToSignUserKeysFilePath, -PublicKeyOfCAUsedToSignUserKeysAsString, -PublicKeyOfCAUsedToSignUserKeysVaultUrl"
        Write-Error $ErrMsg
    }
    if ($($PSBoundParameters.Keys -match "UserKeys").Count -eq 0) {
        $ErrMsg = "The $($MyInvocation.MyCommand.Name) MUST use one of the following parameters: " +
        "-PublicKeyOfCAUsedToSignUserKeysFilePath, -PublicKeyOfCAUsedToSignUserKeysAsString, -PublicKeyOfCAUsedToSignUserKeysVaultUrl"
        Write-Error $ErrMsg
    }

    if ($($PSBoundParameters.Keys -match "HostKeys").Count -gt 1) {
        $ErrMsg = "The $($MyInvocation.MyCommand.Name) only takes one of the following parameters: " +
        "-PublicKeyOfCAUsedToSignHostKeysFilePath, -PublicKeyOfCAUsedToSignHostKeysAsString, -PublicKeyOfCAUsedToSignHostKeysVaultUrl"
        Write-Error $ErrMsg
    }
    if ($($PSBoundParameters.Keys -match "HostKeys").Count -eq 0) {
        $ErrMsg = "The $($MyInvocation.MyCommand.Name) MUST use one of the following parameters: " +
        "-PublicKeyOfCAUsedToSignHostKeysFilePath, -PublicKeyOfCAUsedToSignHostKeysAsString, -PublicKeyOfCAUsedToSignHostKeysVaultUrl"
        Write-Error $ErrMsg
    }

    if (!$AuthorizedUserPrincipals -and !$AuthorizedPrincipalsUserGroup) {
        $AuthPrincErrMsg = "The $($MyInvocation.MyCommand.Name) function requires one of the following parameters: " +
        "-AuthorizedUserPrincipals, -AuthorizedPrincipalsUserGroup"
        Write-Error $AuthPrincErrMsg
        $global:FunctionResult = "1"
        return
    }

    if ($($VaultSSHHostSigningUrl -and !$VaultAuthToken) -or $(!$VaultSSHHostSigningUrl -and $VaultAuthToken)) {
        $ErrMsg = "If you would like this function to facilitate signing $env:ComputerName's ssh_host_rsa_key.pub, " +
        "both -VaultSSHHostSigningUrl and -VaultAuthToken parameters are required! Halting!"
        Write-Error $ErrMsg
        $global:FunctionResult = "1"
        return
    }

    # Setup our $Output Hashtable which we will add to as necessary as we go
    [System.Collections.ArrayList]$FilesUpdated = @()
    $Output = @{
        FilesUpdated = $FilesUpdated
    }


    # Make sure sshd service is installed and running. If it is, we shouldn't need to use
    # the New-SSHD server function
    if (![bool]$(Get-Service sshd -ErrorAction SilentlyContinue)) {
        if (![bool]$(Get-Service ssh-agent -ErrorAction SilentlyContinue)) {
            $InstallWinSSHSplatParams = @{
                GiveWinSSHBinariesPathPriority  = $True
                ConfigureSSHDOnLocalHost        = $True
                DefaultShell                    = "powershell"
                GitHubInstall                   = $True
                ErrorAction                     = "SilentlyContinue"
                ErrorVariable                   = "IWSErr"
            }

            try {
                $InstallWinSSHResults = Install-WinSSH @InstallWinSSHSplatParams -ErrorAction Stop
                if (!$InstallWinSSHResults) {throw "There was a problem with the Install-WinSSH function! Halting!"}

                $Output.Add("InstallWinSSHResults",$InstallWinSSHResults)
            }
            catch {
                Write-Error $_
                Write-Host "Errors for the Install-WinSSH function are as follows:"
                Write-Error $($IWSErr | Out-String)
                $global:FunctionResult = "1"
                return
            }
        }
        else {
            $NewSSHDServerSplatParams = @{
                ErrorAction         = "SilentlyContinue"
                ErrorVariable       = "SSHDErr"
                DefaultShell        = "powershell"
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
    }

    if (Test-Path "$env:ProgramData\ssh\sshd_config") {
        $sshdir = "$env:ProgramData\ssh"
        $sshdConfigPath = "$sshdir\sshd_config"
    }
    elseif (Test-Path "$env:ProgramFiles\OpenSSH-Win64\sshd_config") {
        $sshdir = "$env:ProgramFiles\OpenSSH-Win64"
        $sshdConfigPath = "$env:ProgramFiles\OpenSSH-Win64\sshd_config"
    }
    if (!$sshdConfigPath) {
        Write-Error "Unable to find file 'sshd_config'! Halting!"
        $global:FunctionResult = "1"
        if ($Output.Count -gt 0) {[pscustomobject]$Output}
        return
    }

    if ($VaultSSHHostSigningUrl) {
        # Make sure $VaultSSHHostSigningUrl is a valid Url
        try {
            $UriObject = [uri]$VaultSSHHostSigningUrl
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            if ($Output.Count -gt 0) {[pscustomobject]$Output}
            return
        }

        if (![bool]$($UriObject.Scheme -match "http")) {
            Write-Error "'$PublicKeyOfCAUsedToSignUserKeysVaultUrl' does not appear to be a URL! Halting!"
            $global:FunctionResult = "1"
            if ($Output.Count -gt 0) {[pscustomobject]$Output}
            return
        }

        # Try to sign this machine's host key (i.e. C:\ProgramData\ssh\ssh_host_rsa_key.pub)
        try {
            # The below 'Sign-SSHHostPublicKey' function outputs a PSCustomObject detailing what was done
            # to the sshd config (if anything). It also writes out C:\ProgramData\ssh\ssh_host_rsa_key-cert.pub
            $SignSSHHostKeySplatParams = @{
                VaultSSHHostSigningUrl      = $VaultSSHHostSigningUrl
                VaultAuthToken              = $VaultAuthToken
                ErrorAction                 = "Stop"
            }
            $SignSSHHostKeyResult = Sign-SSHHostPublicKey @SignSSHHostKeySplatParams
            if (!$SignSSHHostKeyResult) {throw "There was a problem with the Sign-SSHHostPublicKey function!"}
            $Output.Add("SignSSHHostKeyResult",$SignSSHHostKeyResult)
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            if ($Output.Count -gt 0) {[pscustomobject]$Output}
            return
        }
    }

    # We need to get $PublicKeyOfCAUsedToSignUserKeysAsString and $PublicKeyOfCAUsedToSignHostKeysAsString
    if ($PublicKeyOfCAUsedToSignUserKeysVaultUrl) {
        # Make sure $SiteUrl is a valid Url
        try {
            $UriObject = [uri]$PublicKeyOfCAUsedToSignUserKeysVaultUrl
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            if ($Output.Count -gt 0) {[pscustomobject]$Output}
            return
        }

        if (![bool]$($UriObject.Scheme -match "http")) {
            Write-Error "'$PublicKeyOfCAUsedToSignUserKeysVaultUrl' does not appear to be a URL! Halting!"
            $global:FunctionResult = "1"
            if ($Output.Count -gt 0) {[pscustomobject]$Output}
            return
        }

        try {
            $PublicKeyOfCAUsedToSignUserKeysAsString = $(Invoke-WebRequest -Uri $PublicKeyOfCAUsedToSignUserKeysVaultUrl).Content.Trim()
            if (!$PublicKeyOfCAUsedToSignUserKeysAsString) {throw "Invoke-WebRequest failed to get the CA's Public Key from Vault! Halting!"}
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            if ($Output.Count -gt 0) {[pscustomobject]$Output}
            return
        }
    }
    if ($PublicKeyOfCAUsedToSignHostKeysVaultUrl) {
        # Make sure $SiteUrl is a valid Url
        try {
            $UriObject = [uri]$PublicKeyOfCAUsedToSignHostKeysVaultUrl
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            if ($Output.Count -gt 0) {[pscustomobject]$Output}
            return
        }

        if (![bool]$($UriObject.Scheme -match "http")) {
            Write-Error "'$PublicKeyOfCAUsedToSignHostKeysVaultUrl' does not appear to be a URL! Halting!"
            $global:FunctionResult = "1"
            if ($Output.Count -gt 0) {[pscustomobject]$Output}
            return
        }

        try {
            $PublicKeyOfCAUsedToSignHostKeysAsString = $(Invoke-WebRequest -Uri $PublicKeyOfCAUsedToSignHostKeysVaultUrl).Content.Trim()
            if (!$PublicKeyOfCAUsedToSignHostKeysAsString) {throw "Invoke-WebRequest failed to get the CA's Public Key from Vault! Halting!"}
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            if ($Output.Count -gt 0) {[pscustomobject]$Output}
            return
        }
    }
    if ($PublicKeyOfCAUsedToSignUserKeysFilePath) {
        if (! $(Test-Path $PublicKeyOfCAUsedToSignUserKeysFilePath)) {
            Write-Error "The path '$PublicKeyOfCAUsedToSignUserKeysFilePath' was not found! Halting!"
            $global:FunctionResult = "1"
            if ($Output.Count -gt 0) {[pscustomobject]$Output}
            return
        }
        
        $PublicKeyOfCAUsedToSignUserKeysAsString = Get-Content $PublicKeyOfCAUsedToSignUserKeysFilePath
    }
    if ($PublicKeyOfCAUsedToSignHostKeysFilePath) {
        if (! $(Test-Path $PublicKeyOfCAUsedToSignHostKeysFilePath)) {
            Write-Error "The path '$PublicKeyOfCAUsedToSignHostKeysFilePath' was not found! Halting!"
            $global:FunctionResult = "1"
            if ($Output.Count -gt 0) {[pscustomobject]$Output}
            return
        }
        
        $PublicKeyOfCAUsedToSignHostKeysAsString = Get-Content $PublicKeyOfCAUsedToSignHostKeysFilePath
    }

    # Now we have $PublicKeyOfCAUsedToSignUserKeysAsString and $PublicKeyOfCAUsedToSignHostKeysAsString
    # Need to make sure these strings exist in dedicated files under $sshdir as well as in 
    # $sshdir/authorized_keys and $sshdir/ssh_known_hosts

    # Before adding these CA Public Keys to $sshdir/authorized_keys, if there's already an existing
    # $sshdir/authorized_keys, archive it in a folder called $sshdir/Archive so that we can revert if necessary
    if (Test-Path "$sshdir/authorized_keys") {
        if (!$(Test-Path "$sshdir/Archive")) {
            $null = New-Item -ItemType Directory -Path "$sshdir/Archive" -Force
        }
        Move-Item -Path "$sshdir/authorized_keys" -Destination "$sshdir/Archive" -Force
    }
    # Before adding these CA Public Keys to $sshdir/ssh_known_hosts, if there's already an existing
    # $sshdir/ssh_known_hosts, archive it in a folder called $sshdir/Archive so that we can revert if necessary
    if (Test-Path "$sshdir/ssh_known_hosts") {
        if (!$(Test-Path "$sshdir/Archive")) {
            $null = New-Item -ItemType Directory -Path "$sshdir/Archive" -Force
        }
        Move-Item -Path "$sshdir/ssh_known_hosts" -Destination "$sshdir/Archive" -Force
    }

    # Add the CA Public Certs to $sshdir/authorized_keys in their appropriate formats
    Add-Content -Path "$sshdir/authorized_keys" -Value $("ssh-rsa-cert-v01@openssh.com " + "$PublicKeyOfCAUsedToSignUserKeysAsString")
    Add-Content -Path "$sshdir/authorized_keys" -Value $("ssh-rsa-cert-v01@openssh.com " + "$PublicKeyOfCAUsedToSignHostKeysAsString")
    $null = $FilesUpdated.Add($(Get-Item "$sshdir/authorized_keys"))

    # Add the CA Public Certs to $sshdir/ssh_known_hosts in their appropriate formats
    Add-Content -Path $sshdir/ssh_known_hosts -Value $("@cert-authority * " + "$PublicKeyOfCAUsedToSignUserKeysAsString")
    Add-Content -Path $sshdir/ssh_known_hosts -Value $("@cert-authority * " + "$PublicKeyOfCAUsedToSignHostKeysAsString")
    $null = $FilesUpdated.Add($(Get-Item "$sshdir/ssh_known_hosts"))

    # Make sure $PublicKeyOfCAUsedToSignUserKeysAsString and $PublicKeyOfCAUsedToSignHostKeysAsString are written
    # to their own dedicated files under $sshdir
    
    # If $PublicKeyOfCAUsedToSignUserKeysFilePath or $PublicKeyOfCAUsedToSignHostKeysFilePath were actually provided
    # maintain the same file name when writing to $sshdir
    if ($PSBoundParameters.ContainsKey('PublicKeyOfCAUsedToSignUserKeysFilePath')) {
        $UserCAPubKeyFileName = $PublicKeyOfCAUsedToSignUserKeysFilePath | Split-Path -Leaf
    }
    else {
        $UserCAPubKeyFileName = "ca_pub_key_of_client_signer.pub"
    }
    if ($PSBoundParameters.ContainsKey('PublicKeyOfCAUsedToSignHostKeysFilePath')) {
        $HostCAPubKeyFileName = $PublicKeyOfCAUsedToSignHostKeysFilePath | Split-Path -Leaf
    }
    else {
        $HostCAPubKeyFileName = "ca_pub_key_of_host_signer.pub"
    }

    if (Test-Path "$sshdir/$UserCAPubKeyFileName") {
        if (!$(Test-Path "$sshdir/Archive")) {
            $null = New-Item -ItemType Directory -Path "$sshdir/Archive" -Force
        }
        Move-Item -Path "$sshdir/$UserCAPubKeyFileName" -Destination "$sshdir/Archive" -Force
    }
    if (Test-Path "$sshdir/$HostCAPubKeyFileName") {
        if (!$(Test-Path "$sshdir/Archive")) {
            $null = New-Item -ItemType Directory -Path "$sshdir/Archive" -Force
        }
        Move-Item -Path "$sshdir/$HostCAPubKeyFileName" -Destination "$sshdir/Archive" -Force
    }

    Set-Content -Path "$sshdir/$UserCAPubKeyFileName" -Value $PublicKeyOfCAUsedToSignUserKeysAsString
    Set-Content -Path "$sshdir/$HostCAPubKeyFileName" -Value $PublicKeyOfCAUsedToSignHostKeysAsString
    $null = $FilesUpdated.Add($(Get-Item "$sshdir/$UserCAPubKeyFileName"))
    $null = $FilesUpdated.Add($(Get-Item "$sshdir/$HostCAPubKeyFileName"))
    

    # Next, we need to generate some content for $sshdir/authorized_principals

    # IMPORTANT NOTE: The Generate-AuthorizedPrincipalsFile will only ADD users to the $sshdir/authorized_principals
    # file (if they're not already in there). It WILL NOT delete or otherwise overwrite existing users in
    # $sshdir/authorized_principals
    $AuthPrincSplatParams = @{
        ErrorAction     = "Stop"
    }
    if ($(!$AuthorizedPrincipalsUserGroup -and !$AuthorizedUserPrincipals) -or
    $AuthorizedPrincipalsUserGroup -contains "AllUsers" -or
    $($AuthorizedPrincipalsUserGroup -contains "LocalAdmins" -and $AuthorizedPrincipalsUserGroup -contains "LocalUsers" -and
    $AuthorizedPrincipalsUserGroup -contains "DomainAdmins" -and $AuthorizedPrincipalsUserGroup -contains "DomainAdmins")
    ) {
        $AuthPrincSplatParams.Add("UserGroupToAdd",@("AllUsers"))
    }
    else {
        if ($AuthorizedPrincipalsUserGroup) {
            $AuthPrincSplatParams.Add("UserGroupToAdd",$AuthorizedPrincipalsUserGroup)
        }
        if ($AuthorizedUserPrincipals) {
            $AuthPrincSplatParams.Add("UsersToAdd",$AuthorizedUserPrincipals)
        }
    }

    try {
        $AuthorizedPrincipalsFile = Generate-AuthorizedPrincipalsFile @AuthPrincSplatParams
        if (!$AuthorizedPrincipalsFile) {throw "There was a problem with the Generate-AuthroizedPrincipalsFile function! Halting!"}

        $null = $FilesUpdated.Add($(Get-Item "$sshdir/authorized_principals"))        
    }
    catch {
        Write-Error $_
        $global:FunctionResult = "1"
        if ($Output.Count -gt 0) {[pscustomobject]$Output}
        return
    }

    # Now we need to fix permissions for $sshdir/authroized_principals...
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
            if ($Output.Count -gt 0) {[pscustomobject]$Output}
            return
        }
    }

    $SecurityDescriptor = Get-NTFSSecurityDescriptor -Path "$sshdir/authorized_principals"
    $SecurityDescriptor | Disable-NTFSAccessInheritance -RemoveInheritedAccessRules
    $SecurityDescriptor | Clear-NTFSAccess
    $SecurityDescriptor | Add-NTFSAccess -Account "NT AUTHORITY\SYSTEM" -AccessRights "FullControl" -AppliesTo ThisFolderSubfoldersAndFiles
    $SecurityDescriptor | Add-NTFSAccess -Account "Administrators" -AccessRights "FullControl" -AppliesTo ThisFolderSubfoldersAndFiles
    $SecurityDescriptor | Set-NTFSSecurityDescriptor

    # Now that we have set content for $PublicKeyOfCAUsedToSignUserKeysFilePath, $sshdir/authorized_principals, and
    # $sshdir/authorized_keys, we need to update sshd_config to reference these files

    $PubKeyOfCAUserKeysFilePathForwardSlashes = "$sshdir\$UserCAPubKeyFileName" -replace '\\','/'
    $TrustedUserCAKeysOptionLine = "TrustedUserCAKeys $PubKeyOfCAUserKeysFilePathForwardSlashes"
    # For more information about authorized_principals content (specifically about setting specific commands and roles
    # for certain users), see: https://framkant.org/2017/07/scalable-access-control-using-openssh-certificates/
    $AuthPrincFilePathForwardSlashes = "$sshdir\authorized_principals" -replace '\\','/'
    $AuthorizedPrincipalsOptionLine = "AuthorizedPrincipalsFile $AuthPrincFilePathForwardSlashes"
    $AuthKeysFilePathForwardSlashes = "$sshdir\authorized_keys" -replace '\\','/'
    $AuthorizedKeysFileOptionLine = "AuthorizedKeysFile	$AuthKeysFilePathForwardSlashes"

    [System.Collections.ArrayList]$sshdContent = Get-Content $sshdConfigPath

    # Determine if sshd_config already has the 'TrustedUserCAKeys' option active
    $ExistingTrustedUserCAKeysOption = $sshdContent -match "TrustedUserCAKeys" | Where-Object {$_ -notmatch "#"}

    # Determine if sshd_config already has 'AuthorizedPrincipals' option active
    $ExistingAuthorizedPrincipalsFileOption = $sshdContent -match "AuthorizedPrincipalsFile" | Where-Object {$_ -notmatch "#"}

    # Determine if sshd_config already has 'AuthorizedKeysFile' option active
    $ExistingAuthorizedKeysFileOption = $sshdContent -match "AuthorizedKeysFile" | Where-Object {$_ -notmatch "#"}
    
    if (!$ExistingTrustedUserCAKeysOption) {
        # If sshd_config already has the 'Match User' option available, don't touch it, else add it with ForceCommand
        try {
            Add-Content -Value $TrustedUserCAKeysOptionLine -Path $sshdConfigPath
            $SSHDConfigContentChanged = $True
            [System.Collections.ArrayList]$sshdContent = Get-Content $sshdConfigPath
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            if ($Output.Count -gt 0) {[pscustomobject]$Output}
            return
        }
    }
    else {
        if ($ExistingTrustedUserCAKeysOption -ne $TrustedUserCAKeysOptionLine) {
            $UpdatedSSHDConfig = $sshdContent -replace [regex]::Escape($ExistingTrustedUserCAKeysOption),"$TrustedUserCAKeysOptionLine"

            try {
                Set-Content -Value $UpdatedSSHDConfig -Path $sshdConfigPath
                $SSHDConfigContentChanged = $True
                [System.Collections.ArrayList]$sshdContent = Get-Content $sshdConfigPath
            }
            catch {
                Write-Error $_
                $global:FunctionResult = "1"
                if ($Output.Count -gt 0) {[pscustomobject]$Output}
                return
            }
        }
        else {
            Write-Warning "The specified 'TrustedUserCAKeys' option is already active in the the sshd_config file. No changes made."
        }
    }

    if (!$ExistingAuthorizedPrincipalsFileOption) {
        try {
            Add-Content -Value $AuthorizedPrincipalsOptionLine -Path $sshdConfigPath
            $SSHDConfigContentChanged = $True
            [System.Collections.ArrayList]$sshdContent = Get-Content $sshdConfigPath
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            if ($Output.Count -gt 0) {[pscustomobject]$Output}
            return
        }
    }
    else {
        if ($ExistingAuthorizedPrincipalsFileOption -ne $AuthorizedPrincipalsOptionLine) {
            $UpdatedSSHDConfig = $sshdContent -replace [regex]::Escape($ExistingAuthorizedPrincipalsFileOption),"$AuthorizedPrincipalsOptionLine"

            try {
                Set-Content -Value $UpdatedSSHDConfig -Path $sshdConfigPath
                $SSHDConfigContentChanged = $True
                [System.Collections.ArrayList]$sshdContent = Get-Content $sshdConfigPath
            }
            catch {
                Write-Error $_
                $global:FunctionResult = "1"
                if ($Output.Count -gt 0) {[pscustomobject]$Output}
                return
            }
        }
        else {
            Write-Warning "The specified 'AuthorizedPrincipalsFile' option is already active in the the sshd_config file. No changes made."
        }
    }

    if (!$ExistingAuthorizedKeysFileOption) {
        try {
            Add-Content -Value $AuthorizedKeysFileOptionLine -Path $sshdConfigPath
            $SSHDConfigContentChanged = $True
            [System.Collections.ArrayList]$sshdContent = Get-Content $sshdConfigPath
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            if ($Output.Count -gt 0) {[pscustomobject]$Output}
            return
        }
    }
    else {
        if ($ExistingAuthorizedKeysFileOption -ne $AuthorizedKeysFileOptionLine) {
            $UpdatedSSHDConfig = $sshdContent -replace [regex]::Escape($ExistingAuthorizedKeysFileOption),"$AuthorizedKeysFileOptionLine"

            try {
                Set-Content -Value $UpdatedSSHDConfig -Path $sshdConfigPath
                $SSHDConfigContentChanged = $True
                [System.Collections.ArrayList]$sshdContent = Get-Content $sshdConfigPath
            }
            catch {
                Write-Error $_
                $global:FunctionResult = "1"
                if ($Output.Count -gt 0) {[pscustomobject]$Output}
                return
            }
        }
        else {
            Write-Warning "The specified 'AuthorizedKeysFile' option is already active in the the sshd_config file. No changes made."
        }
    }

    if ($SSHDConfigContentChanged) {
        $null = $FilesUpdated.Add($(Get-Item $sshdConfigPath))
        
        try {
            Restart-Service sshd -ErrorAction Stop
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            if ($Output.Count -gt 0) {[pscustomobject]$Output}
            return
        }
    }

    [pscustomobject]$Output
}

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
        $LDAPServerNetworkInfo = Resolve-Host -HostNameOrIP $LDAPServerHostNameOrIP
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
        $DomainControllerInfo = Get-DomainController -ErrorAction Stop
        $LDAPInfo = Test-LDAP -ADServerHostNameOrIP $DomainControllerInfo.PrimaryDomainController -ErrorAction Stop
        if (!$DomainControllerInfo) {throw "Problem with Get-DomainController function! Halting!"}
        if (!$LDAPInfo) {throw "Problem with Test-LDAP function! Halting!"}
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
        $DomainControllerInfo = Get-DomainController -ErrorAction Stop
        $LDAPInfo = Test-LDAP -ADServerHostNameOrIP $DomainControllerInfo.PrimaryDomainController -ErrorAction Stop
        if (!$DomainControllerInfo) {throw "Problem with Get-DomainController function! Halting!"}
        if (!$LDAPInfo) {throw "Problem with Test-LDAP function! Halting!"}
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
        $LDAPServerNetworkInfo = Resolve-Host -HostNameOrIP $LDAPServerHostNameOrIP
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
        if (![bool]$(Test-IsValidIPAddress -IPAddress $IPAddress)) {
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
    $NewVMName = New-UniqueString -ArrayOfStrings $VMs.Name -PossibleNewUniqueString $VMName

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

    $NewVMIP = $(Get-VM -Name $NewVMName).NetworkAdapters.IPAddresses | Where-Object {Test-IsValidIPAddress -IPAddress $_}
    $Counter = 0
    while (!$NewVMIP -or $Counter -le 5) {
        Write-Host "Waiting for VM $NewVMName to report its IP Address..."
        Start-Sleep -Seconds 10
        $NewVMIP = $(Get-VM -Name $NewVMName).NetworkAdapters.IPAddresses | Where-Object {Test-IsValidIPAddress -IPAddress $_}
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
