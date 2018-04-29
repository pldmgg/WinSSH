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