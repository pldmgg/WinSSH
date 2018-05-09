@{
    # Some defaults for all dependencies
    PSDependOptions = @{
        Target = '$ENV:USERPROFILE\Documents\WindowsPowerShell\Modules'
        AddToPath = $True
    }

    # Grab some modules without depending on PowerShellGet
    'ProgramManagement' = @{
        DependencyType  = 'PSGalleryNuget'
        Version         = 'Latest'
    }
    'NTFSSecurity' = @{
        DependencyType  = 'PSGalleryNuget'
        Version         = 'Latest'
    }
}
