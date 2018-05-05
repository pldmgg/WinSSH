function ConvertFromHCLToPrintF {
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