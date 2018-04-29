function NewUniqueString {
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