param([Parameter(Mandatory=$true)][string]$ConfigPath,[Parameter(Mandatory=$true)][string]$DataDirectory)
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Security\Microsoft.PowerShell.Security.psd1') -ErrorAction Stop
try {
    $allowed=@([Security.Principal.WindowsIdentity]::GetCurrent().User.Value,'S-1-5-18','S-1-5-32-544')
    $items=@(Get-Item -LiteralPath $ConfigPath -Force)
    if(Test-Path -LiteralPath $DataDirectory){$items+=@(Get-Item -LiteralPath $DataDirectory -Force);$items+=@(Get-ChildItem -LiteralPath $DataDirectory -Force -Recurse)}
    foreach($item in $items){
        if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Unsafe path.'}
        $acl=Get-Acl -LiteralPath $item.FullName
        # Compare raw SIDs. Resolving account names can block on unavailable domain
        # services when an MCP host starts the process with a minimal environment.
        foreach($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])){
            if($rule.AccessControlType -eq 'Allow' -and $rule.IdentityReference.Value -notin $allowed){throw 'Unsafe permissions.'}
        }
    }
}catch{[Console]::Error.WriteLine('Private storage permission validation failed.');exit 1}
