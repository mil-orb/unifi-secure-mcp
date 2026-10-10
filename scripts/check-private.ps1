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
        foreach($rule in $acl.Access){
            if($rule.AccessControlType -eq 'Allow' -and $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -notin $allowed){throw 'Unsafe permissions.'}
        }
    }
}catch{[Console]::Error.WriteLine('Private storage permission validation failed.');exit 1}
