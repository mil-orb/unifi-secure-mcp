param([Parameter(Mandatory=$true)][string]$Path)
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Security\Microsoft.PowerShell.Security.psd1') -ErrorAction Stop
$resolved=[IO.Path]::GetFullPath($Path)
$item=Get-Item -LiteralPath $resolved -Force
if(!$item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {throw 'Unsafe data directory.'}
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User
$items=@($item)+@(Get-ChildItem -LiteralPath $resolved -Force -Recurse)
foreach($entry in $items){if(($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -or ($entry.FullName -ne $resolved -and !$entry.FullName.StartsWith($resolved+'\',[StringComparison]::OrdinalIgnoreCase))){throw 'Unsafe private path.'}}
foreach($entry in $items){
    $acl=Get-Acl -LiteralPath $entry.FullName
    $acl.SetAccessRuleProtection($true,$false)
    foreach($rule in @($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))){$acl.RemoveAccessRuleSpecific($rule)}
    $inherit=if($entry.PSIsContainer){[Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit'}else{[Security.AccessControl.InheritanceFlags]::None}
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid,'FullControl',$inherit,'None','Allow'))
    $entry.SetAccessControl($acl)
}
