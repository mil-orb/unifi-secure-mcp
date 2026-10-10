# Run in PowerShell 7 from outside the installation directory.
$ErrorActionPreference='Stop'
$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..')).TrimEnd('\')
if(!(Test-Path -LiteralPath (Join-Path $root 'src\server.mjs')) -or !(Test-Path -LiteralPath (Join-Path $root 'package.json'))){throw 'Not an MCP installation.'}
$items=@(Get-Item -LiteralPath $root -Force)+@(Get-ChildItem -LiteralPath $root -Force -Recurse)
foreach($item in $items){
    $resolved=[IO.Path]::GetFullPath($item.FullName)
    if(($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or ($resolved -ne $root -and !$resolved.StartsWith($root+'\',[StringComparison]::OrdinalIgnoreCase))){throw 'Unsafe installation path.'}
}
$sids=@([Security.Principal.WindowsIdentity]::GetCurrent().User,[Security.Principal.SecurityIdentifier]::new('S-1-5-18'),[Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
foreach($item in $items){
    $acl=Get-Acl -LiteralPath $item.FullName
    $acl.SetAccessRuleProtection($true,$false)
    foreach($rule in @($acl.Access)){$acl.RemoveAccessRuleSpecific($rule)}
    foreach($sid in $sids){
        $inherit=if($item.PSIsContainer){[Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit'}else{[Security.AccessControl.InheritanceFlags]::None}
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid,'FullControl',$inherit,'None','Allow'))
    }
    [IO.FileSystemAclExtensions]::SetAccessControl($item,$acl)
}
Write-Output ('Installation objects hardened: '+$items.Count)
