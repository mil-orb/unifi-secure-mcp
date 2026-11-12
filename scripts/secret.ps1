param([ValidateSet('Read','Store')][string]$Mode,[Parameter(Mandatory=$true)][string]$Path)
$ErrorActionPreference='Stop'
# The pipe to Node carries UTF-8 bytes in both directions, independent of the console
# code page. Exit 2 marks a failure this script detected, distinct from PowerShell
# refusing to run it.
$utf8=[Text.UTF8Encoding]::new($false)
try {
    Import-Module (Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Security\Microsoft.PowerShell.Security.psd1') -ErrorAction Stop
    if ($Mode -eq 'Store') {
        $buffer=[IO.MemoryStream]::new()
        [Console]::OpenStandardInput().CopyTo($buffer)
        $plain=$utf8.GetString($buffer.GetBuffer(),0,[int]$buffer.Length)
        $secure=ConvertTo-SecureString -String $plain -AsPlainText -Force
        try { [IO.File]::WriteAllText($Path,(ConvertFrom-SecureString $secure),$utf8) }
        finally { $secure.Dispose(); $plain=$null; [Array]::Clear($buffer.GetBuffer(),0,$buffer.Capacity); $buffer.Dispose() }
    } else {
        # Internal child-process pipe only. Never run Read interactively or print its output.
        $secure=ConvertTo-SecureString ([IO.File]::ReadAllText($Path))
        $pointer=[Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
        $bytes=$null
        try {
            $bytes=$utf8.GetBytes([Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer))
            $out=[Console]::OpenStandardOutput()
            $out.Write($bytes,0,$bytes.Length)
            $out.Flush()
        }
        finally { if($bytes){[Array]::Clear($bytes,0,$bytes.Length)}; [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer); $secure.Dispose() }
    }
} catch { [Console]::Error.WriteLine('Secret operation failed.'); exit 2 }
