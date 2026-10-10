param([ValidateSet('Read','Store')][string]$Mode,[Parameter(Mandatory=$true)][string]$Path)
$ErrorActionPreference='Stop'
try {
    Import-Module (Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Security\Microsoft.PowerShell.Security.psd1') -ErrorAction Stop
    if ($Mode -eq 'Store') {
        $plain=[Console]::In.ReadToEnd()
        $secure=ConvertTo-SecureString -String $plain -AsPlainText -Force
        try { [IO.File]::WriteAllText($Path,(ConvertFrom-SecureString $secure),[Text.UTF8Encoding]::new($false)) }
        finally { $secure.Dispose(); $plain=$null }
    } else {
        # Internal child-process pipe only. Never run Read interactively or print its output.
        $secure=ConvertTo-SecureString ([IO.File]::ReadAllText($Path))
        $pointer=[Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
        try { [Console]::Out.Write([Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)) }
        finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer); $secure.Dispose() }
    }
} catch { [Console]::Error.WriteLine('Secret operation failed.'); exit 1 }
