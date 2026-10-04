# Create .env from .env.example with a fresh random value for every CHANGE_ME.
#
#   powershell -ExecutionPolicy Bypass -File scripts\init-env.ps1     (Windows)
#
# Refuses to overwrite an existing .env. Values are 48 hex characters from the
# OS cryptographic RNG: URL-safe, because the passwords go into connection URLs.
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$target = Join-Path $root ".env"
if (Test-Path $target) {
    Write-Error ".env already exists; leaving it alone. Delete it first to regenerate."
}

function New-Secret {
    $bytes = New-Object byte[] 24
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    -join ($bytes | ForEach-Object { $_.ToString("x2") })
}

$count = 0
$lines = Get-Content (Join-Path $root ".env.example") | ForEach-Object {
    if ($_ -match '^(.+)=CHANGE_ME$') { $count++; "$($Matches[1])=$(New-Secret)" } else { $_ }
}
# UTF-8 without BOM and LF endings, so Docker Compose reads it exactly.
[System.IO.File]::WriteAllText($target, (($lines -join "`n") + "`n"), (New-Object System.Text.UTF8Encoding $false))
Write-Output "Created .env with $count generated secrets."
