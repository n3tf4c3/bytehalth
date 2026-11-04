[CmdletBinding()]
param(
    # Impressão digital (SHA-1) de um certificado de assinatura de código no repositório do usuário.
    # Sem ela os executáveis saem SEM assinatura (Smart App Control/SmartScreen vão avisar ou bloquear).
    [string]$SignThumbprint = $env:BYTEHALT_SIGN_THUMBPRINT,
    [string]$TimestampUrl = 'http://time.certum.pl',
    # Pasta de saída (o pacote do Sandbox usa outra, para não sobrescrever as versões assinadas).
    [string]$OutDir
)
# Gera artifacts\installer\ByteHalt-Setup-<versão>.exe: compila interface e serviço em release, assina-os
# (se houver certificado), embute-os no bytehalt-setup e assina o instalador.
$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$version = (Select-String -Path (Join-Path $repo 'Cargo.toml') -Pattern '^version = "(.+)"').Matches[0].Groups[1].Value
$out = if ($OutDir) { $OutDir } else { Join-Path $repo 'artifacts\installer' }
$payload = Join-Path $out 'payload'
$release = Join-Path $repo 'artifacts\rust-target\release'

function Invoke-Cargo([string]$cargoArgs) {
    & cmd.exe /c "cargo $cargoArgs 2>&1" | Out-Host
    if ($LASTEXITCODE -ne 0) { throw "cargo $cargoArgs falhou ($LASTEXITCODE)." }
}

function Invoke-Sign([string[]]$files) {
    if (-not $SignThumbprint) { return $false }
    $signtool = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64\signtool.exe" -ErrorAction SilentlyContinue | Sort-Object FullName | Select-Object -Last 1
    if (-not $signtool) { throw 'signtool.exe não encontrado (Windows SDK).' }
    & $signtool.FullName sign /sha1 $SignThumbprint /fd SHA256 /tr $TimestampUrl /td SHA256 /d 'ByteHalt' @files | Out-Host
    if ($LASTEXITCODE -ne 0) { throw "Assinatura falhou ($LASTEXITCODE)." }
    return $true
}

Push-Location $repo
try {
    Invoke-Cargo 'build --release --locked -p bytehalt-service -p bytehalt-app'
    if (Test-Path -LiteralPath $payload) { Remove-Item -LiteralPath $payload -Recurse -Force }
    New-Item -ItemType Directory -Force -Path $payload | Out-Null
    foreach ($f in 'bytehalt.exe', 'bytehalt-service.exe') { Copy-Item -LiteralPath (Join-Path $release $f) -Destination $payload }
    $signed = Invoke-Sign @((Join-Path $payload 'bytehalt.exe'), (Join-Path $payload 'bytehalt-service.exe'))
    $env:BYTEHALT_PAYLOAD_DIR = $payload
    try { Invoke-Cargo 'build --release --locked -p bytehalt-setup' } finally { Remove-Item Env:\BYTEHALT_PAYLOAD_DIR }
    $setup = Join-Path $out "ByteHalt-Setup-$version.exe"
    Copy-Item -LiteralPath (Join-Path $release 'bytehalt-setup.exe') -Destination $setup -Force
    if ($signed) { [void](Invoke-Sign @($setup)) }
    $hash = (Get-FileHash -LiteralPath $setup -Algorithm SHA256).Hash
    "$hash  $(Split-Path $setup -Leaf)" | Set-Content -Encoding ASCII "$setup.sha256"
    Write-Host ("Instalador: {0} ({1:N1} MB) — {2}" -f $setup, ((Get-Item -LiteralPath $setup).Length / 1MB), $(if ($signed) { 'assinado' } else { 'SEM assinatura' }))
    Write-Host "SHA-256: $hash"
    return $setup
} finally {
    Pop-Location
}
