[CmdletBinding()]
param()

# Monta o pacote de testes do Windows Sandbox em artifacts\sandbox-package:
#   app\bytehalt.exe (release), proof\bytehalt.exe (release + gui-test), service\bytehalt-service.exe,
#   tests\*.exe (binários de teste do cargo, compilados aqui e EXECUTADOS só no Sandbox), scripts\.
# CRT estático (.cargo\config.toml): nada de runtime do Visual C++. Nenhum segredo real é incluído.
$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$package = Join-Path $repo 'artifacts\sandbox-package'
$artifacts = Join-Path $repo 'artifacts'
$target = Join-Path $repo 'artifacts\rust-target'
$proofTarget = Join-Path $repo 'artifacts\rust-target-gui-test'

# Via cmd, com o stderr juntado DENTRO dele: o PowerShell 5.1 só vê stdout e não transforma as
# mensagens do cargo em ErrorRecord. (Start-Process -Wait travou sem filhos vivos em 03/11 18:36.)
function Invoke-Cargo([string[]]$arguments) {
    Push-Location $repo
    try {
        $line = ($arguments | ForEach-Object { if ($_ -match '\s') { "`"$_`"" } else { $_ } }) -join ' '
        & cmd.exe /c "cargo $line 2>&1" | Out-Host
        if ($LASTEXITCODE -ne 0) { throw "cargo $line falhou ($LASTEXITCODE)." }
    } finally {
        Pop-Location
    }
}

# Proteção: só apaga a pasta do pacote dentro de artifacts\ do próprio repositório.
if (Test-Path -LiteralPath $package) {
    $full = (Resolve-Path -LiteralPath $package).Path
    if (!$full.StartsWith($artifacts + '\', [StringComparison]::OrdinalIgnoreCase)) { throw "Recusa: $full fora de $artifacts." }
    Remove-Item -LiteralPath $full -Recurse -Force
}
foreach ($d in 'app', 'proof', 'service', 'tests') { New-Item -ItemType Directory -Force -Path (Join-Path $package $d) | Out-Null }

Invoke-Cargo @('build', '--release', '--locked', '-p', 'bytehalt-service', '-p', 'bytehalt-app')
Invoke-Cargo @('build', '--release', '--locked', '-p', 'bytehalt-app', '--features', 'gui-test', '--target-dir', $proofTarget)
Copy-Item -LiteralPath (Join-Path $target 'release\bytehalt.exe') -Destination (Join-Path $package 'app')
Copy-Item -LiteralPath (Join-Path $target 'release\bytehalt-service.exe') -Destination (Join-Path $package 'service')
Copy-Item -LiteralPath (Join-Path $proofTarget 'release\bytehalt.exe') -Destination (Join-Path $package 'proof')
# Instalador com o conteúdo embutido (Fase 5); o roteiro InstallerMode.ps1 instala e desinstala no Sandbox.
$setup = & (Join-Path $PSScriptRoot '..\release\Build-Installer.ps1') -OutDir (Join-Path $artifacts 'sandbox-build\installer') | Select-Object -Last 1
New-Item -ItemType Directory -Force -Path (Join-Path $package 'setup') | Out-Null
Copy-Item -LiteralPath $setup -Destination (Join-Path $package 'setup\bytehalt-setup.exe')
# Pacote portátil (os atalhos são testados pelo PortableMode.ps1 numa cópia gravável).
$portable = & (Join-Path $PSScriptRoot '..\portable\Build-Portable.ps1') -OutDir (Join-Path $artifacts 'sandbox-build\portable') | Select-Object -Last 1
Copy-Item -LiteralPath $portable -Destination (New-Item -ItemType Directory -Force -Path (Join-Path $package 'portable')) -Recurse

# Binários de teste: compilados sem executar; a lista sai do JSON do cargo.
$json = Join-Path $artifacts 'test-build.json'
# cmd grava o stdout em bytes crus (o `>` do PowerShell 5.1 gravaria UTF-16).
Push-Location $repo
try {
    & cmd.exe /c "cargo test --workspace --locked --no-run --message-format=json > `"$json`" 2>&1"
    if ($LASTEXITCODE -ne 0) { throw "cargo test --no-run falhou ($LASTEXITCODE)." }
} finally {
    Pop-Location
}
# "test":true precisa ser o do PERFIL (o alvo também tem um campo test). Regex em vez de ConvertFrom-Json por linha (que levava minutos com as milhares de linhas do GPUI).
$tests = foreach ($line in [IO.File]::ReadAllLines($json)) {
    if ($line -notmatch '"reason":"compiler-artifact"' -or $line -notmatch '"profile":\{[^}]*"test":true' -or $line -notmatch '"executable":"([^"]+)"') { continue }
    $exe = $Matches[1].Replace('\\', '\')
    if ($line -match '"target":\{"kind":\["([^"]+)"\][^}]*?"name":"([^"]+)"') {
        [pscustomobject]@{ name = "$($Matches[2])-$($Matches[1])"; exe = $exe }
    }
}
if (@($tests).Count -eq 0) { throw 'Nenhum binário de teste encontrado na saída do cargo.' }
Remove-Item -LiteralPath $json -Force
foreach ($t in $tests) { Copy-Item -LiteralPath $t.exe -Destination (Join-Path $package "tests\$($t.name).exe") }
Copy-Item -Path (Join-Path $PSScriptRoot 'inside\*') -Destination (New-Item -ItemType Directory -Force -Path (Join-Path $package 'scripts')) -Recurse

$hashes = [ordered]@{}
foreach ($file in 'app\bytehalt.exe', 'proof\bytehalt.exe', 'service\bytehalt-service.exe') {
    $hashes[$file] = (Get-FileHash -LiteralPath (Join-Path $package $file) -Algorithm SHA256).Hash
}
$info = [ordered]@{
    product = 'ByteHalt'
    version = ((Select-String -Path (Join-Path $repo 'Cargo.toml') -Pattern '^version = "(.+)"').Matches[0].Groups[1].Value)
    configuration = 'release (testes: debug)'
    built_at_utc = [DateTime]::UtcNow.ToString('o')
    toolchain = ((& rustc --version) -join '')
    git_commit = $(if (Test-Path -LiteralPath (Join-Path $repo '.git')) { (git -C $repo rev-parse --short HEAD) } else { $null })
    test_binaries = @($tests | ForEach-Object name)
    sha256 = $hashes
    secrets_included = $false
}
[IO.File]::WriteAllText((Join-Path $package 'build-info.json'), ($info | ConvertTo-Json -Depth 5), (New-Object Text.UTF8Encoding $false))
Write-Host "Pacote pronto: $package ($(@($tests).Count) binários de teste)"
return $package
