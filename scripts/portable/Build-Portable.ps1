[CmdletBinding()]
param(
    # Impressão digital do certificado de assinatura de código (ex.: SimplySign conectado). Sem ela, sem assinatura.
    [string]$SignThumbprint = $env:BYTEHALT_SIGN_THUMBPRINT,
    [string]$TimestampUrl = 'http://time.certum.pl',
    [string]$OutDir
)
# Monta a versão portátil em artifacts\portable\ByteHalt-<versão>-portable (+ .zip), sem instalar nada:
#   - Demonstração: serviço simulado como o usuário; nenhum disco real é tocado.
#   - Modo real: serviço em console ELEVADO protegendo unidades BitLocker de verdade enquanto aberto.
#     Cofres reais ficam de fora (exigem o serviço instalado; o serviço recusa no console).
$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$version = (Select-String -Path (Join-Path $repo 'Cargo.toml') -Pattern '^version = "(.+)"').Matches[0].Groups[1].Value
$name = "ByteHalt-$version-portable"
$root = if ($OutDir) { $OutDir } else { Join-Path $repo 'artifacts\portable' }
New-Item -ItemType Directory -Force -Path $root | Out-Null
$dir = Join-Path $root $name
$zip = Join-Path $root "$name.zip"

Push-Location $repo
try {
    & cmd.exe /c 'cargo build --release --locked -p bytehalt-service -p bytehalt-app 2>&1' | Out-Host
    if ($LASTEXITCODE -ne 0) { throw "cargo build falhou ($LASTEXITCODE)." }
} finally {
    Pop-Location
}

# Proteção: só recria dentro de artifacts\portable do próprio repositório.
foreach ($p in $dir, $zip) {
    if (Test-Path -LiteralPath $p) {
        $full = (Resolve-Path -LiteralPath $p).Path
        if (!$full.StartsWith($root + '\', [StringComparison]::OrdinalIgnoreCase)) { throw "Recusa: $full fora de $root." }
        Remove-Item -LiteralPath $full -Recurse -Force
    }
}
New-Item -ItemType Directory -Force -Path (Join-Path $dir 'licencas'), (Join-Path $dir 'ferramentas') | Out-Null
Copy-Item -LiteralPath (Join-Path $repo 'artifacts\rust-target\release\bytehalt.exe'), (Join-Path $repo 'artifacts\rust-target\release\bytehalt-service.exe') -Destination $dir
Copy-Item -LiteralPath (Join-Path $repo 'assets\GPUI-APACHE.txt') -Destination (Join-Path $dir 'licencas\GPUI-Apache-2.0.txt')
Copy-Item -LiteralPath (Join-Path $repo 'assets\icons\LICENSE') -Destination (Join-Path $dir 'licencas\Material-Symbols-Apache-2.0.txt')

$signed = $false
if ($SignThumbprint) {
    $signtool = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64\signtool.exe" -ErrorAction SilentlyContinue | Sort-Object FullName | Select-Object -Last 1
    if (-not $signtool) { throw 'signtool.exe não encontrado (Windows SDK).' }
    & $signtool.FullName sign /sha1 $SignThumbprint /fd SHA256 /tr $TimestampUrl /td SHA256 /d 'ByteHalt' (Join-Path $dir 'bytehalt.exe') (Join-Path $dir 'bytehalt-service.exe') | Out-Host
    if ($LASTEXITCODE -ne 0) { throw "Assinatura falhou ($LASTEXITCODE)." }
    $signed = $true
}
$publisher = if ($signed) { (Get-AuthenticodeSignature (Join-Path $dir 'bytehalt.exe')).SignerCertificate.GetNameInfo('SimpleName', $false) } else { $null }

$utf8 = New-Object Text.UTF8Encoding $true
$ascii = New-Object Text.ASCIIEncoding
function Write-Text([string]$path, [string]$text, $enc) { [IO.File]::WriteAllText($path, $text.Replace("`r`n", "`n").Replace("`n", "`r`n"), $enc) }

# Ferramentas (PowerShell com -ExecutionPolicy Bypass só no processo; nada é alterado no sistema).
Write-Text (Join-Path $dir 'ferramentas\iniciar.ps1') @'
param([ValidateSet('demo', 'real')][string]$Modo = 'demo')
# Inicia o serviço (simulado como o usuário, ou real elevado) e a interface. Nada é instalado.
$base = Split-Path $PSScriptRoot -Parent
$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$pipe = "ByteHalt.Dev.v1.$sid"
function PipeUp { @(Get-ChildItem '\\.\pipe\' | Where-Object Name -eq $pipe).Count -gt 0 }
if (-not (PipeUp)) {
    $svc = Join-Path $base 'bytehalt-service.exe'
    if ($Modo -eq 'demo') {
        Start-Process -FilePath $svc -ArgumentList @('--simulate', '--data-dir', "`"$(Join-Path $base 'dados')`"") -WindowStyle Minimized
    } else {
        # BitLocker exige administrador: o Windows pede a confirmação (UAC).
        try {
            Start-Process -FilePath $svc -ArgumentList @('--data-dir', "`"$(Join-Path $base 'dados-real')`"") -Verb RunAs -WindowStyle Minimized
        } catch {
            [void](New-Object -ComObject WScript.Shell).Popup('O modo real precisa de permissão de administrador (BitLocker).', 0, 'ByteHalt', 48)
            exit 1
        }
    }
    $deadline = (Get-Date).AddSeconds(20)
    while (-not (PipeUp) -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 300 }
    if (-not (PipeUp)) {
        [void](New-Object -ComObject WScript.Shell).Popup('O serviço do ByteHalt não iniciou.', 0, 'ByteHalt', 16)
        exit 1
    }
}
Start-Process -FilePath (Join-Path $base 'bytehalt.exe') -ArgumentList '--dev'
'@ $utf8

Write-Text (Join-Path $dir 'ferramentas\encerrar.ps1') @'
# Encerra a interface (pela bandeja) e o serviço DESTA pasta portátil (demonstração ou real).
# O serviço do modo real roda elevado: se houver um que não dá para identificar, roda de novo como administrador.
Add-Type -Namespace ByteHalt -Name Win -MemberDefinition @"
[DllImport("user32.dll", CharSet = CharSet.Unicode)] public static extern System.IntPtr FindWindowW(string c, string n);
[DllImport("user32.dll")] public static extern bool PostMessageW(System.IntPtr h, uint m, System.IntPtr w, System.IntPtr l);
"@
$log = Join-Path $env:TEMP 'bytehalt-encerrar.log'
function Log($m) { Add-Content -LiteralPath $log -Value ('{0:HH:mm:ss} {1}' -f (Get-Date), $m) }
$base = Split-Path $PSScriptRoot -Parent
# Só processos desta pasta (nunca uma instalação do ByteHalt aberta ao mesmo tempo).
function Mine([string]$name) { @(Get-Process $name -ErrorAction SilentlyContinue | Where-Object { $_.Path -and $_.Path.StartsWith($base, [StringComparison]::OrdinalIgnoreCase) }) }
$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (Mine 'bytehalt') {
    # A interface pode estar abrindo: espera a janela da bandeja aparecer (até 8 s).
    $h = [IntPtr]::Zero
    $until = (Get-Date).AddSeconds(8)
    while ($h -eq [IntPtr]::Zero -and (Mine 'bytehalt') -and (Get-Date) -lt $until) {
        # [NullString]: o PowerShell converteria $null em texto vazio (procuraria um título vazio).
        $h = [ByteHalt.Win]::FindWindowW('ByteHalt.Tray.v1', [NullString]::Value)
        if ($h -eq [IntPtr]::Zero) { Start-Sleep -Milliseconds 300 }
    }
    Log "janela da bandeja: $h"
    if ($h -ne [IntPtr]::Zero) {
        Log ("pedido de saída enviado: " + [ByteHalt.Win]::PostMessageW($h, 0x8000 + 20, [IntPtr]::Zero, [IntPtr]::Zero))
        $deadline = (Get-Date).AddSeconds(10)
        while ((Mine 'bytehalt') -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 300 }
    }
    foreach ($p in Mine 'bytehalt') { Log "interface ainda aberta (PID $($p.Id)): encerrando à força"; Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }
}
foreach ($p in Mine 'bytehalt-service') { Log "serviço PID $($p.Id): encerrando"; Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }
$hidden = @(Get-Process bytehalt-service -ErrorAction SilentlyContinue | Where-Object { -not $_.Path })
if ($hidden.Count -and -not $admin) {
    Log 'serviço elevado (modo real): pedindo administrador para encerrá-lo'
    try { Start-Process powershell.exe -ArgumentList '-NoProfile', '-ExecutionPolicy', 'Bypass', '-WindowStyle', 'Hidden', '-File', "`"$PSCommandPath`"" -Verb RunAs -Wait } catch { Log 'administrador negado' }
}
Log 'fim'
'@ $utf8

Write-Text (Join-Path $dir 'Iniciar-demonstracao.cmd') @'
@echo off
rem ByteHalt - demonstracao (modo simulado). Nenhuma unidade real e tocada.
powershell -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "%~dp0ferramentas\iniciar.ps1" -Modo demo
'@ $ascii
Write-Text (Join-Path $dir 'Iniciar-modo-real.cmd') @'
@echo off
rem ByteHalt - modo real portatil: protege unidades BitLocker de verdade enquanto o servico estiver aberto.
powershell -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "%~dp0ferramentas\iniciar.ps1" -Modo real
'@ $ascii
Write-Text (Join-Path $dir 'Encerrar.cmd') @'
@echo off
rem Encerra a interface e o servico portatil (demonstracao ou real).
powershell -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "%~dp0ferramentas\encerrar.ps1"
'@ $ascii

$sha = @{}
foreach ($f in 'bytehalt.exe', 'bytehalt-service.exe') { $sha[$f] = (Get-FileHash -LiteralPath (Join-Path $dir $f) -Algorithm SHA256).Hash }
$sigText = if ($signed) { "Executáveis assinados digitalmente por $publisher (carimbo de tempo Certum)." } else { 'Executáveis SEM assinatura digital: o Windows pode avisar ou bloquear (SmartScreen/Smart App Control).' }
Write-Text (Join-Path $dir 'LEIA-ME.txt') @"
ByteHalt $version - versão portátil (sem instalação)
====================================================

$sigText

DOIS MODOS (use um de cada vez)
  Demonstração  "Iniciar-demonstracao.cmd"
                Unidades e cofres SIMULADOS: nenhum disco ou BitLocker real é tocado.
                Sem administrador. Dados em .\dados. Senha das unidades simuladas: bytehalt-teste
  Modo real     "Iniciar-modo-real.cmd"
                Protege unidades BitLocker DE VERDADE enquanto o serviço estiver aberto (janela de
                console minimizada). Pede administrador (UAC), porque o BitLocker exige. Dados em
                .\dados-real. Use a senha real de cada unidade para desbloquear.
  Para encerrar: "Sair" no menu da bandeja e "Encerrar.cmd" (encerra também o serviço).

A interface fica na BANDEJA do Windows. Fechar a janela leva para a bandeja; o ícone abre o painel.

LIMITES DO MODO REAL PORTÁTIL (use o instalador para proteção completa)
  - Só protege enquanto o serviço portátil está aberto: não inicia com o Windows.
  - Bloquear o Windows ou suspender NÃO dispara bloqueio (esses eventos só chegam ao serviço
    instalado). Inatividade, bloqueio manual e "Bloquear tudo" funcionam.
  - Cofres de pastas ficam desativados: exigem o serviço instalado (sem ele, os discos dos cofres
    não seriam anexados depois de reiniciar).
  - A unidade do sistema nunca é bloqueada. Arquivos abertos adiam o bloqueio (nunca força).
  - Unidade bloqueada há 24 h ou mais pede também o código do autenticador (senha mestra e TOTP
    na tela Segurança).

ROTEIRO RÁPIDO (demonstração)
  - Unidades: "Procurar unidades" -> D: e E: -> Adicionar.
  - Grupos: "Novo grupo" -> 1 min, marque D: -> Salvar. Espere ~1 minuto: D: bloqueia e a bandeja avisa.
  - "Simular arquivo aberto" + grupo de 5 min: bloqueio ADIADO; "Fechar arquivos" e ele bloqueia.
  - Cofres: use só uma PASTA DE TESTE. Analisar -> Criar cofre -> guarde a chave -> "Trocar a pasta
    pelo cofre" -> Bloquear/Desbloquear -> "Remover cofre" (devolve a pasta). Remova os cofres antes de
    apagar a pasta da demonstração.
  - Segurança: crie a senha mestra e cadastre o autenticador do celular (QR code).

O QUE FICA NO SEU PC
  - Esta pasta\dados e \dados-real          (banco, estado protegido, credenciais)
  - %LOCALAPPDATA%\ByteHalt\ui-settings.json  (tema e preferências da interface)
  - HKCU\SOFTWARE\ByteHalt\Boot                 (chave volátil; o Windows apaga ao reiniciar)
  - HKCU\...\Run\ByteHalt só se você marcar "Abrir ao entrar no Windows" (não use no portátil).
  Para remover: "Encerrar.cmd", apague esta pasta e, no PowerShell:
    Remove-Item "`$env:LOCALAPPDATA\ByteHalt" -Recurse -Force
    Remove-Item HKCU:\SOFTWARE\ByteHalt -Recurse -Force

AVISO
  O código TOTP é verificado pelo ByteHalt, não pelo BitLocker: não é MFA criptográfico do volume.
  Quem tem a senha da unidade, a chave de recuperação ou é administrador desbloqueia sem o ByteHalt.

INTEGRIDADE (SHA-256)
  bytehalt.exe          $($sha['bytehalt.exe'])
  bytehalt-service.exe  $($sha['bytehalt-service.exe'])
"@ $utf8

Compress-Archive -Path (Join-Path $dir '*') -DestinationPath $zip
Get-ChildItem -LiteralPath $dir -Recurse -File | Select-Object @{ n = 'arquivo'; e = { $_.FullName.Replace($dir + '\', '') } }, @{ n = 'KB'; e = { [math]::Round($_.Length / 1KB) } } | Format-Table -AutoSize | Out-Host
Write-Host ("Zip: {0} ({1:N1} MB) — {2}" -f $zip, ((Get-Item -LiteralPath $zip).Length / 1MB), $(if ($signed) { "assinado por $publisher" } else { 'SEM assinatura' }))
return $dir
