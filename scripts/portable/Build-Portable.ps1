[CmdletBinding()]
param()

# Monta a versão portátil de DEMONSTRAÇÃO em artifacts\portable\ByteHalt-<versão>-portable (+ .zip).
# Modo simulado: serviço em console como o usuário, volumes simulados, dados dentro da pasta.
# Não inclui instalação de serviço nem modo real de BitLocker.
$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$version = (Select-String -Path (Join-Path $repo 'Cargo.toml') -Pattern '^version = "(.+)"').Matches[0].Groups[1].Value
$name = "ByteHalt-$version-portable"
$root = Join-Path $repo 'artifacts\portable'
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
New-Item -ItemType Directory -Force -Path (Join-Path $dir 'licencas') | Out-Null
Copy-Item -LiteralPath (Join-Path $repo 'artifacts\rust-target\release\bytehalt.exe'), (Join-Path $repo 'artifacts\rust-target\release\bytehalt-service.exe') -Destination $dir
Copy-Item -LiteralPath (Join-Path $repo 'assets\GPUI-APACHE.txt') -Destination (Join-Path $dir 'licencas\GPUI-Apache-2.0.txt')
Copy-Item -LiteralPath (Join-Path $repo 'assets\icons\LICENSE') -Destination (Join-Path $dir 'licencas\Material-Symbols-Apache-2.0.txt')

$ascii = New-Object Text.ASCIIEncoding
[IO.File]::WriteAllText((Join-Path $dir 'Iniciar-demonstracao.cmd'), @'
@echo off
rem ByteHalt - demonstracao (modo simulado). Nenhuma unidade real e tocada.
setlocal
cd /d "%~dp0"
tasklist /fi "imagename eq bytehalt-service.exe" | find /i "bytehalt-service.exe" >nul
if errorlevel 1 start "ByteHalt - servico (demonstracao, nao feche durante o teste)" /min "%~dp0bytehalt-service.exe" --simulate --data-dir "%~dp0dados"
timeout /t 2 /nobreak >nul
start "" "%~dp0bytehalt.exe" --dev
'@.Replace("`n", "`r`n"), $ascii)
[IO.File]::WriteAllText((Join-Path $dir 'Encerrar-demonstracao.cmd'), @'
@echo off
rem Encerra a interface e o servico da demonstracao. Prefira "Sair" no menu da bandeja.
taskkill /im bytehalt.exe >nul 2>&1
timeout /t 2 /nobreak >nul
taskkill /im bytehalt.exe /f >nul 2>&1
taskkill /im bytehalt-service.exe /f >nul 2>&1
echo ByteHalt encerrado.
timeout /t 2 >nul
'@.Replace("`n", "`r`n"), $ascii)

$sha = @{}
foreach ($f in 'bytehalt.exe', 'bytehalt-service.exe') { $sha[$f] = (Get-FileHash -LiteralPath (Join-Path $dir $f) -Algorithm SHA256).Hash }
$readme = @"
ByteHalt $version - versão portátil de DEMONSTRAÇÃO
=================================================

O QUE É
  Modo simulado: as unidades são fictícias e NENHUM disco ou BitLocker real é tocado.
  O serviço roda como o seu usuário (sem administrador, sem instalação) e os dados ficam
  na pasta "dados" ao lado destes arquivos.

COMO USAR
  1. Execute "Iniciar-demonstracao.cmd".
     Abre o serviço (janela de console minimizada - não feche durante o teste) e a interface.
  2. A interface fica na BANDEJA do Windows (perto do relógio). Fechar ou minimizar a janela
     leva para a bandeja; clique no ícone para abrir. "Sair" no menu da bandeja encerra a
     interface. Para encerrar tudo: "Encerrar-demonstracao.cmd".
  Senha fictícia das unidades simuladas: bytehalt-teste

ROTEIRO SUGERIDO
  - Unidades: "Procurar unidades" -> escolha D: e E: -> Adicionar. (A unidade do sistema
    aparece, mas não pode ser escolhida.)
  - Grupos: "Novo grupo" -> 1 min, marque D: -> Salvar. Espere ~1 minuto sem usar o botão
    "Simular atividade": D: é bloqueada e aparece uma notificação na bandeja.
  - "Simular arquivo aberto" + grupo de 5 min: o bloqueio é ADIADO (ícone laranja na
    bandeja); "Fechar arquivos" e ele bloqueia na nova tentativa.
  - Desbloquear: senha errada é recusada; 3 erros ativam espera progressiva.
  - Cofres (use só uma PASTA DE TESTE, com cópias de arquivos): "Escolher..." -> Analisar ->
    nome e senha -> Criar cofre. Anote a chave de recuperação (simulada) -> "Trocar a pasta pelo
    cofre". A pasta original vira uma reserva ao lado dela. Depois: Bloquear/Desbloquear (senha
    bytehalt-teste no modo simulado), "Apagar reserva" e "Remover cofre" (devolve a pasta ao normal).
    Na demonstração não há disco virtual nem BitLocker: o conteúdo fica em "dados\cofres-simulados"
    ligado à pasta por uma junção. Remova os cofres antes de apagar a pasta da demonstração.
  - Segurança: a regra de 24 h e a limitação do TOTP. (Cadastro TOTP: Fase 3.)
  - Configurações: tema escuro.
  - Bandeja: passe o mouse no ícone (resumo e próximo bloqueio); clique direito para o menu
    (Abrir o ByteHalt, Bloquear tudo, Bloquear grupo, Sair).

O QUE A DEMONSTRAÇÃO GRAVA NO SEU PC
  - Esta pasta\dados                                   (banco, estado protegido, volumes simulados)
  - %LOCALAPPDATA%\ByteHalt\ui-settings.json             (tema e preferências da interface)
  - HKCU\SOFTWARE\ByteHalt\Boot                         (chave volátil; o Windows apaga ao reiniciar)
  - HKCU\Software\Microsoft\Windows\CurrentVersion\Run\ByteHalt
      só se você marcar "Abrir ao entrar no Windows" - não recomendado na demonstração.
  Para remover tudo: encerre, apague esta pasta e execute no PowerShell
    Remove-Item "`$env:LOCALAPPDATA\ByteHalt" -Recurse -Force
    Remove-Item HKCU:\SOFTWARE\ByteHalt -Recurse -Force
    Remove-ItemProperty HKCU:\Software\Microsoft\Windows\CurrentVersion\Run -Name ByteHalt -ErrorAction SilentlyContinue

LIMITAÇÕES DESTA VERSÃO (Fase 1)
  - Não bloqueia BitLocker real nesta demonstração; os cofres reais (VHDX + BitLocker) exigem o
    serviço instalado e foram validados só na VM de teste. TOTP é da Fase 3.
  - Executáveis sem assinatura digital: o Windows pode avisar (SmartScreen/Smart App Control).
  - O TOTP será verificado pelo ByteHalt, não pelo BitLocker: não é MFA criptográfico do volume.

INTEGRIDADE (SHA-256)
  bytehalt.exe          $($sha['bytehalt.exe'])
  bytehalt-service.exe  $($sha['bytehalt-service.exe'])
"@
[IO.File]::WriteAllText((Join-Path $dir 'LEIA-ME.txt'), $readme.Replace("`r`n", "`n").Replace("`n", "`r`n"), (New-Object Text.UTF8Encoding $true))

Compress-Archive -Path (Join-Path $dir '*') -DestinationPath $zip
Get-ChildItem -LiteralPath $dir -Recurse -File | Select-Object @{ n = 'arquivo'; e = { $_.FullName.Replace($dir + '\', '') } }, @{ n = 'KB'; e = { [math]::Round($_.Length / 1KB) } } | Format-Table -AutoSize | Out-Host
Write-Host ("Zip: {0} ({1:N1} MB)" -f $zip, ((Get-Item -LiteralPath $zip).Length / 1MB))
return $dir
