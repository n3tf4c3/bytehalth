[CmdletBinding()]
param(
    # Autoriza a exportação controlada: cria UMA pasta nova e vazia por rodada, única gravável pelo Sandbox.
    # Sem esta opção o Sandbox abre, executa e mostra o resultado na própria tela, sem nada gravado no host.
    [switch]$ExportResults,
    [switch]$SkipBuild,
    [switch]$SkipUi,
    [switch]$SkipServiceMode,
    # Roda também o teste de bloqueio do Windows (encerra a sessão interativa do Sandbox; vai por último).
    [switch]$IncludeWorkstationLock,
    # Desliga o Smart App Control SOMENTE dentro deste Sandbox descartável (a imagem vem com o SAC em
    # bloqueio e recusa DLLs sem assinatura). Nunca altera o host. Exige decisão explícita do titular.
    [switch]$DisableSmartAppControlInSandbox,
    [int]$TimeoutMinutes = 45,
    [string]$ReportsRoot = 'C:\Codes\relatorios\bytehalt\sandbox'
)

# Executa a bateria de testes do ByteHalt no Windows Sandbox descartável e sem rede.
# No host: compila, monta o pacote, gera o .wsb e espera. Nenhum teste do ByteHalt roda no host.
$ErrorActionPreference = 'Stop'
$sandboxExe = Join-Path $env:SystemRoot 'System32\WindowsSandbox.exe'
if (!(Test-Path -LiteralPath $sandboxExe)) { throw 'Windows Sandbox não está habilitado. Não habilito recursos do Windows sem autorização.' }
# O WindowsSandboxServer fica ocioso depois de fechar o Sandbox; o que conta é haver sessão aberta.
$wsbCli = Get-Command wsb.exe -ErrorAction SilentlyContinue
$open = if ($wsbCli) { @(& $wsbCli.Source list 2>$null | Where-Object { "$_".Trim() }).Count } else { @(Get-Process WindowsSandboxClient, WindowsSandboxRemoteSession -ErrorAction SilentlyContinue).Count }
if ($open) {
    throw 'Já existe um Windows Sandbox aberto; feche-o antes (só cabe um por vez).'
}

$repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$package = Join-Path $repo 'artifacts\sandbox-package'
if (!$SkipBuild) { & (Join-Path $PSScriptRoot 'Build-SandboxPackage.ps1') | Out-Null }
if (!(Test-Path -LiteralPath (Join-Path $package 'build-info.json'))) { throw "Pacote ausente: $package" }

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$runDir = Join-Path $ReportsRoot $stamp
$in = New-Item -ItemType Directory -Force -Path (Join-Path $runDir 'in')
$out = $null
if ($ExportResults) { $out = New-Item -ItemType Directory -Force -Path (Join-Path $runDir 'out') }

$runConfig = [ordered]@{
    run_id = $stamp
    ui = -not $SkipUi
    service_mode = -not $SkipServiceMode
    workstation_lock = [bool]$IncludeWorkstationLock
    disable_smart_app_control = [bool]$DisableSmartAppControlInSandbox
    shutdown_when_done = [bool]$ExportResults
}
[IO.File]::WriteAllText((Join-Path $in 'run.json'), ($runConfig | ConvertTo-Json), (New-Object Text.UTF8Encoding $false))
Copy-Item -LiteralPath (Join-Path $package 'build-info.json') -Destination $runDir

$wsb = Join-Path $runDir 'ByteHalt-Run.wsb'
$configArgs = @{ PackageDirectory = $package; RunDirectory = $in.FullName; Destination = $wsb }
if ($out) { $configArgs.OutputDirectory = $out.FullName }
& (Join-Path $PSScriptRoot 'New-SandboxConfig.ps1') @configArgs | Out-Null

Write-Host "Rodada $stamp — $runDir"
Start-Process -FilePath $sandboxExe -ArgumentList ('"' + $wsb + '"')
if (!$out) {
    Write-Host 'Sem -ExportResults: acompanhe o resultado na janela do Sandbox. Nada será gravado no host.'
    return $runDir
}

$result = Join-Path $out.FullName 'result.json'
$deadline = [DateTime]::UtcNow.AddMinutes($TimeoutMinutes)
while (!(Test-Path -LiteralPath $result) -and [DateTime]::UtcNow -lt $deadline) { Start-Sleep -Seconds 5 }
if (!(Test-Path -LiteralPath $result)) {
    Write-Warning "O Sandbox não gerou resultado em $TimeoutMinutes minutos. Veja $($out.FullName)."
} else {
    Start-Sleep -Seconds 3
}

# O roteiro interno desliga o Sandbox; se não desligar, encerra pela CLI.
$closeDeadline = [DateTime]::UtcNow.AddMinutes(2)
while (@(Get-Process WindowsSandboxRemoteSession, WindowsSandboxClient -ErrorAction SilentlyContinue).Count -and [DateTime]::UtcNow -lt $closeDeadline) { Start-Sleep -Seconds 3 }
if (@(Get-Process WindowsSandboxRemoteSession, WindowsSandboxClient -ErrorAction SilentlyContinue).Count) {
    $wsbCli = Get-Command wsb.exe -ErrorAction SilentlyContinue
    if ($wsbCli) {
        try {
            $listed = (& $wsbCli.Source list --raw) -join '' | ConvertFrom-Json
            foreach ($id in @($listed.WindowsSandboxEnvironments | ForEach-Object { $_.Id })) { if ($id) { & $wsbCli.Source stop --id $id | Out-Null } }
        } catch {
            Write-Warning "Não foi possível encerrar o Sandbox pela CLI: $($_.Exception.Message). Feche a janela manualmente."
        }
    }
}

if (Test-Path -LiteralPath $result) {
    & (Join-Path $PSScriptRoot 'New-TestReport.ps1') -RunDirectory $runDir
}
return $runDir
