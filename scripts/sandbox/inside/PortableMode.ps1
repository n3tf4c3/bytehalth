# Modo real portátil (Fase 5) DENTRO do Sandbox: o serviço em console SEM --simulate, elevado, atende o
# pipe por usuário, informa modo real e recusa cofres (que exigem o serviço instalado).

$P = 'Portátil (modo real)'
$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$devPipe = "ByteHalt.Dev.v1.$sid"
$realData = "$work\portable-real"
$proc = $null
Invoke-Step $P 'Serviço em console sem simulação inicia e responde em modo real' {
    Assert-That (-not (Test-PipeExists $devPipe)) 'Já existe um serviço de desenvolvimento rodando.'
    $script:PortableProc = Start-Process -FilePath "$pkg\service\bytehalt-service.exe" -ArgumentList @('--data-dir', "`"$realData`"") `
        -RedirectStandardError (Join-Path $live.FullName 'portable-real.log') -NoNewWindow -PassThru
    Wait-Until { Test-PipeExists $devPipe } 30 'pipe do modo real portátil'
    $pong = Invoke-ByteHaltPipe $devPipe 'Ping' $null @($sid)
    Assert-That (-not $pong.simulated) 'O console respondeu em modo simulado.'
    $v = Invoke-ByteHaltPipe $devPipe 'DiscoverVolumes' $null @($sid)
    "modo real; volumes consultados: $(@($v.volumes).Count) ($($v.warning))"
}
Invoke-Step $P 'Cofres são recusados no modo portátil' {
    $refused = $false
    try { Invoke-ByteHaltPipe $devPipe 'AnalyzeVault' @{ path = 'C:\bytehalt-work' } @($sid) | Out-Null } catch { $refused = $_.Exception.Message -like '*exigem o ByteHalt instalado*' }
    Assert-That $refused 'AnalyzeVault não foi recusado.'
}
if ($script:PortableProc) { Stop-Process -Id $script:PortableProc.Id -Force -ErrorAction SilentlyContinue }
try { Wait-Until { -not (Test-PipeExists $devPipe) } 15 'fim do serviço em console' } catch { Write-Log $_.Exception.Message }

# Atalhos do pacote portátil (ferramentas\iniciar.ps1 / encerrar.ps1), numa cópia gravável da pasta.
$portableSrc = Get-ChildItem "$pkg\portable" -Directory -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $portableSrc) {
    Skip-Step $P 'Atalhos do pacote portátil' 'Pacote sem a pasta portable.'
} else {
    $copy = "$work\portable"
    Copy-Item $portableSrc.FullName $copy -Recurse -Force
    function Wait-Gone { Wait-Until { -not (Get-Process bytehalt, bytehalt-service -ErrorAction SilentlyContinue) -and -not (Test-PipeExists $devPipe) } 30 'interface e serviço encerrados' }
    foreach ($mode in 'demo', 'real') {
        Invoke-Step $P "Iniciar e Encerrar ($mode) pelos atalhos do pacote" {
            $elog = Join-Path $env:TEMP 'bytehalt-encerrar.log'
            Remove-Item $elog -ErrorAction SilentlyContinue
            # Sem -Wait: no PowerShell 5.1 ele espera também os filhos (serviço e interface continuam rodando).
            Start-Process powershell.exe -ArgumentList '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$copy\ferramentas\iniciar.ps1`"", '-Modo', $mode
            Wait-Until { (Test-PipeExists $devPipe) -and (Get-Process bytehalt -ErrorAction SilentlyContinue) } 40 "serviço e interface ($mode)"
            $pong = Invoke-ByteHaltPipe $devPipe 'Ping' $null @($sid)
            Assert-That ($pong.simulated -eq ($mode -eq 'demo')) "Modo: simulated=$($pong.simulated)"
            $dataDir = if ($mode -eq 'demo') { 'dados' } else { 'dados-real' }
            Assert-That (Test-Path "$copy\$dataDir\bytehalt.db") "Banco não criado em $dataDir."
            Start-Process powershell.exe -ArgumentList '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$copy\ferramentas\encerrar.ps1`"" -Wait
            $text = (Get-Content $elog -ErrorAction SilentlyContinue) -join ' | '
            try { Wait-Gone } catch { throw "$($_.Exception.Message) — restam: $((Get-Process bytehalt, bytehalt-service -ErrorAction SilentlyContinue | ForEach-Object { "$($_.Name)($($_.Id))" }) -join ', ') — registro: $text" }
            Assert-That ($text -notmatch 'à força') "A interface não atendeu ao pedido de saída: $text"
            "simulated=$($pong.simulated); dados em $dataDir; encerrado — $text"
        }
    }
}
