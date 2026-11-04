# Prova visual da interface GPUI (dot-sourced por Run-InsideSandbox.ps1). O GPUI não expõe UI
# Automation, então o próprio aplicativo (build gui-test) executa o roteiro, grava proof.json e
# capturas. Aqui: serviço em console + simulado, e atendimento aos pedidos de queda/reinício.

$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$devPipe = "ByteHalt.Dev.v1.$sid"
$svcData = "$work\svc-dev"
$proofDir = Join-Path $live.FullName 'proof'
New-Item -ItemType Directory -Force -Path $proofDir | Out-Null
$script:SvcProc = $null
$script:SvcLogIndex = 0

function Start-DevService {
    $script:SvcLogIndex++
    $script:SvcProc = Start-Process -FilePath "$pkg\service\bytehalt-service.exe" -ArgumentList @('--simulate', '--data-dir', "`"$svcData`"") `
        -RedirectStandardOutput (Join-Path $live.FullName "service-dev-$($script:SvcLogIndex).out") -RedirectStandardError (Join-Path $live.FullName "service-dev-$($script:SvcLogIndex).log") -NoNewWindow -PassThru
    Wait-Until { Test-PipeExists $devPipe } 40 'pipe do serviço de desenvolvimento'
}

$S = 'Interface'
Invoke-Step $S 'Serviço simulado inicia e cria o pipe por usuário' { Start-DevService; "pipe $devPipe" }
# Pasta do cofre de teste: na área descartável do Sandbox (nunca na pasta de exportação mapeada do
# host, para que a junção do cofre simulado não exista no disco do host).
$vaultDir = "$work\cofre-teste\Projeto"
New-Item -ItemType Directory -Force -Path "$vaultDir\src" | Out-Null
[IO.File]::WriteAllText("$vaultDir\README.md", '# projeto de teste')
[IO.File]::WriteAllText("$vaultDir\src\main.rs", 'fn main() {}')
[IO.File]::WriteAllBytes("$vaultDir\dados.bin", (New-Object byte[] 150000))
$env:BYTEHALT_PROOF_VAULT_DIR = $vaultDir
$app = Start-Process -FilePath "$pkg\proof\bytehalt.exe" -ArgumentList @('--dev', '--gui-proof', "`"$proofDir`"") `
    -RedirectStandardOutput (Join-Path $live.FullName 'proof.out') -RedirectStandardError (Join-Path $live.FullName 'proof.log') -NoNewWindow -PassThru
$null = $app.Handle
$deadline = [DateTime]::UtcNow.AddMinutes(15)
while (-not $app.HasExited -and [DateTime]::UtcNow -lt $deadline) {
    if (Test-Path "$proofDir\request-stop-service") {
        Remove-Item "$proofDir\request-stop-service" -Force
        Write-Log 'Prova pediu queda do serviço: encerrando o processo à força.'
        Stop-Process -Id $script:SvcProc.Id -Force
    }
    if (Test-Path "$proofDir\request-start-service") {
        Remove-Item "$proofDir\request-start-service" -Force
        Write-Log 'Prova pediu o reinício do serviço.'
        Start-DevService
    }
    Start-Sleep -Milliseconds 300
}
if (-not $app.HasExited) { Stop-Process -Id $app.Id -Force; Add-Step $S 'Roteiro da interface terminou no prazo' 'failed' 900 'Excedeu 15 minutos.' }
$app.WaitForExit()
if (Test-Path "$proofDir\proof.json") {
    foreach ($s in ([IO.File]::ReadAllText("$proofDir\proof.json") | ConvertFrom-Json)) { Add-Step $s.suite $s.name $s.status $s.seconds $s.detail }
} else {
    Add-Step $S 'Prova visual' 'failed' 0 "Sem proof.json (saída $($app.ExitCode)). Ver logs\proof.log."
}
if (-not (Test-Path "$proofDir\proof-done")) { Add-Step $S 'Prova chegou ao fim' 'failed' 0 "O aplicativo encerrou antes do fim (saída $($app.ExitCode))." }
Copy-Item "$proofDir\shots\*" "$work\shots\" -ErrorAction SilentlyContinue
if ($script:SvcProc -and -not $script:SvcProc.HasExited) { Stop-Process -Id $script:SvcProc.Id -Force }
