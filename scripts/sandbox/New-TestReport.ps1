[CmdletBinding()]
param([Parameter(Mandatory = $true)][string]$RunDirectory)

# Gera report.md a partir de out\result.json (exportado pelo Sandbox). Não inventa resultados:
# só lista o que o roteiro registrou; ausência de resultado é reportada como tal.
$ErrorActionPreference = 'Stop'
$resultPath = Join-Path $RunDirectory 'out\result.json'
if (!(Test-Path -LiteralPath $resultPath)) { throw "Sem resultado em $resultPath." }
$r = [IO.File]::ReadAllText($resultPath).TrimStart([char]0xFEFF) | ConvertFrom-Json

$suites = @($r.suites)
$steps = @($r.steps)
$unitTotal = ($suites | Measure-Object total -Sum).Sum
$unitPassed = ($suites | Measure-Object passed -Sum).Sum
$unitFailed = ($suites | Measure-Object failed -Sum).Sum
$unitSkipped = ($suites | Measure-Object skipped -Sum).Sum
$stepPassed = @($steps | Where-Object status -eq 'passed').Count
$stepFailed = @($steps | Where-Object status -eq 'failed').Count
$stepSkipped = @($steps | Where-Object status -eq 'skipped').Count
# Suíte que não executou nenhum teste ou saiu com erro sem registrar falhas também é problema.
$crashed = @($suites | Where-Object { "$($_.exit_code)" -ne '0' -and $_.failed -eq 0 })

$md = New-Object System.Text.StringBuilder
function L([string]$s = '') { [void]$md.AppendLine($s) }
function Cell([object]$s) { if ($null -eq $s) { return '' } return ([string]$s).Replace('|', '\|').Replace("`r", ' ').Replace("`n", ' ') }

L "# Relatório de testes — ByteHalt $($r.build.version)"
L
L "Rodada **$($r.run_id)** · início $($r.started_utc) · fim $($r.finished_utc) (UTC)"
L
L '## Build'
L
L "| Campo | Valor |"
L "|---|---|"
L "| Produto | $($r.build.product) $($r.build.version) ($($r.build.configuration)) |"
L "| Compilado em (UTC) | $($r.build.built_at_utc) |"
L "| Toolchain | $($r.build.toolchain) |"
L "| Commit | $(if ($r.build.git_commit) { $r.build.git_commit } else { 'sem repositório Git' }) |"
L "| Segredos reais no pacote | $($r.build.secrets_included) |"
foreach ($p in $r.build.sha256.PSObject.Properties) { L "| SHA-256 $($p.Name) | ``$($p.Value)`` |" }
L
L '## Ambiente'
L
L '| Item | Valor |'
L '|---|---|'
foreach ($p in $r.environment.PSObject.Properties) { L "| $($p.Name) | $(Cell $p.Value) |" }
L
L '## Resumo'
L
L "- Testes automatizados: **$unitPassed de $unitTotal aprovados**, $unitFailed reprovados, $unitSkipped ignorados."
L "- Roteiro de interface, temporizadores e serviço: **$stepPassed aprovados**, $stepFailed reprovados, $stepSkipped não executados."
if ($r.fatal) { L "- **Erro fatal do roteiro:** $(Cell $r.fatal)" }
if ($crashed.Count) { L "- **Suítes que não executaram ou terminaram com erro:** $(($crashed | ForEach-Object name) -join ', ')" }
L
L "## Testes automatizados (cargo test, executados dentro do Sandbox)"
L
L '| Suíte | Total | Aprovados | Reprovados | Ignorados | Saída | Tempo (s) |'
L '|---|---:|---:|---:|---:|---:|---:|'
foreach ($s in $suites) { L "| $($s.name) | $($s.total) | $($s.passed) | $($s.failed) | $($s.skipped) | $($s.exit_code) | $($s.seconds) |" }
$failures = @($suites | ForEach-Object { $suite = $_.name; @($_.failures) | ForEach-Object { [pscustomobject]@{ suite = $suite; test = $_.test; message = $_.message } } })
if ($failures.Count) {
    L
    L '### Falhas'
    L
    foreach ($f in $failures) { L "- **$($f.suite)** · $(Cell $f.test): $(Cell $f.message)" }
}
L
L '## Casos executados no Sandbox'
L
L '| Área | Caso | Resultado | Tempo (s) | Evidência / detalhe |'
L '|---|---|---|---:|---|'
$label = @{ passed = 'Aprovado'; failed = '**Reprovado**'; skipped = 'Não executado' }
foreach ($st in $steps) { L "| $($st.suite) | $(Cell $st.name) | $($label[$st.status]) | $($st.seconds) | $(Cell $st.detail) |" }
L
L '## Limitações identificadas'
L
foreach ($l in @($r.limitations)) { L "- $l" }
L '- Testes reais de BitLocker (bloqueio/desbloqueio de volume, arquivos abertos, recuperação) exigem VM Hyper-V com vTPM e VHDX descartáveis (Fase 4); não foram executados.'
L '- O GPUI não expõe UI Automation: a interface é provada por roteiro interno (gui-test); o clique físico no ícone da bandeja não é simulado.'
L
L '## Problemas que impedem o lançamento'
L
$blockers = @()
if ($unitFailed -gt 0 -or $crashed.Count) { $blockers += 'Há testes automatizados reprovados ou suítes com erro.' }
if ($stepFailed -gt 0) { $blockers += 'Há casos do roteiro do Sandbox reprovados.' }
if ($r.fatal) { $blockers += 'O roteiro terminou com erro fatal.' }
$blockers += 'Fase 1 não inclui TOTP, autenticação primária própria, cofres VHDX nem validação real de BitLocker: não é uma versão de lançamento.'
$blockers += 'Binários sem assinatura digital (Fase 5).'
foreach ($b in $blockers) { L "- $b" }
L
L '## Evidências'
L
L 'Arquivos exportados nesta rodada (pasta `out`): `result.json`, `logs\`, `tests\*.log` (saída do cargo test), `shots\*.png`. Os logs não contêm senhas, códigos TOTP nem chaves.'

$report = Join-Path $RunDirectory 'report.md'
[IO.File]::WriteAllText($report, $md.ToString(), (New-Object Text.UTF8Encoding $false))
Write-Host "Relatório: $report"
Write-Host "Automatizados: $unitPassed/$unitTotal · Roteiro: $stepPassed ok, $stepFailed falhas, $stepSkipped não executados"
return $report
