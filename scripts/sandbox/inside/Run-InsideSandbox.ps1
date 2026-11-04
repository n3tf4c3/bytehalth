# Roteiro executado no logon do Windows Sandbox (Windows PowerShell 5.1).
# Lê C:\bytehalt\run\run.json (somente leitura). Grava apenas em C:\bytehalt-work (descartável) e,
# se existir, em C:\bytehalt\out (pasta de exportação autorizada para esta rodada).
$ErrorActionPreference = 'Stop'
$pkg = 'C:\bytehalt\pkg'
$runDir = 'C:\bytehalt\run'
$outDir = 'C:\bytehalt\out'
$work = 'C:\bytehalt-work'
New-Item -ItemType Directory -Force -Path $work, "$work\logs", "$work\tests", "$work\shots" | Out-Null
# Com exportação autorizada, o log e a saída dos testes vão AO VIVO para a pasta da rodada: se algo
# travar, o host ainda vê até onde chegou.
$live = if (Test-Path $outDir) { New-Item -ItemType Directory -Force -Path "$outDir\live" } else { Get-Item "$work\logs" }
$script:LogFile = Join-Path $live.FullName 'run.log'
. "$pkg\scripts\Common.ps1"

$config = if (Test-Path "$runDir\run.json") { Get-Content "$runDir\run.json" -Raw | ConvertFrom-Json } else {
    [pscustomobject]@{ run_id = 'interativo'; ui = $true; service_mode = $true; workstation_lock = $false; disable_smart_app_control = $false; shutdown_when_done = $false }
}
$export = Test-Path $outDir
$result = [ordered]@{
    run_id = $config.run_id
    build = Get-Content "$pkg\build-info.json" -Raw | ConvertFrom-Json
    started_utc = [DateTime]::UtcNow.ToString('o')
    environment = [ordered]@{}
    suites = @()
    steps = @()
    limitations = @()
    fatal = $null
}

try {
    # ---------------- Ambiente ----------------
    Write-Log 'Sondando o ambiente.'
    $os = Get-CimInstance Win32_OperatingSystem
    $envInfo = $result.environment
    $envInfo.os = "$($os.Caption) $($os.Version) (build $($os.BuildNumber))"
    $envInfo.user = "$env:USERDOMAIN\$env:USERNAME"
    $envInfo.is_admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    $envInfo.memory_gb = [math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 1)
    $envInfo.network_adapters_up = @(Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object Status -eq 'Up').Count
    $ciPolicy = 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy'
    $envInfo.smart_app_control = (Get-ItemProperty $ciPolicy -ErrorAction SilentlyContinue).VerifiedAndReputablePolicyState
    if ($config.disable_smart_app_control) {
        # Pedido explícito da rodada: só neste Sandbox descartável; o host não é tocado.
        Set-ItemProperty $ciPolicy -Name VerifiedAndReputablePolicyState -Value 0 -Type DWord
        & CiTool.exe --refresh --json | Out-Null
        $envInfo.smart_app_control_after = (Get-ItemProperty $ciPolicy).VerifiedAndReputablePolicyState
        $result.limitations += 'Smart App Control foi DESLIGADO somente dentro deste Sandbox, por decisão explícita da rodada, porque os binários de teste não têm assinatura. Revalidar com binários assinados (Fase 5).'
    } elseif ($envInfo.smart_app_control -eq 1) {
        $result.limitations += 'Smart App Control em bloqueio no Sandbox: executáveis sem assinatura são recusados. O SAC não foi desligado.'
    }
    try { $envInfo.tpm_present = (Get-Tpm).TpmPresent } catch { $envInfo.tpm_present = "erro: $($_.Exception.Message)" }
    try {
        $vols = @(Get-CimInstance -Namespace 'root\CIMV2\Security\MicrosoftVolumeEncryption' -ClassName Win32_EncryptableVolume -ErrorAction Stop)
        $envInfo.bitlocker_wmi = "disponível ($($vols.Count) volume(s))"
    } catch { $envInfo.bitlocker_wmi = "indisponível: $($_.Exception.Message)" }
    # VHDX: cria/anexa/desanexa um disco de 64 MB DENTRO do Sandbox descartável, com limite de tempo
    # (o provedor de armazenamento pode travar no Sandbox; Get-Disk travou a rodada 20261103-153231).
    Write-Log 'Sondando VHDX (diskpart, até 60 s).'
    $probe = "$work\probe.vhdx"
    $dp = "$work\dp.txt"
    Set-Content -LiteralPath $dp -Encoding ASCII -Value @("create vdisk file=`"$probe`" maximum=64 type=expandable", "select vdisk file=`"$probe`"", 'attach vdisk', 'detach vdisk')
    $d = Start-Process -FilePath diskpart.exe -ArgumentList '/s', "`"$dp`"" -RedirectStandardOutput "$work\diskpart.txt" -NoNewWindow -PassThru
    $null = $d.Handle
    $envInfo.vhdx_attach = if (-not $d.WaitForExit(60000)) {
        $d.Kill(); 'não confirmado (diskpart excedeu 60 s)'
    } elseif ($d.ExitCode -eq 0) {
        'diskpart criou, anexou e desanexou sem erro (código 0)'
    } else {
        "não confirmado (diskpart $($d.ExitCode))"
    }
    Remove-Item -LiteralPath $probe, $dp -Force -ErrorAction SilentlyContinue
    Write-Log 'Sondando Smart App Control, TPM e BitLocker concluído.'
    Write-Log ('Ambiente: ' + ($envInfo | ConvertTo-Json -Compress))
    $result.limitations += 'Windows Sandbox não é uma VM completa: a pilha do BitLocker não foi validada; os testes usam volumes simulados.'
    if ($envInfo.tpm_present -ne $true) { $result.limitations += 'Sem TPM no Sandbox (esperado). Não houve tentativa de contornar.' }

    # ---------------- Testes automatizados (cargo test, binários compilados no host) ----------------
    foreach ($exe in Get-ChildItem "$pkg\tests" -Filter *.exe) {
        $name = $exe.BaseName
        $log = Join-Path $live.FullName "$name.log"
        Write-Log "Executando $name"
        $sw = [Diagnostics.Stopwatch]::StartNew()
        # Process direto: o Start-Process do 5.1 perde o handle de processos muito rápidos (ExitCode -1).
        $psi = New-Object Diagnostics.ProcessStartInfo $exe.FullName, '--color never'
        $psi.UseShellExecute = $false
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $psi.WorkingDirectory = $work
        $p = [Diagnostics.Process]::Start($psi)
        $stdout = $p.StandardOutput.ReadToEndAsync()
        $stderr = $p.StandardError.ReadToEndAsync()
        if (-not $p.WaitForExit(3 * 60 * 1000)) { $p.Kill(); Write-Log "$name excedeu 3 min e foi encerrado." }
        $p.WaitForExit()
        [IO.File]::WriteAllText($log, $stdout.Result, (New-Object Text.UTF8Encoding $false))
        [IO.File]::WriteAllText("$log.err", $stderr.Result, (New-Object Text.UTF8Encoding $false))
        $lines = @(Get-Content -LiteralPath $log -Encoding UTF8 -ErrorAction SilentlyContinue)
        $cases = @($lines | Where-Object { $_ -match '^test (\S+) \.\.\. (ok|FAILED|ignored)' })
        $suite = [ordered]@{
            name = $name; exit_code = $p.ExitCode; seconds = [math]::Round($sw.Elapsed.TotalSeconds, 1)
            total = $cases.Count
            passed = @($cases | Where-Object { $_ -match '\.\.\. ok$' }).Count
            failed = @($cases | Where-Object { $_ -match '\.\.\. FAILED$' }).Count
            skipped = @($cases | Where-Object { $_ -match '\.\.\. ignored$' }).Count
            failures = @()
        }
        foreach ($f in $cases | Where-Object { $_ -match '\.\.\. FAILED$' }) {
            $test = ($f -replace '^test (\S+) .*', '$1')
            $start = [Array]::IndexOf($lines, "---- $test stdout ----")
            $msg = if ($start -ge 0) { ($lines[($start + 1)..([Math]::Min($start + 8, $lines.Count - 1))] -join ' ') } else { '' }
            $suite.failures += [ordered]@{ test = $test; message = $msg }
        }
        if ($p.ExitCode -ne 0 -and $suite.failed -eq 0) {
            $suite.failures += [ordered]@{ test = '(execução)'; message = ((Get-Content "$log.err" -ErrorAction SilentlyContinue | Select-Object -Last 5) -join ' ') }
        }
        $result.suites += $suite
        Write-Log ('{0}: total {1}, ok {2}, falhas {3}, ignorados {4}, saída {5}' -f $name, $suite.total, $suite.passed, $suite.failed, $suite.skipped, $p.ExitCode)
    }

    # ---------------- Interface (prova GPUI) e serviço do Windows ----------------
    if ($config.ui) { . "$pkg\scripts\GuiProof.ps1" } else { Skip-Step 'Interface' 'Prova visual da interface' 'Desativada nesta rodada.' }
    if ($config.service_mode) { . "$pkg\scripts\ServiceMode.ps1" } else { Skip-Step 'Serviço do Windows' 'Serviço LocalSystem' 'Desativado nesta rodada.' }
} catch {
    $result.fatal = "$($_.Exception.Message) @ $($_.InvocationInfo.PositionMessage)"
    Write-Log "ERRO FATAL: $($result.fatal)"
} finally {
    $result.steps = @($script:Steps)
    $result.finished_utc = [DateTime]::UtcNow.ToString('o')
    [IO.File]::WriteAllText("$work\result.json", ($result | ConvertTo-Json -Depth 8), (New-Object Text.UTF8Encoding $false))
    $problems = @($result.suites | Where-Object { $_.failed -gt 0 -or $_.exit_code -ne 0 }).Count + @($script:Steps | Where-Object { $_.status -eq 'failed' }).Count
    Write-Log ('Concluído. Problemas: {0}{1}' -f $problems, $(if ($result.fatal) { ' + erro fatal' } else { '' }))
    if ($export) {
        # Exportação controlada: só a pasta desta rodada; result.json por último (o host espera por ele).
        Copy-Item "$work\logs", "$work\tests", "$work\shots" -Destination $outDir -Recurse -Force
        Copy-Item "$work\result.json" -Destination "$outDir\result.json.tmp" -Force
        Rename-Item "$outDir\result.json.tmp" 'result.json'
    }
    if ($config.shutdown_when_done) {
        Start-Sleep -Seconds 2
        & shutdown.exe /s /t 0 /f
    } else {
        Write-Host "`nResultado em $work\result.json. Esta janela pode ser fechada."
        Read-Host 'Pressione Enter para sair' | Out-Null
    }
}
