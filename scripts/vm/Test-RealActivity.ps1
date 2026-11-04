param(
    [Parameter(Mandatory)][string]$Drive,          # unidade de TESTE autorizada (ex.: E:)
    [Parameter(Mandatory)][string]$Passphrase      # senha de teste do BitLocker dessa unidade
)
# Fase 4 em modo real: o uso do volume (contadores de E/S) adia o bloqueio por inatividade, e o volume
# parado bloqueia. Só a unidade $Drive é usada; ao final ela fica desbloqueada e a configuração removida.
$ErrorActionPreference = 'Stop'
$work = Join-Path $env:TEMP 'bytehalt-vm-test'
New-Item -ItemType Directory -Force $work | Out-Null
$script:LogFile = Join-Path $work 'activity.log'
. (Join-Path $PSScriptRoot 'Common.ps1')

$S = 'Atividade real'
$pipe = 'ByteHalt.Service.v1'
$Drive = $Drive.TrimEnd('\').ToUpper()
if ($Drive -eq $env:SystemDrive.ToUpper()) { throw "Recusa: $Drive é a unidade do sistema." }
$nil = '00000000-0000-0000-0000-000000000000'
$file = "$Drive\bh-atividade.txt"
$secure = ConvertTo-SecureString $Passphrase -AsPlainText -Force
function P([string]$command, $payload = $null) { Invoke-ByteHaltPipe $pipe $command $payload @('S-1-5-18') }
function Real { (Get-BitLockerVolume -MountPoint $Drive).LockStatus.ToString() }
function View { @((P 'GetSnapshot').resources) | Where-Object { $_.resource.id -eq $script:Id } }
$script:Id = $null; $script:GroupId = $null

try {
    Invoke-Step $S 'Pré-condições: serviço real, sem configuração, unidade desbloqueada' {
        if ((Real) -eq 'Locked') { Unlock-BitLocker -MountPoint $Drive -Password $secure | Out-Null }
        Assert-That (-not (P 'Ping').simulated) 'Serviço simulado.'
        Assert-That (@((P 'GetSnapshot').resources).Count -eq 0) 'Já existe configuração.'
        $r = P 'SaveResource' @{ resource = @{ id = $nil; displayName = "Teste $Drive"; kind = 'BitLockerVolume'; target = $Drive } }
        Assert-That $r.success "SaveResource: $($r.errors -join ' ')"
        $script:Id = (@((P 'GetSnapshot').resources) | Where-Object { $_.resource.target -eq $Drive }).resource.id
        $g = P 'SaveGroup' @{ group = @{ id = $nil; name = 'Atividade'; resourceIds = @($script:Id); inactivitySecs = 60; mode = 'ResourceIdle'; totpThresholdSecs = 86400; lockOnWorkstationLock = $false; lockOnSuspend = $true } }
        Assert-That $g.success "SaveGroup: $($g.errors -join ' ')"
        $grp = @((P 'GetSnapshot').groups)[0]
        $script:GroupId = $grp.id
        Assert-That ($grp.lockOnSuspend -eq $true) 'Opção "bloquear ao suspender" não foi gravada.'
        'grupo de 1 min (modo recurso) com bloqueio ao suspender'
    }

    Invoke-Step $S 'Gravando a cada 20 s por 100 s: a unidade NÃO bloqueia' {
        $t0 = Get-Date
        while (((Get-Date) - $t0).TotalSeconds -lt 100) {
            [IO.File]::AppendAllText($file, "uso $(Get-Date -Format o)`r`n")
            $fs = [IO.File]::Open($file, 'Open', 'ReadWrite', 'ReadWrite'); $fs.Flush($true); $fs.Dispose()
            Start-Sleep 20
            Assert-That ((Real) -eq 'Unlocked') "Bloqueou com uso real aos $([int]((Get-Date) - $t0).TotalSeconds) s."
        }
        $v = View
        "após 100 s de uso: $(Real); próximo bloqueio em $($v.nextLockInSecs) s"
    }

    Invoke-Step $S 'Parado: bloqueia por inatividade cerca de 1 minuto depois do último uso' {
        $t0 = Get-Date
        Wait-Until { (Real) -eq 'Locked' } 120 'bloqueio por inatividade'
        $secs = [int]((Get-Date) - $t0).TotalSeconds
        Assert-That ($secs -ge 30) "Bloqueou cedo demais ($secs s)."
        $h = @(P 'GetHistory' @{ limit = 5 }) | Where-Object { $_.message -like '*inatividade*' } | Select-Object -First 1
        Assert-That ($null -ne $h) 'Histórico sem bloqueio por inatividade.'
        "bloqueou $secs s depois de parar de gravar"
    }

    Invoke-Step $S 'Desbloqueio com a senha (menos de 24 h)' {
        $u = P 'Unlock' @{ id = $script:Id; passphrase = $Passphrase; totp = $null }
        Assert-That ($u.code -eq 'Unlocked' -and (Real) -eq 'Unlocked') "Desbloqueio: $($u.code)"
    }
} catch {
    Add-Step $S 'Erro fatal' 'failed' 0 "$($_.Exception.Message)"
} finally {
    try {
        if ((Real) -eq 'Locked') { Unlock-BitLocker -MountPoint $Drive -Password $secure | Out-Null }
        if ($script:GroupId) { P 'DeleteGroup' @{ id = $script:GroupId } | Out-Null }
        if ($script:Id) { P 'DeleteResource' @{ id = $script:Id } | Out-Null }
        Remove-Item $file -ErrorAction SilentlyContinue
    } catch { Add-Step $S 'Limpeza' 'failed' 0 $_.Exception.Message }
    $result = [ordered]@{ finished = (Get-Date).ToString('o'); drive_final = (Real); steps = @($script:Steps) }
    '=====RESULT====='
    $result | ConvertTo-Json -Depth 8 -Compress
}
