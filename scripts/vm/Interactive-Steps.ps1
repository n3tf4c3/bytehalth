param(
    [Parameter(Mandatory)][ValidateSet('Prepare', 'Probe', 'LockSession', 'Status', 'Unlock', 'Suspend', 'Cleanup')][string]$Action,
    [string]$Drive = 'E:',
    [string]$Passphrase = ''
)
# Passos da Fase 4 que dependem da sessão interativa na VM de teste. Rodados por Invoke-AsTask.ps1:
# Prepare/Status/Unlock/Suspend/Cleanup como o usuário de teste (logon local, pipe de produção);
# Probe/LockSession na sessão interativa do usuário (token comum, sem elevação).
# Só a unidade de teste $Drive é usada. A senha é de teste e nunca vai para a saída.
$ErrorActionPreference = 'Stop'
$base = 'C:\Users\Public\bh-task'
$script:LogFile = Join-Path $base 'steps.log'
. (Join-Path $base 'Common.ps1')
$pipe = 'ByteHalt.Service.v1'
$nil = '00000000-0000-0000-0000-000000000000'
function P([string]$command, $payload = $null) { Invoke-ByteHaltPipe $pipe $command $payload @('S-1-5-18') }
function Real { (Get-BitLockerVolume -MountPoint $Drive).LockStatus.ToString() }
function Clear-Config {
    foreach ($g in @((P 'GetSnapshot').groups)) { P 'DeleteGroup' @{ id = $g.id } | Out-Null }
    foreach ($r in @((P 'GetSnapshot').resources) | Where-Object { $_.resource.kind -eq 'BitLockerVolume' }) { P 'DeleteResource' @{ id = $r.resource.id } | Out-Null }
}

switch ($Action) {
    'Prepare' {
        if ((Real) -eq 'Locked') { Unlock-BitLocker -MountPoint $Drive -Password (ConvertTo-SecureString $Passphrase -AsPlainText -Force) | Out-Null }
        Clear-Config
        $r = P 'SaveResource' @{ resource = @{ id = $nil; displayName = "Teste $Drive"; kind = 'BitLockerVolume'; target = $Drive } }
        if (-not $r.success) { throw "SaveResource: $($r.errors -join ' ')" }
        $id = (@((P 'GetSnapshot').resources) | Where-Object { $_.resource.target -eq $Drive }).resource.id
        $g = P 'SaveGroup' @{ group = @{ id = $nil; name = 'Interativo'; resourceIds = @($id); inactivitySecs = $null; mode = 'ResourceIdle'; totpThresholdSecs = 86400; lockOnWorkstationLock = $true; lockOnSuspend = $true } }
        if (-not $g.success) { throw "SaveGroup: $($g.errors -join ' ')" }
        "PRONTO: $Drive=$(Real); grupo Interativo (bloqueia com o Windows e ao suspender)"
    }
    'Probe' {
        $out = Join-Path $base 'probe'
        Remove-Item $out -Recurse -Force -ErrorAction SilentlyContinue
        $p = Start-Process -FilePath (Join-Path $base 'bytehalt-probe.exe') -ArgumentList @('--gui-probe', "`"$out`"") -PassThru
        if (-not $p.WaitForExit(60000)) { Stop-Process -Id $p.Id -Force; throw 'A sondagem não terminou em 60 s.' }
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        $admin = ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        "USUARIO: $($id.Name); sessão $((Get-Process -Id $PID).SessionId); elevado: $admin"
        'PROBE: ' + [IO.File]::ReadAllText((Join-Path $out 'probe.json'))
    }
    'LockSession' {
        & rundll32.exe user32.dll, LockWorkStation
        'Windows bloqueado (sessão interativa)'
    }
    'Status' {
        $v = @((P 'GetSnapshot').resources) | Where-Object { $_.resource.target -eq $Drive }
        "ESTADO: BitLocker $Drive=$(Real); ByteHalt=$($v.state)"
        foreach ($h in @(P 'GetHistory' @{ limit = 6 })) { 'HIST: ' + $h.message }
    }
    'Unlock' {
        $id = (@((P 'GetSnapshot').resources) | Where-Object { $_.resource.target -eq $Drive }).resource.id
        $u = P 'Unlock' @{ id = $id; passphrase = $Passphrase; totp = $null }
        "DESBLOQUEIO: $($u.code); BitLocker $Drive=$(Real)"
    }
    'Suspend' {
        # Hibernação indisponível na VM: SetSuspendState(0, …) entra em espera (S1).
        Start-Process rundll32.exe -ArgumentList 'powrprof.dll,SetSuspendState 0,1,0'
        'Suspensão pedida'
    }
    'Cleanup' {
        if ((Real) -eq 'Locked') { Unlock-BitLocker -MountPoint $Drive -Password (ConvertTo-SecureString $Passphrase -AsPlainText -Force) | Out-Null }
        Clear-Config
        "LIMPO: $Drive=$(Real)"
    }
}
