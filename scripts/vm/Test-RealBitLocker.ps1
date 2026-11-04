param(
    [Parameter(Mandatory)][string]$Drive,          # unidade de TESTE autorizada (ex.: E:)
    [Parameter(Mandatory)][string]$Passphrase,     # senha de teste do BitLocker dessa unidade
    [string]$TestFile = 'teste.txt'
)
# Testes do serviço ByteHalt em MODO REAL contra o BitLocker de uma VM de teste (Windows PowerShell 5.1,
# administrador). Pré-requisitos: serviço "ByteHalt" instalado como LocalSystem sem --simulate e a
# unidade $Drive com BitLocker (protetor de senha). Só a unidade $Drive é bloqueada; a senha nunca é
# escrita no log nem no resultado. Ao final a unidade fica DESBLOQUEADA e a configuração é removida.
$ErrorActionPreference = 'Stop'
$work = Join-Path $env:TEMP 'bytehalt-vm-test'
New-Item -ItemType Directory -Force $work | Out-Null
$script:LogFile = Join-Path $work 'run.log'
. (Join-Path $PSScriptRoot 'Common.ps1')

$S = 'BitLocker real'
$pipe = 'ByteHalt.Service.v1'
$Drive = $Drive.TrimEnd('\').ToUpper()
$system = $env:SystemDrive.ToUpper()
if ($Drive -eq $system) { throw "Recusa: $Drive é a unidade do sistema." }
$nil = '00000000-0000-0000-0000-000000000000'
$secure = ConvertTo-SecureString $Passphrase -AsPlainText -Force

function P([string]$command, $payload = $null) { Invoke-ByteHaltPipe $pipe $command $payload @('S-1-5-18') }
function Real { (Get-BitLockerVolume -MountPoint $Drive).LockStatus.ToString() }
function View { @((P 'GetSnapshot').resources) | Where-Object { $_.resource.id -eq $script:Id } }
function Ensure-Unlocked { if ((Real) -eq 'Locked') { Unlock-BitLocker -MountPoint $Drive -Password $secure | Out-Null } }
function Set-TestGroup([object]$inactivity, [string]$mode = 'ResourceIdle') {
    $g = @{ id = $(if ($script:GroupId) { $script:GroupId } else { $nil }); name = 'Teste VM'; resourceIds = @($script:Id); inactivitySecs = $inactivity
        mode = $mode; totpThresholdSecs = 86400; lockOnWorkstationLock = $false }
    $r = P 'SaveGroup' @{ group = $g }
    Assert-That $r.success "SaveGroup: $($r.errors -join ' ')"
    $script:GroupId = @((P 'GetSnapshot').groups)[0].id
}
$script:Id = $null
$script:GroupId = $null

try {
    Invoke-Step $S 'Pré-condições: BitLocker com senha, unidade desbloqueada, serviço real' {
        $v = Get-BitLockerVolume -MountPoint $Drive
        Assert-That ($v.VolumeType -eq 'Data' -and $v.ProtectionStatus -eq 'On') "Volume: $($v.VolumeType) / $($v.ProtectionStatus)"
        Assert-That (@($v.KeyProtector | Where-Object KeyProtectorType -eq 'Password').Count -eq 1) 'Sem protetor de senha.'
        Ensure-Unlocked
        $pong = P 'Ping'
        Assert-That (-not $pong.simulated) 'O serviço está em modo simulado.'
        Assert-That (@((P 'GetSnapshot').resources).Count -eq 0) 'Já existe configuração no serviço; use uma instalação limpa.'
        "serviço $($pong.version), modo real; $Drive $($v.EncryptionMethod), protetores $(($v.KeyProtector.KeyProtectorType) -join ',')"
    }

    Invoke-Step $S 'Descoberta lista as unidades reais e marca a do sistema' {
        $vols = P 'DiscoverVolumes'
        $sys = @($vols.volumes) | Where-Object drive_letter -eq $system
        if (-not $sys) { $sys = @($vols.volumes) | Where-Object driveLetter -eq $system }
        $test = @($vols.volumes) | Where-Object { $_.driveLetter -eq $Drive -or $_.drive_letter -eq $Drive }
        Assert-That ($null -ne $test) "Unidade $Drive não listada: $($vols | ConvertTo-Json -Compress -Depth 5)"
        $sysFlag = if ($sys) { $sys.isSystemVolume, $sys.is_system_volume | Where-Object { $null -ne $_ } | Select-Object -First 1 } else { $null }
        Assert-That ($null -eq $sys -or $sysFlag -eq $true) "Unidade do sistema não marcada: $($sys | ConvertTo-Json -Compress)"
        ($vols.volumes | ConvertTo-Json -Compress -Depth 4)
    }

    Invoke-Step $S 'Unidade do sistema é recusada sem tocar no volume' {
        $before = Real
        $r = P 'SaveResource' @{ resource = @{ id = $nil; displayName = 'Sistema'; kind = 'BitLockerVolume'; target = $system } }
        if ($r.success) {
            $sid = (@((P 'GetSnapshot').resources) | Where-Object { $_.resource.target -eq $system }).resource.id
            $l = @(P 'LockResources' @{ ids = @($sid) })
            P 'DeleteResource' @{ id = $sid } | Out-Null
            Assert-That ($l[0].outcome -eq 'Refused') "Resultado: $($l[0].outcome) $($l[0].detail)"
            "cadastro aceito, bloqueio recusado: $($l[0].detail)"
        } else {
            "cadastro recusado: $($r.errors -join ' ')"
        }
        Assert-That ((Real) -eq $before) "Estado de $Drive mudou."
    }

    Invoke-Step $S "Cadastro de $Drive e grupo sem temporizador" {
        $r = P 'SaveResource' @{ resource = @{ id = $nil; displayName = "Teste $Drive"; kind = 'BitLockerVolume'; target = $Drive } }
        Assert-That $r.success "SaveResource: $($r.errors -join ' ')"
        $script:Id = (@((P 'GetSnapshot').resources) | Where-Object { $_.resource.target -eq $Drive }).resource.id
        Set-TestGroup $null
        $v = View
        Assert-That ($v.state -eq 'Unlocked') "Estado: $($v.state)"
        "id $script:Id"
    }

    Invoke-Step $S 'Arquivo aberto: bloqueio manual é ADIADO e a unidade continua acessível' {
        $fs = [IO.File]::Open("$Drive\$TestFile", 'Open', 'Read', 'ReadWrite')
        try {
            $l = @(P 'LockResources' @{ ids = @($script:Id) })
            Assert-That ($l[0].outcome -eq 'Postponed') "Resultado: $($l[0].outcome) $($l[0].detail)"
            Assert-That ((Real) -eq 'Unlocked') 'A unidade foi bloqueada com arquivo aberto.'
            $script:PostponedDetail = $l[0].detail
        } finally { $fs.Dispose() }
        "adiado: $script:PostponedDetail"
    }

    Invoke-Step $S 'Arquivo fechado: a nova tentativa automática bloqueia' {
        Wait-Until { (Real) -eq 'Locked' } 120 "$Drive bloqueada pela nova tentativa"
        Wait-Until { (View).state -eq 'Locked' } 15 'snapshot Locked'
        Assert-That (-not (Test-Path "$Drive\$TestFile")) 'Arquivo ainda legível com a unidade bloqueada.'
        "BitLocker: $(Real)"
    }

    Invoke-Step $S 'Antes de 24 h, o desbloqueio pede só a senha' {
        $req = P 'GetUnlockRequirement' @{ id = $script:Id }
        Assert-That ($req.factors -eq 'Primary') "Exigência: $($req.factors) / $($req.reason)"
        "$($req.factors) / $($req.reason)"
    }

    Invoke-Step $S 'Senha errada é recusada e a unidade continua bloqueada' {
        $u = P 'Unlock' @{ id = $script:Id; passphrase = 'senha-errada-123'; totp = $null }
        Assert-That ($u.code -eq 'BadCredential') "Código: $($u.code) — $($u.message)"
        Assert-That ((Real) -eq 'Locked') 'Unidade desbloqueada com senha errada.'
        $u.message
    }

    Invoke-Step $S 'Senha certa desbloqueia e o conteúdo está intacto' {
        $u = P 'Unlock' @{ id = $script:Id; passphrase = $Passphrase; totp = $null }
        Assert-That ($u.code -eq 'Unlocked') "Código: $($u.code) — $($u.message)"
        Assert-That ((Real) -eq 'Unlocked') "BitLocker: $(Real)"
        $text = [IO.File]::ReadAllText("$Drive\$TestFile")
        "conteúdo de ${TestFile}: $($text.Length) caractere(s)"
    }

    Invoke-Step $S 'Bloqueio manual sem arquivos abertos' {
        $l = @(P 'LockResources' @{ ids = @($script:Id) })
        Assert-That ($l[0].outcome -eq 'Locked') "Resultado: $($l[0].outcome) $($l[0].detail)"
        Assert-That ((Real) -eq 'Locked') "BitLocker: $(Real)"
        $l[0].detail
    }

    Invoke-Step $S 'Reinício do serviço com a unidade bloqueada preserva estado e registro' {
        Restart-Service ByteHalt
        Wait-Until { Test-PipeExists $pipe } 30 'pipe após reinício'
        Wait-Until { (View).state -eq 'Locked' } 20 'estado Locked após reinício'
        $req = P 'GetUnlockRequirement' @{ id = $script:Id }
        Assert-That ($req.factors -eq 'Primary') "Exigência após reinício: $($req.factors) / $($req.reason)"
        $u = P 'Unlock' @{ id = $script:Id; passphrase = $Passphrase; totp = $null }
        Assert-That ($u.code -eq 'Unlocked' -and (Real) -eq 'Unlocked') "Desbloqueio: $($u.code) / $(Real)"
    }

    Invoke-Step $S 'Bloqueio por inatividade (1 min, modo recurso)' {
        Set-TestGroup 60 'ResourceIdle'
        $t0 = [DateTime]::UtcNow
        Wait-Until { (Real) -eq 'Locked' } 120 "$Drive bloqueada por inatividade"
        $secs = [math]::Round(([DateTime]::UtcNow - $t0).TotalSeconds)
        Assert-That ($secs -ge 55) "Bloqueou cedo demais: $secs s"
        $h = @(P 'GetHistory' @{ limit = 10 }) | Where-Object { $_.resourceId -eq $script:Id } | Select-Object -First 1
        "bloqueada após $secs s; último evento: $($h.message)"
    }

    Invoke-Step $S 'Inatividade com arquivo aberto adia e bloqueia depois de fechar' {
        $u = P 'Unlock' @{ id = $script:Id; passphrase = $Passphrase; totp = $null }
        Assert-That ($u.code -eq 'Unlocked') "Desbloqueio: $($u.code)"
        $fs = [IO.File]::Open("$Drive\$TestFile", 'Open', 'Read', 'ReadWrite')
        try {
            Wait-Until { (View).last_outcome -eq 'Postponed' -or (View).lastOutcome -eq 'Postponed' } 120 'adiamento por arquivo aberto'
            Assert-That ((Real) -eq 'Unlocked') 'Bloqueou com arquivo aberto.'
        } finally { $fs.Dispose() }
        Wait-Until { (Real) -eq 'Locked' } 120 'bloqueio após fechar o arquivo'
        'adiado com arquivo aberto; bloqueado após fechar'
    }

    Invoke-Step $S 'Bloqueio externo (fora do ByteHalt) é detectado' {
        Set-TestGroup $null
        Ensure-Unlocked
        Wait-Until { (View).state -eq 'Unlocked' } 20 'desbloqueio externo detectado'
        Lock-BitLocker -MountPoint $Drive | Out-Null
        Wait-Until { (View).state -eq 'Locked' } 20 'bloqueio externo detectado'
        $req = P 'GetUnlockRequirement' @{ id = $script:Id }
        "detectado; exigência para desbloquear: $($req.factors) / $($req.reason)"
    }

    Invoke-Step $S 'Senha e registro não aparecem em texto puro nos dados do serviço' {
        $needles = @([Text.Encoding]::UTF8.GetBytes($Passphrase), [Text.Encoding]::Unicode.GetBytes($Passphrase))
        $hits = @()
        foreach ($f in Get-ChildItem 'C:\ProgramData\ByteHalt' -Recurse -File) {
            $s = [IO.File]::Open($f.FullName, 'Open', 'Read', 'ReadWrite')
            try { $bytes = New-Object byte[] $s.Length; [void]$s.Read($bytes, 0, $bytes.Length) } finally { $s.Dispose() }
            $hex = [BitConverter]::ToString($bytes)
            foreach ($n in $needles) { if ($hex.Contains([BitConverter]::ToString($n))) { $hits += $f.Name } }
            if ($f.Extension -eq '.lock' -and $bytes.Length -gt 0 -and $bytes[0] -eq [byte][char]'{') { $hits += "$($f.Name) (JSON em claro)" }
        }
        Assert-That ($hits.Count -eq 0) "Encontrado em: $($hits -join ', ')"
        "$(@(Get-ChildItem 'C:\ProgramData\ByteHalt' -Recurse -File).Count) arquivo(s) verificados"
    }
} catch {
    Add-Step $S 'Erro fatal' 'failed' 0 "$($_.Exception.Message)"
} finally {
    # Limpeza: unidade desbloqueada e configuração removida (o serviço continua instalado).
    try { Ensure-Unlocked } catch { Add-Step $S 'Limpeza: desbloquear' 'failed' 0 $_.Exception.Message }
    try {
        if ($script:GroupId) { P 'DeleteGroup' @{ id = $script:GroupId } | Out-Null }
        if ($script:Id) { P 'DeleteResource' @{ id = $script:Id } | Out-Null }
    } catch { Add-Step $S 'Limpeza: configuração' 'failed' 0 $_.Exception.Message }
    $history = try { @(P 'GetHistory' @{ limit = 60 }) } catch { @() }
    $result = [ordered]@{ finished = (Get-Date).ToString('o'); drive_final = (Real); steps = @($script:Steps); history = $history }
    '=====RESULT====='
    $result | ConvertTo-Json -Depth 8 -Compress
}
