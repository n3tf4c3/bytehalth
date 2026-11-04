param(
    [Parameter(Mandatory)][string]$Drive,          # unidade de TESTE autorizada (ex.: E:)
    [Parameter(Mandatory)][string]$Passphrase      # senha de teste do cofre criado aqui
)
# Testes dos COFRES em modo real numa VM de teste (Windows PowerShell 5.1, administrador, logon local).
# Cria uma pasta sintética em <Drive>\bh-cofre-teste, transforma em cofre (VHDX + BitLocker + ponto de
# montagem), exercita troca, bloqueio, reinício, "reboot" (desanexar), reserva e remoção, e limpa tudo.
# A senha e a chave de recuperação nunca vão para o log nem para os passos.
$ErrorActionPreference = 'Stop'
$work = Join-Path $env:TEMP 'bytehalt-vm-test'
New-Item -ItemType Directory -Force $work | Out-Null
$script:LogFile = Join-Path $work 'vault.log'
. (Join-Path $PSScriptRoot 'Common.ps1')

$S = 'Cofre real'
$pipe = 'ByteHalt.Service.v1'
$Drive = $Drive.TrimEnd('\').ToUpper()
if ($Drive -eq $env:SystemDrive.ToUpper()) { throw "Recusa: $Drive é a unidade do sistema." }
$root = "$Drive\bh-cofre-teste"
$folder = "$root\Projeto"
$store = "$Drive\ByteHalt.Cofres"
$script:Vault = $null
$script:Recovery = $null

function P([string]$command, $payload = $null) { Invoke-ByteHaltPipe $pipe $command $payload @('S-1-5-18') }
function V { @(P 'GetVaults') | Where-Object { $_.vault.id -eq $script:Vault.id } | Select-Object -First 1 }
# mountvol escreve o erro na saída comum: só vale um nome de volume.
function Mounted {
    $o = (& mountvol.exe "$folder\" /L 2>$null) -join ' '
    if ($o -match '\\\\\?\\Volume\{[0-9a-fA-F-]+\}\\') { $Matches[0] } else { '' }
}
function Row { $rid = (V).vault.resourceId; @((P 'GetSnapshot').resources) | Where-Object { $_.resource.id -eq $rid } }
function Enc([string]$device) { Get-CimInstance -Namespace root\CIMV2\Security\MicrosoftVolumeEncryption -ClassName Win32_EncryptableVolume | Where-Object DeviceID -eq $device }
# Passo essencial falhou: interrompe (a limpeza no finally desfaz o que foi criado).
function Must { if ($script:Steps[-1].status -eq 'failed') { throw "Interrompido em: $($script:Steps[-1].name)" } }

# Desfaz só o que este teste cria: cofres sob $root, a pasta $root e a pasta dos VHDX se vazia.
function Clear-Test {
    if ((Get-Service ByteHalt).Status -ne 'Running') { Start-Service ByteHalt; Wait-Until { Test-PipeExists $pipe } 30 'pipe' }
    foreach ($v in @(P 'GetVaults') | Where-Object { $_.vault.originalPath -like "$root\*" }) {
        if ($v.vault.stage -eq 'Active') {
            $e = Enc $v.vault.volume
            if ($e) { Invoke-CimMethod -InputObject $e -MethodName UnlockWithPassphrase -Arguments @{ Passphrase = $Passphrase } | Out-Null }
            Start-Sleep 2
            P 'RemoveVault' @{ id = $v.vault.id } | Out-Null
        } else {
            P 'DiscardVault' @{ id = $v.vault.id } | Out-Null
        }
    }
    if (Test-Path $root) { Remove-Item $root -Recurse -Force }
    if ((Test-Path $store) -and -not (Get-ChildItem $store -Force)) { Remove-Item $store -Force }
}

try {
    Invoke-Step $S 'Sobras de uma rodada anterior deste teste são limpas' {
        $before = @(P 'GetVaults' | Where-Object { $_.vault.originalPath -like "$root\*" }).Count
        Clear-Test
        "$before cofre(s) de teste anterior(es) removido(s)"
    }
    Must
    Invoke-Step $S 'Pré-condições: serviço real, sem cofres, pasta de teste criada' {
        Assert-That (-not (P 'Ping').simulated) 'Serviço em modo simulado.'
        Assert-That (@(P 'GetVaults').Count -eq 0) 'Já existe cofre no serviço.'
        Assert-That (-not (Test-Path $root)) "$root já existe."
        New-Item -ItemType Directory -Force "$folder\src", "$folder\docs" | Out-Null
        [IO.File]::WriteAllText("$folder\README.md", '# projeto')
        [IO.File]::WriteAllText("$folder\src\main.rs", 'fn main() {}')
        $rnd = New-Object byte[] (3MB); (New-Object Random 42).NextBytes($rnd); [IO.File]::WriteAllBytes("$folder\dados.bin", $rnd)
        [IO.File]::WriteAllText("$folder\docs\oculto.txt", 'oculto'); (Get-Item "$folder\docs\oculto.txt").Attributes = 'Hidden'
        # Arquivo com DACL protegida e explícita (só SYSTEM, Administradores e o usuário de teste).
        [IO.File]::WriteAllText("$folder\docs\restrito.txt", 'restrito')
        $acl = Get-Acl "$folder\docs\restrito.txt"; $acl.SetAccessRuleProtection($true, $false)
        foreach ($id in 'NT AUTHORITY\SYSTEM', 'BUILTIN\Administradores', "$env:COMPUTERNAME\$env:USERNAME") {
            try { $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($id, 'FullControl', 'Allow'))) } catch { }
        }
        Set-Acl "$folder\docs\restrito.txt" $acl
        $script:RestritoSddl = (Get-Acl "$folder\docs\restrito.txt").Sddl
        "5 arquivos; DACL restrita: $script:RestritoSddl"
    }

    Must
    Invoke-Step $S 'Pastas do sistema e o perfil são recusados' {
        foreach ($p in $env:SystemRoot, $env:USERPROFILE, "$env:USERPROFILE\AppData\Local") {
            $plan = P 'AnalyzeVault' @{ path = $p }
            Assert-That (@($plan.issues).Count -gt 0) "$p foi aceito."
        }
        'Windows, perfil e AppData recusados'
    }

    Invoke-Step $S 'Análise da pasta de teste' {
        $plan = P 'AnalyzeVault' @{ path = $folder }
        Assert-That (@($plan.issues).Count -eq 0) "Impedimentos: $($plan.issues -join ' | ')"
        Assert-That ($plan.inventory.files -eq 5) "Arquivos: $($plan.inventory.files)"
        $script:Max = $plan.suggestedMaxBytes
        "{0} arquivo(s), {1:N0} bytes, máximo sugerido {2:N0} bytes" -f $plan.inventory.files, $plan.inventory.bytes, $plan.suggestedMaxBytes
    }

    Must
    Invoke-Step $S 'Preparação: VHDX, BitLocker, cópia e verificação' {
        $script:Vault = P 'PrepareVault' @{ name = 'Projeto VM'; path = $folder; passphrase = $Passphrase; max_bytes = [uint64]$script:Max }
        $deadline = (Get-Date).AddMinutes(5)
        do {
            Start-Sleep -Milliseconds 700
            $v = V
            if ($v.job.recoveryKey) { $script:Recovery = $v.job.recoveryKey }
        } while ($v.vault.stage -eq 'Preparing' -and (Get-Date) -lt $deadline)
        if (-not $script:Recovery) { $v2 = V; if ($v2.job.recoveryKey) { $script:Recovery = $v2.job.recoveryKey } }
        Assert-That ($v.vault.stage -eq 'Ready') "Etapa: $($v.vault.stage) — $($v.vault.error) $($v.job.error)"
        Assert-That ($script:Recovery -match '^\d{6}(-\d{6}){7}$') 'Chave de recuperação ausente ou fora do formato.'
        Assert-That (-not (V).job.recoveryKey) 'A chave de recuperação saiu mais de uma vez.'
        $script:Vault = $v.vault
        Assert-That (Test-Path $v.vault.storePath) "VHDX ausente: $($v.vault.storePath)"
        $e = Enc $v.vault.volume
        $prot = (Invoke-CimMethod -InputObject $e -MethodName GetProtectionStatus).ProtectionStatus
        $types = @((Invoke-CimMethod -InputObject $e -MethodName GetKeyProtectors).VolumeKeyProtectorID | ForEach-Object { (Invoke-CimMethod -InputObject $e -MethodName GetKeyProtectorType -Arguments @{ VolumeKeyProtectorID = $_ }).KeyProtectorType })
        Assert-That ($prot -eq 1) "Proteção BitLocker: $prot"
        Assert-That (($types -contains 8) -and ($types -contains 3)) "Protetores: $($types -join ',')"
        $storeSddl = (Get-Acl $store).Sddl
        Assert-That ($storeSddl -notmatch ';;;BU\)' -and $storeSddl -notmatch ';;;WD\)') "ACL de $store : $storeSddl"
        "volume $($v.vault.volume); protetores senha+recuperação; $store restrita"
    }

    Must
    Invoke-Step $S 'Arquivo aberto impede a troca e nada muda' {
        $fs = [IO.File]::Open("$folder\README.md", 'Open', 'Read', 'ReadWrite')
        try {
            $refused = $false
            try { P 'SwapVault' @{ id = $script:Vault.id } | Out-Null } catch { $refused = $_.Exception.Message -match 'Feche os programas' }
            Assert-That $refused 'A troca não foi recusada com arquivo aberto.'
        } finally { $fs.Dispose() }
        Assert-That ((V).vault.stage -eq 'Ready' -and -not (Mounted)) 'Estado mudou após a recusa.'
        Assert-That ((Get-Content "$folder\README.md") -eq '# projeto') 'Original alterado.'
    }

    Invoke-Step $S 'Troca: cofre montado no caminho, reserva preservada, ACL e atributos fiéis' {
        [IO.File]::WriteAllText("$folder\depois.txt", 'criado depois da preparação')
        $script:Vault = P 'SwapVault' @{ id = $script:Vault.id }
        Assert-That ($script:Vault.stage -eq 'Active') "Etapa: $($script:Vault.stage)"
        $m = Mounted
        Assert-That ($m -and $m.Trim() -eq $script:Vault.volume) "Ponto de montagem: '$m'"
        Assert-That ((Test-Path "$folder\depois.txt") -and (Test-Path $script:Vault.reservePath)) 'Ressincronização ou reserva falhou.'
        Assert-That ((Get-Item "$folder\docs\oculto.txt" -Force).Attributes -match 'Hidden') 'Atributo oculto perdido.'
        $now = (Get-Acl "$folder\docs\restrito.txt").Sddl
        Assert-That ($now -eq $script:RestritoSddl) "DACL diferente: $now"
        "montado; reserva $($script:Vault.reservePath); DACL restrita preservada"
    }

    Must
    Invoke-Step $S 'Bloquear o cofre deixa o caminho inacessível' {
        $rid = $script:Vault.resourceId
        $l = @(P 'LockResources' @{ ids = @($rid) })
        Assert-That ($l[0].outcome -eq 'Locked') "Resultado: $($l[0].outcome) $($l[0].detail)"
        $msg = try { Get-ChildItem $folder -ErrorAction Stop | Out-Null; 'ACESSÍVEL' } catch { $_.Exception.Message }
        Assert-That ($msg -ne 'ACESSÍVEL') 'Pasta legível com o cofre bloqueado.'
        Assert-That ((Row).state -eq 'Locked') "Estado: $((Row).state)"
        $msg.Trim()
    }

    Invoke-Step $S 'Senha errada é recusada; a certa desbloqueia' {
        $rid = $script:Vault.resourceId
        $u = P 'Unlock' @{ id = $rid; passphrase = 'senha-errada-123'; totp = $null }
        Assert-That ($u.code -eq 'BadCredential') "Errada: $($u.code)"
        $u = P 'Unlock' @{ id = $rid; passphrase = $Passphrase; totp = $null }
        Assert-That ($u.code -eq 'Unlocked') "Certa: $($u.code) — $($u.message)"
        Assert-That ((Get-Content "$folder\README.md") -eq '# projeto') 'Conteúdo incorreto.'
    }

    Invoke-Step $S 'Reinício do serviço mantém o cofre ativo e montado' {
        Restart-Service ByteHalt
        Wait-Until { Test-PipeExists $pipe } 30 'pipe após reinício'
        Assert-That ((V).vault.stage -eq 'Active' -and (Mounted)) 'Cofre não está ativo e montado.'
        Wait-Until { (Row).state -eq 'Unlocked' } 20 'estado Unlocked'
    }

    Invoke-Step $S 'Disco desanexado (como após reiniciar o PC) volta bloqueado e montado' {
        Stop-Service ByteHalt
        $dp = "$work\dp.txt"; Set-Content $dp "select vdisk file=`"$($script:Vault.storePath)`"", 'detach vdisk' -Encoding ASCII
        & diskpart.exe /s $dp | Out-Null; Remove-Item $dp
        Assert-That (-not (Test-Path "$folder\README.md")) 'Conteúdo visível com o disco desanexado.'
        Start-Service ByteHalt
        Wait-Until { Test-PipeExists $pipe } 30 'pipe'
        Wait-Until { (Row).state -eq 'Locked' } 30 'cofre anexado de novo e bloqueado'
        $req = P 'GetUnlockRequirement' @{ id = $script:Vault.resourceId }
        if ($req.factors -eq 'Primary') {
            $u = P 'Unlock' @{ id = $script:Vault.resourceId; passphrase = $Passphrase; totp = $null }
            Assert-That ($u.code -eq 'Unlocked') "Desbloqueio: $($u.code)"
            $how = 'desbloqueado pelo ByteHalt com a senha'
        } else {
            # Sem registro do horário do bloqueio, a regra de 24 h falha fechada (TOTP, Fase 3):
            # desbloqueia direto pelo BitLocker para seguir o teste.
            $r = Invoke-CimMethod -InputObject (Enc $script:Vault.volume) -MethodName UnlockWithPassphrase -Arguments @{ Passphrase = $Passphrase }
            Assert-That ($r.ReturnValue -eq 0) ("BitLocker: 0x{0:X8}" -f $r.ReturnValue)
            $how = "o ByteHalt exigiu $($req.factors) ($($req.reason)); desbloqueado direto pelo BitLocker"
        }
        Wait-Until { Test-Path "$folder\src\main.rs" } 15 'conteúdo pelo caminho'
        Assert-That ((Get-Content "$folder\src\main.rs") -eq 'fn main() {}') 'Conteúdo após reanexar.'
        Wait-Until { (Row).state -eq 'Unlocked' } 20 'estado Unlocked'
        "reanexado pelo serviço e bloqueado; $how"
    }

    Invoke-Step $S 'Apagar a reserva' {
        $r = $script:Vault.reservePath
        $script:Vault = P 'DeleteVaultReserve' @{ id = $script:Vault.id }
        Assert-That (-not $script:Vault.reservePath -and -not (Test-Path $r)) 'Reserva não apagada.'
        Assert-That (Test-Path "$folder\dados.bin") 'Conteúdo do cofre sumiu.'
    }

    Invoke-Step $S 'Remover o cofre devolve a pasta comum com o trabalho feito no cofre' {
        [IO.File]::WriteAllText("$folder\no-cofre.txt", 'escrito dentro do cofre')
        $store_path = $script:Vault.storePath; $rid = $script:Vault.resourceId
        P 'RemoveVault' @{ id = $script:Vault.id } | Out-Null
        Assert-That (-not (Mounted)) 'Ainda é ponto de montagem.'
        Assert-That ((Get-Content "$folder\no-cofre.txt") -eq 'escrito dentro do cofre') 'Trabalho no cofre perdido.'
        Assert-That ((Get-Acl "$folder\docs\restrito.txt").Sddl -eq $script:RestritoSddl) 'DACL perdida na volta.'
        Assert-That (-not (Test-Path $store_path)) 'VHDX não apagado.'
        Assert-That (@(P 'GetVaults').Count -eq 0 -and -not (@((P 'GetSnapshot').resources) | Where-Object { $_.resource.id -eq $rid })) 'Registro ou recurso sobrou.'
        $script:Vault = $null
        'pasta comum, conteúdo e DACL preservados, disco apagado'
    }
} catch {
    Add-Step $S 'Erro fatal' 'failed' 0 "$($_.Exception.Message)"
} finally {
    # Limpeza: só o que este teste criou.
    try { Clear-Test } catch { Add-Step $S 'Limpeza' 'failed' 0 $_.Exception.Message }
    $result = [ordered]@{ finished = (Get-Date).ToString('o'); leftovers = @((Test-Path $root), (Test-Path $store)); steps = @($script:Steps); history = @(try { P 'GetHistory' @{ limit = 40 } } catch { }) }
    '=====RECOVERY=====' + $script:Recovery
    '=====RESULT====='
    $result | ConvertTo-Json -Depth 8 -Compress
}
