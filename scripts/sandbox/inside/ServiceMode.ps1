# Serviço do Windows real (LocalSystem) DENTRO do Sandbox, com volumes simulados.
# Valida o pipe de produção (dono SYSTEM, ACL, identificação do chamador) e a interface sem --dev.

$W = 'Serviço do Windows'
$svcName = 'ByteHalt'
$prodPipe = 'ByteHalt.Service.v1'
$owners = @('S-1-5-18')   # somente SYSTEM
$prodData = 'C:\ProgramData\ByteHalt-sandbox'
$pass = 'bytehalt-teste'  # senha FICTÍCIA do volume simulado

function Prod([string]$command, $payload = $null) { Invoke-ByteHaltPipe $prodPipe $command $payload $owners }
function Remove-TestService { try { Stop-Service $svcName -ErrorAction SilentlyContinue; & sc.exe delete $svcName | Out-Null } catch { } }

Invoke-Step $W 'Instalar e iniciar como LocalSystem (simulado)' {
    $bin = "`"$pkg\service\bytehalt-service.exe`" --service --simulate --data-dir `"$prodData`""
    New-Service -Name $svcName -BinaryPathName $bin -DisplayName 'ByteHalt (teste no Sandbox)' -StartupType Manual | Out-Null
    Start-Service $svcName
    Wait-Until { (Get-Service $svcName).Status -eq 'Running' -and (Test-PipeExists $prodPipe) } 60 'serviço em execução com pipe'
}
if (@($script:Steps | Where-Object { $_.suite -eq $W -and $_.status -eq 'failed' }).Count) {
    Skip-Step $W 'Demais casos do serviço do Windows' 'Interrompidos: o serviço não iniciou.'
    Remove-TestService
    return
}
Invoke-Step $W 'Pipe de produção pertence ao SYSTEM e nega a rede' {
    $client = New-Object System.IO.Pipes.NamedPipeClientStream('.', $prodPipe, [System.IO.Pipes.PipeDirection]::InOut)
    try {
        $client.Connect(5000)
        $acl = $client.GetAccessControl()
        $owner = $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
        $sddl = $acl.GetSecurityDescriptorSddlForm('Access')
    } finally { $client.Dispose() }
    Assert-That ($owner -eq 'S-1-5-18') "Dono: $owner"
    Assert-That ($sddl -match 'D;;[^;]*;;;NU') "Sem negação para NETWORK: $sddl"
    Assert-That ($sddl -notmatch ';;;WD\)' -and $sddl -notmatch ';;;BU\)') "Acesso para Todos/Usuários: $sddl"
    $iu = [regex]::Match($sddl, 'A;;(0x[0-9a-fA-F]+);;;IU').Groups[1].Value
    Assert-That ($iu -and (([Convert]::ToInt32($iu, 16) -band 0x4) -eq 0)) "Usuários interativos podem criar instâncias do pipe: $sddl"
    "dono $owner; $sddl"
}
Invoke-Step $W 'Pasta de dados restrita a SYSTEM e Administradores' {
    $sddl = (Get-Acl -LiteralPath $prodData).Sddl
    Assert-That ($sddl -notmatch ';;;BU\)' -and $sddl -notmatch ';;;WD\)' -and $sddl -notmatch ';;;AU\)') "ACL: $sddl"
    $sddl
}
Invoke-Step $W 'Comando fora da lista é recusado pelo serviço' {
    $refused = $false
    try { Prod 'RunShell' @{ cmd = 'whoami' } | Out-Null } catch { $refused = $_.Exception.Message -like '*BadRequest*' }
    Assert-That $refused 'Comando desconhecido não foi recusado como BadRequest.'
}
Invoke-Step $W 'Configuração pelo pipe com identificação do chamador' {
    $saved = Prod 'SaveResource' @{ resource = @{ id = '00000000-0000-0000-0000-000000000000'; displayName = 'Unidade D:'; kind = 'BitLockerVolume'; target = 'D:' } }
    Assert-That $saved.success "SaveResource: $($saved.errors -join ' ')"
    $script:ProdResource = (Prod 'GetSnapshot').resources[0].resource.id
    $g = Prod 'SaveGroup' @{ group = @{ id = '00000000-0000-0000-0000-000000000000'; name = 'Discos'; resourceIds = @($script:ProdResource); inactivitySecs = 3600; mode = 'Combined'; totpThresholdSecs = 86400; lockOnWorkstationLock = $true } }
    Assert-That $g.success "SaveGroup: $($g.errors -join ' ')"
}
Invoke-Step $W 'Bloqueio pelo pipe grava o registro protegido (só senha antes de 24 h)' {
    $l = @(Prod 'LockAll')
    Assert-That ($l[0].outcome -eq 'Locked') "LockAll: $($l[0].outcome)"
    $req = Prod 'GetUnlockRequirement' @{ id = $script:ProdResource }
    Assert-That ($req.factors -eq 'Primary') "Exigência: $($req.factors) / $($req.reason)"
}
Invoke-Step $W 'Interface sem --dev conecta ao serviço do sistema' {
    $probeDir = "$work\probe"
    $p = Start-Process -FilePath "$pkg\proof\bytehalt.exe" -ArgumentList @('--gui-probe', "`"$probeDir`"") -RedirectStandardError "$work\logs\probe.log" -NoNewWindow -PassThru
    if (-not $p.WaitForExit(60000)) { Stop-Process -Id $p.Id -Force }
    Copy-Item "$probeDir\shots\*" "$work\shots\" -ErrorAction SilentlyContinue
    $probe = [IO.File]::ReadAllText("$probeDir\probe.json") | ConvertFrom-Json
    Assert-That ($probe.connected -and $probe.text -like 'Conectado*') "Interface: $($probe.text)"
    $probe.text
}
Invoke-Step $W 'Reinício do serviço do Windows preserva estado e registro' {
    Restart-Service $svcName
    Wait-Until { Test-PipeExists $prodPipe } 30 'pipe após reinício'
    $snap = Prod 'GetSnapshot'
    Assert-That (@($snap.groups).Count -eq 1 -and $snap.resources[0].state -eq 'Locked') "Estado: $(@($snap.groups).Count) grupo(s), $($snap.resources[0].state)"
    $unlock = Prod 'Unlock' @{ id = $script:ProdResource; passphrase = $pass; totp = $null }
    Assert-That ($unlock.code -eq 'Unlocked') "Desbloqueio: $($unlock.code)"
}
if ($config.workstation_lock) {
    Invoke-Step $W 'Bloquear o Windows bloqueia o grupo com essa opção' {
        [void][ByteHaltTest.Native]::LockWorkStation()
        Wait-Until { (Prod 'GetSnapshot').resources[0].state -eq 'Locked' } 30 'D: bloqueado após bloquear o Windows'
    }
} else {
    Skip-Step $W 'Bloquear o Windows bloqueia o grupo com essa opção' 'Desativado (use -IncludeWorkstationLock); encerra a sessão interativa do Sandbox.'
}
Remove-TestService
