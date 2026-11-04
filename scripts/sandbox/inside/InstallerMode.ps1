# Instalador (Fase 5) DENTRO do Sandbox: instalar, atualizar por cima, desinstalar mantendo os dados,
# reinstalar e desinstalar com /purge. Tudo em modo silencioso, conferindo serviço, arquivos, registro e
# atalho a cada passo. Dot-sourced por Run-InsideSandbox.ps1 (depois do ServiceMode, que remove o seu serviço).

$I = 'Instalador'
$setup = "$pkg\setup\bytehalt-setup.exe"
$dir = Join-Path $env:ProgramW6432 'ByteHalt'
$data = Join-Path $env:ProgramData 'ByteHalt'
$lnk = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\ByteHalt.lnk'
$uninstallKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\ByteHalt'
$runKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'

function Invoke-Setup([string[]]$setupArgs) {
    $p = Start-Process -FilePath $setup -ArgumentList $setupArgs -PassThru -Wait
    return $p.ExitCode
}

function Assert-Installed {
    $svc = Get-CimInstance Win32_Service -Filter "Name='ByteHalt'"
    Assert-That ($null -ne $svc) 'Serviço ByteHalt não existe.'
    Assert-That ($svc.State -eq 'Running' -and $svc.StartMode -eq 'Auto') "Serviço: $($svc.State) / $($svc.StartMode)"
    Assert-That ($svc.PathName -like "*$dir\bytehalt-service.exe*--service*") "Caminho do serviço: $($svc.PathName)"
    Assert-That ($svc.StartName -eq 'LocalSystem') "Conta do serviço: $($svc.StartName)"
    foreach ($f in 'bytehalt.exe', 'bytehalt-service.exe', 'bytehalt-setup.exe', 'licencas\GPUI-Apache-2.0.txt') { Assert-That (Test-Path (Join-Path $dir $f)) "Falta $f" }
    $run = (Get-ItemProperty $runKey -Name ByteHalt -ErrorAction SilentlyContinue).ByteHalt
    Assert-That ($run -eq "`"$dir\bytehalt.exe`" --tray") "Inicialização: $run"
    $u = Get-ItemProperty $uninstallKey -ErrorAction SilentlyContinue
    Assert-That ($u.DisplayName -eq 'ByteHalt' -and $u.DisplayVersion -and $u.UninstallString -like '*bytehalt-setup.exe* /uninstall') "Aplicativos instalados: $($u | ConvertTo-Json -Compress)"
    Assert-That (Test-Path $lnk) 'Atalho do menu Iniciar ausente.'
    Wait-Until { Test-PipeExists 'ByteHalt.Service.v1' } 30 'pipe de produção do serviço instalado'
    $pong = Invoke-ByteHaltPipe 'ByteHalt.Service.v1' 'Ping' $null @('S-1-5-18')
    Assert-That (-not $pong.simulated) 'Serviço instalado em modo simulado.'
    "serviço $($svc.State)/$($svc.StartMode), v$($pong.version), atalho e entrada de desinstalação presentes"
}

function Assert-Removed {
    Assert-That ($null -eq (Get-CimInstance Win32_Service -Filter "Name='ByteHalt'")) 'Serviço ainda existe.'
    Assert-That (-not (Test-Path (Join-Path $dir 'bytehalt-service.exe'))) 'Executáveis ainda em Program Files.'
    Assert-That ($null -eq (Get-ItemProperty $runKey -Name ByteHalt -ErrorAction SilentlyContinue)) 'Inicialização ainda registrada.'
    Assert-That (-not (Test-Path $uninstallKey)) 'Entrada de desinstalação ainda existe.'
    Assert-That (-not (Test-Path $lnk)) 'Atalho ainda existe.'
}

if (-not (Test-Path $setup)) {
    Skip-Step $I 'Instalador' 'Pacote sem setup\bytehalt-setup.exe.'
} else {
    # O ServiceMode acabou de remover o serviço de teste com o mesmo nome: espera a remoção concluir.
    Wait-Until { -not (Get-Service ByteHalt -ErrorAction SilentlyContinue) } 60 'remoção do serviço de teste anterior'
    Invoke-Step $I 'Instalação silenciosa registra serviço, inicialização, atalho e desinstalação' {
        $code = Invoke-Setup @('/quiet')
        Assert-That ($code -eq 0) "Código de saída: $code — $(Get-Content (Join-Path $env:TEMP 'bytehalt-setup.log') -Raw -ErrorAction SilentlyContinue)"
        Assert-Installed
    }
    Invoke-Step $I 'Configuração criada antes da atualização' {
        $r = Invoke-ByteHaltPipe 'ByteHalt.Service.v1' 'SaveGroup' @{ group = @{ id = '00000000-0000-0000-0000-000000000000'; name = 'Persistente'; resourceIds = @(); inactivitySecs = 600; mode = 'Combined'; totpThresholdSecs = 86400; lockOnWorkstationLock = $false; lockOnSuspend = $true } } @('S-1-5-18')
        Assert-That $r.success "SaveGroup: $($r.errors -join ' ')"
    }
    Invoke-Step $I 'Atualização por cima mantém o serviço e a configuração' {
        $code = Invoke-Setup @('/quiet')
        Assert-That ($code -eq 0) "Código de saída: $code"
        $detail = Assert-Installed
        $groups = @((Invoke-ByteHaltPipe 'ByteHalt.Service.v1' 'GetSnapshot' $null @('S-1-5-18')).groups)
        Assert-That ($groups.name -contains 'Persistente') "Grupos após atualizar: $($groups.name -join ', ')"
        $detail
    }
    Invoke-Step $I 'Desinstalação silenciosa remove tudo e mantém os dados' {
        $code = Invoke-Setup @('/uninstall', '/quiet')
        Assert-That ($code -eq 0) "Código de saída: $code — $(Get-Content (Join-Path $env:TEMP 'bytehalt-setup.log') -Raw -ErrorAction SilentlyContinue)"
        Assert-Removed
        Assert-That (Test-Path (Join-Path $data 'bytehalt.db')) 'Dados apagados sem /purge.'
        "removido; dados mantidos em $data"
    }
    Invoke-Step $I 'Reinstalação reaproveita os dados; /purge apaga tudo' {
        Assert-That ((Invoke-Setup @('/quiet')) -eq 0) 'Reinstalação falhou.'
        $groups = @((Invoke-ByteHaltPipe 'ByteHalt.Service.v1' 'GetSnapshot' $null @('S-1-5-18')).groups)
        Assert-That ($groups.name -contains 'Persistente') 'Configuração não foi reaproveitada.'
        $code = Invoke-Setup @('/uninstall', '/quiet', '/purge')
        Assert-That ($code -eq 0) "Código de saída: $code"
        Assert-Removed
        Assert-That (-not (Test-Path $data)) "Dados ainda em $data"
        'reinstalado com a configuração anterior; /purge apagou os dados'
    }
}
