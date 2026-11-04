param(
    [Parameter(Mandatory)][string]$Drive,          # unidade de TESTE autorizada (ex.: E:)
    [Parameter(Mandatory)][string]$Passphrase      # senha do cofre de teste criado aqui
)
# Fase 5 em modo real: o instalador atualiza a instalação de teste, RECUSA desinstalar com um cofre,
# desinstala sem cofres e reinstala. Só a unidade $Drive é usada; a VM termina com o ByteHalt instalado.
$ErrorActionPreference = 'Stop'
$work = Join-Path $env:TEMP 'bytehalt-vm-test'
New-Item -ItemType Directory -Force $work | Out-Null
$script:LogFile = Join-Path $work 'installer.log'
. (Join-Path $PSScriptRoot 'Common.ps1')

$S = 'Instalador real'
$pipe = 'ByteHalt.Service.v1'
$setup = Join-Path $PSScriptRoot 'ByteHalt-Setup.exe'
$dir = Join-Path $env:ProgramW6432 'ByteHalt'
$folder = "$($Drive.TrimEnd('\'))\bh-setup-teste\Projeto"
$script:Vault = $null
function P([string]$command, $payload = $null) { Invoke-ByteHaltPipe $pipe $command $payload @('S-1-5-18') }
function Setup([string[]]$a) { (Start-Process -FilePath $setup -ArgumentList $a -PassThru -Wait).ExitCode }
function Svc { Get-CimInstance Win32_Service -Filter "Name='ByteHalt'" }

try {
    Invoke-Step $S 'Atualiza a instalação manual de teste para Program Files\ByteHalt' {
        $before = (Svc).PathName
        $code = Setup @('/quiet')
        Assert-That ($code -eq 0) "Código: $code — $(Get-Content (Join-Path $env:TEMP 'bytehalt-setup.log') -Raw -ErrorAction SilentlyContinue)"
        $s = Svc
        Assert-That ($s.State -eq 'Running' -and $s.StartMode -eq 'Auto' -and $s.PathName -like "*$dir\bytehalt-service.exe*") "Serviço: $($s.State)/$($s.StartMode) $($s.PathName)"
        Wait-Until { Test-PipeExists $pipe } 30 'pipe'
        Assert-That (-not (P 'Ping').simulated) 'Modo simulado.'
        "antes: $before; agora: $($s.PathName)"
    }

    Invoke-Step $S 'Desinstalação é RECUSADA com um cofre registrado' {
        New-Item -ItemType Directory -Force $folder | Out-Null
        [IO.File]::WriteAllText("$folder\a.txt", 'conteudo')
        $plan = P 'AnalyzeVault' @{ path = $folder }
        Assert-That (@($plan.issues).Count -eq 0) "Análise: $($plan.issues -join ' | ')"
        $script:Vault = P 'PrepareVault' @{ name = 'Teste instalador'; path = $folder; passphrase = $Passphrase; max_bytes = [uint64]$plan.suggestedMaxBytes }
        Wait-Until { (@(P 'GetVaults') | Where-Object { $_.vault.id -eq $script:Vault.id }).vault.stage -eq 'Ready' } 300 'cofre pronto'
        $code = Setup @('/uninstall', '/quiet')
        Assert-That ($code -eq 2) "Código: $code (esperado 2 = recusado)"
        Assert-That ((Svc).State -eq 'Running') 'O serviço foi parado mesmo com a recusa.'
        $log = Get-Content (Join-Path $env:TEMP 'bytehalt-setup.log') -Raw
        Assert-That ($log -match 'Teste instalador') "Mensagem sem o nome do cofre: $log"
        'recusado (código 2); serviço intacto'
    }

    Invoke-Step $S 'Sem cofres, desinstala; reinstala com a configuração preservada' {
        P 'DiscardVault' @{ id = $script:Vault.id } | Out-Null
        $script:Vault = $null
        $code = Setup @('/uninstall', '/quiet')
        Assert-That ($code -eq 0) "Desinstalar: $code"
        Assert-That ($null -eq (Svc)) 'Serviço ainda existe.'
        Assert-That (-not (Test-Path "$dir\bytehalt-service.exe")) 'Arquivos ainda em Program Files.'
        $code = Setup @('/quiet')
        Assert-That ($code -eq 0) "Reinstalar: $code"
        Wait-Until { Test-PipeExists $pipe } 30 'pipe'
        Assert-That ((Svc).State -eq 'Running') 'Serviço não voltou.'
        'desinstalado e reinstalado'
    }
} catch {
    Add-Step $S 'Erro fatal' 'failed' 0 "$($_.Exception.Message)"
} finally {
    try {
        if ($script:Vault) { P 'DiscardVault' @{ id = $script:Vault.id } | Out-Null }
        $root = Split-Path $folder -Parent
        if (Test-Path $root) { Remove-Item $root -Recurse -Force }
        $store = "$($Drive.TrimEnd('\'))\ByteHalt.Cofres"
        if ((Test-Path $store) -and -not (Get-ChildItem $store -Force)) { Remove-Item $store -Force }
        # A instalação manual dos testes anteriores (não é mais usada pelo serviço).
        $old = Join-Path $env:ProgramW6432 'ByteHalt-teste'
        if ((Test-Path $old) -and (Svc).PathName -notlike "*ByteHalt-teste*") { Remove-Item $old -Recurse -Force }
    } catch { Add-Step $S 'Limpeza' 'failed' 0 $_.Exception.Message }
    $result = [ordered]@{ finished = (Get-Date).ToString('o'); steps = @($script:Steps) }
    '=====RESULT====='
    $result | ConvertTo-Json -Depth 8 -Compress
}
