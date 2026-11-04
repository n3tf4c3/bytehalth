param(
    [Parameter(Mandatory)][string]$Drive,
    [Parameter(Mandatory)][string]$Passphrase,
    [ValidateSet('Test-RealBitLocker.ps1', 'Test-RealVault.ps1', 'Test-RealActivity.ps1')][string]$Test = 'Test-RealBitLocker.ps1'
)
# Executado na VM pela sessão SSH (logon de REDE). 1) Prova que o pipe de produção nega a rede.
# 2) Roda o roteiro ($Test) numa tarefa agendada local (S4U, elevada, sem senha guardada),
# porque o pipe só aceita logons locais. A tarefa é removida ao final.
$ErrorActionPreference = 'Stop'
$work = Join-Path $env:TEMP 'bytehalt-vm-test'
New-Item -ItemType Directory -Force $work | Out-Null
$out = Join-Path $work 'task-out.txt'
Remove-Item $out -ErrorAction SilentlyContinue

$c = New-Object System.IO.Pipes.NamedPipeClientStream('.', 'ByteHalt.Service.v1', [System.IO.Pipes.PipeDirection]::InOut)
$network = try { $c.Connect(3000); 'ACEITO' } catch { "negado: $($_.Exception.InnerException.Message)" } finally { $c.Dispose() }
'=====NETWORK=====' + $network

$task = 'ByteHalt-VM-Test'
$arg = "-NoProfile -ExecutionPolicy Bypass -Command `"& '$PSScriptRoot\$Test' -Drive $Drive -Passphrase '$Passphrase' *> '$out'`""
$principal = New-ScheduledTaskPrincipal -UserId "$env:COMPUTERNAME\$env:USERNAME" -LogonType S4U -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 40) -AllowStartIfOnBatteries
try {
    Register-ScheduledTask -TaskName $task -Action (New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $arg) -Principal $principal -Settings $settings -Force | Out-Null
    Start-ScheduledTask -TaskName $task
    Start-Sleep 3
    $deadline = (Get-Date).AddMinutes(40)
    while ((Get-ScheduledTask -TaskName $task).State -eq 'Running' -and (Get-Date) -lt $deadline) { Start-Sleep 5 }
    '=====TASK=====' + (Get-ScheduledTaskInfo -TaskName $task).LastTaskResult
} finally {
    Unregister-ScheduledTask -TaskName $task -Confirm:$false -ErrorAction SilentlyContinue
}
if (Test-Path $out) { Get-Content $out } else { 'Sem saída da tarefa.' }
