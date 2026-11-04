param(
    [Parameter(Mandatory)][string]$Action,
    [string]$Passphrase = '',
    # S4U: usuário atual em logon local (pipe de produção). Interactive: sessão já aberta do usuário.
    [ValidateSet('S4U', 'Interactive')][string]$Logon = 'S4U',
    [string]$User = "$env:COMPUTERNAME\$env:USERNAME",
    [int]$TimeoutSec = 120
)
# Executado na VM pela sessão SSH (logon de rede): roda uma ação de Interactive-Steps.ps1 como tarefa
# agendada e devolve a saída. A tarefa é removida ao final.
$ErrorActionPreference = 'Stop'
$base = 'C:\Users\Public\bh-task'
$out = Join-Path $base "out-$Action.txt"
Remove-Item $out -ErrorAction SilentlyContinue
$task = "ByteHalt-VM-$Action"
$arg = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command `"& '$base\Interactive-Steps.ps1' -Action $Action -Passphrase '$Passphrase' *> '$out'`""
$principal = if ($Logon -eq 'S4U') { New-ScheduledTaskPrincipal -UserId $User -LogonType S4U -RunLevel Highest } else { New-ScheduledTaskPrincipal -UserId $User -LogonType Interactive -RunLevel Limited }
try {
    Register-ScheduledTask -TaskName $task -Action (New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $arg) -Principal $principal -Settings (New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries) -Force | Out-Null
    Start-ScheduledTask -TaskName $task
    Start-Sleep 2
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    while ((Get-ScheduledTask -TaskName $task).State -eq 'Running' -and (Get-Date) -lt $deadline) { Start-Sleep 1 }
    'TAREFA: ' + (Get-ScheduledTaskInfo -TaskName $task).LastTaskResult
} finally {
    Unregister-ScheduledTask -TaskName $task -Confirm:$false -ErrorAction SilentlyContinue
}
if (Test-Path $out) { Get-Content $out } else { 'Sem saída.' }
