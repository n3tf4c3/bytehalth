# Funções comuns dos roteiros executados DENTRO do Windows Sandbox (Windows PowerShell 5.1).

$script:Steps = New-Object System.Collections.ArrayList

# Só arquivo: escrever no console trava o roteiro se alguém clicar na janela (QuickEdit).
function Write-Log([string]$message) {
    $line = '[{0:HH:mm:ss}] {1}' -f (Get-Date), $message
    Add-Content -LiteralPath $script:LogFile -Value $line -Encoding UTF8
}

function Add-Step([string]$suite, [string]$name, [string]$status, [double]$seconds, [string]$detail) {
    [void]$script:Steps.Add([ordered]@{ suite = $suite; name = $name; status = $status; seconds = [math]::Round($seconds, 1); detail = $detail })
    Write-Log ("{0,-7} {1} :: {2}{3}" -f $status.ToUpper(), $suite, $name, $(if ($detail) { " — $detail" } else { '' }))
}

# Registra um caso com resultado REAL. Exceção dentro do bloco = reprovado.
function Invoke-Step([string]$suite, [string]$name, [scriptblock]$body) {
    $sw = [Diagnostics.Stopwatch]::StartNew()
    try {
        $value = & $body
        Add-Step $suite $name 'passed' $sw.Elapsed.TotalSeconds $(if ($value -is [string]) { $value } else { $null })
    } catch {
        Add-Step $suite $name 'failed' $sw.Elapsed.TotalSeconds $_.Exception.Message
    }
}

function Skip-Step([string]$suite, [string]$name, [string]$reason) { Add-Step $suite $name 'skipped' 0 $reason }

function Assert-That([bool]$condition, [string]$message) { if (-not $condition) { throw $message } }

function Wait-Until([scriptblock]$condition, [int]$timeoutSeconds, [string]$what) {
    $deadline = [DateTime]::UtcNow.AddSeconds($timeoutSeconds)
    while ([DateTime]::UtcNow -lt $deadline) {
        try { if (& $condition) { return } } catch { }
        Start-Sleep -Milliseconds 500
    }
    throw "Tempo esgotado ($timeoutSeconds s): $what"
}

function Test-PipeExists([string]$name) { return @(Get-ChildItem '\\.\pipe\' | Where-Object Name -eq $name).Count -gt 0 }

# Cliente do pipe (mesmo protocolo do crate bytehalt-ipc):
#   pedido   {"version":1,"id":"<uuid>","request":{"command":"X","payload":{...}}}
#   resposta {"version":1,"id":"<uuid>","result":{"Ok":{"kind":"...","value":...}}} ou {"Err":["Codigo","mensagem"]}
# O dono do pipe é verificado ANTES de enviar qualquer dado.
function Invoke-ByteHaltPipe([string]$pipeName, [string]$command, $payload = $null, [string[]]$allowedOwners = $null) {
    $client = New-Object System.IO.Pipes.NamedPipeClientStream('.', $pipeName, [System.IO.Pipes.PipeDirection]::InOut)
    try {
        $client.Connect(5000)
        if ($allowedOwners) {
            $owner = $client.GetAccessControl().GetOwner([System.Security.Principal.SecurityIdentifier]).Value
            if ($allowedOwners -notcontains $owner) { throw "Dono do pipe inesperado: $owner" }
        }
        $inner = [ordered]@{ command = $command }
        if ($null -ne $payload) { $inner.payload = $payload }
        $request = [ordered]@{ version = 1; id = [guid]::NewGuid().ToString(); request = $inner }
        $bytes = [Text.Encoding]::UTF8.GetBytes(($request | ConvertTo-Json -Depth 12 -Compress))
        $client.Write([BitConverter]::GetBytes([int]$bytes.Length), 0, 4)
        $client.Write($bytes, 0, $bytes.Length)
        $client.Flush()
        $header = New-Object byte[] 4
        $read = 0
        while ($read -lt 4) { $n = $client.Read($header, $read, 4 - $read); if ($n -le 0) { throw "Pipe encerrado ao enviar $command." }; $read += $n }
        $length = [BitConverter]::ToInt32($header, 0)
        $body = New-Object byte[] $length
        $read = 0
        while ($read -lt $length) { $n = $client.Read($body, $read, $length - $read); if ($n -le 0) { throw 'Resposta truncada.' }; $read += $n }
        $response = [Text.Encoding]::UTF8.GetString($body) | ConvertFrom-Json
        if ($null -ne $response.result.Err) { throw "Serviço recusou ${command}: $($response.result.Err -join ' — ')" }
        return $response.result.Ok.value
    } finally {
        $client.Dispose()
    }
}

Add-Type -Namespace ByteHaltTest -Name Native -MemberDefinition @'
[DllImport("user32.dll")] public static extern bool LockWorkStation();
'@
