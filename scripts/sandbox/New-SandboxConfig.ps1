[CmdletBinding()]
param(
    # Pasta do pacote (somente leitura no Sandbox).
    [Parameter(Mandatory = $true)][string]$PackageDirectory,
    # Pasta da rodada com run.json (somente leitura). Opcional: sem ela o Sandbox roda em modo interativo.
    [string]$RunDirectory,
    # Pasta de saída NOVA E VAZIA, única gravável. Só com autorização explícita (-ExportResults no chamador).
    [string]$OutputDirectory,
    [Parameter(Mandatory = $true)][string]$Destination
)

# Gera um arquivo .wsb com os padrões exigidos: rede, área de transferência, impressoras, áudio e
# vídeo desligados; somente o pacote (e a rodada) mapeados, ambos somente leitura.
$ErrorActionPreference = 'Stop'
$escape = [Security.SecurityElement]

function Folder([string]$hostPath, [string]$sandboxPath, [bool]$readOnly) {
    $full = (Resolve-Path -LiteralPath $hostPath).Path
    foreach ($forbidden in @($env:USERPROFILE, (Join-Path $env:USERPROFILE 'OneDrive'), $env:OneDrive) | Where-Object { $_ }) {
        if ($full.TrimEnd('\') -ieq $forbidden.TrimEnd('\')) { throw "Recusa: não mapear pasta pessoal ($full)." }
    }
    if ($full -match '^[A-Za-z]:\\?$') { throw "Recusa: não mapear raiz de unidade ($full)." }
    $ro = if ($readOnly) { 'true' } else { 'false' }
    return "    <MappedFolder><HostFolder>$($escape::Escape($full))</HostFolder><SandboxFolder>$sandboxPath</SandboxFolder><ReadOnly>$ro</ReadOnly></MappedFolder>"
}

$folders = @(Folder $PackageDirectory 'C:\bytehalt\pkg' $true)
if ($RunDirectory) { $folders += Folder $RunDirectory 'C:\bytehalt\run' $true }
if ($OutputDirectory) {
    if (@(Get-ChildItem -LiteralPath $OutputDirectory -Force).Count -ne 0) { throw "Recusa: a pasta de saída precisa estar vazia ($OutputDirectory)." }
    $folders += Folder $OutputDirectory 'C:\bytehalt\out' $false
}

$xml = @"
<Configuration>
  <Networking>Disable</Networking>
  <ClipboardRedirection>Disable</ClipboardRedirection>
  <PrinterRedirection>Disable</PrinterRedirection>
  <AudioInput>Disable</AudioInput>
  <VideoInput>Disable</VideoInput>
  <ProtectedClient>Disable</ProtectedClient>
  <MemoryInMB>4096</MemoryInMB>
  <MappedFolders>
$($folders -join "`r`n")
  </MappedFolders>
  <LogonCommand>
    <Command>powershell.exe -NoProfile -WindowStyle Minimized -ExecutionPolicy Bypass -File C:\bytehalt\pkg\scripts\Run-InsideSandbox.ps1</Command>
  </LogonCommand>
</Configuration>
"@
[IO.File]::WriteAllText($Destination, $xml, (New-Object Text.UTF8Encoding $false))
return $Destination
