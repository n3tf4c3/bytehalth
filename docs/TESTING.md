# ByteHalt — Testes

## Onde cada coisa roda

| Etapa | Onde |
|---|---|
| `cargo fmt`, `cargo clippy -D warnings` (normal e `--features gui-test`), `cargo build` | PC (host) |
| `cargo test` (todos os crates) | **Windows Sandbox**: os binários são compilados no host com `cargo test --no-run` e executados só no Sandbox |
| Prova visual da interface (GPUI), temporizadores em tempo real, falha e recuperação do serviço | **Windows Sandbox** |
| Serviço do Windows real (LocalSystem), pipe de produção, bloqueio da estação | **Windows Sandbox** |
| BitLocker real (unidade E: de teste) e cofres reais (VHDX + BitLocker + ponto de montagem) | **VM de teste** (VMware, rede local) por SSH + tarefa agendada local: `scripts/vm/Run-VmTests.ps1 -Test Test-RealBitLocker.ps1` ou `Test-RealVault.ps1` ou `Test-RealActivity.ps1`. O pipe de produção recusa logon de rede, por isso os casos rodam numa tarefa S4U elevada, removida ao final. Só a unidade de teste autorizada é usada. |
| Uso real do disco (contadores de E/S) | **VM de teste**: `Test-RealActivity.ps1` |
| Interface com o serviço real (token comum), bloquear o Windows, suspender | **VM de teste**, na sessão interativa do usuário: `Interactive-Steps.ps1` via `Invoke-AsTask.ps1` (com aviso prévio: bloqueia a sessão e suspende a VM) |

Nenhum teste altera o relógio do Windows: a regra de 24 h usa `TestClock` (parede e monotônico
separados) e `TestBoot`. Nenhum teste toca em unidades reais: o BitLocker é exercitado por uma API
falsa (tradução de códigos) e por `SimulatedLocker`. Testes de registro usam valores descartáveis
(`ByteHalt.Test.<uuid>`), nunca a chave real de inicialização.

## Comandos

```powershell
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo clippy -p bytehalt-app --all-targets --features gui-test -- -D warnings

# Bateria completa no Sandbox, com exportação controlada do resultado
.\scripts\sandbox\Invoke-SandboxTests.ps1 -ExportResults -DisableSmartAppControlInSandbox
#   -IncludeWorkstationLock  testa "bloquear ao bloquear o Windows" (último passo; trava a sessão do Sandbox)
#   -SkipUi / -SkipServiceMode / -SkipBuild

# Sandbox interativo, sem nada gravado no host
.\scripts\sandbox\Build-SandboxPackage.ps1
Start-Process .\sandbox\ByteHalt-Test.wsb
```

## Configuração do Sandbox

`sandbox/ByteHalt-Test.wsb` (gerado por `New-SandboxConfig.ps1`):

- rede, área de transferência, impressoras, microfone e câmera **desligados**;
- **uma** pasta mapeada: `artifacts\sandbox-package` → `C:\bytehalt\pkg`, **somente leitura**
  (executáveis, binários de teste e roteiros — sem código-fonte, sem segredos);
- o roteiro `Run-InsideSandbox.ps1` roda no logon.

`New-SandboxConfig.ps1` recusa mapear a pasta do perfil, o OneDrive ou a raiz de uma unidade.

### Exportação controlada

Com `-ExportResults`, `Invoke-SandboxTests.ps1` cria `C:\Codes\relatorios\bytehalt\sandbox\<rodada>\out\`
**nova e vazia** e a mapeia como a única pasta gravável. O Sandbox grava ali `result.json`, logs,
saída dos testes e capturas, e desliga. O host gera `report.md`. Sem `-ExportResults`, nada sai.

### Smart App Control

A imagem do Sandbox vem com o SAC em bloqueio e recusa executáveis sem assinatura. Até existir
assinatura (Fase 5), as rodadas usam `-DisableSmartAppControlInSandbox`: o SAC é desligado **somente
dentro** do Sandbox descartável, por decisão explícita (titular, 03/11/2026), e o relatório registra.

## O que a bateria verifica

- **Ambiente:** edição/versão, TPM, namespace WMI do BitLocker, VHDX (64 MB, dentro do Sandbox),
  Smart App Control, adaptadores de rede.
- **cargo test:** domínio (política, inatividade, 24 h, motor, orquestrador, desbloqueio), IPC
  (envelope, lista fechada, limites), Windows (DPAPI, SQLite, BitLocker falso, ACL e dono do pipe,
  identidade do chamador, sessão de boot, inicialização), serviço (autorização e fluxo completo pelo
  pipe, reinício), interface (textos, painel, editor de grupos, menu da bandeja).
- **Prova visual (GPUI):** as 7 telas claro/escuro, unidade do sistema não selecionável, cadastro de
  unidades, grupos (criação, validação, edição), 1 minuto com atividade aos 40 s, 5 minutos com arquivo
  em uso e nova tentativa, notificação, desbloqueio (senha errada/certa), exigência na Segurança,
  histórico sem senhas, queda e reinício do serviço, bandeja (menu, Bloquear tudo, fechar/minimizar e
  Abrir).
- **Serviço do Windows:** LocalSystem, dono SYSTEM e ACL do pipe (sem `FILE_CREATE_PIPE_INSTANCE`),
  ACL da pasta de dados, comando fora da lista recusado, bloqueio pelo pipe grava o registro, interface
  sem `--dev`, reinício do serviço, bloqueio da estação.

## Limitações conhecidas

- GPUI não expõe UI Automation: não há teste externo de acessibilidade; a prova é interna.
- O clique físico no ícone da bandeja não é simulado (o roteiro injeta o comando do menu na janela da
  bandeja); verificar manualmente uma vez por versão.
- HRESULTs do BitLocker marcados "confirmar" em `bitlocker::codes` precisam de validação na VM.
