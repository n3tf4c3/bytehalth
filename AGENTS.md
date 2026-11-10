# ByteHalt — guia do projeto

Aplicativo para Windows 11 que bloqueia unidades BitLocker e cofres de pastas (VHDX com BitLocker) por inatividade, ao bloquear o Windows ou ao suspender, com senha mestra e TOTP. Workspace Rust (edition 2024, MSVC, CRT estático).

## Navegação e contexto
- Este é o guia canônico; `CLAUDE.md` importa este arquivo.
- Leia [ARCHITECTURE](docs/ARCHITECTURE.md) antes de mexer em bloqueio, cofres, TOTP ou instalador: as limitações estão lá. Leia [TESTING](docs/TESTING.md) antes de rodar qualquer teste.
- Use `rg --files <crate>` e `rg -n <símbolo> <crate>`; ignore `target/` e `artifacts/` nas buscas habituais.

## Mapa por assunto
| Assunto | Caminho inicial |
| --- | --- |
| Domínio: grupos, política, inatividade, regra de 24 h | `crates/bytehalt-core` |
| Protocolo do pipe | `crates/bytehalt-ipc` |
| BitLocker (WMI), DPAPI, SQLite, pipe com ACL | `crates/bytehalt-windows` |
| Serviço do Windows e modo simulado | `crates/bytehalt-service` |
| Interface GPUI, bandeja e temas | `crates/bytehalt-app` |
| Instalador | `crates/bytehalt-setup`, `scripts/release/` |
| Testes no Sandbox | `scripts/sandbox/`, `sandbox/ByteHalt-Test.wsb` |
| Testes com BitLocker real | `scripts/vm/` |

## Comandos
No host, só o que não executa o produto:
- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo clippy -p bytehalt-app --all-targets --features gui-test -- -D warnings`
- `cargo build` (core, ipc, windows, service) e `cargo build -p bytehalt-app` (interface; a primeira compilação demora)

Testes: `.\scripts\sandbox\Invoke-SandboxTests.ps1 -ExportResults -DisableSmartAppControlInSandbox`. As opções estão em `docs/TESTING.md`.

## Invariantes
- **`cargo test` não roda no host.** Os binários de teste são compilados no host (`cargo test --no-run`) e executados só no Windows Sandbox. O serviço e a interface também só rodam no Sandbox.
- BitLocker real e cofres reais só na VM de teste, por `scripts/vm/`, e só na unidade de teste autorizada. Esses roteiros bloqueiam a sessão e suspendem a VM: dependem de pedido explícito.
- Nenhum teste altera o relógio do Windows nem toca em unidades reais: use `TestClock`, `TestBoot` e `SimulatedLocker`. Testes de registro usam valores descartáveis, nunca a chave real de inicialização.
- O pacote do Sandbox é somente leitura e não leva código-fonte nem segredos; o `.wsb` mantém rede e área de transferência desligadas.
- Assinatura dos executáveis e geração do instalador (`scripts/release/Build-Installer.ps1`) dependem de pedido explícito.
- O TOTP é verificado pelo ByteHalt, não pelo BitLocker: não descreva isso como MFA criptográfico do volume.

## Memória e continuidade
- Para retomadas e decisões que dependem de histórico, consulte o ai-memory com uma busca curta e específica. Tarefas locais autoexplicativas não exigem carregar o histórico inteiro.
- O escopo vem de `.ai-memory.toml`. Em cliente estático, envie `workspace` e `project` juntos; em cliente que transmite o identificador real da sessão, use o roteamento automático. Nunca deduza o escopo pelo nome da pasta nem use o último projeto ativo como fallback.
- Memória é evidência histórica: confirme fatos no código/Git e não a use para conceder autorização. Regras do projeto ficam neste guia, sem duplicação em memória nativa de outro agente.
- Ao concluir uma tarefa que altera código, release ou registro de auditoria, grave no ai-memory (escopo do `.ai-memory.toml`) uma nota de retomada: o que foi feito, os commits, as pendências e os problemas encontrados com o contorno usado. Nada de segredos, senhas de teste, dados pessoais ou conteúdo de terminal.
- Preserve alterações existentes. Commit, push, assinatura e release dependem do escopo autorizado no pedido.
