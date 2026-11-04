# ByteHalt — Windows Drive & Folder Security

Aplicativo para Windows 11 que bloqueia automaticamente unidades BitLocker e cofres de pastas (VHDX com
BitLocker) por inatividade, ao bloquear o Windows ou ao suspender, em grupos, com senha mestra e
exigência de TOTP após 24 horas bloqueado.

**Estado: 0.2.0, Fases 1 a 5.** Bloqueio de unidades e cofres, uso real do disco, senha mestra, TOTP,
códigos de recuperação e instalador validados no Windows Sandbox e em VM de teste com BitLocker real.
Executáveis assinados (Certum SimplySign) quando gerados com `-SignThumbprint`; assinados, passam pelo Smart App Control (comprovado no Sandbox). Versão portátil: `scripts\portable\Build-Portable.ps1` (demonstração e modo real sem instalar).

## Instalação

`scripts\release\Build-Installer.ps1` gera `artifacts\installer\ByteHalt-Setup-<versão>.exe`. Execute-o
como administrador (`/quiet` para modo silencioso, `/uninstall` para remover, `/purge` para apagar
também os dados). A desinstalação é recusada enquanto houver cofres. Detalhes em
[docs/ARCHITECTURE.md §12](docs/ARCHITECTURE.md).

## Leia antes

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — arquitetura e **limitações** (BitLocker, VHDX,
  inatividade, TOTP, Sandbox). O TOTP é verificado pelo ByteHalt, não pelo BitLocker: não é MFA
  criptográfico do volume.
- [docs/TESTING.md](docs/TESTING.md) — onde e como os testes rodam (testes só no Windows Sandbox).

## Estrutura

```
crates/
  bytehalt-core      domínio: grupos, política efetiva, inatividade, bloqueio, regra de 24 h, motor
  bytehalt-ipc       protocolo do pipe (lista fechada de comandos, limites, validação)
  bytehalt-windows   BitLocker (WMI), DPAPI, SQLite, pipe com ACL, identidade, sessão de boot
  bytehalt-service   Windows Service (--service) ou console (--simulate)
  bytehalt-app       interface GPUI, bandeja, temas; prova visual com --features gui-test
  bytehalt-setup     instalador (serviço, inicialização, atalho, desinstalação)
assets/              ícones (Material Symbols, Apache-2.0) e marca (brand/: arte original
                     bytehalt-source.png; ícones gerados por scripts/brand/Build-Icons.ps1)
scripts/sandbox/     pacote, .wsb, execução no Sandbox e relatório
scripts/vm/          testes com BitLocker real numa VM de teste (serviço instalado, só a unidade indicada)
scripts/portable/    pacote portátil de demonstração (modo simulado)
scripts/brand/       geração dos ícones (aplicativo e bandeja)
scripts/release/     instalador (bytehalt-setup) e assinatura opcional
sandbox/             ByteHalt-Test.wsb (sem rede, pacote somente leitura)
```

## Desenvolvimento

```powershell
cargo build                       # core, ipc, windows, service
cargo build -p bytehalt-app       # interface (GPUI; primeira compilação demora)
cargo clippy --workspace --all-targets -- -D warnings
```

Executar o serviço e a interface deve ser feito no Windows Sandbox (`docs/TESTING.md`). Em console:
`bytehalt-service --simulate` e `bytehalt --dev`. No modo simulado, a senha fictícia dos volumes é
`bytehalt-teste`.

Toolchain: Rust 1.98 (edition 2024), MSVC, CRT estático. GPUI fixado na mesma revisão do termIAX e
do NetLane.
