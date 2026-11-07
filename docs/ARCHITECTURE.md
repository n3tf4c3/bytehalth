# ByteHalt — Análise de arquitetura

Versão do documento: 0.3 (Fase 1 + cofres da Fase 2). Data: 04/11/2026.

Este documento registra as decisões de arquitetura e, principalmente, as limitações técnicas que
condicionam o que o ByteHalt pode prometer. Onde houver conflito entre o que a especificação deseja
e o que o Windows permite garantir, prevalece a descrição honesta da limitação.

## 1. Visão de componentes

```
┌──────────────────────────────┐   Named Pipe (ACL + verificação de dono)   ┌──────────────────────────────┐
│ bytehalt-app (GPUI, usuário) │ ─────────── comandos fechados ───────────▶ │ bytehalt-service (SYSTEM)    │
│  telas, bandeja, notificações│ ◀────────── respostas/estado ───────────── │  orquestração, temporizadores│
│  relata ociosidade da sessão │                                            │  journal, persistência       │
└──────────────────────────────┘                                            └──────────────┬───────────────┘
                                                                                           │ abstrações
                                         ┌─────────────────────────────────────────────────┼───────────────────┐
                                         │ bytehalt-core (sem dependência de Windows)         │                   │
                                         │  grupos, política efetiva, inatividade, bloqueio, │ regra de 24 h     │
                                         └─────────────────────────────────────────────────┬───────────────────┘
                                                                                           │
                                         ┌─────────────────────────────────────────────────┴───────────────────┐
                                         │ bytehalt-windows                                                     │
                                         │  BitLocker (WMI Win32_EncryptableVolume), DPAPI, SQLite, ACL do pipe │
                                         └──────────────────────────────────────────────────────────────────────┘
```

| Crate | Responsabilidade |
|---|---|
| `bytehalt-core` | Domínio e regras puras: grupos, política efetiva determinística, inatividade, orquestração do bloqueio, regra de 24 h, motor, simuladores. Relógio injetável (`Clock`: parede UTC e monotônico separados) e sessão de boot (`BootSession`). Sem dependência de Windows. |
| `bytehalt-ipc` | Protocolo do pipe: envelope versionado, `enum` fechado de comandos com payload tipado (`deny_unknown_fields`), enquadramento com limite de 64 KiB, validação de limites. |
| `bytehalt-windows` | BitLocker via WMI (`wmi`), DPAPI, SQLite (`rusqlite`), pipes com ACL por SDDL, dono verificado pelo cliente, identidade do chamador pelo token do processo, sessão de boot (registro volátil + `GetTickCount64`), ociosidade da sessão, inicialização com o Windows. Win32 por `windows-sys` (Microsoft). |
| `bytehalt-service` | Windows Service (`windows-service`, eventos de sessão do SCM) ou console (`--simulate`, pipe por usuário). Importações estáticas só do System32 (`/DEPENDENTLOADFLAG:0x800`). |
| `bytehalt-app` | Interface GPUI (mesma base do termIAX e do NetLane): 7 telas, temas claro/escuro, bandeja nativa (`Shell_NotifyIconW`) com menu e balões, prova visual `gui-test`. |

**Linguagem (decisão do titular, 03/11/2026):** 100% Rust, substituindo a versão C#/WPF validada no
mesmo dia. Motivos: processo privilegiado sem runtime/JIT, segurança de memória, binário único com
CRT estático, baixo consumo para um serviço sempre ativo e para o ETW da Fase 4. Custo aceito: o GPUI
**não expõe UI Automation** (perda de acessibilidade para leitores de tela em relação ao WPF) e a prova
de interface no Sandbox passa a ser um roteiro interno com capturas, como no NetLane.

Princípios: o serviço privilegiado só executa operações nomeadas e validadas; a interface não carrega
segredos de volume; toda decisão de segurança relevante (bloquear, exigir TOTP) é tomada no serviço.

## 2. BitLocker — limitações

1. **Somente volumes de dados.** O volume do sistema operacional em execução não pode ser bloqueado
   (`Lock` falha e não faz sentido). O ByteHalt recusa antes de chamar a API: compara a letra com
   `%SystemDrive%` e com `VolumeType = 0` (volume de SO) do `Win32_EncryptableVolume`.
2. **Privilégio.** `Win32_EncryptableVolume` (`root\CIMV2\Security\MicrosoftVolumeEncryption`) exige
   administrador. Por isso as operações ficam no serviço (LocalSystem), nunca na interface.
3. **Edição.** Gerenciar BitLocker (ativar, adicionar protetores) exige Pro, Enterprise ou Education.
   O Home tem apenas "Criptografia do dispositivo". O host de desenvolvimento é Windows 11 Pro 26300.
4. **Bloqueio com arquivos abertos.** `Lock(ForceDismount = false)` falha quando há identificadores
   abertos no volume (`E_ACCESSDENIED`, documentado como "aplicativos estão acessando o volume"). O
   ByteHalt **nunca** usa `ForceDismount = true` automaticamente: forçar a desmontagem invalida
   identificadores abertos e pode perder gravações em cache de aplicativos. Volume ocupado ⇒ adiar,
   notificar e registrar.
5. **Desbloqueio automático.** Um volume de dados com *auto-unlock* é reaberto pelo Windows na próxima
   montagem (reinício, reconexão) sem passar pelo ByteHalt. O aplicativo detecta
   (`IsAutoUnlockEnabled`) e marca a política como comprometida; não desativa por conta própria.
6. **Chaves de recuperação.** O ByteHalt não cria, remove nem gira protetores automaticamente. Qualquer
   mudança de protetor será uma ação explícita do usuário, com confirmação e aviso de backup da chave
   de recuperação.
7. **Desbloqueio fora do ByteHalt.** Quem conhece a senha do volume desbloqueia pelo Explorer ou por
   `manage-bde -unlock` — inclusive usuário comum, em unidades de dados com protetor de senha. Um
   administrador também pode usar a chave de recuperação ou ler protetores. Ver §5.
8. **Chaves em memória.** Enquanto desbloqueado, a FVEK está na memória do kernel. Suspensão (S3/S0ix)
   mantém o volume desbloqueado; hibernação com volume de SO protegido é aceitável, mas volumes de
   dados desbloqueados continuam desbloqueados ao retomar. **Implementado (Fase 4):** opção por grupo
   "Bloquear ao suspender ou hibernar"; o serviço trata `PBT_APMSUSPEND` (`SERVICE_CONTROL_POWEREVENT`)
   e bloqueia ANTES de responder ao Windows (sem forçar: recurso em uso fica adiado para a volta).
   Confirmado na VM: o E: bloqueou no instante da suspensão (S1).

## 3. Cofres VHDX — limitações

**Implementado (Fase 2, 04/11/2026).** `bytehalt-core::vault` (registro, regras de caminho),
`migrate` (inventário, cópia, manifesto SHA-256, ressincronização) e `vault_manager` (fluxo e
recuperação); `bytehalt-windows::vhd` (Virtual Disk API, Storage WMI, BitLocker WMI no volume,
pontos de montagem), `acl` (dono, grupo e DACL; acesso do chamador), `restart` (Restart Manager) e
`sim_vault` (modo simulado com junções). Etapas persistidas antes de cada operação:
`Preparing → Ready → Swapping → Active → Removing`, ou `Failed`; `recover` conclui ou desfaz na partida.

| Etapa | O que acontece | Se falhar |
|---|---|---|
| Analisar | Regras de caminho (Windows, Program Files, ProgramData, raiz e cada perfil, AppData, dados do ByteHalt, sobreposição com cofres), inventário (links, junções e arquivos só na nuvem bloqueiam), espaço (conteúdo + 10% + 256 MiB). No serviço do sistema, o **chamador** precisa ter direito de mover a pasta (AccessCheck com o token dele). | Nada é criado. |
| Preparar | VHDX dinâmico em `<unidade>:ByteHalt.Cofres` (só SYSTEM/Administradores), anexado sem letra e com vida permanente; GPT + NTFS; BitLocker XTS-AES 256, só espaço usado, protetor de senha + chave de recuperação; espera a conversão e confere a proteção; cópia com dono, grupo, DACL, atributos e fluxos alternativos; verificação por SHA-256. | Disco descartado; original intocado. |
| Chave de recuperação | Retirada explicitamente pelo SID que preparou o cofre, repetível até a confirmação de que foi guardada; nunca incluída na listagem, gravada pelo ByteHalt ou registrada. | Reinício do serviço perde a cópia pendente em memória. |
| Trocar (confirmação) | Recusa se o Restart Manager listar programas com arquivos abertos; renomeia o original para `<pasta>.bytehalt-reserva-<data>` (o Windows recusa se houver arquivo aberto sem compartilhamento de exclusão); compara de novo por SHA-256 e reaplica o que mudou; compara os fluxos alternativos (arquivos, pastas e raiz) e regrava os diferentes; reaplica dono e DACL em **todos** os itens (permissão revogada depois da preparação não muda o SHA-256); cria a pasta vazia e monta o volume nela. | Desmonta, apaga a pasta vazia e devolve o original. |
| Apagar reserva (confirmação) | Só a reserva criada pelo ByteHalt, ao lado do original, com o cofre ativo e montado. | Reserva mantida. |
| Remover cofre (confirmação) | Cofre desbloqueado e sem arquivos abertos: copia de volta para `<pasta>.bytehalt-restaurando-<data>`, confere por SHA-256, desmonta, põe a cópia no caminho e só então apaga o disco. A reserva antiga não é tocada. | Cofre continua ativo; cópia parcial apagada. |

**Confirmado na VM de teste (04/11/2026, disco E: de teste):** montagem em pasta funciona sem letra;
com o volume bloqueado o caminho existe mas o acesso falha com a mensagem do BitLocker; desanexar e
anexar de novo devolve o mesmo GUID, bloqueado, e o ponto de montagem volta sozinho; renomear pasta
com arquivo aberto (sem compartilhamento de exclusão) é recusado. Defeitos achados só no modo real e
corrigidos: (1) copiar a DACL **herdada** para a raiz do volume a deixava vazia (raiz sem pai) — a raiz
recebe a herança como entradas explícitas e protegidas; (2) logo após `Encrypt` a proteção ainda é 0 —
espera-se a conversão; (3) a cópia de volta tentava levar `System Volume Information`; (4) o Restart
Manager lista o próprio kernel (PID 4) com arquivos recém-gravados — ignorado.

**Pendência de produto:** depois de reiniciar o PC (ou desanexar o disco) o cofre volta bloqueado sem
registro do ByteHalt sobre quando foi bloqueado; pela regra de 24 h isso exige TOTP (`LockStateMissing`),
que só chega na Fase 3. O mesmo vale para unidades sem desbloqueio automático. **Decisão do titular
(04/11/2026): manter assim até a Fase 3** (sem inferir o horário do bloqueio a partir da última vez
em que o recurso foi visto desbloqueado).

Limitações de projeto:


1. **Modelo.** Cada pasta protegida vira um VHDX dinâmico com um volume NTFS protegido por BitLocker.
   BitLocker em VHDX anexado como disco de dados é suportado; o volume é tratado como unidade de dados
   fixa.
2. **Privilégio.** Criar/anexar/desanexar VHDX (Virtual Disk API, `AttachVirtualDisk`) exige
   `SeManageVolumePrivilege`, logo o serviço.
3. **Caminho compatível.** Após a migração, o volume do cofre é montado como **ponto de montagem NTFS**
   no caminho original (ex.: `C:\Codes\safynia`). Projetos continuam usando o mesmo caminho. Restrições:
   o volume hospedeiro precisa ser NTFS; não funciona para pastas sincronizadas pelo OneDrive (cloud
   files), caminhos de rede, FAT/exFAT; ferramentas que tratam a troca de volume (hard links do Git
   entre volumes, `MoveFile` que vira cópia, watchers no pai) podem se comportar de forma diferente.
4. **Bloqueado = caminho inacessível.** Com o volume bloqueado, o ponto de montagem existe mas o acesso
   falha. IDEs e indexadores registram erros; a interface deve explicar isso.
5. **Migração segura.** Cópia para o cofre, verificação de hash por arquivo, verificação de
   contagem/tamanho, detecção de arquivos abertos (Restart Manager), e só então — com confirmação
   explícita — renomear o original para uma pasta de reserva antes de montar no caminho original. A
   remoção da reserva é outra confirmação. Links simbólicos, junctions, ADS e ACLs precisam de
   tratamento explícito (Fase 2).
6. **Capacidade.** VHDX dinâmico cresce até o tamanho máximo declarado; o espaço livre do volume
   hospedeiro precisa ser monitorado. BitLocker "somente espaço usado" é suficiente para cofre novo.
7. **Antivírus e indexação.** O Windows Search e o Defender abrem arquivos do cofre e geram I/O que
   parece atividade (ver §4).

## 4. Detecção de inatividade

**Implementado (Fase 4): contadores de E/S do volume** (`IOCTL_DISK_PERFORMANCE` em `\\.\E:` ou
`\\.\Volume{GUID}` do cofre), lidos a cada volta do serviço (5 s); contador diferente = uso e o tempo de
inatividade recomeça. Medido na VM: 60 s parado não mexe nos contadores; gravações mexem em segundos;
leituras atendidas pelo cache de memória **não** aparecem (mesma limitação do ETW de disco). No teste
real, gravar a cada 20 s manteve o E: aberto por 100 s e, parado, ele bloqueou cerca de 1 min depois.
E/S do indexador, do antivírus ou de backup no volume conta como uso; o modo "Combinado" (sessão
ociosa) cobre quem só lê arquivos já em cache. ETW Kernel-File (filtrar processos) fica como evolução.

`FileSystemWatcher` vê criação/alteração/renomeação, não leituras. Ele não serve como fonte única.

Fontes previstas, por ordem de precisão:

| Fonte | Vê leitura? | Granularidade | Observações |
|---|---|---|---|
| ETW `Microsoft-Windows-Kernel-Disk` (Read/Write por disco) | Sim, só I/O físico | Disco | **Ideal para cofres VHDX**: cada cofre é um disco próprio, então I/O no disco = atividade do cofre. Leituras servidas do cache do sistema não chegam ao disco ⇒ subestima atividade de leitura repetida. |
| ETW `Microsoft-Windows-Kernel-File` (Create/Read/Write) | Sim, inclusive em cache | Arquivo | Precisa resolver `FileObject` → caminho; volume de eventos alto; requer sessão ETW com privilégio. Útil para unidades inteiras e para filtrar processos (indexador, antivírus). |
| `FileSystemWatcher` | Não | Pasta | Complementar, barato, sinal de gravação. |
| Identificadores abertos (Restart Manager / handles) | Indireto | Arquivo | Usado antes do bloqueio para "há algo em uso?", não para medir inatividade. |

Limitações a documentar ao usuário:

- **Pastas individuais em unidade compartilhada** (sem cofre) não têm sinal de disco próprio; só
  Kernel-File distingue o caminho, com custo e precisão menores. Por isso pastas protegidas devem ser
  cofres VHDX.
- Indexador, antivírus e backup geram I/O. A Fase 4 deve permitir excluir processos de sistema
  conhecidos (`SearchProtocolHost`, `MsMpEng`) do sinal de atividade, quando a fonte for Kernel-File.
- **Ociosidade da sessão:** o serviço roda na sessão 0 e não lê `GetLastInputInfo` da sessão do
  usuário. A interface (na sessão do usuário) informa o tempo de ociosidade por IPC. Um processo do
  usuário poderia mentir, mas só para **adiar** o bloqueio do próprio usuário; bloqueio da estação
  (`SessionLock`) vem direto do SCM e é confiável.

Na Fase 1 a fonte de atividade é **simulada** (`SimulatedActivitySource`) e a interface é
`IActivitySource`. Os modos de política são:

- `ResourceIdle`: bloqueia quando o recurso fica ocioso pelo tempo configurado.
- `SessionIdle`: bloqueia quando a sessão do usuário fica ociosa pelo tempo configurado.
- `Combined`: bloqueia quando **qualquer** das duas condições ocorre (o mais restritivo).

## 5. Autenticação primária e TOTP — limitações

**Implementado (Fase 3, 04/11/2026; decisão do titular: senha mestra do ByteHalt).**
`bytehalt-core::master` + `bytehalt-windows::dpapi::DpapiCredentialStore`:

| Item | Como |
|---|---|
| Senha mestra | Mín. 12 caracteres. Só o hash Argon2id (19 MiB, 2 iterações, 1 via; crate `argon2`). Libera, por **15 min e só para o mesmo usuário do Windows**, os comandos que podem enfraquecer a proteção (cadastro, grupos, cofres). Sem sessão ⇒ erro `AuthRequired` e a interface pede a senha. Bloquear o Windows encerra todas as sessões. Bloquear recursos nunca exige senha. |
| Autenticador | RFC 6238 (HMAC-SHA1, 6 dígitos, 30 s, ±1 passo; crates `hmac`/`sha1`, comparação em tempo constante com `subtle`). Segredo de 160 bits do gerador do sistema, QR code `otpauth://` (crate `qrcode`). O cadastro só é gravado depois do primeiro código válido. Código aceito não vale de novo. |
| Códigos de recuperação | 10 códigos `XXXXX-XXXXX` (50 bits), mostrados uma vez, guardados só como hash Argon2id, uso único. Redefinem a senha mestra ou, junto com ela, recadastram o autenticador. |
| Recadastrar o autenticador | Senha mestra **mais** código atual do aplicativo ou de recuperação (só a senha anularia o segundo fator). |
| Regenerar códigos de recuperação | Senha mestra **mais** TOTP atual ainda não usado ou código de recuperação anterior. A prova é consumida junto da gravação dos novos códigos; os anteriores deixam de valer. |
| Tentativas | 5 erros de senha ou código de recuperação ⇒ espera de 30 s, dobrando até 15 min. |
| Armazenamento | Um arquivo `state\credentials.dat`, DPAPI de máquina com entropia própria (`ByteHalt.Credentials.v1`). Ilegível ⇒ erro (falha fechada): nunca vira "sem senha" nem permite cadastrar outra por cima. |

As operações de credenciais e autenticação são serializadas pela instância compartilhada de
`MasterAuth`: leitura, validação, consumo e gravação ficam sob o mesmo mutex. Cadastro inicial,
troca ou redefinição de senha, regeneração de códigos e conclusão do recadastro invalidam os demais
cadastros de autenticador pendentes; falha de persistência mantém o cadastro pendente para
nova tentativa. O mutex não é uma transação entre processos e não cancela retroativamente comandos
já autorizados. O contador de tentativas continua compartilhado: uma autenticação bem-sucedida o
reinicia, portanto não há orçamento independente contra alternância de endpoints de segunda prova.

Desbloqueio: senha da unidade/cofre (BitLocker) e, depois de 24 h bloqueado ou sem registro do
bloqueio, também o código do autenticador. A senha mestra não substitui a do BitLocker: o ByteHalt
continua sem guardar senhas de volume.

1. **TOTP não é MFA criptográfico do BitLocker.** O código TOTP é verificado pelo serviço do ByteHalt;
   o BitLocker não sabe que ele existe. Quem tem a senha do volume, a chave de recuperação ou
   privilégio de administrador desbloqueia sem o ByteHalt. **O produto não pode ser anunciado como MFA
   obrigatório para volumes BitLocker.**
2. **Segredo TOTP local.** O segredo fica no computador (DPAPI escopo máquina). Um administrador pode
   extraí-lo. Os códigos de recuperação e a senha mestra ficam apenas como hash Argon2id; os códigos
   são de uso único.
3. **Relógio.** TOTP depende do relógio. A tolerância é de ±1 passo (30 s) e um código aceito não é
   aceito de novo (último passo usado persistido).
4. **Proposta para versão avançada** (fora do escopo do MVP): o protetor do volume deixa de ser algo
   que o usuário conhece. Opções:
   - **Chave externa em hardware** (FIDO2 `hmac-secret` / YubiKey challenge-response) que deriva a
     senha do protetor: sem o token, nem o próprio serviço tem a chave.
   - **Liberação remota de chave**: um servidor guarda a parte da chave e só a libera após verificar o
     TOTP do lado servidor (o segredo TOTP não fica no computador).
   - Mesmo assim, enquanto o volume estiver desbloqueado, um administrador local pode ler os dados.

### Regra de 24 horas

- No bloqueio efetivo, o serviço grava `LockRecord { lockedAtUtc, bootId, monotonicAtLock }` protegido
  por DPAPI (integridade incluída: blob alterado não decifra).
- O serviço mantém uma **marca d'água** do maior horário UTC já observado, atualizada periodicamente.
- Avaliação (`UnlockPolicyEvaluator`):
  - `elapsed = agora − lockedAtUtc`. Se `elapsed ≥ limiar` (24 h padrão) ⇒ primária + TOTP.
  - Na mesma sessão de boot, usa `max(elapsed_relógio, elapsed_monotônico)`: atrasar o relógio não
    encurta o tempo.
  - Se `agora < lockedAtUtc` ou `agora < marca d'água − tolerância` ⇒ **alteração suspeita** ⇒ TOTP.
  - Registro ausente, ilegível ou adulterado para um recurso bloqueado ⇒ TOTP (falha fechada).
- Limitação: entre boots, sem fonte de tempo confiável (rede/TPM), adiantar o relógio só torna a
  política mais restritiva; atrasá-lo para antes da marca d'água é detectado; atrasá-lo para um horário
  entre a marca d'água e o tempo real não é detectável sem fonte externa.

## 6. Comunicação entre processos

- Pipe `\\.\pipe\ByteHalt.Service.v1`, criado pelo serviço com `FILE_FLAG_FIRST_PIPE_INSTANCE` (impede
  que outro processo crie o pipe antes), `PIPE_REJECT_REMOTE_CLIENTS` e ACL por SDDL: SYSTEM e
  Administradores controle total; usuários interativos só `0x120183` (ler/gravar dados e atributos, ler o
  descritor, sincronizar), **sem `FILE_CREATE_PIPE_INSTANCE`**: em pipes, `GENERIC_WRITE` incluiria esse
  direito e permitiria criar instâncias falsas do servidor; `NETWORK` negado; no máximo 8 conexões.
- O serviço define o **dono** do pipe explicitamente como SYSTEM (com token elevado o dono padrão
  seria Administradores, e qualquer processo elevado poderia criar um pipe com esse dono). O cliente
  aceita somente dono SYSTEM antes de enviar qualquer dado (defesa contra *pipe squatting*).
- O servidor identifica o chamador pelo token do **processo** cliente (`GetNamedPipeClientProcessId`
  → `OpenProcess` → `OpenProcessToken`), **sem impersonation**. Usar `ImpersonateNamedPipeClient`
  deixou threads do pool com token restrito e fez gravações de arquivo e SQLite falharem em
  seguida (achado no Sandbox em 03/11/2026). O cliente conecta com nível *Identification*, o que
  impede um servidor falso de agir com a identidade do usuário.
- Protocolo: mensagens JSON com prefixo de tamanho (máx. 64 KiB),
  `{"version":1,"id":…,"request":{"command":…,"payload":…}}`, com `command` de uma **lista fechada**
  (`enum` com `deny_unknown_fields`). Comando desconhecido, JSON inválido ou payload fora do limite ⇒ erro, sem
  execução. Não existe comando genérico "executar".
- `GetVaults` devolve apenas estado público. `ClaimVaultRecovery` e `AckVaultRecovery` exigem o
  SID iniciador mesmo quando o chamador é administrador; também exigem sessão mestra quando a conta
  está configurada. Antes do cadastro, mantém-se o fluxo inicial permitido ao iniciador. A retirada
  não consome a chave: somente o ACK a remove da memória do serviço, permitindo retentativa após
  perda de resposta. A interface mantém sua cópia até receber o ACK. Um reinício do serviço perde
  as chaves pendentes; não foi criado armazenamento persistente de segredos.
- O envelope permanece na versão 1. `RegenerateRecoveryCodes` agora exige `proof`; clientes antigos
  sem esse campo recebem erro e a interface nova precisa dos comandos de retirada/ACK. Serviço e
  interface devem ser atualizados juntos, sem assumir compatibilidade funcional entre versões.
- Operações destrutivas (bloquear volume) só aceitam identificadores de recursos já cadastrados; a
  interface não envia caminhos arbitrários para o serviço agir.
- Classes de comando: **leitura/proteção** (consultar, bloquear, desbloquear com as credenciais do
  volume) para qualquer usuário interativo identificado; **configuração** (recursos, grupos, cofres)
  para o dono ou administrador **e** com sessão da senha mestra, quando criada; **conta** (cadastro e
  troca da senha mestra, códigos de recuperação, autenticador) para o dono ou administrador, cada
  comando com a própria prova; **simulação** só no modo `--simulate`. Cofres exigem ainda que o
  chamador possa mover a pasta (AccessCheck com o token dele).

## 7. Grupos e regra determinística de política

Um recurso pode estar em vários grupos. A política efetiva é a combinação mais restritiva, calculada
sempre da mesma forma, independentemente da ordem dos grupos:

| Atributo | Regra |
|---|---|
| Tempo de inatividade | o **menor** entre os grupos (desligado só se todos desligados) |
| Modo | `Combined` se houver modos diferentes; senão o modo comum |
| Limiar do TOTP | o **menor** |
| Bloquear ao bloquear o Windows | **verdadeiro** se qualquer grupo pedir |
| Bloqueio manual de um grupo | bloqueia todos os recursos do grupo, mesmo que outro grupo os mantenha abertos |

A interface mostra a política efetiva de cada recurso e quais grupos a originaram.

## 8. Windows Sandbox — limitações

- **Sem TPM virtual e sem pilha completa do BitLocker**: não há como validar bloqueio/desbloqueio real.
  No Sandbox, o BitLocker é testado com o provedor simulado; a disponibilidade do namespace WMI é
  apenas sondada e registrada.
- **VHDX**: anexar VHDX pode ou não funcionar no Sandbox; o roteiro sonda e registra. Testes reais de
  cofre ficam para a VM Hyper-V.
- **Smart App Control**: a imagem do Sandbox vem com o SAC em bloqueio e recusa DLLs sem assinatura,
  inclusive quando carregadas por um executável assinado (comprovado com a versão .NET na rodada
  20261103-130602: `0x800711C7`); os executáveis Rust sem assinatura têm o mesmo bloqueio. Sem assinatura digital, os testes só rodam com o SAC desligado **dentro** do Sandbox
  (`-DisableSmartAppControlInSandbox`, decisão explícita por rodada, registrada no relatório). O host
  nunca é alterado. A solução definitiva é assinar os binários (Fase 5).
- Uma instância por vez; conteúdo perdido ao fechar; sem rede por padrão. Os executáveis usam CRT
  estático e não dependem de runtime na imagem.
- O GPUI não expõe UI Automation: a prova de interface é um roteiro interno do próprio aplicativo
  (`gui-test`), com capturas por `render_to_image` e resultado passo a passo em `proof.json`.
- Exportação de resultados: apenas para uma pasta **nova e vazia por rodada**, criada pelo roteiro no
  host, e somente com `-ExportResults` (autorização explícita na linha de comando).

## 9. VM de teste (Fase 4)

VM VMware com Windows Pro, TPM e um disco de teste (E:) autorizado pelo titular. Por SSH + tarefas
agendadas (o pipe recusa logon de rede): BitLocker real, cofres reais, uso real do disco; na sessão
interativa do usuário (token comum, sem elevação): interface com o serviço real, bloquear o Windows e
suspender (S1). Achado só aí: o cliente pedia `GENERIC_READ|GENERIC_WRITE` no pipe, o que inclui
`FILE_CREATE_PIPE_INSTANCE`; quem não era administrador elevado tinha o acesso negado. O cliente agora
pede exatamente `0x120183`, travado por teste.

## 10. Persistência

| Dado | Onde | Proteção |
|---|---|---|
| Recursos, grupos, políticas, histórico | SQLite em `%ProgramData%\ByteHalt\bytehalt.db` | ACL: SYSTEM e Administradores; nenhum segredo |
| Estado de bloqueio (instante, boot, marca d'água) | `%ProgramData%\ByteHalt\state\*.lock`, `clock.mark` | DPAPI escopo máquina + entropia da aplicação |
| Senha mestra (hash), segredo TOTP, hashes de recuperação | `%ProgramData%\ByteHalt\state\credentials.dat` | DPAPI escopo máquina + entropia própria; Argon2id |
| Cofres (caminhos, etapa, volume; sem senha nem chave) | tabela `vaults` do SQLite | idem SQLite |
| Discos dos cofres | `<unidade>:\ByteHalt.Cofres\<id>.vhdx` | ACL: SYSTEM e Administradores; conteúdo cifrado pelo BitLocker |

As pastas `%ProgramData%\ByteHalt` e `<unidade>:\ByteHalt.Cofres` são preparadas por `secure_dir`: criadas já com
dono Administradores e DACL protegida numa única chamada. Se a pasta já existir, ela é aberta sem seguir links e
só é adotada quando o dono é SYSTEM, Administradores ou a conta do próprio serviço (o dono tem WRITE_DAC
implícito); caso contrário é renomeada para `<pasta>.nao-confiavel-<segundos>` (nada é apagado) e recriada,
com aviso no histórico. Numa pasta adotada, dono e DACL são reaplicados pelo handle (que impede a troca da pasta
por um link até o fim) e cada item dentro é conferido: link ou junção, dono não confiável ou hard link fazem o
serviço recusar o uso da pasta (falha fechada, com o caminho do item).

Logs e histórico nunca contêm segredo TOTP, código, senha nem chave de recuperação.

## 11. Escopo entregue

Incluído: workspace Rust (5 crates); domínio e política; inatividade com fonte simulada; orquestrador
de bloqueio com adiamento por recurso ocupado; regra de 24 h (avaliação pura e persistência protegida);
BitLocker via WMI atrás de abstração, com guarda da unidade do sistema; IPC autenticado; serviço do
Windows; interface GPUI com as 7 áreas, bandeja, notificações e temas; testes automatizados; prova
visual; roteiro e `.wsb` do Sandbox.

Fase 2 (cofres) implementada e validada na VM de teste (§3). Fase 3 (senha mestra, TOTP e códigos de
recuperação) implementada (§5). Fase 4 (uso real do disco, bloqueio ao suspender, testes interativos na VM) implementada (§2, §4, §9). Fase 5 (instalador, assinatura, portátil) implementada (§12). Fora: ETW Kernel-File para filtrar processos (evolução da F4).

## 12. Instalação (Fase 5)

Decisões do titular (04/11/2026): **instalador próprio em Rust** (`bytehalt-setup`) e assinatura com o
certificado de assinatura de código do titular na **Certum SimplySign** (nuvem; o SimplySign Desktop
precisa estar conectado durante o build).

- `scripts/release/Build-Installer.ps1` compila interface e serviço em release, embute-os no
  `bytehalt-setup.exe` (`BYTEHALT_PAYLOAD_DIR`) e gera `artifacts\installer\ByteHalt-Setup-<versão>.exe`
  com `.sha256`. Com `-SignThumbprint` (ou `BYTEHALT_SIGN_THUMBPRINT`) assina os três executáveis com
  `signtool` (SHA-256 + carimbo de tempo Certum); sem certificado saem **sem assinatura**.
- **Smart App Control, comprovado no Sandbox com o SAC em bloqueio** (`-InstallerOnly`, sem desligar o
  SAC): instalador e serviço **assinados** rodam e os 5 casos passam; o mesmo pacote **sem assinatura**
  é recusado ("Uma política de Controle de Aplicativo bloqueou este arquivo"). SmartScreen: desde 2024
  nenhum certificado dá reputação imediata; os primeiros downloads ainda podem avisar, com o nome do
  editor verificado.
- Manifesto `requireAdministrator`. Instalar/atualizar: pede à interface aberta que encerre (mensagem
  da bandeja), para o serviço, grava em `%ProgramFiles%\ByteHalt` (executável em uso é renomeado e
  apagado no reinício), cria/atualiza o serviço `ByteHalt` (LocalSystem, início automático, reinício
  em falha 5 s/5 s/30 s), `HKLM\…\Run\ByteHalt = bytehalt.exe --tray`, atalho no menu Iniciar e a
  entrada em Aplicativos instalados. Dados em `%ProgramData%\ByteHalt` são mantidos.
- Desinstalar: **recusado enquanto houver cofres** (sem o serviço, os discos dos cofres não são
  anexados depois de reiniciar); remove serviço, inicialização, atalho, entrada e arquivos; os dados
  ficam, salvo `/purge` (só exatamente `%ProgramData%\ByteHalt`). Unidades BitLocker não são
  alteradas.
- `/quiet` com códigos de saída: 0 ok, 1 erro, 2 recusado (cofres), 3 sem administrador, 4 cancelado,
  5 instalador sem conteúdo. Registro em `%TEMP%\bytehalt-setup.log`.
- Validado no Sandbox (instalar, atualizar mantendo configuração, desinstalar mantendo dados,
  reinstalar, `/purge`) e na VM (atualizar a instalação manual, **recusa com cofre real**, desinstalar,
  reinstalar).
- **Portátil** (`scripts/portable/Build-Portable.ps1`, assinado com `-SignThumbprint`): *demonstração*
  (serviço simulado como o usuário) e *modo real* (serviço em console **elevado**, unidades BitLocker
  de verdade enquanto aberto; dados ao lado). No modo real portátil o serviço **recusa cofres** (sem
  serviço instalado ninguém anexaria os discos depois de reiniciar) e não recebe bloqueio do Windows
  nem suspensão (eventos só do SCM). Os atalhos `.cmd` só chamam o executável assinado:
  `bytehalt.exe --portable demo|real` (sobe o serviço oculto; no modo real pelo UAC) e
  `--portable-stop` (pedido de saída pela bandeja + `StopConsole` no pipe, comando aceito só no console).
  "Sair" na bandeja também encerra o serviço portátil. Sem PowerShell: antivírus vigiam
  `-ExecutionPolicy Bypass` e políticas de aplicativo põem scripts sem assinatura em modo restrito.
  Testado no Sandbox pelos próprios `.cmd`, numa cópia gravável. Os builds do Sandbox saem em `artifacts\sandbox-build` para não
  sobrescrever as versões assinadas.
