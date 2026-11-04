//! Montagem do serviço e tratamento dos comandos do pipe (separado do `main` para ser testável).
#![cfg(windows)]

use bytehalt_core::auth::{LockStateStore, UnlockCoordinator};
use bytehalt_core::clock::{BootSession, Clock};
use bytehalt_core::engine::Engine;
use bytehalt_core::inactivity::ReportedSessionIdle;
use bytehalt_core::journal::{EventType, JournalEntry, Severity, append_or_log};
use bytehalt_core::locking::{LockOrchestrator, LockState, NoBusyProbe, ResourceLocker};
use bytehalt_core::master::{AuthError, MasterAuth};
use bytehalt_core::model::{ConfigRepository, ResourceKind, normalize_drive_letter};
use bytehalt_core::simulated::SimulatedLocker;
use bytehalt_core::vault::{PathRules, VaultPlatform, normalize_path};
use bytehalt_core::vault_manager::VaultManager;
use bytehalt_ipc::{Command, ErrorCode, Reply, Request, Response, VolumeInfo};
use bytehalt_windows::bitlocker::{BitLockerApi, BitLockerLocker, VaultLocker, WmiBitLocker, map_status};
use bytehalt_windows::pipe::{Caller, Handler, SecurityDescriptor, Server, development_sddl, production_sddl};
use bytehalt_windows::{acl, sim_vault::SimulatedVaultPlatform, vhd::VhdPlatform};
use bytehalt_windows::{boot::WindowsBootSession, dpapi::DpapiStateStore, secure_dir, sqlite::SqliteStore, user};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const OWNER_KEY: &str = "owner_sid";

#[derive(Clone, Debug)]
pub struct Options {
    pub simulated: bool,
    /// Console: pipe por usuário, DPAPI de usuário, sem ACL de máquina.
    pub development: bool,
    pub pipe: String,
    pub data_dir: PathBuf,
    pub tick: Duration,
}

impl Options {
    pub fn parse(args: &[String], as_service: bool) -> anyhow::Result<Self> {
        let simulated = args.iter().any(|a| a == "--simulate");
        let value = |flag: &str| args.iter().position(|a| a == flag).and_then(|i| args.get(i + 1)).cloned();
        let data_dir = match value("--data-dir") {
            Some(d) => PathBuf::from(d),
            None if as_service => PathBuf::from(std::env::var("ProgramData").unwrap_or_else(|_| "C:\\ProgramData".into())).join("ByteHalt"),
            None => PathBuf::from(std::env::var("LOCALAPPDATA")?).join("ByteHalt-dev"),
        };
        anyhow::ensure!(data_dir.is_absolute(), "--data-dir deve ser um caminho absoluto.");
        let tick = value("--tick-seconds").and_then(|s| s.parse::<u64>().ok()).filter(|s| (1..=60).contains(s)).unwrap_or(5);
        let pipe = if as_service { bytehalt_ipc::PRODUCTION_PIPE.to_owned() } else { bytehalt_ipc::development_pipe(&user::current_user_sid()?) };
        Ok(Self { simulated, development: !as_service, pipe, data_dir, tick: Duration::from_secs(tick) })
    }
}

/// Grafo de objetos do serviço.
pub struct Host {
    pub options: Options,
    pub engine: Arc<Engine>,
    pub config: Arc<SqliteStore>,
    pub simulated: Option<Arc<SimulatedLocker>>,
    pub bitlocker: Option<Arc<BitLockerLocker<WmiBitLocker>>>,
    pub vaults: Arc<VaultManager>,
    pub auth: Arc<MasterAuth>,
    pub clock: Arc<dyn Clock>,
}

impl Host {
    pub fn create(options: Options, clock: Arc<dyn Clock>) -> anyhow::Result<Self> {
        let rules = path_rules(&options.data_dir);
        Self::create_with_rules(options, clock, rules)
    }

    /// Como `create`, com regras de caminho dos cofres explícitas (testes).
    pub fn create_with_rules(options: Options, clock: Arc<dyn Clock>, rules: PathRules) -> anyhow::Result<Self> {
        if options.development {
            std::fs::create_dir_all(&options.data_dir)?;
        } else {
            secure_dir::ensure_machine_only(&options.data_dir)?;
        }
        let db = Arc::new(SqliteStore::open(&options.data_dir.join("bytehalt.db"))?);
        let state: Arc<dyn LockStateStore> = Arc::new(DpapiStateStore::new(options.data_dir.join("state"), !options.development)?);
        let boot: Arc<dyn BootSession> = Arc::new(WindowsBootSession::new(!options.development)?);
        let system_drive = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".into());
        let (simulated, bitlocker, locker): (_, _, Arc<dyn ResourceLocker>) = if options.simulated {
            let s = Arc::new(SimulatedLocker::new(ResourceKind::BitLockerVolume, Some(&system_drive), Some(options.data_dir.join("simulated-volumes.json"))));
            (Some(s.clone()), None, s)
        } else {
            let b = Arc::new(BitLockerLocker::new(WmiBitLocker, &system_drive));
            (None, Some(b.clone()), b)
        };
        let (vault_locker, vault_platform): (Arc<dyn ResourceLocker>, Arc<dyn VaultPlatform>) = if options.simulated {
            (
                Arc::new(SimulatedLocker::new(ResourceKind::Vault, None, Some(options.data_dir.join("simulated-vaults.json")))),
                Arc::new(SimulatedVaultPlatform::new(&options.data_dir)),
            )
        } else {
            (Arc::new(VaultLocker::new(WmiBitLocker, db.clone())), Arc::new(VhdPlatform::default()))
        };
        if !options.development {
            // Cópia fiel de dono/ACL e leitura de tudo durante a migração; anexar VHDX.
            if let Err(e) = acl::enable_privileges(&["SeBackupPrivilege", "SeRestorePrivilege", "SeManageVolumePrivilege"]) {
                eprintln!("{e:#}");
            }
        }
        let vaults = Arc::new(VaultManager::new(vault_platform, db.clone(), db.clone(), clock.clone(), rules));
        vaults.recover();
        let orchestrator =
            LockOrchestrator::new(vec![locker, vault_locker], Arc::new(NoBusyProbe), state.clone(), db.clone(), clock.clone(), boot.clone(), None);
        // Senha mestra, autenticador e recuperação (Fase 3), protegidos por DPAPI na pasta de estado.
        let credentials = Arc::new(bytehalt_windows::dpapi::DpapiCredentialStore::new(options.data_dir.join("state"), !options.development)?);
        let auth = Arc::new(MasterAuth::new(credentials, clock.clone(), db.clone()));
        let unlock = UnlockCoordinator::new(state.clone(), auth.clone(), db.clone(), clock.clone(), boot);
        let session = Arc::new(ReportedSessionIdle::new(clock.clone()));
        let engine = Arc::new(Engine::new(db.clone(), orchestrator, unlock, session, state, db.clone(), clock.clone(), options.simulated));
        engine.reload()?;
        // Recursos de cofres que deixaram de existir (remoção concluída na recuperação).
        if let Ok(resources) = db.resources() {
            for rid in vaults.orphan_resources(&resources) {
                let _ = engine.delete_resource(rid);
            }
        }
        Ok(Self { options, engine, config: db, simulated, bitlocker, vaults, auth, clock })
    }

    pub fn journal(&self, event: EventType, message: &str) {
        append_or_log(
            self.config.as_ref(),
            JournalEntry { at: self.clock.now_utc(), event, severity: Severity::Info, resource_id: None, message: message.into(), detail: None },
        );
    }

    pub fn serve(self: &Arc<Self>) -> anyhow::Result<Server> {
        let sd = if self.options.development {
            SecurityDescriptor::from_sddl(&development_sddl(&user::current_user_sid()?))?
        } else {
            SecurityDescriptor::from_sddl(&production_sddl())?
        };
        let host = self.clone();
        let handler: Handler = Arc::new(move |req: Request, caller: &Caller| host.handle(req, caller));
        Server::start(&self.options.pipe, sd, handler)
    }

    /// Autoriza e executa um comando. Erros internos não expõem detalhes ao cliente.
    pub fn handle(&self, req: Request, caller: &Caller) -> Response {
        let id = Some(req.id);
        let owner = self.config.setting(OWNER_KEY).ok().flatten();
        if !authorized(&req.request, caller, owner.as_deref(), self.engine.simulated()) {
            eprintln!("Comando {} negado para {} (PID {}).", req.request.name(), caller.sid, caller.pid);
            return Response::error(id, ErrorCode::Forbidden, "Operação não permitida para este usuário.");
        }
        let class = classify(&req.request);
        // Com senha mestra criada, alterar a configuração exige a sessão aberta por ela.
        if class == Class::Configure && self.auth.configured() && !self.auth.has_session(&caller.sid) {
            return Response::error(id, ErrorCode::AuthRequired, "Digite a senha mestra do ByteHalt para alterar a configuração.");
        }
        if matches!(class, Class::Configure | Class::Account) && owner.is_none() {
            let _ = self.config.set_setting(OWNER_KEY, &caller.sid);
        }
        match self.dispatch(req.request, caller) {
            Ok(reply) => Response { version: bytehalt_ipc::VERSION, id, result: Ok(reply) },
            Err((code, message)) => Response::error(id, code, message),
        }
    }

    fn dispatch(&self, command: Command, caller: &Caller) -> Result<Reply, (ErrorCode, String)> {
        let e = &self.engine;
        let internal = |err: anyhow::Error| {
            eprintln!("Erro interno: {err:#}");
            (ErrorCode::Internal, "Erro interno do serviço.".to_owned())
        };
        let not_found = || (ErrorCode::NotFound, "Recurso não encontrado.".to_owned());
        let invalid = |errors: Vec<String>| (ErrorCode::Validation, errors.join(" "));
        let auth_err = |e: AuthError| match e {
            AuthError::Storage(_) => {
                eprintln!("Credenciais: {}", e.message());
                (ErrorCode::Internal, "Erro interno do serviço.".to_owned())
            }
            other => (ErrorCode::Validation, other.message()),
        };
        Ok(match command {
            Command::Ping => Reply::Pong { version: VERSION.into(), simulated: e.simulated() },
            Command::GetSnapshot => Reply::Snapshot(e.snapshot()),
            Command::GetHistory { limit } => Reply::History(self.config.as_ref().recent_entries(limit as usize).map_err(internal)?),
            Command::SaveResource { mut resource } => {
                if resource.kind == ResourceKind::BitLockerVolume
                    && let Some(l) = normalize_drive_letter(&resource.target)
                {
                    resource.target = l;
                }
                if resource.id.is_nil() {
                    resource.id = uuid::Uuid::new_v4();
                }
                resource.display_name = resource.display_name.trim().to_owned();
                Reply::Operation(e.save_resource(resource).map_err(internal)?)
            }
            Command::DeleteResource { id } => Reply::Operation(e.delete_resource(id).map_err(internal)?),
            Command::SaveGroup { mut group } => {
                if group.id.is_nil() {
                    group.id = uuid::Uuid::new_v4();
                }
                Reply::Operation(e.save_group(group).map_err(internal)?)
            }
            Command::DeleteGroup { id } => Reply::Operation(e.delete_group(id).map_err(internal)?),
            Command::LockResources { ids } => Reply::Locks(e.lock_resources(&ids, bytehalt_core::locking::LockTrigger::Manual)),
            Command::LockGroup { id } => Reply::Locks(e.lock_group(id).ok_or((ErrorCode::NotFound, "Grupo não encontrado.".to_owned()))?),
            Command::LockAll => Reply::Locks(e.lock_all()),
            Command::GetUnlockRequirement { id } => Reply::Requirement(e.unlock_requirement(id).ok_or_else(not_found)?),
            Command::Unlock { id, passphrase, totp } => Reply::Unlock(e.unlock(id, &passphrase, totp.as_deref()).ok_or_else(not_found)?),
            Command::ReportSessionIdle { idle_secs } => {
                e.session().report(Duration::from_secs(idle_secs));
                Reply::Ack
            }
            Command::DiscoverVolumes => self.discover(),
            Command::GetVaults => Reply::Vaults(self.vaults.list()),
            Command::GetAuthStatus => Reply::AuthStatus(self.auth.status(&caller.sid)),
            Command::BeginAuthSetup { password } => Reply::Enrollment(self.auth.begin_setup(&caller.sid, &password).map_err(auth_err)?),
            Command::FinishAuthSetup { code } => Reply::RecoveryCodes(self.auth.finish_setup(&caller.sid, &code).map_err(auth_err)?),
            Command::Authenticate { password } => {
                self.auth.authenticate(&caller.sid, &password).map_err(auth_err)?;
                Reply::AuthStatus(self.auth.status(&caller.sid))
            }
            Command::EndAuthSession => {
                self.auth.end_session(&caller.sid);
                Reply::Ack
            }
            Command::ChangeMasterPassword { current, new } => {
                self.auth.change_password(&caller.sid, &current, &new).map_err(auth_err)?;
                Reply::Ack
            }
            Command::RegenerateRecoveryCodes { password } => Reply::RecoveryCodes(self.auth.regenerate_recovery(&password).map_err(auth_err)?),
            Command::ResetMasterPassword { recovery_code, new } => {
                self.auth.reset_password(&caller.sid, &recovery_code, &new).map_err(auth_err)?;
                Reply::AuthStatus(self.auth.status(&caller.sid))
            }
            Command::BeginTotpReset { password, proof } => Reply::Enrollment(self.auth.begin_totp_reset(&caller.sid, &password, &proof).map_err(auth_err)?),
            Command::FinishTotpReset { code } => {
                self.auth.finish_totp_reset(&caller.sid, &code).map_err(auth_err)?;
                Reply::Ack
            }
            Command::AnalyzeVault { path } => {
                self.may_replace(caller, &path)?;
                Reply::VaultPlan(Box::new(self.vaults.analyze(&path)))
            }
            Command::PrepareVault { name, path, passphrase, max_bytes } => {
                self.may_replace(caller, &path)?;
                Reply::Vault(Box::new(self.vaults.prepare(&name, &path, passphrase, max_bytes).map_err(invalid)?))
            }
            Command::SwapVault { id } => {
                let v = self.vaults.vault(id).ok_or_else(not_found)?;
                self.may_replace(caller, &v.original_path)?;
                let v = self.vaults.swap(id).map_err(invalid)?;
                // Recurso de bloqueio do cofre (alvo = id do cofre), como as unidades.
                let resource = bytehalt_core::model::ProtectedResource {
                    id: uuid::Uuid::new_v4(),
                    display_name: v.name.clone(),
                    kind: ResourceKind::Vault,
                    target: v.id.to_string(),
                };
                let rid = resource.id;
                let saved = e.save_resource(resource).map_err(internal)?;
                if !saved.success {
                    return Err((ErrorCode::Validation, saved.errors.join(" ")));
                }
                self.vaults.set_resource(id, rid).map_err(invalid)?;
                Reply::Vault(Box::new(self.vaults.vault(id).ok_or_else(not_found)?))
            }
            Command::DiscardVault { id } => {
                let v = self.vaults.vault(id).ok_or_else(not_found)?;
                self.may_replace(caller, &v.original_path)?;
                self.vaults.discard(id).map_err(invalid)?;
                Reply::Ack
            }
            Command::DeleteVaultReserve { id } => {
                let v = self.vaults.vault(id).ok_or_else(not_found)?;
                self.may_replace(caller, &v.original_path)?;
                Reply::Vault(Box::new(self.vaults.delete_reserve(id).map_err(invalid)?))
            }
            Command::RemoveVault { id } => {
                let v = self.vaults.vault(id).ok_or_else(not_found)?;
                self.may_replace(caller, &v.original_path)?;
                if let Some(rid) = self.vaults.remove(id).map_err(invalid)? {
                    e.delete_resource(rid).map_err(internal)?;
                }
                Reply::Ack
            }
            Command::SimulateActivity { id } => {
                e.record_activity(id);
                Reply::Ack
            }
            Command::SimulateVolume { id, present, locked, open_handles, auto_unlock } => {
                let s = self.simulated.as_ref().ok_or((ErrorCode::Forbidden, "Somente no modo simulado.".to_owned()))?;
                s.with_volume(id, |v| {
                    if let Some(p) = present {
                        v.present = p;
                    }
                    if let Some(l) = locked {
                        v.locked = l;
                    }
                    if let Some(h) = open_handles {
                        v.open_handles = h;
                    }
                    if let Some(a) = auto_unlock {
                        v.auto_unlock = a;
                    }
                });
                Reply::Ack
            }
        })
    }

    /// No serviço do sistema (SYSTEM), o CHAMADOR precisa poder substituir a pasta: sem isso, qualquer
    /// usuário local transformaria em cofre (e trancaria) a pasta de outro. No console de
    /// desenvolvimento o serviço já roda como o próprio usuário.
    fn may_replace(&self, caller: &Caller, raw: &str) -> Result<(), (ErrorCode, String)> {
        if self.options.development {
            return Ok(());
        }
        let Some(path) = normalize_path(raw) else { return Ok(()) };
        let p = Path::new(&path);
        if !p.exists() {
            return Ok(());
        }
        match acl::caller_can_replace(caller.pid, p) {
            Ok(true) => Ok(()),
            Ok(false) => Err((ErrorCode::Forbidden, "Você não tem permissão para mover essa pasta.".into())),
            Err(e) => {
                eprintln!("Verificação de acesso: {e:#}");
                Err((ErrorCode::Forbidden, "Não foi possível verificar sua permissão na pasta.".into()))
            }
        }
    }

    fn discover(&self) -> Reply {
        let system = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".into()).to_uppercase();
        let Some(b) = &self.bitlocker else {
            let v = |l: &str, sys: bool, auto: bool, d: &str| VolumeInfo {
                drive_letter: l.into(),
                state: LockState::Unlocked,
                is_system_volume: sys,
                auto_unlock: auto,
                detail: Some(d.into()),
            };
            return Reply::Volumes {
                volumes: vec![
                    v(&system, true, false, "Simulado: unidade do sistema"),
                    v("D:", false, false, "Simulado"),
                    v("E:", false, true, "Simulado: desbloqueio automático ativo"),
                ],
                warning: Some("Modo simulado: nenhuma unidade real é consultada.".into()),
            };
        };
        match b.api().list() {
            Ok(list) => Reply::Volumes {
                volumes: list
                    .iter()
                    .map(|i| {
                        let s = map_status(Some(i), &system);
                        VolumeInfo {
                            drive_letter: i.drive_letter.clone(),
                            state: s.state,
                            is_system_volume: s.is_system_volume,
                            auto_unlock: s.auto_unlock,
                            detail: s.detail,
                        }
                    })
                    .collect(),
                warning: None,
            },
            Err(err) => Reply::Volumes { volumes: vec![], warning: Some(format!("{err:#}")) },
        }
    }
}

/// Histórico com limite, sem expor a trait no `dispatch`.
trait RecentEntries {
    fn recent_entries(&self, limit: usize) -> anyhow::Result<Vec<JournalEntry>>;
}

impl RecentEntries for SqliteStore {
    fn recent_entries(&self, limit: usize) -> anyhow::Result<Vec<JournalEntry>> {
        bytehalt_core::journal::Journal::recent(self, limit)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Class {
    /// Consulta ou ação que só aumenta a proteção (bloquear).
    ReadOrProtect,
    /// Pode enfraquecer a proteção: dono ou administrador.
    Configure,
    /// Só existe no modo --simulate.
    Simulation,
    /// Conta da senha mestra (cadastro, troca, recuperação): dono ou administrador; cada comando
    /// traz a própria prova (senha, código), sem exigir sessão.
    Account,
}

pub fn classify(c: &Command) -> Class {
    match c {
        Command::SaveResource { .. }
        | Command::DeleteResource { .. }
        | Command::SaveGroup { .. }
        | Command::DeleteGroup { .. }
        | Command::AnalyzeVault { .. }
        | Command::PrepareVault { .. }
        | Command::SwapVault { .. }
        | Command::DiscardVault { .. }
        | Command::DeleteVaultReserve { .. }
        | Command::RemoveVault { .. } => Class::Configure,
        Command::SimulateActivity { .. } | Command::SimulateVolume { .. } => Class::Simulation,
        Command::BeginAuthSetup { .. }
        | Command::FinishAuthSetup { .. }
        | Command::ChangeMasterPassword { .. }
        | Command::RegenerateRecoveryCodes { .. }
        | Command::ResetMasterPassword { .. }
        | Command::BeginTotpReset { .. }
        | Command::FinishTotpReset { .. } => Class::Account,
        _ => Class::ReadOrProtect,
    }
}

/// Regras de autorização (docs/ARCHITECTURE.md §6). `owner` é o SID que configurou primeiro.
pub fn authorized(c: &Command, caller: &Caller, owner: Option<&str>, simulated: bool) -> bool {
    if caller.sid.is_empty() {
        return false;
    }
    match classify(c) {
        Class::ReadOrProtect => true,
        Class::Configure | Class::Account => caller.is_admin || owner.is_none_or(|o| o.eq_ignore_ascii_case(&caller.sid)),
        Class::Simulation => simulated,
    }
}

/// Pastas que nunca viram cofre: sistema, programas, ProgramData, dados do ByteHalt, a raiz dos
/// perfis, cada perfil e o AppData de cada perfil.
pub fn path_rules(data_dir: &Path) -> PathRules {
    let env = |k: &str| std::env::var(k).ok().and_then(|v| normalize_path(&v));
    let mut forbidden_trees: Vec<String> =
        ["SystemRoot", "ProgramFiles", "ProgramFiles(x86)", "ProgramW6432", "ProgramData"].iter().filter_map(|k| env(k)).collect();
    forbidden_trees.extend(normalize_path(&data_dir.to_string_lossy()));
    if let Some(dir) = std::env::current_exe().ok().and_then(|e| e.parent().map(|p| p.to_string_lossy().into_owned())) {
        forbidden_trees.extend(normalize_path(&dir));
    }
    let users_root = std::env::var("SystemDrive").ok().and_then(|d| normalize_path(&format!(r"{d}\Users")));
    let mut forbidden_exact: Vec<String> = users_root.iter().cloned().collect();
    if let Some(root) = &users_root
        && let Ok(entries) = std::fs::read_dir(root)
    {
        forbidden_exact.extend(entries.flatten().filter_map(|e| normalize_path(&e.path().to_string_lossy())));
    }
    forbidden_trees.sort();
    forbidden_trees.dedup();
    PathRules { forbidden_trees, forbidden_exact, forbidden_in_profile: vec!["AppData".into()], users_root }
}
