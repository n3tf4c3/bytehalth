//! Serviço completo (console + simulado) pelo pipe real, em pasta temporária e relógio de teste.
//! Executado no Windows Sandbox.
#![cfg(windows)]

use bytehalt_core::auth::{Factors, UnlockCode};
use bytehalt_core::clock::TestClock;
use bytehalt_core::journal::EventType;
use bytehalt_core::locking::LockOutcome;
use bytehalt_core::model::{InactivityMode, ProtectedResource, ProtectionGroup, ResourceKind};
use bytehalt_core::simulated::TEST_PASSPHRASE;
use bytehalt_ipc::{Command, ErrorCode, Reply, ServiceError, call};
use bytehalt_service::{Host, Options, authorized};
use bytehalt_windows::pipe::{Caller, Server, connect};
use bytehalt_windows::user::current_user_sid;
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

fn caller(sid: &str, admin: bool) -> Caller {
    Caller { sid: sid.into(), is_admin: admin, pid: 1 }
}

#[test]
fn consultar_e_bloquear_sao_permitidos_a_qualquer_usuario_identificado() {
    for c in [
        Command::GetSnapshot,
        Command::LockAll,
        Command::LockGroup { id: Uuid::new_v4() },
        Command::Unlock { id: Uuid::new_v4(), passphrase: "x".into(), totp: None },
    ] {
        assert!(authorized(&c, &caller("S-1-5-21-200", false), Some("S-1-5-21-100"), false), "{}", c.name());
    }
}

#[test]
fn alterar_configuracao_exige_dono_ou_administrador() {
    let g = ProtectionGroup {
        id: Uuid::new_v4(),
        name: "x".into(),
        resource_ids: vec![],
        inactivity_secs: None,
        mode: InactivityMode::ResourceIdle,
        totp_threshold_secs: 86_400,
        lock_on_workstation_lock: false,
        lock_on_suspend: false,
    };
    for c in [Command::SaveGroup { group: g.clone() }, Command::DeleteGroup { id: g.id }, Command::DeleteResource { id: g.id }] {
        assert!(authorized(&c, &caller("S-1-5-21-100", false), Some("S-1-5-21-100"), false));
        assert!(authorized(&c, &caller("S-1-5-21-300", true), Some("S-1-5-21-100"), false));
        assert!(!authorized(&c, &caller("S-1-5-21-200", false), Some("S-1-5-21-100"), false));
        assert!(authorized(&c, &caller("S-1-5-21-200", false), None, false), "primeiro a configurar vira dono");
    }
}

#[test]
fn simulacao_so_no_modo_simulado_e_chamador_sem_identidade_sempre_recusado() {
    let sim = Command::SimulateActivity { id: Uuid::new_v4() };
    assert!(!authorized(&sim, &caller("S-1-5-21-1", true), None, false));
    assert!(authorized(&sim, &caller("S-1-5-21-1", false), None, true));
    for c in [Command::Ping, Command::LockAll, sim] {
        assert!(!authorized(&c, &caller("", true), None, true));
    }
}

/// Ordem dos campos = ordem de descarte: servidor, motor e só então a pasta temporária.
struct Svc {
    server: Option<Server>,
    host: Option<Arc<Host>>,
    clock: Arc<TestClock>,
    pipe: String,
    dir: tempfile::TempDir,
}

impl Svc {
    fn start() -> Self {
        let mut s = Self {
            dir: tempfile::tempdir().unwrap(),
            clock: Arc::new(TestClock::new()),
            pipe: format!("ByteHalt.Test.{}", Uuid::new_v4().simple()),
            host: None,
            server: None,
        };
        s.boot();
        s
    }

    fn boot(&mut self) {
        let options =
            Options { simulated: true, development: true, pipe: self.pipe.clone(), data_dir: self.dir.path().to_path_buf(), tick: Duration::from_secs(5) };
        let host = Arc::new(Host::create_with_rules(options, self.clock.clone(), bytehalt_core::vault::PathRules::default()).unwrap());
        self.server = Some(host.serve().unwrap());
        self.host = Some(host);
    }

    fn restart(&mut self) {
        if let Some(mut s) = self.server.take() {
            s.stop();
        }
        self.host = None;
        self.boot();
    }

    fn call(&self, c: Command) -> anyhow::Result<Reply> {
        let mut p = connect(&self.pipe, &[current_user_sid().unwrap()], Duration::from_secs(5))?;
        call(&mut p, c)
    }

    fn add(&self, letter: &str) -> ProtectedResource {
        let r = ProtectedResource {
            id: Uuid::nil(),
            display_name: format!("Unidade {}", letter.to_uppercase()),
            kind: ResourceKind::BitLockerVolume,
            target: letter.to_lowercase(),
        };
        let Reply::Operation(op) = self.call(Command::SaveResource { resource: r }).unwrap() else { panic!() };
        assert!(op.success, "{:?}", op.errors);
        let Reply::Snapshot(s) = self.call(Command::GetSnapshot).unwrap() else { panic!() };
        s.resources.into_iter().find(|v| v.resource.target.eq_ignore_ascii_case(letter)).unwrap().resource
    }

    fn snapshot(&self) -> bytehalt_core::engine::Snapshot {
        let Reply::Snapshot(s) = self.call(Command::GetSnapshot).unwrap() else { panic!() };
        s
    }

    fn requirement(&self, id: Uuid) -> bytehalt_core::auth::Requirement {
        let Reply::Requirement(r) = self.call(Command::GetUnlockRequirement { id }).unwrap() else { panic!() };
        r
    }

    fn history(&self) -> Vec<bytehalt_core::journal::JournalEntry> {
        let Reply::History(h) = self.call(Command::GetHistory { limit: 100 }).unwrap() else { panic!() };
        h
    }
}

fn group(name: &str, ids: Vec<Uuid>, minutes: u64, ws: bool) -> ProtectionGroup {
    ProtectionGroup {
        id: Uuid::nil(),
        name: name.into(),
        resource_ids: ids,
        inactivity_secs: Some(minutes * 60),
        mode: InactivityMode::ResourceIdle,
        totp_threshold_secs: 86_400,
        lock_on_workstation_lock: ws,
        lock_on_suspend: false,
    }
}

#[test]
fn fluxo_completo_cadastro_grupo_bloqueio_e_desbloqueio_pelo_pipe() {
    let s = Svc::start();
    let Reply::Pong { simulated, .. } = s.call(Command::Ping).unwrap() else { panic!() };
    assert!(simulated);
    let d = s.add("d:");
    assert_eq!(d.target, "D:", "letra normalizada pelo serviço");
    let Reply::Operation(op) = s.call(Command::SaveGroup { group: group("Discos", vec![d.id], 1, true) }).unwrap() else { panic!() };
    assert!(op.success);
    let gid = s.snapshot().groups[0].id;
    let Reply::Locks(l) = s.call(Command::LockGroup { id: gid }).unwrap() else { panic!() };
    assert_eq!(l[0].outcome, LockOutcome::Locked);
    // O bloqueio feito pelo pipe grava o registro protegido (regressão da impersonation).
    let req = s.requirement(d.id);
    assert_eq!(req.factors, Factors::Primary, "{req:?} / histórico: {:?}", s.history());
    let Reply::Unlock(bad) = s.call(Command::Unlock { id: d.id, passphrase: "errada".into(), totp: None }).unwrap() else { panic!() };
    assert_eq!(bad.code, UnlockCode::BadCredential);
    let Reply::Unlock(good) = s.call(Command::Unlock { id: d.id, passphrase: TEST_PASSPHRASE.into(), totp: None }).unwrap() else { panic!() };
    assert_eq!(good.code, UnlockCode::Unlocked);
    let h = s.history();
    assert!(h.iter().any(|e| e.event == EventType::Locked) && h.iter().any(|e| e.event == EventType::UnlockDenied));
    assert!(!h.iter().any(|e| {
        let t = format!("{} {:?}", e.message, e.detail);
        t.contains(TEST_PASSPHRASE) || t.contains("errada")
    }));
}

#[test]
fn unidade_do_sistema_aparece_e_e_recusada() {
    let s = Svc::start();
    let system = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".into()).to_uppercase();
    let Reply::Volumes { volumes, .. } = s.call(Command::DiscoverVolumes).unwrap() else { panic!() };
    assert!(volumes.iter().any(|v| v.drive_letter == system && v.is_system_volume));
    let c = s.add(&system);
    let Reply::Locks(l) = s.call(Command::LockResources { ids: vec![c.id] }).unwrap() else { panic!() };
    assert_eq!(l[0].outcome, LockOutcome::Refused);
}

#[test]
fn grupo_invalido_volta_com_validacao_e_payload_errado_e_recusado() {
    let s = Svc::start();
    let Reply::Operation(op) = s.call(Command::SaveGroup { group: group("  ", vec![Uuid::new_v4()], 30, false) }).unwrap() else { panic!() };
    assert!(!op.success && !op.errors.is_empty());
    let e = s.call(Command::GetHistory { limit: 0 }).unwrap_err();
    assert_eq!(e.downcast_ref::<ServiceError>().unwrap().code, ErrorCode::Validation);
}

#[test]
fn arquivo_aberto_simulado_adia_o_bloqueio() {
    let s = Svc::start();
    let e = s.add("E:");
    s.call(Command::SimulateVolume { id: e.id, present: None, locked: None, open_handles: Some(3), auto_unlock: None }).unwrap();
    let Reply::Locks(l) = s.call(Command::LockAll).unwrap() else { panic!() };
    assert_eq!(l[0].outcome, LockOutcome::Postponed);
    assert!(s.snapshot().resources[0].pending_lock);
}

#[test]
fn reinicio_do_servico_mantem_bloqueio_grupos_e_regra_de_24h() {
    let mut s = Svc::start();
    let d = s.add("D:");
    s.call(Command::SaveGroup { group: group("Discos", vec![d.id], 10, false) }).unwrap();
    s.call(Command::LockAll).unwrap();
    s.clock.advance(Duration::from_secs(23 * 3600 + 59 * 60));
    s.restart();
    let snap = s.snapshot();
    assert_eq!(snap.resources[0].state, bytehalt_core::locking::LockState::Locked);
    assert_eq!(snap.groups[0].name, "Discos");
    assert_eq!(s.requirement(d.id).factors, Factors::Primary);
    s.clock.advance(Duration::from_secs(60));
    assert_eq!(s.requirement(d.id).factors, Factors::PrimaryAndTotp);
    let Reply::Unlock(u) = s.call(Command::Unlock { id: d.id, passphrase: TEST_PASSPHRASE.into(), totp: None }).unwrap() else { panic!() };
    assert_eq!(u.code, UnlockCode::TotpNotEnrolled, "Fase 1: sem autenticador, falha fechada");
}

#[test]
fn ociosidade_relatada_aparece_no_estado() {
    let s = Svc::start();
    s.call(Command::ReportSessionIdle { idle_secs: 42 }).unwrap();
    assert_eq!(s.snapshot().session_idle_secs, Some(42));
    let e = s.call(Command::ReportSessionIdle { idle_secs: 30 * 86_400 }).unwrap_err();
    assert_eq!(e.downcast_ref::<ServiceError>().unwrap().code, ErrorCode::Validation);
}

#[test]
fn cofre_simulado_preparar_trocar_bloquear_e_apagar_a_reserva_pelo_pipe() {
    use bytehalt_core::vault::{RESERVE_MARK, VaultStage};
    let s = Svc::start();
    let work = tempfile::tempdir().unwrap();
    let folder = work.path().join("Projeto");
    std::fs::create_dir_all(folder.join("src")).unwrap();
    std::fs::write(folder.join("README.md"), b"# projeto").unwrap();
    std::fs::write(folder.join("src").join("main.rs"), b"fn main() {}").unwrap();
    let path = folder.to_string_lossy().into_owned();

    let Reply::VaultPlan(plan) = s.call(Command::AnalyzeVault { path: path.clone() }).unwrap() else { panic!() };
    assert!(plan.ok(), "{:?}", plan.issues);
    assert_eq!(plan.inventory.files, 2);
    let err = s.call(Command::PrepareVault { name: "Projeto".into(), path: path.clone(), passphrase: "curta".into(), max_bytes: plan.suggested_max_bytes });
    assert!(err.unwrap_err().to_string().contains("pelo menos 8"));
    let Reply::Vault(v) = s
        .call(Command::PrepareVault { name: "Projeto".into(), path: path.clone(), passphrase: "senha-do-cofre-1".into(), max_bytes: plan.suggested_max_bytes })
        .unwrap()
    else {
        panic!()
    };

    // O progresso público não entrega nem consome a chave pendente.
    let mut stage = VaultStage::Preparing;
    for _ in 0..400 {
        let Reply::Vaults(list) = s.call(Command::GetVaults).unwrap() else { panic!() };
        assert!(!serde_json::to_string(&list).unwrap().contains("recoveryKey"));
        let view = list.into_iter().find(|x| x.vault.id == v.id).unwrap();
        stage = view.vault.stage;
        if stage != VaultStage::Preparing && view.job.is_some_and(|j| j.done) {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(stage, VaultStage::Ready);
    let Reply::VaultRecovery { id, key: Some(key) } = s.call(Command::ClaimVaultRecovery { id: v.id }).unwrap() else { panic!() };
    assert_eq!(id, v.id);
    assert!(!key.is_empty());
    for _ in 0..2 {
        let Reply::Vaults(list) = s.call(Command::GetVaults).unwrap() else { panic!() };
        assert!(!serde_json::to_string(&list).unwrap().contains(&key));
        let Reply::VaultRecovery { id, key: Some(retry) } = s.call(Command::ClaimVaultRecovery { id: v.id }).unwrap() else { panic!() };
        assert_eq!(id, v.id);
        assert!(retry == key, "nova conexão deve recuperar a mesma chave até a confirmação");
    }
    for _ in 0..2 {
        assert!(matches!(s.call(Command::AckVaultRecovery { id: v.id }).unwrap(), Reply::Ack));
    }
    assert!(matches!(s.call(Command::ClaimVaultRecovery { id: v.id }).unwrap(), Reply::VaultRecovery { key: None, .. }));

    let Reply::Vault(v) = s.call(Command::SwapVault { id: v.id }).unwrap() else { panic!() };
    assert_eq!(v.stage, VaultStage::Active);
    let reserve = std::path::PathBuf::from(v.reserve_path.clone().unwrap());
    assert!(reserve.to_string_lossy().contains(RESERVE_MARK) && reserve.join("README.md").exists());
    assert_eq!(std::fs::read(folder.join("README.md")).unwrap(), b"# projeto", "o caminho original mostra o cofre");

    let rid = v.resource_id.unwrap();
    let r = s.snapshot().resources.into_iter().find(|x| x.resource.id == rid).unwrap();
    assert_eq!((r.resource.kind, r.resource.target.clone()), (ResourceKind::Vault, v.id.to_string()));
    let Reply::Locks(l) = s.call(Command::LockResources { ids: vec![rid] }).unwrap() else { panic!() };
    assert_eq!(l[0].outcome, LockOutcome::Locked);
    let Reply::Unlock(u) = s.call(Command::Unlock { id: rid, passphrase: TEST_PASSPHRASE.into(), totp: None }).unwrap() else { panic!() };
    assert_eq!(u.code, UnlockCode::Unlocked);

    let Reply::Vault(v) = s.call(Command::DeleteVaultReserve { id: v.id }).unwrap() else { panic!() };
    assert!(v.reserve_path.is_none() && !reserve.exists());
    assert!(folder.join("src").join("main.rs").exists());
    assert!(s.history().iter().any(|e| e.event == EventType::VaultChanged && e.message.contains("ativo")));
    let err = s.call(Command::DiscardVault { id: v.id }).unwrap_err().to_string();
    assert!(err.contains("ainda não ativado"), "{err}");
}

#[test]
fn remover_cofre_pelo_pipe_devolve_a_pasta_e_apaga_o_recurso() {
    use bytehalt_core::vault::VaultStage;
    let s = Svc::start();
    let work = tempfile::tempdir().unwrap();
    let folder = work.path().join("Docs");
    std::fs::create_dir_all(&folder).unwrap();
    std::fs::write(folder.join("a.txt"), b"a").unwrap();
    let path = folder.to_string_lossy().into_owned();
    let Reply::VaultPlan(plan) = s.call(Command::AnalyzeVault { path: path.clone() }).unwrap() else { panic!() };
    let Reply::Vault(v) =
        s.call(Command::PrepareVault { name: "Docs".into(), path, passphrase: "senha-do-cofre-1".into(), max_bytes: plan.suggested_max_bytes }).unwrap()
    else {
        panic!()
    };
    for _ in 0..400 {
        let Reply::Vaults(list) = s.call(Command::GetVaults).unwrap() else { panic!() };
        if list.iter().any(|x| x.vault.id == v.id && x.vault.stage == VaultStage::Ready) {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let Reply::Vault(v) = s.call(Command::SwapVault { id: v.id }).unwrap() else { panic!() };
    std::fs::write(folder.join("b.txt"), b"b").unwrap();
    let rid = v.resource_id.unwrap();
    let Reply::Ack = s.call(Command::RemoveVault { id: v.id }).unwrap() else { panic!() };
    assert!(!std::fs::symlink_metadata(&folder).unwrap().file_type().is_symlink());
    assert!(folder.join("a.txt").exists() && folder.join("b.txt").exists());
    let Reply::Vaults(list) = s.call(Command::GetVaults).unwrap() else { panic!() };
    assert!(list.is_empty());
    assert!(s.snapshot().resources.iter().all(|r| r.resource.id != rid), "o recurso do cofre foi apagado");
}

fn code_of(e: anyhow::Error) -> Option<ErrorCode> {
    e.downcast_ref::<ServiceError>().map(|s| s.code)
}

#[test]
fn recuperacao_do_cofre_exige_sid_iniciador_e_sessao_quando_configurada() {
    use bytehalt_core::clock::Clock;
    use bytehalt_core::master::{STEP_SECS, totp};
    use bytehalt_core::vault::VaultStage;
    use bytehalt_ipc::{Request, VERSION};
    let s = Svc::start();
    let a = caller("S-1-5-21-111-222-333-1001", false);
    let b = caller("S-1-5-21-111-222-333-1002", false);
    let admin_b = caller(&b.sid, true);
    // Identidades sintéticas percorrem a autorização real, sem criar contas do Windows.
    let send = |command, who: &Caller| s.host.as_ref().unwrap().handle(Request { version: VERSION, id: Uuid::new_v4(), request: command }, who).result;
    let work = tempfile::tempdir().unwrap();
    let folder = work.path().join("Projeto");
    std::fs::create_dir(&folder).unwrap();
    std::fs::write(folder.join("a.txt"), b"a").unwrap();
    let path = folder.to_string_lossy().into_owned();
    let Reply::VaultPlan(plan) = send(Command::AnalyzeVault { path: path.clone() }, &a).unwrap() else { panic!() };
    assert!(plan.ok());
    let Reply::Vault(v) =
        send(Command::PrepareVault { name: "Projeto".into(), path, passphrase: "senha-do-cofre-1".into(), max_bytes: plan.suggested_max_bytes }, &a).unwrap()
    else {
        panic!()
    };
    let mut ready = false;
    for _ in 0..400 {
        let Reply::Vaults(list) = send(Command::GetVaults, &b).unwrap() else { panic!() };
        assert!(!serde_json::to_string(&list).unwrap().contains("recoveryKey"));
        ready = list.iter().any(|x| x.vault.id == v.id && x.vault.stage == VaultStage::Ready && x.job.as_ref().is_some_and(|j| j.done));
        if ready {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(ready, "preparação simulada deve terminar");
    let claim = Command::ClaimVaultRecovery { id: v.id };
    let ack = Command::AckVaultRecovery { id: v.id };
    // Antes do cadastro, nem outro usuário nem outro administrador recebe/apaga a chave.
    for foreign in [&b, &admin_b] {
        for command in [claim.clone(), ack.clone()] {
            assert_eq!(send(command, foreign).unwrap_err().0, ErrorCode::Forbidden);
        }
    }
    let Reply::VaultRecovery { id, key: Some(key) } = send(claim.clone(), &a).unwrap() else { panic!() };
    assert_eq!(id, v.id);
    assert!(!key.is_empty());
    let password = "senha-mestra-de-teste";
    let Reply::Enrollment(enrollment) = send(Command::BeginAuthSetup { password: password.into() }, &a).unwrap() else { panic!() };
    let secret = data_encoding::BASE32_NOPAD.decode(enrollment.secret.as_bytes()).unwrap();
    let step = s.clock.now_utc().div_euclid(1000).div_euclid(STEP_SECS);
    assert!(matches!(send(Command::FinishAuthSetup { code: totp(&secret, step) }, &a).unwrap(), Reply::RecoveryCodes(_)));
    assert!(matches!(send(Command::EndAuthSession, &a).unwrap(), Reply::Ack));
    for command in [claim.clone(), ack.clone()] {
        assert_eq!(send(command.clone(), &a).unwrap_err().0, ErrorCode::AuthRequired);
        assert_eq!(send(command, &admin_b).unwrap_err().0, ErrorCode::AuthRequired);
    }
    for who in [&a, &admin_b] {
        let Reply::AuthStatus(status) = send(Command::Authenticate { password: password.into() }, who).unwrap() else { panic!() };
        assert!(status.session_active);
    }
    // Sessão mestra válida de B não concede a propriedade do trabalho iniciado por A.
    for command in [claim.clone(), ack.clone()] {
        assert_eq!(send(command.clone(), &admin_b).unwrap_err().0, ErrorCode::Forbidden);
        assert_eq!(send(command, &b).unwrap_err().0, ErrorCode::Forbidden);
    }
    for _ in 0..2 {
        let Reply::Vaults(list) = send(Command::GetVaults, &b).unwrap() else { panic!() };
        assert!(!serde_json::to_string(&list).unwrap().contains(&key));
        let Reply::VaultRecovery { key: Some(retry), .. } = send(claim.clone(), &a).unwrap() else { panic!() };
        assert!(retry == key, "listagem e recusas não podem consumir a chave");
    }
    for _ in 0..2 {
        assert!(matches!(send(ack.clone(), &a).unwrap(), Reply::Ack));
    }
    assert!(matches!(send(claim, &a).unwrap(), Reply::VaultRecovery { key: None, .. }));
}

#[test]
fn regeneracao_sem_prova_e_recusada_pelo_pipe() {
    use bytehalt_core::clock::Clock;
    use bytehalt_core::master::{RECOVERY_CODES, STEP_SECS, totp};
    let s = Svc::start();
    let password = "senha-mestra-de-teste";
    let Reply::Enrollment(enrollment) = s.call(Command::BeginAuthSetup { password: password.into() }).unwrap() else { panic!() };
    let secret = data_encoding::BASE32_NOPAD.decode(enrollment.secret.as_bytes()).unwrap();
    let step = s.clock.now_utc().div_euclid(1000).div_euclid(STEP_SECS);
    let Reply::RecoveryCodes(codes) = s.call(Command::FinishAuthSetup { code: totp(&secret, step) }).unwrap() else { panic!() };
    assert_eq!(codes.len(), RECOVERY_CODES);
    let before = std::fs::read(s.dir.path().join("state").join("credentials.dat")).unwrap();
    // Reproduz o cliente antigo em JSON: o teste também compila no protocolo vulnerável.
    let payload = serde_json::json!({
        "version": bytehalt_ipc::VERSION, "id": Uuid::new_v4(),
        "request": {"command": "RegenerateRecoveryCodes", "payload": {"password": password}}
    });
    let mut pipe = connect(&s.pipe, &[current_user_sid().unwrap()], Duration::from_secs(5)).unwrap();
    bytehalt_ipc::write_frame(&mut pipe, &serde_json::to_vec(&payload).unwrap()).unwrap();
    let bytes = bytehalt_ipc::read_frame(&mut pipe).unwrap().unwrap();
    let response: bytehalt_ipc::Response = serde_json::from_slice(&bytes).unwrap();
    assert!(matches!(response.result, Err((ErrorCode::BadRequest, _))), "senha sozinha regenerou códigos pelo pipe");
    assert!(std::fs::read(s.dir.path().join("state").join("credentials.dat")).unwrap() == before);
    let Reply::AuthStatus(status) = s.call(Command::GetAuthStatus).unwrap() else { panic!() };
    assert!(status.configured && status.recovery_left == RECOVERY_CODES);
}

#[test]
fn regeneracao_pelo_pipe_preserva_fatores_sem_prova_e_permite_recuperacao_legitima() {
    use bytehalt_core::clock::Clock;
    use bytehalt_core::master::{CredentialStore, RECOVERY_CODES, STEP_SECS, totp};
    let s = Svc::start();
    let password = "senha-mestra-de-teste";
    let step = || s.clock.now_utc().div_euclid(1000).div_euclid(STEP_SECS);
    let Reply::Enrollment(enrollment) = s.call(Command::BeginAuthSetup { password: password.into() }).unwrap() else { panic!() };
    let original_secret = data_encoding::BASE32_NOPAD.decode(enrollment.secret.as_bytes()).unwrap();
    let Reply::RecoveryCodes(original_codes) = s.call(Command::FinishAuthSetup { code: totp(&original_secret, step()) }).unwrap() else { panic!() };
    assert_eq!(original_codes.len(), RECOVERY_CODES);
    let credential_path = s.dir.path().join("state").join("credentials.dat");
    let before = std::fs::read(&credential_path).unwrap();
    for proof in ["", "prova-invalida"] {
        let err = s.call(Command::RegenerateRecoveryCodes { password: password.into(), proof: proof.into() }).unwrap_err();
        assert_eq!(code_of(err), Some(ErrorCode::Validation));
        assert!(std::fs::read(&credential_path).unwrap() == before, "recusa não altera TOTP nem códigos persistidos");
    }
    let Reply::RecoveryCodes(rotated) = s.call(Command::RegenerateRecoveryCodes { password: password.into(), proof: original_codes[0].clone() }).unwrap()
    else {
        panic!()
    };
    assert_eq!(rotated.len(), RECOVERY_CODES);
    assert!(rotated.iter().all(|code| !original_codes.contains(code)));
    // Uma chave do conjunto substituído não permite assumir o autenticador.
    let err = s.call(Command::BeginTotpReset { password: password.into(), proof: original_codes[1].clone() }).unwrap_err();
    assert_eq!(code_of(err), Some(ErrorCode::Validation));
    let Reply::Enrollment(replacement) = s.call(Command::BeginTotpReset { password: password.into(), proof: rotated[0].clone() }).unwrap() else { panic!() };
    let new_secret = data_encoding::BASE32_NOPAD.decode(replacement.secret.as_bytes()).unwrap();
    assert!(matches!(s.call(Command::FinishTotpReset { code: totp(&new_secret, step()) }).unwrap(), Reply::Ack));
    let store = bytehalt_windows::dpapi::DpapiCredentialStore::new(s.dir.path().join("state"), false).unwrap();
    let credentials = store.load().unwrap().unwrap();
    assert!(credentials.totp_secret == new_secret && credentials.totp_secret != original_secret);
    let Reply::AuthStatus(status) = s.call(Command::GetAuthStatus).unwrap() else { panic!() };
    assert_eq!(status.recovery_left, RECOVERY_CODES - 1);
    // O novo autenticador funciona como segundo fator pelo mesmo pipe.
    s.clock.advance(Duration::from_secs(STEP_SECS as u64));
    let Reply::RecoveryCodes(next) = s.call(Command::RegenerateRecoveryCodes { password: password.into(), proof: totp(&new_secret, step()) }).unwrap() else {
        panic!()
    };
    assert_eq!(next.len(), RECOVERY_CODES);
}

#[test]
fn senha_mestra_protege_a_configuracao_e_totp_libera_depois_de_24h() {
    use bytehalt_core::clock::Clock;
    use bytehalt_core::master::{RECOVERY_CODES, STEP_SECS, totp};
    let s = Svc::start();
    let d = s.add("D:");
    let step = |s: &Svc| s.clock.now_utc().div_euclid(1000).div_euclid(STEP_SECS);
    let Reply::AuthStatus(st) = s.call(Command::GetAuthStatus).unwrap() else { panic!() };
    assert!(!st.configured);

    // Cadastro: senha fraca recusada; o primeiro código do aplicativo confirma.
    assert!(s.call(Command::BeginAuthSetup { password: "curta".into() }).unwrap_err().to_string().contains("12"));
    let Reply::Enrollment(e) = s.call(Command::BeginAuthSetup { password: "senha-mestra-de-teste".into() }).unwrap() else { panic!() };
    let secret = data_encoding::BASE32_NOPAD.decode(e.secret.as_bytes()).unwrap();
    let Reply::RecoveryCodes(codes) = s.call(Command::FinishAuthSetup { code: totp(&secret, step(&s)) }).unwrap() else { panic!() };
    assert_eq!(codes.len(), RECOVERY_CODES);

    // Sessão aberta pelo cadastro; encerrada, a configuração exige a senha mestra.
    let Reply::Operation(op) = s.call(Command::SaveGroup { group: group("G", vec![d.id], 5, false) }).unwrap() else { panic!() };
    assert!(op.success);
    let Reply::Ack = s.call(Command::EndAuthSession).unwrap() else { panic!() };
    let err = s.call(Command::SaveGroup { group: group("H", vec![d.id], 5, false) }).unwrap_err();
    assert_eq!(code_of(err), Some(ErrorCode::AuthRequired));
    assert!(s.call(Command::Authenticate { password: "errada-errada-errada".into() }).is_err());
    let Reply::AuthStatus(st) = s.call(Command::Authenticate { password: "senha-mestra-de-teste".into() }).unwrap() else { panic!() };
    assert!(st.session_active && st.recovery_left == RECOVERY_CODES);
    let Reply::Operation(op) = s.call(Command::SaveGroup { group: group("H", vec![d.id], 5, false) }).unwrap() else { panic!() };
    assert!(op.success);
    // Bloquear continua livre, sem sessão.
    let Reply::Ack = s.call(Command::EndAuthSession).unwrap() else { panic!() };
    let Reply::Locks(l) = s.call(Command::LockResources { ids: vec![d.id] }).unwrap() else { panic!() };
    assert_eq!(l[0].outcome, LockOutcome::Locked);

    // Depois de 24 h bloqueado: senha da unidade + código do aplicativo, uma vez só.
    s.clock.advance(Duration::from_secs(25 * 3600));
    assert_eq!(s.requirement(d.id).factors, Factors::PrimaryAndTotp);
    let Reply::Unlock(u) = s.call(Command::Unlock { id: d.id, passphrase: TEST_PASSPHRASE.into(), totp: None }).unwrap() else { panic!() };
    assert_eq!(u.code, UnlockCode::TotpRequired);
    let code = totp(&secret, step(&s));
    let Reply::Unlock(u) = s.call(Command::Unlock { id: d.id, passphrase: TEST_PASSPHRASE.into(), totp: Some(code.clone()) }).unwrap() else { panic!() };
    assert_eq!(u.code, UnlockCode::Unlocked);
    let Reply::Locks(_) = s.call(Command::LockResources { ids: vec![d.id] }).unwrap() else { panic!() };
    s.clock.advance(Duration::from_secs(25 * 3600));
    let Reply::Unlock(u) = s.call(Command::Unlock { id: d.id, passphrase: TEST_PASSPHRASE.into(), totp: Some(code.clone()) }).unwrap() else { panic!() };
    assert_eq!(u.code, UnlockCode::TotpInvalid, "o código de 25 h atrás não vale");

    // Esqueceu a senha mestra: um código de recuperação cria outra.
    let Reply::AuthStatus(st) = s.call(Command::ResetMasterPassword { recovery_code: codes[0].clone(), new: "outra-senha-mestra-1".into() }).unwrap() else {
        panic!()
    };
    assert_eq!(st.recovery_left, RECOVERY_CODES - 1);
    assert!(s.call(Command::ResetMasterPassword { recovery_code: codes[0].clone(), new: "mais-uma-senha-1".into() }).is_err());
    assert!(s.history().iter().all(|e| !e.message.contains("senha-mestra-de-teste") && !e.message.contains(&codes[1])));
}

/// Achado de auditoria #8: uma linha de cofre ilegível no banco não pode fazer a partida do serviço
/// tratar cofres como órfãos e apagar as proteções.
#[test]
fn cofre_ilegivel_no_banco_nao_remove_protecoes_na_partida() {
    use bytehalt_core::journal::Journal;
    use bytehalt_core::model::ConfigRepository;
    use bytehalt_windows::sqlite::SqliteStore;
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("bytehalt.db");
    let (rid, vid) = (Uuid::new_v4(), Uuid::new_v4());
    SqliteStore::open(&db_path)
        .unwrap()
        .upsert_resource(&ProtectedResource { id: rid, display_name: "Cofre".into(), kind: ResourceKind::Vault, target: vid.to_string() })
        .unwrap();
    rusqlite::Connection::open(&db_path).unwrap().execute("INSERT INTO vaults (id, data) VALUES (?1, '{corrompido')", [vid.to_string()]).unwrap();
    let options = Options {
        simulated: true,
        development: true,
        pipe: format!("ByteHalt.Teste.{}", Uuid::new_v4()),
        data_dir: dir.path().to_path_buf(),
        tick: Duration::from_secs(5),
    };
    drop(Host::create_with_rules(options, Arc::new(TestClock::new()), bytehalt_core::vault::PathRules::default()).unwrap());
    let db = SqliteStore::open(&db_path).unwrap();
    assert!(db.resources().unwrap().iter().any(|r| r.id == rid), "a proteção do cofre foi apagada na partida");
    assert!(
        db.recent(50).unwrap().iter().any(|e| e.message.contains("nenhuma proteção de cofre foi removida")),
        "a falha de leitura dos cofres não ficou registrada"
    );
}
