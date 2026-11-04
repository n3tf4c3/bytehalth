//! Motor completo com relógio de teste, locker e sonda simulados (especificação §7:
//! temporizadores, grupos, falhas, regra de 24 h, retomada). Executado no Windows Sandbox.

use bytehalt_core::auth::{Factors, InMemoryStateStore, LockStateStore, NotEnrolled, Reason, StoreRead, TotpVerifier, UnlockCode, UnlockCoordinator};
use bytehalt_core::clock::{BootSession, Clock, TestBoot, TestClock};
use bytehalt_core::engine::Engine;
use bytehalt_core::inactivity::ReportedSessionIdle;
use bytehalt_core::journal::{EventType, InMemoryJournal, JournalEntry, Severity};
use bytehalt_core::locking::{LockOrchestrator, LockOutcome, LockState, LockTrigger, ResourceLocker};
use bytehalt_core::model::{ConfigRepository, InMemoryConfig, InactivityMode, ProtectedResource, ProtectionGroup, ResourceKind};
use bytehalt_core::simulated::{SimulatedBusy, SimulatedLocker, TEST_PASSPHRASE};
use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use uuid::Uuid;

const DAY: Duration = Duration::from_secs(86_400);

struct FakeTotp(Mutex<HashSet<String>>);

impl TotpVerifier for FakeTotp {
    fn enrolled(&self) -> bool {
        true
    }

    fn verify(&self, code: &str) -> bool {
        code == "123456" && self.0.lock().unwrap().insert(code.to_owned())
    }
}

struct Rig {
    clock: Arc<TestClock>,
    boot: Arc<TestBoot>,
    store: Arc<InMemoryStateStore>,
    locker: Arc<SimulatedLocker>,
    journal: Arc<InMemoryJournal>,
    busy: Arc<SimulatedBusy>,
    notified: Arc<Mutex<Vec<JournalEntry>>>,
    engine: Engine,
    orchestrator: LockOrchestrator,
    unlock: UnlockCoordinator,
}

impl Rig {
    fn new() -> Self {
        let clock = Arc::new(TestClock::new());
        let boot = Arc::new(TestBoot::new(clock.clone()));
        Self::with(
            clock,
            boot,
            Arc::default(),
            Arc::new(SimulatedLocker::new(ResourceKind::BitLockerVolume, Some("C:"), None)),
            Arc::default(),
            Arc::new(NotEnrolled),
        )
    }

    fn with(
        clock: Arc<TestClock>,
        boot: Arc<TestBoot>,
        store: Arc<InMemoryStateStore>,
        locker: Arc<SimulatedLocker>,
        config: Arc<InMemoryConfig>,
        totp: Arc<dyn TotpVerifier>,
    ) -> Self {
        let journal = Arc::new(InMemoryJournal::default());
        let busy = Arc::new(SimulatedBusy::default());
        let notified: Arc<Mutex<Vec<JournalEntry>>> = Arc::default();
        let n = notified.clone();
        let make_orchestrator = || {
            let n = n.clone();
            LockOrchestrator::new(
                vec![locker.clone() as Arc<dyn ResourceLocker>],
                busy.clone(),
                store.clone(),
                journal.clone(),
                clock.clone(),
                boot.clone(),
                Some(Arc::new(move |e: &JournalEntry| n.lock().unwrap().push(e.clone()))),
            )
        };
        let make_unlock = || UnlockCoordinator::new(store.clone(), totp.clone(), journal.clone(), clock.clone(), boot.clone());
        let session = Arc::new(ReportedSessionIdle::new(clock.clone()));
        let engine = Engine::new(config.clone(), make_orchestrator(), make_unlock(), session, store.clone(), journal.clone(), clock.clone(), true);
        engine.reload().unwrap();
        Self { orchestrator: make_orchestrator(), unlock: make_unlock(), clock, boot, store, locker, journal, busy, notified, engine }
    }

    fn vol(name: &str, letter: &str) -> ProtectedResource {
        ProtectedResource { id: Uuid::new_v4(), display_name: name.into(), kind: ResourceKind::BitLockerVolume, target: letter.into() }
    }

    fn add(&self, name: &str, letter: &str) -> ProtectedResource {
        let r = Self::vol(name, letter);
        let res = self.engine.save_resource(r.clone()).unwrap();
        assert!(res.success, "{:?}", res.errors);
        r
    }

    fn group(&self, name: &str, minutes: Option<u64>, mode: InactivityMode, ws: bool, rs: &[&ProtectedResource]) -> ProtectionGroup {
        let g = ProtectionGroup {
            id: Uuid::new_v4(),
            name: name.into(),
            resource_ids: rs.iter().map(|r| r.id).collect(),
            inactivity_secs: minutes.map(|m| m * 60),
            mode,
            totp_threshold_secs: 86_400,
            lock_on_workstation_lock: ws,
        };
        let res = self.engine.save_group(g.clone()).unwrap();
        assert!(res.success, "{:?}", res.errors);
        g
    }

    /// Avança o relógio em passos de 5 s executando o ciclo do motor, como o serviço.
    fn run(&self, d: Duration) -> Vec<bytehalt_core::locking::LockResult> {
        let mut out = Vec::new();
        let mut t = Duration::ZERO;
        while t < d {
            self.clock.advance(Duration::from_secs(5));
            out.extend(self.engine.tick());
            t += Duration::from_secs(5);
        }
        out
    }

    fn locked(&self, r: &ProtectedResource) -> bool {
        self.locker.volume(r.id).locked
    }

    fn has(&self, event: EventType, text: &str) -> bool {
        self.journal.entries().iter().any(|e| e.event == event && e.message.contains(text))
    }

    fn view(&self, r: &ProtectedResource) -> bytehalt_core::engine::ResourceView {
        self.engine.snapshot().resources.into_iter().find(|v| v.resource.id == r.id).unwrap()
    }
}

fn secs(s: u64) -> Duration {
    Duration::from_secs(s)
}

// ---------------- Orquestrador ----------------

#[test]
fn bloqueio_bem_sucedido_grava_instante_historico_e_notifica() {
    let rig = Rig::new();
    let d = Rig::vol("Unidade D:", "D:");
    assert_eq!(rig.orchestrator.lock(&d, LockTrigger::Manual).outcome, LockOutcome::Locked);
    assert!(rig.locked(&d));
    let StoreRead::Found(rec) = rig.store.read(d.id) else { panic!("sem registro") };
    assert_eq!(rec.locked_at, rig.clock.now_utc());
    assert_eq!(rec.boot_id, rig.boot.boot_id());
    assert!(rig.has(EventType::Locked, "Unidade D: — bloqueado"));
    assert_eq!(rig.notified.lock().unwrap().len(), 1);
}

#[test]
fn unidade_do_sistema_e_recusada_sem_tentar_bloquear() {
    let rig = Rig::new();
    let c = Rig::vol("Sistema", "C:");
    assert_eq!(rig.orchestrator.lock(&c, LockTrigger::Manual).outcome, LockOutcome::Refused);
    assert_eq!(rig.locker.volume(c.id).lock_calls, 0);
}

#[test]
fn sem_bitlocker_ou_indisponivel_nao_e_tocado() {
    let rig = Rig::new();
    let d = Rig::vol("D", "D:");
    rig.locker.with_volume(d.id, |v| v.protected = false);
    assert_eq!(rig.orchestrator.lock(&d, LockTrigger::Manual).outcome, LockOutcome::Refused);
    let f = Rig::vol("USB", "F:");
    rig.locker.with_volume(f.id, |v| v.present = false);
    assert_eq!(rig.orchestrator.lock(&f, LockTrigger::Inactivity).outcome, LockOutcome::Unavailable);
    assert_eq!(rig.locker.volume(d.id).lock_calls + rig.locker.volume(f.id).lock_calls, 0);
}

#[test]
fn ja_bloqueado_nao_regrava_o_instante() {
    let rig = Rig::new();
    let d = Rig::vol("D", "D:");
    rig.orchestrator.lock(&d, LockTrigger::Manual);
    let StoreRead::Found(first) = rig.store.read(d.id) else { panic!() };
    rig.clock.advance(secs(3 * 3600));
    assert_eq!(rig.orchestrator.lock(&d, LockTrigger::Manual).outcome, LockOutcome::AlreadyLocked);
    let StoreRead::Found(again) = rig.store.read(d.id) else { panic!() };
    assert_eq!(first.locked_at, again.locked_at);
}

#[test]
fn operacao_em_andamento_adia_sem_chamar_a_api() {
    let rig = Rig::new();
    let d = Rig::vol("D", "D:");
    rig.busy.set(d.id, &["devenv.exe", "Code.exe"]);
    let r = rig.orchestrator.lock(&d, LockTrigger::Inactivity);
    assert_eq!(r.outcome, LockOutcome::Postponed);
    assert!(r.detail.unwrap().contains("devenv.exe"));
    assert_eq!(rig.locker.volume(d.id).lock_calls, 0);
    rig.busy.clear(d.id);
}

#[test]
fn arquivo_aberto_detectado_pela_api_adia_sem_forcar() {
    let rig = Rig::new();
    let d = Rig::vol("D", "D:");
    rig.locker.with_volume(d.id, |v| v.open_handles = 2);
    assert_eq!(rig.orchestrator.lock(&d, LockTrigger::Inactivity).outcome, LockOutcome::Postponed);
    assert!(!rig.locked(&d));
    assert_eq!(rig.store.read(d.id), StoreRead::NotFound);
}

#[test]
fn bloqueio_aceito_mas_nao_efetivado_e_falha_e_falha_da_api_e_registrada() {
    let rig = Rig::new();
    let d = Rig::vol("D", "D:");
    rig.locker.with_volume(d.id, |v| v.ignore_lock = true);
    assert_eq!(rig.orchestrator.lock(&d, LockTrigger::Manual).outcome, LockOutcome::Failed);
    assert_eq!(rig.store.read(d.id), StoreRead::NotFound);
    let e = Rig::vol("E", "E:");
    rig.locker.with_volume(e.id, |v| v.fail_next_lock = true);
    assert_eq!(rig.orchestrator.lock(&e, LockTrigger::Manual).outcome, LockOutcome::Failed);
    assert!(rig.journal.entries().iter().any(|x| x.event == EventType::LockFailed && x.severity == Severity::Error));
}

#[test]
fn falha_ao_persistir_mantem_o_bloqueio_e_falha_fechada() {
    let rig = Rig::new();
    let d = Rig::vol("D", "D:");
    rig.store.fail_writes.store(true, std::sync::atomic::Ordering::Relaxed);
    assert_eq!(rig.orchestrator.lock(&d, LockTrigger::Manual).outcome, LockOutcome::Locked);
    assert!(rig.locked(&d));
    assert!(rig.journal.entries().iter().any(|e| e.event == EventType::StateStoreError));
    let req = rig.unlock.requirement(d.id, DAY);
    assert_eq!((req.factors, req.reason), (Factors::PrimaryAndTotp, Reason::LockStateMissing));
}

#[test]
fn varios_recursos_tem_resultado_individual() {
    let rig = Rig::new();
    let (d, e, c) = (Rig::vol("D", "D:"), Rig::vol("E", "E:"), Rig::vol("Sistema", "C:"));
    rig.locker.with_volume(e.id, |v| v.open_handles = 1);
    let outcomes: Vec<_> = rig.orchestrator.lock_many(&[d, e, c], LockTrigger::Manual).into_iter().map(|r| r.outcome).collect();
    assert_eq!(outcomes, [LockOutcome::Locked, LockOutcome::Postponed, LockOutcome::Refused]);
}

// ---------------- Desbloqueio ----------------

fn locked_rig(totp: Arc<dyn TotpVerifier>) -> (Rig, ProtectedResource) {
    let clock = Arc::new(TestClock::new());
    let boot = Arc::new(TestBoot::new(clock.clone()));
    let rig = Rig::with(clock, boot, Arc::default(), Arc::new(SimulatedLocker::new(ResourceKind::BitLockerVolume, Some("C:"), None)), Arc::default(), totp);
    let d = Rig::vol("Unidade D:", "D:");
    rig.orchestrator.lock(&d, LockTrigger::Manual);
    (rig, d)
}

#[test]
fn senha_correta_antes_de_24h_desbloqueia_e_apaga_registro() {
    let (rig, d) = locked_rig(Arc::new(NotEnrolled));
    rig.clock.advance(secs(23 * 3600 + 59 * 60));
    assert_eq!(rig.unlock.unlock(&d, rig.locker.as_ref(), DAY, TEST_PASSPHRASE, None).code, UnlockCode::Unlocked);
    assert!(!rig.locked(&d));
    assert_eq!(rig.store.read(d.id), StoreRead::NotFound);
}

#[test]
fn senha_incorreta_e_negada_sem_registrar_a_senha() {
    let (rig, d) = locked_rig(Arc::new(NotEnrolled));
    assert_eq!(rig.unlock.unlock(&d, rig.locker.as_ref(), DAY, "senha-errada-XYZ", None).code, UnlockCode::BadCredential);
    assert!(rig.locked(&d));
    assert!(rig.journal.entries().iter().any(|e| e.event == EventType::UnlockDenied));
    assert!(!rig.journal.entries().iter().any(|e| format!("{}{:?}", e.message, e.detail).contains("senha-errada-XYZ")));
}

#[test]
fn tentativas_repetidas_aumentam_a_espera() {
    let (rig, d) = locked_rig(Arc::new(NotEnrolled));
    for _ in 0..3 {
        rig.unlock.unlock(&d, rig.locker.as_ref(), DAY, "x", None);
    }
    let blocked = rig.unlock.unlock(&d, rig.locker.as_ref(), DAY, TEST_PASSPHRASE, None);
    assert_eq!(blocked.code, UnlockCode::Throttled);
    assert_eq!(blocked.retry_after_secs, Some(30));
    rig.clock.advance(secs(31));
    assert_eq!(rig.unlock.unlock(&d, rig.locker.as_ref(), DAY, TEST_PASSPHRASE, None).code, UnlockCode::Unlocked);
}

#[test]
fn apos_24h_sem_autenticador_o_desbloqueio_e_negado() {
    let (rig, d) = locked_rig(Arc::new(NotEnrolled));
    rig.clock.advance(DAY);
    assert_eq!(rig.unlock.unlock(&d, rig.locker.as_ref(), DAY, TEST_PASSPHRASE, None).code, UnlockCode::TotpNotEnrolled);
    assert!(rig.locked(&d));
}

#[test]
fn apos_24h_exige_totp_valido_e_nao_reutilizado() {
    let (rig, d) = locked_rig(Arc::new(FakeTotp(Mutex::default())));
    rig.clock.advance(secs(25 * 3600));
    let l = rig.locker.as_ref();
    assert_eq!(rig.unlock.unlock(&d, l, DAY, TEST_PASSPHRASE, None).code, UnlockCode::TotpRequired);
    assert_eq!(rig.unlock.unlock(&d, l, DAY, TEST_PASSPHRASE, Some("000000")).code, UnlockCode::TotpInvalid);
    assert_eq!(rig.unlock.unlock(&d, l, DAY, TEST_PASSPHRASE, Some("123456")).code, UnlockCode::Unlocked);
    rig.orchestrator.lock(&d, LockTrigger::Manual);
    rig.clock.advance(DAY);
    assert_eq!(rig.unlock.unlock(&d, l, DAY, TEST_PASSPHRASE, Some("123456")).code, UnlockCode::TotpInvalid);
    assert!(!rig.journal.entries().iter().any(|e| format!("{}{:?}", e.message, e.detail).contains("123456")));
}

#[test]
fn registro_adulterado_exige_totp() {
    let (rig, d) = locked_rig(Arc::new(NotEnrolled));
    rig.store.corrupt(d.id);
    let r = rig.unlock.requirement(d.id, DAY);
    assert_eq!((r.factors, r.reason), (Factors::PrimaryAndTotp, Reason::LockStateUnreadable));
}

// ---------------- Motor ----------------

#[test]
fn inatividade_de_1_minuto_bloqueia_apos_um_minuto_e_nao_antes() {
    let rig = Rig::new();
    let d = rig.add("D", "D:");
    rig.group("Discos", Some(1), InactivityMode::ResourceIdle, false, &[&d]);
    rig.run(secs(55));
    assert!(!rig.locked(&d));
    let results = rig.run(secs(5));
    assert!(rig.locked(&d));
    assert!(results.iter().any(|r| r.resource_id == d.id && r.outcome == LockOutcome::Locked));
    assert!(rig.has(EventType::Locked, "inatividade"));
}

#[test]
fn inatividade_de_5_minutos_com_atividade_reinicia_o_contador() {
    let rig = Rig::new();
    let d = rig.add("D", "D:");
    rig.group("Discos", Some(5), InactivityMode::ResourceIdle, false, &[&d]);
    rig.run(secs(240));
    rig.engine.record_activity(d.id);
    rig.run(secs(240));
    assert!(!rig.locked(&d));
    assert_eq!(rig.view(&d).next_lock_in_secs, Some(60));
    rig.run(secs(60));
    assert!(rig.locked(&d));
}

#[test]
fn grupos_com_politicas_diferentes_bloqueiam_cada_um_no_seu_tempo() {
    let rig = Rig::new();
    let cred = rig.add("Credenciais", "E:");
    let dev = rig.add("Desenvolvimento", "D:");
    rig.group("Credenciais", Some(1), InactivityMode::ResourceIdle, false, &[&cred]);
    rig.group("Desenvolvimento", Some(5), InactivityMode::ResourceIdle, false, &[&dev]);
    rig.run(secs(60));
    assert!(rig.locked(&cred) && !rig.locked(&dev));
    rig.run(secs(240));
    assert!(rig.locked(&dev));
}

#[test]
fn recurso_em_dois_grupos_bloqueia_no_menor_tempo() {
    let rig = Rig::new();
    let env = rig.add(".env", "E:");
    rig.group("Desenvolvimento", Some(30), InactivityMode::ResourceIdle, false, &[&env]);
    rig.group("Credenciais", Some(1), InactivityMode::ResourceIdle, false, &[&env]);
    rig.run(secs(60));
    assert!(rig.locked(&env));
}

#[test]
fn recurso_ocupado_e_adiado_notificado_e_bloqueado_quando_liberado() {
    let rig = Rig::new();
    let d = rig.add("D", "D:");
    rig.group("Discos", Some(1), InactivityMode::ResourceIdle, false, &[&d]);
    rig.locker.with_volume(d.id, |v| v.open_handles = 1);
    rig.run(secs(60));
    assert!(!rig.locked(&d) && rig.view(&d).pending_lock);
    assert!(rig.notified.lock().unwrap().iter().any(|e| e.event == EventType::LockPostponed));
    let calls = rig.locker.volume(d.id).lock_calls;
    rig.run(secs(20));
    assert_eq!(rig.locker.volume(d.id).lock_calls, calls, "não deve martelar a API antes do intervalo");
    rig.locker.with_volume(d.id, |v| v.open_handles = 0);
    rig.run(secs(15));
    assert!(rig.locked(&d) && !rig.view(&d).pending_lock);
}

#[test]
fn recurso_indisponivel_nao_impede_os_demais() {
    let rig = Rig::new();
    let usb = rig.add("USB", "F:");
    let d = rig.add("D", "D:");
    rig.group("Discos", Some(1), InactivityMode::ResourceIdle, false, &[&usb, &d]);
    rig.locker.with_volume(usb.id, |v| v.present = false);
    rig.run(secs(60));
    assert!(rig.locked(&d));
    assert_eq!(rig.view(&usb).state, LockState::Unavailable);
}

#[test]
fn bloqueio_do_windows_bloqueia_somente_os_grupos_que_pedem() {
    let rig = Rig::new();
    let cred = rig.add("Credenciais", "E:");
    let dev = rig.add("Desenvolvimento", "D:");
    rig.group("Credenciais", Some(60), InactivityMode::ResourceIdle, true, &[&cred]);
    rig.group("Desenvolvimento", Some(60), InactivityMode::ResourceIdle, false, &[&dev]);
    assert_eq!(rig.engine.on_workstation_locked().len(), 1);
    assert!(rig.locked(&cred) && !rig.locked(&dev));
}

#[test]
fn bloqueio_manual_do_grupo_informa_bloqueio_parcial() {
    let rig = Rig::new();
    let sys = rig.add("Sistema", "C:");
    let d = rig.add("D", "D:");
    let g = rig.group("Discos", None, InactivityMode::ResourceIdle, false, &[&sys, &d]);
    let r = rig.engine.lock_group(g.id).unwrap();
    assert_eq!(r.iter().find(|x| x.resource_id == sys.id).unwrap().outcome, LockOutcome::Refused);
    assert_eq!(r.iter().find(|x| x.resource_id == d.id).unwrap().outcome, LockOutcome::Locked);
}

#[test]
fn modo_sessao_bloqueia_quando_a_interface_para_de_relatar_atividade() {
    let rig = Rig::new();
    let d = rig.add("D", "D:");
    rig.group("Sessão", Some(5), InactivityMode::SessionIdle, false, &[&d]);
    rig.run(secs(600));
    assert!(!rig.locked(&d), "sem relato da sessão não há decisão por sessão");
    rig.engine.session().report(secs(10));
    rig.run(secs(240));
    assert!(!rig.locked(&d));
    rig.run(secs(60));
    assert!(rig.locked(&d));
}

#[test]
fn reinicio_do_servico_preserva_estado_e_contagem_de_24h() {
    let clock = Arc::new(TestClock::new());
    let boot = Arc::new(TestBoot::new(clock.clone()));
    let store: Arc<InMemoryStateStore> = Arc::default();
    let locker = Arc::new(SimulatedLocker::new(ResourceKind::BitLockerVolume, None, None));
    let config: Arc<InMemoryConfig> = Arc::default();
    let first = Rig::with(clock.clone(), boot.clone(), store.clone(), locker.clone(), config.clone(), Arc::new(NotEnrolled));
    let d = first.add("D", "D:");
    first.engine.lock_all();
    drop(first);
    clock.advance(secs(10 * 3600));
    let second = Rig::with(clock.clone(), boot, store, locker, config.clone(), Arc::new(NotEnrolled));
    assert_eq!(second.view(&d).state, LockState::Locked);
    assert_eq!(second.engine.unlock_requirement(d.id).unwrap().factors, Factors::Primary);
    clock.advance(secs(14 * 3600));
    assert_eq!(second.engine.unlock_requirement(d.id).unwrap().factors, Factors::PrimaryAndTotp);
    assert_eq!(config.resources().unwrap().len(), 1);
}

#[test]
fn reinicio_do_windows_mantem_a_contagem_pelo_relogio_de_parede() {
    let rig = Rig::new();
    let d = rig.add("D", "D:");
    rig.engine.lock_all();
    rig.clock.advance(secs(23 * 3600));
    rig.boot.reboot("boot-2");
    assert_eq!(rig.engine.unlock_requirement(d.id).unwrap().factors, Factors::Primary);
    rig.clock.advance(secs(3600));
    assert_eq!(rig.engine.unlock_requirement(d.id).unwrap().factors, Factors::PrimaryAndTotp);
}

#[test]
fn relogio_voltando_no_tempo_e_registrado_e_passa_a_exigir_totp() {
    let rig = Rig::new();
    let d = rig.add("D", "D:");
    rig.run(secs(60));
    rig.engine.lock_all();
    rig.boot.reboot("boot-2");
    rig.clock.set_wall(rig.clock.now_utc() - 2 * 86_400_000);
    rig.run(secs(5));
    assert!(rig.journal.entries().iter().any(|e| e.event == EventType::ClockAnomaly));
    let req = rig.engine.unlock_requirement(d.id).unwrap();
    assert_eq!((req.factors, req.reason), (Factors::PrimaryAndTotp, Reason::ClockRollbackDetected));
}

#[test]
fn desbloqueio_externo_e_detectado_e_reinicia_o_contador() {
    let rig = Rig::new();
    let d = rig.add("D", "D:");
    rig.group("Discos", Some(5), InactivityMode::ResourceIdle, false, &[&d]);
    rig.engine.lock_all();
    rig.locker.with_volume(d.id, |v| v.locked = false);
    rig.run(secs(5));
    assert!(rig.has(EventType::Warning, "fora do ByteHalt"));
    assert_eq!(rig.store.read(d.id), StoreRead::NotFound);
    assert_eq!(rig.view(&d).state, LockState::Unlocked);
}

#[test]
fn desbloqueio_pelo_bytehalt_reinicia_o_contador() {
    let rig = Rig::new();
    let d = rig.add("D", "D:");
    rig.group("Discos", Some(1), InactivityMode::ResourceIdle, false, &[&d]);
    rig.run(secs(60));
    assert!(rig.locked(&d));
    assert_eq!(rig.engine.unlock(d.id, TEST_PASSPHRASE, None).unwrap().code, UnlockCode::Unlocked);
    assert!(!rig.has(EventType::Warning, "fora do ByteHalt"));
    rig.run(secs(55));
    assert!(!rig.locked(&d));
    rig.run(secs(5));
    assert!(rig.locked(&d));
}

#[test]
fn mudanca_de_temporizador_reinicia_a_contagem_e_renomear_nao() {
    let rig = Rig::new();
    let d = rig.add("D", "D:");
    rig.run(secs(600));
    let g = rig.group("Discos", Some(1), InactivityMode::ResourceIdle, false, &[&d]);
    rig.run(secs(30));
    assert!(!rig.locked(&d), "não bloqueia com a ociosidade acumulada antes da política");
    assert!(rig.engine.save_group(ProtectionGroup { name: "Discos externos".into(), ..g }).unwrap().success);
    rig.run(secs(30));
    assert!(rig.locked(&d), "renomear não recomeçou a contagem");
}

#[test]
fn cadastro_rejeita_duplicado_e_grupo_invalido() {
    let rig = Rig::new();
    rig.add("D", "D:");
    assert!(!rig.engine.save_resource(Rig::vol("D de novo", "D:")).unwrap().success);
    let bad = ProtectionGroup {
        id: Uuid::new_v4(),
        name: "".into(),
        resource_ids: vec![Uuid::new_v4()],
        inactivity_secs: Some(5),
        mode: InactivityMode::ResourceIdle,
        totp_threshold_secs: 86_400,
        lock_on_workstation_lock: false,
    };
    let r = rig.engine.save_group(bad).unwrap();
    assert!(!r.success && r.errors.len() >= 3, "{:?}", r.errors);
}

#[test]
fn remover_recurso_tira_do_grupo_e_do_monitoramento() {
    let rig = Rig::new();
    let d = rig.add("D", "D:");
    let g = rig.group("Discos", Some(1), InactivityMode::ResourceIdle, false, &[&d]);
    assert!(rig.engine.delete_resource(d.id).unwrap().success);
    rig.run(secs(120));
    assert!(!rig.locked(&d));
    assert!(rig.engine.snapshot().groups.iter().find(|x| x.id == g.id).unwrap().resource_ids.is_empty());
}
