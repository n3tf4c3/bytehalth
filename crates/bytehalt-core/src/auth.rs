//! Regra de 24 horas e desbloqueio (docs/ARCHITECTURE.md §5). Sempre falha fechada: na dúvida
//! sobre a passagem do tempo ou sobre o estado persistido, exige primária + TOTP.

use crate::clock::{BootSession, Clock, UtcMillis};
use crate::journal::{EventType, Journal, JournalEntry, Severity, append_or_log};
use crate::locking::{LockState, ResourceLocker, UnlockOutcome};
use crate::model::ProtectedResource;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use uuid::Uuid;

/// Registro persistido (protegido) do bloqueio efetivo.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LockRecord {
    pub resource_id: Uuid,
    pub locked_at: UtcMillis,
    pub boot_id: String,
    pub uptime_at_lock_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StoreRead<T> {
    Found(T),
    NotFound,
    /// Ilegível ou adulterado (falha de integridade/descriptografia).
    Corrupted,
    /// Falha de E/S ou permissão.
    Error,
}

/// Persistência protegida do estado de bloqueio (DPAPI no Windows).
pub trait LockStateStore: Send + Sync {
    fn read(&self, id: Uuid) -> StoreRead<LockRecord>;
    fn write(&self, record: &LockRecord) -> anyhow::Result<()>;
    fn delete(&self, id: Uuid) -> anyhow::Result<()>;
    /// Maior horário UTC já observado (nunca diminui).
    fn read_watermark(&self) -> StoreRead<UtcMillis>;
    fn write_watermark(&self, value: UtcMillis) -> anyhow::Result<()>;
}

/// Registros, marca d'água e recursos marcados como corrompidos.
type MemoryState = (HashMap<Uuid, LockRecord>, Option<UtcMillis>, Vec<Uuid>);

#[derive(Default)]
pub struct InMemoryStateStore {
    state: Mutex<MemoryState>,
    pub fail_writes: std::sync::atomic::AtomicBool,
}

impl InMemoryStateStore {
    pub fn corrupt(&self, id: Uuid) {
        self.state.lock().unwrap_or_else(|e| e.into_inner()).2.push(id);
    }
}

impl LockStateStore for InMemoryStateStore {
    fn read(&self, id: Uuid) -> StoreRead<LockRecord> {
        let s = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if s.2.contains(&id) {
            return StoreRead::Corrupted;
        }
        s.0.get(&id).cloned().map_or(StoreRead::NotFound, StoreRead::Found)
    }

    fn write(&self, record: &LockRecord) -> anyhow::Result<()> {
        anyhow::ensure!(!self.fail_writes.load(std::sync::atomic::Ordering::Relaxed), "falha simulada de persistência");
        let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
        s.2.retain(|x| *x != record.resource_id);
        s.0.insert(record.resource_id, record.clone());
        Ok(())
    }

    fn delete(&self, id: Uuid) -> anyhow::Result<()> {
        let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
        s.0.remove(&id);
        s.2.retain(|x| *x != id);
        Ok(())
    }

    fn read_watermark(&self) -> StoreRead<UtcMillis> {
        self.state.lock().unwrap_or_else(|e| e.into_inner()).1.map_or(StoreRead::NotFound, StoreRead::Found)
    }

    fn write_watermark(&self, value: UtcMillis) -> anyhow::Result<()> {
        anyhow::ensure!(!self.fail_writes.load(std::sync::atomic::Ordering::Relaxed), "falha simulada de persistência");
        self.state.lock().unwrap_or_else(|e| e.into_inner()).1 = Some(value);
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Factors {
    Primary,
    PrimaryAndTotp,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Reason {
    WithinThreshold,
    ThresholdReached,
    /// Relógio voltou para antes do bloqueio ou da marca d'água.
    ClockRollbackDetected,
    /// Mesma sessão de boot: o tempo monotônico passou mais que o relógio de parede.
    ClockMismatchDetected,
    LockStateMissing,
    LockStateUnreadable,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Requirement {
    pub factors: Factors,
    pub reason: Reason,
    pub elapsed_secs: Option<u64>,
}

impl Requirement {
    pub fn requires_totp(&self) -> bool {
        self.factors == Factors::PrimaryAndTotp
    }

    fn totp(reason: Reason, elapsed: Option<Duration>) -> Self {
        Self { factors: Factors::PrimaryAndTotp, reason, elapsed_secs: elapsed.map(|d| d.as_secs()) }
    }
}

/// Diferença tolerada entre parede e monotônico (pequenos ajustes de NTP).
pub const CLOCK_TOLERANCE: Duration = Duration::from_secs(300);

pub fn evaluate(
    record: &StoreRead<LockRecord>,
    watermark: &StoreRead<UtcMillis>,
    now: UtcMillis,
    boot_id: &str,
    uptime: Duration,
    threshold: Duration,
) -> Requirement {
    let r = match record {
        StoreRead::Found(r) => r,
        StoreRead::NotFound => return Requirement::totp(Reason::LockStateMissing, None),
        StoreRead::Corrupted | StoreRead::Error => return Requirement::totp(Reason::LockStateUnreadable, None),
    };
    let tol = CLOCK_TOLERANCE.as_millis() as i64;
    let wall_elapsed_ms = now - r.locked_at;
    if wall_elapsed_ms < -tol {
        return Requirement::totp(Reason::ClockRollbackDetected, None);
    }
    // Marca d'água ilegível não prova nada; só uma marca válida maior que "agora" acusa recuo.
    if let StoreRead::Found(mark) = watermark
        && now < mark - tol
    {
        return Requirement::totp(Reason::ClockRollbackDetected, None);
    }
    let elapsed = Duration::from_millis(wall_elapsed_ms.max(0) as u64);
    if r.boot_id == boot_id {
        let at_lock = Duration::from_millis(r.uptime_at_lock_ms);
        match uptime.checked_sub(at_lock) {
            // O relógio de parede andou menos que o tempo real: alguém o atrasou.
            Some(mono) if mono > elapsed + CLOCK_TOLERANCE => return Requirement::totp(Reason::ClockMismatchDetected, Some(mono)),
            None => return Requirement::totp(Reason::ClockMismatchDetected, None),
            _ => {}
        }
    }
    if elapsed >= threshold {
        Requirement::totp(Reason::ThresholdReached, Some(elapsed))
    } else {
        Requirement { factors: Factors::Primary, reason: Reason::WithinThreshold, elapsed_secs: Some(elapsed.as_secs()) }
    }
}

/// Segundo fator (RFC 6238 na Fase 3). Deve impedir reutilização dentro da janela aceita.
pub trait TotpVerifier: Send + Sync {
    fn enrolled(&self) -> bool;
    fn verify(&self, code: &str) -> bool;
}

/// Fase 1: nenhum autenticador cadastrado.
pub struct NotEnrolled;

impl TotpVerifier for NotEnrolled {
    fn enrolled(&self) -> bool {
        false
    }

    fn verify(&self, _: &str) -> bool {
        false
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum UnlockCode {
    Unlocked,
    AlreadyUnlocked,
    BadCredential,
    TotpRequired,
    TotpInvalid,
    TotpNotEnrolled,
    Throttled,
    Unavailable,
    Failed,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnlockResult {
    pub code: UnlockCode,
    pub requirement: Requirement,
    pub message: String,
    pub retry_after_secs: Option<u64>,
}

pub const FREE_ATTEMPTS: u32 = 3;
pub const MAX_BACKOFF: Duration = Duration::from_secs(15 * 60);

/// Aplica a regra de 24 h antes de repassar a credencial ao locker; limite progressivo de tentativas.
pub struct UnlockCoordinator {
    store: Arc<dyn LockStateStore>,
    totp: Arc<dyn TotpVerifier>,
    journal: Arc<dyn Journal>,
    clock: Arc<dyn Clock>,
    boot: Arc<dyn BootSession>,
    failures: Mutex<HashMap<Uuid, (u32, Option<Duration>)>>,
}

impl UnlockCoordinator {
    pub fn new(
        store: Arc<dyn LockStateStore>,
        totp: Arc<dyn TotpVerifier>,
        journal: Arc<dyn Journal>,
        clock: Arc<dyn Clock>,
        boot: Arc<dyn BootSession>,
    ) -> Self {
        Self { store, totp, journal, clock, boot, failures: Mutex::new(HashMap::new()) }
    }

    pub fn requirement(&self, id: Uuid, threshold: Duration) -> Requirement {
        evaluate(&self.store.read(id), &self.store.read_watermark(), self.clock.now_utc(), &self.boot.boot_id(), self.boot.uptime(), threshold)
    }

    pub fn unlock(&self, r: &ProtectedResource, locker: &dyn ResourceLocker, threshold: Duration, passphrase: &str, totp_code: Option<&str>) -> UnlockResult {
        let requirement = self.requirement(r.id, threshold);
        let result = |code, message: &str, retry: Option<Duration>| UnlockResult {
            code,
            requirement: requirement.clone(),
            message: message.into(),
            retry_after_secs: retry.map(|d| d.as_secs().max(1)),
        };
        if let Some(wait) = self.remaining_block(r.id) {
            return result(UnlockCode::Throttled, "Muitas tentativas. Aguarde antes de tentar de novo.", Some(wait));
        }
        let status = locker.status(r);
        match status.state {
            LockState::Unlocked => return result(UnlockCode::AlreadyUnlocked, "O recurso já está desbloqueado.", None),
            LockState::Locked => {}
            _ => return result(UnlockCode::Unavailable, status.detail.as_deref().unwrap_or("Recurso indisponível."), None),
        }
        if requirement.requires_totp() {
            if !self.totp.enrolled() {
                self.denied(r, "TOTP exigido, mas nenhum autenticador está cadastrado.");
                return result(
                    UnlockCode::TotpNotEnrolled,
                    "Este desbloqueio exige TOTP, mas nenhum autenticador está cadastrado. Use o guia de recuperação.",
                    None,
                );
            }
            if totp_code.is_none_or(|c| c.trim().is_empty()) {
                return result(UnlockCode::TotpRequired, "Informe o código do aplicativo autenticador.", None);
            }
        }
        if passphrase.is_empty() {
            return result(UnlockCode::BadCredential, "Informe a senha.", None);
        }
        if requirement.requires_totp() && !self.totp.verify(totp_code.unwrap_or_default().trim()) {
            self.register_failure(r.id);
            self.denied(r, "Código TOTP inválido.");
            return result(UnlockCode::TotpInvalid, "Código inválido ou já utilizado.", self.remaining_block(r.id));
        }
        let attempt = locker.unlock(r, passphrase);
        match attempt.outcome {
            UnlockOutcome::Unlocked | UnlockOutcome::AlreadyUnlocked => {
                self.failures.lock().unwrap_or_else(|e| e.into_inner()).remove(&r.id);
                // Registro antigo sobrando só torna o próximo desbloqueio mais restritivo.
                let _ = self.store.delete(r.id);
                append_or_log(
                    self.journal.as_ref(),
                    JournalEntry {
                        at: self.clock.now_utc(),
                        event: EventType::Unlocked,
                        severity: Severity::Info,
                        resource_id: Some(r.id),
                        message: format!("{} — desbloqueado ({}).", r.display_name, if requirement.requires_totp() { "senha + TOTP" } else { "senha" }),
                        detail: Some(format!("Motivo da política: {:?}.", requirement.reason)),
                    },
                );
                result(UnlockCode::Unlocked, "Desbloqueado.", None)
            }
            UnlockOutcome::BadCredential => {
                self.register_failure(r.id);
                self.denied(r, "Credencial primária incorreta.");
                result(UnlockCode::BadCredential, "Senha incorreta.", self.remaining_block(r.id))
            }
            UnlockOutcome::Unavailable => result(UnlockCode::Unavailable, attempt.detail.as_deref().unwrap_or("Recurso indisponível."), None),
            UnlockOutcome::Failed => {
                let why = attempt.detail.unwrap_or_else(|| "Falha no desbloqueio.".into());
                self.denied(r, &why);
                result(UnlockCode::Failed, &why, None)
            }
        }
    }

    pub fn remaining_block(&self, id: Uuid) -> Option<Duration> {
        let now = self.clock.monotonic();
        let f = self.failures.lock().unwrap_or_else(|e| e.into_inner());
        f.get(&id).and_then(|(_, until)| *until).and_then(|until| until.checked_sub(now)).filter(|d| !d.is_zero())
    }

    fn register_failure(&self, id: Uuid) {
        let now = self.clock.monotonic();
        let mut f = self.failures.lock().unwrap_or_else(|e| e.into_inner());
        let entry = f.entry(id).or_insert((0, None));
        entry.0 += 1;
        if entry.0 >= FREE_ATTEMPTS {
            // 30 s, 60 s, 120 s… até 15 min.
            let secs = 30u64.saturating_mul(1 << (entry.0 - FREE_ATTEMPTS).min(10));
            entry.1 = Some(now + Duration::from_secs(secs).min(MAX_BACKOFF));
        }
    }

    fn denied(&self, r: &ProtectedResource, why: &str) {
        append_or_log(
            self.journal.as_ref(),
            JournalEntry {
                at: self.clock.now_utc(),
                event: EventType::UnlockDenied,
                severity: Severity::Warning,
                resource_id: Some(r.id),
                message: format!("{} — desbloqueio negado.", r.display_name),
                detail: Some(why.into()),
            },
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOCKED: UtcMillis = 1_793_520_000_000;
    const DAY: Duration = Duration::from_secs(86_400);
    const UP: u64 = 2 * 3_600_000;

    fn rec(boot: &str) -> StoreRead<LockRecord> {
        StoreRead::Found(LockRecord { resource_id: Uuid::new_v4(), locked_at: LOCKED, boot_id: boot.into(), uptime_at_lock_ms: UP })
    }

    fn after(elapsed_min: i64, boot: &str, mono_min: Option<i64>, mark: StoreRead<UtcMillis>) -> Requirement {
        let mono = mono_min.unwrap_or(elapsed_min).max(0) as u64;
        evaluate(&rec("boot-A"), &mark, LOCKED + elapsed_min * 60_000, boot, Duration::from_millis(UP + mono * 60_000), DAY)
    }

    #[test]
    fn bloqueado_ha_23h59_exige_somente_primaria() {
        let r = after(23 * 60 + 59, "boot-B", None, StoreRead::NotFound);
        assert_eq!((r.factors, r.reason), (Factors::Primary, Reason::WithinThreshold));
    }

    #[test]
    fn bloqueado_ha_24h00_exige_primaria_e_totp() {
        let r = after(24 * 60, "boot-B", None, StoreRead::NotFound);
        assert_eq!((r.factors, r.reason), (Factors::PrimaryAndTotp, Reason::ThresholdReached));
    }

    #[test]
    fn bloqueado_ha_25h_exige_primaria_e_totp() {
        assert!(after(25 * 60, "boot-B", None, StoreRead::NotFound).requires_totp());
    }

    #[test]
    fn mesma_sessao_com_relogio_coerente_usa_o_tempo_decorrido() {
        assert_eq!(after(23 * 60, "boot-A", None, StoreRead::NotFound).factors, Factors::Primary);
    }

    #[test]
    fn relogio_atrasado_na_mesma_sessao_e_detectado_pelo_monotonico() {
        let r = after(2 * 60, "boot-A", Some(30 * 60), StoreRead::NotFound);
        assert_eq!((r.factors, r.reason), (Factors::PrimaryAndTotp, Reason::ClockMismatchDetected));
    }

    #[test]
    fn pequeno_ajuste_de_relogio_dentro_da_tolerancia_e_aceito() {
        assert_eq!(after(60, "boot-A", Some(62), StoreRead::NotFound).factors, Factors::Primary);
    }

    #[test]
    fn relogio_antes_do_bloqueio_exige_totp() {
        let r = after(-180, "boot-B", Some(0), StoreRead::NotFound);
        assert_eq!(r.reason, Reason::ClockRollbackDetected);
    }

    #[test]
    fn relogio_antes_da_marca_dagua_exige_totp_mesmo_apos_reinicio() {
        let r = after(60, "boot-B", None, StoreRead::Found(LOCKED + 2 * 86_400_000));
        assert_eq!((r.factors, r.reason), (Factors::PrimaryAndTotp, Reason::ClockRollbackDetected));
    }

    #[test]
    fn marca_dagua_ilegivel_nao_bloqueia_sozinha() {
        assert_eq!(after(60, "boot-B", None, StoreRead::Corrupted).factors, Factors::Primary);
    }

    #[test]
    fn falha_no_estado_persistido_exige_totp() {
        for (s, reason) in [
            (StoreRead::NotFound, Reason::LockStateMissing),
            (StoreRead::Corrupted, Reason::LockStateUnreadable),
            (StoreRead::Error, Reason::LockStateUnreadable),
        ] {
            let r = evaluate(&s, &StoreRead::NotFound, LOCKED, "boot-A", Duration::from_millis(UP), DAY);
            assert_eq!((r.factors, r.reason), (Factors::PrimaryAndTotp, reason));
        }
    }

    #[test]
    fn limiar_configuravel() {
        let r = evaluate(&rec("boot-A"), &StoreRead::NotFound, LOCKED + 2 * 3_600_000, "boot-B", Duration::ZERO, Duration::from_secs(3600));
        assert!(r.requires_totp());
    }
}
