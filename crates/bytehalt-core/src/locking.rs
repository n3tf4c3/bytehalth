//! Roteiro seguro de bloqueio (especificação §5): verifica o estado, identifica operações em
//! andamento, tenta bloqueio normal sem forçar desmontagem, adia se ocupado e registra o resultado
//! REAL, conferindo o estado depois da operação. Cada recurso tem resultado próprio.

use crate::auth::{LockRecord, LockStateStore};
use crate::clock::{BootSession, Clock};
use crate::journal::{EventType, Journal, JournalEntry, Severity, append_or_log};
use crate::model::{ProtectedResource, ResourceKind};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum LockState {
    Unknown,
    Unlocked,
    Locked,
    /// Volume existe mas sem BitLocker ativo: não há o que bloquear.
    NotProtected,
    /// Ausente (desconectado, letra trocada) ou sem permissão de consulta.
    Unavailable,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResourceStatus {
    pub state: LockState,
    pub is_system_volume: bool,
    pub auto_unlock: bool,
    pub detail: Option<String>,
}

impl ResourceStatus {
    pub fn unavailable(detail: impl Into<String>) -> Self {
        Self { state: LockState::Unavailable, is_system_volume: false, auto_unlock: false, detail: Some(detail.into()) }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum LockOutcome {
    Locked,
    AlreadyLocked,
    /// Em uso; adiado e tentado de novo.
    Postponed,
    /// Recusado por segurança (unidade do sistema, sem BitLocker, tipo não suportado).
    Refused,
    Unavailable,
    Failed,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LockAttempt {
    pub outcome: LockOutcome,
    pub detail: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnlockOutcome {
    Unlocked,
    AlreadyUnlocked,
    BadCredential,
    Unavailable,
    Failed,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnlockAttempt {
    pub outcome: UnlockOutcome,
    pub detail: Option<String>,
}

/// Operações de baixo nível de um tipo de recurso. Nunca forçam desmontagem: volume em uso deve
/// resultar em [`LockOutcome::Postponed`]. A senha nunca vai para logs ou mensagens.
pub trait ResourceLocker: Send + Sync {
    fn kind(&self) -> ResourceKind;
    fn status(&self, resource: &ProtectedResource) -> ResourceStatus;
    fn lock(&self, resource: &ProtectedResource) -> LockAttempt;
    fn unlock(&self, resource: &ProtectedResource, passphrase: &str) -> UnlockAttempt;
}

/// Sonda de operações em andamento (Restart Manager/handles na Fase 4). Retorna nomes de processos.
pub trait BusyProbe: Send + Sync {
    fn holders(&self, resource: &ProtectedResource) -> Option<Vec<String>>;
}

pub struct NoBusyProbe;

impl BusyProbe for NoBusyProbe {
    fn holders(&self, _: &ProtectedResource) -> Option<Vec<String>> {
        None
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum LockTrigger {
    Manual,
    Inactivity,
    WorkstationLock,
    Retry,
    /// Windows suspendendo ou hibernando.
    Suspend,
}

impl LockTrigger {
    fn text(self) -> &'static str {
        match self {
            Self::Manual => "manual",
            Self::Inactivity => "inatividade",
            Self::WorkstationLock => "Windows bloqueado",
            Self::Retry => "nova tentativa",
            Self::Suspend => "suspensão do Windows",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LockResult {
    pub resource_id: Uuid,
    pub display_name: String,
    pub outcome: LockOutcome,
    pub detail: Option<String>,
}

pub type Notifier = Arc<dyn Fn(&JournalEntry) + Send + Sync>;

pub struct LockOrchestrator {
    lockers: Vec<Arc<dyn ResourceLocker>>,
    busy: Arc<dyn BusyProbe>,
    store: Arc<dyn LockStateStore>,
    journal: Arc<dyn Journal>,
    clock: Arc<dyn Clock>,
    boot: Arc<dyn BootSession>,
    notifier: Option<Notifier>,
}

impl LockOrchestrator {
    pub fn new(
        lockers: Vec<Arc<dyn ResourceLocker>>,
        busy: Arc<dyn BusyProbe>,
        store: Arc<dyn LockStateStore>,
        journal: Arc<dyn Journal>,
        clock: Arc<dyn Clock>,
        boot: Arc<dyn BootSession>,
        notifier: Option<Notifier>,
    ) -> Self {
        Self { lockers, busy, store, journal, clock, boot, notifier }
    }

    pub fn locker(&self, kind: ResourceKind) -> Option<&Arc<dyn ResourceLocker>> {
        self.lockers.iter().find(|l| l.kind() == kind)
    }

    pub fn lock_many(&self, resources: &[ProtectedResource], trigger: LockTrigger) -> Vec<LockResult> {
        resources.iter().map(|r| self.lock(r, trigger)).collect()
    }

    pub fn lock(&self, resource: &ProtectedResource, trigger: LockTrigger) -> LockResult {
        let (outcome, detail) = self.lock_core(resource);
        let result = LockResult { resource_id: resource.id, display_name: resource.display_name.clone(), outcome, detail };
        self.record(resource, trigger, &result);
        result
    }

    fn lock_core(&self, r: &ProtectedResource) -> (LockOutcome, Option<String>) {
        let Some(locker) = self.locker(r.kind) else {
            return (LockOutcome::Refused, Some("Tipo de recurso ainda não suportado.".into()));
        };
        // 1. Estado atual.
        let status = locker.status(r);
        if status.is_system_volume {
            return (LockOutcome::Refused, Some("A unidade do sistema em execução não pode ser bloqueada.".into()));
        }
        match status.state {
            LockState::Locked => return (LockOutcome::AlreadyLocked, None),
            LockState::Unavailable | LockState::Unknown => {
                return (LockOutcome::Unavailable, Some(status.detail.unwrap_or_else(|| "Recurso indisponível.".into())));
            }
            LockState::NotProtected => return (LockOutcome::Refused, Some("O volume não está protegido pelo BitLocker.".into())),
            LockState::Unlocked => {}
        }
        // 2-3. Operações em andamento: não interromper gravações.
        if let Some(holders) = self.busy.holders(r) {
            let who = if holders.is_empty() { "processo não identificado".to_owned() } else { holders.iter().take(5).cloned().collect::<Vec<_>>().join(", ") };
            return (LockOutcome::Postponed, Some(format!("Em uso por: {who}.")));
        }
        // 4-5. Bloqueio normal, sem forçar desmontagem.
        let attempt = locker.lock(r);
        if attempt.outcome != LockOutcome::Locked {
            return (attempt.outcome, attempt.detail);
        }
        // 6. Resultado real: conferir depois da operação.
        if locker.status(r).state != LockState::Locked {
            return (LockOutcome::Failed, Some("O bloqueio foi aceito, mas o volume continua desbloqueado.".into()));
        }
        (LockOutcome::Locked, None)
    }

    fn record(&self, r: &ProtectedResource, trigger: LockTrigger, result: &LockResult) {
        let now = self.clock.now_utc();
        if result.outcome == LockOutcome::Locked {
            let record =
                LockRecord { resource_id: r.id, locked_at: now, boot_id: self.boot.boot_id(), uptime_at_lock_ms: self.boot.uptime().as_millis() as u64 };
            if let Err(e) = self.store.write(&record) {
                // Falha fechada: sem registro, o desbloqueio exigirá TOTP.
                eprintln!("Falha ao gravar estado de bloqueio: {e:#}");
                append_or_log(
                    self.journal.as_ref(),
                    JournalEntry {
                        at: now,
                        event: EventType::StateStoreError,
                        severity: Severity::Error,
                        resource_id: Some(r.id),
                        message: format!("Não foi possível gravar o instante de bloqueio de {}; o desbloqueio exigirá TOTP.", r.display_name),
                        detail: Some(format!("{e:#}")),
                    },
                );
            }
        }
        let (event, severity, verb) = match result.outcome {
            LockOutcome::Locked => (EventType::Locked, Severity::Info, "bloqueado"),
            LockOutcome::AlreadyLocked => (EventType::Locked, Severity::Info, "já estava bloqueado"),
            LockOutcome::Postponed => (EventType::LockPostponed, Severity::Warning, "em uso; bloqueio adiado"),
            LockOutcome::Refused => (EventType::LockRefused, Severity::Warning, "bloqueio recusado"),
            LockOutcome::Unavailable => (EventType::LockFailed, Severity::Warning, "indisponível"),
            LockOutcome::Failed => (EventType::LockFailed, Severity::Error, "falha no bloqueio"),
        };
        let entry = JournalEntry {
            at: now,
            event,
            severity,
            resource_id: Some(r.id),
            message: format!("{} — {verb} ({}).", r.display_name, trigger.text()),
            detail: result.detail.clone(),
        };
        append_or_log(self.journal.as_ref(), entry.clone());
        if result.outcome != LockOutcome::AlreadyLocked
            && let Some(n) = &self.notifier
        {
            n(&entry);
        }
    }
}
