//! Coração do serviço: mantém recursos e grupos, avalia inatividade a cada ciclo, bloqueia o que
//! venceu, reprograma bloqueios adiados e atualiza a marca d'água do relógio. Operações serializadas.

use crate::auth::{CLOCK_TOLERANCE, LockStateStore, Requirement, StoreRead, UnlockCode, UnlockCoordinator, UnlockResult};
use crate::clock::{Clock, UtcMillis};
use crate::inactivity::{InactivityTracker, ReportedSessionIdle, evaluate};
use crate::journal::{EventType, Journal, JournalEntry, Severity, append_or_log};
use crate::locking::{LockOrchestrator, LockOutcome, LockResult, LockState, LockTrigger};
use crate::model::{ConfigRepository, ProtectedResource, ProtectionGroup, ResourceKind};
use crate::policy::{EffectivePolicy, resolve};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;
use uuid::Uuid;

pub const FIRST_RETRY: Duration = Duration::from_secs(30);
pub const MAX_RETRY: Duration = Duration::from_secs(300);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourceView {
    pub resource: ProtectedResource,
    pub state: LockState,
    pub auto_unlock: bool,
    pub is_system_volume: bool,
    pub policy: EffectivePolicy,
    pub next_lock_in_secs: Option<u64>,
    pub pending_lock: bool,
    pub last_outcome: Option<LockOutcome>,
    pub last_detail: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Snapshot {
    pub taken_at: UtcMillis,
    pub resources: Vec<ResourceView>,
    pub groups: Vec<ProtectionGroup>,
    pub session_idle_secs: Option<u64>,
    pub simulated: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OperationResult {
    pub success: bool,
    pub errors: Vec<String>,
}

impl OperationResult {
    pub fn ok() -> Self {
        Self { success: true, errors: vec![] }
    }

    pub fn fail(errors: Vec<String>) -> Self {
        Self { success: false, errors }
    }
}

struct Runtime {
    state: LockState,
    auto_unlock: bool,
    system: bool,
    pending: bool,
    retry_at: Duration,
    retry_delay: Duration,
    last_outcome: Option<LockOutcome>,
    last_detail: Option<String>,
}

impl Default for Runtime {
    fn default() -> Self {
        Self {
            state: LockState::Unknown,
            auto_unlock: false,
            system: false,
            pending: false,
            retry_at: Duration::ZERO,
            retry_delay: Duration::ZERO,
            last_outcome: None,
            last_detail: None,
        }
    }
}

#[derive(Default)]
struct Inner {
    resources: Vec<ProtectedResource>,
    groups: Vec<ProtectionGroup>,
    policies: HashMap<Uuid, EffectivePolicy>,
    runtime: HashMap<Uuid, Runtime>,
    clock_anomaly_reported: bool,
}

pub struct Engine {
    config: Arc<dyn ConfigRepository>,
    orchestrator: LockOrchestrator,
    unlock: UnlockCoordinator,
    tracker: InactivityTracker,
    session: Arc<ReportedSessionIdle>,
    store: Arc<dyn LockStateStore>,
    journal: Arc<dyn Journal>,
    clock: Arc<dyn Clock>,
    simulated: bool,
    inner: Mutex<Inner>,
}

impl Engine {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        config: Arc<dyn ConfigRepository>,
        orchestrator: LockOrchestrator,
        unlock: UnlockCoordinator,
        session: Arc<ReportedSessionIdle>,
        store: Arc<dyn LockStateStore>,
        journal: Arc<dyn Journal>,
        clock: Arc<dyn Clock>,
        simulated: bool,
    ) -> Self {
        Self {
            tracker: InactivityTracker::new(clock.clone()),
            config,
            orchestrator,
            unlock,
            session,
            store,
            journal,
            clock,
            simulated,
            inner: Mutex::new(Inner::default()),
        }
    }

    pub fn simulated(&self) -> bool {
        self.simulated
    }

    pub fn session(&self) -> &ReportedSessionIdle {
        &self.session
    }

    fn lock_inner(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn reload(&self) -> anyhow::Result<()> {
        let mut inner = self.lock_inner();
        self.reload_core(&mut inner)
    }

    /// Um ciclo do monitor, chamado periodicamente pelo serviço.
    pub fn tick(&self) -> Vec<LockResult> {
        let mut inner = self.lock_inner();
        self.update_watermark(&mut inner);
        let session_idle = self.session.current();
        let now = self.clock.monotonic();
        let mut results = Vec::new();
        for r in inner.resources.clone() {
            self.refresh(&mut inner, &r);
            let policy = inner.policies.get(&r.id).cloned().unwrap_or_else(EffectivePolicy::ungrouped);
            let rt = inner.runtime.entry(r.id).or_default();
            if rt.state != LockState::Unlocked {
                rt.pending = false;
                continue;
            }
            let trigger = if rt.pending {
                (now >= rt.retry_at).then_some(LockTrigger::Retry)
            } else {
                evaluate(&policy, self.tracker.idle(r.id), session_idle).due.then_some(LockTrigger::Inactivity)
            };
            if let Some(t) = trigger {
                results.push(self.lock_one(&mut inner, &r, t));
            }
        }
        results
    }

    pub fn lock_resources(&self, ids: &[Uuid], trigger: LockTrigger) -> Vec<LockResult> {
        let mut inner = self.lock_inner();
        let targets: Vec<ProtectedResource> = inner.resources.iter().filter(|r| ids.contains(&r.id)).cloned().collect();
        targets.iter().map(|r| self.lock_one(&mut inner, r, trigger)).collect()
    }

    pub fn lock_group(&self, group: Uuid) -> Option<Vec<LockResult>> {
        let ids = self.lock_inner().groups.iter().find(|g| g.id == group)?.resource_ids.clone();
        Some(self.lock_resources(&ids, LockTrigger::Manual))
    }

    pub fn lock_all(&self) -> Vec<LockResult> {
        let ids: Vec<Uuid> = self.lock_inner().resources.iter().map(|r| r.id).collect();
        self.lock_resources(&ids, LockTrigger::Manual)
    }

    /// Bloqueio da estação (SessionLock do SCM): só recursos cuja política pede.
    pub fn on_workstation_locked(&self) -> Vec<LockResult> {
        let ids: Vec<Uuid> = self.lock_inner().policies.iter().filter(|(_, p)| p.lock_on_workstation_lock).map(|(id, _)| *id).collect();
        self.lock_resources(&ids, LockTrigger::WorkstationLock)
    }

    pub fn record_activity(&self, id: Uuid) {
        self.tracker.record_activity(id);
    }

    pub fn unlock_requirement(&self, id: Uuid) -> Option<Requirement> {
        let threshold = self.lock_inner().policies.get(&id)?.totp_threshold_secs;
        Some(self.unlock.requirement(id, Duration::from_secs(threshold)))
    }

    pub fn unlock(&self, id: Uuid, passphrase: &str, totp: Option<&str>) -> Option<UnlockResult> {
        let mut inner = self.lock_inner();
        let r = inner.resources.iter().find(|r| r.id == id)?.clone();
        let locker = self.orchestrator.locker(r.kind)?.clone();
        let threshold = Duration::from_secs(inner.policies.get(&id).map_or(crate::model::DEFAULT_TOTP_THRESHOLD_SECS, |p| p.totp_threshold_secs));
        let result = self.unlock.unlock(&r, locker.as_ref(), threshold, passphrase, totp);
        if result.code == UnlockCode::Unlocked {
            self.tracker.reset(id);
            let rt = inner.runtime.entry(id).or_default();
            rt.pending = false;
            rt.state = LockState::Unlocked; // evita classificar como desbloqueio externo
            self.refresh(&mut inner, &r);
        }
        Some(result)
    }

    pub fn save_resource(&self, resource: ProtectedResource) -> anyhow::Result<OperationResult> {
        let mut inner = self.lock_inner();
        let errors = resource.validate();
        if !errors.is_empty() {
            return Ok(OperationResult::fail(errors));
        }
        if inner.resources.iter().any(|r| r.id != resource.id && r.kind == resource.kind && r.target.eq_ignore_ascii_case(&resource.target)) {
            return Ok(OperationResult::fail(vec!["Este recurso já está cadastrado.".into()]));
        }
        self.config.upsert_resource(&resource)?;
        self.tracker.reset(resource.id);
        self.config_event(format!("Recurso salvo: {} ({}).", resource.display_name, resource.target));
        self.reload_core(&mut inner)?;
        Ok(OperationResult::ok())
    }

    pub fn delete_resource(&self, id: Uuid) -> anyhow::Result<OperationResult> {
        let mut inner = self.lock_inner();
        let Some(r) = inner.resources.iter().find(|r| r.id == id).cloned() else {
            return Ok(OperationResult::fail(vec!["Recurso não encontrado.".into()]));
        };
        self.config.delete_resource(id)?;
        self.tracker.forget(id);
        inner.runtime.remove(&id);
        self.config_event(format!("Recurso removido da proteção: {}.", r.display_name));
        self.reload_core(&mut inner)?;
        Ok(OperationResult::ok())
    }

    pub fn save_group(&self, mut group: ProtectionGroup) -> anyhow::Result<OperationResult> {
        let mut inner = self.lock_inner();
        group.name = group.name.trim().to_owned();
        let known: Vec<Uuid> = inner.resources.iter().map(|r| r.id).collect();
        let errors = group.validate(&known);
        if !errors.is_empty() {
            return Ok(OperationResult::fail(errors));
        }
        if inner.groups.iter().any(|g| g.id != group.id && g.name.to_lowercase() == group.name.to_lowercase()) {
            return Ok(OperationResult::fail(vec!["Já existe um grupo com este nome.".into()]));
        }
        self.config.upsert_group(&group)?;
        self.config_event(format!("Grupo salvo: {}.", group.name));
        self.reload_core(&mut inner)?;
        Ok(OperationResult::ok())
    }

    pub fn delete_group(&self, id: Uuid) -> anyhow::Result<OperationResult> {
        let mut inner = self.lock_inner();
        let Some(g) = inner.groups.iter().find(|g| g.id == id).cloned() else {
            return Ok(OperationResult::fail(vec!["Grupo não encontrado.".into()]));
        };
        self.config.delete_group(id)?;
        self.config_event(format!("Grupo removido: {}.", g.name));
        self.reload_core(&mut inner)?;
        Ok(OperationResult::ok())
    }

    pub fn snapshot(&self) -> Snapshot {
        let mut inner = self.lock_inner();
        let session_idle = self.session.current();
        let Inner { resources, groups, policies, runtime, .. } = &mut *inner;
        let views = resources
            .iter()
            .map(|r| {
                let rt = runtime.entry(r.id).or_default();
                let policy = policies.get(&r.id).cloned().unwrap_or_else(EffectivePolicy::ungrouped);
                let next = (rt.state == LockState::Unlocked && !rt.pending)
                    .then(|| evaluate(&policy, self.tracker.idle(r.id), session_idle).remaining)
                    .flatten()
                    .map(|d| d.as_secs() + u64::from(d.subsec_nanos() > 0));
                ResourceView {
                    resource: r.clone(),
                    state: rt.state,
                    auto_unlock: rt.auto_unlock,
                    is_system_volume: rt.system,
                    policy,
                    next_lock_in_secs: next,
                    pending_lock: rt.pending,
                    last_outcome: rt.last_outcome,
                    last_detail: rt.last_detail.clone(),
                }
            })
            .collect();
        Snapshot {
            taken_at: self.clock.now_utc(),
            resources: views,
            groups: groups.clone(),
            session_idle_secs: session_idle.map(|d| d.as_secs()),
            simulated: self.simulated,
        }
    }

    fn lock_one(&self, inner: &mut Inner, r: &ProtectedResource, trigger: LockTrigger) -> LockResult {
        let result = self.orchestrator.lock(r, trigger);
        let now = self.clock.monotonic();
        let rt = inner.runtime.entry(r.id).or_default();
        rt.last_outcome = Some(result.outcome);
        rt.last_detail = result.detail.clone();
        if result.outcome == LockOutcome::Postponed {
            rt.pending = true;
            rt.retry_delay = if rt.retry_delay.is_zero() { FIRST_RETRY } else { (rt.retry_delay * 2).min(MAX_RETRY) };
            rt.retry_at = now + rt.retry_delay;
        } else {
            rt.pending = false;
            rt.retry_delay = Duration::ZERO;
        }
        if matches!(result.outcome, LockOutcome::Locked | LockOutcome::AlreadyLocked) {
            rt.state = LockState::Locked;
        }
        result
    }

    fn refresh(&self, inner: &mut Inner, r: &ProtectedResource) {
        let Some(locker) = self.orchestrator.locker(r.kind) else {
            inner.runtime.entry(r.id).or_default().state = LockState::Unavailable;
            return;
        };
        let status = locker.status(r);
        let rt = inner.runtime.entry(r.id).or_default();
        if rt.state == LockState::Locked && status.state == LockState::Unlocked {
            // Desbloqueado fora do ByteHalt (Explorer, manage-bde): recomeça a contagem.
            self.tracker.reset(r.id);
            let _ = self.store.delete(r.id);
            append_or_log(
                self.journal.as_ref(),
                JournalEntry {
                    at: self.clock.now_utc(),
                    event: EventType::Warning,
                    severity: Severity::Warning,
                    resource_id: Some(r.id),
                    message: format!("{} — desbloqueado fora do ByteHalt.", r.display_name),
                    detail: Some("A regra de TOTP não se aplica a desbloqueios externos.".into()),
                },
            );
        }
        rt.state = status.state;
        rt.auto_unlock = status.auto_unlock;
        rt.system = status.is_system_volume;
    }

    fn update_watermark(&self, inner: &mut Inner) {
        let now = self.clock.now_utc();
        let tol = CLOCK_TOLERANCE.as_millis() as i64;
        match self.store.read_watermark() {
            StoreRead::Found(mark) if now < mark - tol => {
                if !inner.clock_anomaly_reported {
                    inner.clock_anomaly_reported = true;
                    append_or_log(
                        self.journal.as_ref(),
                        JournalEntry {
                            at: now,
                            event: EventType::ClockAnomaly,
                            severity: Severity::Warning,
                            resource_id: None,
                            message: "O relógio do Windows voltou no tempo; desbloqueios passarão a exigir TOTP.".into(),
                            detail: Some(format!("Maior horário já observado: {mark} ms UTC.")),
                        },
                    );
                }
            }
            StoreRead::Found(mark) => {
                inner.clock_anomaly_reported = false;
                if now > mark {
                    let _ = self.store.write_watermark(now);
                }
            }
            _ => {
                let _ = self.store.write_watermark(now);
            }
        }
    }

    fn reload_core(&self, inner: &mut Inner) -> anyhow::Result<()> {
        let previous = std::mem::take(&mut inner.policies);
        inner.resources = self.config.resources()?;
        inner.groups = self.config.groups()?;
        inner.policies = resolve(&inner.resources, &inner.groups);
        for r in inner.resources.clone() {
            // Temporizador ou modo mudou (ex.: entrou num grupo): a contagem recomeça agora, para a
            // nova política não bloquear de imediato com a ociosidade acumulada antes dela.
            if let (Some(before), Some(after)) = (previous.get(&r.id), inner.policies.get(&r.id))
                && (before.inactivity_secs != after.inactivity_secs || before.mode != after.mode)
            {
                self.tracker.reset(r.id);
            }
            if inner.runtime.entry(r.id).or_default().state == LockState::Unknown {
                self.refresh(inner, &r);
            }
        }
        Ok(())
    }

    fn config_event(&self, message: String) {
        append_or_log(
            self.journal.as_ref(),
            JournalEntry {
                at: self.clock.now_utc(),
                event: EventType::ConfigurationChanged,
                severity: Severity::Info,
                resource_id: None,
                message,
                detail: None,
            },
        );
    }
}

/// Atalho: o locker de unidades é o único suportado na Fase 1.
pub fn supported_kinds() -> &'static [ResourceKind] {
    &[ResourceKind::BitLockerVolume, ResourceKind::Vault]
}
