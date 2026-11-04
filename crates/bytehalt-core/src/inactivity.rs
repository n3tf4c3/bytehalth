//! Rastreamento e avaliação de inatividade. A fonte real de I/O (ETW, Fase 4) e a ociosidade da
//! sessão (relatada pela interface) entram aqui; a medição usa só o tempo monotônico.

use crate::clock::Clock;
use crate::model::InactivityMode;
use crate::policy::EffectivePolicy;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use uuid::Uuid;

pub struct InactivityTracker {
    clock: Arc<dyn Clock>,
    last: Mutex<HashMap<Uuid, Duration>>,
}

impl InactivityTracker {
    pub fn new(clock: Arc<dyn Clock>) -> Self {
        Self { clock, last: Mutex::new(HashMap::new()) }
    }

    pub fn record_activity(&self, id: Uuid) {
        let now = self.clock.monotonic();
        self.last.lock().unwrap_or_else(|e| e.into_inner()).insert(id, now);
    }

    /// Recomeça a contagem (desbloqueio, cadastro, mudança de política).
    pub fn reset(&self, id: Uuid) {
        self.record_activity(id);
    }

    pub fn forget(&self, id: Uuid) {
        self.last.lock().unwrap_or_else(|e| e.into_inner()).remove(&id);
    }

    /// Ociosidade do recurso; recurso nunca visto começa a contar agora.
    pub fn idle(&self, id: Uuid) -> Duration {
        let now = self.clock.monotonic();
        let mut last = self.last.lock().unwrap_or_else(|e| e.into_inner());
        now.saturating_sub(*last.entry(id).or_insert(now))
    }
}

/// Fonte real de atividade (Fase 4): um contador crescente de operações de E/S do volume do recurso.
/// Contador diferente da leitura anterior = houve uso. `None` = indisponível (volume bloqueado,
/// ausente ou fonte desligada).
pub trait ActivityProbe: Send + Sync {
    fn counter(&self, resource: &crate::model::ProtectedResource) -> Option<u64>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Decision {
    pub due: bool,
    pub remaining: Option<Duration>,
}

/// Ociosidade de sessão desconhecida nunca dispara bloqueio por sessão; o ramo de recurso do modo
/// Combined continua valendo.
pub fn evaluate(policy: &EffectivePolicy, resource_idle: Duration, session_idle: Option<Duration>) -> Decision {
    let Some(secs) = policy.inactivity_secs else {
        return Decision { due: false, remaining: None };
    };
    let timeout = Duration::from_secs(secs);
    let resource = matches!(policy.mode, InactivityMode::ResourceIdle | InactivityMode::Combined).then(|| timeout.saturating_sub(resource_idle));
    let session =
        matches!(policy.mode, InactivityMode::SessionIdle | InactivityMode::Combined).then_some(session_idle).flatten().map(|s| timeout.saturating_sub(s));
    let remaining = match (resource, session) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    };
    Decision { due: remaining == Some(Duration::ZERO), remaining }
}

/// Ociosidade da sessão relatada pela interface por IPC. Sem relatos novos, ela continua crescendo
/// a partir do último relato (falha fechada: interface encerrada não impede o bloqueio).
pub struct ReportedSessionIdle {
    clock: Arc<dyn Clock>,
    state: Mutex<Option<(Duration, Duration)>>, // (ociosidade relatada, instante monotônico)
}

impl ReportedSessionIdle {
    pub fn new(clock: Arc<dyn Clock>) -> Self {
        Self { clock, state: Mutex::new(None) }
    }

    pub fn report(&self, idle: Duration) {
        *self.state.lock().unwrap_or_else(|e| e.into_inner()) = Some((idle, self.clock.monotonic()));
    }

    pub fn current(&self) -> Option<Duration> {
        let state = *self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.map(|(idle, at)| idle + self.clock.monotonic().saturating_sub(at))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::TestClock;

    fn p(min: Option<u64>, mode: InactivityMode) -> EffectivePolicy {
        EffectivePolicy { inactivity_secs: min.map(|m| m * 60), mode, ..EffectivePolicy::ungrouped() }
    }
    const M: u64 = 60;

    #[test]
    fn temporizador_desligado_nunca_vence() {
        assert!(!evaluate(&p(None, InactivityMode::Combined), Duration::from_secs(3 * 86400), Some(Duration::from_secs(3 * 86400))).due);
    }

    #[test]
    fn inatividade_do_recurso_vence_exatamente_no_tempo() {
        let pol = p(Some(5), InactivityMode::ResourceIdle);
        let before = evaluate(&pol, Duration::from_secs(5 * M - 1), None);
        assert!(!before.due);
        assert_eq!(before.remaining, Some(Duration::from_secs(1)));
        assert!(evaluate(&pol, Duration::from_secs(5 * M), None).due);
    }

    #[test]
    fn modo_recurso_ignora_a_sessao_e_modo_sessao_sem_dados_nao_bloqueia() {
        assert!(!evaluate(&p(Some(5), InactivityMode::ResourceIdle), Duration::from_secs(M), Some(Duration::from_secs(7200))).due);
        let d = evaluate(&p(Some(1), InactivityMode::SessionIdle), Duration::from_secs(5 * 3600), None);
        assert!(!d.due);
        assert_eq!(d.remaining, None);
        assert!(evaluate(&p(Some(10), InactivityMode::SessionIdle), Duration::ZERO, Some(Duration::from_secs(10 * M))).due);
    }

    #[test]
    fn modo_combinado_vence_pelo_que_ocorrer_primeiro() {
        let pol = p(Some(10), InactivityMode::Combined);
        assert!(evaluate(&pol, Duration::from_secs(10 * M), Some(Duration::ZERO)).due);
        assert!(evaluate(&pol, Duration::ZERO, Some(Duration::from_secs(10 * M))).due);
        assert!(evaluate(&pol, Duration::from_secs(10 * M), None).due);
        let n = evaluate(&pol, Duration::from_secs(3 * M), Some(Duration::from_secs(8 * M)));
        assert!(!n.due);
        assert_eq!(n.remaining, Some(Duration::from_secs(2 * M)));
    }

    #[test]
    fn atividade_reinicia_e_relogio_de_parede_nao_afeta() {
        let c = Arc::new(TestClock::new());
        let t = InactivityTracker::new(c.clone());
        let id = Uuid::new_v4();
        assert_eq!(t.idle(id), Duration::ZERO);
        c.advance(Duration::from_secs(240));
        assert_eq!(t.idle(id), Duration::from_secs(240));
        t.record_activity(id);
        assert_eq!(t.idle(id), Duration::ZERO);
        c.set_wall(0);
        assert_eq!(t.idle(id), Duration::ZERO);
    }

    #[test]
    fn sessao_sem_relato_e_desconhecida_e_depois_cresce() {
        let c = Arc::new(TestClock::new());
        let s = ReportedSessionIdle::new(c.clone());
        assert_eq!(s.current(), None);
        s.report(Duration::from_secs(20));
        c.advance(Duration::from_secs(600));
        assert_eq!(s.current(), Some(Duration::from_secs(620)));
    }
}
