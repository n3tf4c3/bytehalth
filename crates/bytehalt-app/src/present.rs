//! Apresentação pura (sem GPUI): textos em pt-BR e modelos das telas, testáveis isoladamente.

use bytehalt_core::auth::{Factors, Reason};
use bytehalt_core::clock::UtcMillis;
use bytehalt_core::engine::{ResourceView, Snapshot};
use bytehalt_core::journal::{EventType, JournalEntry, Severity};
use bytehalt_core::locking::{LockOutcome, LockResult, LockState};
use bytehalt_core::model::{InactivityMode, ProtectionGroup, ResourceKind};
use bytehalt_core::vault::VaultStage;
use bytehalt_core::vault_manager::JobView;
use uuid::Uuid;

pub fn duration(secs: Option<u64>) -> String {
    let Some(s) = secs else { return "—".into() };
    if s == 0 {
        return "agora".into();
    }
    let (h, m, sec) = (s / 3600, (s % 3600) / 60, s % 60);
    match (h, m, sec) {
        (0, 0, s) => format!("{s} s"),
        (0, m, 0) => format!("{m} min"),
        (0, m, s) => format!("{m} min {s} s"),
        (h, 0, _) => format!("{h} h"),
        (h, m, _) => format!("{h} h {m} min"),
    }
}

pub fn minutes(secs: Option<u64>) -> String {
    match secs.map(|s| s / 60) {
        None => "Desligado".into(),
        Some(m) if m < 60 => format!("{m} min"),
        Some(m) if m % 60 == 0 => format!("{} h", m / 60),
        Some(m) => format!("{} h {} min", m / 60, m % 60),
    }
}

pub fn state(s: LockState) -> &'static str {
    match s {
        LockState::Locked => "Bloqueado",
        LockState::Unlocked => "Desbloqueado",
        LockState::NotProtected => "Sem BitLocker",
        LockState::Unavailable => "Indisponível",
        LockState::Unknown => "Desconhecido",
    }
}

pub fn mode(m: InactivityMode) -> &'static str {
    match m {
        InactivityMode::ResourceIdle => "Inatividade do recurso",
        InactivityMode::SessionIdle => "Inatividade da sessão",
        InactivityMode::Combined => "Combinada (o que ocorrer primeiro)",
    }
}

pub fn outcome(o: LockOutcome) -> &'static str {
    match o {
        LockOutcome::Locked => "Bloqueado",
        LockOutcome::AlreadyLocked => "Já estava bloqueado",
        LockOutcome::Postponed => "Adiado: em uso",
        LockOutcome::Refused => "Recusado",
        LockOutcome::Unavailable => "Indisponível",
        LockOutcome::Failed => "Falhou",
    }
}

pub fn factors(f: Factors) -> &'static str {
    match f {
        Factors::Primary => "Senha",
        Factors::PrimaryAndTotp => "Senha + código TOTP",
    }
}

pub fn reason(r: Reason) -> &'static str {
    match r {
        Reason::WithinThreshold => "Bloqueado há menos que o limite.",
        Reason::ThresholdReached => "Bloqueado há tempo igual ou maior que o limite.",
        Reason::ClockRollbackDetected => "O relógio do Windows voltou no tempo.",
        Reason::ClockMismatchDetected => "O relógio do Windows não confere com o tempo real decorrido.",
        Reason::LockStateMissing => "Não há registro do instante do bloqueio.",
        Reason::LockStateUnreadable => "O registro do bloqueio está ilegível ou foi alterado.",
    }
}

pub fn severity(s: Severity) -> &'static str {
    match s {
        Severity::Info => "Info",
        Severity::Warning => "Aviso",
        Severity::Error => "Erro",
    }
}

/// Data e hora locais (dd/mm/aaaa hh:mm:ss) pelo fuso do Windows.
pub fn local_time(at: UtcMillis) -> String {
    use windows_sys::Win32::Foundation::{FILETIME, SYSTEMTIME};
    use windows_sys::Win32::System::Time::{FileTimeToSystemTime, SystemTimeToTzSpecificLocalTime};
    let ticks = (at.max(0) as u64) * 10_000 + 116_444_736_000_000_000;
    let ft = FILETIME { dwLowDateTime: ticks as u32, dwHighDateTime: (ticks >> 32) as u32 };
    let (mut utc, mut local) = (SYSTEMTIME::default(), SYSTEMTIME::default());
    // SAFETY: estruturas locais válidas; fuso nulo = fuso atual do sistema.
    let ok = unsafe { FileTimeToSystemTime(&ft, &mut utc) != 0 && SystemTimeToTzSpecificLocalTime(std::ptr::null(), &utc, &mut local) != 0 };
    if !ok {
        return format!("{at} ms UTC");
    }
    format!("{:02}/{:02}/{} {:02}:{:02}:{:02}", local.wDay, local.wMonth, local.wYear, local.wHour, local.wMinute, local.wSecond)
}

pub fn lock_summary(results: &[LockResult]) -> String {
    if results.is_empty() {
        return "Nenhum recurso para bloquear.".into();
    }
    let ok = results.iter().filter(|r| matches!(r.outcome, LockOutcome::Locked | LockOutcome::AlreadyLocked)).count();
    if ok == results.len() {
        return if ok == 1 { format!("{} bloqueado.", results[0].display_name) } else { format!("{ok} recursos bloqueados.") };
    }
    let failed: Vec<String> = results
        .iter()
        .filter(|r| !matches!(r.outcome, LockOutcome::Locked | LockOutcome::AlreadyLocked))
        .map(|r| format!("{}: {}{}", r.display_name, outcome(r.outcome), r.detail.as_ref().map(|d| format!(" ({d})")).unwrap_or_default()))
        .collect();
    format!("Bloqueio parcial ({ok} de {}). {}", results.len(), failed.join("; "))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tone {
    Neutral,
    Good,
    Warning,
    Danger,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ResourceRow {
    pub id: Uuid,
    pub kind: ResourceKind,
    pub name: String,
    pub target: String,
    pub state: LockState,
    pub state_text: String,
    pub tone: Tone,
    pub policy_text: String,
    pub next_lock_text: String,
    pub groups_text: String,
    pub warning: Option<String>,
    pub last_result: Option<String>,
    pub can_lock: bool,
    pub next_lock_secs: Option<u64>,
}

impl ResourceRow {
    pub fn from_view(v: &ResourceView, groups: &[ProtectionGroup]) -> Self {
        let state_text = if v.pending_lock { "Bloqueio pendente (em uso)".to_owned() } else { state(v.state).to_owned() };
        let tone = match v.state {
            LockState::Locked => Tone::Good,
            LockState::Unlocked if v.pending_lock => Tone::Warning,
            LockState::Unlocked => Tone::Neutral,
            LockState::NotProtected | LockState::Unavailable => Tone::Danger,
            LockState::Unknown => Tone::Warning,
        };
        let policy_text = match v.policy.inactivity_secs {
            None => "Somente bloqueio manual".to_owned(),
            Some(_) => format!("{} · {}", minutes(v.policy.inactivity_secs), mode(v.policy.mode)),
        };
        let next_lock_text = if v.state != LockState::Unlocked {
            String::new()
        } else if v.pending_lock {
            "Nova tentativa em breve".into()
        } else {
            match (v.next_lock_in_secs, v.policy.inactivity_secs) {
                (Some(0), _) => "Bloqueio em instantes".into(),
                (Some(s), _) => format!("Bloqueia em {}", duration(Some(s))),
                (None, None) => String::new(),
                (None, Some(_)) => "Aguardando dados da sessão".into(),
            }
        };
        let names: Vec<&str> = groups.iter().filter(|g| v.policy.source_groups.contains(&g.id)).map(|g| g.name.as_str()).collect();
        let mut warnings = Vec::new();
        if v.is_system_volume {
            warnings.push("Unidade do sistema: não pode ser bloqueada.");
        }
        if v.auto_unlock {
            warnings.push("Desbloqueio automático do BitLocker ativo: o Windows reabre a unidade sem o ByteHalt.");
        }
        if v.state == LockState::NotProtected {
            warnings.push("BitLocker desligado: não há proteção criptográfica.");
        }
        Self {
            id: v.resource.id,
            name: v.resource.display_name.clone(),
            kind: v.resource.kind,
            target: v.resource.target.clone(),
            state: v.state,
            state_text,
            tone,
            policy_text,
            next_lock_text,
            groups_text: if names.is_empty() { "Sem grupo".into() } else { names.join(", ") },
            warning: (!warnings.is_empty()).then(|| warnings.join(" ")),
            last_result: v
                .last_outcome
                .map(|o| format!("Última tentativa: {}{}", outcome(o), v.last_detail.as_ref().map(|d| format!(" — {d}")).unwrap_or_default())),
            can_lock: v.state == LockState::Unlocked && !v.is_system_volume,
            next_lock_secs: v.next_lock_in_secs,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Dashboard {
    pub total: usize,
    pub locked: usize,
    pub unlocked: usize,
    pub attention: usize,
    pub upcoming: Vec<ResourceRow>,
    pub alerts: Vec<String>,
}

pub fn dashboard(s: &Snapshot) -> Dashboard {
    let rows: Vec<ResourceRow> = s.resources.iter().map(|v| ResourceRow::from_view(v, &s.groups)).collect();
    let mut upcoming: Vec<ResourceRow> = rows.iter().filter(|r| r.state == LockState::Unlocked).cloned().collect();
    upcoming.sort_by_key(|r| r.next_lock_secs.unwrap_or(u64::MAX));
    let mut alerts = Vec::new();
    if s.simulated {
        alerts.push("Modo simulado: nenhuma unidade real é bloqueada. Use apenas para testes.".to_owned());
    }
    alerts.extend(rows.iter().filter_map(|r| r.warning.as_ref().map(|w| format!("{}: {w}", r.name))));
    alerts.extend(rows.iter().filter(|r| r.tone == Tone::Warning).filter_map(|r| r.last_result.as_ref().map(|l| format!("{}: {l}", r.name))));
    Dashboard {
        total: s.resources.len(),
        locked: s.resources.iter().filter(|v| v.state == LockState::Locked).count(),
        unlocked: s.resources.iter().filter(|v| v.state == LockState::Unlocked).count(),
        attention: s
            .resources
            .iter()
            .filter(|v| v.pending_lock || matches!(v.state, LockState::Unavailable | LockState::NotProtected | LockState::Unknown) || v.auto_unlock)
            .count(),
        upcoming,
        alerts,
    }
}

/// Entradas novas e relevantes para notificar (bloqueios, adiamentos, falhas, anomalias).
pub fn to_notify(history: &[JournalEntry], since: UtcMillis) -> Vec<&JournalEntry> {
    let mut out: Vec<&JournalEntry> = history
        .iter()
        .filter(|e| e.at > since)
        .filter(|e| {
            matches!(
                e.event,
                EventType::Locked
                    | EventType::LockPostponed
                    | EventType::LockFailed
                    | EventType::LockRefused
                    | EventType::ClockAnomaly
                    | EventType::StateStoreError
                    | EventType::UnlockDenied
            )
        })
        .filter(|e| !e.message.contains("já estava bloqueado"))
        .collect();
    out.sort_by_key(|e| e.at);
    out
}

pub const TIMEOUT_CHOICES: [(&str, Option<u64>); 8] = [
    ("1 min", Some(1)),
    ("5 min", Some(5)),
    ("10 min", Some(10)),
    ("15 min", Some(15)),
    ("30 min", Some(30)),
    ("60 min", Some(60)),
    ("Personalizado", None),
    ("Desligado", None),
];
pub const CUSTOM: usize = 6;
pub const OFF: usize = 7;

/// Monta o grupo a partir dos campos do editor, com as mesmas regras do serviço.
#[allow(clippy::too_many_arguments)] // um argumento por campo do formulário
pub fn build_group(
    id: Uuid,
    name: &str,
    timeout_choice: usize,
    custom_minutes: &str,
    mode: InactivityMode,
    totp_hours: &str,
    ws_lock: bool,
    suspend_lock: bool,
    resources: Vec<Uuid>,
) -> Result<ProtectionGroup, String> {
    let name = name.trim();
    if name.is_empty() {
        return Err("Informe o nome do grupo.".into());
    }
    let minutes = match timeout_choice {
        OFF => None,
        CUSTOM => match custom_minutes.trim().parse::<u64>() {
            Ok(m) if (1..=1440).contains(&m) => Some(m),
            _ => return Err("Tempo personalizado: informe de 1 a 1440 minutos.".into()),
        },
        i => TIMEOUT_CHOICES.get(i).and_then(|c| c.1).or(Some(10)),
    };
    let hours: f64 = totp_hours.trim().replace(',', ".").parse().map_err(|_| "Limite do TOTP: informe de 0,02 a 720 horas (padrão: 24).".to_owned())?;
    if !(hours * 60.0 >= 1.0 && hours <= 720.0) {
        return Err("Limite do TOTP: informe de 0,02 a 720 horas (padrão: 24).".into());
    }
    Ok(ProtectionGroup {
        id,
        name: name.to_owned(),
        resource_ids: resources,
        inactivity_secs: minutes.map(|m| m * 60),
        mode,
        totp_threshold_secs: (hours * 3600.0).round() as u64,
        lock_on_workstation_lock: ws_lock,
        lock_on_suspend: suspend_lock,
    })
}

/// Aparência da bandeja: o ícone mostra o estado da proteção sem abrir o painel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrayLook {
    Locked,
    Unlocked,
    Attention,
}

/// Ícone, linha de status do menu e dica (até 127 caracteres) da bandeja.
pub fn tray_summary(snapshot: Option<&Snapshot>, connected: Option<bool>) -> (TrayLook, String, String) {
    let s = match (connected, snapshot) {
        (Some(true), Some(s)) => s,
        (Some(false), _) => return (TrayLook::Attention, "Serviço indisponível".into(), "ByteHalt · serviço indisponível".into()),
        _ => return (TrayLook::Attention, "Conectando…".into(), "ByteHalt · conectando ao serviço".into()),
    };
    let total = s.resources.len();
    let locked = s.resources.iter().filter(|v| v.state == LockState::Locked).count();
    let attention = s.resources.iter().any(|v| v.pending_lock || matches!(v.state, LockState::Unavailable | LockState::NotProtected | LockState::Unknown));
    let unlocked = s.resources.iter().any(|v| v.state == LockState::Unlocked && !v.is_system_volume);
    let look = if attention {
        TrayLook::Attention
    } else if unlocked || total == 0 {
        TrayLook::Unlocked
    } else {
        TrayLook::Locked
    };
    let status = format!("{total} recurso(s) · {locked} bloqueado(s)");
    let mut tip = format!("ByteHalt · {status}");
    if s.resources.iter().any(|v| v.pending_lock) {
        tip.push_str(" · bloqueio pendente");
    } else if let Some(next) = s.resources.iter().filter(|v| v.state == LockState::Unlocked).filter_map(|v| v.next_lock_in_secs).min() {
        tip.push_str(&format!(" · próximo bloqueio em {}", duration(Some(next))));
    }
    let tip: String = tip.chars().take(127).collect();
    (look, status, tip)
}

/// Tamanho em unidades binárias, com vírgula decimal (pt-BR).
pub fn bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["bytes", "KB", "MB", "GB", "TB"];
    let mut v = n as f64;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 { format!("{n} bytes") } else { format!("{v:.1} {}", UNITS[u]).replace('.', ",") }
}

pub fn vault_stage(s: VaultStage) -> (&'static str, Tone) {
    match s {
        VaultStage::Preparing => ("Preparando", Tone::Neutral),
        VaultStage::Ready => ("Pronto para trocar", Tone::Warning),
        VaultStage::Swapping => ("Trocando", Tone::Warning),
        VaultStage::Active => ("Ativo", Tone::Good),
        VaultStage::Removing => ("Removendo", Tone::Warning),
        VaultStage::Failed => ("Falhou", Tone::Danger),
    }
}

/// "Copiando · 45% (1,2 GB de 2,7 GB)".
pub fn job_progress(j: &JobView) -> String {
    if j.total_bytes == 0 || j.done || !j.step.starts_with("Copiando") {
        return j.step.clone();
    }
    let pct = (j.progress_bytes.min(j.total_bytes) * 100 / j.total_bytes).min(100);
    format!("{} · {pct}% ({} de {})", j.step, bytes(j.progress_bytes), bytes(j.total_bytes))
}

/// Problemas da senha nova do cofre (a do serviço é a regra final).
pub fn vault_password_issue(a: &str, b: &str) -> Option<&'static str> {
    if a.chars().count() < bytehalt_core::vault::MIN_PASSPHRASE {
        Some("A senha precisa de pelo menos 8 caracteres.")
    } else if a != b {
        Some("As senhas não conferem.")
    } else {
        None
    }
}

pub const MANDATORY_LIMITATION: &str = "O código TOTP é verificado pelo ByteHalt, não pelo BitLocker. Quem conhece a senha da unidade, tem a chave de recuperação ou privilégios de administrador consegue desbloquear sem o ByteHalt. Isto não é autenticação multifator criptograficamente obrigatória para volumes BitLocker.";

#[cfg(test)]
mod tests {
    use super::*;
    use bytehalt_core::model::{ProtectedResource, ResourceKind};
    use bytehalt_core::policy::EffectivePolicy;

    #[test]
    fn textos_dos_cofres() {
        assert_eq!(bytes(512), "512 bytes");
        assert_eq!(bytes(1536), "1,5 KB");
        assert_eq!(bytes(3 << 30), "3,0 GB");
        let j = JobView { step: "Copiando".into(), progress_bytes: 1 << 30, total_bytes: 4 << 30, ..Default::default() };
        assert_eq!(job_progress(&j), "Copiando · 25% (1,0 GB de 4,0 GB)");
        assert_eq!(job_progress(&JobView { step: "Formatando".into(), ..Default::default() }), "Formatando");
        assert_eq!(vault_password_issue("1234567", "1234567"), Some("A senha precisa de pelo menos 8 caracteres."));
        assert_eq!(vault_password_issue("12345678", "12345679"), Some("As senhas não conferem."));
        assert_eq!(vault_password_issue("12345678", "12345678"), None);
        assert_eq!(vault_stage(VaultStage::Active).0, "Ativo");
    }

    fn view(name: &str, target: &str, state: LockState, next: Option<u64>, auto: bool, system: bool, pending: bool) -> ResourceView {
        ResourceView {
            resource: ProtectedResource { id: Uuid::new_v4(), display_name: name.into(), kind: ResourceKind::BitLockerVolume, target: target.into() },
            state,
            auto_unlock: auto,
            is_system_volume: system,
            policy: EffectivePolicy { inactivity_secs: Some(300), ..EffectivePolicy::ungrouped() },
            next_lock_in_secs: next,
            pending_lock: pending,
            last_outcome: pending.then_some(LockOutcome::Postponed),
            last_detail: pending.then(|| "Em uso por: Code.exe.".into()),
        }
    }

    #[test]
    fn duracoes_e_minutos_em_portugues() {
        for (s, e) in [
            (None, "—"),
            (Some(0), "agora"),
            (Some(45), "45 s"),
            (Some(300), "5 min"),
            (Some(90), "1 min 30 s"),
            (Some(3660), "1 h 1 min"),
            (Some(7200), "2 h"),
        ] {
            assert_eq!(duration(s), e);
        }
        assert_eq!(minutes(None), "Desligado");
        assert_eq!(minutes(Some(1440 * 60)), "24 h");
    }

    #[test]
    fn painel_conta_estados_e_lista_alertas() {
        let s = Snapshot {
            taken_at: 0,
            resources: vec![
                view("Unidade D:", "D:", LockState::Unlocked, Some(90), false, false, false),
                view("Unidade E:", "E:", LockState::Locked, None, true, false, false),
                view("Sistema", "C:", LockState::Unlocked, None, false, true, false),
                view("USB", "F:", LockState::Unavailable, None, false, false, false),
            ],
            groups: vec![],
            session_idle_secs: Some(12),
            simulated: true,
        };
        let d = dashboard(&s);
        assert_eq!((d.total, d.locked, d.unlocked, d.attention), (4, 1, 2, 2));
        assert_eq!(d.upcoming[0].name, "Unidade D:");
        assert_eq!(d.upcoming[0].next_lock_text, "Bloqueia em 1 min 30 s");
        assert!(d.alerts.iter().any(|a| a.contains("simulado")));
        assert!(d.alerts.iter().any(|a| a.contains("Desbloqueio automático")));
        let sys = ResourceRow::from_view(&s.resources[2], &[]);
        assert!(!sys.can_lock && sys.warning.unwrap().contains("sistema"));
    }

    #[test]
    fn bloqueio_pendente_aparece_como_atencao_e_em_instantes_nao_diz_agora() {
        let p = ResourceRow::from_view(&view("D", "D:", LockState::Unlocked, None, false, false, true), &[]);
        assert_eq!(p.tone, Tone::Warning);
        assert!(p.state_text.contains("pendente"));
        let z = ResourceRow::from_view(&view("D", "D:", LockState::Unlocked, Some(0), false, false, false), &[]);
        assert_eq!(z.next_lock_text, "Bloqueio em instantes");
    }

    #[test]
    fn resumo_de_bloqueio_parcial() {
        let r = |n: &str, o, d: Option<&str>| LockResult { resource_id: Uuid::new_v4(), display_name: n.into(), outcome: o, detail: d.map(Into::into) };
        let s = lock_summary(&[r("D", LockOutcome::Locked, None), r("E", LockOutcome::Postponed, Some("Em uso por: Code.exe."))]);
        assert!(s.starts_with("Bloqueio parcial (1 de 2)") && s.contains("E: Adiado"), "{s}");
        assert_eq!(lock_summary(&[r("D", LockOutcome::Locked, None)]), "D bloqueado.");
    }

    #[test]
    fn notificacoes_so_para_eventos_novos_e_relevantes() {
        let e = |at, ev, msg: &str| JournalEntry { at, event: ev, severity: Severity::Info, resource_id: None, message: msg.into(), detail: None };
        let h = vec![e(3, EventType::LockPostponed, "D — em uso"), e(2, EventType::ConfigurationChanged, "Grupo salvo"), e(1, EventType::Locked, "antigo")];
        let n = to_notify(&h, 1);
        assert_eq!(n.len(), 1);
        assert_eq!(n[0].event, EventType::LockPostponed);
    }

    #[test]
    fn editor_de_grupo_valida_como_o_servico() {
        let ok = build_group(Uuid::nil(), "  Discos ", 2, "", InactivityMode::Combined, "24", true, true, vec![]).unwrap();
        assert_eq!((ok.name.as_str(), ok.inactivity_secs, ok.totp_threshold_secs), ("Discos", Some(600), 86_400));
        assert_eq!(build_group(Uuid::nil(), "X", 0, "", InactivityMode::ResourceIdle, "1,5", false, false, vec![]).unwrap().totp_threshold_secs, 5400);
        assert_eq!(build_group(Uuid::nil(), "X", OFF, "", InactivityMode::ResourceIdle, "24", false, false, vec![]).unwrap().inactivity_secs, None);
        for bad in ["0", "1441", "dez"] {
            assert!(build_group(Uuid::nil(), "X", CUSTOM, bad, InactivityMode::ResourceIdle, "24", false, false, vec![]).is_err());
        }
        assert!(build_group(Uuid::nil(), " ", 0, "", InactivityMode::ResourceIdle, "24", false, false, vec![]).is_err());
        assert_eq!(TIMEOUT_CHOICES.iter().filter_map(|c| c.1).collect::<Vec<_>>(), [1, 5, 10, 15, 30, 60]);
    }

    #[test]
    fn bandeja_mostra_o_estado_no_icone_e_na_dica() {
        let snap = |vs: Vec<ResourceView>| Snapshot { taken_at: 0, resources: vs, groups: vec![], session_idle_secs: None, simulated: false };
        let (look, _, tip) = tray_summary(None, Some(false));
        assert_eq!(look, TrayLook::Attention);
        assert!(tip.contains("indisponível"));
        let all_locked =
            snap(vec![view("D", "D:", LockState::Locked, None, false, false, false), view("E", "E:", LockState::Locked, None, false, false, false)]);
        let (look, status, tip) = tray_summary(Some(&all_locked), Some(true));
        assert_eq!((look, status.as_str()), (TrayLook::Locked, "2 recurso(s) · 2 bloqueado(s)"));
        assert!(tip.starts_with("ByteHalt · 2 recurso(s)"));
        let one_open =
            snap(vec![view("D", "D:", LockState::Unlocked, Some(150), false, false, false), view("E", "E:", LockState::Locked, None, false, false, false)]);
        let (look, _, tip) = tray_summary(Some(&one_open), Some(true));
        assert_eq!(look, TrayLook::Unlocked);
        assert!(tip.ends_with("próximo bloqueio em 2 min 30 s"), "{tip}");
        let pending = snap(vec![view("D", "D:", LockState::Unlocked, None, false, false, true)]);
        let (look, _, tip) = tray_summary(Some(&pending), Some(true));
        assert_eq!(look, TrayLook::Attention);
        assert!(tip.contains("pendente"));
        let system_only =
            snap(vec![view("C", "C:", LockState::Unlocked, None, false, true, false), view("D", "D:", LockState::Locked, None, false, false, false)]);
        assert_eq!(tray_summary(Some(&system_only), Some(true)).0, TrayLook::Locked, "a unidade do sistema não conta como desprotegida");
    }

    #[test]
    fn limitacao_obrigatoria_e_explicita() {
        assert!(MANDATORY_LIMITATION.contains("não é autenticação multifator"));
    }
}
