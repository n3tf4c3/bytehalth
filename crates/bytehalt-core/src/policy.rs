//! Regra determinística da política mais restritiva (docs/ARCHITECTURE.md §7): menor tempo de
//! inatividade; modo Combined quando os modos divergem; menor limiar de TOTP; bloqueio ao bloquear
//! o Windows se qualquer grupo pedir. O resultado não depende da ordem dos grupos.

use crate::model::{DEFAULT_TOTP_THRESHOLD_SECS, InactivityMode, ProtectedResource, ProtectionGroup};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap};
use uuid::Uuid;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EffectivePolicy {
    pub inactivity_secs: Option<u64>,
    pub mode: InactivityMode,
    pub totp_threshold_secs: u64,
    pub lock_on_workstation_lock: bool,
    pub lock_on_suspend: bool,
    /// Grupos que originaram a política, ordenados por id.
    pub source_groups: Vec<Uuid>,
}

impl EffectivePolicy {
    /// Recurso fora de qualquer grupo: só bloqueio manual, limiar de TOTP padrão.
    pub fn ungrouped() -> Self {
        Self {
            inactivity_secs: None,
            mode: InactivityMode::ResourceIdle,
            totp_threshold_secs: DEFAULT_TOTP_THRESHOLD_SECS,
            lock_on_workstation_lock: false,
            lock_on_suspend: false,
            source_groups: Vec::new(),
        }
    }
}

pub fn resolve(resources: &[ProtectedResource], groups: &[ProtectionGroup]) -> HashMap<Uuid, EffectivePolicy> {
    let mut ordered: Vec<&ProtectionGroup> = groups.iter().collect();
    ordered.sort_by_key(|g| g.id);
    resources
        .iter()
        .map(|r| {
            let owning: Vec<&ProtectionGroup> = ordered.iter().copied().filter(|g| g.resource_ids.contains(&r.id)).collect();
            (r.id, if owning.is_empty() { EffectivePolicy::ungrouped() } else { combine(&owning) })
        })
        .collect()
}

fn combine(owning: &[&ProtectionGroup]) -> EffectivePolicy {
    let mut timeout: Option<u64> = None;
    let mut modes = BTreeSet::new();
    for g in owning {
        if let Some(t) = g.inactivity_secs {
            timeout = Some(timeout.map_or(t, |c| c.min(t)));
            modes.insert(g.mode);
        }
    }
    let mode = match modes.len() {
        0 => InactivityMode::ResourceIdle,
        1 => *modes.iter().next().unwrap_or(&InactivityMode::ResourceIdle),
        _ => InactivityMode::Combined,
    };
    EffectivePolicy {
        inactivity_secs: timeout,
        mode,
        totp_threshold_secs: owning.iter().map(|g| g.totp_threshold_secs).min().unwrap_or(DEFAULT_TOTP_THRESHOLD_SECS),
        lock_on_workstation_lock: owning.iter().any(|g| g.lock_on_workstation_lock),
        lock_on_suspend: owning.iter().any(|g| g.lock_on_suspend),
        source_groups: owning.iter().map(|g| g.id).collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::ResourceKind;

    fn res(name: &str, letter: &str) -> ProtectedResource {
        ProtectedResource { id: Uuid::new_v4(), display_name: name.into(), kind: ResourceKind::BitLockerVolume, target: letter.into() }
    }

    fn grp(min: Option<u64>, mode: InactivityMode, totp_h: u64, ws: bool, rs: &[&ProtectedResource]) -> ProtectionGroup {
        ProtectionGroup {
            id: Uuid::new_v4(),
            name: "g".into(),
            resource_ids: rs.iter().map(|r| r.id).collect(),
            inactivity_secs: min.map(|m| m * 60),
            mode,
            totp_threshold_secs: totp_h * 3600,
            lock_on_workstation_lock: ws,
            lock_on_suspend: ws,
        }
    }

    #[test]
    fn recurso_sem_grupo_fica_somente_manual_com_totp_em_24h() {
        let d = res("D", "D:");
        let p = &resolve(std::slice::from_ref(&d), &[])[&d.id];
        assert_eq!(p.inactivity_secs, None);
        assert_eq!(p.totp_threshold_secs, 24 * 3600);
        assert!(!p.lock_on_workstation_lock);
        assert!(p.source_groups.is_empty());
    }

    #[test]
    fn recurso_em_varios_grupos_recebe_a_combinacao_mais_restritiva() {
        let saf = res("Safynia", "D:");
        let env = res(".env", "E:");
        let dev = grp(Some(30), InactivityMode::ResourceIdle, 24, false, &[&saf, &env]);
        let cred = grp(Some(5), InactivityMode::SessionIdle, 8, true, &[&env]);
        let p = resolve(&[saf.clone(), env.clone()], &[dev, cred]);
        let e = &p[&env.id];
        assert_eq!(e.inactivity_secs, Some(300));
        assert_eq!(e.mode, InactivityMode::Combined);
        assert_eq!(e.totp_threshold_secs, 8 * 3600);
        assert!(e.lock_on_workstation_lock);
        assert_eq!(e.source_groups.len(), 2);
        let s = &p[&saf.id];
        assert_eq!(s.inactivity_secs, Some(1800));
        assert_eq!(s.mode, InactivityMode::ResourceIdle);
        assert!(!s.lock_on_workstation_lock);
    }

    #[test]
    fn resultado_nao_depende_da_ordem_dos_grupos() {
        let d = res("D", "D:");
        let a = grp(Some(10), InactivityMode::ResourceIdle, 12, false, &[&d]);
        let b = grp(Some(60), InactivityMode::SessionIdle, 48, true, &[&d]);
        let c = grp(None, InactivityMode::ResourceIdle, 24, false, &[&d]);
        let expected = resolve(std::slice::from_ref(&d), &[a.clone(), b.clone(), c.clone()])[&d.id].clone();
        for order in [[c.clone(), b.clone(), a.clone()], [b.clone(), a.clone(), c.clone()], [c.clone(), a.clone(), b.clone()]] {
            assert_eq!(resolve(std::slice::from_ref(&d), &order)[&d.id], expected);
        }
        assert_eq!(expected.inactivity_secs, Some(600));
        assert_eq!(expected.mode, InactivityMode::Combined);
        assert_eq!(expected.totp_threshold_secs, 12 * 3600);
    }

    #[test]
    fn grupo_desligado_nao_anula_o_temporizador_de_outro() {
        let d = res("D", "D:");
        let manual = grp(None, InactivityMode::SessionIdle, 24, false, &[&d]);
        let auto = grp(Some(10), InactivityMode::ResourceIdle, 24, false, &[&d]);
        let p = &resolve(std::slice::from_ref(&d), &[manual, auto])[&d.id];
        assert_eq!(p.inactivity_secs, Some(600));
        assert_eq!(p.mode, InactivityMode::ResourceIdle);
    }
}
