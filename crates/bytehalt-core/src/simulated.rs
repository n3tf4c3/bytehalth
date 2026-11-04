//! Volumes simulados para testes e o modo --simulate do serviço (Sandbox sem BitLocker).
//! Não tocam em discos. A senha de desbloqueio é fictícia.

use crate::locking::{BusyProbe, LockAttempt, LockOutcome, LockState, ResourceLocker, ResourceStatus, UnlockAttempt, UnlockOutcome};
use crate::model::{ProtectedResource, ResourceKind};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;
use uuid::Uuid;

pub const TEST_PASSPHRASE: &str = "bytehalt-teste";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct SimulatedVolume {
    pub present: bool,
    pub protected: bool,
    pub locked: bool,
    pub system: bool,
    pub auto_unlock: bool,
    /// > 0 faz o bloqueio normal falhar como ocupado.
    pub open_handles: u32,
    pub fail_next_lock: bool,
    /// Aceita o pedido mas não bloqueia (testa a conferência pós-operação).
    pub ignore_lock: bool,
    pub lock_calls: u32,
}

impl Default for SimulatedVolume {
    fn default() -> Self {
        Self {
            present: true,
            protected: true,
            locked: false,
            system: false,
            auto_unlock: false,
            open_handles: 0,
            fail_next_lock: false,
            ignore_lock: false,
            lock_calls: 0,
        }
    }
}

/// Com `state_path`, o estado "bloqueado" sobrevive ao reinício do serviço (testes de retomada).
pub struct SimulatedLocker {
    kind: ResourceKind,
    system_drive: Option<String>,
    state_path: Option<PathBuf>,
    volumes: Mutex<HashMap<Uuid, SimulatedVolume>>,
}

impl SimulatedLocker {
    pub fn new(kind: ResourceKind, system_drive: Option<&str>, state_path: Option<PathBuf>) -> Self {
        let volumes = state_path
            .as_ref()
            .and_then(|p| std::fs::read(p).ok())
            .and_then(|b| serde_json::from_slice::<Vec<Uuid>>(&b).ok())
            .map(|ids| ids.into_iter().map(|id| (id, SimulatedVolume { locked: true, ..Default::default() })).collect())
            .unwrap_or_default();
        Self { kind, system_drive: system_drive.map(|s| s.trim_end_matches('\\').to_uppercase()), state_path, volumes: Mutex::new(volumes) }
    }

    /// Altera um volume simulado e persiste.
    pub fn with_volume<R>(&self, id: Uuid, f: impl FnOnce(&mut SimulatedVolume) -> R) -> R {
        let mut v = self.volumes.lock().unwrap_or_else(|e| e.into_inner());
        let out = f(v.entry(id).or_default());
        self.save(&v);
        out
    }

    pub fn volume(&self, id: Uuid) -> SimulatedVolume {
        self.volumes.lock().unwrap_or_else(|e| e.into_inner()).get(&id).cloned().unwrap_or_default()
    }

    fn save(&self, v: &HashMap<Uuid, SimulatedVolume>) {
        if let Some(path) = &self.state_path {
            let locked: Vec<Uuid> = v.iter().filter(|(_, x)| x.locked).map(|(id, _)| *id).collect();
            let tmp = path.with_extension("tmp");
            if std::fs::write(&tmp, serde_json::to_vec(&locked).unwrap_or_default()).is_ok() {
                let _ = std::fs::rename(&tmp, path);
            }
        }
    }

    fn is_system(&self, r: &ProtectedResource, v: &SimulatedVolume) -> bool {
        v.system || self.system_drive.as_deref() == Some(r.target.to_uppercase().as_str())
    }
}

impl ResourceLocker for SimulatedLocker {
    fn kind(&self) -> ResourceKind {
        self.kind
    }

    fn status(&self, r: &ProtectedResource) -> ResourceStatus {
        let v = self.volume(r.id);
        if !v.present {
            return ResourceStatus::unavailable("Volume simulado ausente.");
        }
        let state = if !v.protected {
            LockState::NotProtected
        } else if v.locked {
            LockState::Locked
        } else {
            LockState::Unlocked
        };
        ResourceStatus { state, is_system_volume: self.is_system(r, &v), auto_unlock: v.auto_unlock, detail: Some("Simulado".into()) }
    }

    fn lock(&self, r: &ProtectedResource) -> LockAttempt {
        let system = self.is_system(r, &self.volume(r.id));
        self.with_volume(r.id, |v| {
            v.lock_calls += 1;
            if system {
                return LockAttempt { outcome: LockOutcome::Refused, detail: Some("A unidade do sistema em execução não pode ser bloqueada.".into()) };
            }
            if v.fail_next_lock {
                v.fail_next_lock = false;
                return LockAttempt { outcome: LockOutcome::Failed, detail: Some("Falha simulada (0x80004005).".into()) };
            }
            if v.open_handles > 0 {
                return LockAttempt { outcome: LockOutcome::Postponed, detail: Some("Há arquivos abertos no volume (simulado).".into()) };
            }
            if !v.ignore_lock {
                v.locked = true;
            }
            LockAttempt { outcome: LockOutcome::Locked, detail: None }
        })
    }

    fn unlock(&self, r: &ProtectedResource, passphrase: &str) -> UnlockAttempt {
        self.with_volume(r.id, |v| {
            if !v.present {
                return UnlockAttempt { outcome: UnlockOutcome::Unavailable, detail: Some("Volume simulado ausente.".into()) };
            }
            if !v.locked {
                return UnlockAttempt { outcome: UnlockOutcome::AlreadyUnlocked, detail: None };
            }
            // Comparação em tempo constante para entradas de mesmo tamanho.
            let ok = passphrase.len() == TEST_PASSPHRASE.len() && passphrase.bytes().zip(TEST_PASSPHRASE.bytes()).fold(0u8, |acc, (a, b)| acc | (a ^ b)) == 0;
            if !ok {
                return UnlockAttempt { outcome: UnlockOutcome::BadCredential, detail: None };
            }
            v.locked = false;
            UnlockAttempt { outcome: UnlockOutcome::Unlocked, detail: None }
        })
    }
}

#[derive(Default)]
pub struct SimulatedBusy {
    busy: Mutex<HashMap<Uuid, Vec<String>>>,
}

impl SimulatedBusy {
    pub fn set(&self, id: Uuid, holders: &[&str]) {
        self.busy.lock().unwrap_or_else(|e| e.into_inner()).insert(id, holders.iter().map(|s| s.to_string()).collect());
    }

    pub fn clear(&self, id: Uuid) {
        self.busy.lock().unwrap_or_else(|e| e.into_inner()).remove(&id);
    }
}

impl BusyProbe for SimulatedBusy {
    fn holders(&self, r: &ProtectedResource) -> Option<Vec<String>> {
        self.busy.lock().unwrap_or_else(|e| e.into_inner()).get(&r.id).cloned()
    }
}
