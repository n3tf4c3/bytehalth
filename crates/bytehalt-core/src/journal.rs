//! Histórico de eventos. Mensagens e detalhes são montados pelo ByteHalt e nunca contêm senhas,
//! códigos TOTP ou chaves de recuperação.

use crate::clock::UtcMillis;
use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use uuid::Uuid;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EventType {
    Locked,
    LockPostponed,
    LockRefused,
    LockFailed,
    Unlocked,
    UnlockDenied,
    ConfigurationChanged,
    ClockAnomaly,
    StateStoreError,
    ServiceStarted,
    ServiceStopped,
    Warning,
    /// Cofre de pasta (Fase 2): preparado, ativado, cancelado, reserva apagada ou falha.
    VaultChanged,
    VaultFailed,
}

impl EventType {
    pub fn code(self) -> i64 {
        self as i64
    }

    pub fn from_code(code: i64) -> Option<Self> {
        use EventType::*;
        [
            Locked,
            LockPostponed,
            LockRefused,
            LockFailed,
            Unlocked,
            UnlockDenied,
            ConfigurationChanged,
            ClockAnomaly,
            StateStoreError,
            ServiceStarted,
            ServiceStopped,
            Warning,
            VaultChanged,
            VaultFailed,
        ]
        .into_iter()
        .find(|t| t.code() == code)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Severity {
    Info,
    Warning,
    Error,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JournalEntry {
    pub at: UtcMillis,
    pub event: EventType,
    pub severity: Severity,
    pub resource_id: Option<Uuid>,
    pub message: String,
    pub detail: Option<String>,
}

pub trait Journal: Send + Sync {
    fn append(&self, entry: &JournalEntry) -> anyhow::Result<()>;
    /// Mais recentes primeiro.
    fn recent(&self, limit: usize) -> anyhow::Result<Vec<JournalEntry>>;
}

/// Grava no histórico sem deixar a falha do histórico impedir a operação principal.
pub fn append_or_log(journal: &dyn Journal, entry: JournalEntry) {
    if let Err(e) = journal.append(&entry) {
        eprintln!("Falha ao gravar histórico: {e:#}");
    }
}

#[derive(Default)]
pub struct InMemoryJournal {
    entries: Mutex<Vec<JournalEntry>>,
}

impl InMemoryJournal {
    pub fn entries(&self) -> Vec<JournalEntry> {
        self.entries.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
}

impl Journal for InMemoryJournal {
    fn append(&self, entry: &JournalEntry) -> anyhow::Result<()> {
        self.entries.lock().unwrap_or_else(|e| e.into_inner()).push(entry.clone());
        Ok(())
    }

    fn recent(&self, limit: usize) -> anyhow::Result<Vec<JournalEntry>> {
        Ok(self.entries.lock().unwrap_or_else(|e| e.into_inner()).iter().rev().take(limit).cloned().collect())
    }
}
