//! Banco SQLite de dados não secretos: recursos, grupos, cofres, configurações e histórico. O registro
//! do cofre não contém senha nem chave de recuperação.

use bytehalt_core::journal::{EventType, Journal, JournalEntry, Severity};
use bytehalt_core::model::{ConfigRepository, InactivityMode, ProtectedResource, ProtectionGroup, ResourceKind};
use rusqlite::{Connection, OptionalExtension, params};
use std::path::Path;
use std::sync::Mutex;
use uuid::Uuid;

pub const JOURNAL_RETENTION: i64 = 10_000;

pub struct SqliteStore {
    conn: Mutex<Connection>,
}

fn kind_code(k: ResourceKind) -> i64 {
    match k {
        ResourceKind::BitLockerVolume => 1,
        ResourceKind::Vault => 2,
    }
}

fn mode_code(m: InactivityMode) -> i64 {
    match m {
        InactivityMode::ResourceIdle => 1,
        InactivityMode::SessionIdle => 2,
        InactivityMode::Combined => 3,
    }
}

fn severity_code(s: Severity) -> i64 {
    match s {
        Severity::Info => 1,
        Severity::Warning => 2,
        Severity::Error => 3,
    }
}

impl SqliteStore {
    pub fn open(path: &Path) -> anyhow::Result<Self> {
        let conn = Connection::open(path)?;
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA foreign_keys = ON;
             CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL);
             CREATE TABLE IF NOT EXISTS resources (id TEXT PRIMARY KEY, display_name TEXT NOT NULL, kind INTEGER NOT NULL, target TEXT NOT NULL);
             CREATE TABLE IF NOT EXISTS groups (id TEXT PRIMARY KEY, name TEXT NOT NULL, inactivity_secs INTEGER NULL, mode INTEGER NOT NULL,
                 totp_threshold_secs INTEGER NOT NULL, lock_on_workstation_lock INTEGER NOT NULL);
             CREATE TABLE IF NOT EXISTS group_resources (group_id TEXT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
                 resource_id TEXT NOT NULL REFERENCES resources(id) ON DELETE CASCADE, position INTEGER NOT NULL, PRIMARY KEY (group_id, resource_id));
             CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
             CREATE TABLE IF NOT EXISTS journal (id INTEGER PRIMARY KEY AUTOINCREMENT, at INTEGER NOT NULL, event INTEGER NOT NULL,
                 severity INTEGER NOT NULL, resource_id TEXT NULL, message TEXT NOT NULL, detail TEXT NULL);
             CREATE TABLE IF NOT EXISTS vaults (id TEXT PRIMARY KEY, data TEXT NOT NULL);
             INSERT INTO schema_version (version) SELECT 1 WHERE NOT EXISTS (SELECT 1 FROM schema_version);",
        )?;
        Ok(Self { conn: Mutex::new(conn) })
    }

    fn conn(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.conn.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl bytehalt_core::vault::VaultRepository for SqliteStore {
    fn vaults(&self) -> anyhow::Result<Vec<bytehalt_core::vault::VaultRecord>> {
        let conn = self.conn();
        let mut stmt = conn.prepare("SELECT data FROM vaults")?;
        let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
        rows.map(|r| Ok(serde_json::from_str(&r?)?)).collect()
    }

    fn upsert_vault(&self, v: &bytehalt_core::vault::VaultRecord) -> anyhow::Result<()> {
        self.conn().execute(
            "INSERT INTO vaults (id, data) VALUES (?1, ?2) ON CONFLICT(id) DO UPDATE SET data = excluded.data",
            params![v.id.to_string(), serde_json::to_string(v)?],
        )?;
        Ok(())
    }

    fn delete_vault(&self, id: Uuid) -> anyhow::Result<()> {
        self.conn().execute("DELETE FROM vaults WHERE id = ?1", params![id.to_string()])?;
        Ok(())
    }
}

fn parse_id(s: String) -> rusqlite::Result<Uuid> {
    Uuid::parse_str(&s).map_err(|e| rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e)))
}

impl ConfigRepository for SqliteStore {
    fn resources(&self) -> anyhow::Result<Vec<ProtectedResource>> {
        let c = self.conn();
        let mut st = c.prepare("SELECT id, display_name, kind, target FROM resources ORDER BY display_name COLLATE NOCASE")?;
        let rows = st.query_map([], |r| {
            Ok(ProtectedResource {
                id: parse_id(r.get(0)?)?,
                display_name: r.get(1)?,
                kind: if r.get::<_, i64>(2)? == 2 { ResourceKind::Vault } else { ResourceKind::BitLockerVolume },
                target: r.get(3)?,
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    fn upsert_resource(&self, r: &ProtectedResource) -> anyhow::Result<()> {
        self.conn().execute(
            "INSERT INTO resources (id, display_name, kind, target) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(id) DO UPDATE SET display_name = excluded.display_name, kind = excluded.kind, target = excluded.target",
            params![r.id.to_string(), r.display_name, kind_code(r.kind), r.target],
        )?;
        Ok(())
    }

    fn delete_resource(&self, id: Uuid) -> anyhow::Result<()> {
        self.conn().execute("DELETE FROM resources WHERE id = ?1", params![id.to_string()])?;
        Ok(())
    }

    fn groups(&self) -> anyhow::Result<Vec<ProtectionGroup>> {
        let c = self.conn();
        let mut members: std::collections::HashMap<Uuid, Vec<Uuid>> = std::collections::HashMap::new();
        let mut st = c.prepare("SELECT group_id, resource_id FROM group_resources ORDER BY group_id, position")?;
        for row in st.query_map([], |r| Ok((parse_id(r.get(0)?)?, parse_id(r.get(1)?)?)))? {
            let (g, r) = row?;
            members.entry(g).or_default().push(r);
        }
        let mut st =
            c.prepare("SELECT id, name, inactivity_secs, mode, totp_threshold_secs, lock_on_workstation_lock FROM groups ORDER BY name COLLATE NOCASE")?;
        let rows = st.query_map([], |r| {
            let id = parse_id(r.get(0)?)?;
            Ok(ProtectionGroup {
                id,
                name: r.get(1)?,
                resource_ids: Vec::new(),
                inactivity_secs: r.get::<_, Option<i64>>(2)?.map(|v| v as u64),
                mode: match r.get::<_, i64>(3)? {
                    2 => InactivityMode::SessionIdle,
                    3 => InactivityMode::Combined,
                    _ => InactivityMode::ResourceIdle,
                },
                totp_threshold_secs: r.get::<_, i64>(4)? as u64,
                lock_on_workstation_lock: r.get::<_, i64>(5)? != 0,
            })
        })?;
        let mut groups: Vec<ProtectionGroup> = rows.collect::<Result<_, _>>()?;
        for g in &mut groups {
            g.resource_ids = members.remove(&g.id).unwrap_or_default();
        }
        Ok(groups)
    }

    fn upsert_group(&self, g: &ProtectionGroup) -> anyhow::Result<()> {
        let mut c = self.conn();
        let tx = c.transaction()?;
        tx.execute(
            "INSERT INTO groups (id, name, inactivity_secs, mode, totp_threshold_secs, lock_on_workstation_lock) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(id) DO UPDATE SET name = excluded.name, inactivity_secs = excluded.inactivity_secs, mode = excluded.mode,
                 totp_threshold_secs = excluded.totp_threshold_secs, lock_on_workstation_lock = excluded.lock_on_workstation_lock",
            params![
                g.id.to_string(),
                g.name,
                g.inactivity_secs.map(|v| v as i64),
                mode_code(g.mode),
                g.totp_threshold_secs as i64,
                i64::from(g.lock_on_workstation_lock)
            ],
        )?;
        tx.execute("DELETE FROM group_resources WHERE group_id = ?1", params![g.id.to_string()])?;
        for (pos, r) in g.resource_ids.iter().enumerate() {
            tx.execute(
                "INSERT INTO group_resources (group_id, resource_id, position) VALUES (?1, ?2, ?3)",
                params![g.id.to_string(), r.to_string(), pos as i64],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    fn delete_group(&self, id: Uuid) -> anyhow::Result<()> {
        self.conn().execute("DELETE FROM groups WHERE id = ?1", params![id.to_string()])?;
        Ok(())
    }

    fn setting(&self, key: &str) -> anyhow::Result<Option<String>> {
        Ok(self.conn().query_row("SELECT value FROM settings WHERE key = ?1", params![key], |r| r.get(0)).optional()?)
    }

    fn set_setting(&self, key: &str, value: &str) -> anyhow::Result<()> {
        self.conn().execute("INSERT INTO settings (key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value = excluded.value", params![key, value])?;
        Ok(())
    }
}

impl Journal for SqliteStore {
    fn append(&self, e: &JournalEntry) -> anyhow::Result<()> {
        let c = self.conn();
        c.execute(
            "INSERT INTO journal (at, event, severity, resource_id, message, detail) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![e.at, e.event.code(), severity_code(e.severity), e.resource_id.map(|r| r.to_string()), e.message, e.detail],
        )?;
        c.execute("DELETE FROM journal WHERE id <= (SELECT MAX(id) FROM journal) - ?1", params![JOURNAL_RETENTION])?;
        Ok(())
    }

    fn recent(&self, limit: usize) -> anyhow::Result<Vec<JournalEntry>> {
        let c = self.conn();
        let mut st = c.prepare("SELECT at, event, severity, resource_id, message, detail FROM journal ORDER BY id DESC LIMIT ?1")?;
        let rows = st.query_map(params![limit.clamp(1, 1000) as i64], |r| {
            Ok(JournalEntry {
                at: r.get(0)?,
                event: EventType::from_code(r.get(1)?).unwrap_or(EventType::Warning),
                severity: match r.get::<_, i64>(2)? {
                    2 => Severity::Warning,
                    3 => Severity::Error,
                    _ => Severity::Info,
                },
                resource_id: r.get::<_, Option<String>>(3)?.map(parse_id).transpose()?,
                message: r.get(4)?,
                detail: r.get(5)?,
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn res(name: &str, letter: &str) -> ProtectedResource {
        ProtectedResource { id: Uuid::new_v4(), display_name: name.into(), kind: ResourceKind::BitLockerVolume, target: letter.into() }
    }

    #[test]
    fn recursos_e_grupos_sobrevivem_a_reabertura() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("b.db");
        let (d, e) = (res("Unidade D:", "D:"), res("Unidade E:", "E:"));
        let g = ProtectionGroup {
            id: Uuid::new_v4(),
            name: "Discos".into(),
            resource_ids: vec![e.id, d.id],
            inactivity_secs: Some(900),
            mode: InactivityMode::Combined,
            totp_threshold_secs: 12 * 3600,
            lock_on_workstation_lock: true,
        };
        let manual = ProtectionGroup {
            id: Uuid::new_v4(),
            name: "Manual".into(),
            resource_ids: vec![d.id],
            inactivity_secs: None,
            mode: InactivityMode::ResourceIdle,
            totp_threshold_secs: 86_400,
            lock_on_workstation_lock: false,
        };
        {
            let s = SqliteStore::open(&db).unwrap();
            s.upsert_resource(&d).unwrap();
            s.upsert_resource(&e).unwrap();
            s.upsert_group(&g).unwrap();
            s.upsert_group(&manual).unwrap();
        }
        let s = SqliteStore::open(&db).unwrap();
        assert_eq!(s.resources().unwrap(), vec![d.clone(), e.clone()]);
        let groups = s.groups().unwrap();
        assert_eq!(groups.iter().find(|x| x.id == g.id).unwrap(), &g);
        assert_eq!(groups.iter().find(|x| x.id == manual.id).unwrap().inactivity_secs, None);
        s.upsert_group(&ProtectionGroup { name: "G2".into(), resource_ids: vec![e.id], ..g.clone() }).unwrap();
        assert_eq!(s.groups().unwrap().iter().find(|x| x.id == g.id).unwrap().resource_ids, vec![e.id]);
        s.delete_resource(e.id).unwrap();
        assert!(s.groups().unwrap().iter().find(|x| x.id == g.id).unwrap().resource_ids.is_empty());
    }

    #[test]
    fn historico_mais_recente_primeiro_com_e_sem_recurso() {
        let dir = tempfile::tempdir().unwrap();
        let s = SqliteStore::open(&dir.path().join("b.db")).unwrap();
        let rid = Uuid::new_v4();
        for i in 0..5 {
            s.append(&JournalEntry {
                at: 1000 + i,
                event: EventType::Locked,
                severity: Severity::Info,
                resource_id: (i % 2 == 0).then_some(rid),
                message: format!("evento {i}"),
                detail: (i % 2 == 1).then(|| "detalhe".into()),
            })
            .unwrap();
        }
        let r = s.recent(3).unwrap();
        assert_eq!(r.iter().map(|e| e.message.as_str()).collect::<Vec<_>>(), ["evento 4", "evento 3", "evento 2"]);
        assert_eq!(r[0].resource_id, Some(rid));
        assert_eq!(r[1].detail.as_deref(), Some("detalhe"));
        assert_eq!(r[0].at, 1004);
    }

    #[test]
    fn configuracoes_simples() {
        let dir = tempfile::tempdir().unwrap();
        let s = SqliteStore::open(&dir.path().join("b.db")).unwrap();
        assert_eq!(s.setting("owner_sid").unwrap(), None);
        s.set_setting("owner_sid", "S-1-5-21-1").unwrap();
        s.set_setting("owner_sid", "S-1-5-21-2").unwrap();
        assert_eq!(s.setting("owner_sid").unwrap().as_deref(), Some("S-1-5-21-2"));
    }
}
