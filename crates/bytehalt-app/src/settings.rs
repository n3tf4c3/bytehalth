//! Preferências da interface em %LOCALAPPDATA%\ByteHalt\ui-settings.json (nada secreto).
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct UiSettings {
    pub dark: bool,
    pub notifications: bool,
    pub close_to_tray: bool,
    /// Aviso "o ByteHalt continua na bandeja" já mostrado uma vez.
    pub tray_hint_shown: bool,
}

impl Default for UiSettings {
    fn default() -> Self {
        Self { dark: false, notifications: true, close_to_tray: true, tray_hint_shown: false }
    }
}

pub struct SettingsFile {
    path: Option<PathBuf>,
}

impl SettingsFile {
    pub fn user() -> Self {
        Self { path: std::env::var_os("LOCALAPPDATA").map(|p| PathBuf::from(p).join("ByteHalt").join("ui-settings.json")) }
    }

    #[cfg_attr(not(feature = "gui-test"), allow(dead_code))]
    pub fn at(path: PathBuf) -> Self {
        Self { path: Some(path) }
    }

    pub fn load(&self) -> UiSettings {
        self.path
            .as_ref()
            .and_then(|p| std::fs::read(p).ok())
            .and_then(|b| serde_json::from_slice(b.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(&b)).ok())
            .unwrap_or_default()
    }

    pub fn save(&self, s: &UiSettings) -> anyhow::Result<()> {
        let Some(path) = &self.path else { return Ok(()) };
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(s)?)?;
        std::fs::rename(tmp, path)?;
        Ok(())
    }
}
