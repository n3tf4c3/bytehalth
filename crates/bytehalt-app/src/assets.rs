//! Ícones embutidos (Material Symbols, Apache-2.0: assets/icons/LICENSE; e desenhos próprios).
use anyhow::Result;
use gpui::{AssetSource, SharedString};
use std::borrow::Cow;

pub struct Assets;

macro_rules! icons {
    ($($name:literal),* $(,)?) => {
        &[$((concat!("icons/", $name, ".svg"), include_bytes!(concat!("../../../assets/icons/", $name, ".svg")))),*]
    };
}

/// Logo da marca (gerado por scripts/brand/Build-Icons.ps1 a partir de assets/brand/bytehalt-source.png).
pub const BRAND_LOGO: &str = "brand/bytehalt-64.png";
static BRAND: &[(&str, &[u8])] = &[(BRAND_LOGO, include_bytes!("../../../assets/brand/bytehalt-64.png"))];

static FILES: &[(&str, &[u8])] = icons![
    "add",
    "check",
    "close",
    "delete",
    "info",
    "refresh",
    "settings",
    "warning",
    "visibility",
    "check_box",
    "check_box_outline_blank",
    "power_settings_new",
    "desktop_windows",
    "folder_open",
    "tune",
    "menu",
    "palette",
    "lock",
    "lock_open",
    "shield",
    "history",
    "storage",
    "dashboard",
    "layers",
];

impl AssetSource for Assets {
    fn load(&self, path: &str) -> Result<Option<Cow<'static, [u8]>>> {
        Ok(FILES.iter().chain(BRAND).find(|(n, _)| *n == path).map(|(_, d)| Cow::Borrowed(*d)))
    }

    fn list(&self, path: &str) -> Result<Vec<SharedString>> {
        Ok(FILES.iter().chain(BRAND).filter(|(n, _)| n.starts_with(path)).map(|(n, _)| SharedString::new_static(n)).collect())
    }
}
