//! Temas claro e escuro do ByteHalt, com os mesmos tokens do termIAX/NetLane.
use gpui::{App, Global, Hsla};
use std::sync::Arc;

pub const UI_FONT: &str = "Segoe UI";

#[derive(Clone, Debug)]
pub struct Theme {
    pub chrome: Hsla,
    pub editor: Hsla,
    pub panel: Hsla,
    pub elevated: Hsla,
    pub hover: Hsla,
    pub selected: Hsla,
    pub border: Hsla,
    pub divider: Hsla,
    pub text: Hsla,
    pub text_strong: Hsla,
    pub text_muted: Hsla,
    pub text_faint: Hsla,
    pub text_disabled: Hsla,
    pub text_on_accent: Hsla,
    pub accent: Hsla,
    pub accent_soft: Hsla,
    pub focus: Hsla,
    pub selection: Hsla,
    pub ok: Hsla,
    pub ok_soft: Hsla,
    pub warning: Hsla,
    pub warning_soft: Hsla,
    pub error: Hsla,
    pub error_soft: Hsla,
}

fn hex(v: u32) -> Hsla {
    gpui::rgb(v).into()
}

impl Theme {
    pub fn light() -> Self {
        Self {
            chrome: hex(0xF4F6FA),
            editor: hex(0xFFFFFF),
            panel: hex(0xEBEEF4),
            elevated: hex(0xFFFFFF),
            hover: hex(0xE3E8F0),
            selected: hex(0xDCE6FB),
            border: hex(0xDDE3EC),
            divider: hex(0xE6EAF0),
            text: hex(0x1A2230),
            text_strong: hex(0x0B1220),
            text_muted: hex(0x56657A),
            text_faint: hex(0x7A8799),
            text_disabled: hex(0xA3AEBD),
            text_on_accent: hex(0xFFFFFF),
            accent: hex(0x2563EB),
            accent_soft: hex(0xE3ECFD),
            focus: hex(0x2563EB),
            selection: gpui::rgba(0x2563EB40).into(),
            ok: hex(0x15803D),
            ok_soft: hex(0xE2F5E8),
            warning: hex(0xB45309),
            warning_soft: hex(0xFDF0DC),
            error: hex(0xC62828),
            error_soft: hex(0xFCE6E6),
        }
    }

    pub fn dark() -> Self {
        Self {
            chrome: hex(0x10151C),
            editor: hex(0x1A222D),
            panel: hex(0x151B24),
            elevated: hex(0x202A36),
            hover: hex(0x243041),
            selected: hex(0x1E2D4A),
            border: hex(0x2A3644),
            divider: hex(0x222C38),
            text: hex(0xE6EDF5),
            text_strong: hex(0xFFFFFF),
            text_muted: hex(0x9AAABE),
            text_faint: hex(0x7D8DA2),
            text_disabled: hex(0x5B6878),
            text_on_accent: hex(0x0B1220),
            accent: hex(0x6E9BFF),
            accent_soft: hex(0x1E2D4A),
            focus: hex(0x6E9BFF),
            selection: gpui::rgba(0x6E9BFF55).into(),
            ok: hex(0x4ADE80),
            ok_soft: hex(0x14301F),
            warning: hex(0xFBBF24),
            warning_soft: hex(0x3A2C10),
            error: hex(0xF87171),
            error_soft: hex(0x3B1A1A),
        }
    }
}

pub struct Themes {
    pub active: Arc<Theme>,
}

impl Global for Themes {}

impl Themes {
    pub fn new(dark: bool) -> Self {
        Self { active: Arc::new(if dark { Theme::dark() } else { Theme::light() }) }
    }

    pub fn set_dark(cx: &mut App, dark: bool) {
        cx.global_mut::<Self>().active = Arc::new(if dark { Theme::dark() } else { Theme::light() });
        cx.refresh_windows();
    }
}

pub trait ActiveTheme {
    fn theme(&self) -> &Arc<Theme>;
}

impl ActiveTheme for App {
    fn theme(&self) -> &Arc<Theme> {
        &self.global::<Themes>().active
    }
}
