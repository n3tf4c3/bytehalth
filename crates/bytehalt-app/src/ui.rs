//! Componentes visuais compactos (densidade ajustada: a v0.1 WPF ficou grande demais).
use crate::present::Tone;
use crate::theme::{ActiveTheme, Theme};
use gpui::{App, Div, ElementId, FontWeight, Hsla, IntoElement, SharedString, Stateful, div, prelude::*, px, svg};

pub fn icon(name: &'static str, size: f32, color: Hsla) -> impl IntoElement {
    svg().path(SharedString::new_static(icon_path(name))).size(px(size)).flex_none().text_color(color)
}

fn icon_path(name: &str) -> &'static str {
    match name {
        "add" => "icons/add.svg",
        "check" => "icons/check.svg",
        "close" => "icons/close.svg",
        "delete" => "icons/delete.svg",
        "refresh" => "icons/refresh.svg",
        "settings" => "icons/settings.svg",
        "warning" => "icons/warning.svg",
        "check_box" => "icons/check_box.svg",
        "check_box_outline_blank" => "icons/check_box_outline_blank.svg",
        "lock" => "icons/lock.svg",
        "lock_open" => "icons/lock_open.svg",
        "shield" => "icons/shield.svg",
        "history" => "icons/history.svg",
        "storage" => "icons/storage.svg",
        "dashboard" => "icons/dashboard.svg",
        "layers" => "icons/layers.svg",
        "folder_open" => "icons/folder_open.svg",
        "palette" => "icons/palette.svg",
        _ => "icons/info.svg",
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Primary,
    Secondary,
    Danger,
}

pub fn button(id: impl Into<ElementId>, label: impl Into<SharedString>, kind: Kind, enabled: bool, cx: &App) -> Stateful<Div> {
    let t = cx.theme();
    let (bg, fg, border) = match (kind, enabled) {
        (_, false) => (t.hover, t.text_disabled, t.border),
        (Kind::Primary, true) => (t.accent, t.text_on_accent, t.accent),
        (Kind::Secondary, true) => (t.elevated, t.text, t.border),
        (Kind::Danger, true) => (t.elevated, t.error, t.border),
    };
    let hover = if kind == Kind::Primary { t.focus } else { t.hover };
    div()
        .id(id)
        .h(px(25.))
        .px(px(10.))
        .flex()
        .flex_none()
        .items_center()
        .justify_center()
        .rounded(px(5.))
        .border_1()
        .border_color(border)
        .bg(bg)
        .text_color(fg)
        .text_size(px(12.))
        .font_weight(FontWeight::MEDIUM)
        .when(enabled, |d| d.cursor_pointer().hover(move |s| s.bg(hover)))
        .child(label.into())
}

pub fn card(t: &Theme) -> Div {
    div().p(px(11.)).rounded(px(7.)).bg(t.editor).border_1().border_color(t.border).flex().flex_col().gap(px(6.)).min_w(px(0.))
}

pub fn title(text: impl Into<SharedString>, t: &Theme) -> Div {
    div().text_size(px(17.)).font_weight(FontWeight::SEMIBOLD).text_color(t.text_strong).child(text.into())
}

pub fn section(text: impl Into<SharedString>, t: &Theme) -> Div {
    div().text_size(px(13.)).font_weight(FontWeight::SEMIBOLD).text_color(t.text_strong).child(text.into())
}

pub fn muted(text: impl Into<SharedString>, t: &Theme) -> Div {
    div().text_size(px(12.)).text_color(t.text_muted).child(text.into())
}

pub fn tone_colors(tone: Tone, t: &Theme) -> (Hsla, Hsla) {
    match tone {
        Tone::Good => (t.ok, t.ok_soft),
        Tone::Warning => (t.warning, t.warning_soft),
        Tone::Danger => (t.error, t.error_soft),
        Tone::Neutral => (t.text_muted, t.hover),
    }
}

pub fn pill(text: impl Into<SharedString>, tone: Tone, t: &Theme) -> Div {
    let (fg, bg) = tone_colors(tone, t);
    div().px(px(8.)).py(px(2.)).rounded(px(10.)).bg(bg).text_color(fg).text_size(px(11.5)).font_weight(FontWeight::SEMIBOLD).flex_none().child(text.into())
}

pub fn notice(text: impl Into<SharedString>, tone: Tone, t: &Theme) -> Div {
    let (fg, bg) = tone_colors(tone, t);
    let _ = fg;
    let bg = if tone == Tone::Neutral { t.accent_soft } else { bg };
    div().px(px(10.)).py(px(6.)).rounded(px(6.)).bg(bg).text_color(t.text).text_size(px(12.5)).child(text.into())
}

pub fn checkbox(id: impl Into<ElementId>, label: impl Into<SharedString>, checked: bool, cx: &App) -> Stateful<Div> {
    let t = cx.theme();
    div()
        .id(id)
        .flex()
        .items_center()
        .gap(px(6.))
        .cursor_pointer()
        .text_size(px(13.))
        .child(icon(if checked { "check_box" } else { "check_box_outline_blank" }, 18., if checked { t.accent } else { t.text_muted }))
        .child(label.into())
}

pub fn chip(id: impl Into<ElementId>, label: impl Into<SharedString>, selected: bool, cx: &App) -> Stateful<Div> {
    let t = cx.theme();
    let hover = t.hover;
    div()
        .id(id)
        .h(px(23.))
        .px(px(9.))
        .flex()
        .items_center()
        .rounded(px(13.))
        .border_1()
        .text_size(px(12.5))
        .cursor_pointer()
        .border_color(if selected { t.accent } else { t.border })
        .bg(if selected { t.accent_soft } else { t.editor })
        .text_color(if selected { t.accent } else { t.text })
        .when(!selected, move |d| d.hover(move |s| s.bg(hover)))
        .child(label.into())
}

/// Campo com rótulo acima.
pub fn field(label: &'static str, input: impl IntoElement, t: &Theme) -> Div {
    div()
        .flex()
        .flex_col()
        .gap(px(4.))
        .child(muted(label, t))
        .child(div().h(px(26.)).px(px(7.)).flex().items_center().rounded(px(5.)).border_1().border_color(t.border).bg(t.editor).child(input))
}
