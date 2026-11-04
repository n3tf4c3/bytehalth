//! Janela principal: navegação, telas, diálogos, atualização periódica e bandeja.

use crate::account::{Account, CodesNotice, MasterPrompt};
use crate::client::{Client, Failure};
use crate::present::{self, CUSTOM, OFF, ResourceRow, TIMEOUT_CHOICES, Tone};
use crate::scrollbar::ScrollbarExt;
use crate::settings::{SettingsFile, UiSettings};
use crate::text_input::TextInput;
use crate::theme::{ActiveTheme, Themes, UI_FONT};
use crate::tray::{Level, Panel, Tray, TrayAction, TrayIcon, TrayState};
use crate::ui::{self, Kind};
use crate::vaults::{RecoveryNotice, VaultForm};
use bytehalt_core::auth::Requirement;
use bytehalt_core::clock::UtcMillis;
use bytehalt_core::engine::Snapshot;
use bytehalt_core::journal::{JournalEntry, Severity};
use bytehalt_core::locking::LockState;
use bytehalt_core::master::AuthStatus;
use bytehalt_core::model::{InactivityMode, ProtectedResource, ProtectionGroup, ResourceKind};
use bytehalt_core::vault_manager::VaultView;
use bytehalt_ipc::{Command, Reply, VolumeInfo};
use gpui::{AnyElement, Context, Entity, FontWeight, IntoElement, Render, SharedString, Window, div, img, prelude::*, px};
use std::collections::HashSet;
use std::time::Duration;
use uuid::Uuid;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Page {
    Dashboard,
    Drives,
    Vaults,
    Groups,
    Security,
    History,
    Settings,
}

pub const PAGES: [(Page, &str, &str); 7] = [
    (Page::Dashboard, "Dashboard", "dashboard"),
    (Page::Drives, "Unidades", "storage"),
    (Page::Vaults, "Cofres", "lock"),
    (Page::Groups, "Grupos", "layers"),
    (Page::Security, "Segurança", "shield"),
    (Page::History, "Histórico", "history"),
    (Page::Settings, "Configurações", "settings"),
];

pub struct GroupEditor {
    pub id: Uuid,
    pub name: Entity<TextInput>,
    pub timeout: usize,
    pub custom: Entity<TextInput>,
    pub mode: InactivityMode,
    pub totp_hours: Entity<TextInput>,
    pub ws_lock: bool,
    pub suspend_lock: bool,
    pub selected: HashSet<Uuid>,
    pub error: Option<String>,
}

pub struct UnlockDialog {
    pub id: Uuid,
    pub name: String,
    pub requirement: Option<Requirement>,
    pub pass: Entity<TextInput>,
    pub totp: Entity<TextInput>,
    pub message: Option<String>,
    pub busy: bool,
}

#[derive(Clone)]
pub enum Confirm {
    RemoveResource(Uuid, String),
    DeleteGroup(Uuid, String),
    /// Cofre: (id, nome, caminho original).
    SwapVault(Uuid, String, String),
    DiscardVault(Uuid, String),
    /// Cofre: (id, nome, caminho da reserva).
    DeleteReserve(Uuid, String, String),
    /// Cofre: (id, nome, caminho original).
    RemoveVault(Uuid, String, String),
}

pub struct Workspace {
    pub client: Client,
    pub page: Page,
    pub connected: Option<bool>,
    pub connection: String,
    pub snapshot: Option<Snapshot>,
    pub history: Vec<JournalEntry>,
    pub notified_until: Option<UtcMillis>,
    pub status: Option<String>,
    pub volumes: Vec<VolumeInfo>,
    pub volume_warning: Option<String>,
    pub selected_volume: Option<String>,
    pub drive_name: Entity<TextInput>,
    pub drives_message: Option<String>,
    pub editor: Option<GroupEditor>,
    pub groups_message: Option<String>,
    pub requirements: Vec<(String, Requirement)>,
    pub only_problems: bool,
    pub unlock: Option<UnlockDialog>,
    pub confirm: Option<Confirm>,
    pub settings: UiSettings,
    pub settings_file: SettingsFile,
    pub settings_message: Option<String>,
    pub autostart: bool,
    /// Abertura automática gravada pelo instalador para todos os usuários (HKLM).
    pub machine_autostart: bool,
    pub tray: Option<Tray>,
    pub panel: Option<Panel>,
    pub tray_checked: std::time::Instant,
    /// Registro de notificações mostradas (prova visual e diagnóstico).
    pub shown_notifications: Vec<String>,
    pub vaults: Vec<VaultView>,
    pub vault_form: VaultForm,
    pub vault_message: Option<String>,
    pub recovery: Option<RecoveryNotice>,
    pub auth: Option<AuthStatus>,
    pub account: Account,
    pub master: Option<MasterPrompt>,
    pub codes: Option<CodesNotice>,
}

const AUTOSTART_VALUE: &str = "ByteHalt";

impl Workspace {
    pub fn new(client: Client, settings_file: SettingsFile, cx: &mut Context<Self>) -> Self {
        let settings = settings_file.load();
        let ws = Self {
            client,
            page: Page::Dashboard,
            connected: None,
            connection: "Conectando ao serviço…".into(),
            snapshot: None,
            history: Vec::new(),
            notified_until: None,
            status: None,
            volumes: Vec::new(),
            volume_warning: None,
            selected_volume: None,
            drive_name: cx.new(|cx| TextInput::new("", "Nome de exibição (opcional)", cx)),
            drives_message: None,
            editor: None,
            groups_message: None,
            requirements: Vec::new(),
            only_problems: false,
            unlock: None,
            confirm: None,
            settings,
            settings_file,
            settings_message: None,
            autostart: bytehalt_windows::user::autostart_enabled(AUTOSTART_VALUE),
            machine_autostart: bytehalt_windows::user::machine_autostart_enabled(AUTOSTART_VALUE),
            tray: None,
            panel: None,
            tray_checked: std::time::Instant::now(),
            shown_notifications: Vec::new(),
            vaults: Vec::new(),
            vault_form: VaultForm::new(cx),
            vault_message: None,
            recovery: None,
            auth: None,
            account: Account::new(cx),
            master: None,
            codes: None,
        };
        cx.spawn(async move |this, cx| {
            loop {
                if this.update(cx, |ws, cx| ws.refresh(cx)).is_err() {
                    break;
                }
                cx.background_executor().timer(Duration::from_secs(2)).await;
            }
        })
        .detach();
        cx.spawn(async move |this, cx| {
            loop {
                let idle = bytehalt_windows::user::session_idle_secs();
                if this.update(cx, |ws, cx| ws.send(Command::ReportSessionIdle { idle_secs: idle }, cx, |_, _, _| {})).is_err() {
                    break;
                }
                cx.background_executor().timer(Duration::from_secs(15)).await;
            }
        })
        .detach();
        ws
    }

    /// Envia um comando em segundo plano (o cliente é bloqueante) e trata a resposta na interface.
    pub fn send(&mut self, command: Command, cx: &mut Context<Self>, done: impl FnOnce(&mut Self, Result<Reply, Failure>, &mut Context<Self>) + 'static) {
        let client = self.client.clone();
        cx.spawn(async move |this, cx| {
            let result = cx.background_executor().spawn(async move { client.call(command) }).await;
            let _ = this.update(cx, |ws, cx| {
                // Alteração protegida pela senha mestra: pede a senha na hora.
                if let Err(Failure::AuthRequired(m)) = &result {
                    ws.open_master_prompt(Some(m.clone()), cx);
                }
                done(ws, result, cx);
                cx.notify();
            });
        })
        .detach();
    }

    pub fn refresh(&mut self, cx: &mut Context<Self>) {
        self.send(Command::GetSnapshot, cx, |ws, r, cx| match r {
            Ok(Reply::Snapshot(s)) => {
                ws.connected = Some(true);
                ws.connection = if s.simulated {
                    format!("Conectado · modo simulado · v{}", env!("CARGO_PKG_VERSION"))
                } else {
                    format!("Conectado · v{}", env!("CARGO_PKG_VERSION"))
                };
                ws.snapshot = Some(s);
                ws.refresh_vaults(cx);
                ws.refresh_auth(cx);
                ws.send(Command::GetHistory { limit: 200 }, cx, |ws, r, _| {
                    if let Ok(Reply::History(h)) = r {
                        ws.history = h;
                        ws.notify_new();
                    }
                });
            }
            Ok(_) => {}
            Err(f) => {
                ws.connected = Some(false);
                ws.connection = f.text();
            }
        });
    }

    fn notify_new(&mut self) {
        let newest = self.history.iter().map(|e| e.at).max();
        let Some(since) = self.notified_until else {
            // Primeira leitura: não reapresenta o histórico antigo.
            self.notified_until = Some(newest.unwrap_or(0));
            return;
        };
        if self.settings.notifications {
            let items: Vec<(String, Level)> = present::to_notify(&self.history, since)
                .into_iter()
                .map(|e| {
                    (
                        e.detail.as_ref().map_or_else(|| e.message.clone(), |d| format!("{} {d}", e.message)),
                        match e.severity {
                            Severity::Error => Level::Error,
                            Severity::Warning => Level::Warning,
                            Severity::Info => Level::Info,
                        },
                    )
                })
                .collect();
            for (text, level) in items {
                if let Some(t) = &self.tray {
                    t.notify("ByteHalt", &text, level);
                }
                self.shown_notifications.push(text);
            }
        }
        self.notified_until = newest.or(Some(since));
    }

    pub fn rows(&self) -> Vec<ResourceRow> {
        self.snapshot.as_ref().map(|s| s.resources.iter().map(|v| ResourceRow::from_view(v, &s.groups)).collect()).unwrap_or_default()
    }

    fn groups(&self) -> Vec<ProtectionGroup> {
        self.snapshot.as_ref().map(|s| s.groups.clone()).unwrap_or_default()
    }

    // ---------------- Ações ----------------

    pub fn lock(&mut self, command: Command, cx: &mut Context<Self>) {
        self.send(command, cx, |ws, r, cx| {
            ws.status = Some(match r {
                Ok(Reply::Locks(l)) => present::lock_summary(&l),
                Ok(_) => String::new(),
                Err(f) => format!("Não foi possível bloquear: {}", f.text()),
            });
            ws.refresh(cx);
        });
    }

    pub fn discover(&mut self, cx: &mut Context<Self>) {
        self.send(Command::DiscoverVolumes, cx, |ws, r, _| match r {
            Ok(Reply::Volumes { volumes, warning }) => {
                let known: Vec<String> = ws.rows().into_iter().map(|r| r.target).collect();
                ws.selected_volume = volumes.iter().find(|v| !v.is_system_volume && !known.contains(&v.drive_letter)).map(|v| v.drive_letter.clone());
                ws.volumes = volumes;
                ws.volume_warning = warning;
            }
            Ok(_) => {}
            Err(f) => ws.volume_warning = Some(format!("Não foi possível listar as unidades: {}", f.text())),
        });
    }

    /// Só habilita "Adicionar" para unidade selecionada que não é do sistema e ainda não está cadastrada
    /// (checado na renderização: a busca pode responder antes do estado ser atualizado).
    pub fn can_add_drive(&self) -> bool {
        let known: Vec<String> = self.rows().into_iter().map(|r| r.target).collect();
        self.selected_volume.as_ref().is_some_and(|l| !known.contains(l) && self.volumes.iter().any(|v| &v.drive_letter == l && !v.is_system_volume))
    }

    pub fn add_drive(&mut self, cx: &mut Context<Self>) {
        if !self.can_add_drive() {
            return;
        }
        let Some(letter) = self.selected_volume.clone() else { return };
        let typed = self.drive_name.read(cx).text().trim().to_owned();
        let name = if typed.is_empty() { format!("Unidade {letter}") } else { typed };
        self.drive_name.update(cx, |i, cx| i.set_text("", cx));
        let resource = ProtectedResource { id: Uuid::nil(), display_name: name.clone(), kind: ResourceKind::BitLockerVolume, target: letter };
        self.send(Command::SaveResource { resource }, cx, move |ws, r, cx| {
            ws.drives_message = Some(match r {
                Ok(Reply::Operation(op)) if op.success => format!("{name} adicionada."),
                Ok(Reply::Operation(op)) => op.errors.join(" "),
                Ok(_) => String::new(),
                Err(f) => f.text(),
            });
            ws.refresh(cx);
            ws.discover(cx);
        });
    }

    pub fn open_unlock(&mut self, id: Uuid, name: String, cx: &mut Context<Self>) {
        let pass = cx.new(|cx| TextInput::new("", "Senha da unidade (BitLocker)", cx).masked());
        let totp = cx.new(|cx| TextInput::new("", "Código de 6 dígitos", cx).masked());
        self.unlock = Some(UnlockDialog { id, name, requirement: None, pass, totp, message: None, busy: false });
        self.send(Command::GetUnlockRequirement { id }, cx, |ws, r, _| {
            if let (Some(d), Ok(Reply::Requirement(req))) = (&mut ws.unlock, r) {
                d.requirement = Some(req);
            }
        });
    }

    pub fn confirm_unlock(&mut self, cx: &mut Context<Self>) {
        let Some(d) = &mut self.unlock else { return };
        if d.busy {
            return;
        }
        d.busy = true;
        let id = d.id;
        let passphrase = d.pass.read(cx).text().to_owned();
        let totp = d.requirement.as_ref().filter(|r| r.requires_totp()).map(|_| d.totp.read(cx).text().trim().to_owned());
        d.pass.update(cx, |i, cx| i.set_text("", cx));
        self.send(Command::Unlock { id, passphrase, totp }, cx, |ws, r, cx| {
            let Some(d) = &mut ws.unlock else { return };
            d.busy = false;
            match r {
                Ok(Reply::Unlock(u)) if matches!(u.code, bytehalt_core::auth::UnlockCode::Unlocked | bytehalt_core::auth::UnlockCode::AlreadyUnlocked) => {
                    ws.unlock = None;
                    ws.refresh(cx);
                }
                Ok(Reply::Unlock(u)) => {
                    d.requirement = Some(u.requirement.clone());
                    d.message = Some(match u.retry_after_secs {
                        Some(w) if w > 0 => format!("{} Aguarde {}.", u.message, present::duration(Some(w))),
                        _ => u.message,
                    });
                }
                Ok(_) => {}
                Err(f) => d.message = Some(f.text()),
            }
        });
    }

    pub fn new_group(&mut self, cx: &mut Context<Self>) {
        self.editor = Some(GroupEditor {
            id: Uuid::nil(),
            name: cx.new(|cx| TextInput::new("", "Nome do grupo", cx)),
            timeout: 2,
            custom: cx.new(|cx| TextInput::new("20", "Minutos", cx)),
            mode: InactivityMode::ResourceIdle,
            totp_hours: cx.new(|cx| TextInput::new("24", "Horas", cx)),
            ws_lock: true,
            suspend_lock: true,
            selected: HashSet::new(),
            error: None,
        });
    }

    pub fn edit_group(&mut self, g: &ProtectionGroup, cx: &mut Context<Self>) {
        let minutes = g.inactivity_secs.map(|s| s / 60);
        let timeout = match minutes {
            None => OFF,
            Some(m) => TIMEOUT_CHOICES.iter().position(|c| c.1 == Some(m)).unwrap_or(CUSTOM),
        };
        let (name, custom, hours) = (g.name.clone(), minutes.unwrap_or(20).to_string(), format!("{}", g.totp_threshold_secs as f64 / 3600.0).replace('.', ","));
        self.editor = Some(GroupEditor {
            id: g.id,
            name: cx.new(|cx| TextInput::new(name, "Nome do grupo", cx)),
            timeout,
            custom: cx.new(|cx| TextInput::new(custom, "Minutos", cx)),
            mode: g.mode,
            totp_hours: cx.new(|cx| TextInput::new(hours, "Horas", cx)),
            ws_lock: g.lock_on_workstation_lock,
            suspend_lock: g.lock_on_suspend,
            selected: g.resource_ids.iter().copied().collect(),
            error: None,
        });
    }

    pub fn save_group(&mut self, cx: &mut Context<Self>) {
        let Some(e) = &mut self.editor else { return };
        let order: Vec<Uuid> =
            self.snapshot.as_ref().map(|s| s.resources.iter().map(|v| v.resource.id).filter(|id| e.selected.contains(id)).collect()).unwrap_or_default();
        let built = present::build_group(
            e.id,
            e.name.read(cx).text(),
            e.timeout,
            e.custom.read(cx).text(),
            e.mode,
            e.totp_hours.read(cx).text(),
            e.ws_lock,
            e.suspend_lock,
            order,
        );
        let group = match built {
            Ok(g) => g,
            Err(m) => {
                e.error = Some(m);
                return;
            }
        };
        let name = group.name.clone();
        self.send(Command::SaveGroup { group }, cx, move |ws, r, cx| match r {
            Ok(Reply::Operation(op)) if op.success => {
                ws.editor = None;
                ws.groups_message = Some(format!("Grupo {name} salvo."));
                ws.refresh(cx);
            }
            Ok(Reply::Operation(op)) => {
                if let Some(e) = &mut ws.editor {
                    e.error = Some(op.errors.join("\n"));
                }
            }
            Ok(_) => {}
            Err(f) => {
                if let Some(e) = &mut ws.editor {
                    e.error = Some(f.text());
                }
            }
        });
    }

    pub fn run_confirm(&mut self, cx: &mut Context<Self>) {
        let Some(c) = self.confirm.take() else { return };
        let (command, name, group) = match c {
            Confirm::RemoveResource(id, n) => (Command::DeleteResource { id }, n, false),
            Confirm::DeleteGroup(id, n) => (Command::DeleteGroup { id }, n, true),
            vault @ (Confirm::SwapVault(..) | Confirm::DiscardVault(..) | Confirm::DeleteReserve(..) | Confirm::RemoveVault(..)) => {
                return self.run_vault_confirm(vault, cx);
            }
        };
        self.send(command, cx, move |ws, r, cx| {
            let text = match r {
                Ok(Reply::Operation(op)) if op.success => {
                    if group {
                        format!("Grupo {name} excluído.")
                    } else {
                        format!("{name} removida.")
                    }
                }
                Ok(Reply::Operation(op)) => op.errors.join(" "),
                Ok(_) => String::new(),
                Err(f) => f.text(),
            };
            if group {
                ws.groups_message = Some(text)
            } else {
                ws.drives_message = Some(text)
            }
            ws.refresh(cx);
        });
    }

    pub fn check_requirements(&mut self, cx: &mut Context<Self>) {
        self.requirements.clear();
        let locked: Vec<(Uuid, String)> = self
            .snapshot
            .as_ref()
            .map(|s| s.resources.iter().filter(|v| v.state == LockState::Locked).map(|v| (v.resource.id, v.resource.display_name.clone())).collect())
            .unwrap_or_default();
        for (id, name) in locked {
            self.send(Command::GetUnlockRequirement { id }, cx, move |ws, r, _| {
                if let Ok(Reply::Requirement(req)) = r {
                    ws.requirements.push((name, req));
                }
            });
        }
    }

    pub fn set_dark(&mut self, dark: bool, cx: &mut Context<Self>) {
        self.settings.dark = dark;
        Themes::set_dark(cx, dark);
        self.persist();
    }

    pub fn persist(&mut self) {
        if let Err(e) = self.settings_file.save(&self.settings) {
            self.settings_message = Some(format!("Não foi possível salvar as preferências: {e:#}"));
        }
    }

    pub fn toggle_autostart(&mut self) {
        let want = !self.autostart;
        let command = std::env::current_exe().ok().map(|p| format!("\"{}\" --tray", p.display()));
        match bytehalt_windows::user::set_autostart(AUTOSTART_VALUE, if want { command.as_deref() } else { None }) {
            Ok(()) => {
                self.autostart = want;
                self.settings_message =
                    Some(if want { "O ByteHalt abrirá na bandeja ao entrar no Windows.".into() } else { "Inicialização automática desligada.".into() });
            }
            Err(e) => self.settings_message = Some(format!("{e:#}")),
        }
    }

    // ---------------- Bandeja e janela ----------------

    pub fn tray_state(&self) -> TrayState {
        let (look, status, tooltip) = present::tray_summary(self.snapshot.as_ref(), self.connected);
        let icon = match look {
            present::TrayLook::Locked => TrayIcon::Locked,
            present::TrayLook::Unlocked => TrayIcon::Unlocked,
            present::TrayLook::Attention => TrayIcon::Attention,
        };
        TrayState { status, groups: self.groups().into_iter().map(|g| g.name).collect(), connected: self.connected == Some(true), icon, tooltip }
    }

    /// Esconde o painel na bandeja; na primeira vez, avisa que o ByteHalt continua em execução.
    pub fn hide_to_tray(&mut self) {
        if self.panel.is_none() || self.tray.is_none() {
            return;
        }
        if let Some(p) = &self.panel {
            p.hide();
        }
        if !self.settings.tray_hint_shown {
            let text = "O ByteHalt continua em execução na bandeja. Use o ícone para abrir o painel ou bloquear.";
            if let Some(t) = &self.tray {
                t.notify("ByteHalt", text, Level::Info);
            }
            self.shown_notifications.push(text.into());
            self.settings.tray_hint_shown = true;
            self.persist();
        }
    }

    pub fn install_desktop(&mut self, start_hidden: bool, window: &mut Window, cx: &mut Context<Self>) {
        use raw_window_handle::{HasWindowHandle, RawWindowHandle};
        if let Ok(h) = HasWindowHandle::window_handle(window)
            && let RawWindowHandle::Win32(w) = h.as_raw()
        {
            self.panel = Some(Panel::from_handle(w.hwnd));
        }
        match Tray::new(self.tray_state()) {
            Ok(t) => self.tray = Some(t),
            Err(e) => self.status = Some(format!("Bandeja indisponível: {e:#}. O painel permanece na barra de tarefas.")),
        }
        if start_hidden
            && self.tray.is_some()
            && let Some(p) = &self.panel
        {
            p.hide();
        }
        cx.spawn_in(window, async move |this, cx| {
            loop {
                cx.background_executor().timer(Duration::from_millis(150)).await;
                if this.update_in(cx, |ws, w, cx| ws.poll_desktop(w, cx)).is_err() {
                    break;
                }
            }
        })
        .detach();
    }

    pub fn poll_desktop(&mut self, _window: &mut Window, cx: &mut Context<Self>) {
        let state = self.tray_state();
        let mut actions = Vec::new();
        if let Some(t) = &self.tray {
            t.update(state);
            while let Some(a) = t.take_action() {
                actions.push(a);
            }
            if self.tray_checked.elapsed() >= Duration::from_secs(2) {
                self.tray_checked = std::time::Instant::now();
                if !t.check() {
                    actions.push(TrayAction::Unavailable);
                }
            }
        }
        // Minimizar leva para a bandeja (se a opção estiver ligada e a bandeja existir).
        let minimized = self.panel.as_ref().is_some_and(|p| p.visible() && p.minimized());
        if self.settings.close_to_tray && self.tray.is_some() && minimized {
            self.hide_to_tray();
        }
        let groups = self.groups();
        for a in actions {
            match a {
                TrayAction::Open => self.show(),
                TrayAction::LockAll => self.lock(Command::LockAll, cx),
                TrayAction::LockGroup(i) => {
                    if let Some(g) = groups.get(i) {
                        self.lock(Command::LockGroup { id: g.id }, cx);
                    }
                }
                TrayAction::Exit => {
                    // Aberta pelo portátil: "Sair" encerra também o serviço em console.
                    crate::portable::on_exit(&self.client);
                    cx.quit()
                }
                TrayAction::Unavailable => {
                    self.tray = None;
                    self.show();
                }
            }
        }
    }

    pub fn show(&self) {
        if let Some(p) = &self.panel {
            p.restore();
        }
    }

    /// X da janela: esconde na bandeja ou encerra, conforme a preferência.
    pub fn request_close(&mut self, cx: &mut Context<Self>) {
        if self.settings.close_to_tray && self.tray.is_some() {
            self.hide_to_tray();
        } else {
            cx.quit();
        }
    }

    // ---------------- Renderização ----------------

    fn sidebar(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let t = cx.theme().clone();
        let mut nav = div().flex().flex_col().gap(px(2.));
        for (page, label, glyph) in PAGES {
            let active = self.page == page;
            let hover = t.hover;
            nav = nav.child(
                div()
                    .id(SharedString::from(format!("nav-{label}")))
                    .h(px(28.))
                    .px(px(9.))
                    .flex()
                    .items_center()
                    .gap(px(10.))
                    .rounded(px(6.))
                    .cursor_pointer()
                    .text_size(px(12.5))
                    .when(active, |d| d.bg(t.selected).text_color(t.text_strong).font_weight(FontWeight::MEDIUM))
                    .when(!active, {
                        let text = t.text;
                        move |d| d.text_color(text).hover(move |s| s.bg(hover))
                    })
                    .on_click(cx.listener(move |ws, _, _, cx| {
                        ws.page = page;
                        cx.notify();
                    }))
                    .child(ui::icon(glyph, 16., if active { t.accent } else { t.text_muted }))
                    .child(label),
            );
        }
        let dot = match self.connected {
            Some(true) => t.ok,
            Some(false) => t.error,
            None => t.text_faint,
        };
        div()
            .w(px(176.))
            .h_full()
            .flex_none()
            .flex()
            .flex_col()
            .justify_between()
            .p(px(12.))
            .bg(t.panel)
            .border_r_1()
            .border_color(t.border)
            .child(
                div()
                    .flex()
                    .flex_col()
                    .gap(px(18.))
                    .child(
                        div().flex().items_center().gap(px(8.)).px(px(4.)).child(img(crate::assets::BRAND_LOGO).size(px(28.)).flex_none()).child(
                            div()
                                .flex()
                                .flex_col()
                                .child(div().text_size(px(15.)).font_weight(FontWeight::SEMIBOLD).text_color(t.text_strong).child("ByteHalt"))
                                .child(div().text_size(px(10.5)).text_color(t.text_muted).child("Drive & Folder Security")),
                        ),
                    )
                    .child(nav),
            )
            .child(
                div()
                    .flex()
                    .flex_col()
                    .gap(px(10.))
                    .child(
                        ui::button("lock-all", "Bloquear tudo", Kind::Primary, self.connected == Some(true), cx)
                            .w_full()
                            .when(self.connected == Some(true), |b| b.on_click(cx.listener(|ws, _, _, cx| ws.lock(Command::LockAll, cx)))),
                    )
                    .child(
                        div()
                            .flex()
                            .items_start()
                            .gap(px(6.))
                            .child(div().mt(px(4.)).size(px(8.)).rounded(px(4.)).bg(dot).flex_none())
                            .child(div().text_size(px(11.5)).text_color(t.text_muted).child(self.connection.clone())),
                    ),
            )
    }

    fn page_dashboard(&self, cx: &mut Context<Self>) -> AnyElement {
        let t = cx.theme().clone();
        let d = self.snapshot.as_ref().map(present::dashboard).unwrap_or_default();
        let metric = |label: &'static str, value: usize, color| {
            ui::card(&t)
                .flex_1()
                .gap(px(2.))
                .child(ui::muted(label, &t))
                .child(div().text_size(px(20.)).font_weight(FontWeight::SEMIBOLD).text_color(color).child(value.to_string()))
        };
        let mut upcoming = ui::card(&t).child(ui::section("Próximos bloqueios", &t));
        if d.upcoming.is_empty() {
            upcoming = upcoming.child(ui::muted("Nenhum recurso desbloqueado com bloqueio automático. Adicione unidades em Unidades e configure grupos.", &t));
        }
        for r in &d.upcoming {
            upcoming = upcoming.child(
                div()
                    .flex()
                    .items_center()
                    .gap(px(12.))
                    .py(px(2.))
                    .child(
                        div()
                            .w(px(170.))
                            .flex()
                            .flex_col()
                            .child(div().font_weight(FontWeight::MEDIUM).child(r.name.clone()))
                            .child(ui::muted(r.target.clone(), &t)),
                    )
                    .child(div().w(px(190.)).flex().child(ui::pill(r.state_text.clone(), r.tone, &t)))
                    .child(div().w(px(170.)).text_size(px(12.5)).child(r.next_lock_text.clone()))
                    .child(div().flex_1().child(ui::muted(r.policy_text.clone(), &t))),
            );
        }
        let mut alerts = ui::card(&t).child(ui::section("Alertas", &t));
        if d.alerts.is_empty() {
            alerts = alerts.child(ui::muted("Nenhum alerta.", &t));
        }
        for a in &d.alerts {
            alerts = alerts.child(ui::notice(a.clone(), Tone::Warning, &t));
        }
        div()
            .flex()
            .flex_col()
            .gap(px(12.))
            .child(div().child(ui::title("Visão geral", &t)).child(ui::muted("Estado dos recursos protegidos e próximos bloqueios automáticos.", &t)))
            .child(
                div()
                    .flex()
                    .gap(px(12.))
                    .child(metric("Recursos protegidos", d.total, t.text_strong))
                    .child(metric("Bloqueados", d.locked, t.ok))
                    .child(metric("Desbloqueados", d.unlocked, t.text_strong))
                    .child(metric("Exigem atenção", d.attention, t.warning)),
            )
            .child(upcoming)
            .child(alerts)
            .into_any_element()
    }

    fn page_drives(&self, cx: &mut Context<Self>) -> AnyElement {
        let t = cx.theme().clone();
        let known: Vec<String> = self.rows().into_iter().map(|r| r.target).collect();
        let mut chips = div().flex().flex_wrap().gap(px(6.));
        for v in &self.volumes {
            let selectable = !v.is_system_volume && !known.contains(&v.drive_letter);
            let label = if v.is_system_volume {
                format!("{} · sistema (não pode ser bloqueada)", v.drive_letter)
            } else if !selectable {
                format!("{} · já cadastrada", v.drive_letter)
            } else {
                format!("{} · {}{}", v.drive_letter, present::state(v.state), if v.auto_unlock { " · desbloqueio automático ativo" } else { "" })
            };
            let letter = v.drive_letter.clone();
            let selected = self.selected_volume.as_deref() == Some(letter.as_str());
            chips = chips.child(ui::chip(SharedString::from(format!("vol-{letter}")), label, selected, cx).when(!selectable, |c| c.opacity(0.55)).when(
                selectable,
                |c| {
                    c.on_click(cx.listener(move |ws, _, _, cx| {
                        ws.selected_volume = Some(letter.clone());
                        cx.notify();
                    }))
                },
            ));
        }
        let can_add = self.can_add_drive();
        let add = ui::card(&t)
            .child(ui::section("Adicionar unidade", &t))
            .child(
                div()
                    .flex()
                    .items_end()
                    .gap(px(8.))
                    .child(ui::button("discover", "Procurar unidades", Kind::Secondary, true, cx).on_click(cx.listener(|ws, _, _, cx| ws.discover(cx))))
                    .child(div().flex_1().min_w(px(0.)).child(ui::field("Nome de exibição", self.drive_name.clone(), &t)))
                    .child(
                        ui::button("add-drive", "Adicionar", Kind::Primary, can_add, cx)
                            .when(can_add, |b| b.on_click(cx.listener(|ws, _, _, cx| ws.add_drive(cx)))),
                    ),
            )
            .when(!self.volumes.is_empty(), |c| c.child(chips))
            .when_some(self.volume_warning.clone(), |c, w| c.child(ui::notice(w, Tone::Warning, &t)))
            .when_some(self.drives_message.clone(), |c, m| c.child(ui::muted(m, &t)));
        let simulated = self.snapshot.as_ref().is_some_and(|s| s.simulated);
        let mut list = div().flex().flex_col().gap(px(10.));
        // Cofres têm a própria tela.
        for r in self.rows().into_iter().filter(|r| r.kind == ResourceKind::BitLockerVolume) {
            let (fg, _) = ui::tone_colors(r.tone, &t);
            let (id, name, locked) = (r.id, r.name.clone(), r.state == LockState::Locked);
            let mut actions = div().flex().gap(px(6.)).flex_none();
            actions = actions.child(
                ui::button(SharedString::from(format!("lock-{id}")), "Bloquear", Kind::Primary, r.can_lock, cx)
                    .when(r.can_lock, |b| b.on_click(cx.listener(move |ws, _, _, cx| ws.lock(Command::LockResources { ids: vec![id] }, cx)))),
            );
            if locked {
                let n = name.clone();
                actions = actions.child(
                    ui::button(SharedString::from(format!("unlock-{id}")), "Desbloquear", Kind::Secondary, true, cx)
                        .on_click(cx.listener(move |ws, _, _, cx| ws.open_unlock(id, n.clone(), cx))),
                );
            }
            let n = name.clone();
            actions = actions.child(ui::button(SharedString::from(format!("remove-{id}")), "Remover", Kind::Danger, true, cx).on_click(cx.listener(
                move |ws, _, _, cx| {
                    ws.confirm = Some(Confirm::RemoveResource(id, n.clone()));
                    cx.notify();
                },
            )));
            let mut sim = div().flex().gap(px(6.));
            if simulated {
                for (label, cmd) in [("Simular atividade", 0u8), ("Simular arquivo aberto", 1), ("Fechar arquivos", 2)] {
                    sim = sim.child(ui::button(SharedString::from(format!("sim{cmd}-{id}")), label, Kind::Secondary, true, cx).on_click(cx.listener(
                        move |ws, _, _, cx| {
                            let command = match cmd {
                                0 => Command::SimulateActivity { id },
                                1 => Command::SimulateVolume { id, present: None, locked: None, open_handles: Some(1), auto_unlock: None },
                                _ => Command::SimulateVolume { id, present: None, locked: None, open_handles: Some(0), auto_unlock: None },
                            };
                            ws.drives_message = Some(match cmd {
                                0 => "Atividade simulada: o contador recomeçou.".into(),
                                1 => "Arquivo aberto simulado.".into(),
                                _ => "Arquivos simulados fechados.".into(),
                            });
                            ws.send(command, cx, |ws, _, cx| ws.refresh(cx));
                        },
                    )));
                }
            }
            list = list.child(
                ui::card(&t).child(
                    div()
                        .flex()
                        .gap(px(12.))
                        .child(div().pt(px(2.)).child(ui::icon("storage", 22., fg)))
                        .child(
                            div()
                                .flex_1()
                                .min_w(px(0.))
                                .flex()
                                .flex_col()
                                .gap(px(4.))
                                .child(
                                    div()
                                        .flex()
                                        .items_center()
                                        .gap(px(8.))
                                        .child(ui::section(name, &t))
                                        .child(ui::muted(r.target.clone(), &t))
                                        .child(ui::pill(r.state_text.clone(), r.tone, &t)),
                                )
                                .child(ui::muted(format!("{}  ·  {}", r.policy_text, r.groups_text), &t))
                                .when(!r.next_lock_text.is_empty(), |d| d.child(div().text_size(px(12.5)).child(r.next_lock_text.clone())))
                                .when_some(r.warning.clone(), |d, w| d.child(ui::notice(w, Tone::Warning, &t)))
                                .when_some(r.last_result.clone(), |d, l| d.child(ui::muted(l, &t)))
                                .when(simulated, |d| d.child(sim)),
                        )
                        .child(actions),
                ),
            );
        }
        div()
            .flex()
            .flex_col()
            .gap(px(12.))
            .child(div().child(ui::title("Unidades", &t)).child(ui::muted("Unidades de dados inteiras protegidas pelo BitLocker. A unidade do sistema em execução nunca é bloqueada e o ByteHalt não altera chaves de recuperação.", &t)))
            .child(add)
            .child(list)
            .into_any_element()
    }

    fn page_groups(&self, cx: &mut Context<Self>) -> AnyElement {
        let t = cx.theme().clone();
        let header = div()
            .flex()
            .items_center()
            .justify_between()
            .child(
                div()
                    .child(ui::title("Grupos", &t))
                    .child(ui::muted("Reúna unidades e cofres com o mesmo tempo de inatividade e a mesma política de autenticação.", &t)),
            )
            .child(
                ui::button("new-group", "Novo grupo", Kind::Primary, self.editor.is_none(), cx)
                    .when(self.editor.is_none(), |b| b.on_click(cx.listener(|ws, _, _, cx| ws.new_group(cx)))),
            );
        let mut page = div().flex().flex_col().gap(px(12.)).child(header);
        if let Some(e) = &self.editor {
            page = page.child(self.group_editor(e, cx));
        }
        if let Some(m) = &self.groups_message {
            page = page.child(ui::muted(m.clone(), &t));
        }
        for g in self.groups() {
            let (gid, gname) = (g.id, g.name.clone());
            let g2 = g.clone();
            page = page.child(
                ui::card(&t).child(
                    div()
                        .flex()
                        .items_center()
                        .gap(px(12.))
                        .child(ui::icon("layers", 20., t.accent))
                        .child(div().flex_1().flex().flex_col().child(ui::section(g.name.clone(), &t)).child(ui::muted(
                            format!(
                                "{} recurso(s)  ·  {}  ·  {}  ·  TOTP após {}{}{}",
                                g.resource_ids.len(),
                                present::minutes(g.inactivity_secs),
                                present::mode(g.mode),
                                present::minutes(Some(g.totp_threshold_secs)),
                                if g.lock_on_workstation_lock { "  ·  bloqueia com o Windows" } else { "" },
                                if g.lock_on_suspend { "  ·  bloqueia ao suspender" } else { "" }
                            ),
                            &t,
                        )))
                        .child(
                            ui::button(SharedString::from(format!("lockg-{gid}")), "Bloquear grupo", Kind::Primary, true, cx)
                                .on_click(cx.listener(move |ws, _, _, cx| ws.lock(Command::LockGroup { id: gid }, cx))),
                        )
                        .child(
                            ui::button(SharedString::from(format!("edit-{gid}")), "Editar", Kind::Secondary, true, cx)
                                .on_click(cx.listener(move |ws, _, _, cx| ws.edit_group(&g2, cx))),
                        )
                        .child(ui::button(SharedString::from(format!("del-{gid}")), "Excluir", Kind::Danger, true, cx).on_click(cx.listener(
                            move |ws, _, _, cx| {
                                ws.confirm = Some(Confirm::DeleteGroup(gid, gname.clone()));
                                cx.notify();
                            },
                        ))),
                ),
            );
        }
        page.into_any_element()
    }

    fn group_editor(&self, e: &GroupEditor, cx: &mut Context<Self>) -> impl IntoElement {
        let t = cx.theme().clone();
        let mut timeouts = div().flex().flex_wrap().gap(px(6.));
        for (i, (label, _)) in TIMEOUT_CHOICES.iter().enumerate() {
            timeouts =
                timeouts.child(ui::chip(SharedString::from(format!("to-{i}")), *label, e.timeout == i, cx).on_click(cx.listener(move |ws, _, _, cx| {
                    if let Some(e) = &mut ws.editor {
                        e.timeout = i;
                    }
                    cx.notify();
                })));
        }
        let mut modes = div().flex().flex_wrap().gap(px(6.));
        for (m, label) in [(InactivityMode::ResourceIdle, "Do recurso"), (InactivityMode::SessionIdle, "Da sessão"), (InactivityMode::Combined, "Combinada")] {
            modes = modes.child(ui::chip(SharedString::from(format!("mode-{label}")), label, e.mode == m, cx).on_click(cx.listener(move |ws, _, _, cx| {
                if let Some(e) = &mut ws.editor {
                    e.mode = m;
                }
                cx.notify();
            })));
        }
        let mut resources = div().flex().flex_col().gap(px(4.));
        for r in self.rows() {
            let id = r.id;
            resources = resources.child(
                ui::checkbox(SharedString::from(format!("gr-{id}")), format!("{} ({})", r.name, r.target), e.selected.contains(&id), cx).on_click(cx.listener(
                    move |ws, _, _, cx| {
                        if let Some(e) = &mut ws.editor
                            && !e.selected.remove(&id)
                        {
                            e.selected.insert(id);
                        }
                        cx.notify();
                    },
                )),
            );
        }
        if self.rows().is_empty() {
            resources = resources.child(ui::muted("Cadastre unidades na tela Unidades.", &t));
        }
        ui::card(&t)
            .border_color(t.accent)
            .child(ui::section(if e.id.is_nil() { "Novo grupo".to_owned() } else { "Editar grupo".to_owned() }, &t))
            .child(
                div()
                    .flex()
                    .gap(px(20.))
                    .child(
                        div()
                            .flex_1()
                            .min_w(px(0.))
                            .flex()
                            .flex_col()
                            .gap(px(10.))
                            .child(ui::field("Nome", e.name.clone(), &t))
                            .child(div().flex().flex_col().gap(px(4.)).child(ui::muted("Bloquear após inatividade de", &t)).child(timeouts))
                            .when(e.timeout == CUSTOM, |d| d.child(ui::field("Minutos (1 a 1440)", e.custom.clone(), &t)))
                            .child(div().flex().flex_col().gap(px(4.)).child(ui::muted("Medir inatividade", &t)).child(modes))
                            .child(ui::field("Exigir TOTP após (horas bloqueado)", e.totp_hours.clone(), &t))
                            .child(ui::checkbox("ws-lock", "Bloquear quando o Windows for bloqueado", e.ws_lock, cx).on_click(cx.listener(|ws, _, _, cx| {
                                if let Some(e) = &mut ws.editor {
                                    e.ws_lock = !e.ws_lock;
                                }
                                cx.notify();
                            })))
                            .child(ui::checkbox("suspend-lock", "Bloquear ao suspender ou hibernar", e.suspend_lock, cx).on_click(cx.listener(|ws, _, _, cx| {
                                if let Some(e) = &mut ws.editor {
                                    e.suspend_lock = !e.suspend_lock;
                                }
                                cx.notify();
                            }))),
                    )
                    .child(div().flex_1().flex().flex_col().gap(px(8.)).child(ui::muted("Recursos do grupo", &t)).child(resources).child(ui::notice("Recurso em vários grupos segue a regra mais restritiva: o menor tempo, modo combinado quando os modos diferem, o menor limite de TOTP e bloqueio com o Windows se qualquer grupo pedir.", Tone::Neutral, &t))),
            )
            .when_some(e.error.clone(), |c, err| c.child(ui::notice(err, Tone::Danger, &t)))
            .child(
                div()
                    .flex()
                    .justify_end()
                    .gap(px(8.))
                    .child(ui::button("cancel-group", "Cancelar", Kind::Secondary, true, cx).on_click(cx.listener(|ws, _, _, cx| {
                        ws.editor = None;
                        cx.notify();
                    })))
                    .child(ui::button("save-group", "Salvar grupo", Kind::Primary, true, cx).on_click(cx.listener(|ws, _, _, cx| ws.save_group(cx)))),
            )
    }

    fn page_security(&self, cx: &mut Context<Self>) -> AnyElement {
        let t = cx.theme().clone();
        let mut reqs = ui::card(&t).child(
            div().flex().items_center().justify_between().child(ui::section("Exigência atual para desbloquear", &t)).child(
                ui::button("check-reqs", "Consultar recursos bloqueados", Kind::Secondary, true, cx)
                    .on_click(cx.listener(|ws, _, _, cx| ws.check_requirements(cx))),
            ),
        );
        for (name, r) in &self.requirements {
            reqs = reqs.child(
                div()
                    .flex()
                    .gap(px(12.))
                    .child(div().w(px(170.)).font_weight(FontWeight::MEDIUM).child(name.clone()))
                    .child(div().w(px(160.)).child(present::factors(r.factors)))
                    .child(
                        div()
                            .flex_1()
                            .min_w(px(0.))
                            .flex()
                            .flex_col()
                            .child(
                                div().child(
                                    r.elapsed_secs
                                        .map_or_else(|| "Tempo bloqueado não confiável".to_owned(), |s| format!("Bloqueado há {}", present::duration(Some(s)))),
                                ),
                            )
                            .child(ui::muted(present::reason(r.reason), &t)),
                    ),
            );
        }
        div()
            .flex()
            .flex_col()
            .gap(px(12.))
            .child(div().child(ui::title("Segurança", &t)).child(ui::muted("Senha mestra, autenticador, códigos de recuperação e a regra de 24 horas.", &t)))
            .child(self.account_card(cx))
            .child(ui::card(&t).bg(t.error_soft).border_color(t.error).child(ui::section("Limitação de segurança", &t)).child(div().text_size(px(13.)).child(present::MANDATORY_LIMITATION)))
            .child(ui::card(&t).child(ui::section("Regra de 24 horas", &t)).child(div().text_size(px(13.)).child("Bloqueado há menos de 24 horas: basta a senha. Bloqueado há 24 horas ou mais: senha e código TOTP. A contagem começa no bloqueio efetivo e continua valendo após reiniciar o serviço ou o Windows.")).child(ui::muted("Se o relógio do Windows voltar no tempo, ou se o registro do bloqueio estiver ausente ou alterado, o ByteHalt passa a exigir TOTP. O limite pode ser alterado por grupo.", &t)))
            .child(reqs)
            .into_any_element()
    }

    fn page_history(&self, cx: &mut Context<Self>) -> AnyElement {
        let t = cx.theme().clone();
        let mut table = ui::card(&t).p(px(0.)).gap(px(0.));
        table = table.child(
            div()
                .flex()
                .px(px(12.))
                .py(px(8.))
                .border_b_1()
                .border_color(t.divider)
                .text_size(px(12.))
                .text_color(t.text_muted)
                .child(div().w(px(150.)).child("Quando"))
                .child(div().w(px(60.)).child("Tipo"))
                .child(div().flex_1().child("Evento")),
        );
        for e in self.history.iter().filter(|e| !self.only_problems || matches!(e.severity, Severity::Warning | Severity::Error)) {
            let color = match e.severity {
                Severity::Error => t.error,
                Severity::Warning => t.warning,
                Severity::Info => t.text_muted,
            };
            table = table.child(
                div()
                    .flex()
                    .px(px(12.))
                    .py(px(6.))
                    .border_b_1()
                    .border_color(t.divider)
                    .text_size(px(12.5))
                    .child(div().w(px(150.)).text_color(t.text_muted).child(present::local_time(e.at)))
                    .child(div().w(px(60.)).text_color(color).child(present::severity(e.severity)))
                    .child(div().flex_1().flex().flex_col().child(e.message.clone()).when_some(e.detail.clone(), |d, x| d.child(ui::muted(x, &t)))),
            );
        }
        div()
            .flex()
            .flex_col()
            .gap(px(12.))
            .child(
                div()
                    .flex()
                    .items_center()
                    .justify_between()
                    .child(
                        div()
                            .child(ui::title("Histórico", &t))
                            .child(ui::muted("Bloqueios, desbloqueios, erros e alertas. Nenhuma senha ou código é registrado.", &t)),
                    )
                    .child(ui::checkbox("only-problems", "Somente avisos e erros", self.only_problems, cx).on_click(cx.listener(|ws, _, _, cx| {
                        ws.only_problems = !ws.only_problems;
                        cx.notify();
                    }))),
            )
            .child(table)
            .into_any_element()
    }

    fn page_settings(&self, cx: &mut Context<Self>) -> AnyElement {
        let t = cx.theme().clone();
        div()
            .flex()
            .flex_col()
            .gap(px(12.))
            .child(div().child(ui::title("Configurações", &t)).child(ui::muted("Aparência, notificações e inicialização.", &t)))
            .child(ui::card(&t).child(ui::section("Aparência", &t)).child(ui::checkbox("dark", "Tema escuro", self.settings.dark, cx).on_click(cx.listener(
                |ws, _, _, cx| {
                    let dark = !ws.settings.dark;
                    ws.set_dark(dark, cx);
                },
            ))))
            .child(
                ui::card(&t)
                    .child(ui::section("Notificações e bandeja", &t))
                    .child(ui::checkbox("notify", "Avisar sobre bloqueios, adiamentos e falhas", self.settings.notifications, cx).on_click(cx.listener(
                        |ws, _, _, cx| {
                            ws.settings.notifications = !ws.settings.notifications;
                            ws.persist();
                            cx.notify();
                        },
                    )))
                    .child(ui::checkbox("tray", "Ao fechar ou minimizar, continuar na bandeja do Windows", self.settings.close_to_tray, cx).on_click(
                        cx.listener(|ws, _, _, cx| {
                            ws.settings.close_to_tray = !ws.settings.close_to_tray;
                            ws.persist();
                            cx.notify();
                        }),
                    )),
            )
            .child(
                ui::card(&t)
                    .child(ui::section("Inicialização", &t))
                    .when(self.machine_autostart, |c| {
                        c.child(ui::notice(
                            "Abre na bandeja ao entrar no Windows para todos os usuários (definido pelo instalador). Para desativar: Gerenciador de Tarefas > Aplicativos de inicialização.",
                            Tone::Neutral,
                            &t,
                        ))
                    })
                    .when(!self.machine_autostart, |c| {
                        c.child(ui::checkbox("autostart", "Abrir o ByteHalt na bandeja ao entrar no Windows", self.autostart, cx).on_click(cx.listener(
                            |ws, _, _, cx| {
                                ws.toggle_autostart();
                                cx.notify();
                            },
                        )))
                    })
                    .child(ui::muted("O serviço de proteção roda independentemente da interface.", &t))
                    .when_some(self.settings_message.clone(), |c, m| c.child(ui::muted(m, &t))),
            )
            .child(
                ui::card(&t).child(ui::section("Temporizadores", &t)).child(
                    div()
                        .text_size(px(13.))
                        .child("Os tempos de inatividade (1, 5, 10, 15, 30, 60 minutos ou personalizado) são definidos em cada grupo, na tela Grupos."),
                ),
            )
            .into_any_element()
    }

    fn overlay(&self, cx: &mut Context<Self>) -> Option<AnyElement> {
        let t = cx.theme().clone();
        let dialog = if let Some(r) = self.recovery_dialog(cx).or_else(|| self.codes_dialog(cx)) {
            // Chave e códigos de recuperação têm prioridade: não podem ser perdidos atrás de outro diálogo.
            div().child(r)
        } else if let Some(m) = self.master_dialog(cx) {
            div().child(m)
        } else if let Some(d) = &self.unlock {
            let requires_totp = d.requirement.as_ref().is_some_and(|r| r.requires_totp());
            let req_text = d
                .requirement
                .as_ref()
                .map_or_else(|| "Consultando a política…".to_owned(), |r| format!("Exigido: {}. {}", present::factors(r.factors), present::reason(r.reason)));
            ui::card(&t)
                .w(px(420.))
                .bg(t.elevated)
                .shadow_lg()
                .child(ui::section(format!("Desbloquear {}", d.name), &t))
                .child(ui::muted(req_text, &t))
                .child(ui::field("Senha da unidade (BitLocker)", d.pass.clone(), &t))
                .when(requires_totp, |c| c.child(ui::field("Código do aplicativo autenticador", d.totp.clone(), &t)))
                .when_some(d.message.clone(), |c, m| c.child(ui::notice(m, Tone::Warning, &t)))
                .child(
                    div()
                        .flex()
                        .justify_end()
                        .gap(px(8.))
                        .child(ui::button("unlock-cancel", "Cancelar", Kind::Secondary, true, cx).on_click(cx.listener(|ws, _, _, cx| {
                            ws.unlock = None;
                            cx.notify();
                        })))
                        .child(
                            ui::button("unlock-confirm", "Desbloquear", Kind::Primary, !d.busy, cx).on_click(cx.listener(|ws, _, _, cx| ws.confirm_unlock(cx))),
                        ),
                )
        } else if let Some(c) = &self.confirm {
            let (title, text, yes) = match c {
                Confirm::RemoveResource(_, n) => (
                    "Remover da proteção".to_owned(),
                    format!("Remover {n} do ByteHalt? A unidade e o BitLocker não são alterados; apenas o monitoramento deixa de existir."),
                    "Confirmar",
                ),
                Confirm::DeleteGroup(_, n) => (
                    "Excluir grupo".to_owned(),
                    format!("Excluir o grupo {n}? Os recursos continuam cadastrados, mas deixam de seguir a política deste grupo."),
                    "Confirmar",
                ),
                vault => crate::vaults::confirm_text(vault).unwrap_or_default(),
            };
            ui::card(&t).w(px(420.)).bg(t.elevated).shadow_lg().child(ui::section(title, &t)).child(div().text_size(px(13.)).child(text)).child(
                div()
                    .flex()
                    .justify_end()
                    .gap(px(8.))
                    .child(ui::button("confirm-no", "Cancelar", Kind::Secondary, true, cx).on_click(cx.listener(|ws, _, _, cx| {
                        ws.confirm = None;
                        cx.notify();
                    })))
                    .child(ui::button("confirm-yes", yes, Kind::Danger, true, cx).on_click(cx.listener(|ws, _, _, cx| ws.run_confirm(cx)))),
            )
        } else {
            return None;
        };
        Some(
            div()
                .absolute()
                .top_0()
                .left_0()
                .size_full()
                .bg(gpui::rgba(0x0000_0066))
                .flex()
                .items_center()
                .justify_center()
                .occlude()
                .child(dialog)
                .into_any_element(),
        )
    }
}

impl Render for Workspace {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let t = cx.theme().clone();
        let page = match self.page {
            Page::Dashboard => self.page_dashboard(cx),
            Page::Drives => self.page_drives(cx),
            Page::Vaults => self.page_vaults(cx),
            Page::Groups => self.page_groups(cx),
            Page::Security => self.page_security(cx),
            Page::History => self.page_history(cx),
            Page::Settings => self.page_settings(cx),
        };
        let overlay = self.overlay(cx);
        div()
            .relative()
            .size_full()
            .flex()
            .bg(t.chrome)
            .text_color(t.text)
            .font_family(UI_FONT)
            .text_size(px(12.5))
            .child(self.sidebar(cx))
            .child(
                div()
                    .flex_1()
                    .min_w(px(0.))
                    .h_full()
                    .flex()
                    .flex_col()
                    .when_some(self.status.clone(), |d, s| d.child(div().px(px(20.)).pt(px(12.)).child(ui::notice(s, Tone::Neutral, &t))))
                    .child(div().id("page").flex_1().min_w(px(0.)).overflow_y_scroll().px(px(16.)).py(px(12.)).child(page).with_scrollbar(cx)),
            )
            .when_some(overlay, |d, o| d.child(o))
    }
}
