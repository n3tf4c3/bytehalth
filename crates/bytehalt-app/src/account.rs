//! Fase 3 na interface: senha mestra, autenticador (QR code) e códigos de recuperação. Senhas e
//! códigos só passam pelo pipe; os campos são limpos logo depois do envio.

use crate::present::Tone;
use crate::text_input::TextInput;
use crate::theme::{ActiveTheme, UI_FONT};
use crate::ui::{self, Kind};
use crate::workspace::Workspace;
use bytehalt_core::master::{Enrollment, MIN_MASTER};
use bytehalt_ipc::{Command, Reply};
use gpui::{AnyElement, ClipboardItem, Context, Div, Entity, FontWeight, Image, ImageFormat, IntoElement, SharedString, div, img, prelude::*, px};
use std::sync::Arc;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Idle,
    /// Cadastro: senha nova (duas vezes).
    SetupPassword,
    /// Cadastro: QR code + primeiro código.
    SetupCode,
    Change,
    Regenerate,
    Forgot,
    /// Recadastrar autenticador: senha + código atual ou de recuperação.
    TotpProof,
    TotpCode,
}

pub struct Account {
    pub mode: Mode,
    pub pass: Entity<TextInput>,
    pub pass2: Entity<TextInput>,
    pub current: Entity<TextInput>,
    pub code: Entity<TextInput>,
    pub enrollment: Option<(Enrollment, Arc<Image>)>,
    pub message: Option<(String, Tone)>,
    pub busy: bool,
}

impl Account {
    pub fn new(cx: &mut Context<Workspace>) -> Self {
        Self {
            mode: Mode::Idle,
            pass: cx.new(|cx| TextInput::new("", "Senha mestra", cx).masked()),
            pass2: cx.new(|cx| TextInput::new("", "Repita a senha", cx).masked()),
            current: cx.new(|cx| TextInput::new("", "Senha mestra atual", cx).masked()),
            code: cx.new(|cx| TextInput::new("", "Código", cx)),
            enrollment: None,
            message: None,
            busy: false,
        }
    }
}

/// Pedido da senha mestra quando uma alteração volta com `AuthRequired`.
pub struct MasterPrompt {
    pub pass: Entity<TextInput>,
    pub message: Option<String>,
    pub busy: bool,
}

/// Códigos de recuperação recém-gerados: ficam na tela até o usuário confirmar que guardou.
pub struct CodesNotice {
    pub codes: Vec<String>,
    pub saved: bool,
    pub copied: bool,
}

pub fn qr_image(uri: &str) -> Option<Arc<Image>> {
    let code = qrcode::QrCode::new(uri.as_bytes()).ok()?;
    let svg = code.render::<qrcode::render::svg::Color>().min_dimensions(220, 220).quiet_zone(true).build();
    Some(Arc::new(Image::from_bytes(ImageFormat::Svg, svg.into_bytes())))
}

/// Segredo em grupos de 4 para digitar no aplicativo.
pub fn grouped(secret: &str) -> String {
    secret.as_bytes().chunks(4).map(|c| String::from_utf8_lossy(c).into_owned()).collect::<Vec<_>>().join(" ")
}

impl Workspace {
    fn text(&self, e: &Entity<TextInput>, cx: &Context<Self>) -> String {
        e.read(cx).text().to_owned()
    }

    fn clear_account_fields(&mut self, cx: &mut Context<Self>) {
        for e in [&self.account.pass, &self.account.pass2, &self.account.current, &self.account.code] {
            e.update(cx, |i, cx| i.set_text("", cx));
        }
    }

    pub fn set_account_mode(&mut self, mode: Mode, cx: &mut Context<Self>) {
        self.clear_account_fields(cx);
        self.account.mode = mode;
        self.account.message = None;
        if !matches!(mode, Mode::SetupCode | Mode::TotpCode) {
            self.account.enrollment = None;
        }
        cx.notify();
    }

    pub fn refresh_auth(&mut self, cx: &mut Context<Self>) {
        self.send(Command::GetAuthStatus, cx, |ws, r, _| {
            if let Ok(Reply::AuthStatus(s)) = r {
                ws.auth = Some(s);
            }
        });
    }

    fn account_done(&mut self, r: Result<Reply, crate::client::Failure>, ok: &str, cx: &mut Context<Self>) -> Option<Reply> {
        self.account.busy = false;
        match r {
            Ok(reply) => {
                self.account.message = Some((ok.to_owned(), Tone::Good));
                self.refresh_auth(cx);
                Some(reply)
            }
            Err(f) => {
                self.account.message = Some((f.text(), Tone::Danger));
                None
            }
        }
    }

    fn enroll(&mut self, reply: Option<Reply>, next: Mode) {
        if let Some(Reply::Enrollment(e)) = reply
            && let Some(image) = qr_image(&e.uri)
        {
            self.account.enrollment = Some((e, image));
            self.account.mode = next;
            self.account.message = None;
        }
    }

    fn show_codes(&mut self, reply: Option<Reply>) {
        if let Some(Reply::RecoveryCodes(codes)) = reply {
            self.codes = Some(CodesNotice { codes, saved: false, copied: false });
        }
    }

    /// Botão principal do formulário atual.
    pub fn account_submit(&mut self, cx: &mut Context<Self>) {
        if self.account.busy {
            return;
        }
        let (pass, pass2, current, code) =
            (self.text(&self.account.pass, cx), self.text(&self.account.pass2, cx), self.text(&self.account.current, cx), self.text(&self.account.code, cx));
        let needs_new = matches!(self.account.mode, Mode::SetupPassword | Mode::Change | Mode::Forgot);
        if needs_new && pass != pass2 {
            self.account.message = Some(("As senhas não conferem.".into(), Tone::Danger));
            return;
        }
        if needs_new && pass.chars().count() < MIN_MASTER {
            self.account.message = Some((format!("A senha mestra precisa de pelo menos {MIN_MASTER} caracteres."), Tone::Danger));
            return;
        }
        let mode = self.account.mode;
        let command = match mode {
            Mode::Idle => return,
            Mode::SetupPassword => Command::BeginAuthSetup { password: pass },
            Mode::SetupCode => Command::FinishAuthSetup { code },
            Mode::Change => Command::ChangeMasterPassword { current, new: pass },
            Mode::Regenerate => Command::RegenerateRecoveryCodes { password: current },
            Mode::Forgot => Command::ResetMasterPassword { recovery_code: code, new: pass },
            Mode::TotpProof => Command::BeginTotpReset { password: current, proof: code },
            Mode::TotpCode => Command::FinishTotpReset { code },
        };
        self.clear_account_fields(cx);
        self.account.busy = true;
        self.send(command, cx, move |ws, r, cx| match mode {
            Mode::SetupPassword => {
                let reply = ws.account_done(r, "", cx);
                ws.enroll(reply, Mode::SetupCode);
            }
            Mode::SetupCode => {
                let reply = ws.account_done(r, "Senha mestra e autenticador cadastrados. Configurações liberadas por 15 minutos.", cx);
                if reply.is_some() {
                    ws.account.mode = Mode::Idle;
                    ws.account.enrollment = None;
                }
                ws.show_codes(reply);
            }
            Mode::Change | Mode::Forgot => {
                if ws.account_done(r, "Senha mestra alterada.", cx).is_some() {
                    ws.account.mode = Mode::Idle;
                }
            }
            Mode::Regenerate => {
                let reply = ws.account_done(r, "Novos códigos gerados; os anteriores deixaram de valer.", cx);
                if reply.is_some() {
                    ws.account.mode = Mode::Idle;
                }
                ws.show_codes(reply);
            }
            Mode::TotpProof => {
                let reply = ws.account_done(r, "", cx);
                ws.enroll(reply, Mode::TotpCode);
            }
            Mode::TotpCode => {
                if ws.account_done(r, "Autenticador recadastrado; o anterior deixou de valer.", cx).is_some() {
                    ws.account.mode = Mode::Idle;
                    ws.account.enrollment = None;
                }
            }
            Mode::Idle => {}
        });
    }

    pub fn end_auth_session(&mut self, cx: &mut Context<Self>) {
        self.send(Command::EndAuthSession, cx, |ws, _, cx| {
            ws.account.message = Some(("Sessão encerrada: alterações voltam a pedir a senha mestra.".into(), Tone::Neutral));
            ws.refresh_auth(cx);
        });
    }

    pub fn open_master_prompt(&mut self, message: Option<String>, cx: &mut Context<Self>) {
        if self.master.is_none() {
            self.master = Some(MasterPrompt { pass: cx.new(|cx| TextInput::new("", "Senha mestra", cx).masked()), message, busy: false });
        }
    }

    pub fn confirm_master(&mut self, cx: &mut Context<Self>) {
        let Some(p) = &mut self.master else { return };
        if p.busy {
            return;
        }
        p.busy = true;
        let password = p.pass.read(cx).text().to_owned();
        p.pass.update(cx, |i, cx| i.set_text("", cx));
        self.send(Command::Authenticate { password }, cx, |ws, r, cx| match r {
            Ok(Reply::AuthStatus(s)) => {
                ws.auth = Some(s);
                ws.master = None;
                ws.account.message = None;
                ws.status = Some("Configurações liberadas por 15 minutos. Repita a alteração.".into());
                ws.refresh(cx);
            }
            Ok(_) => {}
            Err(f) => {
                if let Some(p) = &mut ws.master {
                    p.busy = false;
                    p.message = Some(f.text());
                }
            }
        });
    }

    fn form(&self, mode: Mode, cx: &mut Context<Self>) -> Div {
        let t = cx.theme().clone();
        let a = &self.account;
        let row = |fields: Vec<AnyElement>| div().flex().gap(px(8.)).children(fields);
        let field = |label: &'static str, e: &Entity<TextInput>| div().flex_1().min_w(px(0.)).child(ui::field(label, e.clone(), &t)).into_any_element();
        let (title, body, submit): (&str, Div, &str) = match mode {
            Mode::SetupPassword => (
                "Criar a senha mestra",
                div().flex().flex_col().gap(px(6.)).child(row(vec![field("Senha mestra (mín. 12)", &a.pass), field("Repita a senha", &a.pass2)])).child(ui::muted(
                    "Ela libera as alterações de configuração e os cofres. Não é a senha das unidades nem do Windows. O ByteHalt guarda só um hash (Argon2id).",
                    &t,
                )),
                "Continuar",
            ),
            Mode::SetupCode | Mode::TotpCode => {
                let (e, image) = a.enrollment.clone().expect("cadastro em andamento");
                (
                    "Cadastrar o aplicativo autenticador",
                    div()
                        .flex()
                        .gap(px(14.))
                        .child(div().p(px(6.)).bg(gpui::white()).rounded(px(6.)).child(img(image).size(px(200.))))
                        .child(
                            div()
                                .flex_1()
                                .min_w(px(0.))
                                .flex()
                                .flex_col()
                                .gap(px(6.))
                                .child(div().text_size(px(13.)).child(
                                    "1. No celular, abra um aplicativo autenticador (Microsoft Authenticator, Google Authenticator, 2FAS, Aegis…) e leia o QR code.",
                                ))
                                .child(div().text_size(px(13.)).child("2. Ou digite a chave manualmente:"))
                                .child(div().font_family(UI_FONT).font_weight(FontWeight::SEMIBOLD).text_size(px(13.)).child(grouped(&e.secret)))
                                .child(div().text_size(px(13.)).child("3. Digite o código de 6 dígitos que aparece no aplicativo."))
                                .child(field("Código de 6 dígitos", &a.code)),
                        ),
                    "Confirmar",
                )
            }
            Mode::Change => ("Trocar a senha mestra", row(vec![field("Senha atual", &a.current), field("Nova senha", &a.pass), field("Repita a nova", &a.pass2)]), "Trocar"),
            Mode::Regenerate => (
                "Gerar novos códigos de recuperação",
                div().flex().flex_col().gap(px(6.)).child(row(vec![field("Senha mestra", &a.current)])).child(ui::muted("Os códigos anteriores deixam de valer.", &t)),
                "Gerar",
            ),
            Mode::Forgot => (
                "Esqueci a senha mestra",
                div().flex().flex_col().gap(px(6.)).child(row(vec![field("Código de recuperação", &a.code), field("Nova senha", &a.pass), field("Repita a nova", &a.pass2)])).child(
                    ui::muted("Cada código de recuperação vale uma vez.", &t),
                ),
                "Redefinir",
            ),
            Mode::TotpProof => (
                "Recadastrar o autenticador (celular novo ou perdido)",
                div()
                    .flex()
                    .flex_col()
                    .gap(px(6.))
                    .child(row(vec![field("Senha mestra", &a.current), field("Código atual ou de recuperação", &a.code)]))
                    .child(ui::muted("Só a senha mestra não basta: ela precisa vir com o código atual do aplicativo ou um código de recuperação.", &t)),
                "Continuar",
            ),
            Mode::Idle => return div(),
        };
        div().flex().flex_col().gap(px(8.)).p(px(10.)).rounded(px(8.)).border_1().border_color(t.border).child(ui::section(title, &t)).child(body).child(
            div()
                .flex()
                .justify_end()
                .gap(px(8.))
                .child(
                    ui::button("account-cancel", "Cancelar", Kind::Secondary, true, cx)
                        .on_click(cx.listener(|ws, _, _, cx| ws.set_account_mode(Mode::Idle, cx))),
                )
                .child(ui::button("account-submit", submit, Kind::Primary, !a.busy, cx).on_click(cx.listener(|ws, _, _, cx| ws.account_submit(cx)))),
        )
    }

    /// Cartão "Senha mestra e autenticador" da tela Segurança.
    pub fn account_card(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let t = cx.theme().clone();
        let mut card = ui::card(&t).child(ui::section("Senha mestra e autenticador", &t));
        let Some(s) = self.auth.clone() else {
            return card.child(ui::muted("Consultando…", &t));
        };
        let mode = self.account.mode;
        if !s.configured {
            card = card
                .child(ui::notice(
                    "Sem senha mestra, qualquer sessão do dono pode mudar a proteção, e o desbloqueio depois de 24 h não é possível pelo ByteHalt (falta o autenticador).",
                    Tone::Warning,
                    &t,
                ))
                .when(mode == Mode::Idle, |c| {
                    c.child(div().flex().child(
                        ui::button("account-setup", "Criar senha mestra", Kind::Primary, true, cx)
                            .on_click(cx.listener(|ws, _, _, cx| ws.set_account_mode(Mode::SetupPassword, cx))),
                    ))
                });
        } else {
            let session = match s.session_secs_left {
                Some(secs) => (format!("Configurações liberadas por mais {} min.", secs.div_ceil(60)), Tone::Good),
                None => ("Configurações protegidas: alterações pedem a senha mestra.".to_owned(), Tone::Neutral),
            };
            card = card
                .child(
                    div()
                        .flex()
                        .items_center()
                        .gap(px(8.))
                        .child(ui::pill(session.0, session.1, &t))
                        .child(ui::muted(format!("Autenticador cadastrado · {} código(s) de recuperação restante(s)", s.recovery_left), &t)),
                )
                .when_some(s.wait_secs, |c, w| c.child(ui::notice(format!("Muitas tentativas erradas: aguarde {w} s."), Tone::Warning, &t)));
            if mode == Mode::Idle {
                let mut buttons = div().flex().flex_wrap().gap(px(6.));
                buttons = if s.session_active {
                    buttons.child(
                        ui::button("account-end", "Encerrar sessão", Kind::Secondary, true, cx).on_click(cx.listener(|ws, _, _, cx| ws.end_auth_session(cx))),
                    )
                } else {
                    buttons.child(
                        ui::button("account-login", "Liberar configurações", Kind::Primary, true, cx)
                            .on_click(cx.listener(|ws, _, _, cx| ws.open_master_prompt(None, cx))),
                    )
                };
                for (id, label, m) in [
                    ("account-change", "Trocar senha", Mode::Change),
                    ("account-codes", "Novos códigos de recuperação", Mode::Regenerate),
                    ("account-totp", "Recadastrar autenticador", Mode::TotpProof),
                    ("account-forgot", "Esqueci a senha mestra", Mode::Forgot),
                ] {
                    buttons =
                        buttons.child(ui::button(id, label, Kind::Secondary, true, cx).on_click(cx.listener(move |ws, _, _, cx| ws.set_account_mode(m, cx))));
                }
                card = card.child(buttons);
            }
        }
        card = card.child(self.form(mode, cx));
        if let Some((m, tone)) = self.account.message.clone().filter(|(m, _)| !m.is_empty()) {
            card = card.child(ui::notice(m, tone, &t));
        }
        card
    }

    pub fn master_dialog(&self, cx: &mut Context<Self>) -> Option<AnyElement> {
        let p = self.master.as_ref()?;
        let t = cx.theme().clone();
        Some(
            ui::card(&t)
                .w(px(420.))
                .bg(t.elevated)
                .shadow_lg()
                .child(ui::section("Senha mestra", &t))
                .child(ui::muted("As alterações de configuração e dos cofres ficam liberadas por 15 minutos para este usuário do Windows.", &t))
                .child(ui::field("Senha mestra do ByteHalt", p.pass.clone(), &t))
                .when_some(p.message.clone(), |c, m| c.child(ui::notice(m, Tone::Warning, &t)))
                .child(
                    div()
                        .flex()
                        .justify_end()
                        .gap(px(8.))
                        .child(ui::button("master-cancel", "Cancelar", Kind::Secondary, true, cx).on_click(cx.listener(|ws, _, _, cx| {
                            ws.master = None;
                            cx.notify();
                        })))
                        .child(ui::button("master-ok", "Liberar", Kind::Primary, !p.busy, cx).on_click(cx.listener(|ws, _, _, cx| ws.confirm_master(cx)))),
                )
                .into_any_element(),
        )
    }

    pub fn codes_dialog(&self, cx: &mut Context<Self>) -> Option<AnyElement> {
        let n = self.codes.as_ref()?;
        let t = cx.theme().clone();
        let all = n.codes.join("\n");
        let mut grid = div().flex().flex_wrap().gap(px(8.)).p(px(10.)).rounded(px(6.)).bg(t.accent_soft);
        for (i, c) in n.codes.iter().enumerate() {
            grid = grid.child(
                div()
                    .w(px(140.))
                    .font_family(UI_FONT)
                    .font_weight(FontWeight::SEMIBOLD)
                    .text_size(px(14.))
                    .child(SharedString::from(format!("{:>2}. {c}", i + 1))),
            );
        }
        Some(
            ui::card(&t)
                .w(px(520.))
                .bg(t.elevated)
                .shadow_lg()
                .child(ui::section("Códigos de recuperação", &t))
                .child(div().text_size(px(13.)).child(
                    "Cada código vale uma vez: redefine a senha mestra ou recadastra o autenticador se você perder o celular. Esta é a única vez que eles aparecem. Guarde fora deste computador.",
                ))
                .child(grid)
                .child(
                    div()
                        .flex()
                        .items_center()
                        .justify_between()
                        .child(
                            ui::button("codes-copy", if n.copied { "Copiados" } else { "Copiar" }, Kind::Secondary, true, cx).on_click(cx.listener(
                                move |ws, _, _, cx| {
                                    cx.write_to_clipboard(ClipboardItem::new_string(all.clone()));
                                    if let Some(n) = &mut ws.codes {
                                        n.copied = true;
                                    }
                                    cx.notify();
                                },
                            )),
                        )
                        .child(ui::checkbox("codes-saved", "Guardei os códigos em lugar seguro", n.saved, cx).on_click(cx.listener(|ws, _, _, cx| {
                            if let Some(n) = &mut ws.codes {
                                n.saved = !n.saved;
                            }
                            cx.notify();
                        }))),
                )
                .child(div().flex().justify_end().child(ui::button("codes-done", "Continuar", Kind::Primary, n.saved, cx).when(n.saved, |b| {
                    b.on_click(cx.listener(|ws, _, _, cx| {
                        ws.codes = None;
                        cx.notify();
                    }))
                })))
                .into_any_element(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn qr_e_chave_agrupada() {
        assert!(qr_image("otpauth://totp/ByteHalt:x?secret=ABCDEFGHIJKLMNOP&issuer=ByteHalt").is_some());
        assert_eq!(grouped("ABCDEFGHIJ"), "ABCD EFGH IJ");
    }
}
