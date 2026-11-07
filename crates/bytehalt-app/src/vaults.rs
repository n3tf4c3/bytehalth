//! Tela Cofres (Fase 2): escolher a pasta, analisar, criar (senha + chave de recuperação mostrada uma
//! vez), acompanhar a cópia verificada, trocar a pasta pelo cofre, apagar a reserva, bloquear e
//! desbloquear. Toda operação de disco acontece no serviço; aqui só há pedidos pelo pipe.

use crate::client::Failure;
use crate::present::{self, Tone};
use crate::text_input::TextInput;
use crate::theme::{ActiveTheme, UI_FONT};
use crate::ui::{self, Kind};
use crate::workspace::{Confirm, Workspace};
use bytehalt_core::locking::LockState;
use bytehalt_core::vault::VaultStage;
use bytehalt_core::vault_manager::{VaultPlan, VaultView};
use bytehalt_ipc::{Command, Reply};
use gpui::{AnyElement, ClipboardItem, Context, Entity, FontWeight, IntoElement, PathPromptOptions, SharedString, div, prelude::*, px};
use uuid::Uuid;

pub struct VaultForm {
    pub path: Entity<TextInput>,
    pub name: Entity<TextInput>,
    pub pass: Entity<TextInput>,
    pub pass2: Entity<TextInput>,
    pub plan: Option<VaultPlan>,
    pub busy: bool,
}

impl VaultForm {
    pub fn new(cx: &mut Context<Workspace>) -> Self {
        Self {
            path: cx.new(|cx| TextInput::new("", "Pasta (ex.: D:\\Projetos\\cliente)", cx)),
            name: cx.new(|cx| TextInput::new("", "Nome do cofre", cx)),
            pass: cx.new(|cx| TextInput::new("", "Senha do cofre", cx).masked()),
            pass2: cx.new(|cx| TextInput::new("", "Repita a senha", cx).masked()),
            plan: None,
            busy: false,
        }
    }
}

/// Chave de recuperação recém-criada: fica na tela até o usuário confirmar que guardou.
pub struct RecoveryNotice {
    pub id: Uuid,
    pub name: String,
    pub key: String,
    pub saved: bool,
    pub copied: bool,
    pub acknowledging: bool,
    pub message: Option<String>,
}

/// Uma resposta perdida ao confirmar não pode apagar a única cópia visível da chave.
fn complete_recovery_ack(recovery: &mut Option<RecoveryNotice>, id: Uuid, result: Result<Reply, Failure>) -> bool {
    let Some(notice) = recovery.as_mut().filter(|notice| notice.id == id) else { return false };
    notice.acknowledging = false;
    match result {
        Ok(Reply::Ack) => {
            *recovery = None;
            true
        }
        Ok(_) => {
            notice.message = Some("O serviço não confirmou o recebimento. A chave continua nesta tela; tente novamente.".into());
            false
        }
        Err(failure) => {
            notice.message = Some(format!("{} A chave continua nesta tela; tente confirmar novamente.", failure.text()));
            false
        }
    }
}

impl Workspace {
    pub fn refresh_vaults(&mut self, cx: &mut Context<Self>) {
        self.send(Command::GetVaults, cx, |ws, r, cx| {
            if let Ok(Reply::Vaults(list)) = r {
                ws.vaults = list;
                ws.claim_next_created_recovery(cx);
            }
        });
    }

    fn claim_next_created_recovery(&mut self, cx: &mut Context<Self>) {
        if self.recovery.is_some() || self.recovery_request.is_some() || !self.auth.as_ref().is_some_and(|auth| !auth.configured || auth.session_active) {
            return;
        }
        self.recovery_queue.retain(|id| !self.vaults.iter().any(|v| v.vault.id == *id && v.vault.stage == VaultStage::Failed));
        if let Some(id) = self
            .recovery_queue
            .iter()
            .find(|id| self.vaults.iter().any(|v| v.vault.id == **id && v.vault.stage == VaultStage::Ready && v.job.as_ref().is_some_and(|j| j.done)))
            .copied()
        {
            // Uma tentativa por criação; falha de transporte/autenticação tem retentativa explícita.
            self.recovery_queue.retain(|queued| *queued != id);
            self.request_vault_recovery(id, cx);
        }
    }

    pub fn request_vault_recovery(&mut self, id: Uuid, cx: &mut Context<Self>) {
        if self.recovery.is_some() || self.recovery_request.is_some() {
            return;
        }
        let Some(name) = self.vaults.iter().find(|v| v.vault.id == id).map(|v| v.vault.name.clone()) else { return };
        self.recovery_request = Some(id);
        self.send(Command::ClaimVaultRecovery { id }, cx, move |ws, result, _| {
            ws.recovery_request = None;
            match result {
                Ok(Reply::VaultRecovery { id: received, key: Some(key) }) if received == id => {
                    ws.recovery = Some(RecoveryNotice { id, name, key, saved: false, copied: false, acknowledging: false, message: None });
                    ws.vault_message = None;
                }
                Ok(Reply::VaultRecovery { id: received, key: None }) if received == id => {
                    ws.vault_message = Some("A chave não está disponível: ela já foi confirmada ou o serviço foi reiniciado.".into());
                }
                Ok(_) => ws.vault_message = Some("Resposta inesperada ao solicitar a chave de recuperação.".into()),
                Err(failure) => ws.vault_message = Some(failure.text()),
            }
        });
    }

    pub fn acknowledge_vault_recovery(&mut self, cx: &mut Context<Self>) {
        let Some(notice) = self.recovery.as_mut().filter(|notice| notice.saved && !notice.acknowledging) else { return };
        let id = notice.id;
        notice.acknowledging = true;
        notice.message = None;
        self.send(Command::AckVaultRecovery { id }, cx, move |ws, result, cx| {
            if complete_recovery_ack(&mut ws.recovery, id, result) {
                ws.claim_next_created_recovery(cx);
            }
        });
    }

    pub fn choose_folder(&mut self, cx: &mut Context<Self>) {
        let rx = cx.prompt_for_paths(PathPromptOptions { files: false, directories: true, multiple: false, prompt: Some("Escolher pasta".into()) });
        cx.spawn(async move |this, cx| {
            if let Ok(Ok(Some(paths))) = rx.await
                && let Some(p) = paths.into_iter().next()
            {
                let _ = this.update(cx, |ws, cx| {
                    let text = p.to_string_lossy().into_owned();
                    ws.vault_form.path.update(cx, |i, cx| i.set_text(text, cx));
                    ws.analyze_vault(cx);
                });
            }
        })
        .detach();
    }

    pub fn analyze_vault(&mut self, cx: &mut Context<Self>) {
        let path = self.vault_form.path.read(cx).text().trim().to_owned();
        if path.is_empty() {
            self.vault_message = Some("Informe a pasta.".into());
            return;
        }
        self.vault_form.plan = None;
        self.vault_message = Some("Analisando a pasta…".into());
        self.send(Command::AnalyzeVault { path }, cx, |ws, r, cx| match r {
            Ok(Reply::VaultPlan(plan)) => {
                ws.vault_message = None;
                if ws.vault_form.name.read(cx).text().trim().is_empty()
                    && let Some(last) = plan.path.rsplit('\\').next().filter(|s| !s.is_empty())
                {
                    let n = last.to_owned();
                    ws.vault_form.name.update(cx, |i, cx| i.set_text(n, cx));
                }
                ws.vault_form.plan = Some(*plan);
            }
            Ok(_) => {}
            Err(f) => ws.vault_message = Some(f.text()),
        });
    }

    pub fn create_vault(&mut self, cx: &mut Context<Self>) {
        let Some(plan) = self.vault_form.plan.clone().filter(|p| p.ok()) else { return };
        let (pass, pass2) = (self.vault_form.pass.read(cx).text().to_owned(), self.vault_form.pass2.read(cx).text().to_owned());
        if let Some(issue) = present::vault_password_issue(&pass, &pass2) {
            self.vault_message = Some(issue.into());
            return;
        }
        let name = self.vault_form.name.read(cx).text().trim().to_owned();
        self.vault_form.pass.update(cx, |i, cx| i.set_text("", cx));
        self.vault_form.pass2.update(cx, |i, cx| i.set_text("", cx));
        self.vault_form.busy = true;
        self.vault_message = Some("Preparando o cofre…".into());
        let command = Command::PrepareVault { name, path: plan.path.clone(), passphrase: pass, max_bytes: plan.suggested_max_bytes };
        self.send(command, cx, |ws, r, cx| {
            ws.vault_form.busy = false;
            match r {
                Ok(Reply::Vault(v)) => {
                    queue_created_recovery(&mut ws.recovery_queue, v.id);
                    ws.vault_message = Some(format!("Cofre \"{}\" em preparação. A pasta original não é alterada até você confirmar a troca.", v.name));
                    ws.vault_form.plan = None;
                    ws.vault_form.path.update(cx, |i, cx| i.set_text("", cx));
                    ws.vault_form.name.update(cx, |i, cx| i.set_text("", cx));
                }
                Ok(_) => {}
                Err(f) => ws.vault_message = Some(f.text()),
            }
            ws.refresh_vaults(cx);
        });
    }

    pub fn run_vault_confirm(&mut self, c: Confirm, cx: &mut Context<Self>) {
        let (command, done): (Command, &'static str) = match c {
            Confirm::SwapVault(id, ..) => (Command::SwapVault { id }, "Cofre ativo: a pasta agora está protegida."),
            Confirm::DiscardVault(id, ..) => (Command::DiscardVault { id }, "Cofre descartado; a pasta original não foi alterada."),
            Confirm::DeleteReserve(id, ..) => (Command::DeleteVaultReserve { id }, "Reserva apagada."),
            Confirm::RemoveVault(id, ..) => (Command::RemoveVault { id }, "Cofre removido: a pasta voltou a ser uma pasta comum."),
            _ => return,
        };
        self.vault_message = Some("Processando…".into());
        self.send(command, cx, move |ws, r, cx| {
            ws.vault_message = Some(match r {
                Ok(_) => done.to_owned(),
                Err(f) => f.text(),
            });
            ws.refresh_vaults(cx);
            ws.refresh(cx);
        });
    }

    pub fn page_vaults(&self, cx: &mut Context<Self>) -> AnyElement {
        let t = cx.theme().clone();
        let f = &self.vault_form;
        let plan = f.plan.clone();
        let can_create = plan.as_ref().is_some_and(|p| p.ok()) && !f.busy;
        let mut form = ui::card(&t).child(ui::section("Novo cofre", &t)).child(
            div()
                .flex()
                .items_end()
                .gap(px(8.))
                .child(div().flex_1().min_w(px(0.)).child(ui::field("Pasta a proteger", f.path.clone(), &t)))
                .child(ui::button("vault-choose", "Escolher…", Kind::Secondary, true, cx).on_click(cx.listener(|ws, _, _, cx| ws.choose_folder(cx))))
                .child(ui::button("vault-analyze", "Analisar", Kind::Secondary, true, cx).on_click(cx.listener(|ws, _, _, cx| ws.analyze_vault(cx)))),
        );
        if let Some(p) = &plan {
            let inv = &p.inventory;
            form = form.child(ui::muted(
                format!(
                    "{} · {} arquivo(s) em {} pasta(s) · {} · livre na unidade: {} · tamanho máximo do cofre: {}",
                    p.path,
                    inv.files,
                    inv.dirs,
                    present::bytes(inv.bytes),
                    present::bytes(p.free_bytes),
                    present::bytes(p.suggested_max_bytes)
                ),
                &t,
            ));
            for issue in p.issues.iter().take(8) {
                form = form.child(ui::notice(issue.clone(), Tone::Danger, &t));
            }
            for w in &inv.warnings {
                form = form.child(ui::notice(w.clone(), Tone::Warning, &t));
            }
            if p.ok() {
                form = form
                    .child(
                        div()
                            .flex()
                            .gap(px(8.))
                            .child(div().flex_1().min_w(px(0.)).child(ui::field("Nome", f.name.clone(), &t)))
                            .child(div().flex_1().min_w(px(0.)).child(ui::field("Senha (mín. 8)", f.pass.clone(), &t)))
                            .child(div().flex_1().min_w(px(0.)).child(ui::field("Repita a senha", f.pass2.clone(), &t))),
                    )
                    .child(ui::muted(
                        "O ByteHalt não guarda a senha. Ao final você recebe uma chave de recuperação: sem a senha e sem a chave, o conteúdo não pode ser lido.",
                        &t,
                    ))
                    .child(
                        div().flex().justify_end().child(
                            ui::button("vault-create", "Criar cofre", Kind::Primary, can_create, cx)
                                .when(can_create, |b| b.on_click(cx.listener(|ws, _, _, cx| ws.create_vault(cx)))),
                        ),
                    );
            }
        }
        if let Some(m) = &self.vault_message {
            form = form.child(ui::muted(m.clone(), &t));
        }

        let rows = self.rows();
        let mut list = div().flex().flex_col().gap(px(10.));
        if self.vaults.is_empty() {
            list = list.child(ui::card(&t).child(ui::muted("Nenhum cofre ainda.", &t)));
        }
        for v in &self.vaults {
            list = list.child(self.vault_card(v, &rows, cx));
        }

        let mut how = ui::card(&t).child(ui::section("Como funciona", &t));
        for s in [
            "1. A pasta é copiada para um disco virtual (VHDX) com BitLocker e cada arquivo é conferido por SHA-256. O original não é tocado.",
            "2. Na troca, a pasta original vira uma reserva ao lado dela e o cofre é montado no mesmo caminho: projetos e atalhos continuam funcionando.",
            "3. Com o cofre bloqueado, o caminho existe mas nada pode ser lido. Arquivos abertos adiam o bloqueio.",
            "4. A reserva só é apagada quando você pedir. Links, junções e arquivos só na nuvem impedem a migração.",
        ] {
            how = how.child(div().text_size(px(12.5)).child(s));
        }
        div()
            .flex()
            .flex_col()
            .gap(px(12.))
            .child(div().child(ui::title("Cofres", &t)).child(ui::muted(
                "Pastas protegidas por criptografia própria: cada pasta vira um disco virtual VHDX com BitLocker, montado no caminho original.",
                &t,
            )))
            .when(self.snapshot.as_ref().is_some_and(|s| s.simulated), |d| {
                d.child(ui::notice("Modo simulado: o cofre é uma pasta comum ligada por junção; não há disco virtual nem BitLocker.", Tone::Warning, &t))
            })
            .child(form)
            .child(list)
            .child(how)
            .into_any_element()
    }

    fn vault_card(&self, view: &VaultView, rows: &[present::ResourceRow], cx: &mut Context<Self>) -> impl IntoElement {
        let t = cx.theme().clone();
        let v = &view.vault;
        let (stage_text, stage_tone) = present::vault_stage(v.stage);
        let row = v.resource_id.and_then(|rid| rows.iter().find(|r| r.id == rid));
        let (id, name, path) = (v.id, v.name.clone(), v.original_path.clone());
        let mut actions = div().flex().gap(px(6.)).flex_none();
        if matches!(v.stage, VaultStage::Ready | VaultStage::Active) {
            let can_claim = self.recovery.is_none() && self.recovery_request.is_none();
            actions = actions.child(
                ui::button(SharedString::from(format!("recovery-{id}")), "Ver chave de recuperação", Kind::Secondary, can_claim, cx)
                    .when(can_claim, |button| button.on_click(cx.listener(move |ws, _, _, cx| ws.request_vault_recovery(id, cx)))),
            );
        }
        match v.stage {
            VaultStage::Ready => {
                let (n, p) = (name.clone(), path.clone());
                actions = actions.child(ui::button(SharedString::from(format!("swap-{id}")), "Trocar a pasta pelo cofre", Kind::Primary, true, cx).on_click(
                    cx.listener(move |ws, _, _, cx| {
                        ws.confirm = Some(Confirm::SwapVault(id, n.clone(), p.clone()));
                        cx.notify();
                    }),
                ));
            }
            VaultStage::Active => {
                if let Some(r) = row {
                    let (rid, rname, can_lock) = (r.id, r.name.clone(), r.can_lock);
                    let (n, p) = (name.clone(), path.clone());
                    let unlocked = r.state == LockState::Unlocked;
                    actions = actions.child(ui::button(SharedString::from(format!("vremove-{id}")), "Remover cofre", Kind::Danger, unlocked, cx).when(
                        unlocked,
                        |b| {
                            b.on_click(cx.listener(move |ws, _, _, cx| {
                                ws.confirm = Some(Confirm::RemoveVault(id, n.clone(), p.clone()));
                                cx.notify();
                            }))
                        },
                    ));
                    actions = actions.child(
                        ui::button(SharedString::from(format!("vlock-{id}")), "Bloquear", Kind::Primary, can_lock, cx)
                            .when(can_lock, |b| b.on_click(cx.listener(move |ws, _, _, cx| ws.lock(Command::LockResources { ids: vec![rid] }, cx)))),
                    );
                    if r.state == LockState::Locked {
                        actions = actions.child(
                            ui::button(SharedString::from(format!("vunlock-{id}")), "Desbloquear", Kind::Secondary, true, cx)
                                .on_click(cx.listener(move |ws, _, _, cx| ws.open_unlock(rid, rname.clone(), cx))),
                        );
                    }
                }
            }
            _ => {}
        }
        if matches!(v.stage, VaultStage::Ready | VaultStage::Failed) {
            let n = name.clone();
            actions = actions.child(ui::button(SharedString::from(format!("discard-{id}")), "Descartar", Kind::Danger, true, cx).on_click(cx.listener(
                move |ws, _, _, cx| {
                    ws.confirm = Some(Confirm::DiscardVault(id, n.clone()));
                    cx.notify();
                },
            )));
        }
        let mut body = div()
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
                    .child(ui::section(name.clone(), &t))
                    .child(ui::pill(stage_text, stage_tone, &t))
                    .when_some(row, |d, r| d.child(ui::pill(r.state_text.clone(), r.tone, &t))),
            )
            .child(ui::muted(format!("{path}  ·  {} arquivo(s) · {}", v.files, present::bytes(v.bytes)), &t));
        if let Some(j) = view.job.as_ref().filter(|j| !j.done) {
            body = body.child(div().text_size(px(12.5)).child(present::job_progress(j)));
        } else if v.stage == VaultStage::Preparing {
            body = body.child(div().text_size(px(12.5)).child("Preparando…"));
        }
        if let Some(r) = row {
            body = body.child(ui::muted(format!("{}  ·  {}", r.policy_text, r.groups_text), &t));
            if !r.next_lock_text.is_empty() {
                body = body.child(div().text_size(px(12.5)).child(r.next_lock_text.clone()));
            }
        }
        if v.stage == VaultStage::Ready {
            body = body.child(ui::notice(
                "Cópia verificada. Feche editores, terminais e o Explorer nessa pasta e confirme a troca para ativar a proteção.",
                Tone::Warning,
                &t,
            ));
        }
        if let Some(e) = &v.error {
            body = body.child(ui::notice(e.clone(), Tone::Danger, &t));
        }
        if let (VaultStage::Active, Some(reserve)) = (v.stage, v.reserve_path.clone()) {
            let n = name.clone();
            let r2 = reserve.clone();
            body = body.child(
                div()
                    .flex()
                    .items_center()
                    .gap(px(8.))
                    .child(div().flex_1().min_w(px(0.)).child(ui::muted(format!("Original preservado em {reserve}"), &t)))
                    .child(ui::button(SharedString::from(format!("reserve-{id}")), "Apagar reserva", Kind::Danger, true, cx).on_click(cx.listener(
                        move |ws, _, _, cx| {
                            ws.confirm = Some(Confirm::DeleteReserve(id, n.clone(), r2.clone()));
                            cx.notify();
                        },
                    ))),
            );
        }
        let fg = ui::tone_colors(stage_tone, &t).0;
        ui::card(&t).child(div().flex().gap(px(12.)).child(div().pt(px(2.)).child(ui::icon("lock", 22., fg))).child(body).child(actions))
    }

    /// Chave de recuperação: mostrada uma única vez, com cópia para a área de transferência.
    pub fn recovery_dialog(&self, cx: &mut Context<Self>) -> Option<AnyElement> {
        let r = self.recovery.as_ref()?;
        let t = cx.theme().clone();
        let key = r.key.clone();
        Some(
            ui::card(&t)
                .w(px(520.))
                .bg(t.elevated)
                .shadow_lg()
                .child(ui::section(format!("Chave de recuperação do cofre \"{}\"", r.name), &t))
                .child(div().text_size(px(13.)).child(
                    "Esta chave abre o cofre se você esquecer a senha. Guarde fora deste computador (gerenciador de senhas ou papel). Depois de confirmar, o ByteHalt deixa de entregá-la.",
                ))
                .child(
                    div()
                        .p(px(10.))
                        .rounded(px(6.))
                        .bg(t.accent_soft)
                        .font_family(UI_FONT)
                        .font_weight(FontWeight::SEMIBOLD)
                        .text_size(px(15.))
                        .child(key.clone()),
                )
                .child(
                    div()
                        .flex()
                        .items_center()
                        .justify_between()
                        .gap(px(8.))
                        .child(
                            ui::button("recovery-copy", if r.copied { "Copiada" } else { "Copiar" }, Kind::Secondary, true, cx).on_click(cx.listener(
                                move |ws, _, _, cx| {
                                    cx.write_to_clipboard(ClipboardItem::new_string(key.clone()));
                                    if let Some(r) = &mut ws.recovery {
                                        r.copied = true;
                                    }
                                    cx.notify();
                                },
                            )),
                        )
                        .child(ui::checkbox("recovery-saved", "Guardei a chave em lugar seguro", r.saved, cx).on_click(cx.listener(|ws, _, _, cx| {
                            if let Some(r) = &mut ws.recovery && !r.acknowledging {
                                r.saved = !r.saved;
                            }
                            cx.notify();
                        }))),
                )
                .child(
                    div().flex().justify_end().child(
                        ui::button("recovery-done", if r.acknowledging { "Confirmando…" } else { "Continuar" }, Kind::Primary, r.saved && !r.acknowledging, cx)
                            .when(r.saved && !r.acknowledging, |button| {
                                button.on_click(cx.listener(|ws, _, _, cx| ws.acknowledge_vault_recovery(cx)))
                            }),
                    ),
                )
                .when_some(r.message.clone(), |dialog, message| dialog.child(ui::notice(message, Tone::Danger, &t)))
                .into_any_element(),
        )
    }
}

fn queue_created_recovery(queue: &mut Vec<Uuid>, id: Uuid) {
    if !queue.contains(&id) {
        queue.push(id);
    }
}

/// Textos de confirmação dos cofres (título, texto, rótulo do botão).
pub fn confirm_text(c: &Confirm) -> Option<(String, String, &'static str)> {
    Some(match c {
        Confirm::SwapVault(_, n, p) => (
            "Trocar a pasta pelo cofre".into(),
            format!(
                "A pasta {p} será renomeada para uma reserva ao lado dela e o cofre \"{n}\" será montado no mesmo caminho. Antes, o ByteHalt confere de novo cada arquivo. Feche editores, terminais e o Explorer nessa pasta."
            ),
            "Trocar",
        ),
        Confirm::DiscardVault(_, n) => {
            ("Descartar cofre".into(), format!("Descartar o cofre \"{n}\"? O disco do cofre é apagado; a pasta original não é alterada."), "Descartar")
        }
        Confirm::RemoveVault(_, n, p) => (
            "Remover o cofre".into(),
            format!(
                "Devolver {p} ao normal? O conteúdo do cofre \"{n}\" é copiado de volta e conferido por SHA-256; só então o disco do cofre é apagado. O cofre precisa estar desbloqueado e sem arquivos abertos."
            ),
            "Remover",
        ),
        Confirm::DeleteReserve(_, n, r) => (
            "Apagar a reserva".into(),
            format!("Apagar {r}? É a cópia original da pasta, de antes do cofre \"{n}\". O conteúdo continua no cofre, mas esta ação não pode ser desfeita."),
            "Apagar",
        ),
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn awaiting_ack(id: Uuid) -> Option<RecoveryNotice> {
        Some(RecoveryNotice {
            id,
            name: "Cofre de teste".into(),
            key: "chave-sintetica-retida".into(),
            saved: true,
            copied: true,
            acknowledging: true,
            message: None,
        })
    }

    #[test]
    fn lost_ack_response_keeps_key_until_successful_retry() {
        let id = Uuid::new_v4();
        let mut recovery = awaiting_ack(id);
        assert!(!complete_recovery_ack(&mut recovery, id, Err(Failure::Unavailable)));
        let notice = recovery.as_ref().unwrap();
        assert_eq!(notice.id, id);
        assert_eq!(notice.key, "chave-sintetica-retida");
        assert!(notice.saved && notice.copied);
        assert!(!notice.acknowledging);
        assert!(notice.message.is_some());
        assert!(!notice.message.as_ref().unwrap().contains(&notice.key));
        assert!(complete_recovery_ack(&mut recovery, id, Ok(Reply::Ack)));
        assert!(recovery.is_none());
    }

    #[test]
    fn expired_session_or_unexpected_reply_does_not_dismiss_key() {
        let id = Uuid::new_v4();
        let mut recovery = awaiting_ack(id);
        assert!(!complete_recovery_ack(&mut recovery, id, Err(Failure::AuthRequired("Abra a sessão".into()))));
        assert_eq!(recovery.as_ref().unwrap().key, "chave-sintetica-retida");
        assert!(!complete_recovery_ack(&mut recovery, id, Ok(Reply::VaultRecovery { id, key: None })));
        assert!(recovery.is_some());
    }

    #[test]
    fn ack_for_another_vault_cannot_dismiss_current_key() {
        let id = Uuid::new_v4();
        let mut recovery = awaiting_ack(id);
        assert!(!complete_recovery_ack(&mut recovery, Uuid::new_v4(), Ok(Reply::Ack)));
        assert_eq!(recovery.as_ref().unwrap().id, id);
        assert!(recovery.as_ref().unwrap().acknowledging);
    }

    #[test]
    fn created_vault_queue_preserves_multiple_keys_without_duplicate_requests() {
        let first = Uuid::new_v4();
        let second = Uuid::new_v4();
        let mut queue = Vec::new();
        queue_created_recovery(&mut queue, first);
        queue_created_recovery(&mut queue, second);
        queue_created_recovery(&mut queue, first);
        assert_eq!(queue, vec![first, second]);
    }
}
