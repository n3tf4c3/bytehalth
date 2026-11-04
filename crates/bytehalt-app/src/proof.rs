//! Prova visual (feature `gui-test`): roteiro em tempo real contra o serviço SIMULADO, com capturas.
//! Substitui a UI Automation (o GPUI não a expõe). Cada passo é gravado em `proof.json` assim que
//! termina, com o resultado real; nada é dado como aprovado sem verificação.

use crate::workspace::{Page, Workspace};
use bytehalt_core::journal::EventType;
use bytehalt_core::locking::LockState;
use bytehalt_core::simulated::TEST_PASSPHRASE;
use bytehalt_ipc::Command;
use gpui::{App, AsyncWindowContext, WeakEntity, WindowHandle};
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

#[derive(Serialize)]
struct Step {
    suite: &'static str,
    name: String,
    status: &'static str,
    seconds: f64,
    detail: Option<String>,
}

struct Proof {
    dir: PathBuf,
    steps: Vec<Step>,
    shot: usize,
}

impl Proof {
    fn record(&mut self, suite: &'static str, name: &str, started: Instant, result: Result<Option<String>, String>) {
        let (status, detail) = match result {
            Ok(d) => ("passed", d),
            Err(e) => ("failed", Some(e)),
        };
        eprintln!("{} {suite} :: {name}{}", status.to_uppercase(), detail.as_ref().map(|d| format!(" — {d}")).unwrap_or_default());
        self.steps.push(Step { suite, name: name.into(), status, seconds: (started.elapsed().as_secs_f64() * 10.0).round() / 10.0, detail });
        let _ = std::fs::write(self.dir.join("proof.json"), serde_json::to_vec_pretty(&self.steps).unwrap_or_default());
    }

    fn skip(&mut self, suite: &'static str, name: &str, why: &str) {
        self.steps.push(Step { suite, name: name.into(), status: "skipped", seconds: 0.0, detail: Some(why.into()) });
        let _ = std::fs::write(self.dir.join("proof.json"), serde_json::to_vec_pretty(&self.steps).unwrap_or_default());
    }
}

type This = WeakEntity<Workspace>;

async fn sleep(cx: &mut AsyncWindowContext, ms: u64) {
    cx.background_executor().timer(Duration::from_millis(ms)).await;
}

async fn until(this: &This, cx: &mut AsyncWindowContext, secs: u64, f: impl Fn(&Workspace) -> bool) -> bool {
    let deadline = Instant::now() + Duration::from_secs(secs);
    loop {
        if this.update(cx, |ws, _| f(ws)).unwrap_or(false) {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        sleep(cx, 250).await;
    }
}

fn check(ok: bool, msg: impl Into<String>) -> Result<Option<String>, String> {
    if ok { Ok(None) } else { Err(msg.into()) }
}

async fn shot(p: &mut Proof, cx: &mut AsyncWindowContext, name: &str) {
    sleep(cx, 450).await;
    p.shot += 1;
    let path = p.dir.join("shots").join(format!("{:02}-{name}.png", p.shot));
    let _ = cx.update(|w, cx| {
        w.refresh();
        w.draw(cx).clear(cx);
        if let Ok(img) = w.render_to_image() {
            let _ = img.save(&path);
        }
    });
}

fn state_of(ws: &Workspace, target: &str) -> Option<LockState> {
    ws.snapshot.as_ref()?.resources.iter().find(|v| v.resource.target == target).map(|v| v.state)
}

fn pending(ws: &Workspace, target: &str) -> bool {
    ws.snapshot.as_ref().and_then(|s| s.resources.iter().find(|v| v.resource.target == target)).is_some_and(|v| v.pending_lock)
}

fn id_of(ws: &Workspace, target: &str) -> Option<uuid::Uuid> {
    ws.snapshot.as_ref()?.resources.iter().find(|v| v.resource.target == target).map(|v| v.resource.id)
}

fn marker(dir: &Path, name: &str) {
    let _ = std::fs::write(dir.join(name), b"1");
}

/// Sondagem curta: espera a conexão (até 25 s), grava o texto de conexão e uma captura, e encerra.
/// Usada para provar que a interface sem `--dev` aceita o pipe do serviço do sistema.
pub fn probe(window: WindowHandle<Workspace>, dir: PathBuf, cx: &mut App) {
    let _ = std::fs::create_dir_all(dir.join("shots"));
    let _ = window.update(cx, |_, w, cx| {
        cx.spawn_in(w, async move |this, cx| {
            let ok = until(&this, cx, 25, |ws| ws.connected == Some(true)).await;
            let text = this.update(cx, |ws, _| ws.connection.clone()).unwrap_or_default();
            let mut p = Proof { dir: dir.clone(), steps: Vec::new(), shot: 0 };
            shot(&mut p, cx, "probe").await;
            let _ = std::fs::write(dir.join("probe.json"), serde_json::to_vec(&serde_json::json!({ "connected": ok, "text": text })).unwrap_or_default());
            let _ = this.update(cx, |_, cx| cx.quit());
        })
        .detach();
    });
}

pub fn start(window: WindowHandle<Workspace>, dir: PathBuf, cx: &mut App) {
    let _ = std::fs::create_dir_all(dir.join("shots"));
    let _ = window.update(cx, |_, w, cx| {
        cx.spawn_in(w, async move |this, cx| {
            let mut p = Proof { dir: dir.clone(), steps: Vec::new(), shot: 0 };
            run(&this, cx, &mut p).await;
            marker(&dir, "proof-done");
            let _ = this.update(cx, |_, cx| cx.quit());
        })
        .detach();
    });
}

async fn run(this: &This, cx: &mut AsyncWindowContext, p: &mut Proof) {
    const I: &str = "Interface";
    const T: &str = "Temporizadores";
    const A: &str = "Autenticação";
    const F: &str = "Falhas";
    const B: &str = "Bandeja";

    let s = Instant::now();
    let ok = until(this, cx, 25, |ws| ws.connected == Some(true)).await;
    let text = this.update(cx, |ws, _| ws.connection.clone()).unwrap_or_default();
    p.record(I, "Interface conecta ao serviço (modo simulado)", s, if ok && text.contains("simulado") { Ok(Some(text)) } else { Err(text) });
    if !ok {
        p.skip(I, "Demais casos", "Interrompidos: a interface não conectou ao serviço.");
        return;
    }

    for (page, name) in [
        (Page::Dashboard, "dashboard"),
        (Page::Drives, "unidades"),
        (Page::Vaults, "cofres"),
        (Page::Groups, "grupos"),
        (Page::Security, "seguranca"),
        (Page::History, "historico"),
        (Page::Settings, "configuracoes"),
    ] {
        let s = Instant::now();
        let _ = this.update(cx, |ws, cx| {
            ws.page = page;
            cx.notify();
        });
        shot(p, cx, &format!("tela-{name}-claro")).await;
        let r = this.update(cx, |ws, _| ws.page == page).unwrap_or(false);
        p.record(I, &format!("Tela {name} abre"), s, check(r, "página não mudou"));
    }

    // Unidades
    let s = Instant::now();
    let _ = this.update(cx, |ws, cx| {
        ws.page = Page::Drives;
        ws.discover(cx);
    });
    let found = until(this, cx, 10, |ws| ws.volumes.len() >= 3).await;
    let r = this
        .update(cx, |ws, _| {
            let sys = ws.volumes.iter().find(|v| v.is_system_volume).map(|v| v.drive_letter.clone());
            (sys.clone(), ws.selected_volume.clone(), sys.is_some() && ws.selected_volume != sys)
        })
        .unwrap_or((None, None, false));
    p.record(I, "Unidade do sistema aparece mas não pode ser escolhida", s, check(found && r.2, format!("sistema {:?}, selecionada {:?}", r.0, r.1)));
    for letter in ["D:", "E:"] {
        let s = Instant::now();
        let _ = this.update(cx, |ws, cx| {
            ws.selected_volume = Some(letter.into());
            let name = format!("Unidade {letter}");
            ws.drive_name.update(cx, |i, cx| i.set_text(name, cx));
            ws.add_drive(cx);
        });
        let ok = until(this, cx, 10, |ws| id_of(ws, letter).is_some()).await;
        p.record(I, &format!("Adicionar unidade {letter} (simulada)"), s, check(ok, "recurso não apareceu"));
    }
    shot(p, cx, "unidades-cadastradas").await;
    let s = Instant::now();
    let _ = this.update(cx, |ws, cx| ws.discover(cx));
    sleep(cx, 1500).await;
    let blocked = this.update(cx, |ws, _| !ws.can_add_drive()).unwrap_or(false);
    p.record(I, "\"Adicionar\" fica desabilitado quando só restam unidades cadastradas ou do sistema", s, check(blocked, "botão habilitado"));

    // Tema escuro e persistência
    let s = Instant::now();
    let _ = this.update(cx, |ws, cx| ws.set_dark(true, cx));
    for (page, name) in [(Page::Settings, "configuracoes-escuro"), (Page::Drives, "unidades-escuro"), (Page::Dashboard, "dashboard-escuro")] {
        let _ = this.update(cx, |ws, cx| {
            ws.page = page;
            cx.notify();
        });
        shot(p, cx, name).await;
    }
    let saved = std::fs::read_to_string(p.dir.join("ui-settings.json")).unwrap_or_default();
    let _ = this.update(cx, |ws, cx| ws.set_dark(false, cx));
    p.record(I, "Troca de tema (escuro) e persistência", s, check(saved.contains("\"dark\": true"), format!("preferência gravada: {saved}")));

    // Grupos
    let make_group = |name: &'static str, timeout: usize, letter: &'static str| {
        move |ws: &mut Workspace, cx: &mut gpui::Context<Workspace>| {
            ws.page = Page::Groups;
            ws.new_group(cx);
            let id = id_of(ws, letter);
            if let Some(e) = &mut ws.editor {
                e.name.update(cx, |i, cx| i.set_text(name, cx));
                e.timeout = timeout;
                e.selected.extend(id);
            }
            ws.save_group(cx);
        }
    };
    let s = Instant::now();
    let _ = this.update(cx, make_group("Discos", 0, "D:"));
    let ok = until(this, cx, 10, |ws| ws.snapshot.as_ref().is_some_and(|s| s.groups.iter().any(|g| g.name == "Discos"))).await;
    let t0 = Instant::now();
    p.record(I, "Criação de grupo \"Discos\" (1 minuto, D:)", s, check(ok, "grupo não apareceu"));
    let s = Instant::now();
    let _ = this.update(cx, make_group("Credenciais", 1, "E:"));
    let ok = until(this, cx, 10, |ws| ws.snapshot.as_ref().is_some_and(|s| s.groups.iter().any(|g| g.name == "Credenciais"))).await;
    p.record(I, "Criação de grupo \"Credenciais\" (5 minutos, E:)", s, check(ok, "grupo não apareceu"));
    shot(p, cx, "grupos").await;

    // 1 minuto com atividade aos 40 s
    let s = Instant::now();
    while t0.elapsed() < Duration::from_secs(40) {
        sleep(cx, 250).await;
    }
    let _ = this.update(cx, |ws, cx| {
        if let Some(id) = id_of(ws, "D:") {
            ws.send(Command::SimulateActivity { id }, cx, |_, _, _| {});
        }
    });
    while t0.elapsed() < Duration::from_secs(75) {
        sleep(cx, 250).await;
    }
    let st = this.update(cx, |ws, _| state_of(ws, "D:")).ok().flatten();
    p.record(T, "Atividade aos 40 s reinicia o contador de 1 minuto", s, check(st == Some(LockState::Unlocked), format!("D: aos 75 s: {st:?}")));
    let s = Instant::now();
    let ok = until(this, cx, 60, |ws| state_of(ws, "D:") == Some(LockState::Locked)).await;
    let elapsed = t0.elapsed().as_secs();
    let _ = this.update(cx, |ws, cx| {
        ws.page = Page::Drives;
        cx.notify();
    });
    shot(p, cx, "bloqueio-por-inatividade").await;
    p.record(
        T,
        "Inatividade de 1 minuto bloqueia D:",
        s,
        if ok { Ok(Some(format!("bloqueado {elapsed} s após criar o grupo (atividade aos 40 s)"))) } else { Err("D: não bloqueou".into()) },
    );
    let s = Instant::now();
    let ok = until(this, cx, 10, |ws| ws.shown_notifications.iter().any(|n| n.contains("Unidade D:") && n.contains("inatividade"))).await;
    p.record(I, "Notificação de bloqueio na bandeja", s, check(ok, "nenhuma notificação de bloqueio registrada"));

    // Desbloqueio pela interface
    let s = Instant::now();
    let _ = this.update(cx, |ws, cx| {
        if let Some(id) = id_of(ws, "D:") {
            ws.open_unlock(id, "Unidade D:".into(), cx);
        }
    });
    let loaded = until(this, cx, 10, |ws| ws.unlock.as_ref().is_some_and(|d| d.requirement.is_some())).await;
    let primary = this.update(cx, |ws, _| ws.unlock.as_ref().and_then(|d| d.requirement.as_ref()).is_some_and(|r| !r.requires_totp())).unwrap_or(false);
    let _ = this.update(cx, |ws, cx| {
        if let Some(d) = &ws.unlock {
            d.pass.update(cx, |i, cx| i.set_text("senha-errada", cx));
        }
        ws.confirm_unlock(cx);
    });
    let refused = until(this, cx, 10, |ws| ws.unlock.as_ref().and_then(|d| d.message.as_ref()).is_some_and(|m| m.contains("incorreta"))).await;
    shot(p, cx, "desbloqueio-senha-errada").await;
    p.record(
        A,
        "Desbloqueio: senha errada é recusada (antes de 24 h só senha)",
        s,
        check(loaded && primary && refused, format!("exigência carregada {loaded}, só senha {primary}, recusa {refused}")),
    );
    let s = Instant::now();
    let _ = this.update(cx, |ws, cx| {
        if let Some(d) = &ws.unlock {
            d.pass.update(cx, |i, cx| i.set_text(TEST_PASSPHRASE, cx));
        }
        ws.confirm_unlock(cx);
    });
    let ok = until(this, cx, 10, |ws| ws.unlock.is_none() && state_of(ws, "D:") == Some(LockState::Unlocked)).await;
    p.record(A, "Desbloqueio: senha correta", s, check(ok, "D: continua bloqueado"));

    // Validação e edição de grupo
    let s = Instant::now();
    let _ = this.update(cx, |ws, cx| {
        ws.page = Page::Groups;
        ws.new_group(cx);
        ws.save_group(cx);
    });
    let err = this.update(cx, |ws, _| ws.editor.as_ref().and_then(|e| e.error.clone())).ok().flatten();
    shot(p, cx, "grupo-validacao").await;
    let _ = this.update(cx, |ws, cx| {
        ws.editor = None;
        cx.notify();
    });
    p.record(I, "Validação de grupo sem nome", s, check(err.as_deref().is_some_and(|e| e.contains("nome")), format!("{err:?}")));
    let s = Instant::now();
    let mut renamed = true;
    for name in ["Credenciais (editado)", "Credenciais"] {
        let _ = this.update(cx, move |ws, cx| {
            if let Some(g) = ws.snapshot.as_ref().and_then(|s| s.groups.iter().find(|g| g.name.starts_with("Credenciais")).cloned()) {
                ws.edit_group(&g, cx);
                if let Some(e) = &ws.editor {
                    e.name.update(cx, |i, cx| i.set_text(name, cx));
                }
                ws.save_group(cx);
            }
        });
        renamed &= until(this, cx, 10, move |ws| ws.snapshot.as_ref().is_some_and(|s| s.groups.iter().any(|g| g.name == name))).await;
    }
    p.record(I, "Edição de grupo (renomear e voltar)", s, check(renamed, "nome não mudou"));

    // Segurança: exigência dos bloqueados
    let s = Instant::now();
    let _ = this.update(cx, |ws, cx| {
        if let Some(id) = id_of(ws, "D:") {
            ws.lock(Command::LockResources { ids: vec![id] }, cx);
        }
    });
    let _ = until(this, cx, 10, |ws| state_of(ws, "D:") == Some(LockState::Locked)).await;
    let _ = this.update(cx, |ws, cx| {
        ws.page = Page::Security;
        ws.check_requirements(cx);
    });
    let ok = until(this, cx, 10, |ws| ws.requirements.iter().any(|(n, r)| n == "Unidade D:" && !r.requires_totp())).await;
    shot(p, cx, "seguranca-exigencias").await;
    p.record(A, "Segurança mostra a exigência dos recursos bloqueados", s, check(ok, "sem linha para Unidade D:"));

    // 5 minutos com arquivo em uso
    let s = Instant::now();
    let _ = this.update(cx, |ws, cx| {
        if let Some(id) = id_of(ws, "E:") {
            ws.send(Command::SimulateVolume { id, present: None, locked: None, open_handles: Some(1), auto_unlock: None }, cx, |_, _, _| {});
        }
    });
    let ok = until(this, cx, 360, |ws| pending(ws, "E:")).await;
    let at = t0.elapsed().as_secs();
    let _ = this.update(cx, |ws, cx| {
        ws.page = Page::Dashboard;
        cx.notify();
    });
    shot(p, cx, "dashboard-bloqueio-adiado").await;
    p.record(
        T,
        "Arquivo em uso adia o bloqueio de 5 minutos de E:",
        s,
        if ok { Ok(Some(format!("adiado {at} s após criar os grupos (limite de 5 min)"))) } else { Err("E: não ficou pendente".into()) },
    );
    let s = Instant::now();
    let ok = until(this, cx, 5, |ws| ws.tray.as_ref().is_some_and(|t| t.icon() == crate::tray::TrayIcon::Attention && t.tooltip().contains("pendente"))).await;
    let tip = this.update(cx, |ws, _| ws.tray.as_ref().map(|t| t.tooltip())).ok().flatten();
    p.record(B, "Ícone da bandeja em atenção e dica com bloqueio pendente", s, check(ok, format!("dica: {tip:?}")));
    let s = Instant::now();
    let _ = this.update(cx, |ws, cx| {
        if let Some(id) = id_of(ws, "E:") {
            ws.send(Command::SimulateVolume { id, present: None, locked: None, open_handles: Some(0), auto_unlock: None }, cx, |_, _, _| {});
        }
    });
    let ok = until(this, cx, 90, |ws| state_of(ws, "E:") == Some(LockState::Locked)).await;
    p.record(T, "Arquivo fechado: nova tentativa bloqueia E:", s, check(ok, "E: não bloqueou após liberar"));

    // Histórico
    let s = Instant::now();
    let _ = this.update(cx, |ws, cx| {
        ws.page = Page::History;
        cx.notify();
    });
    let _ = until(this, cx, 5, |ws| ws.history.iter().any(|e| e.event == EventType::LockPostponed)).await;
    shot(p, cx, "historico").await;
    let r = this
        .update(cx, |ws, _| {
            let all: String = ws.history.iter().map(|e| format!("{} {:?}\n", e.message, e.detail)).collect();
            (
                ws.history.iter().any(|e| e.event == EventType::Locked && e.message.contains("inatividade")),
                ws.history.iter().any(|e| e.event == EventType::LockPostponed),
                !all.contains(TEST_PASSPHRASE) && !all.contains("senha-errada"),
            )
        })
        .unwrap_or((false, false, false));
    p.record(
        I,
        "Histórico registra bloqueio e adiamento, sem senhas",
        s,
        check(r.0 && r.1 && r.2, format!("inatividade {}, adiamento {}, sem senhas {}", r.0, r.1, r.2)),
    );

    vault_steps(this, cx, p).await;
    auth_steps(this, cx, p).await;

    // Falha e recuperação do serviço (o roteiro do Sandbox derruba e reinicia o processo).
    let s = Instant::now();
    marker(&p.dir, "request-stop-service");
    let down = until(this, cx, 30, |ws| ws.connected == Some(false)).await;
    shot(p, cx, "servico-indisponivel").await;
    p.record(F, "Serviço encerrado: interface mostra indisponível", s, check(down, "a interface não percebeu a queda"));
    let s = Instant::now();
    marker(&p.dir, "request-start-service");
    let up = until(this, cx, 45, |ws| ws.connected == Some(true) && state_of(ws, "D:").is_some()).await;
    let r = this.update(cx, |ws, _| (state_of(ws, "D:"), ws.snapshot.as_ref().map_or(0, |s| s.groups.len()))).unwrap_or((None, 0));
    p.record(
        F,
        "Serviço reiniciado: estado e grupos preservados",
        s,
        check(up && r.0 == Some(LockState::Locked) && r.1 == 2, format!("D: {:?}, grupos {}", r.0, r.1)),
    );

    // Bandeja e janela
    let s = Instant::now();
    let has_tray = this.update(cx, |ws, _| ws.tray.is_some()).unwrap_or(false);
    let menu = this.update(cx, |ws, _| ws.tray.as_ref().map(|t| t.proof_menu()).unwrap_or_default()).unwrap_or_default();
    p.record(
        B,
        "Ícone na bandeja com menu (Abrir, Bloquear tudo, grupos, Sair)",
        s,
        check(has_tray && menu.iter().any(|(l, _)| l == "Bloquear grupo: Discos") && menu.iter().any(|(l, _)| l == "Sair"), format!("{menu:?}")),
    );
    let s = Instant::now();
    let _ = this.update(cx, |ws, cx| {
        if let Some(id) = id_of(ws, "D:") {
            ws.send(Command::Unlock { id, passphrase: TEST_PASSPHRASE.into(), totp: None }, cx, |_, _, _| {});
        }
    });
    let _ = until(this, cx, 10, |ws| state_of(ws, "D:") == Some(LockState::Unlocked)).await;
    let _ = this.update(cx, |ws, _| {
        ws.status = None;
        if let Some(t) = &ws.tray {
            t.proof_post(crate::tray::TrayAction::LockAll);
        }
    });
    let ok = until(this, cx, 10, |ws| state_of(ws, "D:") == Some(LockState::Locked) && ws.status.as_deref().is_some_and(|m| m.contains("bloquead"))).await;
    p.record(B, "\"Bloquear tudo\" pelo menu da bandeja", s, check(ok, "D: não bloqueou pelo menu"));
    let s = Instant::now();
    // Todos os recursos (unidades e o cofre da prova) devem aparecer bloqueados na dica.
    let ok = until(this, cx, 5, |ws| {
        let n = ws.snapshot.as_ref().map_or(0, |s| s.resources.len());
        ws.tray.as_ref().is_some_and(|t| t.icon() == crate::tray::TrayIcon::Locked && t.tooltip().contains(&format!("{n} bloqueado")))
    })
    .await;
    let tip = this.update(cx, |ws, _| ws.tray.as_ref().map(|t| t.tooltip())).ok().flatten();
    p.record(B, "Ícone da bandeja fechado e dica com tudo bloqueado", s, if ok { Ok(tip) } else { Err(format!("dica: {tip:?}")) });
    let s = Instant::now();
    let _ = this.update(cx, |ws, _| {
        if let Some(pn) = &ws.panel {
            pn.proof_post(false);
        }
    });
    let hidden = until(this, cx, 5, |ws| ws.panel.as_ref().is_some_and(|p| !p.visible())).await;
    let _ = this.update(cx, |ws, _| {
        if let Some(t) = &ws.tray {
            t.proof_post(crate::tray::TrayAction::Open);
        }
    });
    let back = until(this, cx, 5, |ws| ws.panel.as_ref().is_some_and(|p| p.visible())).await;
    p.record(B, "Fechar a janela mantém o ByteHalt na bandeja e \"Abrir\" restaura", s, check(hidden && back, format!("escondeu {hidden}, voltou {back}")));
    let s = Instant::now();
    let hint = this.update(cx, |ws, _| ws.shown_notifications.iter().any(|n| n.contains("continua em execução na bandeja"))).unwrap_or(false);
    p.record(B, "Primeira ida para a bandeja avisa que o ByteHalt continua em execução", s, check(hint, "aviso não mostrado"));
    let s = Instant::now();
    let _ = this.update(cx, |ws, _| {
        if let Some(pn) = &ws.panel {
            pn.hide();
        }
    });
    let hidden = until(this, cx, 5, |ws| ws.panel.as_ref().is_some_and(|p| !p.visible())).await;
    // Mesmo caminho de uma segunda instância aberta pelo menu Iniciar.
    let delivered = crate::tray::signal_existing();
    let back = until(this, cx, 5, |ws| ws.panel.as_ref().is_some_and(|p| p.visible())).await;
    p.record(
        B,
        "Abrir o ByteHalt de novo traz o painel que já está na bandeja",
        s,
        check(hidden && delivered && back, format!("escondeu {hidden}, sinal {delivered}, voltou {back}")),
    );
    let s = Instant::now();
    let _ = this.update(cx, |ws, _| {
        if let Some(pn) = &ws.panel {
            pn.proof_post(true);
        }
    });
    let hidden = until(this, cx, 5, |ws| ws.panel.as_ref().is_some_and(|p| !p.visible())).await;
    let _ = this.update(cx, |ws, _| ws.show());
    let back = until(this, cx, 5, |ws| ws.panel.as_ref().is_some_and(|p| p.visible())).await;
    p.record(B, "Minimizar leva para a bandeja", s, check(hidden && back, format!("escondeu {hidden}, voltou {back}")));
    let _ = this.update(cx, |ws, cx| {
        ws.page = Page::Dashboard;
        cx.notify();
    });
    shot(p, cx, "final").await;
}

fn vault_of(ws: &Workspace) -> Option<&bytehalt_core::vault_manager::VaultView> {
    ws.vaults.first()
}

/// Cofre no modo simulado, numa pasta descartável indicada pelo roteiro do Sandbox
/// (`BYTEHALT_PROOF_VAULT_DIR`, fora da pasta de exportação mapeada do host).
async fn vault_steps(this: &This, cx: &mut AsyncWindowContext, p: &mut Proof) {
    use crate::workspace::Confirm;
    use bytehalt_core::vault::VaultStage;
    const V: &str = "Cofres";
    let Some(folder) = std::env::var_os("BYTEHALT_PROOF_VAULT_DIR").map(PathBuf::from).filter(|d| d.join("README.md").exists()) else {
        p.skip(V, "Fluxo do cofre", "BYTEHALT_PROOF_VAULT_DIR ausente: pasta de teste não preparada pelo roteiro.");
        return;
    };
    let path = folder.to_string_lossy().into_owned();

    let s = Instant::now();
    let _ = this.update(cx, |ws, cx| {
        ws.page = Page::Vaults;
        ws.vault_form.path.update(cx, |i, cx| i.set_text(path.clone(), cx));
        ws.analyze_vault(cx);
    });
    let ok = until(this, cx, 15, |ws| ws.vault_form.plan.as_ref().is_some_and(|p| p.ok())).await;
    shot(p, cx, "cofre-analise").await;
    let detail = this.update(cx, |ws, _| ws.vault_form.plan.as_ref().map(|p| (p.inventory.files, p.issues.clone()))).ok().flatten();
    p.record(V, "Análise da pasta: inventário e espaço, sem impedimentos", s, check(ok && detail.as_ref().is_some_and(|d| d.0 == 3), format!("{detail:?}")));

    let s = Instant::now();
    let msg = this
        .update(cx, |ws, cx| {
            ws.vault_form.pass.update(cx, |i, cx| i.set_text("curta", cx));
            ws.vault_form.pass2.update(cx, |i, cx| i.set_text("curta", cx));
            ws.create_vault(cx);
            ws.vault_message.clone()
        })
        .ok()
        .flatten();
    p.record(V, "Senha curta é recusada antes de chegar ao serviço", s, check(msg.as_deref().is_some_and(|m| m.contains("8 caracteres")), format!("{msg:?}")));

    let s = Instant::now();
    let _ = this.update(cx, |ws, cx| {
        ws.vault_form.pass.update(cx, |i, cx| i.set_text("senha-do-cofre-1", cx));
        ws.vault_form.pass2.update(cx, |i, cx| i.set_text("senha-do-cofre-1", cx));
        ws.create_vault(cx);
    });
    let shown = until(this, cx, 40, |ws| ws.recovery.is_some()).await;
    shot(p, cx, "cofre-chave-recuperacao").await;
    let key = this.update(cx, |ws, _| ws.recovery.as_ref().map(|r| r.key.clone())).ok().flatten().unwrap_or_default();
    let well_formed = key.split('-').count() == 8 && key.split('-').all(|g| g.len() == 6 && g.chars().all(|c| c.is_ascii_digit()));
    p.record(V, "Cofre preparado: chave de recuperação mostrada para guardar", s, check(shown && well_formed, format!("chave: {} caractere(s)", key.len())));

    let s = Instant::now();
    let _ = this.update(cx, |ws, cx| {
        if let Some(r) = &mut ws.recovery {
            r.saved = true;
        }
        ws.recovery = None;
        cx.notify();
    });
    let ready = until(this, cx, 30, |ws| vault_of(ws).is_some_and(|v| v.vault.stage == VaultStage::Ready)).await;
    shot(p, cx, "cofre-pronto").await;
    let original_intact = folder.join("README.md").exists() && !std::fs::symlink_metadata(&folder).is_ok_and(|m| m.file_type().is_symlink());
    p.record(
        V,
        "Cópia verificada; a pasta original continua intacta até a troca",
        s,
        check(ready && original_intact, format!("pronto {ready}, original intacto {original_intact}")),
    );

    let s = Instant::now();
    let _ = this.update(cx, |ws, cx| {
        if let Some(v) = vault_of(ws).map(|v| v.vault.clone()) {
            ws.confirm = Some(Confirm::SwapVault(v.id, v.name, v.original_path));
        }
        cx.notify();
    });
    shot(p, cx, "cofre-confirmar-troca").await;
    let _ = this.update(cx, |ws, cx| ws.run_confirm(cx));
    let active = until(this, cx, 30, |ws| {
        vault_of(ws).is_some_and(|v| v.vault.stage == VaultStage::Active && v.vault.resource_id.is_some_and(|rid| ws.rows().iter().any(|r| r.id == rid)))
    })
    .await;
    shot(p, cx, "cofre-ativo").await;
    let reserve = this.update(cx, |ws, _| vault_of(ws).and_then(|v| v.vault.reserve_path.clone())).ok().flatten().map(PathBuf::from);
    let via_path = std::fs::read(folder.join("README.md")).is_ok_and(|b| b == b"# projeto de teste");
    let kept = reserve.as_ref().is_some_and(|r| r.join("README.md").exists());
    p.record(
        V,
        "Troca: o cofre aparece no caminho original e a reserva fica preservada",
        s,
        check(active && via_path && kept, format!("ativo {active}, caminho {via_path}, reserva {kept}")),
    );

    let s = Instant::now();
    let rid = this.update(cx, |ws, _| vault_of(ws).and_then(|v| v.vault.resource_id)).ok().flatten();
    if let Some(rid) = rid {
        let _ = this.update(cx, |ws, cx| ws.lock(Command::LockResources { ids: vec![rid] }, cx));
        let locked = until(this, cx, 15, |ws| ws.rows().iter().any(|r| r.id == rid && r.state == LockState::Locked)).await;
        shot(p, cx, "cofre-bloqueado").await;
        p.record(V, "Bloquear o cofre pela tela Cofres", s, check(locked, "o cofre não ficou bloqueado"));
        let s = Instant::now();
        let _ = this.update(cx, |ws, cx| {
            let name = ws.rows().into_iter().find(|r| r.id == rid).map(|r| r.name).unwrap_or_default();
            ws.open_unlock(rid, name, cx);
        });
        let _ = until(this, cx, 10, |ws| ws.unlock.as_ref().is_some_and(|d| d.requirement.is_some())).await;
        let _ = this.update(cx, |ws, cx| {
            if let Some(d) = &ws.unlock {
                d.pass.update(cx, |i, cx| i.set_text(TEST_PASSPHRASE, cx));
            }
            ws.confirm_unlock(cx);
        });
        let unlocked = until(this, cx, 15, |ws| ws.unlock.is_none() && ws.rows().iter().any(|r| r.id == rid && r.state == LockState::Unlocked)).await;
        p.record(V, "Desbloquear o cofre com a senha", s, check(unlocked, "o cofre não desbloqueou"));
    } else {
        p.skip(V, "Bloquear e desbloquear o cofre", "cofre sem recurso de bloqueio");
    }

    let s = Instant::now();
    let _ = this.update(cx, |ws, cx| {
        if let Some(v) = vault_of(ws).map(|v| v.vault.clone())
            && let Some(r) = v.reserve_path
        {
            ws.confirm = Some(Confirm::DeleteReserve(v.id, v.name, r));
            ws.run_confirm(cx);
        }
    });
    let gone = until(this, cx, 20, |ws| vault_of(ws).is_some_and(|v| v.vault.reserve_path.is_none())).await;
    let deleted = reserve.as_ref().is_some_and(|r| !r.exists());
    let still = folder.join("src").join("main.rs").exists();
    shot(p, cx, "cofre-sem-reserva").await;
    p.record(
        V,
        "Apagar a reserva mantém o conteúdo no cofre",
        s,
        check(gone && deleted && still, format!("registro {gone}, apagada {deleted}, cofre {still}")),
    );

    let s = Instant::now();
    let _ = this.update(cx, |ws, cx| {
        if let Some(v) = vault_of(ws).map(|v| v.vault.clone()) {
            ws.confirm = Some(Confirm::RemoveVault(v.id, v.name, v.original_path));
        }
        cx.notify();
    });
    shot(p, cx, "cofre-confirmar-remocao").await;
    let _ = this.update(cx, |ws, cx| ws.run_confirm(cx));
    let removed = until(this, cx, 30, |ws| ws.vaults.is_empty()).await;
    let plain = std::fs::symlink_metadata(&folder).is_ok_and(|m| m.is_dir() && !m.file_type().is_symlink());
    let content = std::fs::read(folder.join("README.md")).is_ok_and(|b| b == b"# projeto de teste") && folder.join("src").join("main.rs").exists();
    shot(p, cx, "cofre-removido").await;
    p.record(
        V,
        "Remover o cofre devolve a pasta comum com o conteúdo",
        s,
        check(removed && plain && content, format!("removido {removed}, pasta comum {plain}, conteúdo {content}")),
    );
}

fn totp_now(secret_b32: &str) -> String {
    let secret = data_encoding::BASE32_NOPAD.decode(secret_b32.as_bytes()).unwrap_or_default();
    let secs = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs() as i64);
    bytehalt_core::master::totp(&secret, secs / bytehalt_core::master::STEP_SECS)
}

/// Fase 3: senha mestra + autenticador + códigos de recuperação, e o pedido da senha numa alteração.
async fn auth_steps(this: &This, cx: &mut AsyncWindowContext, p: &mut Proof) {
    use crate::account::Mode;
    const S: &str = "Senha mestra";
    const PASS: &str = "senha-mestra-de-teste";

    let s = Instant::now();
    let _ = this.update(cx, |ws, cx| {
        ws.page = Page::Security;
        ws.set_account_mode(Mode::SetupPassword, cx);
        ws.account.pass.update(cx, |i, cx| i.set_text("curta", cx));
        ws.account.pass2.update(cx, |i, cx| i.set_text("curta", cx));
        ws.account_submit(cx);
    });
    let weak = this.update(cx, |ws, _| ws.account.message.as_ref().is_some_and(|(m, _)| m.contains("12"))).unwrap_or(false);
    p.record(S, "Senha mestra curta é recusada", s, check(weak, "aceitou senha curta"));

    let s = Instant::now();
    let _ = this.update(cx, |ws, cx| {
        ws.account.pass.update(cx, |i, cx| i.set_text(PASS, cx));
        ws.account.pass2.update(cx, |i, cx| i.set_text(PASS, cx));
        ws.account_submit(cx);
    });
    let qr = until(this, cx, 15, |ws| ws.account.mode == Mode::SetupCode && ws.account.enrollment.is_some()).await;
    shot(p, cx, "senha-mestra-qr").await;
    p.record(S, "Cadastro mostra o QR code e a chave do autenticador", s, check(qr, "QR code não apareceu"));

    let s = Instant::now();
    let secret = this.update(cx, |ws, _| ws.account.enrollment.as_ref().map(|(e, _)| e.secret.clone())).ok().flatten().unwrap_or_default();
    let _ = this.update(cx, |ws, cx| {
        let code = totp_now(&secret);
        ws.account.code.update(cx, |i, cx| i.set_text(code, cx));
        ws.account_submit(cx);
    });
    let shown = until(this, cx, 15, |ws| ws.codes.is_some()).await;
    shot(p, cx, "codigos-recuperacao").await;
    let n = this.update(cx, |ws, _| ws.codes.as_ref().map_or(0, |c| c.codes.len())).unwrap_or(0);
    let _ = this.update(cx, |ws, cx| {
        ws.codes = None;
        ws.refresh_auth(cx);
    });
    let active = until(this, cx, 10, |ws| ws.auth.as_ref().is_some_and(|a| a.configured && a.session_active)).await;
    p.record(
        S,
        "Primeiro código confirma o cadastro e entrega 10 códigos de recuperação",
        s,
        check(shown && n == 10 && active, format!("códigos {n}, sessão {active}")),
    );

    let s = Instant::now();
    let _ = this.update(cx, |ws, cx| ws.end_auth_session(cx));
    let _ = until(this, cx, 10, |ws| ws.auth.as_ref().is_some_and(|a| !a.session_active)).await;
    let _ = this.update(cx, |ws, cx| ws.send(Command::DeleteGroup { id: uuid::Uuid::new_v4() }, cx, |_, _, _| {}));
    let asked = until(this, cx, 10, |ws| ws.master.is_some()).await;
    shot(p, cx, "senha-mestra-pedido").await;
    p.record(S, "Alteração sem sessão pede a senha mestra", s, check(asked, "o pedido da senha não apareceu"));

    let s = Instant::now();
    let _ = this.update(cx, |ws, cx| {
        if let Some(m) = &ws.master {
            m.pass.update(cx, |i, cx| i.set_text("errada-errada-errada", cx));
        }
        ws.confirm_master(cx);
    });
    let refused = until(this, cx, 10, |ws| ws.master.as_ref().is_some_and(|m| m.message.as_deref().is_some_and(|t| t.contains("incorreta")))).await;
    let _ = this.update(cx, |ws, cx| {
        if let Some(m) = &ws.master {
            m.pass.update(cx, |i, cx| i.set_text(PASS, cx));
        }
        ws.confirm_master(cx);
    });
    let ok = until(this, cx, 10, |ws| ws.master.is_none() && ws.auth.as_ref().is_some_and(|a| a.session_active)).await;
    shot(p, cx, "senha-mestra-liberada").await;
    p.record(S, "Senha errada é recusada; a certa libera as configurações", s, check(refused && ok, format!("recusa {refused}, liberado {ok}")));
}
