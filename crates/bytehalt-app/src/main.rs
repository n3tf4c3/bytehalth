#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
//! Interface do ByteHalt. `--dev` conecta ao serviço em console do mesmo usuário; `--tray` inicia
//! escondido na bandeja. Sem `--dev`, só o pipe do serviço do sistema (dono SYSTEM) é aceito.

mod account;
mod assets;
mod client;
mod present;
#[cfg(feature = "gui-test")]
mod proof;
mod scrollbar;
mod settings;
mod text_input;
mod theme;
mod tray;
mod ui;
mod vaults;
mod workspace;

use gpui::{App, Bounds, TitlebarOptions, WindowBounds, WindowOptions, prelude::*, px, size};

fn main() {
    if let Err(e) = run() {
        eprintln!("{e:#}");
        std::process::exit(1);
    }
}

fn run() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let development = args.iter().any(|a| a == "--dev");
    let start_hidden = args.iter().any(|a| a == "--tray");
    let client = client::Client::new(development)?;
    #[cfg(feature = "gui-test")]
    let proof = args.iter().position(|a| a == "--gui-proof").and_then(|i| args.get(i + 1)).map(std::path::PathBuf::from);
    #[cfg(feature = "gui-test")]
    let probe = args.iter().position(|a| a == "--gui-probe").and_then(|i| args.get(i + 1)).map(std::path::PathBuf::from);
    #[cfg(feature = "gui-test")]
    let settings_file = match proof.as_ref().or(probe.as_ref()) {
        // A prova usa preferências próprias, nunca as do usuário.
        Some(dir) => settings::SettingsFile::at(dir.join("ui-settings.json")),
        None => settings::SettingsFile::user(),
    };
    #[cfg(not(feature = "gui-test"))]
    let settings_file = settings::SettingsFile::user();
    let dark = settings_file.load().dark;
    let _single = SingleInstance::acquire()?;
    gpui_platform::application().with_assets(assets::Assets).run(move |cx: &mut App| {
        cx.set_global(theme::Themes::new(dark));
        text_input::bind_keys(cx);
        // Densidade compacta (a v0.1 WPF abria grande demais).
        let bounds = Bounds::centered(None, size(px(920.), px(600.)), cx);
        let result = cx.open_window(
            WindowOptions {
                window_bounds: Some(WindowBounds::Windowed(bounds)),
                titlebar: Some(TitlebarOptions { title: Some("ByteHalt".into()), ..Default::default() }),
                window_min_size: Some(size(px(780.), px(500.))),
                focus: !start_hidden,
                show: !start_hidden,
                ..Default::default()
            },
            move |_, cx| cx.new(|cx| workspace::Workspace::new(client, settings_file, cx)),
        );
        match result {
            Ok(window) => {
                let _ = window.update(cx, |ws, w, cx| {
                    let weak = cx.entity().downgrade();
                    w.on_window_should_close(cx, move |_, cx| {
                        let _ = weak.update(cx, |ws, cx| ws.request_close(cx));
                        false
                    });
                    ws.install_desktop(start_hidden, w, cx);
                });
                #[cfg(feature = "gui-test")]
                if let Some(dir) = proof {
                    proof::start(window, dir, cx);
                } else if let Some(dir) = probe {
                    proof::probe(window, dir, cx);
                }
                if !start_hidden {
                    cx.activate(true);
                }
            }
            Err(e) => {
                eprintln!("Janela: {e:#}");
                cx.quit();
            }
        }
    });
    Ok(())
}

/// Uma instância por sessão: a segunda pede à primeira que mostre o painel e encerra.
struct SingleInstance(windows_sys::Win32::Foundation::HANDLE);

impl SingleInstance {
    fn acquire() -> anyhow::Result<Self> {
        use windows_sys::Win32::Foundation::{ERROR_ALREADY_EXISTS, GetLastError};
        let name = bytehalt_windows::wide("Local\\ByteHalt.App.SingleInstance");
        // SAFETY: nome terminado em nulo; o handle vive até o fim do processo.
        let h = unsafe { windows_sys::Win32::System::Threading::CreateMutexW(std::ptr::null(), 1, name.as_ptr()) };
        // SAFETY: lê o erro logo após a criação.
        if h.is_null() || unsafe { GetLastError() } == ERROR_ALREADY_EXISTS {
            // App de bandeja: abrir de novo (menu Iniciar, atalho) mostra o painel que já existe.
            tray::signal_existing();
            std::process::exit(0);
        }
        Ok(Self(h))
    }
}

impl Drop for SingleInstance {
    fn drop(&mut self) {
        // SAFETY: handle próprio.
        unsafe { windows_sys::Win32::Foundation::CloseHandle(self.0) };
    }
}
