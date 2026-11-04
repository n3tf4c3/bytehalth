//! Versão portátil sem scripts: `bytehalt.exe --portable demo|real` sobe o serviço em console ao lado do
//! executável (demo: simulado, como o usuário; real: elevado pelo UAC) e abre a interface;
//! `bytehalt.exe --portable-stop` fecha a interface pela bandeja e encerra o serviço pelo pipe
//! (`StopConsole`, aceito só no console). "Sair" na bandeja também encerra o serviço portátil.
//! Tudo pelo executável assinado: nada de PowerShell (antivírus vigiam `-ExecutionPolicy Bypass`, e
//! políticas de aplicativo põem scripts sem assinatura em modo restrito).

use crate::client::Client;
use bytehalt_ipc::{Command, Reply};
use bytehalt_windows::wide;
use std::path::PathBuf;
use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use windows_sys::Win32::UI::Shell::{SEE_MASK_NOASYNC, SHELLEXECUTEINFOW, ShellExecuteExW};
use windows_sys::Win32::UI::WindowsAndMessaging::{FindWindowW, MB_ICONERROR, MB_ICONWARNING, MessageBoxW, PostMessageW, SW_HIDE, WM_APP};

/// A interface foi aberta pelo portátil: "Sair" também encerra o serviço.
pub static ACTIVE: AtomicBool = AtomicBool::new(false);

const TRAY_CLASS: &str = "ByteHalt.Tray.v1";
/// Mesma mensagem de saída da bandeja (`tray.rs`).
const TRAY_QUIT: u32 = WM_APP + 20;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Demo,
    Real,
}

pub fn parse(v: &str) -> Option<Mode> {
    match v {
        "demo" => Some(Mode::Demo),
        "real" => Some(Mode::Real),
        _ => None,
    }
}

fn base() -> anyhow::Result<PathBuf> {
    Ok(std::env::current_exe()?.parent().ok_or_else(|| anyhow::anyhow!("pasta do executável"))?.to_path_buf())
}

pub fn message(text: &str, warn: bool) {
    let (t, c) = (wide(text), wide("ByteHalt"));
    // SAFETY: cadeias terminadas em nulo; sem janela dona.
    unsafe { MessageBoxW(null_mut(), t.as_ptr(), c.as_ptr(), if warn { MB_ICONWARNING } else { MB_ICONERROR }) };
}

fn ping(client: &Client) -> Option<bool> {
    match client.call(Command::Ping) {
        Ok(Reply::Pong { simulated, .. }) => Some(simulated),
        _ => None,
    }
}

/// Garante o serviço portátil no modo pedido (inicia se não houver).
pub fn ensure_service(mode: Mode, client: &Client) -> anyhow::Result<()> {
    if let Some(simulated) = ping(client) {
        anyhow::ensure!(
            simulated == (mode == Mode::Demo),
            "O ByteHalt já está aberto no outro modo ({}). Use \"Encerrar\" antes de trocar.",
            if simulated { "demonstração" } else { "real" }
        );
        return Ok(());
    }
    let dir = base()?;
    let service = dir.join("bytehalt-service.exe");
    anyhow::ensure!(service.exists(), "bytehalt-service.exe não está ao lado do bytehalt.exe.");
    match mode {
        Mode::Demo => {
            use std::os::windows::process::CommandExt;
            const CREATE_NO_WINDOW: u32 = 0x0800_0000;
            std::process::Command::new(&service).arg("--simulate").arg("--data-dir").arg(dir.join("dados")).creation_flags(CREATE_NO_WINDOW).spawn()?;
        }
        Mode::Real => {
            // BitLocker exige administrador: o Windows pede a confirmação (UAC).
            let (verb, file) = (wide("runas"), wide(&service.to_string_lossy()));
            let params = wide(&format!("--data-dir \"{}\"", dir.join("dados-real").display()));
            let mut info = SHELLEXECUTEINFOW {
                cbSize: std::mem::size_of::<SHELLEXECUTEINFOW>() as u32,
                fMask: SEE_MASK_NOASYNC,
                lpVerb: verb.as_ptr(),
                lpFile: file.as_ptr(),
                lpParameters: params.as_ptr(),
                nShow: SW_HIDE,
                ..Default::default()
            };
            // SAFETY: estrutura inicializada com cadeias vivas até o retorno.
            anyhow::ensure!(unsafe { ShellExecuteExW(&mut info) } != 0, "O modo real precisa da permissão de administrador (BitLocker).");
        }
    }
    let deadline = Instant::now() + Duration::from_secs(25);
    while Instant::now() < deadline {
        if ping(client).is_some() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(300));
    }
    anyhow::bail!("O serviço do ByteHalt não iniciou.")
}

/// Fecha a interface (pela bandeja) e encerra o serviço portátil.
pub fn stop(client: &Client) {
    let class = wide(TRAY_CLASS);
    // SAFETY: classe terminada em nulo; título nulo = qualquer.
    let find = || unsafe { FindWindowW(class.as_ptr(), null()) };
    let hwnd = find();
    if !hwnd.is_null() {
        // SAFETY: janela encontrada acima; mensagem sem ponteiros.
        unsafe { PostMessageW(hwnd, TRAY_QUIT, 0, 0) };
        let deadline = Instant::now() + Duration::from_secs(10);
        while !find().is_null() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(200));
        }
    }
    // A interface já pede o encerramento ao sair; aqui cobre o serviço sem interface aberta.
    let _ = client.call(Command::StopConsole);
}

/// Chamado ao "Sair" da interface aberta pelo portátil.
pub fn on_exit(client: &Client) {
    if ACTIVE.load(Ordering::SeqCst) {
        let _ = client.call(Command::StopConsole);
    }
}
