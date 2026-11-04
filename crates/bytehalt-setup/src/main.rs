//! Instalador do ByteHalt (Fase 5). `bytehalt-setup.exe` instala ou atualiza; `/uninstall` remove;
//! `/quiet` não mostra janelas (códigos de saída em `plan::exit`); `/purge` apaga também os dados.
//! Sempre elevado (manifesto `requireAdministrator`). Nunca toca em unidades nem em cofres.
#![windows_subsystem = "windows"]
#![cfg(windows)]

mod plan;

use bytehalt_core::vault::VaultRepository;
use bytehalt_windows::wide;
use plan::{Mode, RUN_KEY, RUN_VALUE, SERVICE, UNINSTALL_KEY, Value, exit};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};
use std::time::{Duration, Instant};
use windows_service::service::{
    ServiceAccess, ServiceAction, ServiceActionType, ServiceErrorControl, ServiceFailureActions, ServiceFailureResetPeriod, ServiceInfo, ServiceStartType,
    ServiceState, ServiceType,
};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_sys::Win32::Foundation::ERROR_SUCCESS;
use windows_sys::Win32::Storage::FileSystem::{MOVEFILE_DELAY_UNTIL_REBOOT, MoveFileExW};
use windows_sys::Win32::System::Registry::*;
use windows_sys::Win32::UI::Shell::IsUserAnAdmin;
use windows_sys::Win32::UI::WindowsAndMessaging::*;

static APP: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/bytehalt.exe"));
static SERVICE_EXE: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/bytehalt-service.exe"));
static LICENSES: &[(&str, &[u8])] = &[
    ("GPUI-Apache-2.0.txt", include_bytes!("../../../assets/GPUI-APACHE.txt")),
    ("Material-Symbols-Apache-2.0.txt", include_bytes!("../../../assets/icons/LICENSE")),
];
const VERSION: &str = env!("CARGO_PKG_VERSION");
const TITLE: &str = "ByteHalt";
/// Mesma classe e mensagem da bandeja do aplicativo (`bytehalt-app/src/tray.rs`).
const TRAY_CLASS: &str = "ByteHalt.Tray.v1";
const TRAY_QUIT: u32 = WM_APP + 20;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    std::process::exit(match plan::parse(&args) {
        Ok(a) => run(&a),
        Err(e) => {
            message(&e, MB_ICONERROR);
            exit::ERROR
        }
    });
}

struct Ctx {
    quiet: bool,
    log: Vec<String>,
}

impl Ctx {
    fn note(&mut self, s: impl Into<String>) {
        self.log.push(s.into());
    }

    fn ask(&self, text: &str, flags: MESSAGEBOX_STYLE) -> i32 {
        if self.quiet { IDYES } else { message(text, flags) }
    }

    fn done(&mut self, code: i32, text: &str) -> i32 {
        self.note(text.to_owned());
        let log = std::env::temp_dir().join("bytehalt-setup.log");
        // Com a marca UTF-8 (BOM): o PowerShell 5.1 lê o arquivo sem quebrar os acentos.
        let _ = std::fs::write(&log, [b"\xEF\xBB\xBF".as_slice(), self.log.join("\r\n").as_bytes()].concat());
        if !self.quiet {
            message(text, if code == exit::OK { MB_ICONINFORMATION } else { MB_ICONWARNING });
        }
        code
    }
}

fn message(text: &str, flags: MESSAGEBOX_STYLE) -> i32 {
    let (t, c) = (wide(text), wide(TITLE));
    // SAFETY: cadeias terminadas em nulo; sem janela dona.
    unsafe { MessageBoxW(null_mut(), t.as_ptr(), c.as_ptr(), flags | MB_SETFOREGROUND) }
}

fn env_dir(var: &str, fallback: &str) -> PathBuf {
    PathBuf::from(std::env::var_os(var).unwrap_or_else(|| fallback.into()))
}

fn install_dir() -> PathBuf {
    env_dir("ProgramW6432", r"C:\Program Files").join("ByteHalt")
}

fn data_dir() -> PathBuf {
    plan::purge_target(&env_dir("ProgramData", r"C:\ProgramData"))
}

fn shortcut() -> PathBuf {
    env_dir("ProgramData", r"C:\ProgramData").join(r"Microsoft\Windows\Start Menu\Programs\ByteHalt.lnk")
}

fn run(a: &plan::Args) -> i32 {
    let mut cx = Ctx { quiet: a.quiet, log: vec![format!("ByteHalt Setup {VERSION}: {:?}", a)] };
    // SAFETY: consulta sem efeitos colaterais.
    if unsafe { IsUserAnAdmin() } == 0 {
        return cx.done(exit::NOT_ADMIN, "Execute o instalador como administrador.");
    }
    let result = match a.mode {
        Mode::Install => install(&mut cx),
        Mode::Uninstall => uninstall(&mut cx, a.purge),
    };
    match result {
        Ok((code, text)) => cx.done(code, &text),
        Err(e) => cx.done(exit::ERROR, &format!("Falhou: {e:#}")),
    }
}

// ---------------- Instalação ----------------

fn install(cx: &mut Ctx) -> anyhow::Result<(i32, String)> {
    if APP.is_empty() || SERVICE_EXE.is_empty() {
        return Ok((exit::EMPTY_PAYLOAD, "Este instalador foi gerado sem os executáveis (use scripts\\release\\Build-Installer.ps1).".into()));
    }
    let dir = install_dir();
    let upgrade = dir.join("bytehalt-service.exe").exists();
    let text = if upgrade {
        format!("Atualizar o ByteHalt para a versão {VERSION}?\n\nO serviço de proteção é reiniciado; configurações, cofres e histórico são mantidos.")
    } else {
        format!(
            "Instalar o ByteHalt {VERSION}?\n\n• Serviço de proteção (LocalSystem) com início automático\n• Interface na bandeja ao entrar no Windows\n• Pasta: {}",
            dir.display()
        )
    };
    if cx.ask(&text, MB_OKCANCEL | MB_ICONQUESTION) == IDCANCEL {
        return Ok((exit::CANCELLED, "Instalação cancelada.".into()));
    }
    close_ui(cx);
    stop_service(cx)?;
    std::fs::create_dir_all(dir.join("licencas"))?;
    put(cx, &dir.join("bytehalt.exe"), APP)?;
    put(cx, &dir.join("bytehalt-service.exe"), SERVICE_EXE)?;
    for (name, bytes) in LICENSES {
        put(cx, &dir.join("licencas").join(name), bytes)?;
    }
    let me = std::env::current_exe()?;
    let setup = dir.join("bytehalt-setup.exe");
    if !same_file(&me, &setup) {
        put(cx, &setup, &std::fs::read(&me)?)?;
    }
    register_service(cx, &dir)?;
    set_string(HKEY_LOCAL_MACHINE, RUN_KEY, RUN_VALUE, &plan::run_command(&dir))?;
    let size = [APP.len(), SERVICE_EXE.len(), std::fs::metadata(&setup).map_or(0, |m| m.len() as usize)].iter().sum::<usize>() / 1024;
    for (name, value) in plan::uninstall_entries(&dir, VERSION, size as u32) {
        match value {
            Value::Str(s) => set_string(HKEY_LOCAL_MACHINE, UNINSTALL_KEY, name, &s)?,
            Value::Dword(d) => set_dword(HKEY_LOCAL_MACHINE, UNINSTALL_KEY, name, d)?,
        }
    }
    if let Err(e) = create_shortcut(&shortcut(), &dir.join("bytehalt.exe")) {
        cx.note(format!("Atalho do menu Iniciar não criado: {e:#}"));
    }
    start_service(cx)?;
    Ok((
        exit::OK,
        if upgrade {
            format!("ByteHalt atualizado para {VERSION}. Abra pelo menu Iniciar ou pelo ícone da bandeja.")
        } else {
            format!("ByteHalt {VERSION} instalado. Abra pelo menu Iniciar; nas próximas entradas no Windows ele abre na bandeja.")
        },
    ))
}

fn same_file(a: &Path, b: &Path) -> bool {
    matches!((a.canonicalize(), b.canonicalize()), (Ok(x), Ok(y)) if x == y)
}

/// Grava ao lado e troca. Executável em uso: o antigo é renomeado (permitido) e apagado no reinício.
fn put(cx: &mut Ctx, target: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    let tmp = target.with_extension("novo");
    std::fs::write(&tmp, bytes)?;
    if target.exists() && std::fs::remove_file(target).is_err() {
        let old = target.with_extension(format!("antigo-{}", std::process::id()));
        std::fs::rename(target, &old)?;
        delete_on_reboot(&old);
        cx.note(format!("{} em uso: substituído; o antigo será apagado no próximo reinício.", target.display()));
    }
    std::fs::rename(&tmp, target)?;
    Ok(())
}

fn delete_on_reboot(p: &Path) {
    let w = wide(&p.to_string_lossy());
    // SAFETY: caminho terminado em nulo; destino nulo = apagar no reinício.
    unsafe { MoveFileExW(w.as_ptr(), null(), MOVEFILE_DELAY_UNTIL_REBOOT) };
}

/// Pede à interface aberta nesta sessão que encerre (atualização/desinstalação).
fn close_ui(cx: &mut Ctx) {
    let class = wide(TRAY_CLASS);
    for _ in 0..5 {
        // SAFETY: classe terminada em nulo.
        let hwnd = unsafe { FindWindowW(class.as_ptr(), null()) };
        if hwnd.is_null() {
            return;
        }
        // SAFETY: janela encontrada acima; mensagem sem ponteiros.
        unsafe { PostMessageW(hwnd, TRAY_QUIT, 0, 0) };
        cx.note("Interface aberta: pedido para encerrar.");
        std::thread::sleep(Duration::from_millis(800));
    }
}

fn manager() -> anyhow::Result<ServiceManager> {
    ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE)
        .map_err(|e| anyhow::anyhow!("Gerenciador de serviços: {e}"))
}

const ACCESS: ServiceAccess =
    ServiceAccess::QUERY_STATUS.union(ServiceAccess::START).union(ServiceAccess::STOP).union(ServiceAccess::DELETE).union(ServiceAccess::CHANGE_CONFIG);

fn wait_state(service: &windows_service::service::Service, want: ServiceState, secs: u64) -> bool {
    let deadline = Instant::now() + Duration::from_secs(secs);
    while Instant::now() < deadline {
        if service.query_status().is_ok_and(|s| s.current_state == want) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(300));
    }
    false
}

fn stop_service(cx: &mut Ctx) -> anyhow::Result<()> {
    let Ok(s) = manager()?.open_service(SERVICE, ACCESS) else { return Ok(()) };
    if s.query_status().is_ok_and(|st| st.current_state != ServiceState::Stopped) {
        let _ = s.stop();
        anyhow::ensure!(wait_state(&s, ServiceState::Stopped, 30), "O serviço não parou em 30 s.");
        cx.note("Serviço parado.");
    }
    Ok(())
}

fn register_service(cx: &mut Ctx, dir: &Path) -> anyhow::Result<()> {
    let info = ServiceInfo {
        name: OsString::from(SERVICE),
        display_name: OsString::from("ByteHalt"),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: dir.join("bytehalt-service.exe"),
        launch_arguments: vec![OsString::from("--service")],
        dependencies: vec![],
        account_name: None,
        account_password: None,
    };
    let m = manager()?;
    let s = match m.open_service(SERVICE, ACCESS) {
        Ok(s) => {
            s.change_config(&info).map_err(|e| anyhow::anyhow!("Atualizar o serviço: {e}"))?;
            cx.note("Serviço atualizado.");
            s
        }
        Err(_) => {
            let s = m.create_service(&info, ACCESS).map_err(|e| anyhow::anyhow!("Criar o serviço: {e}"))?;
            cx.note("Serviço criado.");
            s
        }
    };
    let _ = s.set_description("Bloqueio automático de unidades BitLocker e cofres de pastas por inatividade.");
    let restart = |secs| ServiceAction { action_type: ServiceActionType::Restart, delay: Duration::from_secs(secs) };
    let _ = s.update_failure_actions(ServiceFailureActions {
        reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(86_400)),
        reboot_msg: None,
        command: None,
        actions: Some(vec![restart(5), restart(5), restart(30)]),
    });
    Ok(())
}

fn start_service(cx: &mut Ctx) -> anyhow::Result<()> {
    let s = manager()?.open_service(SERVICE, ACCESS).map_err(|e| anyhow::anyhow!("Abrir o serviço: {e}"))?;
    s.start::<&str>(&[]).map_err(|e| anyhow::anyhow!("Iniciar o serviço: {e}"))?;
    anyhow::ensure!(wait_state(&s, ServiceState::Running, 30), "O serviço não iniciou em 30 s.");
    cx.note("Serviço em execução.");
    Ok(())
}

// ---------------- Registro ----------------

fn open_key(root: HKEY, path: &str) -> anyhow::Result<HKEY> {
    let p = wide(path);
    let mut key: HKEY = null_mut();
    // SAFETY: caminho terminado em nulo; chave fechada pelo chamador.
    let r = unsafe { RegCreateKeyExW(root, p.as_ptr(), 0, null(), REG_OPTION_NON_VOLATILE, KEY_WRITE | KEY_WOW64_64KEY, null(), &mut key, null_mut()) };
    anyhow::ensure!(r == ERROR_SUCCESS, "Registro {path}: erro {r}");
    Ok(key)
}

fn set_string(root: HKEY, path: &str, name: &str, value: &str) -> anyhow::Result<()> {
    let key = open_key(root, path)?;
    let (n, v) = (wide(name), wide(value));
    // SAFETY: chave aberta acima; dados REG_SZ terminados em nulo (tamanho em bytes).
    let r = unsafe { RegSetValueExW(key, n.as_ptr(), 0, REG_SZ, v.as_ptr() as *const u8, (v.len() * 2) as u32) };
    // SAFETY: chave própria.
    unsafe { RegCloseKey(key) };
    anyhow::ensure!(r == ERROR_SUCCESS, "Registro {path}\\{name}: erro {r}");
    Ok(())
}

fn set_dword(root: HKEY, path: &str, name: &str, value: u32) -> anyhow::Result<()> {
    let key = open_key(root, path)?;
    let n = wide(name);
    // SAFETY: chave aberta acima; 4 bytes de dados.
    let r = unsafe { RegSetValueExW(key, n.as_ptr(), 0, REG_DWORD, &value as *const u32 as *const u8, 4) };
    // SAFETY: chave própria.
    unsafe { RegCloseKey(key) };
    anyhow::ensure!(r == ERROR_SUCCESS, "Registro {path}\\{name}: erro {r}");
    Ok(())
}

fn delete_value(root: HKEY, path: &str, name: &str) {
    let (p, n) = (wide(path), wide(name));
    let mut key: HKEY = null_mut();
    // SAFETY: caminho terminado em nulo; chave fechada abaixo.
    if unsafe { RegOpenKeyExW(root, p.as_ptr(), 0, KEY_SET_VALUE | KEY_WOW64_64KEY, &mut key) } == ERROR_SUCCESS {
        // SAFETY: chave aberta acima.
        unsafe {
            RegDeleteValueW(key, n.as_ptr());
            RegCloseKey(key);
        }
    }
}

fn delete_tree(root: HKEY, path: &str) {
    let p = wide(path);
    // SAFETY: caminho terminado em nulo.
    unsafe { RegDeleteTreeW(root, p.as_ptr()) };
    // A chave em si (RegDeleteTree apaga só o conteúdo).
    // SAFETY: idem.
    unsafe { RegDeleteKeyExW(root, p.as_ptr(), KEY_WOW64_64KEY, 0) };
}

// ---------------- Atalho ----------------

fn create_shortcut(lnk: &Path, target: &Path) -> anyhow::Result<()> {
    use windows::Win32::System::Com::{CLSCTX_INPROC_SERVER, COINIT_APARTMENTTHREADED, CoCreateInstance, CoInitializeEx, CoUninitialize, IPersistFile};
    use windows::Win32::UI::Shell::{IShellLinkW, ShellLink};
    use windows::core::{HSTRING, Interface};
    // SAFETY: COM inicializado nesta thread e encerrado ao fim; interfaces liberadas ao sair do escopo.
    unsafe {
        CoInitializeEx(None, COINIT_APARTMENTTHREADED).ok()?;
        let r = (|| -> windows::core::Result<()> {
            let link: IShellLinkW = CoCreateInstance(&ShellLink, None, CLSCTX_INPROC_SERVER)?;
            link.SetPath(&HSTRING::from(target.as_os_str()))?;
            link.SetDescription(&HSTRING::from("ByteHalt: bloqueio automático de unidades e cofres"))?;
            link.SetIconLocation(&HSTRING::from(target.as_os_str()), 0)?;
            if let Some(dir) = target.parent() {
                link.SetWorkingDirectory(&HSTRING::from(dir.as_os_str()))?;
            }
            link.cast::<IPersistFile>()?.Save(&HSTRING::from(lnk.as_os_str()), true)
        })();
        CoUninitialize();
        r.map_err(|e| anyhow::anyhow!("{e}"))
    }
}

// ---------------- Desinstalação ----------------

fn uninstall(cx: &mut Ctx, purge: bool) -> anyhow::Result<(i32, String)> {
    let data = data_dir();
    let db = data.join("bytehalt.db");
    if db.exists() {
        let vaults = bytehalt_windows::sqlite::SqliteStore::open(&db).and_then(|s| s.vaults()).map_err(|e| anyhow::anyhow!("Ler os cofres: {e:#}"))?;
        if let Some(reason) = plan::refuse_reason(&vaults) {
            return Ok((exit::REFUSED, format!("Desinstalação recusada.\n\n{reason}")));
        }
    }
    if cx.ask(
        "Desinstalar o ByteHalt?\n\nUnidades BitLocker não são alteradas: as bloqueadas continuam bloqueadas (desbloqueie pelo Windows).",
        MB_YESNO | MB_ICONQUESTION,
    ) != IDYES
    {
        return Ok((exit::CANCELLED, "Desinstalação cancelada.".into()));
    }
    let purge = purge
        || (!cx.quiet
            && message(
                "Apagar também as configurações, o histórico e a senha mestra?\n\n(Escolha Não para manter e reaproveitar numa reinstalação.)",
                MB_YESNO | MB_ICONQUESTION | MB_DEFBUTTON2,
            ) == IDYES);
    close_ui(cx);
    stop_service(cx)?;
    if let Ok(s) = manager()?.open_service(SERVICE, ACCESS) {
        s.delete().map_err(|e| anyhow::anyhow!("Remover o serviço: {e}"))?;
        drop(s);
        cx.note("Serviço removido.");
    }
    delete_value(HKEY_LOCAL_MACHINE, RUN_KEY, RUN_VALUE);
    delete_tree(HKEY_LOCAL_MACHINE, UNINSTALL_KEY);
    let _ = std::fs::remove_file(shortcut());
    let dir = install_dir();
    let me = std::env::current_exe()?;
    let mut later = 0;
    if dir.is_dir() {
        for entry in walk(&dir) {
            if same_file(&entry, &me) || (entry.is_file() && std::fs::remove_file(&entry).is_err()) {
                delete_on_reboot(&entry);
                later += 1;
            }
        }
        for d in dirs_deepest_first(&dir) {
            if std::fs::remove_dir(&d).is_err() {
                delete_on_reboot(&d);
            }
        }
    }
    if purge && data.is_dir() {
        // Só exatamente <ProgramData>\ByteHalt (plan::purge_target).
        std::fs::remove_dir_all(&data).map_err(|e| anyhow::anyhow!("Apagar {}: {e}", data.display()))?;
        cx.note(format!("Dados apagados: {}", data.display()));
    }
    let mut text = "ByteHalt desinstalado.".to_owned();
    if !purge && data.is_dir() {
        text.push_str(&format!("\n\nConfigurações e histórico mantidos em {}.", data.display()));
    }
    if later > 0 {
        text.push_str("\n\nAlguns arquivos em uso serão apagados no próximo reinício.");
    }
    Ok((exit::OK, text))
}

fn walk(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).into_iter().flatten().flatten() {
            let p = e.path();
            if p.is_dir() { stack.push(p) } else { out.push(p) }
        }
    }
    out
}

fn dirs_deepest_first(dir: &Path) -> Vec<PathBuf> {
    let mut out = vec![dir.to_path_buf()];
    let mut i = 0;
    while i < out.len() {
        let d = out[i].clone();
        out.extend(std::fs::read_dir(&d).into_iter().flatten().flatten().map(|e| e.path()).filter(|p| p.is_dir()));
        i += 1;
    }
    out.reverse();
    out
}
