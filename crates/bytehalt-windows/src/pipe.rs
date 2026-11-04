//! Pipes nomeados com ACL explícita, verificação do dono pelo cliente e identificação do chamador
//! pelo token do PROCESSO cliente, sem impersonation (docs/ARCHITECTURE.md §6).
//!
//! - Produção: dono SYSTEM; SYSTEM/Administradores com acesso total; usuários interativos só
//!   leitura/gravação de dados (sem FILE_CREATE_PIPE_INSTANCE); rede negada; clientes remotos
//!   recusados; primeira instância com FILE_FLAG_FIRST_PIPE_INSTANCE.
//! - Desenvolvimento: pipe por usuário, dono e único acesso = usuário atual.

use crate::{user, wide};
use bytehalt_ipc::{ErrorCode, Request, Response, parse_request, read_frame, write_frame};
use std::fs::File;
use std::os::windows::io::{FromRawHandle, RawHandle};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::Security::Authorization::*;
use windows_sys::Win32::Security::*;
use windows_sys::Win32::Storage::FileSystem::*;
use windows_sys::Win32::System::Pipes::*;
use windows_sys::Win32::System::Threading::{OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION};

pub const SYSTEM_SID: &str = "S-1-5-18";
const BUFFER: u32 = 64 * 1024;
pub const MAX_CONNECTIONS: usize = 8;

/// Direitos dos usuários interativos: FILE_READ_DATA | FILE_WRITE_DATA | FILE_READ_ATTRIBUTES |
/// FILE_WRITE_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE. Sem FILE_CREATE_PIPE_INSTANCE (0x4).
pub const CLIENT_RIGHTS: u32 = 0x0012_0183;

pub fn production_sddl() -> String {
    format!("O:SYG:SYD:P(D;;GA;;;NU)(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x{CLIENT_RIGHTS:x};;;IU)")
}

pub fn development_sddl(user_sid: &str) -> String {
    format!("O:{user_sid}G:{user_sid}D:P(D;;GA;;;NU)(A;;GA;;;{user_sid})")
}

/// Descritor de segurança próprio (liberado no Drop).
pub struct SecurityDescriptor(PSECURITY_DESCRIPTOR);

// SAFETY: o descritor é memória imutável do processo, só lida pelas APIs após a criação.
unsafe impl Send for SecurityDescriptor {}
// SAFETY: idem; nenhum método o altera.
unsafe impl Sync for SecurityDescriptor {}

impl SecurityDescriptor {
    pub fn from_sddl(sddl: &str) -> anyhow::Result<Self> {
        let s = wide(sddl);
        let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        // SAFETY: SDDL terminado em nulo; `sd` recebe memória do sistema liberada no Drop.
        let ok = unsafe { ConvertStringSecurityDescriptorToSecurityDescriptorW(s.as_ptr(), SDDL_REVISION_1, &mut sd, std::ptr::null_mut()) };
        anyhow::ensure!(ok != 0, "SDDL do pipe inválido ({}).", last_error());
        Ok(Self(sd))
    }

    /// Lista os direitos concedidos a um SID (para testes da ACL).
    pub fn sddl(&self) -> String {
        let mut out: windows_sys::core::PWSTR = std::ptr::null_mut();
        // SAFETY: descritor válido; a cadeia retornada é liberada com LocalFree.
        let ok = unsafe {
            ConvertSecurityDescriptorToStringSecurityDescriptorW(
                self.0,
                SDDL_REVISION_1,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut out,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 || out.is_null() {
            return String::new();
        }
        // SAFETY: `out` é uma cadeia UTF-16 terminada em nulo alocada pelo sistema.
        let s = unsafe { from_pwstr(out) };
        // SAFETY: memória alocada pela API acima.
        unsafe { LocalFree(out.cast()) };
        s
    }
}

impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        // SAFETY: memória alocada por ConvertStringSecurityDescriptorToSecurityDescriptorW.
        unsafe { LocalFree(self.0) };
    }
}

/// SAFETY: `p` deve apontar para UTF-16 terminado em nulo.
unsafe fn from_pwstr(p: *const u16) -> String {
    let mut len = 0;
    // SAFETY: garantido pelo chamador.
    while unsafe { *p.add(len) } != 0 {
        len += 1;
    }
    // SAFETY: `len` unidades válidas lidas acima.
    String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(p, len) })
}

fn last_error() -> u32 {
    // SAFETY: lê o último erro da thread.
    unsafe { GetLastError() }
}

fn pipe_path(name: &str) -> Vec<u16> {
    wide(&format!("\\\\.\\pipe\\{name}"))
}

/// Cria uma instância do servidor. `first` usa FILE_FLAG_FIRST_PIPE_INSTANCE: falha se o nome já existir.
pub fn create_instance(name: &str, sd: &SecurityDescriptor, first: bool) -> anyhow::Result<File> {
    let path = pipe_path(name);
    let sa = SECURITY_ATTRIBUTES { nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32, lpSecurityDescriptor: sd.0, bInheritHandle: 0 };
    let open_mode = PIPE_ACCESS_DUPLEX | if first { FILE_FLAG_FIRST_PIPE_INSTANCE } else { 0 };
    // SAFETY: caminho terminado em nulo; atributos apontam para descritor vivo durante a chamada.
    let h = unsafe {
        CreateNamedPipeW(
            path.as_ptr(),
            open_mode,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            PIPE_UNLIMITED_INSTANCES,
            BUFFER,
            BUFFER,
            0,
            &sa,
        )
    };
    anyhow::ensure!(h != INVALID_HANDLE_VALUE, "Não foi possível criar o pipe {name} ({}).", last_error());
    // SAFETY: handle próprio e válido; o File passa a ser o dono.
    Ok(unsafe { File::from_raw_handle(h as RawHandle) })
}

fn raw(f: &File) -> HANDLE {
    std::os::windows::io::AsRawHandle::as_raw_handle(f) as HANDLE
}

/// Espera um cliente. Retorna erro se a conexão falhar.
pub fn accept(pipe: &File) -> anyhow::Result<()> {
    // SAFETY: handle de servidor válido; operação síncrona.
    let ok = unsafe { ConnectNamedPipe(raw(pipe), std::ptr::null_mut()) };
    anyhow::ensure!(ok != 0 || last_error() == ERROR_PIPE_CONNECTED, "Falha ao aceitar conexão ({}).", last_error());
    Ok(())
}

/// Conecta como cliente (nível de impersonation Identification) e verifica o dono do pipe ANTES de
/// enviar qualquer dado (defesa contra pipe squatting).
pub fn connect(name: &str, allowed_owners: &[String], timeout: Duration) -> anyhow::Result<File> {
    let path = pipe_path(name);
    let deadline = std::time::Instant::now() + timeout;
    let h = loop {
        // SAFETY: caminho terminado em nulo; sem atributos de segurança.
        let h = unsafe {
            CreateFileW(
                path.as_ptr(),
                // Exatamente o que o serviço concede a usuários comuns: GENERIC_READ/WRITE incluiriam
                // FILE_CREATE_PIPE_INSTANCE e atributos estendidos e o acesso seria NEGADO a quem não
                // é administrador (achado na VM, Fase 4).
                CLIENT_RIGHTS,
                0,
                std::ptr::null(),
                OPEN_EXISTING,
                SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
                std::ptr::null_mut(),
            )
        };
        if h != INVALID_HANDLE_VALUE {
            break h;
        }
        let err = last_error();
        anyhow::ensure!(err == ERROR_PIPE_BUSY && std::time::Instant::now() < deadline, "Serviço do ByteHalt indisponível ({err}).");
        // SAFETY: caminho terminado em nulo.
        unsafe { WaitNamedPipeW(path.as_ptr(), 500) };
    };
    // SAFETY: handle de cliente próprio e válido.
    let file = unsafe { File::from_raw_handle(h as RawHandle) };
    let owner = owner_sid(&file)?;
    anyhow::ensure!(allowed_owners.iter().any(|o| o.eq_ignore_ascii_case(&owner)), OwnerRejected(owner));
    Ok(file)
}

/// Pipe com dono diferente do esperado: conexão recusada.
#[derive(Debug)]
pub struct OwnerRejected(pub String);

impl std::fmt::Display for OwnerRejected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "O pipe do ByteHalt não pertence ao serviço esperado (dono {}). Conexão recusada.", self.0)
    }
}

impl std::error::Error for OwnerRejected {}

pub fn owner_sid(f: &File) -> anyhow::Result<String> {
    let mut owner: PSID = std::ptr::null_mut();
    let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: handle válido com READ_CONTROL; `owner` aponta para dentro de `sd`, liberado abaixo.
    let r = unsafe {
        GetSecurityInfo(
            raw(f),
            SE_KERNEL_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut sd,
        )
    };
    anyhow::ensure!(r == ERROR_SUCCESS, "Não foi possível ler o dono do pipe ({r}).");
    // SAFETY: `owner` aponta para dentro de `sd`, liberado só depois.
    let s = unsafe { user::sid_to_string(owner) };
    // SAFETY: memória alocada por GetSecurityInfo.
    unsafe { LocalFree(sd) };
    s
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Caller {
    pub sid: String,
    pub is_admin: bool,
    pub pid: u32,
}

/// Identidade do cliente pelo token do processo (sem ImpersonateNamedPipeClient, que deixava
/// threads com token restrito — achado no Sandbox em 03/11/2026).
pub fn caller(pipe: &File) -> Option<Caller> {
    let mut pid = 0u32;
    // SAFETY: handle de servidor conectado.
    if unsafe { GetNamedPipeClientProcessId(raw(pipe), &mut pid) } == 0 {
        return None;
    }
    // SAFETY: consulta limitada; handle fechado abaixo.
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if process.is_null() {
        return None;
    }
    let mut token: HANDLE = std::ptr::null_mut();
    // SAFETY: processo aberto acima; token fechado abaixo.
    let ok = unsafe { OpenProcessToken(process, TOKEN_QUERY | TOKEN_DUPLICATE, &mut token) };
    // SAFETY: handle próprio.
    unsafe { CloseHandle(process) };
    if ok == 0 {
        return None;
    }
    // SAFETY: token aberto acima com TOKEN_QUERY | TOKEN_DUPLICATE e fechado só depois.
    let result = unsafe { user::token_user_sid(token).ok().map(|sid| Caller { sid, is_admin: user::token_is_admin(token), pid }) };
    // SAFETY: handle próprio.
    unsafe { CloseHandle(token) };
    result
}

/// Servidor com várias instâncias e uma thread por conexão (limitado a [`MAX_CONNECTIONS`]).
pub struct Server {
    name: String,
    stop: Arc<AtomicBool>,
    acceptor: Option<std::thread::JoinHandle<()>>,
}

pub type Handler = Arc<dyn Fn(Request, &Caller) -> Response + Send + Sync>;

impl Server {
    /// A primeira instância é criada antes de retornar: ao voltar, o nome já pertence ao servidor.
    pub fn start(name: &str, sd: SecurityDescriptor, handler: Handler) -> anyhow::Result<Self> {
        let first = create_instance(name, &sd, true)?;
        let stop = Arc::new(AtomicBool::new(false));
        let (n, s) = (name.to_owned(), stop.clone());
        let active = Arc::new(AtomicUsize::new(0));
        let acceptor = std::thread::Builder::new().name("bytehalt-pipe".into()).spawn(move || {
            let mut next = Some(first);
            while !s.load(Ordering::SeqCst) {
                let pipe = match next.take() {
                    Some(p) => p,
                    None => match create_instance(&n, &sd, false) {
                        Ok(p) => p,
                        Err(e) => {
                            eprintln!("{e:#}");
                            std::thread::sleep(Duration::from_millis(200));
                            continue;
                        }
                    },
                };
                if accept(&pipe).is_err() || s.load(Ordering::SeqCst) {
                    continue;
                }
                if active.load(Ordering::SeqCst) >= MAX_CONNECTIONS {
                    continue; // conexão excedente é fechada ao descartar `pipe`
                }
                active.fetch_add(1, Ordering::SeqCst);
                let (h, a) = (handler.clone(), active.clone());
                let _ = std::thread::Builder::new().name("bytehalt-conn".into()).spawn(move || {
                    serve_connection(pipe, h.as_ref());
                    a.fetch_sub(1, Ordering::SeqCst);
                });
            }
        })?;
        Ok(Self { name: name.to_owned(), stop, acceptor: Some(acceptor) })
    }

    pub fn stop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        // Desbloqueia o ConnectNamedPipe pendente com uma conexão vazia.
        let path = pipe_path(&self.name);
        // SAFETY: abre e fecha imediatamente uma conexão local ao próprio pipe.
        unsafe {
            let h = CreateFileW(
                path.as_ptr(),
                GENERIC_READ,
                0,
                std::ptr::null(),
                OPEN_EXISTING,
                SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
                std::ptr::null_mut(),
            );
            if h != INVALID_HANDLE_VALUE {
                CloseHandle(h);
            }
        }
        if let Some(a) = self.acceptor.take() {
            let _ = a.join();
        }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop();
    }
}

fn serve_connection(mut pipe: File, handler: &(dyn Fn(Request, &Caller) -> Response + Send + Sync)) {
    let mut who: Option<Caller> = None;
    // Fim, truncado ou acima do limite: encerra sem processar.
    while let Ok(Some(bytes)) = read_frame(&mut pipe) {
        if who.is_none() {
            who = caller(&pipe);
        }
        let Some(c) = &who else { break };
        let response = match parse_request(&bytes) {
            Ok(request) => {
                let id = request.id;
                match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| handler(request, c))) {
                    Ok(r) => r,
                    // Detalhes internos não vão para o cliente.
                    Err(_) => Response::error(Some(id), ErrorCode::Internal, "Erro interno do serviço."),
                }
            }
            Err(r) => r,
        };
        let Ok(out) = serde_json::to_vec(&response) else { break };
        if write_frame(&mut pipe, &out).is_err() {
            break;
        }
    }
    // SAFETY: desconecta o cliente do handle próprio antes de fechá-lo.
    unsafe { DisconnectNamedPipe(raw(&pipe)) };
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytehalt_ipc::{Command, Reply, call};
    use std::io::Write;

    fn me() -> String {
        user::current_user_sid().unwrap()
    }

    fn echo() -> Handler {
        Arc::new(|req: Request, c: &Caller| {
            if let Command::DeleteGroup { .. } = req.request {
                panic!("detalhe interno secreto C:\\caminho");
            }
            Response { version: 1, id: Some(req.id), result: Ok(Reply::Pong { version: c.sid.clone(), simulated: c.pid == std::process::id() }) }
        })
    }

    fn name() -> String {
        format!("ByteHalt.Test.{}", uuid::Uuid::new_v4().simple())
    }

    #[test]
    fn acl_de_producao_nega_rede_e_nao_permite_criar_instancias_para_usuarios() {
        let sddl = SecurityDescriptor::from_sddl(&production_sddl()).unwrap().sddl();
        assert!(sddl.starts_with("O:SY"), "{sddl}");
        assert!(sddl.contains(";;;NU)") && sddl.contains("(D;"), "{sddl}");
        assert!(!sddl.contains(";;;WD)") && !sddl.contains(";;;BU)") && !sddl.contains(";;;AN)"), "{sddl}");
        assert_eq!(CLIENT_RIGHTS & 0x4, 0, "FILE_CREATE_PIPE_INSTANCE não pode ser concedido");
        assert_eq!(CLIENT_RIGHTS & 0x0004_0000, 0, "WRITE_DAC não pode ser concedido");
        // O cliente pede só o que IU recebe: ler/gravar dados e atributos, ler o descritor (para conferir o
        // dono) e sincronizar. Nada de leitura/gravação de atributos estendidos nem de criar instância.
        for needed in [0x1u32, 0x2, 0x80, 0x100, 0x2_0000, 0x10_0000] {
            assert_ne!(CLIENT_RIGHTS & needed, 0, "direito 0x{needed:x} faltando");
        }
        for forbidden in [0x4u32, 0x8, 0x10, 0x4000_0000, 0x8000_0000] {
            assert_eq!(CLIENT_RIGHTS & forbidden, 0, "direito 0x{forbidden:x} não pode ser pedido nem concedido");
        }
        assert!(SecurityDescriptor::from_sddl(&development_sddl(&me())).unwrap().sddl().starts_with(&format!("O:{}", me())));
    }

    #[test]
    fn cliente_verifica_o_dono_e_servidor_identifica_o_chamador_pelo_processo() {
        let n = name();
        let _s = Server::start(&n, SecurityDescriptor::from_sddl(&development_sddl(&me())).unwrap(), echo()).unwrap();
        let mut c = connect(&n, &[me()], Duration::from_secs(5)).unwrap();
        let Reply::Pong { version: sid, simulated: same_pid } = call(&mut c, Command::Ping).unwrap() else { panic!() };
        assert_eq!(sid, me());
        assert!(same_pid);
        // Várias requisições na mesma conexão.
        assert!(call(&mut c, Command::GetSnapshot).is_ok());
    }

    #[test]
    fn cliente_de_producao_recusa_pipe_que_nao_pertence_ao_system() {
        let n = name();
        let _s = Server::start(&n, SecurityDescriptor::from_sddl(&development_sddl(&me())).unwrap(), echo()).unwrap();
        let e = connect(&n, &[SYSTEM_SID.to_owned()], Duration::from_secs(5)).unwrap_err();
        assert!(e.downcast_ref::<OwnerRejected>().is_some(), "{e:#}");
    }

    #[test]
    fn segunda_primeira_instancia_nao_toma_o_nome() {
        let n = name();
        let sd = SecurityDescriptor::from_sddl(&development_sddl(&me())).unwrap();
        let _s = Server::start(&n, SecurityDescriptor::from_sddl(&development_sddl(&me())).unwrap(), echo()).unwrap();
        assert!(create_instance(&n, &sd, true).is_err());
    }

    #[test]
    fn mensagem_acima_do_limite_derruba_a_conexao_e_erro_interno_nao_vaza() {
        let n = name();
        let _s = Server::start(&n, SecurityDescriptor::from_sddl(&development_sddl(&me())).unwrap(), echo()).unwrap();
        let mut c = connect(&n, &[me()], Duration::from_secs(5)).unwrap();
        c.write_all(&((bytehalt_ipc::MAX_MESSAGE as u32) + 1).to_le_bytes()).unwrap();
        assert!(matches!(read_frame(&mut c), Ok(None) | Err(_)));
        let mut c = connect(&n, &[me()], Duration::from_secs(5)).unwrap();
        let e = call(&mut c, Command::DeleteGroup { id: uuid::Uuid::new_v4() }).unwrap_err();
        let se = e.downcast_ref::<bytehalt_ipc::ServiceError>().unwrap();
        assert_eq!(se.code, ErrorCode::Internal);
        assert!(!se.message.contains("secreto"));
    }
}
