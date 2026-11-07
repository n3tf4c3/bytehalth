//! Pasta de dados do serviço: dono Administradores, acesso só para SYSTEM e Administradores, sem herança.
//!
//! O dono de um objeto tem WRITE_DAC implícito: trocar só a DACL de uma pasta criada antes por um
//! usuário comum (ProgramData e a raiz das unidades permitem criar pastas) deixaria esse usuário
//! capaz de desfazer a restrição. Por isso a pasta é criada já com dono e DACL (uma única operação),
//! uma pasta existente com dono não confiável é posta de lado e recriada, e o conteúdo de uma pasta
//! adotada é conferido item a item (links, dono, hard links) antes de qualquer uso.

use crate::wide;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};
use windows_sys::Win32::Foundation::{CloseHandle, ERROR_ALREADY_EXISTS, ERROR_SUCCESS, GetLastError, HANDLE, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo, SDDL_REVISION_1, SE_FILE_OBJECT, SetNamedSecurityInfoW, SetSecurityInfo,
};
use windows_sys::Win32::Security::{
    ACL, DACL_SECURITY_INFORMATION, EqualSid, GetSecurityDescriptorDacl, GetSecurityDescriptorOwner, GetTokenInformation, IsWellKnownSid,
    OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER, TokenUser,
    WinBuiltinAdministratorsSid, WinLocalSystemSid,
};
use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, CreateDirectoryW, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS,
    FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, GetFileInformationByHandle, MoveFileExW, READ_CONTROL, WRITE_DAC,
    WRITE_OWNER,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

pub const MACHINE_ONLY_SDDL: &str = "O:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";

/// Como a pasta foi preparada.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Prepared {
    Created,
    Adopted,
    /// A pasta existente tinha dono não confiável ou era um link; foi renomeada para o caminho indicado.
    Quarantined(PathBuf),
}

/// Descritor de segurança alocado pelo sistema.
struct Descriptor(PSECURITY_DESCRIPTOR);

impl Drop for Descriptor {
    fn drop(&mut self) {
        // SAFETY: memória alocada pelo sistema (Convert…/GetSecurityInfo), liberada uma única vez.
        unsafe { LocalFree(self.0) };
    }
}

fn machine_only() -> anyhow::Result<Descriptor> {
    let sddl = wide(MACHINE_ONLY_SDDL);
    let mut sd: PSECURITY_DESCRIPTOR = null_mut();
    // SAFETY: SDDL terminado em nulo; `sd` recebe memória do sistema liberada no Drop.
    let ok = unsafe { ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.as_ptr(), SDDL_REVISION_1, &mut sd, null_mut()) };
    anyhow::ensure!(ok != 0, "SDDL da pasta inválido.");
    Ok(Descriptor(sd))
}

/// SID do usuário do processo (SYSTEM no serviço; o administrador elevado nos testes).
fn process_user() -> anyhow::Result<Vec<u8>> {
    let mut token: HANDLE = null_mut();
    // SAFETY: token do próprio processo, fechado abaixo.
    anyhow::ensure!(unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } != 0, "token do processo");
    let mut buf = vec![0u8; 256];
    let mut needed = 0u32;
    // SAFETY: buffer local do tamanho informado.
    let mut ok = unsafe { GetTokenInformation(token, TokenUser, buf.as_mut_ptr() as _, buf.len() as u32, &mut needed) } != 0;
    if !ok && needed as usize > buf.len() {
        buf.resize(needed as usize, 0);
        // SAFETY: idem, com o tamanho pedido.
        ok = unsafe { GetTokenInformation(token, TokenUser, buf.as_mut_ptr() as _, buf.len() as u32, &mut needed) } != 0;
    }
    // SAFETY: handle próprio.
    unsafe { CloseHandle(token) };
    anyhow::ensure!(ok, "usuário do processo");
    Ok(buf)
}

struct Trust {
    user: Vec<u8>,
}

impl Trust {
    fn new() -> anyhow::Result<Self> {
        Ok(Self { user: process_user()? })
    }

    fn owner(&self, sid: PSID) -> bool {
        if sid.is_null() {
            return false;
        }
        // SAFETY: `user` contém um TOKEN_USER válido preenchido por GetTokenInformation.
        let user = unsafe { (*(self.user.as_ptr() as *const TOKEN_USER)).User.Sid };
        // SAFETY: SIDs válidos (do descritor lido e do token).
        unsafe { IsWellKnownSid(sid, WinLocalSystemSid) != 0 || IsWellKnownSid(sid, WinBuiltinAdministratorsSid) != 0 || EqualSid(sid, user) != 0 }
    }
}

/// Abre sem seguir links. Sem FILE_SHARE_DELETE (quando `exclusive`): enquanto o handle existir, a
/// pasta não pode ser renomeada nem trocada por outra.
fn open(path: &Path, access: u32, exclusive: bool) -> std::io::Result<std::fs::File> {
    let share = FILE_SHARE_READ | FILE_SHARE_WRITE | if exclusive { 0 } else { FILE_SHARE_DELETE };
    std::fs::OpenOptions::new().access_mode(access).share_mode(share).custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT).open(path)
}

fn info(file: &std::fs::File) -> std::io::Result<BY_HANDLE_FILE_INFORMATION> {
    let mut i = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: handle válido do `file`; estrutura local.
    if unsafe { GetFileInformationByHandle(file.as_raw_handle() as HANDLE, &mut i) } == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(i)
}

/// O dono do objeto aberto é confiável. Dono ilegível conta como não confiável.
fn owner_trusted(file: &std::fs::File, trust: &Trust) -> bool {
    let mut owner: PSID = null_mut();
    let mut sd: PSECURITY_DESCRIPTOR = null_mut();
    // SAFETY: handle aberto com READ_CONTROL; `owner` aponta para dentro de `sd`, liberado no Drop.
    let r = unsafe {
        GetSecurityInfo(file.as_raw_handle() as HANDLE, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION, &mut owner, null_mut(), null_mut(), null_mut(), &mut sd)
    };
    if r != ERROR_SUCCESS {
        return false;
    }
    let _sd = Descriptor(sd);
    trust.owner(owner)
}

/// A pasta existente pode ser adotada: é uma pasta de verdade (não link) e o dono é confiável.
fn adoptable(dir: &Path, trust: &Trust) -> bool {
    let Ok(f) = open(dir, READ_CONTROL, false) else { return false };
    let Ok(i) = info(&f) else { return false };
    i.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0 && i.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT == 0 && owner_trusted(&f, trust)
}

fn quarantine_name(dir: &Path) -> PathBuf {
    let secs = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let mut name = dir.as_os_str().to_owned();
    name.push(format!(".nao-confiavel-{secs}"));
    PathBuf::from(name)
}

/// Cria a pasta com o descritor final numa única operação. `false` se ela já existir.
fn create(dir: &Path, sd: &Descriptor) -> anyhow::Result<bool> {
    let path = wide(&dir.to_string_lossy());
    let sa = SECURITY_ATTRIBUTES { nLength: size_of::<SECURITY_ATTRIBUTES>() as u32, lpSecurityDescriptor: sd.0, bInheritHandle: 0 };
    // SAFETY: caminho terminado em nulo; descritor válido durante a chamada.
    if unsafe { CreateDirectoryW(path.as_ptr(), &sa) } != 0 {
        return Ok(true);
    }
    // SAFETY: lido logo após a chamada.
    let e = unsafe { GetLastError() };
    anyhow::ensure!(e == ERROR_ALREADY_EXISTS, "Não foi possível criar {} ({e}).", dir.display());
    Ok(false)
}

/// Prepara `dir` para dados restritos a SYSTEM e Administradores. Ver o comentário do módulo.
pub fn ensure_machine_only(dir: &Path) -> anyhow::Result<Prepared> {
    if let Some(parent) = dir.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let sd = machine_only()?;
    let trust = Trust::new()?;
    let mut outcome = None;
    for _ in 0..3 {
        if create(dir, &sd)? {
            outcome.get_or_insert(Prepared::Created);
            break;
        }
        if adoptable(dir, &trust) {
            outcome.get_or_insert(Prepared::Adopted);
            break;
        }
        // Nunca foi do ByteHalt: põe de lado (sem apagar) e cria de novo.
        let aside = quarantine_name(dir);
        let (from, to) = (wide(&dir.to_string_lossy()), wide(&aside.to_string_lossy()));
        // SAFETY: caminhos terminados em nulo. Renomeia o próprio link, se for um link.
        let moved = unsafe { MoveFileExW(from.as_ptr(), to.as_ptr(), 0) } != 0;
        anyhow::ensure!(moved, "A pasta {} já existia com dono não confiável e não pôde ser isolada ({}).", dir.display(), std::io::Error::last_os_error());
        outcome = Some(Prepared::Quarantined(aside));
    }
    let outcome = outcome.ok_or_else(|| anyhow::anyhow!("A pasta {} foi recriada por outro processo durante a preparação.", dir.display()))?;
    secure(dir, &sd, &trust)?;
    Ok(outcome)
}

/// Aplica dono e DACL pelo handle (sem seguir links), propaga a herança e confere o conteúdo.
fn secure(dir: &Path, sd: &Descriptor, trust: &Trust) -> anyhow::Result<()> {
    // Sem FILE_SHARE_DELETE: a pasta não pode ser trocada por um link até o fim.
    let f = open(dir, READ_CONTROL | WRITE_DAC | WRITE_OWNER, true).map_err(|e| anyhow::anyhow!("Abrir {}: {e}", dir.display()))?;
    let i = info(&f)?;
    anyhow::ensure!(
        i.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0 && i.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT == 0,
        "{} não é uma pasta comum.",
        dir.display()
    );
    let (mut owner, mut defaulted, mut present) = (null_mut(), 0i32, 0i32);
    let mut dacl: *mut ACL = null_mut();
    // SAFETY: `sd` válido; ponteiros para dentro dele, vivo até o fim da função.
    let got = unsafe {
        GetSecurityDescriptorOwner(sd.0, &mut owner, &mut defaulted) != 0 && GetSecurityDescriptorDacl(sd.0, &mut present, &mut dacl, &mut defaulted) != 0
    };
    anyhow::ensure!(got && present != 0 && !owner.is_null(), "SDDL da pasta inválido.");
    // SAFETY: handle com WRITE_DAC | WRITE_OWNER; dono e DACL de `sd`.
    let r = unsafe {
        SetSecurityInfo(
            f.as_raw_handle() as HANDLE,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            owner,
            null_mut(),
            dacl,
            null(),
        )
    };
    anyhow::ensure!(r == ERROR_SUCCESS, "Não foi possível restringir a pasta de dados ({r}).");
    // Propaga as entradas herdáveis aos itens existentes. A pasta já está restrita e presa pelo handle.
    let path = wide(&dir.to_string_lossy());
    // SAFETY: caminho terminado em nulo; DACL válida dentro de `sd`.
    let r = unsafe {
        SetNamedSecurityInfoW(
            path.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            dacl,
            null(),
        )
    };
    anyhow::ensure!(r == ERROR_SUCCESS, "Não foi possível propagar a restrição da pasta de dados ({r}).");
    check_contents(dir, trust)?;
    drop(f);
    Ok(())
}

/// Itens que um usuário comum poderia ter deixado antes da restrição: links, dono não confiável
/// (o dono mantém WRITE_DAC) e hard links para arquivos de fora. Falha fechada.
fn check_contents(dir: &Path, trust: &Trust) -> anyhow::Result<()> {
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for entry in std::fs::read_dir(&d).map_err(|e| anyhow::anyhow!("Ler {}: {e}", d.display()))? {
            let path = entry?.path();
            let bad = |why: &str| anyhow::anyhow!("Item não confiável na pasta de dados ({why}): {}. Remova-o e inicie de novo.", path.display());
            let f = open(&path, READ_CONTROL, false).map_err(|e| bad(&e.to_string()))?;
            let i = info(&f).map_err(|e| bad(&e.to_string()))?;
            if i.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                return Err(bad("link ou junção"));
            }
            if !owner_trusted(&f, trust) {
                return Err(bad("dono"));
            }
            if i.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0 {
                stack.push(path);
            } else if i.nNumberOfLinks > 1 {
                return Err(bad("hard link"));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "secure_dir_tests.rs"]
mod tests;
