//! Segurança de arquivos para os cofres: cópia fiel de dono e DACL (com a proteção de herança),
//! privilégios do serviço e verificação de que o CHAMADOR (não o serviço) pode substituir a pasta.

use crate::wide;
use bytehalt_core::vault::SecurityCopier;
use std::path::Path;
use std::ptr::{null, null_mut};
use windows_sys::Win32::Foundation::{CloseHandle, ERROR_SUCCESS, HANDLE, LUID, LocalFree};
use windows_sys::Win32::Security::Authorization::{GetNamedSecurityInfoW, SE_FILE_OBJECT, SetNamedSecurityInfoW};
use windows_sys::Win32::Security::*;
use windows_sys::Win32::Storage::FileSystem::{DELETE, FILE_ALL_ACCESS, FILE_GENERIC_EXECUTE, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_LIST_DIRECTORY};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION};

const SE_DACL_PROTECTED: u16 = 0x1000;

/// Copia dono (só com `owner`, exige SeRestorePrivilege) e DACL de um item para outro.
pub struct FileSecurity {
    pub owner: bool,
}

impl SecurityCopier for FileSecurity {
    fn copy(&self, from: &Path, to: &Path) -> std::io::Result<()> {
        self.apply(from, to, false)
    }

    fn copy_root(&self, from: &Path, to: &Path) -> std::io::Result<()> {
        self.apply(from, to, true)
    }

    fn streams(&self, path: &Path) -> std::io::Result<Vec<String>> {
        named_streams(path)
    }
}

/// Fluxos de dados com nome (`arquivo:nome`) de um arquivo ou pasta, sem seguir links. Aberto com
/// FILE_FLAG_BACKUP_SEMANTICS: no serviço (SeBackupPrivilege) lê mesmo sem permissão na DACL.
pub fn named_streams(path: &Path) -> std::io::Result<Vec<String>> {
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FileStreamInfo,
        GetFileInformationByHandleEx,
    };
    let f = std::fs::OpenOptions::new()
        .access_mode(FILE_READ_ATTRIBUTES)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    let mut buf = vec![0u64; 512];
    loop {
        let bytes = (buf.len() * 8) as u32;
        // SAFETY: handle válido; buffer alinhado a 8 bytes com o tamanho informado.
        if unsafe { GetFileInformationByHandleEx(f.as_raw_handle() as HANDLE, FileStreamInfo, buf.as_mut_ptr() as _, bytes) } != 0 {
            break;
        }
        // SAFETY: lido logo após a chamada.
        match unsafe { windows_sys::Win32::Foundation::GetLastError() } {
            // ERROR_HANDLE_EOF: nenhum fluxo (pasta sem fluxos).
            38 => return Ok(Vec::new()),
            // ERROR_MORE_DATA.
            234 if buf.len() < 1 << 20 => buf.resize(buf.len() * 4, 0),
            _ => return Err(std::io::Error::last_os_error()),
        }
    }
    // FILE_STREAM_INFO: NextEntryOffset u32, StreamNameLength u32, StreamSize i64,
    // StreamAllocationSize i64, StreamName [u16] (sem nulo). Lido byte a byte do buffer.
    // SAFETY: buffer próprio, reinterpretado como bytes.
    let raw = unsafe { std::slice::from_raw_parts(buf.as_ptr() as *const u8, buf.len() * 8) };
    let u32_at = |at: usize| u32::from_le_bytes([raw[at], raw[at + 1], raw[at + 2], raw[at + 3]]) as usize;
    let mut out = Vec::new();
    let mut at = 0usize;
    loop {
        if at + 24 > raw.len() {
            return Err(std::io::Error::other("lista de fluxos inválida"));
        }
        let (next, len) = (u32_at(at), u32_at(at + 4));
        if at + 24 + len > raw.len() {
            return Err(std::io::Error::other("lista de fluxos inválida"));
        }
        let name: Vec<u16> = raw[at + 24..at + 24 + len].as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes(*c)).collect();
        let name = String::from_utf16_lossy(&name);
        // ":nome:$DATA"; o principal é "::$DATA".
        if let Some(n) = name.strip_prefix(':').and_then(|n| n.strip_suffix(":$DATA"))
            && !n.is_empty()
        {
            out.push(n.to_owned());
        }
        if next == 0 {
            break;
        }
        at += next;
    }
    Ok(out)
}

const INHERITED_ACE: u8 = 0x10;

impl FileSecurity {
    /// `root`: o destino não tem o mesmo pai (raiz do volume do cofre). As entradas herdadas da
    /// origem viram explícitas e a DACL fica protegida; sem isso o Windows recalcularia a herança a
    /// partir de um pai inexistente e a raiz ficaria sem nenhuma permissão (visto na VM).
    fn apply(&self, from: &Path, to: &Path, root: bool) -> std::io::Result<()> {
        let (src, dst) = (wide(&from.to_string_lossy()), wide(&to.to_string_lossy()));
        let mut owner: PSID = null_mut();
        let mut group: PSID = null_mut();
        let mut dacl: *mut ACL = null_mut();
        let mut sd: PSECURITY_DESCRIPTOR = null_mut();
        // Dono e grupo primário só com privilégio de restauração (serviço).
        let what = DACL_SECURITY_INFORMATION | if self.owner { OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION } else { 0 };
        // SAFETY: caminho terminado em nulo; as saídas apontam para dentro de `sd`, liberado no fim.
        let r = unsafe { GetNamedSecurityInfoW(src.as_ptr(), SE_FILE_OBJECT, what, &mut owner, &mut group, &mut dacl, null_mut(), &mut sd) };
        if r != ERROR_SUCCESS {
            return Err(std::io::Error::from_raw_os_error(r as i32));
        }
        let mut control = 0u16;
        let mut revision = 0u32;
        // SAFETY: `sd` válido devolvido acima.
        unsafe { GetSecurityDescriptorControl(sd, &mut control, &mut revision) };
        let inherit = if root || control & SE_DACL_PROTECTED != 0 { PROTECTED_DACL_SECURITY_INFORMATION } else { UNPROTECTED_DACL_SECURITY_INFORMATION };
        let mut explicit: Vec<u8> = Vec::new();
        if root && !dacl.is_null() {
            // SAFETY: `dacl` aponta para um ACL válido de `AclSize` bytes dentro de `sd`.
            let size = unsafe { (*dacl).AclSize } as usize;
            // SAFETY: idem; cópia byte a byte para um buffer próprio.
            explicit = unsafe { std::slice::from_raw_parts(dacl as *const u8, size) }.to_vec();
            let count = u16::from_le_bytes([explicit[4], explicit[5]]) as usize;
            let mut at = 8;
            for _ in 0..count {
                if at + 4 > explicit.len() {
                    break;
                }
                explicit[at + 1] &= !INHERITED_ACE;
                at += u16::from_le_bytes([explicit[at + 2], explicit[at + 3]]) as usize;
            }
        }
        let dacl: *const ACL = if explicit.is_empty() { dacl } else { explicit.as_ptr() as *const ACL };
        // SAFETY: dono e DACL vêm de `sd`, que ainda está vivo; o Windows copia os dados.
        let w = unsafe {
            SetNamedSecurityInfoW(
                dst.as_ptr(),
                SE_FILE_OBJECT,
                what | inherit,
                if self.owner { owner } else { null_mut() },
                if self.owner { group } else { null_mut() },
                dacl,
                null(),
            )
        };
        // SAFETY: `sd` foi alocado por GetNamedSecurityInfoW.
        unsafe { LocalFree(sd as _) };
        if w != ERROR_SUCCESS {
            return Err(std::io::Error::from_raw_os_error(w as i32));
        }
        Ok(())
    }
}

/// Liga privilégios já presentes no token do processo (o serviço LocalSystem os tem desligados).
pub fn enable_privileges(names: &[&str]) -> anyhow::Result<()> {
    let mut token: HANDLE = null_mut();
    // SAFETY: token do próprio processo, fechado no fim.
    anyhow::ensure!(unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &mut token) } != 0, "token do processo");
    let mut failed = Vec::new();
    for name in names {
        let mut luid = LUID::default();
        let n = wide(name);
        // SAFETY: nome terminado em nulo.
        if unsafe { LookupPrivilegeValueW(null(), n.as_ptr(), &mut luid) } == 0 {
            failed.push(*name);
            continue;
        }
        let tp = TOKEN_PRIVILEGES { PrivilegeCount: 1, Privileges: [LUID_AND_ATTRIBUTES { Luid: luid, Attributes: SE_PRIVILEGE_ENABLED }] };
        // SAFETY: estrutura válida; sem estado anterior.
        let ok = unsafe { AdjustTokenPrivileges(token, 0, &tp, 0, null_mut(), null_mut()) } != 0;
        // ERROR_NOT_ALL_ASSIGNED (1300) quando o token não tem o privilégio.
        // SAFETY: lê o erro logo após a chamada.
        if !ok || unsafe { windows_sys::Win32::Foundation::GetLastError() } == 1300 {
            failed.push(*name);
        }
    }
    // SAFETY: handle próprio.
    unsafe { CloseHandle(token) };
    anyhow::ensure!(failed.is_empty(), "Privilégios indisponíveis: {}", failed.join(", "));
    Ok(())
}

/// O processo `pid` (o chamador do pipe) pode listar e apagar/renomear a pasta? Avalia o token do
/// chamador contra a ACL da pasta (o serviço, como SYSTEM, poderia tudo).
pub fn caller_can_replace(pid: u32, dir: &Path) -> anyhow::Result<bool> {
    let parent = dir.parent().ok_or_else(|| anyhow::anyhow!("pasta sem pai"))?;
    let token = caller_token(pid)?;
    if access(token.0, dir, FILE_LIST_DIRECTORY | DELETE)? {
        return Ok(true);
    }
    // Renomear também vale com "apagar filhos" (FILE_DELETE_CHILD) no pai.
    Ok(access(token.0, dir, FILE_LIST_DIRECTORY)? && access(token.0, parent, 0x40)?)
}

struct Token(HANDLE);

impl Drop for Token {
    fn drop(&mut self) {
        // SAFETY: handle próprio.
        unsafe { CloseHandle(self.0) };
    }
}

fn caller_token(pid: u32) -> anyhow::Result<Token> {
    // SAFETY: handles locais fechados abaixo.
    unsafe {
        let process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        anyhow::ensure!(!process.is_null(), "processo do chamador indisponível");
        let mut primary: HANDLE = null_mut();
        let ok = OpenProcessToken(process, TOKEN_QUERY | TOKEN_DUPLICATE, &mut primary) != 0;
        CloseHandle(process);
        anyhow::ensure!(ok, "token do chamador indisponível");
        let mut imp: HANDLE = null_mut();
        let ok = DuplicateToken(primary, SecurityIdentification, &mut imp) != 0;
        CloseHandle(primary);
        anyhow::ensure!(ok, "não foi possível duplicar o token do chamador");
        Ok(Token(imp))
    }
}

fn access(token: HANDLE, path: &Path, desired: u32) -> anyhow::Result<bool> {
    let p = wide(&path.to_string_lossy());
    let what = OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
    let mut needed = 0u32;
    // SAFETY: primeira chamada só mede o tamanho.
    unsafe { GetFileSecurityW(p.as_ptr(), what, null_mut(), 0, &mut needed) };
    anyhow::ensure!(needed > 0, "segurança de {} indisponível", path.display());
    let mut buf = vec![0u8; needed as usize];
    // SAFETY: buffer do tamanho pedido.
    anyhow::ensure!(unsafe { GetFileSecurityW(p.as_ptr(), what, buf.as_mut_ptr() as _, needed, &mut needed) } != 0, "segurança de {}", path.display());
    let mapping =
        GENERIC_MAPPING { GenericRead: FILE_GENERIC_READ, GenericWrite: FILE_GENERIC_WRITE, GenericExecute: FILE_GENERIC_EXECUTE, GenericAll: FILE_ALL_ACCESS };
    let mut desired = desired;
    // SAFETY: máscara e mapeamento válidos.
    unsafe { MapGenericMask(&mut desired, &mapping) };
    let mut privileges = [0u8; 256];
    let mut plen = privileges.len() as u32;
    let (mut granted, mut status) = (0u32, 0i32);
    // SAFETY: descritor lido acima, token de identificação do chamador, buffers locais.
    let ok = unsafe { AccessCheck(buf.as_mut_ptr() as _, token, desired, &mapping, privileges.as_mut_ptr() as _, &mut plen, &mut granted, &mut status) } != 0;
    anyhow::ensure!(ok, "AccessCheck falhou em {}", path.display());
    Ok(status != 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sddl(p: &Path) -> String {
        let out = std::process::Command::new("powershell")
            .args(["-NoProfile", "-Command", &format!("(Get-Acl -LiteralPath '{}').Sddl", p.display())])
            .output()
            .unwrap();
        String::from_utf8_lossy(&out.stdout).trim().to_owned()
    }

    #[test]
    fn raiz_do_cofre_recebe_a_heranca_como_entradas_explicitas() {
        let t = tempfile::tempdir().unwrap();
        let (src, dst) = (t.path().join("origem"), t.path().join("destino"));
        std::fs::create_dir(&src).unwrap();
        std::fs::create_dir(&dst).unwrap();
        let before = sddl(&src);
        assert!(before.contains("ID;"), "a origem deveria ter só entradas herdadas: {before}");
        FileSecurity { owner: false }.copy_root(&src, &dst).unwrap();
        let after = sddl(&dst);
        // Protegida (P), sem entradas marcadas como herdadas e com as mesmas permissões.
        assert!(after.contains("D:P"), "{after}");
        assert!(!after.contains("ID;"), "{after}");
        assert_eq!(after.matches("(A;").count(), before.matches("(A;").count(), "{before} -> {after}");
        // E continua gravável pelo próprio usuário.
        std::fs::write(dst.join("x.txt"), b"x").unwrap();
    }
}
