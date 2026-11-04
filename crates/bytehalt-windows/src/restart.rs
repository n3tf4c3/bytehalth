//! Processos com arquivos abertos numa pasta (Restart Manager). Usado antes da troca da pasta pelo
//! cofre: um arquivo aberto com compartilhamento de exclusão não impede renomear a pasta, e o programa
//! continuaria gravando na reserva.

use crate::{from_wide, wide};
use std::path::Path;
use std::ptr::{null, null_mut};
use windows_sys::Win32::Foundation::{ERROR_MORE_DATA, ERROR_SUCCESS};
use windows_sys::Win32::System::RestartManager::*;

/// Acima disso a pasta é grande demais para registrar arquivo por arquivo; a renomeação continua
/// sendo a verificação final.
const MAX_FILES: usize = 50_000;
const CHUNK: usize = 1_000;

struct Session(u32);

impl Drop for Session {
    fn drop(&mut self) {
        // SAFETY: sessão aberta por RmStartSession.
        unsafe { RmEndSession(self.0) };
    }
}

fn files(dir: &Path) -> Vec<String> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&d) else { continue };
        for e in entries.flatten() {
            let p = e.path();
            match std::fs::symlink_metadata(&p) {
                Ok(m) if m.is_dir() && !m.file_type().is_symlink() => stack.push(p),
                Ok(m) if m.is_file() => out.push(p.to_string_lossy().into_owned()),
                _ => {}
            }
            if out.len() >= MAX_FILES {
                return out;
            }
        }
    }
    out
}

/// Nomes dos processos (com PID) que usam arquivos da pasta.
pub fn holders(dir: &Path) -> anyhow::Result<Vec<String>> {
    let list = files(dir);
    if list.is_empty() {
        return Ok(vec![]);
    }
    let mut handle = 0u32;
    let mut key = [0u16; (CCH_RM_SESSION_KEY + 1) as usize];
    // SAFETY: saídas locais.
    let r = unsafe { RmStartSession(&mut handle, 0, key.as_mut_ptr()) };
    anyhow::ensure!(r == ERROR_SUCCESS, "Restart Manager: {r}");
    let session = Session(handle);
    for chunk in list.chunks(CHUNK) {
        let wides: Vec<Vec<u16>> = chunk.iter().map(|f| wide(f)).collect();
        let ptrs: Vec<*const u16> = wides.iter().map(|w| w.as_ptr()).collect();
        // SAFETY: vetor de ponteiros para cadeias vivas durante a chamada.
        let r = unsafe { RmRegisterResources(session.0, ptrs.len() as u32, ptrs.as_ptr(), 0, null(), 0, null()) };
        anyhow::ensure!(r == ERROR_SUCCESS, "Restart Manager (registrar): {r}");
    }
    let mut needed = 0u32;
    let mut count = 0u32;
    let mut reasons = 0u32;
    let mut infos: Vec<RM_PROCESS_INFO> = Vec::new();
    loop {
        // SAFETY: `infos` tem `count` posições.
        let r = unsafe { RmGetList(session.0, &mut needed, &mut count, if infos.is_empty() { null_mut() } else { infos.as_mut_ptr() }, &mut reasons) };
        if r == ERROR_SUCCESS {
            break;
        }
        anyhow::ensure!(r == ERROR_MORE_DATA, "Restart Manager (lista): {r}");
        // SAFETY: RM_PROCESS_INFO é POD; zerado é válido.
        infos = vec![unsafe { std::mem::zeroed() }; needed as usize + 4];
        count = infos.len() as u32;
    }
    let me = std::process::id();
    // PID 4 (System): o próprio kernel mantém arquivos recém-gravados no cache; não é um programa
    // que o usuário possa fechar (visto na VM). A renomeação continua sendo a prova final.
    let mut names: Vec<String> = infos
        .iter()
        .take(count as usize)
        .filter(|i| i.Process.dwProcessId != me && i.Process.dwProcessId != 4)
        .map(|i| format!("{} (PID {})", from_wide(&i.strAppName), i.Process.dwProcessId))
        .collect();
    names.sort();
    names.dedup();
    Ok(names)
}
