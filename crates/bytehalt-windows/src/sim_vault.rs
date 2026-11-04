//! Cofres no modo simulado (`--simulate`, demonstração e Windows Sandbox): o "disco" é uma pasta em
//! `<dados>\cofres-simulados` e a montagem é uma junção NTFS no caminho original. A cópia, a
//! verificação por SHA-256, a reserva e a recuperação são as mesmas do modo real; o BitLocker não.

use crate::acl::FileSecurity;
use crate::wide;
use bytehalt_core::vault::{SecurityCopier, VaultPlatform};
use std::fs;
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};
use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Storage::FileSystem::{CreateFileW, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, OPEN_EXISTING};
use windows_sys::Win32::System::IO::DeviceIoControl;

const FSCTL_SET_REPARSE_POINT: u32 = 0x0009_00A4;
const IO_REPARSE_TAG_MOUNT_POINT: u32 = 0xA000_0003;
const GENERIC_WRITE: u32 = 0x4000_0000;

/// Transforma a pasta vazia `link` numa junção para `target` (caminho absoluto existente).
pub fn create_junction(link: &Path, target: &Path) -> std::io::Result<()> {
    let t = target.to_string_lossy();
    let t = t.strip_prefix(r"\\?\").unwrap_or(&t).trim_end_matches('\\').to_owned();
    let substitute: Vec<u16> = format!(r"\??\{t}").encode_utf16().collect();
    let print: Vec<u16> = t.encode_utf16().collect();
    let (sub_len, print_len) = (substitute.len() * 2, print.len() * 2);
    let path_bytes = sub_len + 2 + print_len + 2;
    let mut buf: Vec<u8> = Vec::with_capacity(16 + path_bytes);
    buf.extend_from_slice(&IO_REPARSE_TAG_MOUNT_POINT.to_le_bytes());
    buf.extend_from_slice(&((8 + path_bytes) as u16).to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    for v in [0usize, sub_len, sub_len + 2, print_len] {
        buf.extend_from_slice(&(v as u16).to_le_bytes());
    }
    for w in substitute.iter().chain(&[0]).chain(print.iter()).chain(&[0]) {
        buf.extend_from_slice(&w.to_le_bytes());
    }
    let p = wide(&link.to_string_lossy());
    // SAFETY: caminho terminado em nulo; handle fechado abaixo.
    let h = unsafe { CreateFileW(p.as_ptr(), GENERIC_WRITE, 0, null(), OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, null_mut()) };
    if h == INVALID_HANDLE_VALUE {
        return Err(std::io::Error::last_os_error());
    }
    let mut ret = 0u32;
    // SAFETY: buffer REPARSE_DATA_BUFFER montado acima com o tamanho correto.
    let ok = unsafe { DeviceIoControl(h, FSCTL_SET_REPARSE_POINT, buf.as_ptr() as _, buf.len() as u32, null_mut(), 0, &mut ret, null_mut()) } != 0;
    let err = std::io::Error::last_os_error();
    // SAFETY: handle próprio.
    unsafe { CloseHandle(h) };
    if ok { Ok(()) } else { Err(err) }
}

pub struct SimulatedVaultPlatform {
    root: PathBuf,
    security: FileSecurity,
}

impl SimulatedVaultPlatform {
    pub fn new(data_dir: &Path) -> Self {
        Self { root: data_dir.join("cofres-simulados"), security: FileSecurity { owner: false } }
    }
}

fn volume_dir(store: &Path) -> PathBuf {
    store.with_extension("vol")
}

fn is_junction(p: &Path) -> bool {
    fs::symlink_metadata(p).is_ok_and(|m| m.file_type().is_symlink())
}

impl VaultPlatform for SimulatedVaultPlatform {
    fn store_dir(&self, _: &Path) -> anyhow::Result<PathBuf> {
        Ok(self.root.clone())
    }

    fn create_disk(&self, store: &Path, max_bytes: u64) -> anyhow::Result<()> {
        anyhow::ensure!(!store.exists(), "O arquivo do cofre já existe.");
        fs::create_dir_all(&self.root)?;
        fs::write(store, format!("cofre simulado; tamanho máximo {max_bytes} bytes\n"))?;
        Ok(())
    }

    fn attach(&self, store: &Path) -> anyhow::Result<()> {
        anyhow::ensure!(store.exists(), "Arquivo do cofre não encontrado.");
        Ok(())
    }

    fn detach(&self, _: &Path) -> anyhow::Result<()> {
        Ok(())
    }

    fn delete_disk(&self, store: &Path) -> anyhow::Result<()> {
        let vol = volume_dir(store);
        if vol.exists() {
            fs::remove_dir_all(&vol)?;
        }
        if store.exists() {
            fs::remove_file(store)?;
        }
        Ok(())
    }

    fn format(&self, store: &Path, _: &str) -> anyhow::Result<String> {
        let vol = volume_dir(store);
        fs::create_dir_all(&vol)?;
        Ok(vol.to_string_lossy().into_owned())
    }

    fn encrypt(&self, _: &str, _: &str) -> anyhow::Result<String> {
        // Chave fictícia no formato do BitLocker (8 grupos de 6 dígitos).
        let b = uuid::Uuid::new_v4().into_bytes();
        Ok(b.chunks(2).map(|c| format!("{:06}", (u32::from(c[0]) << 8 | u32::from(c[1])) * 11 % 1_000_000)).collect::<Vec<_>>().join("-"))
    }

    fn volume_root(&self, volume: &str) -> PathBuf {
        PathBuf::from(volume)
    }

    fn mount(&self, volume: &str, dir: &Path) -> anyhow::Result<()> {
        anyhow::ensure!(fs::read_dir(dir)?.next().is_none(), "A pasta de montagem não está vazia.");
        create_junction(dir, Path::new(volume)).map_err(|e| anyhow::anyhow!("Criar a junção: {e}"))
    }

    fn unmount(&self, dir: &Path) -> anyhow::Result<()> {
        if is_junction(dir) {
            fs::remove_dir(dir)?;
            fs::create_dir(dir)?;
        }
        Ok(())
    }

    fn is_mounted(&self, volume: &str, dir: &Path) -> bool {
        is_junction(dir) && fs::canonicalize(dir).ok() == fs::canonicalize(volume).ok()
    }

    fn free_bytes(&self, path: &Path) -> anyhow::Result<u64> {
        crate::vhd::free_bytes(path)
    }

    fn holders(&self, dir: &Path) -> anyhow::Result<Vec<String>> {
        crate::restart::holders(dir)
    }

    fn security(&self) -> &dyn SecurityCopier {
        &self.security
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn juncao_aponta_para_o_destino_e_some_sem_apagar_o_destino() {
        let t = tempfile::tempdir().unwrap();
        let (link, target) = (t.path().join("link"), t.path().join("alvo"));
        fs::create_dir(&link).unwrap();
        fs::create_dir(&target).unwrap();
        fs::write(target.join("a.txt"), b"a").unwrap();
        create_junction(&link, &target).unwrap();
        assert!(is_junction(&link));
        assert_eq!(fs::read(link.join("a.txt")).unwrap(), b"a");
        let p = SimulatedVaultPlatform::new(t.path());
        assert!(p.is_mounted(&target.to_string_lossy(), &link));
        p.unmount(&link).unwrap();
        assert!(link.is_dir() && !is_junction(&link) && target.join("a.txt").exists());
    }

    #[test]
    fn chave_simulada_tem_formato_do_bitlocker() {
        let t = tempfile::tempdir().unwrap();
        let k = SimulatedVaultPlatform::new(t.path()).encrypt("x", "y").unwrap();
        assert_eq!(k.len(), 8 * 6 + 7);
        assert!(k.split('-').all(|g| g.len() == 6 && g.chars().all(|c| c.is_ascii_digit())));
    }
}
