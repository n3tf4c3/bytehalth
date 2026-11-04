//! Fonte real de atividade (Fase 4): contadores de E/S do volume (`IOCTL_DISK_PERFORMANCE`), lidos a
//! cada volta do serviço. Na VM de teste: 60 s parado não mexe nos contadores; gravações mexem em
//! poucos segundos; leituras atendidas pelo cache de memória NÃO aparecem (mesma limitação do ETW de
//! disco). Vale para unidades (`\\.\E:`) e cofres (cada cofre é um volume: `\\.\Volume{GUID}`).

use crate::bitlocker::is_volume_device;
use crate::wide;
use bytehalt_core::inactivity::ActivityProbe;
use bytehalt_core::model::{ProtectedResource, ResourceKind, normalize_drive_letter};
use bytehalt_core::vault::VaultRepository;
use std::ptr::{null, null_mut};
use std::sync::Arc;
use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Storage::FileSystem::{CreateFileW, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING};
use windows_sys::Win32::System::IO::DeviceIoControl;

const IOCTL_DISK_PERFORMANCE: u32 = 0x0007_0020;
/// `DISK_PERFORMANCE`: BytesRead (0), BytesWritten (8), …, ReadCount (40), WriteCount (44).
const SIZE: usize = 88;

pub struct VolumeActivity {
    vaults: Arc<dyn VaultRepository>,
}

impl VolumeActivity {
    pub fn new(vaults: Arc<dyn VaultRepository>) -> Self {
        Self { vaults }
    }

    fn device(&self, r: &ProtectedResource) -> Option<String> {
        match r.kind {
            ResourceKind::BitLockerVolume => normalize_drive_letter(&r.target).map(|l| format!(r"\\.\{l}")),
            ResourceKind::Vault => {
                let id = uuid::Uuid::parse_str(&r.target).ok()?;
                let v = self.vaults.vaults().ok()?.into_iter().find(|v| v.id == id)?;
                let vol = v.volume.filter(|d| is_volume_device(d))?;
                Some(format!(r"\\.\{}", vol.trim_start_matches(r"\\?\").trim_end_matches('\\')))
            }
        }
    }
}

/// Soma de bytes e operações lidas e gravadas desde a montagem do volume.
pub fn io_counter(device: &str) -> Option<u64> {
    let p = wide(device);
    // Acesso 0: só consulta; o handle vive só durante a chamada (não segura o volume).
    // SAFETY: caminho terminado em nulo; handle fechado abaixo.
    let h = unsafe { CreateFileW(p.as_ptr(), 0, FILE_SHARE_READ | FILE_SHARE_WRITE, null(), OPEN_EXISTING, 0, null_mut()) };
    if h == INVALID_HANDLE_VALUE {
        return None;
    }
    let mut buf = [0u8; SIZE];
    let mut ret = 0u32;
    // SAFETY: buffer local do tamanho de DISK_PERFORMANCE.
    let ok = unsafe { DeviceIoControl(h, IOCTL_DISK_PERFORMANCE, null(), 0, buf.as_mut_ptr() as _, SIZE as u32, &mut ret, null_mut()) } != 0;
    // SAFETY: handle próprio.
    unsafe { CloseHandle(h) };
    if !ok || (ret as usize) < 48 {
        return None;
    }
    let i64_at = |o: usize| i64::from_le_bytes(buf[o..o + 8].try_into().unwrap_or_default()) as u64;
    let u32_at = |o: usize| u64::from(u32::from_le_bytes(buf[o..o + 4].try_into().unwrap_or_default()));
    Some(i64_at(0).wrapping_add(i64_at(8)).wrapping_add(u32_at(40)).wrapping_add(u32_at(44)))
}

impl ActivityProbe for VolumeActivity {
    fn counter(&self, r: &ProtectedResource) -> Option<u64> {
        io_counter(&self.device(r)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contador_do_volume_do_sistema_e_lido_e_cresce_com_gravacao() {
        let drive = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".into());
        let Some(before) = io_counter(&format!(r"\\.\{drive}")) else {
            // Sem acesso ao contador neste ambiente: o serviço só perde a fonte real (registra-se assim).
            eprintln!("contador indisponível");
            return;
        };
        let t = tempfile::tempdir().unwrap();
        let f = t.path().join("io.bin");
        std::fs::write(&f, vec![1u8; 1 << 20]).unwrap();
        let file = std::fs::OpenOptions::new().write(true).open(&f).unwrap();
        file.sync_all().unwrap();
        let mut after = before;
        for _ in 0..20 {
            after = io_counter(&format!(r"\\.\{drive}")).unwrap();
            if after != before {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(250));
        }
        assert_ne!(before, after, "1 MiB gravado com sync deveria mexer no contador");
    }
}
