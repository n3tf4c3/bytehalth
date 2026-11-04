//! Plataforma real dos cofres: Virtual Disk API (VHDX dinâmico, anexado sem letra e com vida
//! permanente), Storage WMI (GPT, partição de dados, NTFS), BitLocker WMI no volume do cofre (senha +
//! chave de recuperação, só espaço usado) e pontos de montagem NTFS. Comportamento confirmado na VM de
//! teste (docs/ARCHITECTURE.md §3): o caminho montado fica inacessível com o volume bloqueado e o
//! ponto de montagem volta sozinho ao anexar o disco de novo.

use crate::acl::FileSecurity;
use crate::bitlocker::{WmiBitLocker, is_volume_device};
use crate::{secure_dir, wide};
use bytehalt_core::vault::{SecurityCopier, VaultPlatform};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};
use windows_sys::Win32::Foundation::{CloseHandle, ERROR_SUCCESS, HANDLE};
use windows_sys::Win32::Storage::FileSystem::{DeleteVolumeMountPointW, GetDiskFreeSpaceExW, GetVolumeNameForVolumeMountPointW, SetVolumeMountPointW};
use windows_sys::Win32::Storage::Vhd::*;

/// Pasta dos VHDX na raiz do volume do original (`E:\ByteHalt.Cofres`), só SYSTEM e Administradores.
pub const STORE_DIR: &str = "ByteHalt.Cofres";
const BASIC_DATA: &str = "{ebd0a0a2-b9e5-4433-87c0-68b6b72699c7}";

pub struct VhdPlatform {
    security: FileSecurity,
}

impl Default for VhdPlatform {
    fn default() -> Self {
        Self { security: FileSecurity { owner: true } }
    }
}

struct Disk(HANDLE);

impl Drop for Disk {
    fn drop(&mut self) {
        // SAFETY: handle próprio.
        unsafe { CloseHandle(self.0) };
    }
}

fn storage_type() -> VIRTUAL_STORAGE_TYPE {
    VIRTUAL_STORAGE_TYPE { DeviceId: VIRTUAL_STORAGE_TYPE_DEVICE_VHDX, VendorId: VIRTUAL_STORAGE_TYPE_VENDOR_MICROSOFT }
}

fn win32(code: u32, what: &str) -> anyhow::Result<()> {
    anyhow::ensure!(code == ERROR_SUCCESS, "{what}: {}", std::io::Error::from_raw_os_error(code as i32));
    Ok(())
}

fn open(store: &Path) -> anyhow::Result<Disk> {
    let p = wide(&store.to_string_lossy());
    let params = OPEN_VIRTUAL_DISK_PARAMETERS { Version: OPEN_VIRTUAL_DISK_VERSION_2, ..Default::default() };
    let mut h: HANDLE = null_mut();
    // SAFETY: caminho terminado em nulo, parâmetros V2 zerados (acesso NONE exige V2).
    let r = unsafe { OpenVirtualDisk(&storage_type(), p.as_ptr(), VIRTUAL_DISK_ACCESS_NONE, OPEN_VIRTUAL_DISK_FLAG_NONE, &params, &mut h) };
    win32(r, "Abrir o VHDX")?;
    Ok(Disk(h))
}

/// `\\.\PhysicalDriveN` do disco anexado; `None` se não estiver anexado.
fn physical_path(d: &Disk) -> Option<String> {
    let mut buf = [0u16; 260];
    let mut size = (buf.len() * 2) as u32;
    // SAFETY: buffer local com o tamanho em bytes.
    let r = unsafe { GetVirtualDiskPhysicalPath(d.0, &mut size, buf.as_mut_ptr()) };
    (r == ERROR_SUCCESS).then(|| crate::from_wide(&buf))
}

fn disk_number(store: &Path) -> anyhow::Result<u32> {
    let d = open(store)?;
    let p = physical_path(&d).ok_or_else(|| anyhow::anyhow!("O VHDX não está anexado."))?;
    p.trim_start_matches(r"\\.\PHYSICALDRIVE").trim_start_matches(r"\\.\PhysicalDrive").parse().map_err(|_| anyhow::anyhow!("Caminho físico inesperado: {p}"))
}

fn dir_slash(dir: &Path) -> Vec<u16> {
    let mut s = dir.to_string_lossy().into_owned();
    if !s.ends_with('\\') {
        s.push('\\');
    }
    wide(&s)
}

// ---------- Storage WMI ----------

const STORAGE: &str = "ROOT\\Microsoft\\Windows\\Storage";

#[derive(Deserialize)]
#[allow(non_camel_case_types, non_snake_case)]
struct MSFT_Disk {
    __Path: String,
    PartitionStyle: Option<u16>,
}

#[derive(Deserialize)]
#[allow(non_camel_case_types, non_snake_case)]
struct MSFT_Partition {
    AccessPaths: Option<Vec<String>>,
    GptType: Option<String>,
}

#[derive(Deserialize)]
#[allow(non_camel_case_types, non_snake_case)]
struct MSFT_Volume {
    __Path: String,
}

#[derive(Serialize)]
#[allow(non_snake_case)]
struct InitializeIn {
    PartitionStyle: u16,
}

#[derive(Serialize)]
#[allow(non_snake_case)]
struct CreatePartitionIn {
    UseMaximumSize: bool,
    AssignDriveLetter: bool,
    GptType: String,
}

#[derive(Serialize)]
#[allow(non_snake_case)]
struct FormatIn {
    FileSystem: String,
    FileSystemLabel: String,
    Full: bool,
    Force: bool,
}

#[derive(Deserialize)]
#[allow(non_snake_case)]
struct Ret {
    ReturnValue: u32,
}

fn storage() -> anyhow::Result<wmi::WMIConnection> {
    wmi::WMIConnection::with_namespace_path(STORAGE).map_err(|e| anyhow::anyhow!("Storage WMI indisponível: {e}"))
}

fn check(r: Result<Ret, wmi::WMIError>, what: &str) -> anyhow::Result<()> {
    let r = r.map_err(|e| anyhow::anyhow!("{what}: {e}"))?;
    anyhow::ensure!(r.ReturnValue == 0, "{what}: código {}", r.ReturnValue);
    Ok(())
}

fn data_volume(con: &wmi::WMIConnection, number: u32) -> anyhow::Result<Option<String>> {
    let parts: Vec<MSFT_Partition> = con
        .raw_query(format!("SELECT AccessPaths, GptType FROM MSFT_Partition WHERE DiskNumber = {number}"))
        .map_err(|e| anyhow::anyhow!("Consultar partições: {e}"))?;
    Ok(parts
        .into_iter()
        .filter(|p| p.GptType.as_deref().is_some_and(|g| g.eq_ignore_ascii_case(BASIC_DATA)))
        .flat_map(|p| p.AccessPaths.unwrap_or_default())
        .find(|a| is_volume_device(a)))
}

impl VaultPlatform for VhdPlatform {
    fn store_dir(&self, original: &Path) -> anyhow::Result<PathBuf> {
        let s = original.to_string_lossy();
        anyhow::ensure!(s.len() >= 3 && s.as_bytes()[1] == b':', "Caminho sem unidade.");
        Ok(PathBuf::from(format!("{}\\{STORE_DIR}", &s[..2])))
    }

    fn create_disk(&self, store: &Path, max_bytes: u64) -> anyhow::Result<()> {
        if let Some(dir) = store.parent() {
            secure_dir::ensure_machine_only(dir)?;
        }
        anyhow::ensure!(!store.exists(), "O arquivo do cofre já existe.");
        let p = wide(&store.to_string_lossy());
        let mut params = CREATE_VIRTUAL_DISK_PARAMETERS { Version: CREATE_VIRTUAL_DISK_VERSION_2, ..Default::default() };
        params.Anonymous.Version2.MaximumSize = max_bytes;
        let mut h: HANDLE = null_mut();
        // SAFETY: parâmetros V2 inicializados; tamanhos de bloco/setor 0 = padrão; sem OVERLAPPED.
        let r = unsafe {
            CreateVirtualDisk(&storage_type(), p.as_ptr(), VIRTUAL_DISK_ACCESS_NONE, null_mut(), CREATE_VIRTUAL_DISK_FLAG_NONE, 0, &params, null(), &mut h)
        };
        win32(r, "Criar o VHDX")?;
        drop(Disk(h));
        Ok(())
    }

    fn attach(&self, store: &Path) -> anyhow::Result<()> {
        let d = open(store)?;
        if physical_path(&d).is_some() {
            return Ok(());
        }
        let params = ATTACH_VIRTUAL_DISK_PARAMETERS { Version: ATTACH_VIRTUAL_DISK_VERSION_1, ..Default::default() };
        let flags = ATTACH_VIRTUAL_DISK_FLAG_NO_DRIVE_LETTER | ATTACH_VIRTUAL_DISK_FLAG_PERMANENT_LIFETIME;
        // SAFETY: handle aberto acima; sem descritor (herda); parâmetros V1 zerados.
        let r = unsafe { AttachVirtualDisk(d.0, null_mut(), flags, 0, &params, null()) };
        win32(r, "Anexar o VHDX")
    }

    fn detach(&self, store: &Path) -> anyhow::Result<()> {
        if !store.exists() {
            return Ok(());
        }
        let d = open(store)?;
        if physical_path(&d).is_none() {
            return Ok(());
        }
        // SAFETY: handle aberto acima.
        let r = unsafe { DetachVirtualDisk(d.0, DETACH_VIRTUAL_DISK_FLAG_NONE, 0) };
        win32(r, "Desanexar o VHDX")
    }

    fn delete_disk(&self, store: &Path) -> anyhow::Result<()> {
        self.detach(store)?;
        match std::fs::remove_file(store) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(anyhow::anyhow!("Apagar o VHDX: {e}")),
            _ => Ok(()),
        }
    }

    fn format(&self, store: &Path, label: &str) -> anyhow::Result<String> {
        let number = disk_number(store)?;
        let con = storage()?;
        let disks: Vec<MSFT_Disk> = con
            .raw_query(format!("SELECT __Path, PartitionStyle FROM MSFT_Disk WHERE Number = {number}"))
            .map_err(|e| anyhow::anyhow!("Consultar o disco: {e}"))?;
        let disk = disks.into_iter().next().ok_or_else(|| anyhow::anyhow!("Disco {number} não encontrado."))?;
        if disk.PartitionStyle.unwrap_or(0) == 0 {
            check(con.exec_instance_method::<MSFT_Disk, Ret>(&disk.__Path, "Initialize", InitializeIn { PartitionStyle: 2 }), "Inicializar (GPT)")?;
        }
        if data_volume(&con, number)?.is_none() {
            check(
                con.exec_instance_method::<MSFT_Disk, Ret>(
                    &disk.__Path,
                    "CreatePartition",
                    CreatePartitionIn { UseMaximumSize: true, AssignDriveLetter: false, GptType: BASIC_DATA.into() },
                ),
                "Criar a partição",
            )?;
        }
        let volume = data_volume(&con, number)?.ok_or_else(|| anyhow::anyhow!("Volume do cofre não apareceu."))?;
        let escaped = volume.replace('\\', "\\\\");
        let vols: Vec<MSFT_Volume> =
            con.raw_query(format!("SELECT __Path FROM MSFT_Volume WHERE Path = '{escaped}'")).map_err(|e| anyhow::anyhow!("Consultar o volume: {e}"))?;
        let v = vols.into_iter().next().ok_or_else(|| anyhow::anyhow!("Volume {volume} não encontrado."))?;
        check(
            con.exec_instance_method::<MSFT_Volume, Ret>(
                &v.__Path,
                "Format",
                FormatIn { FileSystem: "NTFS".into(), FileSystemLabel: label.into(), Full: false, Force: true },
            ),
            "Formatar (NTFS)",
        )?;
        Ok(volume)
    }

    fn encrypt(&self, volume: &str, passphrase: &str) -> anyhow::Result<String> {
        WmiBitLocker.enable_for_vault(volume, passphrase)
    }

    fn volume_root(&self, volume: &str) -> PathBuf {
        PathBuf::from(volume)
    }

    fn mount(&self, volume: &str, dir: &Path) -> anyhow::Result<()> {
        anyhow::ensure!(is_volume_device(volume), "Volume inválido.");
        let (d, v) = (dir_slash(dir), wide(volume));
        // SAFETY: cadeias terminadas em nulo; a pasta existe e está vazia (verificado pelo chamador).
        anyhow::ensure!(unsafe { SetVolumeMountPointW(d.as_ptr(), v.as_ptr()) } != 0, "SetVolumeMountPoint: {}", std::io::Error::last_os_error());
        Ok(())
    }

    fn unmount(&self, dir: &Path) -> anyhow::Result<()> {
        if self.mounted_volume(dir).is_none() {
            return Ok(());
        }
        let d = dir_slash(dir);
        // SAFETY: cadeia terminada em nulo.
        anyhow::ensure!(unsafe { DeleteVolumeMountPointW(d.as_ptr()) } != 0, "DeleteVolumeMountPoint: {}", std::io::Error::last_os_error());
        Ok(())
    }

    fn is_mounted(&self, volume: &str, dir: &Path) -> bool {
        self.mounted_volume(dir).is_some_and(|v| v.eq_ignore_ascii_case(volume))
    }

    fn free_bytes(&self, path: &Path) -> anyhow::Result<u64> {
        free_bytes(path)
    }

    fn holders(&self, dir: &Path) -> anyhow::Result<Vec<String>> {
        crate::restart::holders(dir)
    }

    fn security(&self) -> &dyn SecurityCopier {
        &self.security
    }
}

impl VhdPlatform {
    fn mounted_volume(&self, dir: &Path) -> Option<String> {
        let d = dir_slash(dir);
        let mut buf = [0u16; 64];
        // SAFETY: buffer local de 64 caracteres (um nome de volume tem 49).
        (unsafe { GetVolumeNameForVolumeMountPointW(d.as_ptr(), buf.as_mut_ptr(), buf.len() as u32) } != 0).then(|| crate::from_wide(&buf))
    }
}

pub fn free_bytes(path: &Path) -> anyhow::Result<u64> {
    let mut probe = path.to_path_buf();
    while !probe.exists() {
        probe = probe.parent().ok_or_else(|| anyhow::anyhow!("Unidade inexistente."))?.to_path_buf();
    }
    let p = dir_slash(&probe);
    let mut free = 0u64;
    // SAFETY: cadeia terminada em nulo; saídas opcionais nulas.
    anyhow::ensure!(unsafe { GetDiskFreeSpaceExW(p.as_ptr(), &mut free, null_mut(), null_mut()) } != 0, "Espaço livre: {}", std::io::Error::last_os_error());
    Ok(free)
}
