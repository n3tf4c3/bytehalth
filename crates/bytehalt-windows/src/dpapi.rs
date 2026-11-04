//! Estado de bloqueio protegido por DPAPI (escopo máquina no serviço, usuário no modo de
//! desenvolvimento). O DPAPI verifica integridade: arquivo alterado não decifra ⇒ `Corrupted` ⇒ TOTP.
//! Limitação: blobs de escopo máquina podem ser gerados por qualquer processo local; a defesa contra
//! forjamento é a ACL da pasta (SYSTEM e Administradores). Ver docs/ARCHITECTURE.md §10.

use bytehalt_core::auth::{LockRecord, LockStateStore, StoreRead};
use bytehalt_core::clock::UtcMillis;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use uuid::Uuid;
use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Security::Cryptography::{
    CRYPT_INTEGER_BLOB, CRYPTPROTECT_LOCAL_MACHINE, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData, CryptUnprotectData,
};

/// Entropia fixa da aplicação: separa os blobs do ByteHalt de outros blobs DPAPI. Não é segredo.
const ENTROPY: &[u8] = b"ByteHalt.LockState.v1";

pub fn protect(plain: &[u8], machine: bool) -> anyhow::Result<Vec<u8>> {
    crypt(plain, machine, true, ENTROPY)
}

pub fn unprotect(blob: &[u8], machine: bool) -> anyhow::Result<Vec<u8>> {
    crypt(blob, machine, false, ENTROPY)
}

/// Entropia própria das credenciais (senha mestra, segredo TOTP, códigos de recuperação).
const CREDENTIALS_ENTROPY: &[u8] = b"ByteHalt.Credentials.v1";

fn crypt(input: &[u8], machine: bool, encrypt: bool, entropy: &[u8]) -> anyhow::Result<Vec<u8>> {
    let data_in = CRYPT_INTEGER_BLOB { cbData: input.len() as u32, pbData: input.as_ptr() as *mut u8 };
    let entropy = CRYPT_INTEGER_BLOB { cbData: entropy.len() as u32, pbData: entropy.as_ptr() as *mut u8 };
    let mut out = CRYPT_INTEGER_BLOB { cbData: 0, pbData: std::ptr::null_mut() };
    let flags = CRYPTPROTECT_UI_FORBIDDEN | if machine { CRYPTPROTECT_LOCAL_MACHINE } else { 0 };
    // SAFETY: os blobs de entrada apontam para fatias vivas durante a chamada; o DPAPI só as lê.
    // A saída é alocada pelo sistema e liberada com LocalFree abaixo.
    let ok = unsafe {
        if encrypt {
            CryptProtectData(&data_in, std::ptr::null(), &entropy, std::ptr::null(), std::ptr::null(), flags, &mut out)
        } else {
            CryptUnprotectData(&data_in, std::ptr::null_mut(), &entropy, std::ptr::null(), std::ptr::null(), flags, &mut out)
        }
    };
    anyhow::ensure!(ok != 0 && !out.pbData.is_null(), "DPAPI recusou os dados.");
    // SAFETY: o DPAPI devolveu `cbData` bytes válidos em `pbData`, copiados antes de liberar.
    let bytes = unsafe { std::slice::from_raw_parts(out.pbData, out.cbData as usize) }.to_vec();
    // SAFETY: memória alocada pelo DPAPI com LocalAlloc.
    unsafe { LocalFree(out.pbData.cast()) };
    Ok(bytes)
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RecordFile {
    version: u32,
    record: LockRecord,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WatermarkFile {
    version: u32,
    highest_observed: UtcMillis,
}

pub struct DpapiStateStore {
    dir: PathBuf,
    machine: bool,
    gate: Mutex<()>,
}

impl DpapiStateStore {
    pub fn new(dir: impl Into<PathBuf>, machine: bool) -> anyhow::Result<Self> {
        let dir = dir.into();
        std::fs::create_dir_all(&dir)?;
        Ok(Self { dir, machine, gate: Mutex::new(()) })
    }

    fn path(&self, id: Uuid) -> PathBuf {
        self.dir.join(format!("{}.lock", id.simple()))
    }

    fn read_blob<T: for<'de> Deserialize<'de>>(&self, path: &Path) -> StoreRead<T> {
        let _g = self.gate.lock().unwrap_or_else(|e| e.into_inner());
        let bytes = match std::fs::read(path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return StoreRead::NotFound,
            Err(_) => return StoreRead::Error,
        };
        match unprotect(&bytes, self.machine).ok().and_then(|plain| serde_json::from_slice(&plain).ok()) {
            Some(v) => StoreRead::Found(v),
            None => StoreRead::Corrupted,
        }
    }

    fn write_blob(&self, path: &Path, value: &impl Serialize) -> anyhow::Result<()> {
        let blob = protect(&serde_json::to_vec(value)?, self.machine)?;
        let _g = self.gate.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = path.with_extension("tmp");
        {
            use std::io::Write;
            let mut f = std::fs::File::create(&tmp)?;
            f.write_all(&blob)?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, path)?;
        Ok(())
    }
}

impl LockStateStore for DpapiStateStore {
    fn read(&self, id: Uuid) -> StoreRead<LockRecord> {
        match self.read_blob::<RecordFile>(&self.path(id)) {
            // O registro precisa pertencer ao arquivo em que está: impede trocar arquivos entre recursos.
            StoreRead::Found(f) if f.version == 1 && f.record.resource_id == id => StoreRead::Found(f.record),
            StoreRead::Found(_) => StoreRead::Corrupted,
            StoreRead::NotFound => StoreRead::NotFound,
            StoreRead::Corrupted => StoreRead::Corrupted,
            StoreRead::Error => StoreRead::Error,
        }
    }

    fn write(&self, record: &LockRecord) -> anyhow::Result<()> {
        self.write_blob(&self.path(record.resource_id), &RecordFile { version: 1, record: record.clone() })
    }

    fn delete(&self, id: Uuid) -> anyhow::Result<()> {
        let _g = self.gate.lock().unwrap_or_else(|e| e.into_inner());
        match std::fs::remove_file(self.path(id)) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e.into()),
            _ => Ok(()),
        }
    }

    fn read_watermark(&self) -> StoreRead<UtcMillis> {
        match self.read_blob::<WatermarkFile>(&self.dir.join("clock.mark")) {
            StoreRead::Found(f) if f.version == 1 => StoreRead::Found(f.highest_observed),
            StoreRead::Found(_) => StoreRead::Corrupted,
            StoreRead::NotFound => StoreRead::NotFound,
            StoreRead::Corrupted => StoreRead::Corrupted,
            StoreRead::Error => StoreRead::Error,
        }
    }

    fn write_watermark(&self, value: UtcMillis) -> anyhow::Result<()> {
        self.write_blob(&self.dir.join("clock.mark"), &WatermarkFile { version: 1, highest_observed: value })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store(dir: &tempfile::TempDir) -> DpapiStateStore {
        DpapiStateStore::new(dir.path().join("state"), false).unwrap()
    }

    fn rec(id: Uuid, boot: &str) -> LockRecord {
        LockRecord { resource_id: id, locked_at: 1_793_707_200_000, boot_id: boot.into(), uptime_at_lock_ms: 42 * 60_000 }
    }

    #[test]
    fn registro_gravado_e_lido_por_outra_instancia_e_nao_fica_em_texto_puro() {
        let dir = tempfile::tempdir().unwrap();
        let id = Uuid::new_v4();
        store(&dir).write(&rec(id, "boot-texto-visivel")).unwrap();
        assert_eq!(store(&dir).read(id), StoreRead::Found(rec(id, "boot-texto-visivel")));
        let raw = std::fs::read(dir.path().join("state").join(format!("{}.lock", id.simple()))).unwrap();
        assert!(!String::from_utf8_lossy(&raw).contains("boot-texto-visivel"));
        assert_eq!(store(&dir).read(Uuid::new_v4()), StoreRead::NotFound);
    }

    #[test]
    fn adulteracao_lixo_e_troca_entre_recursos_sao_detectados() {
        let dir = tempfile::tempdir().unwrap();
        let s = store(&dir);
        let (a, b, c) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
        s.write(&rec(a, "x")).unwrap();
        let pa = dir.path().join("state").join(format!("{}.lock", a.simple()));
        std::fs::copy(&pa, dir.path().join("state").join(format!("{}.lock", b.simple()))).unwrap();
        assert_eq!(s.read(b), StoreRead::Corrupted);
        std::fs::write(dir.path().join("state").join(format!("{}.lock", c.simple())), b"{\"version\":1}").unwrap();
        assert_eq!(s.read(c), StoreRead::Corrupted);
        let mut bytes = std::fs::read(&pa).unwrap();
        let n = bytes.len();
        bytes[n - 10] ^= 0xFF;
        std::fs::write(&pa, bytes).unwrap();
        assert_eq!(s.read(a), StoreRead::Corrupted);
    }

    #[test]
    fn marca_dagua_e_remocao() {
        let dir = tempfile::tempdir().unwrap();
        let s = store(&dir);
        s.write_watermark(1_793_707_200_000).unwrap();
        assert_eq!(store(&dir).read_watermark(), StoreRead::Found(1_793_707_200_000));
        let id = Uuid::new_v4();
        s.write(&rec(id, "b")).unwrap();
        s.delete(id).unwrap();
        s.delete(id).unwrap();
        assert_eq!(s.read(id), StoreRead::NotFound);
    }
}

/// Credenciais da Fase 3 num único arquivo DPAPI (`credentials.dat`, entropia própria). Arquivo
/// ilegível é ERRO (falha fechada): nunca vira "não configurado".
pub struct DpapiCredentialStore {
    path: PathBuf,
    machine: bool,
    gate: Mutex<()>,
}

impl DpapiCredentialStore {
    pub fn new(dir: impl Into<PathBuf>, machine: bool) -> anyhow::Result<Self> {
        let dir = dir.into();
        std::fs::create_dir_all(&dir)?;
        Ok(Self { path: dir.join("credentials.dat"), machine, gate: Mutex::new(()) })
    }
}

#[derive(Serialize, Deserialize)]
struct CredentialsFile {
    version: u32,
    credentials: bytehalt_core::master::Credentials,
}

impl bytehalt_core::master::CredentialStore for DpapiCredentialStore {
    fn load(&self) -> anyhow::Result<Option<bytehalt_core::master::Credentials>> {
        let _g = self.gate.lock().unwrap_or_else(|e| e.into_inner());
        let bytes = match std::fs::read(&self.path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => anyhow::bail!("Credenciais ilegíveis: {e}"),
        };
        let plain = zeroize::Zeroizing::new(crypt(&bytes, self.machine, false, CREDENTIALS_ENTROPY).map_err(|_| anyhow::anyhow!("Credenciais corrompidas."))?);
        let file: CredentialsFile = serde_json::from_slice(&plain).map_err(|_| anyhow::anyhow!("Credenciais corrompidas."))?;
        anyhow::ensure!(file.version == 1, "Versão de credenciais desconhecida.");
        Ok(Some(file.credentials))
    }

    fn save(&self, c: &bytehalt_core::master::Credentials) -> anyhow::Result<()> {
        let plain = zeroize::Zeroizing::new(serde_json::to_vec(&CredentialsFile { version: 1, credentials: c.clone() })?);
        let blob = crypt(&plain, self.machine, true, CREDENTIALS_ENTROPY)?;
        let _g = self.gate.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = self.path.with_extension("tmp");
        {
            use std::io::Write;
            let mut f = std::fs::File::create(&tmp)?;
            f.write_all(&blob)?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, &self.path)?;
        Ok(())
    }
}

#[cfg(test)]
mod credential_tests {
    use super::*;
    use bytehalt_core::master::{CredentialStore, Credentials};

    fn sample() -> Credentials {
        Credentials { password: "$argon2id$x".into(), totp_secret: vec![1, 2, 3], last_step: 7, recovery: vec!["$argon2id$y".into()], created_at: 1 }
    }

    #[test]
    fn credenciais_cifradas_e_arquivo_corrompido_nao_vira_vazio() {
        let t = tempfile::tempdir().unwrap();
        let s = DpapiCredentialStore::new(t.path(), false).unwrap();
        assert!(s.load().unwrap().is_none());
        s.save(&sample()).unwrap();
        let raw = std::fs::read(t.path().join("credentials.dat")).unwrap();
        assert!(!String::from_utf8_lossy(&raw).contains("argon2id"), "o arquivo não pode ter texto puro");
        let back = s.load().unwrap().unwrap();
        assert_eq!((back.last_step, back.totp_secret.clone()), (7, vec![1, 2, 3]));
        std::fs::write(t.path().join("credentials.dat"), b"lixo").unwrap();
        assert!(s.load().is_err(), "corrompido deve ser erro, não ausência");
        // Blob do estado de bloqueio (outra entropia) não é aceito como credencial.
        std::fs::write(t.path().join("credentials.dat"), protect(b"{}", false).unwrap()).unwrap();
        assert!(s.load().is_err());
    }
}
