//! BitLocker via WMI (`root\CIMV2\Security\MicrosoftVolumeEncryption`, `Win32_EncryptableVolume`).
//! Exige administrador: usado só pelo serviço (LocalSystem). Nunca força a desmontagem e recusa a
//! unidade do sistema antes de qualquer chamada de bloqueio.

use bytehalt_core::locking::{LockAttempt, LockOutcome, LockState, ResourceLocker, ResourceStatus, UnlockAttempt, UnlockOutcome};
use bytehalt_core::model::{ProtectedResource, ResourceKind, normalize_drive_letter};
use serde::{Deserialize, Serialize};

/// Dados brutos de um volume criptografável.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VolumeInfo {
    pub drive_letter: String,
    /// 0 = SO, 1 = dados fixo, 2 = removível (Windows 8+); `None` se ausente.
    pub volume_type: Option<u32>,
    /// 0 = desligada, 1 = ligada, 2 = desconhecida (ex.: bloqueado).
    pub protection_status: u32,
    /// 0 = desbloqueado, 1 = bloqueado.
    pub lock_status: u32,
    /// `None` quando a consulta falhou (ex.: volume bloqueado).
    pub auto_unlock: Option<bool>,
}

/// Fachada mínima sobre o BitLocker, para testes sem tocar em discos.
pub trait BitLockerApi: Send + Sync {
    fn find(&self, letter: &str) -> anyhow::Result<Option<VolumeInfo>>;
    fn list(&self) -> anyhow::Result<Vec<VolumeInfo>>;
    /// HRESULT de `Lock`. O ByteHalt sempre passa `force_dismount = false`.
    fn lock(&self, letter: &str, force_dismount: bool) -> anyhow::Result<u32>;
    fn unlock_with_passphrase(&self, letter: &str, passphrase: &str) -> anyhow::Result<u32>;
}

pub mod codes {
    pub const OK: u32 = 0;
    /// E_ACCESSDENIED em Lock: "aplicativos estão acessando este volume".
    pub const ACCESS_DENIED: u32 = 0x8007_0005;
    /// FVE_E_LOCKED_VOLUME.
    pub const LOCKED_VOLUME: u32 = 0x8031_0000;
    /// FVE_E_NOT_ENCRYPTED.
    pub const NOT_ENCRYPTED: u32 = 0x8031_0001;
    /// FVE_E_FAILED_AUTHENTICATION (confirmado na VM de teste: senha errada).
    pub const FAILED_AUTHENTICATION: u32 = 0x8031_0027;
}

/// `\\?\Volume{GUID}\` (identificador de volume sem letra, como o dos cofres).
pub fn is_volume_device(s: &str) -> bool {
    let Some(guid) = s.strip_prefix(r"\\?\Volume{").and_then(|r| r.strip_suffix("}\\")) else { return false };
    guid.len() == 36 && guid.char_indices().all(|(i, c)| if matches!(i, 8 | 13 | 18 | 23) { c == '-' } else { c.is_ascii_hexdigit() })
}

pub fn is_system_volume(info: &VolumeInfo, system_drive: &str) -> bool {
    info.volume_type == Some(0) || info.drive_letter.eq_ignore_ascii_case(system_drive.trim_end_matches('\\'))
}

pub fn map_status(info: Option<&VolumeInfo>, system_drive: &str) -> ResourceStatus {
    let Some(info) = info else {
        return ResourceStatus::unavailable("Volume não encontrado ou não criptografável.");
    };
    let system = is_system_volume(info, system_drive);
    let auto = info.auto_unlock.unwrap_or(false);
    let (state, detail) = if info.lock_status == 1 {
        (LockState::Locked, None)
    } else {
        match info.protection_status {
            1 => (LockState::Unlocked, auto.then(|| "Desbloqueio automático ativo: o Windows reabrirá o volume na próxima montagem.".to_owned())),
            0 => (LockState::NotProtected, Some("BitLocker desligado ou suspenso neste volume.".to_owned())),
            _ => (LockState::Unknown, Some("Estado de proteção desconhecido.".to_owned())),
        }
    };
    ResourceStatus { state, is_system_volume: system, auto_unlock: auto, detail }
}

pub fn map_lock(hresult: u32) -> LockAttempt {
    let (outcome, detail) = match hresult {
        codes::OK => (LockOutcome::Locked, None),
        codes::ACCESS_DENIED => (LockOutcome::Postponed, Some("Há aplicativos usando o volume.".to_owned())),
        codes::LOCKED_VOLUME => (LockOutcome::AlreadyLocked, None),
        codes::NOT_ENCRYPTED => (LockOutcome::Refused, Some("O volume não está criptografado.".to_owned())),
        other => (LockOutcome::Failed, Some(format!("BitLocker retornou 0x{other:08X}."))),
    };
    LockAttempt { outcome, detail }
}

pub fn map_unlock(hresult: u32) -> UnlockAttempt {
    match hresult {
        codes::OK => UnlockAttempt { outcome: UnlockOutcome::Unlocked, detail: None },
        codes::FAILED_AUTHENTICATION => UnlockAttempt { outcome: UnlockOutcome::BadCredential, detail: None },
        other => UnlockAttempt { outcome: UnlockOutcome::Failed, detail: Some(format!("BitLocker retornou 0x{other:08X}.")) },
    }
}

pub struct BitLockerLocker<A: BitLockerApi> {
    api: A,
    system_drive: String,
}

impl<A: BitLockerApi> BitLockerLocker<A> {
    pub fn new(api: A, system_drive: &str) -> Self {
        Self { api, system_drive: system_drive.trim_end_matches('\\').to_uppercase() }
    }

    pub fn api(&self) -> &A {
        &self.api
    }

    fn refused_system() -> LockAttempt {
        LockAttempt { outcome: LockOutcome::Refused, detail: Some("A unidade do sistema em execução não pode ser bloqueada.".to_owned()) }
    }
}

impl<A: BitLockerApi> ResourceLocker for BitLockerLocker<A> {
    fn kind(&self) -> ResourceKind {
        ResourceKind::BitLockerVolume
    }

    fn status(&self, r: &ProtectedResource) -> ResourceStatus {
        match self.api.find(&r.target) {
            Ok(info) => map_status(info.as_ref(), &self.system_drive),
            Err(e) => ResourceStatus::unavailable(format!("{e:#}")),
        }
    }

    fn lock(&self, r: &ProtectedResource) -> LockAttempt {
        if r.target.eq_ignore_ascii_case(&self.system_drive) {
            return Self::refused_system();
        }
        let info = match self.api.find(&r.target) {
            Ok(Some(info)) => info,
            Ok(None) => return LockAttempt { outcome: LockOutcome::Unavailable, detail: Some("Volume não encontrado.".to_owned()) },
            Err(e) => return LockAttempt { outcome: LockOutcome::Unavailable, detail: Some(format!("{e:#}")) },
        };
        if is_system_volume(&info, &self.system_drive) {
            return Self::refused_system();
        }
        match self.api.lock(&r.target, false) {
            Ok(code) => map_lock(code),
            Err(e) => LockAttempt { outcome: LockOutcome::Unavailable, detail: Some(format!("{e:#}")) },
        }
    }

    fn unlock(&self, r: &ProtectedResource, passphrase: &str) -> UnlockAttempt {
        match self.api.unlock_with_passphrase(&r.target, passphrase) {
            Ok(code) => map_unlock(code),
            // A mensagem de erro do WMI não contém a senha.
            Err(e) => UnlockAttempt { outcome: UnlockOutcome::Unavailable, detail: Some(format!("{e:#}")) },
        }
    }
}

/// Implementação real. Cada chamada abre a própria conexão (o COM é por thread).
pub struct WmiBitLocker;

const NAMESPACE: &str = "ROOT\\CIMV2\\Security\\MicrosoftVolumeEncryption";

#[derive(Deserialize)]
#[allow(non_camel_case_types, non_snake_case)]
struct Win32_EncryptableVolume {
    __Path: String,
    DriveLetter: Option<String>,
    VolumeType: Option<u32>,
}

#[derive(Serialize)]
#[allow(non_snake_case)]
struct LockInput {
    ForceDismount: bool,
}

#[derive(Serialize)]
#[allow(non_snake_case)]
struct UnlockInput {
    Passphrase: String,
}

#[derive(Deserialize)]
#[allow(non_snake_case)]
struct ReturnOnly {
    ReturnValue: u32,
}

impl WmiBitLocker {
    fn connect() -> anyhow::Result<wmi::WMIConnection> {
        wmi::WMIConnection::with_namespace_path(NAMESPACE).map_err(|e| anyhow::anyhow!("BitLocker indisponível: {e}"))
    }

    fn volumes(con: &wmi::WMIConnection, letter: Option<&str>) -> anyhow::Result<Vec<Win32_EncryptableVolume>> {
        let query = match letter {
            // Identificador de volume validado (só hexadecimal e hífens): pode entrar na consulta.
            Some(d) if is_volume_device(d) => {
                format!("SELECT __Path, DriveLetter, VolumeType FROM Win32_EncryptableVolume WHERE DeviceID = '{}'", d.replace('\\', "\\\\"))
            }
            // A letra já foi normalizada para "X:": nada do usuário entra sem validação na consulta.
            Some(l) => format!("SELECT __Path, DriveLetter, VolumeType FROM Win32_EncryptableVolume WHERE DriveLetter = '{l}'"),
            None => "SELECT __Path, DriveLetter, VolumeType FROM Win32_EncryptableVolume".to_owned(),
        };
        con.raw_query(query).map_err(|e| anyhow::anyhow!("Consulta ao BitLocker falhou: {e}"))
    }

    fn uint_out(con: &wmi::WMIConnection, path: &str, method: &str, property: &str) -> Option<u32> {
        let out = con.exec_method(path, method, None).ok()??;
        let ret = out.get_property("ReturnValue").ok()?;
        if !matches!(ret, wmi::Variant::UI4(0)) {
            return None;
        }
        match out.get_property(property).ok()? {
            wmi::Variant::UI4(v) => Some(v),
            wmi::Variant::I4(v) => u32::try_from(v).ok(),
            _ => None,
        }
    }

    fn read(con: &wmi::WMIConnection, v: &Win32_EncryptableVolume) -> VolumeInfo {
        let auto_unlock = con.exec_method(&v.__Path, "IsAutoUnlockEnabled", None).ok().flatten().and_then(|o| {
            match (o.get_property("ReturnValue").ok(), o.get_property("IsAutoUnlockEnabled").ok()) {
                (Some(wmi::Variant::UI4(0)), Some(wmi::Variant::Bool(b))) => Some(b),
                _ => None,
            }
        });
        VolumeInfo {
            drive_letter: v.DriveLetter.clone().unwrap_or_default(),
            volume_type: v.VolumeType,
            protection_status: Self::uint_out(con, &v.__Path, "GetProtectionStatus", "ProtectionStatus").unwrap_or(2),
            lock_status: Self::uint_out(con, &v.__Path, "GetLockStatus", "LockStatus").unwrap_or(0),
            auto_unlock,
        }
    }

    fn path(con: &wmi::WMIConnection, letter: &str) -> anyhow::Result<String> {
        if is_volume_device(letter) {
            return Self::volumes(con, Some(letter))?.into_iter().next().map(|v| v.__Path).ok_or_else(|| anyhow::anyhow!("Volume do cofre não encontrado."));
        }
        let l = normalize_drive_letter(letter).ok_or_else(|| anyhow::anyhow!("Letra de unidade inválida."))?;
        Self::volumes(con, Some(&l))?.into_iter().next().map(|v| v.__Path).ok_or_else(|| anyhow::anyhow!("Volume não encontrado."))
    }
}

impl BitLockerApi for WmiBitLocker {
    fn find(&self, letter: &str) -> anyhow::Result<Option<VolumeInfo>> {
        let Some(l) = normalize_drive_letter(letter).or_else(|| is_volume_device(letter).then(|| letter.to_owned())) else { return Ok(None) };
        let con = Self::connect()?;
        Ok(Self::volumes(&con, Some(&l))?.first().map(|v| Self::read(&con, v)))
    }

    fn list(&self) -> anyhow::Result<Vec<VolumeInfo>> {
        let con = Self::connect()?;
        Ok(Self::volumes(&con, None)?.iter().filter(|v| v.DriveLetter.as_deref().is_some_and(|d| !d.is_empty())).map(|v| Self::read(&con, v)).collect())
    }

    fn lock(&self, letter: &str, force_dismount: bool) -> anyhow::Result<u32> {
        let con = Self::connect()?;
        let path = Self::path(&con, letter)?;
        let out: ReturnOnly = con
            .exec_instance_method::<Win32_EncryptableVolume, _>(&path, "Lock", LockInput { ForceDismount: force_dismount })
            .map_err(|e| anyhow::anyhow!("Lock falhou: {e}"))?;
        Ok(out.ReturnValue)
    }

    fn unlock_with_passphrase(&self, letter: &str, passphrase: &str) -> anyhow::Result<u32> {
        let con = Self::connect()?;
        let path = Self::path(&con, letter)?;
        let out: ReturnOnly = con
            .exec_instance_method::<Win32_EncryptableVolume, _>(&path, "UnlockWithPassphrase", UnlockInput { Passphrase: passphrase.to_owned() })
            .map_err(|_| anyhow::anyhow!("UnlockWithPassphrase falhou."))?;
        Ok(out.ReturnValue)
    }
}

#[derive(Serialize)]
#[allow(non_snake_case)]
struct PassphraseIn {
    FriendlyName: String,
    Passphrase: String,
}

#[derive(Serialize)]
#[allow(non_snake_case)]
struct NumericalIn {
    FriendlyName: String,
}

#[derive(Deserialize)]
#[allow(non_snake_case)]
struct ProtectorOut {
    ReturnValue: u32,
    VolumeKeyProtectorID: Option<String>,
}

#[derive(Serialize)]
#[allow(non_snake_case)]
struct ProtectorIdIn {
    VolumeKeyProtectorID: String,
}

#[derive(Deserialize)]
#[allow(non_snake_case)]
struct NumericalOut {
    ReturnValue: u32,
    NumericalPassword: Option<String>,
}

#[derive(Serialize)]
#[allow(non_snake_case)]
struct EncryptIn {
    EncryptionMethod: u32,
    EncryptionFlags: u32,
}

/// XTS-AES 256 e "somente espaço usado" (volume novo: nada a converter).
const XTS_AES_256: u32 = 7;
const USED_SPACE_ONLY: u32 = 1;

impl WmiBitLocker {
    /// Liga o BitLocker no volume novo de um cofre: protetor de senha, chave de recuperação numérica
    /// e criptografia. Devolve a chave de recuperação (exibida ao usuário uma vez; nunca registrada).
    pub fn enable_for_vault(&self, device: &str, passphrase: &str) -> anyhow::Result<String> {
        anyhow::ensure!(is_volume_device(device), "Volume do cofre inválido.");
        let con = Self::connect()?;
        let path = Self::path(&con, device)?;
        let hr = |what: &str, code: u32| -> anyhow::Result<()> {
            anyhow::ensure!(code == 0, "{what}: BitLocker retornou 0x{code:08X}.");
            Ok(())
        };
        let p: ProtectorOut = con
            .exec_instance_method::<Win32_EncryptableVolume, _>(
                &path,
                "ProtectKeyWithPassphrase",
                PassphraseIn { FriendlyName: "ByteHalt".into(), Passphrase: passphrase.to_owned() },
            )
            .map_err(|_| anyhow::anyhow!("ProtectKeyWithPassphrase falhou."))?;
        hr("Protetor de senha", p.ReturnValue)?;
        let n: ProtectorOut = con
            .exec_instance_method::<Win32_EncryptableVolume, _>(
                &path,
                "ProtectKeyWithNumericalPassword",
                NumericalIn { FriendlyName: "ByteHalt (recuperação)".into() },
            )
            .map_err(|e| anyhow::anyhow!("ProtectKeyWithNumericalPassword falhou: {e}"))?;
        hr("Chave de recuperação", n.ReturnValue)?;
        let id = n.VolumeKeyProtectorID.ok_or_else(|| anyhow::anyhow!("Chave de recuperação sem identificador."))?;
        let k: NumericalOut = con
            .exec_instance_method::<Win32_EncryptableVolume, _>(&path, "GetKeyProtectorNumericalPassword", ProtectorIdIn { VolumeKeyProtectorID: id })
            .map_err(|e| anyhow::anyhow!("GetKeyProtectorNumericalPassword falhou: {e}"))?;
        hr("Ler a chave de recuperação", k.ReturnValue)?;
        let key = k.NumericalPassword.filter(|s| !s.is_empty()).ok_or_else(|| anyhow::anyhow!("Chave de recuperação vazia."))?;
        let mut e: ReturnOnly = con
            .exec_instance_method::<Win32_EncryptableVolume, _>(&path, "Encrypt", EncryptIn { EncryptionMethod: XTS_AES_256, EncryptionFlags: USED_SPACE_ONLY })
            .map_err(|e| anyhow::anyhow!("Encrypt falhou: {e}"))?;
        if e.ReturnValue != 0 {
            // Política do Windows pode exigir outro método: 0 = o padrão da política.
            e = con
                .exec_instance_method::<Win32_EncryptableVolume, _>(&path, "Encrypt", EncryptIn { EncryptionMethod: 0, EncryptionFlags: USED_SPACE_ONLY })
                .map_err(|e| anyhow::anyhow!("Encrypt falhou: {e}"))?;
        }
        hr("Criptografar", e.ReturnValue)?;
        // A proteção só fica ativa ao fim da conversão (na VM: ~1 s num volume novo, "só espaço usado").
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(600);
        loop {
            // 1 = totalmente criptografado.
            if Self::uint_out(&con, &path, "GetConversionStatus", "ConversionStatus") == Some(1) {
                break;
            }
            anyhow::ensure!(std::time::Instant::now() < deadline, "A criptografia do cofre não terminou em 10 minutos.");
            std::thread::sleep(std::time::Duration::from_millis(500));
        }
        let protection = Self::uint_out(&con, &path, "GetProtectionStatus", "ProtectionStatus");
        anyhow::ensure!(protection == Some(1), "O BitLocker não ficou ativo no cofre (proteção {protection:?}).");
        Ok(key)
    }
}

/// Bloqueio de cofres: o mesmo BitLocker, endereçado pelo volume do cofre (sem letra).
pub struct VaultLocker<A: BitLockerApi> {
    api: A,
    vaults: std::sync::Arc<dyn bytehalt_core::vault::VaultRepository>,
}

impl<A: BitLockerApi> VaultLocker<A> {
    pub fn new(api: A, vaults: std::sync::Arc<dyn bytehalt_core::vault::VaultRepository>) -> Self {
        Self { api, vaults }
    }

    fn volume(&self, r: &ProtectedResource) -> Result<String, String> {
        let id = uuid::Uuid::parse_str(&r.target).map_err(|_| "Cofre inválido.".to_owned())?;
        let v = self.vaults.vaults().map_err(|e| format!("{e:#}"))?.into_iter().find(|v| v.id == id).ok_or("Cofre não encontrado.")?;
        if v.stage != bytehalt_core::vault::VaultStage::Active {
            return Err("O cofre ainda não está ativo.".into());
        }
        v.volume.filter(|d| is_volume_device(d)).ok_or_else(|| "Cofre sem volume.".into())
    }
}

impl<A: BitLockerApi> ResourceLocker for VaultLocker<A> {
    fn kind(&self) -> ResourceKind {
        ResourceKind::Vault
    }

    fn status(&self, r: &ProtectedResource) -> ResourceStatus {
        match self.volume(r) {
            Ok(d) => match self.api.find(&d) {
                Ok(Some(info)) => {
                    let mut s = map_status(Some(&info), "");
                    s.is_system_volume = false;
                    s
                }
                Ok(None) => ResourceStatus::unavailable("Disco do cofre não anexado."),
                Err(e) => ResourceStatus::unavailable(format!("{e:#}")),
            },
            Err(e) => ResourceStatus::unavailable(e),
        }
    }

    fn lock(&self, r: &ProtectedResource) -> LockAttempt {
        match self.volume(r) {
            Ok(d) => match self.api.lock(&d, false) {
                Ok(code) => map_lock(code),
                Err(e) => LockAttempt { outcome: LockOutcome::Unavailable, detail: Some(format!("{e:#}")) },
            },
            Err(e) => LockAttempt { outcome: LockOutcome::Unavailable, detail: Some(e) },
        }
    }

    fn unlock(&self, r: &ProtectedResource, passphrase: &str) -> UnlockAttempt {
        match self.volume(r) {
            Ok(d) => match self.api.unlock_with_passphrase(&d, passphrase) {
                Ok(code) => map_unlock(code),
                Err(e) => UnlockAttempt { outcome: UnlockOutcome::Unavailable, detail: Some(format!("{e:#}")) },
            },
            Err(e) => UnlockAttempt { outcome: UnlockOutcome::Unavailable, detail: Some(e) },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[test]
    fn identificador_de_volume_e_validado() {
        assert!(is_volume_device(r"\\?\Volume{2e7c39d3-62c1-4a69-8e6e-29e517835e30}\"));
        for bad in [r"\\?\Volume{2e7c39d3-62c1-4a69-8e6e-29e517835e30}", r"\\?\Volume{2e7c39d3'62c1-4a69-8e6e-29e517835e30}\", "E:", r"\\?\Volume{x}\"] {
            assert!(!is_volume_device(bad), "{bad}");
        }
    }
    use uuid::Uuid;

    #[derive(Default)]
    struct Fake {
        volumes: Vec<VolumeInfo>,
        calls: Mutex<Vec<(String, bool)>>,
        lock_result: u32,
        unlock_result: u32,
        fail: bool,
    }

    impl BitLockerApi for Fake {
        fn find(&self, letter: &str) -> anyhow::Result<Option<VolumeInfo>> {
            anyhow::ensure!(!self.fail, "BitLocker indisponível (teste).");
            Ok(self.volumes.iter().find(|v| v.drive_letter.eq_ignore_ascii_case(letter)).cloned())
        }
        fn list(&self) -> anyhow::Result<Vec<VolumeInfo>> {
            Ok(self.volumes.clone())
        }
        fn lock(&self, letter: &str, force: bool) -> anyhow::Result<u32> {
            anyhow::ensure!(!self.fail, "BitLocker indisponível (teste).");
            self.calls.lock().unwrap().push((letter.into(), force));
            Ok(self.lock_result)
        }
        fn unlock_with_passphrase(&self, _: &str, _: &str) -> anyhow::Result<u32> {
            anyhow::ensure!(!self.fail, "BitLocker indisponível (teste).");
            Ok(self.unlock_result)
        }
    }

    fn vol(letter: &str, vt: u32, prot: u32, lock: u32, auto: Option<bool>) -> VolumeInfo {
        VolumeInfo { drive_letter: letter.into(), volume_type: Some(vt), protection_status: prot, lock_status: lock, auto_unlock: auto }
    }

    fn res(letter: &str) -> ProtectedResource {
        ProtectedResource { id: Uuid::new_v4(), display_name: letter.into(), kind: ResourceKind::BitLockerVolume, target: letter.into() }
    }

    #[test]
    fn estados_sao_traduzidos() {
        assert_eq!(map_status(Some(&vol("D:", 1, 2, 1, None)), "C:").state, LockState::Locked);
        let auto = map_status(Some(&vol("E:", 1, 1, 0, Some(true))), "C:");
        assert!(auto.state == LockState::Unlocked && auto.auto_unlock && auto.detail.unwrap().contains("automático"));
        assert_eq!(map_status(Some(&vol("D:", 1, 0, 0, Some(false))), "C:").state, LockState::NotProtected);
        assert_eq!(map_status(None, "C:").state, LockState::Unavailable);
    }

    #[test]
    fn unidade_do_sistema_pela_letra_ou_pelo_tipo() {
        assert!(is_system_volume(&vol("C:", 1, 1, 0, None), "C:"));
        assert!(is_system_volume(&vol("D:", 0, 1, 0, None), "C:"));
        assert!(is_system_volume(&vol("d:", 1, 1, 0, None), "D:\\"));
        assert!(!is_system_volume(&vol("E:", 1, 1, 0, None), "C:"));
    }

    #[test]
    fn codigos_de_lock_sao_traduzidos() {
        for (code, expected) in [
            (0, LockOutcome::Locked),
            (0x8007_0005, LockOutcome::Postponed),
            (0x8031_0000, LockOutcome::AlreadyLocked),
            (0x8031_0001, LockOutcome::Refused),
            (0x8031_FFFF, LockOutcome::Failed),
        ] {
            assert_eq!(map_lock(code).outcome, expected, "{code:#x}");
        }
        assert!(map_lock(0x8031_FFFF).detail.unwrap().contains("0x8031FFFF"));
        assert_eq!(map_unlock(codes::FAILED_AUTHENTICATION).outcome, UnlockOutcome::BadCredential);
    }

    #[test]
    fn bloqueio_nunca_forca_a_desmontagem() {
        let l = BitLockerLocker::new(Fake { volumes: vec![vol("D:", 1, 1, 0, Some(false))], ..Default::default() }, "C:");
        assert_eq!(l.lock(&res("D:")).outcome, LockOutcome::Locked);
        assert_eq!(*l.api().calls.lock().unwrap(), vec![("D:".to_owned(), false)]);
    }

    #[test]
    fn unidade_do_sistema_e_recusada_antes_de_chamar_a_api() {
        let l = BitLockerLocker::new(Fake { volumes: vec![vol("C:", 0, 1, 0, None), vol("G:", 0, 1, 0, None)], ..Default::default() }, "C:");
        assert_eq!(l.lock(&res("C:")).outcome, LockOutcome::Refused);
        assert_eq!(l.lock(&res("G:")).outcome, LockOutcome::Refused);
        assert!(l.api().calls.lock().unwrap().is_empty());
    }

    #[test]
    fn volume_em_uso_adia_e_indisponivel_nao_explode() {
        let busy = BitLockerLocker::new(Fake { volumes: vec![vol("D:", 1, 1, 0, None)], lock_result: codes::ACCESS_DENIED, ..Default::default() }, "C:");
        assert_eq!(busy.lock(&res("D:")).outcome, LockOutcome::Postponed);
        let down = BitLockerLocker::new(Fake { fail: true, ..Default::default() }, "C:");
        assert_eq!(down.status(&res("D:")).state, LockState::Unavailable);
        assert_eq!(down.lock(&res("D:")).outcome, LockOutcome::Unavailable);
        assert_eq!(down.unlock(&res("D:"), "x").outcome, UnlockOutcome::Unavailable);
        let bad = BitLockerLocker::new(Fake { unlock_result: codes::FAILED_AUTHENTICATION, ..Default::default() }, "C:");
        assert_eq!(bad.unlock(&res("D:"), "x").outcome, UnlockOutcome::BadCredential);
    }

    #[test]
    fn consulta_wmi_so_aceita_letra_valida() {
        // Não chega a consultar o BitLocker: entrada inválida é recusada antes.
        assert!(WmiBitLocker.find("D:' OR DriveLetter LIKE '%").unwrap().is_none());
    }
}
