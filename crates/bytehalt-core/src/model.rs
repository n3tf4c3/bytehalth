//! Recursos, políticas e grupos. Os tipos são serializáveis e trafegam no pipe tal como são.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ResourceKind {
    /// Unidade de dados inteira protegida por BitLocker (ex.: D:).
    BitLockerVolume,
    /// Cofre de pasta: VHDX com volume BitLocker (Fase 2).
    Vault,
}

/// Recurso cadastrado. `target` é a letra ("D:") ou o identificador do cofre.
/// O serviço só age sobre recursos cadastrados.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProtectedResource {
    pub id: Uuid,
    pub display_name: String,
    pub kind: ResourceKind,
    pub target: String,
}

pub const MAX_NAME_LEN: usize = 80;
pub const MAX_GROUP_RESOURCES: usize = 256;

/// Normaliza uma letra de unidade ("d", "D:", "D:\\" → "D:"). `None` se não for letra de unidade.
pub fn normalize_drive_letter(input: &str) -> Option<String> {
    let s = input.trim();
    let s = s.strip_suffix('\\').unwrap_or(s);
    let mut chars = s.chars();
    let letter = chars.next()?;
    if !letter.is_ascii_alphabetic() {
        return None;
    }
    match (chars.next(), chars.next()) {
        (None, None) | (Some(':'), None) => Some(format!("{}:", letter.to_ascii_uppercase())),
        _ => None,
    }
}

fn valid_name(name: &str) -> bool {
    let n = name.trim();
    !n.is_empty() && n.chars().count() <= MAX_NAME_LEN && !n.chars().any(char::is_control)
}

impl ProtectedResource {
    pub fn validate(&self) -> Vec<String> {
        let mut errors = Vec::new();
        if self.id.is_nil() {
            errors.push("Recurso sem identificador.".into());
        }
        if !valid_name(&self.display_name) {
            errors.push(format!("Nome do recurso inválido (1 a {MAX_NAME_LEN} caracteres, sem controle)."));
        }
        match self.kind {
            ResourceKind::BitLockerVolume => {
                if normalize_drive_letter(&self.target).as_deref() != Some(self.target.as_str()) {
                    errors.push("Unidade inválida: use a forma \"D:\".".into());
                }
            }
            ResourceKind::Vault => {
                if Uuid::parse_str(&self.target).is_err() {
                    errors.push("Identificador de cofre inválido.".into());
                }
            }
        }
        errors
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum InactivityMode {
    /// Bloqueia quando o recurso fica ocioso pelo tempo configurado.
    ResourceIdle,
    /// Bloqueia quando a sessão do usuário fica ociosa pelo tempo configurado.
    SessionIdle,
    /// Bloqueia quando qualquer das duas condições ocorre (o mais restritivo).
    Combined,
}

pub const MIN_TIMEOUT_SECS: u64 = 60;
pub const MAX_TIMEOUT_SECS: u64 = 24 * 3600;
/// Temporizadores oferecidos na interface; "Personalizado" aceita qualquer valor no intervalo.
pub const TIMEOUT_PRESETS_MIN: [u64; 6] = [1, 5, 10, 15, 30, 60];

pub const DEFAULT_TOTP_THRESHOLD_SECS: u64 = 24 * 3600;
pub const MIN_TOTP_THRESHOLD_SECS: u64 = 60;
pub const MAX_TOTP_THRESHOLD_SECS: u64 = 30 * 24 * 3600;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProtectionGroup {
    pub id: Uuid,
    pub name: String,
    pub resource_ids: Vec<Uuid>,
    /// `None` desliga o bloqueio automático (somente manual).
    pub inactivity_secs: Option<u64>,
    pub mode: InactivityMode,
    pub totp_threshold_secs: u64,
    pub lock_on_workstation_lock: bool,
}

impl ProtectionGroup {
    pub fn validate(&self, known_resources: &[Uuid]) -> Vec<String> {
        let mut errors = Vec::new();
        if self.id.is_nil() {
            errors.push("Grupo sem identificador.".into());
        }
        let name = self.name.trim();
        if name.is_empty() {
            errors.push("Informe o nome do grupo.".into());
        } else if name.chars().count() > MAX_NAME_LEN {
            errors.push(format!("O nome do grupo deve ter até {MAX_NAME_LEN} caracteres."));
        } else if name.chars().any(char::is_control) {
            errors.push("O nome do grupo contém caracteres de controle.".into());
        }
        if self.resource_ids.len() > MAX_GROUP_RESOURCES {
            errors.push("Recursos demais no grupo.".into());
        }
        let mut seen = std::collections::HashSet::new();
        if !self.resource_ids.iter().all(|id| seen.insert(*id)) {
            errors.push("O grupo lista o mesmo recurso mais de uma vez.".into());
        }
        for id in self.resource_ids.iter().filter(|id| !known_resources.contains(id)) {
            errors.push(format!("Recurso não cadastrado: {id}."));
        }
        if let Some(t) = self.inactivity_secs
            && !(MIN_TIMEOUT_SECS..=MAX_TIMEOUT_SECS).contains(&t)
        {
            errors.push("O tempo de inatividade deve ficar entre 1 minuto e 24 horas.".into());
        }
        if !(MIN_TOTP_THRESHOLD_SECS..=MAX_TOTP_THRESHOLD_SECS).contains(&self.totp_threshold_secs) {
            errors.push("O limiar do TOTP deve ficar entre 1 minuto e 30 dias.".into());
        }
        errors
    }
}

/// Recursos, grupos e configurações não secretas (SQLite no Windows).
pub trait ConfigRepository: Send + Sync {
    fn resources(&self) -> anyhow::Result<Vec<ProtectedResource>>;
    fn upsert_resource(&self, resource: &ProtectedResource) -> anyhow::Result<()>;
    /// Remove o recurso e suas participações em grupos.
    fn delete_resource(&self, id: Uuid) -> anyhow::Result<()>;
    fn groups(&self) -> anyhow::Result<Vec<ProtectionGroup>>;
    fn upsert_group(&self, group: &ProtectionGroup) -> anyhow::Result<()>;
    fn delete_group(&self, id: Uuid) -> anyhow::Result<()>;
    fn setting(&self, key: &str) -> anyhow::Result<Option<String>>;
    fn set_setting(&self, key: &str, value: &str) -> anyhow::Result<()>;
}

/// Recursos, grupos e pares chave/valor.
type MemoryConfig = (Vec<ProtectedResource>, Vec<ProtectionGroup>, Vec<(String, String)>);

#[derive(Default)]
pub struct InMemoryConfig {
    inner: std::sync::Mutex<MemoryConfig>,
}

impl ConfigRepository for InMemoryConfig {
    fn resources(&self) -> anyhow::Result<Vec<ProtectedResource>> {
        let mut r = self.inner.lock().unwrap_or_else(|e| e.into_inner()).0.clone();
        r.sort_by_key(|x| x.display_name.to_lowercase());
        Ok(r)
    }

    fn upsert_resource(&self, resource: &ProtectedResource) -> anyhow::Result<()> {
        let mut s = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        s.0.retain(|r| r.id != resource.id);
        s.0.push(resource.clone());
        Ok(())
    }

    fn delete_resource(&self, id: Uuid) -> anyhow::Result<()> {
        let mut s = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        s.0.retain(|r| r.id != id);
        for g in &mut s.1 {
            g.resource_ids.retain(|r| *r != id);
        }
        Ok(())
    }

    fn groups(&self) -> anyhow::Result<Vec<ProtectionGroup>> {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner()).1.clone();
        g.sort_by_key(|x| x.name.to_lowercase());
        Ok(g)
    }

    fn upsert_group(&self, group: &ProtectionGroup) -> anyhow::Result<()> {
        let mut s = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        s.1.retain(|g| g.id != group.id);
        s.1.push(group.clone());
        Ok(())
    }

    fn delete_group(&self, id: Uuid) -> anyhow::Result<()> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).1.retain(|g| g.id != id);
        Ok(())
    }

    fn setting(&self, key: &str) -> anyhow::Result<Option<String>> {
        let s = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        Ok(s.2.iter().find(|(k, _)| k == key).map(|(_, v)| v.clone()))
    }

    fn set_setting(&self, key: &str, value: &str) -> anyhow::Result<()> {
        let mut s = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        s.2.retain(|(k, _)| k != key);
        s.2.push((key.into(), value.into()));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn group(known: Uuid) -> ProtectionGroup {
        ProtectionGroup {
            id: Uuid::new_v4(),
            name: "Discos".into(),
            resource_ids: vec![known],
            inactivity_secs: Some(300),
            mode: InactivityMode::ResourceIdle,
            totp_threshold_secs: DEFAULT_TOTP_THRESHOLD_SECS,
            lock_on_workstation_lock: true,
        }
    }

    #[test]
    fn letra_de_unidade_e_normalizada() {
        for (i, o) in [("d", "D:"), ("D:", "D:"), ("e:\\", "E:"), (" f: ", "F:")] {
            assert_eq!(normalize_drive_letter(i).as_deref(), Some(o), "{i}");
        }
    }

    #[test]
    fn entrada_que_nao_e_letra_de_unidade_e_recusada() {
        for i in ["", "1:", "DD", "D:\\pasta", "\\\\servidor\\c$", "D:' OR 1=1 --", "Ç:"] {
            assert_eq!(normalize_drive_letter(i), None, "{i}");
        }
    }

    #[test]
    fn grupo_valido_nao_tem_erros() {
        let k = Uuid::new_v4();
        assert!(group(k).validate(&[k]).is_empty());
    }

    #[test]
    fn nome_invalido_e_recusado() {
        let k = Uuid::new_v4();
        for name in ["", "   ", "nome\u{7}", &"x".repeat(81)] {
            assert!(!ProtectionGroup { name: name.into(), ..group(k) }.validate(&[k]).is_empty(), "{name:?}");
        }
    }

    #[test]
    fn recurso_repetido_ou_desconhecido_e_recusado() {
        let k = Uuid::new_v4();
        assert!(!ProtectionGroup { resource_ids: vec![k, k], ..group(k) }.validate(&[k]).is_empty());
        assert!(!ProtectionGroup { resource_ids: vec![Uuid::new_v4()], ..group(k) }.validate(&[k]).is_empty());
    }

    #[test]
    fn tempos_fora_do_intervalo_sao_recusados_e_personalizado_valido_aceito() {
        let k = Uuid::new_v4();
        for t in [30, 25 * 3600] {
            assert!(!ProtectionGroup { inactivity_secs: Some(t), ..group(k) }.validate(&[k]).is_empty());
        }
        assert!(ProtectionGroup { inactivity_secs: Some(7 * 60), ..group(k) }.validate(&[k]).is_empty());
        for t in [10, 31 * 24 * 3600] {
            assert!(!ProtectionGroup { totp_threshold_secs: t, ..group(k) }.validate(&[k]).is_empty());
        }
    }

    #[test]
    fn os_temporizadores_oferecidos_sao_os_da_especificacao() {
        assert_eq!(TIMEOUT_PRESETS_MIN, [1, 5, 10, 15, 30, 60]);
    }

    #[test]
    fn volume_com_alvo_nao_normalizado_e_invalido() {
        let r = ProtectedResource { id: Uuid::new_v4(), display_name: "X".into(), kind: ResourceKind::BitLockerVolume, target: "d".into() };
        assert!(!r.validate().is_empty());
    }
}
