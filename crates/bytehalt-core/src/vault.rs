//! Cofres de pasta (Fase 2, docs/ARCHITECTURE.md §3): cada pasta protegida vira um VHDX com um volume
//! BitLocker montado no caminho original. Aqui ficam o registro persistido, as regras de caminho e os
//! contratos com a plataforma; a migração está em `migrate` e o fluxo em `vault_manager`.

use crate::clock::UtcMillis;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use uuid::Uuid;

/// Sufixo da pasta de reserva criada na troca (`<pasta>.bytehalt-reserva-<data>`).
pub const RESERVE_MARK: &str = ".bytehalt-reserva-";
/// Sufixo da cópia de volta feita ao remover o cofre (`<pasta>.bytehalt-restaurando-<data>`).
pub const RESTORE_MARK: &str = ".bytehalt-restaurando-";
/// Senha do BitLocker: o mínimo do próprio BitLocker é 8 caracteres.
pub const MIN_PASSPHRASE: usize = 8;
pub const MAX_PASSPHRASE: usize = 256;
pub const MIN_VAULT_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_VAULT_BYTES: u64 = 64 * 1024 * 1024 * 1024 * 1024;

/// Etapas persistidas. Cada transição é gravada ANTES da operação seguinte, para que o serviço saiba
/// desfazer ou concluir depois de uma queda (`VaultManager::recover`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum VaultStage {
    /// Criando o disco, formatando, criptografando e copiando. O original não foi tocado.
    Preparing,
    /// Cópia verificada; aguarda a confirmação do usuário para trocar a pasta pelo cofre.
    Ready,
    /// Troca em andamento (renomear o original para a reserva e montar o cofre no caminho).
    Swapping,
    /// Cofre montado no caminho original.
    Active,
    /// Remoção em andamento: copiando o conteúdo de volta para uma pasta comum.
    Removing,
    /// Preparação falhou; o original não foi tocado. Pode ser descartado.
    Failed,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultRecord {
    pub id: Uuid,
    pub name: String,
    /// Caminho protegido, normalizado (`E:\Projetos\x`).
    pub original_path: String,
    /// Pasta de reserva com o conteúdo original, depois da troca e até o usuário apagá-la.
    pub reserve_path: Option<String>,
    /// Arquivo VHDX.
    pub store_path: String,
    /// `\\?\Volume{GUID}\` do volume do cofre, depois de formatado.
    pub volume: Option<String>,
    pub max_bytes: u64,
    pub stage: VaultStage,
    pub files: u64,
    pub bytes: u64,
    pub created_at: UtcMillis,
    /// Recurso de bloqueio criado na ativação (tipo `Vault`, alvo = `id`).
    pub resource_id: Option<Uuid>,
    pub error: Option<String>,
    /// Cópia de volta em andamento (remoção do cofre).
    #[serde(default)]
    pub restore_path: Option<String>,
}

pub trait VaultRepository: Send + Sync {
    fn vaults(&self) -> anyhow::Result<Vec<VaultRecord>>;
    fn upsert_vault(&self, vault: &VaultRecord) -> anyhow::Result<()>;
    fn delete_vault(&self, id: Uuid) -> anyhow::Result<()>;
}

#[derive(Default)]
pub struct InMemoryVaults(Mutex<Vec<VaultRecord>>);

impl VaultRepository for InMemoryVaults {
    fn vaults(&self) -> anyhow::Result<Vec<VaultRecord>> {
        Ok(self.0.lock().unwrap_or_else(|e| e.into_inner()).clone())
    }
    fn upsert_vault(&self, v: &VaultRecord) -> anyhow::Result<()> {
        let mut all = self.0.lock().unwrap_or_else(|e| e.into_inner());
        all.retain(|x| x.id != v.id);
        all.push(v.clone());
        Ok(())
    }
    fn delete_vault(&self, id: Uuid) -> anyhow::Result<()> {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).retain(|x| x.id != id);
        Ok(())
    }
}

/// Copia a segurança (dono e DACL, com a proteção de herança) de um item para a cópia.
pub trait SecurityCopier: Send + Sync {
    fn copy(&self, from: &Path, to: &Path) -> std::io::Result<()>;
    /// Para a raiz do volume do cofre (sem o mesmo pai da origem): herança vira explícita.
    fn copy_root(&self, from: &Path, to: &Path) -> std::io::Result<()> {
        self.copy(from, to)
    }
    /// Nomes dos fluxos alternativos de dados de um item (sem o fluxo principal). Implementação
    /// real: NTFS; padrão: nenhum (testes e plataformas sem fluxos).
    fn streams(&self, _: &Path) -> std::io::Result<Vec<String>> {
        Ok(Vec::new())
    }
}

/// Sem cópia de segurança (testes e modo simulado sem privilégio).
pub struct NoSecurity;

impl SecurityCopier for NoSecurity {
    fn copy(&self, _: &Path, _: &Path) -> std::io::Result<()> {
        Ok(())
    }
}

/// Operações de disco e montagem. Implementação real: Virtual Disk API + Storage WMI + BitLocker WMI +
/// pontos de montagem; simulada: pastas e junções.
pub trait VaultPlatform: Send + Sync {
    /// Pasta onde ficam os VHDX dos cofres de uma pasta (mesmo volume do original).
    fn store_dir(&self, original: &Path) -> anyhow::Result<PathBuf>;
    fn create_disk(&self, store: &Path, max_bytes: u64) -> anyhow::Result<()>;
    /// Idempotente: anexar um disco já anexado não é erro.
    fn attach(&self, store: &Path) -> anyhow::Result<()>;
    /// Idempotente.
    fn detach(&self, store: &Path) -> anyhow::Result<()>;
    fn delete_disk(&self, store: &Path) -> anyhow::Result<()>;
    /// Particiona e formata em NTFS; devolve o identificador do volume.
    fn format(&self, store: &Path, label: &str) -> anyhow::Result<String>;
    /// Liga o BitLocker (senha + chave de recuperação, só espaço usado); devolve a chave de recuperação.
    fn encrypt(&self, volume: &str, passphrase: &str) -> anyhow::Result<String>;
    /// Raiz acessível do volume (`\\?\Volume{GUID}\`) para copiar antes de montar.
    fn volume_root(&self, volume: &str) -> PathBuf;
    /// Monta o volume na pasta vazia `dir`.
    fn mount(&self, volume: &str, dir: &Path) -> anyhow::Result<()>;
    fn unmount(&self, dir: &Path) -> anyhow::Result<()>;
    fn is_mounted(&self, volume: &str, dir: &Path) -> bool;
    fn free_bytes(&self, path: &Path) -> anyhow::Result<u64>;
    /// Processos com arquivos abertos na pasta (Restart Manager). A troca recusa se houver algum:
    /// um arquivo aberto com compartilhamento de exclusão não impede o Windows de renomear a pasta.
    fn holders(&self, dir: &Path) -> anyhow::Result<Vec<String>>;
    fn security(&self) -> &dyn SecurityCopier;
}

/// Pastas que nunca viram cofre (sistema, programas, raiz de perfis, dados do ByteHalt).
#[derive(Clone, Debug, Default)]
pub struct PathRules {
    /// Pastas proibidas, inclusive tudo abaixo delas (Windows, Program Files, ProgramData…).
    pub forbidden_trees: Vec<String>,
    /// Pastas proibidas só elas mesmas (raiz de Users, cada perfil).
    pub forbidden_exact: Vec<String>,
    /// Nomes proibidos logo abaixo de um perfil (AppData).
    pub forbidden_in_profile: Vec<String>,
    /// Raiz dos perfis (`C:\Users`).
    pub users_root: Option<String>,
}

/// Normaliza `X:\a\b` (barra final, barras repetidas, `/`). Recusa caminhos relativos, de rede, com
/// `.`/`..`, caracteres inválidos e a raiz da unidade.
pub fn normalize_path(raw: &str) -> Option<String> {
    let s = raw.trim().replace('/', "\\");
    let bytes = s.as_bytes();
    if bytes.len() < 4 || !bytes[0].is_ascii_alphabetic() || bytes[1] != b':' || bytes[2] != b'\\' {
        return None;
    }
    let mut out = format!("{}:", (bytes[0] as char).to_ascii_uppercase());
    let mut parts = 0;
    for part in s[3..].split('\\').filter(|p| !p.is_empty()) {
        if part == "." || part == ".." || part.ends_with(' ') || part.ends_with('.') {
            return None;
        }
        if part.chars().any(|c| c.is_control() || matches!(c, '<' | '>' | ':' | '"' | '|' | '?' | '*')) {
            return None;
        }
        out.push('\\');
        out.push_str(part);
        parts += 1;
    }
    (parts > 0 && out.len() <= 240).then_some(out)
}

fn same(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}

/// `inner` é `outer` ou está abaixo dele.
pub fn is_within(inner: &str, outer: &str) -> bool {
    let (i, o) = (inner.to_ascii_lowercase(), outer.trim_end_matches('\\').to_ascii_lowercase());
    i == o || i.strip_prefix(&o).is_some_and(|rest| rest.starts_with('\\'))
}

/// Motivos que impedem a pasta (já normalizada) de virar cofre.
pub fn path_issues(path: &str, rules: &PathRules, vaults: &[VaultRecord]) -> Vec<String> {
    let mut issues = Vec::new();
    for t in &rules.forbidden_trees {
        if is_within(path, t) || is_within(t, path) {
            issues.push(format!("Pasta do sistema ou que contém uma ({t}) não pode virar cofre."));
        }
    }
    for e in &rules.forbidden_exact {
        if same(path, e) || is_within(e, path) {
            issues.push(format!("A pasta {e} não pode virar cofre (nem uma pasta que a contenha)."));
        }
    }
    if let Some(users) = &rules.users_root
        && let Some(rest) = path.to_ascii_lowercase().strip_prefix(&format!("{}\\", users.to_ascii_lowercase()))
    {
        let mut segs = rest.split('\\');
        let _profile = segs.next();
        if let Some(second) = segs.next()
            && rules.forbidden_in_profile.iter().any(|f| same(f, second))
        {
            issues.push(format!("Dados de aplicativos do perfil ({second}) não podem virar cofre."));
        }
    }
    let lower = path.to_ascii_lowercase();
    if lower.contains(RESERVE_MARK) || lower.contains(RESTORE_MARK) {
        issues.push("Pasta de reserva ou de restauração de um cofre não pode virar cofre.".into());
    }
    for v in vaults {
        if is_within(path, &v.original_path) || is_within(&v.original_path, path) {
            issues.push(format!("Sobrepõe o cofre \"{}\" ({}).", v.name, v.original_path));
        }
        if let Some(r) = &v.reserve_path
            && (is_within(path, r) || is_within(r, path))
        {
            issues.push(format!("Sobrepõe a reserva do cofre \"{}\".", v.name));
        }
        if let Some(dir) = Path::new(&v.store_path).parent().and_then(|p| p.to_str())
            && (is_within(path, dir) || is_within(dir, path))
        {
            issues.push("Pasta dos arquivos de cofre não pode virar cofre.".into());
        }
    }
    issues.dedup();
    issues
}

pub fn passphrase_issues(passphrase: &str) -> Vec<String> {
    let n = passphrase.chars().count();
    let mut v = Vec::new();
    if n < MIN_PASSPHRASE {
        v.push(format!("A senha do cofre precisa de pelo menos {MIN_PASSPHRASE} caracteres."));
    }
    if n > MAX_PASSPHRASE {
        v.push(format!("A senha do cofre pode ter até {MAX_PASSPHRASE} caracteres."));
    }
    if passphrase.chars().any(char::is_control) {
        v.push("A senha do cofre contém caracteres de controle.".into());
    }
    v
}

/// Tamanho máximo sugerido: o dobro do conteúdo, entre 1 GiB e o espaço livre, arredondado para GiB.
pub fn suggested_max(bytes: u64, free: u64) -> u64 {
    const GIB: u64 = 1024 * 1024 * 1024;
    let want = (bytes.saturating_mul(2)).max(GIB);
    let rounded = want.div_ceil(GIB) * GIB;
    rounded.min(free.max(MIN_VAULT_BYTES)).max(MIN_VAULT_BYTES)
}

/// Espaço necessário no volume hospedeiro: o conteúdo (cópia + reserva), com folga de 10% e 256 MiB.
pub fn required_free(bytes: u64) -> u64 {
    bytes + bytes / 10 + 256 * 1024 * 1024
}

/// Nome da pasta de reserva para `original` no instante `stamp` (AAAAMMDD-HHMMSS).
pub fn reserve_name(original: &str, stamp: &str) -> String {
    format!("{original}{RESERVE_MARK}{stamp}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules() -> PathRules {
        PathRules {
            forbidden_trees: vec!["C:\\Windows".into(), "C:\\Program Files".into(), "C:\\ProgramData".into()],
            forbidden_exact: vec!["C:\\Users".into(), "C:\\Users\\ana".into()],
            forbidden_in_profile: vec!["AppData".into()],
            users_root: Some("C:\\Users".into()),
        }
    }

    fn vault(path: &str) -> VaultRecord {
        VaultRecord {
            id: Uuid::new_v4(),
            name: "x".into(),
            original_path: path.into(),
            reserve_path: None,
            store_path: "E:\\ByteHalt.Cofres\\a.vhdx".into(),
            volume: None,
            max_bytes: 0,
            stage: VaultStage::Active,
            files: 0,
            bytes: 0,
            created_at: 0,
            resource_id: None,
            error: None,
            restore_path: None,
        }
    }

    #[test]
    fn normalizacao_de_caminho() {
        assert_eq!(normalize_path("e:/Projetos//x\\").as_deref(), Some("E:\\Projetos\\x"));
        for bad in ["E:\\", "E:", "\\\\srv\\share\\x", "x\\y", "E:\\a\\..\\b", "E:\\a\\.", "E:\\a?b", "E:\\fim.\\x", "E:\\a\\b \\c"] {
            assert_eq!(normalize_path(bad), None, "{bad}");
        }
    }

    #[test]
    fn contencao_de_caminhos() {
        assert!(is_within("C:\\Windows\\System32", "C:\\Windows"));
        assert!(is_within("c:\\windows", "C:\\Windows\\"));
        assert!(!is_within("C:\\WindowsApps", "C:\\Windows"));
    }

    #[test]
    fn pastas_proibidas_e_sobreposicao() {
        let r = rules();
        assert!(path_issues("D:\\Projetos\\a", &r, &[]).is_empty());
        assert!(path_issues("C:\\Users\\ana\\Projetos", &r, &[]).is_empty());
        assert!(!path_issues("C:\\Windows\\Temp", &r, &[]).is_empty());
        assert!(!path_issues("C:\\Users", &r, &[]).is_empty());
        assert!(!path_issues("C:\\Users\\ana", &r, &[]).is_empty());
        assert!(!path_issues("C:\\Users\\ana\\AppData\\Local\\x", &r, &[]).is_empty());
        let v = vec![vault("D:\\Projetos\\a")];
        assert!(!path_issues("D:\\Projetos\\a\\sub", &r, &v).is_empty());
        assert!(!path_issues("D:\\Projetos", &r, &v).is_empty());
        assert!(path_issues("D:\\Projetos\\ab", &r, &v).is_empty());
        assert!(!path_issues("E:\\ByteHalt.Cofres", &r, &v).is_empty());
        assert!(!path_issues("D:\\x.bytehalt-reserva-20261104-010101", &r, &[]).is_empty());
    }

    #[test]
    fn senha_e_tamanhos() {
        assert!(!passphrase_issues("1234567").is_empty());
        assert!(passphrase_issues("12345678").is_empty());
        const GIB: u64 = 1 << 30;
        assert_eq!(suggested_max(10, 100 * GIB), GIB);
        assert_eq!(suggested_max(3 * GIB / 2, 100 * GIB), 3 * GIB);
        assert_eq!(suggested_max(30 * GIB, 10 * GIB), 10 * GIB);
        assert!(required_free(GIB) > GIB);
    }
}
