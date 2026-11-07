//! Fluxo dos cofres (docs/ARCHITECTURE.md §3):
//!
//! 1. **Analisar**: regras de caminho, inventário (links, nuvem, ilegíveis), espaço livre.
//! 2. **Preparar** (em segundo plano): criar o VHDX, anexar, formatar, ligar o BitLocker (senha +
//!    chave de recuperação), copiar e verificar por SHA-256. O original não é tocado.
//! 3. **Trocar** (confirmação explícita): renomear o original para a reserva (o Windows recusa se houver
//!    arquivo aberto), comparar de novo por SHA-256 e ressincronizar, criar a pasta vazia e montar o
//!    cofre nela. Qualquer falha desfaz a troca e devolve o original ao lugar.
//! 4. **Apagar a reserva**: outra confirmação explícita.
//!
//! Cada etapa é gravada antes de executar; `recover` conclui ou desfaz depois de uma queda.

use crate::clock::Clock;
use crate::journal::{EventType, Journal, JournalEntry, Severity, append_or_log};
use crate::migrate::{self, Inventory};
use crate::vault::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use uuid::Uuid;
use zeroize::Zeroize;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultPlan {
    pub path: String,
    pub inventory: Inventory,
    /// Impedimentos (regras de caminho, inventário, espaço).
    pub issues: Vec<String>,
    pub free_bytes: u64,
    pub required_bytes: u64,
    pub suggested_max_bytes: u64,
}

impl VaultPlan {
    pub fn ok(&self) -> bool {
        self.issues.is_empty()
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JobView {
    pub step: String,
    pub progress_bytes: u64,
    pub total_bytes: u64,
    pub done: bool,
    pub error: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultView {
    pub vault: VaultRecord,
    pub job: Option<JobView>,
}

#[derive(Default)]
struct Job {
    view: JobView,
    /// Identidade obtida pelo serviço, nunca pelo payload do cliente.
    initiator_sid: String,
    recovery: Option<String>,
}

impl Drop for Job {
    fn drop(&mut self) {
        if let Some(key) = self.recovery.as_mut() {
            key.zeroize();
        }
    }
}

pub struct VaultManager {
    platform: Arc<dyn VaultPlatform>,
    repo: Arc<dyn VaultRepository>,
    journal: Arc<dyn Journal>,
    clock: Arc<dyn Clock>,
    rules: PathRules,
    jobs: Mutex<HashMap<Uuid, Job>>,
    /// Serializa preparação, troca, descarte e reserva (uma alteração de disco por vez).
    exclusive: Mutex<()>,
}

type Fail = Vec<String>;

fn one(msg: impl Into<String>) -> Fail {
    vec![msg.into()]
}

impl VaultManager {
    pub fn new(platform: Arc<dyn VaultPlatform>, repo: Arc<dyn VaultRepository>, journal: Arc<dyn Journal>, clock: Arc<dyn Clock>, rules: PathRules) -> Self {
        Self { platform, repo, journal, clock, rules, jobs: Mutex::new(HashMap::new()), exclusive: Mutex::new(()) }
    }

    fn log(&self, event: EventType, severity: Severity, v: &VaultRecord, message: String) {
        append_or_log(self.journal.as_ref(), JournalEntry { at: self.clock.now_utc(), event, severity, resource_id: v.resource_id, message, detail: None });
    }

    fn save(&self, v: &VaultRecord) -> Result<(), Fail> {
        self.repo.upsert_vault(v).map_err(|e| one(format!("Não foi possível gravar o cofre: {e:#}")))
    }

    pub fn vault(&self, id: Uuid) -> Option<VaultRecord> {
        self.repo.vaults().ok()?.into_iter().find(|v| v.id == id)
    }

    /// Cofres com o andamento da preparação, sem entregar nem consumir segredos.
    pub fn list(&self) -> Vec<VaultView> {
        let jobs = self.jobs.lock().unwrap_or_else(|e| e.into_inner());
        let mut out: Vec<VaultView> = self
            .repo
            .vaults()
            .unwrap_or_default()
            .into_iter()
            .map(|vault| {
                let job = jobs.get(&vault.id).map(|j| j.view.clone());
                VaultView { vault, job }
            })
            .collect();
        out.sort_by_key(|v| v.vault.created_at);
        out
    }

    /// Retirada explícita pelo iniciador, após autenticação no serviço. Conserva a chave até o ACK
    /// para que uma resposta perdida no pipe não torne a recuperação irrecuperável.
    pub fn claim_recovery(&self, id: Uuid, caller_sid: &str) -> Result<Option<String>, Fail> {
        let jobs = self.jobs.lock().unwrap_or_else(|e| e.into_inner());
        let job = jobs
            .get(&id)
            .filter(|job| !caller_sid.is_empty() && job.initiator_sid == caller_sid)
            .ok_or_else(|| one("Chave de recuperação indisponível para este usuário."))?;
        Ok(job.recovery.clone())
    }

    /// Confirmação explícita do iniciador de que guardou a chave. Repetir o ACK é seguro.
    pub fn acknowledge_recovery(&self, id: Uuid, caller_sid: &str) -> Result<(), Fail> {
        let mut jobs = self.jobs.lock().unwrap_or_else(|e| e.into_inner());
        let job = jobs
            .get_mut(&id)
            .filter(|job| !caller_sid.is_empty() && job.initiator_sid == caller_sid)
            .ok_or_else(|| one("Chave de recuperação indisponível para este usuário."))?;
        if let Some(mut key) = job.recovery.take() {
            key.zeroize();
        }
        Ok(())
    }

    pub fn analyze(&self, raw: &str) -> VaultPlan {
        let mut plan = VaultPlan {
            path: raw.trim().to_owned(),
            inventory: Inventory::default(),
            issues: vec![],
            free_bytes: 0,
            required_bytes: 0,
            suggested_max_bytes: 0,
        };
        let Some(path) = normalize_path(raw) else {
            plan.issues.push("Informe uma pasta local completa (ex.: D:\\Projetos\\cliente), sem ser a raiz da unidade.".into());
            return plan;
        };
        plan.path = path.clone();
        let existing = self.repo.vaults().unwrap_or_default();
        plan.issues.extend(path_issues(&path, &self.rules, &existing));
        let p = Path::new(&path);
        if !p.is_dir() {
            plan.issues.push("A pasta não existe.".into());
            return plan;
        }
        match self.platform.store_dir(p) {
            Ok(dir) if dir.to_str().is_some_and(|d| is_within(d, &path)) => plan.issues.push("A pasta contém o local dos arquivos de cofre.".into()),
            Ok(_) => {}
            Err(e) => plan.issues.push(format!("{e:#}")),
        }
        match migrate::scan(p) {
            Ok(inv) => {
                plan.issues.extend(inv.blocking.iter().cloned());
                plan.inventory = inv;
            }
            Err(e) => plan.issues.push(format!("Não foi possível ler a pasta: {e}")),
        }
        plan.required_bytes = required_free(plan.inventory.bytes);
        match self.platform.free_bytes(p) {
            Ok(free) => {
                plan.free_bytes = free;
                if free < plan.required_bytes {
                    plan.issues.push(format!(
                        "Espaço livre insuficiente na unidade: {} MiB livres, {} MiB necessários (cópia + reserva).",
                        free >> 20,
                        plan.required_bytes >> 20
                    ));
                }
            }
            Err(e) => plan.issues.push(format!("Espaço livre desconhecido: {e:#}")),
        }
        plan.suggested_max_bytes = suggested_max(plan.inventory.bytes, plan.free_bytes);
        plan
    }

    /// Inicia a preparação em segundo plano. A senha só é usada para criar o protetor do BitLocker.
    pub fn prepare(self: &Arc<Self>, initiator_sid: &str, name: &str, raw_path: &str, passphrase: String, max_bytes: u64) -> Result<VaultRecord, Fail> {
        if initiator_sid.trim().is_empty() {
            return Err(one("Usuário iniciador não identificado."));
        }
        let _x = self.exclusive.lock().unwrap_or_else(|e| e.into_inner());
        let plan = self.analyze(raw_path);
        let mut errors = plan.issues.clone();
        errors.extend(passphrase_issues(&passphrase));
        let name = name.trim();
        if name.is_empty() || name.chars().count() > crate::model::MAX_NAME_LEN || name.chars().any(char::is_control) {
            errors.push("Nome do cofre inválido.".into());
        }
        let min = (plan.inventory.bytes + plan.inventory.bytes / 10 + (64 << 20)).max(MIN_VAULT_BYTES);
        if max_bytes < min || max_bytes > MAX_VAULT_BYTES {
            errors.push(format!("Tamanho máximo do cofre fora do intervalo ({} MiB a {} TiB).", min >> 20, MAX_VAULT_BYTES >> 40));
        }
        if self.repo.vaults().unwrap_or_default().iter().any(|v| v.stage == VaultStage::Preparing) {
            errors.push("Já existe um cofre em preparação.".into());
        }
        if !errors.is_empty() {
            return Err(errors);
        }
        let id = Uuid::new_v4();
        let store = self.platform.store_dir(Path::new(&plan.path)).map_err(|e| one(format!("{e:#}")))?.join(format!("{id}.vhdx"));
        let record = VaultRecord {
            id,
            name: name.to_owned(),
            original_path: plan.path.clone(),
            reserve_path: None,
            store_path: store.to_string_lossy().into_owned(),
            volume: None,
            max_bytes,
            stage: VaultStage::Preparing,
            files: plan.inventory.files,
            bytes: plan.inventory.bytes,
            created_at: self.clock.now_utc(),
            resource_id: None,
            error: None,
            restore_path: None,
        };
        self.save(&record)?;
        self.jobs.lock().unwrap_or_else(|e| e.into_inner()).insert(
            id,
            Job {
                view: JobView { step: "Criando o disco do cofre".into(), total_bytes: plan.inventory.bytes, ..Default::default() },
                initiator_sid: initiator_sid.to_owned(),
                recovery: None,
            },
        );
        self.log(EventType::VaultChanged, Severity::Info, &record, format!("Cofre \"{}\": preparação iniciada para {}.", record.name, record.original_path));
        let me = self.clone();
        let r = record.clone();
        std::thread::Builder::new()
            .name(format!("cofre-{id}"))
            .spawn(move || me.run_prepare(r, passphrase))
            .map_err(|e| one(format!("Não foi possível iniciar a preparação: {e}")))?;
        Ok(record)
    }

    fn step(&self, id: Uuid, step: &str) {
        if let Some(j) = self.jobs.lock().unwrap_or_else(|e| e.into_inner()).get_mut(&id) {
            j.view.step = step.into();
        }
    }

    fn run_prepare(&self, mut v: VaultRecord, mut passphrase: String) {
        let result = self.prepare_steps(&mut v, &passphrase);
        passphrase.zeroize();
        let mut jobs = self.jobs.lock().unwrap_or_else(|e| e.into_inner());
        let job = jobs.entry(v.id).or_default();
        job.view.done = true;
        match result {
            Ok(recovery) => {
                v.stage = VaultStage::Ready;
                job.view.step = "Pronto para trocar a pasta pelo cofre".into();
                job.recovery = Some(recovery);
                drop(jobs);
                let _ = self.save(&v);
                self.log(
                    EventType::VaultChanged,
                    Severity::Info,
                    &v,
                    format!("Cofre \"{}\": cópia verificada ({} arquivo(s)); aguarda a troca.", v.name, v.files),
                );
            }
            Err(e) => {
                job.view.error = Some(e.clone());
                job.view.step = "Falhou".into();
                drop(jobs);
                // O original não foi tocado: descarta o disco.
                let _ = self.platform.detach(Path::new(&v.store_path));
                let _ = self.platform.delete_disk(Path::new(&v.store_path));
                v.stage = VaultStage::Failed;
                v.volume = None;
                v.error = Some(e.clone());
                let _ = self.save(&v);
                self.log(
                    EventType::VaultFailed,
                    Severity::Error,
                    &v,
                    format!("Cofre \"{}\": preparação falhou; a pasta original não foi alterada. {e}", v.name),
                );
            }
        }
    }

    fn prepare_steps(&self, v: &mut VaultRecord, passphrase: &str) -> Result<String, String> {
        let store = PathBuf::from(&v.store_path);
        fn e(what: &'static str) -> impl Fn(anyhow::Error) -> String {
            move |err| format!("{what}: {err:#}")
        }
        if let Some(dir) = store.parent() {
            fs::create_dir_all(dir).map_err(|x| format!("Pasta dos cofres: {x}"))?;
        }
        self.platform.create_disk(&store, v.max_bytes).map_err(e("Criar o disco"))?;
        self.platform.attach(&store).map_err(e("Anexar o disco"))?;
        self.step(v.id, "Formatando");
        let volume = self.platform.format(&store, "ByteHalt").map_err(e("Formatar"))?;
        v.volume = Some(volume.clone());
        self.save(v).map_err(|x| x.join(" "))?;
        self.step(v.id, "Ligando o BitLocker");
        let recovery = self.platform.encrypt(&volume, passphrase).map_err(e("BitLocker"))?;
        self.step(v.id, "Copiando");
        let root = self.platform.volume_root(&volume);
        let src = PathBuf::from(&v.original_path);
        let id = v.id;
        let progress = |n: u64| {
            if let Some(j) = self.jobs.lock().unwrap_or_else(|e| e.into_inner()).get_mut(&id) {
                j.view.progress_bytes = n;
            }
        };
        migrate::copy_tree(&src, &root, self.platform.security(), &progress).map_err(|x| format!("Copiar: {x}"))?;
        self.step(v.id, "Verificando (SHA-256)");
        let (a, b) = (
            migrate::manifest(&src, true).map_err(|x| format!("Ler o original: {x}"))?,
            migrate::manifest(&root, true).map_err(|x| format!("Ler o cofre: {x}"))?,
        );
        let d = migrate::diff(&a, &b);
        if !d.is_empty() {
            return Err(format!("A cópia não confere com o original ({} diferença(s)): {}", d.len(), d.iter().take(3).cloned().collect::<Vec<_>>().join("; ")));
        }
        v.files = a.values().filter(|x| !x.dir).count() as u64;
        v.bytes = a.values().map(|x| x.size).sum();
        Ok(recovery)
    }

    fn stamp(&self) -> String {
        // AAAAMMDD-HHMMSS em UTC, sem dependência de calendário externo.
        let secs = self.clock.now_utc().div_euclid(1000);
        let (days, rem) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
        let (y, m, d) = civil_from_days(days);
        format!("{y:04}{m:02}{d:02}-{:02}{:02}{:02}", rem / 3600, rem % 3600 / 60, rem % 60)
    }

    /// Troca a pasta pelo cofre. Exige o cofre pronto e nenhum arquivo aberto na pasta.
    pub fn swap(&self, id: Uuid) -> Result<VaultRecord, Fail> {
        let _x = self.exclusive.lock().unwrap_or_else(|e| e.into_inner());
        let mut v = self.vault(id).ok_or_else(|| one("Cofre não encontrado."))?;
        if v.stage != VaultStage::Ready {
            return Err(one("O cofre não está pronto para a troca."));
        }
        let volume = v.volume.clone().ok_or_else(|| one("Cofre sem volume."))?;
        let original = PathBuf::from(&v.original_path);
        if !original.is_dir() {
            return Err(one("A pasta original não existe mais."));
        }
        self.platform.attach(Path::new(&v.store_path)).map_err(|e| one(format!("Anexar o disco: {e:#}")))?;
        match self.platform.holders(&original) {
            Ok(h) if !h.is_empty() => {
                return Err(one(format!("Feche os programas que estão usando arquivos da pasta: {}.", h.join(", "))));
            }
            Ok(_) => {}
            Err(e) => return Err(one(format!("Não foi possível verificar arquivos abertos: {e:#}"))),
        }
        let reserve = PathBuf::from(reserve_name(&v.original_path, &self.stamp()));
        if reserve.exists() {
            return Err(one("Já existe uma pasta de reserva com esse nome; tente de novo em um segundo."));
        }
        v.stage = VaultStage::Swapping;
        v.reserve_path = Some(reserve.to_string_lossy().into_owned());
        self.save(&v)?;
        if let Err(e) = fs::rename(&original, &reserve) {
            v.stage = VaultStage::Ready;
            v.reserve_path = None;
            self.save(&v)?;
            return Err(one(format!(
                "Não foi possível mover a pasta original ({e}). Feche os programas que estão usando arquivos dela (editor, terminal, Explorer) e tente de novo."
            )));
        }
        match self.finish_swap(&volume, &original, &reserve) {
            Ok(()) => {
                v.stage = VaultStage::Active;
                v.error = None;
                self.save(&v)?;
                self.log(
                    EventType::VaultChanged,
                    Severity::Info,
                    &v,
                    format!("Cofre \"{}\" ativo em {}. Original preservado em {}.", v.name, v.original_path, reserve.display()),
                );
                Ok(v)
            }
            Err(msg) => {
                let undo = self.undo_swap(&original, &reserve);
                v.stage = VaultStage::Ready;
                v.reserve_path = None;
                if let Err(u) = &undo {
                    // Situação grave: registra onde está o original.
                    v.stage = VaultStage::Swapping;
                    v.reserve_path = Some(reserve.to_string_lossy().into_owned());
                    v.error = Some(format!("{msg} Ao desfazer: {u}. O conteúdo original está em {}.", reserve.display()));
                }
                self.save(&v)?;
                self.log(EventType::VaultFailed, Severity::Error, &v, format!("Cofre \"{}\": troca desfeita. {msg}", v.name));
                Err(one(match undo {
                    Ok(()) => format!("{msg} A pasta original voltou ao lugar."),
                    Err(u) => format!("{msg} Não foi possível desfazer ({u}); o conteúdo original está em {}.", reserve.display()),
                }))
            }
        }
    }

    fn finish_swap(&self, volume: &str, original: &Path, reserve: &Path) -> Result<(), String> {
        let root = self.platform.volume_root(volume);
        let sec = self.platform.security();
        // O original pode ter mudado entre a preparação e a troca: compara por SHA-256 e reaplica.
        let read = |p: &Path, what: &str| migrate::manifest(p, true).map_err(|e| format!("Ler {what}: {e}"));
        let (src, copy) = (read(reserve, "o original")?, read(&root, "o cofre")?);
        if !migrate::diff(&src, &copy).is_empty() {
            let (changed, gone) = migrate::to_resync(&src, &copy);
            migrate::resync(reserve, &root, &changed, &gone, sec).map_err(|e| format!("Atualizar a cópia: {e}"))?;
            let again = migrate::diff(&read(reserve, "o original")?, &read(&root, "o cofre")?);
            if !again.is_empty() {
                return Err(format!("A cópia não confere com o original ({} diferença(s)).", again.len()));
            }
        }
        fs::create_dir(original).map_err(|e| format!("Criar a pasta de montagem: {e}"))?;
        let _ = sec.copy(reserve, original);
        self.platform.mount(volume, original).map_err(|e| format!("Montar o cofre: {e:#}"))?;
        if !self.platform.is_mounted(volume, original) {
            return Err("O cofre não ficou montado no caminho.".into());
        }
        Ok(())
    }

    fn undo_swap(&self, original: &Path, reserve: &Path) -> Result<(), String> {
        let _ = self.platform.unmount(original);
        if original.exists() {
            fs::remove_dir(original).map_err(|e| format!("remover {}: {e}", original.display()))?;
        }
        fs::rename(reserve, original).map_err(|e| format!("renomear a reserva: {e}"))
    }

    /// Descarta um cofre que não chegou a ser ativado (pronto ou com falha). O original não é tocado.
    pub fn discard(&self, id: Uuid) -> Result<(), Fail> {
        let _x = self.exclusive.lock().unwrap_or_else(|e| e.into_inner());
        let v = self.vault(id).ok_or_else(|| one("Cofre não encontrado."))?;
        if !matches!(v.stage, VaultStage::Ready | VaultStage::Failed) {
            return Err(one("Só é possível descartar um cofre pronto ou com falha (ainda não ativado)."));
        }
        let store = Path::new(&v.store_path);
        self.platform.detach(store).map_err(|e| one(format!("Desanexar: {e:#}")))?;
        self.platform.delete_disk(store).map_err(|e| one(format!("Apagar o disco: {e:#}")))?;
        self.repo.delete_vault(id).map_err(|e| one(format!("{e:#}")))?;
        self.jobs.lock().unwrap_or_else(|e| e.into_inner()).remove(&id);
        self.log(EventType::VaultChanged, Severity::Info, &v, format!("Cofre \"{}\" descartado; a pasta original não foi alterada.", v.name));
        Ok(())
    }

    /// Apaga a pasta de reserva de um cofre ativo (depois de confirmação explícita na interface).
    pub fn delete_reserve(&self, id: Uuid) -> Result<VaultRecord, Fail> {
        let _x = self.exclusive.lock().unwrap_or_else(|e| e.into_inner());
        let mut v = self.vault(id).ok_or_else(|| one("Cofre não encontrado."))?;
        let reserve = v.reserve_path.clone().ok_or_else(|| one("Este cofre não tem reserva."))?;
        if v.stage != VaultStage::Active {
            return Err(one("A reserva só pode ser apagada com o cofre ativo."));
        }
        // Só apaga a reserva que o próprio ByteHalt criou, ao lado do original.
        let (r, o) = (Path::new(&reserve), Path::new(&v.original_path));
        let named = r.file_name().and_then(|n| n.to_str()).is_some_and(|n| n.to_ascii_lowercase().contains(RESERVE_MARK));
        if !named || r.parent() != o.parent() || !reserve.to_ascii_lowercase().starts_with(&v.original_path.to_ascii_lowercase()) {
            return Err(one("Reserva fora do padrão; não foi apagada."));
        }
        if !self.platform.is_mounted(v.volume.as_deref().unwrap_or_default(), o) {
            return Err(one("O cofre não está montado no caminho original; a reserva foi mantida."));
        }
        if r.exists() {
            fs::remove_dir_all(r).map_err(|e| one(format!("Não foi possível apagar a reserva: {e}")))?;
        }
        v.reserve_path = None;
        self.save(&v)?;
        self.log(EventType::VaultChanged, Severity::Info, &v, format!("Cofre \"{}\": reserva apagada.", v.name));
        Ok(v)
    }

    /// Devolve a pasta ao normal: copia o conteúdo do cofre (desbloqueado) para uma pasta ao lado,
    /// confere por SHA-256, desmonta o cofre, põe a cópia no caminho original e só então apaga o
    /// disco do cofre. A reserva antiga, se existir, não é tocada. Devolve o recurso de bloqueio que
    /// deixou de existir.
    pub fn remove(&self, id: Uuid) -> Result<Option<Uuid>, Fail> {
        let _x = self.exclusive.lock().unwrap_or_else(|e| e.into_inner());
        let mut v = self.vault(id).ok_or_else(|| one("Cofre não encontrado."))?;
        if v.stage != VaultStage::Active {
            return Err(one("Só um cofre ativo pode ser removido."));
        }
        let volume = v.volume.clone().ok_or_else(|| one("Cofre sem volume."))?;
        let original = PathBuf::from(&v.original_path);
        if !self.platform.is_mounted(&volume, &original) {
            return Err(one("O cofre não está montado no caminho original."));
        }
        if fs::read_dir(&original).is_err() {
            return Err(one("Desbloqueie o cofre antes de removê-lo."));
        }
        match self.platform.holders(&original) {
            Ok(h) if !h.is_empty() => return Err(one(format!("Feche os programas que estão usando arquivos da pasta: {}.", h.join(", ")))),
            Ok(_) => {}
            Err(e) => return Err(one(format!("Não foi possível verificar arquivos abertos: {e:#}"))),
        }
        let restore = PathBuf::from(format!("{}{RESTORE_MARK}{}", v.original_path, self.stamp()));
        if restore.exists() {
            return Err(one("Já existe uma pasta de restauração com esse nome; tente de novo em um segundo."));
        }
        let free = self.platform.free_bytes(&original).unwrap_or(0);
        if free < required_free(v.bytes) {
            return Err(one(format!("Espaço livre insuficiente para copiar o conteúdo de volta ({} MiB livres).", free >> 20)));
        }
        v.stage = VaultStage::Removing;
        v.restore_path = Some(restore.to_string_lossy().into_owned());
        self.save(&v)?;
        let back_to_active = |me: &Self, mut v: VaultRecord, msg: String| -> Fail {
            if restore.exists() && fs::read_dir(&original).is_ok() {
                let _ = fs::remove_dir_all(&restore);
            }
            v.stage = VaultStage::Active;
            v.restore_path = None;
            let _ = me.save(&v);
            me.log(EventType::VaultFailed, Severity::Error, &v, format!("Cofre \"{}\": remoção desfeita. {msg}", v.name));
            one(format!("{msg} O cofre continua ativo."))
        };
        if let Err(e) = fs::create_dir(&restore) {
            return Err(back_to_active(self, v, format!("Criar a pasta de restauração: {e}")));
        }
        let sec = self.platform.security();
        if let Err(e) = migrate::copy_tree(&original, &restore, sec, &|_| {}) {
            return Err(back_to_active(self, v, format!("Copiar de volta: {e}")));
        }
        let check = migrate::manifest(&original, true).and_then(|a| migrate::manifest(&restore, true).map(|b| migrate::diff(&a, &b)));
        match check {
            Ok(d) if d.is_empty() => {}
            Ok(d) => return Err(back_to_active(self, v, format!("A cópia de volta não confere ({} diferença(s)).", d.len()))),
            Err(e) => return Err(back_to_active(self, v, format!("Conferir a cópia de volta: {e}"))),
        }
        if let Err(e) = self.platform.unmount(&original) {
            return Err(back_to_active(self, v, format!("Desmontar o cofre: {e:#}")));
        }
        let swap = fs::remove_dir(&original).and_then(|()| fs::rename(&restore, &original));
        if let Err(e) = swap {
            // Volta a montar o cofre: o conteúdo continua lá e a cópia fica em `restore`.
            let _ = fs::create_dir(&original);
            let remount = self.platform.mount(&volume, &original);
            v.stage = VaultStage::Active;
            v.error = Some(format!("Remoção interrompida ({e}). A cópia do conteúdo está em {}.", restore.display()));
            if remount.is_err() {
                v.stage = VaultStage::Removing;
            }
            let _ = self.save(&v);
            return Err(one(format!("Não foi possível pôr a cópia no lugar: {e}. A cópia está em {}.", restore.display())));
        }
        self.finish_remove(&v);
        Ok(v.resource_id)
    }

    fn finish_remove(&self, v: &VaultRecord) {
        let store = Path::new(&v.store_path);
        let _ = self.platform.detach(store);
        if let Err(e) = self.platform.delete_disk(store) {
            self.log(
                EventType::VaultFailed,
                Severity::Warning,
                v,
                format!("Cofre \"{}\": disco não apagado ({e:#}); apague {} manualmente.", v.name, v.store_path),
            );
        }
        let _ = self.repo.delete_vault(v.id);
        self.jobs.lock().unwrap_or_else(|e| e.into_inner()).remove(&v.id);
        let reserve = v.reserve_path.as_ref().map(|r| format!(" A reserva antiga continua em {r}.")).unwrap_or_default();
        self.log(
            EventType::VaultChanged,
            Severity::Info,
            v,
            format!("Cofre \"{}\" removido: {} voltou a ser uma pasta comum.{reserve}", v.name, v.original_path),
        );
    }

    pub fn set_resource(&self, id: Uuid, resource: Uuid) -> Result<(), Fail> {
        let mut v = self.vault(id).ok_or_else(|| one("Cofre não encontrado."))?;
        v.resource_id = Some(resource);
        self.save(&v)
    }

    /// Na partida do serviço: anexa os cofres e conclui ou desfaz operações interrompidas.
    pub fn recover(&self) {
        let _x = self.exclusive.lock().unwrap_or_else(|e| e.into_inner());
        for mut v in self.repo.vaults().unwrap_or_default() {
            let store = PathBuf::from(&v.store_path);
            match v.stage {
                VaultStage::Preparing => {
                    let _ = self.platform.detach(&store);
                    let _ = self.platform.delete_disk(&store);
                    v.stage = VaultStage::Failed;
                    v.volume = None;
                    v.error = Some("Preparação interrompida (serviço reiniciado); a pasta original não foi alterada.".into());
                    let _ = self.save(&v);
                    self.log(EventType::VaultFailed, Severity::Warning, &v, format!("Cofre \"{}\": preparação interrompida e descartada.", v.name));
                }
                VaultStage::Ready | VaultStage::Active => {
                    if let Err(e) = self.platform.attach(&store) {
                        self.log(EventType::VaultFailed, Severity::Error, &v, format!("Cofre \"{}\": não foi possível anexar o disco: {e:#}", v.name));
                    }
                }
                VaultStage::Swapping => {
                    let _ = self.platform.attach(&store);
                    let original = PathBuf::from(&v.original_path);
                    let mounted = v.volume.as_deref().is_some_and(|vol| self.platform.is_mounted(vol, &original));
                    let result = if mounted {
                        v.stage = VaultStage::Active;
                        Ok("troca concluída")
                    } else if let Some(reserve) = v.reserve_path.clone().map(PathBuf::from).filter(|r| r.exists()) {
                        self.undo_swap(&original, &reserve).map(|()| {
                            v.stage = VaultStage::Ready;
                            v.reserve_path = None;
                            "troca desfeita; a pasta original voltou ao lugar"
                        })
                    } else {
                        v.stage = VaultStage::Ready;
                        v.reserve_path = None;
                        Ok("troca não tinha começado")
                    };
                    match result {
                        Ok(what) => {
                            v.error = None;
                            let _ = self.save(&v);
                            self.log(EventType::VaultChanged, Severity::Warning, &v, format!("Cofre \"{}\": troca interrompida — {what}.", v.name));
                        }
                        Err(e) => {
                            v.error = Some(format!("Troca interrompida e não desfeita ({e}). O conteúdo original está na reserva."));
                            let _ = self.save(&v);
                            self.log(EventType::VaultFailed, Severity::Error, &v, format!("Cofre \"{}\": {e}", v.name));
                        }
                    }
                }
                VaultStage::Removing => {
                    let _ = self.platform.attach(&store);
                    let original = PathBuf::from(&v.original_path);
                    let restore = v.restore_path.clone().map(PathBuf::from);
                    let mounted = v.volume.as_deref().is_some_and(|vol| self.platform.is_mounted(vol, &original));
                    if mounted {
                        // A cópia de volta não chegou ao lugar: o cofre continua valendo.
                        if let Some(r) = restore.filter(|r| r.exists()) {
                            let _ = fs::remove_dir_all(r);
                        }
                        v.stage = VaultStage::Active;
                        v.restore_path = None;
                        let _ = self.save(&v);
                        self.log(
                            EventType::VaultChanged,
                            Severity::Warning,
                            &v,
                            format!("Cofre \"{}\": remoção interrompida; o cofre continua ativo.", v.name),
                        );
                    } else if original.is_dir() && restore.as_ref().is_none_or(|r| !r.exists()) {
                        // A cópia já está no caminho original: conclui a remoção.
                        self.finish_remove(&v);
                    } else {
                        v.error = Some(format!(
                            "Remoção interrompida em estado inesperado. Conteúdo: cofre {} e cópia {}.",
                            v.store_path,
                            v.restore_path.as_deref().unwrap_or("-")
                        ));
                        let _ = self.save(&v);
                        self.log(EventType::VaultFailed, Severity::Error, &v, format!("Cofre \"{}\": {}", v.name, v.error.clone().unwrap_or_default()));
                    }
                }
                VaultStage::Failed => {}
            }
        }
    }

    /// Recursos de bloqueio de cofres que já não existem (removidos ou concluídos na recuperação).
    pub fn orphan_resources(&self, resources: &[crate::model::ProtectedResource]) -> Vec<Uuid> {
        let vaults = self.repo.vaults().unwrap_or_default();
        resources
            .iter()
            .filter(|r| r.kind == crate::model::ResourceKind::Vault)
            .filter(|r| !vaults.iter().any(|v| v.id.to_string() == r.target))
            .map(|r| r.id)
            .collect()
    }
}

/// Data civil (proléptica gregoriana) a partir de dias desde 1970-01-01 (algoritmo de H. Hinnant).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (yoe + era * 400 + i64::from(m <= 2), m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_civil() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(20_761), (2026, 11, 4));
        assert_eq!(civil_from_days(11_016), (2000, 2, 29));
    }
}
