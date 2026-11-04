//! Fluxo dos cofres com uma plataforma falsa: o "disco" é uma pasta e a montagem é uma junção.
//! Tudo acontece em pastas temporárias criadas pelo próprio teste (rodam no Windows Sandbox).
#![cfg(windows)]

use bytehalt_core::clock::TestClock;
use bytehalt_core::journal::InMemoryJournal;
use bytehalt_core::migrate;
use bytehalt_core::vault::*;
use bytehalt_core::vault_manager::VaultManager;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const PASS: &str = "senha-de-teste-123";

#[derive(Default)]
struct Fake {
    store: PathBuf,
    fail_format: AtomicBool,
    fail_mount: AtomicBool,
    holders: Mutex<Vec<String>>,
    attached: Mutex<Vec<PathBuf>>,
}

fn vol_dir(store: &Path) -> PathBuf {
    store.with_extension("vol")
}

impl VaultPlatform for Fake {
    fn store_dir(&self, _: &Path) -> anyhow::Result<PathBuf> {
        Ok(self.store.clone())
    }
    fn create_disk(&self, store: &Path, _: u64) -> anyhow::Result<()> {
        fs::write(store, b"vhdx")?;
        Ok(())
    }
    fn attach(&self, store: &Path) -> anyhow::Result<()> {
        anyhow::ensure!(store.exists(), "disco inexistente");
        let mut a = self.attached.lock().unwrap();
        if !a.contains(&store.to_path_buf()) {
            a.push(store.to_path_buf());
        }
        Ok(())
    }
    fn detach(&self, store: &Path) -> anyhow::Result<()> {
        self.attached.lock().unwrap().retain(|s| s != store);
        Ok(())
    }
    fn delete_disk(&self, store: &Path) -> anyhow::Result<()> {
        let _ = fs::remove_file(store);
        let _ = fs::remove_dir_all(vol_dir(store));
        Ok(())
    }
    fn format(&self, store: &Path, _: &str) -> anyhow::Result<String> {
        anyhow::ensure!(!self.fail_format.load(Ordering::SeqCst), "formatação falhou (simulado)");
        fs::create_dir_all(vol_dir(store))?;
        Ok(vol_dir(store).to_string_lossy().into_owned())
    }
    fn encrypt(&self, _: &str, passphrase: &str) -> anyhow::Result<String> {
        assert_eq!(passphrase, PASS);
        Ok("111111-222222-333333-444444-555555-666666-777777-888888".into())
    }
    fn volume_root(&self, volume: &str) -> PathBuf {
        PathBuf::from(volume)
    }
    fn mount(&self, volume: &str, dir: &Path) -> anyhow::Result<()> {
        anyhow::ensure!(!self.fail_mount.load(Ordering::SeqCst), "montagem falhou (simulado)");
        anyhow::ensure!(fs::read_dir(dir)?.next().is_none(), "pasta de montagem não está vazia");
        fs::remove_dir(dir)?;
        let ok = std::process::Command::new("cmd").args(["/c", "mklink", "/J"]).arg(dir).arg(volume).stdout(std::process::Stdio::null()).status()?;
        anyhow::ensure!(ok.success(), "mklink falhou");
        Ok(())
    }
    fn unmount(&self, dir: &Path) -> anyhow::Result<()> {
        if fs::symlink_metadata(dir).is_ok_and(|m| m.file_type().is_symlink()) {
            fs::remove_dir(dir)?;
            fs::create_dir(dir)?;
        }
        Ok(())
    }
    fn is_mounted(&self, volume: &str, dir: &Path) -> bool {
        fs::symlink_metadata(dir).is_ok_and(|m| m.file_type().is_symlink()) && fs::canonicalize(dir).ok() == fs::canonicalize(volume).ok()
    }
    fn free_bytes(&self, _: &Path) -> anyhow::Result<u64> {
        Ok(100 << 30)
    }
    fn holders(&self, _: &Path) -> anyhow::Result<Vec<String>> {
        Ok(self.holders.lock().unwrap().clone())
    }
    fn security(&self) -> &dyn SecurityCopier {
        &NoSecurity
    }
}

struct World {
    _tmp: tempfile::TempDir,
    data: PathBuf,
    fake: Arc<Fake>,
    repo: Arc<InMemoryVaults>,
    journal: Arc<InMemoryJournal>,
    m: Arc<VaultManager>,
}

fn world() -> World {
    let tmp = tempfile::tempdir().unwrap();
    let data = tmp.path().join("Projetos").join("cliente");
    fs::create_dir_all(data.join("src")).unwrap();
    fs::write(data.join("README.md"), b"# cliente").unwrap();
    fs::write(data.join("src").join("main.rs"), b"fn main() {}").unwrap();
    fs::write(data.join("dados.bin"), vec![42u8; 200_000]).unwrap();
    let store = tmp.path().join("ByteHalt.Cofres");
    let fake = Arc::new(Fake { store, ..Default::default() });
    let repo = Arc::new(InMemoryVaults::default());
    let journal = Arc::new(InMemoryJournal::default());
    let m = Arc::new(VaultManager::new(fake.clone(), repo.clone(), journal.clone(), Arc::new(TestClock::new()), PathRules::default()));
    World { _tmp: tmp, data, fake, repo, journal, m }
}

fn path(p: &Path) -> String {
    p.to_string_lossy().into_owned()
}

fn wait_ready(w: &World, id: uuid::Uuid) -> VaultRecord {
    let t = Instant::now();
    loop {
        let v = w.m.vault(id).unwrap();
        if v.stage != VaultStage::Preparing {
            return v;
        }
        assert!(t.elapsed() < Duration::from_secs(20), "preparação não terminou");
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn prepare(w: &World) -> VaultRecord {
    let v = w.m.prepare("Cliente", &path(&w.data), PASS.into(), 2 << 30).unwrap();
    assert_eq!(v.stage, VaultStage::Preparing);
    wait_ready(w, v.id)
}

fn same_content(a: &Path, b: &Path) -> Vec<String> {
    migrate::diff(&migrate::manifest(a, true).unwrap(), &migrate::manifest(b, true).unwrap())
}

#[test]
fn preparacao_copia_verifica_e_entrega_a_chave_uma_vez() {
    let w = world();
    let before = migrate::manifest(&w.data, true).unwrap();
    let v = prepare(&w);
    assert_eq!(v.stage, VaultStage::Ready, "{:?}", v.error);
    assert_eq!((v.files, v.bytes), (3, 200_000 + 9 + 12));
    let root = PathBuf::from(v.volume.clone().unwrap());
    assert!(same_content(&w.data, &root).is_empty());
    // O original não foi tocado.
    assert!(migrate::diff(&before, &migrate::manifest(&w.data, true).unwrap()).is_empty());
    let first = w.m.list();
    assert!(first[0].job.as_ref().unwrap().recovery_key.as_deref().is_some_and(|k| k.starts_with("111111")));
    assert!(w.m.list()[0].job.as_ref().unwrap().recovery_key.is_none(), "a chave só pode sair uma vez");
}

#[test]
fn troca_monta_o_cofre_no_caminho_e_preserva_a_reserva() {
    let w = world();
    let v = prepare(&w);
    let v = w.m.swap(v.id).unwrap();
    assert_eq!(v.stage, VaultStage::Active);
    let reserve = PathBuf::from(v.reserve_path.clone().unwrap());
    assert!(reserve.to_string_lossy().contains(RESERVE_MARK));
    assert!(w.fake.is_mounted(v.volume.as_deref().unwrap(), &w.data));
    assert_eq!(fs::read(w.data.join("README.md")).unwrap(), b"# cliente", "o caminho original mostra o cofre");
    assert!(same_content(&reserve, &w.data).is_empty());
}

#[test]
fn alteracoes_depois_da_preparacao_entram_no_cofre_na_troca() {
    let w = world();
    let v = prepare(&w);
    fs::write(w.data.join("README.md"), b"# cliente (editado depois)").unwrap();
    fs::write(w.data.join("novo.txt"), b"novo").unwrap();
    fs::remove_file(w.data.join("dados.bin")).unwrap();
    let v = w.m.swap(v.id).unwrap();
    assert_eq!(fs::read(w.data.join("README.md")).unwrap(), b"# cliente (editado depois)");
    assert!(w.data.join("novo.txt").exists() && !w.data.join("dados.bin").exists());
    assert!(same_content(Path::new(v.reserve_path.as_deref().unwrap()), &w.data).is_empty());
}

#[test]
fn arquivo_aberto_impede_a_troca_sem_mexer_em_nada() {
    let w = world();
    let v = prepare(&w);
    *w.fake.holders.lock().unwrap() = vec!["code.exe".into()];
    let err = w.m.swap(v.id).unwrap_err().join(" ");
    assert!(err.contains("code.exe"), "{err}");
    assert_eq!(w.m.vault(v.id).unwrap().stage, VaultStage::Ready);
    assert!(!fs::symlink_metadata(&w.data).unwrap().file_type().is_symlink());
    // Arquivo aberto sem compartilhamento de exclusão: o próprio Windows recusa a renomeação.
    w.fake.holders.lock().unwrap().clear();
    use std::os::windows::fs::OpenOptionsExt;
    let open = fs::OpenOptions::new().read(true).share_mode(1 | 2).open(w.data.join("README.md")).unwrap();
    let err = w.m.swap(v.id).unwrap_err().join(" ");
    assert!(err.contains("Feche os programas"), "{err}");
    drop(open);
    assert_eq!(w.m.vault(v.id).unwrap().stage, VaultStage::Ready);
    assert!(w.data.join("README.md").exists());
    assert!(w.m.swap(v.id).is_ok());
}

#[test]
fn falha_ao_montar_desfaz_a_troca() {
    let w = world();
    let v = prepare(&w);
    w.fake.fail_mount.store(true, Ordering::SeqCst);
    let err = w.m.swap(v.id).unwrap_err().join(" ");
    assert!(err.contains("voltou ao lugar"), "{err}");
    let v = w.m.vault(v.id).unwrap();
    assert_eq!((v.stage, v.reserve_path.clone()), (VaultStage::Ready, None));
    assert_eq!(fs::read(w.data.join("README.md")).unwrap(), b"# cliente");
    let parent = w.data.parent().unwrap();
    assert_eq!(fs::read_dir(parent).unwrap().count(), 1, "nenhuma reserva sobrou");
}

#[test]
fn falha_na_preparacao_descarta_o_disco_e_nao_toca_no_original() {
    let w = world();
    w.fake.fail_format.store(true, Ordering::SeqCst);
    let v = w.m.prepare("Cliente", &path(&w.data), PASS.into(), 2 << 30).unwrap();
    let v = wait_ready(&w, v.id);
    assert_eq!(v.stage, VaultStage::Failed);
    assert!(v.error.unwrap().contains("Formatar"));
    assert!(!Path::new(&v.store_path).exists());
    assert_eq!(fs::read(w.data.join("README.md")).unwrap(), b"# cliente");
    w.m.discard(v.id).unwrap();
    assert!(w.m.list().is_empty());
}

#[test]
fn descartar_cofre_pronto_apaga_o_disco() {
    let w = world();
    let v = prepare(&w);
    w.m.discard(v.id).unwrap();
    assert!(!Path::new(&v.store_path).exists() && !vol_dir(Path::new(&v.store_path)).exists());
    assert!(w.repo.vaults().unwrap().is_empty());
    assert!(w.data.join("README.md").exists());
}

#[test]
fn reserva_so_e_apagada_com_o_cofre_ativo_e_montado() {
    let w = world();
    let v = prepare(&w);
    assert!(w.m.delete_reserve(v.id).is_err());
    let v = w.m.swap(v.id).unwrap();
    let reserve = PathBuf::from(v.reserve_path.clone().unwrap());
    let v = w.m.delete_reserve(v.id).unwrap();
    assert!(v.reserve_path.is_none() && !reserve.exists());
    assert_eq!(fs::read(w.data.join("README.md")).unwrap(), b"# cliente", "o cofre continua no caminho");
    assert!(w.m.discard(v.id).is_err(), "cofre ativo não pode ser descartado");
}

#[test]
fn recuperacao_desfaz_troca_interrompida_e_descarta_preparacao_interrompida() {
    let w = world();
    let v = prepare(&w);
    // Queda depois de renomear o original e antes de montar.
    let reserve = PathBuf::from(reserve_name(&path(&w.data), "20261104-010203"));
    fs::rename(&w.data, &reserve).unwrap();
    fs::create_dir(&w.data).unwrap();
    let mut swapping = v.clone();
    swapping.stage = VaultStage::Swapping;
    swapping.reserve_path = Some(path(&reserve));
    w.repo.upsert_vault(&swapping).unwrap();
    // E uma preparação que caiu no meio.
    let mut prep = v.clone();
    prep.id = uuid::Uuid::new_v4();
    prep.original_path = path(&w.data.with_file_name("outro"));
    prep.store_path = path(&w.fake.store.join("outro.vhdx"));
    prep.stage = VaultStage::Preparing;
    fs::write(&prep.store_path, b"vhdx").unwrap();
    w.repo.upsert_vault(&prep).unwrap();

    w.m.recover();
    let v = w.m.vault(v.id).unwrap();
    assert_eq!((v.stage, v.reserve_path.clone()), (VaultStage::Ready, None));
    assert_eq!(fs::read(w.data.join("README.md")).unwrap(), b"# cliente");
    assert!(!reserve.exists());
    let p = w.m.vault(prep.id).unwrap();
    assert_eq!(p.stage, VaultStage::Failed);
    assert!(!Path::new(&prep.store_path).exists());
    assert!(w.journal.entries().iter().any(|e| e.message.contains("troca desfeita")));
}

#[test]
fn preparacao_recusa_caminho_proibido_senha_curta_e_sobreposicao() {
    let w = world();
    let err = w.m.prepare("X", &path(&w.data), "curta".into(), 2 << 30).unwrap_err().join(" ");
    assert!(err.contains("pelo menos 8"), "{err}");
    let err = w.m.prepare("X", "relativo\\pasta", PASS.into(), 2 << 30).unwrap_err().join(" ");
    assert!(err.contains("pasta local completa"), "{err}");
    let err = w.m.prepare("X", &path(&w.data), PASS.into(), 1 << 20).unwrap_err().join(" ");
    assert!(err.contains("Tamanho máximo"), "{err}");
    let v = prepare(&w);
    w.m.swap(v.id).unwrap();
    let err = w.m.prepare("Y", &path(&w.data.join("src")), PASS.into(), 2 << 30).unwrap_err().join(" ");
    assert!(err.contains("Sobrepõe"), "{err}");
    let plan = w.m.analyze(&path(w.data.parent().unwrap()));
    assert!(!plan.ok());
}

#[test]
fn remover_devolve_a_pasta_com_as_alteracoes_feitas_no_cofre() {
    let w = world();
    let v = prepare(&w);
    let v = w.m.swap(v.id).unwrap();
    w.m.set_resource(v.id, uuid::Uuid::from_u128(7)).unwrap();
    // Trabalho feito dentro do cofre, pelo caminho original.
    fs::write(w.data.join("README.md"), b"# cliente (no cofre)").unwrap();
    fs::write(w.data.join("src").join("novo.rs"), b"// novo").unwrap();
    let reserve = PathBuf::from(v.reserve_path.clone().unwrap());

    *w.fake.holders.lock().unwrap() = vec!["code.exe".into()];
    assert!(w.m.remove(v.id).unwrap_err().join(" ").contains("code.exe"));
    w.fake.holders.lock().unwrap().clear();

    let rid = w.m.remove(v.id).unwrap();
    assert_eq!(rid, Some(uuid::Uuid::from_u128(7)));
    assert!(!fs::symlink_metadata(&w.data).unwrap().file_type().is_symlink(), "voltou a ser pasta comum");
    assert_eq!(fs::read(w.data.join("README.md")).unwrap(), b"# cliente (no cofre)");
    assert!(w.data.join("src").join("novo.rs").exists());
    assert!(!Path::new(&v.store_path).exists() && !vol_dir(Path::new(&v.store_path)).exists(), "disco do cofre apagado");
    assert!(w.repo.vaults().unwrap().is_empty());
    assert_eq!(fs::read(reserve.join("README.md")).unwrap(), b"# cliente", "a reserva antiga não é tocada");
    let restos: Vec<_> = fs::read_dir(w.data.parent().unwrap()).unwrap().flatten().filter(|e| e.file_name().to_string_lossy().contains(RESTORE_MARK)).collect();
    assert!(restos.is_empty(), "nenhuma pasta de restauração sobrou");
}

#[test]
fn recuperacao_de_remocao_interrompida() {
    // Caso 1: caiu durante a cópia de volta — o cofre continua montado e a cópia parcial some.
    let w = world();
    let v = prepare(&w);
    let mut v = w.m.swap(v.id).unwrap();
    let restore = PathBuf::from(format!("{}{RESTORE_MARK}20261104-020304", v.original_path));
    fs::create_dir(&restore).unwrap();
    fs::write(restore.join("parcial.txt"), b"x").unwrap();
    v.stage = VaultStage::Removing;
    v.restore_path = Some(path(&restore));
    w.repo.upsert_vault(&v).unwrap();
    w.m.recover();
    assert_eq!(w.m.vault(v.id).unwrap().stage, VaultStage::Active);
    assert!(!restore.exists());
    assert_eq!(fs::read(w.data.join("README.md")).unwrap(), b"# cliente");

    // Caso 2: caiu depois de pôr a cópia no lugar — conclui apagando o disco e o registro.
    let mut v = w.m.vault(v.id).unwrap();
    w.fake.unmount(&w.data).unwrap();
    fs::remove_dir(&w.data).unwrap();
    migrate::copy_tree(
        Path::new(v.volume.as_deref().unwrap()),
        &{
            fs::create_dir(&w.data).unwrap();
            w.data.clone()
        },
        &NoSecurity,
        &|_| {},
    )
    .unwrap();
    v.stage = VaultStage::Removing;
    v.restore_path = Some(path(&restore));
    w.repo.upsert_vault(&v).unwrap();
    w.m.recover();
    assert!(w.m.vault(v.id).is_none());
    assert!(!Path::new(&v.store_path).exists());
    assert_eq!(fs::read(w.data.join("README.md")).unwrap(), b"# cliente");
    assert!(
        w.m.orphan_resources(&[bytehalt_core::model::ProtectedResource {
            id: uuid::Uuid::from_u128(9),
            display_name: "x".into(),
            kind: bytehalt_core::model::ResourceKind::Vault,
            target: v.id.to_string(),
        }]) == vec![uuid::Uuid::from_u128(9)]
    );
}
