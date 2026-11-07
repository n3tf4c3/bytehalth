//! Achado de auditoria #4: mudanças só de permissão (DACL) ou de fluxos alternativos (ADS) entre a
//! preparação e a troca precisam chegar ao cofre. Plataforma simulada (pastas e junção) com a cópia
//! de segurança REAL do Windows. Só no Windows Sandbox: troca DACL de arquivos temporários.

use bytehalt_core::clock::TestClock;
use bytehalt_core::journal::InMemoryJournal;
use bytehalt_core::vault::{PathRules, VaultRecord, VaultStage};
use bytehalt_core::vault_manager::VaultManager;
use bytehalt_windows::sim_vault::SimulatedVaultPlatform;
use bytehalt_windows::sqlite::SqliteStore;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

const INITIATOR: &str = "S-1-5-21-111-222-333-1001";

struct World {
    _tmp: tempfile::TempDir,
    data: PathBuf,
    m: Arc<VaultManager>,
}

fn world() -> World {
    let tmp = tempfile::tempdir().unwrap();
    let data = tmp.path().join("Projeto");
    fs::create_dir_all(data.join("sub")).unwrap();
    fs::write(data.join("a.txt"), b"conteudo").unwrap();
    fs::write(data.join("sub").join("b.txt"), b"b").unwrap();
    let service = tmp.path().join("servico");
    fs::create_dir_all(&service).unwrap();
    let db = Arc::new(SqliteStore::open(&service.join("bytehalt.db")).unwrap());
    let platform = Arc::new(SimulatedVaultPlatform::new(&service));
    let m = Arc::new(VaultManager::new(platform, db, Arc::new(InMemoryJournal::default()), Arc::new(TestClock::new()), PathRules::default()));
    World { _tmp: tmp, data, m }
}

fn ready(w: &World) -> VaultRecord {
    let v = w.m.prepare(INITIATOR, "Projeto", &w.data.to_string_lossy(), "senha-de-teste-123".into(), 1 << 30).unwrap();
    let t = Instant::now();
    loop {
        let v = w.m.vault(v.id).unwrap();
        if v.stage != VaultStage::Preparing {
            assert_eq!(v.stage, VaultStage::Ready, "{:?}", v.error);
            return v;
        }
        assert!(t.elapsed() < Duration::from_secs(30), "preparação não terminou");
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn swap(w: &World, v: &VaultRecord) -> VaultRecord {
    let v = w.m.swap(v.id).unwrap_or_else(|e| panic!("troca falhou: {e:?}"));
    assert_eq!(v.stage, VaultStage::Active);
    v
}

/// O cofre visto pelo caminho original (junção para o "volume").
fn vault_item(w: &World, rel: &str) -> PathBuf {
    w.data.join(rel)
}

fn reserve_item(v: &VaultRecord, rel: &str) -> PathBuf {
    Path::new(v.reserve_path.as_deref().unwrap()).join(rel)
}

fn stream(p: &Path, name: &str) -> PathBuf {
    let mut s = p.as_os_str().to_owned();
    s.push(":");
    s.push(name);
    PathBuf::from(s)
}

/// Parte da DACL do SDDL (sem dono e grupo).
fn dacl(p: &Path) -> String {
    let out =
        std::process::Command::new("powershell").args(["-NoProfile", "-Command", &format!("(Get-Acl -LiteralPath '{}').Sddl", p.display())]).output().unwrap();
    let s = String::from_utf8_lossy(&out.stdout).trim().to_owned();
    s.find("D:").map(|i| s[i..].to_owned()).unwrap_or(s)
}

fn icacls(p: &Path, args: &[&str]) {
    let ok = std::process::Command::new("icacls").arg(p).args(args).stdout(std::process::Stdio::null()).status().unwrap();
    assert!(ok.success(), "icacls {args:?}");
}

#[test]
fn permissao_revogada_depois_da_preparacao_chega_ao_cofre() {
    let w = world();
    let v = ready(&w);
    // Revoga tudo que vinha por herança; só Administradores e SYSTEM continuam (conteúdo intacto).
    icacls(&w.data.join("a.txt"), &["/inheritance:r", "/grant:r", "*S-1-5-32-544:F", "*S-1-5-18:F"]);
    let expected = dacl(&w.data.join("a.txt"));
    assert!(expected.starts_with("D:P"), "{expected}");
    let v = swap(&w, &v);
    let got = dacl(&vault_item(&w, "a.txt"));
    assert_eq!(got, expected, "o cofre manteve a permissão anterior à revogação");
    assert_eq!(dacl(&reserve_item(&v, "a.txt")), expected);
    assert_eq!(fs::read(vault_item(&w, "a.txt")).unwrap(), b"conteudo");
}

#[test]
fn permissao_de_pasta_alterada_depois_da_preparacao_chega_ao_cofre() {
    let w = world();
    let v = ready(&w);
    icacls(&w.data.join("sub"), &["/inheritance:r", "/grant:r", "*S-1-5-32-544:(OI)(CI)F", "*S-1-5-18:(OI)(CI)F"]);
    let expected = dacl(&w.data.join("sub"));
    swap(&w, &v);
    assert_eq!(dacl(&vault_item(&w, "sub")), expected, "o cofre manteve a permissão anterior da pasta");
}

#[test]
fn fluxo_alternativo_alterado_depois_da_preparacao_chega_ao_cofre() {
    let w = world();
    fs::write(stream(&w.data.join("a.txt"), "nota"), b"antes").unwrap();
    let v = ready(&w);
    fs::write(stream(&w.data.join("a.txt"), "nota"), b"depois").unwrap();
    swap(&w, &v);
    assert_eq!(fs::read(stream(&vault_item(&w, "a.txt"), "nota")).unwrap(), b"depois");
    assert_eq!(fs::read(vault_item(&w, "a.txt")).unwrap(), b"conteudo");
}

#[test]
fn fluxo_alternativo_removido_depois_da_preparacao_some_do_cofre() {
    let w = world();
    fs::write(stream(&w.data.join("a.txt"), "nota"), b"segredo").unwrap();
    let v = ready(&w);
    fs::remove_file(stream(&w.data.join("a.txt"), "nota")).unwrap();
    swap(&w, &v);
    assert!(fs::read(stream(&vault_item(&w, "a.txt"), "nota")).is_err(), "fluxo removido continuou no cofre");
}

#[test]
fn fluxos_alternativos_de_pastas_sao_copiados_e_atualizados() {
    let w = world();
    fs::write(stream(&w.data.join("sub"), "nota"), b"pasta-antes").unwrap();
    let v = ready(&w);
    fs::write(stream(&w.data.join("sub"), "nova"), b"pasta-nova").unwrap();
    swap(&w, &v);
    assert_eq!(fs::read(stream(&vault_item(&w, "sub"), "nota")).unwrap(), b"pasta-antes");
    assert_eq!(fs::read(stream(&vault_item(&w, "sub"), "nova")).unwrap(), b"pasta-nova");
}
