//! Achado de auditoria #9: a desinstalação não pode seguir links ou junções da pasta de instalação.
//! Só no Windows Sandbox (o binário do instalador exige elevação). Tudo em pastas temporárias.

use super::*;

fn junction(link: &Path, target: &Path) {
    let ok = std::process::Command::new("cmd").args(["/c", "mklink", "/J"]).arg(link).arg(target).stdout(std::process::Stdio::null()).status().unwrap();
    assert!(ok.success(), "mklink /J");
}

/// Instalação com uma junção `ext` para uma pasta de fora que contém arquivo e subpasta.
fn layout(t: &Path) -> (PathBuf, PathBuf) {
    let (install, outside) = (t.join("ByteHalt"), t.join("fora"));
    std::fs::create_dir_all(install.join("licencas")).unwrap();
    std::fs::write(install.join("bytehalt.exe"), b"exe").unwrap();
    std::fs::write(install.join("licencas").join("a.txt"), b"a").unwrap();
    std::fs::create_dir_all(outside.join("sub")).unwrap();
    std::fs::write(outside.join("segredo.txt"), b"de fora").unwrap();
    std::fs::write(outside.join("sub").join("b.txt"), b"b").unwrap();
    junction(&install.join("ext"), &outside);
    (install, outside)
}

#[test]
fn percurso_da_desinstalacao_nao_entra_em_juncao() {
    let t = tempfile::tempdir().unwrap();
    let (install, _) = layout(t.path());
    let link = install.join("ext");
    let files = walk(&install);
    assert!(!files.iter().any(|p| p.starts_with(&link) && p != &link), "arquivos de fora entraram na lista: {files:?}");
    assert!(files.contains(&install.join("bytehalt.exe")) && files.contains(&install.join("licencas").join("a.txt")), "{files:?}");
    let dirs = dirs_deepest_first(&install);
    assert!(!dirs.iter().any(|p| p.starts_with(&link)), "pastas de fora entraram na lista: {dirs:?}");
}

// --- Daqui para baixo só existe na versão corrigida (função extraída). ---

#[test]
fn remocao_apaga_a_instalacao_e_preserva_o_destino_da_juncao() {
    let t = tempfile::tempdir().unwrap();
    let (install, outside) = layout(t.path());
    let later = remove_install_tree(&install, &t.path().join("nao-sou-eu.exe"));
    assert_eq!(later, 0);
    assert!(!install.exists(), "a pasta de instalação ficou");
    assert_eq!(std::fs::read(outside.join("segredo.txt")).unwrap(), b"de fora");
    assert_eq!(std::fs::read(outside.join("sub").join("b.txt")).unwrap(), b"b");
}

#[test]
fn pasta_de_instalacao_que_e_juncao_perde_so_o_link() {
    let t = tempfile::tempdir().unwrap();
    let outside = t.path().join("fora");
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::write(outside.join("segredo.txt"), b"de fora").unwrap();
    let install = t.path().join("ByteHalt");
    junction(&install, &outside);
    assert_eq!(remove_install_tree(&install, &t.path().join("nao-sou-eu.exe")), 0);
    assert!(std::fs::symlink_metadata(&install).is_err(), "o link continuou");
    assert_eq!(std::fs::read(outside.join("segredo.txt")).unwrap(), b"de fora");
}

// --- Achado de auditoria #10: cofres conferidos de novo depois de parar o serviço. ---

fn vault(name: &str) -> bytehalt_core::vault::VaultRecord {
    bytehalt_core::vault::VaultRecord {
        id: uuid::Uuid::new_v4(),
        name: name.into(),
        original_path: r"D:\Projetos\x".into(),
        reserve_path: None,
        store_path: r"D:\ByteHalt.Cofres\a.vhdx".into(),
        volume: None,
        max_bytes: 0,
        stage: bytehalt_core::vault::VaultStage::Preparing,
        files: 0,
        bytes: 0,
        created_at: 0,
        resource_id: None,
        error: None,
        restore_path: None,
    }
}

fn db(data: &Path) -> bytehalt_windows::sqlite::SqliteStore {
    bytehalt_windows::sqlite::SqliteStore::open(&data.join("bytehalt.db")).unwrap()
}

#[test]
fn cofre_criado_antes_da_parada_do_servico_recusa_e_religa_o_servico() {
    use bytehalt_core::vault::VaultRepository;
    let t = tempfile::tempdir().unwrap();
    drop(db(t.path()));
    assert!(vault_refusal(t.path()).unwrap().is_none(), "primeira consulta: sem cofres");
    let started = std::cell::Cell::new(false);
    // Uma preparação autorizada grava o cofre entre a primeira consulta e a parada do serviço.
    let r = stop_and_recheck(
        t.path(),
        || {
            db(t.path()).upsert_vault(&vault("Tardio")).unwrap();
            Ok(())
        },
        || {
            started.set(true);
            Ok(())
        },
    )
    .unwrap();
    assert!(r.is_some_and(|m| m.contains("Tardio")), "desinstalação seguiria com um cofre criado na janela");
    assert!(started.get(), "o serviço precisa voltar a rodar quando a desinstalação é recusada");
}

#[test]
fn sem_cofres_depois_da_parada_o_servico_fica_parado() {
    let t = tempfile::tempdir().unwrap();
    drop(db(t.path()));
    let started = std::cell::Cell::new(false);
    let r = stop_and_recheck(
        t.path(),
        || Ok(()),
        || {
            started.set(true);
            Ok(())
        },
    )
    .unwrap();
    assert!(r.is_none());
    assert!(!started.get());
}

#[test]
fn cofres_ilegiveis_depois_da_parada_recusam_e_religam_o_servico() {
    let t = tempfile::tempdir().unwrap();
    drop(db(t.path()));
    rusqlite::Connection::open(t.path().join("bytehalt.db"))
        .unwrap()
        .execute("INSERT INTO vaults (id, data) VALUES (?1, '{corrompido')", [uuid::Uuid::new_v4().to_string()])
        .unwrap();
    let started = std::cell::Cell::new(false);
    let r = stop_and_recheck(
        t.path(),
        || Ok(()),
        || {
            started.set(true);
            Ok(())
        },
    );
    assert!(r.is_err(), "leitura ilegível não pode liberar a desinstalação");
    assert!(started.get());
}
