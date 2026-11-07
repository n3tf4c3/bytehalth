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
