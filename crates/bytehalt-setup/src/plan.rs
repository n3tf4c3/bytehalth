//! Decisões puras do instalador (testáveis sem tocar no sistema).

use bytehalt_core::vault::{VaultRecord, VaultStage};
use std::path::Path;

pub const SERVICE: &str = "ByteHalt";
pub const RUN_VALUE: &str = "ByteHalt";
pub const UNINSTALL_KEY: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\ByteHalt";
pub const RUN_KEY: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
pub const PUBLISHER: &str = "ByteHalt";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Install,
    Uninstall,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Args {
    pub mode: Mode,
    pub quiet: bool,
    /// Desinstalar também apaga configurações, histórico e credenciais.
    pub purge: bool,
}

/// `/install` (padrão), `/uninstall`, `/quiet`, `/purge`. Aceita `-` no lugar de `/`.
pub fn parse(args: &[String]) -> Result<Args, String> {
    let mut a = Args { mode: Mode::Install, quiet: false, purge: false };
    for raw in args {
        match raw.trim_start_matches(['/', '-']).to_ascii_lowercase().as_str() {
            "install" => a.mode = Mode::Install,
            "uninstall" => a.mode = Mode::Uninstall,
            "quiet" | "q" | "silent" => a.quiet = true,
            "purge" => a.purge = true,
            other => return Err(format!("Opção desconhecida: {other}")),
        }
    }
    Ok(a)
}

/// Códigos de saída (modo silencioso e scripts).
pub mod exit {
    pub const OK: i32 = 0;
    pub const ERROR: i32 = 1;
    /// Desinstalação recusada: há cofres.
    pub const REFUSED: i32 = 2;
    pub const NOT_ADMIN: i32 = 3;
    pub const CANCELLED: i32 = 4;
    pub const EMPTY_PAYLOAD: i32 = 5;
}

pub fn run_command(dir: &Path) -> String {
    format!("\"{}\" --tray", dir.join("bytehalt.exe").display())
}

pub fn uninstall_command(dir: &Path, quiet: bool) -> String {
    format!("\"{}\" /uninstall{}", dir.join("bytehalt-setup.exe").display(), if quiet { " /quiet" } else { "" })
}

/// Valores da entrada em "Aplicativos instalados".
pub fn uninstall_entries(dir: &Path, version: &str, size_kb: u32) -> Vec<(&'static str, Value)> {
    vec![
        ("DisplayName", Value::Str("ByteHalt".into())),
        ("DisplayVersion", Value::Str(version.into())),
        ("Publisher", Value::Str(PUBLISHER.into())),
        ("InstallLocation", Value::Str(dir.display().to_string())),
        ("DisplayIcon", Value::Str(format!("{},0", dir.join("bytehalt.exe").display()))),
        ("UninstallString", Value::Str(uninstall_command(dir, false))),
        ("QuietUninstallString", Value::Str(uninstall_command(dir, true))),
        ("NoModify", Value::Dword(1)),
        ("NoRepair", Value::Dword(1)),
        ("EstimatedSize", Value::Dword(size_kb)),
    ]
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    Str(String),
    Dword(u32),
}

/// Sem o serviço, cofres ficam inacessíveis depois de reiniciar (ninguém anexa os discos). Por isso a
/// desinstalação é recusada enquanto houver qualquer cofre registrado.
pub fn refuse_reason(vaults: &[VaultRecord]) -> Option<String> {
    if vaults.is_empty() {
        return None;
    }
    let list: Vec<String> = vaults
        .iter()
        .map(|v| {
            let what = match v.stage {
                VaultStage::Active => "ativo",
                VaultStage::Ready => "pronto, não ativado",
                VaultStage::Preparing | VaultStage::Swapping | VaultStage::Removing => "em operação",
                VaultStage::Failed => "com falha",
            };
            format!("• {} ({what}) — {}", v.name, v.original_path)
        })
        .collect();
    Some(format!(
        "Há {} cofre(s) no ByteHalt:\n{}\n\nSem o serviço, o conteúdo dos cofres fica inacessível depois de reiniciar o Windows. \
         Abra o ByteHalt e use \"Remover cofre\" (ou \"Descartar\") em cada um antes de desinstalar.",
        vaults.len(),
        list.join("\n")
    ))
}

/// Pasta de dados que o `/purge` pode apagar: só exatamente `<ProgramData>\ByteHalt`.
pub fn purge_target(program_data: &Path) -> std::path::PathBuf {
    program_data.join("ByteHalt")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn argumentos() {
        let p = |v: &[&str]| parse(&v.iter().map(|s| s.to_string()).collect::<Vec<_>>());
        assert_eq!(p(&[]).unwrap(), Args { mode: Mode::Install, quiet: false, purge: false });
        assert_eq!(p(&["/uninstall", "-quiet", "/PURGE"]).unwrap(), Args { mode: Mode::Uninstall, quiet: true, purge: true });
        assert!(p(&["/qualquer"]).is_err());
    }

    #[test]
    fn comandos_e_entradas_de_registro() {
        let dir = PathBuf::from(r"C:\Program Files\ByteHalt");
        assert_eq!(run_command(&dir), r#""C:\Program Files\ByteHalt\bytehalt.exe" --tray"#);
        assert_eq!(uninstall_command(&dir, true), r#""C:\Program Files\ByteHalt\bytehalt-setup.exe" /uninstall /quiet"#);
        let e = uninstall_entries(&dir, "0.2.0", 15_000);
        assert!(e.iter().any(|(k, v)| *k == "DisplayVersion" && *v == Value::Str("0.2.0".into())));
        assert!(e.iter().any(|(k, v)| *k == "EstimatedSize" && *v == Value::Dword(15_000)));
        assert_eq!(purge_target(&PathBuf::from(r"C:\ProgramData")), PathBuf::from(r"C:\ProgramData\ByteHalt"));
    }

    #[test]
    fn desinstalacao_recusada_com_cofres() {
        assert!(refuse_reason(&[]).is_none());
        let v = VaultRecord {
            id: uuid::Uuid::new_v4(),
            name: "Projeto".into(),
            original_path: r"D:\Projetos\x".into(),
            reserve_path: None,
            store_path: r"D:\ByteHalt.Cofres\a.vhdx".into(),
            volume: None,
            max_bytes: 0,
            stage: VaultStage::Active,
            files: 0,
            bytes: 0,
            created_at: 0,
            resource_id: None,
            error: None,
            restore_path: None,
        };
        let msg = refuse_reason(&[v]).unwrap();
        assert!(msg.contains("Projeto (ativo)") && msg.contains("Remover cofre"), "{msg}");
    }
}
