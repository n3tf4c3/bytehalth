// Identidade dos executáveis (ícone + VERSIONINFO). Compartilhado por interface e serviço.
fn main() {
    println!("cargo:rerun-if-changed=../windows-resources.rs");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }
    let icon = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../assets/brand/bytehalt.ico");
    println!("cargo:rerun-if-changed={}", icon.display());
    let icon = icon.canonicalize().expect("ícone do ByteHalt").display().to_string().trim_start_matches(r"\\?\").replace('\\', "/");
    let version = std::env::var("CARGO_PKG_VERSION").unwrap();
    let n: Vec<u16> = version.split('.').map(|p| p.parse().expect("versão numérica")).collect();
    let [major, minor, patch] = n[..] else { panic!("versão com três partes") };
    let service = std::env::var("CARGO_PKG_NAME").as_deref() == Ok("bytehalt-service");
    let (description, filename) = if service { ("ByteHalt Service", "bytehalt-service.exe") } else { ("ByteHalt", "bytehalt.exe") };
    // O serviço roda como SYSTEM: importações estáticas só do System32, nunca da pasta do executável.
    if service && std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc") {
        println!("cargo:rustc-link-arg-bins=/DEPENDENTLOADFLAG:0x800");
    }
    // Ícones de estado da bandeja (só a interface): 2 = tudo bloqueado, 3 = algo desbloqueado, 4 = atenção.
    let tray_icons = if service {
        String::new()
    } else {
        ["tray-locked.ico", "tray-unlocked.ico", "tray-attention.ico"]
            .iter()
            .enumerate()
            .map(|(i, name)| {
                let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../assets/brand").join(name);
                println!("cargo:rerun-if-changed={}", p.display());
                let p = p.canonicalize().expect("ícone da bandeja").display().to_string().trim_start_matches(r"\\?\").replace('\\', "/");
                format!("{} ICON \"{p}\"\n", i + 2)
            })
            .collect()
    };
    let rc = format!(
        r#"#include <winver.h>
1 ICON "{icon}"
{tray_icons}VS_VERSION_INFO VERSIONINFO
FILEVERSION {major},{minor},{patch},0
PRODUCTVERSION {major},{minor},{patch},0
FILEFLAGSMASK VS_FFI_FILEFLAGSMASK
FILEFLAGS 0
FILEOS VOS_NT_WINDOWS32
FILETYPE VFT_APP
FILESUBTYPE VFT2_UNKNOWN
BEGIN
 BLOCK "StringFileInfo"
 BEGIN
  BLOCK "041604B0"
  BEGIN
   VALUE "FileDescription", "{description}"
   VALUE "FileVersion", "{version}"
   VALUE "OriginalFilename", "{filename}"
   VALUE "ProductName", "ByteHalt"
   VALUE "ProductVersion", "{version}"
  END
 END
 BLOCK "VarFileInfo"
 BEGIN
  VALUE "Translation", 0x0416, 0x04B0
 END
END
"#
    );
    let path = std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap()).join("bytehalt-version.rc");
    std::fs::write(&path, rc).expect("recursos Win32");
    embed_resource::compile(&path, embed_resource::NONE).manifest_optional().expect("compilar recursos Win32");
}
