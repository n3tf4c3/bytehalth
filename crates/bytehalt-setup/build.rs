// Recursos do instalador (ícone, versão, manifesto elevado) e conteúdo embutido. O conteúdo vem de
// BYTEHALT_PAYLOAD_DIR (pasta com bytehalt.exe e bytehalt-service.exe em release, preparada por
// scripts/release/Build-Installer.ps1). Sem a variável, o instalador compila vazio e recusa instalar.
fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=setup.manifest");
    println!("cargo:rerun-if-env-changed=BYTEHALT_PAYLOAD_DIR");
    let out = std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap());
    let payload = std::env::var_os("BYTEHALT_PAYLOAD_DIR").map(std::path::PathBuf::from);
    for name in ["bytehalt.exe", "bytehalt-service.exe"] {
        let dst = out.join(name);
        match &payload {
            Some(dir) => {
                let src = dir.join(name);
                println!("cargo:rerun-if-changed={}", src.display());
                std::fs::copy(&src, &dst).unwrap_or_else(|e| panic!("conteúdo {}: {e}", src.display()));
            }
            None => std::fs::write(&dst, b"").unwrap(),
        }
    }
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let fix = |p: std::path::PathBuf| p.canonicalize().unwrap().display().to_string().trim_start_matches(r"\\?\").replace('\\', "/");
    let icon = fix(root.join("../../assets/brand/bytehalt.ico"));
    let manifest = fix(root.join("setup.manifest"));
    let version = std::env::var("CARGO_PKG_VERSION").unwrap();
    let n: Vec<u16> = version.split('.').map(|p| p.parse().unwrap()).collect();
    let rc = format!(
        r#"#include <winver.h>
1 ICON "{icon}"
1 24 "{manifest}"
VS_VERSION_INFO VERSIONINFO
FILEVERSION {a},{b},{c},0
PRODUCTVERSION {a},{b},{c},0
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
   VALUE "FileDescription", "Instalador do ByteHalt"
   VALUE "FileVersion", "{version}"
   VALUE "OriginalFilename", "bytehalt-setup.exe"
   VALUE "ProductName", "ByteHalt"
   VALUE "ProductVersion", "{version}"
  END
 END
 BLOCK "VarFileInfo"
 BEGIN
  VALUE "Translation", 0x0416, 0x04B0
 END
END
"#,
        a = n[0],
        b = n[1],
        c = n[2]
    );
    let path = out.join("setup.rc");
    std::fs::write(&path, rc).unwrap();
    embed_resource::compile(&path, embed_resource::NONE).manifest_required().unwrap();
}
