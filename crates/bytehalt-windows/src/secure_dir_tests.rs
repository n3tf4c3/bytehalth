//! Pasta de dados preexistente (achado de auditoria #3). Só no Windows Sandbox: troca dono e DACL
//! de pastas temporárias e exige SeRestorePrivilege (administrador elevado).
//! As asserções olham o estado no disco (não o valor devolvido) para valerem também contra a
//! versão anterior da função, que só trocava a DACL.

use super::ensure_machine_only;
use crate::wide;
use std::path::Path;
use std::ptr::{null, null_mut};
use windows_sys::Win32::Foundation::{ERROR_SUCCESS, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1, SE_FILE_OBJECT, SetNamedSecurityInfoW,
};
use windows_sys::Win32::Security::{
    ACL, DACL_SECURITY_INFORMATION, GetSecurityDescriptorDacl, GetSecurityDescriptorOwner, OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR,
};
use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

struct Descriptor(PSECURITY_DESCRIPTOR);

impl Drop for Descriptor {
    fn drop(&mut self) {
        // SAFETY: alocado por ConvertStringSecurityDescriptorToSecurityDescriptorW.
        unsafe { LocalFree(self.0) };
    }
}

fn sddl(p: &Path) -> String {
    let out =
        std::process::Command::new("powershell").args(["-NoProfile", "-Command", &format!("(Get-Acl -LiteralPath '{}').Sddl", p.display())]).output().unwrap();
    String::from_utf8_lossy(&out.stdout).trim().to_owned()
}

/// Descritor arbitrário (dono incluído) — simula a pasta criada por outro usuário.
fn set_sd(p: &Path, text: &str) {
    crate::acl::enable_privileges(&["SeRestorePrivilege", "SeTakeOwnershipPrivilege"]).expect("teste exige administrador elevado");
    let s = wide(text);
    let mut sd: PSECURITY_DESCRIPTOR = null_mut();
    // SAFETY: SDDL terminado em nulo; liberado no Drop.
    assert_ne!(unsafe { ConvertStringSecurityDescriptorToSecurityDescriptorW(s.as_ptr(), SDDL_REVISION_1, &mut sd, null_mut()) }, 0);
    let sd = Descriptor(sd);
    let (mut owner, mut d, mut present) = (null_mut(), 0i32, 0i32);
    let mut dacl: *mut ACL = null_mut();
    // SAFETY: descritor válido.
    unsafe {
        GetSecurityDescriptorOwner(sd.0, &mut owner, &mut d);
        GetSecurityDescriptorDacl(sd.0, &mut present, &mut dacl, &mut d);
    }
    let path = wide(&p.to_string_lossy());
    // SAFETY: caminho terminado em nulo; dono/DACL de `sd`.
    let r = unsafe {
        SetNamedSecurityInfoW(
            path.as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            owner,
            null_mut(),
            dacl,
            null(),
        )
    };
    assert_eq!(r, ERROR_SUCCESS, "SetNamedSecurityInfoW em {}", p.display());
}

/// Dono = Usuários (BU) e controle total para Todos: o que um usuário comum deixaria.
const USER_PLANTED: &str = "O:BUD:PAI(A;OICI;FA;;;WD)";

fn is_reparse(p: &Path) -> bool {
    std::os::windows::fs::MetadataExt::file_attributes(&std::fs::symlink_metadata(p).unwrap()) & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

fn assert_machine_only(dir: &Path) {
    let s = sddl(dir);
    assert!(s.starts_with("O:BA") || s.starts_with("O:SY"), "dono não confiável: {s}");
    assert!(s.contains("D:P"), "DACL não protegida: {s}");
    assert!(!s.contains(";;;WD)") && !s.contains(";;;BU)") && !s.contains(";;;AU)"), "acesso além de SYSTEM/Administradores: {s}");
}

#[test]
fn pasta_nova_nasce_com_dono_administradores_e_dacl_restrita() {
    let t = tempfile::tempdir().unwrap();
    let dir = t.path().join("ByteHalt");
    let _ = ensure_machine_only(&dir).unwrap();
    assert_machine_only(&dir);
    // Idempotente: a segunda chamada adota a pasta e mantém o conteúdo do próprio serviço.
    std::fs::write(dir.join("bytehalt.db"), b"x").unwrap();
    let _ = ensure_machine_only(&dir).unwrap();
    assert_eq!(std::fs::read(dir.join("bytehalt.db")).unwrap(), b"x");
    assert_machine_only(&dir);
}

#[test]
fn pasta_precriada_por_usuario_comum_nao_mantem_o_dono() {
    let t = tempfile::tempdir().unwrap();
    let dir = t.path().join("ByteHalt");
    std::fs::create_dir(&dir).unwrap();
    std::fs::write(dir.join("bytehalt.db"), b"plantado").unwrap();
    set_sd(&dir.join("bytehalt.db"), USER_PLANTED);
    set_sd(&dir, USER_PLANTED);
    let _ = ensure_machine_only(&dir).unwrap();
    // O dono antigo (com WRITE_DAC implícito) não pode continuar dono da pasta em uso.
    assert_machine_only(&dir);
    assert!(!dir.join("bytehalt.db").exists(), "arquivo plantado continuou na pasta em uso");
    // Nada é apagado: a pasta antiga fica ao lado, renomeada.
    let aside: Vec<_> = std::fs::read_dir(t.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().starts_with("ByteHalt.nao-confiavel-"))
        .collect();
    assert_eq!(aside.len(), 1, "pasta antiga deveria ficar ao lado");
    assert_eq!(std::fs::read(aside[0].path().join("bytehalt.db")).unwrap(), b"plantado");
}

#[test]
fn juncao_no_lugar_da_pasta_nao_e_seguida() {
    let t = tempfile::tempdir().unwrap();
    let (dir, target) = (t.path().join("ByteHalt"), t.path().join("alvo"));
    std::fs::create_dir(&target).unwrap();
    let before = sddl(&target);
    let ok = std::process::Command::new("cmd").args(["/c", "mklink", "/J"]).arg(&dir).arg(&target).stdout(std::process::Stdio::null()).status().unwrap();
    assert!(ok.success());
    let _ = ensure_machine_only(&dir).unwrap();
    assert_eq!(sddl(&target), before, "a segurança do alvo da junção foi alterada");
    assert!(!is_reparse(&dir), "a pasta de dados continuou sendo uma junção");
    assert_machine_only(&dir);
}

#[test]
fn item_com_dono_nao_confiavel_impede_o_uso_da_pasta() {
    let t = tempfile::tempdir().unwrap();
    let dir = t.path().join("ByteHalt");
    let _ = ensure_machine_only(&dir).unwrap();
    std::fs::create_dir(dir.join("state")).unwrap();
    std::fs::write(dir.join("state\\credentials.dat"), b"x").unwrap();
    set_sd(&dir.join("state\\credentials.dat"), USER_PLANTED);
    let r = ensure_machine_only(&dir);
    assert!(r.is_err(), "arquivo cujo dono é um usuário comum foi aceito");
    // Falha fechada sem mover nada do próprio serviço.
    assert!(dir.join("state\\credentials.dat").exists());
}

#[test]
fn hard_link_dentro_da_pasta_impede_o_uso() {
    let t = tempfile::tempdir().unwrap();
    let dir = t.path().join("ByteHalt");
    let _ = ensure_machine_only(&dir).unwrap();
    let outside = t.path().join("fora.txt");
    std::fs::write(&outside, b"fora").unwrap();
    std::fs::hard_link(&outside, dir.join("bytehalt.db")).unwrap();
    assert!(ensure_machine_only(&dir).is_err(), "hard link para arquivo de fora foi aceito");
}

#[test]
fn juncao_dentro_da_pasta_impede_o_uso() {
    let t = tempfile::tempdir().unwrap();
    let dir = t.path().join("ByteHalt");
    let _ = ensure_machine_only(&dir).unwrap();
    let target = t.path().join("alvo");
    std::fs::create_dir(&target).unwrap();
    let ok = std::process::Command::new("cmd")
        .args(["/c", "mklink", "/J"])
        .arg(dir.join("state"))
        .arg(&target)
        .stdout(std::process::Stdio::null())
        .status()
        .unwrap();
    assert!(ok.success());
    assert!(ensure_machine_only(&dir).is_err(), "junção dentro da pasta de dados foi aceita");
}
