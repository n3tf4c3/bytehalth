//! Pasta de dados do serviço: acesso só para SYSTEM e Administradores, sem herança.

use crate::wide;
use std::path::Path;
use windows_sys::Win32::Foundation::{ERROR_SUCCESS, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1, SE_FILE_OBJECT, SetNamedSecurityInfoW,
};
use windows_sys::Win32::Security::{ACL, DACL_SECURITY_INFORMATION, GetSecurityDescriptorDacl, PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR};

pub const MACHINE_ONLY_SDDL: &str = "D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";

pub fn ensure_machine_only(dir: &Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(dir)?;
    let sddl = wide(MACHINE_ONLY_SDDL);
    let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: SDDL terminado em nulo; `sd` recebe memória do sistema liberada com LocalFree.
    let ok = unsafe { ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.as_ptr(), SDDL_REVISION_1, &mut sd, std::ptr::null_mut()) };
    anyhow::ensure!(ok != 0, "SDDL da pasta inválido.");
    let mut present = 0i32;
    let mut defaulted = 0i32;
    let mut dacl: *mut ACL = std::ptr::null_mut();
    // SAFETY: `sd` válido; `dacl` aponta para dentro de `sd`, vivo até o LocalFree.
    let got = unsafe { GetSecurityDescriptorDacl(sd, &mut present, &mut dacl, &mut defaulted) };
    let path = wide(&dir.to_string_lossy());
    let result = if got != 0 && present != 0 {
        // SAFETY: caminho terminado em nulo; DACL válida dentro de `sd`.
        unsafe {
            SetNamedSecurityInfoW(
                path.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                dacl,
                std::ptr::null(),
            )
        }
    } else {
        1
    };
    // SAFETY: memória alocada por ConvertStringSecurityDescriptorToSecurityDescriptorW.
    unsafe { LocalFree(sd) };
    anyhow::ensure!(result == ERROR_SUCCESS, "Não foi possível restringir a pasta de dados ({result}).");
    Ok(())
}
