//! Identidade, ociosidade da sessão e inicialização com o Windows.

use crate::wide;
use windows_sys::Win32::Foundation::{CloseHandle, ERROR_SUCCESS, HANDLE, LocalFree};
use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows_sys::Win32::Security::*;
use windows_sys::Win32::System::Registry::*;
use windows_sys::Win32::System::SystemInformation::GetTickCount;
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows_sys::Win32::UI::Input::KeyboardAndMouse::{GetLastInputInfo, LASTINPUTINFO};

/// Converte um SID em texto ("S-1-5-...").
///
/// # Safety
/// `sid` deve apontar para um SID válido durante a chamada.
pub unsafe fn sid_to_string(sid: PSID) -> anyhow::Result<String> {
    let mut s: windows_sys::core::PWSTR = std::ptr::null_mut();
    // SAFETY: `sid` válido fornecido pelo chamador; a cadeia é liberada com LocalFree.
    anyhow::ensure!(unsafe { ConvertSidToStringSidW(sid, &mut s) } != 0, "SID inválido.");
    let mut len = 0;
    // SAFETY: `s` é UTF-16 terminado em nulo.
    while unsafe { *s.add(len) } != 0 {
        len += 1;
    }
    // SAFETY: `len` unidades lidas acima.
    let out = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(s, len) });
    // SAFETY: memória alocada por ConvertSidToStringSidW.
    unsafe { LocalFree(s.cast()) };
    Ok(out)
}

/// SID do usuário dono do token.
///
/// # Safety
/// `token` deve ser um handle de token válido aberto com TOKEN_QUERY.
pub unsafe fn token_user_sid(token: HANDLE) -> anyhow::Result<String> {
    let mut buf = vec![0u8; 256];
    let mut len = 0u32;
    // SAFETY: buffer de 256 bytes (suficiente para TOKEN_USER); token aberto com TOKEN_QUERY.
    let ok = unsafe { GetTokenInformation(token, TokenUser, buf.as_mut_ptr().cast(), buf.len() as u32, &mut len) };
    anyhow::ensure!(ok != 0, "Não foi possível ler o usuário do token.");
    // SAFETY: GetTokenInformation preencheu um TOKEN_USER alinhado no início do buffer.
    let user = unsafe { &*(buf.as_ptr() as *const TOKEN_USER) };
    // SAFETY: o SID aponta para dentro de `buf`, vivo durante a conversão.
    unsafe { sid_to_string(user.User.Sid) }
}

/// Membro ativo de Administradores (token filtrado pelo UAC responde falso, como deve).
///
/// # Safety
/// `token` deve ser um handle de token válido aberto com TOKEN_DUPLICATE.
pub unsafe fn token_is_admin(token: HANDLE) -> bool {
    let mut dup: HANDLE = std::ptr::null_mut();
    // SAFETY: token aberto com TOKEN_DUPLICATE; a cópia de identificação é fechada abaixo.
    if unsafe { DuplicateToken(token, SecurityIdentification, &mut dup) } == 0 {
        return false;
    }
    let mut sid = [0u8; 68];
    let mut size = sid.len() as u32;
    let mut member = 0i32;
    // SAFETY: buffer suficiente para um SID conhecido; `dup` é token de impersonation válido.
    let ok = unsafe {
        CreateWellKnownSid(WinBuiltinAdministratorsSid, std::ptr::null_mut(), sid.as_mut_ptr().cast(), &mut size) != 0
            && CheckTokenMembership(dup, sid.as_mut_ptr().cast(), &mut member) != 0
    };
    // SAFETY: handle próprio.
    unsafe { CloseHandle(dup) };
    ok && member != 0
}

pub fn current_user_sid() -> anyhow::Result<String> {
    let mut token: HANDLE = std::ptr::null_mut();
    // SAFETY: pseudo-handle do processo atual; token fechado abaixo.
    anyhow::ensure!(unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } != 0, "Token do processo indisponível.");
    // SAFETY: token aberto acima com TOKEN_QUERY e ainda não fechado.
    let r = unsafe { token_user_sid(token) };
    // SAFETY: handle próprio.
    unsafe { CloseHandle(token) };
    r
}

/// Segundos desde a última entrada de teclado/mouse da sessão atual.
pub fn session_idle_secs() -> u64 {
    let mut info = LASTINPUTINFO { cbSize: std::mem::size_of::<LASTINPUTINFO>() as u32, dwTime: 0 };
    // SAFETY: estrutura inicializada com o tamanho correto.
    if unsafe { GetLastInputInfo(&mut info) } == 0 {
        return 0;
    }
    // SAFETY: sem argumentos.
    let now = unsafe { GetTickCount() };
    u64::from(now.wrapping_sub(info.dwTime) / 1000)
}

const RUN_KEY: &str = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";

/// Inicialização com o Windows (HKCU\...\Run, valor "ByteHalt"), alterada só por ação do usuário.
pub fn autostart_enabled(value_name: &str) -> bool {
    let (key, name) = (wide(RUN_KEY), wide(value_name));
    let mut size = 0u32;
    // SAFETY: cadeias terminadas em nulo; só consulta o tamanho.
    unsafe {
        RegGetValueW(HKEY_CURRENT_USER, key.as_ptr(), name.as_ptr(), RRF_RT_REG_SZ, std::ptr::null_mut(), std::ptr::null_mut(), &mut size) == ERROR_SUCCESS
    }
}

pub fn set_autostart(value_name: &str, command: Option<&str>) -> anyhow::Result<()> {
    let key_path = wide(RUN_KEY);
    let mut key: HKEY = std::ptr::null_mut();
    // SAFETY: caminho terminado em nulo; chave fechada abaixo.
    let r = unsafe {
        RegCreateKeyExW(
            HKEY_CURRENT_USER,
            key_path.as_ptr(),
            0,
            std::ptr::null(),
            REG_OPTION_NON_VOLATILE,
            KEY_SET_VALUE,
            std::ptr::null(),
            &mut key,
            std::ptr::null_mut(),
        )
    };
    anyhow::ensure!(r == ERROR_SUCCESS, "Registro indisponível ({r}).");
    let name = wide(value_name);
    let r = match command {
        Some(cmd) => {
            let v = wide(cmd);
            // SAFETY: valor UTF-16 terminado em nulo; tamanho em bytes inclui o nulo.
            unsafe { RegSetValueExW(key, name.as_ptr(), 0, REG_SZ, v.as_ptr().cast(), (v.len() * 2) as u32) }
        }
        None => {
            // SAFETY: nome terminado em nulo.
            let r = unsafe { RegDeleteValueW(key, name.as_ptr()) };
            if r == windows_sys::Win32::Foundation::ERROR_FILE_NOT_FOUND { ERROR_SUCCESS } else { r }
        }
    };
    // SAFETY: chave própria.
    unsafe { RegCloseKey(key) };
    anyhow::ensure!(r == ERROR_SUCCESS, "Não foi possível alterar a inicialização ({r}).");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sid_do_usuario_atual_tem_formato_de_sid() {
        assert!(current_user_sid().unwrap().starts_with("S-1-5-"));
    }

    #[test]
    fn inicializacao_usa_valor_descartavel_nos_testes() {
        // Nunca a chave real "ByteHalt": valor próprio do teste, removido ao final.
        let name = format!("ByteHalt.Test.{}", uuid::Uuid::new_v4().simple());
        assert!(!autostart_enabled(&name));
        set_autostart(&name, Some("\"C:\\nao-existe\\bytehalt.exe\" --tray")).unwrap();
        assert!(autostart_enabled(&name));
        set_autostart(&name, None).unwrap();
        assert!(!autostart_enabled(&name));
        set_autostart(&name, None).unwrap();
    }
}
