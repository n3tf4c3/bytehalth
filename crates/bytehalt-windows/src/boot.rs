//! Sessão de boot: identificador aleatório numa chave **volátil** do registro (o Windows a descarta
//! no reinício; sobrevive ao reinício do serviço) e uptime por GetTickCount64 (monotônico, inclui
//! suspensão). Ler-ou-criar sob mutex nomeado: duas instâncias simultâneas não geram IDs diferentes.

use crate::wide;
use bytehalt_core::clock::BootSession;
use std::ptr::null_mut;
use std::time::Duration;
use windows_sys::Win32::Foundation::{CloseHandle, ERROR_SUCCESS, WAIT_ABANDONED, WAIT_OBJECT_0};
use windows_sys::Win32::System::Registry::*;
use windows_sys::Win32::System::SystemInformation::GetTickCount64;
use windows_sys::Win32::System::Threading::{CreateMutexW, ReleaseMutex, WaitForSingleObject};

pub struct WindowsBootSession {
    boot_id: String,
}

impl WindowsBootSession {
    pub fn new(machine_scope: bool) -> anyhow::Result<Self> {
        let mutex_name = wide(if machine_scope { "Global\\ByteHalt.BootSession" } else { "Local\\ByteHalt.BootSession" });
        // SAFETY: nome terminado em nulo; o handle é fechado abaixo.
        let mutex = unsafe { CreateMutexW(std::ptr::null(), 0, mutex_name.as_ptr()) };
        anyhow::ensure!(!mutex.is_null(), "Mutex da sessão de boot indisponível.");
        // SAFETY: handle válido criado acima.
        let wait = unsafe { WaitForSingleObject(mutex, 10_000) };
        let owned = wait == WAIT_OBJECT_0 || wait == WAIT_ABANDONED;
        let result = Self::read_or_create(machine_scope);
        // SAFETY: libera só se a posse foi obtida; fecha o handle próprio.
        unsafe {
            if owned {
                ReleaseMutex(mutex);
            }
            CloseHandle(mutex);
        }
        Ok(Self { boot_id: result? })
    }

    fn read_or_create(machine_scope: bool) -> anyhow::Result<String> {
        let root = if machine_scope { HKEY_LOCAL_MACHINE } else { HKEY_CURRENT_USER };
        let parent = create_key(root, "SOFTWARE\\ByteHalt", REG_OPTION_NON_VOLATILE)?;
        let key = create_key(parent, "Boot", REG_OPTION_VOLATILE);
        // SAFETY: fecha a chave pai aberta acima.
        unsafe { RegCloseKey(parent) };
        let key = key?;
        let name = wide("BootId");
        let mut buf = [0u16; 64];
        let mut size = std::mem::size_of_val(&buf) as u32;
        let mut kind = 0u32;
        // SAFETY: buffer e tamanho válidos; a chave está aberta.
        let read = unsafe { RegQueryValueExW(key, name.as_ptr(), null_mut(), &mut kind, buf.as_mut_ptr().cast(), &mut size) };
        let existing = (read == ERROR_SUCCESS && kind == REG_SZ).then(|| crate::from_wide(&buf)).filter(|s| uuid::Uuid::try_parse(s).is_ok());
        let id = match existing {
            Some(id) => id,
            None => {
                let id = uuid::Uuid::new_v4().simple().to_string();
                let value = wide(&id);
                // SAFETY: valor UTF-16 terminado em nulo, tamanho em bytes inclui o nulo.
                let set = unsafe { RegSetValueExW(key, name.as_ptr(), 0, REG_SZ, value.as_ptr().cast(), (value.len() * 2) as u32) };
                if set != ERROR_SUCCESS {
                    // SAFETY: fecha a chave própria antes de sair.
                    unsafe { RegCloseKey(key) };
                    anyhow::bail!("Não foi possível gravar o identificador da sessão de boot ({set}).");
                }
                id
            }
        };
        // SAFETY: fecha a chave própria.
        unsafe { RegCloseKey(key) };
        Ok(id)
    }
}

fn create_key(root: HKEY, path: &str, options: u32) -> anyhow::Result<HKEY> {
    let path = wide(path);
    let mut key: HKEY = null_mut();
    // SAFETY: caminho terminado em nulo; `key` recebe um handle próprio.
    let r = unsafe { RegCreateKeyExW(root, path.as_ptr(), 0, std::ptr::null(), options, KEY_READ | KEY_WRITE, std::ptr::null(), &mut key, null_mut()) };
    anyhow::ensure!(r == ERROR_SUCCESS, "Registro indisponível ({r}).");
    Ok(key)
}

impl BootSession for WindowsBootSession {
    fn boot_id(&self) -> String {
        self.boot_id.clone()
    }

    fn uptime(&self) -> Duration {
        // SAFETY: sem argumentos.
        Duration::from_millis(unsafe { GetTickCount64() })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mesmo_boot_mesmo_identificador_mesmo_com_instancias_simultaneas() {
        let ids: Vec<String> = (0..8)
            .map(|_| std::thread::spawn(|| WindowsBootSession::new(false).unwrap().boot_id()))
            .collect::<Vec<_>>()
            .into_iter()
            .map(|h| h.join().unwrap())
            .collect();
        assert!(ids.windows(2).all(|w| w[0] == w[1]), "{ids:?}");
        assert!(uuid::Uuid::try_parse(&ids[0]).is_ok());
        let s = WindowsBootSession::new(false).unwrap();
        let u = s.uptime();
        std::thread::sleep(Duration::from_millis(40));
        assert!(s.uptime() > u);
    }
}
