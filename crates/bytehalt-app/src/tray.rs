//! Bandeja nativa (Shell_NotifyIconW), adaptada do NetLane: ícone embutido, menu nativo, balões
//! de notificação, recriação após reinício do Explorer. Tudo na thread da interface.
use anyhow::{Result, ensure};
use bytehalt_windows::wide;
use std::cell::{Cell, RefCell};
use std::marker::PhantomData;
use std::ptr::{null, null_mut};
use std::rc::Rc;
use std::sync::mpsc::{self, Receiver, Sender};
use windows_sys::Win32::Foundation::{ERROR_CLASS_ALREADY_EXISTS, GetLastError, HWND, LPARAM, LRESULT, POINT, WPARAM};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::UI::{Shell::*, WindowsAndMessaging::*};

const CALLBACK: u32 = WM_APP + 17;
const PROOF: u32 = WM_APP + 18;
/// Pedido de outra instância (menu Iniciar, atalho): mostrar o painel existente.
const SHOW: u32 = WM_APP + 19;
/// Pedido do instalador (atualizar ou desinstalar): encerrar a interface. O `bytehalt-setup` usa o mesmo
/// valor e a mesma classe de janela (`CLASS`); mudar aqui exige mudar lá.
const QUIT: u32 = WM_APP + 20;
const CLASS: &str = "ByteHalt.Tray.v1";
const GROUP_BASE: usize = 100;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrayAction {
    Open,
    LockAll,
    LockGroup(usize),
    Exit,
    Unavailable,
}

/// Ícone conforme o estado da proteção (recursos 2, 3 e 4 do executável).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum TrayIcon {
    #[default]
    Locked,
    Unlocked,
    Attention,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TrayState {
    pub status: String,
    pub groups: Vec<String>,
    pub connected: bool,
    pub icon: TrayIcon,
    /// Dica ao passar o mouse (até 127 caracteres).
    pub tooltip: String,
}

impl TrayState {
    fn menu(&self) -> Vec<(usize, String, bool)> {
        let mut rows = vec![(0, self.status.clone(), false), (1, "Abrir o ByteHalt".into(), true), (2, "Bloquear tudo".into(), self.connected)];
        rows.extend(self.groups.iter().enumerate().map(|(i, g)| (GROUP_BASE + i, format!("Bloquear grupo: {g}"), self.connected)));
        rows.push((3, "Sair".into(), true));
        rows
    }
}

fn action(id: usize) -> Option<TrayAction> {
    match id {
        1 => Some(TrayAction::Open),
        2 => Some(TrayAction::LockAll),
        3 => Some(TrayAction::Exit),
        i if i >= GROUP_BASE => Some(TrayAction::LockGroup(i - GROUP_BASE)),
        _ => None,
    }
}

struct CallbackState {
    hwnd: Cell<HWND>,
    icons: [HICON; 3],
    available: Cell<bool>,
    taskbar_created: u32,
    model: RefCell<TrayState>,
    sender: Sender<TrayAction>,
}

fn copy_into(dst: &mut [u16], s: &str) {
    let w = wide(s);
    let n = w.len().min(dst.len());
    dst[..n].copy_from_slice(&w[..n]);
    dst[dst.len() - 1] = 0;
}

impl CallbackState {
    fn data(&self) -> NOTIFYICONDATAW {
        let mut d = NOTIFYICONDATAW {
            cbSize: std::mem::size_of::<NOTIFYICONDATAW>() as u32,
            hWnd: self.hwnd.get(),
            uID: 1,
            uFlags: NIF_MESSAGE | NIF_ICON | NIF_TIP | NIF_SHOWTIP,
            uCallbackMessage: CALLBACK,
            hIcon: self.icons[self.model.borrow().icon as usize],
            ..Default::default()
        };
        let tip = self.model.borrow().tooltip.clone();
        copy_into(&mut d.szTip, if tip.is_empty() { "ByteHalt · Proteção de unidades e pastas" } else { &tip });
        d
    }

    fn add(&self) -> bool {
        let mut d = self.data();
        // SAFETY: dados inicializados referenciam esta janela oculta viva e o ícone do módulo.
        if unsafe { Shell_NotifyIconW(NIM_ADD, &d) } == 0 {
            return false;
        }
        d.Anonymous.uVersion = NOTIFYICON_VERSION_4;
        // SAFETY: o ícone com esta janela/id foi adicionado acima.
        if unsafe { Shell_NotifyIconW(NIM_SETVERSION, &d) } == 0 {
            self.remove();
            return false;
        }
        true
    }

    fn remove(&self) {
        // SAFETY: identifica só o ícone próprio deste processo.
        unsafe { Shell_NotifyIconW(NIM_DELETE, &self.data()) };
        self.available.set(false);
    }

    fn popup(&self) {
        // Clona antes: nenhum empréstimo do RefCell sobrevive ao laço aninhado do menu nativo.
        let rows = self.model.borrow().menu();
        // SAFETY: sem ponteiros; retorna um handle próprio.
        let menu = unsafe { CreatePopupMenu() };
        if menu.is_null() {
            return;
        }
        let mut valid = true;
        for (id, label, enabled) in rows {
            let text = wide(&label);
            // SAFETY: menu vivo e texto terminado em nulo durante a chamada.
            valid &= unsafe { AppendMenuW(menu, MF_STRING | if enabled { MF_ENABLED } else { MF_GRAYED }, id, text.as_ptr()) } != 0;
        }
        let mut point = POINT::default();
        // SAFETY: `point` gravável; hwnd/menu pertencem a esta thread.
        let selection = unsafe {
            if valid && GetCursorPos(&mut point) != 0 {
                SetForegroundWindow(self.hwnd.get());
                let id = TrackPopupMenu(menu, TPM_RETURNCMD | TPM_NONOTIFY | TPM_RIGHTBUTTON, point.x, point.y, 0, self.hwnd.get(), null());
                PostMessageW(self.hwnd.get(), WM_NULL, 0, 0);
                id as usize
            } else {
                0
            }
        };
        // SAFETY: menu próprio; TrackPopupMenu retornou.
        unsafe {
            DestroyMenu(menu);
            Shell_NotifyIconW(NIM_SETFOCUS, &self.data());
        }
        if let Some(a) = action(selection) {
            let _ = self.sender.send(a);
        }
    }
}

unsafe extern "system" fn window_proc(hwnd: HWND, message: u32, w: WPARAM, l: LPARAM) -> LRESULT {
    if message == WM_NCCREATE {
        // SAFETY: o Windows fornece CREATESTRUCTW no WM_NCCREATE; o Rc em lpCreateParams vive até o DestroyWindow do Drop.
        unsafe {
            let create = &*(l as *const CREATESTRUCTW);
            SetWindowLongPtrW(hwnd, GWLP_USERDATA, create.lpCreateParams as isize);
        }
    }
    // SAFETY: esta classe guarda só o ponteiro estável do Rc em GWLP_USERDATA.
    let ptr = unsafe { GetWindowLongPtrW(hwnd, GWLP_USERDATA) } as *const CallbackState;
    if !ptr.is_null() {
        // SAFETY: ponteiro de Rc::as_ptr; a Tray mantém uma referência forte e uma temporária protege
        // o estado se o laço aninhado do menu descartar a Tray antes de retornar.
        let state = unsafe {
            Rc::increment_strong_count(ptr);
            Rc::from_raw(ptr)
        };
        if message == SHOW {
            let _ = state.sender.send(TrayAction::Open);
            return 0;
        }
        if message == QUIT {
            let _ = state.sender.send(TrayAction::Exit);
            return 0;
        }
        if message == PROOF {
            if let Some(a) = action(w) {
                let _ = state.sender.send(a);
            }
            return 0;
        }
        if message == state.taskbar_created && state.taskbar_created != 0 {
            state.available.set(state.add());
            if !state.available.get() {
                let _ = state.sender.send(TrayAction::Unavailable);
            }
            return 0;
        }
        if message == CALLBACK {
            let event = (l as u32) & 0xffff;
            if event == WM_CONTEXTMENU {
                state.popup();
            } else if event == NIN_SELECT || event == (NIN_SELECT | 1) || event == WM_LBUTTONUP || event == NIN_BALLOONUSERCLICK {
                let _ = state.sender.send(TrayAction::Open);
            }
            return 0;
        }
        if message == WM_NCDESTROY {
            // SAFETY: limpa o ponteiro antes da destruição final.
            unsafe { SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0) };
        }
    }
    // SAFETY: repassa os argumentos nativos intactos.
    unsafe { DefWindowProcW(hwnd, message, w, l) }
}

pub struct Tray {
    state: Rc<CallbackState>,
    receiver: Receiver<TrayAction>,
    _ui_thread: PhantomData<Rc<()>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Level {
    Info,
    Warning,
    Error,
}

impl Tray {
    pub fn new(model: TrayState) -> Result<Self> {
        let class = wide(CLASS);
        // SAFETY: nulo pede o módulo do executável atual.
        let module = unsafe { GetModuleHandleW(null()) };
        ensure!(!module.is_null(), "Módulo da bandeja indisponível.");
        let descriptor = WNDCLASSW { lpfnWndProc: Some(window_proc), hInstance: module, lpszClassName: class.as_ptr(), ..Default::default() };
        // SAFETY: descritor e nome vivos durante o registro; o Windows copia o nome.
        let registered = unsafe { RegisterClassW(&descriptor) } != 0;
        // SAFETY: lê o último erro logo após o registro.
        let existing = unsafe { GetLastError() } == ERROR_CLASS_ALREADY_EXISTS;
        ensure!(registered || existing, "Classe da bandeja indisponível.");
        // Recursos 2..4 = ícones de estado; sem eles (build sem recursos) usa o ícone 1. Carrega a
        // entrada do tamanho pequeno do sistema (16/20/24 px conforme a escala) em vez de reduzir a de 32.
        // SAFETY: consulta de métricas sem efeitos colaterais.
        let (cx, cy) = unsafe { (GetSystemMetrics(SM_CXSMICON), GetSystemMetrics(SM_CYSMICON)) };
        let load = |id: usize| -> HICON {
            // SAFETY: MAKEINTRESOURCE(id) nomeia um ícone embutido; LR_SHARED devolve um ícone que o
            // sistema libera com o módulo (tamanho padrão, como exige LR_SHARED).
            let i = unsafe { LoadImageW(module, std::ptr::without_provenance(id), IMAGE_ICON, cx, cy, LR_SHARED) };
            if i.is_null() {
                // SAFETY: idem, ícone principal.
                unsafe { LoadImageW(module, std::ptr::without_provenance(1), IMAGE_ICON, cx, cy, LR_SHARED) }
            } else {
                i
            }
        };
        let icons = [load(2), load(3), load(4)];
        ensure!(icons.iter().all(|i| !i.is_null()), "Ícone da bandeja indisponível.");
        let (sender, receiver) = mpsc::channel();
        // SAFETY: literal terminado em nulo lido só durante o registro.
        let taskbar_created = unsafe { RegisterWindowMessageW(wide("TaskbarCreated").as_ptr()) };
        let state =
            Rc::new(CallbackState { hwnd: Cell::new(null_mut()), icons, available: Cell::new(false), taskbar_created, model: RefCell::new(model), sender });
        // SAFETY: ponteiro estável do Rc sobrevive à janela; janela de topo oculta (recebe o broadcast do Explorer).
        let hwnd = unsafe {
            CreateWindowExW(
                WS_EX_TOOLWINDOW,
                class.as_ptr(),
                wide("ByteHalt Tray").as_ptr(),
                WS_POPUP,
                0,
                0,
                0,
                0,
                null_mut(),
                null_mut(),
                module,
                Rc::as_ptr(&state).cast(),
            )
        };
        ensure!(!hwnd.is_null(), "Janela da bandeja indisponível.");
        state.hwnd.set(hwnd);
        let tray = Self { state, receiver, _ui_thread: PhantomData };
        tray.state.available.set(tray.state.add());
        ensure!(tray.available(), "O Windows não confirmou o ícone da bandeja.");
        Ok(tray)
    }

    pub fn available(&self) -> bool {
        self.state.available.get()
    }

    pub fn take_action(&self) -> Option<TrayAction> {
        self.receiver.try_recv().ok()
    }

    pub fn update(&self, model: TrayState) {
        let changed = {
            let old = self.state.model.borrow();
            old.icon != model.icon || old.tooltip != model.tooltip
        };
        *self.state.model.borrow_mut() = model;
        if changed && self.available() {
            // SAFETY: modifica só o ícone próprio (ícone e dica novos).
            unsafe { Shell_NotifyIconW(NIM_MODIFY, &self.state.data()) };
        }
    }

    #[cfg_attr(not(feature = "gui-test"), allow(dead_code))]
    pub fn icon(&self) -> TrayIcon {
        self.state.model.borrow().icon
    }

    #[cfg_attr(not(feature = "gui-test"), allow(dead_code))]
    pub fn tooltip(&self) -> String {
        self.state.model.borrow().tooltip.clone()
    }

    pub fn check(&self) -> bool {
        // SAFETY: identifica só o ícone/janela próprios.
        if self.available() && unsafe { Shell_NotifyIconW(NIM_MODIFY, &self.state.data()) } == 0 {
            self.state.remove();
        }
        self.available()
    }

    /// Balão/notificação do Windows a partir do ícone da bandeja.
    pub fn notify(&self, title: &str, message: &str, level: Level) {
        let mut d = self.state.data();
        d.uFlags |= NIF_INFO;
        copy_into(&mut d.szInfoTitle, title);
        copy_into(&mut d.szInfo, message);
        d.dwInfoFlags = match level {
            Level::Info => NIIF_INFO,
            Level::Warning => NIIF_WARNING,
            Level::Error => NIIF_ERROR,
        };
        // SAFETY: modifica só o ícone próprio.
        unsafe { Shell_NotifyIconW(NIM_MODIFY, &d) };
    }

    /// Roteiro de prova: injeta um clique de menu na própria janela da bandeja.
    #[cfg(feature = "gui-test")]
    pub fn proof_post(&self, a: TrayAction) {
        let id = match a {
            TrayAction::Open => 1,
            TrayAction::LockAll => 2,
            TrayAction::Exit => 3,
            TrayAction::LockGroup(i) => GROUP_BASE + i,
            TrayAction::Unavailable => 0,
        };
        // SAFETY: posta só para a janela da bandeja deste processo.
        unsafe { PostMessageW(self.state.hwnd.get(), PROOF, id, 0) };
    }

    #[cfg(feature = "gui-test")]
    pub fn proof_menu(&self) -> Vec<(String, bool)> {
        self.state.model.borrow().menu().into_iter().map(|(_, l, e)| (l, e)).collect()
    }
}

impl Drop for Tray {
    fn drop(&mut self) {
        self.state.remove();
        // SAFETY: esta thread é dona da janela e o Rc do callback ainda vive.
        unsafe { DestroyWindow(self.state.hwnd.get()) };
    }
}

/// Janela do painel (emprestada do GPUI) para esconder/restaurar.
pub struct Panel {
    hwnd: HWND,
    _ui_thread: PhantomData<Rc<()>>,
}

impl Panel {
    pub fn from_handle(hwnd: std::num::NonZeroIsize) -> Self {
        Self { hwnd: hwnd.get() as HWND, _ui_thread: PhantomData }
    }

    pub fn hide(&self) {
        // SAFETY: ShowWindow só recebe o handle.
        unsafe { ShowWindow(self.hwnd, SW_HIDE) };
    }

    pub fn restore(&self) {
        // SAFETY: opera só no handle emprestado do painel.
        unsafe {
            ShowWindow(self.hwnd, if IsIconic(self.hwnd) != 0 { SW_RESTORE } else { SW_SHOW });
            SetForegroundWindow(self.hwnd);
        }
    }

    pub fn minimized(&self) -> bool {
        // SAFETY: consulta o handle emprestado.
        unsafe { IsIconic(self.hwnd) != 0 }
    }

    pub fn visible(&self) -> bool {
        // SAFETY: consulta o handle emprestado.
        unsafe { IsWindowVisible(self.hwnd) != 0 }
    }

    #[cfg(feature = "gui-test")]
    pub fn proof_post(&self, minimize: bool) {
        let (m, v) = if minimize { (WM_SYSCOMMAND, SC_MINIMIZE as usize) } else { (WM_CLOSE, 0) };
        // SAFETY: posta só para o painel emprestado.
        unsafe { PostMessageW(self.hwnd, m, v, 0) };
    }
}

/// Se já existe uma instância (janela oculta da bandeja), pede que ela mostre o painel.
/// Retorna verdadeiro quando o pedido foi entregue.
pub fn signal_existing() -> bool {
    let class = wide(CLASS);
    // SAFETY: nome de classe terminado em nulo; procura só janelas de topo deste usuário/sessão.
    let hwnd = unsafe { FindWindowW(class.as_ptr(), null()) };
    // SAFETY: posta uma mensagem própria do ByteHalt para a janela encontrada.
    !hwnd.is_null() && unsafe { PostMessageW(hwnd, SHOW, 0, 0) } != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn menu_lista_grupos_e_desabilita_bloqueio_sem_servico() {
        let s =
            TrayState { status: "Serviço indisponível".into(), groups: vec!["Discos".into(), "Credenciais".into()], connected: false, ..Default::default() };
        let rows = s.menu();
        assert_eq!(rows[0], (0, "Serviço indisponível".into(), false));
        assert!(rows.iter().any(|r| r.1 == "Bloquear grupo: Credenciais" && !r.2));
        assert!(rows.last().unwrap().2, "Sair sempre disponível");
        assert_eq!(action(GROUP_BASE + 1), Some(TrayAction::LockGroup(1)));
        assert_eq!(action(0), None);
    }
}
