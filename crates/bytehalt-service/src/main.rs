//! `bytehalt-service --service ...` roda sob o SCM (LocalSystem, pipe de produção);
//! sem `--service` roda em console (pipe por usuário). `--simulate` usa volumes simulados.

#[cfg(windows)]
fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = if args.iter().any(|a| a == "--service") { service::run() } else { console(&args) };
    if let Err(e) = result {
        eprintln!("{e:#}");
        std::process::exit(1);
    }
}

#[cfg(not(windows))]
fn main() {
    eprintln!("O serviço do ByteHalt só roda no Windows.");
}

#[cfg(windows)]
fn console(args: &[String]) -> anyhow::Result<()> {
    let options = bytehalt_service::Options::parse(args, false)?;
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    run(options, &stop)
}

#[cfg(windows)]
fn run(options: bytehalt_service::Options, stop: &std::sync::atomic::AtomicBool) -> anyhow::Result<()> {
    use bytehalt_core::journal::EventType;
    use std::sync::atomic::Ordering;
    use std::time::{Duration, Instant};
    let tick = options.tick;
    eprintln!(
        "ByteHalt {} — simulado={} desenvolvimento={} pipe={} dados={}",
        bytehalt_service::VERSION,
        options.simulated,
        options.development,
        options.pipe,
        options.data_dir.display()
    );
    let host = std::sync::Arc::new(bytehalt_service::Host::create(options, std::sync::Arc::new(bytehalt_core::clock::SystemClock::new()))?);
    host.journal(EventType::ServiceStarted, if host.options.simulated { "Serviço iniciado (modo simulado)." } else { "Serviço iniciado." });
    let mut server = host.serve()?;
    let mut next = Instant::now() + tick;
    while !stop.load(Ordering::SeqCst) && !host.stop_requested.load(Ordering::SeqCst) {
        std::thread::sleep(Duration::from_millis(200));
        if Instant::now() < next {
            continue;
        }
        next = Instant::now() + tick;
        for r in host.engine.tick() {
            eprintln!("Bloqueio automático: {} => {:?} {}", r.display_name, r.outcome, r.detail.unwrap_or_default());
        }
    }
    server.stop();
    host.journal(EventType::ServiceStopped, "Serviço encerrado.");
    Ok(())
}

#[cfg(windows)]
mod service {
    use std::ffi::OsString;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;
    use windows_service::service::{
        PowerEventParam, ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType, SessionChangeReason,
    };
    use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
    use windows_service::{define_windows_service, service_dispatcher};

    pub const NAME: &str = "ByteHalt";

    define_windows_service!(ffi_service_main, service_main);

    pub fn run() -> anyhow::Result<()> {
        service_dispatcher::start(NAME, ffi_service_main)?;
        Ok(())
    }

    fn service_main(_: Vec<OsString>) {
        if let Err(e) = run_service() {
            eprintln!("{e:#}");
        }
    }

    fn status(state: ServiceState, accept: ServiceControlAccept) -> ServiceStatus {
        ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted: accept,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::from_secs(10),
            process_id: None,
        }
    }

    fn run_service() -> anyhow::Result<()> {
        // Os argumentos do binPath (ex.: --simulate, --data-dir) vêm da linha de comando do processo.
        let args: Vec<String> = std::env::args().skip(1).collect();
        let options = bytehalt_service::Options::parse(&args, true)?;
        let stop = Arc::new(AtomicBool::new(false));
        let locker: Arc<std::sync::Mutex<Option<Arc<bytehalt_service::Host>>>> = Arc::default();
        let (s, l) = (stop.clone(), locker.clone());
        let handle = service_control_handler::register(NAME, move |control| match control {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                s.store(true, Ordering::SeqCst);
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::SessionChange(change) => {
                // Fonte confiável: vem do SCM, não da interface.
                if matches!(change.reason, SessionChangeReason::SessionLock | SessionChangeReason::SessionLogoff)
                    && let Some(host) = l.lock().unwrap_or_else(|e| e.into_inner()).clone()
                {
                    std::thread::spawn(move || {
                        // Bloquear o Windows também fecha as sessões da senha mestra.
                        host.auth.end_all_sessions();
                        let results = host.engine.on_workstation_locked();
                        eprintln!("Windows bloqueado: {} recurso(s) processado(s).", results.len());
                    });
                }
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::PowerEvent(PowerEventParam::Suspend) => {
                // Bloqueia ANTES de responder: o Windows espera o tratamento para suspender.
                if let Some(host) = l.lock().unwrap_or_else(|e| e.into_inner()).clone() {
                    host.auth.end_all_sessions();
                    let results = host.engine.on_suspend();
                    eprintln!("Suspensão: {} recurso(s) processado(s).", results.len());
                }
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::PowerEvent(_) => ServiceControlHandlerResult::NoError,
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        })?;
        handle.set_service_status(status(ServiceState::StartPending, ServiceControlAccept::empty()))?;
        let result = (|| -> anyhow::Result<()> {
            use bytehalt_core::journal::EventType;
            let tick = options.tick;
            let host = Arc::new(bytehalt_service::Host::create(options, Arc::new(bytehalt_core::clock::SystemClock::new()))?);
            *locker.lock().unwrap_or_else(|e| e.into_inner()) = Some(host.clone());
            host.journal(EventType::ServiceStarted, if host.options.simulated { "Serviço iniciado (modo simulado)." } else { "Serviço iniciado." });
            let mut server = host.serve()?;
            handle.set_service_status(status(
                ServiceState::Running,
                ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN | ServiceControlAccept::SESSION_CHANGE | ServiceControlAccept::POWER_EVENT,
            ))?;
            let mut next = std::time::Instant::now() + tick;
            while !stop.load(Ordering::SeqCst) {
                std::thread::sleep(Duration::from_millis(200));
                if std::time::Instant::now() >= next {
                    next = std::time::Instant::now() + tick;
                    host.engine.tick();
                }
            }
            server.stop();
            host.journal(EventType::ServiceStopped, "Serviço encerrado.");
            Ok(())
        })();
        handle.set_service_status(status(ServiceState::Stopped, ServiceControlAccept::empty()))?;
        result
    }
}
